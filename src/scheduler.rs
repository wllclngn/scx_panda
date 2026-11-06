// scx_panda LOADER
// OPEN, SIZE, LOAD, FILL, ATTACH, READ COUNTERS, READ THE EXIT. NOTHING HERE
// DECIDES ANYTHING ABOUT SCHEDULING.

use std::mem::MaybeUninit;

use anyhow::{Context, Result};
use libbpf_rs::skel::{OpenSkel, SkelBuilder};
use libbpf_rs::MapCore;

use crate::bpf_intf::{EWMA_HIST_BUCKETS, MAX_AFFINITY_CANDIDATES, MAX_CPUS};
use crate::bpf_skel::*;
use crate::scx_enums as e;

const SCX_EXIT_NONE: i32 = 0;
const SCX_ECODE_RST_MASK: u64 = 1 << 16;

// THE KERNEL'S EXIT DUMP, CARRIED IN THE EXIT INFO. THE PROGRAM'S
// exit_dump_len AND THE UEI BUFFER ARE SIZED TOGETHER.
pub const EXIT_DUMP_LEN: u32 = 262144;

// THE VERIFIER'S OWN COUNTS, ONE LINE PER PROGRAM, CAPTURED FROM libbpf's
// DEBUG PRINT WHEN --check ASKS FOR THEM. libbpf PRINTS EACH PROGRAM'S WHOLE
// LOAD LOG IN ONE CALL, HEADED BY THE PROGRAM'S NAME AND ENDED BY THE
// "processed N insns" SUMMARY THE STATS LOG LEVEL ADDS.
static VERIFIER_LINES: std::sync::Mutex<Vec<String>> = std::sync::Mutex::new(Vec::new());

fn capture_verifier_print(_level: libbpf_rs::PrintLevel, msg: String) {
    let mut prog = String::new();
    for line in msg.lines() {
        if let Some(rest) = line.strip_prefix("libbpf: prog '") {
            if let Some(end) = rest.find('\'') {
                prog = rest[..end].to_string();
            }
        }
        if line.starts_with("processed ") {
            if let Ok(mut v) = VERIFIER_LINES.lock() {
                v.push(format!("{prog}: {line}"));
            }
        }
    }
}

pub fn verifier_lines() -> Vec<String> {
    VERIFIER_LINES.lock().map(|v| v.clone()).unwrap_or_default()
}

// MATCHES struct panda_stats IN BPF (intf.h), FIELD FOR FIELD.
#[repr(C)]
#[derive(Default, Clone, Copy)]
pub struct PandaStats {
    pub nr_dispatches: u64,
    pub nr_idle_hits: u64,
    pub nr_shared: u64,
    pub nr_preempt: u64,
    pub wake_lat_sum: u64,
    pub wake_lat_samples: u64,
    pub nr_keep_running: u64,
    pub nr_hard_kicks: u64,
    pub nr_soft_kicks: u64,
    pub nr_enq_wakeup: u64,
    pub nr_enq_requeue: u64,
    pub wake_lat_idle_sum: u64,
    pub wake_lat_idle_cnt: u64,
    pub wake_lat_kick_sum: u64,
    pub wake_lat_kick_cnt: u64,
    pub nr_l2_hit_batch: u64,
    pub nr_l2_miss_batch: u64,
    pub nr_l2_hit_interactive: u64,
    pub nr_l2_miss_interactive: u64,
    pub batch_sojourn_ns: u64,
    pub longrun_mode_active: u64,
    pub nr_overflow_rescue: u64,
    pub nr_cross_domain: [u64; 8],
    pub nr_osc_park: u64,
    pub nr_spill_kick_preempt: u64,
    pub nr_steal: u64,
    pub nr_kick_declined: u64,
    pub nr_seat_expect_used: u64,
    pub nr_seat_expect_overrun: u64,
    pub ewma_hist: [u64; EWMA_HIST_BUCKETS],
    pub codel_target_live: u64,
}

// 22 SCALARS + 8 (nr_cross_domain) + 6 SCALARS + 16 (ewma_hist) + 1 = 53 u64.
const _: () = assert!(std::mem::size_of::<PandaStats>() == 53 * 8);
const _: () = assert!(MAX_AFFINITY_CANDIDATES == MAX_CPUS >> 3);

pub struct Scheduler<'a> {
    skel: MainSkel<'a>,
    link: Option<libbpf_rs::Link>,
}

impl<'a> Scheduler<'a> {
    // OPEN THE OBJECT, WRITE RODATA, SIZE THE TOPOLOGY TABLES TO THIS BOX AND
    // LOAD. THE VERIFIER RUNS HERE. NOTHING IS ATTACHED YET.
    pub fn open_and_load(
        open_object: &'a mut MaybeUninit<libbpf_rs::OpenObject>,
        nr_cpus: u32,
        verifier_stats: bool,
    ) -> Result<Self> {
        if verifier_stats {
            libbpf_rs::set_print(Some((libbpf_rs::PrintLevel::Debug, capture_verifier_print)));
        }
        let builder = MainSkelBuilder::default();
        let mut open_skel = builder.open(open_object).context("open")?;

        if verifier_stats {
            // BPF_LOG_STATS: THE VERIFIER APPENDS ITS INSTRUCTION AND STATE
            // COUNTS TO EACH PROGRAM'S LOG.
            for mut prog in open_skel.open_object_mut().progs_mut() {
                prog.set_log_level(4);
            }
        }

        {
            let rodata = open_skel
                .maps
                .rodata_data
                .as_mut()
                .context("rodata not mapped")?;
            rodata.nr_cpu_ids = nr_cpus as u64;
            rodata.uei_dump_len = EXIT_DUMP_LEN;
            // EVERY sched_ext ENUM SHIM THE OBJECT CARRIES, FROM THE KERNEL'S
            // OWN vmlinux.h. AN UNWRITTEN SHIM READS ZERO, WHICH IS A FLAG THAT
            // NEVER FIRES OR A DSQ ID THAT NAMES THE WRONG QUEUE. THE LIST IS
            // THE SKELETON'S LESS THE FIVE ENUMERATORS THIS KERNEL'S BTF DOES
            // NOT DEFINE (SCX_RQ_BAL_PENDING, SCX_RQ_BAL_KEEP, SCX_RQ_BYPASSING,
            // SCX_TASK_CURSOR, SCX_TASK_NR_STATES), WHICH THE PROGRAM NEVER
            // READS. A SHIM ABSENT FROM EITHER SIDE FAILS THE BUILD.
            rodata.__SCX_OPS_NAME_LEN = e::SCX_OPS_NAME_LEN;
            rodata.__SCX_SLICE_DFL = e::SCX_SLICE_DFL;
            rodata.__SCX_SLICE_INF = e::SCX_SLICE_INF;
            rodata.__SCX_RQ_ONLINE = e::SCX_RQ_ONLINE;
            rodata.__SCX_RQ_CAN_STOP_TICK = e::SCX_RQ_CAN_STOP_TICK;
            rodata.__SCX_RQ_CLK_VALID = e::SCX_RQ_CLK_VALID;
            rodata.__SCX_RQ_IN_WAKEUP = e::SCX_RQ_IN_WAKEUP;
            rodata.__SCX_RQ_IN_BALANCE = e::SCX_RQ_IN_BALANCE;
            rodata.__SCX_DSQ_FLAG_BUILTIN = e::SCX_DSQ_FLAG_BUILTIN;
            rodata.__SCX_DSQ_FLAG_LOCAL_ON = e::SCX_DSQ_FLAG_LOCAL_ON;
            rodata.__SCX_DSQ_INVALID = e::SCX_DSQ_INVALID;
            rodata.__SCX_DSQ_GLOBAL = e::SCX_DSQ_GLOBAL;
            rodata.__SCX_DSQ_LOCAL = e::SCX_DSQ_LOCAL;
            rodata.__SCX_DSQ_LOCAL_ON = e::SCX_DSQ_LOCAL_ON;
            rodata.__SCX_DSQ_LOCAL_CPU_MASK = e::SCX_DSQ_LOCAL_CPU_MASK;
            rodata.__SCX_TASK_QUEUED = e::SCX_TASK_QUEUED;
            rodata.__SCX_TASK_RESET_RUNNABLE_AT = e::SCX_TASK_RESET_RUNNABLE_AT;
            rodata.__SCX_TASK_DEQD_FOR_SLEEP = e::SCX_TASK_DEQD_FOR_SLEEP;
            rodata.__SCX_TASK_STATE_SHIFT = e::SCX_TASK_STATE_SHIFT;
            rodata.__SCX_TASK_STATE_BITS = e::SCX_TASK_STATE_BITS;
            rodata.__SCX_TASK_STATE_MASK = e::SCX_TASK_STATE_MASK;
            rodata.__SCX_TASK_NONE = e::SCX_TASK_NONE;
            rodata.__SCX_TASK_INIT = e::SCX_TASK_INIT;
            rodata.__SCX_TASK_READY = e::SCX_TASK_READY;
            rodata.__SCX_TASK_ENABLED = e::SCX_TASK_ENABLED;
            rodata.__SCX_TASK_DSQ_ON_PRIQ = e::SCX_TASK_DSQ_ON_PRIQ;
            rodata.__SCX_KICK_IDLE = e::SCX_KICK_IDLE;
            rodata.__SCX_KICK_PREEMPT = e::SCX_KICK_PREEMPT;
            rodata.__SCX_KICK_WAIT = e::SCX_KICK_WAIT;
            rodata.__SCX_ENQ_WAKEUP = e::SCX_ENQ_WAKEUP;
            rodata.__SCX_ENQ_HEAD = e::SCX_ENQ_HEAD;
            rodata.__SCX_ENQ_PREEMPT = e::SCX_ENQ_PREEMPT;
            rodata.__SCX_ENQ_REENQ = e::SCX_ENQ_REENQ;
            rodata.__SCX_ENQ_LAST = e::SCX_ENQ_LAST;
            rodata.__SCX_ENQ_CLEAR_OPSS = e::SCX_ENQ_CLEAR_OPSS;
            rodata.__SCX_ENQ_DSQ_PRIQ = e::SCX_ENQ_DSQ_PRIQ;
        }

        // THE DYNAMIC ALLOCATION. THE TABLES ARE DECLARED AT MAX_CPUS AND
        // SIZED HERE TO THE CPUs THIS BOX HAS; THE BPF TREATS A LOOKUP PAST THE
        // END AS THE SENTINEL.
        let table = nr_cpus
            .checked_mul(MAX_AFFINITY_CANDIDATES)
            .context("affinity table size overflow")?;
        open_skel.maps.affinity_rank.set_max_entries(table)?;
        open_skel.maps.reff_value.set_max_entries(table)?;
        open_skel.maps.reff_frac.set_max_entries(table)?;
        open_skel.maps.domain_phi.set_max_entries(table)?;
        open_skel.maps.cache_domain.set_max_entries(nr_cpus)?;
        open_skel.maps.cpu_domain.set_max_entries(nr_cpus)?;
        // THE UEI DUMP BUFFER IS A RESIZABLE .data ARRAY; IT IS SIZED HERE TO
        // THE LENGTH THE PROGRAM's exit_dump_len AND uei_dump_len NAME.
        open_skel.maps.data_uei_dump.set_value_size(EXIT_DUMP_LEN)?;

        let skel = open_skel.load().context("load")?;
        Ok(Self { skel, link: None })
    }

    // THE KERNEL'S EXIT DUMP, EMPTY WHEN THE EXIT CARRIED NONE.
    pub fn read_exit_dump(&self) -> String {
        let key = 0u32.to_ne_bytes();
        match self.skel.maps.data_uei_dump.lookup(&key, libbpf_rs::MapFlags::ANY) {
            Ok(Some(bytes)) => cstr(&bytes),
            _ => String::new(),
        }
    }

    pub fn attach(&mut self) -> Result<()> {
        let link = self.skel.maps.panda_ops.attach_struct_ops().context("attach")?;
        self.link = Some(link);
        Ok(())
    }

    pub fn read_stats_percpu(&self) -> Vec<PandaStats> {
        let key = 0u32.to_ne_bytes();
        let percpu_vals = match self
            .skel
            .maps
            .stats_map
            .lookup_percpu(&key, libbpf_rs::MapFlags::ANY)
        {
            Ok(Some(v)) => v,
            _ => return Vec::new(),
        };
        percpu_vals
            .iter()
            .filter(|v| v.len() >= std::mem::size_of::<PandaStats>())
            .map(|v| unsafe { std::ptr::read_unaligned(v.as_ptr() as *const PandaStats) })
            .collect()
    }

    // THE FOLD. batch_sojourn_ns AND longrun_mode_active TAKE A MAX ACROSS
    // CPUs; EVERYTHING ELSE SUMS.
    pub fn fold_stats(percpu: &[PandaStats]) -> PandaStats {
        let mut t = PandaStats::default();
        for s in percpu {
            t.nr_dispatches += s.nr_dispatches;
            t.nr_idle_hits += s.nr_idle_hits;
            t.nr_shared += s.nr_shared;
            t.nr_preempt += s.nr_preempt;
            t.wake_lat_sum += s.wake_lat_sum;
            t.wake_lat_samples += s.wake_lat_samples;
            t.nr_keep_running += s.nr_keep_running;
            t.nr_hard_kicks += s.nr_hard_kicks;
            t.nr_soft_kicks += s.nr_soft_kicks;
            t.nr_enq_wakeup += s.nr_enq_wakeup;
            t.nr_enq_requeue += s.nr_enq_requeue;
            t.wake_lat_idle_sum += s.wake_lat_idle_sum;
            t.wake_lat_idle_cnt += s.wake_lat_idle_cnt;
            t.wake_lat_kick_sum += s.wake_lat_kick_sum;
            t.wake_lat_kick_cnt += s.wake_lat_kick_cnt;
            t.nr_l2_hit_batch += s.nr_l2_hit_batch;
            t.nr_l2_miss_batch += s.nr_l2_miss_batch;
            t.nr_l2_hit_interactive += s.nr_l2_hit_interactive;
            t.nr_l2_miss_interactive += s.nr_l2_miss_interactive;
            t.batch_sojourn_ns = t.batch_sojourn_ns.max(s.batch_sojourn_ns);
            t.longrun_mode_active = t.longrun_mode_active.max(s.longrun_mode_active);
            t.nr_overflow_rescue += s.nr_overflow_rescue;
            for i in 0..8 {
                t.nr_cross_domain[i] += s.nr_cross_domain[i];
            }
            t.nr_osc_park += s.nr_osc_park;
            t.nr_spill_kick_preempt += s.nr_spill_kick_preempt;
            t.nr_steal += s.nr_steal;
            t.nr_kick_declined += s.nr_kick_declined;
            t.nr_seat_expect_used += s.nr_seat_expect_used;
            t.nr_seat_expect_overrun += s.nr_seat_expect_overrun;
            if s.codel_target_live > t.codel_target_live {
                t.codel_target_live = s.codel_target_live;
            }
            for i in 0..EWMA_HIST_BUCKETS {
                t.ewma_hist[i] += s.ewma_hist[i];
            }
        }
        t
    }

    pub fn read_stats(&self) -> PandaStats {
        Self::fold_stats(&self.read_stats_percpu())
    }

    fn write_u32(map: &impl MapCore, key: u32, val: u32) -> Result<()> {
        map.update(&key.to_ne_bytes(), &val.to_ne_bytes(), libbpf_rs::MapFlags::ANY)?;
        Ok(())
    }

    pub fn write_cache_domain(&self, cpu: u32, l2_group: u32) -> Result<()> {
        Self::write_u32(&self.skel.maps.cache_domain, cpu, l2_group)
    }

    pub fn write_cpu_domain(&self, cpu: u32, domain: u32) -> Result<()> {
        Self::write_u32(&self.skel.maps.cpu_domain, cpu, domain)
    }

    // THE FOUR TABLES PAIR 1:1 ON cpu * MAX_AFFINITY_CANDIDATES + slot.
    pub fn write_affinity_rank(&self, cpu: u32, slot: u32, target_cpu: u32) -> Result<()> {
        Self::write_u32(&self.skel.maps.affinity_rank, cpu * MAX_AFFINITY_CANDIDATES + slot, target_cpu)
    }

    pub fn write_reff_value(&self, cpu: u32, slot: u32, value: u32) -> Result<()> {
        Self::write_u32(&self.skel.maps.reff_value, cpu * MAX_AFFINITY_CANDIDATES + slot, value)
    }

    pub fn write_domain_phi(&self, cpu: u32, slot: u32, value: u32) -> Result<()> {
        Self::write_u32(&self.skel.maps.domain_phi, cpu * MAX_AFFINITY_CANDIDATES + slot, value)
    }

    pub fn write_reff_frac(&self, cpu: u32, slot: u32, value: u32) -> Result<()> {
        Self::write_u32(&self.skel.maps.reff_frac, cpu * MAX_AFFINITY_CANDIDATES + slot, value)
    }

    // THE "GO" SIGNAL. WRITTEN LAST, AFTER EVERY TABLE: THE FIRST TICK THAT
    // SEES A NON-ZERO tau DERIVES EVERY tau-SCALED STATIC FROM TABLES THAT ARE
    // ALREADY FILLED.
    pub fn write_topo(
        &mut self,
        tau_ns: u64,
        codel_eq_ns: u64,
        nr_overflow_domains: u32,
        affinity_domain_peers: u32,
    ) -> Result<()> {
        let data = self.skel.maps.data_data.as_mut().context("data not mapped")?;
        data.topo.nr_overflow_domains = nr_overflow_domains;
        data.topo.affinity_domain_peers = affinity_domain_peers;
        data.topo.codel_eq_ns = codel_eq_ns;
        data.topo.tau_ns = tau_ns;
        Ok(())
    }

    // READ THE EXIT. RETURNS WHETHER THE KERNEL ASKED FOR A RESTART.
    pub fn read_exit_info(&self) -> bool {
        let Some(data) = self.skel.maps.data_data.as_ref() else { return false };
        let kind = data.uei.kind;
        let exit_code = data.uei.exit_code;
        if kind != SCX_EXIT_NONE {
            let reason = cstr(&data.uei.reason);
            let msg = cstr(&data.uei.msg);
            log_warn!("BPF exit: kind={} code={}", kind, exit_code);
            if !reason.is_empty() {
                log_warn!("BPF exit reason: {}", reason);
            }
            if !msg.is_empty() {
                log_warn!("BPF exit msg: {}", msg);
            }
        }
        (exit_code as u64 & SCX_ECODE_RST_MASK) != 0
    }

    pub fn exited(&self) -> bool {
        self.skel
            .maps
            .data_data
            .as_ref()
            .map(|d| d.uei.kind != SCX_EXIT_NONE)
            .unwrap_or(true)
    }
}

fn cstr<T>(field: &[T]) -> String {
    let bytes: &[u8] = unsafe {
        std::slice::from_raw_parts(field.as_ptr() as *const u8, std::mem::size_of_val(field))
    };
    let end = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8_lossy(&bytes[..end]).into_owned()
}

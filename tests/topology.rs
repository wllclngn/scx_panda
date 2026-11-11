// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// THE LOADER'S TOPOLOGY DERIVATION, ON PARTS BUILT BY HAND: THE 12C REFERENCE
// BOX WHOLE AND WITH CPUs TAKEN OFFLINE AS prism TAKES THEM, AND SYMMETRIC
// PARTS FROM 2 TO 1,024 CPUs. EVERYTHING HERE READS THE LIBRARY'S PUBLIC
// ITEMS; NO TEST LIVES UNDER src/.

use scx_panda::bpf_intf::{CODEL_FLOOR_MIN_NS, MAX_AFFINITY_CANDIDATES};
use scx_panda::topology::{
    CpuTopology, LAMBDA_ZERO_EPS, OFFLINE_ID, TAU_CEIL_NS, TAU_FLOOR_NS, extract_fiedler,
    parse_cpu_list,
};

// K_CODEL_FLOOR AND K_CODEL_MAX AS main.bpf.c HOLDS THEM, Q16.
const K_CODEL_FLOOR: u64 = 1147;
const K_CODEL_MAX: u64 = 3277;

// THE 12C REFERENCE: SIX SMT PAIRS {c, c+6}, TWO L3 DOMAINS OF THREE CORES,
// ONE SOCKET.
fn box_12c() -> CpuTopology {
    let n = 12;
    let l2_domain: Vec<u32> = (0..n).map(|c| (c % 6) as u32).collect();
    let l2_groups: Vec<Vec<u32>> = (0..6).map(|g| vec![g as u32, g as u32 + 6]).collect();
    let llc_domain: Vec<u32> = (0..n).map(|c| if c % 6 < 3 { 0 } else { 1 }).collect();
    CpuTopology {
        nr_cpus: n,
        online: (0..n).collect(),
        l2_domain,
        l2_groups,
        socket_domain: vec![0; n],
        llc_domain,
        nr_sockets: 1,
    }
}

// THE 12C REFERENCE WITH ONLY CPUs 0..k ONLINE, AS detect() READS IT: AN
// OFFLINE CPU CARRIES OFFLINE_ID IN EVERY GROUP, AND AN L2 GROUP LISTS ITS
// ONLINE MEMBERS ONLY.
fn box_12c_online(k: usize) -> CpuTopology {
    let mut t = box_12c();
    t.online = (0..k).collect();
    for cpu in k..t.nr_cpus {
        t.l2_domain[cpu] = OFFLINE_ID;
        t.llc_domain[cpu] = OFFLINE_ID;
        t.socket_domain[cpu] = OFFLINE_ID;
    }
    for g in t.l2_groups.iter_mut() {
        g.retain(|&c| (c as usize) < k);
    }
    t
}

// A SYMMETRIC PART: l3s L3 DOMAINS OF cores CORES EACH ON ONE SOCKET, EVERY
// CORE'S SECOND THREAD NUMBERED AFTER ALL THE FIRST ONES WHEN smt.
fn box_grid(l3s: usize, cores: usize, smt: bool) -> CpuTopology {
    let nr_cores = l3s * cores;
    let n = if smt { 2 * nr_cores } else { nr_cores };
    CpuTopology {
        nr_cpus: n,
        online: (0..n).collect(),
        l2_domain: (0..n).map(|c| (c % nr_cores) as u32).collect(),
        l2_groups: (0..nr_cores)
            .map(|g| if smt { vec![g as u32, (g + nr_cores) as u32] } else { vec![g as u32] })
            .collect(),
        socket_domain: vec![0; n],
        llc_domain: (0..n).map(|c| ((c % nr_cores) / cores) as u32).collect(),
        nr_sockets: 1,
    }
}

// THE BAND tau ALONE GIVES, K_CODEL_FLOOR * tau TO K_CODEL_MAX * tau, IN
// apply_tau_scaling()'s OWN INTEGER ARITHMETIC AND BEFORE ANY RAIL.
fn tau_band(tau_ns: u64) -> (u64, u64) {
    ((tau_ns * K_CODEL_FLOOR) >> 16, (tau_ns * K_CODEL_MAX) >> 16)
}

// apply_tau_scaling()'s WINDOW, RAILS INCLUDED: (FLOOR, MAX).
fn bpf_window(tau_ns: u64) -> (u64, u64) {
    let (raw_floor, raw_max) = tau_band(tau_ns);
    let floor = raw_floor.clamp(CODEL_FLOOR_MIN_NS, 800_000);
    let max = raw_max.max(floor * K_CODEL_MAX / K_CODEL_FLOOR).min(8_000_000);
    (floor, max)
}

#[test]
fn cpu_list_parses_ranges_and_singles() {
    assert_eq!(parse_cpu_list("0,6"), vec![0, 6]);
    assert_eq!(parse_cpu_list("0-2,6-8"), vec![0, 1, 2, 6, 7, 8]);
    assert_eq!(parse_cpu_list("3"), vec![3]);
    assert_eq!(parse_cpu_list("8-8,1,1"), vec![1, 8]);
    assert!(parse_cpu_list("").is_empty());
}

#[test]
fn reference_box_tau_and_equilibrium() {
    let t = box_12c();
    let (reff, rank, spectrum) = t.compute_resistance_affinity();
    assert_eq!(reff.len(), 144);
    assert_eq!(rank.len(), 144);
    // tau = 160ms / sqrt(lambda_2 * N); lambda_2 = 12 on this graph.
    assert!(spectrum.fiedler > 11.9 && spectrum.fiedler < 12.1, "lambda_2 {}", spectrum.fiedler);
    assert!(spectrum.tau_ns > 13_000_000 && spectrum.tau_ns < 13_700_000, "tau {}", spectrum.tau_ns);
    let (floor, max) = tau_band(spectrum.tau_ns);
    let eq = spectrum.codel_eq_ns;
    assert!(eq + 1 >= floor && eq <= max + 1, "codel_eq {} outside [{}, {}]", eq, floor, max);
}

#[test]
fn effective_resistance_is_a_metric_with_three_rungs() {
    let t = box_12c();
    let (reff, rank, _) = t.compute_resistance_affinity();
    let n = 12;
    for i in 0..n {
        assert_eq!(reff[i * n + i], 0.0);
        for j in 0..n {
            assert!((reff[i * n + j] - reff[j * n + i]).abs() < 1e-9);
            for k in 0..n {
                assert!(reff[i * n + j] <= reff[i * n + k] + reff[k * n + j] + 1e-9);
            }
        }
    }
    // SLOT 0 OF EVERY RANK IS THE SMT SIBLING, THE NEAREST RUNG.
    for cpu in 0..n {
        assert_eq!(rank[cpu * n], ((cpu + 6) % 12) as u32, "cpu {} slot 0", cpu);
        assert_eq!(rank[cpu * n + n - 1], u32::MAX, "cpu {} sentinel", cpu);
    }
    // SAME-L3 PEERS PRECEDE EVERY CROSS-L3 PEER.
    let smt = reff[6];
    let same_l3 = reff[1];
    let cross_l3 = reff[3];
    assert!(smt < same_l3 && same_l3 < cross_l3, "{} {} {}", smt, same_l3, cross_l3);
}

#[test]
fn domains_follow_the_l3_seam() {
    let t = box_12c();
    let tree = t.compute_domain_tree();
    assert_eq!(t.domain_count(), 2);
    let dom = t.domain_partition(&tree, 2);
    assert_eq!(dom.len(), 12);
    for cpu in 0..12 {
        for other in 0..12 {
            let same = t.llc_domain[cpu] == t.llc_domain[other];
            assert_eq!(dom[cpu] == dom[other], same, "cpus {} {}", cpu, other);
        }
    }
    let (_, rank, _) = t.compute_resistance_affinity();
    // FIVE SAME-DOMAIN PEERS BEFORE THE FIRST CROSS-DOMAIN SLOT.
    assert_eq!(t.min_in_domain_peers(&rank, &dom), 5);
    // LEAVES ARE L2 GROUPS: AN SMT PAIR SHARES NO CUT, A SAME-L3 PAIR
    // CROSSES A TIGHT SEAM (HIGH phi), A CROSS-L3 PAIR A LOOSE ONE (LOW).
    let phi = t.domain_cross_phi_matrix(&tree);
    assert_eq!(phi[6], u32::MAX);
    assert_ne!(phi[1], u32::MAX);
    assert_ne!(phi[3], u32::MAX);
    assert!(phi[3] < phi[1], "{} {}", phi[3], phi[1]);
    assert_eq!(phi[3], phi[3 * 12]);
}

#[test]
fn two_cores_one_l3_price_nothing() {
    let t = CpuTopology {
        nr_cpus: 2,
        online: vec![0, 1],
        l2_domain: vec![0, 1],
        l2_groups: vec![vec![0], vec![1]],
        socket_domain: vec![0, 0],
        llc_domain: vec![0, 0],
        nr_sockets: 1,
    };
    let (reff, rank, spectrum) = t.compute_resistance_affinity();
    assert!(reff[1] > 0.0);
    assert_eq!(rank[0], 1);
    assert_eq!(rank[1], u32::MAX);
    assert_eq!(rank[2], 0);
    assert_eq!(t.domain_count(), 1);
    assert!(spectrum.tau_ns >= TAU_FLOOR_NS && spectrum.tau_ns <= TAU_CEIL_NS);
}

// THE BAND KEEPS ITS RANGE WHERE tau PUTS ITS FLOOR UNDER THE 200us RAIL,
// AND THE EQUILIBRIUM LIES STRICTLY INSIDE IT: 16 CPUs IN TWO L3s, 32 IN
// TWO WITH SMT, 32 IN EIGHT AND 64 IN EIGHT WITH SMT.
#[test]
fn the_band_keeps_its_range_on_large_parts() {
    for (l3s, cores, smt) in [(2, 8, false), (2, 8, true), (8, 4, false), (8, 4, true)] {
        let t = box_grid(l3s, cores, smt);
        let (_, _, spectrum) = t.compute_resistance_affinity();
        let (floor, max) = bpf_window(spectrum.tau_ns);
        let eq = spectrum.codel_eq_ns;
        assert_eq!(floor, CODEL_FLOOR_MIN_NS,
                   "{} CPUs: tau {} leaves the rail", t.nr_cpus, spectrum.tau_ns);
        assert!(max >= floor * K_CODEL_MAX / K_CODEL_FLOOR,
                "{} CPUs: window [{}, {}]", t.nr_cpus, floor, max);
        assert!(floor < eq && eq < max,
                "{} CPUs in {} L3s: eq {} outside ({}, {}) at tau {}",
                t.nr_cpus, l3s, eq, floor, max, spectrum.tau_ns);
    }
    // THE REFERENCE BOX IS ABOVE THE RAIL AND ITS WINDOW IS tau's.
    let (_, _, spectrum) = box_12c().compute_resistance_affinity();
    assert_eq!(bpf_window(spectrum.tau_ns), tau_band(spectrum.tau_ns));
}

// THE FACTORED PSEUDOINVERSE AGAINST THE EIGENSOLVE'S, ON THE REFERENCE
// BOX AND AT THE WIDEST PART THE EIGENSOLVE STILL SERVES: R_eff, lambda_2
// AND Tr(L+) AGREE.
#[test]
fn the_factored_pseudoinverse_agrees_with_the_eigensolve() {
    for t in [box_12c(), box_grid(8, 4, true)] {
        let m = t.online.len();
        let lap = t.build_laplacian();
        let (ev, evec) = CpuTopology::symmetric_eigen(&lap, m);
        let by_eigen = CpuTopology::extract_reff(
            &CpuTopology::compute_pseudoinverse(&ev, &evec, m), m);
        let pinv = CpuTopology::pseudoinverse_by_factor(&lap, m).expect("positive definite");
        let by_factor = CpuTopology::extract_reff(&pinv, m);
        for (a, b) in by_eigen.iter().zip(&by_factor) {
            assert!((a - b).abs() < 1e-9, "{} CPUs: R_eff {} against {}", m, a, b);
        }
        let fiedler = CpuTopology::fiedler_from_pseudoinverse(&pinv, m);
        let want = extract_fiedler(&ev);
        assert!((fiedler - want).abs() < 1e-9 * want, "{} CPUs: lambda_2 {} against {}", m, fiedler, want);
        let trace: f64 = (0..m).map(|i| pinv[i * m + i]).sum();
        let sum_inv: f64 = ev.iter().filter(|&&x| x > LAMBDA_ZERO_EPS).map(|x| 1.0 / x).sum();
        assert!((trace - sum_inv).abs() < 1e-9 * sum_inv, "{} CPUs: Tr(L+) {} against {}", m, trace, sum_inv);
    }
}

// A PART PAST THE EIGENSOLVE'S REACH TAKES THE FACTOR AND THE WALK CUT:
// 128 CPUs IN EIGHT L3s. ITS DOMAINS ARE ITS L3s, SLOT 0 OF EVERY ROW IS THE
// SMT SIBLING, AND THE PEER COUNT IS THE DOMAIN'S.
#[test]
fn a_wide_part_keeps_its_l3s() {
    let t = box_grid(8, 8, true);
    let n = t.nr_cpus;
    let (_, rank, spectrum) = t.compute_resistance_affinity();
    assert!(spectrum.fiedler > 127.9 && spectrum.fiedler < 128.1, "lambda_2 {}", spectrum.fiedler);
    assert_eq!(t.domain_count(), 8);
    let tree = t.compute_domain_tree();
    let dom = t.domain_partition(&tree, 8);
    for a in 0..n {
        for b in 0..n {
            assert_eq!(dom[a] == dom[b], t.llc_domain[a] == t.llc_domain[b], "cpus {} {}", a, b);
        }
    }
    assert_eq!(t.min_in_domain_peers(&rank, &dom), 15);
    for cpu in 0..n {
        assert_eq!(rank[cpu * n], ((cpu + 64) % 128) as u32, "cpu {} slot 0", cpu);
    }
}

// THE WHOLE DERIVATION AT 256, 512 AND 1,024 CPUs, TIMED. RUN BY NAME:
// cargo test --release --test topology -- --ignored --nocapture the_solver_at_scale
#[test]
#[ignore]
fn the_solver_at_scale() {
    for (l3s, cores) in [(16, 8), (32, 8), (64, 8)] {
        let t = box_grid(l3s, cores, true);
        let n = t.nr_cpus;
        let t0 = std::time::Instant::now();
        let (reff, rank, spectrum) = t.compute_resistance_affinity();
        let t1 = std::time::Instant::now();
        let tree = t.compute_domain_tree();
        let phi = t.domain_cross_phi_matrix(&tree);
        let nd = t.domain_count();
        let dom = t.domain_partition(&tree, nd);
        let peers = t.min_in_domain_peers(&rank, &dom);
        let tb = t.affinity_tables(&reff, &rank, spectrum.phi_dist_scale_q16,
                                   spectrum.codel_eq_ns, &phi);
        let t2 = std::time::Instant::now();
        println!("SOLVER cpus={} spectrum={:?} tree_and_tables={:?} lambda2={:.3} tau={} eq={} domains={} peers={}",
                 n, t1 - t0, t2 - t1, spectrum.fiedler, spectrum.tau_ns, spectrum.codel_eq_ns, nd, peers);
        assert!((spectrum.fiedler - n as f64).abs() < 1e-6 * n as f64);
        assert_eq!(nd, l3s);
        for a in 0..n {
            assert_eq!(dom[a], dom[(a + n / 2) % n], "cpu {} and its sibling", a);
        }
        assert_eq!(tb.rank.len(), n * MAX_AFFINITY_CANDIDATES as usize);
        assert_eq!(peers, 15);
    }
}

// prism's 8C: CPUs 8..11 OFFLINE. CORES 0 AND 1 KEEP THEIR SIBLINGS (6, 7),
// CORE 2 AND THE WHOLE SECOND L3 RUN ONE THREAD EACH.
#[test]
fn eight_of_twelve_online_keeps_two_domains() {
    let t = box_12c_online(8);
    let n = t.nr_cpus;
    let (reff, rank, spectrum) = t.compute_resistance_affinity();
    assert_eq!(t.domain_count(), 2);
    let tree = t.compute_domain_tree();
    let dom = t.domain_partition(&tree, 2);
    for &a in &[0usize, 1, 2, 6, 7] {
        assert_eq!(dom[a], dom[0], "cpu {} with cpu 0", a);
    }
    for &b in &[3usize, 4, 5] {
        assert_eq!(dom[b], dom[3], "cpu {} with cpu 3", b);
    }
    assert_ne!(dom[0], dom[3]);
    // THE SECOND L3'S THREE CPUs EACH HAVE TWO PEERS IN IT.
    assert_eq!(t.min_in_domain_peers(&rank, &dom), 2);
    for cpu in 0..8 {
        let row = &rank[cpu * n..cpu * n + n];
        assert!(row[..7].iter().all(|&c| c < 8 && c as usize != cpu), "cpu {} row {:?}", cpu, row);
        assert!(row[7..].iter().all(|&c| c == u32::MAX), "cpu {} tail {:?}", cpu, row);
    }
    for cpu in 8..12 {
        assert!(rank[cpu * n..cpu * n + n].iter().all(|&c| c == u32::MAX), "cpu {} offline row", cpu);
        assert_eq!(dom[cpu], OFFLINE_ID);
        for other in 0..12 {
            assert_eq!(reff[cpu * n + other], 0.0);
        }
    }
    assert_eq!(rank[0], 6, "cpu 0 slot 0 is its SMT sibling");
    // A SAME-L3 PEER PRECEDES EVERY CROSS-L3 ONE IN THE ROW, WHERE R_eff
    // ALONE WOULD NOT PUT IT: CPU 3 HAS NO SIBLING ONLINE AND READS THE
    // OTHER L3'S SIBLING-BEARING CPUs NEARER THAN ITS OWN L3'S.
    assert!(reff[3 * n] < reff[3 * n + 4]);
    assert_eq!(&rank[3 * n..3 * n + 2], &[4, 5]);
    assert_eq!(&rank[2 * n..2 * n + 4], &[0, 1, 6, 7]);
    for cpu in 0..8 {
        let own: Vec<bool> = rank[cpu * n..cpu * n + 7].iter()
            .map(|&c| dom[c as usize] == dom[cpu]).collect();
        assert!(own.windows(2).all(|w| w[0] || !w[1]), "cpu {} row leaves its L3 and returns: {:?}", cpu, own);
    }
    let (floor, max) = tau_band(spectrum.tau_ns);
    let eq = spectrum.codel_eq_ns;
    assert!(eq + 1 >= floor && eq <= max + 1, "codel_eq {} outside [{}, {}]", eq, floor, max);
    // THE STORED ROWS: AN OFFLINE CPU'S IS SENTINEL IN ALL FOUR TABLES, AN
    // ONLINE ONE'S HOLDS ITS SEVEN PEERS AND THEN THE SENTINEL.
    let phi = t.domain_cross_phi_matrix(&tree);
    let tb = t.affinity_tables(&reff, &rank, spectrum.phi_dist_scale_q16,
                               spectrum.codel_eq_ns, &phi);
    let stride = MAX_AFFINITY_CANDIDATES as usize;
    for cpu in 0..12 {
        let peers = if cpu < 8 { 7 } else { 0 };
        for slot in 0..stride {
            let at = cpu * stride + slot;
            assert_eq!(tb.rank[at] == u32::MAX, slot >= peers, "cpu {} slot {}", cpu, slot);
            if slot >= peers {
                assert_eq!(tb.value[at], u32::MAX);
                assert_eq!(tb.frac[at], u32::MAX);
                assert_eq!(tb.phi[at], u32::MAX);
            } else {
                assert!(tb.frac[at] <= 65536);
            }
        }
    }
    // THE SMT SIBLING IS THE NEAREST PAIR ON THE MACHINE: FRACTION 0.
    assert_eq!(tb.frac[0], 0);
}

// prism's 4C: CPUs 0..3, NO SIBLING ONLINE, {0,1,2} ON ONE L3 AND {3} ALONE
// ON THE OTHER.
#[test]
fn four_of_twelve_online_leaves_a_singleton_domain() {
    let t = box_12c_online(4);
    let n = t.nr_cpus;
    let (_, rank, _) = t.compute_resistance_affinity();
    assert_eq!(t.domain_count(), 2);
    let tree = t.compute_domain_tree();
    let dom = t.domain_partition(&tree, 2);
    assert!(dom[0] == dom[1] && dom[1] == dom[2]);
    assert_ne!(dom[0], dom[3]);
    // CPU 3 HAS NO IN-DOMAIN PEER AND DOES NOT SET THE BOUND.
    assert_eq!(t.min_in_domain_peers(&rank, &dom), 2);
    for cpu in 0..4 {
        assert!(rank[cpu * n..cpu * n + 3].iter().all(|&c| c < 4));
        assert_eq!(rank[cpu * n + 3], u32::MAX);
    }
    // CPU 3'S ROW: THE THREE CROSS-L3 PEERS, ALL AT ONE DISTANCE.
    assert_eq!(&rank[3 * n..3 * n + 3], &[0, 1, 2]);
}

// THE SWEEP'S AND THE TICK SCAN'S WINDOWS, IN apply_tau_scaling()'s OWN INTEGER
// ARITHMETIC (main.bpf.c, sweep_win_count), WITH THE TWO BUDGETS HELD HERE AS
// main.bpf.c HOLDS THEM: AS MANY WINDOWS AS KEEP A SEAT OUT OF ALL OF THEM NO
// LONGER THAN lag_cap_ns, AND THE SEATS FROM ONE WINDOW'S START TO THE NEXT'S.
const BOUND_SWEEP_BUDGET: u32 = 8;
const TICK_SCAN_BUDGET: u32 = 4;

fn windows(n: u32, budget: u32, lag_cap_ns: u64) -> (u32, u32) {
    let gap = (lag_cap_ns >> 20) as u32;
    let w = ((n + budget + gap - 1) / (budget + gap)).max(1);
    (w, if w > 1 { (n + w - 1) / w } else { 0 })
}

// THE LONGEST RUN OF CLOCK STEPS A SEAT SPENDS OUTSIDE EVERY WINDOW. THE
// WINDOWS MOVE ONE SEAT A STEP, SO EVERY SEAT SEES SEAT 0's PATTERN SHIFTED AND
// ONE ROTATION OF n STEPS IS THE WHOLE OF IT.
fn longest_gap(n: u32, budget: u32, w: u32, stride: u32) -> u32 {
    let covered: Vec<bool> = (0..n)
        .map(|t| (0..w).any(|g| (2 * n - t % n - (g * stride) % n) % n < budget))
        .collect();
    if covered.iter().all(|&c| c) {
        return 0;
    }
    let first = covered.iter().position(|&c| c).expect("a window covers its own start");
    let (mut worst, mut run) = (0u32, 0u32);
    for i in 0..n as usize {
        if covered[(first + i) % n as usize] {
            run = 0;
        } else {
            run += 1;
            worst = worst.max(run);
        }
    }
    worst
}

#[test]
fn the_windows_keep_every_seat_inside_lag_cap() {
    // THE REFERENCE BOX AT ITS OWN WIDTH AND prism's: ONE WINDOW, THE CLOCK'S.
    for (n, lag) in [(12u32, 13_333_333u64), (8, 20_000_000), (4, 40_000_000)] {
        assert_eq!(windows(n, BOUND_SWEEP_BUDGET, lag), (1, 0));
        assert_eq!(windows(n, TICK_SCAN_BUDGET, lag), (1, 0));
    }
    // THE PARTS THE CLOCK'S ROTATION FAILS, AT lag_cap_ns's 8 ms FLOOR.
    assert_eq!(windows(16, BOUND_SWEEP_BUDGET, 8_000_000).0, 2);
    assert_eq!(windows(32, BOUND_SWEEP_BUDGET, 8_000_000).0, 3);
    assert_eq!(windows(128, BOUND_SWEEP_BUDGET, 8_000_000).0, 9);
    assert_eq!(windows(128, TICK_SCAN_BUDGET, 8_000_000).0, 12);
    // ONE WINDOW AT 128 CPUs LEAVES A SEAT OUT FOR 120 STEPS, 126 ms.
    assert_eq!(longest_gap(128, BOUND_SWEEP_BUDGET, 1, 0), 120);
    for lag in [8_000_000u64, 13_333_333, 20_000_000, 40_000_000, 80_000_000] {
        let bound = (lag >> 20) as u32;
        for n in 1..=1024u32 {
            for budget in [BOUND_SWEEP_BUDGET, TICK_SCAN_BUDGET] {
                let (w, stride) = windows(n, budget, lag);
                // EVERY WINDOW HAS A CPU: CPUs JOIN ONE BY THEIR NUMBER MOD w.
                assert!(w >= 1 && w <= n, "n={n} budget={budget} lag={lag}: {w} windows");
                let gap = longest_gap(n, budget, w, stride);
                assert!(gap <= bound,
                        "n={n} budget={budget} lag={lag}: {w} windows {stride} apart \
                         leave a seat out for {gap} steps, past {bound}");
            }
        }
    }
}

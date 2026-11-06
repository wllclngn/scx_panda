# 🐼

scx_panda is a sched_ext scheduler built from discarded ideas and unspent
potential, written in C23 for BPF with a Rust loader. Every scheduling decision is made in the kernel. The loader opens
the program, sizes its topology tables to the box, fills them from sysfs once,
attaches, and reads counters. Nothing in userspace runs while the scheduler
runs except a hotplug poll.

## What it carries

**The waterfall.** The per-CPU seat architecture and dispatch ladder of
PANDEMONIUM v5.24.0, lifted whole: Per-CPU DSQs with a queue clock judged by
CoDel's control law, admission by backlog in nanoseconds, a direct hand-off
to an idle CPU, a cutting wake seated on its local DSQ with a preempt kick,
one task into the local DSQ per dispatch, the aged overflow taken near first,
the R_eff steal, the bound sweep acting at the clock's own target between
ticks, the fan-out wake that takes the queue, and every array index masked
behind a compiler barrier for the verifier.

**The run habit.** One EWMA per task, `avg_run_ns`, fed in `stopping()` from
the kernel's own service accounting: Seeded on the first run, then
`avg += (sample - avg) / 8` with a signed shift, the sample clamped to four
live CoDel targets. It is read as a price and never as a class. `seat_wait()`
takes the resident's habit as the bound on what the resident has left while
it runs inside that habit, so a seat whose resident is a 240us job worker
reads as freeing in microseconds where the granted slice alone read a full
millisecond, and a wake that would have gone to the shared domain queue is
admitted to a named seat instead. A resident past its habit is not behaving
like its history, and the granted slice stands. The two outcomes are counted
(`expect_used`, `expect_overrun`) and the habit's distribution is exported as
a log2 histogram, so the price is read against the population it prices.

**Topology as allocation.** Effective resistance over the cache graph, the
min-conductance domain tree, tau from the Laplacian spectrum and the CoDel
equilibrium are computed once by the loader and folded into per-peer tables
the BPF reads by index. The base knob set (slice, standing ceiling, burst
ceiling, rescue threshold) is derived from tau inside BPF; no userspace
writer touches a knob.

## What it does not carry

No adaptive control loop, no sensors, no chaos lenses, no depth ring, no
per-second knob writes. No task classifier, no tier, no boolean gate on the
habit. No credit-for-service term in the ordering key: Every queue is
oldest-first on the arrival stamp.

## Build and install

```
./panda.py check              # build, then load through the verifier without attaching
./panda.py install --enable   # build, install /usr/local/bin/scx_panda, start it, start it on boot
./panda.py status
./panda.py stop               # back to EEVDF
./panda.py uninstall
./panda.py prism --dev frame --iterations 5   # PANDEMONIUM's prism with scx_panda as the arm
./panda.py measure --control --iterations 3   # the measurement-arm A/B on prism-scale
```

`prism` hands its arguments to PANDEMONIUM's harness in the sibling tree
(`PANDEMONIUM_DIR` overrides the path) with `--only scx_panda` added unless
the arguments name the field themselves, refuses to start while another bench
is running, and starts the service again afterwards if it was active. prism
asks for sudo itself. `measure` runs the shipped program and each measurement
arm through prism-scale in turn and prints the reports side by side.

`install` builds into `~/.cache/panda-build`, installs the binary with the
file capabilities it needs to load without root
(`cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_nice`), and
writes `scx_panda.service`. `start` refuses while another sched_ext scheduler
holds the kernel and names it. The build directory lives outside the source
tree because libbpf's vendored build does not survive a space in the path.
The first build on a kernel dumps its BTF to
`~/.cache/panda/vmlinux-<release>.h` with bpftool, and the loader's sched_ext
enum values are extracted from that same header at build time, so the program
and the shims it is given always describe one kernel.

By hand: `CARGO_TARGET_DIR=~/.cache/panda-build cargo build --release`, then
`scx_panda --check` loads through the verifier and exits without attaching,
and `scx_panda -v` runs with one counter line per second. On exit the binary
prints the run habit's histogram and the seat price's two counters.

## scx catalog and export

`catalog/profiles.json` carries the profile scxcli and scxtui start the
scheduler by once scx's own scx_panda is installed; `panda.py install` offers
it into `/etc/scx/catalog.json` where scxcli is present. `export_scx.py
/path/to/scx` lays the crate into `scheds/rust/scx_panda` of an scx checkout
the way PANDEMONIUM's exporter does: It refuses while an upstream commit to the
crate is unported, checks scx's catalog, copies the sources and the catalog,
replaces the build script with scx_cargo's BpfBuilder, swaps the build-time
enum shims for `scx_utils::scx_enum_init!`, registers the workspace member and
runs cargo fmt and a build of the crate. `--dry-run` applies the transforms
without the fetch or the cargo steps. It commits nothing.

## Requirements

Linux 6.12+ with `CONFIG_SCHED_CLASS_EXT=y`, clang 17+, Rust 1.91+, bpftool
for the first build on a kernel.

## License

GPL-2.0-only. The scheduler core descends from PANDEMONIUM by the same
author.

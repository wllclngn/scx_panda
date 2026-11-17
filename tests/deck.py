#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Will Clingan
"""
deck: the Steam Deck driver for scx_panda.

Switches a Steam Deck between schedulers over SSH in timed segments while the
player plays the game Steam is running: stock (steamosctl's none, the
kernel's EEVDF with Valve's tunings), Valve's scx_lavd (steamosctl's lavd) and
scx_panda (the staged /var/lib/panda/scx_panda under the Deck's narrow sudo
rule). Each segment's scheduler is read from /sys/kernel/sched_ext/root/ops at
both ends and every few seconds between, and a segment whose scheduler changed
under it is void. Rounds alternate one order and its reverse, so drift falls
on every arm alike. Blind, the default, shuffles that order and names no arm
until the run ends. Every exit, Ctrl+C included, stops any capture and puts
the Deck back on none.

--montauk records every segment with montauk's recorder line on the Deck
(/var/lib/montauk/montauk under its own sudo rule, captures under
/home/.montauk/captures). --trace-arm ARM --pattern NAMES runs one traced pass
instead: one arm for --trace-seconds under montauk's traced line, for the
player to take at the same place in the game under each arm in turn. A
segment's window opens at montauk's first scrape, a traced pass's once its
trace is attached with the DSQ probes on the newest kfuncs, and a capture that
misses either voids its segment. Each capture is copied back beside the run's
records and named in segments.tsv.

Before anything is switched it reads the Deck (SteamOS, kernel, the scheduler
setting, the staged build, the sudo rules, the running game), prints every
segment, the exact commands and the total time, and starts only on a typed
`go`.

The records are raw, under ~/.cache/panda-scratch/deck/STAMP-appAPPID/:
plan.json, preflight.txt, segments.tsv, snapshots.tsv, seg-NN/ holding the
sched_ext events at both ends, the segment's kernel log and, on scx_panda's
segments, its counter lines, and montauk/ holding each capture. sublimation
and montauk read them.

Usage:
    ./tests/deck.py [--host deck] [--arms stock,lavd,panda] [--segment 180]
                    [--rounds 1] [--settle 10] [--labeled] [--seed N]
                    [--montauk] [--dry-run]
    ./tests/deck.py --trace-arm ARM --pattern NAMES [--trace-seconds 60]
                    [--host deck] [--settle 10] [--dry-run]
"""

import argparse
import json
import math
import random
import re
import signal
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

PANDA = "/var/lib/panda/scx_panda"
UNIT = "panda-deck"
# THE NAME EACH ARM'S SCHEDULER REGISTERS IN root/ops; STOCK REGISTERS NONE.
# scx's loader may append its version and target: Valve's 1.1.3 registers
# lavd_1.1.3_x86_64_unknown_linux_gnu.
OPS = {"stock": "", "lavd": "lavd", "panda": "scx_panda"}
COMMANDS = {
    "none": "steamosctl set-cpu-scheduler none",
    "lavd": "steamosctl set-cpu-scheduler lavd",
    "panda": f"sudo -n /usr/bin/systemd-run --unit={UNIT} {PANDA} --verbose",
    "stop": f"sudo -n /usr/bin/systemctl stop {UNIT}",
    "reset": f"sudo -n /usr/bin/systemctl reset-failed {UNIT}",
}
# montauk's two Deck lines, word for word as its sudo rule admits them. RUN
# and PATTERN are held to the rule's own forms before either is sent.
MONTAUK = "/var/lib/montauk/montauk"
CAPTURES = "/home/.montauk/captures"
STDOUT_DIR = "/home/deck/montauk"
RECORD = "--headless --log {cap}/{run} --log-interval-ms 250 --thermal-interval-ms 250 --pmu-system"
TRACE = ("--trace {pattern} --log {cap}/{run} --log-interval-ms 100 --trace-ring-bytes 256M --bpf-stats "
         "--trace-out {cap}/{run}.events --sched-detail --trace-classes sched,fork,exec,exit,comm")
RUN_FORM = re.compile(r"[a-z0-9]+(-[a-z0-9]+)*")
PATTERN_FORM = re.compile(r"[a-z0-9._-]{1,15}(,[a-z0-9._-]{1,15}){0,3}")
# A SEGMENT'S WINDOW OPENS AT montauk's FIRST SCRAPE, WHERE ITS BATTERY ENERGY
# STARTS COUNTING; A TRACED PASS'S 60 s OPENS ONCE ITS TRACE IS ATTACHED, WITH
# THE DSQ PROBES ON THE NEWEST KFUNCS THE KERNEL HAS.
FIRST_SCRAPE_S = 10.0
ATTACH_S = 30.0
ATTACHED = "eBPF trace attached"
DSQ_MARK = "scx dsq attribution probes attached"
DSQ_LINE = (f"{DSQ_MARK} (6 of 6), drain on scx_bpf_dsq_move_to_local___v2, insert on "
            "scx_bpf_dsq_insert___v2, vtime insert on scx_bpf_dsq_insert_vtime and __scx_bpf_dsq_insert_vtime")
OUT_ROOT = Path.home() / ".cache" / "panda-scratch" / "deck"
SWITCH_TIMEOUT = 20.0
POLL = 5.0
LOST_AFTER = 30.0
# ONE SSH CONNECTION SERVES THE WHOLE RUN; EACH CALL RIDES IT.
CONTROL = "/tmp/panda-deck-ssh-%C"
# STEAM STARTS EVERY GAME UNDER ITS REAPER WITH THE GAME'S APPID ON THE LINE.
STEAM_GAME = re.compile(r"SteamLaunch AppId=(\d+)")

STATE = r"""
s=/sys/kernel/sched_ext
printf 'epoch=%s\n' "$(date +%s.%N)"
printf 'state=%s\n' "$(<$s/state)"
if [ -r $s/root/ops ]; then printf 'ops=%s\n' "$(<$s/root/ops)"; else printf 'ops=\n'; fi
"""

SNAPSHOT = STATE + r"""
p=/sys/class/power_supply
printf 'acad=%s\n' "$(<$p/ACAD/online)"
for k in status capacity current_now voltage_now charge_now; do
    printf 'bat_%s=%s\n' $k "$(<$p/BAT1/$k)"
done
for h in /sys/class/hwmon/hwmon*; do
    n=$(<$h/name)
    case $n in k10temp|amdgpu) printf 'temp_%s=%s\n' $n "$(<$h/temp1_input)";; esac
done
printf 'epp=%s\n' "$(</sys/devices/system/cpu/cpu0/cpufreq/energy_performance_preference)"
printf -- '--raw--\n'
if [ -r $s/root/events ]; then printf '%s\n' "$(<$s/root/events)"; fi
"""

PREFLIGHT = STATE + r"""
one() { local v; v=$("$@" 2>&1); printf '%s\n' "${v//$'\n'/ }"; }
. /etc/os-release
printf 'steamos=%s\nbuild=%s\n' "$VERSION_ID" "$BUILD_ID"
printf 'kernel=%s\n' "$(uname -r)"
printf 'model=%s\n' "$(</sys/class/dmi/id/product_name)"
printf 'scheduler=%s\n' "$(one steamosctl get-cpu-scheduler)"
printf 'tdp=%s\n' "$(one steamosctl get-tdp-limit)"
printf 'gpu_level=%s\n' "$(one steamosctl get-gpu-performance-level)"
printf 'governor=%s\n' "$(</sys/devices/system/cpu/cpu0/cpufreq/scaling_governor)"
printf 'panda=%s\n' "$(one @PANDA@ --version)"
printf 'sudo=%s\n' "$(one sudo -n /usr/bin/systemctl reset-failed @UNIT@)"
printf 'unit=%s\n' "$(one systemctl is-active @UNIT@)"
printf 'acad=%s\n' "$(</sys/class/power_supply/ACAD/online)"
printf -- '--raw--\n'
ps -eo comm=,args=
""".replace("@PANDA@", PANDA).replace("@UNIT@", UNIT)

SEGMENT_COLUMNS = ("seg", "round", "arm", "kind", "run", "start", "end", "ops_start", "ops_end",
                   "valid", "note")
SNAPSHOT_COLUMNS = ("seg", "phase", "epoch", "state", "ops", "acad", "bat_status", "bat_capacity",
                    "bat_current_now", "bat_voltage_now", "bat_charge_now",
                    "temp_k10temp", "temp_amdgpu", "epp")


class DeckLost(Exception):
    pass


class CaptureFailed(Exception):
    pass


def log(level: str, msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] [{level}]{' ' * (8 - len(level))}{msg}", flush=True)


def ssh(host: str, script: str, timeout: float = 30.0) -> subprocess.CompletedProcess:
    cmd = ["ssh", "-o", "BatchMode=yes", "-o", "ConnectTimeout=8",
           "-o", "ServerAliveInterval=5", "-o", "ServerAliveCountMax=3",
           "-o", "ControlMaster=auto", "-o", f"ControlPath={CONTROL}",
           "-o", "ControlPersist=120", host, "bash", "-s"]
    return subprocess.run(cmd, input=script, capture_output=True, text=True, timeout=timeout)


def remote(host: str, command: str) -> str:
    r = ssh(host, command + "\n")
    return (r.stdout + r.stderr).strip()


def keyvals(text: str) -> tuple[dict[str, str], str]:
    head, _, raw = text.partition("--raw--\n")
    kv = {}
    for line in head.splitlines():
        k, sep, v = line.partition("=")
        if sep:
            kv[k] = v
    return kv, raw


def state(host: str) -> dict[str, str]:
    return keyvals(ssh(host, STATE).stdout)[0]


def is_arm(arm: str, st: dict[str, str]) -> bool:
    ops, want = st.get("ops", ""), OPS[arm]
    if not want:
        return st.get("state") == "disabled" and not ops
    return st.get("state") == "enabled" and (ops == want or ops.startswith(want + "_"))


def wait_state(host: str, arm: str) -> dict[str, str] | None:
    deadline = time.monotonic() + SWITCH_TIMEOUT
    while time.monotonic() < deadline:
        st = state(host)
        if is_arm(arm, st):
            return st
        time.sleep(0.5)
    return None


def to_stock(host: str) -> dict[str, str] | None:
    if remote(host, f"systemctl is-active {UNIT}") in ("active", "activating", "reloading"):
        remote(host, COMMANDS["stop"])
    if remote(host, f"systemctl is-failed {UNIT}") == "failed":
        remote(host, COMMANDS["reset"])
    remote(host, COMMANDS["none"])
    return wait_state(host, "stock")


def switch(host: str, arm: str) -> dict[str, str] | None:
    st = to_stock(host)
    if st is None or arm == "stock":
        return st
    remote(host, COMMANDS[arm])
    return wait_state(host, arm)


class Capture:
    """One montauk capture on the Deck: started detached under its sudo rule
    with its drain thread pinned to CPU 7, stopped by SIGINT (which sudo relays
    and on which montauk writes its last scrape) and then SIGTERM, never
    SIGKILL, which would reach sudo and leave montauk running."""

    def __init__(self, host: str, run: str, pattern: str = ""):
        if not RUN_FORM.fullmatch(run) or len(run) > 64:
            raise CaptureFailed(f"run name {run!r} is outside montauk's form")
        self.host, self.run, self.traced, self.pid = host, run, bool(pattern), ""
        if pattern:
            self.args, self.env = TRACE.format(cap=CAPTURES, run=run, pattern=pattern), "MONTAUK_SCX_DSQ=1 "
        else:
            self.args, self.env = RECORD.format(cap=CAPTURES, run=run), ""

    def command(self) -> str:
        return f"{self.env}taskset -c 7 sudo -n {MONTAUK} {self.args}"

    def start(self) -> None:
        # ONLY THE LAST COMMAND GOES TO THE BACKGROUND: A BACKGROUNDED && LIST IS
        # A SUBSHELL THAT HOLDS THE SSH SESSION OPEN, AND $! WOULD NAME IT.
        try:
            pid = remote(self.host, f"mkdir -p {STDOUT_DIR}\ncd /\n{self.env}setsid taskset -c 7 "
                                    f"sudo -n {MONTAUK} {self.args} > {STDOUT_DIR}/{self.run}.stdout 2>&1 "
                                    f"< /dev/null &\necho $!")
        except subprocess.TimeoutExpired:
            pid = "the launch did not return"
        if not pid.isdigit():
            raise CaptureFailed(f"montauk {self.run} did not start: {pid}")
        self.pid = pid
        time.sleep(2)
        if remote(self.host, f"kill -0 {pid} 2>/dev/null && echo alive") != "alive":
            self.pid = ""
            raise CaptureFailed(f"montauk {self.run} exited at its start: {self.said()[-400:]}")
        scrape = f'for f in {CAPTURES}/{self.run}/montauk_*.prom; do [ -e "$f" ] && echo yes; break; done'
        deadline = time.monotonic() + FIRST_SCRAPE_S
        while remote(self.host, scrape) != "yes":
            if time.monotonic() > deadline:
                raise CaptureFailed(f"montauk {self.run} wrote no scrape within {FIRST_SCRAPE_S:.0f} s")
            time.sleep(0.5)
        if not self.traced:
            return
        deadline = time.monotonic() + ATTACH_S
        while not (ATTACHED in (said := self.said()) and DSQ_MARK in said):
            if time.monotonic() > deadline:
                raise CaptureFailed(f"montauk {self.run} did not attach its trace within {ATTACH_S:.0f} s")
            time.sleep(0.5)
        dsq = next(line for line in said.splitlines() if DSQ_MARK in line).rstrip()
        if not dsq.endswith(DSQ_LINE):
            raise CaptureFailed(f"montauk {self.run}'s DSQ probes read: {dsq[dsq.index(DSQ_MARK):]}")

    def said(self) -> str:
        return remote(self.host, f"printf '%s\\n' \"$(<{STDOUT_DIR}/{self.run}.stdout)\"")

    def stop(self) -> bool:
        # A CAPTURE WHOSE PID WAS NEVER READ IS FOUND BY ITS RUN NAME, UNIQUE TO
        # IT: sudo's OWN PROCESS, WHICH THE DECK USER MAY SIGNAL AND WHICH
        # RELAYS THE SIGNAL TO montauk.
        pid = self.pid or remote(self.host, f"pgrep -f -x 'sudo -n {MONTAUK} .*/{self.run}( .*)?'"
                                            f" | {{ read -r p; echo \"$p\"; }}")
        self.pid = ""
        if not pid.isdigit():
            return True
        script = (f"kill -INT {pid} 2>/dev/null\n"
                  f"for i in $(seq 150); do kill -0 {pid} 2>/dev/null || exit 0; sleep 0.2; done\n"
                  f"kill -TERM {pid} 2>/dev/null\n"
                  f"for i in $(seq 50); do kill -0 {pid} 2>/dev/null || exit 2; sleep 0.2; done\n"
                  f"exit 1\n")
        return ssh(self.host, script, timeout=60).returncode == 0

    def fetch(self, out: Path) -> None:
        dest = out / "montauk"
        dest.mkdir(exist_ok=True)
        srcs = [f"{self.host}:{CAPTURES}/{self.run}", f"{self.host}:{STDOUT_DIR}/{self.run}.stdout"]
        if self.traced:
            srcs.append(f"{self.host}:{CAPTURES}/{self.run}.events")
        r = subprocess.run(["scp", "-q", "-r", "-o", "BatchMode=yes", "-o", f"ControlPath={CONTROL}",
                            *srcs, str(dest)], capture_output=True, text=True, timeout=900)
        if r.returncode != 0:
            log("WARN", f"  copying {self.run} back: {r.stderr.strip()}")


ACTIVE: list[Capture] = []


def montauk_ready(host: str) -> list[str]:
    """What stands between the Deck and a capture, read without running one:
    The binary, and montauk's NOPASSWD rule in sudo's listing. The listing
    cannot say the rule admits a line without a password, since the deck
    user's wheel rule admits every line with one; a capture's start says
    that, and voids its segment when sudo asks for a password."""
    out = remote(host, f"test -x {MONTAUK} || echo missing\nsudo -n -l 2>&1")
    problems = []
    if "missing" in out:
        problems.append(f"{MONTAUK} is not installed")
    if f"NOPASSWD: {MONTAUK} ^" not in out:
        problems.append("montauk's sudo rule is not installed")
    return problems


def build_plan(arms: list[str], rounds: int, blind: bool, rng: random.Random) -> list[tuple[int, int, str]]:
    order = arms[:]
    if blind:
        rng.shuffle(order)
    segs = []
    for r in range(rounds):
        for arm in (order if r % 2 == 0 else order[::-1]):
            segs.append((len(segs) + 1, r + 1, arm))
    return segs


def print_plan(args, segs: list[tuple[int, int, str]], seconds: int, show_arms: bool,
               probe: Capture | None) -> None:
    total_min = math.ceil(len(segs) * (args.settle + seconds + 5) / 60)
    if args.trace_arm:
        log("INFO", f"PLAN: one traced pass under {args.trace_arm}, {seconds} s after {args.settle} s "
                    f"settling, montauk tracing {args.pattern}, about {total_min} min")
    else:
        log("INFO", f"PLAN: {len(segs)} segments of {seconds} s after {args.settle} s settling, "
                    f"{args.rounds} round{'' if args.rounds == 1 else 's'}, about {total_min} min in all"
                    + ("" if show_arms else ", blind: arms named at the end"))
        for idx, rnd, arm in segs:
            log("INFO", f"  segment {idx:>2}  round {rnd}" + (f"  {arm}" if show_arms else ""))
    log("INFO", f"COMMANDS on {args.host}, each arm switched from none:")
    for name in ("stop", "reset", "none", "lavd", "panda"):
        log("INFO", f"  {name:<7} {COMMANDS[name]}")
    if probe:
        log("INFO", f"  montauk {probe.command()}, RUN named per segment, stopped by SIGINT")


def preflight(args, probe: Capture | None) -> tuple[str, str] | None:
    """The Deck's state as read, and the running game's AppId, or None when
    the Deck cannot be measured as it stands."""
    try:
        r = ssh(args.host, PREFLIGHT)
    except subprocess.TimeoutExpired:
        log("ERROR", f"{args.host} did not answer")
        return None
    if not r.stdout:
        log("ERROR", f"{args.host} did not answer: {r.stderr.strip()}")
        return None
    kv, procs = keyvals(r.stdout)
    log("INFO", f"DECK: SteamOS {kv.get('steamos')} ({kv.get('build')}), {kv.get('model')}, "
                f"kernel {kv.get('kernel')}")
    log("INFO", f"  scheduler setting: {kv.get('scheduler')}; tdp: {kv.get('tdp')}; "
                f"gpu: {kv.get('gpu_level')}; governor: {kv.get('governor')}")
    games = sorted({m.group(1) for m in STEAM_GAME.finditer(procs)})
    problems = []
    if kv.get("state") != "disabled":
        problems.append(f"a sched_ext scheduler is attached ({kv.get('ops') or kv.get('state')})")
    if not kv.get("scheduler", "").endswith("none"):
        problems.append(f"SteamOS's scheduler setting is not none ({kv.get('scheduler')})")
    if "panda" in args.arms:
        log("INFO", f"  staged: {kv.get('panda')}")
        if "scx_panda" not in kv.get("panda", ""):
            problems.append(f"{PANDA} does not answer --version")
        if "password is required" in kv.get("sudo", ""):
            problems.append(f"the sudo rule for {PANDA} is not in place")
        if kv.get("unit") in ("active", "activating"):
            problems.append(f"{UNIT} is already running")
    if len(games) != 1:
        problems.append("no Steam game is running" if not games
                        else f"more than one Steam game is running ({', '.join(games)})")
    if probe:
        problems += montauk_ready(args.host)
    for p in problems:
        log("ERROR", f"  {p}")
    if problems:
        return None
    log("INFO", f"  game: AppId {games[0]}")
    if kv.get("acad") == "1":
        log("WARN", "  on AC: BAT1 reads the charging current, not the Deck's draw; "
                    "energy needs the Deck unplugged")
    return r.stdout, games[0]


def write_tsv_row(path: Path, columns: tuple[str, ...], row: dict) -> None:
    new = not path.exists()
    with path.open("a") as f:
        if new:
            f.write("\t".join(columns) + "\n")
        f.write("\t".join(str(row.get(c, "")) for c in columns) + "\n")


def snapshot(host: str, seg: int, phase: str, seg_dir: Path, out: Path) -> dict[str, str]:
    kv, events = keyvals(ssh(host, SNAPSHOT).stdout)
    (seg_dir / f"events-{phase}.txt").write_text(events)
    write_tsv_row(out / "snapshots.tsv", SNAPSHOT_COLUMNS, {"seg": seg, "phase": phase, **kv})
    return kv


def journal(host: str, selector: str, since: float, until: float) -> str:
    r = ssh(host, f"journalctl {selector} --since @{math.floor(since)} --until @{math.ceil(until)} "
                  f"-o short-precise --no-pager\n", timeout=60)
    return r.stdout


def run_segment(args, seg: tuple[int, int, str], total: int, out: Path, seconds: int,
                capture: Capture | None) -> bool:
    idx, rnd, arm = seg
    kind = "trace" if args.trace_arm else "scored"
    name = f"segment {idx}/{total}" + (f" ({arm})" if args.labeled or args.trace_arm else "")
    seg_dir = out / f"seg-{idx:02d}"
    seg_dir.mkdir()
    row = {"seg": idx, "round": rnd, "arm": arm, "kind": kind, "run": capture.run if capture else "",
           "valid": 0}
    log("INFO", f"{name}: switching")
    if switch(args.host, arm) is None:
        st = state(args.host)
        row["note"] = f"switch failed: root/ops read {st.get('ops') or st.get('state')!r}"
        log("WARN", f"{name}: the switch failed; skipped")
        write_tsv_row(out / "segments.tsv", SEGMENT_COLUMNS, row)
        return False
    time.sleep(args.settle)
    if capture:
        try:
            capture.start()
        except CaptureFailed as e:
            capture.stop()
            capture.fetch(out)
            row["note"] = str(e)
            log("WARN", f"{name}: {e}; void")
            write_tsv_row(out / "segments.tsv", SEGMENT_COLUMNS, row)
            return False
        ACTIVE.append(capture)
    start = snapshot(args.host, idx, "start", seg_dir, out)
    log("INFO", f"{name}: running {seconds} s" + (f", montauk {capture.run}" if capture else ""))
    note, lost_since = "", None
    t0 = time.monotonic()
    end = t0 + seconds
    while (now := time.monotonic()) < end:
        time.sleep(min(POLL, end - now))
        try:
            st = state(args.host)
        except subprocess.TimeoutExpired:
            st = {}
        if not st:
            lost_since = lost_since or time.monotonic()
            if time.monotonic() - lost_since > LOST_AFTER:
                raise DeckLost(f"{args.host} stopped answering during {name}")
            continue
        lost_since = None
        if not is_arm(arm, st) and not note:
            note = f"root/ops read {st.get('ops') or st.get('state')!r} at +{time.monotonic() - t0:.0f} s"
            log("WARN", f"{name}: the scheduler changed under it; void")
    stop = snapshot(args.host, idx, "end", seg_dir, out)
    if capture:
        ACTIVE.remove(capture)
        if not capture.stop() and not note:
            note = f"montauk {capture.run} did not stop on SIGINT"
            log("WARN", f"{name}: {note}")
        log("INFO", f"{name}: copying {capture.run} back")
        capture.fetch(out)
    since, until = float(start.get("epoch", 0)), float(stop.get("epoch", 0))
    (seg_dir / "kernel.log").write_text(journal(args.host, "-k", since, until))
    if arm == "panda":
        (seg_dir / "panda.log").write_text(journal(args.host, f"-u {UNIT}", since, until))
    valid = not note and is_arm(arm, start) and is_arm(arm, stop)
    row.update({"start": start.get("epoch"), "end": stop.get("epoch"), "ops_start": start.get("ops"),
                "ops_end": stop.get("ops"), "valid": int(valid), "note": note})
    write_tsv_row(out / "segments.tsv", SEGMENT_COLUMNS, row)
    log("INFO", f"{name}: done" + ("" if valid else " (void)"))
    return valid


def interrupt(signum, frame):
    raise KeyboardInterrupt


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--host", default="deck", help="ssh host of the Deck (default deck)")
    ap.add_argument("--arms", default="stock,lavd,panda", help="comma-separated: stock, lavd, panda")
    ap.add_argument("--segment", type=int, default=180, help="seconds a segment runs (default 180)")
    ap.add_argument("--rounds", type=int, default=1, help="rounds of every arm (default 1)")
    ap.add_argument("--settle", type=int, default=10, help="seconds after a switch before a segment (default 10)")
    ap.add_argument("--labeled", action="store_true", help="name each segment's arm as it runs")
    ap.add_argument("--seed", type=int, help="the blind order's seed (default from the clock)")
    ap.add_argument("--montauk", action="store_true", help="record every segment with montauk's recorder")
    ap.add_argument("--trace-arm", choices=list(OPS), help="one traced pass under this arm instead")
    ap.add_argument("--pattern", help="the traced pass's process names, as montauk --trace takes them")
    ap.add_argument("--trace-seconds", type=int, default=60, help="the traced pass's length (default 60)")
    ap.add_argument("--dry-run", action="store_true", help="print the plan and touch nothing")
    args = ap.parse_args()

    args.arms = [a.strip() for a in args.arms.split(",") if a.strip()]
    bad = [a for a in args.arms if a not in OPS]
    if bad or not args.arms or len(set(args.arms)) != len(args.arms):
        log("ERROR", f"--arms takes each of {', '.join(OPS)} once ({', '.join(args.arms)})")
        return 2
    if args.segment < 10 or args.rounds < 1 or args.settle < 0 or args.trace_seconds < 10:
        log("ERROR", "--segment and --trace-seconds are at least 10, --rounds at least 1 "
                     "and --settle not negative")
        return 2
    if args.trace_arm:
        if not args.pattern or not PATTERN_FORM.fullmatch(args.pattern):
            log("ERROR", "--trace-arm needs --pattern: one to four names of [a-z0-9._-], "
                         "at most 15 characters each, comma-separated")
            return 2
        args.arms = [args.trace_arm]
    elif args.pattern:
        log("ERROR", "--pattern belongs to --trace-arm")
        return 2

    stamp = f"{datetime.now():%Y%m%d-%H%M%S}"
    seed = args.seed if args.seed is not None else time.time_ns() % 1_000_000
    if args.trace_arm:
        segs, seconds = [(1, 1, args.trace_arm)], args.trace_seconds
    else:
        segs, seconds = build_plan(args.arms, args.rounds, not args.labeled, random.Random(seed)), args.segment

    def capture_for(idx: int, arm: str) -> Capture | None:
        if args.trace_arm:
            return Capture(args.host, f"deck-{stamp}-trace-{arm}", args.pattern)
        return Capture(args.host, f"deck-{stamp}-s{idx:02d}") if args.montauk else None

    probe = capture_for(1, segs[0][2])
    if args.dry_run:
        print_plan(args, segs, seconds, True, probe)
        return 0
    pre = preflight(args, probe)
    if pre is None:
        return 2
    print_plan(args, segs, seconds, args.labeled or bool(args.trace_arm), probe)
    try:
        answer = input("type go to start: ").strip()
    except (EOFError, KeyboardInterrupt):
        answer = ""
    if answer != "go":
        log("INFO", "not started")
        return 0

    raw, appid = pre
    out = OUT_ROOT / (f"{stamp}-app{appid}" + (f"-trace-{args.trace_arm}" if args.trace_arm else ""))
    out.mkdir(parents=True)
    (out / "preflight.txt").write_text(raw)
    (out / "plan.json").write_text(json.dumps({
        "host": args.host, "appid": appid, "kind": "trace" if args.trace_arm else "scored",
        "arms": args.arms, "seconds": seconds, "settle_s": args.settle, "rounds": args.rounds,
        "blind": not (args.labeled or args.trace_arm), "seed": seed, "pattern": args.pattern,
        "montauk": probe.command() if probe else None, "panda": PANDA, "commands": COMMANDS,
        "segments": [{"seg": i, "round": r, "arm": a} for i, r, a in segs],
    }, indent=2) + "\n")
    log("INFO", f"RECORDS: {out}")

    signal.signal(signal.SIGTERM, interrupt)
    signal.signal(signal.SIGHUP, interrupt)
    results, rc = [], 0
    try:
        for seg in segs:
            results.append((seg, run_segment(args, seg, len(segs), out, seconds,
                                             capture_for(seg[0], seg[2]))))
    except KeyboardInterrupt:
        log("WARN", "interrupted")
        rc = 130
    except (DeckLost, CaptureFailed) as e:
        log("ERROR", str(e))
        rc = 1
    except subprocess.TimeoutExpired:
        log("ERROR", f"{args.host} stopped answering")
        rc = 1
    finally:
        for capture in ACTIVE:
            log("INFO", f"stopping montauk {capture.run}")
            try:
                if capture.stop():
                    capture.fetch(out)
                else:
                    log("ERROR", f"montauk {capture.run} did not stop; on the Deck it runs as sudo's child")
            except subprocess.TimeoutExpired:
                log("ERROR", f"montauk {capture.run} was not confirmed stopped")
        log("INFO", "restoring none")
        try:
            restored = to_stock(args.host)
        except subprocess.TimeoutExpired:
            restored = None
        if restored is None:
            log("ERROR", f"the Deck was not confirmed on none; on it run: {COMMANDS['stop']}; {COMMANDS['none']}")
            rc = rc or 1
        else:
            log("INFO", "the Deck is on none, sched_ext disabled")
    for (idx, rnd, arm), valid in results:
        log("INFO", f"  segment {idx:>2}  round {rnd}  {arm:<6}" + ("" if valid else "  void"))
    if any(not v for _, v in results):
        rc = rc or 1
    log("INFO", f"RECORDS: {out}")
    return rc


if __name__ == "__main__":
    sys.exit(main())

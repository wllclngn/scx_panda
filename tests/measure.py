#!/usr/bin/env python3
# SPDX-License-Identifier: GPL-2.0-only
# Copyright (c) 2026 Will Clingan
"""
measure: the bench driver for this tree's scx_panda.

Builds and installs the tree's program once, runs PANDEMONIUM's prism benches on
it alone (scale and frame by default), folds the seat-price counters it wrote
under /tmp/panda and prints every report's tables side by side. --control adds
PANDEMONIUM's own two arms from the same evening.

Usage:
    ./tests/measure.py [--benches scale,frame] [--cores 8,12] [--iterations 1]
                       [--scale-iterations 1] [--control] [--dry-run]
    ./tests/measure.py --read REPORT [REPORT ...]

--cores applies to scale; frame runs at native width. Runs as the user.
panda.py and prism ask for sudo where a step needs it.
"""

import argparse
import os
import re
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

PANDA_DIR = Path(__file__).resolve().parent.parent
PANDEMONIUM_DIR = Path(os.environ.get("PANDEMONIUM_DIR", PANDA_DIR.parent / "PANDEMONIUM"))
# UNDER sudo THE HARNESS WRITES ITS REPORTS TO THE INVOKING USER'S CACHE.
_HOME = Path(os.path.expanduser(f"~{os.environ['SUDO_USER']}")) if os.environ.get("SUDO_USER") else Path.home()
REPORT_DIR = _HOME / ".cache" / "pandemonium"
SUMMARY_DIR = Path("/tmp/panda")
BENCHES = ("scale", "frame")

SCALE_METRICS = [
    ("compile_s", "compile s"),
    ("lat_p99", "latency p99 us"),
    ("burst_p99", "burst p99 us"),
    ("longrun_p99", "long-run p99 us"),
    ("mixed_p99", "mixed p99 us"),
    ("deadline_miss_pct", "deadline misses %"),
    ("jitter_p99", "deadline jitter p99 us"),
    ("ipc_pipe_p99", "ipc pipe p99 us"),
    ("ipc_eventfd_p99", "ipc eventfd p99 us"),
    ("ipc_sem_p99", "ipc sem p99 us"),
    ("ipc_fanout_p99", "ipc fanout p99 us"),
    ("launch_p99", "launch p99 us"),
]

FRAME_METRICS = [
    ("AVG FPS", "avg fps"),
    ("1% LOW FPS (p99)", "1% low fps"),
    ("1% LOW FPS (avg)", "1% low fps (avg)"),
    ("0.1% LOW FPS (p99.9)", "0.1% low fps"),
    ("FRAME TIME p99 ms", "frame time p99 ms"),
    ("FRAME TIME MAX ms", "frame time max ms"),
    ("STUTTERS PER 1K FRAMES", "stutters per 1k"),
    ("LATE FRAMES %", "late frames %"),
    ("JOB WAKE p50 us", "job wake p50 us"),
    ("JOB WAKE p99 us", "job wake p99 us"),
    ("JOB WAKE p99.9 us", "job wake p99.9 us"),
    ("AUDIO LATE p99 us", "audio late p99 us"),
]


def log(level: str, msg: str) -> None:
    print(f"[{datetime.now():%H:%M:%S}] [{level}]{' ' * (8 - len(level))}{msg}", flush=True)


def num(tok: str) -> float | None:
    t = tok.rstrip("%").removesuffix("us").removesuffix("ms").removesuffix("s")
    try:
        return float(t)
    except ValueError:
        return None


def short(sched: str) -> str:
    return (sched.replace("PANDEMONIUM (BPF)", "PANDEMONIUM-BPF")
                 .replace("PANDEMONIUM (ADAPTIVE)", "PANDEMONIUM-ADAPTIVE"))


# SCALE REPORTS

def split_row(line: str) -> tuple[str, list[str]]:
    """A report row is a scheduler name, then tokens. The name is every leading
    token that is not a number, a status or a primitive."""
    toks = line.split()
    name = []
    while toks and num(toks[0]) is None and toks[0] not in ("OK", "CRASHED", "FAILED") \
            and toks[0] not in ("pipe", "socket", "eventfd", "sem", "fanout", "hop", "pair"):
        name.append(toks.pop(0))
    return " ".join(name), toks


def parse_scale(path: Path) -> dict:
    """{width: {scheduler: {metric: value}}} from one prism-scale report."""
    out: dict = {}
    width = None
    table = None
    lat_seen = 0
    current = None
    for raw in path.read_text().splitlines():
        line = raw.rstrip()
        m = re.match(r"\[(\d+) CORES\]", line)
        if m:
            width = int(m.group(1))
            out.setdefault(width, {})
            lat_seen = 0
            table = None
            continue
        if width is None:
            continue
        if not line.strip():
            table = None
            continue
        if line.startswith("SCHEDULER"):
            h = line
            if "STDEV" in h:
                table = "compile"
            elif "SAMPLES     MEDIAN" in h:
                table = "latency"
            elif "BURST P99" in h:
                table = "burst"
            elif "LAT P99" in h and "WORK TOT" in h:
                lat_seen += 1
                table = "longrun" if lat_seen == 1 else "mixed"
            elif "MISSES" in h:
                table = "deadline"
            elif "PRIM" in h:
                table = "ipc"
            elif "COUNT" in h and "MEAN" in h:
                table = "launch"
            else:
                table = None
            continue
        if table is None:
            continue
        # THE IPC BLOCK CARRIES DIAGNOSTIC LINES UNDER EACH SCHEDULER (hop,
        # pair, sem waits, run slice); NONE IS A ROW.
        first = line.split()[:2]
        if table == "ipc" and (first[0] in ("hop", "pair", "run") or "waits" in first):
            continue
        name, toks = split_row(line)
        if name:
            current = name
        sched = current
        if not sched or not toks:
            continue
        row = out[width].setdefault(sched, {})
        try:
            if table == "compile":
                row["compile_s"] = num(toks[0])
            elif table == "latency":
                row["lat_p99"] = num(toks[-2])
            elif table == "burst":
                row["burst_p99"] = num(toks[-4])
            elif table in ("longrun", "mixed"):
                row[f"{table}_p99"] = num(toks[-5])
            elif table == "deadline":
                row["deadline_miss_pct"] = num(toks[-3])
                row["jitter_p99"] = num(toks[-2])
            elif table == "launch":
                row["launch_p99"] = num(toks[-2])
            elif table == "ipc":
                for prim in ("pipe", "socket", "eventfd", "sem", "fanout"):
                    if prim in toks:
                        i = toks.index(prim)
                        if i + 2 < len(toks) and toks[i + 1].endswith("us") \
                                and toks[i + 2].endswith("us"):
                            row[f"ipc_{prim}_p99"] = num(toks[i + 2])
        except (IndexError, TypeError):
            continue
    return out


# FRAME REPORTS

def parse_frame(path: Path) -> dict:
    """{scenario: {scheduler: {metric: mean}}} from one prism-frame report. A
    row is a metric label and one "mean ±sd" cell per scheduler column."""
    out: dict = {}
    scen = None
    cols: list[str] = []
    for raw in path.read_text().splitlines():
        line = raw.rstrip()
        m = re.match(r"SCENARIO (\w+)", line)
        if m:
            scen = m.group(1).lower()
            out.setdefault(scen, {})
            cols = []
            continue
        if scen is None:
            continue
        if line.startswith("METRIC"):
            cols = [c for c in re.split(r"\s{2,}", line.strip())[1:] if c]
            continue
        if not line.strip():
            cols = []
            continue
        if line.startswith("vs EEVDF") or not cols:
            continue
        cells = re.split(r"\s{2,}", line.strip())
        label, values = cells[0], cells[1:]
        if len(values) != len(cols):
            continue
        for col, cell in zip(cols, values):
            mean = num(cell.split("±")[0].strip())
            if mean is not None:
                out[scen].setdefault(col, {})[label] = mean
    return out


# TABLES

def print_tables(kind: str, results: list[tuple[str, dict]]) -> None:
    """results: [(label, parsed)]; one table per width or scenario."""
    metrics = SCALE_METRICS if kind == "scale" else FRAME_METRICS
    keys = sorted({k for _, r in results for k in r}, key=str)
    for k in keys:
        cols = []
        for label, r in results:
            for sched, row in r.get(k, {}).items():
                cols.append((f"{label}:{short(sched)}" if label else short(sched), row))
        if not cols:
            continue
        head = f"[{k} CORES]" if kind == "scale" else f"[{str(k).upper()}]"
        print(f"\n{head}")
        print(f"{'metric':<24}" + "".join(f"{c[0][-34:]:>36}" for c in cols))
        for key, title in metrics:
            vals = [c[1].get(key) for c in cols]
            if all(v is None for v in vals):
                continue
            print(f"{title:<24}" + "".join(f"{'' if v is None else f'{v:g}':>36}" for v in vals))


def read_summaries(since: float) -> tuple[int, int, int]:
    """(files, expect_used, expect_overrun) over the summaries written since."""
    files = used = over = 0
    for p in SUMMARY_DIR.glob("summary-*.txt"):
        try:
            if p.stat().st_mtime < since:
                continue
            text = p.read_text()
        except OSError:
            continue
        files += 1
        m = re.search(r"expect_used=(\d+) expect_overrun=(\d+)", text)
        if m:
            used += int(m.group(1))
            over += int(m.group(2))
    return files, used, over


def newest_report(bench_name: str, since: float) -> Path | None:
    cands = [p for p in REPORT_DIR.glob(f"prism-{bench_name}-*.log")
             if p.stat().st_mtime >= since]
    return max(cands, key=lambda p: p.stat().st_mtime) if cands else None


def run(cmd: list[str], cwd: Path, dry: bool) -> int:
    log("INFO", f"$ {' '.join(cmd)}  (cwd {cwd})")
    if dry:
        return 0
    return subprocess.run(cmd, cwd=cwd).returncode


def install(dry: bool) -> bool:
    return run([sys.executable, "panda.py", "install"], PANDA_DIR, dry) == 0


def bench(name: str, extra: list[str], cores: str, iterations: int, dry: bool) -> Path | None:
    t0 = time.time()
    cmd = [sys.executable, "pandemonium.py", "prism", "--dev", name,
           "--iterations", str(iterations)]
    if name == "scale":
        cmd += ["--cores", cores]
    cmd += extra
    rc = run(cmd, PANDEMONIUM_DIR, dry)
    if dry:
        return None
    if rc != 0:
        log("WARN", f"prism {name} exited {rc}")
    return newest_report(name, t0)


def parse(name: str, path: Path) -> dict:
    return parse_scale(path) if name == "scale" else parse_frame(path)


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__.strip().splitlines()[0])
    ap.add_argument("--benches", default=",".join(BENCHES),
                    help="comma-separated: scale, frame (default both)")
    ap.add_argument("--cores", default="8,12", help="scale widths (default 8,12)")
    ap.add_argument("--iterations", type=int, default=1, help="frame iterations (default 1)")
    ap.add_argument("--scale-iterations", type=int, default=1,
                    help="scale iterations; scale is the saturation guard (default 1)")
    ap.add_argument("--control", action="store_true",
                    help="also run PANDEMONIUM's two arms (prism --pandemonium-only)")
    ap.add_argument("--dry-run", action="store_true", help="print the commands only")
    ap.add_argument("--read", nargs="+", metavar="REPORT",
                    help="print the tables of existing prism-scale or prism-frame reports and exit")
    args = ap.parse_args()

    if args.read:
        for kind in BENCHES:
            picked = [(Path(p).stem.removeprefix(f"prism-{kind}-")[4:], parse(kind, Path(p)))
                      for p in args.read if Path(p).name.startswith(f"prism-{kind}-")]
            if picked:
                print_tables(kind, picked)
        return 0

    benches = [b.strip() for b in args.benches.split(",") if b.strip()]
    unknown = [b for b in benches if b not in BENCHES]
    if unknown:
        log("ERROR", f"unknown: {', '.join(unknown)}; benches are {', '.join(BENCHES)}")
        return 2
    if not (PANDEMONIUM_DIR / "pandemonium.py").exists():
        log("ERROR", f"PANDEMONIUM not found at {PANDEMONIUM_DIR} (set PANDEMONIUM_DIR)")
        return 2

    results: dict[str, list[tuple[str, dict]]] = {b: [] for b in benches}
    reports: list[tuple[str, Path]] = []
    log("INFO", "scx_panda: install")
    if not install(args.dry_run):
        log("ERROR", "scx_panda: install failed")
        return 1
    since = time.time()
    for b in benches:
        iters = args.scale_iterations if b == "scale" else args.iterations
        log("INFO", f"scx_panda: prism {b}, {iters} iteration(s)"
                    + (f" at {args.cores} CPUs" if b == "scale" else ""))
        rep = bench(b, ["--only", "scx_panda"], args.cores, iters, args.dry_run)
        if rep is None:
            if not args.dry_run:
                log("WARN", f"scx_panda: no {b} report found")
            continue
        results[b].append(("", parse(b, rep)))
        reports.append((f"scx_panda {b}", rep))
    files, used, over = read_summaries(since)
    share = f"{100 * over / (used + over):.0f}%" if used + over else "n/a"
    log("INFO", f"scx_panda: {files} summaries, expect_used {used}, "
                f"expect_overrun {over} (overrun share {share})")
    if args.control:
        for b in benches:
            log("INFO", f"control: PANDEMONIUM's two arms on {b}")
            iters = args.scale_iterations if b == "scale" else args.iterations
            rep = bench(b, ["--pandemonium-only"], args.cores, iters, args.dry_run)
            if rep is not None:
                results[b].append(("", parse(b, rep)))
                reports.append((f"control {b}", rep))

    for b in benches:
        if results[b]:
            print(f"\n{b.upper()}")
            print_tables(b, results[b])
    if reports:
        print()
        for label, rep in reports:
            log("INFO", f"{label}: {rep}")
    return 0


if __name__ == "__main__":
    sys.exit(main())

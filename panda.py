#!/usr/bin/env python3
"""
scx_panda build/install manager.

Usage:
    ./panda.py build              Build the release binary
    ./panda.py check              Build, then load through the verifier without attaching
    ./panda.py install [--enable] Build, install /usr/local/bin/scx_panda, set its
                                    capabilities, write scx_panda.service; --enable
                                    also enables and starts it
    ./panda.py start | stop       Start or stop the service (start refuses while
                                    another sched_ext scheduler is loaded)
    ./panda.py enable | disable   Enable or disable the service at boot
    ./panda.py uninstall          Stop and disable the service, remove unit and binary
    ./panda.py status             Show build, install and scheduler state
    ./panda.py clean              Remove the build directory
    ./panda.py rebuild            Clean the package artifacts and build again
    ./panda.py prism ARGS...      Run PANDEMONIUM's prism with scx_panda as the
                                    arm (--only scx_panda unless ARGS name the
                                    field), e.g. prism --dev frame --iterations 5;
                                    refuses while another bench runs, and
                                    restarts the service after if it was active
    ./panda.py measure ARGS...    Run the measurement-arm A/B (tests/measure.py)
    --measure ARM                 With build, rebuild, check or install: a
                                    measurement arm of the program in place of
                                    the shipped one, for an A/B and never left
                                    installed (no-habit-price)
"""

import json
import os
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime
from pathlib import Path

SCRIPT_DIR = Path(__file__).parent.resolve()
NAME = "scx_panda"
_home = Path(os.environ.get("SUDO_USER") and f"/home/{os.environ['SUDO_USER']}"
             or Path.home())
# OUTSIDE THE SOURCE TREE: libbpf's vendored make does not survive the space in
# the source path.
TARGET_DIR = _home / ".cache" / "panda-build"
BINARY = TARGET_DIR / "release" / NAME
INSTALL_PATH = Path("/usr/local/bin") / NAME
SERVICE_PATH = Path(f"/etc/systemd/system/{NAME}.service")
OPS_PATH = Path("/sys/kernel/sched_ext/root/ops")
OPS_NAME = "scx_panda"
CAPS = "cap_sys_admin,cap_bpf,cap_perfmon,cap_sys_resource,cap_sys_nice+ep"
ARMS = ("no-habit-price",)
PANDEMONIUM_DIR = Path(os.environ.get("PANDEMONIUM_DIR", SCRIPT_DIR.parent / "PANDEMONIUM"))
MEASURE = SCRIPT_DIR / "tests" / "measure.py"
BENCH_PATTERNS = ("tests/prism", "pandemonium-tests.py", "tests/measure.py", "framebench")
# scx's CATALOG RULES FOR A CUSTOM PROFILE, AS PANDEMONIUM HOLDS ITS OWN TO.
SCX_PROFILES = SCRIPT_DIR / "catalog" / "profiles.json"
_PROFILE_KEYS = {"id", "label", "description", "sched", "args"}
_PROFILE_ID = re.compile(r"[a-z0-9][a-z0-9_-]{0,63}")
_PROFILE_ARG = re.compile(r"[A-Za-z0-9_=.,:/+-]{1,256}")
MIN_KERNEL = (6, 12)
SOURCE_PATTERNS = ("src/**/*.rs", "src/bpf/*.c", "src/bpf/*.h", "include/scx/*.h",
                   "build.rs", "Cargo.toml")


def _stamp() -> str:
    return datetime.now().strftime("[%H:%M:%S]")


def log_info(msg: str) -> None:
    print(f"{_stamp()} [INFO]   {msg}")


def log_warn(msg: str) -> None:
    print(f"{_stamp()} [WARN]   {msg}")


def log_error(msg: str) -> None:
    print(f"{_stamp()} [ERROR]  {msg}")


def run(cmd: list[str], **kw) -> int:
    return subprocess.run(cmd, **kw).returncode


def capture(cmd: list[str]) -> tuple[int, str]:
    r = subprocess.run(cmd, capture_output=True, text=True)
    return r.returncode, (r.stdout or "") + (r.stderr or "")


def version() -> str:
    for line in (SCRIPT_DIR / "Cargo.toml").read_text().splitlines():
        if line.startswith("version"):
            return line.split('"')[1]
    return "?.?.?"


def active_ops() -> str:
    try:
        return OPS_PATH.read_text().strip()
    except OSError:
        return ""


def check_kernel() -> bool:
    release = platform.release()
    try:
        major, minor = (int(x) for x in release.split(".")[:2])
    except ValueError:
        log_error(f"Cannot parse kernel release '{release}'")
        return False
    if (major, minor) < MIN_KERNEL:
        log_error(f"Kernel {release} is older than {MIN_KERNEL[0]}.{MIN_KERNEL[1]}; "
                  "sched_ext needs 6.12 or newer")
        return False
    if not Path("/sys/kernel/sched_ext").exists():
        log_error("/sys/kernel/sched_ext is absent: CONFIG_SCHED_CLASS_EXT is off")
        return False
    return True


def sources_changed() -> list[str]:
    if not BINARY.exists():
        return ["(binary not found)"]
    bin_mtime = BINARY.stat().st_mtime
    changed = []
    for pattern in SOURCE_PATTERNS:
        for src in SCRIPT_DIR.glob(pattern):
            if src.stat().st_mtime > bin_mtime:
                changed.append(str(src.relative_to(SCRIPT_DIR)))
    return changed


def root_owned_files() -> bool:
    if not TARGET_DIR.exists():
        return False
    rc, out = capture(["find", str(TARGET_DIR), "-user", "root", "-maxdepth", "4",
                       "-print", "-quit"])
    return rc == 0 and bool(out.strip())


def clean_root_files() -> bool:
    """Remove root-owned build artifacts without asking: The directory holds
    nothing but build products, and a build that needs it gone rebuilds it.
    Returns True when the build can go on."""
    log_warn(f"Root-owned build files in {TARGET_DIR}; removing the build directory")
    if run(["sudo", "rm", "-rf", str(TARGET_DIR)]) != 0 or root_owned_files():
        log_error("Could not remove the root-owned build directory")
        return False
    log_info("Build directory cleaned")
    return True


def first_build_needs_bpftool() -> bool:
    cache = _home / ".cache" / "panda" / f"vmlinux-{platform.release()}.h"
    return not cache.exists() and shutil.which("bpftool") is None


def binary_arm(path: Path = BINARY) -> str:
    """The arm a built binary names in its --version line, "" if it cannot say."""
    if not path.exists():
        return ""
    rc, out = capture([str(path), "--version"])
    if rc != 0:
        return ""
    toks = out.split()
    return toks[toks.index("arm") + 1] if "arm" in toks and toks.index("arm") + 1 < len(toks) else ""


def build(force: bool = False, measure: str = "") -> bool:
    if not check_kernel():
        return False
    if first_build_needs_bpftool():
        log_error("First build on this kernel dumps its BTF with bpftool, which is "
                  "not installed")
        return False
    if root_owned_files() and not clean_root_files():
        return False
    env = {**os.environ, "CARGO_TARGET_DIR": str(TARGET_DIR)}
    env.pop("PANDA_MEASURE", None)
    arm = measure or "shipped"
    if measure:
        env["PANDA_MEASURE"] = measure
    if force:
        log_info("Cleaning package artifacts")
        subprocess.run(["cargo", "clean", "-p", NAME], env=env, cwd=SCRIPT_DIR,
                       capture_output=True)
        for d in (TARGET_DIR / "release" / "build").glob(f"{NAME}-*"):
            shutil.rmtree(d, ignore_errors=True)
    elif not sources_changed() and binary_arm() == arm:
        log_info(f"Binary up to date ({BINARY.stat().st_size // 1024} KB, arm {arm})")
        return True
    log_info(f"Building release into {TARGET_DIR} (arm {arm})")
    if run(["cargo", "build", "--release"], env=env, cwd=SCRIPT_DIR) != 0:
        log_error("Build failed")
        return False
    built = binary_arm()
    if built != arm:
        log_error(f"Built binary names arm {built or 'none'}, wanted {arm}")
        return False
    log_info(f"Built {BINARY} ({BINARY.stat().st_size // 1024} KB, arm {arm})")
    return True


def cmd_build(measure: str = "") -> int:
    return 0 if build(measure=measure) else 1


def cmd_rebuild(measure: str = "") -> int:
    return 0 if build(force=True, measure=measure) else 1


def cmd_check(measure: str = "") -> int:
    if not build(measure=measure):
        return 1
    log_info("Loading through the verifier (no attach)")
    rc = run(["sudo", str(BINARY), "--check"])
    if rc != 0:
        log_error(f"--check failed ({rc})")
    return rc


def _unit() -> str:
    return f"""\
[Unit]
Description={NAME}, a sched_ext scheduler built from discarded ideas and unspent potential
After=multi-user.target
ConditionPathExists=/sys/kernel/sched_ext
Conflicts=pandemonium.service scx.service scx_loader.service

[Service]
Type=simple
ExecStart={INSTALL_PATH}
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
"""


def cmd_install(enable: bool = False, measure: str = "") -> int:
    if not build(force=True, measure=measure):
        return 1
    log_info(f"Installing {INSTALL_PATH} (arm {measure or 'shipped'})")
    if run(["sudo", "install", "-m", "0755", str(BINARY), str(INSTALL_PATH)]) != 0:
        log_error("Install failed (sudo required)")
        return 1
    if run(["sudo", "setcap", CAPS, str(INSTALL_PATH)]) != 0:
        log_error("setcap failed; the binary will need root to load")
        return 1
    log_info(f"Capabilities set: {CAPS}")
    proc = subprocess.run(["sudo", "tee", str(SERVICE_PATH)], input=_unit(),
                          text=True, stdout=subprocess.DEVNULL)
    if proc.returncode != 0:
        log_error("Writing the unit failed")
        return 1
    if run(["sudo", "systemctl", "daemon-reload"]) != 0:
        log_error("daemon-reload failed")
        return 1
    log_info(f"Wrote {SERVICE_PATH}")
    log_info(f"{NAME} v{version()} is installed")
    if measure:
        log_warn(f"measurement arm {measure} is installed; ./panda.py install "
                 "restores the shipped program")
    offer_scx_profile()
    if enable:
        rc = cmd_enable()
        if rc != 0:
            return rc
        return cmd_start()
    log_info(f"Start now:        sudo systemctl start {NAME}")
    log_info(f"Start on boot:    sudo systemctl enable {NAME}")
    log_info(f"Status:           systemctl status {NAME}")
    return 0


def cmd_start() -> int:
    ops = active_ops()
    if ops == OPS_NAME:
        log_info(f"{NAME} is already the active scheduler")
        return 0
    if ops:
        log_error(f"Another sched_ext scheduler is loaded: '{ops}'. Stop it first; "
                  "the kernel runs one at a time")
        return 1
    if not INSTALL_PATH.exists():
        log_error(f"{INSTALL_PATH} is not installed; run ./panda.py install")
        return 1
    if run(["sudo", "systemctl", "start", NAME]) != 0:
        log_error("systemctl start failed")
        return 1
    deadline = time.monotonic() + 10.0
    while time.monotonic() < deadline:
        if active_ops() == OPS_NAME:
            log_info(f"{NAME} is active ({OPS_PATH} reads '{OPS_NAME}')")
            return 0
        time.sleep(0.2)
    log_error(f"{NAME} did not register within 10 s; see: journalctl -u {NAME} -n 50")
    return 1


def cmd_stop() -> int:
    rc = run(["sudo", "systemctl", "stop", NAME])
    if rc == 0:
        deadline = time.monotonic() + 5.0
        while time.monotonic() < deadline and active_ops() == OPS_NAME:
            time.sleep(0.2)
        log_info(f"Active scheduler: {active_ops() or 'EEVDF'}")
    return rc


def cmd_enable() -> int:
    rc = run(["sudo", "systemctl", "enable", NAME])
    if rc == 0:
        log_info(f"{NAME} starts on boot")
    return rc


def cmd_disable() -> int:
    rc = run(["sudo", "systemctl", "disable", NAME])
    if rc == 0:
        log_info(f"{NAME} no longer starts on boot")
    return rc


def cmd_uninstall() -> int:
    subprocess.run(["sudo", "systemctl", "disable", "--now", NAME], capture_output=True)
    for p in (SERVICE_PATH, INSTALL_PATH):
        if p.exists():
            run(["sudo", "rm", "-f", str(p)])
            log_info(f"Removed {p}")
    run(["sudo", "systemctl", "daemon-reload"])
    log_info(f"{NAME} is uninstalled; active scheduler: {active_ops() or 'EEVDF'}")
    return 0


def cmd_clean() -> int:
    if not TARGET_DIR.exists():
        log_info("Already clean")
        return 0
    rc, out = capture(["du", "-sh", str(TARGET_DIR)])
    size = out.split()[0] if rc == 0 and out.split() else "?"
    if input(f"Remove {TARGET_DIR} ({size})? [y/N] ").strip().lower() not in ("y", "yes"):
        log_info("Aborted")
        return 0
    if root_owned_files():
        run(["sudo", "rm", "-rf", str(TARGET_DIR)])
    else:
        shutil.rmtree(TARGET_DIR, ignore_errors=True)
    log_info("Clean complete")
    return 0


def bench_running() -> str:
    """The command line of a bench already running, "" if none. Our own
    process and its ancestors are skipped: A shell that launched this manager
    carries the whole command text in its own arguments."""
    rc, out = capture(["ps", "-eo", "pid,ppid,args"])
    if rc != 0:
        return ""
    rows = []
    parent = {}
    for line in out.splitlines()[1:]:
        parts = line.split(None, 2)
        if len(parts) < 3:
            continue
        pid, ppid, args = int(parts[0]), int(parts[1]), parts[2]
        parent[pid] = ppid
        rows.append((pid, args))
    mine = set()
    pid = os.getpid()
    while pid in parent and pid not in mine:
        mine.add(pid)
        pid = parent[pid]
    for pid, args in rows:
        if pid in mine or "ps -eo" in args:
            continue
        if any(pat in args for pat in BENCH_PATTERNS):
            return args.strip()
    return ""


def _run_bench(cmd: list[str], cwd: Path) -> int:
    """Run a bench as the user. prism elevates itself. The service, if it was
    active, is stopped by prism's pre-flight and started again after."""
    busy = bench_running()
    if busy:
        log_error(f"a bench is already running: {busy[:100]}")
        return 2
    if not INSTALL_PATH.exists():
        log_error(f"{INSTALL_PATH} is not installed; prism starts the arm from PATH")
        return 2
    _, active = capture(["systemctl", "is-active", NAME])
    was_active = active.strip() == "active"
    log_info(f"$ {' '.join(cmd)}  (cwd {cwd})")
    rc = subprocess.run(cmd, cwd=cwd).returncode
    if was_active and not active_ops():
        log_info(f"{NAME}.service was active before the run; starting it again")
        cmd_start()
    return rc


def cmd_prism(args: list[str]) -> int:
    if not (PANDEMONIUM_DIR / "pandemonium.py").exists():
        log_error(f"PANDEMONIUM not found at {PANDEMONIUM_DIR} (set PANDEMONIUM_DIR)")
        return 2
    if not args:
        log_error("prism needs its arguments, e.g. ./panda.py prism --dev frame --iterations 5")
        return 2
    field_flags = ("--only", "--schedulers", "--all-scx", "--pandemonium-only")
    if not any(a in field_flags or a.split("=", 1)[0] in field_flags for a in args):
        args = [*args, "--only", NAME]
    return _run_bench([sys.executable, "pandemonium.py", "prism", *args], PANDEMONIUM_DIR)


def cmd_measure(args: list[str]) -> int:
    return _run_bench([sys.executable, str(MEASURE), *args], SCRIPT_DIR)


def scx_profiles() -> list[dict]:
    """The profiles in catalog/profiles.json, held to scx's rules for a custom
    profile. Raises ValueError naming the first entry that breaks one."""
    profiles = json.loads(SCX_PROFILES.read_text())
    if not isinstance(profiles, list) or not profiles:
        raise ValueError("catalog/profiles.json is not a non-empty list")
    ids = set()
    for p in profiles:
        pid = p.get("id", "")

        def bad(why: str) -> ValueError:
            return ValueError(f"catalog/profiles.json: profile '{pid}' {why}")
        if set(p) - _PROFILE_KEYS:
            raise bad(f"has unknown keys {sorted(set(p) - _PROFILE_KEYS)}")
        if (not _PROFILE_ID.fullmatch(pid) or pid == "default"
                or pid.startswith("scx_")):
            raise bad("has an id scx would read as a scheduler or an option")
        if pid in ids:
            raise bad("is listed twice")
        ids.add(pid)
        if p.get("sched") != NAME:
            raise bad(f"does not start {NAME}")
        args = p.get("args", [])
        if (not isinstance(args, list) or len(args) > 32
                or not all(isinstance(a, str) and _PROFILE_ARG.fullmatch(a)
                           for a in args)):
            raise bad("has options outside scx's allowlist")
        if not 1 <= len(p.get("label", "")) <= 64:
            raise bad("needs a label of 1 to 64 characters")
        if len(p.get("description", "")) > 256:
            raise bad("has a description over 256 characters")
    return profiles


def _scx_binary_installed() -> bool:
    """scx's own scx_panda on systemd's default search path, which is where
    scx's service finds a catalog's scheduler."""
    rc, out = capture(["systemd-path", "search-binaries-default"])
    if rc != 0:
        return False
    return any((Path(d) / NAME).exists() for d in out.strip().split(":") if d)


def offer_scx_profile() -> None:
    """scxcli and scxtui start schedulers from scx's catalog (version 2). A
    profile comes only from an administrator's /etc/scx/catalog.json, so where
    scxcli and scx's scx_panda are installed, offer catalog/profiles.json there."""
    if not shutil.which("scxcli"):
        return
    if not _scx_binary_installed():
        log_info(f"scxcli is installed but scx's {NAME} is not; no catalog profile")
        return
    try:
        profiles = scx_profiles()
    except (OSError, ValueError) as e:
        log_warn(f"no catalog profile: {e}")
        return
    r = subprocess.run(["scxcli", "catalog", "show"], capture_output=True, text=True)
    if r.returncode != 0:
        log_warn(f"scxcli catalog show failed: {r.stderr.strip()}")
        return
    try:
        catalog = json.loads(r.stdout)
    except ValueError:
        log_warn("scxcli catalog show did not print JSON; no catalog profile")
        return
    if catalog.get("version") != 2:
        log_info(f"scx's catalog is version {catalog.get('version')}, before "
                 "profiles; no catalog profile")
        return
    have = {p.get("id") for p in catalog.get("recommended", [])}
    missing = [p for p in profiles if p["id"] not in have]
    if not missing:
        log_info("scx's catalog already carries " + ", ".join(p["id"] for p in profiles))
        return
    if not sys.stdin.isatty():
        return
    print()
    for p in missing:
        log_info(f"scx's catalog can carry profile '{p['id']}' ({p['label']}: "
                 f"{p['sched']} {' '.join(p.get('args', []))}), so "
                 f"`scxcli start {p['id']}` and scxtui start it by name.")
    log_info("The catalog then lives in /etc/scx/catalog.json and stops following "
             "scx's updates to the shipped one until `sudo scxcli catalog reset`.")
    if input("Add the profile? [y/N] ").strip().lower() not in ("y", "yes"):
        return
    catalog["recommended"].extend(missing)
    r = subprocess.run(["sudo", "scxcli", "catalog", "save"],
                       input=json.dumps(catalog, indent=2) + "\n",
                       text=True, capture_output=True)
    if r.returncode != 0:
        log_error(f"scxcli catalog save failed: {r.stderr.strip()}")
        return
    for p in missing:
        log_info(f"Added profile {p['id']}: scxcli start {p['id']}")


def cmd_status() -> int:
    print()
    if BINARY.exists():
        st = BINARY.stat()
        print(f"  binary:     {BINARY}")
        print(f"              {st.st_size // 1024} KB, built "
              f"{datetime.fromtimestamp(st.st_mtime):%Y-%m-%d %H:%M:%S}")
        changed = sources_changed()
        print(f"  sources:    {'up to date' if not changed else f'{len(changed)} file(s) changed since the build'}")
        print(f"  arm:        {binary_arm() or 'unknown'}")
    else:
        print("  binary:     not built")
    if INSTALL_PATH.exists():
        rc, caps = capture(["getcap", str(INSTALL_PATH)])
        print(f"  install:    {INSTALL_PATH}")
        print(f"  caps:       {caps.strip().split(' ', 1)[1] if rc == 0 and ' ' in caps.strip() else 'none'}")
        print(f"  arm:        {binary_arm(INSTALL_PATH) or 'unknown'}")
    else:
        print("  install:    not installed")
    if SERVICE_PATH.exists():
        _, enabled = capture(["systemctl", "is-enabled", NAME])
        _, active = capture(["systemctl", "is-active", NAME])
        print(f"  service:    {SERVICE_PATH} ({enabled.strip()}, {active.strip()})")
    else:
        print("  service:    not installed")
    print(f"  scheduler:  {active_ops() or 'EEVDF (no sched_ext scheduler loaded)'}")
    print(f"  kernel:     {platform.release()}")
    print()
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__.strip())
        return 0
    args = sys.argv[2:]
    if sys.argv[1] in ("prism", "measure"):
        log_info(f"{NAME} v{version()}: {sys.argv[1]} SELECTED")
        return cmd_prism(args) if sys.argv[1] == "prism" else cmd_measure(args)
    measure = ""
    if "--measure" in args:
        i = args.index("--measure")
        if i + 1 >= len(args) or args[i + 1] not in ARMS:
            log_error(f"--measure takes one of: {', '.join(ARMS)}")
            return 2
        measure = args[i + 1]
        del args[i:i + 2]
    cmd, flags = sys.argv[1], set(args)
    if measure and cmd not in ("build", "rebuild", "check", "install"):
        log_error("--measure applies to build, rebuild, check and install")
        return 2
    table = {
        "build": lambda: cmd_build(measure),
        "rebuild": lambda: cmd_rebuild(measure),
        "check": lambda: cmd_check(measure),
        "install": lambda: cmd_install(enable="--enable" in flags, measure=measure),
        "start": cmd_start,
        "stop": cmd_stop,
        "enable": cmd_enable,
        "disable": cmd_disable,
        "uninstall": cmd_uninstall,
        "status": cmd_status,
        "clean": cmd_clean,
    }
    if cmd not in table:
        print(__doc__.strip())
        return 2
    return table[cmd]()


if __name__ == "__main__":
    try:
        sys.exit(main())
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)

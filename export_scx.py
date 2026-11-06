#!/usr/bin/env python3
# scx_panda -> scx MONOREPO EXPORT
# AUTOMATES THE IMPORT PROCESS FOR sched-ext/scx, AFTER PANDEMONIUM's.
#
# USAGE:
#   ./export_scx.py /path/to/scx [--ported HASH ...] [--dry-run]
#
# BEFORE ANYTHING IS TOUCHED:
#   FETCHES THE sched-ext REMOTE AND REFUSES IF ANY COMMIT TOUCHED THE CRATE
#   SINCE OUR LAST RELEASE THERE. THE EXPORT REPLACES THE CRATE WHOLESALE, SO AN
#   UNPORTED UPSTREAM EDIT WOULD BE REVERTED. PORT EACH ONE INTO THIS TREE, THEN
#   RERUN WITH --ported NAMING EVERY LISTED HASH. A CRATE THAT HAS NEVER BEEN
#   RELEASED UPSTREAM IS THE FIRST IMPORT, AND PASSES.
#   READS scx's SCHEDULER CATALOG (services/catalog.json), WHICH scxcli AND
#   scxtui START SCHEDULERS FROM. A CRATE LISTED BELOW STABLE IS REFUSED; ONE
#   NOT LISTED AT ALL IS THE FIRST IMPORT, AND THE PR ADDS IT.
#
# WHAT IT DOES:
#   1. COPIES SOURCE FILES INTO scheds/rust/scx_panda/, catalog/profiles.json
#      INCLUDED FOR AN ADMINISTRATOR's /etc/scx/catalog.json
#   2. STRIPS [profile.release] (THE WORKSPACE PROVIDES ITS OWN)
#   3. REPLACES build.rs WITH scx_cargo::BpfBuilder (MATCHES OTHER SCHEDULERS);
#      THE MEASUREMENT ARMS STAY IN THIS TREE, THE EXPORT IS THE SHIPPED PROGRAM
#   4. SWAPS libbpf-cargo FOR THE scx_cargo PATH+VERSION DEP, ADDS scx_utils
#   5. STRIPS default-features=false FROM libbpf-rs (VENDORED LIBBPF FOR CI)
#   6. REPLACES THE BUILD-TIME ENUM SHIMS WITH scx_utils::import_enums!, WHICH
#      READS THE RUNNING KERNEL'S BTF AT LOAD; src/scx_enums.rs IS NOT EXPORTED
#   7. PATCHES bpf_skel.rs INCLUDE PATH FOR BpfBuilder OUTPUT
#   8. INJECTS THE VERSION SUFFIX INTO THE OPS NAME FOR scx_loader's DISPLAY
#   9. ADDS THE WORKSPACE MEMBER TO THE ROOT Cargo.toml IF MISSING
#  10. FORMATS, UPDATES Cargo.lock, THEN FAILS ON cargo fmt --check OR A FAILED
#      cargo build OF THE CRATE
#  11. WRITES THE PR BODY FROM COMMIT_MESSAGE.txt TO ~/.cache/panda/ WHEN THE
#      TREE HAS ONE (THE PUBLISHED TREE DOES NOT)
#
# THE BPF SOURCE IS COPIED AS IT STANDS: IT IS WRITTEN AGAINST THE scx HEADER
# API THE MONOREPO BUILDS IT WITH; THE VENDORED include/scx IS NOT EXPORTED.
#
# --dry-run SKIPS THE UPSTREAM FETCH AND THE cargo STEPS, SO THE TRANSFORMS CAN
# BE READ ON ANY WORKSPACE-SHAPED DIRECTORY.
#
# WHAT IT DOES NOT DO:
#   - DOES NOT COMMIT OR PUSH ANYTHING

import json
import os
import re
import shutil
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from panda import log_error, log_info, log_warn, scx_profiles, version  # noqa: E402

CRATE = "scx_panda"
DEST_REL = os.path.join("scheds", "rust", CRATE)

# FILES TO COPY (RELATIVE TO THE panda ROOT)
INCLUDE = [
    "Cargo.toml",
    "LICENSE",
    "README.md",
    "build.rs",
    "catalog/",
    "src/",
    "veristat/",
]

# FILES TO SKIP (NEVER EXPORT)
EXCLUDE = {
    ".git",
    ".gitignore",
    "target",
    "COMMIT_MESSAGE.txt",
    "ROADMAP.md",
    "FINDINGS.md",
    "export_scx.py",
    "panda.py",
    "tests",
    "include",
    "Cargo.lock",
    "__pycache__",
    "scx_enums.rs",
}


def section(title: str) -> None:
    print()
    log_info(title)


def report(text: str) -> None:
    for line in text.splitlines():
        print(f"    {line}")


def assert_export_is_exactly_include(dst_root):
    """The export tree may contain WHAT INCLUDE NAMES AND NOTHING ELSE. The
    check is of the RESULT, not of the list consulted while copying."""
    permitted = {e.rstrip("/").split("/")[0] for e in INCLUDE}
    present = set(os.listdir(dst_root))
    unexpected = sorted(present - permitted)
    if unexpected:
        log_error("the export tree holds entries INCLUDE does not name: "
                  + ", ".join(unexpected))
        shutil.rmtree(dst_root, ignore_errors=True)
        raise SystemExit(2)
    log_info(f"export tree matches INCLUDE exactly ({len(present)} entries)")


def copy_tree(src_root, dst_root):
    """Copy INCLUDE paths from src_root to dst_root, skipping EXCLUDE."""
    copied = 0
    for entry in INCLUDE:
        src = os.path.join(src_root, entry)
        dst = os.path.join(dst_root, entry)
        if not os.path.exists(src):
            log_warn(f"skipped {entry}: missing")
            continue
        if os.path.isdir(src):
            if os.path.exists(dst):
                shutil.rmtree(dst)
            shutil.copytree(src, dst, ignore=shutil.ignore_patterns(*EXCLUDE))
            count = sum(len(files) for _, _, files in os.walk(dst))
            log_info(f"copied {entry} ({count} files)")
            copied += count
        else:
            if os.path.basename(entry) in EXCLUDE:
                log_warn(f"skipped {entry}: excluded")
                continue
            os.makedirs(os.path.dirname(dst), exist_ok=True)
            shutil.copy2(src, dst)
            log_info(f"copied {entry}")
            copied += 1
    return copied


def require_crate_name(dst_root):
    text = open(os.path.join(dst_root, "Cargo.toml")).read()
    if f'name = "{CRATE}"' not in text:
        log_error(f"Cargo.toml does not name the package {CRATE}")
        sys.exit(1)
    log_info(f"package is {CRATE}; no rename")


def strip_profile_release(dst_root):
    """Remove the [profile.release] block from Cargo.toml."""
    cargo_path = os.path.join(dst_root, "Cargo.toml")
    text = open(cargo_path).read()
    new_text = re.sub(r'\n\[profile\.release\]\n(?:[^\[]*)', '\n', text)
    if new_text != text:
        open(cargo_path, "w").write(new_text.rstrip() + "\n")
        log_info("stripped [profile.release] (the workspace provides its own)")
        return 1
    return 0


SCX_BUILD_RS = """\
use std::process::Command;

fn main() {
    // BUILD ID: GIT SHA, DIRTY FLAG, TARGET TRIPLE. THE EXPORT IS THE SHIPPED
    // PROGRAM; THE MEASUREMENT ARMS LIVE IN THE STANDALONE TREE.
    let git_sha = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_string())
        .unwrap_or_default();

    let git_dirty = Command::new("git")
        .args(["status", "--porcelain", "--", "."])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .map(|o| !o.stdout.is_empty())
        .unwrap_or(false);

    let build_id = if git_sha.is_empty() {
        String::new()
    } else if git_dirty {
        format!("-g{}-dirty", git_sha)
    } else {
        format!("-g{}", git_sha)
    };

    let target = std::env::var("TARGET").unwrap_or_default();

    println!("cargo:rustc-env=PANDA_BUILD_ID={}", build_id);
    println!("cargo:rustc-env=PANDA_TARGET={}", target);
    println!("cargo:rustc-env=PANDA_KERNEL=scx vmlinux.h");
    println!("cargo:rustc-env=PANDA_ARM=shipped");

    scx_cargo::BpfBuilder::new()
        .unwrap()
        .enable_intf("src/bpf/intf.h", "bpf_intf.rs")
        .enable_skel("src/bpf/main.bpf.c", "main")
        .build()
        .unwrap();
}
"""


def replace_build_rs(dst_root):
    open(os.path.join(dst_root, "build.rs"), "w").write(SCX_BUILD_RS)
    log_info("replaced build.rs with scx_cargo::BpfBuilder")
    return 1


def read_crate_version(scx_root, crate):
    """The version of rust/<crate>/Cargo.toml in the monorepo."""
    cargo_path = os.path.join(scx_root, "rust", crate, "Cargo.toml")
    if not os.path.exists(cargo_path):
        log_warn(f"{cargo_path} not found, falling back to wildcard version")
        return "*"
    m = re.search(r'^version\s*=\s*"([^"]+)"', open(cargo_path).read(), re.MULTILINE)
    if not m:
        log_warn(f"no version found in {cargo_path}, falling back to wildcard")
        return "*"
    return m.group(1)


def swap_build_deps(dst_root, scx_root):
    """Replace libbpf-cargo with the scx_cargo path+version dep."""
    ver = read_crate_version(scx_root, "scx_cargo")
    dep = f'scx_cargo = {{ path = "../../../rust/scx_cargo", version = "{ver}" }}'
    cargo_path = os.path.join(dst_root, "Cargo.toml")
    text = open(cargo_path).read()
    new_text = re.sub(r'libbpf-cargo\s*=\s*"[^"]*"', dep, text)
    if new_text != text:
        open(cargo_path, "w").write(new_text)
        log_info(f"swapped libbpf-cargo for scx_cargo {ver}")
        return 1
    log_warn("libbpf-cargo not found in [build-dependencies]")
    return 0


def fix_libbpf_vendoring(dst_root):
    """Strip default-features = false from libbpf-rs: scx CI has no system
    libbpf on the linker path and builds the vendored one."""
    cargo_path = os.path.join(dst_root, "Cargo.toml")
    text = open(cargo_path).read()
    new_text = re.sub(r'(libbpf-rs\s*=\s*\{[^}]*),\s*default-features\s*=\s*false',
                      r'\1', text)
    if new_text != text:
        open(cargo_path, "w").write(new_text)
        log_info("stripped default-features = false from libbpf-rs (vendored libbpf)")
        return 1
    log_info("libbpf-rs already uses default features")
    return 0


def normalize_dep_versions(dst_root):
    """Reduce dependency versions to API boundaries, the monorepo's convention:
    0.x.y -> 0.x, X.y.z -> X. An exact pin (=X.Y.Z) is left alone; libbpf-rs
    must match the workspace's and the pin says which."""
    cargo_path = os.path.join(dst_root, "Cargo.toml")
    text = open(cargo_path).read()

    def normalize(m):
        prefix, ver = m.group(1), m.group(2)
        parts = ver.split(".")
        if len(parts) >= 2 and parts[0] == "0":
            normalized = f"{parts[0]}.{parts[1]}"
        elif parts and int(parts[0]) >= 1:
            normalized = parts[0]
        else:
            normalized = ver
        return f'{prefix}"{normalized}"'

    new_text = re.sub(
        r'((?:libc|anyhow|clap|ctrlc|libbpf-rs)\s*=\s*(?:\{[^}]*version\s*=\s*|))"(\d+\.\d+\.\d+)"',
        normalize, text)
    if new_text != text:
        open(cargo_path, "w").write(new_text)
        log_info("reduced dependency versions to API boundaries")
        return 1
    log_info("dependency versions already normalized")
    return 0


def add_scx_utils_dep(dst_root, scx_root):
    ver = read_crate_version(scx_root, "scx_utils")
    cargo_path = os.path.join(dst_root, "Cargo.toml")
    text = open(cargo_path).read()
    if "scx_utils" in text:
        log_info("scx_utils dependency already present")
        return 0
    line = f'scx_utils = {{ path = "../../../rust/scx_utils", version = "{ver}" }}'
    new_text = text.replace("[dependencies]\n", f"[dependencies]\n{line}\n")
    if new_text != text:
        open(cargo_path, "w").write(new_text)
        log_info(f"added scx_utils {ver}")
        return 1
    log_warn("could not find the [dependencies] section")
    return 0


def patch_bpf_skel_include(dst_root):
    skel_path = os.path.join(dst_root, "src", "bpf_skel.rs")
    if not os.path.exists(skel_path):
        log_warn("src/bpf_skel.rs not found")
        return 0
    text = open(skel_path).read()
    new_text = text.replace("/bpf.skel.rs", "/main_skel.rs")
    if new_text != text:
        open(skel_path, "w").write(new_text)
        log_info("patched the bpf_skel.rs include path to main_skel.rs")
        return 1
    return 0


def patch_enum_shims(dst_root):
    """The standalone loader writes every __SCX_* shim from constants build.rs
    extracted out of the kernel's vmlinux.h. In the monorepo the BPF is built
    against scx's own header set, so the shims come from scx_utils, which reads
    the running kernel's BTF at load. The block goes, the module goes, and
    import_enums! takes their place after the rodata borrow ends."""
    changes = 0
    lib_path = os.path.join(dst_root, "src", "lib.rs")
    text = open(lib_path).read()
    new_text = re.sub(r'(?m)^(?:#\[allow\([^)]*\)\]\n)*pub mod scx_enums;\n', '', text)
    if new_text != text:
        open(lib_path, "w").write(new_text)
        log_info("removed the scx_enums module from lib.rs")
        changes += 1

    sched_path = os.path.join(dst_root, "src", "scheduler.rs")
    text = open(sched_path).read()
    orig = text
    text = text.replace("use crate::scx_enums as e;\n", "")
    # THE COMMENT ABOVE THE SHIMS AND EVERY SHIM LINE.
    text = re.sub(r'(?m)^[ \t]*// EVERY sched_ext ENUM SHIM.*\n(?:[ \t]*//.*\n)*', '', text)
    shims = re.findall(r'(?m)^[ \t]*rodata\.__SCX_\w+ = e::\w+;\n', text)
    text = re.sub(r'(?m)^[ \t]*rodata\.__SCX_\w+ = e::\w+;\n', '', text)
    anchor = "            rodata.uei_dump_len = EXIT_DUMP_LEN;\n        }\n"
    if anchor not in text:
        log_error("scheduler.rs: the rodata block does not end where the export expects")
        sys.exit(1)
    text = text.replace(anchor, anchor
                        + "\n        // THE sched_ext ENUM SHIMS, FROM THE RUNNING KERNEL'S BTF\n"
                        + "        // VIA scx_utils.\n"
                        + "        scx_utils::import_enums!(open_skel);\n", 1)
    if text != orig:
        open(sched_path, "w").write(text)
        log_info(f"replaced {len(shims)} build-time shims with scx_utils::import_enums!")
        changes += 1
    return changes


def patch_ops_version_suffix(dst_root):
    """Inject the version suffix into the struct_ops name, so scx_loader shows
    the version beside the name it reads from /sys/kernel/sched_ext/root/ops."""
    sched_path = os.path.join(dst_root, "src", "scheduler.rs")
    text = open(sched_path).read()
    if "ops_version_suffix" in text:
        log_info("ops version suffix already present")
        return 0
    anchor = '        let mut open_skel = builder.open(open_object).context("open")?;'
    if anchor not in text:
        log_warn("could not find the open_skel anchor in scheduler.rs")
        return 0
    inject = anchor + (
        '\n'
        '\n'
        '        // INJECT THE VERSION SUFFIX INTO THE OPS NAME FOR scx_loader\n'
        '        {\n'
        '            let ops = open_skel.struct_ops.panda_ops_mut();\n'
        '            let name_field = &mut ops.name;\n'
        '            let version_suffix = scx_utils::build_id::ops_version_suffix(env!("CARGO_PKG_VERSION"));\n'
        '            let bytes = version_suffix.as_bytes();\n'
        '            let mut i = 0;\n'
        '            let mut bytes_idx = 0;\n'
        '            let mut found_null = false;\n'
        '            while i < name_field.len() - 1 {\n'
        '                found_null |= name_field[i] == 0;\n'
        '                if !found_null {\n'
        '                    i += 1;\n'
        '                    continue;\n'
        '                }\n'
        '                if bytes_idx < bytes.len() {\n'
        '                    name_field[i] = bytes[bytes_idx] as i8;\n'
        '                    bytes_idx += 1;\n'
        '                } else {\n'
        '                    break;\n'
        '                }\n'
        '                i += 1;\n'
        '            }\n'
        '            name_field[i] = 0;\n'
        '        }'
    )
    open(sched_path, "w").write(text.replace(anchor, inject, 1))
    log_info("patched scheduler.rs with the ops version suffix (scx_loader)")
    return 1


def add_workspace_member(scx_root):
    cargo_path = os.path.join(scx_root, "Cargo.toml")
    if not os.path.exists(cargo_path):
        log_warn(f"{cargo_path} not found, skipping workspace registration")
        return 0
    text = open(cargo_path).read()
    member_line = f'    "{DEST_REL}",'
    # THE QUOTED PATH: scheds/rust/scx_panda IS A PREFIX OF scx_pandemonium.
    if f'"{DEST_REL}"' in text:
        log_info("workspace member already registered")
        return 0
    lines, out, inserted, in_members = text.split("\n"), [], False, False
    for line in lines:
        if line.strip() == "members = [":
            in_members = True
            out.append(line)
            continue
        if in_members and not inserted:
            stripped = line.strip()
            if stripped == "]":
                out.append(member_line)
                inserted = True
            elif stripped.startswith('"') and stripped.rstrip(",") > f'"{DEST_REL}"':
                out.append(member_line)
                inserted = True
                in_members = False
        out.append(line)
    if inserted:
        open(cargo_path, "w").write("\n".join(out))
        log_info(f"added {DEST_REL} to workspace members")
        return 1
    log_warn("could not find an insertion point in workspace Cargo.toml")
    return 0


def git(cwd, *args):
    return subprocess.run(["git", "-C", cwd, *args], capture_output=True, text=True)


def upstream_remote(scx_root):
    r = git(scx_root, "remote", "-v")
    for line in r.stdout.splitlines():
        name, url = line.split()[:2]
        if "sched-ext/scx" in url:
            return name
    log_error(f"no remote in {scx_root} points at sched-ext/scx")
    sys.exit(1)


def require_upstream_ported(scx_root, ported):
    """Refuse while a crate commit since our last upstream release is unported.
    No release yet and no crate directory upstream is the first import."""
    remote = upstream_remote(scx_root)
    r = git(scx_root, "fetch", "-q", remote, "main")
    if r.returncode != 0:
        log_error(f"git fetch {remote} main failed: {r.stderr.strip()}")
        sys.exit(1)
    main_ref = f"{remote}/main"
    r = git(scx_root, "log", main_ref, "-1", "--format=%h", "-i", "-E",
            f"--grep=^{CRATE}v[0-9]", "--", DEST_REL)
    last = r.stdout.strip()
    if not last:
        exists = git(scx_root, "cat-file", "-e", f"{main_ref}:{DEST_REL}").returncode == 0
        if exists:
            log_error(f"{DEST_REL} exists on {main_ref} with no {CRATE} release "
                      "commit; review it before an export replaces it")
            sys.exit(1)
        log_info(f"no {CRATE} release on {main_ref}: the first import")
        return
    r = git(scx_root, "log", "--no-merges", "--format=%h%x09%an%x09%s",
            f"{last}..{main_ref}", "--", DEST_REL)
    since = [line.split("\t") for line in r.stdout.splitlines()]
    unported = [c for c in since
                if not any(c[0].startswith(p) or p.startswith(c[0]) for p in ported)]
    log_info(f"last release {last}, {len(since)} crate commit(s) since")
    if unported:
        log_error(f"{len(unported)} upstream commit(s) touched the crate since "
                  f"{last}, and the export would revert them")
        log_error("port each into this tree, then rerun with --ported naming every hash")
        report("\n".join([f"{'HASH':<12}{'AUTHOR':<20}SUBJECT"]
                         + [f"{h:<12}{author:<20}{subject}" for h, author, subject in unported]))
        log_info(f"REVIEW: git -C {scx_root} show HASH -- {DEST_REL}")
        sys.exit(1)


def require_catalog(scx_root):
    """scx's catalog lists the crate featured or stable, or not at all yet, and
    the profiles the crate ships pass the catalog's rules and take no id the
    catalog already uses."""
    try:
        profiles = scx_profiles()
    except (OSError, ValueError) as e:
        log_error(str(e))
        sys.exit(1)
    path = os.path.join(scx_root, "services", "catalog.json")
    if not os.path.exists(path):
        log_warn("services/catalog.json not found: this scx predates the "
                 "catalog; the profiles ship in the crate regardless")
        return
    with open(path) as f:
        catalog = json.load(f)
    tiers = [t for t in ("featured", "stable", "experimental", "hidden")
             if CRATE in (catalog.get(t) or [])]
    if tiers and not ({"featured", "stable"} & set(tiers)):
        log_error(f"{CRATE} is listed {'/'.join(tiers)} in scx's catalog "
                  "(services/catalog.json); scxcli and scxtui would not present "
                  "it as stable. Settle that in scx first")
        sys.exit(1)
    if not tiers:
        log_warn(f"{CRATE} is not in scx's catalog yet; the import PR adds it to "
                 "services/catalog.json")
    taken = ({r.get("id") for r in catalog.get("recommended", [])}
             | {s for t in ("featured", "hidden", "stable", "experimental")
                for s in (catalog.get(t) or [])})
    clash = [p["id"] for p in profiles if p["id"] in taken]
    if clash:
        log_error(f"profile id(s) already taken in scx's catalog: {', '.join(clash)}")
        sys.exit(1)
    log_info(f"catalog: {CRATE} is {tiers[0] if tiers else 'unlisted'}; ships "
             "profile(s) " + ", ".join(p["id"] for p in profiles))


def run_checked(cmd, cwd, label):
    r = subprocess.run(cmd, capture_output=True, text=True, cwd=cwd)
    if r.returncode != 0:
        log_error(f"{label} failed: {' '.join(cmd)}")
        report("\n".join((r.stdout + r.stderr).strip().splitlines()[-20:]))
        sys.exit(1)
    log_info(f"{label}: ok")


def write_pr_body(panda_root):
    """The PR description: COMMIT_MESSAGE.txt without the subject, one line per
    paragraph, bullet and section header. The published tree has none."""
    message = os.path.join(panda_root, "COMMIT_MESSAGE.txt")
    if not os.path.exists(message):
        log_info("no COMMIT_MESSAGE.txt in this tree, so no PR body is written")
        return None
    lines = open(message).read().splitlines()
    start = next((i + 1 for i, l in enumerate(lines) if l.startswith("— ")), 1)
    blocks, items = [], []
    for line in lines[start:] + [""]:
        if not line.strip():
            if items:
                blocks.append(items)
                items = []
            continue
        if line.startswith("- ") or not items:
            items.append(line)
        else:
            items[-1] += " " + line.strip()
    # NOT /tmp/panda: THE LOADER OWNS THAT DIRECTORY AS ROOT.
    out_dir = os.path.join(os.path.expanduser("~"), ".cache", "panda")
    os.makedirs(out_dir, exist_ok=True)
    out = os.path.join(out_dir, f"scx-pr-body-v{version()}.md")
    open(out, "w").write("\n\n".join("\n".join(b) for b in blocks) + "\n")
    return out


def main():
    args = sys.argv[1:]
    dry = "--dry-run" in args
    args = [a for a in args if a != "--dry-run"]
    ported = []
    if "--ported" in args:
        i = args.index("--ported")
        ported = [h for h in args[i + 1:] for h in h.split(",") if h]
        args = args[:i]
    if len(args) != 1:
        log_error(f"usage: {sys.argv[0]} /path/to/scx [--ported HASH ...] [--dry-run]")
        sys.exit(1)

    scx_root = os.path.abspath(args[0])
    panda_root = os.path.dirname(os.path.abspath(__file__))
    dst_root = os.path.join(scx_root, DEST_REL)

    if not os.path.isdir(scx_root):
        log_error(f"{scx_root} is not a directory")
        sys.exit(1)
    if not os.path.exists(os.path.join(scx_root, "Cargo.toml")):
        log_error(f"{scx_root}/Cargo.toml not found (is this an scx checkout?)")
        sys.exit(1)

    log_info(f"export_scx {CRATE} v{version()} [scx={scx_root}]"
             + (" [dry run]" if dry else ""))
    log_info(f"TARGET: {dst_root}")

    section("upstream: CHECK")
    if dry:
        log_info("dry run: the upstream fetch is skipped")
    else:
        require_upstream_ported(scx_root, ported)
    section("catalog: CHECK")
    require_catalog(scx_root)

    section("source: COPY")
    if os.path.exists(dst_root):
        shutil.rmtree(dst_root)
        log_info(f"removed the existing {DEST_REL}/")
    os.makedirs(dst_root, exist_ok=True)
    copied = copy_tree(panda_root, dst_root)
    assert_export_is_exactly_include(dst_root)
    require_crate_name(dst_root)

    section("build system: PATCH")
    stripped = strip_profile_release(dst_root)
    replace_build_rs(dst_root)
    swap_build_deps(dst_root, scx_root)
    fix_libbpf_vendoring(dst_root)
    normalize_dep_versions(dst_root)
    patch_bpf_skel_include(dst_root)
    add_scx_utils_dep(dst_root, scx_root)
    patch_enum_shims(dst_root)
    patch_ops_version_suffix(dst_root)

    section("workspace: REGISTER")
    registered = add_workspace_member(scx_root)

    section("cargo: VERIFY")
    if dry:
        log_info("dry run: cargo fmt, update and build are skipped")
    else:
        manifest = os.path.join(dst_root, "Cargo.toml")
        run_checked(["cargo", "fmt", "--manifest-path", manifest], scx_root, "cargo fmt")
        # cargo update -p MATCHES THE SPEC AGAINST THE LOCKFILE'S PACKAGES, SO
        # A MEMBER JUST ADDED TO THE WORKSPACE IS NOT THERE YET; --workspace
        # ENTERS THE NEW MEMBER AND ITS EDGES WITHOUT MOVING ANY OTHER VERSION.
        lock = os.path.join(scx_root, "Cargo.lock")
        locked = os.path.exists(lock) and f'name = "{CRATE}"' in open(lock).read()
        if locked:
            run_checked(["cargo", "update", "-p", CRATE], scx_root, "cargo update")
        else:
            run_checked(["cargo", "update", "--workspace"], scx_root,
                        "cargo update --workspace (first entry in Cargo.lock)")
        run_checked(["cargo", "fmt", "--check", "-p", CRATE], scx_root, "cargo fmt --check")
        run_checked(["cargo", "build", "-p", CRATE, "--release"], scx_root, "cargo build")

    body = write_pr_body(panda_root)

    print()
    log_info(f"EXPORT COMPLETE: {copied} files copied, {stripped} profile stripped, "
             f"{registered} workspace update")
    if body:
        log_info(f"PR BODY: {body}")
    log_info(f"NEXT: cd {scx_root} && git add -A && git diff --cached --stat")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\nInterrupted by user.")
        sys.exit(130)

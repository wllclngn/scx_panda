// scx_panda BUILD SCRIPT
// COMPILES src/bpf/main.bpf.c INTO BPF BYTECODE, GENERATES THE RUST SKELETON
// AND EXTRACTS EVERY sched_ext ENUM VALUE FROM THE KERNEL'S OWN vmlinux.h INTO
// A RUST CONSTANTS FILE, SO THE LOADER WRITES THE RODATA SHIMS FROM THE KERNEL
// THE PROGRAM WAS BUILT AGAINST AND NEVER FROM A HAND LIST.
// vmlinux.h IS CACHED AT $HOME/.cache/panda/vmlinux-<release>.h, KEYED ON THE
// RUNNING KERNEL'S RELEASE, AND GENERATED FROM ITS BTF VIA bpftool ON A MISS.

use std::env;
use std::path::PathBuf;
use std::process::Command;

use libbpf_cargo::SkeletonBuilder;

const BPF_SRC: &str = "src/bpf/main.bpf.c";

fn main() {
    let out_dir = PathBuf::from(env::var("OUT_DIR").unwrap());

    let vmlinux_dir = out_dir.join("include").join("vmlinux");
    std::fs::create_dir_all(&vmlinux_dir).expect("failed to create vmlinux dir");
    let vmlinux_h = vmlinux_dir.join("vmlinux.h");

    let release = std::fs::read_to_string("/proc/sys/kernel/osrelease")
        .map(|s| s.trim().to_string())
        .unwrap_or_else(|_| "unknown".into());
    let cache_dir = PathBuf::from(env::var("HOME").expect("HOME not set"))
        .join(".cache")
        .join("panda");
    std::fs::create_dir_all(&cache_dir).expect("failed to create cache dir");
    let cache_path = cache_dir.join(format!("vmlinux-{release}.h"));

    let raw = if cache_path.exists()
        && cache_path.metadata().map(|m| m.len() > 1000).unwrap_or(false)
    {
        std::fs::read_to_string(&cache_path).expect("cached vmlinux.h is not utf-8")
    } else {
        let output = Command::new("bpftool")
            .args(["btf", "dump", "file", "/sys/kernel/btf/vmlinux", "format", "c"])
            .output()
            .expect("bpftool not found: install it once for the first build on this kernel");
        if !output.status.success() {
            panic!("bpftool failed: {}", String::from_utf8_lossy(&output.stderr));
        }
        std::fs::write(&cache_path, &output.stdout).expect("failed to cache vmlinux.h");
        String::from_utf8(output.stdout).expect("vmlinux.h is not utf-8")
    };
    let patched = patch_vmlinux_anon_fields(&raw);
    std::fs::write(&vmlinux_h, patched.as_bytes()).expect("failed to write vmlinux.h");

    // THE scx HEADERS INCLUDE ../vmlinux.h RELATIVE TO include/scx/.
    let vmlinux_symlink = out_dir.join("include").join("vmlinux.h");
    let _ = std::fs::remove_file(&vmlinux_symlink);
    std::os::unix::fs::symlink(vmlinux_dir.join("vmlinux.h"), &vmlinux_symlink)
        .expect("failed to symlink vmlinux.h");

    let enums_rs = out_dir.join("scx_enums.rs");
    std::fs::write(&enums_rs, extract_scx_enums(&raw)).expect("failed to write scx_enums.rs");

    let gen_include = out_dir.join("include");
    let skel_out = out_dir.join("bpf.skel.rs");
    let mut cflags: Vec<String> = vec![
        "-I".into(),
        "include".into(),
        "-I".into(),
        gen_include.to_str().unwrap().into(),
        "-I".into(),
        vmlinux_dir.to_str().unwrap().into(),
    ];

    // MEASUREMENT ARMS. PANDA_MEASURE NAMES A COMPILE-TIME ARM OF THE PROGRAM
    // BUILT FOR AN A/B AND NEVER SHIPPED: THE DEFINE REACHES clang AND THE
    // ARM'S NAME RIDES IN THE BINARY'S VERSION, BANNER AND SUMMARY.
    let measure = env::var("PANDA_MEASURE").unwrap_or_default();
    let (arm, defines): (&str, &[&str]) = match measure.as_str() {
        "" | "shipped" => ("shipped", &[]),
        "no-habit-price" => ("no-habit-price", &["-DPANDA_NO_HABIT_PRICE"]),
        "rank-order" => ("rank-order", &[]),
        "l3-walk" => ("l3-walk", &["-DPANDA_L3_WALK"]),
        other => panic!("PANDA_MEASURE={other}: the arms are no-habit-price, rank-order and l3-walk"),
    };
    for d in defines {
        cflags.push((*d).into());
    }

    SkeletonBuilder::new()
        .source(BPF_SRC)
        .clang_args(cflags)
        .build_and_generate(&skel_out)
        .unwrap();

    println!("cargo:rerun-if-changed={BPF_SRC}");
    println!("cargo:rerun-if-changed=src/bpf/intf.h");
    println!("cargo:rerun-if-changed=include/scx");
    println!("cargo:rerun-if-env-changed=PANDA_MEASURE");
    println!("cargo:rustc-env=PANDA_ARM={arm}");
    // THE LOADER-ONLY ARM IS A RUST cfg, NOT A clang DEFINE.
    println!("cargo::rustc-check-cfg=cfg(panda_rank_order)");
    if arm == "rank-order" {
        println!("cargo:rustc-cfg=panda_rank_order");
    }

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
        format!("-g{git_sha}-dirty")
    } else {
        format!("-g{git_sha}")
    };
    let target = env::var("TARGET").unwrap_or_default();
    println!("cargo:rustc-env=PANDA_BUILD_ID={build_id}");
    println!("cargo:rustc-env=PANDA_TARGET={target}");
    println!("cargo:rustc-env=PANDA_KERNEL={release}");
}

// EVERY ENUMERATOR NAMED SCX_* OR __SCX_* IN vmlinux.h BECOMES A u64 CONST.
// bpftool PRINTS ENUMERATORS AS `\tNAME = VALUE,` WITH AN OPTIONAL ULL SUFFIX;
// A NAME THAT APPEARS TWICE KEEPS ITS FIRST VALUE.
fn extract_scx_enums(raw: &str) -> String {
    let mut seen: Vec<String> = Vec::new();
    let mut out = String::from(
        "// GENERATED BY build.rs FROM THE KERNEL'S vmlinux.h. DO NOT EDIT.\n",
    );
    for line in raw.lines() {
        let t = line.trim();
        if !(t.starts_with("SCX_") || t.starts_with("__SCX_")) {
            continue;
        }
        let Some((name, rest)) = t.split_once('=') else { continue };
        let name = name.trim();
        if !name.chars().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_') {
            continue;
        }
        let value = rest
            .trim()
            .trim_end_matches(',')
            .trim_end_matches("ULL")
            .trim_end_matches("UL")
            .trim_end_matches('U')
            .trim();
        let Ok(v) = value.parse::<u64>() else { continue };
        if seen.iter().any(|s| s == name) {
            continue;
        }
        seen.push(name.to_string());
        out.push_str(&format!("pub const {name}: u64 = {v};\n"));
    }
    out
}

// KERNEL PATCHES (BORE) ADD STRUCT FIELDS NAMED `_`, VALID C AND INVALID AS A
// RUST FIELD. RENAME THEM BEFORE SKELETON GENERATION.
fn patch_vmlinux_anon_fields(raw: &str) -> String {
    let mut count = 0u32;
    let mut result = String::with_capacity(raw.len() + 1);
    for line in raw.lines() {
        let trimmed = line.trim();
        if trimmed.ends_with(" _;") || trimmed.ends_with("\t_;") {
            result.push_str(&line.replacen(" _;", &format!(" _anon_pad_{count};"), 1));
            count += 1;
        } else {
            result.push_str(line);
        }
        result.push('\n');
    }
    result
}

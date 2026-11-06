// sched_ext ENUM VALUES, EXTRACTED BY build.rs FROM THE vmlinux.h THE BPF WAS
// COMPILED AGAINST. ONE SOURCE FOR THE RODATA SHIMS THE LOADER WRITES.
#![allow(dead_code)]
include!(concat!(env!("OUT_DIR"), "/scx_enums.rs"));

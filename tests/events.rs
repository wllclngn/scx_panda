// SPDX-License-Identifier: GPL-2.0-only
// Copyright (c) 2026 Will Clingan
// THE KERNEL'S sched_ext EVENT COUNTERS AS THE LOADER READS THEM: THE PARSE,
// THE PER-SECOND DELTA LINE AND THE EXIT SUMMARY'S TOTAL LINE.

use scx_panda::events::ScxEvents;

const SAMPLE: &str = "SCX_EV_SELECT_CPU_FALLBACK 146755\n\
SCX_EV_DISPATCH_LOCAL_DSQ_OFFLINE 0\n\
SCX_EV_DISPATCH_KEEP_LAST 3663\n\
SCX_EV_ENQ_SKIP_EXITING 7256\n\
SCX_EV_ENQ_SKIP_MIGRATION_DISABLED 34864\n\
SCX_EV_REENQ_IMMED 0\n\
SCX_EV_REFILL_SLICE_DFL 46069\n\
SCX_EV_BYPASS_DURATION 9286705\n\
garbage line without a number\n";

#[test]
fn parses_name_value_lines_and_skips_the_rest() {
    let e = ScxEvents::parse(SAMPLE);
    assert_eq!(e.0.len(), 8);
    assert_eq!(e.get("SCX_EV_SELECT_CPU_FALLBACK"), 146755);
    assert_eq!(e.get("SCX_EV_REENQ_IMMED"), 0);
    assert_eq!(e.get("SCX_EV_NOT_THERE"), 0);
}

#[test]
fn delta_line_subtracts_in_the_fixed_order() {
    let prev = ScxEvents::parse(SAMPLE);
    let mut cur = prev.clone();
    cur.0.insert("SCX_EV_SELECT_CPU_FALLBACK".into(), 146755 + 49);
    cur.0.insert("SCX_EV_REFILL_SLICE_DFL".into(), 46069 + 15);
    assert_eq!(
        cur.delta_line(&prev),
        "fallback=49 refill=15 migdis=0 exiting=0 keeplast=0 reenq=0"
    );
}

#[test]
fn total_line_drops_the_prefix() {
    let e = ScxEvents::parse("SCX_EV_REENQ_IMMED 7\n");
    assert_eq!(e.total_line(), "REENQ_IMMED=7");
}

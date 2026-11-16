//! §4.2's tie rule: greater density, then smaller reach, then smaller slot, and the whole key decides at
//! every comparison, including when a refreshed entry is accepted over the next stale one.

use super::bridge::*;
use crate::{Pick, Rule, offline};

#[test]
fn reach_decides_an_exact_density_tie_in_a_warm_group() {
    let mut b = Build::new();
    let (c0, c1) = (b.class(1.0), b.class(1.0));
    let x = b.step(10.0);
    let wide = b.probe_r(1.0, &[c0], &[x], 5); // slot 0, reaches more
    let narrow = b.probe_r(1.0, &[c1], &[x], 1); // slot 1, reaches less
    let inputs = b.done();
    let mut rule = Rule::new(&inputs, &[x]);
    assert_eq!(
        rule.next(),
        Pick::Run(narrow),
        "equal density: the narrower probe first, though its slot is larger"
    );
    assert_eq!(rule.next(), Pick::Run(wide));
    assert_eq!(offline(&inputs).as_slice(), &[narrow, wide]);
}

#[test]
fn the_smaller_slot_decides_when_reach_is_equal_too() {
    let mut b = Build::new();
    let (c0, c1) = (b.class(1.0), b.class(1.0));
    let x = b.step(10.0);
    let first = b.probe_r(1.0, &[c0], &[x], 3);
    let second = b.probe_r(1.0, &[c1], &[x], 3);
    let inputs = b.done();
    assert_eq!(offline(&inputs).as_slice(), &[first, second]);
}

#[test]
fn a_refreshed_entry_must_beat_the_next_stale_one_on_the_whole_key() {
    // Slot 0 (reach 5) kills x and y, slot 1 (reach 1) kills z, slot 2 (reach 0, half the cost) kills x.
    // At the start slots 0 and 2 tie at density 2 and reach picks slot 2. Then slot 0's refreshed density
    // is 1, which equals slot 1's stale 1: a rule that accepts on equal density would run slot 0; the whole
    // key puts the narrower slot 1 first.
    let mut b = Build::new();
    let (x, y, z) = (b.class(1.0), b.class(1.0), b.class(1.0));
    let step = b.step(10.0);
    let p0 = b.probe_r(1.0, &[x, y], &[step], 5);
    let p1 = b.probe_r(1.0, &[z], &[step], 1);
    let p2 = b.probe_r(0.5, &[x], &[step], 0);
    let inputs = b.done();
    let mut rule = Rule::new(&inputs, &[step]);
    assert_eq!(rule.next(), Pick::Run(p2));
    assert_eq!(
        rule.next(),
        Pick::Run(p1),
        "a refreshed tie must lose to the stale entry that wins on reach"
    );
    assert_eq!(rule.next(), Pick::Run(p0));
}

#[test]
fn reach_decides_an_exact_tie_between_groups() {
    // Two cold groups with the same set-up and an identical single probe each; the probe of the larger
    // slot is the narrower one.
    let mut b = Build::new();
    let (c0, c1) = (b.class(1.0), b.class(1.0));
    let (s0, s1) = (b.step(2.0), b.step(2.0));
    let wide = b.probe_r(1.0, &[c0], &[s0], 5);
    let narrow = b.probe_r(1.0, &[c1], &[s1], 1);
    let inputs = b.done();
    let mut rule = Rule::new(&inputs, &[]);
    assert_eq!(
        rule.next(),
        Pick::SetUp(s1),
        "the group whose first probe is narrower is set up first"
    );
    rule.up(s1);
    assert_eq!(rule.next(), Pick::Run(narrow));
    // Both warm: the same tie, now between warm groups.
    let mut rule = Rule::new(&inputs, &[s0, s1]);
    assert_eq!(rule.next(), Pick::Run(narrow));
    assert_eq!(rule.next(), Pick::Run(wide));
}

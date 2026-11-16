//! The crate against the simulator it was ported from: same instances, same positive-gain order.

use super::bench::shapes;
use super::bridge::*;
use super::reference_sim::bundle_greedy;
use super::support::*;
use crate::offline;

/// The orders must agree on every probe the simulator's rule picks for its gain. What follows is the
/// zero-gain tail, and there the document is the rule (§4.2: probes whose steps are up first, then
/// cheapest first; every probe is dispatched) and the simulator is wrong: `sim.rs` appends the tail in
/// index order and its online loop does not run it. That changes no `J` on one worker and does change
/// the list-scheduled rows of §4.4 (core, 16 workers: 137.8 with the simulator's tail, 105.1 with the
/// document's). So only the *set* of the tail is compared here, never its order.
fn same_positive_prefix(inst: &Instance, what: &str) {
    let (sim, _, boundary) = bundle_greedy(inst);
    let mine = offline(&inputs_of(inst));
    assert_eq!(
        &mine.as_slice()[..boundary],
        &sim[..boundary],
        "{what}: the orders differ before the zero-gain tail"
    );
    let (mut a, mut b) = (
        mine.as_slice()[boundary..].to_vec(),
        sim[boundary..].to_vec(),
    );
    a.sort_unstable();
    b.sort_unstable();
    assert_eq!(a, b, "{what}: the tails hold different probes");
}

#[test]
fn agrees_with_the_reference_simulator_on_small_instances() {
    for seed in [1u64, 7] {
        let mut r = Rng(seed);
        for i in 0..2000 {
            let mut inst = small_instance(&mut r);
            round_weights(&mut inst);
            same_positive_prefix(&inst, &format!("small instance {i} of seed {seed}"));
        }
    }
}

#[test]
fn agrees_with_the_reference_simulator_on_large_instances() {
    for shape in shapes(20_000) {
        for seed in [1u64, 2] {
            let mut inst = generate(&shape, seed);
            round_weights(&mut inst);
            same_positive_prefix(&inst, &format!("{} seed {seed}", shape.name));
        }
    }
}

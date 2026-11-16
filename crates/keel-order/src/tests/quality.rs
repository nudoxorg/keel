//! How good the order is: against the exhaustive optimum, and the instance that motivated the rule.

use super::bridge::*;
use super::support::*;
use crate::offline;

/// Runs the simulator's small-instance experiment with the crate's order: `(mean, worst, share optimal)` of J over the optimum.
fn small_experiment(instances: usize, seed: u64) -> (f64, f64, f64) {
    let mut r = Rng(seed);
    let (mut worst, mut sum, mut optimal) = (1.0f64, 0.0f64, 0usize);
    for _ in 0..instances {
        let mut inst = small_instance(&mut r);
        round_weights(&mut inst);
        let opt = optimum(&inst);
        if opt <= 0.0 {
            continue;
        }
        let order = offline(&inputs_of(&inst));
        let mut covered = vec![false; inst.weight.len()];
        let mut built = vec![false; inst.setup.len()];
        let ratio = serial_j(&inst, order.as_slice(), &mut covered, &mut built) / opt;
        assert!(
            ratio > 1.0 - 1e-9,
            "an order beat the exhaustive optimum: {ratio}"
        );
        worst = worst.max(ratio);
        sum += ratio;
        if ratio < 1.0 + 1e-9 {
            optimal += 1;
        }
    }
    (
        sum / instances as f64,
        worst,
        100.0 * optimal as f64 / instances as f64,
    )
}

#[test]
fn within_a_quarter_of_the_exhaustive_optimum() {
    // The document's table (§4.4), same generator and seeds as `keel-sim small 2000 <seed>`:
    // seed 1: mean 1.0010, worst 1.08, optimal in 95.3%; seed 7: mean 1.0012, worst 1.12.
    let runs = [(1u64, 1.0010, 1.08), (7, 1.0012, 1.12)];
    let results: Vec<(f64, f64, f64)> = std::thread::scope(|s| {
        let hs: Vec<_> = runs
            .iter()
            .map(|&(seed, _, _)| s.spawn(move || small_experiment(2000, seed)))
            .collect();
        hs.into_iter()
            .map(|h| h.join().expect("experiment thread"))
            .collect()
    });
    for (&(seed, doc_mean, doc_worst), &(mean, worst, optimal)) in runs.iter().zip(&results) {
        println!(
            "small, 2000 instances, seed {seed}: mean {mean:.4} (document {doc_mean}), worst {worst:.4} (document {doc_worst}), optimal in {optimal:.1}%"
        );
        assert!(
            worst <= 1.25,
            "worst ratio {worst} exceeds 1.25 on seed {seed}"
        );
        assert!(mean < 1.003, "mean ratio {mean} on seed {seed}");
    }
}

/// Which instance of the seed-1 stream is the one §4.4 describes: found once with the simulator, pinned here.
const DEAR_BINARY_INDEX: usize = 838;

#[test]
fn cheap_test_in_a_dear_binary() {
    // §4.4: set-ups 839, 8.4, 0.10, 0.35 s; the best test per own second is the only useful test of the 839 s binary.
    // Set-up blind: J = 2157.8. The rule starts in the 0.10 s binary and reaches the optimum, J = 5.93.
    let mut r = Rng(1);
    let mut found = None;
    for i in 0..2000 {
        let inst = small_instance(&mut r);
        if (inst.setup.len() == 4)
            && (inst.setup[0] - 838.62).abs() < 0.01
            && (inst.setup[2] - 0.10).abs() < 0.005
        {
            found = Some((i, inst));
            break;
        }
    }
    let (index, mut inst) = found.expect("the instance of section 4.4 is in the seed-1 stream");
    println!("the 839 s instance is number {index} of the seed-1 stream");
    assert_eq!(index, DEAR_BINARY_INDEX);
    round_weights(&mut inst);
    let mut covered = vec![false; inst.weight.len()];
    let mut built = vec![false; inst.setup.len()];
    let opt = optimum(&inst);
    let order = offline(&inputs_of(&inst));
    let j = serial_j(&inst, order.as_slice(), &mut covered, &mut built);
    let blind = serial_j(&inst, &blind_order(&inst), &mut covered, &mut built);
    println!(
        "order {:?}: J = {j:.3} (document 5.93), optimum {opt:.3}, set-up blind J = {blind:.1} (document 2157.8)",
        order.as_slice()
    );
    assert_eq!(
        inst.bin_of[order.as_slice()[0] as usize],
        2,
        "the order must start in the 0.10 s binary"
    );
    assert!(
        (j - opt).abs() <= 1e-6 * opt,
        "J {j} is not the optimum {opt}"
    );
    assert!((j - 5.93).abs() < 0.005, "J {j} is not the document's 5.93");
    assert!(
        (blind - 2157.8).abs() < 0.5,
        "the set-up-blind J {blind} is not the document's 2157.8"
    );
}

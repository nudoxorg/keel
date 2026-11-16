//! Measurements for the report rather than assertions: how often the greedy bundle value of §4.2
//! rises when it should only fall (so that lazy evaluation's upper bound is not exact), and whether
//! the lazy order ever differs from the recomputed one.

use super::bridge::*;
use super::reference::naive_order;
use super::support::*;
use crate::{DoubtInputs, Pick, Rule, offline};

/// Whether any group's greedy density rose after a probe ran, over one one-worker run.
fn greedy_density_rose(inputs: &DoubtInputs) -> bool {
    let mut rule = Rule::new(inputs, &[]);
    let snap = |rule: &mut Rule<'_>| -> Vec<f64> {
        (0..rule.group_count())
            .map(|g| rule.group_density(g))
            .collect()
    };
    let mut prev = snap(&mut rule);
    loop {
        match rule.next() {
            Pick::Finished => return false,
            Pick::Idle => panic!("a lone worker idled"),
            Pick::SetUp(x) => {
                rule.up(x);
                prev = snap(&mut rule);
            }
            Pick::Run(_) => {
                let now = snap(&mut rule);
                if now.iter().zip(&prev).any(|(n, p)| n > p) {
                    return true;
                }
                prev = now;
            }
        }
    }
}

#[test]
#[ignore = "measurement: run with `cargo-stock test --release -p keel-order -- --ignored --nocapture how_often`"]
fn how_often_the_greedy_density_rises() {
    let mut families: Vec<(String, Vec<DoubtInputs>)> = Vec::new();
    for ties in [false, true] {
        let mut r = Rng(99);
        families.push((
            format!("shared set-ups, soft kills, ties={ties}"),
            (0..100_000).map(|_| random_inputs(&mut r, ties)).collect(),
        ));
    }
    let mut r = Rng(5);
    families.push((
        "the simulator's small instances".to_owned(),
        (0..100_000)
            .map(|_| {
                let mut inst = small_instance(&mut r);
                round_weights(&mut inst);
                inputs_of(&inst)
            })
            .collect(),
    ));
    for (name, all) in &families {
        let rose = all.iter().filter(|i| greedy_density_rose(i)).count();
        let differ = all
            .iter()
            .filter(|i| offline(i).as_slice() != naive_order(i).as_slice())
            .count();
        println!(
            "{name}: {} instances; a greedy density rose after a probe ran in {rose}; lazy order differs from the recomputed one in {differ}",
            all.len()
        );
    }
}

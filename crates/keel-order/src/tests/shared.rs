//! Beyond what the document measured: set-ups shared between groups (D2) and gates (§4.8 condition 2),
//! against the exhaustive optimum. The document guarantees nothing here (§4.3); these tests bound
//! how far the rule strays and the numbers go into the report.

use super::bridge::*;
use super::support::*;
use crate::{DoubtInputs, offline};

/// The least `J` over every order of the probes in which each probe follows the gate probes it waits
/// for. Certain kills only; a step is paid when the first probe that needs it starts, a gate step
/// not at all (its price is its probe's run).
fn optimum_of(inputs: &DoubtInputs) -> f64 {
    optimum_with_order(inputs).0
}

/// The same, with the first order that attains it.
fn optimum_with_order(inputs: &DoubtInputs) -> (f64, Vec<u32>) {
    fn go(
        inputs: &DoubtInputs,
        placed: &mut Vec<u32>,
        used: &mut Vec<bool>,
        best: &mut (f64, Vec<u32>),
    ) {
        if placed.len() == inputs.units as usize {
            let j = serial_j_of(inputs, placed);
            if j < best.0 {
                *best = (j, placed.clone());
            }
            return;
        }
        for u in 0..inputs.units {
            if used[u as usize] {
                continue;
            }
            let ready = inputs.needs.row(u as usize).iter().all(|&x| {
                match inputs.gate_of.iter().position(|g| *g == Some(x)) {
                    Some(g) => used[g],
                    None => true,
                }
            });
            if !ready {
                continue;
            }
            used[u as usize] = true;
            placed.push(u);
            go(inputs, placed, used, best);
            placed.pop();
            used[u as usize] = false;
        }
    }
    let mut best = (f64::INFINITY, Vec::new());
    go(
        inputs,
        &mut Vec::new(),
        &mut vec![false; inputs.units as usize],
        &mut best,
    );
    best
}

fn small_shared_instance(r: &mut Rng) -> DoubtInputs {
    let n = 5 + r.below(4);
    let steps = 2 + r.below(3);
    let classes = 3 + r.below(6);
    let mut b = Build::new();
    let cl: Vec<u32> = (0..classes)
        .map(|_| b.class((0.05 + r.unit()) as f32))
        .collect();
    let st: Vec<u32> = (0..steps)
        .map(|_| b.step(1000.0 * r.lognormal(2.0, 1.8)))
        .collect();
    for _ in 0..n {
        let mut kills: Vec<u32> = cl.iter().copied().filter(|_| r.below(4) == 0).collect();
        if kills.is_empty() {
            kills.push(cl[r.below(classes)]);
        }
        let mut needs = vec![st[r.below(steps)]];
        if r.below(2) == 0 {
            needs.push(st[r.below(steps)]);
        }
        b.probe(1000.0 * r.lognormal(0.5, 1.2), &kills, &needs);
    }
    b.done()
}

fn small_gate_instance(r: &mut Rng) -> DoubtInputs {
    let mut b = Build::new();
    let classes = 3 + r.below(5);
    let cl: Vec<u32> = (0..classes)
        .map(|_| b.class((0.05 + r.unit()) as f32))
        .collect();
    let worlds: Vec<u32> = (0..1 + r.below(2))
        .map(|_| b.step(1000.0 * r.lognormal(2.0, 1.8)))
        .collect();
    let mut left = 8usize;
    let kills = |r: &mut Rng| -> Vec<u32> {
        let mut k: Vec<u32> = cl.iter().copied().filter(|_| r.below(4) == 0).collect();
        if k.is_empty() {
            k.push(cl[r.below(cl.len())]);
        }
        k
    };
    for _ in 0..1 + r.below(2) {
        let w = worlds[r.below(worlds.len())];
        if left >= 3 && r.below(3) != 0 {
            let (_, g) = b.gate(1000.0 * r.lognormal(0.5, 1.2), &kills(r), &[w]);
            left -= 1;
            for _ in 0..1 + r.below(3).min(left.saturating_sub(1)) {
                if left == 0 {
                    break;
                }
                b.probe(1000.0 * r.lognormal(0.5, 1.2), &kills(r), &[w, g]);
                left -= 1;
            }
        }
    }
    for _ in 0..1 + r.below(3) {
        if left == 0 {
            break;
        }
        let w = worlds[r.below(worlds.len())];
        b.probe(1000.0 * r.lognormal(0.5, 1.2), &kills(r), &[w]);
        left -= 1;
    }
    b.done()
}

fn ratios(count: usize, seed: u64, make: fn(&mut Rng) -> DoubtInputs) -> (f64, f64, f64, usize) {
    let mut r = Rng(seed);
    let (mut worst, mut sum, mut optimal, mut n) = (1.0f64, 0.0f64, 0usize, 0usize);
    for _ in 0..count {
        let inputs = make(&mut r);
        let opt = optimum_of(&inputs);
        if !(opt > 0.0 && opt.is_finite()) {
            continue;
        }
        let order = offline(&inputs);
        let j = serial_j_of(&inputs, order.as_slice());
        let ratio = j / opt;
        assert!(
            ratio > 1.0 - 1e-9,
            "an order beat the exhaustive optimum: {ratio}\n{}",
            describe(&inputs)
        );
        worst = worst.max(ratio);
        sum += ratio;
        n += 1;
        if ratio < 1.0 + 1e-9 {
            optimal += 1;
        }
    }
    (sum / n as f64, worst, 100.0 * optimal as f64 / n as f64, n)
}

#[test]
fn shared_setups_against_the_exhaustive_optimum() {
    // D2 of the document: confirmed if the worst ratio is at most 1.5 over 4,000 instances, refuted by any ratio above 3.
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| ratios(2000, 31, small_shared_instance));
        let b = s.spawn(|| ratios(2000, 32, small_shared_instance));
        (a.join().expect("thread"), b.join().expect("thread"))
    });
    let ((mean, worst, optimal, n), (mean2, worst2, optimal2, n2)) = (a, b);
    println!(
        "D2, set-ups shared between groups, {n}+{n2} instances: mean {mean:.4} / {mean2:.4}, worst {worst:.3} / {worst2:.3}, optimal in {optimal:.1}% / {optimal2:.1}%"
    );
    assert!(
        worst.max(worst2) < 3.0,
        "the rule is more than three times the optimum with shared set-ups"
    );
}

#[test]
fn gates_against_the_precedence_constrained_optimum() {
    // The three-level instance D2 gains in §4.8: world, plain cell, twins.
    let (a, b) = std::thread::scope(|s| {
        let a = s.spawn(|| ratios(2000, 41, small_gate_instance));
        let b = s.spawn(|| ratios(2000, 42, small_gate_instance));
        (a.join().expect("thread"), b.join().expect("thread"))
    });
    let ((mean, worst, optimal, n), (mean2, worst2, optimal2, n2)) = (a, b);
    println!(
        "D2, world -> cell -> twins, {n}+{n2} instances: mean {mean:.4} / {mean2:.4}, worst {worst:.3} / {worst2:.3}, optimal in {optimal:.1}% / {optimal2:.1}%"
    );
    assert!(
        worst.max(worst2) < 3.0,
        "the rule is more than three times the optimum with gates"
    );
}

/// What an order does, step by step: when each set-up is paid, when each probe finishes, which classes it detects first.
fn timeline(inputs: &DoubtInputs, order: &[u32]) -> String {
    let mut paid = vec![false; inputs.steps as usize];
    let mut seen = vec![false; inputs.class_mass.len()];
    let (mut clock, mut j, mut text) = (0.0f64, 0.0f64, String::new());
    for &t in order {
        for &x in inputs.needs.row(t as usize) {
            if !std::mem::replace(&mut paid[x as usize], true) && !inputs.gate_of.contains(&Some(x))
            {
                clock += inputs.setup_ms[x as usize].millis();
                text += &format!(
                    "    pay step {x}: {:.1} ms -> clock {clock:.1}\n",
                    inputs.setup_ms[x as usize].millis()
                );
            }
        }
        clock += inputs.cost_ms[t as usize].millis();
        let mut new = Vec::new();
        for &(c, _) in inputs.kills.row(t as usize) {
            if !std::mem::replace(&mut seen[c as usize], true) {
                j += f64::from(inputs.class_mass[c as usize]) * clock;
                new.push(c);
            }
        }
        text += &format!(
            "    run probe {t}: {:.1} ms -> clock {clock:.1}, first detects classes {new:?}\n",
            inputs.cost_ms[t as usize].millis()
        );
    }
    format!("{text}    J = {j:.3}")
}

#[test]
#[ignore = "prints the gate instance where the rule was worst against the exhaustive optimum (D2d): `cargo-stock test -p keel-order -- --ignored --nocapture print_the_worst_gate_instance`"]
fn print_the_worst_gate_instance() {
    let (mut worst, mut shown) = (0.0f64, None);
    for seed in [41u64, 42] {
        let mut r = Rng(seed);
        for index in 0..2000 {
            let inputs = small_gate_instance(&mut r);
            let (opt, best_order) = optimum_with_order(&inputs);
            if !(opt > 0.0 && opt.is_finite()) {
                continue;
            }
            let order = offline(&inputs).into_vec();
            let ratio = serial_j_of(&inputs, &order) / opt;
            if ratio > worst {
                worst = ratio;
                shown = Some((seed, index, inputs, order, best_order, opt));
            }
        }
    }
    let (seed, index, inputs, order, best_order, opt) = shown.expect("some instance");
    println!(
        "the gate instance where the rule was worst: {worst:.3} times the exhaustive optimum (seed {seed}, instance {index} of 2,000)"
    );
    println!("{}", describe(&inputs));
    println!(
        "  the rule's order {order:?}:\n{}",
        timeline(&inputs, &order)
    );
    println!(
        "  the optimal order {best_order:?}:\n{}",
        timeline(&inputs, &best_order)
    );
    println!("  optimum J = {opt:.3}");
}

#[test]
fn a_twin_that_pays_for_its_world() {
    // D2d's worst instance before §4.8 priced a nested bundle against the outermost cold bundle: seed 42,
    // instance 384 of 2,000, where the rule was 1.789 times the optimum. World 0 costs 9.7 s and world 1
    // 26.9 s. Cell 0 (the gate, 111 ms) is the gate of twin 2 (259 ms, three classes). Judged against
    // the cell alone, the twin dilutes the bundle (8.0e-3 against 6.7e-3 per ms) and was left out, so world
    // 0 was priced at 9.07e-5 and lost to world 1's 9.8e-5; judged against world 0's bundle, the twin pays
    // (2.47e-4) and world 0 goes first.
    let mut r = Rng(42);
    let mut inputs = small_gate_instance(&mut r);
    for _ in 0..384 {
        inputs = small_gate_instance(&mut r);
    }
    assert_eq!(
        inputs.units, 8,
        "the generator no longer produces the instance of D2d"
    );
    let order = offline(&inputs);
    let first = order.as_slice()[0];
    assert!(
        inputs.needs.row(first as usize).contains(&0),
        "the order starts with probe {first}, outside world 0: {:?}",
        order.as_slice()
    );
    let (opt, _) = optimum_with_order(&inputs);
    let ratio = serial_j_of(&inputs, order.as_slice()) / opt;
    println!(
        "seed 42, instance 384: the rule is {ratio:.3} times the exhaustive optimum (1.789 before the change)"
    );
    assert!(ratio <= 1.2, "J is {ratio} times the optimum");
}

#[test]
fn a_leaf_two_gates_deep_pays_for_its_world() {
    // §4.8 at depth three: world A (cold, 10 s) -> gate 1 -> gate 2 -> a leaf. Each gate is denser than the
    // leaf behind it (5e-3 and 6e-3 against 4e-3 per ms), so judged against its own cost a gate leaves its
    // child out, at the second level too; judged against the running totals of world A's bundle the leaf
    // pays (about 2.9e-4 against world B's 1.5e-4). A rule that used the enclosing totals for the first
    // level only would leave the leaf out, price world A at about 1.1e-4 and set up world B first.
    let mut b = Build::new();
    let (c1, c2, c3, cd) = (b.class(0.5), b.class(0.6), b.class(2.0), b.class(3.0));
    let (a, w) = (b.step(10_000.0), b.step(20_000.0));
    let (g1, s1) = b.gate(100.0, &[c1], &[a]);
    let (g2, s2) = b.gate(100.0, &[c2], &[a, s1]);
    let leaf = b.probe(500.0, &[c3], &[a, s1, s2]);
    let other = b.probe(100.0, &[cd], &[w]);
    let inputs = b.done();
    inputs.validate().expect("a valid chain");
    let order = offline(&inputs);
    assert_eq!(
        order.as_slice(),
        &[g1, g2, leaf, other],
        "world A, with its whole chain, goes first"
    );
    let ratio = serial_j_of(&inputs, order.as_slice()) / optimum_of(&inputs);
    assert!(ratio < 1.0 + 1e-9, "J is {ratio} times the optimum");
}

#[test]
fn rich_twins_behind_a_poor_cell() {
    // §4.8 point 2: inside a bundle a gate is ordered by its own bundle (the gate and its first k children
    // over their own costs, greatest over k), not by its own probe alone and not by the composite as cut under
    // the enclosing totals. World: a cold 1 s set-up; a cheap cell (10 ms) that detects almost nothing
    // itself; two twins, one rich (1.0 for 10 ms) and one poor (0.1 for 10 ms); and a plain probe of middling
    // density (0.4 for 10 ms, 0.04 per ms). The cell with its twins is 0.0505 per ms (cell and the rich
    // twin), above the middling probe; by the cell alone it is 0.001, and as cut under the world's totals,
    // which also bring the poor twin, 0.037, both below it.
    let mut b = Build::new();
    let (ca, cb, cc, cd) = (b.class(0.01), b.class(1.0), b.class(0.1), b.class(0.4));
    let world = b.step(1000.0);
    let (cell, gate) = b.gate(10.0, &[ca], &[world]);
    let rich = b.probe(10.0, &[cb], &[world, gate]);
    let poor = b.probe(10.0, &[cc], &[world, gate]);
    let middling = b.probe(10.0, &[cd], &[world]);
    let inputs = b.done();
    inputs.validate().expect("valid");
    let mut rule = crate::Rule::new(&inputs, &[]);
    let plan = rule.bundle_plan(0);
    assert_eq!(
        plan,
        vec![cell, rich, poor, middling],
        "the gate with its twins must be ordered before the middling probe"
    );
    let order = offline(&inputs);
    let (opt, best) = optimum_with_order(&inputs);
    let j = serial_j_of(&inputs, order.as_slice());
    assert!(
        (j - opt).abs() <= 1e-9 * opt,
        "J {j} is not the optimum {opt}: the rule {:?}, the optimum {best:?}",
        order.as_slice()
    );
}

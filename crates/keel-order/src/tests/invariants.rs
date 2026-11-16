//! The invariants of §4.2 (B1 to B4), §2.3 (M1) and §4.6 (O1, O2), and determinism.
//!
//! B2 and B3 are the document's corrected ones (0f6354b): about the best *subset* of a site's
//! probes, and about how the greedy prefix of §4.2 brackets it. B4 is a measurement.

use super::bridge::*;
use super::reference::{naive_order, sites_of};
use super::support::*;
use crate::{DoubtInputs, Order, OrderError, Pick, Rule, offline};

fn instances(seed: u64, count: usize) -> Vec<DoubtInputs> {
    let mut r = Rng(seed);
    (0..count)
        .map(|i| random_inputs(&mut r, i % 2 == 0))
        .collect()
}

/// What just happened to the rule, as the watcher sees it.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Ev {
    /// A probe was started.
    Run,
    /// A step was picked to be set up.
    SetUp,
    /// A step came up.
    Up(u32),
}

/// A site's best subset, found by enumeration.
#[derive(Clone, Copy, Debug)]
struct Best {
    /// `max_T F(T | done) / (B + C(T))`.
    density: f64,
    /// `α' = (1 − 1/e)(B + L)/(B + L + c_max)` of §4.3 step 3 (whose two readings, fixed there, are used here), for the densest `T*` with the
    /// greatest run cost `L` (the strictest of the densest bundles), `c_max` the dearest probe
    /// that still detects something.
    alpha: f64,
}

/// The pricing before and after one event.
struct Obs<'o> {
    ev: Ev,
    /// The rule's greedy-prefix density per site (group) before and after.
    prev: &'o [f64],
    now: &'o [f64],
    opt_prev: &'o [Best],
    opt_now: &'o [Best],
}

/// The densest bundle of a site over all subsets of its undone probes. Brute force, for sites of a dozen probes.
fn best_subset(inputs: &DoubtInputs, rule: &Rule<'_>, steps: &[u32], members: &[u32]) -> Best {
    let b: f64 = steps
        .iter()
        .filter(|&&x| !rule.step_is_up(x))
        .map(|&x| inputs.setup_ms[x as usize].millis())
        .sum();
    let live: Vec<u32> = members
        .iter()
        .copied()
        .filter(|&u| !rule.unit_done(u))
        .collect();
    assert!(
        live.len() <= 12,
        "enumeration is for sites of at most 12 probes"
    );
    // §4.3 step 3 fixes two readings, and this takes the strictest of each. `c_max`: the greatest cost among
    // the site's probes whose gain is positive at this moment (a probe that detects nothing is in no densest
    // subset, and the greedy reaches run cost `L` before it reaches one).
    let c_max = live
        .iter()
        .filter(|&&u| rule.unit_gain(u) > 0.0)
        .map(|&u| inputs.cost_ms[u as usize].millis())
        .fold(0.0f64, f64::max);
    let mut found: Vec<(f64, f64)> = Vec::new(); // (density, run cost)
    let mut best = 0.0f64;
    for mask in 1u32..1 << live.len() {
        let mut keep = vec![1.0f64; inputs.class_mass.len()];
        let mut run = 0.0;
        for (i, &u) in live.iter().enumerate() {
            if mask >> i & 1 == 1 {
                run += inputs.cost_ms[u as usize].millis();
                for &(c, q) in inputs.kills.row(u as usize) {
                    keep[c as usize] *= 1.0 - f64::from(q);
                }
            }
        }
        let gain: f64 = rule
            .miss()
            .iter()
            .zip(&keep)
            .map(|(&m, &k)| f64::from(m) * (1.0 - k))
            .sum();
        let d = gain / (b + run);
        best = best.max(d);
        found.push((d, run));
    }
    // `T*`: when several subsets are equally dense, the one of greatest run cost `L`; the argument holds
    // for any of them and this one gives the largest `α'`.
    let l = found
        .iter()
        .filter(|(d, _)| *d >= best * (1.0 - 1e-12))
        .map(|&(_, run)| run)
        .fold(0.0f64, f64::max);
    let alpha = (1.0 - (-1.0f64).exp()) * (b + l) / (b + l + c_max);
    Best {
        density: best,
        alpha,
    }
}

/// Runs `inputs` with one worker, handing the pricing before and after every event to `watch`.
fn watch_run(inputs: &DoubtInputs, mut watch: impl FnMut(&Obs<'_>, &mut Rule<'_>)) {
    let sites = sites_of(inputs);
    let mut rule = Rule::new(inputs, &[]);
    let snapshot = |rule: &mut Rule<'_>| -> (Vec<f64>, Vec<Best>) {
        let dens = (0..rule.group_count())
            .map(|g| rule.group_density(g))
            .collect();
        let opt = sites
            .iter()
            .map(|(steps, members)| best_subset(inputs, rule, steps, members))
            .collect();
        (dens, opt)
    };
    let (mut prev, mut opt_prev) = snapshot(&mut rule);
    loop {
        let ev = match rule.next() {
            Pick::Finished => return,
            Pick::Idle => panic!("a lone worker idled"),
            Pick::Run(_) => Ev::Run,
            Pick::SetUp(x) => {
                let (now, opt_now) = snapshot(&mut rule);
                watch(
                    &Obs {
                        ev: Ev::SetUp,
                        prev: &prev,
                        now: &now,
                        opt_prev: &opt_prev,
                        opt_now: &opt_now,
                    },
                    &mut rule,
                );
                (prev, opt_prev) = (now, opt_now);
                rule.up(x);
                Ev::Up(x)
            }
        };
        let (now, opt_now) = snapshot(&mut rule);
        watch(
            &Obs {
                ev,
                prev: &prev,
                now: &now,
                opt_prev: &opt_prev,
                opt_now: &opt_now,
            },
            &mut rule,
        );
        (prev, opt_prev) = (now, opt_now);
    }
}

const SLACK: f64 = 1e-9;

#[test]
fn best_subset_density_never_rises() {
    // B2. On sites of at most 12 probes, the best-subset density never rises after a pick, while no
    // step of the site comes up. Two drives: arbitrary picks with no step ever coming up, and the
    // rule's own run, where a rise is allowed only after `up` of a step of that very site.
    let (mut after_picks, mut after_events) = (0usize, 0usize);
    let mut r = Rng(12);
    for inputs in instances(2, 600) {
        let sites = sites_of(&inputs);
        let mut rule = Rule::new(&inputs, &[]);
        let mut seq: Vec<u32> = (0..inputs.units).collect();
        for i in (1..seq.len()).rev() {
            seq.swap(i, r.below(i + 1));
        }
        let at = |rule: &Rule<'_>| -> Vec<Best> {
            sites
                .iter()
                .map(|(s, m)| best_subset(&inputs, rule, s, m))
                .collect()
        };
        let mut before = at(&rule);
        for &pick in &seq {
            rule.force_run(pick);
            let now = at(&rule);
            for (s, (b, n)) in before.iter().zip(&now).enumerate() {
                after_picks += 1;
                assert!(
                    n.density <= b.density * (1.0 + SLACK),
                    "the best subset of site {s} rose from {} to {} after probe {pick} ran\n{}",
                    b.density,
                    n.density,
                    describe(&inputs)
                );
            }
            before = now;
        }
    }
    let mut rises = 0usize;
    for inputs in instances(3, 600) {
        watch_run(&inputs, |o, rule| {
            for g in 0..rule.group_count() {
                after_events += 1;
                if o.opt_now[g].density > o.opt_prev[g].density * (1.0 + SLACK) {
                    rises += 1;
                    let Ev::Up(x) = o.ev else {
                        panic!(
                            "the best subset of a site rose after {:?}\n{}",
                            o.ev,
                            describe(&inputs)
                        )
                    };
                    assert!(
                        rule.group_has_step(g, x),
                        "the best subset of a site rose after step {x} came up, but the site does not use it"
                    );
                }
            }
        });
    }
    println!(
        "B2: {after_picks} (site, arbitrary pick) pairs with no step coming up, none rose; {after_events} (site, event) pairs in the rule's own run, {rises} rises, each after `up` of a step of that site"
    );
    assert!(
        rises > 0,
        "the instances never exercised a rise, so the second half proves nothing"
    );
}

#[test]
fn prefix_density_brackets_best_subset() {
    // B3. `α' · best ≤ density ≤ best` on sites of at most 12 probes, at every point of the rule's run
    // and after arbitrary picks. The lower bound is the author's derivation (§4.3 step 3) under test;
    // it carries no slack. Its two readings are the ones §4.3 step 3 fixes: `T*` is the densest subset of
    // greatest run cost, and `c_max` is over the probes whose gain is positive at that moment.
    let (mut checked, mut equal, mut tightest) = (0usize, 0usize, f64::INFINITY);
    let mut rose = 0usize;
    let mut check = |inputs: &DoubtInputs, dens: f64, b: Best, what: &str| {
        checked += 1;
        if b.density <= 0.0 {
            assert!(
                dens <= 0.0,
                "{what}: positive greedy density where no subset detects anything"
            );
            return;
        }
        // The rule keeps miss masses in f32 and rounds at every tentative pick; the enumeration multiplies in
        // f64 from the same masses. The upper bound is therefore checked to f32 rounding, the lower with no slack.
        assert!(
            dens <= b.density * (1.0 + 1e-6),
            "{what}: greedy density {dens} above the best subset {}\n{}",
            b.density,
            describe(inputs)
        );
        assert!(
            dens >= b.alpha * b.density,
            "{what}: greedy density {dens} below α'·best = {} · {} = {}\n{}",
            b.alpha,
            b.density,
            b.alpha * b.density,
            describe(inputs)
        );
        if dens >= b.density * (1.0 - 1e-12) {
            equal += 1;
        }
        tightest = tightest.min(dens / (b.alpha * b.density));
    };
    let mut r = Rng(13);
    let mut all = instances(3, 600);
    all.extend((0..300).map(|_| private_inputs(&mut r)));
    let mut sim = Rng(1);
    all.extend((0..300).map(|_| {
        let mut inst = small_instance(&mut sim);
        round_weights(&mut inst);
        inputs_of(&inst)
    }));
    for inputs in &all {
        let sites = sites_of(inputs);
        watch_run(inputs, |o, rule| {
            for g in 0..rule.group_count() {
                check(inputs, o.now[g], o.opt_now[g], "in the rule's run");
                if o.now[g] > o.prev[g] {
                    rose += 1;
                }
            }
            let _ = o.ev;
        });
        let mut rule = Rule::new(inputs, &[]);
        let mut seq: Vec<u32> = (0..inputs.units).collect();
        for i in (1..seq.len()).rev() {
            seq.swap(i, r.below(i + 1));
        }
        for &pick in &seq {
            rule.force_run(pick);
            for (g, (steps, members)) in sites.iter().enumerate() {
                let b = best_subset(inputs, &rule, steps, members);
                let d = rule.group_density(g);
                check(inputs, d, b, "after arbitrary picks");
            }
        }
    }
    println!(
        "B3: {checked} (site, moment) checks on {} instances; the bracket held every time; greedy equals the best subset in {equal}; the tightest lower bound had {:.2}x of margin over α'·best; the greedy density rose {rose} times in the rule's runs (allowed, and inside the bracket)",
        all.len(),
        tightest
    );
}

#[test]
fn lazy_order_against_recomputed_order() {
    // B4, a measurement: on 1,000 fixed-seed instances, half with exact ties, how many positions the heap
    // order and the order with every density recomputed before every pick disagree at, and the largest
    // ratio of the two `J`. Fails only if `J` differs by more than 1%.
    let all = instances(4, 1000);
    let (mut differing_instances, mut positions, mut worst) = (0usize, 0usize, 1.0f64);
    for inputs in &all {
        let lazy = offline(inputs);
        let naive = naive_order(inputs);
        let wrong = lazy
            .as_slice()
            .iter()
            .zip(&naive)
            .filter(|(a, b)| a != b)
            .count();
        positions += wrong;
        if wrong > 0 {
            differing_instances += 1;
        }
        let (jl, jn) = (
            additive_j(inputs, lazy.as_slice()),
            additive_j(inputs, &naive),
        );
        if jl > 0.0 && jn > 0.0 {
            worst = worst.max(jl / jn).max(jn / jl);
        }
    }
    println!(
        "B4: {} instances ({} with integer costs, masses and reach so that densities tie): the orders differ at {positions} positions in {differing_instances} instances; largest ratio of the two J is {worst:.6}",
        all.len(),
        all.len() / 2
    );
    assert!(worst <= 1.01, "J differs by more than 1%: {worst}");
}

#[test]
fn a_duplicate_moves_detection_share_within_its_bound() {
    // M1 with its bound (§2.3). Adding a copy of a test t in S raises each class's detection by
    // m·P·q with P ≤ 1 − q, so by at most Σ m q (1 − q) over the classes t kills; any number of copies by
    // at most Σ m (1 − q). Exactly zero when every q is 1.
    let mut r = Rng(5);
    let (mut worst_one, mut worst_many, mut cases) = (0.0f64, 0.0f64, 0usize);
    for k in 0..300 {
        let inputs = random_inputs(&mut r, k % 2 == 0);
        let n = inputs.units;
        let certain = {
            let mut c = inputs.clone();
            for e in &mut c.kills.items {
                e.1 = 1.0;
            }
            c
        };
        for base in [&inputs, &certain] {
            for t in 0..n {
                let row = base.kills.row(t as usize);
                let one: f64 = row
                    .iter()
                    .map(|&(c, q)| {
                        f64::from(base.class_mass[c as usize]) * f64::from(q) * (1.0 - f64::from(q))
                    })
                    .sum();
                let many: f64 = row
                    .iter()
                    .map(|&(c, q)| f64::from(base.class_mass[c as usize]) * (1.0 - f64::from(q)))
                    .sum();
                for _ in 0..4 {
                    let mut set: Vec<u32> = (0..n).filter(|_| r.below(2) == 0).collect();
                    if !set.contains(&t) {
                        set.push(t);
                    }
                    let with = |copies: usize| -> f64 {
                        let mut b = base.clone();
                        let mut s = set.clone();
                        for _ in 0..copies {
                            b.units += 1;
                            let mut rows: Vec<Vec<(u32, f32)>> = (0..b.units - 1)
                                .map(|u| b.kills.row(u as usize).to_vec())
                                .collect();
                            rows.push(row.to_vec());
                            b.kills = crate::Csr::from_rows(rows);
                            s.push(b.units - 1);
                        }
                        detection_share(&b, &s)
                    };
                    let (d0, d1, d3) = (detection_share(base, &set), with(1), with(3));
                    cases += 1;
                    let (delta1, delta3) = (d1 - d0, d3 - d0);
                    assert!(
                        delta1 >= -1e-12 && delta1 <= one + 1e-9,
                        "one copy moved the share by {delta1}, bound {one}"
                    );
                    assert!(
                        delta3 >= -1e-12 && delta3 <= many + 1e-9,
                        "three copies moved the share by {delta3}, bound {many}"
                    );
                    if base.kills.items.iter().all(|e| e.1 == 1.0) {
                        assert_eq!(d0, d1, "a copy changed the share with every q = 1");
                        assert_eq!(d0, d3);
                    }
                    let total: f64 = base.class_mass.iter().map(|&m| f64::from(m)).sum();
                    worst_one = worst_one.max(delta1 / total);
                    worst_many = worst_many.max(delta3 / total);
                }
            }
        }
    }
    println!(
        "M1: {cases} cases; exactly zero at q = 1; with free soft q the largest change was {:.1}% (one copy) and {:.1}% (three) of the total class mass",
        100.0 * worst_one,
        100.0 * worst_many
    );
}

#[test]
fn the_bound_of_the_model_for_a_unit_with_measured_mutants() {
    // §2.3's numbers: with ω0 = 0.09 and exact bits (ε = 0.02) a copy moves c_u by at most 0.04 and any
    // number by at most 0.11; with stale bits (ε = 0.10) 0.10 and 0.18. Checked on the formula and on a
    // unit built to those weights, where the classes z ≥ 1 have q = 1 − ε and class 0 has q = d.
    let w0 = 0.09f64;
    let bound = |eps: f64, d: f64| {
        (
            (1.0 - w0) * eps * (1.0 - eps) + w0 * d * (1.0 - d),
            (1.0 - w0) * eps + w0,
        )
    };
    assert!(bound(0.02, 0.5).0 <= 0.0405 && bound(0.02, 0.5).1 <= 0.1085);
    assert!(bound(0.10, 0.5).0 <= 0.1050 && bound(0.10, 0.5).1 <= 0.1815);
    for (eps, d) in [(0.02f64, 0.3f64), (0.10, 0.5), (0.02, 0.9)] {
        // 20 mutants in 4 classes of 5, kappa = 2: weights 5/22 each, class 0 has 2/22.
        let mut b = Build::new();
        let masses = [5.0 / 22.0, 5.0 / 22.0, 5.0 / 22.0, 5.0 / 22.0, 2.0 / 22.0];
        let cl: Vec<u32> = masses.iter().map(|&m| b.class(m as f32)).collect();
        let x = b.step(1.0);
        let t = b.probe(1.0, &cl, &[x]);
        let mut inputs = b.done();
        for (c, e) in inputs.kills.items.iter_mut().enumerate() {
            e.1 = if c < 4 { (1.0 - eps) as f32 } else { d as f32 };
        }
        let mut with = inputs.clone();
        with.units += 1;
        with.kills =
            crate::Csr::from_rows([inputs.kills.row(0).to_vec(), inputs.kills.row(0).to_vec()]);
        with.cost_ms.push(inputs.cost_ms[0].clone());
        with.needs = crate::Csr::from_rows([vec![x], vec![x]]);
        with.reach.push(0);
        let delta = detection_share(&with, &[t, 1]) - detection_share(&inputs, &[t]);
        let w0 = 2.0 / 22.0;
        let one = (1.0 - w0) * eps * (1.0 - eps) + w0 * d * (1.0 - d);
        assert!(
            delta <= one + 1e-6,
            "eps {eps}, d {d}: a copy moved the share by {delta}, bound {one}"
        );
        assert!(delta > 0.0);
    }
}

#[test]
fn a_non_killer_has_no_entry_in_the_kill_row() {
    // §2.3 after the ruling: a test that ran against a class and did not kill it has q = 0, which is no
    // entry. A row with q = 0 (or a small epsilon standing in for it) is not how that is said; q = 0 is refused.
    let mut b = Build::new();
    let (c0, c1) = (b.class(1.0), b.class(1.0));
    let x = b.step(1.0);
    b.probe(1.0, &[c0, c1], &[x]);
    let mut inputs = b.done();
    assert_eq!(inputs.validate(), Ok(()));
    inputs.kills.items[1].1 = 0.0;
    assert!(
        matches!(inputs.validate(), Err(crate::InputsError::BadKill { unit: 0, class: 1, q }) if q == 0.0)
    );
    // And the generators emit no such entries: every kill is certain or at least 0.1, standing for a
    // measured kill (1 − ε), a stale bit, or the class-0 fallback d(t, u), never for a non-killer.
    let mut r = Rng(77);
    let mut smallest = 1.0f32;
    for k in 0..2000 {
        let inputs = match k % 3 {
            0 => random_inputs(&mut r, true),
            1 => random_inputs(&mut r, false),
            _ => private_inputs(&mut r),
        };
        for &(_, q) in &inputs.kills.items {
            smallest = smallest.min(q);
        }
    }
    assert!(
        smallest >= 0.1,
        "a generator emitted a kill with q = {smallest}"
    );
}

#[test]
fn one_worker_online_equals_offline() {
    // O2. `offline` is the rule driven by one worker, so this holds by construction; the test pins it
    // for private set-ups, shared set-ups, the simulator's instances and gates, and against a second,
    // independent driver written in the test.
    let mut cases = [0usize; 4];
    let mut r = Rng(7);
    for _ in 0..800 {
        let inputs = private_inputs(&mut r);
        assert_eq!(
            serial_online(&inputs),
            offline(&inputs).as_slice(),
            "private set-ups"
        );
        cases[0] += 1;
    }
    for inputs in instances(8, 1000) {
        assert_eq!(
            serial_online(&inputs),
            offline(&inputs).as_slice(),
            "shared set-ups\n{}",
            describe(&inputs)
        );
        cases[1] += 1;
    }
    let mut r = Rng(1);
    for _ in 0..500 {
        let mut inst = small_instance(&mut r);
        round_weights(&mut inst);
        let inputs = inputs_of(&inst);
        assert_eq!(
            serial_online(&inputs),
            offline(&inputs).as_slice(),
            "simulator instance"
        );
        cases[2] += 1;
    }
    let mut r = Rng(21);
    for _ in 0..1000 {
        let inputs = super::gates::gate_instance(&mut r);
        assert_eq!(
            serial_online(&inputs),
            offline(&inputs).as_slice(),
            "gates\n{}",
            describe(&inputs)
        );
        cases[3] += 1;
    }
    println!(
        "O2: identical Run sequences on {} private, {} shared, {} simulator and {} gate instances",
        cases[0], cases[1], cases[2], cases[3]
    );
}

#[test]
fn gain_never_rises() {
    // B1, over random pick sequences, certain and soft kills, and ties.
    let mut r = Rng(11);
    for inputs in instances(1, 400) {
        let mut rule = Rule::new(&inputs, &[]);
        let mut seq: Vec<u32> = (0..inputs.units).collect();
        for i in (1..seq.len()).rev() {
            seq.swap(i, r.below(i + 1));
        }
        for &pick in &seq {
            let before: Vec<f64> = (0..inputs.units).map(|u| rule.unit_gain(u)).collect();
            rule.force_run(pick);
            for u in 0..inputs.units {
                assert!(
                    rule.unit_gain(u) <= before[u as usize],
                    "the gain of probe {u} rose after probe {pick} ran"
                );
            }
        }
    }
}

#[test]
fn a_copy_of_a_test_is_never_picked_for_its_gain() {
    // The rule's side of M1: after the original has run, its copy detects nothing and waits for the tail.
    let mut r = Rng(6);
    for k in 0..300 {
        let mut inputs = random_inputs(&mut r, k % 2 == 0);
        for row in 0..inputs.kills.items.len() {
            inputs.kills.items[row].1 = 1.0;
        }
        let t = r.below(inputs.units as usize) as u32;
        let n = inputs.units;
        inputs.units += 1;
        let mut rows: Vec<Vec<(u32, f32)>> = (0..n)
            .map(|u| inputs.kills.row(u as usize).to_vec())
            .collect();
        rows.push(rows[t as usize].clone());
        let mut needs: Vec<Vec<u32>> = (0..n)
            .map(|u| inputs.needs.row(u as usize).to_vec())
            .collect();
        needs.push(needs[t as usize].clone());
        inputs.kills = crate::Csr::from_rows(rows);
        inputs.needs = crate::Csr::from_rows(needs);
        inputs.cost_ms.push(inputs.cost_ms[t as usize].clone());
        inputs.reach.push(inputs.reach[t as usize]);
        if inputs.kills.row(t as usize).is_empty() {
            continue;
        }
        let order = serial_online(&inputs);
        let (a, b) = (
            order.iter().position(|&u| u == t).unwrap(),
            order.iter().position(|&u| u == n).unwrap(),
        );
        let before: Vec<u32> = order[..a.max(b)].to_vec();
        // Whichever of the two came second detected nothing new.
        assert!(
            detection_share(&inputs, &before) == detection_share(&inputs, &order[..a.max(b) + 1]),
            "the second of two copies still added share"
        );
    }
}

#[test]
fn order_is_exactly_the_run_set() {
    // O1.
    let run: Vec<u32> = vec![3, 5, 8];
    assert_eq!(
        Order::new(&run, vec![5, 3, 8]).unwrap().as_slice(),
        &[5, 3, 8]
    );
    assert_eq!(
        Order::new(&run, vec![5, 3]),
        Err(OrderError::Missing { unit: 8 })
    );
    assert_eq!(
        Order::new(&run, vec![5, 3, 5, 8]),
        Err(OrderError::Repeated { unit: 5 })
    );
    assert_eq!(
        Order::new(&run, vec![5, 3, 8, 9]),
        Err(OrderError::NotInRunSet { unit: 9 })
    );
    for e in [
        OrderError::Missing { unit: 8 },
        OrderError::Repeated { unit: 5 },
        OrderError::NotInRunSet { unit: 9 },
    ] {
        let text = e.to_string();
        assert!(text.contains(&match e {
            OrderError::Missing { unit }
            | OrderError::Repeated { unit }
            | OrderError::NotInRunSet { unit } => unit.to_string(),
        }));
    }
    // And what the rule produces is exactly the run set.
    for inputs in instances(9, 200) {
        let all: Vec<u32> = (0..inputs.units).collect();
        Order::new(&all, offline(&inputs).into_vec()).expect("offline is a permutation");
        let mut online = serial_online(&inputs);
        online.sort_unstable();
        assert_eq!(online, all);
    }
}

#[test]
fn same_inputs_same_order() {
    let mut r = Rng(10);
    for _ in 0..200 {
        // No two probes tie on density (continuous values), so the only thing that could move the order is numbering.
        let inputs = random_inputs(&mut r, false);
        let base = offline(&inputs).into_vec();
        let n = inputs.units as usize;
        // Across threads.
        let results: Vec<Vec<u32>> = std::thread::scope(|s| {
            let hs: Vec<_> = (0..4)
                .map(|_| s.spawn(|| offline(&inputs).into_vec()))
                .collect();
            hs.into_iter().map(|h| h.join().unwrap()).collect()
        });
        assert!(results.iter().all(|x| *x == base));
        // Across a shuffle of the unit numbering, mapped back.
        let mut perm: Vec<u32> = (0..n as u32).collect();
        for i in (1..n).rev() {
            perm.swap(i, r.below(i + 1));
        }
        let shuffled = permuted(&inputs, &perm);
        let mut inv = vec![0u32; n];
        for (u, &p) in perm.iter().enumerate() {
            inv[p as usize] = u as u32;
        }
        let back: Vec<u32> = offline(&shuffled)
            .as_slice()
            .iter()
            .map(|&p| inv[p as usize])
            .collect();
        assert_eq!(back, base, "renumbering the probes changed the order");
        // Two runs, same sequence of calls, same results.
        assert_eq!(serial_online(&inputs), serial_online(&inputs));
    }
}

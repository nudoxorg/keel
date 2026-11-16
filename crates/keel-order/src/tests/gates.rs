//! Gate probes (§4.8 condition 2), stranding, idling, the zero-gain tail, and what the rule refuses.

use std::panic::{AssertUnwindSafe, catch_unwind};

use super::bridge::*;
use super::support::*;
use crate::{Csr, DoubtInputs, InputsError, Pick, Rule, offline};

/// A world, a plain cell (a gate) with two twins, and an unrelated binary with one probe.
/// Probes: 0 = cell, 1 and 2 = twins, 3 = a plain probe in the world, 4 = a probe in the other binary.
fn cell_with_twins() -> (DoubtInputs, u32, u32) {
    let mut b = Build::new();
    let (c0, c1, c2, c3, c4) = (
        b.class(0.1),
        b.class(0.5),
        b.class(0.5),
        b.class(0.2),
        b.class(0.3),
    );
    let world = b.step(100.0);
    let binary = b.step(10.0);
    let (cell, gate) = b.gate(10.0, &[c0], &[world]);
    let t1 = b.probe(5.0, &[c1], &[world, gate]);
    let t2 = b.probe(5.0, &[c2], &[world, gate]);
    let p = b.probe(5.0, &[c3], &[world]);
    let q = b.probe(5.0, &[c4], &[binary]);
    assert_eq!((cell, t1, t2, p, q), (0, 1, 2, 3, 4));
    (b.done(), world, gate)
}

/// Drives the rule with one worker; `verdict(kind, number)` says whether a set-up (false) or gate (true)... passes.
fn drive_one(inputs: &DoubtInputs, passes: impl Fn(u32) -> bool) -> (Vec<u32>, Vec<u32>) {
    let mut rule = Rule::new(inputs, &[]);
    let mut runs = Vec::new();
    loop {
        match rule.next() {
            Pick::SetUp(x) => rule.up(x),
            Pick::Run(u) => {
                runs.push(u);
                if let Some(x) = inputs.gate_of.get(u as usize).copied().flatten() {
                    if passes(u) {
                        rule.up(x)
                    } else {
                        rule.failed_setup(x)
                    }
                }
            }
            Pick::Idle => panic!("a lone worker idled"),
            Pick::Finished => return (runs, rule.stranded().to_vec()),
        }
    }
}

#[test]
fn a_gate_probe_whose_failure_strands_its_twins() {
    let (inputs, _, _) = cell_with_twins();
    // The cell fails: its twins are stranded, listed once, and never run; everything else runs.
    let (runs, stranded) = drive_one(&inputs, |_| false);
    assert_eq!(stranded, vec![1, 2]);
    let mut all = runs.clone();
    all.extend(&stranded);
    all.sort_unstable();
    assert_eq!(
        all,
        vec![0, 1, 2, 3, 4],
        "every probe is either run or stranded, none both"
    );
    assert!(runs.iter().all(|u| !stranded.contains(u)));
    // The cell passes: the twins run, after it.
    let (runs, stranded) = drive_one(&inputs, |_| true);
    assert!(stranded.is_empty());
    let pos = |u: u32| runs.iter().position(|&x| x == u).expect("ran");
    assert!(
        pos(0) < pos(1) && pos(0) < pos(2),
        "twins must wait for the gate: {runs:?}"
    );
}

#[test]
fn twins_are_priced_into_their_gates_bundle() {
    // The cell itself detects little; its twins detect a lot. With the world warm, the cell's bundle
    // (itself plus its best twins) is denser than the plain probe, so the cell goes first.
    let mut b = Build::new();
    let (c0, c1, c2, c3) = (b.class(0.01), b.class(1.0), b.class(1.0), b.class(0.3));
    let world = b.step(100.0);
    let (cell, gate) = b.gate(10.0, &[c0], &[world]);
    let _t1 = b.probe(5.0, &[c1], &[world, gate]);
    let _t2 = b.probe(5.0, &[c2], &[world, gate]);
    let plain = b.probe(5.0, &[c3], &[world]);
    let inputs = b.done();
    let mut rule = Rule::new(&inputs, &[world]);
    assert_eq!(
        rule.next(),
        Pick::Run(cell),
        "the gate should start before the plain probe"
    );
    // While the gate is in flight its twins cannot start; the plain probe can.
    assert_eq!(rule.next(), Pick::Run(plain));
    assert_eq!(
        rule.next(),
        Pick::Idle,
        "only the twins are left and they wait for the gate"
    );
    rule.up(gate);
    assert!(matches!(rule.next(), Pick::Run(1 | 2)));
}

#[test]
fn a_chain_of_gates_strands_by_depth() {
    // world -> cell (gate 1) -> twin that is itself a gate (gate 2) -> grandtwins.
    let build = || {
        let mut b = Build::new();
        let (a, c, d, e) = (b.class(0.2), b.class(0.2), b.class(0.2), b.class(0.2));
        let world = b.step(50.0);
        let (cell, g1) = b.gate(4.0, &[a], &[world]);
        let (mid, g2) = b.gate(4.0, &[c], &[world, g1]);
        let leaf1 = b.probe(3.0, &[d], &[world, g1, g2]);
        let leaf2 = b.probe(3.0, &[e], &[world, g1, g2]);
        assert_eq!((cell, mid, leaf1, leaf2), (0, 1, 2, 3));
        b.done()
    };
    let inputs = build();
    // The middle gate fails: only its leaves are stranded.
    let (runs, stranded) = drive_one(&inputs, |u| u != 1);
    assert_eq!(stranded, vec![2, 3]);
    assert_eq!(runs, vec![0, 1]);
    // The top gate fails: the middle gate and the leaves are stranded together.
    let (runs, stranded) = drive_one(&inputs, |u| u != 0);
    assert_eq!(stranded, vec![1, 2, 3]);
    assert_eq!(runs, vec![0]);
    // All pass: the order respects the chain.
    let (runs, stranded) = drive_one(&inputs, |_| true);
    assert!(stranded.is_empty());
    assert_eq!(&runs[..2], &[0, 1]);
}

#[test]
fn a_failed_build_strands_every_group_that_stands_on_it() {
    let (inputs, world, _) = cell_with_twins();
    let mut rule = Rule::new(&inputs, &[]);
    rule.failed_setup(world);
    assert_eq!(
        rule.stranded(),
        &[0, 1, 2, 3],
        "the cell, its twins and the plain probe all stand on the world"
    );
    // The unrelated binary still runs, and the rule finishes.
    let mut runs = Vec::new();
    loop {
        match rule.next() {
            Pick::SetUp(x) => rule.up(x),
            Pick::Run(u) => runs.push(u),
            Pick::Idle => panic!("idle with nothing in flight"),
            Pick::Finished => break,
        }
    }
    assert_eq!(runs, vec![4]);
    // Reporting the same failure again changes nothing.
    rule.failed_setup(world);
    assert_eq!(rule.stranded(), &[0, 1, 2, 3]);
}

#[test]
fn a_worker_is_left_idle_while_the_best_group_is_setting_up() {
    let mut b = Build::new();
    let c = b.class(1.0);
    let x = b.step(50.0);
    let p = b.probe(5.0, &[c], &[x]);
    let inputs = b.done();
    let mut rule = Rule::new(&inputs, &[]);
    assert_eq!(rule.next(), Pick::SetUp(x));
    assert_eq!(
        rule.next(),
        Pick::Idle,
        "the second worker waits for the step rather than start nothing"
    );
    rule.up(x);
    assert_eq!(rule.next(), Pick::Run(p));
    assert_eq!(rule.next(), Pick::Finished);
    assert_eq!(rule.next(), Pick::Finished, "finished stays finished");
}

#[test]
fn steps_already_up_are_not_set_up_again() {
    let mut b = Build::new();
    let c = b.class(1.0);
    let x = b.step(50.0);
    let p = b.probe(5.0, &[c], &[x]);
    let inputs = b.done();
    let mut rule = Rule::new(&inputs, &[x]);
    assert_eq!(rule.next(), Pick::Run(p));
}

#[test]
fn the_tail_runs_every_probe() {
    // Probe 0 detects the only class; 1 to 3 detect nothing. Probe 1 and 2 share the warm step, 3 needs a cold one.
    let mut b = Build::new();
    let c = b.class(1.0);
    let hot = b.step(10.0);
    let cold = b.step(1.0);
    let p0 = b.probe(5.0, &[c], &[hot]);
    let p1 = b.probe(9.0, &[], &[hot]);
    let p2 = b.probe(2.0, &[], &[hot]);
    let p3 = b.probe(1.0, &[], &[cold]);
    let inputs = b.done();
    let mut rule = Rule::new(&inputs, &[]);
    let mut seq = Vec::new();
    loop {
        match rule.next() {
            Pick::SetUp(x) => {
                seq.push(format!("set up {x}"));
                rule.up(x)
            }
            Pick::Run(u) => seq.push(format!("run {u}")),
            Pick::Idle => panic!("idle"),
            Pick::Finished => break,
        }
    }
    // Ready ones before any new set-up even though probe 3 is cheaper than both: "groups already up first".
    assert_eq!(
        seq,
        vec![
            format!("set up {hot}"),
            format!("run {p0}"),
            format!("run {p2}"),
            format!("run {p1}"),
            format!("set up {cold}"),
            format!("run {p3}")
        ]
    );
    assert_eq!(offline(&inputs).as_slice(), &[p0, p2, p1, p3]);
}

#[test]
fn inputs_that_cannot_be_ordered_are_refused_with_the_reason() {
    let (good, _, _) = cell_with_twins();
    assert_eq!(good.validate(), Ok(()));
    let mut e = good.clone();
    e.cost_ms.pop();
    assert!(matches!(
        e.validate(),
        Err(InputsError::Count {
            table: "cost_ms",
            ..
        })
    ));
    let mut e = good.clone();
    e.kills.items[0].0 = 99;
    assert!(matches!(
        e.validate(),
        Err(InputsError::ClassOutOfRange {
            unit: 0,
            class: 99,
            ..
        })
    ));
    let mut e = good.clone();
    e.kills.items[0].1 = 0.0;
    assert!(matches!(
        e.validate(),
        Err(InputsError::BadKill { unit: 0, .. })
    ));
    let mut e = good.clone();
    e.cost_ms[2] = ms(0.0);
    assert!(matches!(
        e.validate(),
        Err(InputsError::BadCost { unit: 2, .. })
    ));
    let mut e = good.clone();
    e.class_mass[0] = f32::NAN;
    assert!(matches!(
        e.validate(),
        Err(InputsError::BadMass { class: 0, .. })
    ));
    let mut e = good.clone();
    e.needs.items[0] = 77;
    assert!(matches!(
        e.validate(),
        Err(InputsError::StepOutOfRange {
            table: "needs",
            unit: 0,
            step: 77,
            ..
        })
    ));
    let mut e = good.clone();
    e.gate_of[4] = e.gate_of[0];
    assert!(matches!(
        e.validate(),
        Err(InputsError::GateStepTaken {
            first: 0,
            second: 4,
            ..
        })
    ));
    // A kill row out of class order.
    let mut b = Build::new();
    let (c0, c1) = (b.class(1.0), b.class(1.0));
    let x = b.step(1.0);
    b.probe(1.0, &[c1, c0], &[x]);
    assert!(matches!(
        b.done().validate(),
        Err(InputsError::ClassesNotAscending { unit: 0 })
    ));
    // Two unrelated gates a probe needs together.
    let mut b = Build::new();
    let c = b.class(1.0);
    let w = b.step(1.0);
    let (_, g1) = b.gate(1.0, &[c], &[w]);
    let (_, g2) = b.gate(1.0, &[c], &[w]);
    b.probe(1.0, &[c], &[w, g1, g2]);
    assert!(matches!(
        b.done().validate(),
        Err(InputsError::GatesJoin { unit: 2 })
    ));
    // A twin that needs a build its gate does not.
    let mut b = Build::new();
    let c = b.class(1.0);
    let (w, other) = (b.step(1.0), b.step(1.0));
    let (_, g) = b.gate(1.0, &[c], &[w]);
    b.probe(1.0, &[c], &[w, other, g]);
    assert!(matches!(
        b.done().validate(),
        Err(InputsError::ChildSetupDiffers { unit: 1, gate: 0 })
    ));
    // Every message says what to do.
    let text = InputsError::GatesJoin { unit: 2 }.to_string();
    assert!(text.contains("probe 2") && text.contains("refuse"));
    // Rule::new panics with the same words, and so do reports about steps that do not exist.
    let mut bad = good.clone();
    bad.cost_ms[0] = ms(-1.0);
    let panic = catch_unwind(AssertUnwindSafe(|| {
        let _ = Rule::new(&bad, &[]);
    }))
    .expect_err("must panic");
    let msg = panic.downcast_ref::<String>().cloned().unwrap_or_default();
    assert!(
        msg.contains("cannot be ordered") && msg.contains("probe 0"),
        "{msg}"
    );
    let mut rule = Rule::new(&good, &[]);
    assert!(catch_unwind(AssertUnwindSafe(|| rule.up(99))).is_err());
    assert!(catch_unwind(AssertUnwindSafe(|| rule.failed_setup(99))).is_err());
}

#[test]
fn a_row_with_no_probes_and_empty_inputs_are_fine() {
    let empty = DoubtInputs {
        plan: Default::default(),
        units: 0,
        steps: 0,
        class_mass: vec![],
        kills: Csr::default(),
        cost_ms: vec![],
        needs: Csr::default(),
        setup_ms: vec![],
        reach: vec![],
        gate_of: vec![],
    };
    let mut rule = Rule::new(&empty, &[]);
    assert_eq!(rule.next(), Pick::Finished);
    assert!(offline(&empty).is_empty());
}

// ---- a whole run against random gate forests ------------------------------------------------

fn add_subtree(
    b: &mut Build,
    r: &mut Rng,
    classes: &[u32],
    base: &[u32],
    gates_above: &[u32],
    depth: usize,
) {
    let kills = |r: &mut Rng| -> Vec<u32> {
        classes
            .iter()
            .copied()
            .filter(|_| r.below(3) == 0)
            .collect()
    };
    let needs: Vec<u32> = base.iter().chain(gates_above).copied().collect();
    for _ in 0..1 + r.below(3) {
        let k = kills(r);
        let cost = 1.0 + 9.0 * r.unit();
        if depth < 2 && r.below(3) == 0 {
            let (_, step) = b.gate(cost, &k, &needs);
            let mut above = gates_above.to_vec();
            above.push(step);
            add_subtree(b, r, classes, base, &above, depth + 1);
        } else {
            b.probe(cost, &k, &needs);
        }
    }
}

pub(super) fn gate_instance(r: &mut Rng) -> DoubtInputs {
    let mut b = Build::new();
    let classes: Vec<u32> = (0..6).map(|_| b.class((0.1 + r.unit()) as f32)).collect();
    let builds: Vec<u32> = (0..2 + r.below(3))
        .map(|_| b.step(1.0 + 50.0 * r.unit()))
        .collect();
    for _ in 0..2 + r.below(3) {
        let mut base = vec![builds[r.below(builds.len())]];
        if r.below(3) == 0 {
            base.push(builds[r.below(builds.len())]);
        }
        base.sort_unstable();
        base.dedup();
        add_subtree(&mut b, r, &classes, &base, &[], 0);
    }
    b.done()
}

/// A tiny executor: `workers` workers, random durations, random failures. Checks what an executor
/// relies on: every probe is started once or stranded, nothing starts before its steps are up, and
/// a probe is stranded exactly when one of its steps failed.
fn run_executor(inputs: &DoubtInputs, workers: usize, seed: u64) {
    let mut r = Rng(seed);
    let mut rule = Rule::new(inputs, &[]);
    let n = inputs.units as usize;
    let mut up_at = vec![f64::NAN; inputs.steps as usize];
    let mut failed = vec![false; inputs.steps as usize];
    let mut started = vec![f64::NAN; n];
    let mut inflight: Vec<(f64, u64, Result<u32, u32>)> = Vec::new(); // Ok(step) or Err(probe)
    let (mut now, mut seq, mut idle) = (0.0f64, 0u64, workers);
    loop {
        while idle > 0 {
            match rule.next() {
                Pick::SetUp(x) => {
                    assert!(
                        up_at[x as usize].is_nan() && !failed[x as usize],
                        "step {x} set up twice"
                    );
                    up_at[x as usize] = f64::INFINITY; // coming
                    idle -= 1;
                    seq += 1;
                    inflight.push((now + 1.0 + 20.0 * r.unit(), seq, Ok(x)));
                }
                Pick::Run(u) => {
                    assert!(started[u as usize].is_nan(), "probe {u} started twice");
                    for &x in inputs.needs.row(u as usize) {
                        assert!(
                            up_at[x as usize] <= now,
                            "probe {u} started at {now} before step {x} was up ({})",
                            up_at[x as usize]
                        );
                    }
                    started[u as usize] = now;
                    idle -= 1;
                    seq += 1;
                    inflight.push((now + inputs.cost_ms[u as usize].millis(), seq, Err(u)));
                }
                Pick::Idle | Pick::Finished => break,
            }
        }
        let Some(i) = (0..inflight.len()).min_by(|&a, &b| {
            (inflight[a].0, inflight[a].1)
                .partial_cmp(&(inflight[b].0, inflight[b].1))
                .unwrap()
        }) else {
            break;
        };
        let (at, _, what) = inflight.swap_remove(i);
        now = at;
        idle += 1;
        match what {
            Ok(x) => {
                if r.below(10) == 0 {
                    up_at[x as usize] = f64::NAN;
                    failed[x as usize] = true;
                    rule.failed_setup(x);
                } else {
                    up_at[x as usize] = now;
                    rule.up(x);
                }
            }
            Err(u) => {
                if let Some(x) = inputs.gate_of.get(u as usize).copied().flatten() {
                    if r.below(3) == 0 {
                        failed[x as usize] = true;
                        rule.failed_setup(x);
                    } else {
                        up_at[x as usize] = now;
                        rule.up(x);
                    }
                }
            }
        }
    }
    assert_eq!(
        rule.next(),
        Pick::Finished,
        "the rule must end with every probe started or stranded\n{}",
        describe(inputs)
    );
    let stranded = rule.stranded();
    for u in 0..n as u32 {
        let was_started = !started[u as usize].is_nan();
        let is_stranded = stranded.contains(&u);
        assert!(
            was_started != is_stranded,
            "probe {u} started={was_started} stranded={is_stranded}\n{}",
            describe(inputs)
        );
        let blocked = inputs
            .needs
            .row(u as usize)
            .iter()
            .any(|&x| failed[x as usize]);
        assert_eq!(
            is_stranded,
            blocked,
            "probe {u} is stranded exactly when a step it needs failed\n{}",
            describe(inputs)
        );
    }
    let mut sorted = stranded.to_vec();
    sorted.dedup();
    assert_eq!(sorted.len(), stranded.len(), "a probe was stranded twice");
}

#[test]
fn random_gate_forests_run_to_the_end_under_any_failures() {
    let mut r = Rng(21);
    let mut with_gates = 0;
    for i in 0..1500u64 {
        let inputs = gate_instance(&mut r);
        inputs.validate().expect("generated forests are valid");
        with_gates += usize::from(!inputs.gate_of.is_empty());
        for workers in 1..=3 {
            run_executor(&inputs, workers, i * 7 + workers as u64);
        }
    }
    println!("{with_gates} of 1500 forests had gates");
    assert!(with_gates > 1000);
}

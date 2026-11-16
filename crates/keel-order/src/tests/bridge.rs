//! Glue between the simulator's instances and the crate's inputs, and the event
//! loops that stand in for an executor.

use std::cmp::Reverse;
use std::collections::BinaryHeap;

use super::support::{Eval, Instance, Rng};
use crate::{Csr, Digest, DoubtInputs, Millis, Number, Pick, Rule};

pub fn ms(v: f64) -> Number<Millis> {
    Number::Placeholder { value: Millis(v) }
}

/// The simulator's instance as the crate's inputs: one step per binary, a kill
/// is certain (`q` = 1), costs in milliseconds, equal reach so that ties fall to
/// the smaller id as in the simulator.
pub fn inputs_of(inst: &Instance) -> DoubtInputs {
    let n = inst.tests();
    DoubtInputs {
        plan: Digest::default(),
        units: n as u32,
        steps: inst.setup.len() as u32,
        class_mass: inst.weight.iter().map(|&w| w as f32).collect(),
        kills: Csr::from_rows((0..n).map(|t| inst.kills(t).iter().map(|&e| (e, 1.0f32)).collect())),
        cost_ms: inst.cost.iter().map(|&c| ms(c * 1000.0)).collect(),
        needs: Csr::from_rows((0..n).map(|t| vec![inst.bin_of[t]])),
        setup_ms: inst.setup.iter().map(|&s| ms(s * 1000.0)).collect(),
        reach: vec![0; n],
        gate_of: Vec::new(),
    }
}

/// Rounds the weights to `f32`, so that the simulator's `J` and the crate's masses are the same numbers.
pub fn round_weights(inst: &mut Instance) {
    for w in &mut inst.weight {
        *w = f64::from(*w as f32);
    }
}

/// The `Run` sequence of one worker that brings every step up the moment it is
/// asked for and passes every gate.
pub fn serial_online(inputs: &DoubtInputs) -> Vec<u32> {
    let mut rule = Rule::new(inputs, &[]);
    let mut out = Vec::new();
    loop {
        match rule.next() {
            Pick::SetUp(x) => rule.up(x),
            Pick::Run(u) => {
                out.push(u);
                if let Some(x) = inputs.gate_of.get(u as usize).copied().flatten() {
                    rule.up(x);
                }
            }
            Pick::Idle => panic!(
                "a lone worker was told to idle with {} probes started",
                out.len()
            ),
            Pick::Finished => return out,
        }
    }
}

/// The simulator's `online` event loop with the rule's `next`/`up` in place of its heap.
pub fn online_eval(inst: &Instance, inputs: &DoubtInputs, workers: usize) -> Eval {
    let micros = |s: f64| (s * 1e6).round().max(1.0) as u64;
    let mut rule = Rule::new(inputs, &[]);
    let coverable: f64 = {
        let mut hit = vec![false; inst.weight.len()];
        for &e in &inst.elem {
            hit[e as usize] = true;
        }
        hit.iter()
            .zip(&inst.weight)
            .filter(|(h, _)| **h)
            .map(|(_, w)| *w)
            .sum()
    };
    let mut seen = vec![false; inst.weight.len()];
    let mut events: BinaryHeap<Reverse<(u64, u64, bool, u32)>> = BinaryHeap::new();
    let (mut now, mut seq, mut idle) = (0u64, 0u64, workers);
    let (mut j, mut got, mut t50, mut t90) = (0.0, 0.0, f64::NAN, f64::NAN);
    loop {
        while idle > 0 {
            match rule.next() {
                Pick::SetUp(x) => {
                    idle -= 1;
                    seq += 1;
                    events.push(Reverse((
                        now + micros(inst.setup[x as usize]),
                        seq,
                        false,
                        x,
                    )));
                }
                Pick::Run(t) => {
                    idle -= 1;
                    seq += 1;
                    events.push(Reverse((now + micros(inst.cost[t as usize]), seq, true, t)));
                }
                Pick::Idle | Pick::Finished => break,
            }
        }
        let Some(Reverse((at, _, is_test, id))) = events.pop() else {
            break;
        };
        now = at;
        idle += 1;
        if is_test {
            let secs = now as f64 / 1e6;
            for &e in inst.kills(id as usize) {
                if !std::mem::replace(&mut seen[e as usize], true) {
                    let w = inst.weight[e as usize];
                    j += w * secs;
                    got += w;
                    if t50.is_nan() && got >= 0.5 * coverable {
                        t50 = secs;
                    }
                    if t90.is_nan() && got >= 0.9 * coverable {
                        t90 = secs;
                    }
                }
            }
        } else {
            rule.up(id);
        }
    }
    Eval {
        j,
        t50,
        t90,
        makespan: now as f64 / 1e6,
    }
}

/// What today's `keel-infer` order does: the test with the best gain per own
/// second first, set-ups ignored. The baseline of §4.4's third row.
pub fn blind_order(inst: &Instance) -> Vec<u32> {
    let n = inst.tests();
    let mut covered = vec![false; inst.weight.len()];
    let mut done = vec![false; n];
    let mut order = Vec::new();
    loop {
        let mut best: Option<(f64, usize)> = None;
        for (t, _) in done.iter().enumerate().filter(|(_, d)| !**d) {
            let g: f64 = inst
                .kills(t)
                .iter()
                .filter(|&&e| !covered[e as usize])
                .map(|&e| inst.weight[e as usize])
                .sum();
            let d = g / inst.cost[t];
            if g > 0.0 && best.is_none_or(|(bd, _)| d > bd) {
                best = Some((d, t));
            }
        }
        let Some((_, t)) = best else { break };
        done[t] = true;
        order.push(t as u32);
        for &e in inst.kills(t) {
            covered[e as usize] = true;
        }
    }
    order.extend((0..n as u32).filter(|&t| !done[t as usize]));
    order
}

/// A random instance in the crate's own terms: shared steps (two per probe at
/// most), soft kill probabilities, ties on purpose when `ties` is set.
pub fn random_inputs(r: &mut Rng, ties: bool) -> DoubtInputs {
    let n = 3 + r.below(10);
    let steps = 1 + r.below(5);
    let classes = 2 + r.below(7);
    let pick = |r: &mut Rng, lo: f64, hi: f64| {
        if ties {
            (lo + r.below((hi - lo) as usize + 1) as f64).max(lo)
        } else {
            lo + (hi - lo) * r.unit()
        }
    };
    let class_mass: Vec<f32> = (0..classes).map(|_| pick(r, 1.0, 3.0) as f32).collect();
    let setup_ms: Vec<_> = (0..steps)
        .map(|_| {
            ms(if ties {
                r.below(7) as f64
            } else {
                0.05 + 8.0 * r.unit()
            })
        })
        .collect();
    let mut kills = Vec::new();
    let mut costs = Vec::new();
    let mut needs = Vec::new();
    let mut reach = Vec::new();
    for _ in 0..n {
        let mut row = Vec::new();
        for c in 0..classes {
            if r.below(3) == 0 {
                let q = if ties {
                    [1.0f32, 0.5][r.below(2)]
                } else if r.below(2) == 0 {
                    1.0
                } else {
                    (0.1 + 0.9 * r.unit()) as f32
                };
                row.push((c as u32, q));
            }
        }
        kills.push(row);
        costs.push(ms(pick(r, 1.0, 4.0)));
        let a = r.below(steps) as u32;
        let mut ns = vec![a];
        if r.below(3) == 0 {
            ns.push(r.below(steps) as u32);
        }
        needs.push(ns);
        reach.push(if ties {
            r.below(3) as u32
        } else {
            r.below(50) as u32
        });
    }
    DoubtInputs {
        plan: Digest::default(),
        units: n as u32,
        steps: steps as u32,
        class_mass,
        kills: Csr::from_rows(kills),
        cost_ms: costs,
        needs: Csr::from_rows(needs),
        setup_ms,
        reach,
        gate_of: Vec::new(),
    }
}

/// The detection share of a set of probes: `Σ_z mass_z (1 − ∏ (1 − q))`, the
/// `c(S)` of §2.3 summed over classes.
pub fn detection_share(inputs: &DoubtInputs, set: &[u32]) -> f64 {
    let mut miss: Vec<f64> = vec![1.0; inputs.class_mass.len()];
    for &t in set {
        for &(c, q) in inputs.kills.row(t as usize) {
            miss[c as usize] *= 1.0 - f64::from(q);
        }
    }
    inputs
        .class_mass
        .iter()
        .zip(&miss)
        .map(|(&m, &x)| f64::from(m) * (1.0 - x))
        .sum()
}

/// `J` of an order on one worker for inputs in the crate's terms: a step is paid
/// when the first probe that needs it starts, and a fault is detected when the
/// first probe that kills it finishes (certain kills only).
pub fn serial_j_of(inputs: &DoubtInputs, order: &[u32]) -> f64 {
    let mut paid = vec![false; inputs.steps as usize];
    let mut covered = vec![false; inputs.class_mass.len()];
    let (mut clock, mut j) = (0.0, 0.0);
    for &t in order {
        for &x in inputs.needs.row(t as usize) {
            if !std::mem::replace(&mut paid[x as usize], true)
                && inputs.gate_of.iter().all(|g| *g != Some(x))
            {
                clock += inputs.setup_ms[x as usize].millis();
            }
        }
        clock += inputs.cost_ms[t as usize].millis();
        for &(c, _) in inputs.kills.row(t as usize) {
            if !std::mem::replace(&mut covered[c as usize], true) {
                j += f64::from(inputs.class_mass[c as usize]) * clock;
            }
        }
    }
    j
}

/// Like `random_inputs` but every group has steps of its own, so set-ups are
/// private to a group: the case §4.3's guarantee and §4.2's online/offline
/// agreement are about.
pub fn private_inputs(r: &mut Rng) -> DoubtInputs {
    let groups = 2 + r.below(4);
    let n = 4 + r.below(9);
    let classes = 3 + r.below(8);
    let class_mass: Vec<f32> = (0..classes).map(|_| (0.05 + r.unit()) as f32).collect();
    let two: Vec<bool> = (0..groups).map(|_| r.below(2) == 0).collect();
    let setup_ms: Vec<_> = (0..groups * 2)
        .map(|_| ms(1000.0 * r.lognormal(2.0, 1.8)))
        .collect();
    let (mut kills, mut costs, mut needs) = (Vec::new(), Vec::new(), Vec::new());
    for _ in 0..n {
        let mut row = Vec::new();
        for c in 0..classes {
            if r.below(3) == 0 {
                row.push((
                    c as u32,
                    if r.below(3) == 0 {
                        (0.2 + 0.8 * r.unit()) as f32
                    } else {
                        1.0
                    },
                ));
            }
        }
        kills.push(row);
        costs.push(ms(1000.0 * r.lognormal(0.5, 1.2)));
        let g = r.below(groups);
        needs.push(if two[g] {
            vec![2 * g as u32, 2 * g as u32 + 1]
        } else {
            vec![2 * g as u32]
        });
    }
    DoubtInputs {
        plan: Digest::default(),
        units: n as u32,
        steps: (groups * 2) as u32,
        class_mass,
        kills: Csr::from_rows(kills),
        cost_ms: costs,
        needs: Csr::from_rows(needs),
        setup_ms,
        reach: (0..n).map(|_| r.below(40) as u32).collect(),
        gate_of: Vec::new(),
    }
}

/// The same inputs with probe `u` renumbered `perm[u]`.
pub fn permuted(inp: &DoubtInputs, perm: &[u32]) -> DoubtInputs {
    let n = inp.units as usize;
    let mut inv = vec![0u32; n];
    for (u, &p) in perm.iter().enumerate() {
        inv[p as usize] = u as u32;
    }
    fn row<T: Clone>(t: &Csr<T>, i: usize) -> Vec<T> {
        t.row(i).to_vec()
    }
    DoubtInputs {
        plan: inp.plan,
        units: inp.units,
        steps: inp.steps,
        class_mass: inp.class_mass.clone(),
        kills: Csr::from_rows((0..n).map(|i| row(&inp.kills, inv[i] as usize))),
        cost_ms: (0..n)
            .map(|i| inp.cost_ms[inv[i] as usize].clone())
            .collect(),
        needs: Csr::from_rows((0..n).map(|i| row(&inp.needs, inv[i] as usize))),
        setup_ms: inp.setup_ms.clone(),
        reach: (0..n).map(|i| inp.reach[inv[i] as usize]).collect(),
        gate_of: if inp.gate_of.is_empty() {
            Vec::new()
        } else {
            (0..n).map(|i| inp.gate_of[inv[i] as usize]).collect()
        },
    }
}

/// One line per probe and step, for failure messages.
pub fn describe(inp: &DoubtInputs) -> String {
    let mut s = format!("class masses {:?}\n", inp.class_mass);
    for x in 0..inp.steps as usize {
        s += &format!("  step {x}: set-up {} ms\n", inp.setup_ms[x].millis());
    }
    for u in 0..inp.units as usize {
        s += &format!(
            "  probe {u}: cost {} ms, reach {}, needs {:?}, kills {:?}, gate {:?}\n",
            inp.cost_ms[u].millis(),
            inp.reach[u],
            inp.needs.row(u),
            inp.kills.row(u),
            inp.gate_of.get(u).copied().flatten()
        );
    }
    s
}

/// Hand-built inputs, one probe at a time.
#[derive(Default)]
pub struct Build {
    masses: Vec<f32>,
    setups: Vec<f64>,
    kills: Vec<Vec<(u32, f32)>>,
    costs: Vec<f64>,
    needs: Vec<Vec<u32>>,
    reach: Vec<u32>,
    gate: Vec<Option<u32>>,
}

impl Build {
    pub fn new() -> Build {
        Build::default()
    }
    /// Adds a class and returns its number.
    pub fn class(&mut self, mass: f32) -> u32 {
        self.masses.push(mass);
        self.masses.len() as u32 - 1
    }
    /// Adds a set-up step and returns its number.
    pub fn step(&mut self, setup_ms: f64) -> u32 {
        self.setups.push(setup_ms);
        self.setups.len() as u32 - 1
    }
    /// Adds a probe and returns its number.
    pub fn probe(&mut self, cost_ms: f64, kills: &[u32], needs: &[u32]) -> u32 {
        self.kills.push(kills.iter().map(|&c| (c, 1.0)).collect());
        self.costs.push(cost_ms);
        self.needs.push(needs.to_vec());
        self.reach.push(0);
        self.gate.push(None);
        self.costs.len() as u32 - 1
    }
    /// Adds a probe with a given reach.
    pub fn probe_r(&mut self, cost_ms: f64, kills: &[u32], needs: &[u32], reach: u32) -> u32 {
        let u = self.probe(cost_ms, kills, needs);
        self.reach[u as usize] = reach;
        u
    }
    /// Adds a probe that is the gate of a new step, and returns (probe, step).
    pub fn gate(&mut self, cost_ms: f64, kills: &[u32], needs: &[u32]) -> (u32, u32) {
        let step = self.step(0.0);
        let u = self.probe(cost_ms, kills, needs);
        self.gate[u as usize] = Some(step);
        (u, step)
    }
    pub fn done(self) -> DoubtInputs {
        let n = self.costs.len();
        DoubtInputs {
            plan: Digest::default(),
            units: n as u32,
            steps: self.setups.len() as u32,
            class_mass: self.masses,
            kills: Csr::from_rows(self.kills),
            cost_ms: self.costs.into_iter().map(ms).collect(),
            needs: Csr::from_rows(self.needs),
            setup_ms: self.setups.into_iter().map(ms).collect(),
            reach: self.reach,
            gate_of: if self.gate.iter().any(Option::is_some) {
                self.gate
            } else {
                Vec::new()
            },
        }
    }
}

/// `J = ∫ (F(all) − F(done by τ)) dτ` for the additive `F` of §2.6 on one worker: a step is paid when
/// the first probe that needs it starts, a gate step not at all. With certain kills it is
/// `Σ_classes mass · (time of the first kill)`.
pub fn additive_j(inputs: &DoubtInputs, order: &[u32]) -> f64 {
    let f = |set: &[u32]| detection_share(inputs, set);
    let total = f(&(0..inputs.units).collect::<Vec<_>>());
    let mut paid = vec![false; inputs.steps as usize];
    let (mut clock, mut j) = (0.0, 0.0);
    for (i, &t) in order.iter().enumerate() {
        let start = clock;
        for &x in inputs.needs.row(t as usize) {
            if !std::mem::replace(&mut paid[x as usize], true) && !inputs.gate_of.contains(&Some(x))
            {
                clock += inputs.setup_ms[x as usize].millis();
            }
        }
        clock += inputs.cost_ms[t as usize].millis();
        // The deficit stays at F(all) − F(first i probes) until this probe finishes.
        j += (total - f(&order[..i])) * (clock - start);
    }
    j
}

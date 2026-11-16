//! The reference simulator's own bundle rule (`Bundler`, `bundle_greedy`), copied from
//! `design/doubt/sim/sim.rs` so the crate can be tested against the code the document was
//! measured with. The only change is that `bundle_greedy` also returns where its
//! zero-gain tail begins (`append_rest` is the simulator's tail), which the crate
//! orders by the document's rule (§4.2: ready groups first, cheapest first). The simulator's
//! index-order tail is the simulator's error, as the document now rules.
#![allow(clippy::all, dead_code)]

use std::cmp::Ordering;
use std::collections::BinaryHeap;

use super::support::Instance;

#[derive(Clone, Copy, PartialEq)]
pub struct Ent {
    d: f64,
    id: u32,
    ver: u32,
}
impl Eq for Ent {}
impl PartialOrd for Ent {
    fn partial_cmp(&self, o: &Self) -> Option<Ordering> {
        Some(self.cmp(o))
    }
}
impl Ord for Ent {
    fn cmp(&self, o: &Self) -> Ordering {
        self.d.total_cmp(&o.d).then_with(|| o.id.cmp(&self.id))
    }
}

fn gain(inst: &Instance, covered: &[bool], t: usize) -> f64 {
    inst.kills(t)
        .iter()
        .filter(|&&e| !covered[e as usize])
        .map(|&e| inst.weight[e as usize])
        .sum()
}
pub struct Bundler<'a> {
    inst: &'a Instance,
    covered: Vec<bool>,
    done: Vec<bool>,
    built: Vec<bool>,
    /// Tests of each binary that may still have gain.
    live: Vec<Vec<u32>>,
    stamp: Vec<u32>,
    now: u32,
    evals: u64,
    /// Per built binary: its live tests by (possibly stale) density. Gains only
    /// fall, so a stale entry is an upper bound and only the top is refreshed.
    warm: Vec<Option<BinaryHeap<Ent>>>,
}

impl Bundler<'_> {
    /// Best single test of a built binary, by lazy greedy on its own heap.
    fn best_warm(&mut self, b: usize) -> (f64, Vec<u32>) {
        let inst = self.inst;
        if self.warm[b].is_none() {
            let heap: BinaryHeap<Ent> = self.live[b]
                .iter()
                .filter(|&&t| !self.done[t as usize])
                .map(|&t| Ent {
                    d: gain(inst, &self.covered, t as usize) / inst.cost[t as usize],
                    id: t,
                    ver: 0,
                })
                .filter(|e| e.d > 0.0)
                .collect();
            self.live[b] = Vec::new();
            self.warm[b] = Some(heap);
        }
        let heap = self.warm[b].as_mut().expect("just built");
        while let Some(top) = heap.pop() {
            let t = top.id as usize;
            if self.done[t] {
                continue;
            }
            let g = gain(inst, &self.covered, t);
            if g <= 0.0 {
                continue;
            }
            let d = g / inst.cost[t];
            let stays_top = !heap.peek().is_some_and(|nx| d < nx.d);
            heap.push(Ent {
                d,
                id: top.id,
                ver: 0,
            });
            if stays_top {
                return (d, vec![top.id]);
            }
        }
        (0.0, Vec::new())
    }

    /// Best bundle of binary `b`: the prefix of the density-greedy order of its
    /// live tests that maximises gain / (set-up if cold + run time). Returns
    /// the density and the tests.
    fn best(&mut self, b: usize) -> (f64, Vec<u32>) {
        self.evals += 1;
        let inst = self.inst;
        if self.built[b] {
            return self.best_warm(b);
        }
        let (covered, done) = (&self.covered, &self.done);
        self.live[b].retain(|&t| !done[t as usize] && gain(inst, covered, t as usize) > 0.0);
        if self.live[b].is_empty() {
            return (0.0, Vec::new());
        }
        self.now += 1;
        let now = self.now;
        let mut heap: BinaryHeap<Ent> = self.live[b]
            .iter()
            .map(|&t| Ent {
                d: gain(inst, covered, t as usize) / inst.cost[t as usize],
                id: t,
                ver: 0,
            })
            .collect();
        let (mut g_sum, mut c_sum) = (0.0, inst.setup[b]);
        let mut picked = Vec::new();
        let (mut best_d, mut best_len) = (0.0, 0usize);
        while let Some(top) = heap.pop() {
            // Every remaining density is at most `top.d`, now and later; a test
            // less dense than the bundle so far can only dilute it.
            if best_len > 0 && top.d <= g_sum / c_sum {
                break;
            }
            let t = top.id as usize;
            let g: f64 = inst
                .kills(t)
                .iter()
                .filter(|&&e| !covered[e as usize] && self.stamp[e as usize] != now)
                .map(|&e| inst.weight[e as usize])
                .sum();
            if g <= 0.0 {
                continue;
            }
            let d = g / inst.cost[t];
            if heap.peek().is_some_and(|nx| d < nx.d) {
                heap.push(Ent {
                    d,
                    id: top.id,
                    ver: 0,
                });
                continue;
            }
            for &e in inst.kills(t) {
                self.stamp[e as usize] = now;
            }
            g_sum += g;
            c_sum += inst.cost[t];
            picked.push(top.id);
            if g_sum / c_sum > best_d {
                best_d = g_sum / c_sum;
                best_len = picked.len();
            }
        }
        picked.truncate(best_len);
        (best_d, picked)
    }
}

/// The proposed order: lazy greedy over bundles. A cold binary's density only
/// falls while other tests run, so a stale density is an upper bound; the
/// binary just run is re-evaluated at once.
pub fn bundle_greedy(inst: &Instance) -> (Vec<u32>, u64, usize) {
    let n = inst.tests();
    let mut s = Bundler {
        inst,
        covered: vec![false; inst.weight.len()],
        done: vec![false; n],
        built: vec![false; inst.setup.len()],
        live: inst.tests_of.clone(),
        stamp: vec![0; inst.weight.len()],
        now: 0,
        evals: 0,
        warm: (0..inst.setup.len()).map(|_| None).collect(),
    };
    let mut heap = BinaryHeap::new();
    for b in 0..inst.setup.len() {
        let (d, _) = s.best(b);
        if d > 0.0 {
            heap.push(Ent {
                d,
                id: b as u32,
                ver: 0,
            });
        }
    }
    let mut order = Vec::with_capacity(n);
    while let Some(top) = heap.pop() {
        let b = top.id as usize;
        let (d, bundle) = s.best(b);
        if d <= 0.0 {
            continue;
        }
        if heap.peek().is_some_and(|nx| d < nx.d) {
            heap.push(Ent {
                d,
                id: top.id,
                ver: 0,
            });
            continue;
        }
        for &t in &bundle {
            s.done[t as usize] = true;
            order.push(t);
            for &e in inst.kills(t as usize) {
                s.covered[e as usize] = true;
            }
        }
        s.built[b] = true;
        let (d, _) = s.best(b);
        if d > 0.0 {
            heap.push(Ent {
                d,
                id: top.id,
                ver: 0,
            });
        }
    }
    let evals = s.evals;
    let boundary = order.len();
    order.extend((0..inst.tests() as u32).filter(|&t| !s.done[t as usize]));
    (order, evals, boundary)
}

//! The reference simulator's scaffolding, copied from `design/doubt/sim/sim.rs`
//! without change where §7.3 says "unchanged" (`evaluate`, `optimum`, `serial_j`)
//! and for the generators, so the same seeds give the same instances.
//!
//! Lints are allowed here so that the copy stays diffable against the original.
#![allow(clippy::all, dead_code)]

use std::cmp::Reverse;
use std::collections::{BTreeSet, BinaryHeap};

pub struct Rng(pub u64);

impl Rng {
    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    pub fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
    pub fn below(&mut self, n: usize) -> usize {
        (self.next() % n as u64) as usize
    }
    pub fn normal(&mut self) -> f64 {
        let u1 = self.unit().max(1e-300);
        let u2 = self.unit();
        (-2.0 * u1.ln()).sqrt() * (2.0 * std::f64::consts::PI * u2).cos()
    }
    pub fn lognormal(&mut self, median: f64, sigma: f64) -> f64 {
        median * (sigma * self.normal()).exp()
    }
}

pub struct Instance {
    pub bin_of: Vec<u32>,
    /// Seconds.
    pub cost: Vec<f64>,
    pub setup: Vec<f64>,
    /// Test -> fault classes it kills, CSR.
    pub off: Vec<usize>,
    pub elem: Vec<u32>,
    pub weight: Vec<f64>,
    pub tests_of: Vec<Vec<u32>>,
}

impl Instance {
    pub fn tests(&self) -> usize {
        self.cost.len()
    }
    pub fn kills(&self, t: usize) -> &[u32] {
        &self.elem[self.off[t]..self.off[t + 1]]
    }
    pub fn from_pairs(
        bin_of: Vec<u32>,
        cost: Vec<f64>,
        setup: Vec<f64>,
        weight: Vec<f64>,
        mut pairs: Vec<(u32, u32)>,
    ) -> Instance {
        pairs.sort_unstable();
        pairs.dedup();
        let n = cost.len();
        let mut off = vec![0usize; n + 1];
        for &(t, _) in &pairs {
            off[t as usize + 1] += 1;
        }
        for i in 0..n {
            off[i + 1] += off[i];
        }
        let elem = pairs.iter().map(|p| p.1).collect();
        let mut tests_of = vec![Vec::new(); setup.len()];
        for (t, &b) in bin_of.iter().enumerate() {
            tests_of[b as usize].push(t as u32);
        }
        Instance {
            bin_of,
            cost,
            setup,
            off,
            elem,
            weight,
            tests_of,
        }
    }
}

pub struct Shape {
    pub name: &'static str,
    pub tests: usize,
    pub bins: usize,
    pub units: usize,
    pub classes: usize,
    /// Median number of tests that kill one class.
    pub killers: f64,
    /// Share of a class's killers that sit in its home binary.
    pub home_share: f64,
}

pub fn generate(s: &Shape, seed: u64) -> Instance {
    let mut r = Rng(seed);
    // Binary sizes are skewed: binary i has weight 1 / (i + 1)^0.8.
    let mut cum = Vec::with_capacity(s.bins);
    let mut total = 0.0;
    for i in 0..s.bins {
        total += 1.0 / ((i + 1) as f64).powf(0.8);
        cum.push(total);
    }
    let mut bin_of = Vec::with_capacity(s.tests);
    let mut cost = Vec::with_capacity(s.tests);
    for _ in 0..s.tests {
        let x = r.unit() * total;
        let b = cum.partition_point(|&c| c < x).min(s.bins - 1);
        bin_of.push(b as u32);
        // One test in ten is an integration test.
        cost.push(if r.below(10) == 0 {
            r.lognormal(2.0, 1.0)
        } else {
            r.lognormal(0.1, 1.2)
        });
    }
    let setup: Vec<f64> = (0..s.bins).map(|_| r.lognormal(8.0, 1.0)).collect();
    let mut tests_of = vec![Vec::new(); s.bins];
    for (t, &b) in bin_of.iter().enumerate() {
        tests_of[b as usize].push(t as u32);
    }
    let mut weight = Vec::new();
    let mut pairs = Vec::new();
    for _ in 0..s.units {
        let prior = (0.02 + 0.3 * r.unit() * r.unit()).min(0.5);
        for _ in 0..s.classes {
            let e = weight.len() as u32;
            weight.push(prior / s.classes as f64);
            let home = bin_of[r.below(s.tests)] as usize;
            let k = r.lognormal(s.killers, 1.0).round().max(1.0) as usize;
            for _ in 0..k.min(s.tests) {
                let t = if r.unit() < s.home_share {
                    tests_of[home][r.below(tests_of[home].len())]
                } else {
                    r.below(s.tests) as u32
                };
                pairs.push((t, e));
            }
        }
    }
    Instance::from_pairs(bin_of, cost, setup, weight, pairs)
}

pub struct Eval {
    pub j: f64,
    pub t50: f64,
    pub t90: f64,
    pub makespan: f64,
}

/// Runs `order` on `workers` identical workers by list scheduling: a free
/// worker takes the earliest listed test that can start, building its binary
/// first if nobody has. Times are whole microseconds so the run is exact.
pub fn evaluate(inst: &Instance, order: &[u32], workers: usize) -> Eval {
    let micros = |s: f64| (s * 1e6).round().max(1.0) as u64;
    let bins = inst.setup.len();
    let mut queue: Vec<Vec<(usize, u32)>> = vec![Vec::new(); bins];
    for (pos, &t) in order.iter().enumerate() {
        queue[inst.bin_of[t as usize] as usize].push((pos, t));
    }
    let mut cur = vec![0usize; bins];
    // 0 cold, 1 building, 2 ready.
    let mut state = vec![0u8; bins];
    let mut ready: BTreeSet<(usize, u32)> = BTreeSet::new();
    for b in 0..bins {
        if let Some(&(pos, _)) = queue[b].first() {
            ready.insert((pos, b as u32));
        }
    }
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
    let mut covered = vec![false; inst.weight.len()];
    // (finish, sequence, is_test, id)
    let mut events: BinaryHeap<Reverse<(u64, u64, bool, u32)>> = BinaryHeap::new();
    let (mut now, mut seq, mut idle) = (0u64, 0u64, workers);
    let (mut j, mut got, mut t50, mut t90) = (0.0, 0.0, f64::NAN, f64::NAN);
    loop {
        while idle > 0 {
            let Some(&(pos, b)) = ready.iter().next() else {
                break;
            };
            ready.remove(&(pos, b));
            let bi = b as usize;
            idle -= 1;
            seq += 1;
            if state[bi] == 0 {
                state[bi] = 1;
                events.push(Reverse((now + micros(inst.setup[bi]), seq, false, b)));
            } else {
                let (_, t) = queue[bi][cur[bi]];
                cur[bi] += 1;
                events.push(Reverse((now + micros(inst.cost[t as usize]), seq, true, t)));
                if let Some(&(p, _)) = queue[bi].get(cur[bi]) {
                    ready.insert((p, b));
                }
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
                if !std::mem::replace(&mut covered[e as usize], true) {
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
            let bi = id as usize;
            state[bi] = 2;
            if let Some(&(p, _)) = queue[bi].get(cur[bi]) {
                ready.insert((p, id));
            }
        }
    }
    Eval {
        j,
        t50,
        t90,
        makespan: now as f64 / 1e6,
    }
}

pub fn serial_j(inst: &Instance, order: &[u32], covered: &mut [bool], built: &mut [bool]) -> f64 {
    covered.fill(false);
    built.fill(false);
    let (mut clock, mut j) = (0.0, 0.0);
    for &t in order {
        let t = t as usize;
        let b = inst.bin_of[t] as usize;
        if !std::mem::replace(&mut built[b], true) {
            clock += inst.setup[b];
        }
        clock += inst.cost[t];
        for &e in inst.kills(t) {
            if !std::mem::replace(&mut covered[e as usize], true) {
                j += inst.weight[e as usize] * clock;
            }
        }
    }
    j
}

/// Exact optimum by trying every order (Heap's algorithm). For at most 9 tests.
pub fn optimum(inst: &Instance) -> f64 {
    let n = inst.tests();
    let mut perm: Vec<u32> = (0..n as u32).collect();
    let mut covered = vec![false; inst.weight.len()];
    let mut built = vec![false; inst.setup.len()];
    let mut best = serial_j(inst, &perm, &mut covered, &mut built);
    let mut c = vec![0usize; n];
    let mut i = 0;
    while i < n {
        if c[i] < i {
            if i % 2 == 0 {
                perm.swap(0, i);
            } else {
                perm.swap(c[i], i);
            }
            best = best.min(serial_j(inst, &perm, &mut covered, &mut built));
            c[i] += 1;
            i = 0;
        } else {
            c[i] = 0;
            i += 1;
        }
    }
    best
}

pub fn small_instance(r: &mut Rng) -> Instance {
    let n = 5 + r.below(4);
    let bins = 2 + r.below(3);
    let elems = 3 + r.below(7);
    let bin_of: Vec<u32> = (0..n).map(|_| r.below(bins) as u32).collect();
    let cost: Vec<f64> = (0..n).map(|_| r.lognormal(0.5, 1.2)).collect();
    // Set-ups range from negligible to dominant, to stress both regimes.
    let setup: Vec<f64> = (0..bins).map(|_| r.lognormal(2.0, 1.8)).collect();
    let weight: Vec<f64> = (0..elems).map(|_| 0.05 + r.unit()).collect();
    let mut pairs = Vec::new();
    for e in 0..elems {
        for _ in 0..1 + r.below(3) {
            pairs.push((r.below(n) as u32, e as u32));
        }
    }
    Instance::from_pairs(bin_of, cost, setup, weight, pairs)
}

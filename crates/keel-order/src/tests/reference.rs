//! The bundle rule written the slow way, for B4: no heaps, no staleness, every
//! density recomputed from the masses before every pick. It shares no code with
//! the rule beyond the arithmetic it is specified to use (§4.2): gains summed in
//! class order in `f64` from `f32` masses, a miss mass updated as
//! `m · (1 − q)` rounded to `f32`.

use std::cmp::Ordering;

use crate::DoubtInputs;

struct Naive<'a> {
    inp: &'a DoubtInputs,
    miss: Vec<f32>,
    done: Vec<bool>,
    up: Vec<bool>,
}

fn gain(inp: &DoubtInputs, mass: &[f32], u: u32) -> f64 {
    inp.kills
        .row(u as usize)
        .iter()
        .map(|&(c, q)| f64::from(mass[c as usize]) * f64::from(q))
        .sum()
}

fn cover(inp: &DoubtInputs, mass: &mut [f32], u: u32) {
    for &(c, q) in inp.kills.row(u as usize) {
        mass[c as usize] = (f64::from(mass[c as usize]) * (1.0 - f64::from(q))) as f32;
    }
}

/// `a` ranks above `b`: greater density, then smaller reach, then smaller id.
fn above(inp: &DoubtInputs, a: (f64, u32), b: (f64, u32)) -> bool {
    a.0.total_cmp(&b.0)
        .then_with(|| inp.reach[b.1 as usize].cmp(&inp.reach[a.1 as usize]))
        .then_with(|| b.1.cmp(&a.1))
        == Ordering::Greater
}

impl Naive<'_> {
    fn sites(&self) -> Vec<Vec<u32>> {
        let mut by: Vec<(Vec<u32>, Vec<u32>)> = Vec::new();
        for u in 0..self.inp.units {
            let mut key = self.inp.needs.row(u as usize).to_vec();
            key.sort_unstable();
            key.dedup();
            match by.iter_mut().find(|(k, _)| *k == key) {
                Some((_, m)) => m.push(u),
                None => by.push((key, vec![u])),
            }
        }
        by.sort();
        by.into_iter().map(|(_, m)| m).collect()
    }

    fn steps_of(&self, members: &[u32]) -> Vec<u32> {
        let mut key = self.inp.needs.row(members[0] as usize).to_vec();
        key.sort_unstable();
        key.dedup();
        key
    }

    /// The best bundle of a site: its density and the probes in the order they would run.
    fn value(&self, members: &[u32]) -> Option<(f64, Vec<u32>)> {
        let steps = self.steps_of(members);
        let cold: Vec<u32> = steps
            .iter()
            .copied()
            .filter(|&x| !self.up[x as usize])
            .collect();
        let b: f64 = cold
            .iter()
            .map(|&x| self.inp.setup_ms[x as usize].millis())
            .sum();
        let mut mass = self.miss.clone();
        let mut left: Vec<u32> = members
            .iter()
            .copied()
            .filter(|&u| !self.done[u as usize])
            .collect();
        let (mut g_sum, mut c_sum) = (0.0f64, b);
        let mut picks: Vec<u32> = Vec::new();
        let (mut best, mut best_len) = (0.0f64, 0usize);
        loop {
            let mut top: Option<(f64, u32)> = None;
            for &u in &left {
                let g = gain(self.inp, &mass, u);
                if g <= 0.0 {
                    continue;
                }
                let cand = (g / self.inp.cost(u), u);
                if top.is_none_or(|t| above(self.inp, cand, t)) {
                    top = Some(cand);
                }
            }
            let Some((_, u)) = top else { break };
            let g = gain(self.inp, &mass, u);
            cover(self.inp, &mut mass, u);
            left.retain(|&x| x != u);
            g_sum += g;
            c_sum += self.inp.cost(u);
            picks.push(u);
            if g_sum / c_sum > best {
                best = g_sum / c_sum;
                best_len = picks.len();
            }
            if cold.is_empty() {
                // A warm site offers its densest probe only.
                break;
            }
        }
        picks.truncate(best_len);
        if picks.is_empty() {
            None
        } else {
            Some((best, picks))
        }
    }

    fn main_phase(&mut self, out: &mut Vec<u32>) {
        let sites = self.sites();
        loop {
            let mut top: Option<(f64, u32, usize, Vec<u32>)> = None;
            for (i, s) in sites.iter().enumerate() {
                let Some((d, picks)) = self.value(s) else {
                    continue;
                };
                if top
                    .as_ref()
                    .is_none_or(|t| above(self.inp, (d, picks[0]), (t.0, t.1)))
                {
                    top = Some((d, picks[0], i, picks));
                }
            }
            let Some((_, _, i, picks)) = top else { break };
            // One step at a time, as the rule does: a site with a cold step sets up its lowest cold step
            // and is priced again; a warm site starts its densest probe.
            let cold = self
                .steps_of(&sites[i])
                .into_iter()
                .find(|&x| !self.up[x as usize]);
            if let Some(x) = cold {
                self.up[x as usize] = true;
                continue;
            }
            let u = picks[0];
            self.done[u as usize] = true;
            cover(self.inp, &mut self.miss, u);
            out.push(u);
        }
    }

    /// Probes that detect nothing: ready ones cheapest first, else the step that
    /// unblocks the cheapest waiting probe.
    fn tail(&mut self, out: &mut Vec<u32>) {
        loop {
            let undone: Vec<u32> = (0..self.inp.units)
                .filter(|&u| !self.done[u as usize])
                .collect();
            if undone.is_empty() {
                return;
            }
            let key = |u: u32| (self.inp.cost(u).to_bits(), self.inp.reach[u as usize], u);
            let ready = undone
                .iter()
                .copied()
                .filter(|&u| {
                    self.inp
                        .needs
                        .row(u as usize)
                        .iter()
                        .all(|&x| self.up[x as usize])
                })
                .min_by_key(|&u| key(u));
            if let Some(u) = ready {
                self.done[u as usize] = true;
                out.push(u);
                continue;
            }
            let u = undone
                .iter()
                .copied()
                .min_by_key(|&u| key(u))
                .expect("non-empty");
            let x = self
                .inp
                .needs
                .row(u as usize)
                .iter()
                .copied()
                .filter(|&x| !self.up[x as usize])
                .min()
                .expect("a cold step");
            self.up[x as usize] = true;
        }
    }
}

/// The one-worker order of the rule with every density recomputed at every step.
pub fn naive_order(inp: &DoubtInputs) -> Vec<u32> {
    let mut n = Naive {
        inp,
        miss: inp.class_mass.clone(),
        done: vec![false; inp.units as usize],
        up: vec![false; inp.steps as usize],
    };
    let mut out = Vec::new();
    n.main_phase(&mut out);
    n.tail(&mut out);
    out
}

/// The sites of a gate-free instance: the distinct step sets, ascending, each with its probes.
/// This is the order in which the rule numbers its groups.
pub fn sites_of(inp: &DoubtInputs) -> Vec<(Vec<u32>, Vec<u32>)> {
    let mut by: Vec<(Vec<u32>, Vec<u32>)> = Vec::new();
    for u in 0..inp.units {
        let mut key = inp.needs.row(u as usize).to_vec();
        key.sort_unstable();
        key.dedup();
        match by.iter_mut().find(|(k, _)| *k == key) {
            Some((_, m)) => m.push(u),
            None => by.push((key, vec![u])),
        }
    }
    by.sort();
    by
}

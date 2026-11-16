//! The benchmark of §4.2 and the state-size claim of §4.6, at 10^5 probes in 1,000 groups.

use std::time::Instant;

use super::bridge::*;
use super::support::*;
use crate::{Pick, Rule};

pub fn shapes(tests: usize) -> [Shape; 3] {
    let bins = (tests / 100).max(4);
    [
        Shape {
            name: "leaf (20 units, killers in one binary)",
            tests,
            bins,
            units: 20,
            classes: 8,
            killers: 30.0,
            home_share: 0.9,
        },
        Shape {
            name: "core (300 units, killers spread)",
            tests,
            bins,
            units: 300,
            classes: 8,
            killers: 200.0,
            home_share: 0.3,
        },
        Shape {
            name: "merge (5000 units)",
            tests,
            bins,
            units: 5000,
            classes: 4,
            killers: 50.0,
            home_share: 0.6,
        },
    ]
}

fn uptime() -> String {
    std::process::Command::new("uptime")
        .output()
        .map(|o| String::from_utf8_lossy(&o.stdout).trim().to_owned())
        .unwrap_or_else(|e| format!("uptime unavailable: {e}"))
}

/// Drives the rule with one worker and returns (Run picks, peak of `state_bytes` over the run, evals).
fn drive_measuring(inputs: &crate::DoubtInputs) -> (Vec<u32>, usize, u64, usize) {
    let mut rule = Rule::new(inputs, &[]);
    let mut peak = rule.state_bytes();
    let mut runs = Vec::with_capacity(inputs.units as usize);
    let mut calls = 0u64;
    loop {
        calls += 1;
        match rule.next() {
            Pick::SetUp(x) => rule.up(x),
            Pick::Run(u) => runs.push(u),
            Pick::Idle => panic!("idle"),
            Pick::Finished => break,
        }
        if calls.is_multiple_of(64) {
            peak = peak.max(rule.state_bytes());
        }
    }
    peak = peak.max(rule.state_bytes());
    (runs, peak, rule.evals(), rule.peak_scratch())
}

#[test]
fn state_stays_under_two_megabytes_at_a_hundred_thousand_units() {
    // §4.6: "4 bytes a class, 1 bit a unit, 1 byte a step, one heap entry a site and one a unit of a warm
    // site: under 2 MB at 10^5 units". The inputs, which the rule borrows, are counted separately.
    let mut worst = 0usize;
    for shape in shapes(100_000) {
        let mut inst = generate(&shape, 1);
        round_weights(&mut inst);
        let inputs = inputs_of(&inst);
        let input_bytes = inputs.kills.items.len() * 8 + inputs.kills.offsets.len() * 4;
        let fresh = Rule::new(&inputs, &[]);
        let at_start = fresh.state_bytes();
        drop(fresh);
        let (_, peak, _, scratch) = drive_measuring(&inputs);
        println!(
            "{}: {} probes, {} classes, {} kill entries ({:.1} MB of borrowed inputs): state {:.2} MB at the start, {:.2} MB at its peak (largest scratch buffer {:.2} MB)",
            shape.name,
            inputs.units,
            inputs.class_mass.len(),
            inputs.kills.items.len(),
            input_bytes as f64 / 1e6,
            at_start as f64 / 1e6,
            peak as f64 / 1e6,
            scratch as f64 / 1e6
        );
        worst = worst.max(peak).max(scratch);
    }
    assert!(
        worst < 2_000_000,
        "state reached {worst} bytes, over the 2 MB of §4.6"
    );
}

#[test]
#[ignore = "benchmark: run with `cargo-stock test --release -p keel-order -- --ignored --nocapture benchmark`"]
fn benchmark_hundred_thousand_probes() {
    println!("machine load at the start: {}", uptime());
    for shape in shapes(100_000) {
        let mut inst = generate(&shape, 1);
        round_weights(&mut inst);
        let inputs = inputs_of(&inst);
        println!(
            "\n{}: {} probes, {} binaries, {} classes, {} kill entries",
            shape.name,
            inputs.units,
            inputs.steps,
            inputs.class_mass.len(),
            inputs.kills.items.len()
        );

        let t = Instant::now();
        let mut rule = Rule::new(&inputs, &[]);
        let new_ms = t.elapsed().as_secs_f64() * 1e3;
        let new_evals = rule.evals();
        let order = rule.offline_for_test();
        let offline_ms = t.elapsed().as_secs_f64() * 1e3;
        let evals = rule.evals();
        println!(
            "  offline order: {offline_ms:.1} ms in all ({new_ms:.1} ms of it in `new`), {evals} bundle evaluations ({new_evals} in `new`); load {}",
            uptime()
        );

        let t = Instant::now();
        let (sim_order, sim_evals, _) = super::reference_sim::bundle_greedy(&inst);
        println!(
            "  the simulator's own bundle_greedy on the same instance: {:.1} ms, {sim_evals} bundle evaluations ({} probes)",
            t.elapsed().as_secs_f64() * 1e3,
            sim_order.len()
        );

        let t = Instant::now();
        let (runs, peak, online_evals, _) = drive_measuring(&inputs);
        let online_ms = t.elapsed().as_secs_f64() * 1e3;
        println!(
            "  online, one worker, every `next`/`up`: {online_ms:.1} ms, {online_evals} evaluations; state peak {:.2} MB; load {}",
            peak as f64 / 1e6,
            uptime()
        );
        assert_eq!(runs.len(), order.len());

        let one = evaluate(&inst, &order, 1);
        let on1 = online_eval(&inst, &inputs, 1);
        let on16 = online_eval(&inst, &inputs, 16);
        let list16 = evaluate(&inst, &order, 16);
        println!(
            "  J, one worker, offline order list-scheduled: {:.1}  (t50 {:.1}, t90 {:.1})",
            one.j, one.t50, one.t90
        );
        println!(
            "  J, one worker, online rule:                  {:.1}  (t50 {:.1}, t90 {:.1})",
            on1.j, on1.t50, on1.t90
        );
        println!(
            "  J, 16 workers, online rule:                  {:.1}  (t50 {:.1}, t90 {:.1})",
            on16.j, on16.t50, on16.t90
        );
        println!(
            "  J, 16 workers, offline order as a list:      {:.1}  (t50 {:.1}, t90 {:.1})",
            list16.j, list16.t50, list16.t90
        );
        let sim16 = evaluate(&inst, &sim_order, 16);
        println!(
            "  J, 16 workers, the simulator's order (same positive prefix, its zero-gain tail in index order) as a list: {:.1}  (t50 {:.1}, t90 {:.1})",
            sim16.j, sim16.t50, sim16.t90
        );
    }
    println!("\nmachine load at the end: {}", uptime());
}

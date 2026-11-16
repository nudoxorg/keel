//! Simulation and scale checks for the planner. Numbers are printed; run with
//! `-- --nocapture` to see them.

use std::time::Instant;

use keel_infer::plan::{Planner, TestModel, Unit};

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
    fn unit(&mut self) -> f64 {
        (self.next() >> 11) as f64 / (1u64 << 53) as f64
    }
}

fn model(seed: u64) -> (Vec<Unit>, Vec<TestModel>) {
    let mut r = Rng(seed);
    let units: Vec<Unit> = (0..40).map(|_| Unit { prior: 0.005 + 0.06 * r.unit() }).collect();
    let tests = (0..150)
        .map(|_| {
            let mut notices: Vec<(u32, f32)> = Vec::new();
            for _ in 0..1 + r.below(5) {
                let a = r.below(40) as u32;
                if !notices.iter().any(|&(b, _)| b == a) {
                    notices.push((a, (0.1 + 0.9 * r.unit()) as f32));
                }
            }
            notices.sort_by_key(|&(a, _)| a);
            // Costs span two orders of magnitude, uncorrelated with value, so
            // index order has no reason to be good.
            TestModel { cost_ms: 100 + r.below(10_000) as u32, notices }
        })
        .collect();
    (units, tests)
}

#[test]
fn planner_order_reaches_first_failure_cheaper_and_risk_is_calibrated() {
    let (units, tests) = model(0xC0FFEE);
    let planner = Planner::new(units.clone(), tests.clone()).unwrap();
    let order = planner.schedule();
    let total_cost: u64 = tests.iter().map(|t| u64::from(t.cost_ms)).sum();

    let mut rng = Rng(0x5EED_1234_ABCD_EF01);
    let trials = 2_000;
    let (mut planner_cost, mut index_cost, mut with_failure) = (0u128, 0u128, 0u64);
    // Calibration, pooled over every schedule step whose reported risk is in the band
    // and whose prefix all passed in this trial.
    let (mut samples, mut some_fail, mut reported_sum) = (0u64, 0u64, 0.0f64);

    for _ in 0..trials {
        let wrong: Vec<bool> = units.iter().map(|u| rng.unit() < u.prior).collect();
        // Draw every (test, unit) detection so the stream does not depend on `wrong`.
        let fails: Vec<bool> = tests
            .iter()
            .map(|t| {
                let mut f = false;
                for &(a, d) in &t.notices {
                    f |= rng.unit() < f64::from(d) && wrong[a as usize];
                }
                f
            })
            .collect();
        if !fails.iter().any(|&f| f) {
            continue;
        }
        with_failure += 1;

        let mut cost = 0u128;
        for s in &order {
            cost += u128::from(tests[s.test as usize].cost_ms);
            if fails[s.test as usize] {
                break;
            }
        }
        planner_cost += cost;

        let mut cost = 0u128;
        for (i, t) in tests.iter().enumerate() {
            cost += u128::from(t.cost_ms);
            if fails[i] {
                break;
            }
        }
        index_cost += cost;
    }

    // Calibration needs trials where the prefix passed, including trials with no failure,
    // so it uses its own pass over fresh draws.
    for _ in 0..trials {
        let wrong: Vec<bool> = units.iter().map(|u| rng.unit() < u.prior).collect();
        let fails: Vec<bool> = tests
            .iter()
            .map(|t| {
                let mut f = false;
                for &(a, d) in &t.notices {
                    f |= rng.unit() < f64::from(d) && wrong[a as usize];
                }
                f
            })
            .collect();
        // suffix_fail[i]: some scheduled test at position > i fails
        let mut suffix_fail = vec![false; order.len() + 1];
        for i in (0..order.len()).rev() {
            suffix_fail[i] = suffix_fail[i + 1] || fails[order[i].test as usize];
        }
        for (i, s) in order.iter().enumerate() {
            if fails[s.test as usize] {
                break; // prefix no longer all-pass
            }
            if (0.05..=0.15).contains(&s.residual_risk) {
                samples += 1;
                reported_sum += s.residual_risk;
                some_fail += u64::from(suffix_fail[i + 1]);
            }
        }
    }

    let mean_planner = planner_cost as f64 / with_failure as f64;
    let mean_index = index_cost as f64 / with_failure as f64;
    let observed = some_fail as f64 / samples as f64;
    println!(
        "SIM trials={trials} with_failure={with_failure} total_suite_ms={total_cost} \
         mean_ms_to_first_failure planner={mean_planner:.0} index={mean_index:.0} ratio={:.3}",
        mean_planner / mean_index
    );
    println!(
        "CALIBRATION samples={samples} mean_reported_risk={:.4} observed_fraction={observed:.4}",
        reported_sum / samples as f64
    );
    assert!(with_failure > 200, "too few trials had a failure to compare orders");
    assert!(mean_planner <= mean_index, "planner {mean_planner} vs index {mean_index}");
    assert!(samples >= 100, "calibration band was reached by only {samples} samples");
    assert!((0.03..=0.20).contains(&observed), "observed {observed}");
}

#[test]
fn live_replanning_matches_the_schedule_while_everything_passes() {
    let (units, tests) = model(7);
    let mut p = Planner::new(units, tests).unwrap();
    let order = p.schedule();
    for s in order.iter().take(40) {
        assert_eq!(p.next(), Some(s.test));
        p.observe(s.test, true);
    }
}

fn log_uniform(r: &mut Rng, lo: f64, hi: f64) -> f64 {
    lo * (hi / lo).powf(r.unit())
}

/// 200,000 tests, 5,000 units, 20 notices each. `skewed` draws costs, priors
/// and notice probabilities log-uniformly (a few cheap, sharp tests and a long
/// tail), which is closer to a real suite than the flat draw.
fn bench(label: &str, skewed: bool) {
    let mut r = Rng(0xBEEF);
    let units: Vec<Unit> = (0..5_000)
        .map(|_| Unit {
            prior: if skewed { log_uniform(&mut r, 0.0005, 0.3) } else { 0.001 + 0.2 * r.unit() },
        })
        .collect();
    let tests: Vec<TestModel> = (0..200_000)
        .map(|_| {
            let mut us: Vec<u32> = Vec::with_capacity(20);
            while us.len() < 20 {
                let a = r.below(5_000) as u32;
                if !us.contains(&a) {
                    us.push(a);
                }
            }
            us.sort_unstable();
            let cost_ms = if skewed {
                log_uniform(&mut r, 10.0, 600_000.0) as u32
            } else {
                50 + r.below(5_000) as u32
            };
            let notices = us
                .into_iter()
                .map(|a| {
                    let d = if skewed {
                        log_uniform(&mut r, 0.001, 0.9)
                    } else {
                        0.05 + 0.9 * r.unit()
                    };
                    (a, d as f32)
                })
                .collect();
            TestModel { cost_ms, notices }
        })
        .collect();
    let planner = Planner::new(units, tests).unwrap();
    let t0 = Instant::now();
    let steps = planner.schedule();
    let wall = t0.elapsed();
    println!(
        "BENCH {label}: 200000 tests x 20 notices, 5000 units -> {} steps in {:.3} s wall, final risk {:.3e}, total {} ms",
        steps.len(),
        wall.as_secs_f64(),
        steps.last().map_or(0.0, |s| s.residual_risk),
        steps.last().map_or(0, |s| s.cumulative_ms),
    );
    assert!(steps.windows(2).all(|w| w[1].residual_risk <= w[0].residual_risk));
}

/// Ignored by default (it builds a large instance); run with
/// `--release -- --ignored --nocapture bench`.
#[test]
#[ignore]
fn bench_schedule_200k_flat() {
    bench("flat", false);
}

#[test]
#[ignore]
fn bench_schedule_200k_skewed() {
    bench("skewed", true);
}

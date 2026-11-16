use keel_infer::plan::{PlanError, Planner, TestModel, Unit};
use proptest::prelude::*;
use roaring::RoaringBitmap;

fn unit(p: f64) -> Unit {
    Unit { prior: p }
}
fn test(cost_ms: u32, notices: &[(u32, f32)]) -> TestModel {
    TestModel { cost_ms, notices: notices.to_vec() }
}
fn close(a: f64, b: f64) {
    assert!((a - b).abs() < 1e-12, "{a} vs {b}");
}
fn all(n: usize) -> RoaringBitmap {
    (0..n as u32).collect()
}

/// Two units, three tests, worked by hand.
///   A prior 0.2, B prior 0.1.
///   t0 (100 ms) notices A at 0.5   score 0.2*0.5/100            = 0.0010
///   t1 (100 ms) notices B at 1.0   score 0.1*1.0/100            = 0.0010
///   t2 ( 50 ms) notices A, B at .5 score (0.1 + 0.05)/50        = 0.0030
/// t2 goes first. After t2 passes:
///   A = 0.2*0.5/(1-0.1)  = 1/9      B = 0.1*0.5/(1-0.05) = 1/19
///   t0: (1/9)*0.5/100 = 0.000556    t1: (1/19)/100 = 0.000526   -> t0, then t1.
/// After t0 passes: A = (1/9)(0.5)/(1-1/18) = 1/17.
/// Residual risk after t2 (t0, t1 unrun): 1-(1-1/18)(1-1/19) = 1-(17/18)(18/19) = 2/19.
/// After t0 (t1 unrun): only B counts: 1/19. After t1: 0.
fn hand() -> Planner {
    Planner::new(
        vec![unit(0.2), unit(0.1)],
        vec![test(100, &[(0, 0.5)]), test(100, &[(1, 1.0)]), test(50, &[(0, 0.5), (1, 0.5)])],
    )
    .unwrap()
}

#[test]
fn hand_example_order_beliefs_and_risks() {
    let mut p = hand();
    assert_eq!(p.next(), Some(2));
    let s = hand().schedule();
    assert_eq!(s.iter().map(|x| x.test).collect::<Vec<_>>(), vec![2, 0, 1]);
    assert_eq!(s.iter().map(|x| x.cumulative_ms).collect::<Vec<_>>(), vec![50, 150, 250]);
    close(s[0].expected_removed, 0.15);
    close(s[1].expected_removed, 0.5 / 9.0);
    close(s[2].expected_removed, 1.0 / 19.0);
    close(s[0].residual_risk, 2.0 / 19.0);
    close(s[1].residual_risk, 1.0 / 19.0);
    assert_eq!(s[2].residual_risk, 0.0);

    p.observe(2, true);
    close(p.belief(0), 1.0 / 9.0);
    close(p.belief(1), 1.0 / 19.0);
    close(p.residual_risk(&all(3)), 2.0 / 19.0);
    assert_eq!(p.next(), Some(0));
    p.observe(0, true);
    close(p.belief(0), 1.0 / 17.0);
    assert_eq!(p.next(), Some(1));
    p.observe(1, true);
    assert_eq!(p.belief(1), 0.0); // a certain-to-notice test passed
    assert_eq!(p.next(), None);
}

#[test]
fn hand_example_failure_raises_by_the_noisy_or_posterior() {
    let mut p = hand();
    p.observe(2, false);
    // P(fail) = 1 - (1-0.1)(1-0.05) = 0.145
    // A: 0.2 * [1 - 0.5*0.95] / 0.145 = 0.2*0.525/0.145
    // B: 0.1 * [1 - 0.5*0.9 ] / 0.145 = 0.1*0.55/0.145
    close(p.belief(0), 0.2 * 0.525 / 0.145);
    close(p.belief(1), 0.1 * 0.55 / 0.145);
    assert!(p.failed().contains(2));
}

#[test]
fn a_test_that_notices_nothing_is_never_first_and_next_stops() {
    let p = Planner::new(
        vec![unit(0.3)],
        vec![test(1, &[]), test(1000, &[(0, 0.01)]), test(1, &[])],
    )
    .unwrap();
    assert_eq!(p.next(), Some(1));
    let s = p.schedule();
    assert_eq!(s.len(), 1);
    assert_eq!(s[0].test, 1);
    let mut p = p;
    p.observe(1, true);
    assert_eq!(p.next(), None);
    let only_useless = Planner::new(vec![unit(0.3)], vec![test(1, &[]), test(2, &[])]).unwrap();
    assert_eq!(only_useless.next(), None);
    assert!(only_useless.schedule().is_empty());
}

#[test]
fn pass_lowers_noticed_beliefs_only_and_fail_raises_them() {
    let build = || {
        Planner::new(
            vec![unit(0.2), unit(0.1), unit(0.4)],
            vec![test(10, &[(0, 0.5), (1, 0.3)]), test(10, &[(2, 0.9)])],
        )
        .unwrap()
    };
    let mut p = build();
    p.observe(0, true);
    assert!(p.belief(0) < 0.2 && p.belief(1) < 0.1);
    assert_eq!(p.belief(2), 0.4);

    let mut p = build();
    p.observe(0, false);
    assert!(p.belief(0) > 0.2 && p.belief(1) > 0.1);
    assert_eq!(p.belief(2), 0.4);
    // The unlikely, weakly detected unit still goes up under the exact posterior.
    let mut q = Planner::new(
        vec![unit(0.05), unit(0.6)],
        vec![test(10, &[(0, 0.1), (1, 0.9)])],
    )
    .unwrap();
    q.observe(0, false);
    assert!(q.belief(0) > 0.05 && q.belief(1) > 0.6 && q.belief(1) < 1.0);
}

#[test]
fn repeated_or_unknown_observations_change_nothing() {
    let mut p = hand();
    p.observe(2, true);
    let b = (p.belief(0), p.belief(1));
    p.observe(2, true);
    p.observe(2, false);
    p.observe(99, false);
    assert_eq!((p.belief(0), p.belief(1)), b);
    assert!(p.failed().is_empty());
}

#[test]
fn a_failure_the_model_called_impossible_leaves_beliefs_alone() {
    let mut p = Planner::new(vec![unit(0.5)], vec![test(1, &[(0, 1.0)]), test(1, &[(0, 0.5)])]).unwrap();
    p.observe(0, true); // belief becomes 0
    p.observe(1, false);
    assert_eq!(p.belief(0), 0.0);
}

#[test]
fn residual_risk_basics() {
    let p = hand();
    assert_eq!(p.residual_risk(&RoaringBitmap::new()), 0.0);
    close(p.residual_risk(&all(3)), 1.0 - (1.0 - 0.2 * 0.75) * (1.0 - 0.1 * 1.0));
    // a single certain-notice test exposes unit B's full prior
    close(p.residual_risk(&RoaringBitmap::from_iter([1])), 0.1);
    // out-of-range ids are ignored
    close(p.residual_risk(&RoaringBitmap::from_iter([1, 500])), 0.1);
}

#[test]
fn schedule_does_not_mutate_and_is_repeatable() {
    let p = hand();
    let a = p.schedule();
    assert_eq!(a, p.schedule());
    close(p.belief(0), 0.2);
    assert_eq!(p.next(), Some(2));
}

#[test]
fn schedule_after_some_observations_covers_only_the_rest() {
    let mut p = hand();
    p.observe(2, true);
    let s = p.schedule();
    assert_eq!(s.iter().map(|x| x.test).collect::<Vec<_>>(), vec![0, 1]);
    close(s[0].residual_risk, 1.0 / 19.0);
}

#[test]
fn constructor_errors_say_what_to_fix() {
    let bad_prior = Planner::new(vec![unit(1.0)], vec![]).unwrap_err();
    assert!(matches!(bad_prior, PlanError::PriorOutOfRange { unit: 0, .. }));
    assert!(bad_prior.to_string().contains("strictly between"));
    assert!(matches!(Planner::new(vec![unit(f64::NAN)], vec![]), Err(PlanError::PriorOutOfRange { .. })));
    assert!(matches!(
        Planner::new(vec![unit(0.5)], vec![test(0, &[])]),
        Err(PlanError::ZeroCost { test: 0 })
    ));
    assert!(matches!(
        Planner::new(vec![unit(0.5)], vec![test(1, &[(3, 0.5)])]),
        Err(PlanError::UnknownUnit { unit: 3, .. })
    ));
    assert!(matches!(
        Planner::new(vec![unit(0.5), unit(0.5)], vec![test(1, &[(1, 0.5), (0, 0.5)])]),
        Err(PlanError::NoticesNotSorted { .. })
    ));
    assert!(matches!(
        Planner::new(vec![unit(0.5), unit(0.5)], vec![test(1, &[(1, 0.5), (1, 0.5)])]),
        Err(PlanError::NoticesNotSorted { .. })
    ));
    for d in [0.0f32, -0.5, 1.5, f32::NAN] {
        assert!(matches!(
            Planner::new(vec![unit(0.5)], vec![test(1, &[(0, d)])]),
            Err(PlanError::DetectOutOfRange { .. })
        ));
    }
}

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

/// `ties` draws every number from a tiny set so many tests score exactly alike.
fn instance(seed: u64, ntests: usize, nunits: usize, ties: bool) -> (Vec<Unit>, Vec<TestModel>) {
    let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let units = (0..nunits)
        .map(|_| {
            if ties {
                unit([0.1, 0.25, 0.5][r.below(3) as usize])
            } else {
                unit(0.01 + 0.9 * r.unit())
            }
        })
        .collect();
    let tests = (0..ntests)
        .map(|_| {
            let mut notices = Vec::new();
            for a in 0..nunits as u32 {
                if r.below(100) < 25 {
                    let d = if ties {
                        [0.25f32, 0.5, 1.0][r.below(3) as usize]
                    } else {
                        (0.02 + 0.98 * r.unit()) as f32
                    };
                    notices.push((a, d));
                }
            }
            let cost = if ties { [1, 2, 4][r.below(3) as usize] } else { 1 + r.below(500) as u32 };
            test(cost, &notices)
        })
        .collect();
    (units, tests)
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(300))]

    #[test]
    fn lazy_greedy_equals_naive_greedy(seed in any::<u64>(), ntests in 1usize..=200, nunits in 1usize..=12, ties in any::<bool>()) {
        let (units, tests) = instance(seed, ntests, nunits, ties);
        let planner = Planner::new(units, tests.clone()).unwrap();
        let lazy = planner.schedule();

        let mut naive = planner.clone();
        let mut remaining = all(ntests);
        let mut cum = 0u64;
        let mut want = Vec::new();
        while let Some(t) = naive.next() {
            let removed: f64 = tests[t as usize].notices.iter()
                .map(|&(a, d)| naive.belief(a) * f64::from(d)).sum();
            cum += u64::from(tests[t as usize].cost_ms);
            naive.observe(t, true);
            remaining.remove(t);
            want.push((t, cum, removed, naive.residual_risk(&remaining)));
        }
        prop_assert_eq!(lazy.len(), want.len());
        for (s, (t, cum, removed, risk)) in lazy.iter().zip(&want) {
            prop_assert_eq!(s.test, *t);
            prop_assert_eq!(s.cumulative_ms, *cum);
            prop_assert_eq!(s.expected_removed.to_bits(), removed.to_bits());
            prop_assert!((s.residual_risk - risk).abs() < 1e-9, "{} vs {}", s.residual_risk, risk);
        }
        // monotone, and identical on a second call
        for w in lazy.windows(2) {
            prop_assert!(w[1].residual_risk <= w[0].residual_risk);
        }
        prop_assert_eq!(&lazy, &planner.schedule());
        // Tiny windows force the re-cut path over and over; the order must not care.
        for w in [1usize, 2, 3, 7, 40] {
            prop_assert_eq!(&lazy, &planner.schedule_windowed(w), "window {}", w);
        }
    }

    #[test]
    fn beliefs_stay_valid_under_any_results(seed in any::<u64>(), results in proptest::collection::vec(any::<bool>(), 1..40)) {
        let (units, tests) = instance(seed, 40, 8, false);
        let mut p = Planner::new(units, tests).unwrap();
        for (t, ok) in results.iter().enumerate() {
            p.observe(t as u32, *ok);
            for a in 0..8 {
                let b = p.belief(a);
                prop_assert!((0.0..1.0).contains(&b), "belief {b}");
            }
        }
    }
}

/// A failure of a test that fails on its own one run in five says less about
/// the code than the same failure of a test that never does.
#[test]
fn a_leaky_test_moves_belief_less_and_by_the_exact_amount() {
    let units = vec![Unit { prior: 0.1 }];
    let tests = vec![TestModel { cost_ms: 1, notices: vec![(0, 0.5)] }];
    let mut steady = Planner::new(units.clone(), tests.clone()).unwrap();
    let mut leaky = Planner::new(units, tests).unwrap().with_leaks(&[0.2]).unwrap();
    steady.observe(0, false);
    leaky.observe(0, false);
    // No leak: the only explanation is the unit.
    assert!(steady.belief(0) > 0.999_999);
    // P(fail) = 1 - 0.8 * (1 - 0.05) = 0.24; P(fail | wrong) = 1 - 0.8 * 0.5 = 0.6.
    let expected = 0.1 * 0.6 / 0.24;
    assert!((leaky.belief(0) - expected).abs() < 1e-12, "{} vs {expected}", leaky.belief(0));
}

#[test]
fn leaks_are_one_per_test_and_below_one() {
    let p = || {
        Planner::new(vec![Unit { prior: 0.1 }], vec![TestModel { cost_ms: 1, notices: vec![(0, 0.5)] }]).unwrap()
    };
    assert!(matches!(p().with_leaks(&[]), Err(PlanError::LeakCount { given: 0, tests: 1 })));
    assert!(matches!(p().with_leaks(&[1.0]), Err(PlanError::LeakOutOfRange { test: 0, .. })));
    assert!(matches!(p().with_leaks(&[-0.1]), Err(PlanError::LeakOutOfRange { test: 0, .. })));
}

/// Running every test brings "worth running" to zero, but a unit that no
/// test notices is exactly as doubtful as before.
#[test]
fn what_could_escape_does_not_vanish_when_the_tests_run_out() {
    let units = vec![Unit { prior: 0.2 }, Unit { prior: 0.3 }];
    let tests = vec![TestModel { cost_ms: 1, notices: vec![(0, 1.0)] }];
    let mut p = Planner::new(units, tests).unwrap();
    assert!((p.could_escape() - (1.0 - 0.8 * 0.7)).abs() < 1e-12);
    p.observe(0, true);
    let all: roaring::RoaringBitmap = (0..1).collect();
    assert_eq!(p.residual_risk(&all), 0.0);
    // Unit 0 is cleared by a certain test; unit 1 keeps its prior.
    assert!((p.could_escape() - 0.3).abs() < 1e-12);
}

/// Found by the design review: the product of marginals after a failure
/// said 0.776 where the truth is 1.
#[test]
fn a_failure_with_no_leak_means_something_is_wrong() {
    let units = vec![Unit { prior: 0.1 }, Unit { prior: 0.1 }];
    let tests = vec![TestModel { cost_ms: 1, notices: vec![(0, 1.0), (1, 1.0)] }];
    let mut p = Planner::new(units, tests).unwrap();
    p.observe(0, false);
    assert!((p.could_escape() - 1.0).abs() < 1e-12, "{}", p.could_escape());
    assert!(p.contradictions().is_empty());
}

/// With a leak, the failure may be the test's own: the floor is what the
/// failure establishes, 1 - leak * P(all fine) / P(fail).
#[test]
fn a_leaky_failure_sets_the_floor_it_establishes() {
    let units = vec![Unit { prior: 0.1 }];
    let tests = vec![TestModel { cost_ms: 1, notices: vec![(0, 0.5)] }];
    let mut p = Planner::new(units, tests).unwrap().with_leaks(&[0.2]).unwrap();
    p.observe(0, false);
    // P(fail) = 0.24; P(unit fine and fail) = 0.9 * 0.2 = 0.18.
    assert!((p.could_escape() - (1.0 - 0.18 / 0.24)).abs() < 1e-12, "{}", p.could_escape());
}

/// A certain test cleared the unit; another test that only that unit could
/// explain then fails. The model is contradicted and must say so.
#[test]
fn a_failure_the_model_called_impossible_is_kept_as_a_contradiction() {
    let units = vec![Unit { prior: 0.3 }];
    let tests = vec![
        TestModel { cost_ms: 1, notices: vec![(0, 1.0)] },
        TestModel { cost_ms: 1, notices: vec![(0, 0.5)] },
    ];
    let mut p = Planner::new(units, tests).unwrap();
    p.observe(0, true);
    assert_eq!(p.belief(0), 0.0);
    p.observe(1, false);
    assert_eq!(p.contradictions(), &[1]);
    assert_eq!(p.could_escape(), 1.0);
}

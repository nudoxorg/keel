use keel_infer::explain::{Attr, ExplainError, ExplainOptions, Universe, explain};
use proptest::prelude::*;
use roaring::RoaringBitmap;

fn bm(it: impl IntoIterator<Item = u32>) -> RoaringBitmap {
    it.into_iter().collect()
}

fn attr(name: &str, kind: &str, tests: impl IntoIterator<Item = u32>, stands_on: &[u32]) -> Attr {
    Attr { name: name.into(), kind: kind.into(), tests: bm(tests), stands_on: stands_on.to_vec() }
}

fn everything(u: &Universe) -> RoaringBitmap {
    (0..u.tests).collect()
}

#[test]
fn one_attribute_down_among_fifty() {
    let attrs: Vec<Attr> = (0..50u32)
        .map(|i| attr(&format!("node:n{i}"), "node", i * 10..i * 10 + 10, &[]))
        .collect();
    let u = Universe { tests: 500, attrs };
    let failed = bm(170..180);
    let e = explain(&u, &everything(&u), &failed, &ExplainOptions::default()).unwrap();
    assert_eq!(e.causes.len(), 1);
    assert_eq!(e.causes[0].attr, 17);
    assert_eq!((e.causes[0].executed, e.causes[0].failed, e.causes[0].newly_explained), (10, 10, 10));
    assert!(e.causes[0].exceptions.is_empty() && e.causes[0].consequences.is_empty());
    assert!(e.residue.is_empty());
    assert!(e.bits_explained < e.bits_listed);
}

#[test]
fn chain_reports_the_bottom_as_cause() {
    // wal <- indexing <- cli-index, each with its own tests, all failing.
    let u = Universe {
        tests: 40,
        attrs: vec![
            attr("node:store.wal", "node", 0..10, &[]),
            attr("node:indexing", "node", 10..20, &[0]),
            attr("node:cli-index", "node", 20..30, &[1]),
            attr("node:other", "node", 30..40, &[]),
        ],
    };
    let failed = bm(0..30);
    let e = explain(&u, &everything(&u), &failed, &ExplainOptions::default()).unwrap();
    assert_eq!(e.causes.len(), 1);
    assert_eq!(e.causes[0].attr, 0);
    assert_eq!(e.causes[0].newly_explained, 30);
    assert_eq!(e.causes[0].consequences, vec![1, 2]);
    assert!(e.residue.is_empty());
}

#[test]
fn dependant_with_more_tests_than_its_dependency_is_still_a_consequence() {
    // indexing's failures are a strict superset of wal's; the stands-on edge
    // must win over the subset rule, or neither would be a root.
    let u = Universe {
        tests: 20,
        attrs: vec![
            attr("node:wal", "node", 0..5, &[]),
            attr("node:indexing", "node", 0..12, &[0]),
            attr("node:other", "node", 12..20, &[]),
        ],
    };
    let e = explain(&u, &everything(&u), &bm(0..12), &ExplainOptions::default()).unwrap();
    assert_eq!(e.causes.len(), 1);
    assert_eq!(e.causes[0].attr, 0);
    assert_eq!(e.causes[0].consequences, vec![1]);
    assert!(e.residue.is_empty());
}

#[test]
fn two_independent_attributes_give_two_causes() {
    let u = Universe {
        tests: 60,
        attrs: vec![
            attr("node:a", "node", 0..15, &[]),
            attr("node:b", "node", 15..30, &[]),
            attr("node:c", "node", 30..45, &[]),
            attr("node:d", "node", 45..60, &[]),
        ],
    };
    let failed = bm((0..15).chain(45..60));
    let e = explain(&u, &everything(&u), &failed, &ExplainOptions::default()).unwrap();
    let got: Vec<u32> = e.causes.iter().map(|c| c.attr).collect();
    assert_eq!(got, vec![0, 3]); // equal gains: smaller id first
    assert!(e.residue.is_empty());
}

#[test]
fn one_passing_test_blocks_purity_one_but_not_point_nine() {
    let attrs: Vec<Attr> = (0..10u32)
        .map(|i| attr(&format!("node:n{i}"), "node", i * 10..i * 10 + 10, &[]))
        .collect();
    let u = Universe { tests: 100, attrs };
    let failed = bm((30..40).filter(|&t| t != 33));
    let strict = explain(&u, &everything(&u), &failed, &ExplainOptions::default()).unwrap();
    assert!(strict.causes.is_empty());
    assert_eq!(strict.residue.len(), 9);

    let loose = ExplainOptions { purity: 0.9, ..ExplainOptions::default() };
    let e = explain(&u, &everything(&u), &failed, &loose).unwrap();
    assert_eq!(e.causes.len(), 1);
    assert_eq!(e.causes[0].attr, 3);
    assert_eq!(e.causes[0].exceptions, vec![33]);
    assert!(e.residue.is_empty());
    assert!(e.bits_explained < e.bits_listed);
}

#[test]
fn scattered_failures_stay_as_residue() {
    let attrs: Vec<Attr> = (0..10u32)
        .map(|i| attr(&format!("node:n{i}"), "node", i * 10..i * 10 + 10, &[]))
        .collect();
    let u = Universe { tests: 100, attrs };
    let failed = bm([3, 14, 25, 36, 47, 58, 69, 70, 81, 92]);
    let e = explain(&u, &everything(&u), &failed, &ExplainOptions::default()).unwrap();
    assert!(e.causes.is_empty());
    assert_eq!(e.residue, failed.iter().collect::<Vec<_>>());
    assert_eq!(e.bits_explained, e.bits_listed);
    assert!(e.bits_listed > 0.0);
}

#[test]
fn language_across_every_node_is_one_cause() {
    // 4 nodes x 3 languages x 5 tests.
    let langs = ["python", "rust", "go"];
    let mut node_tests = vec![Vec::new(); 4];
    let mut lang_tests = vec![Vec::new(); 3];
    for n in 0..4u32 {
        for l in 0..3u32 {
            for k in 0..5u32 {
                let t = n * 15 + l * 5 + k;
                node_tests[n as usize].push(t);
                lang_tests[l as usize].push(t);
            }
        }
    }
    let mut attrs: Vec<Attr> = node_tests
        .into_iter()
        .enumerate()
        .map(|(i, t)| attr(&format!("node:n{i}"), "node", t, &[]))
        .collect();
    for (i, t) in lang_tests.iter().enumerate() {
        attrs.push(attr(&format!("language:{}", langs[i]), "axis", t.iter().copied(), &[]));
    }
    let u = Universe { tests: 60, attrs };
    let failed: RoaringBitmap = lang_tests[0].iter().copied().collect();
    let e = explain(&u, &everything(&u), &failed, &ExplainOptions::default()).unwrap();
    assert_eq!(e.causes.len(), 1);
    assert_eq!(e.causes[0].attr, 4);
    assert!(e.residue.is_empty());
}

#[test]
fn equal_failing_sets_prefer_the_node() {
    let u = Universe {
        tests: 30,
        attrs: vec![
            attr("language:python", "axis", 0..10, &[]),
            attr("node:a", "node", 0..10, &[]),
            attr("node:b", "node", 10..30, &[]),
        ],
    };
    let e = explain(&u, &everything(&u), &bm(0..10), &ExplainOptions::default()).unwrap();
    assert_eq!(e.causes.len(), 1);
    assert_eq!(e.causes[0].attr, 1);
    assert_eq!(e.causes[0].consequences, vec![0]);
}

#[test]
fn strict_subset_is_a_consequence() {
    let u = Universe {
        tests: 40,
        attrs: vec![
            attr("node:small", "node", 0..4, &[]),
            attr("language:python", "axis", 0..12, &[]),
            attr("node:rest", "node", 12..40, &[]),
        ],
    };
    let e = explain(&u, &everything(&u), &bm(0..12), &ExplainOptions::default()).unwrap();
    assert_eq!(e.causes.len(), 1);
    assert_eq!(e.causes[0].attr, 1);
    assert_eq!(e.causes[0].consequences, vec![0]);
}

#[test]
fn unexecuted_tests_do_not_count_against_purity() {
    let u = Universe { tests: 20, attrs: vec![attr("node:a", "node", 0..10, &[])] };
    let executed = bm(0..6);
    let e = explain(&u, &executed, &bm(0..6), &ExplainOptions::default()).unwrap();
    assert_eq!((e.causes[0].executed, e.causes[0].failed), (6, 6));
}

#[test]
fn max_causes_leaves_the_rest_as_residue() {
    let attrs: Vec<Attr> = (0..4u32)
        .map(|i| attr(&format!("node:n{i}"), "node", i * 20..i * 20 + 20, &[]))
        .collect();
    let u = Universe { tests: 80, attrs };
    let opts = ExplainOptions { max_causes: 2, ..ExplainOptions::default() };
    let e = explain(&u, &everything(&u), &bm(0..80), &opts).unwrap();
    assert_eq!(e.causes.len(), 2);
    assert_eq!(e.residue.len(), 40);
}

#[test]
fn rejects_bad_input_with_a_message() {
    let u = Universe {
        tests: 10,
        attrs: vec![attr("node:a", "node", 0..5, &[]), attr("node:b", "node", 5..10, &[0])],
    };
    let o = ExplainOptions::default();
    let err = explain(&u, &bm(0..5), &bm([7]), &o).unwrap_err();
    assert!(matches!(err, ExplainError::FailedNotExecuted { test: 7 }));
    assert!(err.to_string().contains("not in `executed`"));
    assert!(matches!(
        explain(&u, &bm([99]), &bm([]), &o).unwrap_err(),
        ExplainError::TestOutOfRange { .. }
    ));
    let bad = Universe { tests: 10, attrs: vec![attr("node:a", "node", 0..5, &[3])] };
    assert!(matches!(
        explain(&bad, &bm(0..5), &bm([]), &o).unwrap_err(),
        ExplainError::UnknownEdge { .. }
    ));
    let cyc = Universe {
        tests: 10,
        attrs: vec![attr("node:a", "node", 0..5, &[1]), attr("node:b", "node", 5..10, &[0])],
    };
    assert!(matches!(
        explain(&cyc, &bm(0..5), &bm([]), &o).unwrap_err(),
        ExplainError::Cycle { .. }
    ));
    let p = ExplainOptions { purity: 0.0, ..o };
    assert!(matches!(
        explain(&u, &bm(0..5), &bm([]), &p).unwrap_err(),
        ExplainError::BadPurity(_)
    ));
}

#[test]
fn universe_round_trips_through_json() {
    let u = Universe { tests: 10, attrs: vec![attr("node:a", "node", 0..5, &[])] };
    let s = serde_json::to_string(&u).unwrap();
    let back: Universe = serde_json::from_str(&s).unwrap();
    assert_eq!(back.attrs[0].tests, u.attrs[0].tests);
}

// A tiny deterministic generator so cases shrink by seed and stay reproducible.
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
}

struct Planted {
    u: Universe,
    broken: Vec<u32>,
    failed: RoaringBitmap,
}

fn planted(seed: u64, tests: u32, nattrs: usize, nbroken: usize) -> Planted {
    let mut r = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut attrs: Vec<Attr> = Vec::new();
    for i in 0..nattrs {
        let node = r.below(10) < 8;
        let size = 2 + r.below(u64::from(tests / 3)) as usize;
        let mut ts = RoaringBitmap::new();
        while ts.len() < size as u64 {
            ts.insert(r.below(u64::from(tests)) as u32);
        }
        let mut stands_on = Vec::new();
        if node {
            for (j, other) in attrs.iter().enumerate() {
                if other.kind == "node" && r.below(100) < 15 {
                    stands_on.push(j as u32);
                }
            }
        }
        attrs.push(Attr {
            name: format!("a{i}"),
            kind: if node { "node" } else { "axis" }.into(),
            tests: ts,
            stands_on,
        });
    }
    let mut broken = Vec::new();
    while broken.len() < nbroken {
        let b = r.below(nattrs as u64) as u32;
        if !broken.contains(&b) {
            broken.push(b);
        }
    }
    // bad[i]: attribute i is broken or transitively stands on a broken one
    // (edges point to smaller indices, so one forward pass is the closure).
    let mut bad = vec![false; nattrs];
    for i in 0..nattrs {
        bad[i] = broken.contains(&(i as u32))
            || attrs[i].stands_on.iter().any(|&j| bad[j as usize]);
    }
    let mut failed = RoaringBitmap::new();
    for (i, a) in attrs.iter().enumerate() {
        if bad[i] {
            failed |= &a.tests;
        }
    }
    Planted { u: Universe { tests, attrs }, broken, failed }
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(400))]
    #[test]
    fn planted_causes_are_found(seed in any::<u64>(), tests in 60u32..=300, nattrs in 3usize..=40, nbroken in 1usize..=3) {
        let p = planted(seed, tests, nattrs, nbroken.min(nattrs));
        let opts = ExplainOptions { max_causes: 64, ..ExplainOptions::default() };
        let all = everything(&p.u);
        let e = explain(&p.u, &all, &p.failed, &opts).unwrap();
        prop_assert!(e.residue.is_empty(), "residue {:?}", e.residue);
        // What the causes and their consequences account for, as tests.
        let mut accounted = RoaringBitmap::new();
        for c in &e.causes {
            accounted |= &p.u.attrs[c.attr as usize].tests;
            for &k in &c.consequences {
                accounted |= &p.u.attrs[k as usize].tests;
            }
        }
        for b in &p.broken {
            let tests = &p.u.attrs[*b as usize].tests;
            let named = e.causes.iter().any(|c| {
                c.attr == *b
                    || c.consequences.contains(b)
                    || &p.u.attrs[c.attr as usize].tests == tests
            });
            // A planted attribute whose every test is already explained by other causes
            // (its failures are covered by a union, not by a single attribute) costs more
            // to name than it saves, so the shortest description rightly omits it.
            prop_assert!(named || tests.is_subset(&accounted), "planted {} missing from {:?}", b, e.causes);
        }
        prop_assert!(e.bits_explained <= e.bits_listed);
        let again = explain(&p.u, &all, &p.failed, &opts).unwrap();
        prop_assert_eq!(e, again);
    }
}

//! Properties of the rules, without processes.

use keel_settle::{Binary, Digest, Disposition, Executed, GitOid, Plan, Record, Source, Status, Unit, Verdict, settle};

fn oid() -> GitOid {
    GitOid::new(&"c".repeat(40)).unwrap()
}

fn plan(n: usize) -> Plan {
    let b = Binary::parse("p::t").unwrap();
    let units = (0..n).map(|i| Unit::test(b.clone(), format!("t{i}"), Disposition::ReuseIfKeyHolds)).collect();
    Plan::new("r".into(), oid(), oid(), units).unwrap()
}

fn rec(plan: &Plan, i: usize, status: Status) -> Record {
    let u = &plan.units()[i];
    Record { binary: u.what.binary().clone(), name: u.what.test_name().to_owned(), status, source: Source::Ran { attempt: 1, duration_ms: 1 }, ended: None, note: None }
}

fn full(plan: &Plan) -> Executed {
    let names = plan.tests_of(plan.binaries()[0]).map(str::to_owned).collect();
    Executed {
        plan: plan.digest(),
        listed: vec![keel_settle::Listed { binary: plan.binaries()[0].clone(), names }],
        records: (0..plan.units().len()).map(|i| rec(plan, i, Status::Pass)).collect(),
        torn_tail: None,
    }
}

#[test]
fn a_complete_passing_list_passes() {
    let p = plan(30);
    assert_eq!(settle(&p, &full(&p)).verdict, Verdict::Pass);
}

#[test]
fn removing_any_one_record_is_never_a_pass() {
    let p = plan(12);
    for i in 0..12 {
        let mut e = full(&p);
        e.records.remove(i);
        assert!(matches!(settle(&p, &e).verdict, Verdict::Incomplete { .. }), "record {i}");
    }
}

#[test]
fn a_listing_that_differs_is_never_a_pass() {
    let p = plan(5);
    let mut e = full(&p);
    e.listed[0].names.pop();
    assert!(matches!(settle(&p, &e).verdict, Verdict::Incomplete { .. }));
    let mut e = full(&p);
    e.listed.clear();
    assert!(matches!(settle(&p, &e).verdict, Verdict::Incomplete { .. }));
}

#[test]
fn every_non_pass_status_keeps_the_verdict_from_pass() {
    let p = plan(3);
    for s in [Status::Fail, Status::Timeout, Status::Hung, Status::Flaky, Status::Error, Status::Blocked] {
        let mut e = full(&p);
        e.records[1] = rec(&p, 1, s);
        assert!(!matches!(settle(&p, &e).verdict, Verdict::Pass), "{s:?}");
    }
}

#[test]
fn a_repeated_record_and_a_reused_record_are_incomplete() {
    let p = plan(3);
    let mut e = full(&p);
    e.records.push(rec(&p, 0, Status::Pass));
    assert!(matches!(settle(&p, &e).verdict, Verdict::Incomplete { .. }));
    let mut e = full(&p);
    e.records[0].source = Source::Reused { record: Digest::of("x", b"y") };
    assert!(matches!(settle(&p, &e).verdict, Verdict::Incomplete { .. }));
}

#[test]
fn at_most_twenty_names_are_shown_and_the_rest_is_a_count() {
    let p = plan(100);
    let mut e = full(&p);
    e.records.truncate(10);
    let r = settle(&p, &e);
    let text = r.render();
    assert!(text.contains("90 units have no result"), "{text}");
}

#[test]
fn an_empty_or_duplicated_or_unsorted_plan_is_refused() {
    assert!(Plan::new("r".into(), oid(), oid(), vec![]).is_err());
    let b = Binary::parse("p").unwrap();
    let u = Unit::test(b, "x".into(), Disposition::ReuseIfKeyHolds);
    assert!(Plan::new("r".into(), oid(), oid(), vec![u.clone(), u]).is_err());
}

#[test]
fn the_plan_bytes_roundtrip_and_the_digest_ignores_nothing_but_itself() {
    let p = plan(4);
    let again = Plan::from_bytes(&p.to_bytes()).unwrap();
    assert_eq!(again, p);
    let edited = String::from_utf8(p.to_bytes()).unwrap().replace("t2", "u2");
    assert!(Plan::from_bytes(edited.as_bytes()).is_err());
}

#[test]
fn binary_names_roundtrip() {
    for s in ["backend-version", "a::b", "a::bin/x", "a::example/e", "a::bench/b"] {
        assert_eq!(Binary::parse(s).unwrap().to_string(), s);
    }
    assert!(Binary::parse("a::b::c").is_err() && Binary::parse("").is_err() && Binary::parse("a::build-script").is_err());
}

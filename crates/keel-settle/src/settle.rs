//! `settle`: Z1, Z2, Z3 and the digest checks of design/ir.md 7.3, for slice 1.
//!
//! The verdict has three values and `Pass` is built in exactly one place, after every rule
//! has found nothing to say. Z4 (reuse) and Z5 to Z9 do not exist in this slice, so a
//! `Reused` record is incomplete here, not trusted.

use crate::digest::Digest;
use crate::executed::{Executed, Record, Source, Status};
use crate::plan::{Binary, Disposition, Plan};
use serde::Serialize;
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::fmt::Write as _;

/// How many names a reason prints; the rest are a count.
pub const SHOWN: usize = 20;

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Cap<T> {
    pub count: usize,
    pub shown: Vec<T>,
}

impl<T> Cap<T> {
    fn of(items: impl IntoIterator<Item = T>) -> Cap<T> {
        let mut c = Cap { count: 0, shown: Vec::new() };
        for it in items {
            c.count += 1;
            if c.shown.len() < SHOWN {
                c.shown.push(it);
            }
        }
        c
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct Failure {
    pub unit: String,
    pub status: Status,
    pub note: Option<String>,
}

/// Why a verdict is not a pass. Units are named `<binary>$<name>`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Reason {
    /// Digest check: the executed list answers another plan.
    StalePlan { executed_answers: Digest, plan: Digest },
    /// Z1.
    NoResult(Cap<String>),
    /// Z1: more than one record for a unit.
    SeveralResults(Cap<String>),
    /// Z1: a record whose status carries no verdict (`Blocked`).
    NoVerdict(Cap<String>),
    /// Z2.
    ForeignResult(Cap<String>),
    /// Z3: the binary listed nothing, or its list is absent from the executed list.
    NotListed { binary: String },
    /// Z3: planned and the binary did not list it.
    PlannedNotListed(Cap<String>),
    /// Z3: the binary lists it and the plan lacks it (generated tests, X7).
    ListedNotPlanned(Cap<String>),
    /// Z3: the binary has two `Listed` lines.
    ListedTwice { binary: String },
    /// Z4 is not in this slice.
    ReusedUnchecked(Cap<String>),
    /// The writer stopped mid-line.
    TornTail { bytes: usize },
}

impl Reason {
    /// One line a person reads, then what to do about it.
    pub fn render(&self) -> (String, &'static str) {
        fn names(c: &Cap<String>) -> String {
            let mut s = c.shown.join(", ");
            if c.count > c.shown.len() {
                let _ = write!(s, ", and {} more", c.count - c.shown.len());
            }
            s
        }
        fn one_or_many(c: &Cap<String>, one: impl Fn(&str) -> String, many: impl Fn(usize, &str) -> String) -> String {
            match c.shown.as_slice() {
                [only] if c.count == 1 => one(only),
                _ => many(c.count, &names(c)),
            }
        }
        match self {
            Reason::StalePlan { executed_answers, plan } => (
                format!("incomplete: this executed list answers plan {executed_answers}, not {plan}"),
                "Run the producer again with this plan; a list from another plan proves nothing about this one.",
            ),
            Reason::NoResult(c) => {
                let first = c.shown.iter().take(3).cloned().collect::<Vec<_>>().join(", ");
                (
                    format!("incomplete: {} units have no result (first: {first})", c.count),
                    "The run ended before these units reported (a unit with no outcome has no line). Rerun it to completion.",
                )
            }
            Reason::SeveralResults(c) => (
                format!("incomplete: {} units have more than one result ({})", c.count, names(c)),
                "A unit has exactly one record (Z1). Rerun into a fresh executed list.",
            ),
            Reason::NoVerdict(c) => (
                format!("incomplete: {} units are Blocked and have no verdict ({})", c.count, names(c)),
                "A blocked unit is not a result. Fix what blocked it and rerun.",
            ),
            Reason::ForeignResult(c) => (
                one_or_many(c, |n| format!("incomplete: a result for {n}, which the plan does not have"), |k, n| format!("incomplete: {k} results for units the plan does not have ({n})")),
                "The list and the plan disagree about what exists. Regenerate the plan, and rerun.",
            ),
            Reason::NotListed { binary } => (
                format!("incomplete: the executed list has no Listed line for binary {binary}"),
                "Z3 compares the binary's own list with the plan; without it nothing is known about what the binary holds. Rerun the producer.",
            ),
            Reason::PlannedNotListed(c) => (
                one_or_many(c, |n| format!("incomplete: {n} is in the plan and the binary did not list it"), |k, n| format!("incomplete: {k} units are in the plan and the binary did not list them ({n})")),
                "The test was filtered out or compiled out of the binary. Remove the filter, or regenerate the plan from this binary.",
            ),
            Reason::ListedNotPlanned(c) => (
                one_or_many(c, |n| format!("incomplete: {n} is listed by the binary and not in the plan"), |k, n| format!("incomplete: {k} tests are listed by the binary and not in the plan ({n})")),
                "The plan could not see them (macro-generated tests). Rebuild the plan from the binary's list (slice 2) before trusting a verdict.",
            ),
            Reason::ListedTwice { binary } => (format!("incomplete: binary {binary} has two Listed lines"), "Rerun the producer into a fresh executed list."),
            Reason::ReusedUnchecked(c) => (
                format!("incomplete: {} results are reused records, which this settle cannot check ({})", c.count, names(c)),
                "Reuse is judged by the store's may_reuse (Z4), not in this slice. Run the units instead.",
            ),
            Reason::TornTail { bytes } => (
                format!("incomplete: the executed list ends in a partial line of {bytes} bytes"),
                "The writer was stopped mid-write. The lines before it are used; rerun to get the rest.",
            ),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub enum Verdict {
    Pass,
    /// `also` holds what else was wrong: a failure cannot be repaired by completing the
    /// run, so it leads, but nothing found is dropped.
    Fail { failed: Cap<Failure>, also: Vec<Reason> },
    Incomplete { reasons: Vec<Reason> },
}

impl Verdict {
    pub fn exit_code(&self) -> u8 {
        match self {
            Verdict::Pass => 0,
            Verdict::Fail { .. } => 1,
            Verdict::Incomplete { .. } => 3,
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Report {
    pub plan: Digest,
    pub units: usize,
    pub records: usize,
    pub verdict: Verdict,
}

impl Report {
    pub fn render(&self) -> String {
        let mut o = String::new();
        match &self.verdict {
            Verdict::Pass => {
                let _ = writeln!(o, "pass: {} units, each with one passing result (plan {})", self.units, self.plan);
            }
            Verdict::Fail { failed, also } => {
                for f in &failed.shown {
                    let _ = writeln!(o, "fail: {} ({:?}{})", f.unit, f.status, f.note.as_deref().map(|n| format!(": {n}")).unwrap_or_default());
                }
                if failed.count > failed.shown.len() {
                    let _ = writeln!(o, "fail: and {} more", failed.count - failed.shown.len());
                }
                let _ = writeln!(o, "{} of {} units failed (plan {})", failed.count, self.units, self.plan);
                render_reasons(&mut o, also);
            }
            Verdict::Incomplete { reasons } => {
                render_reasons(&mut o, reasons);
                let _ = writeln!(o, "no verdict: {} units in plan {}, {} records", self.units, self.plan, self.records);
            }
        }
        o
    }
}

fn render_reasons(o: &mut String, reasons: &[Reason]) {
    for r in reasons {
        let (line, todo) = r.render();
        let _ = writeln!(o, "{line}\n  to do: {todo}");
    }
}

type UnitKey<'a> = (&'a Binary, &'a str);

fn key(r: &Record) -> UnitKey<'_> {
    (&r.binary, &r.name)
}

pub fn settle(plan: &Plan, exec: &Executed) -> Report {
    let report = |verdict| Report { plan: plan.digest(), units: plan.units().len(), records: exec.records.len(), verdict };
    // A list for another plan says nothing about this one, failures included.
    if exec.plan != plan.digest() {
        return report(Verdict::Incomplete { reasons: vec![Reason::StalePlan { executed_answers: exec.plan, plan: plan.digest() }] });
    }
    let mut reasons = Vec::new();

    let planned: HashMap<UnitKey<'_>, &Disposition> = plan.units().iter().map(|u| ((u.what.binary(), u.what.test_name()), &u.expect)).collect();
    let mut by_unit: HashMap<UnitKey<'_>, Vec<&Record>> = HashMap::new();
    for r in &exec.records {
        by_unit.entry(key(r)).or_default().push(r);
    }
    let label = |b: &Binary, n: &str| b.label(n);

    // Z2, in file order and once per name.
    let mut seen = BTreeSet::new();
    let foreign: Vec<String> = exec.records.iter().filter(|r| !planned.contains_key(&key(r))).map(|r| label(&r.binary, &r.name)).filter(|l| seen.insert(l.clone())).collect();
    if !foreign.is_empty() {
        reasons.push(Reason::ForeignResult(Cap::of(foreign)));
    }

    // Z1, in plan order.
    let mut missing = Vec::new();
    let mut several = Vec::new();
    let mut blocked = Vec::new();
    let mut reused = Vec::new();
    let mut failed = Vec::new();
    for u in plan.units() {
        let (b, n) = (u.what.binary(), u.what.test_name());
        let Some(rs) = by_unit.get(&(b, n)) else {
            missing.push(label(b, n));
            continue;
        };
        if rs.len() > 1 {
            several.push(label(b, n));
            continue;
        }
        let r = rs[0];
        if matches!(r.source, Source::Reused { .. }) || matches!(u.expect, Disposition::Reuse { .. } | Disposition::Deferred) {
            reused.push(label(b, n));
            continue;
        }
        match r.status {
            Status::Pass => {}
            Status::Blocked => blocked.push(label(b, n)),
            Status::Fail | Status::Timeout | Status::Hung | Status::Flaky | Status::Error => {
                failed.push(Failure { unit: label(b, n), status: r.status, note: r.note.clone() });
            }
        }
    }
    if !missing.is_empty() {
        reasons.push(Reason::NoResult(Cap::of(missing)));
    }
    if !several.is_empty() {
        reasons.push(Reason::SeveralResults(Cap::of(several)));
    }
    if !blocked.is_empty() {
        reasons.push(Reason::NoVerdict(Cap::of(blocked)));
    }
    if !reused.is_empty() {
        reasons.push(Reason::ReusedUnchecked(Cap::of(reused)));
    }

    // Z3: for every binary the plan has, and every binary that listed.
    let mut listed_by: BTreeMap<&Binary, Vec<&crate::executed::Listed>> = BTreeMap::new();
    for l in &exec.listed {
        listed_by.entry(&l.binary).or_default().push(l);
    }
    let planned_binaries: BTreeSet<&Binary> = plan.binaries().into_iter().collect();
    for b in &planned_binaries {
        let want: BTreeSet<&str> = plan.tests_of(b).collect();
        match listed_by.get(b).map(Vec::as_slice) {
            None | Some([]) => reasons.push(Reason::NotListed { binary: b.to_string() }),
            Some([l]) => {
                let got: BTreeSet<&str> = l.names.iter().map(String::as_str).collect();
                let lacking: Vec<String> = want.difference(&got).map(|n| label(b, n)).collect();
                let extra: Vec<String> = got.difference(&want).map(|n| label(b, n)).collect();
                if !lacking.is_empty() {
                    reasons.push(Reason::PlannedNotListed(Cap::of(lacking)));
                }
                if !extra.is_empty() {
                    reasons.push(Reason::ListedNotPlanned(Cap::of(extra)));
                }
            }
            Some(_) => reasons.push(Reason::ListedTwice { binary: b.to_string() }),
        }
    }
    // A binary the plan has no test of that lists tests: all of them are invisible to the plan.
    let extra_binaries: Vec<String> = listed_by.iter().filter(|(b, _)| !planned_binaries.contains(*b)).flat_map(|(b, ls)| ls.iter().flat_map(move |l| l.names.iter().map(move |n| b.label(n)))).collect();
    if !extra_binaries.is_empty() {
        reasons.push(Reason::ListedNotPlanned(Cap::of(extra_binaries)));
    }

    if let Some(bytes) = exec.torn_tail {
        reasons.push(Reason::TornTail { bytes });
    }

    let verdict = if !failed.is_empty() {
        Verdict::Fail { failed: Cap::of(failed), also: reasons }
    } else if !reasons.is_empty() {
        Verdict::Incomplete { reasons }
    } else {
        // Every unit has one passing, run record; every binary's list equals the plan's;
        // no record or listed name is outside the plan; the digests agree.
        Verdict::Pass
    };
    report(verdict)
}

//! Statuses, roots and the run verdict, DESIGN.md §2.4.

use serde::{Deserialize, Serialize};

use crate::node::NodeId;
use crate::report::Record;

/// The `reason` of a negative control that passed alongside its twin: the most
/// damning result a run can have, because the test could not have caught the
/// bug it exists to catch.
pub const CONTROL_DID_NOT_FAIL: &str = "control-did-not-fail";

/// The outcome of one node in one run.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Status {
    /// Ran and passed.
    Pass,
    /// Ran and failed.
    Fail,
    /// Ran past its timeout.
    Timeout,
    /// Could not run (build, spawn or harness failure).
    Error,
    /// Not run: an upstream root exists for it.
    Blocked,
    /// A stored pass exists for this exact key.
    Cached,
    /// Failed, then passed on retry under the same key. Never stored as a pass
    /// and never blocks anything.
    Flaky,
    /// Filtered out.
    Skipped,
    /// Declared out of the gate with an expiry; never blocks, never caches.
    Quarantined,
}

impl Status {
    /// Whether this status counts as a pass for gating: `cached` does, and
    /// nothing else besides `pass` itself.
    pub fn gates_as_pass(&self) -> bool {
        matches!(self, Status::Pass | Status::Cached)
    }

    /// How alarming a status is, for choosing between two records of the same
    /// node and key when reports are merged. A failure is never discarded in
    /// favour of a pass.
    pub(crate) fn severity(self) -> u8 {
        match self {
            Status::Fail => 8,
            Status::Timeout => 7,
            Status::Error => 6,
            Status::Blocked => 5,
            Status::Flaky => 4,
            Status::Quarantined => 3,
            Status::Pass => 2,
            Status::Cached => 1,
            Status::Skipped => 0,
        }
    }
}

/// The run verdict, which is also the forge status.
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Verdict {
    /// No root, no error and no timeout.
    Pass,
    /// At least one root, error or timeout.
    Fail,
}

fn is_control_failure(r: &Record) -> bool {
    r.reason.as_deref() == Some(CONTROL_DID_NOT_FAIL)
}

/// The `reason` of a node that ran and checked nothing: a Go package whose
/// every test skipped, say. It is `skipped`, never `pass`, and a run that
/// contains one is not green, because the node it stands for was not verified.
pub const RAN_NOTHING: &str = "ran-nothing";

/// The nodes that failed, timed out or could not run, and are the cause rather
/// than a consequence; control failures first.
///
/// A record is a root when its status is `fail`, `timeout` or `error` and it
/// names no `blocked_by` root that is itself failing in `records` (one that ran
/// under `--no-block` and still names a present root is a symptom, not a
/// cause; one whose named root is not in this report has no other explanation
/// and is listed), or when its reason is `control-did-not-fail`, which is a
/// root whatever else is true of it. A node that timed out or never ran gives
/// no evidence that what stands on it is sound, so it blocks downstream
/// exactly as a failure does.
///
/// Being a symptom changes how a failure is *reported*. It never changes
/// whether the run is red: see [`verdict`].
pub fn roots(records: &[Record]) -> Vec<NodeId> {
    let failing: std::collections::HashSet<&NodeId> = records
        .iter()
        .filter(|r| matches!(r.status, Status::Fail | Status::Timeout | Status::Error))
        .map(|r| &r.id)
        .collect();
    let is_root = |r: &&Record| {
        (matches!(r.status, Status::Fail | Status::Timeout | Status::Error)
            && !r
                .blocked_by
                .iter()
                .any(|b| *b != r.id && failing.contains(b)))
            || is_control_failure(r)
    };
    let (control, mut other): (Vec<&Record>, Vec<&Record>) = records
        .iter()
        .filter(is_root)
        .partition(|r| is_control_failure(r));
    // Failures that blame each other in a circle have no root by the rule
    // above, yet the run is red; list them all rather than say nothing.
    if other.is_empty() {
        other = records
            .iter()
            .filter(|r| failing.contains(&r.id) && !is_control_failure(r))
            .collect();
    }
    control
        .into_iter()
        .chain(other)
        .map(|r| r.id.clone())
        .collect()
}

/// Whether a record alone makes the run red. The match has no wildcard: a
/// new status must be placed here before the crate compiles.
fn is_red(r: &Record) -> bool {
    is_control_failure(r)
        || match r.status {
            // `blocked_by` only says which root explains a failure; it is not
            // an excuse. A blocked node never ran, and a flaky one disagreed
            // with itself under one key.
            Status::Fail | Status::Timeout | Status::Error | Status::Flaky | Status::Blocked => {
                true
            }
            Status::Skipped => r.reason.as_deref() == Some(RAN_NOTHING),
            Status::Pass | Status::Cached | Status::Quarantined => false,
        }
}

/// `pass` only if no record is `fail`, `timeout`, `error`, `flaky` or
/// `blocked`, no control failed, and no node ran nothing; regardless of how
/// many nodes were `cached` and of what any record's `blocked_by` says.
/// Skipped (filtered out) and quarantined (declared out, with an expiry)
/// nodes do not by themselves fail a run.
///
/// This cannot see nodes that have no record at all; use
/// [`verdict_expecting`] wherever the planned node list is known.
pub fn verdict(records: &[Record]) -> Verdict {
    verdict_expecting(records, &[])
}

/// [`verdict`], and also `fail` when any node in `expected` has no record: a
/// node that was planned and left no trace was not verified.
pub fn verdict_expecting(records: &[Record], expected: &[NodeId]) -> Verdict {
    let present: std::collections::HashSet<&NodeId> = records.iter().map(|r| &r.id).collect();
    if records.iter().any(is_red) || expected.iter().any(|e| !present.contains(e)) {
        Verdict::Fail
    } else {
        Verdict::Pass
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::digest::Digest;

    fn rec(id: &str, status: Status) -> Record {
        Record {
            id: NodeId::new(id),
            key: Digest::Blake3([0; 32]),
            status,
            reason: None,
            blocked_by: vec![],
            duration_ms: None,
            attempt: None,
            detail: None,
            evidence: vec![],
            cached_from: None,
        }
    }

    #[test]
    fn serialises_lowercase() {
        assert_eq!(
            serde_json::to_string(&Status::Quarantined).unwrap(),
            "\"quarantined\""
        );
        assert_eq!(
            serde_json::from_str::<Status>("\"cached\"").unwrap(),
            Status::Cached
        );
        assert!(serde_json::from_str::<Status>("\"Pass\"").is_err());
    }

    #[test]
    fn only_pass_and_cached_gate_as_pass() {
        use Status::*;
        for s in [Pass, Cached] {
            assert!(s.gates_as_pass());
        }
        for s in [Fail, Timeout, Error, Blocked, Flaky, Skipped, Quarantined] {
            assert!(!s.gates_as_pass(), "{s:?}");
        }
    }

    #[test]
    fn a_wall_of_cached_never_turns_a_failure_green() {
        let mut v: Vec<Record> = (0..1000)
            .map(|i| rec(&format!("c{i}"), Status::Cached))
            .collect();
        assert_eq!(verdict(&v), Verdict::Pass);
        v.push(rec("bad", Status::Fail));
        assert_eq!(verdict(&v), Verdict::Fail);
        assert_eq!(roots(&v), [NodeId::new("bad")]);
    }

    #[test]
    fn timeout_and_error_are_roots_and_fail_the_run() {
        for s in [Status::Error, Status::Timeout] {
            let v = [rec("a", Status::Pass), rec("b", s)];
            assert_eq!(verdict(&v), Verdict::Fail);
            assert_eq!(roots(&v), [NodeId::new("b")]);
        }
    }

    #[test]
    fn a_timeout_that_names_a_root_is_a_symptom() {
        let mut late = rec("late", Status::Timeout);
        late.blocked_by = vec![NodeId::new("cause")];
        let v = [rec("cause", Status::Error), late];
        assert_eq!(roots(&v), [NodeId::new("cause")]);
    }

    #[test]
    fn skipped_and_quarantined_do_not_fail_alone_but_flaky_and_blocked_do() {
        let v = [rec("c", Status::Skipped), rec("d", Status::Quarantined)];
        assert_eq!(verdict(&v), Verdict::Pass);
        for s in [Status::Flaky, Status::Blocked] {
            assert_eq!(
                verdict(&[rec("a", Status::Pass), rec("b", s)]),
                Verdict::Fail,
                "{s:?}"
            );
        }
        // A node that ran nothing is not verified, however it is spelled.
        let mut nothing = rec("n", Status::Skipped);
        nothing.reason = Some(RAN_NOTHING.into());
        assert_eq!(verdict(&[nothing]), Verdict::Fail);
    }

    #[test]
    fn a_failure_that_names_a_root_still_fails_the_run() {
        // The named root is not in this report (it is another repository's),
        // so the symptom is the only record: it must be red and it must be listed.
        let mut symptom = rec("symptom", Status::Fail);
        symptom.blocked_by = vec![NodeId::new("foreign-cause")];
        let v = [rec("fine", Status::Pass), symptom];
        assert_eq!(verdict(&v), Verdict::Fail);
        assert_eq!(roots(&v), [NodeId::new("symptom")]);
        // With the root present the symptom is only reported as its consequence.
        let mut symptom = rec("symptom", Status::Fail);
        symptom.blocked_by = vec![NodeId::new("cause")];
        let v = [rec("cause", Status::Fail), symptom];
        assert_eq!(verdict(&v), Verdict::Fail);
        assert_eq!(roots(&v), [NodeId::new("cause")]);
        // A record that names itself is not explained by itself.
        let mut selfish = rec("x", Status::Error);
        selfish.blocked_by = vec![NodeId::new("x")];
        assert_eq!(roots(&[selfish]), [NodeId::new("x")]);
    }

    #[test]
    fn a_planned_node_with_no_record_fails_the_run() {
        let v = [rec("a", Status::Pass)];
        let expected = [NodeId::new("a"), NodeId::new("b")];
        assert_eq!(verdict_expecting(&v, &expected[..1]), Verdict::Pass);
        assert_eq!(verdict_expecting(&v, &expected), Verdict::Fail);
    }

    mod property {
        use proptest::prelude::*;

        use super::*;

        fn status() -> impl Strategy<Value = Status> {
            prop_oneof![
                Just(Status::Pass),
                Just(Status::Fail),
                Just(Status::Timeout),
                Just(Status::Error),
                Just(Status::Blocked),
                Just(Status::Cached),
                Just(Status::Flaky),
                Just(Status::Skipped),
                Just(Status::Quarantined),
            ]
        }

        /// Up to 12 records with distinct ids; `blocked_by` points at any id
        /// (present or not), and a few carry the `ran-nothing` or
        /// `control-did-not-fail` reasons. Plus an expected set drawn from a
        /// slightly larger universe, so some expected nodes have no record.
        fn world() -> impl Strategy<Value = (Vec<Record>, Vec<NodeId>)> {
            let one = (
                status(),
                proptest::collection::vec(0usize..14, 0..3),
                0u8..6,
            );
            (
                proptest::collection::vec(one, 0..12),
                proptest::collection::vec(0usize..14, 0..8),
            )
                .prop_map(|(specs, expected)| {
                    let id = |i: usize| NodeId::new(format!("n{i}"));
                    let records = specs
                        .into_iter()
                        .enumerate()
                        .map(|(i, (s, by, flavour))| {
                            let mut r = rec(&format!("n{i}"), s);
                            r.blocked_by = by.into_iter().map(id).collect();
                            r.reason = match flavour {
                                0 => Some(RAN_NOTHING.to_owned()),
                                1 => Some(CONTROL_DID_NOT_FAIL.to_owned()),
                                _ => None,
                            };
                            r
                        })
                        .collect();
                    (records, expected.into_iter().map(id).collect())
                })
        }

        proptest! {
            /// The verdict is pass only if nothing failed, timed out, errored or
            /// flaked, whatever `blocked_by` says, and every expected node has a record.
            #[test]
            fn pass_implies_no_bad_record_and_no_missing_node((records, expected) in world()) {
                if verdict_expecting(&records, &expected) == Verdict::Pass {
                    for r in &records {
                        prop_assert!(
                            !matches!(r.status, Status::Fail | Status::Timeout | Status::Error | Status::Flaky),
                            "{:?} passed the run", r
                        );
                        prop_assert!(!is_control_failure(r));
                    }
                    for e in &expected {
                        prop_assert!(records.iter().any(|r| r.id == *e), "{e} has no record");
                    }
                }
            }

            /// And the other direction for the cases that matter most: one
            /// failure makes the run red even when it names a root.
            #[test]
            fn any_failure_fails_the_run((mut records, expected) in world()) {
                if let Some(r) = records.first_mut() {
                    r.status = Status::Fail;
                    prop_assert_eq!(verdict_expecting(&records, &expected), Verdict::Fail);
                    prop_assert!(!roots(&records).is_empty(), "a red run must say why");
                }
            }

            /// Cached nodes never turn anything green.
            #[test]
            fn adding_cached_nodes_never_improves_the_verdict((records, expected) in world()) {
                let before = verdict_expecting(&records, &expected);
                let mut more = records.clone();
                more.extend((100..110).map(|i| rec(&format!("c{i}"), Status::Cached)));
                if before == Verdict::Fail {
                    prop_assert_eq!(verdict_expecting(&more, &expected), Verdict::Fail);
                }
            }
        }
    }

    #[test]
    fn a_failure_that_names_a_root_is_not_itself_a_root() {
        let mut symptom = rec("symptom", Status::Fail);
        symptom.blocked_by = vec![NodeId::new("cause")];
        let v = [rec("cause", Status::Fail), symptom];
        assert_eq!(roots(&v), [NodeId::new("cause")]);
    }

    #[test]
    fn control_failures_are_roots_and_listed_first() {
        let mut control = rec("nix:twin!wrong", Status::Fail);
        control.reason = Some(CONTROL_DID_NOT_FAIL.into());
        control.blocked_by = vec![NodeId::new("nix:other")]; // still a root
        let v = [
            rec("plain", Status::Fail),
            control,
            rec("also", Status::Fail),
        ];
        assert_eq!(
            roots(&v),
            ["nix:twin!wrong", "plain", "also"].map(NodeId::new)
        );
        assert_eq!(verdict(&v), Verdict::Fail);
    }
}

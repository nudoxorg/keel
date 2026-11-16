//! The two cross-repo documents of DESIGN.md §8: the node [`Manifest`]
//! (runner to conductor) and the run [`Report`] (result record).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::key::Platform;
use crate::node::{Node, NodeId, PartId};
use crate::status::{self, Status, Verdict};

/// The only schema this crate reads or writes.
pub const SCHEMA: u32 = 1;

/// §8.1: what a runner says it can run.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Manifest {
    /// Document schema; see [`SCHEMA`].
    pub schema: u32,
    /// Who wrote it, `nextest-keel 0.1.0`.
    pub producer: String,
    /// The repository, `Nudox/Backend`.
    pub repo: String,
    /// The certified revision.
    pub revision: String,
    /// Where the keys were computed.
    pub platform: Platform,
    /// The nodes.
    pub nodes: Vec<Node>,
}

/// Why a node ran the way it did: what was run and what was expected.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Detail {
    /// The test name or command that ran.
    pub ran: String,
    /// What should have happened.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected: Option<String>,
    /// What did.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub actual: Option<String>,
}

/// A named blob in the store (`stderr`, `journal:unit.service`).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    /// What the blob is.
    pub name: String,
    /// Where to find it; the JSON field is `ref`.
    #[serde(rename = "ref")]
    pub reference: Digest,
}

/// One node's outcome in a run.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Record {
    /// The node.
    pub id: NodeId,
    /// The key it ran or was looked up under.
    pub key: Digest,
    /// The outcome.
    pub status: Status,
    /// A machine-readable qualifier, e.g. `control-did-not-fail`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// For blocked nodes, the roots that block them; roots only.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub blocked_by: Vec<NodeId>,
    /// Wall time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub duration_ms: Option<u64>,
    /// Which attempt produced this record, starting at 1.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt: Option<u32>,
    /// Expected on every failure.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<Detail>,
    /// Expected on every failure.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evidence: Vec<Evidence>,
    /// For `cached` nodes, the run that produced the stored pass.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cached_from: Option<String>,
}

/// One attempt of a flaky node.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Attempt {
    /// How the attempt ended.
    pub status: Status,
    /// Its outputs.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

/// A node that failed and then passed under the same key, with both outputs.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Flaky {
    /// The node.
    pub id: NodeId,
    /// The key all attempts shared.
    pub key: Digest,
    /// Every attempt, in order.
    pub attempts: Vec<Attempt>,
}

/// A registered pair of parts and how many nodes cover it (§2.7).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Interaction {
    /// The two parts that must be exercised together.
    pub interaction: [PartId; 2],
    /// The registry it came from.
    pub source: String,
    /// How many nodes join both parts; zero means untested.
    pub nodes: u64,
}

/// The time budget and the critical path through the run.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Budget {
    /// The budget.
    pub limit_ms: u64,
    /// Length of the critical path.
    pub critical_path_ms: u64,
    /// The nodes on it, in order.
    pub critical_path: Vec<NodeId>,
}

/// Wall time per stage (§5).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stages {
    /// Stage 0, answering without compiling.
    #[serde(default)]
    pub stage0_ms: u64,
    /// Building.
    #[serde(default)]
    pub build_ms: u64,
    /// Keying.
    #[serde(default)]
    pub key_ms: u64,
    /// Running.
    #[serde(default)]
    pub run_ms: u64,
    /// Milliseconds from the start of the run to the first test starting; written
    /// by the nextest fork's session (`session.rs`), absent from other producers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_test_ms: Option<u64>,
    /// Milliseconds to the first root (failing node) being known.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub first_root_ms: Option<u64>,
    /// Milliseconds until cargo exited, so the build can be told apart from the tail of the run.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cargo_exit_ms: Option<u64>,
}

/// How many records ended in each status.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Counts {
    /// `pass`
    #[serde(default)]
    pub pass: u64,
    /// `fail`
    #[serde(default)]
    pub fail: u64,
    /// `blocked`
    #[serde(default)]
    pub blocked: u64,
    /// `cached`
    #[serde(default)]
    pub cached: u64,
    /// `flaky`
    #[serde(default)]
    pub flaky: u64,
    /// `skipped`
    #[serde(default)]
    pub skipped: u64,
    /// `quarantined`
    #[serde(default)]
    pub quarantined: u64,
    /// `timeout`
    #[serde(default)]
    pub timeout: u64,
    /// `error`
    #[serde(default)]
    pub error: u64,
}

impl Counts {
    /// Tallies `records` by status.
    pub fn from_records(records: &[Record]) -> Counts {
        let mut c = Counts::default();
        for r in records {
            let slot = match r.status {
                Status::Pass => &mut c.pass,
                Status::Fail => &mut c.fail,
                Status::Blocked => &mut c.blocked,
                Status::Cached => &mut c.cached,
                Status::Flaky => &mut c.flaky,
                Status::Skipped => &mut c.skipped,
                Status::Quarantined => &mut c.quarantined,
                Status::Timeout => &mut c.timeout,
                Status::Error => &mut c.error,
            };
            *slot += 1;
        }
        c
    }
}

/// §8.2: the result record and run report.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// Document schema; see [`SCHEMA`].
    pub schema: u32,
    /// Unique id of the run.
    pub run_id: String,
    /// The repository.
    pub repo: String,
    /// The certified (merge) revision.
    pub revision: String,
    /// The PR head, on PR runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub head: Option<String>,
    /// The canonical base, on PR runs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,
    /// Where the run happened.
    pub platform: Platform,
    /// Derived from `nodes`; see [`Report::derive`].
    pub verdict: Verdict,
    /// RFC 3339 start time.
    pub started_at: String,
    /// Total wall time.
    pub duration_ms: u64,
    /// The budget, when one applies.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<Budget>,
    /// Per-stage wall time.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub stages: Option<Stages>,
    /// Derived from `nodes`.
    pub counts: Counts,
    /// Derived from `nodes`; control failures first.
    pub roots: Vec<NodeId>,
    /// One record per node.
    pub nodes: Vec<Record>,
    /// Nodes that failed and then passed.
    #[serde(default)]
    pub flaky: Vec<Flaky>,
    /// Registered interactions and their coverage.
    #[serde(default)]
    pub interactions: Vec<Interaction>,
}

/// Why reports could not be merged.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum MergeError {
    /// There was nothing to merge.
    #[error("no reports to merge; pass at least one report.json")]
    Empty,
    /// Reports speak different protocol versions.
    #[error(
        "report {run_id} has schema {found} but the first report has schema {expected}; regenerate the older runner's output or upgrade it, reports of different schemas cannot be combined"
    )]
    SchemaMismatch {
        /// The first report's schema.
        expected: u32,
        /// The offending schema.
        found: u32,
        /// The offending report.
        run_id: String,
    },
    /// The same node was keyed differently by two runners.
    #[error(
        "node `{id}` has key {first} in one report and {second} in another; the runners saw different inputs for the same node, so rerun both against the same revision"
    )]
    KeyConflict {
        /// The node.
        id: NodeId,
        /// Its key in the earlier report.
        first: Digest,
        /// Its key in the later report.
        second: Digest,
    },
}

impl Report {
    /// Recomputes `roots`, `counts` and `verdict` from `nodes`. It cannot
    /// know which nodes were planned; where that is known, use
    /// [`derive_against`](Self::derive_against).
    pub fn derive(&mut self) {
        self.derive_against(&[]);
    }

    /// [`derive`](Self::derive), and the verdict is `fail` as well when a node
    /// in `expected` has no record, or when `flaky` lists any node: a retry that
    /// passed is not the same run passing.
    pub fn derive_against(&mut self, expected: &[NodeId]) {
        self.roots = status::roots(&self.nodes);
        self.counts = Counts::from_records(&self.nodes);
        self.verdict = if self.flaky.is_empty() {
            status::verdict_expecting(&self.nodes, expected)
        } else {
            Verdict::Fail
        };
    }

    /// Combines the reports of several runners into one (§8.2, last
    /// paragraph).
    ///
    /// `nodes` are concatenated, in report order; `roots`, `counts` and the
    /// verdict are re-derived, never copied. Header fields come from the first
    /// report, except `started_at` (earliest, which assumes UTC timestamps as
    /// the protocol writes them) and `duration_ms` and `stages` (the maximum,
    /// because runners work concurrently). `budget` is the first one present,
    /// `flaky` is concatenated, and interactions with the same pair and source
    /// have their node counts added.
    ///
    /// If two reports carry the same node id and key, the record with the more
    /// severe status survives, so a failure is never dropped for a pass; with
    /// different keys the merge fails. Resolving cross-repo `stands_on` is the
    /// conductor's job and not done here.
    pub fn merge(reports: Vec<Report>) -> Result<Report, MergeError> {
        let mut iter = reports.into_iter();
        let mut merged = iter.next().ok_or(MergeError::Empty)?;
        let mut seen: BTreeMap<NodeId, usize> = merged
            .nodes
            .iter()
            .enumerate()
            .map(|(i, r)| (r.id.clone(), i))
            .collect();
        for other in iter {
            if other.schema != merged.schema {
                return Err(MergeError::SchemaMismatch {
                    expected: merged.schema,
                    found: other.schema,
                    run_id: other.run_id,
                });
            }
            for record in other.nodes {
                match seen.get(&record.id) {
                    None => {
                        seen.insert(record.id.clone(), merged.nodes.len());
                        merged.nodes.push(record);
                    }
                    Some(&i) => {
                        let kept = &mut merged.nodes[i];
                        if kept.key != record.key {
                            return Err(MergeError::KeyConflict {
                                id: record.id,
                                first: kept.key,
                                second: record.key,
                            });
                        }
                        if record.status.severity() > kept.status.severity() {
                            *kept = record;
                        }
                    }
                }
            }
            merged.started_at = merged.started_at.min(other.started_at);
            merged.duration_ms = merged.duration_ms.max(other.duration_ms);
            merged.stages = match (merged.stages, other.stages) {
                (Some(a), Some(b)) => Some(Stages {
                    stage0_ms: a.stage0_ms.max(b.stage0_ms),
                    build_ms: a.build_ms.max(b.build_ms),
                    key_ms: a.key_ms.max(b.key_ms),
                    run_ms: a.run_ms.max(b.run_ms),
                    // Milestones are times since each runner started; the later
                    // is the conservative one, and a runner that has none adds none.
                    first_test_ms: a.first_test_ms.max(b.first_test_ms),
                    first_root_ms: a.first_root_ms.max(b.first_root_ms),
                    cargo_exit_ms: a.cargo_exit_ms.max(b.cargo_exit_ms),
                }),
                (a, b) => a.or(b),
            };
            if merged.budget.is_none() {
                merged.budget = other.budget;
            }
            merged.flaky.extend(other.flaky);
            for i in other.interactions {
                match merged
                    .interactions
                    .iter_mut()
                    .find(|m| m.interaction == i.interaction && m.source == i.source)
                {
                    Some(m) => m.nodes += i.nodes,
                    None => merged.interactions.push(i),
                }
            }
        }
        merged.derive();
        Ok(merged)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The §8.1 example with its `…` placeholders replaced by valid hex.
    const MANIFEST: &str = include_str!("../tests/fixtures/manifest.json");
    /// The §8.2 example, likewise.
    const REPORT: &str = include_str!("../tests/fixtures/report.json");

    fn round_trip<T: Serialize + for<'de> Deserialize<'de> + PartialEq + std::fmt::Debug>(
        text: &str,
    ) -> T {
        let value: T = serde_json::from_str(text).unwrap();
        let again: T =
            serde_json::from_str(&serde_json::to_string_pretty(&value).unwrap()).unwrap();
        assert_eq!(value, again);
        value
    }

    #[test]
    fn manifest_example_parses_and_round_trips() {
        let m: Manifest = round_trip(MANIFEST);
        assert_eq!(m.nodes.len(), 3);
        assert_eq!(m.nodes[0].id.kind_prefix(), Some("rust"));
        assert_eq!(
            m.nodes[1].inputs.drv.as_deref(),
            Some("/nix/store/…-scenario-backend.drv")
        );
        assert!(matches!(m.nodes[1].key, Digest::Sha256(_)));
        assert_eq!(
            m.nodes[2].policy.twin.as_ref().unwrap().as_str(),
            "nix:scenario:backend-mcp-serves"
        );
        assert!(m.nodes[2].policy.blocks);
        assert_eq!(m.platform.extra.len(), 0);
    }

    #[test]
    fn report_example_parses_and_round_trips() {
        let r: Report = round_trip(REPORT);
        assert_eq!(r.nodes.len(), 4);
        assert_eq!(r.nodes[3].reason.as_deref(), Some("control-did-not-fail"));
        assert_eq!(r.interactions[1].nodes, 0);
        assert_eq!(r.flaky[0].attempts.len(), 2);
        let json = serde_json::to_value(&r.nodes[0]).unwrap();
        assert!(json["evidence"][0].get("ref").is_some());
    }

    #[test]
    fn example_counts_roots_and_verdict_are_what_derive_computes() {
        let mut r: Report = serde_json::from_str(REPORT).unwrap();
        let stated = (r.counts, r.roots.clone(), r.verdict);
        r.derive();
        // The example's counts describe a 20k-node run of which four nodes are
        // listed; roots and verdict must agree, with the control failure now
        // listed first as §2.4 says.
        assert_eq!(r.verdict, stated.2);
        assert_eq!(r.counts.fail, 2);
        assert_eq!(r.roots.len(), 2);
        assert_eq!(
            r.roots[0].as_str(),
            "nix:scenario:backend-mcp-serves!wrong-port"
        );
        assert!(stated.1.iter().all(|s| r.roots.contains(s)));
    }

    #[test]
    fn the_nextest_forks_milestones_in_stages_parse_and_round_trip() {
        let with = REPORT.replacen(
            "\"stages\": {",
            "\"stages\": { \"first_test_ms\": 812, \"first_root_ms\": 4410, \"cargo_exit_ms\": 9031,",
            1,
        );
        assert_ne!(with, REPORT, "the fixture has a stages object to extend");
        let r: Report = serde_json::from_str(&with).unwrap();
        let s = r.stages.unwrap();
        assert_eq!(
            (s.first_test_ms, s.first_root_ms, s.cargo_exit_ms),
            (Some(812), Some(4410), Some(9031))
        );
        let again = serde_json::to_value(&r).unwrap();
        assert_eq!(again["stages"]["cargo_exit_ms"], 9031);
        // Reports from producers that do not write them stay unchanged on the wire.
        let plain: Report = serde_json::from_str(REPORT).unwrap();
        let wire = serde_json::to_value(&plain).unwrap();
        assert!(wire["stages"].get("first_test_ms").is_none());
        // Still strict about everything else.
        let bad = REPORT.replacen("\"stages\": {", "\"stages\": { \"first_tst_ms\": 1,", 1);
        let err = serde_json::from_str::<Report>(&bad)
            .unwrap_err()
            .to_string();
        assert!(err.contains("first_tst_ms"), "{err}");
    }

    #[test]
    fn unknown_fields_are_rejected() {
        let bad = MANIFEST.replacen("\"schema\": 1,", "\"schema\": 1, \"surprise\": true,", 1);
        let err = serde_json::from_str::<Manifest>(&bad)
            .unwrap_err()
            .to_string();
        assert!(err.contains("surprise"), "{err}");
        let bad = REPORT.replacen("\"verdict\"", "\"verdictt\": 1, \"verdict\"", 1);
        assert!(serde_json::from_str::<Report>(&bad).is_err());
        // but `platform` is open
        let open = MANIFEST.replacen(
            "\"net\": \"isolated\"",
            "\"net\": \"isolated\", \"host\": \"ilo\"",
            1,
        );
        let m: Manifest = serde_json::from_str(&open).unwrap();
        assert_eq!(m.platform.extra["host"], "ilo");
        let again = serde_json::to_value(&m).unwrap();
        assert_eq!(again["platform"]["host"], "ilo");
    }

    fn report(run: &str, nodes: Vec<Record>) -> Report {
        let mut r: Report = serde_json::from_str(REPORT).unwrap();
        r.run_id = run.into();
        r.nodes = nodes;
        r.flaky.clear();
        r.interactions.clear();
        r.derive();
        r
    }

    fn rec(id: &str, key: u8, status: Status) -> Record {
        Record {
            id: NodeId::new(id),
            key: Digest::Blake3([key; 32]),
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
    fn merge_concatenates_and_rederives() {
        let a = report(
            "a",
            vec![rec("x", 1, Status::Pass), rec("y", 2, Status::Cached)],
        );
        let mut b = report("b", vec![rec("z", 3, Status::Fail)]);
        b.duration_ms = a.duration_ms + 5;
        let m = Report::merge(vec![a.clone(), b.clone()]).unwrap();
        assert_eq!(m.nodes.len(), 3);
        assert_eq!(m.verdict, Verdict::Fail);
        assert_eq!(m.roots, [NodeId::new("z")]);
        assert_eq!((m.counts.pass, m.counts.cached, m.counts.fail), (1, 1, 1));
        assert_eq!(m.duration_ms, b.duration_ms);
        let ok = Report::merge(vec![a]).unwrap();
        assert_eq!(ok.verdict, Verdict::Pass);
    }

    #[test]
    fn merge_rejects_empty_schema_drift_and_key_conflicts() {
        assert_eq!(Report::merge(vec![]), Err(MergeError::Empty));
        let a = report("a", vec![rec("x", 1, Status::Pass)]);
        let mut drift = report("b", vec![]);
        drift.schema = 2;
        assert!(matches!(
            Report::merge(vec![a.clone(), drift]),
            Err(MergeError::SchemaMismatch { found: 2, .. })
        ));
        let clash = report("c", vec![rec("x", 9, Status::Pass)]);
        let err = Report::merge(vec![a, clash]).unwrap_err();
        assert!(matches!(err, MergeError::KeyConflict { .. }));
        assert!(err.to_string().contains("`x`"));
    }

    #[test]
    fn merge_collapses_equal_keys_keeping_the_failure() {
        let a = report("a", vec![rec("x", 1, Status::Cached)]);
        let b = report("b", vec![rec("x", 1, Status::Fail)]);
        let c = report("c", vec![rec("x", 1, Status::Pass)]);
        let m = Report::merge(vec![a, b, c]).unwrap();
        assert_eq!(m.nodes.len(), 1);
        assert_eq!(m.nodes[0].status, Status::Fail);
        assert_eq!(m.roots, [NodeId::new("x")]);
    }

    #[test]
    fn merge_adds_interaction_counts() {
        let mut a = report("a", vec![]);
        let mut b = report("b", vec![]);
        let i = Interaction {
            interaction: ["crate:a".parse().unwrap(), "crate:b".parse().unwrap()],
            source: "cargo".into(),
            nodes: 2,
        };
        a.interactions.push(i.clone());
        b.interactions.push(Interaction { nodes: 3, ..i });
        assert_eq!(Report::merge(vec![a, b]).unwrap().interactions[0].nodes, 5);
    }
}

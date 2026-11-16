// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A Keel run from planning to report (DESIGN.md §7).

use super::{
    gate::{GateFinal, GateTimings, KeelGate, Outcome, RanOutcome},
    history::{HistoryEntry, KeelHistory},
};
use crate::errors::KeelError;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Local, SecondsFormat, Utc};
use keel::{
    Attempt, Budget, Counts, Detail, Evidence, Flaky, GroupId, LocalStore, Node, NodeId, Plan,
    Platform, Record, Report, ResultStore, SCHEMA, Stages, Status, StoredRecord, Upstream, Verdict,
};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    sync::Arc,
    time::{Duration, Instant},
};

/// Options that shape the report of a run.
#[derive(Clone, Debug)]
pub struct KeelReportOptions {
    /// Where to write `report.json`, if anywhere.
    pub report_path: Option<Utf8PathBuf>,

    /// The run budget from the config, if any.
    pub budget: Option<Duration>,

    /// The workspace root, used to name the repository and find its revision.
    pub workspace_root: Utf8PathBuf,

    /// When the run started. Every time in the report is measured from here.
    pub started: Instant,
}

/// Facts about the run that only the caller knows.
#[derive(Clone, Debug)]
pub struct KeelRunFacts {
    /// The run ID.
    pub run_id: String,

    /// When the run started.
    pub started_at: DateTime<Local>,

    /// How long the runner took, from its first event to its last.
    pub run_duration: Duration,
}

/// When the milestones of a run happened, in milliseconds since the run started.
///
/// These are written to `stages` in `report.json` as `first_test_ms`,
/// `first_root_ms` and `cargo_exit_ms`.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct KeelTimings {
    /// When the first test was started, if any test was.
    pub first_test_ms: Option<u64>,

    /// When the first root became final, if any did.
    pub first_root_ms: Option<u64>,

    /// When Cargo exited.
    pub cargo_exit_ms: Option<u64>,
}

impl KeelTimings {
    fn from_gate(timings: &GateTimings) -> Self {
        Self {
            first_test_ms: timings.first_test.map(duration_millis),
            first_root_ms: timings.first_root.map(duration_millis),
            cargo_exit_ms: timings.cargo_exit.map(duration_millis),
        }
    }
}

/// The outcome of finishing a Keel run.
#[derive(Debug)]
pub struct KeelFinish {
    /// The report, as written to `report.json`.
    pub report: Report,

    /// When the milestones of the run happened. They are in `report.json` too,
    /// next to the stage times.
    pub timings: KeelTimings,

    /// The text to print after nextest's own summary.
    pub summary: String,
}

/// A planned run that is executing.
#[derive(Debug)]
pub struct KeelSession {
    gate: Arc<KeelGate>,
    store: LocalStore,
    history: Arc<KeelHistory>,
    platform: Platform,
    options: KeelReportOptions,
}

impl KeelSession {
    /// Starts a session around `gate`.
    pub fn new(
        gate: Arc<KeelGate>,
        store: LocalStore,
        history: Arc<KeelHistory>,
        platform: Platform,
        options: KeelReportOptions,
    ) -> Self {
        Self {
            gate,
            store,
            history,
            platform,
            options,
        }
    }

    /// Returns the gate the runner schedules through.
    pub fn gate(&self) -> Arc<KeelGate> {
        self.gate.clone()
    }

    /// Finishes the run: stores passes, writes the report and the history, and
    /// renders the summary.
    pub fn finish(self, facts: &KeelRunFacts) -> Result<KeelFinish, KeelError> {
        let fin = self.gate.finish();
        if !fin.stalled.is_empty() {
            let nodes: Vec<Node> = fin.tests.iter().map(|test| test.node.clone()).collect();
            return Err(match Plan::new(&nodes) {
                Err(error) => KeelError::Plan(error),
                Ok(_) => KeelError::Stalled {
                    count: fin.stalled.len(),
                    first: fin.stalled[0].to_string(),
                },
            });
        }

        let mut records = Vec::with_capacity(fin.tests.len());
        let mut flaky = Vec::new();
        let mut executed = Vec::new();
        for (idx, test) in fin.tests.iter().enumerate() {
            let outcome = fin.outcomes[idx].as_ref();
            let record = self.record_for(idx, outcome, &fin, &mut flaky)?;
            if record.status == Status::Pass {
                self.store_pass(&test.node.id, &test.node.key, facts)?;
            }
            if let Some(Outcome::Ran(ran)) = outcome {
                executed.push((
                    test.node.id.to_string(),
                    HistoryEntry {
                        failed: !ran.status.gates_as_pass() && ran.status != Status::Flaky,
                        duration_ms: duration_millis(ran.duration),
                    },
                ));
            }
            records.push(record);
        }

        let timings = KeelTimings::from_gate(&fin.timings);
        let total = self.options.started.elapsed();
        let mut report = Report {
            schema: SCHEMA,
            run_id: facts.run_id.clone(),
            repo: self
                .options
                .workspace_root
                .file_name()
                .unwrap_or("workspace")
                .to_owned(),
            revision: revision(&self.options.workspace_root),
            head: None,
            base: None,
            platform: self.platform.clone(),
            verdict: Verdict::Pass,
            started_at: facts
                .started_at
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            duration_ms: duration_millis(total),
            budget: None,
            stages: Some(Stages {
                stage0_ms: 0,
                build_ms: timings.cargo_exit_ms.unwrap_or(0),
                key_ms: duration_millis(fin.key_time),
                run_ms: duration_millis(facts.run_duration),
            }),
            counts: Counts::default(),
            roots: Vec::new(),
            nodes: records,
            flaky,
            interactions: Vec::new(),
        };
        report.derive();
        let (path_ids, path_ms) = critical_path(&fin);
        if let Some(limit) = self.options.budget {
            report.budget = Some(Budget {
                limit_ms: duration_millis(limit),
                critical_path_ms: path_ms,
                critical_path: path_ids.clone(),
            });
        }

        if let Some(path) = &self.options.report_path {
            write_report(path, &report, &timings)?;
        }
        if let Err(error) = self.history.with_executed(executed).write() {
            tracing::warn!("could not update the Keel history: {error}");
        }
        let text = render_summary(&report, &fin, &timings, &path_ids, path_ms);
        Ok(KeelFinish {
            report,
            timings,
            summary: text,
        })
    }

    fn record_for(
        &self,
        idx: usize,
        outcome: Option<&Outcome>,
        fin: &GateFinal,
        flaky: &mut Vec<Flaky>,
    ) -> Result<Record, KeelError> {
        let node = &fin.tests[idx].node;
        let mut record = Record {
            id: node.id.clone(),
            key: node.key,
            status: Status::Skipped,
            reason: Some("run-cancelled".to_owned()),
            blocked_by: Vec::new(),
            duration_ms: None,
            attempt: None,
            detail: None,
            evidence: Vec::new(),
            cached_from: None,
        };
        match outcome {
            None => {}
            Some(Outcome::Cached { from }) => {
                record.status = Status::Cached;
                record.reason = None;
                record.cached_from = Some(from.clone());
            }
            Some(Outcome::Blocked { by }) => {
                record.status = Status::Blocked;
                record.reason = None;
                record.blocked_by = by.clone();
            }
            Some(Outcome::Ran(ran)) => {
                record.status = ran.status;
                record.reason = None;
                record.duration_ms = Some(duration_millis(ran.duration));
                record.attempt = Some(ran.attempts.len() as u32);
                record.blocked_by = fin.ran_blocked_by.get(&idx).cloned().unwrap_or_default();
                record.detail = Some(Detail {
                    ran: node.id.to_string(),
                    expected: None,
                    actual: ran.summary.clone(),
                });
                let last_outputs = ran.attempts.last().map(|a| a.outputs.as_slice());
                record.evidence = self.evidence(last_outputs.unwrap_or_default())?;
                if ran.status == Status::Flaky {
                    flaky.push(self.flaky_entry(node, ran)?);
                }
            }
        }
        Ok(record)
    }

    fn evidence(&self, outputs: &[(String, Vec<u8>)]) -> Result<Vec<Evidence>, KeelError> {
        outputs
            .iter()
            .map(|(name, bytes)| {
                let reference = self.store.put_blob(bytes).map_err(KeelError::Store)?;
                Ok(Evidence {
                    name: name.clone(),
                    reference,
                })
            })
            .collect()
    }

    fn flaky_entry(&self, node: &keel::Node, ran: &RanOutcome) -> Result<Flaky, KeelError> {
        let attempts = ran
            .attempts
            .iter()
            .map(|attempt| {
                Ok(Attempt {
                    status: attempt.status,
                    evidence: self.evidence(&attempt.outputs)?,
                })
            })
            .collect::<Result<Vec<_>, KeelError>>()?;
        Ok(Flaky {
            id: node.id.clone(),
            key: node.key,
            attempts,
        })
    }

    fn store_pass(
        &self,
        id: &NodeId,
        key: &keel::Digest,
        facts: &KeelRunFacts,
    ) -> Result<(), KeelError> {
        self.store
            .put(&StoredRecord {
                key: *key,
                id: id.clone(),
                status: Status::Pass,
                run_id: facts.run_id.clone(),
                recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                platform: self.platform.clone(),
                evidence: Vec::new(),
            })
            .map_err(KeelError::Store)
    }
}

fn duration_millis(duration: Duration) -> u64 {
    duration.as_millis().try_into().unwrap_or(u64::MAX)
}

fn revision(workspace_root: &Utf8Path) -> String {
    if let Ok(revision) = std::env::var("KEEL_REVISION") {
        return revision;
    }
    duct::cmd("git", ["rev-parse", "HEAD"])
        .dir(workspace_root)
        .stdout_capture()
        .stderr_null()
        .unchecked()
        .run()
        .ok()
        .filter(|output| output.status.success())
        .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_owned())
        .filter(|text| !text.is_empty())
        .unwrap_or_else(|| "unknown".to_owned())
}

/// Writes the report, with the milestones added to `stages`.
///
/// `keel::Stages` has no fields for the milestones, and `keel::Report` rejects
/// fields it does not know, so they are added to the JSON here.
fn write_report(path: &Utf8Path, report: &Report, timings: &KeelTimings) -> Result<(), KeelError> {
    let write_error = |error| KeelError::ReportWrite {
        path: path.to_owned(),
        error,
    };
    let mut value = serde_json::to_value(report).map_err(KeelError::ReportSerialize)?;
    if let Some(stages) = value
        .get_mut("stages")
        .and_then(serde_json::Value::as_object_mut)
    {
        for (name, milestone) in [
            ("first_test_ms", timings.first_test_ms),
            ("first_root_ms", timings.first_root_ms),
            ("cargo_exit_ms", timings.cargo_exit_ms),
        ] {
            if let Some(milestone) = milestone {
                stages.insert(name.to_owned(), milestone.into());
            }
        }
    }
    if let Some(parent) = path.parent().filter(|parent| !parent.as_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(write_error)?;
    }
    let json = serde_json::to_vec_pretty(&value).map_err(KeelError::ReportSerialize)?;
    std::fs::write(path, json).map_err(write_error)
}

/// Approximates the critical path as the longest chain of node durations
/// through `stands_on`.
///
/// Nodes are visited in the order in which they became terminal. A node became
/// terminal after everything it stood on, so this is a topological order of the
/// nodes that took part in the run, and nodes are compared by group, not by
/// member, so the path of a group is the path of its longest member.
fn critical_path(fin: &GateFinal) -> (Vec<NodeId>, u64) {
    let index: HashMap<&NodeId, usize> = fin
        .tests
        .iter()
        .enumerate()
        .map(|(idx, test)| (&test.node.id, idx))
        .collect();
    let duration = |idx: usize| -> u64 {
        match &fin.outcomes[idx] {
            Some(Outcome::Ran(ran)) => duration_millis(ran.duration),
            _ => 0,
        }
    };
    let mut best: Vec<Option<(u64, Option<usize>)>> = vec![None; fin.tests.len()];
    let mut group_best: HashMap<&GroupId, (u64, usize)> = HashMap::new();
    let mut winner: Option<(usize, u64)> = None;
    for &idx in &fin.terminal_order {
        let node = &fin.tests[idx].node;
        let mut before: (u64, Option<usize>) = (0, None);
        for edge in &node.stands_on {
            let candidate = match edge {
                Upstream::Group(group) => group_best.get(group).map(|&(total, at)| (total, at)),
                Upstream::Node(id) => index
                    .get(id)
                    .and_then(|&at| best[at].map(|(total, _)| (total, at))),
            };
            if let Some((total, at)) = candidate
                && (before.1.is_none() || total > before.0)
            {
                before = (total, Some(at));
            }
        }
        let total = before.0 + duration(idx);
        best[idx] = Some((total, before.1));
        let slot = group_best.entry(&node.group).or_insert((total, idx));
        if total > slot.0 {
            *slot = (total, idx);
        }
        if winner.is_none_or(|(_, w)| total > w) {
            winner = Some((idx, total));
        }
    }
    let Some((mut at, total)) = winner else {
        return (Vec::new(), 0);
    };
    let mut path = vec![fin.tests[at].node.id.clone()];
    while let Some((_, Some(parent))) = best[at] {
        path.push(fin.tests[parent].node.id.clone());
        at = parent;
    }
    path.reverse();
    (path, total)
}

fn format_ms(ms: u64) -> String {
    let seconds = ms as f64 / 1000.0;
    if seconds < 60.0 {
        format!("{seconds:.1}s")
    } else {
        format!("{}m{:04.1}s", ms / 60_000, (ms % 60_000) as f64 / 1000.0)
    }
}

/// What a root block shows.
pub(super) struct RootBlock<'a> {
    pub(super) id: &'a NodeId,
    pub(super) status: Status,
    pub(super) duration_ms: Option<u64>,

    /// How many symbols of its own package the root exercises, if known.
    pub(super) exercised: Option<usize>,

    /// The group of the root, for naming its package.
    pub(super) group: &'a str,

    /// The tests the root blocks.
    pub(super) blocked: &'a [&'a NodeId],

    /// The lines of the failure output to show.
    pub(super) stderr: Option<&'a str>,
}

/// Writes the block that reports a root (DESIGN.md §7).
pub(super) fn write_root_block(out: &mut String, block: &RootBlock<'_>) {
    let _ = writeln!(
        out,
        "\nROOT  {}   {}   {}",
        block.id,
        status_word(block.status),
        block.duration_ms.map_or_else(String::new, format_ms),
    );
    if let Some(exercised) = block.exercised {
        let _ = writeln!(
            out,
            "      exercised: {exercised} symbols in {}",
            block.group
        );
    }
    if !block.blocked.is_empty() {
        let shown: Vec<String> = block
            .blocked
            .iter()
            .take(3)
            .map(|id| id.to_string())
            .collect();
        let more = block.blocked.len().saturating_sub(shown.len());
        let tail = if more > 0 {
            format!(", and {more} more")
        } else {
            String::new()
        };
        let _ = writeln!(
            out,
            "      blocks:    {} tests ({}{tail})",
            block.blocked.len(),
            shown.join(", ")
        );
    }
    if let Some(actual) = block.stderr {
        for (n, line) in actual.lines().enumerate() {
            let label = if n == 0 { "stderr:" } else { "       " };
            let _ = writeln!(out, "      {label} {line}");
        }
    }
}

fn render_summary(
    report: &Report,
    fin: &GateFinal,
    timings: &KeelTimings,
    path: &[NodeId],
    path_ms: u64,
) -> String {
    let mut out = String::new();
    let counts = &report.counts;
    let stages = report.stages.unwrap_or_default();
    let cached = fin
        .tests
        .iter()
        .filter(|test| test.cached.is_some())
        .count();
    let _ = writeln!(
        out,
        "\nkeel: {} tests in {} binaries ({}, {})",
        fin.tests.len(),
        fin.binaries_keyed,
        report.platform.triple,
        report.platform.toolchain,
    );
    let _ = writeln!(
        out,
        "build     {}\nkeys      executable keys for {} binaries   {}{}\nselect    {} to run, {} cached\nrun       {} passed, {} failed, {} blocked, {} flaky   {}",
        format_ms(stages.build_ms),
        fin.binaries_keyed,
        format_ms(stages.key_ms),
        if fin.streamed {
            " (summed over threads)"
        } else {
            ""
        },
        fin.tests.len() - cached,
        cached,
        counts.pass,
        counts.fail + counts.timeout + counts.error,
        counts.blocked,
        counts.flaky,
        format_ms(stages.run_ms),
    );
    match timings.first_test_ms {
        Some(first_test) => {
            let _ = writeln!(
                out,
                "first test started at {}, Cargo exited at {}",
                format_ms(first_test),
                timings.cargo_exit_ms.map_or("n/a".to_owned(), format_ms),
            );
        }
        None => {
            let _ = writeln!(out, "no test was started");
        }
    }

    let by_id: BTreeMap<&NodeId, &Record> = report.nodes.iter().map(|r| (&r.id, r)).collect();
    let index: HashMap<&NodeId, usize> = fin
        .tests
        .iter()
        .enumerate()
        .map(|(idx, test)| (&test.node.id, idx))
        .collect();
    for root in &report.roots {
        let Some(record) = by_id.get(root) else {
            continue;
        };
        let planned = index.get(root).map(|&idx| &fin.tests[idx]);
        let blocked: Vec<&NodeId> = report
            .nodes
            .iter()
            .filter(|r| r.status == Status::Blocked && r.blocked_by.contains(root))
            .map(|r| &r.id)
            .collect();
        write_root_block(
            &mut out,
            &RootBlock {
                id: root,
                status: record.status,
                duration_ms: record.duration_ms,
                exercised: planned
                    .and_then(|planned| planned.exercised.as_ref())
                    .map(std::collections::BTreeSet::len),
                group: planned.map_or("", |planned| planned.node.group.name()),
                blocked: &blocked,
                stderr: record.detail.as_ref().and_then(|d| d.actual.as_deref()),
            },
        );
    }

    let budget = match &report.budget {
        Some(budget) => format!(
            "   budget {} of {}; critical path {} through {}",
            format_ms(report.duration_ms),
            format_ms(budget.limit_ms),
            format_ms(path_ms),
            path.last()
                .map_or("nothing".to_owned(), |id| id.to_string()),
        ),
        None => format!(
            "   critical path {}{}",
            format_ms(path_ms),
            path.last()
                .map_or(String::new(), |id| format!(" through {id}")),
        ),
    };
    let verdict = match report.verdict {
        Verdict::Pass => "PASS".to_owned(),
        Verdict::Fail => format!(
            "FAIL ({} {})",
            report.roots.len(),
            if report.roots.len() == 1 {
                "root"
            } else {
                "roots"
            }
        ),
    };
    let _ = writeln!(out, "\nverdict   {verdict}{budget}");
    out
}

fn status_word(status: Status) -> &'static str {
    match status {
        Status::Fail => "FAIL",
        Status::Timeout => "TIMEOUT",
        Status::Error => "ERROR",
        _ => "OTHER",
    }
}

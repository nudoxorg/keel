// Copyright (c) The nextest Contributors
// SPDX-License-Identifier: MIT OR Apache-2.0

//! A Keel run from planning to report (DESIGN.md §7).

use super::{
    gate::{GateSummary, KeelGate, Outcome, RanOutcome},
    plan::KeelPlan,
};
use crate::errors::KeelError;
use camino::{Utf8Path, Utf8PathBuf};
use chrono::{DateTime, Local, SecondsFormat, Utc};
use keel::{
    Attempt, Budget, Counts, Detail, Evidence, Flaky, LocalStore, NodeId, Record, Report,
    ResultStore, SCHEMA, Stages, Status, StoredRecord, Verdict,
};
use std::{
    collections::{BTreeMap, HashMap},
    fmt::Write as _,
    sync::Arc,
    time::Duration,
};

/// Options that shape the report of a run.
#[derive(Clone, Debug, Default)]
pub struct KeelReportOptions {
    /// Where to write `report.json`, if anywhere.
    pub report_path: Option<Utf8PathBuf>,

    /// The run budget from the config, if any.
    pub budget: Option<Duration>,

    /// The time spent building test binaries.
    pub build_duration: Duration,

    /// The workspace root, used to name the repository and find its revision.
    pub workspace_root: Utf8PathBuf,
}

/// Facts about the run that only the caller knows.
#[derive(Clone, Debug)]
pub struct KeelRunFacts {
    /// The run ID.
    pub run_id: String,

    /// When the run started.
    pub started_at: DateTime<Local>,

    /// How long the run took, from the first test to the last.
    pub run_duration: Duration,
}

/// The outcome of finishing a Keel run.
#[derive(Debug)]
pub struct KeelFinish {
    /// The report, as written to `report.json`.
    pub report: Report,

    /// The text to print after nextest's own summary.
    pub summary: String,
}

/// A planned run that is executing.
#[derive(Debug)]
pub struct KeelSession {
    gate: Arc<KeelGate>,
    store: LocalStore,
    options: KeelReportOptions,
}

impl KeelSession {
    /// Starts a session for `plan`.
    pub fn new(
        plan: KeelPlan,
        no_block: bool,
        store: LocalStore,
        options: KeelReportOptions,
    ) -> Self {
        Self {
            gate: KeelGate::new(Arc::new(plan), no_block),
            store,
            options,
        }
    }

    /// Returns the plan.
    pub fn plan(&self) -> &KeelPlan {
        self.gate.plan()
    }

    /// Returns the gate the runner schedules through.
    pub fn gate(&self) -> Arc<KeelGate> {
        self.gate.clone()
    }

    /// Finishes the run: stores passes, writes the report and renders the
    /// summary.
    pub fn finish(self, facts: &KeelRunFacts) -> Result<KeelFinish, KeelError> {
        let plan = self.gate.plan().clone();
        let summary = self.gate.summary();
        let mut records = Vec::with_capacity(plan.tests.len());
        let mut flaky = Vec::new();
        for (idx, test) in plan.tests.iter().enumerate() {
            let outcome = summary.outcomes[idx].as_ref();
            let record = self.record_for(idx, outcome, &summary, &plan, &mut flaky)?;
            if record.status == Status::Pass {
                self.store_pass(&test.node.id, &test.node.key, &plan, facts)?;
            }
            records.push(record);
        }

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
            platform: plan.platform.clone(),
            verdict: Verdict::Pass,
            started_at: facts
                .started_at
                .with_timezone(&Utc)
                .to_rfc3339_opts(SecondsFormat::Secs, true),
            duration_ms: millis(
                self.options.build_duration + plan.key_duration + facts.run_duration,
            ),
            budget: None,
            stages: Some(Stages {
                stage0_ms: 0,
                build_ms: millis(self.options.build_duration),
                key_ms: millis(plan.key_duration),
                run_ms: millis(facts.run_duration),
            }),
            counts: Counts::default(),
            roots: Vec::new(),
            nodes: records,
            flaky,
            interactions: Vec::new(),
        };
        report.derive();
        let (path_ids, path_ms) = critical_path(&plan, &summary);
        if let Some(limit) = self.options.budget {
            report.budget = Some(Budget {
                limit_ms: millis(limit),
                critical_path_ms: path_ms,
                critical_path: path_ids.clone(),
            });
        }

        if let Some(path) = &self.options.report_path {
            write_report(path, &report)?;
        }
        let text = render_summary(&report, &plan, &self.options, &path_ids, path_ms);
        Ok(KeelFinish {
            report,
            summary: text,
        })
    }

    fn record_for(
        &self,
        idx: usize,
        outcome: Option<&Outcome>,
        summary: &GateSummary,
        plan: &KeelPlan,
        flaky: &mut Vec<Flaky>,
    ) -> Result<Record, KeelError> {
        let node = &plan.tests[idx].node;
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
                record.duration_ms = Some(millis(ran.duration));
                record.attempt = Some(ran.attempts.len() as u32);
                record.blocked_by = summary
                    .ran_blocked_by
                    .get(&idx)
                    .cloned()
                    .unwrap_or_default();
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
        plan: &KeelPlan,
        facts: &KeelRunFacts,
    ) -> Result<(), KeelError> {
        self.store
            .put(&StoredRecord {
                key: *key,
                id: id.clone(),
                status: Status::Pass,
                run_id: facts.run_id.clone(),
                recorded_at: Utc::now().to_rfc3339_opts(SecondsFormat::Secs, true),
                platform: plan.platform.clone(),
                evidence: Vec::new(),
            })
            .map_err(KeelError::Store)
    }
}

fn millis(duration: Duration) -> u64 {
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

fn write_report(path: &Utf8Path, report: &Report) -> Result<(), KeelError> {
    let write_error = |error| KeelError::ReportWrite {
        path: path.to_owned(),
        error,
    };
    if let Some(parent) = path.parent().filter(|parent| !parent.as_str().is_empty()) {
        std::fs::create_dir_all(parent).map_err(write_error)?;
    }
    let json = serde_json::to_vec_pretty(report).map_err(KeelError::ReportSerialize)?;
    std::fs::write(path, json).map_err(write_error)
}

/// Approximates the critical path as the longest chain of node durations
/// through `stands_on`.
fn critical_path(plan: &KeelPlan, summary: &GateSummary) -> (Vec<NodeId>, u64) {
    let duration = |id: &NodeId| -> u64 {
        plan.index
            .get(id)
            .and_then(|&idx| summary.outcomes[idx].as_ref())
            .map_or(0, |outcome| match outcome {
                Outcome::Ran(ran) => millis(ran.duration),
                _ => 0,
            })
    };
    let mut best: HashMap<&NodeId, (u64, Option<&NodeId>)> = HashMap::new();
    let mut winner: Option<(&NodeId, u64)> = None;
    for id in plan.plan.order() {
        let (before, parent) = plan
            .plan
            .upstream(id)
            .unwrap_or_default()
            .into_iter()
            .filter_map(|up| best.get(up).map(|(total, _)| (*total, Some(up))))
            .max_by_key(|(total, _)| *total)
            .unwrap_or((0, None));
        let total = before + duration(id);
        best.insert(id, (total, parent));
        if winner.is_none_or(|(_, w)| total > w) {
            winner = Some((id, total));
        }
    }
    let Some((mut at, total)) = winner else {
        return (Vec::new(), 0);
    };
    let mut path = vec![at.clone()];
    while let Some((_, Some(parent))) = best.get(at) {
        path.push((*parent).clone());
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

fn render_summary(
    report: &Report,
    plan: &KeelPlan,
    options: &KeelReportOptions,
    path: &[NodeId],
    path_ms: u64,
) -> String {
    let mut out = String::new();
    let counts = &report.counts;
    let stages = report.stages.unwrap_or_default();
    let _ = writeln!(
        out,
        "\nkeel: {} tests in {} binaries ({}, {})",
        plan.len(),
        plan.binaries_keyed(),
        report.platform.triple,
        report.platform.toolchain,
    );
    let _ = writeln!(
        out,
        "build     {}\nkeys      executable keys for {} binaries   {}\nselect    {} to run, {} cached\nrun       {} passed, {} failed, {} blocked, {} flaky   {}",
        format_ms(stages.build_ms),
        plan.binaries_keyed(),
        format_ms(stages.key_ms),
        plan.len() - plan.cached_count(),
        plan.cached_count(),
        counts.pass,
        counts.fail + counts.timeout + counts.error,
        counts.blocked,
        counts.flaky,
        format_ms(stages.run_ms),
    );

    let by_id: BTreeMap<&NodeId, &Record> = report.nodes.iter().map(|r| (&r.id, r)).collect();
    for root in &report.roots {
        let Some(record) = by_id.get(root) else {
            continue;
        };
        let _ = writeln!(
            out,
            "\nROOT  {root}   {}   {}",
            status_word(record.status),
            record.duration_ms.map_or_else(String::new, format_ms),
        );
        if let Some(exercised) = plan
            .reach
            .as_ref()
            .and_then(|reach| reach.exercised.get(root))
        {
            let group = plan
                .index
                .get(root)
                .map_or("", |&idx| plan.tests[idx].node.group.name());
            let _ = writeln!(
                out,
                "      exercised: {} symbols in {group}",
                exercised.len()
            );
        }
        let blocked: Vec<&NodeId> = report
            .nodes
            .iter()
            .filter(|r| r.status == Status::Blocked && r.blocked_by.contains(root))
            .map(|r| &r.id)
            .collect();
        if !blocked.is_empty() {
            let shown: Vec<String> = blocked.iter().take(3).map(|id| id.to_string()).collect();
            let more = blocked.len().saturating_sub(shown.len());
            let tail = if more > 0 {
                format!(", and {more} more")
            } else {
                String::new()
            };
            let _ = writeln!(
                out,
                "      blocks:    {} tests ({}{tail})",
                blocked.len(),
                shown.join(", ")
            );
        }
        if let Some(actual) = record.detail.as_ref().and_then(|d| d.actual.as_deref()) {
            for (n, line) in actual.lines().enumerate() {
                let label = if n == 0 { "stderr:" } else { "       " };
                let _ = writeln!(out, "      {label} {line}");
            }
        }
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
    let _ = options;
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

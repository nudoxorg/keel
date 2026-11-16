//! Durable executable-check observations emitted by `keel-tree tree`.
//!
//! Like the other judge logs, this records supplied observations; it is not a
//! signature or an independent attestation of a historical process.
use crate::state::{Jsonl, read_jsonl};
use anyhow::{Context, Result, bail};
use keel_tree::driver::Evidence;
use serde::{Deserialize, Serialize};
use std::{collections::BTreeSet, path::Path};

pub const SCHEMA: &str = "keel.judge.checks.v1";
#[derive(Serialize, Deserialize)]
pub struct Record {
    pub schema: String,
    pub evidence: Evidence,
}

#[derive(Serialize, Default, Debug)]
pub struct Summary {
    pub pass: usize,
    pub fail: usize,
    pub blocked: usize,
    pub unknown: usize,
    pub failed_worlds: usize,
}

fn valid_hash(s: &str) -> bool {
    s.len() == 64
        && s.bytes()
            .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
}

/// A recorded verdict has already been bound by tree to the evaluated model,
/// exact manifest and artifact files. Reject malformed or internally
/// inconsistent records instead of treating them as green.
pub fn validate(e: &Evidence) -> Result<()> {
    if e.schema != 1 {
        bail!("unsupported check evidence schema");
    }
    if e.manifest_sha256.as_deref().is_some_and(|s| !valid_hash(s)) {
        bail!("invalid manifest identity");
    }
    if e.authority_environment_sha256
        .as_deref()
        .is_some_and(|s| !valid_hash(s))
    {
        bail!("invalid authority identity");
    }
    if e.driver_sha256.as_deref().is_some_and(|s| !valid_hash(s)) {
        bail!("invalid driver identity");
    }
    if e.driver_verified && e.driver_sha256.is_none() {
        bail!("verified driver has no identity");
    }
    if e.artifacts.values().any(|s| !valid_hash(s)) {
        bail!("invalid artifact identity");
    }
    if !e.failed_worlds.is_empty() && !(e.artifacts_verified && e.driver_verified) {
        bail!("unverified world failures");
    }
    for (world, error) in &e.failed_worlds {
        if error.is_empty()
            || !e
                .world_definitions
                .get(world)
                .is_some_and(|hash| valid_hash(hash))
        {
            bail!("unbound failed world {world}");
        }
    }
    if !e.case_outcomes.is_empty()
        && !(e.artifacts_verified && e.driver_verified && e.manifest_sha256.is_some())
    {
        bail!("unverified case outcomes");
    }
    for (id, outcome) in &e.case_outcomes {
        if id.is_empty()
            || !valid_hash(&outcome.definition_sha256)
            || !["pass", "fail", "blocked"].contains(&outcome.state.as_str())
        {
            bail!("invalid case outcome {id}");
        }
    }
    for (id, outcome) in &e.case_outcomes {
        if (outcome.state == "blocked") != !outcome.blocked_by_cases.is_empty() {
            bail!("invalid case blockers for {id}");
        }
        let mut pending = outcome.blocked_by_cases.clone();
        let mut seen = BTreeSet::new();
        while let Some(dependency) = pending.pop() {
            if dependency == *id {
                bail!("cyclic case dependency for {id}");
            }
            if !seen.insert(dependency.clone()) {
                continue;
            }
            let prior = e
                .case_outcomes
                .get(&dependency)
                .with_context(|| format!("missing case prerequisite {dependency}"))?;
            match prior.state.as_str() {
                "fail" => {}
                "blocked" => pending.extend(prior.blocked_by_cases.iter().cloned()),
                _ => bail!("case {id} names a passing prerequisite as blocked"),
            }
        }
    }
    let mut ids = BTreeSet::new();
    for c in &e.checks {
        if c.id.is_empty() || !ids.insert(&c.id) {
            bail!("empty or duplicate check id");
        }
        if c.definition_sha256
            .as_deref()
            .is_some_and(|s| !valid_hash(s))
            || c.case_inputs
                .values()
                .chain(c.artifacts.values())
                .any(|s| !valid_hash(s))
        {
            bail!("invalid identity for {}", c.id);
        }
        match c.state.as_str() {
            "unknown" if c.blocked_by.is_none() && c.blocked_by_cases.is_empty() => {}
            "pass" | "fail"
                if e.artifacts_verified
                    && e.driver_verified
                    && e.manifest_sha256.is_some()
                    && c.case.is_some()
                    && c.definition_sha256.is_some()
                    && !c.artifacts.is_empty()
                    && c.blocked_by.is_none()
                    && c.blocked_by_cases.is_empty()
                    && (e.case_outcomes.is_empty()
                        || c.case
                            .as_ref()
                            .and_then(|id| e.case_outcomes.get(id))
                            .is_some_and(|outcome| {
                                outcome.state == c.state
                                    && Some(outcome.definition_sha256.as_str())
                                        == c.definition_sha256.as_deref()
                            }))
                    && c.artifacts
                        .iter()
                        .all(|(k, v)| e.artifacts.get(k) == Some(v)) => {}
            "blocked"
                if e.artifacts_verified
                    && e.driver_verified
                    && ((c.blocked_by_cases.is_empty()
                        && c.blocked_by
                            .as_ref()
                            .is_some_and(|w| e.failed_worlds.contains_key(w)))
                        || (c.blocked_by.is_none()
                            && !c.blocked_by_cases.is_empty()
                            && c.case
                                .as_ref()
                                .and_then(|id| e.case_outcomes.get(id))
                                .is_some_and(|o| {
                                    o.state == "blocked"
                                        && Some(o.definition_sha256.as_str())
                                            == c.definition_sha256.as_deref()
                                        && o.blocked_by_cases == c.blocked_by_cases
                                })
                            && c.blocked_by_cases.iter().all(|id| {
                                e.case_outcomes
                                    .get(id)
                                    .is_some_and(|o| o.state == "fail" || o.state == "blocked")
                            }))) => {}
            _ => bail!("unbound or inconsistent outcome for {}", c.id),
        }
    }
    Ok(())
}

pub fn record(tree_verdict: &Path, state: &Path) -> Result<()> {
    let raw =
        std::fs::read(tree_verdict).with_context(|| format!("read {}", tree_verdict.display()))?;
    let value: serde_json::Value = serde_json::from_slice(&raw).context("invalid tree verdict")?;
    let evidence: Evidence = serde_json::from_value(
        value
            .get("check_evidence")
            .cloned()
            .context("tree verdict has no check evidence")?,
    )
    .context("invalid typed check evidence")?;
    validate(&evidence)?;
    std::fs::create_dir_all(state)?;
    Jsonl::open(&state.join("checks.jsonl"))?.append(&Record {
        schema: SCHEMA.into(),
        evidence,
    })
}

pub fn latest(state: &Path) -> Result<Option<Summary>> {
    let mut current = None;
    read_jsonl::<Record>(&state.join("checks.jsonl"), |record| {
        if record.schema != SCHEMA {
            bail!("unsupported check record schema {}", record.schema);
        }
        validate(&record.evidence)?;
        let mut summary = Summary {
            failed_worlds: record.evidence.failed_worlds.len(),
            ..Summary::default()
        };
        for c in record.evidence.checks {
            match c.state.as_str() {
                "pass" => summary.pass += 1,
                "fail" => summary.fail += 1,
                "blocked" => summary.blocked += 1,
                _ => summary.unknown += 1,
            }
        }
        current = Some(summary);
        Ok(())
    })?;
    Ok(current)
}

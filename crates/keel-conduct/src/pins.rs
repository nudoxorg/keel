//! Cross-repo pins (DESIGN §8.2): `{"<owner>/<repo>": "<revision>"}`.
//!
//! A cross-repo `stands_on` is resolved against the run recorded for the
//! pinned revision of the other repository, never against whatever ran last.

use std::collections::BTreeMap;
use std::path::Path;

use anyhow::{Context, Result, bail};
use keel::{NodeId, Record, Report, Status};

/// The pin table.
#[derive(Debug, Default, Clone)]
pub struct Pins(pub BTreeMap<String, String>);

impl Pins {
    /// Reads a pins file: the bare map, or `{"pins": {...}}` as a run-level
    /// document carries it.
    pub fn load(path: &Path) -> Result<Pins> {
        let text = std::fs::read_to_string(path).with_context(|| {
            format!(
                "cannot read the pins file {}; pass --pins <pins.json>",
                path.display()
            )
        })?;
        let value: serde_json::Value = serde_json::from_str(&text).with_context(|| {
            format!(
                "{} is not JSON; it must be {{\"owner/repo\": \"revision\"}}",
                path.display()
            )
        })?;
        let map = value.get("pins").unwrap_or(&value);
        let pins = serde_json::from_value(map.clone()).with_context(|| {
            format!("{} must map `owner/repo` to a revision string, e.g. {{\"Nudox/Backend\": \"4b841ca\"}}", path.display())
        })?;
        Ok(Pins(pins))
    }

    /// Fails unless `report` is the run of the revision its repository is
    /// pinned to. `must_be_pinned` makes an unpinned repository an error too.
    pub fn check(&self, report: &Report, source: &str, must_be_pinned: bool) -> Result<()> {
        match self.0.get(&report.repo) {
            Some(rev) if *rev == report.revision => Ok(()),
            Some(rev) => bail!(
                "{source} is the run of {} at revision {}, but the pins file pins {} to {rev}; fetch the report for {rev} (or change the pin on purpose)",
                report.repo,
                report.revision,
                report.repo
            ),
            None if must_be_pinned => bail!(
                "{source} is a report of {} but the pins file does not pin that repository; add \"{}\": \"{}\" to it, because cross-repo results are only trusted at a pinned revision",
                report.repo,
                report.repo,
                report.revision
            ),
            None => Ok(()),
        }
    }
}

/// How an upstream node from another repository stands: `Ok(())` when it
/// gates as a pass, else the roots that block whatever stands on it.
pub fn upstream_roots(id: &NodeId, records: &BTreeMap<NodeId, Record>) -> Option<Vec<NodeId>> {
    let r = records.get(id)?;
    Some(match r.status {
        s if s.gates_as_pass() => Vec::new(),
        Status::Fail | Status::Timeout | Status::Error if r.blocked_by.is_empty() => {
            vec![id.clone()]
        }
        Status::Fail | Status::Timeout | Status::Error | Status::Blocked => r.blocked_by.clone(),
        // Flaky, skipped and quarantined never block (§2.4).
        _ => Vec::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pins(pairs: &[(&str, &str)]) -> Pins {
        Pins(
            pairs
                .iter()
                .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
                .collect(),
        )
    }

    #[test]
    fn upstream_status_decides_roots() {
        let rec = |id: &str, status, by: &[&str]| Record {
            id: NodeId::new(id),
            key: keel::Digest::of(b"k"),
            status,
            reason: None,
            blocked_by: by.iter().map(|b| NodeId::new(*b)).collect(),
            duration_ms: None,
            attempt: None,
            detail: None,
            evidence: Vec::new(),
            cached_from: None,
        };
        let map: BTreeMap<_, _> = [
            rec("rust:a", Status::Fail, &[]),
            rec("rust:b", Status::Blocked, &["rust:a"]),
            rec("rust:c", Status::Cached, &[]),
        ]
        .into_iter()
        .map(|r| (r.id.clone(), r))
        .collect();
        assert_eq!(
            upstream_roots(&"rust:a".into(), &map),
            Some(vec!["rust:a".into()])
        );
        assert_eq!(
            upstream_roots(&"rust:b".into(), &map),
            Some(vec!["rust:a".into()])
        );
        assert_eq!(upstream_roots(&"rust:c".into(), &map), Some(vec![]));
        assert_eq!(upstream_roots(&"rust:z".into(), &map), None);
        let _ = pins(&[]);
    }
}

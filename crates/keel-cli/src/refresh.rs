//! `keel refresh`: a cached pass is evidence from a past execution. Listing the
//! ones older than a window lets the next run execute them again, which is how a
//! test that depends on something the key cannot see (the machine, the date, a
//! service it forgot to declare) is caught instead of trusted forever.

use std::collections::HashMap;

use anyhow::Result;
use keel::{Digest, NodeId, Report, Status};

use crate::store::Store;
use crate::util::parse_rfc3339;

pub struct Stale {
    pub id: NodeId,
    pub run_id: String,
    pub age_secs: i64,
}

/// The cached nodes of `report` whose stored pass was recorded more than
/// `older_than_secs` before `now`. A pass the store no longer has, or whose
/// time cannot be read, counts as stale: unknown age is not freshness.
pub fn stale(store: &Store, report: &Report, older_than_secs: i64, now: i64) -> Result<Vec<Stale>> {
    let mut keys: HashMap<Digest, Vec<&NodeId>> = HashMap::new();
    for r in report.nodes.iter().filter(|r| r.status == Status::Cached) {
        keys.entry(r.key).or_default().push(&r.id);
    }
    let keys: Vec<(Digest, Vec<&NodeId>)> = keys.into_iter().collect();
    // The store is a network hop per key; a handful of threads hides the latency.
    let workers = 8.min(keys.len().max(1));
    let chunk = keys.len().div_ceil(workers).max(1);
    let found: Vec<Result<Vec<Stale>>> = std::thread::scope(|s| {
        let handles: Vec<_> = keys
            .chunks(chunk)
            .map(|part| {
                s.spawn(move || -> Result<Vec<Stale>> {
                    let mut out = Vec::new();
                    for (key, ids) in part {
                        let (run_id, age) = match store.pass(key)? {
                            Some(p) => (
                                p.run_id,
                                parse_rfc3339(&p.recorded_at).map_or(i64::MAX, |t| now - t),
                            ),
                            None => ("(no stored pass)".to_owned(), i64::MAX),
                        };
                        if age > older_than_secs {
                            out.extend(ids.iter().map(|id| Stale {
                                id: (*id).clone(),
                                run_id: run_id.clone(),
                                age_secs: age,
                            }));
                        }
                    }
                    Ok(out)
                })
            })
            .collect();
        handles
            .into_iter()
            .map(|h| {
                h.join()
                    .unwrap_or_else(|_| Err(anyhow::anyhow!("a store worker panicked")))
            })
            .collect()
    });
    let mut all = Vec::new();
    for f in found {
        all.extend(f?);
    }
    all.sort_by(|a, b| a.id.cmp(&b.id));
    Ok(all)
}

/// The file `--keel-force` reads: one exact node id per line.
pub fn force_file(stale: &[Stale]) -> String {
    let mut s =
        String::from("# keel refresh: node ids to re-execute even though a stored pass exists\n");
    for x in stale {
        s.push_str(x.id.as_str());
        s.push('\n');
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel::store::{LocalStore, ResultStore, StoredRecord};
    use keel::{NetMode, Platform, Record};

    fn temp() -> std::path::PathBuf {
        crate::util::TempDir::new("refresh")
            .map(|t| {
                let p = t.path().to_path_buf();
                std::mem::forget(t);
                p
            })
            .unwrap()
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
    fn lists_cached_passes_older_than_the_window_and_unknown_ones() {
        let dir = temp();
        let local = LocalStore::open(&dir).unwrap();
        let put = |key: u8, at: &str| {
            local
                .put(&StoredRecord {
                    key: Digest::Blake3([key; 32]),
                    id: NodeId::new("x"),
                    status: Status::Pass,
                    run_id: format!("run-{key}"),
                    recorded_at: at.into(),
                    platform: Platform::new("t", "r", NetMode::Isolated),
                    evidence: vec![],
                })
                .unwrap()
        };
        put(1, "2026-11-13T00:00:00Z"); // one day old
        put(2, "2026-10-01T00:00:00Z"); // six weeks old
        let mut report: Report =
            serde_json::from_str(include_str!("../../keel/tests/fixtures/report.json")).unwrap();
        report.nodes = vec![
            rec("rust:fresh", 1, Status::Cached),
            rec("rust:old", 2, Status::Cached),
            rec("rust:gone", 3, Status::Cached),
            rec("rust:ran", 4, Status::Pass),
        ];
        let store = Store::Local(local);
        let now = parse_rfc3339("2026-11-14T00:00:00Z").unwrap();
        let s = stale(&store, &report, 7 * 86_400, now).unwrap();
        let ids: Vec<&str> = s.iter().map(|x| x.id.as_str()).collect();
        assert_eq!(ids, ["rust:gone", "rust:old"]);
        assert_eq!(s[1].run_id, "run-2");
        let f = force_file(&s);
        assert!(f.contains("\nrust:old\n") && !f.contains("rust:fresh"));
        std::fs::remove_dir_all(dir).unwrap();
    }
}

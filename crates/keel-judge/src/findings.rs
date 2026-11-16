//! Artifacts a quantum left behind, turned into deduplicated findings.

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::time::UNIX_EPOCH;

use anyhow::{Context, Result};

use crate::quantum::{ArtifactKind, signal_name};
use crate::sched::Claim;
use crate::state::{ExitInfo, FINDING_SCHEMA, FindingRecord, FindingStore, Jsonl, Outcome};
use crate::util::now_rfc3339;

// keel-fuzz is outside the workspace because of LibAFL, so it cannot be a dependency, but
// dedup.rs is self-contained (serde, blake3, rustc-demangle) and one copy keeps the keys
// the same in the gate and in the idle loop. Its API is larger than the part used here.
#[path = "../../keel-fuzz/src/dedup.rs"]
#[allow(dead_code, clippy::all)]
mod dedup;

/// Stderr kept next to a finding's input.
const STDERR_LINES: usize = 400;

/// File name -> (modified nanoseconds, length). A same-named file rewritten by a repeat
/// crash has a new mtime, and libFuzzer names artifacts by content, so names alone would
/// hide every repeat.
pub type Snapshot = BTreeMap<String, (u128, u64)>;

pub fn snapshot(dir: &Path) -> Result<Snapshot> {
    let mut out = Snapshot::new();
    let rd = std::fs::read_dir(dir).with_context(|| format!("cannot read {} (the artifacts of a target): check its permissions", dir.display()))?;
    for e in rd {
        let e = e?;
        let Ok(meta) = e.metadata() else { continue };
        if !meta.is_file() {
            continue;
        }
        let m = meta.modified().ok().and_then(|t| t.duration_since(UNIX_EPOCH).ok()).map_or(0, |d| d.as_nanos());
        out.insert(e.file_name().to_string_lossy().into_owned(), (m, meta.len()));
    }
    Ok(out)
}

pub fn count_files(dir: &Path) -> u64 {
    std::fs::read_dir(dir).map_or(0, |rd| rd.flatten().filter(|e| e.file_type().is_ok_and(|t| t.is_file())).count() as u64)
}

pub fn new_files(before: &Snapshot, after: &Snapshot) -> Vec<(String, ArtifactKind)> {
    after
        .iter()
        .filter(|(n, v)| before.get(*n) != Some(v))
        .filter_map(|(n, _)| ArtifactKind::of(n).map(|k| (n.clone(), k)))
        .collect()
}

/// What the loop knows about a finished quantum, for the finding step.
pub struct Scan<'a> {
    pub artifacts_dir: &'a Path,
    pub files: &'a [(String, ArtifactKind)],
    pub outcome: Outcome,
    pub exit: &'a ExitInfo,
    pub log_lines: &'a [String],
}

pub struct Noted {
    pub key: Option<String>,
    pub slow_units: u64,
}

fn moved(from: &Path, to: &Path) -> Result<()> {
    if std::fs::rename(from, to).is_ok() {
        return Ok(());
    }
    // Across filesystems (durable disk to the state dir) rename cannot work.
    std::fs::copy(from, to).with_context(|| format!("cannot copy {} to {} (a crash input kept as a finding); free space or fix the permissions of --state", from.display(), to.display()))?;
    std::fs::remove_file(from).with_context(|| format!("cannot remove {} after copying it", from.display()))
}

/// Writes one finding line per crash-like artifact (or one without an input when the run
/// failed but left none, so the target is still blocked) and updates `store`. The first
/// sighting of a key on a target moves its input into the state directory; later ones
/// are counted and their files left where they are.
pub fn record(store: &mut FindingStore, log: &mut Jsonl, state_dir: &Path, claim: &Claim, scan: &Scan<'_>) -> Result<Noted> {
    let slow_units = scan.files.iter().filter(|(_, k)| *k == ArtifactKind::SlowUnit).count() as u64;
    let mut inputs: Vec<Option<PathBuf>> =
        scan.files.iter().filter(|(_, k)| *k != ArtifactKind::SlowUnit).map(|(n, _)| Some(scan.artifacts_dir.join(n))).collect();
    // An oom with a SIGKILL and no `oom-` file is the cgroup's kill (quantum::classify): the
    // target did not break itself, the unit's memory ran out, perhaps through another
    // worker's child. It is recorded as the quantum's outcome, not as a bug that blocks the target.
    let cgroup_kill = scan.outcome == Outcome::Oom && scan.exit.signal == Some(libc::SIGKILL) && scan.files.is_empty();
    if inputs.is_empty() && scan.outcome != Outcome::Ok && scan.outcome != Outcome::Error && !cgroup_kill {
        inputs.push(None);
    }
    if inputs.is_empty() {
        return Ok(Noted { key: None, slow_units });
    }

    let text = scan.log_lines.join("\n");
    // libFuzzer catches the signal itself and exits 77, so the exit carries none. Without a
    // sanitizer it prints no stack either, and every such crash of one target shares a key;
    // the target is blocked by the first anyway, so the kind at least says which case it is.
    let deadly = scan.log_lines.iter().any(|l| l.contains("ERROR: libFuzzer: deadly signal"));
    let signal = scan.exit.signal.map(signal_name).or(match scan.outcome {
        Outcome::Oom => Some("OOM".to_string()),
        Outcome::Leak => Some("LEAK".to_string()),
        _ if deadly => Some("libfuzzer-deadly-signal".to_string()),
        _ => None,
    });
    let ck = dedup::crash_key(
        &text,
        &dedup::Exit { signal: signal.as_deref(), timed_out: scan.outcome == Outcome::Timeout, coverage_signature: "" },
        &|_| None,
    );

    let id = &claim.target.id;
    for input in inputs {
        let now = now_rfc3339();
        let known = store.get(id, &ck.key).is_some();
        let mut rec = FindingRecord {
            schema: FINDING_SCHEMA.into(),
            target: id.clone(),
            key: ck.key.clone(),
            kind: ck.kind.clone(),
            frames: ck.frames.clone(),
            source: ck.source.clone(),
            identity: claim.identity.clone(),
            first_seen: None,
            seen_again: None,
            input: input.as_ref().map(|p| p.display().to_string()),
        };
        if known {
            rec.seen_again = Some(now);
        } else {
            let dir = state_dir.join("findings").join(id).join(&ck.key);
            std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {} (the directory of a finding); fix the permissions of --state", dir.display()))?;
            if let Some(from) = &input {
                let bytes = std::fs::read(from).with_context(|| format!("cannot read {} (a crash input of target {id})", from.display()))?;
                let short = &blake3::hash(&bytes).to_hex()[..12];
                let to = dir.join(format!("input-{short}"));
                moved(from, &to)?;
                rec.input = Some(to.display().to_string());
            }
            let tail = &scan.log_lines[scan.log_lines.len().saturating_sub(STDERR_LINES)..];
            std::fs::write(dir.join("stderr.txt"), tail.join("\n") + "\n")
                .with_context(|| format!("cannot write {}/stderr.txt; fix the permissions of --state", dir.display()))?;
            rec.first_seen = Some(now);
        }
        log.append(&rec)?;
        store.apply(&rec);
    }
    Ok(Noted { key: Some(ck.key), slow_units })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChosenBy, Jsonl, read_jsonl};
    use crate::targets::Target;

    fn claim() -> Claim {
        Claim {
            idx: 0,
            seq: 1,
            target: Target {
                id: "pack".into(),
                name: "pack".into(),
                rank: 1,
                start_order: 1,
                complexity: None,
                gap: None,
                blast: None,
                argv: vec![],
                corpus: String::new(),
                artifacts: String::new(),
            },
            identity: "v1".into(),
            chosen_by: ChosenBy::Cold,
            rank: 1,
            rate: 0.1,
            index: 0.1,
        }
    }

    fn lines() -> Vec<String> {
        ["thread '<unnamed>' panicked at src/decode.rs:41:9:", "==5== ERROR: libFuzzer: deadly signal"].map(String::from).to_vec()
    }

    #[test]
    fn new_files_see_rewritten_same_named_files_but_not_old_ones() {
        let dir = tempfile::tempdir().unwrap();
        std::fs::write(dir.path().join("crash-a"), "1").unwrap();
        let before = snapshot(dir.path()).unwrap();
        assert!(new_files(&before, &snapshot(dir.path()).unwrap()).is_empty());
        std::thread::sleep(std::time::Duration::from_millis(5));
        std::fs::write(dir.path().join("crash-a"), "1").unwrap();
        std::fs::write(dir.path().join("slow-unit-b"), "x").unwrap();
        std::fs::write(dir.path().join("notes.txt"), "x").unwrap();
        let new = new_files(&before, &snapshot(dir.path()).unwrap());
        assert_eq!(new, vec![("crash-a".to_string(), ArtifactKind::Crash), ("slow-unit-b".to_string(), ArtifactKind::SlowUnit)]);
    }

    #[test]
    fn first_sighting_moves_the_input_and_a_repeat_is_counted() {
        let state = tempfile::tempdir().unwrap();
        let arts = tempfile::tempdir().unwrap();
        std::fs::write(arts.path().join("crash-1"), b"boom").unwrap();
        let mut store = FindingStore::default();
        let mut log = Jsonl::open(&state.path().join("findings.jsonl")).unwrap();
        let exit = ExitInfo { code: Some(1), signal: None };
        let log_lines = lines();
        let files = [("crash-1".to_string(), ArtifactKind::Crash)];
        let scan = Scan { artifacts_dir: arts.path(), files: &files, outcome: Outcome::Crash, exit: &exit, log_lines: &log_lines };
        let noted = record(&mut store, &mut log, state.path(), &claim(), &scan).unwrap();
        let key = noted.key.unwrap();
        assert!(!arts.path().join("crash-1").exists());
        let dir = state.path().join("findings/pack").join(&key);
        let kept: Vec<_> = std::fs::read_dir(&dir).unwrap().flatten().map(|e| e.file_name().to_string_lossy().into_owned()).collect();
        assert!(kept.iter().any(|n| n.starts_with("input-")) && kept.contains(&"stderr.txt".to_string()), "{kept:?}");
        assert_eq!(std::fs::read(dir.join(kept.iter().find(|n| n.starts_with("input-")).unwrap())).unwrap(), b"boom");

        // The same bug again, from a later build: counted, not stored twice.
        std::fs::write(arts.path().join("crash-1"), b"boom").unwrap();
        let mut c2 = claim();
        c2.identity = "v2".into();
        let again = record(&mut store, &mut log, state.path(), &c2, &scan).unwrap();
        assert_eq!(again.key.as_deref(), Some(key.as_str()));
        assert!(arts.path().join("crash-1").exists());
        assert_eq!(store.get("pack", &key).unwrap().times_seen, 2);
        assert!(store.is_blocked("pack", "v1") && store.is_blocked("pack", "v2"));

        let mut recs = Vec::new();
        read_jsonl::<FindingRecord>(&state.path().join("findings.jsonl"), |r| {
            recs.push(r);
            Ok(())
        })
        .unwrap();
        assert_eq!(recs.len(), 2);
        assert!(recs[0].first_seen.is_some() && recs[0].seen_again.is_none());
        assert!(recs[1].seen_again.is_some() && recs[1].first_seen.is_none());
        assert_eq!((recs[0].kind.as_str(), recs[0].source.as_str()), ("rust-panic", "panic"));
        assert_eq!(recs[0].frames, vec!["src/decode.rs:41:9".to_string()]);
    }

    #[test]
    fn a_failure_without_an_artifact_still_records_a_finding_and_slow_units_do_not() {
        let state = tempfile::tempdir().unwrap();
        let mut store = FindingStore::default();
        let mut log = Jsonl::open(&state.path().join("findings.jsonl")).unwrap();
        let exit = ExitInfo { code: Some(77), signal: None };
        let log_lines = lines();
        let scan = Scan { artifacts_dir: state.path(), files: &[], outcome: Outcome::Crash, exit: &exit, log_lines: &log_lines };
        assert!(record(&mut store, &mut log, state.path(), &claim(), &scan).unwrap().key.is_some());

        // The cgroup's SIGKILL is an oom quantum and no finding: the target is not blocked.
        let killed = ExitInfo { code: None, signal: Some(libc::SIGKILL) };
        let scan = Scan { artifacts_dir: state.path(), files: &[], outcome: Outcome::Oom, exit: &killed, log_lines: &[] };
        let mut fresh = FindingStore::default();
        assert_eq!(record(&mut fresh, &mut log, state.path(), &claim(), &scan).unwrap().key, None);
        assert!(fresh.by_key.is_empty() && !fresh.is_blocked("pack", "v1"));
        // libFuzzer's own oom (exit 71, an oom- file) still is one.
        let oom_file = [("oom-1".to_string(), ArtifactKind::Oom)];
        std::fs::write(state.path().join("oom-1"), b"x").unwrap();
        let own = ExitInfo { code: Some(71), signal: None };
        let scan = Scan { artifacts_dir: state.path(), files: &oom_file, outcome: Outcome::Oom, exit: &own, log_lines: &[] };
        assert!(record(&mut fresh, &mut log, state.path(), &claim(), &scan).unwrap().key.is_some());

        let slow = [("slow-unit-1".to_string(), ArtifactKind::SlowUnit)];
        let scan = Scan { artifacts_dir: state.path(), files: &slow, outcome: Outcome::Ok, exit: &exit, log_lines: &[] };
        let n = record(&mut FindingStore::default(), &mut log, state.path(), &claim(), &scan).unwrap();
        assert_eq!((n.key, n.slow_units), (None, 1));
    }
}

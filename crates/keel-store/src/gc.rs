//! `keel-store gc`: retention for a store directory (DESIGN §6).
//!
//! This is the only code that deletes anything, and it runs offline from the
//! service, as the same user. It follows `LocalStore`'s write protocol (the
//! per-shard `.lock`, write to a temp file then rename) so a running service
//! and a gc never see a torn results file.

use std::collections::HashSet;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use keel::{Digest, StoredRecord};

use crate::server::INDEX_KINDS;

/// What to keep.
#[derive(Clone, Copy, Debug)]
pub struct Policy {
    /// Retention of `pass` and `cached` record lines, by `recorded_at`.
    pub keep_pass: Duration,
    /// Retention of every other status (failures, flakes, ...).
    pub keep_fail: Duration,
    /// Blobs younger than this are never removed, even when no record names
    /// them yet: the conductor stores evidence before it appends the record,
    /// and `put_blob` does not touch an existing file, so only age can tell a
    /// blob in flight from an orphan.
    pub blob_grace: Duration,
    /// Free space the filesystem must still have after pruning.
    pub reserve_bytes: u64,
}

/// Why gc did not run.
#[derive(Debug, thiserror::Error)]
pub enum GcError {
    /// `statvfs` failed.
    #[error(
        "cannot stat the filesystem of {path}: {source}; refusing to prune without knowing the free space, check that the path exists and is mounted"
    )]
    Stat {
        /// The store directory.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },
    /// A filesystem operation failed.
    #[error("cannot {op} {path}: {source}; check the permissions of the store directory")]
    Io {
        /// What was being done.
        op: &'static str,
        /// The path.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },
}

fn io_err(op: &'static str, path: &Path) -> impl FnOnce(io::Error) -> GcError {
    let path = path.to_path_buf();
    move |source| GcError::Io { op, path, source }
}

/// What a gc pass did, or with `dry_run` would do.
#[derive(Debug, Default)]
pub struct Outcome {
    /// Record lines removed.
    pub records: u64,
    /// Results files removed because every line expired.
    pub record_files: u64,
    /// Manifest and report index entries removed.
    pub index_entries: u64,
    /// Blobs (and stale temp files) removed.
    pub blobs: u64,
    /// Bytes those blobs occupied.
    pub bytes_freed: u64,
    /// Free bytes on the filesystem before pruning.
    pub free_before: u64,
    /// Estimated free bytes after pruning (blob sizes only; record rewrites
    /// are not counted, they are small).
    pub free_after: u64,
    /// One line per removal, for `--dry-run` and the log.
    pub actions: Vec<String>,
    /// Things gc left alone because it could not understand them.
    pub warnings: Vec<String>,
}

impl Outcome {
    /// Whether free space is below `reserve_bytes` even after pruning.
    pub fn below_reserve(&self, policy: &Policy) -> bool {
        self.free_after < policy.reserve_bytes
    }
}

/// Runs retention on `dir` as of `now` (unix seconds). With `dry_run`
/// nothing is modified and not even the lock files are created.
pub fn run(dir: &Path, policy: &Policy, now: u64, dry_run: bool) -> Result<Outcome, GcError> {
    let stat = rustix::fs::statvfs(dir).map_err(|e| GcError::Stat {
        path: dir.into(),
        source: e.into(),
    })?;
    let mut out = Outcome {
        free_before: stat.f_bavail.saturating_mul(stat.f_frsize),
        ..Outcome::default()
    };
    let mut referenced: HashSet<Digest> = HashSet::new();

    prune_records(dir, policy, now, dry_run, &mut out, &mut referenced)?;
    prune_index(dir, policy, now, dry_run, &mut out, &mut referenced)?;
    prune_blobs(dir, policy, now, dry_run, &mut out, &referenced)?;

    out.free_after = out.free_before.saturating_add(out.bytes_freed);
    Ok(out)
}

fn list(dir: &Path) -> Result<Vec<PathBuf>, GcError> {
    match fs::read_dir(dir) {
        Ok(rd) => Ok(rd.flatten().map(|e| e.path()).collect()),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(vec![]),
        Err(e) => Err(io_err("list", dir)(e)),
    }
}

fn prune_records(
    dir: &Path,
    policy: &Policy,
    now: u64,
    dry_run: bool,
    out: &mut Outcome,
    referenced: &mut HashSet<Digest>,
) -> Result<(), GcError> {
    for shard in list(&dir.join("results"))? {
        for file in list(&shard)? {
            if file.extension().is_none_or(|e| e != "json") {
                continue;
            }
            // Writers hold this lock while they read-modify-rename; so do we.
            let _lock = if dry_run {
                None
            } else {
                let p = shard.join(".lock");
                let f = fs::OpenOptions::new()
                    .create(true)
                    .truncate(false)
                    .write(true)
                    .open(&p)
                    .map_err(io_err("open", &p))?;
                f.lock().map_err(io_err("lock", &p))?;
                Some(f)
            };
            let bytes = match fs::read(&file) {
                Ok(b) => b,
                Err(e) if e.kind() == io::ErrorKind::NotFound => continue,
                Err(e) => return Err(io_err("read", &file)(e)),
            };
            let (mut kept, mut dropped) = (Vec::new(), 0u64);
            for line in bytes.split(|&b| b == b'\n').filter(|l| !l.is_empty()) {
                match serde_json::from_slice::<StoredRecord>(line) {
                    Ok(r) => match parse_rfc3339(&r.recorded_at) {
                        Some(at) => {
                            let keep = if r.status.gates_as_pass() {
                                policy.keep_pass
                            } else {
                                policy.keep_fail
                            };
                            if now.saturating_sub(at) > keep.as_secs() {
                                dropped += 1;
                                continue;
                            }
                        }
                        None => out.warnings.push(format!(
                            "{}: kept a record with unreadable recorded_at `{}`; fix or delete the line by hand",
                            file.display(),
                            r.recorded_at
                        )),
                    },
                    Err(e) => out.warnings.push(format!(
                        "{}: kept a line that is not a record ({e}); gc never deletes what it cannot read",
                        file.display()
                    )),
                }
                // Evidence of every surviving line stays; an unreadable line
                // may reference anything, so its blobs cannot be known.
                if let Ok(r) = serde_json::from_slice::<StoredRecord>(line) {
                    referenced.extend(r.evidence.iter().map(|e| e.reference));
                }
                kept.push(line);
            }
            if dropped == 0 {
                continue;
            }
            out.records += dropped;
            if kept.is_empty() {
                out.record_files += 1;
                out.actions.push(format!(
                    "remove results file {} ({dropped} lines)",
                    file.display()
                ));
                if !dry_run {
                    fs::remove_file(&file).map_err(io_err("remove", &file))?;
                }
            } else {
                out.actions.push(format!(
                    "remove {dropped} expired lines from {}",
                    file.display()
                ));
                if !dry_run {
                    let mut text = kept.join(&b'\n');
                    text.push(b'\n');
                    write_atomic(&file, &text)?;
                }
            }
        }
    }
    Ok(())
}

/// Manifest and report index entries expire after the longer retention, by
/// file age; the rest point at blobs that must stay until then.
fn prune_index(
    dir: &Path,
    policy: &Policy,
    now: u64,
    dry_run: bool,
    out: &mut Outcome,
    referenced: &mut HashSet<Digest>,
) -> Result<(), GcError> {
    let keep = policy.keep_pass.max(policy.keep_fail);
    for kind in INDEX_KINDS {
        for entry in list(&dir.join("index").join(kind))? {
            if entry.extension().is_some() {
                continue; // a temp file; the blob sweep handles stale debris
            }
            if age(&entry, now).is_some_and(|a| a > keep.as_secs()) {
                out.index_entries += 1;
                out.actions
                    .push(format!("remove index entry {}", entry.display()));
                if !dry_run {
                    fs::remove_file(&entry).map_err(io_err("remove", &entry))?;
                }
            } else if let Ok(text) = fs::read_to_string(&entry)
                && let Ok(d) = Digest::from_str(text.trim())
            {
                referenced.insert(d);
            }
        }
    }
    Ok(())
}

fn prune_blobs(
    dir: &Path,
    policy: &Policy,
    now: u64,
    dry_run: bool,
    out: &mut Outcome,
    referenced: &HashSet<Digest>,
) -> Result<(), GcError> {
    for shard in list(&dir.join("objects"))? {
        for file in list(&shard)? {
            let name = file.file_name().map(|n| n.to_string_lossy().into_owned());
            let Some(name) = name else { continue };
            // Either a blob (named by its hex) or temp debris from a writer
            // that died mid-write; both go once they are older than the grace.
            let in_use =
                Digest::from_str(&format!("blake3:{name}")).is_ok_and(|d| referenced.contains(&d));
            if in_use || age(&file, now).is_none_or(|a| a <= policy.blob_grace.as_secs()) {
                continue;
            }
            let size = fs::metadata(&file).map(|m| m.len()).unwrap_or(0);
            out.blobs += 1;
            out.bytes_freed += size;
            out.actions
                .push(format!("remove blob {} ({size} bytes)", file.display()));
            if !dry_run {
                match fs::remove_file(&file) {
                    Err(e) if e.kind() != io::ErrorKind::NotFound => {
                        return Err(io_err("remove", &file)(e));
                    }
                    _ => {}
                }
            }
        }
    }
    Ok(())
}

fn age(path: &Path, now: u64) -> Option<u64> {
    let modified = fs::metadata(path).ok()?.modified().ok()?;
    let at = modified.duration_since(UNIX_EPOCH).ok()?.as_secs();
    Some(now.saturating_sub(at))
}

/// Same protocol as `keel::store`'s private writer: temp sibling then rename.
fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<(), GcError> {
    let tmp = dest.with_extension(format!("tmp-gc-{}", std::process::id()));
    let result = fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(io_err("write", &tmp))
        .and_then(|()| fs::rename(&tmp, dest).map_err(io_err("rename into place", dest)));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

/// Seconds since the epoch for an RFC 3339 timestamp, or `None`. Handles
/// `Z` and `+hh:mm` offsets and ignores fractional seconds; a calendar crate
/// would be a dependency for twenty lines.
pub fn parse_rfc3339(s: &str) -> Option<u64> {
    let b = s.as_bytes();
    if b.len() < 20
        || !s.is_ascii()
        || b[4] != b'-'
        || b[7] != b'-'
        || !matches!(b[10], b'T' | b't' | b' ')
    {
        return None;
    }
    let num = |r: std::ops::Range<usize>| s.get(r)?.parse::<i64>().ok();
    let (y, mo, d) = (num(0..4)?, num(5..7)?, num(8..10)?);
    let (h, mi, sec) = (num(11..13)?, num(14..16)?, num(17..19)?);
    if !(1..=12).contains(&mo) || !(1..=31).contains(&d) || h > 23 || mi > 59 || sec > 60 {
        return None;
    }
    let mut rest = &s[19..];
    if let Some(frac) = rest.strip_prefix('.') {
        rest = frac.trim_start_matches(|c: char| c.is_ascii_digit());
    }
    let offset = match rest {
        "Z" | "z" => 0,
        _ if rest.len() == 6 && (rest.starts_with('+') || rest.starts_with('-')) => {
            let sign = if rest.starts_with('-') { -1 } else { 1 };
            let oh = rest.get(1..3)?.parse::<i64>().ok()?;
            let om = rest.get(4..6)?.parse::<i64>().ok()?;
            sign * (oh * 3600 + om * 60)
        }
        _ => return None,
    };
    // Days from civil (Howard Hinnant's algorithm).
    let y = if mo <= 2 { y - 1 } else { y };
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let doy = (153 * (if mo > 2 { mo - 3 } else { mo + 9 }) + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    u64::try_from(days * 86_400 + h * 3600 + mi * 60 + sec - offset).ok()
}

/// Parses `30d`, `12h`, `90m`, `45s`, `2w`.
pub fn parse_duration(s: &str) -> Result<Duration, String> {
    let bad =
        || format!("`{s}` is not a duration; write a number and a unit, like 30d, 12h, 90m or 2w");
    let (n, unit) = s.split_at(s.len().checked_sub(1).ok_or_else(bad)?);
    let n: u64 = n.parse().map_err(|_| bad())?;
    let secs = match unit {
        "s" => 1,
        "m" => 60,
        "h" => 3600,
        "d" => 86_400,
        "w" => 604_800,
        _ => return Err(bad()),
    };
    Ok(Duration::from_secs(n * secs))
}

/// The current time in unix seconds.
pub fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timestamps_and_durations_parse() {
        assert_eq!(parse_rfc3339("1970-01-01T00:00:00Z"), Some(0));
        assert_eq!(parse_rfc3339("2026-11-14T08:12:03Z"), Some(1_794_643_923));
        assert_eq!(
            parse_rfc3339("2026-11-14T10:12:03.250+02:00"),
            parse_rfc3339("2026-11-14T08:12:03Z")
        );
        assert_eq!(parse_rfc3339("yesterday"), None);
        assert_eq!(parse_rfc3339("2026-13-14T08:12:03Z"), None);
        assert_eq!(
            parse_duration("30d").unwrap(),
            Duration::from_secs(30 * 86_400)
        );
        assert!(parse_duration("30").is_err());
        assert!(parse_duration("d").is_err());
        assert!(parse_duration("").is_err());
    }
}

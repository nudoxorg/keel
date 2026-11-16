//! The local result store of DESIGN.md §6: a filesystem content-addressed
//! store under one directory.
//!
//! ```text
//! objects/<2hex>/<hex>          blobs, named by their blake3
//! results/<2hex>/<hex>.json     JSON lines: every record ever written for key <hex>
//! results/<2hex>/.lock          serialises writers within one shard
//! ```
//!
//! Only `pass` is ever reused (§3.9); failures and flakes are kept as history.

use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};

use crate::digest::Digest;
use crate::key::Platform;
use crate::node::NodeId;
use crate::report::Evidence;
use crate::status::Status;

/// Why a store operation failed.
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    /// A filesystem operation failed.
    #[error(
        "cannot {op} {path}: {source}; check that the store directory exists and is writable by this user"
    )]
    Io {
        /// What was being done.
        op: &'static str,
        /// The file or directory.
        path: PathBuf,
        /// The OS error.
        source: io::Error,
    },
    /// Stored bytes are not what their name says they are.
    #[error(
        "store file {path} is corrupt: {reason}; delete it, the entry will be recomputed (at worst one rerun)"
    )]
    Corrupt {
        /// The file.
        path: PathBuf,
        /// What is wrong with it.
        reason: String,
    },
    /// A remote result store could not be used.
    #[error(
        "cannot use the result store at {endpoint}: {reason}; check that keel-store is running and reachable from this host, and that the writer token file is set (KEEL_STORE_TOKEN_FILE) for writes"
    )]
    Remote {
        /// The request that failed, `METHOD url`.
        endpoint: String,
        /// What went wrong, as the client reports it.
        reason: String,
    },
    /// A record could not be encoded.
    #[error("cannot encode a result record for {key}: {source}")]
    Encode {
        /// The record's key.
        key: Digest,
        /// The serde error.
        source: serde_json::Error,
    },
}

/// Result alias for store operations.
pub type Result<T> = std::result::Result<T, StoreError>;

fn io_err<'a>(op: &'static str, path: &'a Path) -> impl FnOnce(io::Error) -> StoreError + 'a {
    move |source| StoreError::Io {
        op,
        path: path.into(),
        source,
    }
}

/// One line of a results file: a node's outcome under a key, as the
/// conductor recorded it (§4 item 9: records carry the writer's run id).
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredRecord {
    /// The key the node ran under.
    pub key: Digest,
    /// The node.
    pub id: NodeId,
    /// How it ended.
    pub status: Status,
    /// The run that wrote this record.
    pub run_id: String,
    /// RFC 3339 time the record was written; supplied by the caller.
    pub recorded_at: String,
    /// The platform the key was computed for.
    pub platform: Platform,
    /// Stored outputs.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

/// A stored `pass`: the evidence that lets a later run report `cached`.
/// Also the JSON body of the result-store service's `GET /v1/pass/{key}`.
#[derive(Clone, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct StoredPass {
    /// The key it passed under.
    pub key: Digest,
    /// The node that passed.
    pub id: NodeId,
    /// The run that executed it (`cached_from` in the report).
    pub run_id: String,
    /// When it was recorded.
    pub recorded_at: String,
    /// The platform it passed on.
    pub platform: Platform,
    /// Its stored outputs.
    #[serde(default)]
    pub evidence: Vec<Evidence>,
}

impl From<StoredRecord> for StoredPass {
    fn from(r: StoredRecord) -> Self {
        StoredPass {
            key: r.key,
            id: r.id,
            run_id: r.run_id,
            recorded_at: r.recorded_at,
            platform: r.platform,
            evidence: r.evidence,
        }
    }
}

/// Storage for results and blobs. The conductor writes; anyone may read.
pub trait ResultStore {
    /// The newest stored `pass` for `key`, and only if every run recorded under
    /// that key agrees with it. A key is meant to cover everything the result
    /// depends on, so a `fail`, `flaky` or `timeout` beside a `pass` under one
    /// key means the key is incomplete or the test is not deterministic. In
    /// both cases the pass proves nothing about the next run, and none is
    /// returned: the test runs again and the disagreement stays on record.
    fn get_pass(&self, key: &Digest) -> Result<Option<StoredPass>>;
    /// Appends a record. Earlier records for the same key are kept.
    fn put(&self, record: &StoredRecord) -> Result<()>;
    /// Stores `bytes` and returns their blake3.
    fn put_blob(&self, bytes: &[u8]) -> Result<Digest>;
    /// The bytes behind `d`, if stored.
    fn get_blob(&self, d: &Digest) -> Result<Option<Vec<u8>>>;
}

/// A [`ResultStore`] in a local directory. Safe for any number of concurrent
/// readers and writers, in one process or several on the same filesystem.
#[derive(Clone, Debug)]
pub struct LocalStore {
    root: PathBuf,
}

impl LocalStore {
    /// Opens (creating if needed) a store rooted at `root`.
    pub fn open(root: impl Into<PathBuf>) -> Result<LocalStore> {
        let root = root.into();
        for sub in ["objects", "results"] {
            let dir = root.join(sub);
            fs::create_dir_all(&dir).map_err(io_err("create", &dir))?;
        }
        Ok(LocalStore { root })
    }

    /// The directory this store lives in.
    pub fn root(&self) -> &Path {
        &self.root
    }

    fn shard(&self, area: &str, d: &Digest) -> (PathBuf, String) {
        let hex = d.to_hex();
        (self.root.join(area).join(&hex[..2]), hex)
    }
}

/// Writes `bytes` to `dest` through a sibling temp file and a rename, so a
/// reader sees the old file or the new one, never half of either. Nothing is
/// fsynced: a lost entry costs one rerun, never a wrong result.
fn write_atomic(dest: &Path, bytes: &[u8]) -> Result<()> {
    static N: AtomicU64 = AtomicU64::new(0);
    let tmp = dest.with_extension(format!(
        "tmp-{}-{}",
        std::process::id(),
        N.fetch_add(1, Ordering::Relaxed)
    ));
    let result = fs::File::create(&tmp)
        .and_then(|mut f| f.write_all(bytes))
        .map_err(io_err("write", &tmp))
        .and_then(|()| fs::rename(&tmp, dest).map_err(io_err("rename into place", dest)));
    if result.is_err() {
        let _ = fs::remove_file(&tmp);
    }
    result
}

fn read_optional(path: &Path) -> Result<Option<Vec<u8>>> {
    match fs::read(path) {
        Ok(b) => Ok(Some(b)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(StoreError::Io {
            op: "read",
            path: path.into(),
            source: e,
        }),
    }
}

impl ResultStore for LocalStore {
    fn get_pass(&self, key: &Digest) -> Result<Option<StoredPass>> {
        let (dir, hex) = self.shard("results", key);
        let path = dir.join(format!("{hex}.json"));
        let Some(bytes) = read_optional(&path)? else {
            return Ok(None);
        };
        let corrupt = |line: usize, reason: String| StoreError::Corrupt {
            path: path.clone(),
            reason: format!("line {line}: {reason}"),
        };
        let mut newest = None;
        let mut disputed = false;
        for (n, line) in bytes
            .split(|&b| b == b'\n')
            .enumerate()
            .filter(|(_, l)| !l.is_empty())
        {
            let record: StoredRecord =
                serde_json::from_slice(line).map_err(|e| corrupt(n + 1, e.to_string()))?;
            if record.key != *key {
                return Err(corrupt(
                    n + 1,
                    format!("holds a record for {} in the file for {key}", record.key),
                ));
            }
            match record.status {
                Status::Pass => newest = Some(record),
                Status::Fail | Status::Flaky | Status::Timeout => disputed = true,
                // Not verdicts on the test: it did not run, or a pass was reused.
                _ => {}
            }
        }
        if disputed {
            return Ok(None);
        }
        Ok(newest.map(StoredPass::from))
    }

    fn put(&self, record: &StoredRecord) -> Result<()> {
        let mut line = serde_json::to_vec(record).map_err(|source| StoreError::Encode {
            key: record.key,
            source,
        })?;
        line.push(b'\n');
        let (dir, hex) = self.shard("results", &record.key);
        fs::create_dir_all(&dir).map_err(io_err("create", &dir))?;

        // Rename replaces the inode, so a lock on the results file itself would
        // not survive it; the lock lives on a per-shard sibling instead.
        let lock_path = dir.join(".lock");
        let lock = fs::OpenOptions::new()
            .create(true)
            .truncate(false)
            .write(true)
            .open(&lock_path)
            .map_err(io_err("open", &lock_path))?;
        lock.lock().map_err(io_err("lock", &lock_path))?;

        let path = dir.join(format!("{hex}.json"));
        let mut all = read_optional(&path)?.unwrap_or_default();
        all.extend_from_slice(&line);
        write_atomic(&path, &all)
        // `lock` is released when the handle closes here.
    }

    fn put_blob(&self, bytes: &[u8]) -> Result<Digest> {
        let digest = Digest::of(bytes);
        let (dir, hex) = self.shard("objects", &digest);
        let path = dir.join(&hex);
        if path.exists() {
            return Ok(digest);
        }
        fs::create_dir_all(&dir).map_err(io_err("create", &dir))?;
        write_atomic(&path, bytes)?;
        Ok(digest)
    }

    fn get_blob(&self, d: &Digest) -> Result<Option<Vec<u8>>> {
        let (dir, hex) = self.shard("objects", d);
        let path = dir.join(hex);
        let Some(bytes) = read_optional(&path)? else {
            return Ok(None);
        };
        // A blake3 name is a promise about the content; check it so a
        // truncated or tampered blob is an error rather than evidence.
        if matches!(d, Digest::Blake3(_)) && Digest::of(&bytes) != *d {
            return Err(StoreError::Corrupt {
                path,
                reason: format!("its bytes hash to {}, not {d}", Digest::of(&bytes)),
            });
        }
        Ok(Some(bytes))
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;

    use super::*;
    use crate::key::NetMode;
    use crate::testutil::TempDir;

    fn record(key: u8, status: Status, run: &str) -> StoredRecord {
        StoredRecord {
            key: Digest::Blake3([key; 32]),
            id: NodeId::new("rust:a::b"),
            status,
            run_id: run.into(),
            recorded_at: "2026-11-14T08:12:03Z".into(),
            platform: Platform::new("x86_64-unknown-linux-gnu", "rustc", NetMode::Isolated),
            evidence: vec![],
        }
    }

    #[test]
    fn blobs_round_trip_and_are_named_by_their_hash() {
        let dir = TempDir::new("blob");
        let store = LocalStore::open(dir.path()).unwrap();
        let d = store.put_blob(b"stderr text").unwrap();
        assert_eq!(d, Digest::of(b"stderr text"));
        assert_eq!(store.put_blob(b"stderr text").unwrap(), d);
        assert_eq!(store.get_blob(&d).unwrap().unwrap(), b"stderr text");
        let hex = d.to_hex();
        assert!(
            dir.path()
                .join("objects")
                .join(&hex[..2])
                .join(&hex)
                .is_file()
        );
        assert_eq!(store.get_blob(&Digest::of(b"absent")).unwrap(), None);
    }

    #[test]
    fn a_tampered_blob_is_an_error_not_evidence() {
        let dir = TempDir::new("tamper");
        let store = LocalStore::open(dir.path()).unwrap();
        let d = store.put_blob(b"original").unwrap();
        let hex = d.to_hex();
        fs::write(
            dir.path().join("objects").join(&hex[..2]).join(&hex),
            b"changed",
        )
        .unwrap();
        let err = store.get_blob(&d).unwrap_err();
        assert!(matches!(err, StoreError::Corrupt { .. }), "{err}");
    }

    #[test]
    fn a_pass_is_returned_only_while_no_run_under_the_key_disagrees() {
        let dir = TempDir::new("pass");
        let store = LocalStore::open(dir.path()).unwrap();
        let k = Digest::Blake3([1; 32]);
        assert!(store.get_pass(&k).unwrap().is_none());

        store.put(&record(1, Status::Pass, "r3")).unwrap();
        store.put(&record(1, Status::Error, "r3e")).unwrap();
        store.put(&record(1, Status::Pass, "r4")).unwrap();
        let pass = store.get_pass(&k).unwrap().unwrap();
        assert_eq!(
            pass.run_id, "r4",
            "the newest pass; a run that could not start is no verdict"
        );

        // The same key has now both passed and failed: the pass is void.
        store.put(&record(1, Status::Fail, "r5")).unwrap();
        assert!(
            store.get_pass(&k).unwrap().is_none(),
            "a pass disputed by a later failure is not served"
        );
        store.put(&record(1, Status::Pass, "r6")).unwrap();
        assert!(
            store.get_pass(&k).unwrap().is_none(),
            "nor does a later pass restore it"
        );

        for (key, disagreeing) in [(3, Status::Fail), (4, Status::Flaky), (5, Status::Timeout)] {
            store.put(&record(key, disagreeing, "a")).unwrap();
            store.put(&record(key, Status::Pass, "b")).unwrap();
            assert!(
                store
                    .get_pass(&Digest::Blake3([key; 32]))
                    .unwrap()
                    .is_none(),
                "{disagreeing:?} before a pass disputes it too"
            );
        }
        assert!(store.get_pass(&Digest::Blake3([2; 32])).unwrap().is_none());

        let hex = k.to_hex();
        let text = fs::read_to_string(
            dir.path()
                .join("results")
                .join(&hex[..2])
                .join(format!("{hex}.json")),
        )
        .unwrap();
        assert_eq!(text.lines().count(), 5, "history is kept");
    }

    #[test]
    fn a_remote_failure_names_the_endpoint_and_what_to_check() {
        let msg = StoreError::Remote {
            endpoint: "GET http://192.0.2.1:4817/v1/health".into(),
            reason: "connection refused".into(),
        }
        .to_string();
        for part in [
            "GET http://192.0.2.1:4817/v1/health",
            "connection refused",
            "keel-store is running and reachable",
            "KEEL_STORE_TOKEN_FILE",
        ] {
            assert!(msg.contains(part), "{msg}");
        }
    }

    #[test]
    fn a_stored_pass_round_trips_as_json() {
        let pass = StoredPass::from(record(1, Status::Pass, "r"));
        let text = serde_json::to_string(&pass).unwrap();
        assert_eq!(serde_json::from_str::<StoredPass>(&text).unwrap(), pass);
        assert!(!text.contains("status"));
    }

    #[test]
    fn a_corrupt_results_file_is_named() {
        let dir = TempDir::new("corrupt");
        let store = LocalStore::open(dir.path()).unwrap();
        let k = Digest::Blake3([3; 32]);
        store.put(&record(3, Status::Pass, "r")).unwrap();
        let hex = k.to_hex();
        let path = dir
            .path()
            .join("results")
            .join(&hex[..2])
            .join(format!("{hex}.json"));
        fs::write(&path, b"{not json}\n").unwrap();
        let err = store.get_pass(&k).unwrap_err().to_string();
        assert!(err.contains(&hex) && err.contains("line 1"), "{err}");
    }

    #[test]
    fn concurrent_writers_lose_nothing_and_readers_never_see_a_torn_line() {
        let dir = TempDir::new("threads");
        let store = Arc::new(LocalStore::open(dir.path()).unwrap());
        let k = Digest::Blake3([9; 32]);
        const THREADS: usize = 8;
        const PER: usize = 25;

        let writers: Vec<_> = (0..THREADS)
            .map(|t| {
                let store = Arc::clone(&store);
                std::thread::spawn(move || {
                    for i in 0..PER {
                        store
                            .put(&record(9, Status::Pass, &format!("t{t}-{i}")))
                            .unwrap();
                        store
                            .put_blob(format!("blob {}", i % 5).as_bytes())
                            .unwrap();
                    }
                })
            })
            .collect();
        let reader = {
            let store = Arc::clone(&store);
            std::thread::spawn(move || {
                for _ in 0..200 {
                    store.get_pass(&k).unwrap();
                }
            })
        };
        for w in writers {
            w.join().unwrap();
        }
        reader.join().unwrap();

        let hex = k.to_hex();
        let text = fs::read_to_string(
            dir.path()
                .join("results")
                .join(&hex[..2])
                .join(format!("{hex}.json")),
        )
        .unwrap();
        let mut runs: Vec<String> = text
            .lines()
            .map(|l| serde_json::from_str::<StoredRecord>(l).unwrap().run_id)
            .collect();
        runs.sort();
        runs.dedup();
        assert_eq!(runs.len(), THREADS * PER);
        let leftovers: Vec<_> = fs::read_dir(dir.path().join("results").join(&hex[..2]))
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.file_name().to_string_lossy().contains("tmp-"))
            .collect();
        assert!(leftovers.is_empty());
    }
}

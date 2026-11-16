//! Fixtures shared by the integration tests. Not every test file uses every
//! helper.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use keel::{Digest, NetMode, NodeId, Platform, Status, StoredRecord};
use keel_store::server::{Config, Limits, Running};

/// A uniquely named directory removed on drop (`tempfile` is not in the
/// workspace table).
pub struct TempDir(PathBuf);

impl TempDir {
    pub fn new(label: &str) -> Self {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "keel-store-test-{label}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
    pub fn path(&self) -> &Path {
        &self.0
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The read token the test servers use for a given writer token.
pub fn read_token(writer: &str) -> String {
    format!("read-{writer}")
}

/// A fresh random writer token, as hex.
pub fn token() -> String {
    hex::encode(rand::random::<[u8; 16]>())
}

pub fn start(dir: &Path, token: &str, limits: Limits) -> Running {
    let config = Config {
        dir: dir.into(),
        token: token.into(),
        read_token: Some(read_token(token)),
        limits,
    };
    Running::spawn(config, "127.0.0.1:0".parse().unwrap()).unwrap()
}

pub fn platform() -> Platform {
    Platform::new(
        "x86_64-unknown-linux-gnu",
        "rustc 1.97.1",
        NetMode::Isolated,
    )
}

pub fn key(n: u8) -> Digest {
    Digest::Blake3([n; 32])
}

pub fn record(key_byte: u8, status: Status, run: &str, recorded_at: &str) -> StoredRecord {
    StoredRecord {
        key: key(key_byte),
        id: NodeId::new("rust:a::b"),
        status,
        run_id: run.into(),
        recorded_at: recorded_at.into(),
        platform: platform(),
        evidence: vec![],
    }
}

/// Unix seconds as `YYYY-MM-DDTHH:MM:SSZ` (civil-from-days, the inverse of
/// the parser under test, so the two check each other).
pub fn rfc3339(secs: u64) -> String {
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = yoe + era * 400 + i64::from(m <= 2);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// Where `LocalStore` keeps the blob `d`.
pub fn blob_path(dir: &Path, d: &Digest) -> PathBuf {
    let hex = d.to_hex();
    dir.join("objects").join(&hex[..2]).join(hex)
}

/// Where `LocalStore` keeps the records for `d`.
pub fn results_path(dir: &Path, d: &Digest) -> PathBuf {
    let hex = d.to_hex();
    dir.join("results")
        .join(&hex[..2])
        .join(format!("{hex}.json"))
}

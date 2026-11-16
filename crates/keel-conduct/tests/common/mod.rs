//! Shared fixtures: a scratch directory, a store, the go binary, and a runner.
#![allow(dead_code)]

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::{AtomicU64, Ordering};

use keel::{Record, Report, Status};
use keel_conduct::config::Config;
use keel_conduct::run::{self, RunOpts};
use keel_conduct::store::Store;

/// A directory removed on drop.
pub struct Tmp(pub PathBuf);

impl Tmp {
    pub fn new(label: &str) -> Tmp {
        static N: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "keel-conduct-test-{label}-{}-{}",
            std::process::id(),
            N.fetch_add(1, Ordering::Relaxed)
        ));
        std::fs::create_dir_all(&dir).unwrap();
        // Canonical, so paths compare equal to what `go list` prints.
        Tmp(dir.canonicalize().unwrap())
    }

    pub fn path(&self) -> &Path {
        &self.0
    }

    pub fn write(&self, rel: &str, text: &str) {
        let p = self.0.join(rel);
        std::fs::create_dir_all(p.parent().unwrap()).unwrap();
        std::fs::write(p, text).unwrap();
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// The go binary from nixpkgs, or `None` (with the reason printed) when nix
/// is unavailable. `KEEL_TEST_GO` overrides it.
pub fn go_binary() -> Option<PathBuf> {
    if let Some(p) = std::env::var_os("KEEL_TEST_GO") {
        return Some(p.into());
    }
    let out = Command::new("nix")
        .args([
            "shell",
            "nixpkgs#go",
            "--command",
            "sh",
            "-c",
            "command -v go",
        ])
        .output();
    match out {
        Ok(o) if o.status.success() => Some(String::from_utf8_lossy(&o.stdout).trim().into()),
        _ => {
            eprintln!(
                "SKIP: `nix shell nixpkgs#go` is unavailable, so there is no go binary for the Go tests"
            );
            None
        }
    }
}

pub fn nix_available() -> bool {
    let ok = Command::new("nix")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("SKIP: nix is unavailable");
    }
    ok
}

pub fn nu_available() -> bool {
    let ok = Command::new("nu")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!("SKIP: nu is not on PATH");
    }
    ok
}

/// Runs the conductor over `root/keel.toml` against a store directory.
pub fn conduct(root: &Path, store: &Path, go: Option<&Path>) -> Report {
    let cfg = Config::load(&root.join("keel.toml")).unwrap();
    let store = Store::open(store.to_str().unwrap()).unwrap();
    run::run(
        &cfg,
        &store,
        &RunOpts {
            repo_root: root.to_path_buf(),
            revision: "0123456789abcdef0123456789abcdef01234567".into(),
            jobs: 4,
            no_block: false,
            go: go.map(Path::to_path_buf),
            work_dir: None,
            upstream: Vec::new(),
            pins: None,
        },
    )
    .unwrap()
    .report
}

pub fn rec<'a>(r: &'a Report, id: &str) -> &'a Record {
    r.nodes
        .iter()
        .find(|n| n.id.as_str() == id)
        .unwrap_or_else(|| panic!("no record for {id}"))
}

pub fn status(r: &Report, id: &str) -> Status {
    rec(r, id).status
}

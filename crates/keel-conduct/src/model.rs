//! What the sources produce and the scheduler consumes: a [`Node`] with its
//! way of running, and the outcome of running it.

use std::collections::{BTreeMap, HashMap};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use keel::store::ResultStore;
use keel::{Detail, EnvContract, Evidence, Node, NodeId, Record, Status, clean_environment};

use crate::{cmd, go, nix};

/// A node and how to run it.
pub struct Planned {
    /// The node as it appears in the manifest, key included.
    pub node: Node,
    /// How to execute it.
    pub runner: Runner,
}

/// The execution side of a node, one variant per source.
pub enum Runner {
    /// `go test -json` of one package.
    Go(go::GoRun),
    /// A command: nushell check, plain command, or artifact producer.
    Cmd(cmd::CmdRun),
    /// A Nix build.
    Nix(nix::NixRun),
}

/// What a runner needs besides the node.
pub struct Cx<'a> {
    /// Where blobs go.
    pub store: &'a (dyn ResultStore + Sync),
    /// Scratch space for per-node HOME, TMPDIR and consumed artifacts.
    pub work: &'a Path,
    /// Evidence of the artifact nodes this node consumes, by producer.
    pub consumed: &'a BTreeMap<NodeId, Vec<Evidence>>,
}

/// How one node ended.
pub struct Outcome {
    /// `pass`, `fail`, `timeout` or `error` (the scheduler adds `cached`).
    pub status: Status,
    /// Machine-readable qualifier.
    pub reason: Option<String>,
    /// What ran and what went wrong.
    pub detail: Option<Detail>,
    /// Stored outputs.
    pub evidence: Vec<Evidence>,
    /// Records for nodes the runner reported on that are not in the plan.
    pub extra: Vec<Record>,
    /// Wall time.
    pub duration_ms: u64,
}

impl Outcome {
    /// A failure to even start, with the cause already worded for a reader.
    pub fn error(message: String, ran: &str, started: std::time::Instant) -> Outcome {
        Outcome {
            status: Status::Error,
            reason: None,
            detail: Some(Detail {
                ran: ran.to_owned(),
                expected: None,
                actual: Some(message),
            }),
            evidence: Vec::new(),
            extra: Vec::new(),
            duration_ms: started.elapsed().as_millis() as u64,
        }
    }
}

/// Stores `bytes` as a blob and names it.
pub fn evidence(store: &dyn ResultStore, name: &str, bytes: &[u8]) -> Result<Evidence> {
    let reference = store.put_blob(bytes).with_context(|| {
        format!("cannot store the `{name}` output of a node; check the store is reachable and the writer token is set")
    })?;
    Ok(Evidence {
        name: name.to_owned(),
        reference,
    })
}

static STORE_WARNINGS: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Reports a store failure. The first is printed in full; a down store would
/// otherwise print one line per node, so the rest are only counted
/// ([`store_warnings`]).
pub fn store_warning(msg: String) {
    if STORE_WARNINGS.fetch_add(1, std::sync::atomic::Ordering::Relaxed) == 0 {
        eprintln!(
            "keel-conduct: warning: {msg}; results stay correct, they are only not shared (further store problems are counted, not printed)"
        );
    }
}

/// How many store operations failed so far in this process.
pub fn store_warnings() -> usize {
    STORE_WARNINGS.load(std::sync::atomic::Ordering::Relaxed)
}

/// Evidence that is best-effort: a store that is down must not turn a pass
/// into an error, it only means the output is not kept.
pub fn evidence_or_skip(store: &dyn ResultStore, name: &str, bytes: &[u8]) -> Vec<Evidence> {
    match evidence(store, name, bytes) {
        Ok(e) => vec![e],
        Err(e) => {
            store_warning(format!("{e:#}"));
            Vec::new()
        }
    }
}

/// The clean environment of §3.4 for one node: allow-listed ambient
/// variables, fixed values, a private `HOME` and `TMPDIR`, and a `PATH` that
/// holds exactly the declared tools.
#[derive(Clone, Debug, Default)]
pub struct CleanEnv {
    /// Allow-list and fixed values.
    pub contract: EnvContract,
    /// Declared tools: name and the resolved binary.
    pub tools: Vec<(String, PathBuf)>,
}

impl CleanEnv {
    /// Creates the node's private directories under `work` and returns the
    /// complete environment.
    ///
    /// `PATH` is a directory of symlinks to the declared tools, not their
    /// parent directories: a tool such as `nu` lives next to hundreds of
    /// programs whose content is not in the key, and exposing the directory
    /// would expose them all.
    pub fn build(&self, work: &Path, id: &NodeId) -> Result<BTreeMap<String, String>> {
        let dir = work.join(sanitize(id.as_str()));
        let (home, tmp, bin) = (dir.join("home"), dir.join("tmp"), dir.join("bin"));
        let _ = std::fs::remove_dir_all(&bin);
        for d in [&home, &tmp, &bin] {
            std::fs::create_dir_all(d).with_context(|| {
                format!(
                    "cannot create {} for {id}; check the work directory is writable",
                    d.display()
                )
            })?;
        }
        for (name, target) in &self.tools {
            std::os::unix::fs::symlink(target, bin.join(name)).with_context(|| {
                format!(
                    "cannot link tool `{name}` ({}) into the PATH directory of {id}",
                    target.display()
                )
            })?;
        }
        let ambient: HashMap<String, String> = std::env::vars().collect();
        Ok(clean_environment(
            &self.contract,
            &ambient,
            &bin.to_string_lossy(),
            &home,
            &tmp,
        ))
    }
}

/// A node id as one safe path component.
pub fn sanitize(id: &str) -> String {
    id.chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.') {
                c
            } else {
                '_'
            }
        })
        .collect()
}

//! The package graph the build uses: every package whose manifest lies under the repository root,
//! workspace member or not, with its resolved dependency edges.
//!
//! A product's build compiles more than its workspace members. A crate reached by a `path`
//! dependency or a `[patch]` entry is compiled into the product, and a change in it changes what
//! depends on it; read as `cargo metadata --no-deps` it is invisible, and its files look like
//! they belong to nothing. So the graph is read as `cargo metadata --offline --locked` (resolved,
//! from `Cargo.lock`, no network, no write), and every package under the root is kept with the
//! edges among them. Registry sources are never read: a package outside the root is an edge
//! target we do not keep.
//!
//! The resolved read takes about two seconds on a large workspace, so its result is cached by the
//! hash of `Cargo.lock` and every tracked `Cargo.toml`. When it cannot be done (no lock, a lock
//! that needs updating, sources not in the local cache) the members alone are read with
//! `--no-deps`, and `Workspace::note` says why.

use crate::error::IndexError;
use crate::{Package, Target};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeSet, HashMap};
use std::path::{Path, PathBuf};
use std::process::Command;

/// Bump when the shape of what is cached changes.
const GRAPH_VERSION: u32 = 1;

#[derive(Deserialize)]
struct Meta {
    packages: Vec<MPkg>,
    #[serde(default)]
    workspace_members: Vec<String>,
    #[serde(default)]
    resolve: Option<MResolve>,
}
#[derive(Deserialize)]
struct MPkg {
    id: String,
    name: String,
    manifest_path: String,
    targets: Vec<MTarget>,
    #[serde(default)]
    dependencies: Vec<MDep>,
}
#[derive(Deserialize)]
struct MTarget {
    name: String,
    kind: Vec<String>,
    src_path: String,
}
#[derive(Deserialize)]
struct MDep {
    name: String,
    /// null = normal, "dev" or "build".
    kind: Option<String>,
}
#[derive(Deserialize)]
struct MResolve {
    nodes: Vec<MNode>,
}
#[derive(Deserialize)]
struct MNode {
    id: String,
    #[serde(default)]
    deps: Vec<MNodeDep>,
}
#[derive(Deserialize)]
struct MNodeDep {
    pkg: String,
    #[serde(default)]
    dep_kinds: Vec<MDepKind>,
}
#[derive(Deserialize)]
struct MDepKind {
    kind: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Workspace {
    pub packages: Vec<Package>,
    /// Target roots from the manifests, keyed by repo-relative path.
    pub roots: HashMap<String, Target>,
    /// Why the resolved graph was not used, when it was not.
    pub note: Option<String>,
}

fn run_metadata(root: &Path, extra: &[&str]) -> Result<Vec<u8>, IndexError> {
    let mut args = vec!["metadata", "--format-version", "1", "--offline"];
    args.extend_from_slice(extra);
    let mut last_err = String::new();
    // `cargo-stock` bypasses the caching shim that `cargo` can be on CI hosts;
    // fall back to plain `cargo` where it does not exist.
    for exe in ["cargo-stock", "cargo"] {
        match Command::new(exe).args(&args).current_dir(root).env("RUSTC_WRAPPER", "").output() {
            Ok(out) if out.status.success() => return Ok(out.stdout),
            Ok(out) => {
                return Err(IndexError::Metadata {
                    dir: root.to_path_buf(),
                    detail: format!(
                        "`{exe} {}` exited with {}: {}",
                        args.join(" "),
                        out.status,
                        String::from_utf8_lossy(&out.stderr).trim()
                    ),
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                last_err = format!("`{exe}` is not on PATH");
            }
            Err(e) => {
                return Err(IndexError::Metadata { dir: root.to_path_buf(), detail: format!("cannot run `{exe}`: {e}") });
            }
        }
    }
    Err(IndexError::Metadata {
        dir: root.to_path_buf(),
        detail: format!("neither cargo-stock nor cargo could be run ({last_err})"),
    })
}

/// The hash a cached graph is keyed by: `Cargo.lock` and every tracked manifest.
fn graph_key(root: &Path) -> Option<String> {
    let out = crate::git::run(root, &["ls-files", "-z", "--", "Cargo.lock", "*Cargo.toml"]).ok()?;
    let mut paths: Vec<String> = out
        .stdout
        .split(|b| *b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    paths.sort();
    let mut h = blake3::Hasher::new();
    h.update(&GRAPH_VERSION.to_le_bytes());
    for p in &paths {
        h.update(p.as_bytes());
        h.update(&[0]);
        h.update(&std::fs::read(root.join(p)).ok()?);
        h.update(&[0]);
    }
    Some(h.finalize().to_hex().to_string())
}

fn cache_file(dir: &Path, key: &str) -> PathBuf {
    dir.join(format!("workspace-{}.json", &key[..32]))
}

/// The package graph of `root`. With `cache_dir`, a resolved graph is reused while `Cargo.lock`
/// and the manifests are unchanged.
pub fn load(root: &Path, cache_dir: Option<&Path>) -> Result<Workspace, IndexError> {
    let key = cache_dir.and_then(|_| graph_key(root));
    if let (Some(dir), Some(key)) = (cache_dir, &key)
        && let Some(ws) = std::fs::read(cache_file(dir, key)).ok().and_then(|b| serde_json::from_slice::<Workspace>(&b).ok())
    {
        return Ok(ws);
    }
    let (raw, resolved_note) = match run_metadata(root, &["--locked"]) {
        Ok(raw) => (raw, None),
        Err(IndexError::Metadata { detail, .. }) => {
            let raw = run_metadata(root, &["--no-deps"])?;
            let first = detail.lines().next().unwrap_or("").chars().take(300).collect::<String>();
            (
                raw,
                Some(format!(
                    "the resolved package graph is not available ({first}), so only workspace members are packages here; \
                     crates reached by path or patch dependencies look like they are in no package. \
                     Make `cargo metadata --offline --locked` succeed (a current Cargo.lock, sources in the local cache)"
                )),
            )
        }
        Err(e) => return Err(e),
    };
    let ws = parse(root, &raw, resolved_note)?;
    if let (Some(dir), Some(key), None) = (cache_dir, &key, &ws.note) {
        // Best effort, like the file-scan cache: failing to write costs time, not correctness.
        let _ = std::fs::create_dir_all(dir);
        if let Ok(json) = serde_json::to_vec(&ws) {
            let path = cache_file(dir, key);
            let tmp = path.with_extension(format!("tmp.{}", std::process::id()));
            if std::fs::write(&tmp, json).is_ok() && std::fs::rename(&tmp, &path).is_err() {
                let _ = std::fs::remove_file(&tmp);
            }
        }
    }
    Ok(ws)
}

fn parse(root: &Path, raw: &[u8], note: Option<String>) -> Result<Workspace, IndexError> {
    let meta: Meta = serde_json::from_slice(raw).map_err(|e| IndexError::Metadata {
        dir: root.to_path_buf(),
        detail: format!("unreadable metadata JSON: {e}"),
    })?;
    // Paths in metadata are absolute and may go through symlinks that `root`
    // does not (macOS /tmp -> /private/tmp), so compare canonical forms.
    let canon_root = root.canonicalize().map_err(|e| crate::error::io(root, e))?;
    let rel = |abs: &str| -> Option<String> {
        let p = Path::new(abs);
        let p = p.canonicalize().unwrap_or_else(|_| p.to_path_buf());
        let r = p.strip_prefix(&canon_root).ok()?;
        Some(r.to_string_lossy().replace('\\', "/"))
    };

    // Every package whose manifest is under the root, member or not. The rest (registry crates,
    // path crates outside the checkout) are not ours to index.
    let mut kept: Vec<(&MPkg, String)> = meta
        .packages
        .iter()
        .filter_map(|p| {
            let manifest_dir = Path::new(&p.manifest_path).parent()?.to_str()?.to_owned();
            rel(&manifest_dir).map(|d| (p, d))
        })
        .collect();
    kept.sort_by(|a, b| a.1.cmp(&b.1).then(a.0.name.cmp(&b.0.name)));
    let by_id: HashMap<&str, u32> = kept.iter().enumerate().map(|(i, (p, _))| (p.id.as_str(), i as u32)).collect();
    let by_name: HashMap<&str, u32> = kept.iter().enumerate().map(|(i, (p, _))| (p.name.as_str(), i as u32)).collect();
    let members: BTreeSet<&str> = meta.workspace_members.iter().map(String::as_str).collect();

    // Edges: (from, to, dev-only). Resolved when the metadata has a resolve section, else by the
    // names declared in each member's manifest.
    let mut edges: Vec<BTreeSet<(u32, bool)>> = vec![BTreeSet::new(); kept.len()];
    match &meta.resolve {
        Some(resolve) => {
            for n in &resolve.nodes {
                let Some(&from) = by_id.get(n.id.as_str()) else { continue };
                for d in &n.deps {
                    let Some(&to) = by_id.get(d.pkg.as_str()) else { continue };
                    if to == from {
                        continue; // a dev-dependency on itself (feature-forcing idiom)
                    }
                    let dev = !d.dep_kinds.is_empty() && d.dep_kinds.iter().all(|k| k.kind.as_deref() == Some("dev"));
                    edges[from as usize].insert((to, dev));
                }
            }
        }
        None => {
            for (i, (p, _)) in kept.iter().enumerate() {
                for d in &p.dependencies {
                    let Some(&to) = by_name.get(d.name.as_str()) else { continue };
                    if to as usize != i {
                        edges[i].insert((to, d.kind.as_deref() == Some("dev")));
                    }
                }
            }
        }
    }

    let mut packages = Vec::with_capacity(kept.len());
    let mut roots = HashMap::new();
    // Normal and build edges per package, for `dev_only_deps` once all are known.
    let mut non_dev_all: Vec<BTreeSet<u32>> = Vec::new();
    for (idx, (p, dir)) in kept.iter().enumerate() {
        let mut all = BTreeSet::new();
        let mut non_dev = BTreeSet::new();
        for &(to, dev) in &edges[idx] {
            all.insert(to);
            if !dev {
                // A dependency listed both ways is a normal one.
                non_dev.insert(to);
            }
        }
        packages.push(Package {
            name: p.name.clone(),
            dir: dir.clone(),
            deps: all.iter().copied().collect(),
            dev_only_deps: Vec::new(),
            member: members.contains(p.id.as_str()),
        });
        non_dev_all.push(non_dev);

        for t in &p.targets {
            let Some(path) = rel(&t.src_path) else { continue };
            let kind = t.kind.first().map(String::as_str).unwrap_or("");
            let target = match kind {
                "bin" => Target::Bin,
                "test" => Target::IntegrationTest(t.name.clone()),
                "bench" => Target::Bench,
                "example" => Target::Example,
                "custom-build" => Target::BuildScript,
                _ => Target::Lib, // lib, rlib, dylib, cdylib, staticlib, proc-macro
            };
            roots.insert(path, target);
        }
    }

    // A direct dependency is dev-only when it is not reachable from the
    // package through normal/build edges at any depth (dev edges of
    // dependencies never apply to someone else's build).
    for i in 0..packages.len() {
        let mut seen = BTreeSet::new();
        let mut stack: Vec<u32> = non_dev_all[i].iter().copied().collect();
        while let Some(n) = stack.pop() {
            if seen.insert(n) {
                stack.extend(non_dev_all[n as usize].iter().copied());
            }
        }
        packages[i].dev_only_deps = packages[i].deps.iter().copied().filter(|d| !seen.contains(d)).collect();
    }
    Ok(Workspace { packages, roots, note })
}

/// Target kind from a package-relative path when the manifests do not name the
/// file as a target root.
pub fn convention_target(rel_to_pkg: &str) -> Target {
    let parts: Vec<&str> = rel_to_pkg.split('/').collect();
    match parts.as_slice() {
        ["build.rs"] => Target::BuildScript,
        ["src", "main.rs"] => Target::Bin,
        ["src", "bin", ..] => Target::Bin,
        ["src", ..] => Target::Lib,
        ["tests", f] => Target::IntegrationTest(f.trim_end_matches(".rs").to_owned()),
        ["tests", dir, ..] => Target::IntegrationTest((*dir).to_owned()),
        ["benches", ..] => Target::Bench,
        ["examples", ..] => Target::Example,
        _ => Target::Other,
    }
}

/// Whether `rel_to_pkg` is the root file of a target by convention: the place
/// `mod x;` is resolved relative to the file's own directory rather than a
/// directory named after it.
pub fn conventional_root(rel_to_pkg: &str) -> bool {
    let parts: Vec<&str> = rel_to_pkg.split('/').collect();
    matches!(
        parts.as_slice(),
        ["build.rs"]
            | ["src", "lib.rs"]
            | ["src", "main.rs"]
            | ["src", "bin", _]
            | ["src", "bin", _, "main.rs"]
            | ["tests", _]
            | ["tests", _, "main.rs"]
            | ["benches", _]
            | ["benches", _, "main.rs"]
            | ["examples", _]
            | ["examples", _, "main.rs"]
    )
}

/// Module path of a file inside its crate, from its location (`src/a/mod.rs`
/// and `src/a.rs` are both `a`). Crate roots are the empty path. `#[path]`
/// attributes are not followed: test ids are an approximation of nextest's.
pub fn module_prefix(rel_to_pkg: &str) -> Vec<String> {
    let parts: Vec<&str> = rel_to_pkg.split('/').collect();
    let rest: &[&str] = match parts.as_slice() {
        ["src", "bin", _] => return Vec::new(),
        ["src", "bin", _, rest @ ..] => rest,
        ["src", rest @ ..] => rest,
        [d @ ("tests" | "benches" | "examples"), _] => {
            let _ = d;
            return Vec::new();
        }
        [_, _, rest @ ..] if matches!(parts[0], "tests" | "benches" | "examples") => rest,
        all => all,
    };
    let mut segs: Vec<String> = rest.iter().map(|s| (*s).to_owned()).collect();
    if let Some(last) = segs.last_mut() {
        *last = last.trim_end_matches(".rs").to_owned();
    }
    match segs.last().map(String::as_str) {
        Some("mod") => {
            segs.pop();
        }
        Some("lib" | "main") if segs.len() == 1 => segs.clear(),
        _ => {}
    }
    segs
}

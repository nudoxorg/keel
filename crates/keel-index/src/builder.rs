//! `CodeIndex::build`: list tracked files, scan them in parallel (through the
//! content-hash cache), then resolve everything that needs more than one file
//! at a time: owning package, target kind, and test-ness inherited through
//! `mod x;` declarations.

use crate::error::IndexError;
use crate::packages::{self, Workspace};
use crate::parse::{self, FileScan, ModDecl, SCAN_VERSION};
use crate::{CodeIndex, Item, SourceFile, Target, git};
use rayon::prelude::*;
use std::collections::{HashMap, VecDeque};
use std::path::{Path, PathBuf};

pub fn build(root: &Path, cache_dir: Option<&Path>) -> Result<CodeIndex, IndexError> {
    let t0 = std::time::Instant::now();
    // KEEL_INDEX_TRACE=1 prints phase timings to stderr; it exists because the
    // cold/warm gap is the first thing anyone asks about.
    let trace = |what: &str| {
        if std::env::var_os("KEEL_INDEX_TRACE").is_some() {
            eprintln!("keel-index: {what} at {} ms", t0.elapsed().as_millis());
        }
    };
    let tracked = git::ls_rs_files(root)?;
    trace("git ls-files");
    let ws = packages::load(root, cache_dir)?;
    trace("cargo metadata");

    // A dedicated pool: deeply nested expressions recurse deeply in syn, and
    // rayon's default worker stack is small enough to overflow on generated
    // code. 64 MiB of address space per worker is cheap.
    let pool = rayon::ThreadPoolBuilder::new()
        .stack_size(64 << 20)
        .build()
        .map_err(|e| IndexError::Pool(e.to_string()))?;
    let scanned: Vec<([u8; 32], FileScan)> = pool.install(|| {
        tracked
            .par_iter()
            .map(|rel| load_one(root, rel, cache_dir))
            .collect()
    });

    let Workspace { packages, roots, note: graph_note } = ws;
    let pkg_by_dir: HashMap<&str, u32> = packages
        .iter()
        .enumerate()
        .map(|(i, p)| (p.dir.as_str(), i as u32))
        .collect();

    let mut files: Vec<SourceFile> = Vec::with_capacity(tracked.len());
    for (path, (content, scan)) in tracked.iter().zip(&scanned) {
        let package = owning_package(path, &pkg_by_dir);
        let rel_pkg = package.map_or(path.as_str(), |p| {
            strip_dir(path, &packages[p as usize].dir)
        });
        let target = roots
            .get(path)
            .cloned()
            .unwrap_or_else(|| packages::convention_target(rel_pkg));
        files.push(SourceFile {
            path: path.clone(),
            package,
            target,
            content: *content,
            parse_error: scan.parse_error.clone(),
        });
    }

    let index_of: HashMap<&str, u32> = tracked
        .iter()
        .enumerate()
        .map(|(i, p)| (p.as_str(), i as u32))
        .collect();

    // children[f] = (child file, declared under #[cfg(test)])
    let mut children: Vec<Vec<(u32, bool)>> = vec![Vec::new(); files.len()];
    let mut is_root = vec![false; files.len()];
    for (i, f) in files.iter().enumerate() {
        let rel_pkg = f.package.map_or(f.path.as_str(), |p| {
            strip_dir(&f.path, &packages[p as usize].dir)
        });
        is_root[i] = roots.contains_key(&f.path) || packages::conventional_root(rel_pkg);
        for d in &scanned[i].1.mods {
            if let Some(c) = resolve_child(&f.path, is_root[i], d, &index_of) {
                children[i].push((c, d.cfg_test));
            }
        }
    }

    // Target kind flows from a root file down to the modules it declares: a
    // `src/foo.rs` under a package whose only target is a binary is not a lib file.
    let mut visited = vec![false; files.len()];
    for r in 0..files.len() {
        if !is_root[r] || visited[r] {
            continue;
        }
        visited[r] = true;
        let target = files[r].target.clone();
        let mut queue = VecDeque::from([r as u32]);
        while let Some(f) = queue.pop_front() {
            for &(c, _) in &children[f as usize] {
                let c = c as usize;
                if visited[c] || is_root[c] {
                    continue;
                }
                visited[c] = true;
                files[c].target = target.clone();
                queue.push_back(c as u32);
            }
        }
    }

    // Test files: integration-test targets, anything under a `tests/`
    // directory, `#[cfg(test)] mod x;` targets, and everything those declare.
    let mut test_file = vec![false; files.len()];
    let mut queue = VecDeque::new();
    for (i, f) in files.iter().enumerate() {
        let in_tests_dir = f.path.split('/').rev().skip(1).any(|c| c == "tests");
        if matches!(f.target, Target::IntegrationTest(_)) || in_tests_dir {
            test_file[i] = true;
            queue.push_back(i as u32);
        }
    }
    for kids in &children {
        for &(c, cfg) in kids {
            if cfg && !test_file[c as usize] {
                test_file[c as usize] = true;
                queue.push_back(c);
            }
        }
    }
    while let Some(f) = queue.pop_front() {
        for &(c, _) in &children[f as usize] {
            if !test_file[c as usize] {
                test_file[c as usize] = true;
                queue.push_back(c);
            }
        }
    }

    let mut items = Vec::new();
    for (fi, (_, scan)) in scanned.iter().enumerate() {
        for it in &scan.items {
            items.push(Item {
                file: fi as u32,
                path: it.path.clone(),
                start_line: it.start_line,
                end_line: it.end_line,
                tokens: it.tokens,
                signature: it.signature,
                branches: it.branches,
                is_test: it.is_test,
                ignored: it.ignored,
                in_test_code: it.cfg_test || test_file[fi],
            });
        }
    }

    trace("resolved");
    Ok(CodeIndex {
        root: root.to_path_buf(),
        packages,
        files,
        items,
        graph_note,
    })
}

fn strip_dir<'a>(path: &'a str, dir: &str) -> &'a str {
    if dir.is_empty() {
        path
    } else {
        path.strip_prefix(dir)
            .and_then(|r| r.strip_prefix('/'))
            .unwrap_or(path)
    }
}

/// Nearest enclosing package directory: walk the file's ancestors, deepest first.
fn owning_package(path: &str, by_dir: &HashMap<&str, u32>) -> Option<u32> {
    let mut dir = path;
    while let Some(i) = dir.rfind('/') {
        dir = &path[..i];
        if let Some(&p) = by_dir.get(dir) {
            return Some(p);
        }
    }
    by_dir.get("").copied()
}

/// Where `mod name;` declared in `parent` lives, following rustc's rules:
/// crate roots and `mod.rs` look beside themselves, other files look in a
/// directory named after themselves, and `#[path]` is relative to the
/// declaring file's directory.
fn resolve_child(
    parent: &str,
    parent_is_root: bool,
    d: &ModDecl,
    index_of: &HashMap<&str, u32>,
) -> Option<u32> {
    let (dir, file) = parent.rsplit_once('/').unwrap_or(("", parent));
    let join = |a: &str, b: &str| {
        if a.is_empty() {
            b.to_owned()
        } else {
            format!("{a}/{b}")
        }
    };
    if let Some(p) = &d.path_attr {
        let mut parts: Vec<&str> = if dir.is_empty() {
            vec![]
        } else {
            dir.split('/').collect()
        };
        for seg in p.split('/') {
            match seg {
                "." | "" => {}
                ".." => {
                    parts.pop();
                }
                s => parts.push(s),
            }
        }
        return index_of.get(parts.join("/").as_str()).copied();
    }
    let mut base = if parent_is_root || file == "mod.rs" {
        dir.to_owned()
    } else {
        join(dir, file.trim_end_matches(".rs"))
    };
    for m in &d.inline {
        base = join(&base, m);
    }
    let flat = join(&base, &format!("{}.rs", d.name));
    if let Some(&i) = index_of.get(flat.as_str()) {
        return Some(i);
    }
    index_of
        .get(join(&join(&base, &d.name), "mod.rs").as_str())
        .copied()
}

fn load_one(root: &Path, rel: &str, cache_dir: Option<&Path>) -> ([u8; 32], FileScan) {
    let bytes = match std::fs::read(root.join(rel)) {
        Ok(b) => b,
        Err(e) => {
            return (
                [0; 32],
                FileScan {
                    version: SCAN_VERSION,
                    parse_error: Some(format!(
                        "cannot read the file: {e} (tracked by git but absent or unreadable in the working tree; restore it or `git rm` it)"
                    )),
                    items: Vec::new(),
                    mods: Vec::new(),
                    outside: [0; 32],
                },
            );
        }
    };
    let hash = *blake3::hash(&bytes).as_bytes();
    if let Some(s) = cache_dir.and_then(|dir| cache_get(dir, &hash)) {
        return (hash, s);
    }
    let scan = parse::scan_bytes(&bytes);
    if let Some(dir) = cache_dir {
        cache_put(dir, &hash, &scan);
    }
    (hash, scan)
}

fn cache_path(dir: &Path, hash: &[u8; 32]) -> PathBuf {
    let hex = crate::hex32::to_hex(hash);
    dir.join(&hex[..2]).join(format!("{hex}.json"))
}

fn cache_get(dir: &Path, hash: &[u8; 32]) -> Option<FileScan> {
    let bytes = std::fs::read(cache_path(dir, hash)).ok()?;
    let scan: FileScan = serde_json::from_slice(&bytes).ok()?;
    (scan.version == SCAN_VERSION).then_some(scan)
}

/// Best effort: a cache that cannot be written costs time, never correctness,
/// so failures are swallowed. Temp name + rename keeps readers from ever
/// seeing a half-written entry, including across concurrent builds.
fn cache_put(dir: &Path, hash: &[u8; 32], scan: &FileScan) {
    let path = cache_path(dir, hash);
    let Some(parent) = path.parent() else { return };
    if std::fs::create_dir_all(parent).is_err() {
        return;
    }
    let Ok(json) = serde_json::to_vec(scan) else {
        return;
    };
    let tmp = path.with_extension(format!(
        "tmp.{}.{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    if std::fs::write(&tmp, json).is_ok() && std::fs::rename(&tmp, &path).is_err() {
        let _ = std::fs::remove_file(&tmp);
    }
}

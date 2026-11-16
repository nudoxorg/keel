//! `diff`: what a pair of git revisions changed, at function granularity.
//!
//! Nothing is checked out. Blob ids come from `git diff --raw`, the blobs
//! from one long-lived `git cat-file --batch` (a process per file would cost
//! seconds on a commit touching hundreds of files), and both sides of each
//! `.rs` file are scanned with the same scanner the index uses.

use crate::error::IndexError;
use crate::git;
use crate::parse::{self, FileScan, RawItem};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::Path;
use std::process::{Command, Stdio};

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Change {
    pub files: Vec<FileChange>,
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct FileChange {
    pub path: String,
    pub status: FileStatus,
    /// Only for `.rs` files that parse on every side that exists.
    pub items: Vec<ItemChange>,
    /// Something other than a fn body or signature changed (`use`, const,
    /// static, struct, macro, attribute, mod). Also true when the file is not
    /// Rust or does not parse, because nothing smaller can be claimed.
    pub outside_items: bool,
    /// The file changed but no fn's token hash did and nothing outside fns
    /// changed token-wise: whitespace and ordinary comments only. Never set for a rename or a
    /// deletion: a file that moves is gone from one path and new at another, whatever its tokens.
    pub position_only: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Added,
    Deleted,
    Modified,
    Renamed { from: String },
}

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct ItemChange {
    pub path: String,
    pub kind: ItemChangeKind,
    pub branches: u32,
    /// Changed lines inside the item: the larger of removed lines (old side)
    /// and added lines (new side) that fall within its line range, from
    /// `git diff -U0`. For Added/Removed, the item's whole length. If no hunk
    /// overlaps (a diff the hunks cannot attribute, such as a pure move),
    /// `|length difference| + 1`.
    pub lines_changed: u32,
    pub is_test: bool,
}

#[derive(Serialize, Deserialize, Debug, Clone, Copy, PartialEq, Eq)]
pub enum ItemChangeKind {
    Added,
    Removed,
    Body,
    /// Wins over Body when both changed.
    Signature,
}

#[derive(Clone, Copy)]
struct Hunk {
    old_start: u32,
    old_len: u32,
    new_start: u32,
    new_len: u32,
}

/// A changed path with the bytes of its old and new blobs, where it has them.
type Job = (RawEntry, Option<Vec<u8>>, Option<Vec<u8>>);

struct RawEntry {
    old_oid: String,
    new_oid: String,
    new_mode: String,
    old_mode: String,
    path: String,
    status: FileStatus,
}

const ZERO_OID_CHAR: char = '0';

pub fn diff(root: &Path, base: &str, head: &str) -> Result<Change, IndexError> {
    let raw = git::run(
        root,
        &[
            "diff",
            "--raw",
            "-z",
            "--no-abbrev",
            "-M",
            "--no-ext-diff",
            base,
            head,
        ],
    )?;
    let entries = parse_raw(&raw.stdout);

    let patch = git::run(
        root,
        &[
            "-c",
            "core.quotepath=off",
            "diff",
            "-U0",
            "-M",
            "--no-color",
            "--no-ext-diff",
            "--no-textconv",
            "--src-prefix=a/",
            "--dst-prefix=b/",
            base,
            head,
            "--",
            "*.rs",
        ],
    )?;
    let hunks = parse_hunks(&String::from_utf8_lossy(&patch.stdout));

    // Fetch sequentially (one pipe), scan in parallel.
    let mut blobs = Blobs::open(root)?;
    let mut jobs: Vec<Job> = Vec::with_capacity(entries.len());
    for e in entries {
        let is_rs = e.path.ends_with(".rs");
        let blob_ok = |mode: &str| mode.starts_with("100"); // regular files; not symlinks or gitlinks
        let old = (is_rs && e.status != FileStatus::Added && blob_ok(&e.old_mode))
            .then(|| blobs.get(&e.old_oid))
            .transpose()?
            .flatten();
        let new = (is_rs && e.status != FileStatus::Deleted && blob_ok(&e.new_mode))
            .then(|| blobs.get(&e.new_oid))
            .transpose()?
            .flatten();
        jobs.push((e, old, new));
    }
    drop(blobs);

    let empty_outside = parse::scan_source("").outside;
    let files: Vec<FileChange> = jobs
        .into_par_iter()
        .map(|(e, old, new)| classify(e, old, new, &hunks, empty_outside))
        .collect();
    Ok(Change { files })
}

fn classify(
    e: RawEntry,
    old: Option<Vec<u8>>,
    new: Option<Vec<u8>>,
    hunks: &HashMap<String, Vec<Hunk>>,
    empty_outside: [u8; 32],
) -> FileChange {
    let opaque = |e: RawEntry| FileChange {
        path: e.path,
        status: e.status,
        items: Vec::new(),
        outside_items: true,
        position_only: false,
    };
    if !e.path.ends_with(".rs") {
        return opaque(e);
    }
    let old_scan = old.as_deref().map(parse::scan_bytes);
    let new_scan = new.as_deref().map(parse::scan_bytes);
    // A side that should exist but has no blob (symlink, submodule) or does
    // not parse makes any per-item claim unsound.
    let need_old = e.status != FileStatus::Added;
    let need_new = e.status != FileStatus::Deleted;
    let bad = |s: &Option<FileScan>, need: bool| match s {
        Some(s) => s.parse_error.is_some(),
        None => need,
    };
    if bad(&old_scan, need_old) || bad(&new_scan, need_new) {
        return opaque(e);
    }
    let old_items: &[RawItem] = old_scan.as_ref().map_or(&[], |s| &s.items);
    let new_items: &[RawItem] = new_scan.as_ref().map_or(&[], |s| &s.items);
    let old_outside = old_scan.as_ref().map_or(empty_outside, |s| s.outside);
    let new_outside = new_scan.as_ref().map_or(empty_outside, |s| s.outside);

    let file_hunks = hunks.get(&e.path).map(Vec::as_slice).unwrap_or(&[]);
    let mut items = Vec::new();

    // Paths repeat (cfg-gated twins, `impl` blocks of the same trait for
    // different generics), so match the nth occurrence to the nth occurrence.
    let mut old_by_path: HashMap<&str, Vec<&RawItem>> = HashMap::new();
    for it in old_items {
        old_by_path.entry(it.path.as_str()).or_default().push(it);
    }
    let mut seen: HashMap<&str, usize> = HashMap::new();
    for new_it in new_items {
        let n = seen.entry(new_it.path.as_str()).or_insert(0);
        let old_it = old_by_path
            .get(new_it.path.as_str())
            .and_then(|v| v.get(*n))
            .copied();
        *n += 1;
        let len = new_it.end_line - new_it.start_line + 1;
        match old_it {
            None => items.push(ItemChange {
                path: new_it.path.clone(),
                kind: ItemChangeKind::Added,
                branches: new_it.branches,
                lines_changed: len,
                is_test: new_it.is_test,
            }),
            Some(o) if o.tokens != new_it.tokens => {
                let kind = if o.signature != new_it.signature {
                    ItemChangeKind::Signature
                } else {
                    ItemChangeKind::Body
                };
                items.push(ItemChange {
                    path: new_it.path.clone(),
                    kind,
                    branches: new_it.branches,
                    lines_changed: lines_changed(o, new_it, file_hunks),
                    is_test: new_it.is_test || o.is_test,
                });
            }
            Some(_) => {}
        }
    }
    let mut consumed: HashMap<&str, usize> = HashMap::new();
    let mut new_count: HashMap<&str, usize> = HashMap::new();
    for it in new_items {
        *new_count.entry(it.path.as_str()).or_insert(0) += 1;
    }
    for old_it in old_items {
        let n = consumed.entry(old_it.path.as_str()).or_insert(0);
        let survives = *n < new_count.get(old_it.path.as_str()).copied().unwrap_or(0);
        *n += 1;
        if !survives {
            items.push(ItemChange {
                path: old_it.path.clone(),
                kind: ItemChangeKind::Removed,
                branches: old_it.branches,
                lines_changed: old_it.end_line - old_it.start_line + 1,
                is_test: old_it.is_test,
            });
        }
    }

    let outside_items = old_outside != new_outside;
    // A rename is a deletion at the old path and an addition at the new one: the package and owner
    // of each may differ, and the tests of the file leave one place and appear in another.
    let position_only = e.status == FileStatus::Modified && items.is_empty() && !outside_items;
    FileChange {
        path: e.path,
        status: e.status,
        items,
        outside_items,
        position_only,
    }
}

fn overlap(start: u32, len: u32, lo: u32, hi: u32) -> u32 {
    if len == 0 {
        return 0;
    }
    let end = start + len - 1;
    let (a, b) = (start.max(lo), end.min(hi));
    if a <= b { b - a + 1 } else { 0 }
}

fn lines_changed(old: &RawItem, new: &RawItem, hunks: &[Hunk]) -> u32 {
    let (mut removed, mut added) = (0, 0);
    for h in hunks {
        removed += overlap(h.old_start, h.old_len, old.start_line, old.end_line);
        added += overlap(h.new_start, h.new_len, new.start_line, new.end_line);
    }
    match removed.max(added) {
        0 => {
            let (a, b) = (old.end_line - old.start_line, new.end_line - new.start_line);
            a.abs_diff(b) + 1
        }
        n => n,
    }
}

/// `:100644 100644 <oid> <oid> M\0path\0` and, for renames, `R100\0old\0new\0`.
fn parse_raw(out: &[u8]) -> Vec<RawEntry> {
    let mut fields = out
        .split(|b| *b == 0)
        .map(|s| String::from_utf8_lossy(s).into_owned());
    let mut entries = Vec::new();
    while let Some(meta) = fields.next() {
        let Some(meta) = meta.strip_prefix(':') else {
            continue;
        };
        let m: Vec<&str> = meta.split(' ').collect();
        if m.len() < 5 {
            continue;
        }
        let code = m[4];
        let Some(first) = fields.next() else { break };
        let (path, status) = match code.chars().next() {
            Some('A') => (first, FileStatus::Added),
            Some('D') => (first, FileStatus::Deleted),
            Some('R') | Some('C') => {
                let Some(second) = fields.next() else { break };
                (second, FileStatus::Renamed { from: first })
            }
            _ => (first, FileStatus::Modified),
        };
        entries.push(RawEntry {
            old_mode: m[0].to_owned(),
            new_mode: m[1].to_owned(),
            old_oid: m[2].to_owned(),
            new_oid: m[3].to_owned(),
            path,
            status,
        });
    }
    entries
}

/// Hunk ranges per new-side path (old-side path for deletions). The header's
/// line counts drive the parse, because a removed source line starting with
/// `-- ` looks exactly like a `--- a/file` header.
fn parse_hunks(patch: &str) -> HashMap<String, Vec<Hunk>> {
    let mut out: HashMap<String, Vec<Hunk>> = HashMap::new();
    let mut old_path = String::new();
    let mut key: Option<String> = None;
    let mut lines = patch.lines();
    while let Some(line) = lines.next() {
        if let Some(p) = line.strip_prefix("--- ") {
            old_path = p.strip_prefix("a/").unwrap_or(p).to_owned();
        } else if let Some(p) = line.strip_prefix("+++ ") {
            key = Some(match p.strip_prefix("b/") {
                Some(n) => n.to_owned(),
                None => old_path.clone(), // +++ /dev/null: a deletion
            });
        } else if let Some(h) = line.strip_prefix("@@ ") {
            let Some(h) = parse_hunk_header(h) else {
                continue;
            };
            if let Some(k) = &key {
                out.entry(k.clone()).or_default().push(h);
            }
            let mut remaining = h.old_len + h.new_len;
            while remaining > 0 {
                match lines.next() {
                    Some(l) if l.starts_with('\\') => {}
                    Some(_) => remaining -= 1,
                    None => break,
                }
            }
        }
    }
    out
}

fn parse_hunk_header(h: &str) -> Option<Hunk> {
    // "-12,3 +14,2 @@ context"
    let mut parts = h.split(' ');
    let range = |s: &str, sign: char| -> Option<(u32, u32)> {
        let s = s.strip_prefix(sign)?;
        match s.split_once(',') {
            Some((a, b)) => Some((a.parse().ok()?, b.parse().ok()?)),
            None => Some((s.parse().ok()?, 1)),
        }
    };
    let (old_start, old_len) = range(parts.next()?, '-')?;
    let (new_start, new_len) = range(parts.next()?, '+')?;
    Some(Hunk {
        old_start,
        old_len,
        new_start,
        new_len,
    })
}

/// A single `git cat-file --batch` process: request an object id, read
/// `<oid> <type> <size>\n<bytes>\n`.
struct Blobs {
    child: std::process::Child,
    stdin: std::process::ChildStdin,
    out: BufReader<std::process::ChildStdout>,
}

impl Blobs {
    fn open(root: &Path) -> Result<Blobs, IndexError> {
        let mut child = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["cat-file", "--batch"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()
            .map_err(|source| IndexError::Spawn {
                command: "git cat-file --batch".into(),
                dir: root.to_path_buf(),
                source,
            })?;
        let stdin = child.stdin.take().expect("stdin was piped");
        let out = BufReader::new(child.stdout.take().expect("stdout was piped"));
        Ok(Blobs { child, stdin, out })
    }

    /// `None` for the zero oid or an object git does not have.
    fn get(&mut self, oid: &str) -> Result<Option<Vec<u8>>, IndexError> {
        if oid.chars().all(|c| c == ZERO_OID_CHAR) {
            return Ok(None);
        }
        let ioerr = |source| IndexError::Spawn {
            command: "git cat-file --batch".into(),
            dir: std::path::PathBuf::new(),
            source,
        };
        writeln!(self.stdin, "{oid}").map_err(ioerr)?;
        self.stdin.flush().map_err(ioerr)?;
        let mut header = String::new();
        self.out.read_line(&mut header).map_err(ioerr)?;
        let f: Vec<&str> = header.split_whitespace().collect();
        if f.len() != 3 || f[1] != "blob" {
            return Ok(None); // "<oid> missing", or a non-blob
        }
        let size: usize = f[2].parse().unwrap_or(0);
        let mut buf = vec![0u8; size + 1]; // content plus the trailing newline
        self.out.read_exact(&mut buf).map_err(ioerr)?;
        buf.truncate(size);
        Ok(Some(buf))
    }
}

impl Drop for Blobs {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

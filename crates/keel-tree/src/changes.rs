//! Facts about a change that the function-level diff of `keel-index` does not carry
//! and `plan` needs to stay sound:
//!
//! * which lines changed, for files whose ownership is by range (`code` patterns);
//! * which tests a deleted or renamed file took with it.

use crate::resolve::Resolution;
use keel_index::{Change, FileStatus};
use std::collections::{BTreeSet, HashMap};
use std::path::Path;
use std::process::Command;

#[derive(Debug, Clone, Default, serde::Serialize)]
pub struct Gone {
    /// The path the tests were at in the base revision.
    pub path: String,
    /// Where the file went, when it was renamed.
    pub moved_to: Option<String>,
    /// `<path>$<test>` of every test function the base revision had there.
    pub tests: Vec<String>,
}

#[derive(Debug, Clone, Default)]
pub struct Facts {
    /// Changed lines of each modified file (1-based, inclusive, new side), for the files asked about.
    pub lines: HashMap<String, Vec<(u32, u32)>>,
    /// Whether the file in the checkout is the file at `head`, so that line ranges computed on
    /// the checkout mean the same lines in the diff.
    pub checkout_is_head: HashMap<String, bool>,
    pub gone: Vec<Gone>,
}

fn git(root: &Path, args: &[&str]) -> Option<Vec<u8>> {
    let out = Command::new("git").arg("-C").arg(root).args(["-c", "core.quotepath=off"]).args(args).output().ok()?;
    out.status.success().then_some(out.stdout)
}

#[derive(Debug, Clone, Copy)]
struct Hunk {
    new: (u32, u32),
}

fn range(s: &str) -> Option<(u32, u32)> {
    let (start, len) = s.split_once(',').map_or((s, "1"), |(a, b)| (a, b));
    Some((start.parse().ok()?, len.parse().ok()?))
}

/// Hunks of `git diff -U0`, by the path on the new side (the old side for a deletion).
fn parse_hunks(patch: &str) -> HashMap<String, Vec<Hunk>> {
    let mut out: HashMap<String, Vec<Hunk>> = HashMap::new();
    let (mut old_path, mut cur) = (String::new(), String::new());
    for line in patch.lines() {
        if let Some(p) = line.strip_prefix("--- ") {
            old_path = p.strip_prefix("a/").unwrap_or(p).to_owned();
        } else if let Some(p) = line.strip_prefix("+++ ") {
            cur = if p == "/dev/null" { old_path.clone() } else { p.strip_prefix("b/").unwrap_or(p).to_owned() };
        } else if let Some(h) = line.strip_prefix("@@ -") {
            let mut it = h.split_whitespace();
            let (Some(o), Some(n)) = (it.next(), it.next()) else { continue };
            if let (Some(_), Some(new)) = (range(o), range(n.trim_start_matches('+'))) {
                out.entry(cur.clone()).or_default().push(Hunk { new });
            }
        }
    }
    out
}

impl Facts {
    /// No line facts: every claim in a changed file counts as touched.
    pub fn none() -> Facts {
        Facts::default()
    }

    pub fn gather(root: &Path, base: &str, head: &str, change: &Change, res: &Resolution<'_>) -> Facts {
        let mut f = Facts::default();
        let site_paths: BTreeSet<&str> = res.sites.iter().map(|s| s.path.as_str()).collect();
        let mut want: Vec<&str> = Vec::new();
        for c in &change.files {
            if c.status == FileStatus::Modified && site_paths.contains(c.path.as_str()) {
                want.push(&c.path);
            }
            if site_paths.contains(c.path.as_str()) && c.status != FileStatus::Deleted {
                let p = &c.path;
                let at_head = git(root, &["rev-parse", &format!("{head}:{p}")]);
                let in_tree = git(root, &["hash-object", "--", p]);
                f.checkout_is_head.insert(p.clone(), at_head.is_some() && at_head == in_tree);
            }
        }
        want.sort_unstable();
        want.dedup();
        let mut hunks: HashMap<String, Vec<Hunk>> = HashMap::new();
        for chunk in want.chunks(200) {
            let mut args = vec!["diff", "-U0", "--no-color", "--no-ext-diff", "--no-textconv", "--src-prefix=a/", "--dst-prefix=b/", base, head, "--"];
            args.extend(chunk.iter().copied());
            if let Some(out) = git(root, &args) {
                hunks.extend(parse_hunks(&String::from_utf8_lossy(&out)));
            }
        }
        for (path, hs) in &hunks {
            f.lines.insert(
                path.clone(),
                hs.iter().map(|h| (h.new.0, h.new.0 + h.new.1.max(1) - u32::from(h.new.1 > 0))).collect(),
            );
        }
        for c in &change.files {
            let (old, moved_to) = match &c.status {
                FileStatus::Deleted => (c.path.as_str(), None),
                FileStatus::Renamed { from } => (from.as_str(), Some(c.path.clone())),
                _ => continue,
            };
            if !old.ends_with(".rs") {
                continue;
            }
            let Some(blob) = git(root, &["show", &format!("{base}:{old}")]) else { continue };
            let scan = keel_index::parse::scan_bytes(&blob);
            let tests: Vec<String> = scan.items.iter().filter(|i| i.is_test).map(|i| format!("{old}${}", i.path)).collect();
            if !tests.is_empty() {
                f.gone.push(Gone { path: old.to_owned(), moved_to, tests });
            }
        }
        f
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hunks_parse_both_sides() {
        let p = "--- a/x.rs\n+++ b/x.rs\n@@ -3,2 +3 @@\n-a\n-b\n+c\n@@ -9,0 +9,2 @@\n+d\n+e\n";
        let h = parse_hunks(p);
        let v = &h["x.rs"];
        assert_eq!(v[0].new, (3, 1));
        assert_eq!(v[1].new, (9, 2));
    }
}

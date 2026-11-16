//! The `git` binary, run through `std::process::Command`. No git library: the
//! plumbing commands below are the interface git promises to keep stable, and
//! shelling out means the answer is exactly what git itself would say.

use std::collections::HashMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

use anyhow::{Context, Result, anyhow, bail};

pub struct Git {
    dir: PathBuf,
}

/// One line of `git diff-tree --raw -z`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct DiffEntry {
    /// `A`, `D`, `M`, `T` or anything else git prints.
    pub status: char,
    pub old_mode: u32,
    pub new_mode: u32,
    pub old_sha: String,
    pub new_sha: String,
    pub path: String,
    /// The path was not valid UTF-8 and `path` is lossy, so no set lookup on it
    /// can be trusted.
    pub non_utf8: bool,
}

pub enum Merge {
    Clean { tree: String },
    Conflict { files: Vec<String> },
}

impl Git {
    pub fn new(repo: &Path) -> Git {
        Git { dir: repo.into() }
    }

    fn command(&self) -> Command {
        let mut c = Command::new("git");
        c.arg("-C").arg(&self.dir);
        // A caller running inside a hook must not redirect us to another repository.
        for var in ["GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE"] {
            c.env_remove(var);
        }
        c.env("GIT_OPTIONAL_LOCKS", "0").env("LC_ALL", "C");
        c
    }

    /// Runs git and returns `(exit code, stdout)`; spawn failure is the only error.
    fn run_code(&self, args: &[&str], input: Option<&[u8]>) -> Result<(i32, Vec<u8>, String)> {
        let mut child = self
            .command()
            .args(args)
            .stdin(if input.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .context("cannot run `git`; install git 2.38 or newer and put it on PATH")?;
        // Written from a thread so a large input and a large output cannot deadlock.
        let stdin = child.stdin.take();
        let out = std::thread::scope(|s| {
            if let (Some(mut stdin), Some(bytes)) = (stdin, input) {
                s.spawn(move || {
                    let _ = stdin.write_all(bytes);
                });
            }
            child.wait_with_output()
        })?;
        Ok((
            out.status.code().unwrap_or(-1),
            out.stdout,
            String::from_utf8_lossy(&out.stderr).trim().to_owned(),
        ))
    }

    pub fn run(&self, args: &[&str]) -> Result<Vec<u8>> {
        let (code, out, err) = self.run_code(args, None)?;
        if code != 0 {
            bail!(
                "`git {}` failed in {} (exit {code}): {err}; check the repository path and that the revisions exist (`git fetch` them first)",
                args.join(" "),
                self.dir.display()
            );
        }
        Ok(out)
    }

    pub fn rev_parse_commit(&self, rev: &str) -> Result<String> {
        let spec = format!("{rev}^{{commit}}");
        let out = self
            .run(&["rev-parse", "--verify", "--end-of-options", &spec])
            .with_context(|| format!("`{rev}` is not a commit in {}", self.dir.display()))?;
        Ok(String::from_utf8_lossy(&out).trim().to_owned())
    }

    /// `git merge-tree --write-tree`: the merge result as a tree, or the
    /// conflicted paths.
    pub fn merge_tree(&self, base: &str, head: &str) -> Result<Merge> {
        let (code, out, err) = self.run_code(
            &[
                "merge-tree",
                "--write-tree",
                "--name-only",
                "-z",
                base,
                head,
            ],
            None,
        )?;
        match code {
            0 | 1 => {
                let mut parts = out.split(|&b| b == 0);
                let tree = String::from_utf8_lossy(parts.next().unwrap_or_default()).into_owned();
                if code == 0 {
                    return Ok(Merge::Clean { tree });
                }
                let files = parts
                    .take_while(|p| !p.is_empty())
                    .map(|p| String::from_utf8_lossy(p).into_owned())
                    .collect();
                Ok(Merge::Conflict { files })
            }
            _ => Err(anyhow!(
                "`git merge-tree --write-tree {base} {head}` failed (exit {code}): {err}; it needs git 2.38 or newer and two commits with a common history"
            )),
        }
    }

    /// `git diff-tree -r -z --raw --no-renames a b`.
    pub fn diff_raw(&self, a: &str, b: &str) -> Result<Vec<DiffEntry>> {
        let out = self.run(&[
            "diff-tree",
            "-r",
            "-z",
            "--raw",
            "--no-renames",
            "--no-abbrev",
            "--no-ext-diff",
            a,
            b,
        ])?;
        parse_raw(&out)
    }

    pub fn blob(&self, sha: &str) -> Result<Vec<u8>> {
        self.run(&["cat-file", "blob", sha])
    }

    /// The file at `path` in `treeish`, or `None` if it does not exist there.
    pub fn blob_at(&self, treeish: &str, path: &str) -> Result<Option<Vec<u8>>> {
        let spec = format!("{treeish}:{path}");
        let (code, out, err) = self.run_code(&["cat-file", "blob", &spec], None)?;
        match code {
            0 => Ok(Some(out)),
            128 if err.contains("does not exist") || err.contains("exists on disk, but not in") => {
                Ok(None)
            }
            _ => bail!("`git cat-file blob {spec}` failed (exit {code}): {err}"),
        }
    }

    /// Every symlink in `treeish` as `(path, blob sha)`.
    pub fn symlinks(&self, treeish: &str) -> Result<Vec<(String, String)>> {
        let out = self.run(&["ls-tree", "-r", "-z", "--full-tree", treeish])?;
        let mut v = Vec::new();
        for rec in out.split(|&b| b == 0).filter(|r| !r.is_empty()) {
            let text = String::from_utf8_lossy(rec);
            let Some((meta, path)) = text.split_once('\t') else {
                continue;
            };
            let mut f = meta.split(' ');
            if f.next() == Some("120000") {
                v.push((path.to_owned(), f.nth(1).unwrap_or_default().to_owned()));
            }
        }
        Ok(v)
    }

    /// The contents of every blob in `shas` that is at most `max` bytes, keyed
    /// by sha. Two long-lived `cat-file` processes instead of one per blob.
    pub fn small_blobs(&self, shas: &[String], max: u64) -> Result<HashMap<String, Vec<u8>>> {
        let mut input = Vec::new();
        for s in shas {
            input.extend_from_slice(s.as_bytes());
            input.push(b'\n');
        }
        let (code, out, err) = self.run_code(&["cat-file", "--batch-check"], Some(&input))?;
        if code != 0 {
            bail!("`git cat-file --batch-check` failed (exit {code}): {err}");
        }
        let small: Vec<String> = String::from_utf8_lossy(&out)
            .lines()
            .filter_map(|l| {
                let mut f = l.split(' ');
                let (sha, kind, size) = (f.next()?, f.next()?, f.next()?);
                (kind == "blob" && size.parse::<u64>().ok()? <= max).then(|| sha.to_owned())
            })
            .collect();
        let mut input = Vec::new();
        for s in &small {
            input.extend_from_slice(s.as_bytes());
            input.push(b'\n');
        }
        let (code, out, err) = self.run_code(&["cat-file", "--batch"], Some(&input))?;
        if code != 0 {
            bail!("`git cat-file --batch` failed (exit {code}): {err}");
        }
        let mut map = HashMap::new();
        let mut rest = &out[..];
        while let Some(nl) = rest.iter().position(|&b| b == b'\n') {
            let header = String::from_utf8_lossy(&rest[..nl]).into_owned();
            let mut f = header.split(' ');
            let (sha, _kind, size) = (f.next(), f.next(), f.next());
            let (Some(sha), Some(size)) = (sha, size.and_then(|s| s.parse::<usize>().ok())) else {
                break;
            };
            let body = rest.get(nl + 1..nl + 1 + size).unwrap_or_default();
            map.insert(sha.to_owned(), body.to_vec());
            rest = rest.get(nl + 2 + size..).unwrap_or_default();
        }
        Ok(map)
    }

    /// Files in `treeish` matching `pathspec` whose content matches the extended
    /// regex `pattern`.
    pub fn grep_files(&self, treeish: &str, pattern: &str, pathspec: &str) -> Result<Vec<String>> {
        let (code, out, err) = self.run_code(
            &[
                "grep", "-l", "-z", "-E", "-e", pattern, treeish, "--", pathspec,
            ],
            None,
        )?;
        match code {
            0 => Ok(out
                .split(|&b| b == 0)
                .filter(|p| !p.is_empty())
                // Each hit is printed as `<treeish>:<path>`.
                .map(|p| {
                    let s = String::from_utf8_lossy(p).into_owned();
                    s.strip_prefix(&format!("{treeish}:"))
                        .unwrap_or(&s)
                        .to_owned()
                })
                .collect()),
            1 => Ok(vec![]),
            _ => bail!("`git grep` failed (exit {code}): {err}"),
        }
    }

    /// Writes the files of `tree` under `dest` through a private index, so the
    /// repository's own index and working tree are never touched.
    pub fn checkout_tree(&self, tree: &str, dest: &Path) -> Result<()> {
        let index = dest.with_extension("index");
        let run = |args: &[&str]| -> Result<()> {
            let out = self
                .command()
                .env("GIT_INDEX_FILE", &index)
                .args(args)
                .output()
                .context("cannot run `git`")?;
            if !out.status.success() {
                bail!(
                    "`git {}` failed: {}",
                    args.join(" "),
                    String::from_utf8_lossy(&out.stderr).trim()
                );
            }
            Ok(())
        };
        std::fs::create_dir_all(dest)?;
        run(&["read-tree", tree])?;
        let prefix = format!("--prefix={}/", dest.display());
        let result = run(&["checkout-index", "-a", &prefix]);
        let _ = std::fs::remove_file(&index);
        result
    }
}

fn parse_raw(out: &[u8]) -> Result<Vec<DiffEntry>> {
    let mut v = Vec::new();
    let mut it = out.split(|&b| b == 0).filter(|p| !p.is_empty());
    while let Some(meta) = it.next() {
        let meta = String::from_utf8_lossy(meta);
        let path = it
            .next()
            .ok_or_else(|| anyhow!("`git diff-tree` output ended after `{meta}`; rerun, and if it repeats report the git version"))?;
        let mut f = meta.trim_start_matches(':').split(' ');
        let mode = |s: Option<&str>| s.and_then(|s| u32::from_str_radix(s, 8).ok());
        let (Some(om), Some(nm), Some(os), Some(ns), Some(st)) =
            (mode(f.next()), mode(f.next()), f.next(), f.next(), f.next())
        else {
            bail!(
                "cannot parse `git diff-tree` line `{meta}`; the git version may be too old or too new"
            );
        };
        let (path, non_utf8) = match std::str::from_utf8(path) {
            Ok(p) => (p.to_owned(), false),
            Err(_) => (String::from_utf8_lossy(path).into_owned(), true),
        };
        v.push(DiffEntry {
            status: st.chars().next().unwrap_or('?'),
            old_mode: om,
            new_mode: nm,
            old_sha: os.to_owned(),
            new_sha: ns.to_owned(),
            path,
            non_utf8,
        });
    }
    Ok(v)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_raw_records() {
        let z = ":100644 100755 aaaa bbbb M\0a/b.rs\0:000000 100644 0000 cccc A\0new\0";
        let v = parse_raw(z.as_bytes()).unwrap();
        assert_eq!(v.len(), 2);
        assert_eq!(
            (v[0].status, v[0].old_mode, v[0].new_mode),
            ('M', 0o100644, 0o100755)
        );
        assert_eq!(v[1].path, "new");
        assert!(parse_raw(b":100644 100644 a b M\0").is_err());
    }
}

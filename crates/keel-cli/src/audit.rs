//! `keel audit`: DESIGN §4 item 1. Run each test under `strace` and report
//! every file it reads that no declaration, and no directory the framework
//! already accounts for, covers. This turns "the test's inputs are the ones
//! declared" from an assumption into a check, and names the `inputs` line that
//! would make the declaration true.
//!
//! Linux only: `strace` and the paths it prints are Linux's. The classifier
//! below is plain text processing and is tested everywhere.

use std::collections::{BTreeSet, HashMap};
use std::path::{Component, Path, PathBuf};
use std::process::Command;

use anyhow::{Context, Result, bail};
use globset::{Glob, GlobSet, GlobSetBuilder};

/// One file the traced process looked at.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Access {
    /// `open`, `stat` (existence and metadata probes), `exec` or `open (missing)`.
    pub kind: &'static str,
    pub path: String,
}

/// Collapses `.` and `..` without touching the filesystem.
pub fn lexical(path: &str) -> String {
    let mut parts: Vec<String> = Vec::new();
    for c in Path::new(path).components() {
        match c {
            Component::ParentDir => {
                parts.pop();
            }
            Component::Normal(s) => parts.push(s.to_string_lossy().into_owned()),
            _ => {}
        }
    }
    format!("/{}", parts.join("/"))
}

/// Splits the text of a call's arguments at top-level commas, keeping quoted
/// strings (with escapes), brackets and `fd</path>` annotations whole.
fn split_args(s: &str) -> Vec<String> {
    let (mut out, mut cur, mut depth, mut in_str, mut esc) =
        (Vec::new(), String::new(), 0i32, false, false);
    let mut prev = ' ';
    let mut in_note = false;
    for c in s.chars() {
        if in_str {
            cur.push(c);
            if esc {
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            }
        } else if in_note {
            cur.push(c);
            in_note = c != '>';
        } else {
            match c {
                '"' => {
                    in_str = true;
                    cur.push(c);
                }
                '<' if prev.is_ascii_digit() => {
                    in_note = true;
                    cur.push(c);
                }
                '(' | '[' | '{' => {
                    depth += 1;
                    cur.push(c);
                }
                ')' | ']' | '}' => {
                    depth -= 1;
                    cur.push(c);
                }
                ',' if depth == 0 => out.push(std::mem::take(&mut cur).trim().to_owned()),
                _ => cur.push(c),
            }
        }
        prev = c;
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_owned());
    }
    out
}

/// Decodes a strace string literal: `"a\"b\n\x41\101"`. `None` if it is not one
/// or was truncated (`"..."...`), because a truncated path proves nothing.
fn unquote(arg: &str) -> Option<String> {
    let inner = arg.strip_prefix('"')?.strip_suffix('"')?;
    let mut out = Vec::new();
    let b = inner.as_bytes();
    let mut i = 0;
    while i < b.len() {
        if b[i] != b'\\' {
            out.push(b[i]);
            i += 1;
            continue;
        }
        i += 1;
        match *b.get(i)? {
            b'n' => out.push(b'\n'),
            b't' => out.push(b'\t'),
            b'r' => out.push(b'\r'),
            b'v' => out.push(0x0b),
            b'f' => out.push(0x0c),
            b'a' => out.push(7),
            b'b' => out.push(8),
            b'x' => {
                let h = inner.get(i + 1..i + 3)?;
                out.push(u8::from_str_radix(h, 16).ok()?);
                i += 2;
            }
            c @ b'0'..=b'7' => {
                let mut v = u32::from(c - b'0');
                let mut n = 1;
                while n < 3 && matches!(b.get(i + 1), Some(b'0'..=b'7')) {
                    i += 1;
                    v = v * 8 + u32::from(b[i] - b'0');
                    n += 1;
                }
                out.push(v as u8);
            }
            c => out.push(c),
        }
        i += 1;
    }
    Some(String::from_utf8_lossy(&out).into_owned())
}

/// The directory an `at` call is relative to: `AT_FDCWD`, or `N</dir>`.
fn dirfd(arg: &str, cwd: &str) -> Option<String> {
    if arg == "AT_FDCWD" {
        return Some(cwd.to_owned());
    }
    let (_, rest) = arg.split_once('<')?;
    rest.strip_suffix('>').map(str::to_owned)
}

fn resolve(dir: Option<String>, path: &str) -> String {
    if path.starts_with('/') {
        lexical(path)
    } else {
        // An fd with no printed path (a socket, a pipe) cannot be resolved; keep
        // the relative text so the report still names something.
        lexical(&format!(
            "{}/{path}",
            dir.unwrap_or_else(|| "/(unknown fd)".into())
        ))
    }
}

/// Splits `args) = ret` at the last `)` followed by `=`; strace pads resumed
/// calls with runs of spaces, so the separator is not a fixed string.
fn split_ret(s: &str) -> Option<(&str, &str)> {
    s.rmatch_indices(')').find_map(|(i, _)| {
        let after = s[i + 1..].trim_start();
        after.strip_prefix('=').map(|ret| (&s[..i], ret.trim()))
    })
}

/// Reads strace's `-f -y -s N -e trace=file` output one line at a time. Keeps
/// the half-printed calls of interleaved threads (`<unfinished ...>`) until their
/// `<... resumed>` line arrives.
pub struct Classifier {
    cwd: String,
    pending: HashMap<String, (String, String)>,
}

impl Classifier {
    pub fn new(cwd: &str) -> Classifier {
        Classifier {
            cwd: cwd.to_owned(),
            pending: HashMap::new(),
        }
    }

    pub fn line(&mut self, raw: &str) -> Option<Access> {
        let mut rest = raw.trim_end();
        let pid = if let Some(r) = rest.strip_prefix("[pid") {
            let (p, r) = r.split_once(']')?;
            rest = r;
            p.trim().to_owned()
        } else {
            let (p, r) = rest.split_once(char::is_whitespace)?;
            if !p.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            rest = r;
            p.to_owned()
        };
        let rest = rest.trim_start();
        if rest.starts_with("+++") || rest.starts_with("---") {
            return None;
        }
        let (name, args, ret) = if let Some(r) = rest.strip_prefix("<... ") {
            let (name, tail) = r.split_once(" resumed>")?;
            let (pname, pargs) = self.pending.remove(&pid)?;
            if pname != name {
                return None;
            }
            // The tail starts mid-call: `, mode) = 3<...>` or `)  = 3<...>`.
            let (more, ret) = split_ret(tail)?;
            (pname, format!("{pargs}{more}"), ret.to_owned())
        } else {
            let (name, r) = rest.split_once('(')?;
            if let Some(args) = r.strip_suffix("<unfinished ...>") {
                self.pending
                    .insert(pid, (name.to_owned(), args.trim_end().to_owned()));
                return None;
            }
            let (args, ret) = split_ret(r)?;
            (name.to_owned(), args.to_owned(), ret.to_owned())
        };
        self.access(&name, &args, &ret)
    }

    fn access(&self, name: &str, args: &str, ret: &str) -> Option<Access> {
        let a = split_args(args);
        let ok = !ret.starts_with('-');
        // (index of the dirfd, index of the path, index of the flags) per call.
        let (dfd, pi, flags_at, kind): (Option<usize>, usize, Option<usize>, &'static str) =
            match name {
                "open" => (None, 0, Some(1), "open"),
                "openat" => (Some(0), 1, Some(2), "open"),
                "openat2" => (Some(0), 1, Some(2), "open"),
                "stat" | "lstat" | "access" | "statfs" | "stat64" | "lstat64" | "readlink" => {
                    (None, 0, None, "stat")
                }
                "newfstatat" | "fstatat64" | "statx" | "faccessat" | "faccessat2"
                | "readlinkat" => (Some(0), 1, None, "stat"),
                "execve" => (None, 0, None, "exec"),
                "execveat" => (Some(0), 1, None, "exec"),
                _ => return None,
            };
        if let Some(fi) = flags_at {
            let flags = a.get(fi)?;
            // `openat2` prints a struct: `{flags=O_RDONLY|..., resolve=...}`.
            let flags = flags
                .strip_prefix('{')
                .and_then(|s| s.strip_prefix("flags="))
                .unwrap_or(flags);
            if flags.contains("O_WRONLY") {
                return None;
            }
        }
        let path = unquote(a.get(pi)?)?;
        if path.is_empty() {
            return None;
        }
        let dir = dfd.and_then(|i| a.get(i)).and_then(|d| dirfd(d, &self.cwd));
        let dir = if dfd.is_none() {
            Some(self.cwd.clone())
        } else {
            dir
        };
        let kind = if !ok && kind == "open" {
            "open (missing)"
        } else {
            kind
        };
        Some(Access {
            kind,
            path: resolve(dir, &path),
        })
    }
}

/// Directories and globs a read may fall under without being a finding.
pub struct Allow {
    prefixes: Vec<String>,
    globs: GlobSet,
    package_dir: String,
}

impl Allow {
    pub fn new(package_dir: &str, prefixes: Vec<String>, declared: &[String]) -> Result<Allow> {
        let mut b = GlobSetBuilder::new();
        for g in declared {
            // A declaration is relative to the package directory unless absolute.
            let abs = if g.starts_with('/') {
                g.clone()
            } else {
                format!("{}/{g}", package_dir.trim_end_matches('/'))
            };
            b.add(Glob::new(&abs).with_context(|| {
                format!("`{g}` in the declared inputs is not a valid glob; fix the pattern")
            })?);
        }
        Ok(Allow {
            prefixes: prefixes.iter().map(|p| lexical(p)).collect(),
            globs: b.build()?,
            package_dir: package_dir.to_owned(),
        })
    }

    pub fn allows(&self, path: &str) -> bool {
        self.prefixes.iter().any(|p| {
            p == "/"
                || path == p
                || path
                    .strip_prefix(p.as_str())
                    .is_some_and(|r| r.starts_with('/'))
        }) || self.globs.is_match(path)
    }

    /// The line to add to the package's `inputs`: relative to `root` when inside it.
    pub fn suggestion(&self, root: &str, path: &str) -> String {
        let root = root.trim_end_matches('/');
        let shown = path.strip_prefix(&format!("{root}/")).unwrap_or(path);
        let _ = &self.package_dir;
        format!("inputs = [\"{shown}\"]")
    }
}

/// Everything in `trace` outside the allowances, deduplicated and sorted.
pub fn findings(trace: &str, cwd: &str, allow: &Allow) -> Vec<Access> {
    let mut c = Classifier::new(cwd);
    let set: BTreeSet<Access> = trace
        .lines()
        .filter_map(|l| c.line(l))
        .filter(|a| !allow.allows(&a.path))
        .collect();
    set.into_iter().collect()
}

pub struct Config {
    pub exe: PathBuf,
    pub package_dir: PathBuf,
    pub declared: Vec<String>,
    pub extra_allow: Vec<String>,
    pub sysroot: Option<String>,
    pub env_allow: Vec<String>,
    /// Only tests whose name ends one of these node ids; `None` audits all.
    pub only: Option<Vec<String>>,
}

pub fn read_declared(text: &str) -> Vec<String> {
    text.lines()
        .map(str::trim)
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .map(str::to_owned)
        .collect()
}

fn sysroot() -> Option<String> {
    let out = Command::new("rustc")
        .args(["--print", "sysroot"])
        .output()
        .ok()?;
    out.status
        .success()
        .then(|| String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// The tests audited, and `(test name, findings)` for those with any.
pub type Audited = (usize, Vec<(String, Vec<Access>)>);

pub fn run(cfg: &Config) -> Result<Audited> {
    let exe = cfg.exe.canonicalize().with_context(|| {
        format!(
            "--exe {} does not exist; pass a built test binary",
            cfg.exe.display()
        )
    })?;
    let pkg = cfg
        .package_dir
        .canonicalize()
        .with_context(|| format!("--package-dir {} does not exist", cfg.package_dir.display()))?;
    let (pkg_s, exe_dir) = (
        pkg.to_string_lossy().into_owned(),
        exe.parent()
            .map_or_else(String::new, |p| p.to_string_lossy().into_owned()),
    );
    let listing = Command::new(&exe)
        .args(["--list", "--format", "terse"])
        .output()
        .with_context(|| format!("cannot run {} --list", exe.display()))?;
    if !listing.status.success() {
        bail!(
            "{} --list failed: {}; --exe must be a libtest binary",
            exe.display(),
            String::from_utf8_lossy(&listing.stderr).trim()
        );
    }
    let tests: Vec<String> = String::from_utf8_lossy(&listing.stdout)
        .lines()
        .filter_map(|l| l.strip_suffix(": test").map(str::to_owned))
        .filter(|t| {
            cfg.only.as_ref().is_none_or(|ids| {
                ids.iter()
                    .any(|id| id.ends_with(&format!("::{t}")) || id.ends_with(&format!(":{t}")))
            })
        })
        .collect();
    let mut found = Vec::new();
    for t in &tests {
        let tmp = crate::util::TempDir::new("audit")?;
        let tmp_s = tmp.path().to_string_lossy().into_owned();
        let mut prefixes = vec![
            pkg_s.clone(),
            tmp_s.clone(),
            "/proc".into(),
            "/dev".into(),
            "/sys".into(),
            "/nix/store".into(),
            exe_dir.clone(),
        ];
        // The dynamic loader's own reads; the libc in use is keyed as platform (§3.7).
        prefixes.extend(
            [
                "/etc/ld.so.cache",
                "/lib",
                "/lib64",
                "/usr/lib",
                "/usr/lib64",
            ]
            .map(String::from),
        );
        prefixes.extend(cfg.sysroot.clone().or_else(sysroot));
        prefixes.extend(cfg.extra_allow.iter().cloned());
        let allow = Allow::new(&pkg_s, prefixes, &cfg.declared)?;

        let trace = tmp.path().join("trace.txt");
        let ambient: HashMap<String, String> = std::env::vars().collect();
        let contract = keel::EnvContract {
            allow: cfg.env_allow.clone(),
            profile_env: Default::default(),
        };
        let path_var = ambient.get("PATH").cloned().unwrap_or_default();
        let env = keel::clean_environment(&contract, &ambient, &path_var, tmp.path(), tmp.path());
        let status = Command::new("strace")
            .args(["-f", "-y", "-s", "4096", "-e", "trace=file", "-o"])
            .arg(&trace)
            .arg("--")
            .arg(&exe)
            .args(["--exact", t, "--test-threads=1", "--nocapture"])
            .current_dir(&pkg)
            .env_clear()
            .envs(&env)
            .output()
            .context("cannot run `strace`; install it (it is the audit's only dependency) or run the audit in a unit that allows ptrace")?;
        // A failing test is still audited: what it opened before failing is evidence.
        let _ = status;
        let text = std::fs::read_to_string(&trace).with_context(|| format!("strace wrote no trace for `{t}`; ptrace may be blocked here (check the sandbox), the audit cannot run without it"))?;
        let f = findings(&text, &pkg_s, &allow);
        if !f.is_empty() {
            found.push((t.clone(), f));
        }
    }
    Ok((tests.len(), found))
}

#[cfg(test)]
mod tests {
    use super::*;

    const TRACE: &str = include_str!("../tests/fixtures/strace.sample.txt");

    fn allow(declared: &[&str]) -> Allow {
        let prefixes = [
            "/work/crates/store",
            "/tmp/keel-t",
            "/proc",
            "/dev",
            "/sys",
            "/nix/store",
            "/work/target/debug/deps",
            "/etc/ld.so.cache",
            "/lib",
        ]
        .map(String::from)
        .to_vec();
        Allow::new(
            "/work/crates/store",
            prefixes,
            &declared.iter().map(|s| s.to_string()).collect::<Vec<_>>(),
        )
        .unwrap()
    }

    fn found(declared: &[&str]) -> Vec<(String, String)> {
        findings(TRACE, "/work/crates/store", &allow(declared))
            .into_iter()
            .map(|a| (a.kind.to_owned(), a.path))
            .collect()
    }

    #[test]
    fn classifies_reads_outside_the_allowances() {
        let f = found(&[]);
        let paths: Vec<&str> = f.iter().map(|(_, p)| p.as_str()).collect();
        // Allowed: ld.so.cache, libc, /proc, the package's own fixture (also via an
        // fd-relative open), the test's tmp dir, and the exe.
        assert!(
            !paths.iter().any(|p| p.starts_with("/proc")
                || p.contains("libc")
                || p.contains("fixtures")
                || p.starts_with("/tmp/keel-t")),
            "{paths:?}"
        );
        // Findings: a probed-but-missing file, a read-write open, a stat, a
        // `..` escape through an fd, an exec, and the interleaved/openat2 reads.
        for want in [
            ("open (missing)", "/home/ci/.config/tool.toml"),
            ("open", "/srv/shared/data.json"),
            ("stat", "/etc/hostname"),
            ("open", "/srv/secret/key.pem"),
            ("stat", "/usr/bin/git"),
            ("open", "/srv/interleaved.txt"),
            ("open", "/srv/openat2.txt"),
        ] {
            assert!(
                f.contains(&(want.0.to_owned(), want.1.to_owned())),
                "missing {want:?} in {f:?}"
            );
        }
    }

    #[test]
    fn writes_empty_paths_and_non_calls_are_not_reads() {
        let f = found(&[]);
        assert!(
            !f.iter()
                .any(|(_, p)| p.contains("out.log") || p.contains("/sub")),
            "{f:?}"
        );
        assert!(
            !f.iter()
                .any(|(_, p)| p == "/work/crates/store/fixtures/wal.bin")
        );
        // readlink of /proc/self/exe is under /proc and allowed.
        assert!(!f.iter().any(|(_, p)| p == "/proc/self/exe"));
    }

    #[test]
    fn escapes_and_resumed_calls_are_decoded() {
        let f = found(&[]);
        assert!(
            f.iter().any(|(_, p)| p == "/opt/odd dir/\"quoted\"\n.txt"),
            "{f:?}"
        );
    }

    #[test]
    fn declarations_silence_exactly_their_globs() {
        let f = found(&["/srv/*.txt", "/srv/shared/**"]);
        let paths: Vec<&str> = f.iter().map(|(_, p)| p.as_str()).collect();
        assert!(
            !paths.contains(&"/srv/interleaved.txt") && !paths.contains(&"/srv/shared/data.json")
        );
        assert!(
            paths.contains(&"/srv/secret/key.pem"),
            "an unrelated read stays a finding"
        );
    }

    #[test]
    fn suggestion_is_relative_to_the_root_when_inside_it() {
        let a = allow(&[]);
        assert_eq!(
            a.suggestion("/work", "/work/crates/x/data.json"),
            "inputs = [\"crates/x/data.json\"]"
        );
        assert_eq!(
            a.suggestion("/work", "/srv/k.pem"),
            "inputs = [\"/srv/k.pem\"]"
        );
    }

    #[test]
    fn helpers() {
        assert_eq!(lexical("/a/b/../c/./d"), "/a/c/d");
        assert_eq!(
            split_args("AT_FDCWD, \"a,b\", O_RDONLY|O_CLOEXEC"),
            ["AT_FDCWD", "\"a,b\"", "O_RDONLY|O_CLOEXEC"]
        );
        assert_eq!(
            split_args("5</x/y,z>, \"p\", {a=1, b=2}"),
            ["5</x/y,z>", "\"p\"", "{a=1, b=2}"]
        );
        assert_eq!(unquote("\"a\\x41\\101\\\"\""), Some("aAA\"".into()));
        assert_eq!(unquote("\"abc\"..."), None);
        assert_eq!(read_declared("# c\n a/** \n\nb\n"), ["a/**", "b"]);
    }
}

//! Small shared pieces: UTC timestamps, running a child with a timeout, tool
//! resolution and hashing, and glob escaping.

use std::collections::BTreeMap;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::mpsc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result, anyhow};
use keel::Digest;

/// Bytes of a child's output kept for evidence. The tail is what explains a
/// failure, and a runaway test must not fill the store.
pub const OUTPUT_KEEP: usize = 1 << 20;

/// RFC 3339 UTC (`2026-11-14T08:12:03Z`) from a system time. Hand-rolled
/// because the workspace carries no date library and the protocol needs one
/// format only; the algorithm is Howard Hinnant's `civil_from_days`.
pub fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let (days, rem) = ((secs / 86_400) as i64, secs % 86_400);
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// The Rust-style target triple of the machine the conductor runs on.
pub fn host_triple() -> String {
    let (arch, os) = (std::env::consts::ARCH, std::env::consts::OS);
    match os {
        "macos" => format!("{arch}-apple-darwin"),
        "linux" => format!("{arch}-unknown-linux-gnu"),
        other => format!("{arch}-unknown-{other}"),
    }
}

/// Everything a child process needs.
pub struct Spawn<'a> {
    /// Program and arguments; the program is used as given (resolve it first).
    pub argv: &'a [String],
    /// Working directory.
    pub cwd: &'a Path,
    /// The complete environment (nothing is inherited).
    pub env: &'a BTreeMap<String, String>,
    /// Kill the child after this long.
    pub timeout: Option<Duration>,
}

/// What a child did.
pub struct Captured {
    /// Exit code, `None` when killed by a signal or on timeout.
    pub code: Option<i32>,
    /// The last [`OUTPUT_KEEP`] bytes of stdout.
    pub stdout: Vec<u8>,
    /// The last [`OUTPUT_KEEP`] bytes of stderr.
    pub stderr: Vec<u8>,
    /// Whether the timeout fired.
    pub timed_out: bool,
    /// Wall time.
    pub elapsed: Duration,
}

fn drain(mut r: impl Read + Send + 'static) -> mpsc::Receiver<Vec<u8>> {
    let (tx, rx) = mpsc::channel();
    std::thread::spawn(move || {
        let mut kept: Vec<u8> = Vec::new();
        let mut buf = [0u8; 16 * 1024];
        while let Ok(n) = r.read(&mut buf) {
            if n == 0 {
                break;
            }
            kept.extend_from_slice(&buf[..n]);
            if kept.len() > 2 * OUTPUT_KEEP {
                kept.drain(..kept.len() - OUTPUT_KEEP);
            }
        }
        if kept.len() > OUTPUT_KEEP {
            kept.drain(..kept.len() - OUTPUT_KEEP);
        }
        let _ = tx.send(kept);
    });
    rx
}

/// Runs a child to completion, draining both pipes while it runs so a chatty
/// child cannot block on a full pipe.
pub fn run_captured(spec: &Spawn<'_>) -> Result<Captured> {
    let (program, args) = spec.argv.split_first().ok_or_else(|| {
        anyhow!("an empty command cannot be run; give `command` at least the program name")
    })?;
    let started = Instant::now();
    let mut child = Command::new(program)
        .args(args)
        .current_dir(spec.cwd)
        .env_clear()
        .envs(spec.env)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| {
            format!(
                "cannot start `{program}` in {}; check the program exists and is executable, and that its directory is listed in `tools`",
                spec.cwd.display()
            )
        })?;
    let out = drain(child.stdout.take().expect("piped"));
    let err = drain(child.stderr.take().expect("piped"));
    let mut timed_out = false;
    let status = loop {
        if let Some(s) = child
            .try_wait()
            .context("cannot wait for the child process")?
        {
            break s;
        }
        if spec.timeout.is_some_and(|t| started.elapsed() > t) {
            timed_out = true;
            let _ = child.kill();
            break child.wait().context("cannot reap the killed child")?;
        }
        std::thread::sleep(Duration::from_millis(10));
    };
    // A grandchild that inherited the pipe can outlive the kill; do not wait
    // for it forever.
    let grace = Duration::from_secs(2);
    Ok(Captured {
        code: status.code(),
        stdout: out.recv_timeout(grace).unwrap_or_default(),
        stderr: err.recv_timeout(grace).unwrap_or_default(),
        timed_out,
        elapsed: started.elapsed(),
    })
}

/// The last `max` bytes of `bytes` as lossy text, for messages.
pub fn tail_text(bytes: &[u8], max: usize) -> String {
    let start = bytes.len().saturating_sub(max);
    String::from_utf8_lossy(&bytes[start..]).trim().to_owned()
}

/// Finds `name` on `path_var` (colon separated) or accepts it as a path.
pub fn which(name: &str, path_var: &str) -> Option<PathBuf> {
    if name.contains('/') {
        let p = PathBuf::from(name);
        return p.is_file().then_some(p);
    }
    std::env::split_paths(path_var)
        .map(|d| d.join(name))
        .find(|p| p.is_file())
}

/// Hashes a file's bytes (streamed).
pub fn hash_file(path: &Path) -> Result<Digest> {
    let mut h = blake3::Hasher::new();
    h.update_reader(std::fs::File::open(path).with_context(|| {
        format!(
            "cannot read {} to hash it as a tool; check it exists and is readable",
            path.display()
        )
    })?)?;
    Ok(Digest::Blake3(*h.finalize().as_bytes()))
}

/// Digest of a set of tools (§3.5): each one's resolved path is *not* hashed
/// (the same binary at another path is the same tool), its content and an
/// optional probe output are.
pub fn tools_digest(tools: &[(String, Digest, String)]) -> Digest {
    let mut sorted: Vec<_> = tools.iter().collect();
    sorted.sort();
    let mut h = blake3::Hasher::new();
    h.update(b"keel-conduct/tools\0");
    for (name, content, probe) in sorted {
        for part in [
            name.as_bytes(),
            content.to_hex().as_bytes(),
            probe.as_bytes(),
        ] {
            h.update(&(part.len() as u64).to_le_bytes());
            h.update(part);
        }
    }
    Digest::Blake3(*h.finalize().as_bytes())
}

/// A tool found on the ambient `PATH`: its resolved binary and content hash.
pub struct Tool {
    /// The name the node declared.
    pub name: String,
    /// The binary after symlinks, so two names for one binary hash alike.
    pub path: PathBuf,
    /// Content hash of the binary.
    pub content: Digest,
}

/// Resolves a declared tool on the ambient `PATH` (or as a path) and hashes it.
pub fn resolve_tool(name: &str) -> Result<Tool> {
    let ambient = std::env::var("PATH").unwrap_or_default();
    let found = which(name, &ambient).ok_or_else(|| {
        anyhow!(
            "tool `{name}` is declared but is not on PATH ({ambient}); install it, or run the conductor from the dev shell that provides it"
        )
    })?;
    let path = found.canonicalize().with_context(|| {
        format!(
            "cannot resolve the tool `{name}` at {}; a dangling symlink on PATH?",
            found.display()
        )
    })?;
    let content = hash_file(&path)?;
    Ok(Tool {
        name: name.rsplit('/').next().unwrap_or(name).to_owned(),
        path,
        content,
    })
}

/// Resolves every declared tool; the digest covers all of them plus `probes`
/// (name, output) such as `go version`.
pub fn resolve_tools(names: &[String], probes: &[(String, String)]) -> Result<(Vec<Tool>, Digest)> {
    let tools: Vec<Tool> = names
        .iter()
        .map(|n| resolve_tool(n))
        .collect::<Result<_>>()?;
    let entries: Vec<(String, Digest, String)> = tools
        .iter()
        .map(|t| {
            let probe = probes
                .iter()
                .find(|(n, _)| *n == t.name)
                .map(|(_, p)| p.clone())
                .unwrap_or_default();
            (t.name.clone(), t.content, probe)
        })
        .collect();
    Ok((tools, tools_digest(&entries)))
}

/// Folds named facts into the files digest. The keel key has fixed slots, and
/// some inputs (a command line, a package's import path, the content keys of
/// consumed artifacts) have none; the files slot is a digest, so they ride in
/// it. Order of `parts` does not matter.
pub fn mix(files: Digest, parts: &[(String, String)]) -> Digest {
    let mut sorted: Vec<_> = parts.iter().collect();
    sorted.sort();
    let mut h = blake3::Hasher::new();
    h.update(b"keel-conduct/mix\0");
    h.update(files.to_hex().as_bytes());
    for (name, value) in sorted {
        for part in [name, value] {
            h.update(&(part.len() as u64).to_le_bytes());
            h.update(part.as_bytes());
        }
    }
    Digest::Blake3(*h.finalize().as_bytes())
}

/// Escapes glob metacharacters so a literal path can ride in `FileSpec::globs`.
pub fn glob_escape(path: &str) -> String {
    let mut out = String::with_capacity(path.len());
    for c in path.chars() {
        if matches!(c, '*' | '?' | '[' | ']' | '{' | '}' | '\\' | '!') {
            out.push('\\');
        }
        out.push(c);
    }
    out
}

/// A path relative to `root` with `/` separators, or `None` when it is outside.
pub fn rel_to(root: &Path, path: &Path) -> Option<String> {
    let rel = path.strip_prefix(root).ok()?;
    Some(
        rel.components()
            .map(|c| c.as_os_str().to_string_lossy().into_owned())
            .collect::<Vec<_>>()
            .join("/"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_known_instants() {
        let at = |s| rfc3339(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_794_671_704), "2026-11-14T15:55:04Z");
    }

    #[test]
    fn escapes_and_normalises() {
        assert_eq!(glob_escape("a[1]/b*.go"), "a\\[1\\]/b\\*.go");
        assert_eq!(
            rel_to(Path::new("/r"), Path::new("/r/a/b")).as_deref(),
            Some("a/b")
        );
        assert_eq!(rel_to(Path::new("/r"), Path::new("/x/a")), None);
    }

    #[test]
    fn a_timed_out_child_is_killed() {
        let env = BTreeMap::from([("PATH".to_owned(), "/bin:/usr/bin".to_owned())]);
        let got = run_captured(&Spawn {
            argv: &["/bin/sleep".to_owned(), "30".to_owned()][..],
            cwd: Path::new("/"),
            env: &env,
            timeout: Some(Duration::from_millis(100)),
        })
        .unwrap();
        assert!(got.timed_out && got.code.is_none());
    }
}

//! Running one quantum of one target and reading how it ended.

use std::collections::VecDeque;
use std::io::{BufRead, BufReader};
use std::os::unix::process::{CommandExt, ExitStatusExt};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use anyhow::{Context, Result};

use crate::parse::Parsed;
use crate::state::{ExitInfo, Outcome, StoppedBy};

/// How long a target gets to leave after SIGINT before the group is killed.
pub const GRACE: Duration = Duration::from_secs(15);
/// Saved output per quantum.
pub const LOG_CAP: usize = 256 * 1024;
const LINE_CAP: usize = 16 * 1024;
const POLL: Duration = Duration::from_millis(5);

/// A probe inherits nothing it could use against the driver.
const CHILD_PATH: &str = "/run/current-system/sw/bin:/usr/bin:/bin";

pub struct Ran {
    pub exit: ExitInfo,
    pub stopped_by: StoppedBy,
    pub seconds: f64,
    pub parsed: Parsed,
    /// The newest output, at most `LOG_CAP` bytes.
    pub lines: Vec<String>,
}

#[derive(Default)]
struct Capture {
    parsed: Parsed,
    lines: VecDeque<String>,
    bytes: usize,
}

fn killpg(pid: u32, sig: libc::c_int) {
    // ESRCH just means everything in the group is already gone.
    unsafe {
        libc::killpg(pid as libc::pid_t, sig);
    }
}

/// Runs `argv` in its own process group until it exits, `quantum` passes (SIGINT to the
/// group, then SIGKILL after `GRACE`) or `stop` is set (the same).
///
/// The child runs in `cwd`, the target's artifacts directory: libFuzzer writes crash
/// inputs to `./` unless told `-artifact_prefix`, and a crash written anywhere else would
/// be a finding with no input (seen with a real libFuzzer build, 2026-11-15).
pub fn run_quantum(argv: &[String], cwd: &std::path::Path, quantum: Duration, stop: &AtomicBool) -> Result<Ran> {
    let (reader, writer) = std::io::pipe().context("cannot create the output pipe of a quantum; too many open files?")?;
    let mut cmd = Command::new(&argv[0]);
    cmd.args(&argv[1..])
        .env_clear()
        .env("PATH", CHILD_PATH)
        .env("LANG", "C")
        .current_dir(cwd)
        .stdin(Stdio::null())
        .stdout(writer.try_clone()?)
        .stderr(writer)
        .process_group(0);
    let start = Instant::now();
    let mut child = cmd
        .spawn()
        .with_context(|| format!("cannot start {} (argv[0] of a target); check that it is executable and that its interpreter exists, or fix the targets file", argv[0]))?;
    // The parent's copies of the write end must close, or the reader never sees EOF.
    drop(cmd);
    let pid = child.id();

    let cap = Arc::new(Mutex::new(Capture::default()));
    let reader_cap = Arc::clone(&cap);
    let thread = std::thread::spawn(move || {
        let mut r = BufReader::new(reader);
        let mut buf = Vec::new();
        loop {
            buf.clear();
            match r.read_until(b'\n', &mut buf) {
                Ok(0) | Err(_) => break,
                Ok(_) => {}
            }
            let at = start.elapsed().as_secs_f64();
            let mut line = String::from_utf8_lossy(&buf).trim_end_matches(['\n', '\r']).to_string();
            if line.len() > LINE_CAP {
                let mut cut = LINE_CAP;
                while !line.is_char_boundary(cut) {
                    cut -= 1;
                }
                line.truncate(cut);
                line.push('…');
            }
            let mut c = reader_cap.lock().unwrap();
            c.parsed.feed(&line, at);
            c.bytes += line.len() + 1;
            c.lines.push_back(line);
            while c.bytes > LOG_CAP && c.lines.len() > 1 {
                let gone = c.lines.pop_front().map_or(0, |l| l.len() + 1);
                c.bytes -= gone;
            }
        }
    });

    let deadline = start + quantum;
    let mut stopped_by = StoppedBy::Target;
    let mut interrupted_at: Option<Instant> = None;
    let mut killed = false;
    let status = loop {
        if let Some(st) = child.try_wait().with_context(|| format!("cannot wait for process {pid} ({})", argv[0]))? {
            break st;
        }
        let now = Instant::now();
        match interrupted_at {
            None => {
                let by = if stop.load(Ordering::SeqCst) {
                    Some(StoppedBy::Supervisor)
                } else if now >= deadline {
                    Some(StoppedBy::Deadline)
                } else {
                    None
                };
                if let Some(by) = by {
                    killpg(pid, libc::SIGINT);
                    stopped_by = by;
                    interrupted_at = Some(now);
                }
            }
            Some(t) if !killed && now.duration_since(t) >= GRACE => {
                killpg(pid, libc::SIGKILL);
                stopped_by = StoppedBy::Kill;
                killed = true;
            }
            Some(_) => {}
        }
        std::thread::sleep(POLL);
    };
    // Stragglers would hold the pipe open and keep running unsupervised.
    killpg(pid, libc::SIGKILL);
    let _ = thread.join();
    let seconds = start.elapsed().as_secs_f64();
    let c = std::mem::take(&mut *cap.lock().unwrap());
    Ok(Ran {
        exit: ExitInfo { code: status.code(), signal: status.signal() },
        stopped_by,
        seconds,
        parsed: c.parsed,
        lines: c.lines.into(),
    })
}

/// The libFuzzer exit code after SIGINT.
pub const EXIT_INTERRUPTED: i32 = 72;

/// The kinds of file libFuzzer writes into the artifact directory.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ArtifactKind {
    Crash,
    Leak,
    Timeout,
    Oom,
    SlowUnit,
}

impl ArtifactKind {
    pub fn of(file_name: &str) -> Option<ArtifactKind> {
        [
            ("crash-", ArtifactKind::Crash),
            ("leak-", ArtifactKind::Leak),
            ("timeout-", ArtifactKind::Timeout),
            ("oom-", ArtifactKind::Oom),
            ("slow-unit-", ArtifactKind::SlowUnit),
        ]
        .into_iter()
        .find(|(p, _)| file_name.starts_with(p))
        .map(|(_, k)| k)
    }
}

/// A SIGKILL the supervisor did not send (`StoppedBy::Kill` is the only place it does). Under
/// the unit's `MemoryMax` that is the kernel's OOM killer: libFuzzer's own limit
/// (`-rss_limit_mb`) makes it exit 71 with an `oom-` file, so a bare SIGKILL is the cgroup's.
pub fn killed_from_outside(exit: &ExitInfo, stopped_by: StoppedBy) -> bool {
    exit.signal == Some(libc::SIGKILL) && stopped_by != StoppedBy::Kill
}

pub fn classify(p: &Parsed, exit: &ExitInfo, stopped_by: StoppedBy, new_kinds: &[ArtifactKind]) -> Outcome {
    let has = |k| new_kinds.contains(&k);
    let clean_exit = matches!(exit.code, Some(0) | Some(EXIT_INTERRUPTED));
    // A target that does not catch our SIGINT dies of it; that is still a clean stop.
    let our_sigint = exit.signal == Some(libc::SIGINT) && matches!(stopped_by, StoppedBy::Deadline | StoppedBy::Supervisor);
    if p.timeout || has(ArtifactKind::Timeout) {
        Outcome::Timeout
    } else if p.oom || has(ArtifactKind::Oom) || killed_from_outside(exit, stopped_by) {
        Outcome::Oom
    } else if p.leak || has(ArtifactKind::Leak) {
        Outcome::Leak
    } else if p.deadly_signal || p.asan || has(ArtifactKind::Crash) || (p.panic && !clean_exit && !our_sigint) {
        Outcome::Crash
    } else if clean_exit || our_sigint {
        Outcome::Ok
    } else {
        Outcome::Error
    }
}

pub fn signal_name(sig: i32) -> String {
    match sig {
        libc::SIGABRT => "SIGABRT".into(),
        libc::SIGSEGV => "SIGSEGV".into(),
        libc::SIGBUS => "SIGBUS".into(),
        libc::SIGILL => "SIGILL".into(),
        libc::SIGFPE => "SIGFPE".into(),
        libc::SIGKILL => "SIGKILL".into(),
        libc::SIGTERM => "SIGTERM".into(),
        libc::SIGINT => "SIGINT".into(),
        n => format!("SIG{n}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn exit(code: i32) -> ExitInfo {
        ExitInfo { code: Some(code), signal: None }
    }

    #[test]
    fn artifact_kinds_come_from_the_file_name() {
        assert_eq!(ArtifactKind::of("crash-caa5ee16"), Some(ArtifactKind::Crash));
        assert_eq!(ArtifactKind::of("slow-unit-1f"), Some(ArtifactKind::SlowUnit));
        assert_eq!(ArtifactKind::of("README"), None);
    }

    #[test]
    fn outcomes() {
        let none = Parsed::default();
        assert_eq!(classify(&none, &exit(72), StoppedBy::Deadline, &[]), Outcome::Ok);
        assert_eq!(classify(&none, &exit(0), StoppedBy::Target, &[]), Outcome::Ok);
        assert_eq!(classify(&none, &ExitInfo { code: None, signal: Some(libc::SIGINT) }, StoppedBy::Deadline, &[]), Outcome::Ok);
        assert_eq!(classify(&none, &exit(2), StoppedBy::Target, &[]), Outcome::Error);
        assert_eq!(classify(&none, &ExitInfo { code: None, signal: Some(libc::SIGKILL) }, StoppedBy::Kill, &[]), Outcome::Error);
        let mut p = Parsed { deadly_signal: true, ..Default::default() };
        assert_eq!(classify(&p, &exit(77), StoppedBy::Target, &[]), Outcome::Crash);
        assert_eq!(classify(&none, &exit(1), StoppedBy::Target, &[ArtifactKind::Crash]), Outcome::Crash);
        p.timeout = true;
        assert_eq!(classify(&p, &exit(70), StoppedBy::Target, &[]), Outcome::Timeout);
        let q = Parsed { panic: true, ..Default::default() };
        assert_eq!(classify(&q, &exit(101), StoppedBy::Target, &[]), Outcome::Crash);
        assert_eq!(classify(&q, &exit(72), StoppedBy::Deadline, &[]), Outcome::Ok);
        // slow units alone are not a failure
        assert_eq!(classify(&none, &exit(72), StoppedBy::Deadline, &[ArtifactKind::SlowUnit]), Outcome::Ok);
    }

    #[test]
    fn a_sigkill_the_supervisor_did_not_send_is_an_oom_and_its_own_is_an_error() {
        let none = Parsed::default();
        let killed = ExitInfo { code: None, signal: Some(libc::SIGKILL) };
        // The kernel's OOM killer, at any point of the quantum.
        for by in [StoppedBy::Target, StoppedBy::Deadline, StoppedBy::Supervisor] {
            assert_eq!(classify(&none, &killed, by, &[]), Outcome::Oom, "{by:?}");
            assert!(killed_from_outside(&killed, by));
        }
        // Ours, sent when SIGINT was ignored for the whole grace: a stuck target, not a memory one.
        assert_eq!(classify(&none, &killed, StoppedBy::Kill, &[]), Outcome::Error);
        assert!(!killed_from_outside(&killed, StoppedBy::Kill));
        // Another signal is not this.
        assert_eq!(classify(&none, &ExitInfo { code: None, signal: Some(libc::SIGTERM) }, StoppedBy::Target, &[]), Outcome::Error);
    }

    #[test]
    fn a_quantum_runs_with_an_empty_environment_and_is_stopped_at_the_deadline() {
        // Prints what it was given, then waits for SIGINT.
        let script = "echo \"env:$(env | sort | tr '\\n' ' ')\"; trap 'echo \"==1== INFO: libFuzzer: run interrupted; exiting\"; exit 72' INT; while :; do sleep 0.05; done";
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), script.to_string()];
        let stop = AtomicBool::new(false);
        let ran = run_quantum(&argv, std::path::Path::new("/"), Duration::from_millis(400), &stop).unwrap();
        assert_eq!(ran.stopped_by, StoppedBy::Deadline);
        assert_eq!(ran.exit.code, Some(72));
        assert!(ran.parsed.interrupted);
        assert!(ran.seconds >= 0.4 && ran.seconds < 5.0);
        let env_line = &ran.lines[0];
        assert!(env_line.contains("LANG=C") && env_line.contains(&format!("PATH={CHILD_PATH}")), "{env_line}");
        assert!(!env_line.contains("HOME=") && !env_line.contains("USER="), "{env_line}");
    }

    #[test]
    fn a_target_that_exits_by_itself_is_stopped_by_target() {
        let argv = vec!["/bin/sh".to_string(), "-c".to_string(), "echo '#2\tINITED cov: 3 ft: 4 corp: 1/1b exec/s: 0 rss: 9Mb'; exit 3".to_string()];
        let ran = run_quantum(&argv, std::path::Path::new("/"), Duration::from_secs(30), &AtomicBool::new(false)).unwrap();
        assert_eq!((ran.stopped_by, ran.exit.code), (StoppedBy::Target, Some(3)));
        assert_eq!(ran.parsed.ft_inited, Some(4));
    }

    #[test]
    fn a_missing_binary_names_what_failed() {
        let err = run_quantum(&["/nonexistent/fuzz-x".to_string()], std::path::Path::new("/"), Duration::from_secs(1), &AtomicBool::new(false)).err().unwrap();
        assert!(format!("{err:#}").contains("/nonexistent/fuzz-x"));
    }
}

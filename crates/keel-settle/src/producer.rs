//! A stand-in for the nextest fork's `--keel-plan` (design/ir.md 11, piece 2).
//!
//! The fork cannot be built here, so this runs one libtest binary the way the fork would:
//! `--list --format terse` once, then each planned test in its own process. It writes the
//! executed list as it goes, one whole line per write, so a killed producer leaves a valid
//! prefix. A planned test the binary did not list is not run and gets no line: absence is
//! what Z1 and Z3 look for.

use crate::error::InputError;
use crate::executed::{Ended, Header, Line, Listed, Record, Source, Status};
use crate::plan::{Binary, Plan};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::path::PathBuf;
use std::process::{Command, Stdio};
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

pub struct Options {
    pub exe: PathBuf,
    pub out: PathBuf,
    pub binary: Option<Binary>,
    pub jobs: usize,
    pub timeout: Duration,
    pub cwd: Option<PathBuf>,
}

struct Sink(Mutex<File>);

impl Sink {
    fn line<T: serde::Serialize>(&self, v: &T) -> Result<(), String> {
        let mut bytes = serde_json::to_vec(v).map_err(|e| e.to_string())?;
        bytes.push(b'\n');
        // One write of a whole line, then flush: a kill between records cannot split one.
        let mut f = self.0.lock().map_err(|_| "the writer lock was poisoned by a panicking worker".to_owned())?;
        f.write_all(&bytes).and_then(|()| f.flush()).map_err(|e| e.to_string())
    }
}

fn command(o: &Options) -> Command {
    let mut c = Command::new(&o.exe);
    if let Some(d) = &o.cwd {
        // Cargo runs a test with the package directory as its cwd and sets this variable at
        // run time; tests that read fixtures rely on both.
        c.current_dir(d).env("CARGO_MANIFEST_DIR", d);
    }
    c
}

/// Returns the number of records written.
pub fn run(plan: &Plan, o: &Options) -> Result<usize, InputError> {
    let binary = match (&o.binary, plan.binaries().as_slice()) {
        (Some(b), bs) if bs.contains(&b) => b.clone(),
        (Some(b), bs) => return Err(InputError::Other(format!("the plan has no tests of binary {b}; it has {}. Pass one of those to --binary.", join(bs)))),
        (None, [only]) => (*only).clone(),
        (None, bs) => return Err(InputError::Other(format!("the plan has {} binaries ({}); pass --binary to say which one --exe is.", bs.len(), join(bs)))),
    };
    // An existing file may hold another run's records; appending would mix two runs.
    if o.out.exists() {
        return Err(InputError::Other(format!("{} exists. The executed list is written once per run; remove it or choose another path.", o.out.display())));
    }
    let file = OpenOptions::new().create_new(true).append(true).open(&o.out).map_err(|source| InputError::Write { path: o.out.clone(), source })?;
    let sink = Sink(Mutex::new(file));
    let fail = |e: String| InputError::Write { path: o.out.clone(), source: std::io::Error::other(e) };
    sink.line(&Header { plan: plan.digest() }).map_err(fail)?;

    let names = list(o)?;
    sink.line(&Line::Listed(Listed { binary: binary.clone(), names: names.clone() })).map_err(fail)?;

    let listed: std::collections::HashSet<&str> = names.iter().map(String::as_str).collect();
    let todo: Vec<&str> = plan.tests_of(&binary).filter(|n| listed.contains(n)).collect();
    let next = AtomicUsize::new(0);
    let written = AtomicUsize::new(0);
    let failure: Mutex<Option<String>> = Mutex::new(None);
    std::thread::scope(|s| {
        for _ in 0..o.jobs.max(1) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::SeqCst);
                    let Some(name) = todo.get(i) else { break };
                    if failure.lock().is_ok_and(|f| f.is_some()) {
                        break;
                    }
                    let rec = run_one(o, &binary, name);
                    match sink.line(&Line::Record(rec)) {
                        Ok(()) => {
                            written.fetch_add(1, Ordering::SeqCst);
                        }
                        Err(e) => {
                            if let Ok(mut f) = failure.lock() {
                                f.get_or_insert(e);
                            }
                            break;
                        }
                    }
                }
            });
        }
    });
    if let Some(e) = failure.into_inner().ok().flatten() {
        return Err(fail(e));
    }
    Ok(written.into_inner())
}

fn join(bs: &[&Binary]) -> String {
    bs.iter().map(|b| b.to_string()).collect::<Vec<_>>().join(", ")
}

/// Every `name: test` line of the binary's own list. Benchmarks are not tests.
fn list(o: &Options) -> Result<Vec<String>, InputError> {
    let out = command(o).args(["--list", "--format", "terse"]).stdin(Stdio::null()).output().map_err(|e| {
        InputError::Other(format!("cannot run {} --list: {e}. Check that --exe is the test binary cargo built, and executable.", o.exe.display()))
    })?;
    if !out.status.success() {
        return Err(InputError::Other(format!(
            "{} --list --format terse failed ({}): {}. The executed list holds only its header, so settle will report every unit as having no result.",
            o.exe.display(),
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        )));
    }
    Ok(String::from_utf8_lossy(&out.stdout).lines().filter_map(|l| l.strip_suffix(": test")).map(str::to_owned).collect())
}

fn tail_reader(mut r: impl Read + Send + 'static) -> std::thread::JoinHandle<Vec<u8>> {
    std::thread::spawn(move || {
        // The summary is at the end, so keep the tail and keep draining, or a chatty test
        // blocks on a full pipe.
        let mut buf = Vec::new();
        let mut chunk = [0u8; 8192];
        while let Ok(n) = r.read(&mut chunk) {
            if n == 0 {
                break;
            }
            buf.extend_from_slice(&chunk[..n]);
            if buf.len() > 256 * 1024 {
                buf.drain(..buf.len() - 64 * 1024);
            }
        }
        buf
    })
}

fn record(binary: &Binary, name: &str, status: Status, ms: u64, ended: Option<Ended>, note: Option<String>) -> Record {
    Record { binary: binary.clone(), name: name.to_owned(), status, source: Source::Ran { attempt: 1, duration_ms: ms }, ended, note }
}

fn run_one(o: &Options, binary: &Binary, name: &str) -> Record {
    let t0 = Instant::now();
    let ms = |t: Instant| t.elapsed().as_millis() as u64;
    let spawned = command(o).args(["--exact", name, "--test-threads", "1"]).stdin(Stdio::null()).stdout(Stdio::piped()).stderr(Stdio::piped()).spawn();
    let mut child = match spawned {
        Ok(c) => c,
        Err(e) => return record(binary, name, Status::Error, ms(t0), None, Some(format!("cannot start {}: {e}", o.exe.display()))),
    };
    let out = child.stdout.take().map(tail_reader);
    let err = child.stderr.take().map(tail_reader);
    let mut pause = Duration::from_millis(1);
    let status = loop {
        match child.try_wait() {
            Ok(Some(s)) => break Some(s),
            Ok(None) if t0.elapsed() >= o.timeout => {
                let _ = child.kill();
                let _ = child.wait();
                break None;
            }
            Ok(None) => {
                std::thread::sleep(pause);
                pause = (pause * 2).min(Duration::from_millis(20));
            }
            Err(e) => return record(binary, name, Status::Error, ms(t0), None, Some(format!("cannot wait for the test process: {e}"))),
        }
    };
    let elapsed = ms(t0);
    let Some(status) = status else {
        // The readers are left to finish by themselves: a grandchild may still hold the pipe.
        return record(binary, name, Status::Timeout, elapsed, None, Some(format!("killed after {}s", o.timeout.as_secs())));
    };
    let text = |h: Option<std::thread::JoinHandle<Vec<u8>>>| h.and_then(|h| h.join().ok()).map(|b| String::from_utf8_lossy(&b).into_owned()).unwrap_or_default();
    let (stdout, stderr) = (text(out), text(err));
    let summary = parse_summary(&stdout);
    let ended = ended_of(&status);
    match (status.code(), summary) {
        (Some(0), Some(s)) if s.passed == 1 && s.failed == 0 => record(binary, name, Status::Pass, elapsed, ended, None),
        (Some(0), s) => {
            let what = s.map_or("no libtest summary".to_owned(), |s| format!("{} passed, {} failed, {} ignored", s.passed, s.failed, s.ignored));
            record(binary, name, Status::Error, elapsed, ended, Some(format!("exit 0 but not one passing test ({what}); an ignored or unmatched test is not a pass")))
        }
        (Some(101), Some(s)) if s.failed >= 1 => record(binary, name, Status::Fail, elapsed, ended, panic_line(&stdout, &stderr)),
        _ => record(binary, name, Status::Error, elapsed, ended, Some(panic_line(&stdout, &stderr).unwrap_or_else(|| "the process ended without a libtest result".to_owned()))),
    }
}

#[cfg(unix)]
fn ended_of(s: &std::process::ExitStatus) -> Option<Ended> {
    use std::os::unix::process::ExitStatusExt;
    s.code().map(Ended::Exit).or_else(|| s.signal().map(Ended::Signal))
}
#[cfg(not(unix))]
fn ended_of(s: &std::process::ExitStatus) -> Option<Ended> {
    s.code().map(Ended::Exit)
}

struct Summary {
    passed: u32,
    failed: u32,
    ignored: u32,
}

/// `test result: ok. 1 passed; 0 failed; 0 ignored; ...`
fn parse_summary(out: &str) -> Option<Summary> {
    let line = out.lines().rev().find(|l| l.starts_with("test result:"))?;
    let num = |word: &str| -> Option<u32> {
        let before = line.split(word).next()?;
        before.trim_end().rsplit(|c: char| !c.is_ascii_digit()).next()?.parse().ok()
    };
    Some(Summary { passed: num(" passed")?, failed: num(" failed")?, ignored: num(" ignored")? })
}

fn panic_line(stdout: &str, stderr: &str) -> Option<String> {
    let line = |l: &str| l.trim().chars().take(200).collect::<String>();
    if let Some(l) = stdout.lines().chain(stderr.lines()).find(|l| l.contains("panicked at")) {
        return Some(line(l));
    }
    // A test that returns Err prints no panic; libtest shows the error under the "---- name stdout ----" header.
    let mut after = stdout.lines().skip_while(|l| !l.starts_with("---- "));
    after.next();
    after.map(line).find(|l| !l.is_empty())
}

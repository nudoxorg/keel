//! The loop: workers sharing one scheduler, one quantum at a time.

use std::ffi::CString;
use std::fs::File;
use std::os::fd::AsRawFd;
use std::panic::AssertUnwindSafe;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Mutex, MutexGuard, PoisonError};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, anyhow, bail};
use sd_notify::NotifyState;

use crate::findings::{self, Scan};
use crate::metrics::{Publisher, WRITE_EVERY};
use crate::quantum::{self, LOG_CAP};
use crate::sched::{Claim, Config, Pick, Sched};
use crate::state::{self, LogAppendFailed, QUANTUM_SCHEMA, Quantum, State, delta_ft};
use crate::targets::{Target, TargetsFile};
use crate::util::{now_rfc3339, per_sec, sci};

const LOGS_KEPT: usize = 20;
const DISK_WAIT: Duration = Duration::from_secs(60);
const IDLE_WAIT: Duration = Duration::from_secs(1);
/// Past a quantum and its SIGINT grace, what one quantum may still take (the log, two fsyncs)
/// before its worker counts as stuck. A quantum is the only thing a worker does that has an end
/// it can overrun; idle, disk waits and backoffs are not timed.
const STALL_MARGIN: Duration = Duration::from_secs(60);
/// How often the heartbeat thread looks at the workers and at STOP.
const HEARTBEAT_TICK: Duration = Duration::from_millis(100);

pub struct RunConfig {
    pub targets: PathBuf,
    pub state: PathBuf,
    pub workers: usize,
    pub quantum: Duration,
    pub quanta: Option<u64>,
    pub starve_every: u64,
    pub min_free_gib: f64,
    pub metrics: Option<PathBuf>,
}

/// Set by SIGTERM/SIGINT (and by a worker's fatal error); the workers see it within a poll.
static STOP: AtomicBool = AtomicBool::new(false);

extern "C" fn on_signal(_: libc::c_int) {
    STOP.store(true, Ordering::SeqCst);
}

fn install_handlers() {
    let handler: extern "C" fn(libc::c_int) = on_signal;
    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        sa.sa_sigaction = handler as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        for sig in [libc::SIGINT, libc::SIGTERM] {
            libc::sigaction(sig, &sa, std::ptr::null_mut());
        }
    }
}

fn sleep_interruptible(d: Duration) {
    let end = Instant::now() + d;
    while !STOP.load(Ordering::SeqCst) && Instant::now() < end {
        std::thread::sleep(Duration::from_millis(20).min(end.saturating_duration_since(Instant::now())));
    }
}

/// Free bytes on the filesystem holding `path`, for an unprivileged user.
fn free_bytes(path: &str) -> Option<u64> {
    let c = CString::new(path).ok()?;
    let mut s: libc::statvfs = unsafe { std::mem::zeroed() };
    if unsafe { libc::statvfs(c.as_ptr(), &mut s) } != 0 {
        return None;
    }
    #[allow(clippy::unnecessary_cast)]
    Some(s.f_bavail as u64 * s.f_frsize as u64)
}

fn ensure_dir(path: &str, what: &str, id: &str) -> Result<()> {
    let p = Path::new(path);
    if !p.is_dir() {
        // The target's own directory (<root>/<id>) is made here, since a fresh host has
        // none and the backend wrapper only makes what is below it. The root above that is
        // not: a missing root means --durable-root is wrong, not that it should be invented.
        let root = p.parent().and_then(Path::parent);
        if !root.is_some_and(Path::is_dir) {
            bail!(
                "cannot create {path} (the {what} of target {id}): the durable root above it does not exist; create it (the NixOS module's tmpfiles rule does) or fix --durable-root"
            );
        }
        std::fs::create_dir_all(p).with_context(|| {
            format!("cannot create {path} (the {what} of target {id}): the durable root must be writable; give the keel-fuzz user write access or fix --durable-root")
        })?;
    }
    let c = CString::new(path)?;
    if unsafe { libc::access(c.as_ptr(), libc::W_OK | libc::X_OK) } != 0 {
        bail!("cannot write to {path} (the {what} of target {id}): permission denied; give the keel-fuzz user write access or fix --durable-root");
    }
    Ok(())
}

fn lock_state(dir: &Path) -> Result<File> {
    let path = dir.join("lock");
    let f = File::create(&path).with_context(|| format!("cannot create {} (the lock of the state directory); fix the permissions of --state", path.display()))?;
    if unsafe { libc::flock(f.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        bail!("{} is locked: another keel-judge is using this state directory; stop it or use a different --state", path.display());
    }
    Ok(f)
}

/// `keel-judge: w0 pack-decode 60.0s index (rank 27750 × 0.31/s) ft 58→61 execs 2.8e7 at 466k/s ok`
pub fn summary_line(q: &Quantum) -> String {
    let n = |v: Option<u64>| v.map_or("?".to_string(), |v| v.to_string());
    let mut s = format!(
        "keel-judge: w{} {} {:.1}s {} (rank {} × {:.2}/s) ft {}→{} execs {} at {}/s {}",
        q.worker,
        q.target,
        q.seconds,
        q.chosen_by.as_str(),
        q.rank,
        q.rate,
        n(q.ft_inited),
        n(q.ft),
        q.execs.map_or("?".to_string(), sci),
        q.exec_per_sec.map_or("?".to_string(), per_sec),
        q.outcome.as_str(),
    );
    if let Some(k) = &q.finding {
        s.push_str(&format!(" finding {k}"));
    }
    s
}

fn save_log(state_dir: &Path, target: &str, started: &str, worker: usize, lines: &[String]) -> Result<PathBuf> {
    let dir = state_dir.join("logs").join(target);
    std::fs::create_dir_all(&dir).with_context(|| format!("cannot create {} (quantum logs of target {target}); fix the permissions of --state", dir.display()))?;
    let path = dir.join(format!("{started}-w{worker}.log"));
    let mut text = lines.join("\n");
    text.push('\n');
    // Whole lines were kept, but one long first line can still push past the cap.
    if text.len() > LOG_CAP {
        let mut from = text.len() - LOG_CAP;
        while !text.is_char_boundary(from) {
            from += 1;
        }
        text.drain(..from);
    }
    std::fs::write(&path, text).with_context(|| format!("cannot write {}; is the disk full?", path.display()))?;
    let mut all: Vec<_> = std::fs::read_dir(&dir)?.flatten().map(|e| e.path()).filter(|p| p.extension().is_some_and(|x| x == "log")).collect();
    all.sort();
    for old in all.iter().take(all.len().saturating_sub(LOGS_KEPT)) {
        let _ = std::fs::remove_file(old);
    }
    Ok(path)
}

struct Shared {
    sched: Mutex<Sched>,
    fatal: Mutex<Option<anyhow::Error>>,
    /// When each worker went into its current quantum; `None` while it is not in one. Apart
    /// from `sched` so the heartbeat can read it while a worker holds that lock, and
    /// tolerant of poison since it is plain data.
    in_quantum: Mutex<Vec<Option<Instant>>>,
    /// Workers that have not returned; the heartbeat ends with the last.
    running: AtomicUsize,
    cfg: RunConfig,
    state_dir: PathBuf,
    metrics: Option<Publisher>,
}

impl Shared {
    fn publish_metrics(&self) {
        if let Some(m) = &self.metrics {
            m.publish(&self.sched);
        }
    }

    fn in_quantum(&self) -> MutexGuard<'_, Vec<Option<Instant>>> {
        self.in_quantum.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// How long a worker may stay in one quantum before the heartbeat stops: the quantum, the
/// grace its target gets to leave after SIGINT, and `STALL_MARGIN`.
pub fn stall_limit(quantum: Duration) -> Duration {
    quantum + quantum::GRACE + STALL_MARGIN
}

/// The worker that has been in one quantum the longest past `limit`, and for how long.
fn stalled(since: &[Option<Instant>], now: Instant, limit: Duration) -> Option<(usize, Duration)> {
    since.iter().enumerate().filter_map(|(w, s)| Some((w, now.saturating_duration_since((*s)?)))).filter(|(_, d)| *d > limit).max_by_key(|(_, d)| *d)
}

fn tell_systemd(state: NotifyState<'_>, what: &str) {
    // Without NOTIFY_SOCKET (a terminal, the tests) this succeeds and sends nothing.
    if let Err(e) = sd_notify::notify(false, &[state]) {
        eprintln!("keel-judge: cannot tell systemd {what}: {e}; is NotifyAccess=main set on the unit?");
    }
}

/// READY once started is sent by `run`; this thread then keeps the watchdog fed while every
/// worker is alive, and says STOPPING when the stop begins. Only a worker inside one quantum
/// can be stuck: a child in uninterruptible sleep never lets `wait` return, and that is what
/// systemd must kill us for. Idle, disk and backoff waits are the workers being well.
fn heartbeat(shared: &Shared) {
    let mut usec = 0;
    let every = sd_notify::watchdog_enabled(false, &mut usec).then(|| Duration::from_micros(usec / 2)).filter(|d| !d.is_zero());
    let limit = stall_limit(shared.cfg.quantum);
    let (mut last, mut stopping, mut said) = (None::<Instant>, false, false);
    while shared.running.load(Ordering::SeqCst) > 0 {
        if STOP.load(Ordering::SeqCst) && !stopping {
            tell_systemd(NotifyState::Stopping, "it is stopping");
            stopping = true;
        }
        if every.is_some_and(|e| last.is_none_or(|t| t.elapsed() >= e)) {
            match stalled(&shared.in_quantum(), Instant::now(), limit) {
                None => {
                    tell_systemd(NotifyState::Watchdog, "it is alive");
                    (last, said) = (Some(Instant::now()), false);
                }
                Some((w, d)) if !said => {
                    eprintln!(
                        "keel-judge: w{w} has been in one quantum for {} s, past {} s (the quantum, its {} s grace and {} s more); no longer telling systemd it is alive, so the watchdog will restart the service",
                        d.as_secs(),
                        limit.as_secs(),
                        quantum::GRACE.as_secs(),
                        STALL_MARGIN.as_secs()
                    );
                    said = true;
                }
                Some(_) => {}
            }
        }
        std::thread::sleep(HEARTBEAT_TICK);
    }
    if !stopping {
        tell_systemd(NotifyState::Stopping, "it is stopping");
    }
}

/// A failure to append to a state log ends the process; the restart rebuilds from what the
/// logs hold. Everything else a quantum can hit is that target's own.
fn is_fatal(e: &anyhow::Error) -> bool {
    e.downcast_ref::<LogAppendFailed>().is_some()
}

/// Runs a thread's body so that a panic becomes the error that stops the process: scoped
/// threads that panic leave the others running, and the service quietly short of workers.
/// A poisoned lock is a panic of another thread's and arrives here the same way.
fn guarded(name: &str, body: impl FnOnce() -> Result<()>) -> Result<()> {
    std::panic::catch_unwind(AssertUnwindSafe(body)).unwrap_or_else(|payload| {
        let why = payload.downcast_ref::<&str>().map(|s| s.to_string()).or_else(|| payload.downcast_ref::<String>().cloned()).unwrap_or_else(|| "a payload that is not text".into());
        Err(anyhow!("{name} panicked: {why}; stopping so systemd restarts every worker (state is rebuilt from the logs); this is a bug in keel-judge, report it with the panic message above"))
    })
}

fn one_quantum(shared: &Shared, worker: usize, claim: &Claim) -> Result<()> {
    let t: &Target = &claim.target;
    let corpus = Path::new(&t.corpus);
    let artifacts = Path::new(&t.artifacts);
    let before = findings::snapshot(artifacts)?;
    let corpus_before = findings::count_files(corpus);
    let started = now_rfc3339();

    let ran = quantum::run_quantum(&t.argv, artifacts, shared.cfg.quantum, &STOP)?;

    let after = findings::snapshot(artifacts)?;
    let files = findings::new_files(&before, &after);
    let kinds: Vec<_> = files.iter().map(|f| f.1).collect();
    let outcome = quantum::classify(&ran.parsed, &ran.exit, ran.stopped_by, &kinds);
    let log = save_log(&shared.state_dir, &t.id, &started, worker, &ran.lines)?;
    let p = &ran.parsed;
    let rec = Quantum {
        schema: QUANTUM_SCHEMA.into(),
        target: t.id.clone(),
        worker,
        seq: claim.seq,
        identity: claim.identity.clone(),
        started,
        seconds: ran.seconds,
        quantum_s: shared.cfg.quantum.as_secs_f64(),
        chosen_by: claim.chosen_by,
        rank: claim.rank,
        rate: claim.rate,
        index: claim.index,
        inited_s: p.inited_s,
        cov: p.cov,
        ft_inited: p.ft_inited,
        ft: p.ft,
        delta_ft: delta_ft(p.ft_inited, p.ft, p.new_units),
        execs: p.execs(),
        exec_per_sec: p.exec_per_sec(),
        new_units: p.new_units,
        peak_rss_mb: p.peak_rss_mb,
        corpus_files_before: corpus_before,
        corpus_files_after: findings::count_files(corpus),
        exit: ran.exit,
        stopped_by: ran.stopped_by,
        outcome,
        finding: None,
        slow_units: 0,
        log: log.display().to_string(),
    };
    let scan = Scan { artifacts_dir: artifacts, files: &files, outcome, exit: &ran.exit, log_lines: &ran.lines };
    let mut done = rec.clone();
    done.finding = shared.sched.lock().unwrap().complete(claim, rec, &scan)?;
    eprintln!("{}", summary_line(&done));
    shared.publish_metrics();
    Ok(())
}

/// The directories a target's quantum needs. Checked before every quantum, not only at
/// startup: someone can remove or replace one while the service runs.
fn prepare(t: &Target) -> Result<()> {
    ensure_dir(&t.corpus, "corpus", &t.id)?;
    ensure_dir(&t.artifacts, "artifacts directory", &t.id)
}

enum Attempt {
    Ran,
    /// Below `--min-free-gib` by this many bytes free.
    DiskLow(u64),
    Stopped,
}

/// Everything a worker does with a claim that can fail on account of the target.
fn attempt(shared: &Shared, id: usize, claim: &Claim, min_free: f64) -> Result<Attempt> {
    prepare(&claim.target)?;
    if let Some(free) = free_bytes(&claim.target.corpus).filter(|f| (*f as f64) < min_free) {
        shared.sched.lock().unwrap().release(claim);
        return Ok(Attempt::DiskLow(free));
    }
    if STOP.load(Ordering::SeqCst) {
        shared.sched.lock().unwrap().release(claim);
        return Ok(Attempt::Stopped);
    }
    one_quantum(shared, id, claim)?;
    Ok(Attempt::Ran)
}

fn worker(shared: &Shared, id: usize) -> Result<()> {
    let min_free = shared.cfg.min_free_gib * (1u64 << 30) as f64;
    let mut idle_noted: Option<Instant> = None;
    while !STOP.load(Ordering::SeqCst) {
        let pick = shared.sched.lock().unwrap().pick();
        let claim = match pick {
            Pick::Done => return Ok(()),
            Pick::Idle => {
                if idle_noted.is_none_or(|t| t.elapsed() > Duration::from_secs(60)) {
                    eprintln!("keel-judge: w{id} no target is free (each is running on another worker, has a finding against its current binary, cannot be read, or is backing off after an error); waiting");
                    idle_noted = Some(Instant::now());
                }
                sleep_interruptible(IDLE_WAIT);
                continue;
            }
            Pick::Run(c) => *c,
        };
        shared.in_quantum()[id] = Some(Instant::now());
        let attempted = attempt(shared, id, &claim, min_free);
        shared.in_quantum()[id] = None;
        match attempted {
            Ok(Attempt::Ran) => {}
            Ok(Attempt::DiskLow(free)) => {
                eprintln!(
                    "keel-judge: w{id} only {:.1} GiB free on the filesystem of {} (the corpus of {}), below --min-free-gib {}; recording nothing, waiting {} s; free space or lower the threshold",
                    free as f64 / (1u64 << 30) as f64,
                    claim.target.corpus,
                    claim.target.id,
                    shared.cfg.min_free_gib,
                    DISK_WAIT.as_secs()
                );
                if let Some(m) = &shared.metrics {
                    m.disk_wait();
                }
                shared.publish_metrics();
                sleep_interruptible(DISK_WAIT);
            }
            Ok(Attempt::Stopped) => return Ok(()),
            Err(e) if is_fatal(&e) => return Err(e),
            Err(e) => {
                let wait = shared.sched.lock().unwrap().fault(&claim, &e);
                eprintln!("keel-judge: w{id} target {} faulted: {e:#}; skipping it for {} s, then trying it again; the other targets go on", claim.target.id, wait.as_secs());
                shared.publish_metrics();
            }
        }
    }
    Ok(())
}

/// Keeps the first fatal error to return from `run` and tells every worker to stop.
fn stop_with(shared: &Shared, e: anyhow::Error) {
    shared.fatal.lock().unwrap().get_or_insert(e);
    STOP.store(true, Ordering::SeqCst);
}

pub fn run(cfg: RunConfig) -> Result<()> {
    let tf = TargetsFile::load(&cfg.targets)?;
    if tf.targets.is_empty() {
        bail!("{} lists no targets; nothing to run (did the bundle have scheduled fuzz rows?)", cfg.targets.display());
    }
    std::fs::create_dir_all(&cfg.state).with_context(|| format!("cannot create {} (--state); fix its permissions", cfg.state.display()))?;
    let _lock = lock_state(&cfg.state)?;
    let st = State::load_for_run(&cfg.state)?;
    state::repair_tail(&state::quanta_path(&cfg.state), st.quanta_tail.unwrap_or(state::Tail::Clean))?;
    state::repair_tail(&state::findings_path(&cfg.state), st.findings_tail.unwrap_or(state::Tail::Clean))?;
    // One target with a bad directory starts faulted and is retried; only when none can run
    // is there nothing to supervise.
    let unready: Vec<(usize, anyhow::Error)> = tf.targets.iter().enumerate().filter_map(|(i, t)| prepare(t).err().map(|e| (i, e))).collect();
    if unready.len() == tf.targets.len() {
        let why: Vec<_> = unready.iter().map(|(i, e)| format!("{}: {e:#}", tf.targets[*i].id)).collect();
        bail!("no target can run: all {} failed their directory check at startup ({}); fix what each says, then restart", tf.targets.len(), why.join("; "));
    }
    let ids: Vec<String> = unready.iter().map(|(i, _)| tf.targets[*i].id.clone()).collect();
    let mut sched = Sched::new(
        &cfg.state,
        st,
        tf.targets,
        Config { quantum_s: cfg.quantum.as_secs_f64(), starve_every: cfg.starve_every, limit: cfg.quanta },
    )?;
    for ((i, e), id) in unready.iter().zip(&ids) {
        let wait = sched.fault_at_start(*i, e);
        eprintln!("keel-judge: target {id} cannot run yet: {e:#}; starting it faulted and trying it again in {} s; the other targets go on", wait.as_secs());
    }
    install_handlers();
    let workers = cfg.workers.max(1);
    let metrics = cfg.metrics.clone().map(|path| Publisher::new(path, workers));
    let shared = Shared {
        sched: Mutex::new(sched),
        fatal: Mutex::new(None),
        in_quantum: Mutex::new(vec![None; workers]),
        running: AtomicUsize::new(workers),
        state_dir: cfg.state.clone(),
        cfg,
        metrics,
    };
    shared.publish_metrics();
    tell_systemd(NotifyState::Ready, "it is ready");
    std::thread::scope(|s| {
        for id in 0..workers {
            let shared = &shared;
            s.spawn(move || {
                if let Err(e) = guarded(&format!("worker w{id}"), || worker(shared, id)) {
                    stop_with(shared, e);
                }
                shared.running.fetch_sub(1, Ordering::SeqCst);
            });
        }
        let shared = &shared;
        s.spawn(move || {
            let beat = guarded("the heartbeat thread", || {
                heartbeat(shared);
                Ok(())
            });
            if let Err(e) = beat {
                stop_with(shared, e);
            }
        });
        // This thread is the metrics timer: workers publish when a quantum ends, but while
        // every target is blocked, faulted or waiting for disk none does, and the file's
        // timestamp is what shows the supervisor is alive. Kept off the heartbeat thread, so
        // a slow write to the metrics directory never delays a WATCHDOG=1.
        if shared.metrics.is_some() {
            let mut next = Instant::now() + WRITE_EVERY;
            while shared.running.load(Ordering::SeqCst) > 0 {
                std::thread::sleep(Duration::from_millis(50));
                if Instant::now() >= next {
                    shared.publish_metrics();
                    next = Instant::now() + WRITE_EVERY;
                }
            }
        }
    });
    shared.publish_metrics();
    if let Some(e) = shared.fatal.lock().unwrap().take() {
        return Err(e);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{ChosenBy, ExitInfo, Outcome, StoppedBy};

    #[test]
    fn the_quantum_line_reads_like_the_documented_one() {
        let q = Quantum {
            schema: QUANTUM_SCHEMA.into(),
            target: "pack-decode".into(),
            worker: 0,
            seq: 1,
            identity: "i".into(),
            started: "t".into(),
            seconds: 60.0,
            quantum_s: 60.0,
            chosen_by: ChosenBy::Index,
            rank: 27750,
            rate: 0.31,
            index: 8602.5,
            inited_s: None,
            cov: None,
            ft_inited: Some(58),
            ft: Some(61),
            delta_ft: 3,
            execs: Some(28_000_000),
            exec_per_sec: Some(466_000.0),
            new_units: None,
            peak_rss_mb: None,
            corpus_files_before: 0,
            corpus_files_after: 0,
            exit: ExitInfo { code: Some(72), signal: None },
            stopped_by: StoppedBy::Deadline,
            outcome: Outcome::Ok,
            finding: None,
            slow_units: 0,
            log: String::new(),
        };
        assert_eq!(summary_line(&q), "keel-judge: w0 pack-decode 60.0s index (rank 27750 × 0.31/s) ft 58→61 execs 2.8e7 at 466k/s ok");
    }

    #[test]
    fn a_missing_parent_directory_is_reported_with_what_to_do() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("absent/x/corpus").display().to_string();
        let err = format!("{:#}", ensure_dir(&path, "corpus", "x").unwrap_err());
        assert!(err.contains(&path) && err.contains("corpus of target x") && err.contains("--durable-root"), "{err}");
        // A fresh host: the root exists, the target's own directory does not yet.
        let fresh = dir.path().join("x/corpus").display().to_string();
        ensure_dir(&fresh, "corpus", "x").unwrap();
        assert!(Path::new(&fresh).is_dir());
    }

    #[test]
    fn only_a_worker_past_the_quantum_grace_and_margin_stops_the_heartbeat() {
        let q = Duration::from_secs(60);
        assert_eq!(stall_limit(q), Duration::from_secs(135));
        let base = Instant::now();
        let now = base + Duration::from_secs(1000);
        let at = |ago: u64| Some(now - Duration::from_secs(ago));
        // Idle, waiting for disk and backing off workers have no start time at all.
        assert_eq!(stalled(&[None, None], now, stall_limit(q)), None);
        // Exactly at the limit is still a quantum finishing.
        assert_eq!(stalled(&[at(100), at(135)], now, stall_limit(q)), None);
        assert_eq!(stalled(&[None, at(100), at(136), at(200)], now, stall_limit(q)), Some((3, Duration::from_secs(200))));
        assert_eq!(stalled(&[], now, stall_limit(q)), None);
    }

    #[test]
    fn a_panic_in_a_worker_becomes_the_error_that_stops_the_process() {
        let e = guarded("worker w3", || panic!("index {} out of range", 7)).unwrap_err();
        let msg = format!("{e:#}");
        assert!(msg.contains("worker w3 panicked: index 7 out of range") && msg.contains("restarts"), "{msg}");
        let e = guarded("worker w1", || panic!("plain")).unwrap_err();
        assert!(format!("{e:#}").contains("worker w1 panicked: plain"));
        assert!(guarded("worker w0", || Ok(())).is_ok());
        // A worker's own error passes through untouched.
        assert_eq!(format!("{:#}", guarded("worker w0", || bail!("disk gone")).unwrap_err()), "disk gone");
    }

    #[test]
    fn only_a_failed_log_append_is_fatal() {
        let append = anyhow::Error::new(std::io::Error::from_raw_os_error(libc::ENOSPC)).context(LogAppendFailed { path: "q.jsonl".into(), how: "x".into() });
        assert!(is_fatal(&append));
        assert!(is_fatal(&append.context("w0 recording a quantum")));
        assert!(!is_fatal(&anyhow!("cannot read the artifacts of a target")));
    }

    #[test]
    fn startup_with_no_runnable_target_names_each_and_why() {
        let dir = tempfile::tempdir().unwrap();
        let target = |id: &str| serde_json::json!({
            "id": id, "name": id, "rank": 1, "start_order": 1, "argv": ["/bin/true"],
            "corpus": dir.path().join("absent").join(id).join("corpus"), "artifacts": dir.path().join("absent").join(id).join("artifacts"),
        });
        let path = dir.path().join("targets.json");
        std::fs::write(&path, serde_json::json!({"schema": "keel.judge.targets.v1", "targets": [target("p"), target("q")]}).to_string()).unwrap();
        let cfg = RunConfig { targets: path, state: dir.path().join("state"), workers: 1, quantum: Duration::from_secs(1), quanta: Some(1), starve_every: 10, min_free_gib: 0.0, metrics: None };
        let err = format!("{:#}", run(cfg).unwrap_err());
        assert!(err.contains("no target can run") && err.contains("all 2") && err.contains("p: ") && err.contains("q: ") && err.contains("--durable-root"), "{err}");
    }

    #[test]
    fn free_space_is_readable() {
        assert!(free_bytes("/").is_some_and(|b| b > 0));
        assert!(free_bytes("/nonexistent/path").is_none());
    }
}

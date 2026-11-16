//! The conductor's HTTP skeleton: `keel-store conduct`.
//!
//! It starts jobs; it does not clone, build or run cargo. For each accepted
//! `POST /v1/jobs` it writes `<jobs-dir>/<id>.env` (only values it chose) and
//! starts the fetch, build and test units of that trust domain in turn with
//! `systemctl start`. A job's outcome is what systemd says
//! ([`crate::job::job_outcome`]); its log is the journal of its units.
//!
//! Authentication is a per-pipeline bearer token: the grants file maps the
//! blake3 of a token to the one repo and the kinds (`pr`, `canonical`) that
//! token may start, so a task running PR code in one pipeline cannot start a
//! canonical job or a job for another repo.

use std::collections::HashMap;
use std::fs;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::path::{Path, PathBuf};
use std::pin::Pin;
use std::process::Stdio;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::{Body, Bytes};
use axum::extract::{Path as UrlPath, State};
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::{Deserialize, Serialize};
use tokio::io::AsyncReadExt;
use tokio::sync::{mpsc, watch};

use crate::job::{self, Outcome};
use crate::wire::ErrorBody;

/// Which trust domain a job runs in (DESIGN §6.1).
#[derive(Clone, Copy, PartialEq, Eq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// A pull request: `keel-build` units.
    Pr,
    /// A canonical revision: `keel-canon` units.
    Canonical,
}

impl Kind {
    /// The unit name of `phase` for job `id`.
    fn unit(self, phase: &str, id: &str) -> String {
        match self {
            Kind::Pr => format!("keel-{phase}@{id}.service"),
            Kind::Canonical => format!("keel-canon-{phase}@{id}.service"),
        }
    }
}

/// The sequence every job runs, each phase a unit of its own.
pub const PHASES: [&str; 3] = ["fetch", "build", "test"];

/// What one pipeline token may start.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    /// The only repo this token may start jobs for.
    pub repo: String,
    /// The kinds it may start; PR pipelines list only `pr`.
    pub kinds: Vec<Kind>,
}

/// Parses the grants file: `{ "<blake3 hex of the token>": {"repo", "kinds"} }`.
pub fn parse_grants(text: &str) -> Result<HashMap<String, Grant>, String> {
    let grants: HashMap<String, Grant> = serde_json::from_str(text).map_err(|e| {
        format!("the pipeline tokens file is not a JSON map of token-hash to {{repo, kinds}}: {e}")
    })?;
    for hash in grants.keys() {
        if hash.len() != 64 || !hash.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Err(format!(
                "pipeline token key `{hash}` is not the 64 hex digits of a blake3 hash of the token"
            ));
        }
    }
    Ok(grants
        .into_iter()
        .map(|(k, v)| (k.to_ascii_lowercase(), v))
        .collect())
}

/// How the conductor talks to systemd; faked in tests.
pub trait Units: Send + Sync + 'static {
    /// `systemctl start <unit>`: returns when the oneshot unit finished.
    fn start(&self, unit: &str) -> Result<(), String>;
    /// How `unit` ended, per `systemctl show`.
    fn outcome(&self, unit: &str) -> Result<Outcome, String>;
    /// Follows the journal of `units`.
    fn journal(&self, units: &[String]) -> std::io::Result<tokio::process::Child>;
}

/// The real thing: `systemctl` and `journalctl` from `PATH`.
pub struct Systemd;

impl Units for Systemd {
    fn start(&self, unit: &str) -> Result<(), String> {
        job::validate_unit(unit).map_err(|e| e.to_string())?;
        let out = std::process::Command::new("systemctl")
            .args(["start", "--", unit])
            .output()
            .map_err(|e| {
                format!("cannot run systemctl: {e}; the conductor unit needs systemd in its PATH")
            })?;
        if out.status.success() {
            Ok(())
        } else {
            Err(format!(
                "`systemctl start {unit}` failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            ))
        }
    }

    fn outcome(&self, unit: &str) -> Result<Outcome, String> {
        job::job_outcome(unit).map_err(|e| e.to_string())
    }

    fn journal(&self, units: &[String]) -> std::io::Result<tokio::process::Child> {
        let mut cmd = tokio::process::Command::new("journalctl");
        cmd.args(["--no-pager", "-o", "cat", "-n", "all", "-f"]);
        for u in units {
            cmd.args(["-u", u]);
        }
        cmd.stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
    }
}

/// Everything `conduct` is configured with.
pub struct Config {
    /// Where env files go (`/ci/keel/jobs`).
    pub jobs_dir: PathBuf,
    /// Repos jobs may be for (the module's `repos`).
    pub repos: Vec<String>,
    /// The Nix store path run for each phase, chosen by the operator; it is
    /// handed `<phase> <id> <repo> <revision> <slot>`.
    pub programs: HashMap<String, String>,
    /// PR slots per lane; the PR number picks one (a placeholder policy).
    pub slots: u32,
    /// Token hash to grant.
    pub grants: HashMap<String, Grant>,
    /// systemd, or a fake.
    pub units: Arc<dyn Units>,
}

impl Config {
    /// Checks what can be checked before serving: the programs and repos
    /// must pass the same validators the job unit applies.
    pub fn check(&self) -> Result<(), String> {
        for phase in PHASES {
            let p = self.programs.get(phase).ok_or_else(|| {
                format!("no --program {phase}=<store path>; the conductor needs one per phase")
            })?;
            job::validate_program(p).map_err(|e| e.to_string())?;
        }
        if self.repos.is_empty() {
            return Err(
                "no --repo given; the conductor starts jobs only for repos on an allow-list".into(),
            );
        }
        for r in &self.repos {
            job::validate_args(r)
                .map_err(|e| format!("repo `{r}` cannot be a job argument: {e}"))?;
        }
        if self.slots == 0 {
            return Err("--slots must be at least 1".into());
        }
        Ok(())
    }
}

#[derive(Default)]
struct State_ {
    stage: String,
    finished: bool,
    error: Option<String>,
    /// Phases whose blocking `systemctl start` returned success. This, not a
    /// later `systemctl show`, is the proof that a phase ran: systemd unloads
    /// a oneshot unit that ended well, and a unit that is not loaded shows
    /// `Result=success` and `ExecMainCode=0` exactly like one that never ran.
    completed: Vec<String>,
}

struct Job {
    id: String,
    repo: String,
    kind: Kind,
    revision: String,
    units: Vec<String>,
    state: Mutex<State_>,
    done: watch::Sender<bool>,
}

struct App {
    cfg: Config,
    jobs: Mutex<HashMap<String, Arc<Job>>>,
    counter: AtomicU64,
}

type Shared = State<Arc<App>>;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewJob {
    repo: String,
    revision: String,
    kind: Kind,
    #[serde(default)]
    pr: Option<u32>,
}

fn err(status: StatusCode, msg: impl Into<String>) -> Response {
    let body = serde_json::to_vec(&ErrorBody {
        error: msg.into(),
        kind: None,
    })
    .unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

fn ok_json<T: Serialize>(status: StatusCode, v: &T) -> Response {
    let body = serde_json::to_vec(v).unwrap_or_default();
    (status, [(header::CONTENT_TYPE, "application/json")], body).into_response()
}

/// The grant for the bearer token, or the 401 to send.
fn grant_for<'a>(app: &'a App, headers: &HeaderMap) -> Result<&'a Grant, Box<Response>> {
    let hash = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|v| v.strip_prefix("Bearer "))
        .map(|t| blake3::hash(t.as_bytes()).to_hex().to_string());
    hash.and_then(|h| app.cfg.grants.get(&h)).ok_or_else(|| {
        Box::new(err(
            StatusCode::UNAUTHORIZED,
            "job requests need the header `Authorization: Bearer <pipeline token>`; it was missing or not a known pipeline token",
        ))
    })
}

/// Writes `<jobs-dir>/<id>.env` through a temp file and a rename, mode 0640;
/// the directory is setgid `keel-jobs`, which gives the file its group.
fn write_env(dir: &Path, id: &str, program: &str, args: &str) -> Result<(), String> {
    let text = format!("KEEL_PROGRAM={program}\nKEEL_ARGS={args}\n");
    job::validate_env_file(&text)
        .map_err(|e| format!("refusing to write an invalid env file: {e}"))?;
    let (tmp, dest) = (
        dir.join(format!(".{id}.env.tmp")),
        dir.join(format!("{id}.env")),
    );
    let io =
        |what: &str, p: &Path, e: std::io::Error| format!("cannot {what} {}: {e}", p.display());
    fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o640)
        .open(&tmp)
        .and_then(|mut f| f.write_all(text.as_bytes()))
        .map_err(|e| io("write", &tmp, e))?;
    fs::rename(&tmp, &dest).map_err(|e| io("rename into place", &dest, e))
}

fn run_job(app: Arc<App>, job: Arc<Job>, slot: u32) {
    let set = |stage: &str, error: Option<String>, finished: bool| {
        if let Ok(mut s) = job.state.lock() {
            s.stage = stage.into();
            s.error = error;
            s.finished = finished;
        }
        if finished {
            // `send` stores nothing when no receiver exists yet, and a log
            // follower may only arrive later; `send_replace` always stores.
            job.done.send_replace(true);
        }
    };
    for (phase, unit) in PHASES.iter().zip(&job.units) {
        set(phase, None, false);
        let args = format!("{phase} {} {} {} {slot}", job.id, job.repo, job.revision);
        let program = &app.cfg.programs[*phase];
        let step = write_env(&app.cfg.jobs_dir, &job.id, program, &args)
            .and_then(|()| app.cfg.units.start(unit));
        if let Err(e) = step {
            set(phase, Some(e), true);
            return;
        }
        if let Ok(mut s) = job.state.lock() {
            s.completed.push((*phase).to_owned());
        }
    }
    set("done", None, true);
}

async fn post_job(State(app): Shared, headers: HeaderMap, body: Bytes) -> Response {
    let grant = match grant_for(&app, &headers) {
        Ok(g) => g,
        Err(r) => return *r,
    };
    let req: NewJob = match serde_json::from_slice(&body) {
        Ok(r) => r,
        Err(e) => {
            return err(
                StatusCode::BAD_REQUEST,
                format!(
                    "the body is not a job request ({e}); send {{\"repo\", \"revision\", \"kind\": \"pr\"|\"canonical\", \"pr\"}}"
                ),
            );
        }
    };
    if !app.cfg.repos.contains(&req.repo) {
        return err(
            StatusCode::BAD_REQUEST,
            format!("repo `{}` is not on the conductor's allow-list", req.repo),
        );
    }
    if grant.repo != req.repo || !grant.kinds.contains(&req.kind) {
        // Same answer for "other repo" and "other kind": nothing to probe.
        return err(
            StatusCode::FORBIDDEN,
            "this pipeline token may not start that job",
        );
    }
    if req.revision.len() != 40
        || !req
            .revision
            .bytes()
            .all(|b| matches!(b, b'0'..=b'9' | b'a'..=b'f'))
    {
        return err(
            StatusCode::BAD_REQUEST,
            "revision must be exactly 40 lowercase hex characters",
        );
    }
    let slot = match (req.kind, req.pr) {
        (Kind::Pr, Some(n)) => n % app.cfg.slots,
        (Kind::Pr, None) => {
            return err(
                StatusCode::BAD_REQUEST,
                "a pr job needs the pull request number in `pr`",
            );
        }
        (Kind::Canonical, _) => 0,
    };

    let nonce = (
        app.counter.fetch_add(1, Ordering::Relaxed),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_or(0, |d| d.as_nanos()),
        std::process::id(),
    );
    let id = format!(
        "j{}",
        &blake3::hash(format!("{nonce:?}{}", req.revision).as_bytes()).to_hex()[..16]
    );
    let units: Vec<String> = PHASES.iter().map(|p| req.kind.unit(p, &id)).collect();
    let job = Arc::new(Job {
        id: id.clone(),
        repo: req.repo,
        kind: req.kind,
        revision: req.revision,
        units: units.clone(),
        state: Mutex::new(State_ {
            stage: "queued".into(),
            ..State_::default()
        }),
        done: watch::channel(false).0,
    });
    if let Ok(mut jobs) = app.jobs.lock() {
        jobs.insert(id.clone(), Arc::clone(&job));
    }
    let app2 = Arc::clone(&app);
    tokio::task::spawn_blocking(move || run_job(app2, job, slot));
    ok_json(
        StatusCode::ACCEPTED,
        &serde_json::json!({ "id": id, "units": units }),
    )
}

/// The job, if `headers` carry a token for its repo. Anything else is a 404,
/// so a token cannot tell another repo's jobs from missing ones.
fn find_job(app: &App, headers: &HeaderMap, id: &str) -> Result<Arc<Job>, Box<Response>> {
    let grant = grant_for(app, headers)?;
    let job = app.jobs.lock().ok().and_then(|j| j.get(id).cloned());
    match job {
        Some(j) if j.repo == grant.repo => Ok(j),
        _ => Err(Box::new(err(
            StatusCode::NOT_FOUND,
            format!("no job `{id}` for this pipeline token"),
        ))),
    }
}

async fn get_job(State(app): Shared, headers: HeaderMap, UrlPath(id): UrlPath<String>) -> Response {
    let job = match find_job(&app, &headers, &id) {
        Ok(j) => j,
        Err(r) => return *r,
    };
    let (stage, finished, error, completed) = match job.state.lock() {
        Ok(s) => (
            s.stage.clone(),
            s.finished,
            s.error.clone(),
            s.completed.clone(),
        ),
        Err(_) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "job state is poisoned; restart the conductor",
            );
        }
    };
    // systemd is asked only about a phase that is running or has failed: it
    // keeps a failed unit loaded, so its Result and exit status are real. A
    // job that finished well has no unit left to ask (see `State_::completed`).
    let unit = if finished && error.is_none() {
        None
    } else {
        PHASES
            .iter()
            .position(|p| *p == stage)
            .and_then(|i| job.units.get(i))
    };
    let result = match (finished, &error) {
        (false, _) => "running",
        (true, None) => "success",
        (true, Some(_)) => "failed",
    };
    let outcome = unit.map(|u| {
        let units = Arc::clone(&app.cfg.units);
        let u = u.clone();
        tokio::task::spawn_blocking(move || units.outcome(&u))
    });
    let outcome = match outcome {
        Some(h) => h.await.ok().map(|r| r.map_err(|e| e.to_string())),
        None => None,
    };
    let (outcome, outcome_error) = match outcome {
        Some(Ok(o)) => (Some(o), None),
        Some(Err(e)) => (None, Some(e)),
        None => (None, None),
    };
    ok_json(
        StatusCode::OK,
        &serde_json::json!({
            "id": job.id, "repo": job.repo, "kind": job.kind, "revision": job.revision,
            "stage": stage, "finished": finished, "error": error,
            "result": result, "completed": completed,
            "outcome": outcome, "outcome_error": outcome_error,
        }),
    )
}

/// How long a log follower may see no output before the conductor closes it.
const LOG_IDLE_LIMIT: Duration = Duration::from_secs(15 * 60);

/// A body stream fed by a channel.
struct Chunks(mpsc::Receiver<std::io::Result<Bytes>>);

impl futures_core::Stream for Chunks {
    type Item = std::io::Result<Bytes>;
    fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Option<Self::Item>> {
        self.0.poll_recv(cx)
    }
}

async fn get_log(State(app): Shared, headers: HeaderMap, UrlPath(id): UrlPath<String>) -> Response {
    let job = match find_job(&app, &headers, &id) {
        Ok(j) => j,
        Err(r) => return *r,
    };
    let mut child = match app.cfg.units.journal(&job.units) {
        Ok(c) => c,
        Err(e) => {
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                format!(
                    "cannot follow the journal: {e}; the conductor's user must be in group systemd-journal and journalctl in its PATH"
                ),
            );
        }
    };
    let Some(mut stdout) = child.stdout.take() else {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            "journalctl gave no output pipe",
        );
    };
    let (tx, rx) = mpsc::channel(16);
    let mut done = job.done.subscribe();
    tokio::spawn(async move {
        let mut buf = vec![0u8; 8192];
        // A watch receiver only reports changes after it was created, so a job
        // that had already finished would never signal and the response would
        // never end (found by the VM test, run 974981). Read the value first.
        let mut finished_at: Option<tokio::time::Instant> =
            (*done.borrow_and_update()).then(tokio::time::Instant::now);
        loop {
            // A follower of a stuck job must not hold a connection forever.
            let idle = tokio::time::sleep(LOG_IDLE_LIMIT);
            // After the job ends, give the journal a moment to flush, then stop following.
            let grace = async {
                match finished_at {
                    Some(t) => tokio::time::sleep_until(t + Duration::from_secs(1)).await,
                    None => std::future::pending().await,
                }
            };
            tokio::select! {
                n = stdout.read(&mut buf) => match n {
                    Ok(0) | Err(_) => break,
                    Ok(n) => {
                        if tx.send(Ok(Bytes::copy_from_slice(&buf[..n]))).await.is_err() {
                            break; // the client went away
                        }
                    }
                },
                _ = done.changed(), if finished_at.is_none() => {
                    finished_at = Some(tokio::time::Instant::now());
                }
                () = grace => break,
                () = idle => break,
            }
        }
        let _ = child.kill().await;
    });
    (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        Body::from_stream(Chunks(rx)),
    )
        .into_response()
}

/// The conductor's router; fails if the configuration cannot work.
pub fn router(cfg: Config) -> Result<Router, String> {
    cfg.check()?;
    let app = Arc::new(App {
        cfg,
        jobs: Mutex::new(HashMap::new()),
        counter: AtomicU64::new(0),
    });
    Ok(Router::new()
        .route("/v1/jobs", post(post_job))
        .route("/v1/jobs/{id}", get(get_job))
        .route("/v1/jobs/{id}/log", get(get_log))
        .with_state(app))
}

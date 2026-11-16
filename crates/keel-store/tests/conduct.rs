//! The conductor skeleton against a fake systemd: who may start what, what
//! gets written and started, and that the outcome and log come back.

mod common;

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use axum::Router;
use common::TempDir;
use keel_store::conduct::{self, Config, Units, parse_grants};
use keel_store::job::{self, Outcome};

const PROG: &str = "/nix/store/0123456789abcdfghijklmnpqrsvwxyz-phase/bin/run";
const REV: &str = "7ab31d07ab31d07ab31d07ab31d07ab31d07ab31";

#[derive(Default)]
struct Fake {
    started: Mutex<Vec<String>>,
    fail_on: Option<&'static str>,
}

impl Units for Fake {
    fn start(&self, unit: &str) -> Result<(), String> {
        self.started.lock().unwrap().push(unit.to_owned());
        if self.fail_on.is_some_and(|f| unit.starts_with(f)) {
            return Err(format!("`systemctl start {unit}` failed: exit-code"));
        }
        Ok(())
    }
    fn outcome(&self, _unit: &str) -> Result<Outcome, String> {
        job::parse_show("Result=success\nExecMainCode=1\nExecMainStatus=0\nActiveState=inactive\n")
            .map_err(|e| e.to_string())
    }
    fn journal(&self, _units: &[String]) -> std::io::Result<tokio::process::Child> {
        // Like `journalctl -f`: prints what there is and then never exits, so
        // ending the response is the conductor's job.
        tokio::process::Command::new("sh")
            .args(["-c", "echo \"the job's log line\"; exec sleep 600"])
            .stdout(std::process::Stdio::piped())
            .kill_on_drop(true)
            .spawn()
    }
}

struct Rig {
    url: String,
    jobs: TempDir,
    fake: Arc<Fake>,
    _rt: std::thread::JoinHandle<()>,
    stop: Option<tokio::sync::oneshot::Sender<()>>,
}

impl Drop for Rig {
    fn drop(&mut self) {
        if let Some(s) = self.stop.take() {
            let _ = s.send(());
        }
    }
}

fn hash(token: &str) -> String {
    blake3::hash(token.as_bytes()).to_hex().to_string()
}

/// Two PR pipelines (repos A and B) and one canonical pipeline for A.
fn rig(fail_on: Option<&'static str>) -> Rig {
    let jobs = TempDir::new("conduct");
    let grants = parse_grants(
        &serde_json::json!({
            hash("pr-a"): {"repo": "Nudox/Backend", "kinds": ["pr"]},
            hash("pr-b"): {"repo": "Nudox/Other", "kinds": ["pr"]},
            hash("canon-a"): {"repo": "Nudox/Backend", "kinds": ["canonical"]},
        })
        .to_string(),
    )
    .unwrap();
    let fake = Arc::new(Fake {
        fail_on,
        ..Fake::default()
    });
    let app: Router = conduct::router(Config {
        jobs_dir: jobs.path().into(),
        repos: vec!["Nudox/Backend".into(), "Nudox/Other".into()],
        programs: ["fetch", "build", "test"]
            .map(|p| (p.to_owned(), PROG.to_owned()))
            .into(),
        slots: 3,
        grants,
        units: fake.clone(),
    })
    .unwrap();
    let (tx, rx) = std::sync::mpsc::channel();
    let (stop, stop_rx) = tokio::sync::oneshot::channel::<()>();
    let rt = std::thread::spawn(move || {
        tokio::runtime::Runtime::new().unwrap().block_on(async {
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            tx.send(l.local_addr().unwrap()).unwrap();
            let _ = keel_store::server::serve(l, app, async {
                let _ = stop_rx.await;
            })
            .await;
        });
    });
    Rig {
        url: format!("http://{}", rx.recv().unwrap()),
        jobs,
        fake,
        _rt: rt,
        stop: Some(stop),
    }
}

fn call(method: &str, url: &str, token: Option<&str>, body: &str) -> (u16, String) {
    let agent: ureq::Agent = ureq::Agent::config_builder()
        .http_status_as_error(false)
        .build()
        .into();
    let mut resp = if method == "POST" {
        let mut r = agent.post(url);
        if let Some(t) = token {
            r = r.header("Authorization", format!("Bearer {t}"));
        }
        r.send(body.as_bytes())
    } else {
        let mut r = agent.get(url);
        if let Some(t) = token {
            r = r.header("Authorization", format!("Bearer {t}"));
        }
        r.call()
    }
    .unwrap();
    (
        resp.status().as_u16(),
        resp.body_mut().read_to_string().unwrap(),
    )
}

fn post(rig: &Rig, token: Option<&str>, body: serde_json::Value) -> (u16, serde_json::Value) {
    let (s, text) = call(
        "POST",
        &format!("{}/v1/jobs", rig.url),
        token,
        &body.to_string(),
    );
    (
        s,
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null),
    )
}

fn pr(repo: &str) -> serde_json::Value {
    serde_json::json!({"repo": repo, "revision": REV, "kind": "pr", "pr": 132})
}

fn wait_finished(rig: &Rig, token: &str, id: &str) -> serde_json::Value {
    let start = Instant::now();
    loop {
        let (s, text) = call("GET", &format!("{}/v1/jobs/{id}", rig.url), Some(token), "");
        assert_eq!(s, 200, "{text}");
        let v: serde_json::Value = serde_json::from_str(&text).unwrap();
        if v["finished"] == true {
            return v;
        }
        assert!(
            start.elapsed() < Duration::from_secs(10),
            "job never finished: {text}"
        );
        std::thread::sleep(Duration::from_millis(20));
    }
}

#[test]
fn a_valid_pr_job_runs_fetch_build_test_in_order_with_a_validated_env_file() {
    let rig = rig(None);
    let (status, v) = post(&rig, Some("pr-a"), pr("Nudox/Backend"));
    assert_eq!(status, 202, "{v}");
    let id = v["id"].as_str().unwrap().to_owned();
    job::validate_name(&id).unwrap();

    let done = wait_finished(&rig, "pr-a", &id);
    assert_eq!(done["stage"], "done");
    assert_eq!(done["result"], "success", "{done}");
    assert_eq!(
        done["completed"],
        serde_json::json!(["fetch", "build", "test"]),
        "every phase is proven by its own start returning: {done}"
    );
    assert!(done["outcome"].is_null(), "no unit is left to ask: {done}");
    assert_eq!(
        *rig.fake.started.lock().unwrap(),
        ["fetch", "build", "test"].map(|p| format!("keel-{p}@{id}.service"))
    );
    let env = std::fs::read_to_string(rig.jobs.path().join(format!("{id}.env"))).unwrap();
    job::validate_env_file(&env).unwrap();
    assert!(
        env.contains(&format!("KEEL_ARGS=test {id} Nudox/Backend {REV} 0")),
        "132 % 3 = 0: {env}"
    );
    let mode = std::os::unix::fs::PermissionsExt::mode(
        &std::fs::metadata(rig.jobs.path().join(format!("{id}.env")))
            .unwrap()
            .permissions(),
    );
    assert_eq!(mode & 0o777, 0o640);

    // The log endpoint returns the journal's bytes, and ends with the job.
    let asked = std::time::Instant::now();
    let (s, log) = call(
        "GET",
        &format!("{}/v1/jobs/{id}/log", rig.url),
        Some("pr-a"),
        "",
    );
    assert_eq!((s, log.trim()), (200, "the job's log line"));
    assert!(
        asked.elapsed() < std::time::Duration::from_secs(5),
        "the log of a finished job must end by itself, took {:?}",
        asked.elapsed()
    );
}

#[test]
fn a_pr_token_cannot_start_canonical_jobs_or_jobs_for_another_repo() {
    let rig = rig(None);
    let canonical =
        serde_json::json!({"repo": "Nudox/Backend", "revision": REV, "kind": "canonical"});
    assert_eq!(post(&rig, Some("pr-a"), canonical.clone()).0, 403);
    assert_eq!(
        post(&rig, Some("pr-a"), pr("Nudox/Other")).0,
        403,
        "repo B with A's token"
    );
    assert_eq!(
        post(&rig, Some("canon-a"), pr("Nudox/Backend")).0,
        403,
        "canonical token, pr job"
    );
    assert_eq!(post(&rig, None, pr("Nudox/Backend")).0, 401);
    assert_eq!(post(&rig, Some("guess"), pr("Nudox/Backend")).0, 401);
    assert_eq!(
        post(&rig, Some("pr-a"), pr("Nudox/Unlisted")).0,
        400,
        "not on the allow-list"
    );
    let mut bad_rev = pr("Nudox/Backend");
    bad_rev["revision"] = "main".into();
    assert_eq!(post(&rig, Some("pr-a"), bad_rev).0, 400);
    let mut no_pr = pr("Nudox/Backend");
    no_pr.as_object_mut().unwrap().remove("pr");
    assert_eq!(post(&rig, Some("pr-a"), no_pr).0, 400);
    let mut extra = pr("Nudox/Backend");
    extra["branch"] = "feature/x".into();
    assert_eq!(
        post(&rig, Some("pr-a"), extra).0,
        400,
        "forge text has no field to ride in"
    );

    assert!(
        rig.fake.started.lock().unwrap().is_empty(),
        "nothing was started"
    );
    assert_eq!(
        std::fs::read_dir(rig.jobs.path()).unwrap().count(),
        0,
        "nothing was written"
    );
}

#[test]
fn canonical_jobs_use_the_canon_units_and_other_repos_cannot_see_a_job() {
    let rig = rig(None);
    let canonical =
        serde_json::json!({"repo": "Nudox/Backend", "revision": REV, "kind": "canonical"});
    let (status, v) = post(&rig, Some("canon-a"), canonical);
    assert_eq!(status, 202, "{v}");
    let id = v["id"].as_str().unwrap();
    wait_finished(&rig, "canon-a", id);
    assert_eq!(
        *rig.fake.started.lock().unwrap(),
        ["fetch", "build", "test"].map(|p| format!("keel-canon-{p}@{id}.service"))
    );
    for t in ["pr-b", "guess"] {
        let (s, _) = call("GET", &format!("{}/v1/jobs/{id}", rig.url), Some(t), "");
        assert_eq!(s, if t == "pr-b" { 404 } else { 401 });
        let (s, _) = call("GET", &format!("{}/v1/jobs/{id}/log", rig.url), Some(t), "");
        assert_eq!(s, if t == "pr-b" { 404 } else { 401 });
    }
}

#[test]
fn a_failed_phase_stops_the_sequence_and_is_reported() {
    let rig = rig(Some("keel-build@"));
    let (_, v) = post(&rig, Some("pr-a"), pr("Nudox/Backend"));
    let id = v["id"].as_str().unwrap();
    let done = wait_finished(&rig, "pr-a", id);
    assert_eq!(done["stage"], "build");
    assert!(
        done["error"].as_str().unwrap().contains("keel-build@"),
        "{done}"
    );
    let started = rig.fake.started.lock().unwrap();
    assert_eq!(started.len(), 2, "test never ran: {started:?}");
}

#[test]
fn configuration_and_grants_are_checked_up_front() {
    let bad_hash = parse_grants(r#"{"short": {"repo": "a", "kinds": ["pr"]}}"#).unwrap_err();
    assert!(bad_hash.contains("blake3"), "{bad_hash}");
    assert!(parse_grants(r#"{"x": 1}"#).is_err());
    let cfg = |programs: HashMap<String, String>, repos: Vec<String>| Config {
        jobs_dir: ".".into(),
        repos,
        programs,
        slots: 3,
        grants: HashMap::new(),
        units: Arc::new(Fake::default()),
    };
    let all: HashMap<_, _> = ["fetch", "build", "test"]
        .map(|p| (p.to_owned(), PROG.to_owned()))
        .into();
    assert!(conduct::router(cfg(all.clone(), vec!["Nudox/Backend".into()])).is_ok());
    assert!(
        conduct::router(cfg(all.clone(), vec![])).is_err(),
        "no repos"
    );
    assert!(
        conduct::router(cfg(all.clone(), vec!["--evil".into()])).is_err(),
        "repo must be a safe word"
    );
    let mut shell = all.clone();
    shell.insert("build".into(), "/bin/sh".into());
    assert!(conduct::router(cfg(shell, vec!["Nudox/Backend".into()])).is_err());
    let mut missing = all;
    missing.remove("test");
    assert!(conduct::router(cfg(missing, vec!["Nudox/Backend".into()])).is_err());
}

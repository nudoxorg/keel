//! End to end: the real `keel-judge` binary supervising `keel-judge-test-target`.

use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use serde_json::{Value, json};

const JUDGE: &str = env!("CARGO_BIN_EXE_keel-judge");
const TEST_TARGET: &str = env!("CARGO_BIN_EXE_keel-judge-test-target");

struct Spec<'a> {
    id: &'a str,
    rank: u64,
    start_order: u64,
    argv0: String,
    flags: Vec<&'a str>,
}

fn write_targets(root: &Path, specs: &[Spec<'_>]) -> PathBuf {
    let targets: Vec<Value> = specs
        .iter()
        .map(|s| {
            let dir = root.join("durable").join(s.id);
            std::fs::create_dir_all(&dir).unwrap();
            let corpus = dir.join("corpus").display().to_string();
            let mut argv = vec![s.argv0.clone(), corpus.clone(), "-print_final_stats=1".to_string()];
            argv.extend(s.flags.iter().map(|f| f.to_string()));
            json!({"id": s.id, "name": s.id, "rank": s.rank, "start_order": s.start_order, "argv": argv, "corpus": corpus,
                   "artifacts": dir.join("artifacts").display().to_string()})
        })
        .collect();
    let path = root.join("targets.json");
    std::fs::write(&path, json!({"schema": "keel.judge.targets.v1", "source": "test", "targets": targets}).to_string()).unwrap();
    path
}

/// Returns what the run wrote to stderr. Every run here passes `--min-free-gib 0`: with the
/// default of 5 GiB a machine short of disk turned each quantum into a 60 s disk wait, and
/// the tests hung or failed for a reason that was the host's, not the supervisor's.
fn run_judge(root: &Path, targets: &Path, extra: &[&str]) -> String {
    let out = Command::new(JUDGE)
        .args(["run", "--min-free-gib", "0", "--targets"])
        .arg(targets)
        .arg("--state")
        .arg(root.join("state"))
        .args(extra)
        .output()
        .unwrap();
    let err = String::from_utf8_lossy(&out.stderr).into_owned();
    assert!(out.status.success(), "keel-judge run failed: {err}");
    err
}

fn lines(path: &Path) -> Vec<Value> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .map(|l| serde_json::from_str(l).unwrap_or_else(|e| panic!("{} has an unparseable line {l:?}: {e}", path.display())))
        .collect()
}

fn quanta(root: &Path) -> Vec<Value> {
    lines(&root.join("state/quanta.jsonl"))
}

fn findings(root: &Path) -> Vec<Value> {
    lines(&root.join("state/findings.jsonl"))
}

fn status_json(root: &Path, targets: &Path) -> Value {
    let out = Command::new(JUDGE).args(["status", "--json", "--targets"]).arg(targets).arg("--state").arg(root.join("state")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    serde_json::from_slice(&out.stdout).unwrap()
}

fn count(records: &[Value], target: &str) -> usize {
    records.iter().filter(|r| r["target"] == target).count()
}

/// What the Nix wrapper script is: a file whose bytes change when the engine path does.
fn wrapper(root: &Path, name: &str, build: u32) -> String {
    let path = root.join(name);
    std::fs::write(&path, format!("#!/bin/sh\n# build {build}\nexec {TEST_TARGET} \"$@\"\n")).unwrap();
    std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o755)).unwrap();
    path.display().to_string()
}

#[test]
fn twelve_quanta_over_three_targets() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let specs = [
        Spec { id: "zero", rank: 0, start_order: 1, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] },
        Spec { id: "hot", rank: 1000, start_order: 2, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] },
        Spec { id: "crashy", rank: 500, start_order: 3, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_crash_after=0.5"] },
    ];
    let targets = write_targets(root, &specs);
    run_judge(root, &targets, &["--workers", "2", "--quantum", "1s", "--quanta", "12", "--starve-every", "4"]);

    let q = quanta(root);
    assert_eq!(q.len(), 12);
    assert!(q.iter().any(|r| r["target"] == "zero" && r["chosen_by"] == "starved"), "rank 0 was never starved in: {q:#?}");

    let f = findings(root);
    assert_eq!(f.len(), 1, "{f:#?}");
    assert_eq!((f[0]["target"].as_str(), f[0]["kind"].as_str(), f[0]["source"].as_str()), (Some("crashy"), Some("rust-panic"), Some("panic")));
    assert_eq!(count(&q, "crashy"), 1, "a blocked target was chosen again");
    let crash = q.iter().find(|r| r["target"] == "crashy").unwrap();
    assert_eq!((crash["outcome"].as_str(), crash["finding"].as_str()), (Some("crash"), f[0]["key"].as_str()));
    assert!(Path::new(f[0]["input"].as_str().unwrap()).is_file());
    assert!(!root.join("durable/crashy/artifacts").read_dir().unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("crash-")));

    for r in &q {
        assert_eq!(r["schema"], "keel.judge.quantum.v1");
        assert!(Path::new(r["log"].as_str().unwrap()).is_file());
        assert!(r["rate"].as_f64().unwrap() > 0.0);
    }
    assert!(q.iter().any(|r| r["target"] == "hot" && r["delta_ft"].as_u64().unwrap() > 0 && r["stopped_by"] == "deadline" && r["exit"]["code"] == 72));

    let s = status_json(root, &targets);
    assert_eq!(s["totals"]["quanta"], 12);
    let seconds: f64 = q.iter().map(|r| r["seconds"].as_f64().unwrap()).sum();
    assert!((s["totals"]["seconds"].as_f64().unwrap() - seconds).abs() < 1e-6);
    let execs: u64 = q.iter().map(|r| r["execs"].as_u64().unwrap_or(0)).sum();
    assert_eq!(s["totals"]["execs"].as_u64().unwrap(), execs);
    let rows = s["targets"].as_array().unwrap();
    for t in ["zero", "hot", "crashy"] {
        let row = rows.iter().find(|r| r["id"] == t).unwrap();
        assert_eq!(row["quanta"].as_u64().unwrap() as usize, count(&q, t));
    }
    assert_eq!(rows.iter().find(|r| r["id"] == "crashy").unwrap()["open_findings"], 1);
    assert_eq!(s["findings"].as_array().unwrap().len(), 1);

    let table = Command::new(JUDGE).args(["status", "--state"]).arg(root.join("state")).output().unwrap();
    let table = String::from_utf8_lossy(&table.stdout);
    assert!(table.contains("crashy") && table.contains(f[0]["key"].as_str().unwrap()), "{table}");
}

#[test]
fn a_new_build_makes_a_blocked_target_eligible_again() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let spec = |build: u32| {
        let crashy = wrapper(root, "crashy-bin", build);
        let steady = wrapper(root, "steady-bin", 1);
        write_targets(
            root,
            &[
                Spec { id: "crashy", rank: 1000, start_order: 1, argv0: crashy, flags: vec!["-keel_test_crash_after=0.5"] },
                Spec { id: "steady", rank: 1, start_order: 2, argv0: steady, flags: vec!["-keel_test_rate=5"] },
            ],
        )
    };

    run_judge(root, &spec(1), &["--quantum", "1s", "--quanta", "3"]);
    let q = quanta(root);
    assert_eq!((count(&q, "crashy"), count(&q, "steady")), (1, 2));
    let first_identity = q[0]["identity"].as_str().unwrap().to_string();

    // The same file path, new bytes: what a rebuilt bundle looks like to the supervisor.
    run_judge(root, &spec(2), &["--quantum", "1s", "--quanta", "2"]);
    let q = quanta(root);
    assert_eq!(q.len(), 5);
    assert_eq!(q[3]["target"], "crashy", "{q:#?}");
    assert_ne!(q[3]["identity"].as_str().unwrap(), first_identity);
    assert_eq!(q[4]["target"], "steady", "the crashy target must be blocked again under its new identity");

    let f = findings(root);
    assert_eq!(f.len(), 2);
    assert_eq!(f[0]["key"], f[1]["key"]);
    assert!(f[0]["first_seen"].is_string() && f[1]["seen_again"].is_string() && f[1]["first_seen"].is_null());
    assert_ne!(f[0]["identity"], f[1]["identity"]);
    let dir = root.join("state/findings/crashy").join(f[0]["key"].as_str().unwrap());
    assert_eq!(dir.read_dir().unwrap().filter(|e| e.as_ref().unwrap().file_name().to_string_lossy().starts_with("input-")).count(), 1);
    assert!(dir.join("stderr.txt").is_file());
}

#[test]
fn sigterm_stops_the_target_and_records_a_partial_quantum() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let targets = write_targets(root, &[Spec { id: "hot", rank: 1, start_order: 1, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] }]);
    let mut child = Command::new(JUDGE)
        .args(["run", "--min-free-gib", "0", "--quantum", "30s", "--targets"])
        .arg(&targets)
        .arg("--state")
        .arg(root.join("state"))
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    // Long enough for the target to be running; the state lock appears at start.
    let up = Instant::now();
    while !root.join("durable/hot/corpus").is_dir() && up.elapsed() < Duration::from_secs(10) {
        std::thread::sleep(Duration::from_millis(50));
    }
    std::thread::sleep(Duration::from_millis(1000));
    unsafe {
        libc::kill(child.id() as i32, libc::SIGTERM);
    }
    let deadline = Instant::now() + Duration::from_secs(20);
    let status = loop {
        if let Some(s) = child.try_wait().unwrap() {
            break s;
        }
        if Instant::now() > deadline {
            child.kill().unwrap();
            panic!("keel-judge did not stop within 20 s of SIGTERM");
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    assert!(status.success(), "{status:?}");
    let q = quanta(root);
    assert_eq!(q.len(), 1);
    assert_eq!(q[0]["stopped_by"], "supervisor");
    assert!(q[0]["seconds"].as_f64().unwrap() < 10.0);
    assert_eq!(q[0]["exit"]["code"], 72);
}

#[test]
fn an_unwritable_durable_root_is_reported_with_what_to_do() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let targets = write_targets(root, &[Spec { id: "x", rank: 1, start_order: 1, argv0: TEST_TARGET.into(), flags: vec![] }]);
    // The target's own directory is made on a fresh host; the root above it never is.
    // --quanta bounds the run, so a supervisor that wrongly starts ends instead of hanging the suite.
    std::fs::remove_dir_all(root.join("durable")).unwrap();
    let out = Command::new(JUDGE).args(["run", "--min-free-gib", "0", "--quanta", "1", "--quantum", "1s", "--targets"]).arg(&targets).arg("--state").arg(root.join("state")).output().unwrap();
    assert!(!out.status.success());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("corpus of target x") && err.contains("durable root") && err.contains("--durable-root"), "{err}");
}

#[test]
fn a_target_whose_artifacts_directory_is_replaced_mid_run_faults_alone() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    // On its first quantum `bad` removes its own artifacts directory and puts a file in its
    // place, as someone clearing a disk by hand might; the scan after the quantum then fails.
    let artifacts = root.join("durable/bad/artifacts");
    let bad = root.join("bad-bin");
    std::fs::create_dir_all(root.join("durable/bad")).unwrap();
    std::fs::write(&bad, format!("#!/bin/sh\ncd /\nrm -rf '{0}'\n: > '{0}'\nexec {TEST_TARGET} \"$@\"\n", artifacts.display())).unwrap();
    std::fs::set_permissions(&bad, std::fs::Permissions::from_mode(0o755)).unwrap();
    let specs = [
        Spec { id: "bad", rank: 1000, start_order: 1, argv0: bad.display().to_string(), flags: vec![] },
        Spec { id: "good", rank: 1, start_order: 2, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] },
    ];
    let targets = write_targets(root, &specs);
    let err = run_judge(root, &targets, &["--workers", "2", "--quantum", "1s", "--quanta", "4"]);

    let q = quanta(root);
    assert_eq!((q.len(), count(&q, "good")), (4, 4), "{q:#?}");
    assert!(err.contains("target bad faulted") && err.contains("artifacts") && err.contains("skipping it for 1 s"), "{err}");
    // It is tried again after its wait and found broken again, with a longer wait: it
    // never goes back to being claimed forever.
    assert!(err.matches("target bad faulted").count() >= 2 && err.contains("skipping it for 2 s"), "{err}");
}

#[test]
fn a_target_with_an_unusable_directory_at_startup_starts_faulted() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let specs = [
        Spec { id: "bad", rank: 1000, start_order: 1, argv0: TEST_TARGET.into(), flags: vec![] },
        Spec { id: "good", rank: 1, start_order: 2, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] },
    ];
    let targets = write_targets(root, &specs);
    // A file where `bad`'s corpus directory belongs.
    std::fs::write(root.join("durable/bad/corpus"), "").unwrap();
    let prom = root.join("m.prom");
    let err = run_judge(root, &targets, &["--quantum", "1s", "--quanta", "2", "--metrics", prom.to_str().unwrap()]);
    let q = quanta(root);
    assert_eq!((q.len(), count(&q, "good")), (2, 2), "{q:#?}");
    assert!(err.contains("target bad cannot run yet") && err.contains("corpus of target bad") && err.contains("trying it again in 1 s"), "{err}");
    // What the dashboard and the KeelJudgeTargetFaulted alert read.
    let text = std::fs::read_to_string(&prom).unwrap();
    assert!(sample(&text, "keel_judge_target_faults_total{target=\"bad\"}").is_some_and(|v| v >= 1.0), "{text}");
    assert_eq!(sample(&text, "keel_judge_target_faults_total{target=\"good\"}"), Some(0.0), "{text}");
}

/// The value of one sample line of an exposition text.
fn sample(text: &str, series: &str) -> Option<f64> {
    text.lines().find_map(|l| l.strip_prefix(series)?.strip_prefix(' ')?.parse().ok())
}

#[test]
fn a_damaged_line_in_a_log_is_moved_aside_at_start_and_status_only_reports_it() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let targets = write_targets(root, &[Spec { id: "hot", rank: 1, start_order: 1, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] }]);
    std::fs::create_dir_all(root.join("state")).unwrap();
    let log = root.join("state/quanta.jsonl");
    std::fs::write(&log, "{broken\n").unwrap();

    let out = Command::new(JUDGE).args(["status", "--state"]).arg(root.join("state")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert!(String::from_utf8_lossy(&out.stdout).contains("WARNING"), "{}", String::from_utf8_lossy(&out.stdout));
    assert_eq!(std::fs::read_to_string(&log).unwrap(), "{broken\n", "status must not modify the log");

    let prom = root.join("m.prom");
    let err = run_judge(root, &targets, &["--quantum", "1s", "--quanta", "1", "--metrics", prom.to_str().unwrap()]);
    assert!(err.contains("1 damaged line") && err.contains("quanta.jsonl.damaged-"), "{err}");
    // What the KeelJudgeStateDamaged alert reads.
    assert_eq!(sample(&std::fs::read_to_string(&prom).unwrap(), "keel_judge_state_damaged_lines"), Some(1.0));
    let kept: Vec<_> = root.join("state").read_dir().unwrap().flatten().filter(|e| e.file_name().to_string_lossy().starts_with("quanta.jsonl.damaged-")).collect();
    assert_eq!(kept.len(), 1);
    assert_eq!(std::fs::read_to_string(kept[0].path()).unwrap(), "{broken\n");
    assert_eq!(quanta(root).len(), 1);
}

#[test]
fn the_service_manager_hears_ready_the_heartbeat_and_stopping() {
    use std::os::unix::net::UnixDatagram;
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let targets = write_targets(root, &[Spec { id: "hot", rank: 1, start_order: 1, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] }]);
    let sock = root.join("notify.sock");
    let listener = UnixDatagram::bind(&sock).unwrap();
    listener.set_read_timeout(Some(Duration::from_millis(200))).unwrap();
    // The watchdog variables only count for the process they name, so the shell names itself and execs.
    let out = Command::new("/bin/sh")
        .args(["-c", "WATCHDOG_PID=$$ exec \"$0\" \"$@\"", JUDGE, "run", "--min-free-gib", "0", "--quantum", "1s", "--quanta", "2", "--targets"])
        .arg(&targets)
        .arg("--state")
        .arg(root.join("state"))
        .env("NOTIFY_SOCKET", &sock)
        .env("WATCHDOG_USEC", "400000")
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let (mut heard, mut buf) = (Vec::new(), [0u8; 256]);
    while let Ok(n) = listener.recv(&mut buf) {
        heard.push(String::from_utf8_lossy(&buf[..n]).trim_end().to_string());
    }
    assert_eq!(heard.first().map(String::as_str), Some("READY=1"), "{heard:?}");
    assert_eq!(heard.last().map(String::as_str), Some("STOPPING=1"), "{heard:?}");
    // Every 0.2 s for the two seconds of quanta, less slack.
    assert!(heard.iter().filter(|m| *m == "WATCHDOG=1").count() >= 3, "{heard:?}");
}

#[test]
fn the_metrics_file_follows_the_run_and_status_prints_the_same_families() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let targets = write_targets(root, &[Spec { id: "hot", rank: 1000, start_order: 1, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] }]);
    let prom = root.join("m.prom");
    run_judge(root, &targets, &["--quantum", "1s", "--quanta", "2", "--metrics", prom.to_str().unwrap()]);

    let text = std::fs::read_to_string(&prom).unwrap();
    assert!(text.contains("keel_judge_quanta_total 2\n"), "{text}");
    assert!(text.contains("keel_judge_target_outcomes_total{target=\"hot\",outcome=\"ok\"} 2\n"), "{text}");
    assert!(text.contains("keel_judge_target_chosen_total{target=\"hot\",chosen_by=\"cold\"} 1\n"), "{text}");
    assert!(text.contains("keel_judge_workers_busy 0\n") && text.contains("keel_judge_workers 1\n"), "{text}");
    assert!(text.contains("keel_judge_target_blocked{target=\"hot\"} 0\n") && text.contains("keel_judge_target_rank{target=\"hot\"} 1000\n"), "{text}");
    assert!(text.contains("\nkeel_judge_start_time_seconds "), "{text}");
    assert!(!root.join("m.prom.tmp").exists());

    let out = Command::new(JUDGE).args(["status", "--prometheus", "--targets"]).arg(&targets).arg("--state").arg(root.join("state")).output().unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let from_logs = String::from_utf8(out.stdout).unwrap();
    assert!(from_logs.contains("keel_judge_quanta_total 2\n") && from_logs.contains("keel_judge_target_outcomes_total{target=\"hot\",outcome=\"ok\"} 2\n"), "{from_logs}");
    // Not the supervisor, so it has no start time and cannot say whether the binary is blocked.
    assert!(!from_logs.contains("\nkeel_judge_start_time_seconds ") && !from_logs.contains("\nkeel_judge_target_blocked{"), "{from_logs}");
    let families = |t: &str| t.lines().filter(|l| l.starts_with("# TYPE ")).map(str::to_string).collect::<Vec<_>>();
    assert_eq!(families(&text), families(&from_logs));
}

#[test]
fn an_unwritable_metrics_file_is_one_note_and_does_not_stop_the_run() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let targets = write_targets(root, &[Spec { id: "hot", rank: 1, start_order: 1, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] }]);
    let prom = root.join("no-such-directory/m.prom");
    let out = Command::new(JUDGE)
        .args(["run", "--min-free-gib", "0", "--quantum", "1s", "--quanta", "2", "--targets"])
        .arg(&targets)
        .arg("--state")
        .arg(root.join("state"))
        .arg("--metrics")
        .arg(&prom)
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    assert_eq!(quanta(root).len(), 2);
    // Four attempts (start, two quanta, end); the note is made once.
    let err = String::from_utf8_lossy(&out.stderr);
    assert_eq!(err.matches("cannot write").count(), 1, "{err}");
    assert!(err.contains(&prom.display().to_string()) && err.contains("--metrics"), "{err}");
}

/// What `keel-judge expect` printed and how it exited.
struct Expected {
    code: i32,
    stdout: String,
    stderr: String,
}

fn expect(root: &Path, spec: &Value, args: &[&str]) -> Expected {
    let path = root.join("spec.json");
    std::fs::write(&path, spec.to_string()).unwrap();
    let out = Command::new(JUDGE).args(["expect", "--spec"]).arg(&path).args(args).output().unwrap();
    Expected { code: out.status.code().unwrap(), stdout: String::from_utf8_lossy(&out.stdout).into_owned(), stderr: String::from_utf8_lossy(&out.stderr).into_owned() }
}

fn spec(expectations: Value) -> Value {
    json!({"schema": "keel.judge.expect.v1", "expectations": expectations})
}

#[test]
fn expect_checks_the_metrics_file_and_the_logs_against_one_spec() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let targets = write_targets(root, &[Spec { id: "hot", rank: 1000, start_order: 1, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] }]);
    let prom = root.join("m.prom");
    let prom_arg = prom.to_str().unwrap();
    run_judge(root, &targets, &["--quantum", "1s", "--quanta", "2", "--metrics", prom_arg]);
    let state = root.join("state");
    let state_arg = state.to_str().unwrap();

    let healthy = spec(json!([
        {"name": "two-quanta", "metric": "keel_judge_quanta_total", "op": "==", "value": 2, "why": "the run was asked for two"},
        {"name": "hot-cold", "metric": "keel_judge_target_chosen_total", "labels": {"target": "hot", "chosen_by": "cold"}, "op": "==", "value": 1, "why": "the first quantum of a target is cold"},
        {"name": "no-laws", "metric": "keel_judge_target_quanta_total", "labels": {"target": "laws"}, "op": "absent", "why": "unscheduled rows never run"},
        {"name": "not-blocked", "metric": "keel_judge_target_blocked", "labels": {"target": "hot"}, "op": "==", "value": 0, "why": "no finding, so nothing holds it back"},
        {"name": "fresh", "metric": "keel_judge_metrics_written_timestamp_seconds", "op": "age_below", "value": 600, "why": "the run has just ended"},
        {"name": "no-faults", "metric": "keel_judge_target_faulted", "op": "==", "value": 0, "why": "nothing went wrong in the supervisor"},
    ]));
    let ok = expect(root, &healthy, &["--metrics", prom_arg]);
    assert_eq!((ok.code, ok.stderr.as_str()), (0, ""), "{}", ok.stdout);
    let lines: Vec<&str> = ok.stdout.lines().collect();
    assert_eq!(lines.len(), 6, "{lines:?}");
    assert_eq!(lines[0], "ok   two-quanta: keel_judge_quanta_total = 2 (== 2)");
    assert_eq!(lines[1], "ok   hot-cold: keel_judge_target_chosen_total{chosen_by=\"cold\",target=\"hot\"} = 1 (== 1)");
    assert_eq!(lines[2], "ok   no-laws: keel_judge_target_quanta_total{target=\"laws\"} = absent (absent)");
    assert_eq!(lines[3], "ok   not-blocked: keel_judge_target_blocked{target=\"hot\"} = 0 (== 0)");
    assert!(lines[4].starts_with("ok   fresh: keel_judge_metrics_written_timestamp_seconds = ") && lines[4].ends_with("(age_below 600)"), "{lines:?}");

    let broken = spec(json!([
        {"name": "five-quanta", "metric": "keel_judge_target_quanta_total", "labels": {"target": "hot"}, "op": "==", "value": 5, "why": "a target that is not held back runs every quantum"},
        {"name": "two-quanta", "metric": "keel_judge_quanta_total", "op": "==", "value": 2, "why": "the run was asked for two"},
    ]));
    let bad = expect(root, &broken, &["--metrics", prom_arg]);
    assert_eq!(bad.code, 1, "{}", bad.stdout);
    assert_eq!(
        bad.stdout,
        "FAIL five-quanta: keel_judge_target_quanta_total{target=\"hot\"} is 2, expected == 5, after 0 s; a target that is not held back runs every quantum\n\
         ok   two-quanta: keel_judge_quanta_total = 2 (== 2)\n"
    );

    // The same spec from the logs. They cannot say whether the binary is blocked, so that
    // series is absent there and the one expectation that needs it says so.
    let from_logs = expect(root, &healthy, &["--state", state_arg, "--targets", targets.to_str().unwrap()]);
    assert_eq!(from_logs.code, 1, "{}", from_logs.stdout);
    assert!(from_logs.stdout.contains("FAIL not-blocked: keel_judge_target_blocked{target=\"hot\"} is absent, expected == 0, after 0 s;"), "{}", from_logs.stdout);
    assert_eq!(from_logs.stdout.lines().filter(|l| l.starts_with("ok   ")).count(), 5, "{}", from_logs.stdout);
    let logs_only = spec(json!([
        {"name": "two-quanta", "metric": "keel_judge_quanta_total", "op": "==", "value": 2, "why": "the logs hold the run"},
        {"name": "hot-two", "metric": "keel_judge_target_quanta_total", "labels": {"target": "hot"}, "op": ">=", "value": 2, "why": "the target ran in both"},
        {"name": "unknown-blocked", "metric": "keel_judge_target_blocked", "op": "absent", "why": "the logs cannot know"},
    ]));
    let ok = expect(root, &logs_only, &["--state", state_arg]);
    assert_eq!((ok.code, ok.stdout.lines().count()), (0, 3), "{}", ok.stdout);

    let nowhere = expect(root, &logs_only, &["--state", root.join("no-such-state").to_str().unwrap()]);
    assert_eq!(nowhere.code, 1);
    assert!(nowhere.stdout.contains("no-such-state") && nowhere.stdout.contains("FAIL two-quanta: keel_judge_quanta_total is unreadable"), "{}", nowhere.stdout);
}

#[test]
fn expect_waits_for_a_file_and_sees_the_counter_rise() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let targets = write_targets(root, &[Spec { id: "hot", rank: 1, start_order: 1, argv0: TEST_TARGET.into(), flags: vec!["-keel_test_rate=5"] }]);
    let prom = root.join("m.prom");
    let prom_arg = prom.to_str().unwrap();
    let healthy = spec(json!([
        {"name": "alive", "metric": "keel_judge_metrics_written_timestamp_seconds", "op": "age_below", "value": 60, "why": "written lately"},
        {"name": "moving", "metric": "keel_judge_quanta_total", "op": "increases", "why": "a quantum ends while this waits"},
    ]));
    // Nothing has written the file: retried for the whole window, then failed naming the path.
    let early = expect(root, &healthy, &["--within", "1s", "--every", "100ms", "--metrics", prom_arg]);
    assert_eq!(early.code, 1, "{}", early.stdout);
    assert!(early.stdout.contains(&format!("cannot read {prom_arg}")), "{}", early.stdout);
    assert!(early.stdout.contains("FAIL alive: keel_judge_metrics_written_timestamp_seconds is unreadable"), "{}", early.stdout);

    let mut judge = Command::new(JUDGE)
        .args(["run", "--min-free-gib", "0", "--quantum", "1s", "--quanta", "3", "--targets"])
        .arg(&targets)
        .arg("--state")
        .arg(root.join("state"))
        .arg("--metrics")
        .arg(&prom)
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let seen = expect(root, &healthy, &["--within", "30s", "--every", "100ms", "--metrics", prom_arg]);
    assert!(judge.wait().unwrap().success());
    assert_eq!((seen.code, seen.stderr.as_str()), (0, ""), "{}", seen.stdout);
    assert!(seen.stdout.contains("ok   moving: keel_judge_quanta_total = ") && seen.stdout.contains("(increases)"), "{}", seen.stdout);
}

#[test]
fn expect_refuses_a_spec_it_cannot_use_with_status_two() {
    let tmp = tempfile::tempdir().unwrap();
    let root = tmp.path();
    let prom = root.join("m.prom");
    std::fs::write(&prom, "keel_judge_quanta_total 1\n").unwrap();
    let prom_arg = prom.to_str().unwrap();

    let typo = expect(root, &spec(json!([{"name": "a", "metric": "keel_judge_quanta_total", "op": "=", "value": 1, "why": "w"}])), &["--metrics", prom_arg]);
    assert_eq!(typo.code, 2);
    assert!(typo.stdout.is_empty() && typo.stderr.contains("expectations[0] (\"a\").op is \"=\""), "{}", typo.stderr);

    let single_read = expect(root, &spec(json!([{"name": "a", "metric": "keel_judge_quanta_total", "op": "increases", "why": "w"}])), &["--metrics", prom_arg]);
    assert_eq!(single_read.code, 2);
    assert!(single_read.stderr.contains("--within"), "{}", single_read.stderr);

    let missing = Command::new(JUDGE).args(["expect", "--metrics", prom_arg, "--spec"]).arg(root.join("nope.json")).output().unwrap();
    assert_eq!(missing.status.code(), Some(2));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("nope.json"));

    // clap's own usage errors are status 2 too: neither source, or both.
    let neither = Command::new(JUDGE).args(["expect", "--spec", "x.json"]).output().unwrap();
    assert_eq!(neither.status.code(), Some(2));
    let both = Command::new(JUDGE).args(["expect", "--spec", "x.json", "--metrics", prom_arg, "--state", "d"]).output().unwrap();
    assert_eq!(both.status.code(), Some(2));
}

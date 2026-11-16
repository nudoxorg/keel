//! Real subprocess receipts flow through the modeled tree and judge's log.
use keel_tree::{
    driver, model::Model, resolve::Resolution, source, testset::TestTable, tree, verdict,
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{fs, path::Path, process::Command, time::Duration};

fn hash(path: &Path) -> String {
    format!("{:x}", Sha256::digest(fs::read(path).unwrap()))
}
fn bytes_hash(dir: &Path, bytes: &[u8]) -> String {
    let p = dir.join("hash-input");
    fs::write(&p, bytes).unwrap();
    hash(&p)
}
fn write_report(dir: &Path, report: &Value) -> std::path::PathBuf {
    let source = dir.join("report-source.json");
    let dest = dir.join("report.json");
    let _ = fs::remove_file(&dest);
    fs::write(&source, serde_json::to_vec(report).unwrap()).unwrap();
    let args = vec![
        "-c".to_owned(),
        "cat \"$1\" > \"$2\"".to_owned(),
        "driver".to_owned(),
        source.display().to_string(),
        dest.display().to_string(),
    ];
    assert!(driver::execute(Path::new("/bin/sh"), &args, &dest, Duration::from_secs(5)).unwrap());
    dest
}

#[test]
fn observed_cases_and_failed_worlds_reach_tree_and_durable_judge_without_inventing_results() {
    let d = tempfile::tempdir().unwrap();
    let root = d.path();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(root)
            .status()
            .unwrap()
            .success()
    );
    fs::write(root.join("source"), "source").unwrap();
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["add", "source"])
            .status()
            .unwrap()
            .success()
    );
    let bins = root.join("bins");
    fs::create_dir(&bins).unwrap();
    fs::copy("/bin/sh", bins.join("probe")).unwrap();
    let cases = vec![
        json!({"id":"one","node":"app","language":"test","daemon":false,"steps":[{"id":"check","kind":"process","binary":"probe"}]}),
        json!({"id":"two","node":"base","language":"test","daemon":false,"steps":[{"id":"check","kind":"process","binary":"probe"}]}),
    ];
    let case_hash = bytes_hash(root, &serde_json::to_vec(&cases[0]).unwrap());
    let manifest = root.join("manifest.json");
    fs::write(
        &manifest,
        serde_json::to_vec(&json!({"schema":1,"cases":cases})).unwrap(),
    )
    .unwrap();
    let manifest_hash = hash(&manifest);
    let artifact_hash = hash(&bins.join("probe"));
    let driver_hash = hash(Path::new("/bin/sh"));
    let model = Model::from_json(&json!({"schema":2,"nodes":[
        {"id":"base","at":"fixture","parent":null,"about":null,"ship":null},
        {"id":"app","at":"fixture","parent":null,"about":null,"ship":"required","on":["base"]}],
        "worlds":[{"name":"base-world","at":null,"from":null},{"name":"leaf-world","at":null,"from":"base-world"}],
        "checks":{"suite":{"checks":[
            {"cell":"one","on":["app"],"run":["keel-case","one"],"expect":{"definitionSha256":case_hash},"world":"leaf-world"},
            {"cell":"two","on":["base"],"run":["keel-case","two"],"expect":{},"world":"base-world"}]}}}).to_string()).unwrap();
    let (index, _) = source::load(root, None, false).unwrap();
    let res = Resolution::build_with(&model, &index, root, Some("fixture"));
    let table = TestTable::build(&res, false);
    let trees = tree::run(&res, &table, None).unwrap();
    let result = verdict::Results {
        seen: vec![None; table.len()],
        lines: 0,
        mapped: 0,
        unmapped: vec![],
        failures_only: false,
    };
    let report = write_report(
        root,
        &json!({"schema":1,"manifest_sha256":manifest_hash,"driver_sha256":driver_hash,"binaries":{"probe":artifact_hash},"cases":[{"id":"one","node":"app","language":"test","status":"pass","steps":[{"id":"check","status":"pass"}]}]}),
    );
    let evidence = driver::evaluate(
        &model,
        &res,
        Some(&manifest),
        Some(&report),
        Some(&bins),
        Some(Path::new("/bin/sh")),
    )
    .unwrap();
    let missing_driver = driver::evaluate(
        &model,
        &res,
        Some(&manifest),
        Some(&report),
        Some(&bins),
        None,
    )
    .unwrap();
    assert!(missing_driver.checks.iter().all(|c| c.state == "unknown"));
    let wrong = root.join("wrong-driver");
    fs::write(&wrong, b"different").unwrap();
    assert!(
        driver::evaluate(
            &model,
            &res,
            Some(&manifest),
            Some(&report),
            Some(&bins),
            Some(&wrong)
        )
        .is_err()
    );
    assert_eq!(
        evidence.checks.iter().filter(|c| c.state == "pass").count(),
        1
    );
    assert_eq!(
        evidence
            .checks
            .iter()
            .filter(|c| c.state == "unknown")
            .count(),
        1
    );
    let mut changed = model.clone();
    changed.checks.get_mut("suite").unwrap().checks[0].expect["definitionSha256"] =
        Value::String("0".repeat(64));
    assert!(
        driver::evaluate(
            &changed,
            &res,
            Some(&manifest),
            Some(&report),
            Some(&bins),
            Some(Path::new("/bin/sh"))
        )
        .is_err()
    );
    let v = verdict::run_with_checks(&res, &table, &trees, &result, Some(&evidence));
    assert_eq!(v.features[0].state, "unknown");
    let verdict_file = root.join("tree.json");
    fs::write(&verdict_file, serde_json::to_vec(&v).unwrap()).unwrap();
    let state = root.join("state");
    keel_judge::checks::record(&verdict_file, &state).unwrap();
    let summary = keel_judge::checks::latest(&state).unwrap().unwrap();
    assert_eq!((summary.pass, summary.unknown), (1, 1));
    let world_hash = &evidence.world_definitions["base-world"];
    let observed_setup = Command::new("/bin/sh")
        .args(["-c", "exit 17"])
        .status()
        .unwrap();
    assert_eq!(observed_setup.code(), Some(17));
    let world_error = format!("setup exited {observed_setup}");
    let report = write_report(
        root,
        &json!({"schema":1,"manifest_sha256":manifest_hash,"driver_sha256":driver_hash,"binaries":{"probe":artifact_hash},"cases":[],"worlds":[{"name":"base-world","definition_sha256":world_hash,"status":"fail","error":world_error}]}),
    );
    let blocked = driver::evaluate(
        &model,
        &res,
        Some(&manifest),
        Some(&report),
        Some(&bins),
        Some(Path::new("/bin/sh")),
    )
    .unwrap();
    assert!(
        blocked
            .checks
            .iter()
            .all(|c| c.state == "blocked" && c.blocked_by.as_deref() == Some("base-world"))
    );
    let v = verdict::run_with_checks(&res, &table, &trees, &result, Some(&blocked));
    assert_eq!(v.features[0].state, "failure");
    assert!(
        v.features[0]
            .roots
            .iter()
            .any(|(name, _)| name == "world:base-world")
    );
    fs::write(&verdict_file, serde_json::to_vec(&v).unwrap()).unwrap();
    keel_judge::checks::record(&verdict_file, &state).unwrap();
    let summary = keel_judge::checks::latest(&state).unwrap().unwrap();
    assert_eq!((summary.blocked, summary.failed_worlds), (2, 1));
}

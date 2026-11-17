//! Adversarial tests run the built harness as an external process.
#![cfg(unix)]
use serde_json::{Value, json};
use std::fs;
use std::os::unix::fs::symlink;
use std::path::PathBuf;
use std::process::{Command, Output};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
static NEXT: AtomicU64 = AtomicU64::new(0);
struct Sandbox(PathBuf);
impl Sandbox {
    fn new() -> Self {
        let root = std::env::temp_dir().join(format!(
            "keel-driver-{}-{}",
            std::process::id(),
            NEXT.fetch_add(1, Ordering::Relaxed)
        ));
        fs::create_dir(&root).expect("private integration scratch");
        fs::create_dir(root.join("bins")).expect("bin directory");
        symlink("/bin/sh", root.join("bins/probe")).expect("real shell process artifact");
        Self(root)
    }
    fn invoke(&self, manifest: &Value, extra: &[&str]) -> Output {
        let path = self.0.join("manifest.json");
        fs::write(
            &path,
            serde_json::to_vec(manifest).expect("manifest encoding"),
        )
        .expect("write manifest");
        Command::new(env!("CARGO_BIN_EXE_backend-keel-harness"))
            .arg("--manifest")
            .arg(path)
            .arg("--bin-dir")
            .arg(self.0.join("bins"))
            .arg("--evidence")
            .arg(self.0.join("evidence"))
            .args(extra)
            .output()
            .expect("real harness process")
    }
    fn report(&self) -> Value {
        serde_json::from_slice(
            &fs::read(self.0.join("evidence/report.json")).expect("report retained"),
        )
        .expect("valid evidence")
    }
}
impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.0);
    }
}
fn process_case(id: &str, script: &str) -> Value {
    json!({"id":id,"language":"protocol","daemon":false,"steps":[{"id":"observe","kind":"process","binary":"probe","args":["-c",script],"timeout_seconds":1,"expect":{"exit":0,"json":[{"pointer":"/answer","equals":"independent-oracle"}]}}]})
}
fn manifest(cases: Vec<Value>) -> Value {
    json!({"schema":1,"cases":cases})
}

#[test]
fn external_driver_rejects_vacuous_and_escaping_definitions_before_spawning() {
    for mutation in ["unknown-field", "traversal", "exit-only", "duplicate-id"] {
        let world = Sandbox::new();
        let mut case = process_case("probe", "echo '{\"answer\":\"independent-oracle\"}'");
        match mutation {
            "unknown-field" => {
                case["steps"][0]["typo"] = json!(true);
            }
            "traversal" => {
                case["files"] = json!({"../escape":"forbidden"});
            }
            "exit-only" => {
                case["steps"][0]["expect"]["json"] = json!([]);
            }
            "duplicate-id" => {
                let duplicate = case["steps"][0].clone();
                case["steps"].as_array_mut().expect("steps").push(duplicate);
            }
            _ => unreachable!(),
        }
        let result = world.invoke(&manifest(vec![case]), &[]);
        assert_eq!(
            result.status.code(),
            Some(2),
            "{mutation}: {}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert!(
            !world.0.join("evidence").exists(),
            "invalid manifest must not produce pass evidence"
        );
        assert!(!world.0.join("escape").exists());
    }
}
#[test]
fn failed_oracle_blocks_its_history_without_hiding_an_independent_pass() {
    let world = Sandbox::new();
    let mut bad = process_case("bad", "echo '{\"answer\":\"wrong\"}'");
    bad["steps"]
        .as_array_mut()
        .expect("steps")
        .push(json!({"id":"must-not-run","kind":"write","files":{"sentinel":"bad dependent ran"}}));
    let good = process_case("good", "echo '{\"answer\":\"independent-oracle\"}'");
    let output = world.invoke(&manifest(vec![bad, good]), &[]);
    assert_eq!(output.status.code(), Some(1));
    let report = world.report();
    assert_eq!(report["status"], "fail");
    assert_eq!(report["cases"][0]["steps"][1]["status"], "blocked");
    assert_eq!(report["cases"][1]["status"], "pass");
    assert!(!world.0.join("evidence/bad/project/sentinel").exists());
    assert_eq!(
        fs::read_to_string(world.0.join("evidence/good/000-observe.stdout")).expect("raw stdout"),
        "{\"answer\":\"independent-oracle\"}\n"
    );
}
#[test]
fn ordering_cannot_drop_unknown_or_duplicate_a_case() {
    for ids in [json!(["a"]), json!(["a", "a"]), json!(["a", "unknown"])] {
        let world = Sandbox::new();
        let order = world.0.join("order.json");
        fs::write(&order, json!({"schema":1,"cases":ids}).to_string()).expect("order");
        let a = process_case("a", "echo '{\"answer\":\"independent-oracle\"}'");
        let b = process_case("b", "echo '{\"answer\":\"independent-oracle\"}'");
        let result = world.invoke(
            &manifest(vec![a, b]),
            &["--order", order.to_str().expect("path")],
        );
        assert_eq!(result.status.code(), Some(2));
        assert!(!world.0.join("evidence").exists());
    }
    let world = Sandbox::new();
    let order = world.0.join("order.json");
    fs::write(&order, json!({"schema":1,"cases":["b","a"]}).to_string()).expect("order");
    let result = world.invoke(
        &manifest(vec![
            process_case("a", "echo '{\"answer\":\"independent-oracle\"}'"),
            process_case("b", "echo '{\"answer\":\"independent-oracle\"}'"),
        ]),
        &["--order", order.to_str().expect("path")],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    assert_eq!(world.report()["cases"][0]["id"], "b");
}
fn alive(pid: &str) -> bool {
    let Some(pid) = pid
        .parse::<i32>()
        .ok()
        .and_then(rustix::process::Pid::from_raw)
    else {
        return false;
    };
    #[cfg(target_os = "linux")]
    if let Ok(stat) = fs::read_to_string(format!("/proc/{}/stat", pid.as_raw_nonzero())) {
        if stat
            .rsplit_once(')')
            .is_some_and(|(_, tail)| tail.trim_start().starts_with('Z'))
        {
            return false;
        }
    }
    rustix::process::test_kill_process(pid).is_ok()
}

#[test]
fn timeout_retires_descendants_and_retains_a_failure_instead_of_a_pass() {
    let world = Sandbox::new();
    let script = "sleep 20 & echo $! > descendant.pid; wait";
    let start = Instant::now();
    let result = world.invoke(&manifest(vec![process_case("hung", script)]), &[]);
    assert_eq!(result.status.code(), Some(1));
    assert!(start.elapsed().as_secs() < 8, "custody deadline escaped");
    let pid = fs::read_to_string(world.0.join("evidence/hung/project/descendant.pid"))
        .expect("child identity");
    // Reparented killed grandchildren may be zombies briefly; process output
    // and failed step prove the timeout, while no sleeping descendant may live.
    let deadline = Instant::now() + std::time::Duration::from_secs(2);
    while alive(pid.trim()) && Instant::now() < deadline {
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert!(
        !alive(pid.trim()),
        "descendant survived process-group timeout: {}",
        pid.trim()
    );
    assert_eq!(world.report()["cases"][0]["steps"][0]["status"], "fail");
    let stderr = fs::read_to_string(world.0.join("evidence/hung/000-observe.stderr"))
        .expect("timeout evidence");
    assert!(stderr.contains("timed out"));
}
#[test]
fn parent_exit_does_not_wait_for_a_descendant_holding_stdout() {
    let world = Sandbox::new();
    let result = world.invoke(
        &manifest(vec![process_case(
            "pipe-holder",
            "sleep 20 & echo '{\"answer\":\"independent-oracle\"}'; exit 0",
        )]),
        &[],
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
}

#[test]
fn copied_identity_bindings_preserve_json_and_symbol_bytes_across_real_processes() {
    // The canonical field shape is retained from an actual 631a Rust owner
    // search response, rather than inferred from the internal Rust field name.
    let live: Value = serde_json::from_str(include_str!("fixtures/selected-symbol-live.json"))
        .expect("retained live identity");
    for (identity, expected) in [
        (
            live,
            "symbol:193be41234a71fb32ed5ff4967cbb58f9919682ae08659ff7900a365480899e2",
        ),
        (
            json!({"kind":"selected-symbol-id","value":(0u8..32).collect::<Vec<_>>()}),
            "symbol:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
        ),
    ] {
        let world = Sandbox::new();
        let emit = format!("printf '%s' '{}'", json!({"identity":identity}));
        let case = json!({"id":"typed-binding","language":"protocol","daemon":false,"steps":[
            {"id":"capture","kind":"process","binary":"probe","args":["-c",emit],"expect":{"exit":0,"json":[{"pointer":"/identity","equals":identity}]},"bind":{"copied":"/identity","key":{"pointer":"/identity","transform":"selected-symbol-key"}}},
            {"id":"consume","kind":"process","binary":"probe","args":["-c","IFS= read -r value; printf '%s' \"$value\""],"input":{"identity":"${copied}","key":"${key}"},"expect":{"exit":0,"json":[{"pointer":"/identity","equals":"${copied}"},{"pointer":"/key","equals":expected}]}}
        ]});
        let result = world.invoke(&manifest(vec![case]), &[]);
        assert!(
            result.status.success(),
            "{}",
            String::from_utf8_lossy(&result.stderr)
        );
        assert_eq!(world.report()["cases"][0]["steps"][1]["status"], "pass");
    }
}

#[test]
fn malformed_selected_identities_cannot_create_a_dependent_world_step() {
    for identity in [
        json!({"kind":"selected-symbol-id","value":"0".repeat(64)}),
        json!({"kind":"selected-symbol-id","value":"AB".repeat(32)}),
        json!({"kind":"selected-symbol-id","value":"12"}),
        json!({"kind":"selected-symbol-id","value":vec![256;32]}),
        json!({"kind":"selected-symbol-id","value":vec![1;31]}),
        json!({"kind":"selected-symbol-id","bytes":vec![1;32]}),
        json!({"kind":"other-id","value":"ab".repeat(32)}),
    ] {
        let world = Sandbox::new();
        let emit = format!("printf '%s' '{}'", json!({"identity":identity}));
        let case = json!({"id":"invalid-identity","language":"protocol","daemon":false,"steps":[
            {"id":"capture","kind":"process","binary":"probe","args":["-c",emit],"expect":{"exit":0,"json":[{"pointer":"/identity","equals":identity}]},"bind":{"key":{"pointer":"/identity","transform":"selected-symbol-key"}}},
            {"id":"must-not-run","kind":"write","files":{"sentinel":"invalid identity propagated"}}
        ]});
        let output = world.invoke(&manifest(vec![case]), &[]);
        assert_eq!(output.status.code(), Some(1));
        assert_eq!(world.report()["cases"][0]["steps"][1]["status"], "blocked");
        assert!(
            !world
                .0
                .join("evidence/invalid-identity/project/sentinel")
                .exists()
        );
    }
}

#[test]
fn inventory_binds_reviewed_expectations_and_never_writes_execution_evidence() {
    let world = Sandbox::new();
    let mut spec = manifest(vec![process_case(
        "inventory",
        "echo '{\"answer\":\"independent-oracle\"}'",
    )]);
    let first = world.invoke(&spec, &["--inventory"]);
    assert!(
        first.status.success(),
        "{}",
        String::from_utf8_lossy(&first.stderr)
    );
    let first: Value = serde_json::from_slice(&first.stdout).expect("typed inventory");
    assert_eq!(first["kind"], "keel-contract-inventory");
    assert_eq!(
        first["driver_sha256"]
            .as_str()
            .expect("driver digest")
            .len(),
        64
    );
    assert_eq!(first["cases"][0]["world"], "process");
    spec["cases"][0]["steps"][0]["expect"]["json"][0]["equals"] =
        json!("different-reviewed-contract");
    let second = world.invoke(&spec, &["--inventory"]);
    assert!(second.status.success());
    let second: Value = serde_json::from_slice(&second.stdout).expect("inventory");
    assert_ne!(first["manifest_sha256"], second["manifest_sha256"]);
    assert_ne!(
        first["cases"][0]["definition_sha256"],
        second["cases"][0]["definition_sha256"]
    );
    assert!(!world.0.join("evidence").exists());
}

#[test]
fn failed_foundation_blocks_dependent_world_and_selection_includes_its_prerequisite() {
    let world = Sandbox::new();
    let bad = process_case("foundation", "echo '{\"answer\":\"wrong\"}'");
    let child = json!({"id":"dependent","language":"protocol","daemon":false,"requires":["foundation"],"steps":[{"id":"must-not-materialize","kind":"write","files":{"sentinel":"unexpected"}}]});
    let good = process_case("independent", "echo '{\"answer\":\"independent-oracle\"}'");
    let result = world.invoke(&manifest(vec![child.clone(), good, bad.clone()]), &[]);
    assert_eq!(result.status.code(), Some(1));
    let report = world.report();
    let cases = report["cases"].as_array().expect("case receipts");
    assert_eq!(
        cases
            .iter()
            .find(|v| v["id"] == "dependent")
            .expect("dependent")["status"],
        "blocked"
    );
    assert_eq!(
        cases
            .iter()
            .find(|v| v["id"] == "independent")
            .expect("independent")["status"],
        "pass"
    );
    assert!(
        !world.0.join("evidence/dependent/project").exists(),
        "blocked world must not be created"
    );
    let selected = Sandbox::new();
    let result = selected.invoke(&manifest(vec![child, bad]), &["--case", "dependent"]);
    assert_eq!(result.status.code(), Some(1));
    let report = selected.report();
    assert_eq!(report["cases"].as_array().expect("closure").len(), 2);
    assert_eq!(report["cases"][0]["id"], "foundation");
}

#[cfg(target_os = "linux")]
#[test]
#[ignore = "requires delegated KEEL_CGROUP_ROOT and pinned KEEL_TEST_SETSID; explicit containment lane"]
fn cgroup_contains_a_descendant_that_creates_a_new_session() {
    let root = std::env::var_os("KEEL_CGROUP_ROOT").expect("explicit delegated cgroup root");
    let setsid = std::env::var("KEEL_TEST_SETSID").expect("explicit setsid authority");
    assert!(std::path::Path::new(&setsid).is_absolute());
    let world = Sandbox::new();
    let script = format!(
        "'{}' /bin/sh -c 'echo $$ > detached.pid; sleep 20' & wait",
        setsid.replace('\'', "'\\''")
    );
    let spec = manifest(vec![process_case("detached", &script)]);
    let path = world.0.join("manifest.json");
    fs::write(&path, spec.to_string()).expect("manifest");
    let result = Command::new(env!("CARGO_BIN_EXE_backend-keel-harness"))
        .arg("--manifest")
        .arg(path)
        .arg("--bin-dir")
        .arg(world.0.join("bins"))
        .arg("--evidence")
        .arg(world.0.join("evidence"))
        .env("KEEL_CGROUP_ROOT", &root)
        .env("KEEL_REQUIRE_CGROUP", "1")
        .output()
        .expect("contained harness process");
    assert_eq!(result.status.code(), Some(1));
    let pid = fs::read_to_string(world.0.join("evidence/detached/project/detached.pid"))
        .expect("detached descendant actually started");
    assert!(
        !alive(pid.trim()),
        "new-session descendant escaped cgroup cleanup"
    );
    let report = world.report();
    assert_eq!(report["containment_policy"]["required"], true);
    assert_eq!(report["cases"][0]["steps"][0]["status"], "fail");
    let entries = fs::read_dir(root)
        .expect("delegated group readable")
        .filter_map(Result::ok)
        .filter(|e| e.file_name().to_string_lossy().starts_with("keel-"))
        .count();
    assert_eq!(entries, 0, "owned scopes removed after timeout");
}

#[test]
fn actual_blocked_case_receipts_reach_tree_and_judge() {
    use keel_tree::{
        driver, model::Model, resolve::Resolution, source, testset::TestTable, tree, verdict,
    };
    use sha2::{Digest, Sha256};
    let world = Sandbox::new();
    let mut base = process_case("foundation", "echo '{\"answer\":\"wrong\"}'");
    base["node"] = json!("foundation");
    let child = json!({"id":"dependent","node":"surface","language":"protocol","daemon":false,"requires":["foundation"],"steps":[{"id":"must-not-run","kind":"write","files":{"sentinel":"unexpected"}}]});
    let transitive = json!({"id":"transitive","node":"surface","language":"protocol","daemon":false,"requires":["dependent"],"steps":[{"id":"never-run","kind":"write","files":{"sentinel":"unexpected"}}]});
    let manifest = manifest(vec![base.clone(), child.clone(), transitive.clone()]);
    let result = world.invoke(&manifest, &[]);
    assert_eq!(result.status.code(), Some(1));
    assert_eq!(world.report()["cases"][1]["status"], "blocked");
    assert_eq!(world.report()["cases"][2]["status"], "blocked");
    let case_hash =
        |case: &Value| format!("{:x}", Sha256::digest(serde_json::to_vec(case).unwrap()));
    let model = Model::from_json(&json!({"schema":2,"nodes":[
        {"id":"foundation","at":"fixture","parent":null,"about":null,"ship":null},
        {"id":"surface","at":"fixture","parent":null,"about":null,"ship":"required","on":["foundation"]}],
        "checks":{"contract":{"checks":[
            {"cell":"foundation","on":["foundation"],"run":["keel-case","foundation"],"expect":{"definitionSha256":case_hash(&base)}},
            {"cell":"dependent","on":["surface"],"run":["keel-case","dependent"],"expect":{"definitionSha256":case_hash(&child)}},
            {"cell":"transitive","on":["surface"],"run":["keel-case","transitive"],"expect":{"definitionSha256":case_hash(&transitive)}}]}}}).to_string()).unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(&world.0)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(&world.0)
            .args(["add", "manifest.json"])
            .status()
            .unwrap()
            .success()
    );
    let (index, _) = source::load(&world.0, None, false).unwrap();
    let res = Resolution::build_with(&model, &index, &world.0, Some("fixture"));
    let evidence = driver::evaluate(
        &model,
        &res,
        Some(&world.0.join("manifest.json")),
        Some(&world.0.join("evidence/report.json")),
        Some(&world.0.join("bins")),
        Some(std::path::Path::new(env!(
            "CARGO_BIN_EXE_backend-keel-harness"
        ))),
    )
    .unwrap();
    assert_eq!(
        evidence
            .checks
            .iter()
            .find(|c| c.case.as_deref() == Some("foundation"))
            .unwrap()
            .state,
        "fail"
    );
    assert_eq!(
        evidence
            .checks
            .iter()
            .find(|c| c.case.as_deref() == Some("dependent"))
            .unwrap()
            .state,
        "blocked"
    );
    let transitive_outcome = evidence.case_outcomes.get("transitive").unwrap();
    assert_eq!(transitive_outcome.blocked_by_cases, vec!["dependent"]);
    let mut missing_foundation = model.clone();
    missing_foundation
        .checks
        .get_mut("contract")
        .unwrap()
        .checks
        .remove(0);
    let not_bound = driver::evaluate(
        &missing_foundation,
        &res,
        Some(&world.0.join("manifest.json")),
        Some(&world.0.join("evidence/report.json")),
        Some(&world.0.join("bins")),
        Some(std::path::Path::new(env!(
            "CARGO_BIN_EXE_backend-keel-harness"
        ))),
    )
    .unwrap();
    assert!(
        not_bound
            .checks
            .iter()
            .all(|check| check.state == "unknown")
    );
    assert!(keel_judge::checks::validate(&not_bound).is_ok());
    // Even a genuinely passing dependent cannot reuse an unmodeled prerequisite.
    let other = Sandbox::new();
    let mut passing_base = process_case("foundation", "echo '{\"answer\":\"independent-oracle\"}'");
    passing_base["node"] = json!("foundation");
    let passing_manifest =
        json!({"schema":1,"cases":[passing_base, child.clone(), transitive.clone()]});
    assert!(other.invoke(&passing_manifest, &[]).status.success());
    assert!(
        other.report()["cases"]
            .as_array()
            .unwrap()
            .iter()
            .all(|case| case["status"] == "pass")
    );
    let missing_pass = driver::evaluate(
        &missing_foundation,
        &res,
        Some(&other.0.join("manifest.json")),
        Some(&other.0.join("evidence/report.json")),
        Some(&other.0.join("bins")),
        Some(std::path::Path::new(env!(
            "CARGO_BIN_EXE_backend-keel-harness"
        ))),
    )
    .unwrap();
    assert!(
        missing_pass
            .checks
            .iter()
            .all(|check| check.state == "unknown")
    );

    let mut forged = world.report();
    forged["cases"][1]["steps"][0]["blocked_by"] = json!(["not-the-prerequisite"]);
    let forged_path = world.0.join("forged.json");
    fs::write(&forged_path, serde_json::to_vec(&forged).unwrap()).unwrap();
    assert!(
        driver::evaluate(
            &model,
            &res,
            Some(&world.0.join("manifest.json")),
            Some(&forged_path),
            Some(&world.0.join("bins")),
            Some(std::path::Path::new(env!(
                "CARGO_BIN_EXE_backend-keel-harness"
            )))
        )
        .is_err()
    );
    forged = world.report();
    forged["cases"].as_array_mut().unwrap().remove(0);
    fs::write(&forged_path, serde_json::to_vec(&forged).unwrap()).unwrap();
    assert!(
        driver::evaluate(
            &model,
            &res,
            Some(&world.0.join("manifest.json")),
            Some(&forged_path),
            Some(&world.0.join("bins")),
            Some(std::path::Path::new(env!(
                "CARGO_BIN_EXE_backend-keel-harness"
            )))
        )
        .is_err()
    );
    let mut bad_evidence = evidence.clone();
    bad_evidence
        .case_outcomes
        .get_mut("foundation")
        .unwrap()
        .state = "pass".to_owned();
    assert!(keel_judge::checks::validate(&bad_evidence).is_err());
    let unverified = driver::evaluate(
        &model,
        &res,
        Some(&world.0.join("manifest.json")),
        Some(&world.0.join("evidence/report.json")),
        Some(&world.0.join("bins")),
        None,
    )
    .unwrap();
    assert!(unverified.checks.iter().all(|c| c.state == "unknown"));
    let table = TestTable::build(&res, false);
    let trees = tree::run(&res, &table, None).unwrap();
    let results = verdict::Results {
        seen: vec![None; table.len()],
        lines: 0,
        mapped: 0,
        unmapped: vec![],
        failures_only: false,
    };
    let value = verdict::run_with_checks(&res, &table, &trees, &results, Some(&evidence));
    assert_eq!(value.features[0].state, "failure");
    assert_eq!(value.features[0].roots, vec![("foundation".to_owned(), 1)]);
    let verdict_file = world.0.join("tree.json");
    fs::write(&verdict_file, serde_json::to_vec(&value).unwrap()).unwrap();
    keel_judge::checks::record(&verdict_file, &world.0.join("judge")).unwrap();
    let saved = keel_judge::checks::latest(&world.0.join("judge"))
        .unwrap()
        .unwrap();
    assert_eq!((saved.fail, saved.blocked, saved.unknown), (1, 2, 0));
}

// A real external JSON-lines peer witnesses lifecycle and cleanup; it does not
// stand in for the product's cursor semantics, which Backend tests separately.
#[test]
fn named_mcp_sessions_span_other_steps_restart_and_reap_on_failure() {
    use std::os::unix::fs::PermissionsExt;
    let world = Sandbox::new();
    let peer = world.0.join("bins/backend-mcp");
    fs::write(&peer, r##"#!/bin/sh
printf '%s\n' "$$" >> session-pids
while IFS= read -r line; do
 case "$line" in
  *'"method":"initialize"'*) printf '%s\n' '{"jsonrpc":"2.0","id":0,"result":{"protocolVersion":"2025-11-25"}}' ;;
  *'"method":"notifications/initialized"'*) ;;
  *'"method":"tools/call"'*)
   id=$(printf '%s' "$line" | sed -n 's/.*"id":\([0-9][0-9]*\).*/\1/p')
   case "$line" in
    *'"name":"first"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":false,"structuredContent":{"pid":%s,"continuation_call":{"name":"next","arguments":{"cursor":{"marker":"untouched","limit":3}}}}}}\n' "$id" "$$" ;;
    *'"marker":"untouched"'*'"name":"next"'*)
      if [ -f changed ]; then changed=true; else changed=false; fi
      printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":false,"structuredContent":{"pid":%s,"changed":%s}}}\n' "$id" "$$" "$changed" ;;
    *'"name":"bad-version"'*) printf '{"jsonrpc":"1.0","id":%s,"result":{"isError":false,"structuredContent":{"pid":0}}}\n' "$id" ;;
    *'"name":"both-result-error"'*) printf '{"jsonrpc":"2.0","id":%s,"error":{"code":-1},"result":{"isError":false,"structuredContent":{"pid":0}}}\n' "$id" ;;
    *'"name":"neither-result-error"'*) printf '{"jsonrpc":"2.0","id":%s}\n' "$id" ;;
    *'"name":"hang"'*) sleep 20 ;;
    *'"name":"refuse"'*) printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":true,"structuredContent":{"slug":"cursor-mismatch"}}}\n' "$id" ;;
    *) printf '{"jsonrpc":"2.0","id":%s,"result":{"isError":false,"structuredContent":{"pid":%s}}}\n' "$id" "$$" ;;
   esac ;;
 esac
done
"##).expect("write fake process");
    fs::set_permissions(&peer, fs::Permissions::from_mode(0o700)).expect("executable peer");
    let case = json!({"id":"session-history","language":"protocol","daemon":false,"steps":[
        {"id":"open","kind":"mcp-start","session":"client","bind":{"first_pid":"/pid"}},
        {"id":"first","kind":"mcp-call","session":"client","tool":"first","arguments":{},"bind":{"next":"/continuation_call"},"expect":{"exit":0,"json":[{"pointer":"/pid","equals":"${first_pid}"}]}},
        {"id":"edit","kind":"write","files":{"changed":"revision two"}},
        {"id":"other-process","kind":"process","binary":"probe","args":["-c","test -f changed && printf '{\"answer\":\"changed\"}'"],"expect":{"exit":0,"json":[{"pointer":"/answer","equals":"changed"}]}},
        {"id":"continued","kind":"mcp-call","session":"client","call":"${next}","expect":{"exit":0,"json":[{"pointer":"/pid","equals":"${first_pid}"},{"pointer":"/changed","equals":true}]}},
        {"id":"refused","kind":"mcp-call","session":"client","tool":"refuse","arguments":{},"mcp_error":true,"expect":{"exit":0,"json":[{"pointer":"/slug","equals":"cursor-mismatch"}]}},
        {"id":"close","kind":"mcp-stop","session":"client"},
        {"id":"reopen","kind":"mcp-start","session":"client","bind":{"second_pid":"/pid"}},
        {"id":"new-process","kind":"mcp-call","session":"client","tool":"new","arguments":{},"expect":{"exit":0,"json":[{"pointer":"/pid","equals":"${second_pid}"}]}},
        {"id":"close-again","kind":"mcp-stop","session":"client"}
    ]});
    let failure = json!({"id":"session-failure","language":"protocol","daemon":false,"steps":[
        {"id":"open","kind":"mcp-start","session":"client"},
        {"id":"fail","kind":"mcp-call","session":"client","tool":"new","arguments":{},"expect":{"exit":0,"json":[{"pointer":"/pid","equals":0}]}},
        {"id":"close","kind":"mcp-stop","session":"client"}
    ]});
    let hung = json!({"id":"session-timeout","language":"protocol","daemon":false,"steps":[
        {"id":"open","kind":"mcp-start","session":"client"},
        {"id":"hang","kind":"mcp-call","session":"client","tool":"hang","arguments":{},"timeout_seconds":1,"expect":{"exit":0,"json":[{"pointer":"/pid","equals":0}]}},
        {"id":"close","kind":"mcp-stop","session":"client"}
    ]});
    let mut cases = vec![case, failure, hung];
    for name in ["bad-version", "both-result-error", "neither-result-error"] {
        cases.push(json!({"id":name,"language":"protocol","daemon":false,"steps":[
            {"id":"open","kind":"mcp-start","session":"client"},
            {"id":"malformed","kind":"mcp-call","session":"client","tool":name,"arguments":{},"expect":{"exit":0,"json":[{"pointer":"/pid","equals":0}]}},
            {"id":"close","kind":"mcp-stop","session":"client"}
        ]}));
    }
    let result = world.invoke(&manifest(cases), &[]);
    assert_eq!(
        result.status.code(),
        Some(1),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let report = world.report();
    assert_eq!(report["cases"][0]["status"], "pass", "{report}");
    assert_eq!(report["cases"][1]["status"], "fail", "{report}");
    assert_eq!(report["cases"][1]["steps"][2]["status"], "blocked");
    assert_eq!(report["cases"][2]["status"], "fail");
    assert!(
        report["cases"][2]["steps"][1]["error"]
            .as_str()
            .expect("timeout error")
            .contains("timed out")
    );
    for case in &report["cases"].as_array().expect("cases")[3..] {
        assert_eq!(case["status"], "fail");
        assert!(
            case["steps"][1]["error"]
                .as_str()
                .expect("envelope error")
                .contains("invalid JSON-RPC response envelope")
        );
        assert_eq!(case["steps"][2]["status"], "blocked");
    }
    let steps = report["cases"][0]["steps"].as_array().expect("steps");
    let first = steps[0]["detail"]["pid"].as_u64().expect("first pid");
    let second = steps[7]["detail"]["pid"].as_u64().expect("second pid");
    assert_eq!(steps[4]["detail"]["pid"], first);
    assert_ne!(first, second, "restarting creates a new process");
    assert_eq!(steps[6]["detail"]["reaped"], true);
    assert_eq!(steps[9]["detail"]["reaped"], true);
    for case in [
        "session-history",
        "session-failure",
        "session-timeout",
        "bad-version",
        "both-result-error",
        "neither-result-error",
    ] {
        let pids = fs::read_to_string(
            world
                .0
                .join("evidence")
                .join(case)
                .join("project/session-pids"),
        )
        .expect("observed peer pids");
        for pid in pids.lines() {
            assert!(!alive(pid), "MCP peer {pid} survived {case}");
        }
    }
    let request: Value = serde_json::from_slice(
        &fs::read(
            world
                .0
                .join("evidence/session-history/004-continued.request.json"),
        )
        .expect("copied request"),
    )
    .expect("JSON");
    assert_eq!(
        request["params"],
        json!({"name":"next","arguments":{"cursor":{"marker":"untouched","limit":3}}})
    );
    for steps in [
        json!([{"id":"call","kind":"mcp-call","session":"missing","tool":"x","arguments":{},"expect":{"exit":0,"json":[{"pointer":"/x","equals":1}]}}]),
        json!([{"id":"stop","kind":"mcp-stop","session":"missing"}]),
        json!([{"id":"misleading","kind":"process","binary":"probe","session":"s","args":["-c","true"],"expect":{"exit":0,"stdout_contains":["x"]}}]),
        json!([{"id":"open","kind":"mcp-start","session":"s","tool":"ignored"},{"id":"stop","kind":"mcp-stop","session":"s"}]),
        json!([{"id":"open","kind":"mcp-start","session":"s"},{"id":"stop","kind":"mcp-stop","session":"s","arguments":{"limit":1}}]),
        json!([{"id":"open","kind":"mcp-start","session":"s"},{"id":"bad","kind":"mcp-call","session":"s","call":{"name":"next","arguments":{}},"arguments":{"limit":5},"expect":{"exit":0,"json":[{"pointer":"/x","equals":1}]}},{"id":"close","kind":"mcp-stop","session":"s"}]),
        json!([{"id":"open","kind":"mcp-start","session":"s"}]),
        json!([{"id":"open","kind":"mcp-start","session":"s"},{"id":"again","kind":"mcp-start","session":"s"},{"id":"close","kind":"mcp-stop","session":"s"}]),
    ] {
        let invalid = Sandbox::new();
        let definition =
            json!({"id":"invalid-lifecycle","language":"protocol","daemon":false,"steps":steps});
        let result = invalid.invoke(&manifest(vec![definition]), &[]);
        assert_eq!(
            result.status.code(),
            Some(2),
            "invalid lifecycle must be refused before execution"
        );
        assert!(!invalid.0.join("evidence").exists());
    }
}

#[test]
fn private_account_key_reaches_only_cli_and_mcp_and_is_redacted() {
    use std::os::unix::fs::PermissionsExt;
    let world = Sandbox::new();
    let private = world.0.join("private");
    fs::create_dir(&private).unwrap();
    fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    let private = private.canonicalize().unwrap();
    let keyfile = private.join("account.key");
    let key = "SYNTHETIC.TEST-KEY_123456";
    fs::write(&keyfile, format!("{key}\n")).unwrap();
    fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o600)).unwrap();
    let daemon = world.0.join("bins/backend-locald");
    fs::write(&daemon, format!("#!/usr/bin/python3\nimport socket,sys,time,os\nassert 'NUDOX_API_KEY' not in os.environ\nsys.stderr.write('{key}\\n'); sys.stderr.flush()\ns=socket.socket(socket.AF_UNIX); s.bind(sys.argv[sys.argv.index('--endpoint')+1]); s.listen()\nwhile True: time.sleep(1)\n")).unwrap();
    let cli = world.0.join("bins/backend-cli");
    fs::write(&cli, "#!/usr/bin/python3\nimport os,sys,json,time\nk=os.environ['NUDOX_API_KEY']; sys.stderr.write(k[:5]); sys.stderr.flush(); time.sleep(.05); sys.stderr.write(k[5:]); sys.stderr.flush(); print(k if sys.argv[sys.argv.index('--format')+1]=='markdown' else json.dumps({'key_echo':k}))\n").unwrap();
    let mcp = world.0.join("bins/backend-mcp");
    fs::write(&mcp, "#!/usr/bin/python3\nimport os,sys,json\nk=os.environ['NUDOX_API_KEY']; sys.stderr.write(k+'\\n'); sys.stderr.flush()\nfor line in sys.stdin:\n r=json.loads(line)\n if r.get('method')=='initialize': print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':{'protocolVersion':'2025-11-25'}}),flush=True)\n elif r.get('method')=='tools/call': print(json.dumps({'jsonrpc':'2.0','id':r['id'],'result':{'isError':False,'structuredContent':{'key_echo':k},'content':[{'type':'text','text':k}]}}),flush=True)\n").unwrap();
    let worker = world.0.join("bins/worker");
    fs::write(
        &worker,
        "#!/bin/sh\nif [ -n \"${NUDOX_API_KEY+x}\" ]; then exit 9; fi\nprintf '{\"ok\":true}\\n'\n",
    )
    .unwrap();
    for path in [&daemon, &cli, &mcp, &worker] {
        fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
    }
    let manifest = manifest(vec![json!({"id":"account","language":"rust","steps":[
      {"id":"cli","kind":"cli","args":["probe"],"expect":{"exit":0,"json":[{"pointer":"/key_echo","equals":"***"}]}},
      {"id":"parity","kind":"query","cli":["probe"],"tool":"probe","arguments":{},"expect":{"exit":0,"json":[{"pointer":"/key_echo","equals":"***"}]}},
      {"id":"start","kind":"mcp-start","session":"reader"},
      {"id":"call","kind":"mcp-call","session":"reader","tool":"probe","arguments":{},"expect":{"exit":0,"json":[{"pointer":"/key_echo","equals":"***"}]}},
      {"id":"stop","kind":"mcp-stop","session":"reader"},
      {"id":"worker","kind":"process","binary":"worker","expect":{"exit":0,"json":[{"pointer":"/ok","equals":true}]}}
    ]})]);
    let path = world.0.join("private-manifest.json");
    fs::write(&path, manifest.to_string()).unwrap();
    let invoke = |file: &std::path::Path, list: bool| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_backend-keel-harness"));
        cmd.args([
            "--manifest",
            path.to_str().unwrap(),
            "--bin-dir",
            world.0.join("bins").to_str().unwrap(),
            "--evidence",
            world.0.join("evidence").to_str().unwrap(),
        ])
        .env("KEEL_NUDOX_API_KEY_FILE", file);
        if list {
            cmd.arg("--list");
        }
        cmd.output().unwrap()
    };
    assert!(invoke(&private.join("missing"), true).status.success());
    let output = invoke(&keyfile, false);
    assert!(
        output.status.success(),
        "{} report {}",
        String::from_utf8_lossy(&output.stderr),
        world.report()
    );
    assert_eq!(
        world.report()["account_key"],
        json!({"present":true,"source_basename":"account.key"})
    );
    fn scan(path: &std::path::Path, secret: &[u8]) {
        for entry in fs::read_dir(path).unwrap() {
            let path = entry.unwrap().path();
            if path.is_dir() {
                scan(&path, secret);
            } else {
                let data = fs::read(&path).unwrap();
                assert!(
                    !data.windows(secret.len()).any(|w| w == secret),
                    "secret leaked into {}",
                    path.display()
                );
            }
        }
    }
    scan(&world.0.join("evidence"), key.as_bytes());
    assert!(
        !output
            .stdout
            .windows(key.len())
            .any(|w| w == key.as_bytes())
    );
    assert!(
        !output
            .stderr
            .windows(key.len())
            .any(|w| w == key.as_bytes())
    );
    fs::remove_dir_all(world.0.join("evidence")).unwrap();
    for bad in [
        "mode",
        "empty",
        "newline",
        "invalid",
        "symlink",
        "parent-symlink",
        "relative",
        "oversized",
        "parent",
    ] {
        fs::write(&keyfile, format!("{key}\n")).unwrap();
        fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o600)).unwrap();
        let mut location = keyfile.clone();
        match bad {
            "mode" => fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o644)).unwrap(),
            "empty" => fs::write(&keyfile, "\n").unwrap(),
            "newline" => fs::write(&keyfile, "bad\nkey\n").unwrap(),
            "invalid" => fs::write(&keyfile, "bad/key").unwrap(),
            "symlink" => {
                location = private.join("link");
                symlink(&keyfile, &location).unwrap();
            }
            "parent-symlink" => {
                let link = world.0.canonicalize().unwrap().join("dir-link");
                symlink(&private, &link).unwrap();
                location = link.join("account.key");
            }
            "relative" => location = PathBuf::from("relative.key"),
            "oversized" => fs::write(&keyfile, "a".repeat(4097)).unwrap(),
            "parent" => fs::set_permissions(&private, fs::Permissions::from_mode(0o755)).unwrap(),
            _ => unreachable!(),
        }
        let output = invoke(&location, false);
        assert_eq!(output.status.code(), Some(2), "{bad}");
        assert!(!world.0.join("evidence").exists(), "{bad}");
        assert!(
            !output
                .stderr
                .windows(key.len())
                .any(|w| w == key.as_bytes())
        );
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
    }
}

#[test]
fn private_key_prefix_is_withheld_at_capture_limits_without_deadlock() {
    use std::os::unix::fs::PermissionsExt;
    let key = "BOUNDARY_TEST-KEY_123456789";
    let prefix = b"BOUNDARY";
    for kind in [
        "stdout",
        "stderr",
        "daemon",
        "session-stdout",
        "session-stderr",
    ] {
        let world = Sandbox::new();
        let private = world.0.join("private");
        fs::create_dir(&private).unwrap();
        fs::set_permissions(&private, fs::Permissions::from_mode(0o700)).unwrap();
        let keyfile = private.canonicalize().unwrap().join("key");
        fs::write(&keyfile, key).unwrap();
        fs::set_permissions(&keyfile, fs::Permissions::from_mode(0o600)).unwrap();
        let daemon = world.0.join("bins/backend-locald");
        let noise = if kind == "daemon" {
            format!(
                "sys.stdout.buffer.write(b'x'*(limit-8)+b'{key}'); sys.stdout.buffer.flush(); open('emitted','w').close()\n"
            )
        } else {
            String::new()
        };
        fs::write(&daemon, format!("#!/usr/bin/python3\nimport socket,sys,time\nlimit=8*1024*1024\ns=socket.socket(socket.AF_UNIX); s.bind(sys.argv[sys.argv.index('--endpoint')+1]); s.listen()\n{noise}while True: time.sleep(1)\n")).unwrap();
        let cli = world.0.join("bins/backend-cli");
        let target = if kind == "stderr" { "stderr" } else { "stdout" };
        fs::write(&cli, format!("#!/usr/bin/python3\nimport os,sys\nk=os.environ['NUDOX_API_KEY'].encode()\nsys.{target}.buffer.write(b'x'*(8*1024*1024-8)+k); sys.{target}.buffer.flush()\n")).unwrap();
        let mcp = world.0.join("bins/backend-mcp");
        let stderr_noise = if kind == "session-stderr" {
            "sys.stderr.buffer.write(b'x'*(limit-8)+k); sys.stderr.buffer.flush()"
        } else {
            "pass"
        };
        let stdout_noise = if kind == "session-stdout" {
            "sys.stdout.buffer.write(b'x'*(limit-len(init)-8)+k); sys.stdout.buffer.flush()"
        } else {
            "pass"
        };
        fs::write(&mcp, format!("#!/usr/bin/python3\nimport sys,os,json\nlimit=8*1024*1024\nk=os.environ['NUDOX_API_KEY'].encode()\ninit=b'{{\"jsonrpc\":\"2.0\",\"id\":0,\"result\":{{}}}}\\n'\n{stderr_noise}\nfor line in sys.stdin:\n r=json.loads(line)\n if r.get('method')=='initialize': sys.stdout.buffer.write(init); sys.stdout.buffer.flush()\n elif r.get('method')=='tools/call': {stdout_noise}\n")).unwrap();
        for binary in [&daemon, &cli, &mcp] {
            fs::set_permissions(binary, fs::Permissions::from_mode(0o755)).unwrap();
        }
        let (steps, capture) = match kind {
            "stdout" | "stderr" => (
                vec![
                    json!({"id":"cli","kind":"cli","args":["probe"],"timeout_seconds":10,"expect":{"exit":0,"stdout_contains":["x"]}}),
                ],
                format!("000-cli.{kind}"),
            ),
            "daemon" => (
                vec![
                    json!({"id":"done","kind":"process","binary":"probe","args":["-c", "while [ ! -f emitted ]; do sleep 0.02; done; echo ready"],"timeout_seconds":10,"expect":{"exit":0,"stdout_contains":["ready"]}}),
                ],
                "locald-1.log".to_owned(),
            ),
            "session-stdout" => (
                vec![
                    json!({"id":"start","kind":"mcp-start","session":"reader","timeout_seconds":10}),
                    json!({"id":"call","kind":"mcp-call","session":"reader","tool":"probe","arguments":{},"timeout_seconds":10,"expect":{"exit":0,"json":[{"pointer":"/ok","equals":true}]} }),
                    json!({"id":"stop","kind":"mcp-stop","session":"reader"}),
                ],
                "000-start.stdout".to_owned(),
            ),
            _ => (
                vec![
                    json!({"id":"start","kind":"mcp-start","session":"reader","timeout_seconds":10}),
                    json!({"id":"stop","kind":"mcp-stop","session":"reader","timeout_seconds":10}),
                ],
                "000-start.stderr".to_owned(),
            ),
        };
        let definition = manifest(vec![
            json!({"id":"boundary","language":"rust","steps":steps}),
        ]);
        let manifest_path = world.0.join("boundary.json");
        fs::write(&manifest_path, definition.to_string()).unwrap();
        let start = Instant::now();
        let output = Command::new(env!("CARGO_BIN_EXE_backend-keel-harness"))
            .args([
                "--manifest",
                manifest_path.to_str().unwrap(),
                "--bin-dir",
                world.0.join("bins").to_str().unwrap(),
                "--evidence",
                world.0.join("evidence").to_str().unwrap(),
            ])
            .env("KEEL_NUDOX_API_KEY_FILE", &keyfile)
            .output()
            .unwrap();
        assert_eq!(
            output.status.code(),
            Some(1),
            "{kind}: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert!(start.elapsed().as_secs() < 30, "{kind} capture deadlocked");
        let bytes = fs::read(world.0.join("evidence/boundary").join(capture)).unwrap();
        assert!(
            bytes.len() >= 8 * 1024 * 1024 - 64,
            "{kind}: capture not at boundary"
        );
        assert!(
            !bytes.windows(prefix.len()).any(|window| window == prefix),
            "{kind}: truncated key prefix leaked"
        );
    }
}

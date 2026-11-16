//! Synthetic protocol controls exercise the CLI, including full inventory.
use serde_json::Value;
use std::process::Command;

#[test]
fn protocol_graph_orders_without_eliding_unknown_cases() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nudox-example");
    let output = Command::new(env!("CARGO_BIN_EXE_keel-judge"))
        .args(["guidance", "--manifest"])
        .arg(dir.join("manifest.json"))
        .arg("--inputs")
        .arg(dir.join("inputs.json"))
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["cases"], serde_json::json!(["observed", "unknown"]));
    assert_eq!(v["evidence"][0]["status"], "observed-match");
    assert_eq!(v["evidence"][1]["status"], "unknown");
    assert_eq!(
        v["evidence"][0]["captures_blake3"]
            .as_array()
            .unwrap()
            .len(),
        4
    );
}

#[test]
fn truncated_graph_and_changed_snapshot_remain_unknown() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nudox-example");
    let tmp = tempfile::tempdir().unwrap();
    for name in [
        "manifest.json",
        "inputs.json",
        "before.json",
        "graph.json",
        "source.json",
        "after.json",
    ] {
        std::fs::copy(fixture.join(name), tmp.path().join(name)).unwrap();
    }
    let graph_path = tmp.path().join("graph.json");
    let mut graph: Value = serde_json::from_slice(&std::fs::read(&graph_path).unwrap()).unwrap();
    graph["more"] = true.into();
    std::fs::write(&graph_path, serde_json::to_vec(&graph).unwrap()).unwrap();
    let after_path = tmp.path().join("after.json");
    let mut after: Value = serde_json::from_slice(&std::fs::read(&after_path).unwrap()).unwrap();
    after["revision"] = "another-snapshot".into();
    std::fs::write(&after_path, serde_json::to_vec(&after).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_keel-judge"))
        .args(["guidance", "--manifest"])
        .arg(tmp.path().join("manifest.json"))
        .arg("--inputs")
        .arg(tmp.path().join("inputs.json"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(v["cases"].as_array().unwrap().len(), 2);
    assert_eq!(v["evidence"][0]["status"], "unknown");
    let reasons = v["evidence"][0]["reasons"].to_string();
    assert!(
        reasons.contains("status snapshots") && reasons.contains("truncated"),
        "{reasons}"
    );
}

#[test]
fn repeated_declaration_rows_do_not_inflate_the_observed_count() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nudox-example");
    let tmp = tempfile::tempdir().unwrap();
    for name in [
        "manifest.json",
        "inputs.json",
        "before.json",
        "graph.json",
        "source.json",
        "after.json",
    ] {
        std::fs::copy(fixture.join(name), tmp.path().join(name)).unwrap();
    }
    let path = tmp.path().join("graph.json");
    let mut graph: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    let duplicate = graph["records"][1].clone();
    graph["records"].as_array_mut().unwrap().push(duplicate);
    std::fs::write(path, serde_json::to_vec(&graph).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_keel-judge"))
        .args(["guidance", "--manifest"])
        .arg(tmp.path().join("manifest.json"))
        .arg("--inputs")
        .arg(tmp.path().join("inputs.json"))
        .output()
        .unwrap();
    assert!(output.status.success());
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        v["evidence"][0]["observed_changed_declarations"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(v["evidence"][0]["dependency_complexity"].is_null());
    assert!(v["evidence"][0]["blast_radius"].is_null());
}

#[test]
fn source_bound_related_edges_measure_the_observed_diamond_and_cycle() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nudox-example");
    let tmp = tempfile::tempdir().unwrap();
    for name in [
        "manifest.json",
        "inputs.json",
        "before.json",
        "graph.json",
        "source.json",
        "after.json",
    ] {
        std::fs::copy(fixture.join(name), tmp.path().join(name)).unwrap();
    }
    let mut inputs: Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join("inputs.json")).unwrap()).unwrap();
    inputs["observations"][0]["related"] = serde_json::json!(["related.json"]);
    std::fs::write(
        tmp.path().join("inputs.json"),
        serde_json::to_vec(&inputs).unwrap(),
    )
    .unwrap();
    let before: Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join("before.json")).unwrap()).unwrap();
    let root = inputs["observations"][0]["coordinate"].as_str().unwrap();
    let ids: Vec<_> = (0..4).map(|n| format!("symbol:{n:064x}")).collect();
    let labels = [root, "b", "c", "d"];
    let edge = |from: usize, to: usize| serde_json::json!({"from_id":ids[from],"to_id":ids[to],"from":labels[from],"to":labels[to],"relation":"calls","confidence":"compiler"});
    // Each edge must be incident to its captured center; four pages exercise
    // deduplication and an observed diamond closed by a cycle.
    let pairs = [
        vec![edge(0, 1), edge(0, 2), edge(3, 0)],
        vec![edge(0, 1), edge(1, 3)],
        vec![edge(0, 2), edge(2, 3)],
        vec![edge(1, 3), edge(2, 3), edge(3, 0)],
    ];
    let mut pages = Vec::new();
    for n in 0..4 {
        let page = serde_json::json!({"answer":"records", "more":false, "related_evidence_withheld":false,
            "related_basis":{"schema":1,"source_view_root":before["revision"],"source_object":"11".repeat(32),"branch":"22".repeat(32),"log":"33".repeat(32),"source_schema":1,"sequence":before["sequence"],"semantic_revision":"44".repeat(32),"neighborhood_root":"55".repeat(32),"center_id":ids[n],"coordinate":labels[n],"relation_coverage":"unknown"},"edges":pairs[n]});
        let name = format!("related{n}.json");
        std::fs::write(tmp.path().join(&name), serde_json::to_vec(&page).unwrap()).unwrap();
        pages.push(name);
    }
    inputs["observations"][0]["related"] = serde_json::json!(pages);
    std::fs::write(
        tmp.path().join("inputs.json"),
        serde_json::to_vec(&inputs).unwrap(),
    )
    .unwrap();
    let run = || {
        Command::new(env!("CARGO_BIN_EXE_keel-judge"))
            .args(["guidance", "--manifest"])
            .arg(tmp.path().join("manifest.json"))
            .arg("--inputs")
            .arg(tmp.path().join("inputs.json"))
            .output()
            .unwrap()
    };
    let output = run();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let v: Value = serde_json::from_slice(&output.stdout).unwrap();
    let m = &v["evidence"][0]["related_metrics"];
    assert_eq!(m["observed_call_edges"], 5);
    assert_eq!(m["observed_join_nodes"], 1);
    assert_eq!(m["direct_callers"], 1);
    assert_eq!(m["transitive_callers"], 3);
    assert_eq!(m["observed_cyclic_components"], 1);
    assert_eq!(m["max_reverse_shortest_depth"], 2);
    let path = tmp.path().join("related0.json");
    let mut page: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    page["related_basis"]["source_view_root"] = "66".repeat(32).into();
    std::fs::write(&path, serde_json::to_vec(&page).unwrap()).unwrap();
    let v: Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(v["evidence"][0]["status"], "unknown");
    assert!(v["evidence"][0]["related_metrics"].is_null());
    page["related_basis"]["source_view_root"] = before["revision"].clone();
    page["more"] = true.into();
    std::fs::write(&path, serde_json::to_vec(&page).unwrap()).unwrap();
    let v: Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(v["evidence"][0]["status"], "unknown");
    page["more"] = false.into();
    page["edges"][0]["to_id"] = "invalid".into();
    std::fs::write(&path, serde_json::to_vec(&page).unwrap()).unwrap();
    let v: Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(v["evidence"][0]["status"], "unknown");
}

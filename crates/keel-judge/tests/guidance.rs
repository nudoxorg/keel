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
            "related_basis":{"schema":1,"source_view_root":before["revision"],"source_object":before["source"],"branch":"22".repeat(32),"log":"33".repeat(32),"source_schema":1,"sequence":before["sequence"],"semantic_revision":"44".repeat(32),"neighborhood_root":"55".repeat(32),"center_id":ids[n],"coordinate":labels[n],"relation_coverage":"unknown"},"edges":pairs[n]});
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

#[test]
fn captured_typed_calls_survive_unobserved_legacy_graph() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nudox-189f");
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
    assert_eq!(v["cases"], serde_json::json!(["fanout", "unobserved"]));
    let e = &v["evidence"][0];
    assert_eq!(
        e["status"], "unknown",
        "legacy graph coverage remains unknown"
    );
    assert_eq!(e["observed_changed_declarations"], serde_json::json!([]));
    assert!(e["blast_radius"].is_null() && e["dependency_complexity"].is_null());
    let m = &e["related_metrics"];
    assert_eq!(
        m["observed_call_edges"], 8,
        "the ninth observed edge is a type reference"
    );
    assert_eq!(m["direct_callers"], 8);
    assert_eq!(
        m["observed_reachable_changed_nodes"], 1,
        "only the independently sourced seed is attributed"
    );
    assert_eq!(
        m["unattributed_related_nodes"], 9,
        "related rows have no project attribution"
    );
}

#[test]
fn typed_edges_reject_stale_source_and_wrong_seed_identity() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nudox-189f");
    let tmp = tempfile::tempdir().unwrap();
    for name in [
        "manifest.json",
        "inputs.json",
        "before.json",
        "after.json",
        "graph.json",
        "source.json",
        "related.json",
    ] {
        std::fs::copy(fixture.join(name), tmp.path().join(name)).unwrap();
    }
    let invoke = || {
        let out = Command::new(env!("CARGO_BIN_EXE_keel-judge"))
            .args(["guidance", "--manifest"])
            .arg(tmp.path().join("manifest.json"))
            .arg("--inputs")
            .arg(tmp.path().join("inputs.json"))
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    let source_path = tmp.path().join("source.json");
    let mut source: Value = serde_json::from_slice(&std::fs::read(&source_path).unwrap()).unwrap();
    source["identity"]["semantic_data"]["value"] = "ab".repeat(32).into();
    std::fs::write(&source_path, serde_json::to_vec(&source).unwrap()).unwrap();
    assert!(invoke()["evidence"][0]["related_metrics"].is_null());
    std::fs::copy(fixture.join("source.json"), &source_path).unwrap();
    let after_path = tmp.path().join("after.json");
    let mut after: Value = serde_json::from_slice(&std::fs::read(&after_path).unwrap()).unwrap();
    after["source"] = "ab".repeat(32).into();
    std::fs::write(after_path, serde_json::to_vec(&after).unwrap()).unwrap();
    assert!(invoke()["evidence"][0]["related_metrics"].is_null());
    std::fs::copy(
        fixture.join("after.json"),
        tmp.path().join("after.json"),
    )
    .unwrap();
    let related_path = tmp.path().join("related.json");
    let mut related: Value =
        serde_json::from_slice(&std::fs::read(&related_path).unwrap()).unwrap();
    related["related_basis"]["source_object"] = "ab".repeat(32).into();
    std::fs::write(related_path, serde_json::to_vec(&related).unwrap()).unwrap();
    assert!(invoke()["evidence"][0]["related_metrics"].is_null());
}

#[test]
fn changed_endpoint_requires_explicit_matching_project_and_selected_id() {
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nudox-189f");
    let tmp = tempfile::tempdir().unwrap();
    for name in [
        "manifest.json",
        "inputs.json",
        "before.json",
        "after.json",
        "graph.json",
        "source.json",
        "related.json",
    ] {
        std::fs::copy(fixture.join(name), tmp.path().join(name)).unwrap();
    }
    let inputs_path = tmp.path().join("inputs.json");
    let mut inputs: Value = serde_json::from_slice(&std::fs::read(&inputs_path).unwrap()).unwrap();
    inputs["changes"] = serde_json::json!(["other.rs"]);
    inputs["observations"][0]
        .as_object_mut()
        .unwrap()
        .remove("graph");
    std::fs::write(&inputs_path, serde_json::to_vec(&inputs).unwrap()).unwrap();
    let related_path = tmp.path().join("related.json");
    let mut related: Value =
        serde_json::from_slice(&std::fs::read(&related_path).unwrap()).unwrap();
    let edge = related["edges"][0].clone();
    let mut reverse = edge.clone();
    reverse["from"] = edge["to"].clone();
    reverse["from_id"] = edge["to_id"].clone();
    reverse["to"] = edge["from"].clone();
    reverse["to_id"] = edge["from_id"].clone();
    related["edges"] = serde_json::json!([reverse]);
    let id = edge["from_id"]
        .as_str()
        .unwrap()
        .strip_prefix("symbol:")
        .unwrap();
    related["records"] = serde_json::json!([{"identity": {"coordinate":edge["from"], "path":"other.rs", "semantic_data":{"kind":"selected-symbol-id","value":id}}}]);
    let invoke = |page: &Value| {
        std::fs::write(&related_path, serde_json::to_vec(page).unwrap()).unwrap();
        let out = Command::new(env!("CARGO_BIN_EXE_keel-judge"))
            .args(["guidance", "--manifest"])
            .arg(tmp.path().join("manifest.json"))
            .arg("--inputs")
            .arg(&inputs_path)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "{}",
            String::from_utf8_lossy(&out.stderr)
        );
        serde_json::from_slice::<Value>(&out.stdout).unwrap()
    };
    let result = invoke(&related);
    assert_eq!(
        result["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"],
        0
    );
    related["records"][0]["identity"]["project"] = "/workspace/example".into();
    let result = invoke(&related);
    assert_eq!(result["cases"], serde_json::json!(["fanout", "unobserved"]));
    assert_eq!(
        result["evidence"][0]["status"], "unknown",
        "missing legacy graph remains unknown"
    );
    assert_eq!(
        result["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"],
        1
    );
    related["records"][0]["identity"]["semantic_data"]["value"] = "ff".repeat(32).into();
    let result = invoke(&related);
    assert_eq!(
        result["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"],
        0
    );
}

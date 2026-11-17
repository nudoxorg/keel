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
    let ids: Vec<_> = (1..=4).map(|n| format!("symbol:{n:064x}")).collect();
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
    // Protocol control: a nonseed endpoint requires a matching visible owner
    // statement. These fields are synthetic; this does not verify an owner MAC.
    page["records"] = serde_json::json!([{ "identity": {
        "project":"/workspace/example", "path":"src/lib.rs", "coordinate":"b",
        "semantic_data":{"kind":"selected-symbol-id", "value":ids[1].strip_prefix("symbol:").unwrap()}
    }}]);
    page["related_project_scope"] = serde_json::json!({"source_relation_root":"66".repeat(32), "workspace_root":"77".repeat(32)});
    page["related_project_attributions"] = serde_json::json!([{
        "row_id":ids[1], "project":"/workspace/example", "path":"src/lib.rs",
        "view_root":before["revision"], "semantic_revision":"44".repeat(32),
        "source_relation_root":"66".repeat(32), "workspace_root":"77".repeat(32),
        "project_key":"88".repeat(32), "source_fact":"99".repeat(32),
        "image_digest":"aa".repeat(32), "seal":"bb".repeat(32), "entity_index":0
    }]);
    std::fs::write(&path, serde_json::to_vec(&page).unwrap()).unwrap();
    let v: Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(
        v["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"],
        2
    );
    for field in [
        "row_id",
        "project",
        "path",
        "view_root",
        "semantic_revision",
        "source_relation_root",
        "workspace_root",
        "project_key",
        "source_fact",
        "image_digest",
        "seal",
        "entity_index",
    ] {
        let mut invalid = page.clone();
        invalid["related_project_attributions"][0][field] = Value::Null;
        std::fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
        let v: Value = serde_json::from_slice(&run().stdout).unwrap();
        assert_eq!(
            v["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"], 1,
            "{field}"
        );
        assert_eq!(
            v["evidence"][0]["related_metrics"]["observed_call_edges"], 5,
            "{field}"
        );
    }
    let mut naked = page.clone();
    naked["related_project_attributions"] = Value::Null;
    std::fs::write(&path, serde_json::to_vec(&naked).unwrap()).unwrap();
    let v: Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(
        v["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"],
        1
    );
    let mut duplicate = page.clone();
    let claim = duplicate["related_project_attributions"][0].clone();
    duplicate["related_project_attributions"]
        .as_array_mut()
        .unwrap()
        .push(claim);
    std::fs::write(&path, serde_json::to_vec(&duplicate).unwrap()).unwrap();
    let v: Value = serde_json::from_slice(&run().stdout).unwrap();
    assert_eq!(
        v["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"],
        1
    );
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
    let original = source["identity"]["semantic_data"]["value"]
        .as_str()
        .unwrap()
        .to_owned();
    let legacy = original
        .as_bytes()
        .chunks_exact(2)
        .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
        .collect::<Vec<_>>();
    source["identity"]["semantic_data"]["value"] = serde_json::json!(legacy);
    std::fs::write(&source_path, serde_json::to_vec(&source).unwrap()).unwrap();
    assert!(
        invoke()["evidence"][0]["related_metrics"].is_object(),
        "nonzero legacy bytes remain supported"
    );
    for invalid in [
        serde_json::json!(original.to_ascii_uppercase()),
        serde_json::json!("0".repeat(64)),
        serde_json::json!(vec![0u8; 32]),
    ] {
        source["identity"]["semantic_data"]["value"] = invalid;
        std::fs::write(&source_path, serde_json::to_vec(&source).unwrap()).unwrap();
        assert!(
            invoke()["evidence"][0]["related_metrics"].is_null(),
            "invalid source ID must not establish related metrics"
        );
    }
    source["identity"]["semantic_data"]["value"] = "ab".repeat(32).into();
    std::fs::write(&source_path, serde_json::to_vec(&source).unwrap()).unwrap();
    assert!(invoke()["evidence"][0]["related_metrics"].is_null());
    std::fs::copy(fixture.join("source.json"), &source_path).unwrap();
    let after_path = tmp.path().join("after.json");
    let mut after: Value = serde_json::from_slice(&std::fs::read(&after_path).unwrap()).unwrap();
    after["source"] = "ab".repeat(32).into();
    std::fs::write(after_path, serde_json::to_vec(&after).unwrap()).unwrap();
    assert!(invoke()["evidence"][0]["related_metrics"].is_null());
    std::fs::copy(fixture.join("after.json"), tmp.path().join("after.json")).unwrap();
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
    assert_eq!(
        result["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"],
        0
    );
    related["related_project_scope"] = serde_json::json!({"source_relation_root":"66".repeat(32), "workspace_root":"77".repeat(32)});
    related["related_project_attributions"] = serde_json::json!([{
        "row_id": edge["from_id"], "project":"/workspace/example", "path":"other.rs",
        "view_root": related["related_basis"]["source_view_root"],
        "semantic_revision": related["related_basis"]["semantic_revision"],
        "source_relation_root":"66".repeat(32), "workspace_root":"77".repeat(32),
        "project_key":"88".repeat(32), "source_fact":"99".repeat(32),
        "image_digest":"aa".repeat(32), "seal":"bb".repeat(32), "entity_index":0
    }]);
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
    for invalid in [
        serde_json::json!(id.to_ascii_uppercase()),
        serde_json::json!("0".repeat(64)),
        serde_json::json!(vec![0u8; 32]),
    ] {
        related["records"][0]["identity"]["semantic_data"]["value"] = invalid;
        let result = invoke(&related);
        assert_eq!(
            result["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"], 0,
            "invalid record ID must not attribute a changed endpoint"
        );
    }
    related["records"][0]["identity"]["semantic_data"]["value"] = "ff".repeat(32).into();
    let result = invoke(&related);
    assert_eq!(
        result["evidence"][0]["related_metrics"]["observed_reachable_changed_nodes"],
        0
    );
}

#[test]
fn receipt_bound_related_chain_checks_handoffs_and_source_basis() {
    use sha2::{Digest, Sha256};
    let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/data/nudox-189f");
    let tmp = tempfile::tempdir().unwrap();
    for name in [
        "manifest.json",
        "inputs.json",
        "before.json",
        "graph.json",
        "source.json",
        "after.json",
        "related.json",
    ] {
        std::fs::copy(fixture.join(name), tmp.path().join(name)).unwrap();
    }
    let hash = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    let digest = |name: &str| hash(&std::fs::read(tmp.path().join(name)).unwrap());
    let inputs_path = tmp.path().join("inputs.json");
    let mut inputs: Value = serde_json::from_slice(&std::fs::read(&inputs_path).unwrap()).unwrap();
    inputs["observations"][0]["related"] = serde_json::json!([]);
    inputs["observations"][0]["related_chains"] = serde_json::json!([{
        "report":"report.json", "before_step":"before", "source_step":"source", "step":"pages", "after_step":"after",
        "pages":[{"request":"request0.json","reply":"reply0.json"},{"request":"request1.json","reply":"reply1.json"}]
    }]);
    std::fs::write(&inputs_path, serde_json::to_vec(&inputs).unwrap()).unwrap();
    let original: Value =
        serde_json::from_slice(&std::fs::read(tmp.path().join("related.json")).unwrap()).unwrap();
    let coordinate = original["related_basis"]["coordinate"].clone();
    let continuation = serde_json::json!({"name":"backend.related","arguments":{"coordinate":coordinate,"cursor":"opaque-cursor","limit":20}});
    let req0 = serde_json::json!({"jsonrpc":"2.0","id":1,"method":"tools/call","params":{"name":"backend.related","arguments":{"coordinate":coordinate,"limit":20}}});
    let req1 =
        serde_json::json!({"jsonrpc":"2.0","id":2,"method":"tools/call","params":continuation});
    let mut first = original.clone();
    let mut last = original.clone();
    let edges = original["edges"].as_array().unwrap();
    first["edges"] = serde_json::json!(edges[..4]);
    last["edges"] = serde_json::json!(edges[4..]);
    first["more"] = true.into();
    first["nextCursor"] = "opaque-cursor".into();
    first["continuation_call"] = continuation;
    last["related_basis"]["neighborhood_root"] = "ab".repeat(32).into();
    let requests = [req0, req1];
    let replies = [
        serde_json::json!({"jsonrpc":"2.0","id":1,"result":{"structuredContent":first}}),
        serde_json::json!({"jsonrpc":"2.0","id":2,"result":{"structuredContent":last}}),
    ];
    for i in 0..2 {
        std::fs::write(
            tmp.path().join(format!("request{i}.json")),
            serde_json::to_vec(&requests[i]).unwrap(),
        )
        .unwrap();
        std::fs::write(
            tmp.path().join(format!("reply{i}.json")),
            serde_json::to_vec(&replies[i]).unwrap(),
        )
        .unwrap();
    }
    let report = serde_json::json!({"schema":1,"status":"pass","driver_sha256":"11".repeat(32),"manifest_sha256":digest("manifest.json"),"cases":[{"id":"fanout","status":"pass","steps":[
        {"id":"before","status":"pass","detail":{"stdout_sha256":digest("before.json")}},
        {"id":"source","status":"pass","detail":{"stdout_sha256":digest("source.json")}},
        {"id":"pages","status":"pass","detail":{"page_receipts":[
            {"pid":123,"request_id":1,"request_sha256":digest("request0.json"),"reply_sha256":digest("reply0.json")},
            {"pid":123,"request_id":2,"request_sha256":digest("request1.json"),"reply_sha256":digest("reply1.json")}
        ]}},
        {"id":"after","status":"pass","detail":{"stdout_sha256":digest("after.json")}}
    ]}]});
    let report_path = tmp.path().join("report.json");
    std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
    let run = || {
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
    let good = run();
    assert_eq!(
        good["evidence"][0]["related_metrics"]["observed_call_edges"],
        8
    );
    for field in ["pid", "request_id", "request_sha256", "reply_sha256"] {
        let mut bad = report.clone();
        bad["cases"][0]["steps"][2]["detail"]["page_receipts"][1][field] = Value::Null;
        std::fs::write(&report_path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(run()["evidence"][0]["related_metrics"].is_null(), "{field}");
    }
    let mut bad = report.clone();
    bad["manifest_sha256"] = "00".repeat(32).into();
    std::fs::write(&report_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(run()["evidence"][0]["related_metrics"].is_null());
    std::fs::write(&report_path, serde_json::to_vec(&report).unwrap()).unwrap();
    let mut bad_request = requests[1].clone();
    bad_request["params"]["arguments"]["cursor"] = "other".into();
    std::fs::write(
        tmp.path().join("request1.json"),
        serde_json::to_vec(&bad_request).unwrap(),
    )
    .unwrap();
    let mut bad = report.clone();
    bad["cases"][0]["steps"][2]["detail"]["page_receipts"][1]["request_sha256"] =
        digest("request1.json").into();
    std::fs::write(&report_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(
        run()["evidence"][0]["related_metrics"].is_null(),
        "rehashed wrong continuation"
    );
    std::fs::write(
        tmp.path().join("request1.json"),
        serde_json::to_vec(&requests[1]).unwrap(),
    )
    .unwrap();
    for variant in [
        "stale_basis",
        "repeat_edge",
        "conflicting_row",
        "not_terminal",
        "withheld",
    ] {
        let mut bad_reply = replies[1].clone();
        let page = &mut bad_reply["result"]["structuredContent"];
        match variant {
            "stale_basis" => page["related_basis"]["semantic_revision"] = "dd".repeat(32).into(),
            "repeat_edge" => page["edges"]
                .as_array_mut()
                .unwrap()
                .push(replies[0]["result"]["structuredContent"]["edges"][0].clone()),
            "conflicting_row" => page["records"][0]["identity"]["coordinate"] = "different".into(),
            "not_terminal" => page["more"] = true.into(),
            "withheld" => page["related_evidence_withheld"] = true.into(),
            _ => unreachable!(),
        }
        std::fs::write(
            tmp.path().join("reply1.json"),
            serde_json::to_vec(&bad_reply).unwrap(),
        )
        .unwrap();
        let mut bad = report.clone();
        bad["cases"][0]["steps"][2]["detail"]["page_receipts"][1]["reply_sha256"] =
            digest("reply1.json").into();
        std::fs::write(&report_path, serde_json::to_vec(&bad).unwrap()).unwrap();
        assert!(
            run()["evidence"][0]["related_metrics"].is_null(),
            "{variant}"
        );
    }
    let mut first_claim = replies[0].clone();
    let mut last_claim = replies[1].clone();
    first_claim["result"]["structuredContent"]["related_project_attributions"] =
        serde_json::json!([{"row_id":"symbol:abc", "path":"a"}]);
    last_claim["result"]["structuredContent"]["related_project_attributions"] =
        serde_json::json!([{"row_id":"symbol:abc", "path":"b"}]);
    std::fs::write(
        tmp.path().join("reply0.json"),
        serde_json::to_vec(&first_claim).unwrap(),
    )
    .unwrap();
    std::fs::write(
        tmp.path().join("reply1.json"),
        serde_json::to_vec(&last_claim).unwrap(),
    )
    .unwrap();
    let mut bad = report.clone();
    bad["cases"][0]["steps"][2]["detail"]["page_receipts"][0]["reply_sha256"] =
        digest("reply0.json").into();
    bad["cases"][0]["steps"][2]["detail"]["page_receipts"][1]["reply_sha256"] =
        digest("reply1.json").into();
    std::fs::write(&report_path, serde_json::to_vec(&bad).unwrap()).unwrap();
    assert!(
        run()["evidence"][0]["related_metrics"].is_null(),
        "conflicting claims"
    );
}

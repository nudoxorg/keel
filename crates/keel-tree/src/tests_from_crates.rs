//! `nodesFromCrates`: the nodes made from the packages no node claims.

use crate::check;
use crate::finding::Severity;
use crate::fixtures::{Fixture, model, standard};
use crate::resolve::Resolution;
use crate::testset::TestTable;
use keel_index::Target;
use std::path::Path;

fn written(id: &str, code: &str, extra: &str) -> String {
    format!(
        r#"{{"id":"{id}","at":"/m/keel.nix:7","parent":null,"about":null,"code":[{code}],"entry":[],"on":[],"never":[],"of":[],"ship":null,"movedBy":[],"unmovedBy":[]{extra}}}"#
    )
}

fn krate(name: &str) -> String {
    format!(r#"{{"by":"crate","name":"{name}"}}"#)
}

fn path(glob: &str) -> String {
    format!(r#"{{"by":"path","glob":"{glob}"}}"#)
}

/// A model with `nodes` and `nodesFromCrates` stripping `strip` from the packages under
/// `crates/`, written at line 3.
fn asking(nodes: &[String], strip: &str) -> String {
    asking_under(nodes, strip, &["crates/**"])
}

fn asking_under(nodes: &[String], strip: &str, under: &[&str]) -> String {
    let under: Vec<String> = under.iter().map(|g| format!("\"{g}\"")).collect();
    format!(
        r#"{{"schema":2,"nodes":[{}],"nodesFromCrates":{{"strip":"{strip}","under":[{}],"at":"/m/keel.nix:3"}},"policy":{{"faults":"report"}}}}"#,
        nodes.join(","),
        under.join(",")
    )
}

/// Packages `backend-a`, `backend-b` (stands on a), `other` (stands on b), in directories of their own.
fn prefixed() -> Fixture {
    Fixture {
        packages: vec![
            ("backend-a", "crates/a", vec![], vec![]),
            ("backend-b", "crates/b", vec![0], vec![]),
            ("other", "crates/other", vec![1], vec![]),
        ],
        files: vec![
            ("crates/a/src/lib.rs", Some(0), Target::Lib),
            ("crates/b/src/lib.rs", Some(1), Target::Lib),
            ("crates/other/src/lib.rs", Some(2), Target::Lib),
        ],
        tests: vec![(0, "tests::a", false), (1, "tests::b", false), (2, "tests::other", false)],
    }
}

fn resolve<'a>(json: &str, idx: &'a keel_index::CodeIndex) -> Resolution<'a> {
    Resolution::build(&model(json), idx, Path::new("/nonexistent"))
}

fn ids(r: &Resolution<'_>) -> Vec<String> {
    r.nodes.iter().map(|n| n.id.clone()).collect()
}

#[test]
fn every_workspace_package_no_node_claims_becomes_a_top_level_node_without_a_prefix_it_lacks() {
    let idx = prefixed().index();
    // Nothing is written: all three packages are derived, `other` keeps its name whole.
    let r = resolve(&asking(&[], "backend-"), &idx);
    assert_eq!(ids(&r), ["a", "b", "other", "unowned"]);
    for n in &r.nodes[..3] {
        assert!(n.parent.is_none() && n.children.is_empty() && n.about.is_none() && n.ship.is_none());
        assert!(n.on.is_empty() && n.never.is_empty() && n.of.is_empty());
        assert_eq!(n.at.as_deref(), Some("/m/keel.nix:3"), "a made node points at the line that asked for it");
    }
    assert_eq!(r.nodes[0].from_crate.as_deref(), Some("backend-a"));
    assert_eq!(r.nodes[2].from_crate.as_deref(), Some("other"));
    assert!(r.findings.iter().all(|f| f.severity != Severity::Error), "{:?}", r.findings);
    // Their edges come from the packages, like any node's.
    let (a, b, other) = (r.node_index("a").unwrap(), r.node_index("b").unwrap(), r.node_index("other").unwrap());
    assert!(r.prod[b].contains(&a) && r.prod[other].contains(&b));
    // And they own their files, so nothing is left to `unowned`.
    assert_eq!(r.nodes[a].own_files, 1);
    assert!(r.unowned_by_package().is_empty());
}

#[test]
fn a_package_a_crate_selector_claims_is_not_made_in_either_spelling_and_a_path_selector_does_not_claim() {
    let idx = prefixed().index();
    let r = resolve(&asking(&[written("alpha", &krate("backend_a"), "")], "backend-"), &idx);
    assert_eq!(ids(&r), ["alpha", "b", "other", "unowned"]);
    // `backend-a` is claimed by a path only: it still gets its node, which owns the files the
    // path does not take (none here, so the path node wins the only file).
    let r = resolve(&asking(&[written("alpha", &path("crates/a/**"), "")], "backend-"), &idx);
    assert_eq!(ids(&r), ["alpha", "a", "b", "other", "unowned"]);
    assert_eq!(r.nodes[r.node_index("alpha").unwrap()].own_files, 1);
    assert_eq!(r.nodes[r.node_index("a").unwrap()].own_files, 0);
}

#[test]
fn only_workspace_members_get_a_node() {
    let mut idx = prefixed().index();
    idx.packages[2].member = false;
    let r = resolve(&asking(&[], "backend-"), &idx);
    assert_eq!(ids(&r), ["a", "b", "unowned"]);
}

/// `prefixed` plus a test suite and a vendored library, in directories of their own.
fn with_tests_and_vendor() -> Fixture {
    let mut fx = prefixed();
    fx.packages.push(("backend-journeys", "tests/journeys", vec![1], vec![]));
    fx.packages.push(("gpui-ce", "vendor/gpui-ce", vec![], vec![]));
    fx.files.push(("tests/journeys/src/lib.rs", Some(3), Target::Lib));
    fx.files.push(("vendor/gpui-ce/src/lib.rs", Some(4), Target::Lib));
    fx
}

#[test]
fn only_a_package_whose_directory_is_under_a_listed_glob_becomes_a_node() {
    let idx = with_tests_and_vendor().index();
    // crates/ only: the test suite and the vendored library stay unowned, whatever they depend on.
    let r = resolve(&asking(&[], "backend-"), &idx);
    assert_eq!(ids(&r), ["a", "b", "other", "unowned"]);
    assert!(r.unowned_by_package().contains_key("backend-journeys"));
    // Listing vendor/ adds exactly that one, named whole because it lacks the prefix.
    let r = resolve(&asking_under(&[], "backend-", &["crates/**", "vendor/**"]), &idx);
    assert_eq!(ids(&r), ["a", "b", "gpui-ce", "other", "unowned"]);
    assert!(r.findings.iter().all(|f| f.severity != Severity::Error), "{:?}", r.findings);
    // A single-level glob matches the directory itself, not what is below it.
    let r = resolve(&asking_under(&[], "backend-", &["crates/*"]), &idx);
    assert_eq!(ids(&r), ["a", "b", "other", "unowned"]);
}

#[test]
fn an_under_glob_that_matches_no_package_directory_or_does_not_parse_is_an_error() {
    let idx = with_tests_and_vendor().index();
    let r = resolve(&asking_under(&[], "backend-", &["crates/**", "tools/**"]), &idx);
    let f = r.findings.iter().find(|f| f.code == "selector-matches-nothing").expect("a glob that matches nothing");
    assert_eq!(f.severity, Severity::Error);
    assert!(f.message.contains("\"tools/**\"") && f.message.contains("Fix the glob or remove it"), "{}", f.message);
    assert_eq!(f.at.as_deref(), Some("/m/keel.nix:3"));
    // The glob that does match still makes its nodes.
    assert_eq!(ids(&r), ["a", "b", "other", "unowned"]);
    let r = resolve(&asking_under(&[], "backend-", &["crates/[**"]), &idx);
    assert!(r.findings.iter().any(|f| f.code == "bad-glob" && f.message.contains("crates/[**")), "{:?}", r.findings);
}

#[test]
fn an_id_a_node_already_has_is_an_error_that_names_the_package_the_node_and_what_to_do() {
    let idx = prefixed().index();
    // `a` is written, by a path, and the package backend-a would be named a as well.
    let r = resolve(&asking(&[written("a", &path("crates/other/**"), "")], "backend-"), &idx);
    let f = r.findings.iter().find(|f| f.code == "node-from-crate-collision").expect("collision");
    assert_eq!(f.severity, Severity::Error);
    for part in [
        "package \"backend-a\"",
        "node \"a\"",
        "/m/keel.nix:7",
        "crate \"backend-a\"",
        "under another name",
    ] {
        assert!(f.message.contains(part), "{part}: {}", f.message);
    }
    assert_eq!(f.at.as_deref(), Some("/m/keel.nix:3"));
    // The written node stays, and the package is not made a second node.
    assert_eq!(ids(&r), ["a", "b", "other", "unowned"]);
    assert_eq!(r.nodes[0].from_crate, None);
}

#[test]
fn two_packages_with_one_id_and_the_engines_own_unowned_cannot_be_made() {
    let mut fx = prefixed();
    fx.packages.push(("a", "crates/plain-a", vec![], vec![]));
    fx.packages.push(("backend-unowned", "crates/un", vec![], vec![]));
    fx.files.push(("crates/plain-a/src/lib.rs", Some(3), Target::Lib));
    fx.files.push(("crates/un/src/lib.rs", Some(4), Target::Lib));
    let idx = fx.index();
    let r = resolve(&asking(&[], "backend-"), &idx);
    let collisions: Vec<&str> = r.findings.iter().filter(|f| f.code == "node-from-crate-collision").map(|f| f.message.as_str()).collect();
    assert_eq!(collisions.len(), 2, "{collisions:?}");
    assert!(collisions.iter().any(|m| m.contains("packages \"a\" and \"backend-a\"") || m.contains("packages \"backend-a\" and \"a\"")), "{collisions:?}");
    assert!(collisions.iter().any(|m| m.contains("package \"backend-unowned\"") && m.contains("the engine gives")), "{collisions:?}");
    // Packages come in name order: "a" is made, "backend-a" is the one that collides.
    assert_eq!(r.nodes.iter().filter(|n| n.id == "a").count(), 1);
    assert_eq!(r.nodes.iter().filter(|n| n.id == "unowned").count(), 1);
}

#[test]
fn without_the_cargo_index_it_says_so_instead_of_making_nothing() {
    let idx = prefixed().index();
    let mdl = model(&asking(&[written("a", &path("crates/a/**"), "")], "backend-"));
    let r = Resolution::build_with(&mdl, &idx, Path::new("/nonexistent"), Some("no cargo here"));
    let f = r.findings.iter().find(|f| f.code == "cargo-required").expect("finding");
    assert!(f.message.contains("nodesFromCrates") && f.message.contains("no cargo here"), "{}", f.message);
    assert!(crate::source::needs_cargo(&mdl), "asking for the nodes needs the index even when no node names a crate");
}

#[test]
fn the_lock_marks_the_made_nodes_and_is_the_same_on_every_run_in_package_order() {
    let idx = prefixed().index();
    let json = asking(&[written("hand", &path("crates/other/**"), "")], "backend-");
    let lock = |json: &str| {
        let r = resolve(json, &idx);
        serde_json::to_string_pretty(&r.lock(&[])).unwrap()
    };
    let first = lock(&json);
    assert_eq!(first, lock(&json));
    let parsed: crate::lock::Lock = serde_json::from_str(&first).unwrap();
    let from: Vec<(&str, Option<&str>)> = parsed.nodes.iter().map(|(id, n)| (id.as_str(), n.from_crate.as_deref())).collect();
    assert_eq!(
        from,
        [("a", Some("backend-a")), ("b", Some("backend-b")), ("hand", None), ("other", Some("other")), ("unowned", None)]
    );
    // A hand-written node has no such key at all, so locks written before it existed still read.
    assert_eq!(first.matches("from_crate").count(), 3);
    // Moving a node between the two shows in the diff, even though no edge moves.
    let by_hand = resolve(
        &format!(
            r#"{{"schema":2,"nodes":[{},{}],"policy":{{"faults":"report"}}}}"#,
            written("hand", &path("crates/other/**"), ""),
            written("a", &krate("backend-a"), "")
        ),
        &idx,
    )
    .lock(&[]);
    let diff = crate::lock::diff(&by_hand, &parsed);
    assert!(diff.contains(&"a: now derived from package backend-a (nodesFromCrates), no longer written by hand".to_owned()), "{diff:?}");
}

#[test]
fn check_counts_the_made_nodes_and_tree_marks_them() {
    let idx = standard().index();
    let top = written("top", &krate("top"), "").replace(r#""ship":null"#, r#""ship":"required""#);
    let mdl = model(&asking(&[top], ""));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    let rep = check::run(&mdl, &r, &table, None, false).unwrap();
    assert_eq!(rep.summary.nodes_from_crates, 3);
    assert!(rep.headline().contains(": 4 nodes (3 from crates, 1 feature), "), "{}", rep.headline());
    assert!(rep.render().contains("(3 made from crates by nodesFromCrates, "), "{}", rep.render());
    let text = crate::tree::render_all(&crate::tree::run(&r, &table, Some("top")).unwrap());
    assert!(text.contains("> mid*  [") && text.contains("> core*  [") && !text.contains("top*"), "{text}");
    let json = serde_json::to_value(crate::tree::run(&r, &table, Some("top")).unwrap()).unwrap();
    assert!(json[0]["lines"].as_array().unwrap().iter().any(|l| l["node"] == "mid" && l["from_crate"] == "mid"));
}

#[test]
fn the_field_is_read_by_a_typed_home_and_a_model_without_it_makes_nothing() {
    let mdl = model(&asking(&[], "backend-"));
    assert!(mdl.unread.is_empty(), "{:?}", mdl.unread);
    let n = mdl.nodes_from_crates.as_ref().unwrap();
    assert_eq!((n.strip.as_str(), n.at.as_deref()), ("backend-", Some("/m/keel.nix:3")));
    assert_eq!(n.under, ["crates/**"]);
    let idx = prefixed().index();
    let plain = model(&format!(r#"{{"schema":2,"nodes":[{}]}}"#, written("only", &krate("backend-a"), "")));
    let r = Resolution::build(&plain, &idx, Path::new("/nonexistent"));
    assert_eq!(ids(&r), ["only", "unowned"]);
    assert!(crate::from_crates::nodes(&plain, &idx, None).0.is_empty());
}

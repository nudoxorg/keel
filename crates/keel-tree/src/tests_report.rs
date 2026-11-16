//! The report a person reads: what is folded, what is counted first, and what `--watch` looks at.

use crate::check::{self, Entry};
use crate::finding::{Finding, Severity};
use crate::fixtures::{model, standard};
use crate::resolve::Resolution;
use crate::testset::TestTable;
use std::collections::BTreeSet;
use std::path::Path;

fn node(id: &str, krate: &str) -> String {
    format!(
        r#"{{"id":"{id}","at":"/m/keel.nix:1","parent":null,"about":null,"code":[{{"by":"crate","name":"{krate}"}}],"entry":[],"on":[],"never":[],"of":[],"ship":null,"movedBy":[],"unmovedBy":[]}}"#
    )
}

/// The four standard packages and `probe`, which stands on two of them, each a node, with faults
/// reported rather than failed.
fn chain() -> String {
    let nodes: Vec<String> = ["core", "mid", "top", "tooling", "probe"].iter().map(|n| node(n, n)).collect();
    format!(r#"{{"schema":2,"nodes":[{}],"policy":{{"faults":"report"}}}}"#, nodes.join(","))
}

fn report() -> check::CheckReport {
    let mut fx = standard();
    fx.packages.push(("probe", "crates/probe", vec![2, 3], vec![]));
    fx.files.push(("crates/probe/src/lib.rs", Some(4), keel_index::Target::Lib));
    let idx = fx.index();
    let mdl = model(&chain());
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    check::run(&mdl, &r, &table, None, false).unwrap()
}

fn shared(code: &'static str, entry: &str, advice: &str) -> Finding {
    Finding::info(code, format!("{entry}. {advice}")).sharing(entry.to_owned(), advice.to_owned())
}

#[test]
fn findings_of_one_kind_and_advice_fold_into_one_entry_and_the_odd_one_stays_whole() {
    let (a, b, c) = (shared("edge", "x on a", "Fix."), shared("edge", "y on b", "Fix."), shared("edge", "z on c", "Fix."));
    let other_advice = shared("edge", "w on d", "Do something else.");
    let other_code = shared("other", "v on e", "Fix.");
    let plain = Finding::info("edge", "unrelated".to_owned());
    let all = [&a, &other_advice, &b, &other_code, &plain, &c];
    let entries = check::fold(&all, false);
    // Smaller entries first, the folded one last; the three that stand alone keep their order.
    assert_eq!(entries.len(), 4);
    let Some(Entry::Many { advice, members }) = entries.last() else { panic!("the last entry is the folded one") };
    assert_eq!((*advice, members.len()), ("Fix.", 3));
    assert!(matches!(&entries[0], Entry::One(f) if f.message == other_advice.message));
    assert!(matches!(&entries[2], Entry::One(f) if f.message == "unrelated"));
    // A finding that shares its advice with no sibling is shown whole, with its own message.
    let alone = check::fold(&[&a], false);
    assert!(matches!(alone.as_slice(), [Entry::One(f)] if f.message == "x on a. Fix."));
    // `--all` is one entry per finding, in the order given.
    let every = check::fold(&all, true);
    assert_eq!(every.len(), 6);
    assert!(matches!(&every[1], Entry::One(f) if f.message == other_advice.message));
}

#[test]
fn the_text_report_folds_edges_with_a_count_the_nodes_and_three_examples_and_all_prints_every_one() {
    let rep = report();
    let faults: Vec<&Finding> = rep.findings.iter().filter(|f| f.code == "edge-never-faulted").collect();
    assert!(faults.len() > 3, "the fixture must have more edges than examples: {}", faults.len());
    let nodes: BTreeSet<&str> = faults.iter().filter_map(|f| f.node.as_deref()).collect();
    let folded = rep.render_with(false);
    assert!(folded.contains(&format!("edge-never-faulted  {} entries on {}", faults.len(), nodes.len())), "{folded}");
    let infos = folded.split("infos (").nth(1).expect("an infos section");
    let shown = infos.lines().filter(|l| l.starts_with("        ") && l.contains(" stands on ")).count();
    assert_eq!(shown, 3, "{folded}");
    assert!(folded.contains(&format!("and {} more; --all lists every entry", faults.len() - 3)), "{folded}");
    // The advice is said once, and not once per edge.
    assert_eq!(folded.matches("Add a fault check whose").count(), 1, "{folded}");
    let every = rep.render_with(true);
    assert!(!every.contains("entries on"), "{every}");
    assert_eq!(every.matches("  edge-never-faulted  node ").count(), faults.len(), "{every}");
    for f in &faults {
        assert!(every.contains(f.message.split(';').next().unwrap()), "{}", f.message);
    }
    // The JSON keeps every entry, and the folding is no part of it.
    let json = serde_json::to_value(&rep).unwrap();
    let in_json = json["findings"].as_array().unwrap().iter().filter(|f| f["code"] == "edge-never-faulted").count();
    assert_eq!(in_json, faults.len());
    assert!(json["findings"][0].get("shared").is_none());
}

#[test]
fn a_folded_entrys_examples_keep_their_model_position() {
    let folded = report().render();
    let example = folded.lines().find(|l| l.starts_with("        ") && l.contains(" stands on ")).expect("an example");
    assert!(example.contains("  at /m/keel.nix:1"), "{example}");
}

#[test]
fn the_headline_says_whether_the_model_holds_and_counts_what_is_in_it() {
    let mut rep = report();
    rep.findings.retain(|f| f.severity != Severity::Error);
    rep.summary.tests_in_table = 15_496;
    rep.summary.check_cells = 256;
    let infos = rep.findings.iter().filter(|f| f.severity == Severity::Info).count();
    let kinds = rep.findings.iter().map(|f| f.code).collect::<BTreeSet<_>>().len();
    assert_eq!(
        rep.headline(),
        format!("model ok: 5 nodes (0 features), 15,496 tests, 256 check cells; 0 errors, 0 warnings, {infos} infos in {kinds} kind{}", if kinds == 1 { "" } else { "s" })
    );
    assert!(rep.render().starts_with("model ok: 5 nodes"));
    rep.findings.push(Finding::error("unknown-node", "x".to_owned()));
    assert!(rep.headline().starts_with("model has 1 error: 5 nodes"), "{}", rep.headline());
    assert!(rep.headline().contains("; 1 error, 0 warnings, "), "{}", rep.headline());
}

fn scratch(name: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("keel-tree-watch-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn watch_lists_the_models_directory_and_the_nix_files_it_imports_by_relative_path() {
    let d = scratch("files");
    std::fs::create_dir_all(d.join("models/app/sub")).unwrap();
    std::fs::create_dir_all(d.join("lib")).unwrap();
    std::fs::write(d.join("models/app/eval.nix"), "import ../../lib/keel.nix { root = ../../app; }\n").unwrap();
    std::fs::write(d.join("models/app/sub/more.nix"), "{ }\n").unwrap();
    std::fs::write(d.join("models/app/notes.txt"), "not nix\n").unwrap();
    std::fs::write(d.join("lib/keel.nix"), "let helper = import ./helper.nix; in helper\n").unwrap();
    std::fs::write(d.join("lib/helper.nix"), "{ }\n").unwrap();
    std::fs::write(d.join("lib/unrelated.nix"), "{ }\n").unwrap();
    let base = d.canonicalize().unwrap();
    let names: Vec<String> = crate::watch::files(&d.join("models/app/eval.nix"))
        .iter()
        .map(|p| p.strip_prefix(&base).unwrap().display().to_string())
        .collect();
    assert_eq!(names, ["lib/helper.nix", "lib/keel.nix", "models/app/eval.nix", "models/app/sub/more.nix"]);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn watch_notices_an_edit_a_new_file_and_a_file_that_went_away() {
    let d = scratch("change");
    let model = d.join("eval.nix");
    std::fs::write(&model, "{ }\n").unwrap();
    let seen = crate::watch::snapshot(&crate::watch::files(&model));
    assert_eq!(seen.len(), 1);
    // The size differs, so the edit shows even where the clock is coarse.
    let writer = {
        let model = model.clone();
        std::thread::spawn(move || {
            std::thread::sleep(std::time::Duration::from_millis(150));
            std::fs::write(&model, "{ a = 1; }\n").unwrap();
        })
    };
    let now = crate::watch::wait_for_change(&model, &seen);
    writer.join().unwrap();
    assert_ne!(now, seen);
    std::fs::write(d.join("added.nix"), "{ }\n").unwrap();
    assert_eq!(crate::watch::snapshot(&crate::watch::files(&model)).len(), 2);
    std::fs::remove_file(d.join("added.nix")).unwrap();
    assert_eq!(crate::watch::snapshot(&crate::watch::files(&model)), now);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn the_separator_gives_the_time_and_how_long_the_check_took() {
    let line = crate::watch::separator(Path::new("models/backend/eval.nix"), 3, std::time::Duration::from_millis(4250));
    assert!(line.starts_with("---- ") && line.ends_with(" ----"), "{line}");
    assert!(line.contains(" UTC  check took 4.2 s; watching 3 .nix files (under models/backend"), "{line}");
    let time = &line[5..13];
    assert!(time.bytes().enumerate().all(|(i, b)| if i % 3 == 2 { b == b':' } else { b.is_ascii_digit() }), "{time}");
}

// ── Where tests sit on an axis ───────────────────────────────────────────

/// The four standard packages as nodes, a `tier` axis, and one rule: the integration target of
/// `top` is a journey. `defaults` is the model's `axisDefaults`.
fn tiered(defaults: &str) -> String {
    let nodes: Vec<String> = ["core", "mid", "top", "tooling"].iter().map(|n| node(n, n)).collect();
    format!(
        r#"{{"schema":2,"nodes":[{}],"axes":{{"tier":["unit","journey"]}},"axisDefaults":{defaults},
        "place":[{{"tests":{{"op":"under","glob":"crates/top/tests/**"}},"coordinates":{{"tier":"journey"}},"world":null}}],
        "policy":{{"faults":"report"}}}}"#,
        nodes.join(",")
    )
}

fn placed(json: &str) -> (crate::testset::Placement, check::CheckReport) {
    let idx = standard().index();
    let mdl = model(json);
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    (crate::testset::place(&mdl, &r, &table), check::run(&mdl, &r, &table, None, false).unwrap())
}

#[test]
fn a_test_no_rule_places_takes_the_axis_default_and_the_report_says_how_many_did() {
    let (p, rep) = placed(&tiered(r#"{"tier":"unit"}"#));
    // Four tests in the table: one is the journey, the other three are on the default.
    assert_eq!((p.by_value["tier"]["journey"].len(), p.by_value["tier"]["unit"].len()), (1, 3));
    let tier = p.summary.iter().find(|a| a.axis == "tier").unwrap();
    assert_eq!((tier.unplaced, tier.defaulted, tier.default.as_deref()), (0, 3, Some("unit")));
    // A default is a value, not a placement: `placed` counts what the rules did.
    assert_eq!(p.placed, 1);
    let f = rep.findings.iter().find(|f| f.code == "axis-defaulted").expect("the default is said");
    assert_eq!(f.severity, Severity::Info);
    assert!(f.message.contains("3 of 4 tests are on `unit`") && f.message.contains("1 are placed by rules"), "{}", f.message);
    assert!(!rep.findings.iter().any(|f| f.code == "axis-unplaced"));
    assert!(rep.render().contains("axis tier: tests journey=1 unit=3; no value=0; 3 of them by the axis default `unit`"), "{}", rep.render());
}

#[test]
fn without_a_default_the_unplaced_tests_stay_unplaced_and_are_listed_by_directory_with_a_rule_to_paste() {
    let (p, rep) = placed(&tiered("{}"));
    let tier = p.summary.iter().find(|a| a.axis == "tier").unwrap();
    assert_eq!((tier.unplaced, tier.defaulted, tier.default.clone()), (3, 0, None));
    assert!(!p.by_value["tier"]["unit"].contains(0));
    let f = rep.findings.iter().find(|f| f.code == "axis-unplaced").expect("unplaced");
    // core holds two of the three, tooling the other.
    assert!(f.message.starts_with("axis `tier`: 3 of 4 tests have no value on it, and 0 of 0 check cells have none"), "{}", f.message);
    assert!(f.message.contains("Largest directories among them: crates/core 2, crates/tooling 1."), "{}", f.message);
    assert!(f.message.contains(r#"{ tests = tests.under "crates/core/**"; tier = "<value>"; }"#), "{}", f.message);
    assert!(f.message.contains("its value is one of unit, journey"), "{}", f.message);
    assert!(f.message.contains("default"), "{}", f.message);
}

#[test]
fn at_most_five_directories_are_listed_the_largest_first_and_ties_by_name() {
    // Seven packages, one directory each, holding 1..=7 tests (two share a count).
    let counts = [3usize, 7, 1, 5, 2, 4, 3];
    let names: Vec<&'static str> = vec!["crates/a", "crates/b", "crates/c", "crates/d", "crates/e", "crates/f", "crates/g"];
    let paths: Vec<&'static str> = names.iter().map(|n| &*Box::leak(format!("{n}/src/lib.rs").into_boxed_str())).collect();
    let mut fx = crate::fixtures::Fixture { packages: Vec::new(), files: Vec::new(), tests: Vec::new() };
    for (i, name) in names.iter().enumerate() {
        fx.packages.push((&name[7..], name, Vec::new(), Vec::new()));
        fx.files.push((paths[i], Some(i as u32), keel_index::Target::Lib));
        for _ in 0..counts[i] {
            fx.tests.push((i as u32, "tests::t", false));
        }
    }
    let nodes: Vec<String> = names.iter().map(|n| node(&n[7..], &n[7..])).collect();
    let json = format!(r#"{{"schema":2,"nodes":[{}],"axes":{{"tier":["unit"]}},"policy":{{"faults":"report"}}}}"#, nodes.join(","));
    let mdl = model(&json);
    let idx = fx.index();
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    let p = crate::testset::place(&mdl, &r, &table);
    let f = p.findings.iter().find(|f| f.code == "axis-unplaced").unwrap();
    assert!(
        f.message.contains("Largest directories among them: crates/b 7, crates/d 5, crates/f 4, crates/a 3, crates/g 3."),
        "{}",
        f.message
    );
    assert!(f.message.contains(r#"tests.under "crates/b/**""#) && !f.message.contains("crates/e 2"), "{}", f.message);
}

#[test]
fn a_test_is_grouped_by_the_first_two_directories_above_its_file() {
    use crate::testset::{directory_prefix, suggested_rule};
    assert_eq!(directory_prefix("crates/engine/tests/a.rs"), "crates/engine");
    assert_eq!(directory_prefix("frontends/python/src/lib.rs"), "frontends/python");
    assert_eq!(directory_prefix("tests/a.rs"), "tests");
    assert_eq!(directory_prefix("build.rs"), ".");
    assert_eq!(suggested_rule("tier", "crates/engine"), r#"{ tests = tests.under "crates/engine/**"; tier = "<value>"; }"#);
    assert_eq!(suggested_rule("tier", "."), r#"{ tests = tests.under "*.rs"; tier = "<value>"; }"#);
}

#[test]
fn a_node_reached_through_an_unowned_package_is_stood_on_not_a_second_top() {
    // top -> mid -> core, and no node claims mid. The tests of `top` reach both nodes, and
    // `core` is not what they are about: top stands on it, through a package nobody owns.
    let nodes = [node("core", "core"), node("top", "top")];
    let mdl = model(&format!(r#"{{"schema":2,"nodes":[{}],"policy":{{"faults":"report"}}}}"#, nodes.join(",")));
    let idx = crate::fixtures::Fixture {
        packages: vec![("core", "crates/core", vec![], vec![]), ("mid", "crates/mid", vec![0], vec![]), ("top", "crates/top", vec![1], vec![])],
        files: vec![
            ("crates/core/src/lib.rs", Some(0), keel_index::Target::Lib),
            ("crates/mid/src/lib.rs", Some(1), keel_index::Target::Lib),
            ("crates/top/src/lib.rs", Some(2), keel_index::Target::Lib),
        ],
        tests: vec![(2, "tests::walks_everything", false)],
    }
    .index();
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let (core, top) = (r.node_index("core").unwrap(), r.node_index("top").unwrap());
    assert!(!r.prod[top].contains(&core), "no node edge: the chain runs through mid");
    assert!(crate::parts::standing(&r)[top][core]);
    assert!(!crate::parts::standing(&r)[core][top]);
    let table = TestTable::build(&r, false);
    let parts = crate::parts::TestParts::build(&r, &table);
    let walks = table.ids.iter().position(|id| id.contains("walks_everything")).unwrap();
    assert_eq!(parts.tops(walks), [top]);
}

// ── What explain may take as evidence ────────────────────────────────────

/// `tiered` with a second rule that places the tests of `core` as units by name.
fn tiered_with_a_unit_rule(defaults: &str) -> String {
    tiered(defaults).replace(
        r#""place":["#,
        r#""place":[{"tests":{"op":"under","glob":"crates/core/**"},"coordinates":{"tier":"unit"},"world":null},"#,
    )
}

fn attrs(json: &str) -> Vec<(String, u64)> {
    let idx = standard().index();
    let mdl = model(json);
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    let placement = crate::testset::place(&mdl, &r, &table);
    let u = crate::explain::universe(&r, &table, &placement, &mdl, false, true);
    u.attrs.iter().map(|a| (a.name.clone(), a.tests.len())).collect()
}

#[test]
fn explain_leaves_out_the_tests_that_have_an_axis_value_only_by_default() {
    let tier = |attrs: &[(String, u64)]| attrs.iter().filter(|a| a.0.starts_with("tier:")).cloned().collect::<Vec<_>>();
    // Every test but one is on the default and nothing places a unit: no attribute, though
    // `check` and `tree` still count three tests on `unit`.
    let only_default = attrs(&tiered(r#"{"tier":"unit"}"#));
    assert_eq!(tier(&only_default), Vec::<(String, u64)>::new());
    // A rule that places the two tests of `core` as units makes them evidence; the third test
    // with the value, `tool`, got it from the default and does not count.
    let (p, _) = placed(&tiered_with_a_unit_rule(r#"{"tier":"unit"}"#));
    assert_eq!(p.by_value["tier"]["unit"].len(), 3);
    assert_eq!(tier(&attrs(&tiered_with_a_unit_rule(r#"{"tier":"unit"}"#))), [("tier:unit".to_owned(), 2)]);
    // Without a default the same rule gives the same attribute.
    assert_eq!(tier(&attrs(&tiered_with_a_unit_rule("{}"))), [("tier:unit".to_owned(), 2)]);
}

#[test]
fn failures_whose_only_shared_axis_value_is_a_default_have_no_axis_cause() {
    let idx = standard().index();
    let mdl = model(&tiered(r#"{"tier":"unit"}"#));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    let placement = crate::testset::place(&mdl, &r, &table);
    // `roundtrip` and `tool` are both on `tier=unit`, and only because that is the default.
    let failures = "FAIL [ 1s] (1/4) core tests::roundtrip\nFAIL [ 1s] (2/4) tooling tests::tool\n";
    let inputs = crate::explain::Inputs { failures, executed: None, max_causes: 12, use_tops: true, failures_only: true };
    let rep = crate::explain::run(&r, &table, &placement, &mdl, &inputs).unwrap();
    assert!(!rep.runs[0].causes.is_empty());
    assert!(rep.runs[0].causes.iter().all(|c| !c.attr.starts_with("tier:")), "{:?}", rep.runs[0].causes.iter().map(|c| &c.attr).collect::<Vec<_>>());
    assert!(!rep.render().contains("tier:unit"), "{}", rep.render());
}

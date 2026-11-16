use crate::fixtures::{model, standard};
use crate::finding::Severity;
use crate::resolve::{EdgeKind, Owner, Resolution};
use crate::testset::{TestTable, place};
use std::path::Path;

fn node(id: &str, parent: Option<&str>, code: &str, extra: &str) -> String {
    let parent = parent.map_or("null".to_owned(), |p| format!("\"{p}\""));
    format!(
        r#"{{"id":"{id}","at":"/m/keel.nix:1","parent":{parent},"about":null,"code":[{code}],"entry":[],"on":[],"never":[],"of":[],"ship":null,"movedBy":[],"unmovedBy":[]{extra}}}"#
    )
}

fn krate(n: &str) -> String {
    format!(r#"{{"by":"crate","name":"{n}"}}"#)
}

fn path(g: &str) -> String {
    format!(r#"{{"by":"path","glob":"{g}"}}"#)
}

fn m(nodes: &[String]) -> String {
    format!(r#"{{"schema":2,"nodes":[{}],"policy":{{"faults":"report"}}}}"#, nodes.join(","))
}

fn codes(r: &Resolution<'_>) -> Vec<&'static str> {
    r.findings.iter().map(|f| f.code).collect()
}

fn id(r: &Resolution<'_>, n: &str) -> usize {
    r.node_index(n).unwrap_or_else(|| panic!("no node {n}"))
}

#[test]
fn module_beats_path_beats_crate() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[
        node("base", None, &krate("core"), ""),
        node("modular", None, r#"{"by":"module","path":"core::wal"}"#, ""),
        node("pathy", None, &path("crates/core/src/wal/mod.rs"), ""),
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    assert_eq!(r.file_owner[0], Owner::Node(id(&r, "base")));
    // wal/mod.rs is claimed by all three; the module selector is the most specific.
    assert_eq!(r.file_owner[1], Owner::Node(id(&r, "modular")));
    assert!(!codes(&r).contains(&"ownership-conflict"));
}

#[test]
fn longer_literal_path_prefix_wins_and_equal_prefixes_conflict() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[
        node("wide", None, &path("crates/core/**"), ""),
        node("narrow", None, &path("crates/core/src/wal/**"), ""),
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    assert_eq!(r.file_owner[0], Owner::Node(id(&r, "wide")));
    assert_eq!(r.file_owner[1], Owner::Node(id(&r, "narrow")));
    let mdl = model(&m(&[
        node("one", None, &path("crates/core/src/**"), ""),
        node("two", None, &path("crates/core/src/*.rs"), ""),
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    assert_eq!(r.file_owner[0], Owner::Conflict);
}

#[test]
fn module_wins_over_crate_when_no_path_claims_it() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[
        node("base", None, &krate("core"), ""),
        node("modular", None, r#"{"by":"module","path":"core::wal"}"#, ""),
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    assert_eq!(r.file_owner[1], Owner::Node(id(&r, "modular")));
    assert_eq!(r.file_owner[0], Owner::Node(id(&r, "base")));
}

#[test]
fn same_specificity_is_a_conflict_naming_both_nodes_and_a_file() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[node("one", None, &krate("core"), ""), node("two", None, &krate("core"), "")]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    assert_eq!(r.file_owner[0], Owner::Conflict);
    let f = r.findings.iter().find(|f| f.code == "ownership-conflict").expect("conflict finding");
    assert_eq!(f.severity, Severity::Error);
    assert!(f.message.contains("`one`") && f.message.contains("`two`"));
    assert!(f.message.contains("crates/core/src/lib.rs"));
    assert!(f.at.is_some());
}

#[test]
fn unclaimed_package_files_belong_to_unowned_and_outside_files_to_nobody() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[node("only", None, &krate("core"), "")]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    assert_eq!(r.file_owner[2], Owner::Node(r.unowned));
    assert_eq!(r.file_owner[6], Owner::Node(r.unowned), "every file has an owner");
    let by_pkg = r.unowned_by_package();
    assert_eq!(by_pkg.get("mid"), Some(&1));
    assert_eq!(by_pkg.get("top"), Some(&2));
    assert!(!by_pkg.contains_key("core"));
}

#[test]
fn a_selector_that_matches_nothing_is_an_error_with_near_names() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[node("x", None, &format!("{},{}", krate("cor"), path("nowhere/**")), "")]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let msgs: Vec<&str> = r
        .findings
        .iter()
        .filter(|f| f.code == "selector-matches-nothing")
        .map(|f| f.message.as_str())
        .collect();
    assert_eq!(msgs.len(), 2, "{msgs:?}");
    assert!(msgs.iter().any(|m| m.contains("does not exist in this repository") && m.contains("core")));
    assert!(msgs.iter().any(|m| m.contains("nowhere/**")));
}

#[test]
fn an_unresolvable_pattern_is_an_error_and_resolution_continues() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[node(
        "p",
        None,
        &format!(r##"{krate},{{"by":"pattern","language":"rust","pattern":"#[tool] fn $A() {{}}"}}"##, krate = krate("core")),
        "",
    )]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let f = r.findings.iter().find(|f| f.code == "selector-matches-nothing").expect("error");
    assert_eq!(f.severity, Severity::Error);
    assert!(f.message.contains("matched no"));
    assert_eq!(r.file_owner[0], Owner::Node(id(&r, "p")));
}

fn chain_model(extra_top: &str) -> String {
    m(&[
        node("core", None, &krate("core"), ""),
        node("mid", None, &krate("mid"), ""),
        node("top", None, &krate("top"), extra_top),
        node("tooling", None, &krate("tooling"), ""),
    ])
}

#[test]
fn edges_follow_package_dependencies_and_keep_dev_apart() {
    let fx = standard();
    let idx = fx.index();
    let r = Resolution::build(&model(&chain_model("")), &idx, Path::new("/nonexistent"));
    let (core, mid, top, tooling) = (id(&r, "core"), id(&r, "mid"), id(&r, "top"), id(&r, "tooling"));
    assert_eq!(r.edges[&(mid, core)].kind, EdgeKind::Product);
    assert_eq!(r.edges[&(top, mid)].kind, EdgeKind::Product);
    assert_eq!(r.edges[&(top, core)].kind, EdgeKind::Product);
    assert_eq!(r.edges[&(tooling, core)].kind, EdgeKind::Dev);
    assert!(!r.prod[tooling].contains(&core));
    // top -> core is implied by top -> mid -> core and drops out of the reduction.
    assert!(r.reduced.contains(&(top, mid)));
    assert!(r.reduced.contains(&(mid, core)));
    assert!(!r.reduced.contains(&(top, core)));
    assert!(r.layer[core] < r.layer[mid] && r.layer[mid] < r.layer[top]);
}

#[test]
fn cone_is_transitive_and_includes_descendants_but_not_dev_edges() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[
        node("core", None, &krate("core"), ""),
        node("mid", None, &krate("mid"), ""),
        node("top", None, &krate("top"), ""),
        node("top.kid", Some("top"), &path("crates/top/tests/**"), ""),
        node("tooling", None, &krate("tooling"), ""),
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let cone = r.cone(id(&r, "top"), false);
    let names: Vec<&str> = cone.iter().map(|&n| r.nodes[n].id.as_str()).collect();
    assert_eq!(names, vec!["core", "mid", "top", "top.kid"]);
    let tooling = r.cone(id(&r, "tooling"), false);
    assert_eq!(tooling.len(), 1);
    assert_eq!(r.cone(id(&r, "tooling"), true).len(), 2);
}

#[test]
fn a_child_node_makes_the_parents_edges_part_of_the_parent() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[
        node("core", None, &krate("core"), ""),
        node("app", None, "", ""),
        node("app.mid", Some("app"), &krate("mid"), ""),
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    assert!(r.cone(id(&r, "app"), false).contains(&id(&r, "core")));
}

#[test]
fn on_law_fails_when_no_dependency_exists_and_passes_when_it_does() {
    let fx = standard();
    let idx = fx.index();
    let on = |target: &str| format!(r#","on":["{target}"]"#).replace(r#"","on""#, r#"","on""#);
    let build = |from: &str, to: &str| {
        let mut top = node(from, None, &krate(if from == "tooling" { "tooling" } else { "top" }), "");
        top = top.replace(r#""on":[]"#, &format!(r#""on":["{to}"]"#));
        let mdl = model(&m(&[
            node("core", None, &krate("core"), ""),
            node("mid", None, &krate("mid"), ""),
            top,
        ]));
        let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
        r.findings.iter().filter(|f| f.code == "on-not-derived").count()
    };
    let _ = on;
    assert_eq!(build("top", "mid"), 0);
    assert_eq!(build("top", "core"), 0);
    // `tooling` has no node-level dependency on mid.
    assert_eq!(build("tooling", "mid"), 1);
}

#[test]
fn never_law_prints_a_concrete_package_path() {
    let fx = standard();
    let idx = fx.index();
    let mut top = node("top", None, &krate("top"), "");
    top = top.replace(r#""never":[]"#, r#""never":["core"]"#);
    let mdl = model(&m(&[node("core", None, &krate("core"), ""), node("mid", None, &krate("mid"), ""), top]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let f = r.findings.iter().find(|f| f.code == "never-violated").expect("violation");
    assert_eq!(f.severity, Severity::Error);
    assert!(f.message.contains("top -[top -> core]-> core"), "{}", f.message);
    assert_eq!(f.at.as_deref(), Some("/m/keel.nix:1"));
}

#[test]
fn path_laws_check_cone_and_existence() {
    let fx = standard();
    let idx = fx.index();
    let mut top = node("top", None, &krate("top"), "");
    top = top.replace(
        r#""movedBy":[]"#,
        r#""movedBy":["crates/core/src/lib.rs","crates/tooling/src/lib.rs"]"#,
    );
    top = top.replace(
        r#""unmovedBy":[]"#,
        r#""unmovedBy":["crates/mid/src/lib.rs","crates/tooling/src/lib.rs","crates/gone/src/lib.rs"]"#,
    );
    let mdl = model(&m(&[
        node("core", None, &krate("core"), ""),
        node("mid", None, &krate("mid"), ""),
        node("tooling", None, &krate("tooling"), ""),
        top,
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let by = |code: &str| r.findings.iter().filter(|f| f.code == code).collect::<Vec<_>>();
    // movedBy core is fine, tooling is not in top's cone.
    let moved = by("moved-by-not-in-cone");
    assert_eq!(moved.len(), 1);
    assert!(moved[0].message.contains("crates/tooling/src/lib.rs"));
    // unmovedBy mid is in the cone; tooling is not (fine); gone does not exist.
    let unmoved = by("unmoved-by-in-cone");
    assert_eq!(unmoved.len(), 1);
    assert!(unmoved[0].message.contains("crates/mid/src/lib.rs"));
    let missing = by("path-law-missing-path");
    assert_eq!(missing.len(), 1);
    assert!(missing[0].message.contains("crates/gone/src/lib.rs"));
}

#[test]
fn test_sets_evaluate_every_op() {
    use crate::model::TestSet as S;
    use crate::testset::Evaluator;
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[
        node("core", None, &krate("core"), ""),
        node("mid", None, &krate("mid"), ""),
        node("top", None, &krate("top"), ""),
        node("tooling", None, &krate("tooling"), ""),
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    // The #[ignore]d test is left out: four tests remain.
    assert_eq!(table.len(), 4);
    assert_eq!(table.excluded_ignored, 1);
    let with_ignored = TestTable::build(&r, true);
    assert_eq!(with_ignored.len(), 5);

    let mut ev = Evaluator::new(&r, &table);
    let mut n = |s: S| ev.eval(&s, "test").len();
    assert_eq!(n(S::All), 4);
    assert_eq!(n(S::Under { glob: "crates/top/tests/**".into() }), 1);
    assert_eq!(n(S::Named { glob: "*walks*".into() }), 1);
    assert_eq!(n(S::Package { name: "core".into() }), 2);
    // reaching core: every test whose package closure contains core (tooling's too).
    assert_eq!(n(S::Reaching { selector: crate::model::Selector::Crate { name: "core".into() } }), 4);
    assert_eq!(n(S::Reaching { selector: crate::model::Selector::Crate { name: "mid".into() } }), 1);
    assert_eq!(n(S::Node { node: "top".into() }), 1);
    assert_eq!(
        n(S::Union { sets: vec![S::Package { name: "core".into() }, S::Package { name: "top".into() }] }),
        3
    );
    assert_eq!(
        n(S::Both {
            sets: vec![
                S::Reaching { selector: crate::model::Selector::Crate { name: "mid".into() } },
                S::Under { glob: "crates/top/**".into() }
            ]
        }),
        1
    );
    assert_eq!(
        n(S::Minus {
            left: Box::new(S::All),
            right: Box::new(S::Node { node: "top".into() })
        }),
        3
    );
    assert!(ev.findings.is_empty(), "{:?}", ev.findings.iter().map(|f| &f.message).collect::<Vec<_>>());
    let mut ev = Evaluator::new(&r, &table);
    assert_eq!(ev.eval(&S::Package { name: "cor".into() }, "rule").len(), 0);
    assert_eq!(ev.findings.len(), 1);
    assert!(ev.findings[0].message.contains("does not exist in this repository"));
}

#[test]
fn conflicting_placements_are_a_warning_with_examples() {
    let fx = standard();
    let idx = fx.index();
    let json = format!(
        r#"{{"schema":2,"nodes":[{}],"axes":{{"tier":["unit","journey"]}},
        "place":[
          {{"tests":{{"op":"all"}},"coordinates":{{"tier":"unit"}},"world":null}},
          {{"tests":{{"op":"under","glob":"crates/top/tests/**"}},"coordinates":{{"tier":"journey"}},"world":null}},
          {{"tests":{{"op":"package","name":"nothing"}},"coordinates":{{"tier":"unit"}},"world":null}}]}}"#,
        node("core", None, &krate("core"), "")
    );
    let mdl = model(&json);
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    let p = place(&mdl, &r, &table);
    let conflict = p.findings.iter().find(|f| f.code == "placement-conflict").expect("conflict");
    assert_eq!(conflict.severity, Severity::Error);
    assert!(conflict.message.contains("walks_everything"));
    assert!(p.findings.iter().any(|f| f.code == "selector-matches-nothing" || f.code == "rule-matches-no-tests"));
    let tier = p.summary.iter().find(|a| a.axis == "tier").unwrap();
    assert_eq!(tier.values.iter().find(|v| v.value == "unit").unwrap().tests, 4);
    assert_eq!(tier.values.iter().find(|v| v.value == "journey").unwrap().tests, 1);
}

#[test]
fn lock_is_deterministic_and_diffs_name_the_change() {
    let fx = standard();
    let idx = fx.index();
    let a = Resolution::build(&model(&chain_model("")), &idx, Path::new("/nonexistent")).lock(&[]);
    let a2 = Resolution::build(&model(&chain_model("")), &idx, Path::new("/nonexistent")).lock(&[]);
    assert_eq!(serde_json::to_string(&a).unwrap(), serde_json::to_string(&a2).unwrap());
    assert!(crate::lock::diff(&a, &a2).is_empty());
    // Dropping `mid` moves its package to unowned and removes edges.
    let mdl = model(&m(&[
        node("core", None, &krate("core"), ""),
        node("top", None, &krate("top"), ""),
        node("tooling", None, &krate("tooling"), ""),
    ]));
    let b = Resolution::build(&mdl, &idx, Path::new("/nonexistent")).lock(&[]);
    let d = crate::lock::diff(&a, &b);
    assert!(d.iter().any(|l| l == "node removed: mid"), "{d:?}");
    assert!(d.iter().any(|l| l.starts_with("top: now stands on (Product) unowned")), "{d:?}");
}

mod status_lines {
    use crate::explain::{Mapper, Named, parse_line};
    use crate::fixtures::standard;
    use crate::resolve::Resolution;
    use crate::testset::TestTable;
    use std::path::Path;

    #[test]
    fn parses_nextest_lines_ids_and_glued_junk() {
        let l = "        FAIL [   1.742s] (44/46) backend-local-service builtin::commands::adapter::tests::name== 1 failing tests' stderr (first 300, 20 lines each) ==";
        assert_eq!(
            parse_line(l),
            Some(Named::Status {
                status: "FAIL".into(),
                binary: "backend-local-service".into(),
                path: "builtin::commands::adapter::tests::name".into()
            })
        );
        let l = "        FAIL [   0.244s] ( 760/18350) backend-engine::python_x py_assign_alias_decoy--";
        let n = parse_line(l).unwrap();
        assert_eq!((n.binary(), n.path()), ("backend-engine::python_x", "py_assign_alias_decoy"));
        assert_eq!(
            parse_line("core$tests::roundtrip"),
            Some(Named::Id { binary: "core".into(), path: "tests::roundtrip".into() })
        );
        assert_eq!(parse_line("CI-TIMING lane=linux step=x seconds=1"), None);
        assert_eq!(parse_line("     Summary [   5.568s] 46 tests run: 45 passed, 1 failed"), None);
        assert!(!parse_line("        PASS [   0.043s] ( 1/46) a b").unwrap().is_failure());
    }

    #[test]
    fn maps_by_binary_and_longest_suffix_and_says_why_not() {
        let fx = standard();
        let idx = fx.index();
        let r = Resolution::build(&crate::fixtures::model(r#"{"schema":2,"nodes":[]}"#), &idx, Path::new("/nonexistent"));
        let table = TestTable::build(&r, false);
        let mapper = Mapper::new(&idx, &table);
        let text = "\
        FAIL [ 1s] (1/4) core tests::roundtrip
        FAIL [ 1s] (2/4) core wal::tests::replays
        FAIL [ 1s] (3/4) top::journey walks_everything
        FAIL [ 1s] (4/4) mid tests::wide
        FAIL [ 1s] (4/4) top::journey nope
        FAIL [ 1s] (4/4) ghost x
";
        let m = mapper.map_text(text);
        assert_eq!(m.lines_seen, 6);
        assert_eq!(m.mapped_lines, 3, "{:?}", m.unmapped);
        assert!(m.unmapped.iter().any(|u| u.reason.contains("ignore")));
        assert!(m.unmapped.iter().any(|u| u.reason.contains("is not a workspace package")));
        assert!(m.unmapped.iter().any(|u| u.reason.contains("no test named nope")));
    }
}

#[test]
fn plan_priors_and_inert_paths() {
    use crate::plan::{assumptions as a, prior};
    assert_eq!(prior(0, 0), a::PRIOR_MIN);
    assert!((prior(5, 10) - 0.12).abs() < 1e-12);
    assert_eq!(prior(500, 500), a::PRIOR_MAX);
}

#[test]
fn nix_output_selectors_are_reported_as_unsupported_not_crashed_on() {
    let fx = standard();
    let idx = fx.index();
    let mdl = model(&m(&[node(
        "x",
        None,
        &format!(r#"{},{{"by":"option","path":"services.x"}},{{"by":"drv","attr":"packages.x"}}"#, krate("core")),
        "",
    )]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let unsupported: Vec<_> = r.findings.iter().filter(|f| f.code == "unsupported-selector").collect();
    assert_eq!(unsupported.len(), 2);
    assert_eq!(unsupported[0].severity, Severity::Error);
    assert_eq!(r.file_owner[0], Owner::Node(id(&r, "x")));
}

/// `only X` keeps a test when every top of its parts lies at or under X. The
/// parts of a test are the nodes owning code in its package closure; its tops
/// are the parts no other part stands on.
#[test]
fn only_uses_tops_of_a_tests_parts() {
    use crate::model::TestSet as S;
    use crate::testset::Evaluator;
    let mut fx = standard();
    // `both` (unowned) depends on `top` and `tooling`, which do not stand on
    // each other: like a test reaching {desktop, mcp}. `lone` depends on `top`
    // only, whose parts {top, mid, core} have the single top `top`: like a test
    // reaching {desktop, engine}, where desktop stands on engine.
    fx.packages.push(("both", "crates/both", vec![2, 3], vec![]));
    fx.packages.push(("lone", "crates/lone", vec![2], vec![]));
    fx.files.push(("crates/both/src/lib.rs", Some(4), keel_index::Target::Lib));
    fx.files.push(("crates/lone/src/lib.rs", Some(5), keel_index::Target::Lib));
    fx.tests.push((7, "tests::both", false));
    fx.tests.push((8, "tests::lone", false));
    let idx = fx.index();
    let mdl = model(&m(&[
        node("core", None, &krate("core"), ""),
        node("mid", None, &krate("mid"), ""),
        node("top", None, &krate("top"), ""),
        node("tooling", None, &krate("tooling"), ""),
    ]));
    let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
    let table = TestTable::build(&r, false);
    let mut ev = Evaluator::new(&r, &table);
    let names = |b: keel_index::RoaringBitmap| -> Vec<String> {
        b.iter().map(|i| table.ids[i as usize].clone()).collect()
    };
    let only_top = names(ev.eval(&S::Only { node: "top".into() }, "t"));
    assert!(only_top.contains(&"lone$tests::lone".to_owned()), "{only_top:?}");
    assert!(only_top.contains(&"top::journey$walks_everything".to_owned()));
    assert!(!only_top.contains(&"both$tests::both".to_owned()), "{only_top:?}");
    // `both` has two tops, so it is in `only` of neither.
    let only_tooling = names(ev.eval(&S::Only { node: "tooling".into() }, "t"));
    assert!(!only_tooling.contains(&"both$tests::both".to_owned()));
    // A top below the named node still counts: `lone` is not in `only mid`.
    let only_mid = names(ev.eval(&S::Only { node: "mid".into() }, "t"));
    assert!(!only_mid.contains(&"lone$tests::lone".to_owned()));
    assert!(ev.findings.is_empty() || ev.findings.iter().all(|f| f.message.contains("selects none")));
}

mod round_two {
    use super::*;
    use crate::source;

    fn temp_repo(name: &str) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("keel-tree-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn git(dir: &Path, args: &[&str]) {
        let st = std::process::Command::new("git")
            .arg("-C")
            .arg(dir)
            .args(["-c", "user.email=t@t", "-c", "user.name=t"])
            .args(args)
            .status()
            .unwrap();
        assert!(st.success(), "git {args:?}");
    }

    /// A repository with no Cargo.toml at all: path selectors, a place rule by
    /// `under`, a world input, a check and declared `on` laws are enough.
    #[test]
    fn git_and_the_model_alone_are_enough() {
        let dir = temp_repo("nocargo");
        for (p, text) in [
            ("svc/a/lib.rs", "#[test]\nfn a_works() {}\n"),
            ("svc/b/lib.rs", "#[test]\nfn b_works() {}\n#[test]\nfn b_more() {}\n"),
            ("tests/journeys/j.rs", "#[test]\nfn journey() {}\n"),
            ("data/cases.json", "{}"),
        ] {
            let f = dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, text).unwrap();
        }
        git(&dir, &["init", "-q"]);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "x"]);
        let json = format!(
            r#"{{"schema":2,"nodes":[{a},{b}],"axes":{{"tier":["unit","journey"]}},
            "place":[{{"tests":{{"op":"under","glob":"tests/journeys/**"}},"coordinates":{{"tier":"journey"}},"world":null}}],
            "worlds":[{{"name":"w","at":null,"from":null,"inputs":[{{"by":"path","glob":"data/cases.json"}}],"maxAgeMinutes":null}}],
            "checks":{{"c":{{"checks":[{{"on":["a","b"],"coordinates":{{}},"inputs":[{{"by":"path","glob":"data/*.json"}}],"cell":"x"}},
              {{"on":["a","b"],"coordinates":{{}},"inputs":[{{"by":"path","glob":"data/*.json"}}],"cell":"x","control":"wrong","breaks":{{"node":"a"}}}}],"uncontrolled":[]}}}},
            "policy":{{"uncovered":"fail","joins":[["a","b"]]}}}}"#,
            a = node("a", None, &path("svc/a/**"), ""),
            b = node("b", None, &path("svc/b/**"), "").replace(r#""on":[]"#, r#""on":["a"]"#),
        );
        let mdl = model(&json);
        assert!(!source::needs_cargo(&mdl));
        let (idx, src) = source::load(&dir, None, source::needs_cargo(&mdl)).unwrap();
        assert!(matches!(src, source::Source::GitOnly { .. }));
        assert!(idx.packages.is_empty());
        let r = Resolution::build_with(&mdl, &idx, &dir, Some("test"));
        let errors: Vec<_> = r.findings.iter().filter(|f| f.severity == Severity::Error).collect();
        assert!(errors.is_empty(), "{:?}", errors.iter().map(|f| &f.message).collect::<Vec<_>>());
        assert_eq!(r.nodes[id(&r, "a")].own_files, 1);
        // The only stands-on edge is the declared one.
        assert!(r.prod[id(&r, "b")].contains(&id(&r, "a")));
        let table = TestTable::build(&r, false);
        assert_eq!(table.len(), 4);
        let p = place(&mdl, &r, &table);
        assert!(p.findings.iter().all(|f| f.severity != Severity::Error), "{:?}", p.findings);
        assert_eq!(p.by_value["tier"]["journey"].len(), 1);
        // The check's control breaks `a`, so the pair is covered by that twin.
        let o = crate::coverage::run(&mdl, &r, &table, None, false);
        let (cov, summary) = (o.findings, o.summary);
        assert!(cov.is_empty(), "{cov:?}");
        assert_eq!(summary.edges, 1);
        assert_eq!(summary.join_pairs, 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn crate_selectors_without_cargo_are_findings_not_crashes() {
        let dir = temp_repo("needscargo");
        std::fs::write(dir.join("x.txt"), "x").unwrap();
        git(&dir, &["init", "-q"]);
        git(&dir, &["add", "."]);
        git(&dir, &["commit", "-q", "-m", "x"]);
        let mdl = model(&m(&[node("n", None, &krate("core"), "")]));
        assert!(source::needs_cargo(&mdl));
        let (idx, src) = source::load(&dir, None, true).unwrap();
        let source::Source::GitOnly { reason } = src else { panic!("no cargo here") };
        let r = Resolution::build_with(&mdl, &idx, &dir, Some(&reason));
        let f = r.findings.iter().find(|f| f.code == "cargo-required").expect("finding");
        assert!(f.message.contains("crate \"core\""));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn coverage_needs_both_ends_in_a_tests_parts_or_a_check_and_joins_always_fail() {
        let fx = standard();
        let idx = fx.index();
        // tooling has a test and depends (dev) on core; add a node `lonely` (no tests) that top declares `on`.
        let mut top = node("top", None, &krate("top"), "");
        top = top.replace(r#""on":[]"#, r#""on":["lonely"]"#);
        let json = format!(
            r#"{{"schema":2,"nodes":[{},{},{},{},{}],"policy":{{"uncovered":"fail","joins":[["core","lonely"]]}}}}"#,
            node("core", None, &krate("core"), ""),
            node("mid", None, &krate("mid"), ""),
            top,
            node("tooling", None, &krate("tooling"), ""),
            node("lonely", None, &path("stray/**"), ""),
        );
        let mdl = model(&json);
        let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
        let table = TestTable::build(&r, false);
        let o = crate::coverage::run(&mdl, &r, &table, None, false);
        let (f, s) = (o.findings, o.summary);
        // top -> lonely is declared and no test reaches `lonely` (stray is outside every package).
        assert!(f.iter().any(|f| f.code == "uncovered-edge" && f.message.contains("top") && f.message.contains("lonely")), "{f:?}");
        assert!(f.iter().any(|f| f.code == "uncovered-join"));
        assert!(f.iter().all(|f| f.severity == Severity::Error));
        // top -> mid and mid -> core are covered by tests of `top`.
        assert!(s.covered_by_tests >= 2);
        // With "report" and --accept the edge is info but the join stays an error.
        let report = model(&json.replace(r#""uncovered":"fail""#, r#""uncovered":"report""#));
        let f = crate::coverage::run(&report, &r, &table, None, true).findings;
        assert!(f.iter().any(|f| f.code == "uncovered-edge" && f.severity == Severity::Info));
        assert!(f.iter().any(|f| f.code == "uncovered-join" && f.severity == Severity::Error));
    }

    #[test]
    fn an_entry_whose_files_lie_in_no_package_moves_nothing() {
        let fx = standard();
        let idx = fx.index();
        let mut n = node("search", None, &krate("core"), "");
        n = n.replace(r#""entry":[]"#, &format!(r#""entry":[{}]"#, path("stray/**")));
        let r = Resolution::build(&model(&m(&[n])), &idx, Path::new("/nonexistent"));
        let f = r.findings.iter().find(|f| f.code == "entry-moves-nothing").expect("finding");
        assert_eq!(f.severity, Severity::Error);
        assert!(f.message.contains("stray") && f.message.contains("no cargo package"), "{}", f.message);
    }

}

mod round_three {
    use super::*;
    use crate::check;
    use crate::model::TestSet as S;
    use crate::testset::{Evaluator, check_on_nodes};

    /// Four standard packages plus `probe` (unowned), which depends on `top`
    /// and `tooling`, with a test.
    fn with_probe() -> crate::fixtures::Fixture {
        let mut fx = standard();
        fx.packages.push(("probe", "crates/probe", vec![2, 3], vec![]));
        fx.files.push(("crates/probe/src/lib.rs", Some(4), keel_index::Target::Lib));
        fx.tests.push((7, "tests::probe", false));
        fx
    }

    fn base_nodes(top_extra: &str) -> Vec<String> {
        vec![
            node("core", None, &krate("core"), ""),
            node("mid", None, &krate("mid"), ""),
            node("top", None, &krate("top"), top_extra),
            node("tooling", None, &krate("tooling"), ""),
        ]
    }

    /// 1. `of` moves, blames and shows like stands-on, and is never coverage.
    #[test]
    fn an_instance_of_edge_is_a_stands_on_edge_but_never_a_coverage_edge() {
        let fx = with_probe();
        let idx = fx.index();
        let mut nodes = base_nodes("");
        nodes[2] = nodes[2].replace(r#""of":[]"#, r#""of":["tooling"]"#);
        let mdl = model(&format!(
            r#"{{"schema":2,"nodes":[{}],"policy":{{"uncovered":"fail","joins":[],"faults":"report"}}}}"#,
            nodes.join(",")
        ));
        let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
        let (top, tooling) = (id(&r, "top"), id(&r, "tooling"));
        assert!(r.prod[top].contains(&tooling));
        assert!(r.is_instance_only(top, tooling));
        assert!(r.cone(top, false).contains(&tooling));
        assert!(r.layer[top] > r.layer[tooling]);
        // Blame follows it: the universe's node attribute for top stands on tooling's.
        let table = TestTable::build(&r, false);
        let out = crate::coverage::run(&mdl, &r, &table, None, false);
        assert!(
            !out.uncovered.iter().any(|e| e == &["top".to_owned(), "tooling".to_owned()]),
            "an `of` edge must not be a coverage edge: {:?}",
            out.uncovered
        );
        assert!(out.findings.iter().all(|f| !f.message.contains("tooling")), "{:?}", out.findings);
        // The tree prints it with its own marker.
        let trees = crate::tree::run(&r, &table, Some("top")).unwrap();
        let line = trees[0].lines.iter().find(|l| l.node == "tooling").expect("tooling in the cone");
        assert_eq!(line.relation, "instance-of");
        assert!(crate::tree::render_all(&trees).contains("~ tooling"));
        // The lock marks it.
        let lock = r.lock(&[]);
        assert!(lock.nodes["top"].stands_on.iter().any(|e| e.to == "tooling" && e.of));
        // Tops use it: the probe test reaches {top, tooling, ...}, and top now stands on tooling.
        let mut ev = Evaluator::new(&r, &table);
        let only_top = ev.eval(&S::Only { node: "top".into() }, "t");
        assert!(only_top.iter().any(|i| table.ids[i as usize] == "probe$tests::probe"));
    }

    /// 2. Sets range over checks: `all` is tests and checks, `node`/`only` use `on`.
    #[test]
    fn sets_range_over_matrix_checks() {
        let fx = standard();
        let idx = fx.index();
        let mut nodes = base_nodes("");
        nodes.push(node("lonely", None, &path("stray/**"), ""));
        let json = format!(
            r#"{{"schema":2,"nodes":[{}],"checks":{{"g":{{"checks":[
              {{"on":["top","mid"],"coordinates":{{}},"inputs":[],"cell":"one"}},
              {{"on":["lonely"],"coordinates":{{}},"inputs":[],"cell":"two"}}],"uncontrolled":[]}}}},
              "policy":{{"deployGate":{{"_keel":"tests","op":"only","node":"lonely"}}}}}}"#,
            nodes.join(",")
        );
        let mdl = model(&json);
        let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
        let table = TestTable::build(&r, false);
        let mut ev = Evaluator::new(&r, &table).with_checks(check_on_nodes(&mdl, &r));
        let sp = |ev: &mut Evaluator<'_, '_>, s: S| {
            let b = ev.eval(&s, "t");
            ev.split(&b)
        };
        assert_eq!(sp(&mut ev, S::All), (4, 2));
        // A check's parts are its `on`; top stands on mid, so cell one's only top is `top`.
        assert_eq!(sp(&mut ev, S::Only { node: "top".into() }).1, 1);
        assert_eq!(sp(&mut ev, S::Node { node: "mid".into() }).1, 1);
        // Selecting only checks is not empty, and not a finding.
        let lonely = ev.eval(&S::Only { node: "lonely".into() }, "t");
        assert_eq!(ev.split(&lonely), (0, 1));
        // under / named / package select tests only.
        assert_eq!(sp(&mut ev, S::Under { glob: "crates/**".into() }).1, 0);
        assert!(ev.findings.is_empty(), "{:?}", ev.findings.iter().map(|f| &f.message).collect::<Vec<_>>());
        // A policy set made only of checks is counted, not rejected.
        let rep = check::run(&mdl, &r, &table, None, false).unwrap();
        let gate = rep.summary.policy_sets.iter().find(|p| p.path == "policy.deployGate").expect("counted");
        assert_eq!((gate.tests, gate.checks), (0, 1));
        assert!(!rep.findings.iter().any(|f| f.message.contains("policy.deployGate")), "{:?}", rep.findings);
    }

    fn tmp(name: &str) -> std::path::PathBuf {
        std::env::temp_dir().join(format!("keel-tree-lock-{name}-{}", std::process::id()))
    }

    /// 3. A failing check never writes the lock; it writes `.rejected`.
    #[test]
    fn the_lock_is_written_only_when_check_is_clean() {
        let fx = standard();
        let idx = fx.index();
        let good = model(&m(&base_nodes("")));
        let bad = model(&m(&[base_nodes("")[0].clone(), node("x", None, &krate("nope"), "")]));
        let path = tmp("accept");
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(path.with_extension("rejected"));
        let run = |mdl: &crate::model::Model| {
            let r = Resolution::build(mdl, &idx, Path::new("/nonexistent"));
            let table = TestTable::build(&r, false);
            check::run(mdl, &r, &table, Some(&path), false).unwrap()
        };
        // A clean model with a coverage policy that reports: accepted.
        let first = run(&good);
        assert!(!first.has_errors(), "{:?}", first.findings.iter().map(|f| &f.message).collect::<Vec<_>>());
        assert!(!first.lock.as_ref().unwrap().rejected);
        let accepted = std::fs::read_to_string(&path).unwrap();
        // A failing model: the accepted lock is untouched, the new one lands beside it.
        let second = run(&bad);
        assert!(second.has_errors());
        let l = second.lock.as_ref().unwrap();
        assert!(l.rejected);
        assert!(l.written_to.ends_with(".rejected"), "{}", l.written_to);
        assert_eq!(std::fs::read_to_string(&path).unwrap(), accepted);
        assert!(std::fs::read_to_string(&l.written_to).unwrap().contains("\"x\""));
        // The diff is against the last accepted lock.
        assert!(l.changes.iter().any(|c| c.contains("node added: x")), "{:?}", l.changes);
        assert!(second.render().contains("lock NOT updated"));
        let _ = std::fs::remove_file(&path);
        let _ = std::fs::remove_file(&l.written_to);
    }

    // 4. Owned files and their digest are in the lock without cargo, and a
    // changed owned set shows in the diff.
    #[test]
    fn the_lock_records_owned_files_digest_and_unsupported_selectors() {
        let fx = standard();
        let idx = fx.index();
        let wide = model(&m(&[node(
            "w",
            None,
            &format!(r#"{},{{"by":"option","path":"services.x"}}"#, path("crates/core/**")),
            "",
        )]));
        let narrow = model(&m(&[node("w", None, &path("crates/core/src/lib.rs"), "")]));
        let a = Resolution::build(&wide, &idx, Path::new("/nonexistent")).lock(&[]);
        let b = Resolution::build(&narrow, &idx, Path::new("/nonexistent")).lock(&[]);
        assert_eq!(a.nodes["w"].files, Some(2));
        assert_eq!(b.nodes["w"].files, Some(1));
        assert_eq!(a.nodes["w"].files_digest.as_ref().unwrap().len(), 64);
        assert_eq!(a.nodes["w"].unsupported.len(), 1);
        assert_eq!(a.nodes["w"].unsupported[0]["by"], "option");
        assert!(a.nodes["w"].packages.is_some());
        let d = crate::lock::diff(&a, &b);
        assert!(d.iter().any(|l| l.starts_with("w: owned files changed (2 -> 1")), "{d:?}");
        assert!(d.iter().any(|l| l.contains("unsupported selectors changed")), "{d:?}");
        // Same count, different files: the digest still moves.
        let other = model(&m(&[node("w", None, &path("crates/core/src/wal/*.rs"), "")]));
        let c = Resolution::build(&other, &idx, Path::new("/nonexistent")).lock(&[]);
        assert_eq!(c.nodes["w"].files, b.nodes["w"].files);
        assert_ne!(c.nodes["w"].files_digest, b.nodes["w"].files_digest);
        assert!(crate::lock::diff(&b, &c).iter().any(|l| l.contains("owned files changed")));
        // Without a package index there are no packages in the lock.
        let git = crate::fixtures::Fixture { packages: vec![], files: vec![("a/x.rs", None, keel_index::Target::Other)], tests: vec![] }.index();
        let g = Resolution::build(&model(&m(&[node("p", None, &path("a/**"), "")])), &git, Path::new("/nonexistent")).lock(&[]);
        assert!(g.nodes["p"].packages.is_none());
        assert_eq!(g.nodes["p"].files, Some(1));
    }

    /// 5. Unverifiable edges and the ratchet.
    #[test]
    fn entry_only_nodes_are_unverifiable_and_new_uncovered_edges_fail_under_report() {
        let fx = standard();
        let idx = fx.index();
        let ghost = node("ghost", None, "", "").replace(r#""on":[]"#, r#""on":["core"]"#).replace(
            r#""entry":[]"#,
            &format!(r#""entry":[{}]"#, path("crates/core/src/lib.rs")),
        );
        let build = |policy: &str| {
            model(&format!(
                r#"{{"schema":2,"nodes":[{},{}],"policy":{{"uncovered":"{policy}","joins":[],"faults":"report"}}}}"#,
                node("core", None, &krate("core"), ""),
                ghost
            ))
        };
        let pair = ("ghost".to_owned(), "core".to_owned());
        let run = |mdl: &crate::model::Model, prev: Option<&std::collections::BTreeSet<(String, String)>>, accept: bool| {
            let r = Resolution::build(mdl, &idx, Path::new("/nonexistent"));
            let table = TestTable::build(&r, false);
            crate::coverage::run(mdl, &r, &table, prev, accept)
        };
        // fail: an error, with the distinct code and text.
        let f = run(&build("fail"), None, false);
        let e = f.findings.iter().find(|f| f.code == "unverifiable-edge").expect("unverifiable");
        assert_eq!(e.severity, Severity::Error);
        assert!(e.message.contains("unverifiable: entry-only node under package reach"));
        assert_eq!(f.summary.unverifiable, 1);
        assert_eq!(f.uncovered, vec![["ghost".to_owned(), "core".to_owned()]]);
        // report with no accepted baseline: an error to review, until --accept records it.
        let first = run(&build("report"), None, false);
        let e = first.findings.iter().find(|f| f.code == "no-accepted-baseline").expect("no baseline");
        assert_eq!(e.severity, Severity::Error);
        assert!(e.message.starts_with("no accepted baseline: review the list and rerun with --accept"));
        let accepted = run(&build("report"), None, true);
        assert!(accepted.findings.iter().all(|f| f.severity == Severity::Info));
        // report against a lock that already has it: info.
        let known: std::collections::BTreeSet<_> = [pair.clone()].into();
        assert!(run(&build("report"), Some(&known), false).findings.iter().all(|f| f.severity == Severity::Info));
        // report against a lock that does not: a new uncovered edge is an error.
        let empty = std::collections::BTreeSet::new();
        let fresh = run(&build("report"), Some(&empty), false);
        let e = fresh.findings.iter().find(|f| f.code == "new-uncovered-edge").expect("new edge");
        assert_eq!(e.severity, Severity::Error);
        assert!(e.message.starts_with("new uncovered edge"));
        assert_eq!(fresh.summary.new_uncovered, 1);
        // --accept admits it, as info.
        let admitted = run(&build("report"), Some(&empty), true);
        assert!(admitted.findings.iter().all(|f| f.severity == Severity::Info));
    }
}

mod round_four {
    use super::*;
    use crate::check;
    use crate::explain::{Inputs, run as explain_run};

    fn one_package() -> crate::fixtures::Fixture {
        crate::fixtures::Fixture {
            packages: vec![("p", "crates/p", vec![], vec![])],
            files: vec![("crates/p/src/lib.rs", Some(0), keel_index::Target::Lib)],
            tests: vec![
                (0, "tests::t1", false),
                (0, "tests::t2", false),
                (0, "tests::t3", false),
                (0, "tests::t4", false),
            ],
        }
    }

    fn explain_with(inputs: Inputs<'_>) -> anyhow::Result<crate::explain::ExplainReport> {
        let idx = one_package().index();
        let mdl = model(&m(&[node("p", None, &krate("p"), "")]));
        let r = Resolution::build(&mdl, &idx, Path::new("/nonexistent"));
        let table = TestTable::build(&r, false);
        let placement = place(&mdl, &r, &table);
        explain_run(&r, &table, &placement, &mdl, &inputs)
    }

    // 1. Unlisted is not passed: explain refuses, and with --failures-only
    // claims no purity and leaves SKIPped tests out of the indexed count.
    #[test]
    fn explain_refuses_to_assume_passes_and_describes_failures_alone() {
        let failures = "\
        FAIL [ 1s] (1/4) p tests::t1
        FAIL [ 1s] (2/4) p tests::t2
        SKIP [ 0s] (3/4) p tests::t3
";
        let base = Inputs { failures, executed: None, max_causes: 12, use_tops: true, failures_only: false };
        let err = explain_with(base).err().expect("refused").to_string();
        assert!(err.contains("--executed FILE") && err.contains("--failures-only"), "{err}");

        let rep = explain_with(Inputs { failures_only: true, ..base }).unwrap();
        assert!(rep.failures_only);
        assert_eq!(rep.runs.len(), 1, "one listing, no purity sections");
        assert_eq!(rep.skipped_tests, 1);
        assert!(!rep.runs[0].causes.is_empty());
        for c in &rep.runs[0].causes {
            // Four indexed with each of these attributes, one of them SKIP.
            assert_eq!((c.failed, c.indexed), (2, 3), "{}", c.attr);
        }
        let text = rep.render();
        assert!(text.contains("causes over the failures only; passes unknown"), "{text}");
        assert!(text.contains("2 failed of 3 indexed with this attribute (whether the other 1 ran is unknown)"), "{text}");
        assert!(text.contains("failures no shared attribute describes"));
        assert!(!text.contains("purity") && !text.contains("description length") && !text.contains("residue"), "{text}");
    }

    /// 3. Without a cargo index a test's parts are its home node only.
    #[test]
    fn git_only_parts_are_the_home_node_so_a_declared_edge_is_uncovered_without_a_check() {
        let idx = crate::fixtures::Fixture {
            packages: vec![],
            files: vec![
                ("a/lib.rs", None, keel_index::Target::Other),
                ("b/lib.rs", None, keel_index::Target::Other),
            ],
            tests: vec![(0, "tests::a_works", false)],
        }
        .index();
        let a = node("a", None, &path("a/**"), "").replace(r#""on":[]"#, r#""on":["b"]"#);
        let b = node("b", None, &path("b/**"), "");
        let json = |checks: &str| {
            format!(
                r#"{{"schema":2,"nodes":[{a},{b}],"checks":{checks},"policy":{{"uncovered":"fail","joins":[],"faults":"report"}}}}"#
            )
        };
        let covered_by_check = r#"{"g":{"checks":[{"on":["a","b"],"coordinates":{},"inputs":[],"cell":"x"}],"uncovered":[]}}"#;
        let go = |checks: &str| {
            let mdl = model(&json(checks));
            let r = Resolution::build_with(&mdl, &idx, Path::new("/nonexistent"), Some("test"));
            let table = TestTable::build(&r, false);
            assert_eq!(table.len(), 1);
            let parts = crate::parts::TestParts::build(&r, &table);
            let names: Vec<&str> = parts.parts(0).iter().map(|&n| r.nodes[n].id.as_str()).collect();
            assert_eq!(names, vec!["a"], "parts are the home node only");
            crate::coverage::run(&mdl, &r, &table, None, false)
        };
        let o = go("{}");
        assert_eq!(o.summary.uncovered, 1, "{:?}", o.findings);
        assert!(o.findings.iter().any(|f| f.code == "uncovered-edge" && f.message.contains("a (")));
        let o = go(covered_by_check);
        assert_eq!(o.summary.uncovered, 0);
        // Listing both in `on` is not evidence: it is declared only, and still an error under `fail`.
        assert_eq!((o.summary.covered_by_breaking_twin, o.summary.declared_only), (0, 1));
        assert!(o.findings.iter().any(|f| f.severity == Severity::Error && f.message.contains("shows nothing about the pair")), "{:?}", o.findings);
    }

    /// 4. The baseline moves only on --accept.
    #[test]
    fn the_uncovered_baseline_is_set_and_changed_only_by_accept() {
        let fx = standard();
        let idx = fx.index();
        // `ghost` is entry-only and stands on core (declared): one unverifiable edge.
        let ghost = |extra_on: &str| {
            node("ghost", None, "", "")
                .replace(r#""on":[]"#, r#""on":["core"]"#)
                .replace(
                    r#""entry":[]"#,
                    &format!(r#""entry":[{}{extra_on}]"#, path("crates/core/src/lib.rs")),
                )
        };
        let build = |extra_on: &str| {
            model(&format!(
                r#"{{"schema":2,"nodes":[{},{},{}],"policy":{{"uncovered":"report","joins":[],"faults":"report"}}}}"#,
                node("core", None, &krate("core"), ""),
                node("mid", None, &krate("mid"), ""),
                ghost(extra_on)
            ))
        };
        let lock = std::env::temp_dir().join(format!("keel-tree-accept-{}", std::process::id()));
        let _ = std::fs::remove_file(&lock);
        let rejected = std::path::PathBuf::from(format!("{}.rejected", lock.display()));
        let _ = std::fs::remove_file(&rejected);
        let go = |mdl: &crate::model::Model, accept: bool| {
            let r = Resolution::build(mdl, &idx, Path::new("/nonexistent"));
            let table = TestTable::build(&r, false);
            check::run(mdl, &r, &table, Some(&lock), accept).unwrap()
        };
        let errors = |rep: &check::CheckReport| -> Vec<&'static str> {
            rep.findings.iter().filter(|f| f.severity == crate::finding::Severity::Error).map(|f| f.code).collect()
        };
        // No accepted lock yet: every uncovered edge is an error to review, nothing is accepted.
        let first = go(&build(""), false);
        assert!(errors(&first).contains(&"no-accepted-baseline"), "{:?}", first.findings.iter().map(|f| (f.code, &f.message)).collect::<Vec<_>>());
        assert!(first.lock.as_ref().unwrap().rejected);
        assert!(!lock.exists(), "nothing is accepted without --accept");
        // --accept sets the baseline.
        let accepted = go(&build(""), true);
        assert!(!accepted.has_errors(), "{:?}", accepted.findings.iter().map(|f| &f.message).collect::<Vec<_>>());
        let text = std::fs::read_to_string(&lock).unwrap();
        assert!(text.contains("\"ghost\"") && text.contains("\"uncovered\""));
        // Unchanged model, no flag: passes and the lock is as it was.
        let again = go(&build(""), false);
        assert!(!again.has_errors());
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), text);
        // A new uncovered edge without the flag: error, rejected, accepted lock untouched.
        let worse = go(&build(&format!(",{}", path("crates/mid/src/lib.rs"))), false);
        assert!(errors(&worse).contains(&"new-uncovered-edge"));
        assert!(worse.lock.as_ref().unwrap().rejected);
        assert_eq!(std::fs::read_to_string(&lock).unwrap(), text, "never rewritten to admit a new edge");
        assert!(std::fs::read_to_string(&rejected).unwrap().contains("\"mid\""));
        // With the flag it is admitted.
        let admitted = go(&build(&format!(",{}", path("crates/mid/src/lib.rs"))), true);
        assert!(!admitted.has_errors());
        assert_ne!(std::fs::read_to_string(&lock).unwrap(), text);
        // Covering an edge does not shrink the baseline without the flag.
        let shrunk = go(&build(""), false);
        assert!(!shrunk.has_errors());
        assert!(shrunk.findings.iter().any(|f| f.code == "baseline-can-tighten"));
        assert!(std::fs::read_to_string(&lock).unwrap().contains("\"mid\""));
        let _ = std::fs::remove_file(&lock);
        let _ = std::fs::remove_file(&rejected);
    }
}

mod round_five {
    use super::*;
    use crate::plan::{Class, effects};
    use keel_index::{Change, FileChange, FileStatus};

    fn temp_repo(name: &str, files: &[(&str, &str)]) -> std::path::PathBuf {
        let dir = std::env::temp_dir().join(format!("keel-tree-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        for (p, text) in files {
            let f = dir.join(p);
            std::fs::create_dir_all(f.parent().unwrap()).unwrap();
            std::fs::write(f, text).unwrap();
        }
        let git = |args: &[&str]| {
            assert!(
                std::process::Command::new("git")
                    .arg("-C")
                    .arg(&dir)
                    .args(["-c", "user.email=t@t", "-c", "user.name=t"])
                    .args(args)
                    .status()
                    .unwrap()
                    .success()
            );
        };
        git(&["init", "-q"]);
        git(&["add", "."]);
        git(&["commit", "-q", "-m", "x"]);
        dir
    }

    fn change(paths: &[&str]) -> Change {
        Change {
            files: paths
                .iter()
                .map(|p| FileChange {
                    path: (*p).to_owned(),
                    status: FileStatus::Modified,
                    items: vec![],
                    outside_items: true,
                    position_only: false,
                })
                .collect(),
        }
    }

    /// A git-only repository: nodes a (stands on nothing) and b (on a), one
    /// check on each, an inert docs tree, and files nobody owns.
    fn setup(name: &str) -> (std::path::PathBuf, crate::model::Model) {
        let dir = temp_repo(
            name,
            &[
                ("svc/a/lib.rs", "#[test]\nfn a_works() {}\n"),
                ("svc/b/lib.rs", "#[test]\nfn b_works() {}\n"),
                ("docs/guide.md", "words"),
                ("ci/pipeline.yml", "steps"),
                ("Makefile", "all:"),
            ],
        );
        let b = node("b", None, &path("svc/b/**"), "").replace(r#""on":[]"#, r#""on":["a"]"#);
        let json = format!(
            r#"{{"schema":2,"nodes":[{a},{b}],"checks":{{"g":{{"checks":[
              {{"on":["a"],"coordinates":{{}},"inputs":[],"cell":"one"}},
              {{"on":["b"],"coordinates":{{}},"inputs":[],"cell":"two"}}],"uncontrolled":[]}}}},
              "policy":{{"uncovered":"report","joins":[],"inert":[{{"by":"path","glob":"docs/**"}}]}}}}"#,
            a = node("a", None, &path("svc/a/**"), ""),
        );
        (dir, model(&json))
    }

    #[test]
    fn owned_unowned_and_inert_add_up_to_the_tracked_files() {
        let (dir, mdl) = setup("census");
        let idx = crate::source::git_only(&dir).unwrap();
        let r = Resolution::build_with(&mdl, &idx, &dir, Some("test"));
        let c = r.census();
        assert_eq!((c.tracked, c.owned, c.unowned, c.inert), (5, 2, 2, 1), "{c:?}");
        assert_eq!(c.owned + c.unowned + c.inert + c.conflict, c.tracked);
        assert_eq!(c.unowned_by_dir["ci"].0, 1);
        assert_eq!(c.unowned_by_dir["Makefile"].0, 1);
        // The unowned node is real and ships as required.
        assert_eq!(r.nodes[r.unowned].ship.as_deref(), Some("required"));
        assert_eq!(r.file_owner.iter().filter(|o| **o == Owner::Node(r.unowned)).count(), 2);
        // check prints the sum.
        let table = TestTable::build(&r, false);
        let rep = crate::check::run(&mdl, &r, &table, None, true).unwrap();
        assert!(rep.render().contains("5 tracked = 2 owned by a node + 2 unowned + 1 inert"), "{}", rep.render());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn changing_an_unowned_file_affects_every_test_and_every_check_and_inert_affects_none() {
        let (dir, mdl) = setup("effects");
        let idx = crate::source::git_only(&dir).unwrap();
        let r = Resolution::build_with(&mdl, &idx, &dir, Some("test"));
        let table = TestTable::build(&r, false);
        assert_eq!(table.len(), 2);

        let unowned = effects(&r, &table, &mdl, &change(&["ci/pipeline.yml"]));
        assert_eq!(unowned.files[0].class, Class::Global);
        assert!(unowned.global);
        assert_eq!(unowned.affected.len(), 2, "every test");
        assert_eq!(unowned.checks_affected.len(), 2, "every matrix check");
        assert_eq!(unowned.checks_total, 2);
        // It moves `unowned`, at layer 0.
        assert_eq!((unowned.touches[0].node.as_str(), unowned.touches[0].layer), ("unowned", 0));

        let inert = effects(&r, &table, &mdl, &change(&["docs/guide.md"]));
        assert_eq!(inert.files[0].class, Class::Inert);
        assert!(!inert.global);
        assert_eq!((inert.affected.len(), inert.checks_affected.len()), (0, 0));
        assert!(inert.touches.is_empty());

        // An owned file moves what stands on it: a's change reaches b through `on`.
        let owned = effects(&r, &table, &mdl, &change(&["svc/a/lib.rs"]));
        assert_eq!(owned.files[0].class, Class::Node);
        assert_eq!((owned.affected.len(), owned.checks_affected.len()), (2, 2));
        let b_only = effects(&r, &table, &mdl, &change(&["svc/b/lib.rs"]));
        assert_eq!((b_only.affected.len(), b_only.checks_affected.len()), (1, 1));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn an_inert_selector_that_matches_nothing_is_an_error() {
        let (dir, mdl) = setup("deadinert");
        let mut dead = mdl.clone();
        dead.policy.inert = vec![crate::model::Selector::Path { glob: "nothing/**".into(), reason: Some("a dead exception".into()) }];
        let idx = crate::source::git_only(&dir).unwrap();
        let r = Resolution::build_with(&dead, &idx, &dir, Some("test"));
        let table = TestTable::build(&r, false);
        let rep = crate::check::run(&dead, &r, &table, None, true).unwrap();
        let f = rep
            .findings
            .iter()
            .find(|f| f.code == "selector-matches-nothing" && f.message.contains("policy.inert"))
            .expect("zero-match error");
        assert_eq!(f.severity, Severity::Error);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

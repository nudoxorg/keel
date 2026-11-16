//! Tests that need a real git history: plan over commits, pattern selectors over
//! tracked files. Each builds a small repository in a temporary directory.

use crate::finding::Severity;
use crate::model::Model;
use crate::plan::{self, Class, PlanReport};
use crate::resolve::{Owner, Resolution};
use crate::source;
use crate::testset::TestTable;
use std::path::Path;
use std::process::Command;
use tempfile::TempDir;

pub struct Repo {
    pub dir: TempDir,
}

impl Repo {
    pub fn new(files: &[(&str, &str)]) -> Repo {
        let r = Repo { dir: tempfile::tempdir().expect("temp dir") };
        r.sh(&["init", "-q"]);
        for (p, text) in files {
            r.write(p, text);
        }
        r.commit("base");
        r
    }

    pub fn root(&self) -> &Path {
        self.dir.path()
    }

    pub fn sh(&self, args: &[&str]) -> String {
        let out = Command::new("git")
            .arg("-C")
            .arg(self.root())
            .args(["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"])
            .args(args)
            .output()
            .expect("git runs");
        assert!(out.status.success(), "git {args:?}: {}", String::from_utf8_lossy(&out.stderr));
        String::from_utf8_lossy(&out.stdout).trim().to_owned()
    }

    pub fn write(&self, rel: &str, text: &str) {
        let f = self.root().join(rel);
        std::fs::create_dir_all(f.parent().expect("a parent")).expect("mkdir");
        std::fs::write(f, text).expect("write");
    }

    /// Stages everything and commits; returns the new revision.
    pub fn commit(&self, msg: &str) -> String {
        self.sh(&["add", "-A"]);
        self.sh(&["commit", "-q", "-m", msg]);
        self.sh(&["rev-parse", "HEAD"])
    }
}

pub fn node(id: &str, code: &str, on: &[&str]) -> String {
    let on: Vec<String> = on.iter().map(|o| format!("\"{o}\"")).collect();
    format!(
        r#"{{"id":"{id}","at":"/m/keel.nix:1","parent":null,"about":null,"code":[{code}],"entry":[],"on":[{}],"never":[],"of":[],"ship":null,"movedBy":[],"unmovedBy":[]}}"#,
        on.join(",")
    )
}

pub fn path(g: &str) -> String {
    format!(r#"{{"by":"path","glob":"{g}"}}"#)
}

pub fn model(nodes: &[String], rest: &str) -> Model {
    let rest = if rest.is_empty() { String::new() } else { format!(",{rest}") };
    Model::from_json(&format!(r#"{{"schema":2,"nodes":[{}]{rest}}}"#, nodes.join(","))).expect("model parses")
}

fn plan_of(repo: &Repo, mdl: &Model, base: &str, head: &str) -> PlanReport {
    let idx = source::git_only(repo.root()).expect("index");
    let res = Resolution::build_with(mdl, &idx, repo.root(), Some("test"));
    let table = TestTable::build(&res, false);
    let opts = plan::Options { by_seconds: None, max_notices: plan::assumptions::MAX_NOTICES, max_candidates: plan::assumptions::MAX_CANDIDATES };
    plan::run(&res, &table, mdl, repo.root(), base, head, &opts).expect("plan runs")
}

fn cell(on: &[&str], cell: &str, inputs: &str, world: Option<&str>, control: Option<&str>) -> String {
    let on: Vec<String> = on.iter().map(|o| format!("\"{o}\"")).collect();
    format!(
        r#"{{"on":[{}],"coordinates":{{}},"inputs":[{inputs}],"cell":"{cell}","control":{},"faults":[],"world":{}}}"#,
        on.join(","),
        control.map_or("null".to_owned(), |c| format!("\"{c}\"")),
        world.map_or("null".to_owned(), |w| format!("\"{w}\""))
    )
}

#[test]
fn a_check_input_or_its_worlds_input_makes_the_check_affected() {
    let repo = Repo::new(&[("a/a.rs", "fn a() {}\n"), ("b/b.rs", "fn b() {}\n"), ("probe/p.sh", "echo 1\n"), ("fix/f.json", "{}\n")]);
    let checks = format!(
        r#""checks":{{"g":{{"checks":[{},{}]}},"w":{{"checks":[{}]}}}},
           "worlds":[{{"name":"base","from":null,"inputs":[{}]}},{{"name":"leaf","from":"base","inputs":[]}}]"#,
        cell(&["b", "a"], "p=one", &path("probe/**"), None, None),
        cell(&["b", "a"], "p=one", &path("probe/**"), None, Some("wrong")),
        cell(&["b", "a"], "q=one", "", Some("leaf"), None),
        path("fix/**"),
    );
    let mdl = model(
        &[node("a", &path("a/**"), &[]), node("b", &path("b/**"), &["a"]), node("probe", &path("probe/**"), &[]), node("fix", &path("fix/**"), &[])],
        &checks,
    );
    let base = repo.sh(&["rev-parse", "HEAD"]);
    repo.write("probe/p.sh", "echo 2\n");
    let probe = repo.commit("probe");
    let p = plan_of(&repo, &mdl, &base, &probe);
    // The two checks listing probe/** are affected though neither exercises node `probe`.
    assert_eq!((p.checks_affected, p.checks_by_inputs, p.checks_total), (2, 2, 3), "{}", p.render());
    repo.write("fix/f.json", "{\"x\":1}\n");
    let fix = repo.commit("fixture");
    // The third check starts in `leaf`, built from `base`, whose input is fix/**.
    let p = plan_of(&repo, &mdl, &probe, &fix);
    assert_eq!((p.checks_affected, p.checks_by_inputs), (1, 1), "{}", p.render());
}

#[test]
fn a_doc_comment_change_is_not_position_only_but_a_plain_comment_is() {
    let repo = Repo::new(&[("a/doc.rs", "/// old\nfn f() {}\n"), ("a/plain.rs", "// one\nfn g() {}\n"), ("a/block.rs", "/**\n old\n*/\nfn h() {}\n")]);
    let mdl = model(&[node("a", &path("a/**"), &[])], "");
    let base = repo.sh(&["rev-parse", "HEAD"]);
    repo.write("a/doc.rs", "/// new\nfn f() {}\n");
    repo.write("a/plain.rs", "// two\nfn g() {}\n");
    repo.write("a/block.rs", "/**\n new\n*/\nfn h() {}\n");
    let head = repo.commit("docs");
    let p = plan_of(&repo, &mdl, &base, &head);
    let class = |f: &str| p.files.iter().find(|x| x.path == f).map(|x| x.class).expect("file listed");
    assert_eq!(class("a/doc.rs"), Class::Node, "{}", p.render());
    assert_eq!(class("a/block.rs"), Class::Node);
    assert_eq!(class("a/plain.rs"), Class::PositionOnly);
}

#[test]
fn a_rename_is_a_deletion_and_an_addition_and_the_tests_that_left_are_named() {
    let repo = Repo::new(&[("x/tests/a.rs", "#[test]\nfn t1() {}\n"), ("y/tests/b.rs", "#[test]\nfn t2() {}\n"), ("docs/readme.md", "words\n")]);
    let policy = format!(r#""policy":{{"uncovered":"report","joins":[],"inert":[{}]}}"#, path("docs/**"));
    let mdl = model(&[node("x", &path("x/**"), &[]), node("y", &path("y/**"), &[])], &policy);
    let base = repo.sh(&["rev-parse", "HEAD"]);
    repo.sh(&["mv", "x/tests/a.rs", "y/tests/a.rs"]);
    let moved = repo.commit("move across nodes");
    let p = plan_of(&repo, &mdl, &base, &moved);
    let by_path = |f: &str| p.files.iter().find(|x| x.path == f).unwrap_or_else(|| panic!("{f} listed in {}", p.render()));
    assert_eq!(by_path("x/tests/a.rs").owner.as_deref(), Some("x"));
    assert!(by_path("x/tests/a.rs").status.starts_with("deleted"));
    assert_eq!(by_path("y/tests/a.rs").owner.as_deref(), Some("y"));
    assert!(by_path("y/tests/a.rs").status.starts_with("added"));
    assert_ne!(by_path("x/tests/a.rs").class, Class::PositionOnly);
    let touched: Vec<&str> = p.touches.iter().map(|t| t.node.as_str()).collect();
    assert!(touched.contains(&"x") && touched.contains(&"y"), "{touched:?}");
    assert_eq!(p.gone_tests.len(), 1);
    assert_eq!(p.gone_tests[0].path, "x/tests/a.rs");
    assert_eq!(p.gone_tests[0].moved_to.as_deref(), Some("y/tests/a.rs"));
    assert!(p.gone_tests[0].tests[0].ends_with("$t1"), "{:?}", p.gone_tests);
    assert!(p.render().contains("tests that went away from x/tests/a.rs"));

    // Into an inert path: still a deletion from y.
    repo.sh(&["mv", "y/tests/b.rs", "docs/b.rs"]);
    let inert = repo.commit("move into docs");
    let p = plan_of(&repo, &mdl, &moved, &inert);
    let old = p.files.iter().find(|x| x.path == "y/tests/b.rs").expect("old side listed");
    let new = p.files.iter().find(|x| x.path == "docs/b.rs").expect("new side listed");
    assert_eq!((old.class, new.class), (Class::Node, Class::Inert), "{}", p.render());
    assert!(p.touches.iter().any(|t| t.node == "y"));
    assert_eq!(p.gone_tests.len(), 1, "{}", p.render());
    assert!(p.gone_tests[0].tests[0].ends_with("$t2"));
}

#[test]
fn a_test_nobody_owns_is_affected_by_every_change_without_a_package_graph() {
    let repo = Repo::new(&[("a/a.rs", "fn a() {}\n"), ("u/t.rs", "#[test]\nfn lonely() {}\n"), ("b/t.rs", "#[test]\nfn owned() {}\n")]);
    let mdl = model(&[node("a", &path("a/**"), &[]), node("b", &path("b/**"), &[])], "");
    let base = repo.sh(&["rev-parse", "HEAD"]);
    repo.write("a/a.rs", "fn a() { let _ = 1; }\n");
    let head = repo.commit("change a");
    let p = plan_of(&repo, &mdl, &base, &head);
    // b's test does not stand on a; the unowned one may.
    assert_eq!((p.tests_affected, p.tests_total), (1, 2), "{}", p.render());
}

#[test]
fn the_model_schema_and_check_ids_are_checked() {
    let nodes = node("a", &path("a/**"), &[]);
    let err = Model::from_json(&format!(r#"{{"schema":1,"nodes":[{nodes}]}}"#)).unwrap_err().to_string();
    assert!(err.contains("schema 1") && err.contains("schema 2"), "{err}");
    let twins = format!(
        r#""checks":{{"g":{{"checks":[{},{},{}]}}}}"#,
        cell(&["a"], "p=1", "", None, None),
        cell(&["a"], "p=1", "", None, Some("wrong")),
        cell(&["a"], "p=1", "", None, None),
    );
    let err = Model::from_json(&format!(r#"{{"schema":2,"nodes":[{nodes}],{twins}}}"#)).unwrap_err().to_string();
    assert!(err.contains("g:p=1 (2 instances)"), "{err}");
    let ok = format!(
        r#""checks":{{"g":{{"checks":[{},{},{}]}}}}"#,
        cell(&["a"], "p=1", "", None, None),
        cell(&["a"], "p=1", "", None, Some("wrong")),
        cell(&["a"], "p=1", "", None, Some("other")),
    );
    let m = Model::from_json(&format!(r#"{{"schema":2,"nodes":[{nodes}],{ok}}}"#)).expect("distinct ids");
    let ids: Vec<String> = m.checks["g"].checks.iter().map(|c| c.id("g")).collect();
    assert_eq!(ids, ["g:p=1", "g:p=1#control=wrong", "g:p=1#control=other"]);
    let fault = r#"{"on":["a"],"coordinates":{},"inputs":[],"cell":"p=1","control":null,"faults":[{"name":"reboot"}],"world":null}"#;
    let m = Model::from_json(&format!(r#"{{"schema":2,"nodes":[{nodes}],"checks":{{"g":{{"checks":[{fault}]}}}}}}"#)).unwrap();
    assert_eq!(m.checks["g"].checks[0].id("g"), "g:p=1#fault=reboot");
}

#[test]
fn census_records_on_one_side_only_are_findings() {
    let repo = Repo::new(&[("a/a.rs", "fn a() {}\n")]);
    let census = r#""census":[
        {"name":"ports","at":"/m/keel.nix:9","key":["port"],"extra":"fail","missing":"report","result":{"extra":[{"port":22}],"missing":[{"port":80}]}},
        {"name":"files","at":"/m/keel.nix:20","key":["f"],"extra":"report","missing":"fail","result":{"extra":[{"f":"x"}],"missing":[]}},
        {"name":"live","at":"/m/keel.nix:30","key":["h"],"result":null}]"#;
    let mdl = model(&[node("a", &path("a/**"), &[])], census);
    let idx = source::git_only(repo.root()).unwrap();
    let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
    let table = TestTable::build(&res, false);
    let rep = crate::check::run(&mdl, &res, &table, None, false).unwrap();
    let find = |code: &str| rep.findings.iter().filter(|f| f.code == code).collect::<Vec<_>>();
    let extra = find("census-extra");
    assert_eq!(extra.len(), 2);
    assert!(extra.iter().any(|f| f.severity == Severity::Error && f.message.contains("ports") && f.message.contains("port=22")));
    assert!(extra.iter().any(|f| f.severity == Severity::Info && f.message.contains("files")));
    let missing = find("census-missing");
    assert_eq!((missing.len(), missing[0].severity), (1, Severity::Info));
    assert!(missing[0].message.contains("port=80"));
    let live = find("census-not-run");
    assert_eq!((live.len(), live[0].severity), (1, Severity::Warning));
    assert!(live[0].message.contains("live") && live[0].message.contains("NOT RUN"));
    assert_eq!(rep.summary.census_not_run, ["live"]);
    assert_eq!(rep.summary.census_compared, 2);
    assert!(rep.render().contains("2 compared; 1 NOT RUN (live)"), "{}", rep.render());
    // Under --strict a census nothing ran fails the check.
    let strict = crate::check::run_with(&mdl, &res, &table, None, false, true).unwrap();
    let live = strict.findings.iter().find(|f| f.code == "census-not-run").unwrap();
    assert_eq!(live.severity, Severity::Error);
}


#[test]
fn a_census_sourced_from_a_boundary_class_compares_production_sites_with_the_declared_files() {
    let repo = Repo::new(&[
        ("a/declared.rs", "pub fn f() { let _ = std::process::Command::new(\"x\"); }\n"),
        ("a/undeclared.rs", "pub fn g() { let _ = std::process::Command::new(\"y\"); }\n"),
        ("a/excused.rs", "pub fn h() { let _ = std::process::Command::new(\"z\"); }\n"),
        ("a/test_only.rs", "#[cfg(test)]\nmod t { fn k() { let _ = std::process::Command::new(\"t\"); } }\n"),
    ]);
    let census = |key: &str, declared: &str| {
        format!(
            r#""census":[{{"name":"spawns","at":"/m/keel.nix:7","boundary":"process-spawn","key":[{key}],"extra":"fail","missing":"report",
            "ignore":[{{"match":{{"file":"a/excused.rs"}},"reason":"a tool the product ships"}}],"declared":[{declared}]}}]"#
        )
    };
    let check = |census: String| {
        let mdl = model(&[node("a", &path("a/**"), &[])], &census);
        let idx = source::git_only(repo.root()).unwrap();
        let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
        let table = TestTable::build(&res, false);
        crate::check::run(&mdl, &res, &table, None, false).unwrap()
    };
    let rep = check(census(r#""file""#, r#"{"file":"a/declared.rs"},{"file":"a/gone.rs"}"#));
    let find = |code: &str| rep.findings.iter().filter(|f| f.code == code).collect::<Vec<_>>();
    let extra = find("census-extra");
    assert_eq!(extra.len(), 1, "{:?}", rep.findings.iter().map(|f| &f.message).collect::<Vec<_>>());
    assert!(extra[0].severity == Severity::Error && extra[0].message.contains("file=a/undeclared.rs"), "{}", extra[0].message);
    let missing = find("census-missing");
    assert!(missing.len() == 1 && missing[0].severity == Severity::Info && missing[0].message.contains("a/gone.rs"));
    assert_eq!((rep.summary.census_compared, rep.summary.census_not_run.len()), (1, 0));

    // `node` in the key adds the owner to each record.
    let rep = check(census(r#""file","node""#, r#"{"file":"a/declared.rs","node":"a"},{"file":"a/undeclared.rs","node":"a"}"#));
    assert!(rep.findings.iter().all(|f| !f.code.starts_with("census-extra")), "{:?}", rep.findings.iter().map(|f| &f.message).collect::<Vec<_>>());

    // A key field the engine cannot supply is an error naming the census, its position and what is available.
    let rep = check(census(r#""file","owner""#, ""));
    let bad = rep.findings.iter().find(|f| f.code == "census-boundary").expect("an error finding");
    assert!(bad.severity == Severity::Error && bad.message.contains("spawns") && bad.message.contains("keel.nix:7") && bad.message.contains("file, node, line"), "{}", bad.message);
}
#[test]
fn explain_does_not_panic_on_a_failing_check_cell_no_cause_covers_and_counts_only_executed_cells() {
    let repo = Repo::new(&[("a/a.rs", "fn a() {}\n")]);
    let checks = format!(
        r#""checks":{{"g":{{"checks":[{},{}]}}}}"#,
        cell(&["a"], "p=one", "", None, None),
        cell(&["a"], "p=two", "", None, None)
    );
    let mdl = model(&[node("a", &path("a/**"), &[])], &checks);
    let idx = source::git_only(repo.root()).unwrap();
    let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
    let table = TestTable::build(&res, false);
    let placement = crate::testset::place(&mdl, &res, &table);
    let run = |failures_only: bool, executed: Option<&str>| {
        crate::explain::run(
            &res,
            &table,
            &placement,
            &mdl,
            &crate::explain::Inputs { failures: "check:g:p=one\n", executed, max_causes: 5, use_tops: true, failures_only },
        )
        .expect("explain runs")
    };
    let r = run(true, None);
    assert!(r.runs.iter().any(|x| x.residue_examples.iter().any(|e| e == "check:g:p=one")), "{:?}", r.runs.iter().map(|x| &x.residue_examples).collect::<Vec<_>>());
    // Only the executed cell is executed: the other was not run, so it is not a pass.
    let r = run(false, Some("check:g:p=one\n"));
    assert!(r.executed_note.contains("1 of 2 check cells executed"), "{}", r.executed_note);
    let r = run(false, Some("check:g:p=one\ncheck:g:p=two\n"));
    assert!(r.executed_note.contains("2 of 2 check cells executed"), "{}", r.executed_note);
}

#[test]
fn a_code_pattern_owns_ranges_not_files() {
    let repo = Repo::new(&[("src/a.py", "def keep():\n    return 1\n\ndef mine():\n    return 2\n\ndef also_keep():\n    return 3\n")]);
    let code = r#"{"by":"path","glob":"src/**"}"#;
    let pat = r#"{"by":"pattern","language":"python","pattern":"def mine():\n    return 2"}"#;
    let mdl = model(&[node("file", code, &[]), node("range", pat, &[])], "");
    let idx = source::git_only(repo.root()).unwrap();
    let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
    let (file, range) = (res.node_index("file").unwrap(), res.node_index("range").unwrap());
    assert_eq!(res.owner_at("src/a.py", 1), Owner::Node(file));
    assert_eq!(res.owner_at("src/a.py", 4), Owner::Node(range));
    assert_eq!(res.owner_at("src/a.py", 5), Owner::Node(range));
    assert_eq!(res.owner_at("src/a.py", 7), Owner::Node(file));
    // The whole-file owner is unchanged.
    assert_eq!(res.owner_of_tracked("src/a.py"), Owner::Node(file));
    assert!(res.findings.iter().all(|f| f.severity != Severity::Error), "{:?}", res.findings);
}

#[test]
fn a_test_file_moved_between_packages_affects_both_packages_in_cargo_mode() {
    use crate::fixtures::standard;
    let repo = Repo::new(&[
        ("crates/core/src/lib.rs", "pub fn c() {}\n"),
        ("crates/mid/src/lib.rs", "pub fn m() {}\n"),
        ("crates/top/src/lib.rs", "pub fn t() {}\n"),
        ("crates/top/tests/journey.rs", "#[test]\nfn walks_everything() {}\n"),
        ("crates/tooling/src/lib.rs", "pub fn x() {}\n"),
    ]);
    let base = repo.sh(&["rev-parse", "HEAD"]);
    std::fs::create_dir_all(repo.root().join("crates/tooling/tests")).unwrap();
    repo.sh(&["mv", "crates/top/tests/journey.rs", "crates/tooling/tests/journey.rs"]);
    let head = repo.commit("move");
    let mut idx = standard().index();
    idx.root = repo.root().to_path_buf();
    let mdl = model(&[node("n", &path("crates/**"), &[])], "");
    let res = Resolution::build(&mdl, &idx, repo.root());
    let table = TestTable::build(&res, false);
    let opts = plan::Options { by_seconds: None, max_notices: plan::assumptions::MAX_NOTICES, max_candidates: plan::assumptions::MAX_CANDIDATES };
    let p = plan::run(&res, &table, &mdl, repo.root(), &base, &head, &opts).expect("plan runs");
    let pkgs: Vec<_> = p.files.iter().map(|f| (f.path.as_str(), f.package.as_deref())).collect();
    assert!(pkgs.contains(&("crates/top/tests/journey.rs", Some("top"))), "{pkgs:?}");
    assert!(pkgs.contains(&("crates/tooling/tests/journey.rs", Some("tooling"))), "{pkgs:?}");
    assert_eq!(p.gone_tests.len(), 1);
    assert!(p.tests_affected > 0, "{}", p.render());
}

mod languages {
    use super::*;
    use crate::pattern;

    /// (language, file, source, pattern that matches it)
    type Case = (&'static str, &'static str, &'static str, &'static str);

    fn found_in(cases: &[Case]) {
        let repo = Repo::new(&cases.iter().map(|c| (c.1, c.2)).collect::<Vec<_>>());
        let tracked: Vec<String> = cases.iter().map(|c| c.1.to_owned()).collect();
        let mut bad = Vec::new();
        for (lang, file, _, pat) in cases {
            match pattern::find(repo.root(), &tracked, lang, pat) {
                Ok(h) if h.files == [file.to_string()] && h.count() >= 1 && h.parsed == 1 => {}
                Ok(h) => bad.push(format!("{lang}: `{pat}` gave {} matches in {:?}, parsed {}", h.count(), h.files, h.parsed)),
                Err(e) => bad.push(format!("{lang}: `{pat}` refused: {e}")),
            }
        }
        assert!(bad.is_empty(), "{}", bad.join("\n"));
    }

    #[test]
    fn systems_languages_rust_c_and_cpp() {
        found_in(&[
            ("rust", "src/lib.rs", "fn serve() { println!(\"hi\"); }\n", "println!($$$A)"),
            ("c", "src/m.c", "int main(void) {\n  free(p);\n  return 0;\n}\n", "free($P);"),
            ("cpp", "src/m.cpp", "int main() {\n  delete p;\n  return 0;\n}\n", "delete $P;"),
        ]);
    }

    #[test]
    fn web_languages_typescript_tsx_javascript_css_html_and_json() {
        found_in(&[
            ("typescript", "web/a.ts", "export function f(): void { console.log(1, 2); }\n", "console.log($$$A)"),
            ("tsx", "web/b.tsx", "export const B = () => <div>{console.log(1)}</div>;\n", "console.log($$$A)"),
            ("javascript", "web/c.js", "const x = require('fs');\n", "require($A)"),
            ("css", "web/d.css", "a { color: red; }\n", "a { color: $V; }"),
            ("html", "web/e.html", "<html><body><a href=\"/x\">x</a></body></html>\n", "<a href=\"$U\">$$$T</a>"),
            ("json", "web/f.json", "{\"a\": 1}\n", "{\"a\": 1}"),
        ]);
    }

    #[test]
    fn scripting_languages_python_ruby_bash_nix_and_yaml() {
        found_in(&[
            ("python", "py/a.py", "def f(x):\n    print(x, 1)\n", "print($$$A)"),
            ("ruby", "rb/a.rb", "def f\n  puts 1\nend\n", "puts $A"),
            ("bash", "sh/a.sh", "#!/bin/sh\necho hello\n", "echo $A"),
            ("nix", "nix/a.nix", "{ pkgs }: pkgs.hello\n", "pkgs.$N"),
            ("yaml", "ci/a.yml", "name: build\non: push\n", "name: $N"),
        ]);
    }

    #[test]
    fn managed_languages_go_java_csharp_and_swift() {
        found_in(&[
            ("go", "go/a.go", "package main\nfunc main() {\n\thttp.ListenAndServe(\":80\", nil)\n}\n", "http.ListenAndServe($$$A)"),
            ("java", "j/A.java", "class A { void f() { System.out.println(1); } }\n", "System.out.println($A);"),
            ("csharp", "cs/A.cs", "class A { void F() { Console.WriteLine(1); } }\n", "Console.WriteLine($A);"),
            ("swift", "sw/a.swift", "func f() { print(1) }\n", "print($A)"),
        ]);
    }

    #[test]
    fn zero_matches_unparsable_patterns_and_unknown_languages_are_three_different_errors() {
        let repo = Repo::new(&[("src/a.py", "def f():\n    return 1\n"), ("src/big.py", "x = 1\n")]);
        let pat = |l: &str, p: &str| format!(r#"{{"by":"pattern","language":"{l}","pattern":"{p}"}}"#);
        let build = |sel: String| {
            let mdl = model(&[node("n", &path("src/a.py"), &[]), node("p", &sel, &[])], "");
            let idx = source::git_only(repo.root()).unwrap();
            Resolution::build_with(&mdl, &idx, repo.root(), Some("test")).findings
        };
        let f = build(pat("python", "print($$$A)"));
        let zero = f.iter().find(|f| f.code == "selector-matches-nothing").expect("zero-match is an error");
        assert_eq!(zero.severity, Severity::Error);
        assert!(zero.message.contains("It parsed 0 of 2 tracked python files") && zero.message.contains("print"), "{}", zero.message);
        let f = build(pat("python", "def ("));
        let bad = f.iter().find(|f| f.code == "bad-pattern").expect("unparsable is its own error");
        assert!(bad.message.contains("syntax error") && bad.message.contains("def ("), "{}", bad.message);
        let f = build(pat("cobol", "x"));
        let unk = f.iter().find(|f| f.code == "unsupported-selector").expect("unknown language");
        assert!(unk.message.contains("cobol") && unk.message.contains("written at /m/keel.nix:1") && unk.message.contains("rust, "), "{}", unk.message);
    }

    #[test]
    fn oversized_files_are_skipped_and_reported_not_silent() {
        let repo = Repo::new(&[("src/a.py", "print(1)\n")]);
        let big = format!("print(2)\n{}", "# pad\n".repeat((pattern::MAX_FILE_BYTES as usize) / 6 + 10));
        repo.write("src/big.py", &big);
        repo.commit("big");
        let tracked = vec!["src/a.py".to_owned(), "src/big.py".to_owned()];
        let h = pattern::find(repo.root(), &tracked, "python", "print($A)").unwrap();
        assert_eq!((h.count(), h.skipped.len(), h.parsed), (1, 1, 1));
        assert!(h.skipped[0].reason.contains("limit"));
        let mdl = model(&[node("p", r#"{"by":"pattern","language":"python","pattern":"print($A)"}"#, &[])], "");
        let idx = source::git_only(repo.root()).unwrap();
        let r = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
        let w = r.findings.iter().find(|f| f.code == "pattern-files-skipped").expect("a skipped file is a finding");
        assert_eq!(w.severity, Severity::Warning);
        assert!(w.message.contains("src/big.py"));
    }

    #[test]
    fn code_patterns_own_ranges_and_conflict_when_two_nodes_overlap() {
        let repo = Repo::new(&[("c/m.c", "int a(void) {\n  free(x);\n  return 0;\n}\nint b(void) {\n  free(y);\n  return 1;\n}\n")]);
        let free = r#"{"by":"pattern","language":"c","pattern":"free($P);"}"#;
        let body = r#"{"by":"pattern","language":"c","pattern":"int a($$$A) { $$$B }"}"#;
        let mdl = model(&[node("freer", free, &[]), node("owner_a", body, &[])], "");
        let idx = source::git_only(repo.root()).unwrap();
        let r = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
        // Lines 2 and 6 are `free` calls; lines 1-4 are function a. Line 2 is in both.
        let conflict = r.findings.iter().find(|f| f.code == "ownership-conflict").expect("overlap is a conflict");
        assert!(conflict.message.contains("c/m.c:2-2"), "{}", conflict.message);
        assert_eq!(r.owner_at("c/m.c", 2), Owner::Conflict);
        assert_eq!(r.owner_at("c/m.c", 3), Owner::Node(r.node_index("owner_a").unwrap()));
        assert_eq!(r.owner_at("c/m.c", 6), Owner::Node(r.node_index("freer").unwrap()));
        assert_eq!(r.owner_at("c/m.c", 7), Owner::Node(r.unowned));
    }
}

#[test]
fn a_rust_entry_pattern_maps_to_the_index_function_and_plan_names_it() {
    use crate::fixtures::standard;
    let src = "use std::io;\n\n#[tool]\nasync fn serve() {\n    let _ = 1;\n}\n\n#[tool]\nasync fn other() {}\n";
    let repo = Repo::new(&[("crates/core/src/lib.rs", src), ("crates/mid/src/lib.rs", "pub fn m() {}\n"), ("crates/top/src/lib.rs", "pub fn t() {}\n"), ("crates/tooling/src/lib.rs", "pub fn x() {}\n")]);
    let base = repo.sh(&["rev-parse", "HEAD"]);
    let mut idx = standard().index();
    idx.root = repo.root().to_path_buf();
    let item = |path: &str, s, e| keel_index::Item {
        file: 0,
        path: path.to_owned(),
        start_line: s,
        end_line: e,
        tokens: [0; 32],
        signature: [0; 32],
        branches: 0,
        is_test: false,
        ignored: false,
        in_test_code: false,
    };
    idx.items = vec![item("serve", 3, 6), item("other", 8, 9)];
    let entry = r##"{"by":"pattern","language":"rust","pattern":"#[tool] async fn $N($$$A) { $$$B }"}"##;
    let mut feature = node("feature", "", &[]);
    feature = feature.replace(r#""entry":[]"#, &format!(r#""entry":[{entry}]"#));
    let mdl = model(&[node("core", &path("crates/core/**"), &[]), feature], "");
    let res = Resolution::build(&mdl, &idx, repo.root());
    assert!(res.findings.iter().all(|f| f.severity != Severity::Error), "{:?}", res.findings);
    let feature = res.node_index("feature").unwrap();
    let sites: Vec<_> = res.sites.iter().map(|s| (s.start_line, s.end_line, s.item)).collect();
    assert_eq!(sites, [(3, 6, Some(0)), (8, 9, Some(1))]);
    // The feature stands on whoever owns the lines it starts from.
    assert!(res.edges.contains_key(&(feature, res.node_index("core").unwrap())));

    repo.write("crates/core/src/lib.rs", &src.replace("let _ = 1;", "let _ = 2;"));
    let head = repo.commit("change serve");
    let table = TestTable::build(&res, false);
    let opts = plan::Options { by_seconds: None, max_notices: plan::assumptions::MAX_NOTICES, max_candidates: plan::assumptions::MAX_CANDIDATES };
    let p = plan::run(&res, &table, &mdl, repo.root(), &base, &head, &opts).expect("plan runs");
    assert_eq!(p.site_touches.len(), 1, "{}", p.render());
    assert_eq!(p.site_touches[0].changed_function.as_deref(), Some("serve"));
    assert!(p.render().contains("the changed function `serve` is an entry of node `feature`"), "{}", p.render());
}

#[test]
fn only_a_check_with_a_breaking_twin_covers_an_edge_and_the_three_counts_are_separate() {
    let repo = Repo::new(&[("a/a.rs", "fn a() {}\n"), ("b/b.rs", "fn b() {}\n"), ("c/c.rs", "fn c() {}\n"), ("d/d.rs", "fn d() {}\n")]);
    let nodes = [
        node("a", &path("a/**"), &[]),
        node("b", &path("b/**"), &["a"]),
        node("c", &path("c/**"), &[]),
        node("d", &path("d/**"), &["c"]),
    ];
    let twin = |on: &[&str], cell: &str, breaks: &str| {
        let on: Vec<String> = on.iter().map(|o| format!("\"{o}\"")).collect();
        format!(r#"{{"on":[{}],"coordinates":{{}},"inputs":[],"cell":"{cell}","control":"wrong","breaks":{breaks}}}"#, on.join(","))
    };
    // a<-b: a twin of the same cell breaks b. c<-d: the check lists both and breaks nothing.
    let checks = format!(
        r#""checks":{{"g":{{"checks":[{},{},{}]}}}},"policy":{{"uncovered":"fail","joins":[]}}"#,
        cell(&["b", "a"], "x", "", None, None),
        twin(&["b", "a"], "x", r#"{"node":"b"}"#),
        cell(&["d", "c"], "y", "", None, None),
    );
    let mdl = model(&nodes, &checks);
    let idx = source::git_only(repo.root()).unwrap();
    let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
    let table = TestTable::build(&res, false);
    let o = crate::coverage::run(&mdl, &res, &table, None, false);
    let s = &o.summary;
    assert_eq!((s.covered_by_tests, s.covered_by_breaking_twin, s.declared_only, s.uncovered), (0, 1, 1, 0), "{:?}", o.findings);
    let err = o.findings.iter().find(|f| f.severity == Severity::Error).expect("the declared-only edge fails under `fail`");
    assert!(err.message.contains("d (") && err.message.contains("shows nothing about the pair"), "{}", err.message);
    // An edge-breaking twin names the pair, in either order.
    let checks = format!(
        r#""checks":{{"g":{{"checks":[{},{}]}}}},"policy":{{"uncovered":"fail","joins":[]}}"#,
        cell(&["b", "a"], "x", "", None, None),
        twin(&["b", "a"], "x", r#"{"edge":["a","b"]}"#),
    );
    let mdl = model(&nodes[..2], &checks);
    let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
    let o = crate::coverage::run(&mdl, &res, &table, None, false);
    assert_eq!((o.summary.covered_by_breaking_twin, o.summary.declared_only), (1, 0), "{:?}", o.findings);
}

#[test]
fn an_entry_in_code_no_package_and_no_node_owns_adds_no_edge_and_does_not_panic() {
    // Found on the real backend: the engine's entry file lies in no cargo package and is unowned.
    for entry in [r#"{"by":"path","glob":"loose/a.rs"}"#, r#"{"by":"pattern","language":"rust","pattern":"fn serve() {}"}"#] {
        let repo = Repo::new(&[("loose/a.rs", "fn serve() {}\n")]);
        let mut feature = node("feature", "", &[]);
        feature = feature.replace(r#""entry":[]"#, &format!(r#""entry":[{entry}]"#));
        let mdl = model(&[feature], "");
        let mut idx = crate::fixtures::standard().index();
        idx.root = repo.root().to_path_buf();
        idx.files.push(keel_index::SourceFile {
            path: "loose/a.rs".to_owned(),
            package: None,
            target: keel_index::Target::Other,
            content: [0; 32],
            parse_error: None,
        });
        let res = Resolution::build(&mdl, &idx, repo.root());
        let f = res.node_index("feature").unwrap();
        assert!(res.edges.keys().all(|&(a, _)| a != f), "{:?}", res.edges.keys().collect::<Vec<_>>());
        // And the entry is called out, since it moves nothing.
        assert!(res.findings.iter().any(|x| x.code == "entry-moves-nothing"), "{:?}", res.findings);
    }
}

#[test]
fn boundaries_read_structure_from_cargo_metadata_and_syntax_from_ast_grep() {
    let repo = Repo::new(&[
        ("Cargo.toml", "[workspace]\nmembers = [\"app\", \"zlib-sys\"]\nresolver = \"2\"\n"),
        (
            "app/Cargo.toml",
            "[package]\nname = \"app\"\nversion = \"0.1.0\"\nedition = \"2021\"\nbuild = \"build.rs\"\n\n[dependencies]\nzlib-sys = { path = \"../zlib-sys\" }\n",
        ),
        ("app/build.rs", "fn main() {\n    cc::Build::new().file(\"native/x.c\").compile(\"x\");\n}\n"),
        ("app/native/x.c", "int x(void) { return 1; }\n"),
        (
            "app/src/lib.rs",
            "extern \"C\" { fn x() -> i32; }\npub fn run() { let _ = std::process::Command::new(\"ls\"); let _ = std::time::Instant::now(); }\n#[cfg(test)]\nmod tests { fn t() { let _ = std::time::Instant::now(); } }\n",
        ),
        ("zlib-sys/Cargo.toml", "[package]\nname = \"zlib-sys\"\nversion = \"0.1.0\"\nedition = \"2021\"\nlinks = \"z\"\n"),
        ("zlib-sys/build.rs", "fn main() {}\n"),
        ("zlib-sys/src/lib.rs", "#[link(name = \"z\")]\nextern \"C\" {}\n"),
    ]);
    let mdl = model(&[node("app", &path("app/**"), &[]), node("sys", &path("zlib-sys/**"), &[])], "");
    let idx = source::git_only(repo.root()).unwrap();
    let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
    let rep = crate::boundaries::run(&res, repo.root(), &crate::boundaries::Options { include_tests: false });
    let at = |class: &str| rep.sites.iter().filter(|s| s.class == class).map(|s| (s.path.as_str(), s.line, s.node.as_str())).collect::<Vec<_>>();
    assert_eq!(at("native-links-key"), [("zlib-sys/Cargo.toml", 5, "sys")], "{:?}", rep.notes);
    assert_eq!(at("native-sys-member"), [("zlib-sys/Cargo.toml", 1, "sys")]);
    assert_eq!(at("native-sys-dependency"), [("app/Cargo.toml", 8, "app")]);
    assert_eq!(at("native-build-script"), [("app/build.rs", 1, "app"), ("zlib-sys/build.rs", 1, "sys")]);
    assert_eq!(at("native-build-tool").len(), 1);
    assert_eq!(at("native-source"), [("app/native/x.c", 1, "app")]);
    assert_eq!(at("ffi-extern-block"), [("app/src/lib.rs", 1, "app"), ("zlib-sys/src/lib.rs", 2, "sys")]);
    assert_eq!(at("ffi-link-attr"), [("zlib-sys/src/lib.rs", 1, "sys")]);
    assert_eq!(at("process-spawn"), [("app/src/lib.rs", 2, "app")]);
    // The clock read in `#[cfg(test)]` is counted apart from the production one.
    assert_eq!(at("nondet-time"), [("app/src/lib.rs", 2, "app")]);
    assert_eq!(rep.test_sites_hidden, 1);
    let all = crate::boundaries::run(&res, repo.root(), &crate::boundaries::Options { include_tests: true });
    assert_eq!(all.sites.iter().filter(|s| s.class == "nondet-time").count(), 2);
    assert!(all.render().contains("LOWER BOUND"));
}

mod library_catch_up {
    use super::*;
    use crate::fixtures::standard;

    fn sel_node(id: &str, code: &str) -> String {
        node(id, code, &[])
    }

    #[test]
    fn within_is_its_outer_selector_narrowed_and_unsupported_when_the_outer_is_a_nix_output() {
        let repo = Repo::new(&[("crates/core/src/lib.rs", "pub fn c() {}\n"), ("tools/bin/run.sh", "echo\n"), ("crates/mid/src/lib.rs", "pub fn m() {}\n"), ("crates/top/src/lib.rs", "pub fn t() {}\n"), ("crates/tooling/src/lib.rs", "pub fn x() {}\n")]);
        let within_path = r#"{"by":"within","of":{"by":"path","glob":"tools/**"},"path":"bin/run.sh"}"#;
        let within_crate = r#"{"by":"within","of":{"by":"crate","name":"core"},"path":"src/lib.rs"}"#;
        let within_drv = r#"{"by":"within","of":{"by":"drv","attr":"pkgs.jdk"},"path":"bin/javac"}"#;
        let state = r#"{"by":"state","path":"owner.sock"}"#;
        let mdl = model(
            &[sel_node("a", within_path), sel_node("b", within_crate), sel_node("c", within_drv), sel_node("d", state)],
            "",
        );
        let mut idx = standard().index();
        idx.root = repo.root().to_path_buf();
        let res = Resolution::build(&mdl, &idx, repo.root());
        // The two that resolve own the file they narrow to (as selected by the outer selector).
        let owner = |p: &str| res.owner_of_tracked(p);
        assert_eq!(owner("crates/core/src/lib.rs"), Owner::Node(res.node_index("b").unwrap()));
        assert_eq!(owner("tools/bin/run.sh"), Owner::Node(res.node_index("a").unwrap()));
        let bad: Vec<_> = res.findings.iter().filter(|f| f.code == "unsupported-selector").collect();
        assert_eq!(bad.len(), 2, "{:?}", res.findings);
        assert!(bad.iter().any(|f| f.message.contains("names a Nix output")), "{bad:?}");
        assert!(bad.iter().any(|f| f.message.contains("world's own state")), "{bad:?}");
        // The lock lists a selector that is inside a Nix output among the unsupported ones.
        assert_eq!(res.nodes[res.node_index("c").unwrap()].unsupported.len(), 1);
    }

    #[test]
    fn a_world_input_naming_a_nix_output_is_said_not_failed() {
        let repo = Repo::new(&[("a/a.rs", "fn a() {}\n")]);
        let worlds = r#""worlds":[{"name":"w","from":null,"inputs":[{"by":"drv","attr":"pkgs.go"},{"by":"within","of":{"by":"drv","attr":"pkgs.jdk"},"path":"bin/javac"},{"by":"pattern","language":"rust","pattern":"fn ("}]}],
            "checks":{"g":{"checks":[{"on":["a"],"coordinates":{},"inputs":[],"cell":"x","world":"w"}]}}"#;
        let mdl = model(&[node("a", &path("a/**"), &[])], worlds);
        let idx = source::git_only(repo.root()).unwrap();
        let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
        let table = TestTable::build(&res, false);
        let rep = crate::check::run(&mdl, &res, &table, None, false).unwrap();
        let codes = |c: &str| rep.findings.iter().filter(|f| f.code == c).count();
        assert_eq!(codes("input-names-nix-output"), 2, "{:?}", rep.findings);
        assert!(rep.findings.iter().filter(|f| f.code == "input-names-nix-output").all(|f| f.severity == Severity::Info));
        // A pattern that is not code is its own error, by kind and not by wording.
        assert_eq!(codes("bad-pattern"), 1);
    }

    #[test]
    fn policy_faults_asks_for_a_fault_that_takes_the_lower_end_away() {
        let repo = Repo::new(&[("a/a.rs", "fn a() {}\n"), ("b/b.rs", "fn b() {}\n"), ("c/c.rs", "fn c() {}\n")]);
        let nodes = [node("a", &path("a/**"), &[]), node("b", &path("b/**"), &["a"]), node("c", &path("c/**"), &["a"])];
        let fault_cell = |breaks: &str| {
            format!(
                r#"{{"on":["b","a"],"coordinates":{{}},"inputs":[],"cell":"x","control":null,"faults":[{{"name":"stop-a"}}],"world":null,"breaks":{breaks}}}"#
            )
        };
        let run = |policy: &str, checks: &str| {
            let mdl = model(&nodes, &format!(r#""policy":{policy},"checks":{{"g":{{"checks":[{checks}]}}}}"#));
            let idx = source::git_only(repo.root()).unwrap();
            let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
            let table = TestTable::build(&res, false);
            crate::check::run(&mdl, &res, &table, None, false).unwrap()
        };
        let never = |rep: &crate::check::CheckReport| rep.findings.iter().filter(|f| f.code == "edge-never-faulted").map(|f| f.message.clone()).collect::<Vec<_>>();
        // Nothing takes `a` away: both edges are findings, errors under "fail".
        let rep = run(r#"{"faults":"fail","uncovered":"report"}"#, &fault_cell("null"));
        let n = never(&rep);
        assert_eq!(n.len(), 2, "{n:?}");
        assert!(n.iter().any(|m| m.starts_with("b stands on a; nothing has ever taken a away.")), "{n:?}");
        assert!(rep.findings.iter().filter(|f| f.code == "edge-never-faulted").all(|f| f.severity == Severity::Error));
        // Under "report" they are infos.
        let rep = run(r#"{"faults":"report","uncovered":"report"}"#, &fault_cell("null"));
        assert!(rep.findings.iter().filter(|f| f.code == "edge-never-faulted").all(|f| f.severity == Severity::Info));
        // A fault whose `breaks` names `a` covers both edges that stand on it.
        let rep = run(r#"{"faults":"fail","uncovered":"report"}"#, &fault_cell(r#"{"node":"a"}"#));
        assert!(never(&rep).is_empty(), "{:?}", never(&rep));
        assert_eq!((rep.summary.faults.faulted, rep.summary.faults.unfaulted), (2, 0));
        // An edge-breaking fault covers that edge only; an `unfaulted` entry excuses the other.
        let policy = r#"{"faults":"fail","uncovered":"report","unfaulted":[{"from":"c","to":"a","reason":"c is a fixture"}]}"#;
        let rep = run(policy, &fault_cell(r#"{"edge":["b","a"]}"#));
        assert!(never(&rep).is_empty(), "{:?}", never(&rep));
        assert_eq!((rep.summary.faults.faulted, rep.summary.faults.excused), (1, 1));
        // An excuse for an edge that does not exist is an error.
        let policy = r#"{"faults":"report","uncovered":"report","unfaulted":[{"from":"a","to":"b","reason":"backwards"}]}"#;
        let rep = run(policy, &fault_cell(r#"{"node":"a"}"#));
        let e = rep.findings.iter().find(|f| f.code == "unfaulted-names-no-edge").expect("an excuse for no edge");
        assert_eq!(e.severity, Severity::Error);
        assert!(e.message.contains("a does not stand on b"), "{}", e.message);
    }

    #[test]
    fn policy_inert_is_listed_with_its_reason_and_the_files_it_matches() {
        let repo = Repo::new(&[("a/a.rs", "fn a() {}\n"), ("docs/x.md", "x\n"), ("docs/y.md", "y\n"), ("docs/sub/z.md", "z\n")]);
        let policy = r#""policy":{"faults":"report","inert":[{"by":"path","glob":"docs/**","reason":"prose; nothing is built from it"}]}"#;
        let mdl = model(&[node("a", &path("a/**"), &[])], policy);
        let idx = source::git_only(repo.root()).unwrap();
        let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
        let table = TestTable::build(&res, false);
        let rep = crate::check::run(&mdl, &res, &table, None, false).unwrap();
        assert_eq!(rep.summary.inert.len(), 1);
        assert_eq!((rep.summary.inert[0].files, rep.summary.inert[0].reason.as_str()), (3, "prose; nothing is built from it"));
        assert!(rep.render().contains("docs/**  (3 tracked files)  prose; nothing is built from it"), "{}", rep.render());
    }

    #[test]
    fn what_is_read_and_not_enforced_is_listed_by_name_and_unread_keys_are_a_finding() {
        let repo = Repo::new(&[("a/a.rs", "fn a() {}\n")]);
        let worlds = r#""worlds":[{"name":"w","from":null,"step":["probe"],"keep":"run","machines":["m"],"env":{"LANG":"C","S":{"by":"state","path":"p.sock"}},"tools":[{"by":"drv","attr":"x"}],"network":true,"readyWithin":9,"frobnicate":1}],
            "checks":{"g":{"checks":[{"on":["a"],"coordinates":{},"inputs":[],"cell":"x","world":"w","together":"t","run":["probe"],"expect":{"ok":true}}]}}"#;
        let mdl = model(&[node("a", &path("a/**"), &[])], worlds);
        assert_eq!(mdl.unread, ["worlds[0].frobnicate"]);
        let idx = source::git_only(repo.root()).unwrap();
        let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
        let table = TestTable::build(&res, false);
        let rep = crate::check::run(&mdl, &res, &table, None, false).unwrap();
        let names: Vec<&str> = rep.summary.read_not_enforced.iter().map(|u| u.name.as_str()).collect();
        for want in ["world.env", "world.tools", "world.network", "world.machines", "world.readyWithin", "check.together", "check.run", "check.expect"] {
            assert!(names.contains(&want), "{want} missing from {names:?}");
        }
        assert!(rep.render().contains("read and not yet enforced"), "{}", rep.render());
        assert!(rep.findings.iter().any(|f| f.code == "model-field-unread" && f.message.contains("worlds[0].frobnicate")));
    }

    #[test]
    fn a_failing_git_is_an_error_naming_git_and_unreadable_files_are_counted() {
        // A directory that exists and is no repository.
        let dir = tempfile::tempdir().unwrap();
        let mut idx = standard().index();
        idx.root = dir.path().to_path_buf();
        let mdl = model(&[node("n", &path("crates/**"), &[])], "");
        let res = Resolution::build(&mdl, &idx, dir.path());
        let why = res.tracked_error().expect("git fails here");
        assert!(why.contains("git ls-files") && why.contains("not a git repository"), "{why}");
        let table = TestTable::build(&res, false);
        let rep = crate::check::run(&mdl, &res, &table, None, false).unwrap();
        assert!(rep.findings.iter().any(|f| f.code == "git-failed" && f.severity == Severity::Error), "{:?}", rep.findings);

        // A tracked Rust file that is gone from the disk is kept and counted.
        let repo = Repo::new(&[("a/a.rs", "fn a() {}\n"), ("a/gone.rs", "#[test] fn t() {}\n")]);
        std::fs::remove_file(repo.root().join("a/gone.rs")).unwrap();
        let idx = source::git_only(repo.root()).unwrap();
        let un = source::unreadable(&idx);
        assert_eq!(un.len(), 1);
        assert_eq!(un[0].0, "a/gone.rs");
        let mdl = model(&[node("a", &path("a/**"), &[])], "");
        let res = Resolution::build_with(&mdl, &idx, repo.root(), Some("test"));
        let table = TestTable::build(&res, false);
        let rep = crate::check::run(&mdl, &res, &table, None, false).unwrap();
        let w = rep.findings.iter().find(|f| f.code == "files-unreadable").expect("counted");
        assert!(w.message.contains("1 Rust files") && w.message.contains("a/gone.rs"), "{}", w.message);
    }

    #[test]
    fn a_non_member_package_has_files_in_a_package_and_its_tests_stay_out_of_the_table() {
        let repo = Repo::new(&[("crates/core/src/lib.rs", "pub fn c() {}\n#[test] fn mine() {}\n"), ("vendor/ext/src/lib.rs", "pub fn e() {}\n#[test] fn theirs() {}\n")]);
        let mut idx = crate::fixtures::Fixture {
            packages: vec![("core", "crates/core", vec![1], vec![]), ("ext", "vendor/ext", vec![], vec![])],
            files: vec![("crates/core/src/lib.rs", Some(0), keel_index::Target::Lib), ("vendor/ext/src/lib.rs", Some(1), keel_index::Target::Lib)],
            tests: vec![(0, "mine", false), (1, "theirs", false)],
        }
        .index();
        idx.root = repo.root().to_path_buf();
        idx.packages[1].member = false;
        let mdl = model(&[node("c", r#"{"by":"crate","name":"core"}"#, &[]), node("e", r#"{"by":"path","glob":"vendor/ext/**"}"#, &["c"])], "");
        let res = Resolution::build(&mdl, &idx, repo.root());
        // The vendored crate is a package: a node owns it by path, and its files are not "in no package".
        assert_eq!(res.owner_of_tracked("vendor/ext/src/lib.rs"), Owner::Node(res.node_index("e").unwrap()));
        let table = TestTable::build(&res, false);
        assert_eq!((table.len(), table.excluded_nonmember), (1, 1));
        // A change there affects what depends on it (core, which depends on ext), not every test.
        let change = keel_index::Change {
            files: vec![keel_index::FileChange {
                path: "vendor/ext/src/lib.rs".into(),
                status: keel_index::FileStatus::Modified,
                items: vec![],
                outside_items: true,
                position_only: false,
            }],
        };
        let eff = crate::plan::effects(&res, &table, &mdl, &change);
        assert!(!eff.global);
        assert_eq!(eff.files[0].package.as_deref(), Some("ext"));
        assert_eq!(eff.affected.len(), 1, "core's test depends on ext");
    }
}

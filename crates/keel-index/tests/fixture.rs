//! End-to-end on throwaway git repositories: build (packages, targets, test
//! ids, caching, persistence) and diff (every change kind).

use keel_index::{CodeIndex, FileStatus, ItemChangeKind, Target, diff};
use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.com",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .expect("git runs");
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

fn write(root: &Path, rel: &str, text: &str) {
    let p = root.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

fn init(root: &Path) {
    git(root, &["init", "-q", "-b", "main"]);
}

fn commit_all(root: &Path, msg: &str) -> String {
    git(root, &["add", "-A"]);
    git(root, &["commit", "-q", "-m", msg]);
    git(root, &["rev-parse", "HEAD"])
}

fn manifest(name: &str, deps: &str) -> String {
    format!("[package]\nname = \"{name}\"\nversion = \"0.1.0\"\nedition = \"2021\"\n{deps}")
}

/// core <- app (normal) ; testkit <- app (dev only) ; testkit -> core
fn workspace(root: &Path) {
    write(
        root,
        "Cargo.toml",
        "[workspace]\nresolver = \"2\"\nmembers = [\"app\", \"core\", \"testkit\"]\n",
    );
    write(root, "core/Cargo.toml", &manifest("core", ""));
    write(root, "core/src/lib.rs", "pub fn base() -> u32 { 1 }\n");
    write(
        root,
        "testkit/Cargo.toml",
        &manifest("testkit", "[dependencies]\ncore = { path = \"../core\" }\n"),
    );
    write(root, "testkit/src/lib.rs", "pub fn fixture() {}\n");
    write(
        root,
        "app/Cargo.toml",
        &manifest(
            "app",
            "[dependencies]\ncore = { path = \"../core\" }\n[dev-dependencies]\ntestkit = { path = \"../testkit\" }\n",
        ),
    );
    write(
        root,
        "app/src/lib.rs",
        "pub struct Ledger;\nimpl Ledger { pub fn open() {} }\nmod wal {\n    #[cfg(test)]\n    mod tests {\n        #[test]\n        fn replays_torn_tail() {}\n    }\n}\n#[cfg(test)]\nmod tests;\n",
    );
    write(
        root,
        "app/src/tests.rs",
        "#[test]\nfn from_out_of_line_module() {}\nmod nested { #[test] fn deeper() {} }\n",
    );
    write(
        root,
        "app/src/main.rs",
        "fn main() {}\n#[test] fn bin_unit() {}\n",
    );
    write(
        root,
        "app/tests/e2e.rs",
        "#[test]\nfn it_works() {}\nfn helper() {}\n",
    );
    write(root, "app/tests/common/mod.rs", "pub fn shared() {}\n");
    write(root, "app/benches/b.rs", "fn bench_thing() {}\n");
    write(root, "app/src/broken.rs", "fn broken( {\n");
    write(root, "stray/loose.rs", "pub fn loose() {}\n");
}

#[test]
fn build_resolves_packages_targets_tests_and_ids() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init(root);
    workspace(root);
    commit_all(root, "init");

    let idx = CodeIndex::build(root, None).unwrap();
    let names: Vec<&str> = idx.packages.iter().map(|p| p.name.as_str()).collect();
    assert_eq!(names, ["app", "core", "testkit"]);
    let (app, core, testkit) = (0u32, 1u32, 2u32);
    assert_eq!(idx.packages[0].deps, [core, testkit]);
    assert_eq!(idx.packages[0].dev_only_deps, [testkit]);
    assert_eq!(idx.packages[2].deps, [core]);
    assert!(idx.packages[2].dev_only_deps.is_empty());

    assert_eq!(
        idx.package_closure(app).iter().collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(
        idx.package_closure(testkit).iter().collect::<Vec<_>>(),
        [1, 2]
    );
    assert_eq!(
        idx.dependents_closure(core).iter().collect::<Vec<_>>(),
        [0, 1, 2]
    );
    assert_eq!(idx.dependents_closure(app).iter().collect::<Vec<_>>(), [0]);

    let file = |p: &str| {
        idx.files
            .iter()
            .find(|f| f.path == p)
            .unwrap_or_else(|| panic!("no file {p}"))
    };
    assert_eq!(file("app/src/lib.rs").target, Target::Lib);
    assert_eq!(file("app/src/lib.rs").package, Some(app));
    assert_eq!(file("app/src/main.rs").target, Target::Bin);
    assert_eq!(
        file("app/tests/e2e.rs").target,
        Target::IntegrationTest("e2e".into())
    );
    assert_eq!(file("app/benches/b.rs").target, Target::Bench);
    assert_eq!(file("app/src/tests.rs").target, Target::Lib);
    assert_eq!(file("stray/loose.rs").package, None);
    assert!(
        file("app/src/broken.rs").parse_error.is_some(),
        "a broken file is kept with its error"
    );
    assert!(file("app/src/lib.rs").parse_error.is_none());

    let mut ids: Vec<String> = idx.tests().map(|(n, _)| idx.test_id(n)).collect();
    ids.sort();
    assert_eq!(
        ids,
        [
            "app$tests::from_out_of_line_module",
            "app$tests::nested::deeper",
            "app$wal::tests::replays_torn_tail",
            "app::bin/app$bin_unit",
            "app::e2e$it_works",
        ]
    );

    let item = |path: &str| {
        idx.items
            .iter()
            .find(|i| i.path == path)
            .unwrap_or_else(|| panic!("no item {path}"))
    };
    assert!(
        item("wal::tests::replays_torn_tail").in_test_code,
        "inside an inline #[cfg(test)] module"
    );
    assert!(
        item("from_out_of_line_module").in_test_code,
        "file declared by #[cfg(test)] mod tests;"
    );
    assert!(item("nested::deeper").in_test_code);
    assert!(item("it_works").in_test_code, "integration test target");
    assert!(item("helper").in_test_code, "tests/ directory");
    assert!(
        item("shared").in_test_code,
        "tests/common/mod.rs is a tests/ file"
    );
    assert!(!item("Ledger::open").in_test_code);
    assert!(!item("bench_thing").in_test_code);
    assert!(!item("base").in_test_code);

    let mut sorted = idx.items.clone();
    sorted.sort_by_key(|i| (i.file, i.start_line));
    assert_eq!(
        sorted
            .iter()
            .map(|i| (i.file, i.start_line))
            .collect::<Vec<_>>(),
        idx.items
            .iter()
            .map(|i| (i.file, i.start_line))
            .collect::<Vec<_>>(),
        "items are sorted by (file, start_line)"
    );
}

#[test]
fn save_load_roundtrip_and_cache_reuse() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path().join("repo");
    std::fs::create_dir_all(&root).unwrap();
    init(&root);
    workspace(&root);
    commit_all(&root, "init");
    let cache = dir.path().join("cache");

    let cold = CodeIndex::build(&root, Some(&cache)).unwrap();
    let entries: Vec<_> = walk(&cache);
    assert!(!entries.is_empty(), "cold build populates the cache");
    assert!(
        entries
            .iter()
            .all(|p| p.extension().is_some_and(|e| e == "json")),
        "no temp files are left behind: {entries:?}"
    );
    let warm = CodeIndex::build(&root, Some(&cache)).unwrap();
    assert_eq!(
        serde_json::to_string(&cold).unwrap(),
        serde_json::to_string(&warm).unwrap(),
        "the cache returns what a scan would"
    );

    // A corrupt entry is rescanned, not trusted and not fatal.
    std::fs::write(&entries[0], b"{ not json").unwrap();
    let healed = CodeIndex::build(&root, Some(&cache)).unwrap();
    assert_eq!(healed.items.len(), cold.items.len());

    let saved = dir.path().join("index.json");
    cold.save(&saved).unwrap();
    let loaded = CodeIndex::load(&saved).unwrap();
    assert_eq!(
        serde_json::to_string(&cold).unwrap(),
        serde_json::to_string(&loaded).unwrap()
    );
    let missing = CodeIndex::load(&dir.path().join("nope.json"))
        .unwrap_err()
        .to_string();
    assert!(missing.contains("nope.json"), "{missing}");
}

fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap() {
        let p = e.unwrap().path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn build_outside_a_git_repository_explains_itself() {
    let dir = tempfile::tempdir().unwrap();
    let err = CodeIndex::build(dir.path(), None).unwrap_err().to_string();
    assert!(err.contains("git"), "{err}");
}

#[test]
fn diff_reports_every_kind_of_change() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init(root);
    write(
        root,
        "body.rs",
        "pub fn f(x: u32) -> u32 {\n    let a = x + 1;\n    let b = a * 2;\n    b\n}\npub fn untouched() {}\n",
    );
    write(root, "sig.rs", "pub fn g(x: u32) -> u32 { x }\n");
    write(root, "add.rs", "pub fn old() {}\n");
    write(
        root,
        "rm.rs",
        "pub fn keep() {}\n#[test]\nfn gone() { if true {} }\n",
    );
    write(root, "comment.rs", "/// doc\npub fn h() {\n    1;\n}\n");
    write(root, "use_line.rs", "use std::fmt;\npub fn k() {}\n");
    write(
        root,
        "renamed.rs",
        "pub fn r1() { let _ = 1; }\npub fn r2() { let _ = 2; }\npub fn r3() { let _ = 3; }\npub fn r4() { let _ = 4; }\n",
    );
    write(
        root,
        "renamed_edit.rs",
        "pub fn e1() { let _ = 1; }\npub fn e2() { let _ = 2; }\npub fn e3() { let _ = 3; }\npub fn e4() { let _ = 4; }\npub fn e5() { let _ = 5; }\n",
    );
    write(root, "deleted.rs", "pub fn d() {}\n");
    write(root, "README.md", "hello\n");
    write(
        root,
        "gated.rs",
        "#[cfg(unix)]\nfn twin() { 1; }\n#[cfg(windows)]\nfn twin() { 2; }\n",
    );
    write(root, "broken_after.rs", "pub fn fine() {}\n");
    let base = commit_all(root, "base");

    write(
        root,
        "body.rs",
        "pub fn f(x: u32) -> u32 {\n    let a = x + 2;\n    let b = a * 3;\n    b\n}\npub fn untouched() {}\n",
    );
    write(root, "sig.rs", "pub fn g(x: u64) -> u32 { x as u32 }\n");
    write(
        root,
        "add.rs",
        "pub fn old() {}\n#[test]\npub fn fresh() {\n    if true { }\n}\n",
    );
    write(root, "rm.rs", "pub fn keep() {}\n");
    write(
        root,
        "comment.rs",
        "/// a rewritten doc\n// and a comment\npub fn h() {\n\n    1; // trailing\n}\n",
    );
    write(root, "use_line.rs", "use std::io;\npub fn k() {}\n");
    git(root, &["mv", "renamed.rs", "moved.rs"]);
    git(root, &["mv", "renamed_edit.rs", "moved_edit.rs"]);
    write(
        root,
        "moved_edit.rs",
        "pub fn e1() { let _ = 1; }\npub fn e2() { let _ = 2; }\npub fn e3() { let _ = 33; }\npub fn e4() { let _ = 4; }\npub fn e5() { let _ = 5; }\n",
    );
    git(root, &["rm", "-q", "deleted.rs"]);
    write(root, "README.md", "hello world\n");
    write(
        root,
        "gated.rs",
        "#[cfg(unix)]\nfn twin() { 1; }\n#[cfg(windows)]\nfn twin() { 3; }\n",
    );
    write(root, "broken_after.rs", "pub fn fine( {\n");
    let head = commit_all(root, "change");

    let change = diff(root, &base, &head).unwrap();
    let f = |p: &str| {
        change
            .files
            .iter()
            .find(|f| f.path == p)
            .unwrap_or_else(|| {
                panic!(
                    "no change for {p}: {:?}",
                    change.files.iter().map(|f| &f.path).collect::<Vec<_>>()
                )
            })
    };

    let body = f("body.rs");
    assert_eq!(body.status, FileStatus::Modified);
    assert_eq!(body.items.len(), 1);
    assert_eq!(
        (body.items[0].path.as_str(), body.items[0].kind),
        ("f", ItemChangeKind::Body)
    );
    assert_eq!(
        body.items[0].lines_changed, 2,
        "two lines of f's body were edited"
    );
    assert!(!body.outside_items && !body.position_only);

    let sig = f("sig.rs");
    assert_eq!(
        sig.items[0].kind,
        ItemChangeKind::Signature,
        "signature wins over body"
    );

    let add = f("add.rs");
    assert_eq!(add.items.len(), 1);
    assert_eq!(
        (add.items[0].path.as_str(), add.items[0].kind),
        ("fresh", ItemChangeKind::Added)
    );
    assert!(add.items[0].is_test);
    assert_eq!(add.items[0].branches, 1);
    assert_eq!(add.items[0].lines_changed, 4);
    assert!(!add.outside_items);

    let rm = f("rm.rs");
    assert_eq!(
        (rm.items[0].path.as_str(), rm.items[0].kind),
        ("gone", ItemChangeKind::Removed)
    );
    assert!(rm.items[0].is_test);
    assert_eq!(rm.items[0].branches, 1);

    // The doc comment was reworded: the function's tokens changed (a doctest may differ).
    let comment = f("comment.rs");
    assert_eq!(comment.items.len(), 1, "{:?}", comment.items);
    assert_eq!((comment.items[0].path.as_str(), comment.items[0].kind), ("h", ItemChangeKind::Body));
    assert!(!comment.position_only);

    let use_line = f("use_line.rs");
    assert!(use_line.outside_items);
    assert!(use_line.items.is_empty());
    assert!(!use_line.position_only);

    let moved = f("moved.rs");
    assert_eq!(
        moved.status,
        FileStatus::Renamed {
            from: "renamed.rs".into()
        }
    );
    assert!(moved.items.is_empty());
    assert!(!moved.position_only, "a rename is a deletion and an addition, whatever its tokens");

    let moved_edit = f("moved_edit.rs");
    assert_eq!(
        moved_edit.status,
        FileStatus::Renamed {
            from: "renamed_edit.rs".into()
        }
    );
    assert_eq!(moved_edit.items.len(), 1);
    assert_eq!(
        (moved_edit.items[0].path.as_str(), moved_edit.items[0].kind),
        ("e3", ItemChangeKind::Body)
    );

    let deleted = f("deleted.rs");
    assert_eq!(deleted.status, FileStatus::Deleted);
    assert_eq!(
        (deleted.items[0].path.as_str(), deleted.items[0].kind),
        ("d", ItemChangeKind::Removed)
    );

    let readme = f("README.md");
    assert!(readme.items.is_empty() && readme.outside_items && !readme.position_only);

    let gated = f("gated.rs");
    assert_eq!(
        gated.items.len(),
        1,
        "the second `twin` is matched to the second `twin`: {:?}",
        gated.items
    );
    assert_eq!(gated.items[0].kind, ItemChangeKind::Body);

    let broken = f("broken_after.rs");
    assert!(
        broken.items.is_empty() && broken.outside_items && !broken.position_only,
        "a file that stops parsing makes no per-item claim"
    );
}

#[test]
fn diff_names_the_problem_for_an_unknown_revision() {
    let dir = tempfile::tempdir().unwrap();
    init(dir.path());
    write(dir.path(), "a.rs", "fn a() {}\n");
    commit_all(dir.path(), "init");
    let err = diff(dir.path(), "HEAD", "no-such-rev")
        .unwrap_err()
        .to_string();
    assert!(err.contains("no-such-rev"), "{err}");
}

fn cargo(dir: &Path, args: &[&str]) {
    // `cargo-stock` bypasses the caching shim `cargo` can be on CI hosts.
    for exe in ["cargo-stock", "cargo"] {
        match Command::new(exe).args(args).current_dir(dir).env("RUSTC_WRAPPER", "").output() {
            Ok(o) => {
                assert!(o.status.success(), "{exe} {args:?}: {}", String::from_utf8_lossy(&o.stderr));
                return;
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => panic!("{e}"),
        }
    }
    panic!("neither cargo-stock nor cargo is on PATH");
}

/// A crate reached by a `path` dependency is compiled into the product though it is no workspace
/// member: it is a package, it carries its files, and what depends on it has an edge to it.
#[test]
fn packages_outside_the_workspace_but_under_the_root_are_in_the_graph() {
    let dir = tempfile::tempdir().unwrap();
    let root = dir.path();
    init(root);
    write(root, "Cargo.toml", "[workspace]\nresolver = \"2\"\nmembers = [\"app\"]\nexclude = [\"vendor\"]\n");
    write(root, "app/Cargo.toml", &manifest("app", "[dependencies]\next = { path = \"../vendor/ext\" }\n"));
    write(root, "app/src/lib.rs", "pub fn a() {}\n");
    write(root, "vendor/ext/Cargo.toml", &manifest("ext", "[dependencies]\ndeep = { path = \"deep\" }\n"));
    write(root, "vendor/ext/src/lib.rs", "pub fn e() {}\n#[test] fn own() {}\n");
    write(root, "vendor/ext/deep/Cargo.toml", &manifest("deep", ""));
    write(root, "vendor/ext/deep/src/lib.rs", "pub fn d() {}\n");
    write(root, "elsewhere/loose.rs", "pub fn loose() {}\n");
    cargo(root, &["generate-lockfile", "--offline"]);
    commit_all(root, "init");

    let cache = tempfile::tempdir().unwrap();
    let idx = CodeIndex::build(root, Some(cache.path())).unwrap();
    assert!(idx.graph_note.is_none(), "{:?}", idx.graph_note);
    let by = |n: &str| idx.packages.iter().position(|p| p.name == n).unwrap_or_else(|| panic!("no package {n}"));
    let (app, ext, deep) = (by("app"), by("ext"), by("deep"));
    assert_eq!(
        idx.packages.iter().map(|p| (p.name.as_str(), p.member)).collect::<Vec<_>>(),
        [("app", true), ("ext", false), ("deep", false)]
    );
    assert_eq!(idx.packages[app].deps, [ext as u32]);
    assert_eq!(idx.packages[ext].deps, [deep as u32]);
    // What depends on ext includes app; ext's closure includes deep.
    assert!(idx.dependents_closure(ext as u32).contains(app as u32));
    assert!(idx.package_closure(app as u32).contains(deep as u32));
    let pkg_of = |p: &str| idx.files.iter().find(|f| f.path == p).map(|f| f.package);
    assert_eq!(pkg_of("vendor/ext/src/lib.rs"), Some(Some(ext as u32)));
    assert_eq!(pkg_of("vendor/ext/deep/src/lib.rs"), Some(Some(deep as u32)));
    assert_eq!(pkg_of("elsewhere/loose.rs"), Some(None));

    // The second build reads the cached graph and gets the same one.
    let again = CodeIndex::build(root, Some(cache.path())).unwrap();
    assert_eq!(again.packages.len(), 3);
    assert!(std::fs::read_dir(cache.path()).unwrap().any(|e| e.unwrap().file_name().to_string_lossy().starts_with("workspace-")));
}

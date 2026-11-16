//! Stage 0 against real git repositories. Every rule has a case that must be
//! accepted and, where the rule is an equivalence, a case it must refuse.

use std::path::{Path, PathBuf};
use std::process::Command;

use keel::Manifest;
use keel::store::{LocalStore, ResultStore, StoredRecord};
use serde_json::{Value, json};

use crate::plan::{Options, Outcome, Sources, plan};
use crate::store::Store;
use crate::util::TempDir;

const LIB: &str = "pub fn add(a: u32, b: u32) -> u32 {\n    // sum them\n    a + b\n}\n\n#[test]\nfn t() {\n    assert_eq!(add(1, 2), 3); // check\n}\n";
const LOCK: &str = "version = 3\n\n[[package]]\nname = \"store\"\nversion = \"0.1.0\"\ndependencies = [\n \"serde\",\n]\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaa\"\n";

const INITIAL: &[(&str, &str)] = &[
    ("Cargo.toml", "[workspace]\nmembers = [\"crates/store\"]\n"),
    ("Cargo.lock", LOCK),
    ("rust-toolchain.toml", "[toolchain]\nchannel = \"1.91\"\n"),
    (
        "crates/store/Cargo.toml",
        "[package]\nname = \"store\"\nversion = \"0.1.0\"\n",
    ),
    ("crates/store/src/lib.rs", LIB),
    ("crates/store/README.md", "store\n"),
    ("crates/store/fixtures/data.txt", "data\n"),
    ("docs/notes.md", "notes\n"),
    ("docs/old.md", "old\n"),
    ("shared/schema.json", "{}\n"),
];

fn git(dir: &Path, args: &[&str]) -> String {
    let out = Command::new("git")
        .arg("-C")
        .arg(dir)
        .args([
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@example.org",
            "-c",
            "commit.gpgsign=false",
            "-c",
            "core.autocrlf=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8_lossy(&out.stdout).trim().to_owned()
}

pub fn write(dir: &Path, rel: &str, text: &str) {
    let p = dir.join(rel);
    std::fs::create_dir_all(p.parent().unwrap()).unwrap();
    std::fs::write(p, text).unwrap();
}

struct Fx {
    dir: TempDir,
    base: String,
    head: String,
}

impl Fx {
    fn path(&self) -> PathBuf {
        self.dir.path().to_path_buf()
    }

    /// Initial commit (plus `extra` files), then `on_base` committed on `main`
    /// (the canonical tip), and `on_head` committed on a branch from the initial commit.
    fn build(extra: &[(&str, &str)], on_base: impl Fn(&Path), on_head: impl Fn(&Path)) -> Fx {
        let dir = TempDir::new("plan").unwrap();
        let d = dir.path();
        git(d, &["init", "-q", "-b", "main"]);
        for (p, t) in INITIAL.iter().chain(extra) {
            write(d, p, t);
        }
        git(d, &["add", "-A"]);
        git(d, &["commit", "-q", "-m", "initial"]);
        git(d, &["checkout", "-q", "-b", "pr"]);
        on_head(d);
        git(d, &["add", "-A"]);
        git(d, &["commit", "-q", "--allow-empty", "-m", "pr"]);
        let head = git(d, &["rev-parse", "HEAD"]);
        git(d, &["checkout", "-q", "main"]);
        // Untracked leftovers of the branch (a nested repository) must not leak into the tip.
        git(d, &["clean", "-q", "-ffdx"]);
        on_base(d);
        git(d, &["add", "-A"]);
        git(d, &["commit", "-q", "--allow-empty", "-m", "tip"]);
        let base = git(d, &["rev-parse", "HEAD"]);
        Fx { dir, base, head }
    }

    fn head_only(extra: &[(&str, &str)], on_head: impl Fn(&Path)) -> Fx {
        Fx::build(extra, |_| {}, on_head)
    }

    fn manifest(&self, nodes: Vec<Value>) -> Manifest {
        let fixture: Value =
            serde_json::from_str(include_str!("../../keel/tests/fixtures/manifest.json")).unwrap();
        serde_json::from_value(json!({
            "schema": 1, "producer": "t", "repo": "Nudox/Test", "revision": self.base,
            "platform": fixture["platform"], "nodes": nodes
        }))
        .unwrap()
    }

    fn sources(&self, sets: Value) -> Sources {
        serde_json::from_value(json!({
            "schema": 1, "revision": self.base, "source_sets": sets,
            "package_roots": ["crates/store"], "toolchain": ["Cargo.lock", "rust-toolchain.toml"]
        }))
        .unwrap()
    }

    fn run_with(&self, nodes: Vec<Value>, sets: Value, opts: &Options) -> Outcome {
        let m = self.manifest(nodes);
        let (_dir, store) = seeded(&m);
        plan(
            &self.path(),
            &self.base,
            &self.head,
            Ok(m),
            Ok(self.sources(sets)),
            opts,
            &store,
        )
        .unwrap()
    }

    fn run(&self) -> Outcome {
        self.run_with(
            vec![rust_node("rust:store::t", 1)],
            default_sets(),
            &Options::default(),
        )
    }
}

/// A store holding one pass, run `run-<id>`, for every node of `m`.
fn seeded(m: &Manifest) -> (TempDir, Store) {
    let dir = TempDir::new("plan-store").unwrap();
    let store = LocalStore::open(dir.path()).unwrap();
    for n in &m.nodes {
        store
            .put(&record(m, n, keel::Status::Pass, &format!("run-{}", n.id)))
            .unwrap();
    }
    (dir, Store::Local(store))
}

fn record(m: &Manifest, n: &keel::Node, status: keel::Status, run: &str) -> StoredRecord {
    StoredRecord {
        key: n.key,
        id: n.id.clone(),
        status,
        run_id: run.into(),
        recorded_at: "2026-11-14T08:12:03Z".into(),
        platform: m.platform.clone(),
        evidence: vec![],
    }
}

fn key(n: u8) -> String {
    format!("blake3:{}", format!("{n:02x}").repeat(32))
}

fn rust_node(id: &str, k: u8) -> Value {
    json!({"id": id, "kind": "rust-test", "group": "unit(store)", "key": key(k)})
}

fn default_sets() -> Value {
    json!({"rust:store::t": ["crates/store/src/lib.rs", "crates/store/Cargo.toml", "Cargo.lock"]})
}

fn reasons(o: Outcome) -> Vec<String> {
    match o {
        Outcome::Stage1(r) => r.iter().map(ToString::to_string).collect(),
        Outcome::Cached { .. } => panic!("expected Stage 1, got all cached"),
    }
}

fn accepted(o: Outcome) -> Vec<(String, &'static str)> {
    match o {
        Outcome::Cached { accepted, .. } => accepted,
        Outcome::Stage1(r) => panic!(
            "expected all cached, got {:?}",
            r.iter().map(ToString::to_string).collect::<Vec<_>>()
        ),
    }
}

fn one(o: Outcome, path: &str, rule: &str) -> String {
    let r = reasons(o);
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(r[0].starts_with(&format!("{path}: {rule}: ")), "{r:?}");
    r[0].clone()
}

#[test]
fn proved_harmless_changes_are_cached_from_the_stored_passes() {
    let fx = Fx::head_only(&[], lib_edit("sum them", "add them"));
    let o = fx.run_with(
        vec![rust_node("rust:store::t", 1), rust_node("rust:store::u", 2)],
        json!({"rust:store::t": ["crates/store/src/lib.rs"], "rust:store::u": []}),
        &Options::default(),
    );
    let Outcome::Cached { report, accepted } = o else {
        panic!("expected cached")
    };
    assert_eq!(accepted.len(), 1);
    assert_eq!(report.nodes.len(), 2);
    assert!(
        report
            .nodes
            .iter()
            .all(|n| n.status == keel::Status::Cached)
    );
    // cached_from is the run that executed the pass, not the manifest revision.
    assert_eq!(
        report.nodes[0].cached_from.as_deref(),
        Some("run-rust:store::t")
    );
    assert_eq!(
        report.nodes[1].cached_from.as_deref(),
        Some("run-rust:store::u")
    );
    assert_eq!(report.nodes[1].key.to_string(), key(2));
    assert_eq!(report.verdict, keel::Verdict::Pass);
    assert_eq!(report.counts.cached, 2);
    assert!(report.stages.is_some());
    assert_eq!(report.base.as_deref(), Some(fx.base.as_str()));
}

#[test]
fn the_diff_is_against_the_merge_result_not_the_head() {
    // The canonical tip moved on after the PR forked: the tip's own source
    // edit must not count against the PR, whose only change is a doc.
    let fx = Fx::build(
        &[],
        |d| {
            write(
                d,
                "crates/store/src/lib.rs",
                &format!("{LIB}// tip edit\npub fn extra() {{}}\n"),
            )
        },
        lib_edit("sum them", "add them"),
    );
    // Only the PR's own comment edit is judged; the tip's extra fn is not in the diff.
    assert_eq!(
        accepted(fx.run()),
        [("crates/store/src/lib.rs".to_owned(), "position-preserving")]
    );
}

#[test]
fn merge_conflicts_go_to_stage_one_and_name_the_file() {
    let fx = Fx::build(
        &[],
        |d| write(d, "docs/notes.md", "tip\n"),
        |d| write(d, "docs/notes.md", "pr\n"),
    );
    let msg = one(fx.run(), "docs/notes.md", "merge-conflict");
    assert!(msg.contains("does not merge"), "{msg}");
}

#[test]
fn a_manifest_for_another_revision_is_refused_with_both_revisions() {
    let fx = Fx::head_only(&[], lib_edit("sum them", "add them"));
    let mut m = fx.manifest(vec![rust_node("rust:store::t", 1)]);
    m.revision = fx.head.clone();
    let (_s, st) = seeded(&m);
    let o = plan(
        &fx.path(),
        &fx.base,
        &fx.head,
        Ok(m),
        Ok(fx.sources(default_sets())),
        &Options::default(),
        &st,
    )
    .unwrap();
    let msg = one(o, "(manifest)", "manifest-revision");
    assert!(
        msg.contains(&fx.head) && msg.contains(&fx.base) && msg.contains("run Stage 1"),
        "{msg}"
    );
    // An abbreviated or symbolic base that names the same commit is the same revision.
    let m = fx.manifest(vec![rust_node("rust:store::t", 1)]);
    let (_s, st) = seeded(&m);
    let o = plan(
        &fx.path(),
        "main",
        &fx.head,
        Ok(m),
        Ok(fx.sources(default_sets())),
        &Options::default(),
        &st,
    )
    .unwrap();
    assert_eq!(accepted(o).len(), 1);
}

#[test]
fn missing_manifest_or_source_sets_exit_to_stage_one() {
    let fx = Fx::head_only(&[], |d| write(d, "docs/notes.md", "x\n"));
    let (_s, st) = seeded(&fx.manifest(vec![rust_node("rust:store::t", 1)]));
    let o = plan(
        &fx.path(),
        &fx.base,
        &fx.head,
        Err("no manifest for abc".into()),
        Err("unused".into()),
        &Options::default(),
        &st,
    )
    .unwrap();
    one(o, "(manifest)", "no-manifest");
    let o = plan(
        &fx.path(),
        &fx.base,
        &fx.head,
        Ok(fx.manifest(vec![rust_node("rust:store::t", 1)])),
        Err("cannot read the sources sidecar".into()),
        &Options::default(),
        &st,
    )
    .unwrap();
    let msg = one(o, "(sources)", "no-source-sets");
    assert!(msg.contains("fork"), "{msg}");
    // A node with no entry cannot be proven unaffected.
    let o = fx.run_with(
        vec![
            rust_node("rust:store::t", 1),
            rust_node("rust:store::new", 2),
        ],
        default_sets(),
        &Options::default(),
    );
    assert!(one(o, "(sources)", "sources-inconsistent").contains("rust:store::new"));
    // A sidecar from another revision.
    let mut s = fx.sources(default_sets());
    s.revision = "0".repeat(40);
    let o = plan(
        &fx.path(),
        &fx.base,
        &fx.head,
        Ok(fx.manifest(vec![rust_node("rust:store::t", 1)])),
        Ok(s),
        &Options::default(),
        &st,
    )
    .unwrap();
    one(o, "(sources)", "sources-revision");
}

#[test]
fn a_modified_source_file_is_stage_one() {
    let fx = Fx::head_only(&[], |d| {
        write(
            d,
            "crates/store/src/lib.rs",
            &LIB.replace("a + b", "a + b + 0"),
        )
    });
    let msg = one(fx.run(), "crates/store/src/lib.rs", "source-modified");
    assert!(
        msg.contains("source set of 1 node") && msg.contains("rust:store::t"),
        "{msg}"
    );
}

#[test]
fn adds_deletes_and_renames_under_a_package_root_are_stage_one() {
    let added = Fx::head_only(&[], |d| write(d, "crates/store/build.rs", "fn main() {}\n"));
    one(added.run(), "crates/store/build.rs", "path-set-changed");
    let deleted = Fx::head_only(&[], |d| {
        std::fs::remove_file(d.join("crates/store/README.md")).unwrap()
    });
    assert!(one(deleted.run(), "crates/store/README.md", "path-set-changed").contains("deleted"));
    let renamed = Fx::head_only(&[], |d| {
        std::fs::rename(
            d.join("crates/store/README.md"),
            d.join("crates/store/README2.md"),
        )
        .unwrap()
    });
    let r = reasons(renamed.run());
    assert_eq!(r.len(), 2, "a rename is a delete and an add: {r:?}");
    // Outside any root the same moves are still objections: nothing owns the files.
    let outside = Fx::head_only(&[], |d| {
        std::fs::rename(d.join("docs/old.md"), d.join("docs/older.md")).unwrap()
    });
    let r = reasons(outside.run());
    assert!(
        r.len() == 2 && r.iter().all(|m| m.contains(": unowned-change: ")),
        "{r:?}"
    );
}

#[test]
fn a_mode_change_is_stage_one_under_a_root_and_unowned_outside() {
    let chmod = |p: &'static str| {
        move |d: &Path| {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(d.join(p), std::fs::Permissions::from_mode(0o755)).unwrap();
        }
    };
    let fx = Fx::head_only(&[], chmod("crates/store/README.md"));
    assert!(one(fx.run(), "crates/store/README.md", "mode-changed").contains("100644 to 100755"));
    one(
        Fx::head_only(&[], chmod("docs/notes.md")).run(),
        "docs/notes.md",
        "unowned-change",
    );
}

#[test]
fn toolchain_files_are_stage_one_wherever_they_are() {
    let fx = Fx::head_only(&[], |d| {
        write(
            d,
            "rust-toolchain.toml",
            "[toolchain]\nchannel = \"1.92\"\n",
        )
    });
    one(fx.run(), "rust-toolchain.toml", "source-modified");
    // Not in the sidecar's toolchain list, but cargo reads it: a new cargo config anywhere.
    let fx = Fx::head_only(&[], |d| {
        write(d, ".cargo/config.toml", "[build]\nrustflags = []\n")
    });
    one(fx.run(), ".cargo/config.toml", "path-set-changed");
    let fx = Fx::head_only(&[], |d| {
        write(d, "tools/other/Cargo.toml", "[package]\nname = \"o\"\n")
    });
    one(fx.run(), "tools/other/Cargo.toml", "path-set-changed");
}

#[test]
fn declared_globs_catch_modifications_and_additions_outside_package_roots() {
    let glob_node = json!({"id": "rust:store::t", "kind": "rust-test", "group": "unit(store)", "key": key(1), "inputs": {"files": ["shared/*.json"]}});
    let modified = Fx::head_only(&[], |d| write(d, "shared/schema.json", "{\"a\":1}\n"));
    one(
        modified.run_with(
            vec![glob_node.clone()],
            json!({"rust:store::t": []}),
            &Options::default(),
        ),
        "shared/schema.json",
        "declared-input",
    );
    let added = Fx::head_only(&[], |d| write(d, "shared/extra.json", "{}\n"));
    one(
        added.run_with(
            vec![glob_node.clone()],
            json!({"rust:store::t": []}),
            &Options::default(),
        ),
        "shared/extra.json",
        "path-set-changed",
    );
    // Without the glob the same edit is owned by nothing, which is an objection too.
    one(
        modified.run_with(
            vec![rust_node("rust:store::t", 1)],
            json!({"rust:store::t": []}),
            &Options::default(),
        ),
        "shared/schema.json",
        "unowned-change",
    );
}

#[test]
fn submodules_symlinks_attributes_and_lfs_are_stage_one() {
    let sub = Fx::head_only(&[], |d| {
        // A nested repository is staged by `git add -A` as a gitlink.
        let dep = d.join("vendor/dep");
        std::fs::create_dir_all(&dep).unwrap();
        git(&dep, &["init", "-q"]);
        git(&dep, &["commit", "-q", "--allow-empty", "-m", "dep"]);
    });
    one(sub.run(), "vendor/dep", "submodule");
    let link = Fx::head_only(&[], |d| {
        std::os::unix::fs::symlink("notes.md", d.join("docs/link.md")).unwrap()
    });
    one(link.run(), "docs/link.md", "symlink");
    for name in ["docs/.gitattributes", ".gitmodules"] {
        let fx = Fx::head_only(&[], |d| write(d, name, "* text=auto\n"));
        one(fx.run(), name, "git-config-file");
    }
    let pointer = |n: u8| {
        format!(
            "version https://git-lfs.github.com/spec/v1\noid sha256:{}\nsize {n}\n",
            "ab".repeat(32)
        )
    };
    let lfs = Fx::build(
        &[("docs/model.bin", &pointer(1))],
        |_| {},
        |d| write(d, "docs/model.bin", &pointer(2)),
    );
    one(lfs.run(), "docs/model.bin", "lfs-pointer");
}

#[test]
fn a_file_behind_a_symlink_is_stage_one_even_though_nothing_reads_it_by_name() {
    // fixtures/data.txt is in no source set; docs/data-link.txt points at it.
    let fx = Fx::build(
        &[],
        |_| {},
        |d| write(d, "crates/store/fixtures/data.txt", "other\n"),
    );
    one(fx.run(), "crates/store/fixtures/data.txt", "unowned-change");
    let dir = TempDir::new("sym").unwrap();
    let d = dir.path();
    git(d, &["init", "-q", "-b", "main"]);
    for (p, t) in INITIAL {
        write(d, p, t);
    }
    std::os::unix::fs::symlink(
        "../crates/store/fixtures/data.txt",
        d.join("docs/data-link.txt"),
    )
    .unwrap();
    git(d, &["add", "-A"]);
    git(d, &["commit", "-q", "-m", "initial"]);
    git(d, &["checkout", "-q", "-b", "pr"]);
    write(d, "crates/store/fixtures/data.txt", "other\n");
    git(d, &["commit", "-q", "-a", "-m", "pr"]);
    let head = git(d, &["rev-parse", "HEAD"]);
    git(d, &["checkout", "-q", "main"]);
    let base = git(d, &["rev-parse", "HEAD"]);
    let fx2 = Fx { dir, base, head };
    let r = reasons(fx2.run());
    assert!(
        r.iter()
            .any(|m| m.starts_with("crates/store/fixtures/data.txt: symlink-target: ")),
        "{r:?}"
    );
}

#[test]
fn network_nodes_never_cache() {
    let fx = Fx::head_only(&[], |d| write(d, "docs/notes.md", "x\n"));
    let mut n = rust_node("rust:store::net", 3);
    n["policy"] = json!({"network": true});
    let o = fx.run_with(vec![n], json!({"rust:store::net": []}), &Options::default());
    assert!(one(o, "(manifest)", "network-node").contains("never caches"));
}

// ---- position-preserving rule through the whole planner ----

fn lib_edit(from: &'static str, to: &'static str) -> impl Fn(&Path) {
    move |d| write(d, "crates/store/src/lib.rs", &LIB.replace(from, to))
}

#[test]
fn rs_comment_edited_in_place_whitespace_and_crlf_are_junk() {
    for (name, edit) in [
        ("comment text", LIB.replace("sum them", "add them")),
        ("trailing spaces", LIB.replace("a + b\n", "a + b   \n")),
        ("crlf", LIB.replace('\n', "\r\n")),
    ] {
        let fx = Fx::head_only(&[], |d| write(d, "crates/store/src/lib.rs", &edit));
        assert_eq!(
            accepted(fx.run()),
            [("crates/store/src/lib.rs".to_owned(), "position-preserving")],
            "{name}"
        );
    }
}

#[test]
fn rs_adversarial_edits_are_refused() {
    let inserted = Fx::head_only(
        &[],
        lib_edit("    // sum them\n", "    // sum them\n    // and more\n"),
    );
    assert!(
        one(inserted.run(), "crates/store/src/lib.rs", "source-modified").contains("moved from")
    );
    let reflowed = Fx::head_only(
        &[],
        lib_edit("add(a: u32, b: u32)", "add(a: u32,\n b: u32)"),
    );
    assert!(
        one(reflowed.run(), "crates/store/src/lib.rs", "source-modified").contains("moved from")
    );
    let literal = Fx::build(
        &[("crates/store/src/s.rs", "const S: &str = \"one\";\n")],
        |_| {},
        |d| write(d, "crates/store/src/s.rs", "const S: &str = \"two\";\n"),
    );
    let sets = json!({"rust:store::t": ["crates/store/src/s.rs"]});
    let msg = one(
        literal.run_with(
            vec![rust_node("rust:store::t", 1)],
            sets,
            &Options::default(),
        ),
        "crates/store/src/s.rs",
        "source-modified",
    );
    assert!(
        msg.contains("`\"one\"`") && msg.contains("`\"two\"`"),
        "{msg}"
    );
    let doc = Fx::build(
        &[("crates/store/src/d.rs", "/// Doc text.\npub fn f() {}\n")],
        |_| {},
        |d| write(d, "crates/store/src/d.rs", "/// Doc test.\npub fn f() {}\n"),
    );
    let sets = json!({"rust:store::t": ["crates/store/src/d.rs"]});
    one(
        doc.run_with(
            vec![rust_node("rust:store::t", 1)],
            sets,
            &Options::default(),
        ),
        "crates/store/src/d.rs",
        "source-modified",
    );
}

#[test]
fn rs_included_as_data_is_refused_even_for_a_comment_edit() {
    let golden = (
        "crates/store/tests/golden.rs",
        "const SRC: &str = include_str!(\"../src/lib.rs\");\n",
    );
    let fx = Fx::build(&[golden], |_| {}, lib_edit("sum them", "add them"));
    let msg = one(fx.run(), "crates/store/src/lib.rs", "source-modified");
    assert!(msg.contains("include_str!"), "{msg}");
}

// ---- lockfile rule through the planner ----

#[test]
fn lockfile_reorder_is_junk_and_resolution_changes_are_not() {
    let reordered = "version = 4\n\n[[package]]\nname = \"serde\"\nversion = \"1.0.200\"\nsource = \"registry+https://github.com/rust-lang/crates.io-index\"\nchecksum = \"aaaa\"\n\n[[package]]\nname = \"store\"\nversion = \"0.1.0\"\ndependencies = [\"serde\"]\n";
    let fx = Fx::head_only(&[], |d| write(d, "Cargo.lock", reordered));
    assert_eq!(
        accepted(fx.run()),
        [("Cargo.lock".to_owned(), "lockfile-resolves-identically")]
    );
    for (name, new, needle) in [
        (
            "version bump",
            LOCK.replace("1.0.200", "1.0.201"),
            "changed version",
        ),
        ("checksum", LOCK.replace("aaaa", "bbbb"), "checksum"),
        (
            "new package",
            format!("{LOCK}\n[[package]]\nname = \"extra\"\nversion = \"0.0.1\"\n"),
            "is new",
        ),
    ] {
        let fx = Fx::head_only(&[], |d| write(d, "Cargo.lock", &new));
        let msg = one(fx.run(), "Cargo.lock", "source-modified");
        assert!(msg.contains(needle), "{name}: {msg}");
    }
}

// ---- Nix and Nickel ----

fn nix_available() -> bool {
    let ok = Command::new("nix")
        .arg("--version")
        .output()
        .is_ok_and(|o| o.status.success());
    if !ok {
        eprintln!(
            "SKIPPED: `nix` is not on PATH, so the Nix derivation rule is not exercised here"
        );
    }
    ok
}

const FLAKE: &str = "# the tiny flake\n{\n  outputs = _: {\n    packages.x86_64-linux.default = derivation {\n      name = \"tiny\";\n      system = \"x86_64-linux\";\n      builder = \"/bin/sh\";\n      args = [ \"-c\" \"echo hi > $out\" ];\n    };\n  };\n}\n";
const INST: &str = ".#packages.x86_64-linux.default";

fn nix_node(drv: &str) -> Value {
    json!({"id": "nix:scenario:tiny", "kind": "nix-check", "group": "scenario(tiny)", "key": key(7), "inputs": {"drv": drv}})
}

fn base_drv(fx: &Fx) -> String {
    let git = crate::git::Git::new(&fx.path());
    crate::nixrule::compare_nix(&git, &fx.base, &fx.base, &[INST.to_owned()])
        .unwrap()
        .base_drvs
        .remove(0)
}

#[test]
fn nix_edit_with_an_unchanged_derivation_is_junk_and_a_changed_one_is_not() {
    if !nix_available() {
        return;
    }
    let opts = Options {
        nix_checks: vec![INST.to_owned()],
        nickel: None,
    };
    let sets = json!({"nix:scenario:tiny": ["flake.nix"]});
    let comment = Fx::build(
        &[("flake.nix", FLAKE)],
        |_| {},
        |d| {
            write(
                d,
                "flake.nix",
                &FLAKE.replace("the tiny flake", "the tiny flake, reworded and longer"),
            )
        },
    );
    let drv = base_drv(&comment);
    assert_eq!(
        accepted(comment.run_with(vec![nix_node(&drv)], sets.clone(), &opts)),
        [("flake.nix".to_owned(), "nix-derivation-unchanged")]
    );

    let renamed = Fx::build(
        &[("flake.nix", FLAKE)],
        |_| {},
        |d| {
            write(
                d,
                "flake.nix",
                &FLAKE.replace("name = \"tiny\"", "name = \"tinier\""),
            )
        },
    );
    let msg = one(
        renamed.run_with(vec![nix_node(&drv)], sets.clone(), &opts),
        "flake.nix",
        "source-modified",
    );
    assert!(
        msg.contains("evaluates to") && msg.contains("tinier"),
        "{msg}"
    );

    // Without --nix-check the rule does not apply and the edit falls through.
    let msg = one(
        comment.run_with(vec![nix_node(&drv)], sets.clone(), &Options::default()),
        "flake.nix",
        "source-modified",
    );
    assert!(!msg.contains("nix rule"), "{msg}");

    // A Rust node that reads flake.nix as data is not described by a derivation path.
    let both = vec![nix_node(&drv), rust_node("rust:store::t", 1)];
    let both_sets = json!({"nix:scenario:tiny": ["flake.nix"], "rust:store::t": ["flake.nix"]});
    let msg = one(
        comment.run_with(both, both_sets, &opts),
        "flake.nix",
        "source-modified",
    );
    assert!(msg.contains("reads this file as data"), "{msg}");

    // A Nix node whose derivation the installables do not account for.
    let msg = one(
        comment.run_with(
            vec![nix_node(
                "/nix/store/aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa-other.drv",
            )],
            sets,
            &opts,
        ),
        "flake.nix",
        "source-modified",
    );
    assert!(
        msg.contains("not one of the --nix-check installables"),
        "{msg}"
    );
}

#[test]
fn nickel_edit_is_junk_only_if_regeneration_reproduces_the_committed_lockfile() {
    let files: &[(&str, &str)] = &[
        ("fleet.ncl", "# fleet\n{}\n"),
        ("fleet.src.json", "{\"a\":1}\n"),
        ("fleet.lock.json", "{\"a\":1}\n"),
    ];
    let node = json!({"id": "nix:scenario:fleet", "kind": "nix-check", "group": "scenario(fleet)", "key": key(8)});
    let sets = json!({"nix:scenario:fleet": ["fleet.ncl"]});
    // `cp` stands in for `nickel export`: the lock is regenerated from fleet.src.json.
    let opts = Options {
        nix_checks: vec![],
        nickel: Some((
            "fleet.lock.json".into(),
            "cp fleet.src.json fleet.lock.json".into(),
        )),
    };

    let same = Fx::build(
        files,
        |_| {},
        |d| write(d, "fleet.ncl", "# fleet, commented\n{}\n"),
    );
    assert_eq!(
        accepted(same.run_with(vec![node.clone()], sets.clone(), &opts)),
        [("fleet.ncl".to_owned(), "nickel-lock-unchanged")]
    );

    let moved = Fx::build(
        files,
        |_| {},
        |d| {
            write(d, "fleet.ncl", "# fleet\n{ a = 2 }\n");
            write(d, "fleet.src.json", "{\"a\":2}\n");
        },
    );
    // The regenerated source (fleet.src.json) is itself unowned here, so there are two objections.
    let r = reasons(moved.run_with(vec![node.clone()], sets.clone(), &opts));
    assert!(
        r.iter()
            .any(|m| m.starts_with("fleet.ncl: source-modified: ")
                && m.contains("differs from the committed base")),
        "{r:?}"
    );

    let broken = Options {
        nix_checks: vec![],
        nickel: Some((
            "fleet.lock.json".into(),
            "cp missing.json fleet.lock.json".into(),
        )),
    };
    assert!(
        one(
            same.run_with(vec![node.clone()], sets.clone(), &broken),
            "fleet.ncl",
            "source-modified"
        )
        .contains("failed")
    );

    // Not configured: the rule does not apply.
    let msg = one(
        same.run_with(vec![node], sets, &Options::default()),
        "fleet.ncl",
        "source-modified",
    );
    assert!(!msg.contains("nickel rule"), "{msg}");
}

// ---- findings 1(a) and 1(b): nothing is cached by default ----

#[test]
fn a_changed_file_nothing_owns_is_an_objection_that_names_it() {
    // docs/notes.md is in no source set, no toolchain list and no glob. The
    // sidecar may be incomplete, so "nothing owns it" is not "nothing reads it".
    let fx = Fx::head_only(&[], |d| write(d, "docs/notes.md", "changed\n"));
    let msg = one(fx.run(), "docs/notes.md", "unowned-change");
    assert!(
        msg.contains("no source set") && msg.contains("Stage 1"),
        "{msg}"
    );
    // Adds and deletes of unowned files outside every root are no different.
    let fx = Fx::head_only(&[], |d| write(d, "docs/new.md", "new\n"));
    one(fx.run(), "docs/new.md", "unowned-change");
    let fx = Fx::head_only(&[], |d| {
        std::fs::remove_file(d.join("docs/old.md")).unwrap()
    });
    one(fx.run(), "docs/old.md", "unowned-change");
}

#[test]
fn cached_is_only_ever_built_from_a_pass_the_store_returned_for_that_key() {
    // Even an empty diff proves only that the keys did not change, not that
    // anything ever passed under them.
    let fx = Fx::head_only(&[], |_| {});
    let nodes = vec![rust_node("rust:store::t", 1), rust_node("rust:store::u", 2)];
    let m = fx.manifest(nodes.clone());
    let run = |store: &Store| {
        plan(
            &fx.path(),
            &fx.base,
            &fx.head,
            Ok(fx.manifest(nodes.clone())),
            Ok(fx.sources(json!({"rust:store::t": [], "rust:store::u": []}))),
            &Options::default(),
            store,
        )
        .unwrap()
    };

    let empty_dir = TempDir::new("plan-empty").unwrap();
    let empty = Store::Local(LocalStore::open(empty_dir.path()).unwrap());
    let r = reasons(run(&empty));
    assert_eq!(r.len(), 2, "{r:?}");
    assert!(
        r[0].starts_with("(store): no-stored-pass: ")
            && r[0].contains("rust:store::t")
            && r[0].contains(&key(1)),
        "{r:?}"
    );

    // One pass present is not enough; the node without one is named.
    let dir = TempDir::new("plan-half").unwrap();
    let ls = LocalStore::open(dir.path()).unwrap();
    ls.put(&record(&m, &m.nodes[0], keel::Status::Pass, "r1"))
        .unwrap();
    let half = Store::Local(ls.clone());
    let r = reasons(run(&half));
    assert_eq!(r.len(), 1, "{r:?}");
    assert!(r[0].contains("rust:store::u"), "{r:?}");

    // A pass the same key has since been disputed by is not a pass.
    ls.put(&record(&m, &m.nodes[1], keel::Status::Pass, "r2"))
        .unwrap();
    assert_eq!(accepted(run(&Store::Local(ls.clone()))), []);
    ls.put(&record(&m, &m.nodes[1], keel::Status::Fail, "r3"))
        .unwrap();
    let r = reasons(run(&Store::Local(ls)));
    assert!(
        r.len() == 1
            && r[0].contains("rust:store::u")
            && r[0].contains("failing, flaky or timed-out"),
        "{r:?}"
    );
}

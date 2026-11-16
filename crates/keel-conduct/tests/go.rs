//! The Go source against a fixture module and, when configured, a real module.

mod common;

use common::*;
use keel::{Status, Upstream};
use keel_conduct::config::Config;
use keel_conduct::run::plan_all;

const MOD: &str = "example.test/m";

fn fixture() -> Tmp {
    let t = Tmp::new("go");
    t.write("go.mod", "module example.test/m\n\ngo 1.21\n");
    t.write(
        "base/base.go",
        "package base\n\nfunc Double(x int) int { return 2 * x }\n",
    );
    t.write(
        "base/base_test.go",
        "package base\n\nimport \"testing\"\n\nfunc TestDouble(t *testing.T) {\n\tif Double(2) != 4 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n",
    );
    t.write(
        "app/app.go",
        "package app\n\nimport \"example.test/m/base\"\n\nfunc Quad(x int) int { return base.Double(base.Double(x)) }\n",
    );
    t.write(
        "app/app_test.go",
        "package app\n\nimport \"testing\"\n\nfunc TestQuad(t *testing.T) {\n\tif Quad(1) != 5 { // deliberately wrong\n\t\tt.Fatalf(\"Quad(1) = %d, want 5\", Quad(1))\n\t}\n}\n",
    );
    t.write("keel.toml", "[go]\n");
    t
}

fn key_of(t: &Tmp, go: &std::path::Path, id: &str) -> keel::Digest {
    let cfg = Config::load(&t.path().join("keel.toml")).unwrap();
    let planned = plan_all(&cfg, t.path(), Some(go)).unwrap();
    planned
        .iter()
        .find(|p| p.node.id.as_str() == id)
        .unwrap()
        .node
        .key
}

#[test]
fn plan_run_cache_and_invalidate() {
    let Some(go) = go_binary() else { return };
    let t = fixture();
    let store = Tmp::new("go-store");
    let (base, app) = (format!("go:{MOD}/base"), format!("go:{MOD}/app"));

    let cfg = Config::load(&t.path().join("keel.toml")).unwrap();
    let planned = plan_all(&cfg, t.path(), Some(&go)).unwrap();
    assert_eq!(planned.len(), 2);
    let a = planned.iter().find(|p| p.node.id.as_str() == app).unwrap();
    assert_eq!(a.node.stands_on, vec![Upstream::Node(base.as_str().into())]);
    assert_eq!(a.node.group.to_string(), format!("unit(go:{MOD}/app)"));

    // First run: base passes, app fails with the test's own message.
    let r1 = conduct(t.path(), store.path(), Some(&go));
    assert_eq!(status(&r1, &base), Status::Pass);
    assert_eq!(status(&r1, &app), Status::Fail);
    let detail = rec(&r1, &app).detail.as_ref().unwrap();
    assert!(
        detail
            .actual
            .as_ref()
            .unwrap()
            .contains("Quad(1) = 4, want 5"),
        "{detail:?}"
    );
    assert_eq!(r1.roots, vec![app.as_str().into()]);

    // Second run: the pass is reused, the failure is not.
    let r2 = conduct(t.path(), store.path(), Some(&go));
    assert_eq!(status(&r2, &base), Status::Cached);
    assert_eq!(status(&r2, &app), Status::Fail);

    // Editing app's test changes app's key and leaves base's alone.
    let (kb, ka) = (key_of(&t, &go, &base), key_of(&t, &go, &app));
    t.write("app/app_test.go", "package app\n\nimport \"testing\"\n\nfunc TestQuad(t *testing.T) {\n\tif Quad(1) != 4 {\n\t\tt.Fatal(\"bad\")\n\t}\n}\n");
    assert_eq!(key_of(&t, &go, &base), kb);
    assert_ne!(key_of(&t, &go, &app), ka);
    let r3 = conduct(t.path(), store.path(), Some(&go));
    assert_eq!(status(&r3, &base), Status::Cached);
    assert_eq!(status(&r3, &app), Status::Pass);

    // Editing base's source changes both keys: app compiles it in.
    t.write(
        "base/base.go",
        "package base\n\nfunc Double(x int) int { return x + x }\n",
    );
    assert_ne!(key_of(&t, &go, &base), kb);
    assert_ne!(key_of(&t, &go, &app), ka);
    let r4 = conduct(t.path(), store.path(), Some(&go));
    assert_eq!(status(&r4, &base), Status::Pass);
    assert_eq!(status(&r4, &app), Status::Pass);
}

#[test]
fn a_failing_foundation_blocks_what_stands_on_it() {
    let Some(go) = go_binary() else { return };
    let t = fixture();
    t.write(
        "base/base.go",
        "package base\n\nfunc Double(x int) int { return 3 * x }\n",
    );
    let r = conduct(t.path(), Tmp::new("go-store2").path(), Some(&go));
    let app = rec(&r, &format!("go:{MOD}/app"));
    assert_eq!(app.status, Status::Blocked);
    assert_eq!(
        app.blocked_by,
        vec![format!("go:{MOD}/base").as_str().into()]
    );
    assert_eq!(r.roots.len(), 1);
}

/// Read-only opt-in: set `KEEL_GO_FIXTURE` to a checkout of nudox-auth to check layering.
#[test]
fn configured_go_module_layering() {
    let Some(go) = go_binary() else { return };
    let Some(root) = std::env::var_os("KEEL_GO_FIXTURE").map(std::path::PathBuf::from) else {
        eprintln!("SKIP: set KEEL_GO_FIXTURE to a Go module checkout to run the opt-in layering check");
        return;
    };
    if !root.join("go.mod").exists() {
        eprintln!("SKIP: KEEL_GO_FIXTURE={} has no go.mod", root.display());
        return;
    }
    let cfg = Config::parse("[go]\n").unwrap();
    let planned = match plan_all(&cfg, &root, Some(&go)) {
        Ok(p) => p,
        Err(e) => {
            eprintln!(
                "SKIP: go list cannot plan nudox-auth here (module cache missing offline?): {e:#}"
            );
            return;
        }
    };
    let edges: usize = planned.iter().map(|p| p.node.stands_on.len()).sum();
    eprintln!("nudox-auth: {} nodes, {edges} edges", planned.len());
    let stands_on = |id: &str| -> Vec<String> {
        planned
            .iter()
            .find(|p| p.node.id.as_str() == id)
            .unwrap_or_else(|| panic!("no node {id}"))
            .node
            .stands_on
            .iter()
            .map(|u| u.to_string())
            .collect()
    };
    let p = "go:dev.nudox.org/nudox/nudox-auth";
    assert!(stands_on(&format!("{p}/auth")).contains(&format!("{p}/db")));
    assert!(stands_on(&format!("{p}/api")).contains(&format!("{p}/auth")));
    assert!(stands_on(&format!("{p}/api")).contains(&format!("{p}/db")));
    assert!(stands_on(&format!("{p}/db")).is_empty());
}

//! A Nix node: key from the derivation, cached from the Nix store, records
//! merged from the output's report.json with `file:` evidence ingested.

mod common;

use common::*;
use keel::store::ResultStore;
use keel::{Digest, Status, Verdict};
use keel_conduct::config::Config;
use keel_conduct::run::plan_all;

fn system() -> String {
    let os = if std::env::consts::OS == "macos" {
        "darwin"
    } else {
        std::env::consts::OS
    };
    format!("{}-{os}", std::env::consts::ARCH)
}

/// The builder: nushell from the Nix store. The darwin sandbox has no `mkdir`
/// of its own, and a store path (with its closure) is the only portable tool.
fn nu_in_store() -> Option<std::path::PathBuf> {
    let path = std::env::var("PATH").ok()?;
    let nu = std::env::split_paths(&path)
        .map(|d| d.join("nu"))
        .find(|p| p.is_file())?
        .canonicalize()
        .ok()?;
    nu.starts_with("/nix/store").then_some(nu)
}

fn fixture(nu: &std::path::Path) -> Tmp {
    let t = Tmp::new("nix");
    let pkg: std::path::PathBuf = nu.components().take(4).collect();
    let sys = system();
    // A nonce, so the derivation is new and the first run really builds it.
    let nonce = format!(
        "{}-{}",
        std::process::id(),
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos()
    );
    let key = "ab".repeat(32);
    t.write(
        "flake.nix",
        &format!(
            r#"{{
  outputs = {{ self }}: {{
    packages.{sys}.probe = derivation {{
      name = "keel-probe-{nonce}";
      system = "{sys}";
      builder = "{pkg}/bin/nu";
      args = [ "-c" ''
        let out = $env.out
        mkdir ($out | path join logs)
        'served' | save ($out | path join logs serve.log)
        '{{"nodes":[{{"id":"nix:scenario:probe-serves","key":"blake3:{key}","status":"pass","evidence":[{{"name":"serve.log","ref":"file:logs/serve.log"}}]}},{{"id":"nix:scenario:probe-serves!wrong-port","key":"blake3:{key}","status":"fail","reason":"control-did-not-fail"}}]}}' | save ($out | path join report.json)
      '' ];
    }};
  }};
}}
"#,
            pkg = pkg.display(),
        ),
    );
    t.write(
        "keel.toml",
        &format!(
            "[[node]]\nid = \"nix:probe\"\ndrv = \"path:{}#packages.{sys}.probe\"\n",
            t.path().display()
        ),
    );
    t
}

#[test]
fn derivation_key_cache_and_report_merge() {
    if !nix_available() {
        return;
    }
    let Some(nu) = nu_in_store() else {
        eprintln!(
            "SKIP: nu is not a /nix/store binary here, so there is no builder for the fixture"
        );
        return;
    };
    let t = fixture(&nu);
    let cfg = Config::load(&t.path().join("keel.toml")).unwrap();
    let planned = plan_all(&cfg, t.path(), None).unwrap();
    let node = &planned[0].node;
    assert!(matches!(node.key, Digest::Sha256(_)), "{}", node.key);
    assert!(node.inputs.drv.as_deref().unwrap().ends_with(".drv"));
    let via = node.via.clone().unwrap();
    assert!(via.starts_with("/nix/store/") && !via.ends_with(".drv"));

    let store = Tmp::new("nix-store");
    let r1 = conduct(t.path(), store.path(), None);
    assert_eq!(
        status(&r1, "nix:probe"),
        Status::Pass,
        "{:?}",
        rec(&r1, "nix:probe").detail
    );
    assert_eq!(status(&r1, "nix:scenario:probe-serves"), Status::Pass);
    // The runner's failed control is a root of the merged report.
    assert_eq!(r1.verdict, Verdict::Fail);
    assert_eq!(
        r1.roots,
        vec!["nix:scenario:probe-serves!wrong-port".into()]
    );

    // `file:` evidence became a blob in the store.
    let ev = &rec(&r1, "nix:scenario:probe-serves").evidence[0];
    let local = keel::LocalStore::open(store.path()).unwrap();
    assert_eq!(local.get_blob(&ev.reference).unwrap().unwrap(), b"served");

    // The output is realised now, so the node is cached.
    let r2 = conduct(t.path(), store.path(), None);
    assert_eq!(status(&r2, "nix:probe"), Status::Cached);
}

#[test]
fn evidence_cannot_point_outside_the_output() {
    let t = Tmp::new("nix-escape");
    t.write("report.json", r#"{"nodes":[{"id":"nix:x","key":"blake3:00","status":"pass","evidence":[{"name":"e","ref":"file:../../etc/passwd"}]}]}"#);
    let store = keel::LocalStore::open(Tmp::new("nix-escape-store").path()).unwrap();
    let err = keel_conduct::nix::read_report(&store, t.path()).unwrap_err();
    assert!(
        format!("{err:#}").contains("does not exist") || format!("{err:#}").contains("outside"),
        "{err:#}"
    );
}

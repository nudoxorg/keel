//! Exercise custody against an actual external driver process.
use keel_tree::driver::execute;
use std::{path::Path, time::Duration};

#[test]
fn external_driver_must_create_fresh_report_and_obey_deadline() {
    let dir = tempfile::tempdir().unwrap();
    let report = dir.path().join("report.json");
    let args = vec![
        "-c".into(),
        "printf '%s' '{\"schema\":1}' > \"$1\"".into(),
        "driver".into(),
        report.display().to_string(),
    ];
    execute(Path::new("/bin/sh"), &args, &report, Duration::from_secs(5)).unwrap();
    assert_eq!(std::fs::read_to_string(&report).unwrap(), "{\"schema\":1}");
    assert!(execute(Path::new("/bin/sh"), &args, &report, Duration::from_secs(5)).is_err());
    let absent = dir.path().join("absent.json");
    let slow = vec!["-c".into(), "sleep 10".into()];
    assert!(
        execute(
            Path::new("/bin/sh"),
            &slow,
            &absent,
            Duration::from_millis(50)
        )
        .is_err()
    );
    let escaped = dir.path().join("grandchild-survived");
    let grandchildren = vec![
        "-c".into(),
        "(sleep 0.3; printf survived > \"$1\") & wait".into(),
        "driver".into(),
        escaped.display().to_string(),
    ];
    assert!(
        execute(
            Path::new("/bin/sh"),
            &grandchildren,
            &absent,
            Duration::from_millis(50)
        )
        .is_err()
    );
    std::thread::sleep(Duration::from_millis(600));
    assert!(!escaped.exists(), "driver descendant outlived timeout");
}

#[test]
fn tree_results_combine_real_driver_receipts_with_unknown_cells() {
    use serde_json::json;
    use sha2::{Digest, Sha256};
    use std::{fs, process::Command};
    if Command::new("nix-instantiate")
        .arg("--version")
        .output()
        .is_err()
    {
        return;
    }
    let temp = tempfile::tempdir().unwrap();
    let root = temp.path();
    fs::create_dir(root.join("src")).unwrap();
    fs::write(root.join("src/lib.rs"), "pub fn a() {}\n").unwrap();
    fs::write(
        root.join("Cargo.toml"),
        "[package]\nname='solo'\nversion='0.1.0'\nedition='2021'\n",
    )
    .unwrap();
    fs::write(
        root.join("Cargo.lock"),
        "version = 4\n\n[[package]]\nname = 'solo'\nversion = '0.1.0'\n",
    )
    .unwrap();
    assert!(
        Command::new("git")
            .args(["init", "-q"])
            .arg(root)
            .status()
            .unwrap()
            .success()
    );
    assert!(
        Command::new("git")
            .arg("-C")
            .arg(root)
            .args(["add", "Cargo.toml", "Cargo.lock", "src"])
            .status()
            .unwrap()
            .success()
    );
    let bins = root.join("bins");
    fs::create_dir(&bins).unwrap();
    fs::copy("/bin/sh", bins.join("probe")).unwrap();
    let cases = vec!["one", "two"].into_iter().map(|id| json!({"id":id,"node":"solo","language":"test","daemon":false,"steps":[{"id":"step","kind":"process","binary":"probe"}]})).collect::<Vec<_>>();
    let manifest = root.join("manifest.json");
    let manifest_bytes = serde_json::to_vec(&json!({"schema":1,"cases":cases})).unwrap();
    fs::write(&manifest, &manifest_bytes).unwrap();
    let digest = |bytes: &[u8]| format!("{:x}", Sha256::digest(bytes));
    let driver_hash = digest(&fs::read("/bin/sh").unwrap());
    let artifact_hash = digest(&fs::read(bins.join("probe")).unwrap());
    let report_source = root.join("source.json");
    let report = root.join("report.json");
    fs::write(&report_source, serde_json::to_vec(&json!({"schema":1,"manifest_sha256":digest(&manifest_bytes),"driver_sha256":driver_hash,"binaries":{"probe":artifact_hash},"cases":[{"id":"one","node":"solo","language":"test","status":"pass","steps":[{"id":"step","status":"pass"}]}]})).unwrap()).unwrap();
    let args = vec![
        "-c".into(),
        "cat \"$1\" > \"$2\"".into(),
        "driver".into(),
        report_source.display().to_string(),
        report.display().to_string(),
    ];
    assert!(execute(Path::new("/bin/sh"), &args, &report, Duration::from_secs(5)).unwrap());
    let lib = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../nix/keel/lib.nix")
        .canonicalize()
        .unwrap();
    let quoted = |p: &Path| serde_json::to_string(&p.to_string_lossy()).unwrap();
    let model = root.join("model.nix");
    fs::write(&model, format!(r#"let keel = import {}; cases = (builtins.fromJSON (builtins.readFile {})).cases; byId = id: builtins.head (builtins.filter (c: c.id == id) cases); in keel.model (m: with keel; {{ root = {}; solo = (node {{ code = [ (crate "solo") ]; movedBy = [ "src/lib.rs" ]; unmovedBy = [ "Cargo.toml" ]; }}) // required; checks.contract = matrix {{ over.case = [ "one" "two" ]; run = c: [ "keel-case" c.case ]; expect = c: {{ definitionSha256 = builtins.hashString "sha256" (builtins.toJSON (byId c.case)); }}; on = _: [ m.solo ]; inputs = [ (crate "solo") ]; uncontrolled = "no negative twin"; }}; policy.deployGate = tests.all; }})"#, quoted(&lib), quoted(&manifest), quoted(root))).unwrap();
    let results = root.join("results.txt");
    fs::write(&results, "").unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_keel-tree"))
        .args(["--json", "--root"])
        .arg(root)
        .arg("--model")
        .arg(&model)
        .args(["tree", "--results"])
        .arg(&results)
        .arg("--check-manifest")
        .arg(&manifest)
        .arg("--check-report")
        .arg(&report)
        .arg("--check-bin-dir")
        .arg(&bins)
        .args(["--check-driver-binary", "/bin/sh"])
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let verdict: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(verdict["features"][0]["state"], "unknown");
    assert_eq!(verdict["features"][0]["checks"]["pass"], 1);
    assert_eq!(verdict["features"][0]["checks"]["unknown"], 1);
}

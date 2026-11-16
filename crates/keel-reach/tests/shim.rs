//! The `keel-linker` binary as rustc runs it: record, preserve, then become the
//! real linker, and never let a recording failure break the link.

use std::path::Path;
use std::process::Command;

fn dir(name: &str) -> std::path::PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("keel-linker")
        .join(name);
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

#[test]
fn passes_the_original_arguments_on_and_records_the_expanded_ones() {
    let d = dir("ok");
    std::fs::write(d.join("a.rcgu.o"), b"x").unwrap();
    std::fs::write(d.join("args.rsp"), "a.rcgu.o\n-o\nout\n").unwrap();
    // A stand-in linker that shows exactly what it was handed and, like a
    // real one, leaves an output behind: the record is written only after
    // a link that produced something.
    let linker = d.join("fake-linker.sh");
    std::fs::write(&linker, "#!/bin/sh\necho \"$@\"\nprintf linked > out\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&linker, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let o = Command::new(env!("CARGO_BIN_EXE_keel-linker"))
        .arg("@args.rsp")
        .arg("-lm")
        .current_dir(&d)
        .env("KEEL_REAL_LINKER", &linker)
        // The dependency-file request would add an argument of its own.
        .env("KEEL_DEPENDENCY_FLAVOUR", "none")
        .output()
        .unwrap();
    assert!(o.status.success());
    assert_eq!(
        String::from_utf8_lossy(&o.stdout).trim(),
        "@args.rsp -lm",
        "the real linker sees the unexpanded arguments"
    );
    let rec = keel_reach::LinkInputs::from_record(&d.join("out.keel-link.json")).unwrap();
    assert_eq!(rec.libs, ["m"]);
    assert_eq!(rec.output, d.join("out"));
    std::fs::remove_file(d.join("a.rcgu.o")).unwrap();
    assert_eq!(std::fs::read(&rec.preserved_objects[0]).unwrap(), b"x");
    assert_eq!(rec.preserved_hashes[0].len(), 64);
}

#[test]
fn a_recording_failure_is_reported_and_does_not_stop_the_link() {
    let d = dir("fail");
    let out = d.join("no-such-dir/out");
    let o = Command::new(env!("CARGO_BIN_EXE_keel-linker"))
        .args(["x.o", "-o"])
        .arg(&out)
        .current_dir(&d)
        .env("KEEL_REAL_LINKER", "/usr/bin/true")
        .output()
        .unwrap();
    assert!(o.status.success(), "the link itself succeeded");
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains(&out.display().to_string()),
        "stderr names the output: {err}"
    );
    assert!(err.contains("fall back to the executable key"), "{err}");
}

#[test]
fn a_missing_response_file_is_reported_and_the_link_still_runs() {
    let d = dir("rsp");
    let o = Command::new(env!("CARGO_BIN_EXE_keel-linker"))
        .arg("@gone.rsp")
        .current_dir(&d)
        .env("KEEL_REAL_LINKER", "/usr/bin/true")
        .output()
        .unwrap();
    assert!(o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("gone.rsp"));
}

#[test]
fn the_real_linker_exit_status_is_the_shims() {
    let d = dir("status");
    let o = Command::new(env!("CARGO_BIN_EXE_keel-linker"))
        .current_dir(&d)
        .env("KEEL_REAL_LINKER", "/usr/bin/false")
        .output()
        .unwrap();
    assert_eq!(o.status.code(), Some(1));
}

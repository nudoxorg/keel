//! The contract between `nix/keel/lib.nix` and the model reader, run through nushell.
//!
//! `tests/contract.nu` evaluates `tests/contract/model.nix` (which uses every constructor the
//! library exports), checks that it does, and feeds the JSON to `keel-tree read-model`, which
//! fails on any key no typed field reads. The reader finds unread keys by reading the model
//! into its typed form, writing it back, and listing what the output lacks; that sees into
//! internally tagged enums, which `serde_ignored` does not.

use std::path::Path;
use std::process::Command;

fn on_path(program: &str, probe: &str) -> bool {
    Command::new(program).arg(probe).output().is_ok_and(|o| o.status.success())
}

#[test]
fn the_library_and_the_model_reader_agree_on_every_constructor() {
    if !on_path("nix-instantiate", "--version") {
        eprintln!("SKIPPED: nix-instantiate is not on PATH, so the contract model cannot be evaluated; install Nix to run this test");
        return;
    }
    if !on_path("nu", "--version") {
        eprintln!("SKIPPED: nu (nushell) is not on PATH, and the contract script is nushell; install it to run this test");
        return;
    }
    let here = Path::new(env!("CARGO_MANIFEST_DIR"));
    let out = Command::new("nu")
        .arg(here.join("tests/contract.nu"))
        .arg(env!("CARGO_BIN_EXE_keel-tree"))
        .arg(here.join("../../nix/keel/lib.nix"))
        .arg(here.join("tests/contract/model.nix"))
        .output()
        .expect("nu runs");
    let text = format!("{}{}", String::from_utf8_lossy(&out.stdout), String::from_utf8_lossy(&out.stderr));
    assert!(out.status.success(), "the contract failed:\n{text}");
    assert!(text.contains("contract ok"), "{text}");
}

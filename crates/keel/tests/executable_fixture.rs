//! End-to-end check of the executable key on real linker output (DESIGN.md
//! §1.2): the same crate built at two checkout paths has different bytes on
//! disk but the same key, and an edit to the source changes the key.
//!
//! Builds with `cargo-stock` and `RUSTC_WRAPPER` emptied, because the `cargo`
//! on PATH is a wrapper that must stay out of a determinism test.

use std::path::{Path, PathBuf};
use std::process::Command;

use keel::executable_key;

const LIB: &str = "pub fn scale(x: u32) -> u32 { x * FACTOR }\nconst FACTOR: u32 = 2;\n\n#[test]\nfn scales() {\n    assert_eq!(scale(21), 42);\n}\n";

const MANIFEST: &str = "[package]\nname = \"keel-fixture\"\nversion = \"0.0.0\"\nedition = \"2024\"\n\n# Keeps cargo from adopting the enclosing keel workspace.\n[workspace]\n\n[profile.test]\nsplit-debuginfo = \"packed\"\n";

/// A scratch directory under cargo's per-target temp dir, removed on drop.
struct Scratch(PathBuf);

impl Scratch {
    fn new(name: &str) -> Scratch {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join(format!("exe-fixture-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(dir.join("src")).unwrap();
        Scratch(dir.canonicalize().unwrap())
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn run(cmd: &mut Command) -> String {
    let out = cmd.output().unwrap_or_else(|e| {
        panic!("cannot spawn {cmd:?}: {e}; this test needs `cargo-stock` on PATH")
    });
    assert!(
        out.status.success(),
        "{cmd:?} failed:\n{}",
        String::from_utf8_lossy(&out.stderr)
    );
    String::from_utf8(out.stdout).unwrap()
}

/// Builds the fixture crate in `dir` with the remap flags of §3.1 and returns
/// its test executable.
fn build(dir: &Path, lib: &str) -> PathBuf {
    std::fs::write(dir.join("Cargo.toml"), MANIFEST).unwrap();
    std::fs::write(dir.join("src/lib.rs"), lib).unwrap();

    let sysroot = run(
        Command::new(std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into()))
            .args(["--print", "sysroot"]),
    );
    let cargo_home = std::env::var_os("CARGO_HOME")
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from(std::env::var_os("HOME").expect("HOME")).join(".cargo"));
    let flags = format!(
        "--remap-path-prefix={}=/src --remap-path-prefix={}=/cargo --remap-path-prefix={}=/sysroot",
        dir.display(),
        cargo_home.display(),
        sysroot.trim()
    );
    let stdout = run(Command::new("cargo-stock")
        .args(["test", "--no-run", "--message-format=json"])
        .current_dir(dir)
        .env("RUSTC_WRAPPER", "")
        .env("RUSTFLAGS", flags)
        // Anything inherited from the outer cargo that would override the above.
        .env_remove("CARGO_ENCODED_RUSTFLAGS")
        .env_remove("CARGO_BUILD_RUSTFLAGS")
        .env_remove("CARGO_TARGET_DIR")
        .env_remove("RUSTC_WORKSPACE_WRAPPER"));

    stdout
        .lines()
        .filter_map(|l| serde_json::from_str::<serde_json::Value>(l).ok())
        .filter(|m| m["reason"] == "compiler-artifact" && m["profile"]["test"] == true)
        .find_map(|m| m["executable"].as_str().map(PathBuf::from))
        .expect("cargo reported no test executable")
}

#[test]
fn key_is_stable_across_checkout_paths_and_follows_the_source() {
    let (a, b) = (Scratch::new("a"), Scratch::new("bbbbbbbbbbbbbbbbbbbb"));
    let exe_a = build(&a.0, LIB);
    let exe_b = build(&b.0, LIB);
    assert_ne!(exe_a, exe_b);

    let (key_a, key_b) = (
        executable_key(&exe_a).unwrap(),
        executable_key(&exe_b).unwrap(),
    );
    assert_eq!(key_a, key_b, "same source at two paths must key equally");

    // The reason the key exists. Measured on macOS (DESIGN.md §1.2); other
    // linkers may happen to produce identical files, so only report there.
    let whole = |p: &Path| blake3::hash(&std::fs::read(p).unwrap());
    if cfg!(target_os = "macos") {
        assert_ne!(
            whole(&exe_a),
            whole(&exe_b),
            "whole-file hashes are expected to differ across checkout paths"
        );
    }

    let edited = LIB.replace("= 2;", "= 3;").replace("42", "63");
    let exe_edited = build(&a.0, &edited);
    assert_ne!(
        executable_key(&exe_edited).unwrap(),
        key_a,
        "an edit to the code must change the key"
    );
}

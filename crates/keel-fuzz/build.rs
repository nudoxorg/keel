//! The engine executable must export the SanitizerCoverage callbacks it defines
//! (`__sanitizer_cov_*`): a dlopened target leaves them undefined and binds them
//! against the main executable. Rust executables do not export their symbols by
//! default, so without this the load fails with "symbol not found".

fn main() {
    println!("cargo::rerun-if-changed=build.rs");
    let os = std::env::var("CARGO_CFG_TARGET_OS").unwrap_or_default();
    match os.as_str() {
        "macos" => println!("cargo::rustc-link-arg-bins=-Wl,-export_dynamic"),
        // Untested on this machine (aarch64-darwin only).
        "linux" => println!("cargo::rustc-link-arg-bins=-Wl,--export-dynamic"),
        _ => {}
    }
}

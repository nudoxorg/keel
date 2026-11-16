//! Loading a fuzz target: a shared library that exports the libFuzzer ABI.
//!
//! The engine is one executable; targets are dlopened. That keeps the engine built
//! once and lets any language produce a target: Rust `cdylib`, a C shared object, a
//! C++ one. Instrumented code registers its coverage through the callbacks in
//! `sancov` while `dlopen` runs its constructors.

use std::ffi::{CString, c_char, c_int, c_void};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub type OneInput = unsafe extern "C" fn(*const u8, usize) -> c_int;
type Initialize = unsafe extern "C" fn(*mut c_int, *mut *mut *mut c_char) -> c_int;

/// What `bench/fuzz/build-target.nu` recorded about how the target was built.
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
pub struct Sidecar {
    #[serde(default)]
    pub asan: bool,
    #[serde(default)]
    pub rust_sancov: bool,
    #[serde(default)]
    pub c_sancov: bool,
    #[serde(default)]
    pub variant: String,
    /// Path of the clang ASan runtime the target was linked against.
    #[serde(default)]
    pub asan_runtime: String,
}

pub fn sidecar_path(target: &Path) -> PathBuf {
    let mut name = target.as_os_str().to_owned();
    name.push(".keel-target.json");
    PathBuf::from(name)
}

pub fn read_sidecar(target: &Path) -> Result<Sidecar> {
    let path = sidecar_path(target);
    match std::fs::read_to_string(&path) {
        Ok(text) => serde_json::from_str(&text)
            .with_context(|| format!("parsing {}: rebuild the target with bench/fuzz/build-target.nu", path.display())),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Sidecar::default()),
        Err(e) => Err(e).with_context(|| format!("reading {}", path.display())),
    }
}

/// A target built with AddressSanitizer needs the sanitizer runtime to be the first
/// image in the process, which `dlopen` cannot arrange. Re-executes the current
/// process with the runtime preloaded, once.
pub fn ensure_runtime_preloaded(target: &Path) -> Result<()> {
    const MARK: &str = "KEEL_FUZZ_PRELOADED";
    if std::env::var_os(MARK).is_some() {
        return Ok(());
    }
    let sidecar = read_sidecar(target)?;
    if !sidecar.asan {
        return Ok(());
    }
    if sidecar.asan_runtime.is_empty() || !Path::new(&sidecar.asan_runtime).exists() {
        bail!(
            "{} was built with AddressSanitizer but the runtime '{}' recorded in {} does not exist; rebuild it with bench/fuzz/build-target.nu --asan on this machine",
            target.display(),
            sidecar.asan_runtime,
            sidecar_path(target).display()
        );
    }
    use std::os::unix::process::CommandExt;
    let exe = std::env::current_exe().context("finding the keel-fuzz executable to re-run with the sanitizer runtime preloaded")?;
    let err = std::process::Command::new(exe)
        .args(std::env::args_os().skip(1))
        .env(MARK, "1")
        .env("DYLD_INSERT_LIBRARIES", &sidecar.asan_runtime)
        .exec();
    bail!("re-executing with DYLD_INSERT_LIBRARIES={} failed: {err}", sidecar.asan_runtime)
}

pub struct Target {
    pub path: PathBuf,
    /// blake3 of the binary: part of every cache key and manifest entry.
    pub key: String,
    pub sidecar: Sidecar,
    one_input: OneInput,
    handle: *mut c_void,
}

// SAFETY: the handle is an opaque dlopen token and `one_input` a plain function
// pointer; the target itself is responsible for its own thread-safety.
unsafe impl Send for Target {}
unsafe impl Sync for Target {}

impl std::fmt::Debug for Target {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Target").field("path", &self.path).field("key", &self.key).finish()
    }
}

fn dl_error() -> String {
    // SAFETY: dlerror returns a NUL-terminated string or null.
    let p = unsafe { libc::dlerror() };
    if p.is_null() { "unknown error".into() } else { unsafe { std::ffi::CStr::from_ptr(p) }.to_string_lossy().into_owned() }
}

impl Target {
    /// Loads `path`, runs its constructors (which register coverage) and calls
    /// `LLVMFuzzerInitialize` when it exists.
    pub fn load(path: &Path) -> Result<Self> {
        let path = path.canonicalize().with_context(|| {
            format!("the target {} does not exist: build it with bench/fuzz/build-target.nu --kind cdylib", path.display())
        })?;
        let bytes = std::fs::read(&path).with_context(|| format!("reading {}", path.display()))?;
        let key = blake3::hash(&bytes).to_hex().to_string();
        let sidecar = read_sidecar(&path)?;
        let c_path = CString::new(path.as_os_str().as_encoded_bytes())?;
        // RTLD_LOCAL: the target's symbols stay out of the engine's namespace, so two
        // targets or a target and the engine cannot capture each other's names.
        let handle = unsafe { libc::dlopen(c_path.as_ptr(), libc::RTLD_NOW | libc::RTLD_LOCAL) };
        if handle.is_null() {
            bail!(
                "dlopen of {} failed: {}. If it names an undefined `___sanitizer_cov_*` or `___asan_*` symbol, the engine did not export it (check the link arg -Wl,-export_dynamic) or the target was not linked with -undefined dynamic_lookup (bench/fuzz/build-target.nu --kind cdylib does that)",
                path.display(),
                dl_error()
            );
        }
        let sym = CString::new("LLVMFuzzerTestOneInput")?;
        let f = unsafe { libc::dlsym(handle, sym.as_ptr()) };
        if f.is_null() {
            bail!(
                "{} does not export LLVMFuzzerTestOneInput: every Keel fuzz target must provide the libFuzzer entry point `int LLVMFuzzerTestOneInput(const uint8_t*, size_t)` as an exported symbol",
                path.display()
            );
        }
        // SAFETY: the symbol is the libFuzzer entry point with this exact signature.
        let one_input: OneInput = unsafe { std::mem::transmute::<*mut c_void, OneInput>(f) };
        let init_sym = CString::new("LLVMFuzzerInitialize")?;
        let init = unsafe { libc::dlsym(handle, init_sym.as_ptr()) };
        if !init.is_null() {
            // SAFETY: the libFuzzer ABI for the optional initialiser.
            let init: Initialize = unsafe { std::mem::transmute::<*mut c_void, Initialize>(init) };
            let mut argc: c_int = 1;
            let prog = CString::new(path.to_string_lossy().as_bytes())?;
            let mut argv0: *mut c_char = prog.as_ptr() as *mut c_char;
            let mut argv: *mut *mut c_char = &mut argv0;
            let rc = unsafe { init(&mut argc, &mut argv) };
            if rc != 0 {
                bail!("LLVMFuzzerInitialize of {} returned {rc}; a target that cannot initialise cannot be fuzzed", path.display());
            }
        }
        Ok(Self { path, key, sidecar, one_input, handle })
    }

    pub fn run(&self, data: &[u8]) -> i32 {
        // SAFETY: the pointer/length pair describes `data`; the entry point follows the libFuzzer ABI.
        unsafe { (self.one_input)(data.as_ptr(), data.len()) }
    }

    pub fn entry(&self) -> OneInput {
        self.one_input
    }
}

impl Drop for Target {
    fn drop(&mut self) {
        // Intentionally leaked: unloading would invalidate the coverage regions the
        // engine holds raw pointers into.
        let _ = self.handle;
    }
}

//! Crash deduplication keys.
//!
//! Two crashes are the same bug when they fail in the same way at the same place.
//! The key is derived, in order of preference, from:
//!   1. an AddressSanitizer report: its error kind and the top frames below the
//!      sanitizer's own interceptors,
//!   2. a Rust panic message: the `file:line:col` the panic names (the message
//!      text is excluded, because it usually embeds values that vary per input),
//!   3. a bare signal or timeout: the signal plus a signature of the edges that
//!      were covered when it happened (so two different crashes behind the same
//!      signal still separate, and the same one always collapses).
//! Function names are demangled with their hashes removed, so a rebuild does not
//! change the key.

use serde::{Deserialize, Serialize};

/// How many frames take part in the key. Deeper frames vary with the caller (the
/// same bug reached through two harnesses), shallower ones merge unrelated bugs.
pub const TOP_FRAMES: usize = 3;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CrashKey {
    /// 16 hex characters of blake3 over `kind` and the frames (or the signature).
    pub key: String,
    /// e.g. "heap-buffer-overflow", "rust-panic", "signal:SIGSEGV", "timeout".
    pub kind: String,
    /// The frames or locations that went into the key, for humans.
    pub frames: Vec<String>,
    /// How the key was derived: "asan", "panic" or "signature".
    pub source: String,
}

/// What the run told us besides its stderr.
pub struct Exit<'a> {
    /// `Some(name)` when the process died of a signal, e.g. "SIGABRT".
    pub signal: Option<&'a str>,
    pub timed_out: bool,
    /// Hex blake3 of the covered-edge set at the time of death.
    pub coverage_signature: &'a str,
}

/// Frames that are the sanitizer's own machinery, not the bug.
fn is_runtime_frame(name: &str) -> bool {
    const PREFIXES: &[&str] = &[
        "__asan_", "__sanitizer_", "__interceptor_", "___asan", "_sigtramp", "abort", "raise",
        "pthread_kill", "__pthread_kill",
    ];
    const EXACT: &[&str] = &["malloc", "free", "calloc", "realloc", "memcpy", "memmove", "memset", "strlen"];
    PREFIXES.iter().any(|p| name.starts_with(p)) || EXACT.contains(&name)
}

/// `main.rs:6` and `+0x154` offsets are not part of a function's identity.
fn clean_frame(raw: &str) -> String {
    let name = raw.split('+').next().unwrap_or(raw);
    let name = name.strip_prefix('_').filter(|n| n.starts_with("ZN") || n.starts_with('R')).map_or(name, |n| {
        // Mach-O adds one underscore to every symbol; the Rust manglers start at the next.
        n
    });
    let candidate = if name.starts_with("ZN") || name.starts_with('R') { format!("_{name}") } else { name.to_string() };
    let demangled = rustc_demangle::demangle(&candidate);
    // `{:#}` drops the trailing hash.
    format!("{demangled:#}")
}

fn asan_frames(report: &str, resolve: &dyn Fn(usize) -> Option<String>) -> Vec<String> {
    let mut frames = Vec::new();
    for line in report.lines() {
        let line = line.trim_start();
        let Some(rest) = line.strip_prefix('#') else { continue };
        // "1 0x0001001c2304 in decode_payload+0x90 (img:arm64+0x100002304)" with
        // symbolize=1, or "1 0x0001001c2304 (img:arm64+0x100002304)" without it.
        let mut words = rest.split_whitespace();
        let _index = words.next();
        let pc = words.next().and_then(|w| usize::from_str_radix(w.trim_start_matches("0x"), 16).ok());
        // Our own symbol table wins: it needs no external symbolizer, so the key is
        // the same whether or not the sanitizer symbolised the report.
        if let Some(name) = pc.and_then(resolve) {
            frames.push(name);
        } else if let Some((_, after_in)) = rest.split_once(" in ") {
            let name = after_in.split_whitespace().next().unwrap_or("");
            if !name.is_empty() {
                frames.push(clean_frame(name));
            }
        } else if let Some(pc) = pc {
            frames.push(format!("{pc:#x}"));
        }
        // The stack that precedes the "is located"/"allocated by" sections is the one
        // that matters; the later stacks are allocation history.
        if frames.len() > 64 {
            break;
        }
    }
    frames
}

fn first_asan_stack(report: &str) -> &str {
    // Everything up to the first blank line after the first frame is the crash stack.
    let start = report.find("ERROR: AddressSanitizer").unwrap_or(0);
    let tail = &report[start..];
    match tail.find("\n\n") {
        Some(end) => &tail[..end],
        None => tail,
    }
}

fn asan_kind(report: &str) -> Option<String> {
    let line = report.lines().find(|l| l.contains("ERROR: AddressSanitizer:"))?;
    let after = line.split("ERROR: AddressSanitizer:").nth(1)?.trim();
    // "heap-buffer-overflow on address ..." -> "heap-buffer-overflow"
    let kind = after.split(" on ").next().unwrap_or(after);
    let kind = kind.split_whitespace().next().unwrap_or(kind);
    Some(kind.to_string())
}

fn panic_location(report: &str) -> Option<String> {
    for line in report.lines() {
        if let Some(rest) = line.split("panicked at ").nth(1) {
            // Rust >= 1.73 prints "panicked at src/lib.rs:70:26:", older ones add the message after a comma.
            let loc = rest.trim_end_matches(':');
            let loc = loc.split(['\n', ' ']).next().unwrap_or(loc);
            let loc = loc.trim_end_matches(':').trim_end_matches(',');
            return Some(loc.to_string());
        }
    }
    None
}

fn hash16(parts: &[&str]) -> String {
    let mut h = blake3::Hasher::new();
    for p in parts {
        h.update(p.as_bytes());
        h.update(b"\0");
    }
    h.finalize().to_hex().to_string()[..16].to_string()
}

/// Derives the key for one crashing run from what it printed and how it ended.
pub fn crash_key(stderr: &str, exit: &Exit<'_>, resolve: &dyn Fn(usize) -> Option<String>) -> CrashKey {
    if let Some(kind) = asan_kind(stderr) {
        let stack = first_asan_stack(stderr);
        let frames: Vec<String> = asan_frames(stack, resolve)
            .into_iter()
            .filter(|f| !is_runtime_frame(f))
            .take(TOP_FRAMES)
            .collect();
        if !frames.is_empty() {
            let mut parts = vec!["asan", kind.as_str()];
            parts.extend(frames.iter().map(String::as_str));
            return CrashKey { key: hash16(&parts), kind, frames, source: "asan".into() };
        }
    }
    if let Some(loc) = panic_location(stderr) {
        return CrashKey {
            key: hash16(&["panic", &loc]),
            kind: "rust-panic".into(),
            frames: vec![loc],
            source: "panic".into(),
        };
    }
    let kind = if exit.timed_out {
        "timeout".to_string()
    } else {
        format!("signal:{}", exit.signal.unwrap_or("unknown"))
    };
    CrashKey {
        key: hash16(&["signature", &kind, exit.coverage_signature]),
        kind,
        frames: vec![format!("coverage:{}", &exit.coverage_signature[..exit.coverage_signature.len().min(16)])],
        source: "signature".into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASAN: &str = "\
=================================================================
==92027==ERROR: AddressSanitizer: heap-buffer-overflow on address 0x606000000480 at pc 0x000100ad71b4 bp 0x00016fc3d2f0 sp 0x00016fc3caa0
WRITE of size 75 at 0x606000000480 thread T0
    #0 0x000100ad71b0 in __asan_memcpy+0x324 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3b1b0)
    #1 0x0001001c2304 in decode_payload+0x90 (demo-libfuzzer:arm64+0x100002304)
    #2 0x0001001c1cd0 in _RNvCsguoXtdRjxNY_14keel_fuzz_demo5parse+0x154 (demo-libfuzzer:arm64+0x100001cd0)
    #3 0x0001001c10c4 in _RNvNvCsfD4DONiaGi_14demo_libfuzzer1__19___libfuzzer_sys_run main.rs:6
    #4 0x0001001c19ac in rust_fuzzer_test_input lib.rs:276

0x606000000480 is located 0 bytes after 64-byte region [0x606000000440,0x606000000480)
allocated by thread T0 here:
    #0 0x000100ad938c in malloc+0x78 (libclang_rt.asan_osx_dynamic.dylib:arm64e+0x3d38c)
    #1 0x0001001c22e0 in decode_payload+0x6c (demo-libfuzzer:arm64+0x1000022e0)
";

    fn exit() -> Exit<'static> {
        Exit { signal: Some("SIGABRT"), timed_out: false, coverage_signature: "0123456789abcdef0123" }
    }

    #[test]
    fn asan_key_uses_kind_and_top_frames_below_the_interceptor() {
        let key = crash_key(ASAN, &exit(), &|_| None);
        assert_eq!(key.kind, "heap-buffer-overflow");
        assert_eq!(key.source, "asan");
        assert_eq!(key.frames[0], "decode_payload");
        assert_eq!(key.frames[1], "keel_fuzz_demo::parse");
        assert_eq!(key.frames.len(), TOP_FRAMES);
    }

    #[test]
    fn the_allocation_stack_does_not_change_the_key() {
        let shorter = ASAN.split("allocated by").next().unwrap();
        assert_eq!(crash_key(ASAN, &exit(), &|_| None).key, crash_key(shorter, &exit(), &|_| None).key);
    }

    #[test]
    fn addresses_and_offsets_do_not_change_the_key() {
        let moved = ASAN.replace("0x000100ad71b0", "0x000200ad71b0").replace("+0x90", "+0x94").replace("0x606000000480", "0x606000000999");
        assert_eq!(crash_key(ASAN, &exit(), &|_| None).key, crash_key(&moved, &exit(), &|_| None).key);
    }

    #[test]
    fn a_different_function_is_a_different_key() {
        let other = ASAN.replace("decode_payload+0x90", "other_function+0x90");
        assert_ne!(crash_key(ASAN, &exit(), &|_| None).key, crash_key(&other, &exit(), &|_| None).key);
    }

    #[test]
    fn panic_key_is_the_location_not_the_message() {
        let a = "thread '<unnamed>' panicked at src/lib.rs:70:26:\nindex out of bounds: the len is 3 but the index is 7\n";
        let b = "thread '<unnamed>' panicked at src/lib.rs:70:26:\nindex out of bounds: the len is 0 but the index is 1\n";
        let c = "thread '<unnamed>' panicked at src/lib.rs:71:26:\nindex out of bounds\n";
        let (ka, kb, kc) = (crash_key(a, &exit(), &|_| None), crash_key(b, &exit(), &|_| None), crash_key(c, &exit(), &|_| None));
        assert_eq!(ka.key, kb.key);
        assert_ne!(ka.key, kc.key);
        assert_eq!(ka.frames, vec!["src/lib.rs:70:26".to_string()]);
        assert_eq!(ka.kind, "rust-panic");
    }

    #[test]
    fn bare_signals_fall_back_to_the_coverage_signature() {
        let sig = |s: &'static str| Exit { signal: Some("SIGSEGV"), timed_out: false, coverage_signature: s };
        let (a, b) = (crash_key("", &sig("aaaaaaaaaaaaaaaaaaaa"), &|_| None), crash_key("", &sig("bbbbbbbbbbbbbbbbbbbb"), &|_| None));
        assert_eq!(a.source, "signature");
        assert_ne!(a.key, b.key);
        assert_eq!(a.key, crash_key("", &sig("aaaaaaaaaaaaaaaaaaaa"), &|_| None).key);
        let t = crash_key("", &Exit { signal: None, timed_out: true, coverage_signature: "cc" }, &|_| None);
        assert_eq!(t.kind, "timeout");
    }
}

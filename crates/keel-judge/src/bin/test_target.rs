//! A stand-in for a libFuzzer target over the same argv contract, so the supervisor can be
//! tested without a fuzzing engine. It exists only for the integration tests and the NixOS
//! VM test.
//!
//! argv[1] is the corpus directory. The supervisor clears the environment, so behaviour
//! comes from flags: `-keel_test_rate=<features per second>`, `-keel_test_crash_after=<s>`,
//! `-print_final_stats=1`, `-artifact_prefix=<dir>/` (default: `artifacts/` beside the
//! corpus). SIGINT prints libFuzzer's interrupt line, the final stats, and exits 72.

use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

static INTERRUPTED: AtomicBool = AtomicBool::new(false);

extern "C" fn on_sigint(_: libc::c_int) {
    INTERRUPTED.store(true, Ordering::SeqCst);
}

const EXECS_PER_SEC: f64 = 100_000.0;

fn flag<'a>(args: &'a [String], name: &str) -> Option<&'a str> {
    args.iter().find_map(|a| a.strip_prefix(name)?.strip_prefix('='))
}

fn stats(print: bool, execs: u64, secs: f64, new_units: u64) {
    if print {
        eprintln!("stat::number_of_executed_units: {execs}");
        eprintln!("stat::average_exec_per_sec:     {}", (execs as f64 / secs.max(0.001)) as u64);
        eprintln!("stat::new_units_added:          {new_units}");
        eprintln!("stat::slowest_unit_time_sec:    0");
        eprintln!("stat::peak_rss_mb:              20");
    }
}

fn main() {
    let args: Vec<String> = std::env::args().skip(1).collect();
    let Some(corpus) = args.first().filter(|a| !a.starts_with('-')).map(PathBuf::from) else {
        eprintln!("keel-judge-test-target: argv[1] must be the corpus directory");
        std::process::exit(2);
    };
    let rate: f64 = flag(&args, "-keel_test_rate").and_then(|v| v.parse().ok()).unwrap_or(0.0);
    let crash_after: Option<f64> = flag(&args, "-keel_test_crash_after").and_then(|v| v.parse().ok());
    let print_stats = flag(&args, "-print_final_stats") == Some("1");
    let prefix = match flag(&args, "-artifact_prefix") {
        Some(p) => PathBuf::from(p),
        None => corpus.parent().unwrap_or(&corpus).join("artifacts"),
    };
    let _ = std::fs::create_dir_all(&prefix);

    unsafe {
        let mut sa: libc::sigaction = std::mem::zeroed();
        let handler: extern "C" fn(libc::c_int) = on_sigint;
        sa.sa_sigaction = handler as libc::sighandler_t;
        libc::sigemptyset(&mut sa.sa_mask);
        libc::sigaction(libc::SIGINT, &sa, std::ptr::null_mut());
    }

    let pid = std::process::id();
    let existing = std::fs::read_dir(&corpus).map_or(0, |d| d.count()) as u64;
    let mut ft = 10 + existing;
    let cov = |ft: u64| ft / 2 + 1;
    eprintln!("INFO: Running with entropic power schedule (0xFF, 100).");
    eprintln!("#2\tINITED cov: {} ft: {ft} corp: {}/{}b exec/s: 0 rss: 20Mb", cov(ft), existing + 1, existing + 1);

    let start = Instant::now();
    let mut produced = 0u64;
    loop {
        let t = start.elapsed().as_secs_f64();
        let execs = (t * EXECS_PER_SEC) as u64;
        if INTERRUPTED.load(Ordering::SeqCst) {
            eprintln!("=={pid}== INFO: libFuzzer: run interrupted; exiting");
            eprintln!("Done {execs} runs in {} second(s)", t as u64);
            stats(print_stats, execs, t, produced);
            std::process::exit(72);
        }
        if crash_after.is_some_and(|c| t >= c) {
            let input = b"keel-judge-test-target crash input";
            let path = prefix.join(format!("crash-{}", blake3::hash(input).to_hex()));
            let _ = std::fs::write(&path, input);
            eprintln!("thread '<unnamed>' panicked at src/decode.rs:41:9:");
            eprintln!("index out of bounds: the len is 3 but the index is 7");
            eprintln!("=={pid}== ERROR: libFuzzer: deadly signal");
            eprintln!("artifact_prefix='{}/'; Test unit written to {}", prefix.display(), path.display());
            stats(print_stats, execs, t, produced);
            std::process::exit(1);
        }
        while (produced as f64) < rate * t {
            produced += 1;
            ft += 1;
            let name = blake3::hash(format!("{pid}-{ft}").as_bytes()).to_hex();
            let _ = std::fs::write(corpus.join(name.as_str()), ft.to_le_bytes());
            eprintln!("#{execs}\tNEW    cov: {} ft: {ft} corp: {}/{}b lim: 4 exec/s: {} rss: 20Mb L: 8/8 MS: 1 ChangeBit-", cov(ft), existing + 1 + produced, 8 * produced, EXECS_PER_SEC as u64);
        }
        std::thread::sleep(Duration::from_millis(10));
    }
}

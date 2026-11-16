//! The deterministic commands: `replay` (gate mode), `coverage`, `cmin`, `tmin`.
//! None of them mutates anything and none depends on a clock or a seed; the only
//! time in play is the per-input timeout that turns a hang into a failure.

use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use serde_json::{Value, json};

use crate::dedup::{CrashKey, Exit, crash_key};
use crate::events::{ENGINE_NAME, EventLog, LIBAFL_VERSION};
use crate::runner::{Isolated, Outcome, Status};
use crate::sancov::{EdgeSpace, edge_space};
use crate::store::{CorpusStore, InputId, ManifestEntry, corpus_key_of, read_inputs};
use crate::symbols::{Lang, Model};
use crate::target::Target;

/// A loaded target together with its edge space and symbol model.
pub struct Session {
    pub target: Target,
    pub space: EdgeSpace,
    pub model: Model,
}

impl Session {
    pub fn load(path: &Path) -> Result<Self> {
        let target = Target::load(path)?;
        let space = edge_space()?;
        let model = Model::build(&space)?;
        Ok(Self { target, space, model })
    }

    pub fn isolated(&self) -> Result<Isolated<'_>> {
        Isolated::new(&self.target, &self.space)
    }

    /// `(edges_total, native_total, rust_total)`.
    pub fn totals(&self) -> (usize, usize, usize) {
        (self.space.total, self.model.native_edges_total, self.model.rust_edges_total)
    }

    pub fn key_of(&self, outcome: &Outcome) -> Option<CrashKey> {
        let (signal, timed_out) = match &outcome.status {
            Status::Ok => return None,
            Status::Timeout => (None, true),
            Status::Crash { signal, .. } => (signal.as_deref(), false),
        };
        let mut hasher = blake3::Hasher::new();
        for e in &outcome.edges {
            hasher.update(&e.to_le_bytes());
        }
        let sig = hasher.finalize().to_hex().to_string();
        let exit = Exit { signal, timed_out, coverage_signature: &sig };
        Some(crash_key(&outcome.stderr, &exit, &|pc| self.model.name_of_pc(pc)))
    }

    pub fn run_start_event(&self, mode: &str, seed: Option<u64>, extra: Value) -> Value {
        let (total, native, rust) = self.totals();
        let mut v = json!({
            "event": "run_start",
            "mode": mode,
            "engine": ENGINE_NAME,
            "engine_version": env!("CARGO_PKG_VERSION"),
            "libafl_version": LIBAFL_VERSION,
            "target": self.target.path.display().to_string(),
            "target_key": self.target.key,
            "target_variant": self.target.sidecar.variant,
            "target_asan": self.target.sidecar.asan,
            "seed": seed,
            "edges_total": total,
            "edges_total_native": native,
            "edges_total_rust": rust,
        });
        if let (Some(o), Some(e)) = (v.as_object_mut(), extra.as_object()) {
            for (k, val) in e {
                o.insert(k.clone(), val.clone());
            }
        }
        v
    }
}

fn split(model: &Model, edges: &BTreeSet<u32>) -> (usize, usize) {
    let v: Vec<u32> = edges.iter().copied().collect();
    model.count_split(&v)
}

// ---------------------------------------------------------------- replay

pub struct ReplayOptions {
    pub corpus: PathBuf,
    pub timeout: Duration,
    /// Wall-clock bound on the whole replay; exceeding it fails the gate as incomplete.
    pub max_total: Duration,
    pub cache_dir: Option<PathBuf>,
}

pub struct ReplayResult {
    pub pass: bool,
    pub cache_hit: bool,
}

/// Gate mode: every input in the corpus exactly once, in sorted order, each in its
/// own child. The verdict is a pure function of (target binary, corpus content), so
/// it is stored under that key and a second run with the same key returns the stored
/// verdict without executing anything.
pub fn replay(session: &Session, opts: &ReplayOptions, log: &EventLog) -> Result<ReplayResult> {
    let started = Instant::now();
    let mut inputs = read_inputs(&opts.corpus)?;
    inputs.sort_by(|a, b| a.0.cmp(&b.0));
    let ids: Vec<InputId> = inputs.iter().map(|(n, _)| InputId::parse(n)).collect::<Result<_>>()?;
    let corpus_key = corpus_key_of(&ids);
    let cache_key = blake3::hash(
        format!("keel-fuzz-replay-v1\0{}\0{}\0{}\0{}", session.target.key, corpus_key, env!("CARGO_PKG_VERSION"), opts.timeout.as_millis()).as_bytes(),
    )
    .to_hex()
    .to_string();

    log.emit(&session.run_start_event(
        "replay",
        None,
        json!({"corpus": opts.corpus.display().to_string(), "corpus_key": corpus_key, "cache_key": cache_key, "inputs": inputs.len()}),
    ))?;

    if let Some(dir) = &opts.cache_dir {
        let path = dir.join(format!("{cache_key}.json"));
        if let Ok(text) = std::fs::read_to_string(&path) {
            if let Ok(mut stored) = serde_json::from_str::<Value>(&text) {
                let pass = stored["result"] == "pass";
                stored["cache_hit"] = json!(true);
                stored["wall_ms"] = json!(started.elapsed().as_millis() as u64);
                log.emit(&stored)?;
                return Ok(ReplayResult { pass, cache_hit: true });
            }
        }
    }

    let isolated = session.isolated()?;
    let mut covered: BTreeSet<u32> = BTreeSet::new();
    let mut crashes: Vec<Value> = Vec::new();
    let mut incomplete = false;
    let mut executed = 0u64;
    for ((name, bytes), id) in inputs.iter().zip(&ids) {
        if started.elapsed() > opts.max_total {
            incomplete = true;
            break;
        }
        let outcome = isolated.run(bytes, opts.timeout)?;
        executed += 1;
        covered.extend(outcome.edges.iter().copied());
        let key = session.key_of(&outcome);
        log.emit(&json!({
            "event": "input", "id": name, "len": bytes.len(),
            "status": outcome.status.label(),
            "crash_key": key.as_ref().map(|k| k.key.clone()),
            "exec_us": outcome.elapsed.as_micros() as u64,
            "edges_hit": outcome.edges.len(),
        }))?;
        if let Some(key) = key {
            let entry = json!({"id": id.to_string(), "key": key.key, "kind": key.kind, "frames": key.frames, "source": key.source});
            log.emit(&json!({"event": "crash", "id": id.to_string(), "key": key.key, "kind": key.kind, "frames": key.frames, "source": key.source}))?;
            crashes.push(entry);
        }
    }
    let pass = crashes.is_empty() && !incomplete;
    let (total, total_native, _) = session.totals();
    let (n_cov, n_native) = split(&session.model, &covered);
    let wall = started.elapsed();
    let end = json!({
        "event": "run_end", "mode": "replay",
        "result": if incomplete { "incomplete" } else if pass { "pass" } else { "fail" },
        "executions": executed,
        "wall_ms": wall.as_millis() as u64,
        "exec_per_s": executed as f64 / wall.as_secs_f64().max(1e-9),
        "edges_covered": n_cov, "edges_total": total,
        "edges_covered_native": n_native, "edges_total_native": total_native,
        "crashes": crashes,
        "corpus_key": corpus_key, "cache_key": cache_key, "target_key": session.target.key,
        "engine": ENGINE_NAME, "engine_version": env!("CARGO_PKG_VERSION"),
        "cache_hit": false,
    });
    log.emit(&end)?;
    if !incomplete {
        if let Some(dir) = &opts.cache_dir {
            std::fs::create_dir_all(dir)?;
            std::fs::write(dir.join(format!("{cache_key}.json")), serde_json::to_vec(&end)?)
                .with_context(|| format!("writing the replay verdict into {}", dir.display()))?;
        }
    }
    Ok(ReplayResult { pass, cache_hit: false })
}

// -------------------------------------------------------------- coverage

pub struct CoverageOptions {
    pub input: PathBuf,
    pub timeout: Duration,
}

/// Runs each input once and reports the functions it executes, split by language.
pub fn coverage(session: &Session, opts: &CoverageOptions, log: &EventLog, quiet: bool) -> Result<()> {
    let inputs = read_inputs(&opts.input)?;
    log.emit(&session.run_start_event("coverage", None, json!({"input": opts.input.display().to_string(), "inputs": inputs.len()})))?;
    let isolated = session.isolated()?;
    let mut union: BTreeSet<u32> = BTreeSet::new();
    for (name, bytes) in &inputs {
        let outcome = isolated.run(bytes, opts.timeout)?;
        union.extend(outcome.edges.iter().copied());
        let funcs = session.model.covered_functions(&outcome.edges);
        let (n, native) = session.model.count_split(&outcome.edges);
        log.emit(&json!({
            "event": "input_coverage", "id": name, "len": bytes.len(), "status": outcome.status.label(),
            "edges_hit": n, "edges_hit_native": native, "edges_hit_rust": n - native,
            "functions": funcs,
        }))?;
        if !quiet {
            println!("{} ({} bytes, {}): {} edges ({} native, {} rust), {} functions", &name[..12.min(name.len())], bytes.len(), outcome.status.label(), n, native, n - native, funcs.len());
            for f in &funcs {
                let side = match f.lang {
                    Lang::Rust => "rust  ",
                    Lang::Native => "native",
                };
                println!("  {side} {:>3}/{:<3} {}", f.edges_hit, f.edges_total, f.function);
            }
        }
    }
    let funcs: Vec<_> = session.model.covered_functions(&union.iter().copied().collect::<Vec<_>>());
    let (n, native) = split(&session.model, &union);
    log.emit(&json!({
        "event": "run_end", "mode": "coverage",
        "inputs": inputs.len(), "edges_covered": n, "edges_total": session.space.total,
        "edges_covered_native": native, "edges_total_native": session.model.native_edges_total,
        "functions_covered": funcs.len(),
        "functions_covered_native": funcs.iter().filter(|f| f.lang == Lang::Native).count(),
        "functions_covered_rust": funcs.iter().filter(|f| f.lang == Lang::Rust).count(),
    }))?;
    if !quiet && inputs.len() > 1 {
        println!("union: {n} of {} edges ({native} native), {} functions", session.space.total, funcs.len());
    }
    Ok(())
}

// ------------------------------------------------------------------ cmin

pub struct CminOptions {
    pub corpus: PathBuf,
    pub out: PathBuf,
    pub timeout: Duration,
}

/// Corpus minimisation: the smallest set of inputs (greedy set cover) whose union
/// covers every edge the whole corpus covers. Inputs that crash are left out; a
/// crash belongs in the gate set, not in the coverage corpus.
pub fn cmin(session: &Session, opts: &CminOptions, log: &EventLog) -> Result<()> {
    let started = Instant::now();
    let inputs = read_inputs(&opts.corpus)?;
    log.emit(&session.run_start_event("cmin", None, json!({"corpus": opts.corpus.display().to_string(), "inputs": inputs.len()})))?;
    let isolated = session.isolated()?;
    struct Cand {
        id: InputId,
        bytes: Vec<u8>,
        edges: BTreeSet<u32>,
    }
    let mut cands: Vec<Cand> = Vec::new();
    let mut all: BTreeSet<u32> = BTreeSet::new();
    let mut skipped = 0usize;
    for (name, bytes) in inputs.iter() {
        let outcome = isolated.run(bytes, opts.timeout)?;
        if !outcome.status.is_ok() {
            skipped += 1;
            continue;
        }
        all.extend(outcome.edges.iter().copied());
        cands.push(Cand { id: InputId::parse(name)?, bytes: bytes.clone(), edges: outcome.edges.into_iter().collect() });
    }
    let store = CorpusStore::open(&opts.out)?;
    let mut remaining = all.clone();
    let mut kept = 0usize;
    let mut covered: BTreeSet<u32> = BTreeSet::new();
    while !remaining.is_empty() {
        // Most new edges first; ties go to the shortest input, then the smallest id,
        // so the result is a function of the corpus content alone.
        let best = cands
            .iter()
            .enumerate()
            .map(|(i, c)| (c.edges.intersection(&remaining).count(), i))
            .filter(|(n, _)| *n > 0)
            .max_by(|a, b| {
                let (ca, cb) = (&cands[a.1], &cands[b.1]);
                a.0.cmp(&b.0).then(cb.bytes.len().cmp(&ca.bytes.len())).then(cb.id.cmp(&ca.id))
            });
        let Some((_, i)) = best else { break };
        let c = cands.swap_remove(i);
        let new_edges: Vec<u32> = c.edges.iter().copied().filter(|e| !covered.contains(e)).collect();
        covered.extend(c.edges.iter().copied());
        for e in &c.edges {
            remaining.remove(e);
        }
        let (id, _) = store.put(&c.bytes)?;
        store.append_manifest(&ManifestEntry {
            id,
            len: c.bytes.len(),
            target_key: session.target.key.clone(),
            origin: "cmin".into(),
            new_edges,
            edges_covered_after: covered.len() as u32,
            found_ms: started.elapsed().as_millis() as u64,
            execs: 0,
            seed: None,
        })?;
        kept += 1;
    }
    if covered != all {
        bail!("cmin lost coverage ({} of {} edges kept); this is a bug in keel-fuzz, please report the corpus", covered.len(), all.len());
    }
    let (n_all, nat_all) = split(&session.model, &all);
    log.emit(&json!({
        "event": "run_end", "mode": "cmin",
        "inputs_before": inputs.len(), "inputs_after": kept, "inputs_skipped_crashing": skipped,
        "edges_covered_before": n_all, "edges_covered_after": covered.len(),
        "edges_covered_native": nat_all, "edges_total": session.space.total,
        "out": opts.out.display().to_string(),
        "wall_ms": started.elapsed().as_millis() as u64,
    }))?;
    println!("cmin: {} inputs -> {kept}; edges covered {} -> {} (all preserved)", inputs.len(), n_all, covered.len());
    Ok(())
}

// ------------------------------------------------------------------ tmin

pub struct TminOptions {
    pub input: PathBuf,
    pub out: PathBuf,
    pub timeout: Duration,
    /// Upper bound on trial executions.
    pub max_trials: usize,
}

/// Crash minimisation. A candidate is accepted only if it crashes with the same
/// dedup key as the original, so minimisation cannot slide from one bug to another.
pub fn tmin(session: &Session, opts: &TminOptions, log: &EventLog) -> Result<()> {
    let original = std::fs::read(&opts.input).with_context(|| format!("reading {}", opts.input.display()))?;
    let isolated = session.isolated()?;
    let first = isolated.run(&original, opts.timeout)?;
    let Some(want) = session.key_of(&first) else {
        bail!("{} does not crash this target (it ran to completion); tmin only minimises crashing inputs: check that --target is the build that crashed", opts.input.display());
    };
    log.emit(&session.run_start_event("tmin", None, json!({"input": opts.input.display().to_string(), "len": original.len(), "crash_key": want.key})))?;
    let started = Instant::now();
    let trials_cell = std::cell::Cell::new(0usize);
    let same = |candidate: &[u8]| -> Result<bool> {
        trials_cell.set(trials_cell.get() + 1);
        let o = isolated.run(candidate, opts.timeout)?;
        Ok(session.key_of(&o).is_some_and(|k| k.key == want.key))
    };
    let trials = || trials_cell.get();
    let mut cur = original.clone();
    // Pass 1: drop chunks, large to small, until a full pass at chunk size 1 removes nothing.
    let mut chunk = cur.len().next_power_of_two() / 2;
    while chunk >= 1 && trials() < opts.max_trials {
        let mut i = 0;
        let mut removed_any = false;
        while i < cur.len() && trials() < opts.max_trials {
            let end = (i + chunk).min(cur.len());
            let mut cand = cur.clone();
            cand.drain(i..end);
            if same(&cand)? {
                cur = cand;
                removed_any = true;
            } else {
                i += chunk;
            }
        }
        if chunk == 1 && !removed_any {
            break;
        }
        if chunk > 1 {
            chunk /= 2;
        }
    }
    // Pass 2: simplify the bytes that must stay. Zero is the most compressible value
    // and the one a reader can skip over when looking at the minimised input.
    for i in 0..cur.len() {
        if trials() >= opts.max_trials {
            break;
        }
        if cur[i] != 0 {
            let mut cand = cur.clone();
            cand[i] = 0;
            if same(&cand)? {
                cur = cand;
            }
        }
    }
    std::fs::write(&opts.out, &cur).with_context(|| format!("writing {}", opts.out.display()))?;
    let id = InputId::of(&cur);
    log.emit(&json!({
        "event": "run_end", "mode": "tmin",
        "crash_key": want.key, "kind": want.kind, "frames": want.frames,
        "len_before": original.len(), "len_after": cur.len(), "trials": trials(),
        "minimised_id": id.to_string(), "out": opts.out.display().to_string(),
        "wall_ms": started.elapsed().as_millis() as u64,
    }))?;
    println!("tmin: {} -> {} bytes in {} trials (crash key {}, {})", original.len(), cur.len(), trials(), want.key, want.kind);
    Ok(())
}

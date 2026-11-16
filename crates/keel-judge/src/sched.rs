//! The index and the choice of the next target.

use std::collections::BTreeMap;
use std::fs::File;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant, SystemTime};

use anyhow::{Context, Result};

use crate::findings::{self, Scan};
use crate::metrics::{self, Snapshot};
use crate::state::{ChosenBy, Jsonl, Outcome, Quantum, State, TargetStats, findings_path, quanta_path};
use crate::targets::Target;

/// The target's rate of new features per second:
/// `(Σ wᵢ Δftᵢ + 1) / (Σ wᵢ sᵢ + Q)` over its previous quanta, `wᵢ = 2^(−ageᵢ/4)`, age 0
/// being the most recent. The `+ 1` and `+ Q` are a prior of one feature per quantum, so a
/// target never run has rate `1/Q` instead of 0 and is not starved by its own lack of data.
///
/// With the rank this is the fuzz index of doubt.md §5.6, Û × exec/s of §5.5, estimated
/// from libFuzzer's feature counter: libFuzzer does not expose the per-feature singleton
/// counts f₁ that Good–Turing needs, so new features per second stands in for f₁/n × exec/s.
///
/// `hist` holds `(seconds, Δft)` oldest first.
pub fn rate<'a>(hist: impl IntoIterator<Item = &'a (f64, f64)>, q: f64) -> f64 {
    let hist: Vec<_> = hist.into_iter().collect();
    let (mut dft, mut secs) = (0.0, 0.0);
    for (i, (s, d)) in hist.iter().rev().enumerate() {
        let w = 2f64.powf(-(i as f64) / 4.0);
        dft += w * d;
        secs += w * s;
    }
    (dft + 1.0) / (secs + q)
}

pub fn index(rank: u64, rate: f64) -> f64 {
    rank as f64 * rate
}

#[derive(Debug, Clone)]
pub struct Candidate {
    pub idx: usize,
    pub start_order: u64,
    pub quanta: u64,
    pub last_seq: u64,
    pub rank: u64,
    pub rate: f64,
    pub index: f64,
    pub busy: bool,
}

/// Applies the picking rules to the eligible targets. A target another worker is running
/// is never picked: two instances on one corpus could both run a target that the first
/// one's crash is about to block, and with a real libFuzzer build the second did
/// (2026-11-15). With more workers than eligible targets the extra workers wait.
///
/// `seq` is this quantum's position over all quanta ever picked. Every `starve_every`-th
/// goes to the least recently served, so rank-0 targets still run.
pub fn choose(cands: &[Candidate], seq: u64, starve_every: u64) -> Option<(usize, ChosenBy)> {
    let pool: Vec<&Candidate> = cands.iter().filter(|c| !c.busy).collect();
    if let Some(c) = pool.iter().filter(|c| c.quanta == 0).min_by_key(|c| (c.start_order, c.idx)) {
        return Some((c.idx, ChosenBy::Cold));
    }
    let least_recent = |a: &&&Candidate, b: &&&Candidate| (a.last_seq, a.start_order, a.idx).cmp(&(b.last_seq, b.start_order, b.idx));
    if starve_every > 0 && seq.is_multiple_of(starve_every) {
        return pool.iter().min_by(least_recent).map(|c| (c.idx, ChosenBy::Starved));
    }
    // Greatest index; a tie (all rank 0, say) goes to the least recently served.
    pool.iter()
        .min_by(|a, b| b.index.total_cmp(&a.index).then_with(|| least_recent(a, b)))
        .map(|c| (c.idx, ChosenBy::Index))
}

/// Blake3 of the bytes of argv[0] after resolving symlinks. For the Nix wrapper script
/// this changes whenever the engine store path inside it does. Re-hashed only when the
/// resolved file's size or mtime changes.
#[derive(Default)]
struct IdentityCache {
    seen: Option<(PathBuf, u64, SystemTime, String)>,
}

impl IdentityCache {
    fn get(&mut self, argv0: &str) -> Result<String> {
        let resolved = std::fs::canonicalize(argv0)
            .with_context(|| format!("cannot resolve {argv0} (argv[0] of a target, the binary whose identity decides eligibility); build it or fix the targets file"))?;
        let meta = std::fs::metadata(&resolved).with_context(|| format!("cannot stat {} (resolved argv[0] of a target)", resolved.display()))?;
        let key = (meta.len(), meta.modified().unwrap_or(SystemTime::UNIX_EPOCH));
        if let Some((p, len, m, id)) = &self.seen
            && *p == resolved
            && (*len, *m) == key
        {
            return Ok(id.clone());
        }
        let mut h = blake3::Hasher::new();
        h.update_reader(File::open(&resolved).with_context(|| format!("cannot read {} (resolved argv[0] of a target): check its permissions", resolved.display()))?)?;
        let id = h.finalize().to_hex().to_string();
        self.seen = Some((resolved, key.0, key.1, id.clone()));
        Ok(id)
    }
}

/// A picked quantum, held until its record is appended or the pick is released.
#[derive(Debug, Clone)]
pub struct Claim {
    pub idx: usize,
    pub seq: u64,
    pub target: Target,
    pub identity: String,
    pub chosen_by: ChosenBy,
    pub rank: u64,
    pub rate: f64,
    pub index: f64,
}

pub enum Pick {
    Run(Box<Claim>),
    /// Nothing can be picked now (each target is running on another worker, blocked by a
    /// finding, or unreadable); try again later.
    Idle,
    /// The `--quanta` budget is spent.
    Done,
}

pub struct Config {
    pub quantum_s: f64,
    pub starve_every: u64,
    pub limit: Option<u64>,
}

/// The longest a faulted target is left alone.
const FAULT_BACKOFF_CAP: Duration = Duration::from_secs(3600);

/// How long a target is ineligible after its `consecutive`-th fault in a row: one quantum
/// after the first, doubling, so a broken one costs a few lines an hour and a repaired one
/// is back within the cap.
pub fn fault_backoff(quantum_s: f64, consecutive: u32) -> Duration {
    let doublings = consecutive.saturating_sub(1).min(32) as i32;
    Duration::from_secs_f64((quantum_s * 2f64.powi(doublings)).min(FAULT_BACKOFF_CAP.as_secs_f64()))
}

/// What a target's faults look like now. In memory only: a restart forgets them, and the
/// first quantum after it finds out again.
#[derive(Debug, Default, Clone)]
struct FaultState {
    consecutive: u32,
    total: u64,
    retry_at: Option<Instant>,
    last_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetFault {
    pub target: String,
    /// Faults since the last quantum of this target that completed.
    pub consecutive: u32,
    /// Faults since this process started.
    pub total: u64,
    /// The target is waiting out its backoff.
    pub faulted_now: bool,
    /// The newest fault's message; kept after the target recovers.
    pub last_error: Option<String>,
}

pub struct Sched {
    pub state: State,
    targets: Vec<Target>,
    idents: Vec<IdentityCache>,
    warned: Vec<bool>,
    busy: Vec<bool>,
    faults: Vec<FaultState>,
    state_dir: PathBuf,
    quanta_log: Jsonl,
    findings_log: Jsonl,
    cfg: Config,
    next_seq: u64,
    claimed: u64,
    pub finished: u64,
}

impl Sched {
    pub fn new(state_dir: &Path, state: State, targets: Vec<Target>, cfg: Config) -> Result<Sched> {
        Sched::new_at(state_dir, state, targets, cfg, Instant::now(), crate::util::unix_now())
    }

    fn new_at(state_dir: &Path, state: State, targets: Vec<Target>, cfg: Config, now: Instant, unix_now: f64) -> Result<Sched> {
        let n = targets.len();
        // The backoff of a target whose last quanta ended in error is rebuilt from the log,
        // counted from when its last quantum ended: in memory alone, every restart (five in
        // BENCH §6.16's soak) gave such a target a new run of short waits. Faults that leave
        // no quantum (a directory the supervisor cannot use) are found again at once anyway.
        let faults = targets
            .iter()
            .map(|t| {
                let Some(st) = state.stats.get(&t.id).filter(|st| st.trailing_errors > 0) else { return FaultState::default() };
                let wait = fault_backoff(cfg.quantum_s, st.trailing_errors);
                let left = st.last_end.map_or(wait.as_secs_f64(), |end| end + wait.as_secs_f64() - unix_now).max(0.0);
                FaultState {
                    consecutive: st.trailing_errors,
                    total: 0,
                    retry_at: (left > 0.0).then(|| now + Duration::from_secs_f64(left)),
                    last_error: Some(format!("its last {} quanta before this start ended in error", st.trailing_errors)),
                }
            })
            .collect();
        Ok(Sched {
            next_seq: state.max_seq + 1,
            state,
            idents: (0..n).map(|_| IdentityCache::default()).collect(),
            warned: vec![false; n],
            busy: vec![false; n],
            faults,
            targets,
            quanta_log: Jsonl::open(&quanta_path(state_dir))?,
            findings_log: Jsonl::open(&findings_path(state_dir))?,
            state_dir: state_dir.to_path_buf(),
            cfg,
            claimed: 0,
            finished: 0,
        })
    }

    pub fn quantum_s(&self) -> f64 {
        self.cfg.quantum_s
    }

    /// Every target's fault counters, in targets-file order, for the metrics.
    pub fn faults(&self) -> Vec<TargetFault> {
        self.faults_at(Instant::now())
    }

    fn faults_at(&self, now: Instant) -> Vec<TargetFault> {
        self.targets
            .iter()
            .zip(&self.faults)
            .map(|(t, f)| TargetFault {
                target: t.id.clone(),
                consecutive: f.consecutive,
                total: f.total,
                faulted_now: f.retry_at.is_some_and(|at| now < at),
                last_error: f.last_error.clone(),
            })
            .collect()
    }

    pub fn pick(&mut self) -> Pick {
        self.pick_at(Instant::now())
    }

    fn pick_at(&mut self, now: Instant) -> Pick {
        if self.cfg.limit.is_some_and(|k| self.claimed >= k) {
            return Pick::Done;
        }
        let empty = TargetStats::default();
        let mut cands = Vec::new();
        let mut identities = Vec::new();
        for (i, t) in self.targets.iter().enumerate() {
            if self.faults[i].retry_at.is_some_and(|at| now < at) {
                identities.push(String::new());
                continue;
            }
            let id = match self.idents[i].get(&t.argv[0]) {
                Ok(id) => {
                    self.warned[i] = false;
                    id
                }
                Err(e) => {
                    if !self.warned[i] {
                        eprintln!("keel-judge: target {} is not eligible: {e:#}", t.id);
                        self.warned[i] = true;
                    }
                    identities.push(String::new());
                    continue;
                }
            };
            identities.push(id.clone());
            if self.state.findings.is_blocked(&t.id, &id) {
                continue;
            }
            let st = self.state.stats.get(&t.id).unwrap_or(&empty);
            let r = rate(&st.hist, self.cfg.quantum_s);
            cands.push(Candidate {
                idx: i,
                start_order: t.start_order,
                quanta: st.quanta,
                last_seq: st.last_seq,
                rank: t.rank,
                rate: r,
                index: index(t.rank, r),
                busy: self.busy[i],
            });
        }
        let seq = self.next_seq;
        let Some((idx, chosen_by)) = choose(&cands, seq, self.cfg.starve_every) else { return Pick::Idle };
        let c = cands.iter().find(|c| c.idx == idx).expect("chosen from cands");
        self.busy[idx] = true;
        self.claimed += 1;
        self.next_seq += 1;
        Pick::Run(Box::new(Claim {
            idx,
            seq,
            target: self.targets[idx].clone(),
            identity: identities[idx].clone(),
            chosen_by,
            rank: c.rank,
            rate: c.rate,
            index: c.index,
        }))
    }

    /// Gives a pick back without recording anything (disk low, or stopping).
    pub fn release(&mut self, claim: &Claim) {
        self.busy[claim.idx] = false;
        self.claimed -= 1;
    }

    /// Gives a pick back after its quantum failed for a reason that is the target's, not the
    /// logs' (its directory is gone, it would not start): the pick does not count toward
    /// `--quanta`, and the target sits out `fault_backoff` while the others go on. Returns
    /// that wait.
    pub fn fault(&mut self, claim: &Claim, err: &anyhow::Error) -> Duration {
        self.release(claim);
        self.mark_faulted(claim.idx, err, Instant::now())
    }

    /// The same for a target that could not be prepared at startup, before any pick.
    pub fn fault_at_start(&mut self, idx: usize, err: &anyhow::Error) -> Duration {
        self.mark_faulted(idx, err, Instant::now())
    }

    fn mark_faulted(&mut self, idx: usize, err: &anyhow::Error, now: Instant) -> Duration {
        let f = &mut self.faults[idx];
        f.consecutive = f.consecutive.saturating_add(1);
        f.total += 1;
        f.last_error = Some(format!("{err:#}"));
        let wait = fault_backoff(self.cfg.quantum_s, f.consecutive);
        f.retry_at = Some(now + wait);
        wait
    }

    /// Records the finished quantum: findings first, so a crash between the two leaves a
    /// blocked target rather than a quantum with a finding nobody wrote down.
    pub fn complete(&mut self, claim: &Claim, rec: Quantum, scan: &Scan<'_>) -> Result<Option<String>> {
        self.complete_at(claim, rec, scan, Instant::now())
    }

    fn complete_at(&mut self, claim: &Claim, mut rec: Quantum, scan: &Scan<'_>, now: Instant) -> Result<Option<String>> {
        let noted = findings::record(&mut self.state.findings, &mut self.findings_log, &self.state_dir, claim, scan)?;
        rec.finding = noted.key;
        rec.slow_units = noted.slow_units;
        self.quanta_log.append(&rec)?;
        self.state.apply_quantum(&rec);
        self.busy[claim.idx] = false;
        self.finished += 1;
        if rec.outcome == Outcome::Error {
            // Recorded, but the target did not fuzz: it would not start, left on its own, or
            // ignored SIGINT for the whole grace. Backed off like a fault, or it takes a worker
            // on every starve turn: in the soak of 2026-11-15 a target that ignored SIGINT
            // held 19.7% of all fuzz time and found nothing.
            let exit = match (rec.exit.code, rec.exit.signal) {
                (Some(c), _) => format!("exit code {c}"),
                (None, Some(s)) => format!("signal {}", crate::quantum::signal_name(s)),
                (None, None) => "no exit status".to_owned(),
            };
            let why = anyhow::anyhow!("its quantum ended in error ({exit}, stopped by {:?}); read {}", rec.stopped_by, rec.log);
            let wait = self.mark_faulted(claim.idx, &why, now);
            eprintln!("keel-judge: target {} {why:#}; skipping it for {} s, then trying it again; the other targets go on", rec.target, wait.as_secs());
        } else {
            let f = &mut self.faults[claim.idx];
            f.consecutive = 0;
            f.retry_at = None;
        }
        Ok(rec.finding)
    }

    /// What the metrics file reports; the caller adds what only it knows. A target whose
    /// binary cannot be read has no `blocked` value: nothing says which build it would run.
    pub fn snapshot(&mut self) -> Snapshot {
        let mut blocked = BTreeMap::new();
        for (i, t) in self.targets.iter().enumerate() {
            if let Ok(id) = self.idents[i].get(&t.argv[0]) {
                blocked.insert(t.id.clone(), self.state.findings.is_blocked(&t.id, &id));
            }
        }
        let mut s = metrics::collect(&self.state, Some(&self.targets), Some(self.cfg.quantum_s), &blocked);
        s.workers_busy = self.busy.iter().filter(|b| **b).count() as u64;
        for f in self.faults() {
            if let Some(t) = s.targets.iter_mut().find(|t| t.id == f.target) {
                t.faulted = f.faulted_now;
                t.faults_total = f.total;
            }
        }
        s
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn cand(idx: usize, start_order: u64, quanta: u64, last_seq: u64, rank: u64, busy: bool) -> Candidate {
        let r = rate(&[], 60.0);
        Candidate { idx, start_order, quanta, last_seq, rank, rate: r, index: index(rank, r), busy }
    }

    #[test]
    fn a_target_never_run_has_the_prior_rate_one_per_quantum() {
        assert!((rate(&[], 60.0) - 1.0 / 60.0).abs() < 1e-12);
        assert!((index(27_750, rate(&[], 60.0)) - 462.5).abs() < 1e-9);
    }

    #[test]
    fn rate_weights_recent_quanta_by_two_to_the_minus_age_over_four() {
        // One quantum: (3 + 1) / (60 + 60).
        assert!((rate(&[(60.0, 3.0)], 60.0) - 4.0 / 120.0).abs() < 1e-12);
        // Two: the older one (age 1) is weighted 2^(-1/4).
        let w = 2f64.powf(-0.25);
        let want = (5.0 + w * 3.0 + 1.0) / (60.0 + w * 60.0 + 60.0);
        assert!((rate(&[(60.0, 3.0), (60.0, 5.0)], 60.0) - want).abs() < 1e-12);
        // A partial quantum counts for its own seconds only.
        assert!((rate(&[(15.0, 0.0)], 60.0) - 1.0 / 75.0).abs() < 1e-12);
    }

    #[test]
    fn cold_targets_go_first_in_start_order() {
        let c = [cand(0, 3, 0, 0, 10, false), cand(1, 1, 0, 0, 5, false), cand(2, 2, 4, 9, 99, false)];
        assert_eq!(choose(&c, 1, 10), Some((1, ChosenBy::Cold)));
        // Cold beats the starve turn.
        assert_eq!(choose(&c, 10, 10), Some((1, ChosenBy::Cold)));
    }

    #[test]
    fn every_nth_quantum_goes_to_the_least_recently_served() {
        let c = [cand(0, 1, 5, 40, 1000, false), cand(1, 2, 5, 12, 0, false), cand(2, 3, 5, 30, 500, false)];
        assert_eq!(choose(&c, 9, 10), Some((0, ChosenBy::Index)));
        assert_eq!(choose(&c, 10, 10), Some((1, ChosenBy::Starved)));
        assert_eq!(choose(&c, 20, 10), Some((1, ChosenBy::Starved)));
    }

    #[test]
    fn otherwise_the_greatest_index_and_ties_go_to_the_least_recent() {
        let mut c = [cand(0, 1, 5, 40, 100, false), cand(1, 2, 5, 12, 200, false)];
        assert_eq!(choose(&c, 3, 10), Some((1, ChosenBy::Index)));
        c[0].index = c[1].index;
        assert_eq!(choose(&c, 3, 10), Some((1, ChosenBy::Index)));
        let zero = [cand(0, 1, 5, 40, 0, false), cand(1, 2, 5, 12, 0, false)];
        assert_eq!(choose(&zero, 3, 10), Some((1, ChosenBy::Index)));
    }

    #[test]
    fn a_busy_target_is_never_picked_twice() {
        let c = [cand(0, 1, 5, 40, 1000, true), cand(1, 2, 5, 12, 10, false)];
        assert_eq!(choose(&c, 3, 10), Some((1, ChosenBy::Index)));
        let all = [cand(0, 1, 5, 40, 1000, true), cand(1, 2, 5, 12, 10, true)];
        assert_eq!(choose(&all, 3, 10), None);
        // A cold target another worker is already running is not picked twice.
        let cold = [cand(0, 1, 0, 0, 1000, true), cand(1, 2, 5, 12, 10, false)];
        assert_eq!(choose(&cold, 3, 10), Some((1, ChosenBy::Index)));
        assert_eq!(choose(&[], 3, 10), None);
    }

    #[test]
    fn a_target_with_an_open_finding_is_skipped_until_its_identity_changes() {
        use std::os::unix::fs::PermissionsExt;
        let dir = tempfile::tempdir().unwrap();
        let bin = |name: &str, body: &str| {
            let p = dir.path().join(name);
            std::fs::write(&p, body).unwrap();
            std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
            p.display().to_string()
        };
        let target = |id: &str, argv0: String, rank, start_order| Target {
            id: id.into(),
            name: id.into(),
            rank,
            start_order,
            complexity: None,
            gap: None,
            blast: None,
            argv: vec![argv0],
            corpus: dir.path().join(id).join("corpus").display().to_string(),
            artifacts: dir.path().join(id).join("artifacts").display().to_string(),
        };
        let a1 = bin("a-v1", "#!/bin/sh\n# v1\n");
        let b = bin("b", "#!/bin/sh\n");
        let mut state = State::default();
        state.findings.apply(&crate::state::FindingRecord {
            schema: crate::state::FINDING_SCHEMA.into(),
            target: "a".into(),
            key: "k".into(),
            kind: "rust-panic".into(),
            frames: vec![],
            source: "panic".into(),
            identity: blake3::hash(b"#!/bin/sh\n# v1\n").to_hex().to_string(),
            first_seen: Some("t".into()),
            seen_again: None,
            input: None,
        });
        // `a` is a symlink, as bundle/bin/fuzz-<id> is; the identity is of the resolved bytes.
        let link = dir.path().join("a-link");
        std::os::unix::fs::symlink(&a1, &link).unwrap();
        let targets = vec![target("a", link.display().to_string(), 1000, 1), target("b", b, 1, 2)];
        let cfg = Config { quantum_s: 60.0, starve_every: 1000, limit: None };
        let mut s = Sched::new(dir.path(), state, targets, cfg).unwrap();
        // b is cold too, but a is blocked, so b is the only possible pick, repeatedly.
        for _ in 0..3 {
            match s.pick() {
                Pick::Run(c) => {
                    assert_eq!(c.target.id, "b");
                    s.release(&c);
                }
                _ => panic!("expected b"),
            }
        }
        // A new build behind the same path: a becomes eligible and, cold, goes first.
        let a2 = bin("a-v2", "#!/bin/sh\n# v2\n");
        std::fs::remove_file(&link).unwrap();
        std::os::unix::fs::symlink(&a2, &link).unwrap();
        match s.pick() {
            Pick::Run(c) => assert_eq!((c.target.id.as_str(), c.chosen_by), ("a", ChosenBy::Cold)),
            _ => panic!("expected a"),
        }
    }

    fn two_targets(dir: &Path, limit: Option<u64>) -> Sched {
        let target = |id: &str, rank, start_order| {
            let bin = dir.join(format!("{id}-bin"));
            std::fs::write(&bin, id).unwrap();
            Target {
                id: id.into(),
                name: id.into(),
                rank,
                start_order,
                complexity: None,
                gap: None,
                blast: None,
                argv: vec![bin.display().to_string()],
                corpus: String::new(),
                artifacts: String::new(),
            }
        };
        let cfg = Config { quantum_s: 60.0, starve_every: 1000, limit };
        Sched::new(dir, State::default(), vec![target("a", 1000, 1), target("b", 1, 2)], cfg).unwrap()
    }

    fn picked(s: &mut Sched, now: Instant) -> Option<String> {
        match s.pick_at(now) {
            Pick::Run(c) => {
                s.release(&c);
                s.claimed += 1; // keep the count as a running pick would
                Some(c.target.id)
            }
            _ => None,
        }
    }

    #[test]
    fn a_fault_backs_off_by_a_quantum_doubling_to_an_hour() {
        let secs = |n| fault_backoff(60.0, n).as_secs();
        assert_eq!([secs(1), secs(2), secs(3), secs(4)], [60, 120, 240, 480]);
        assert_eq!([secs(6), secs(7), secs(8), secs(1000), secs(u32::MAX)], [1920, 3600, 3600, 3600, 3600]);
        // Zero is not a fault yet; it must not underflow.
        assert_eq!(secs(0), 60);
        // A quantum longer than the cap is capped too.
        assert_eq!(fault_backoff(7200.0, 1).as_secs(), 3600);
    }

    #[test]
    fn a_faulted_target_is_skipped_until_its_backoff_passes_and_the_pick_is_not_counted() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = two_targets(dir.path(), Some(1));
        let t0 = Instant::now();
        let Pick::Run(a) = s.pick_at(t0) else { panic!("a goes first") };
        assert_eq!(a.target.id, "a");
        assert_eq!(s.claimed, 1);
        let err = anyhow::anyhow!("cannot read the artifacts");
        s.release(&a);
        let wait = s.mark_faulted(a.idx, &err, t0);
        assert_eq!(wait, Duration::from_secs(60));
        assert_eq!(s.claimed, 0, "a faulted pick must not spend --quanta");
        // While it waits, b is the only candidate: this is isolation, not a stop.
        assert_eq!(picked(&mut s, t0 + Duration::from_secs(59)).as_deref(), Some("b"));
        let f = s.faults_at(t0 + Duration::from_secs(59));
        assert_eq!((f[0].consecutive, f[0].total, f[0].faulted_now), (1, 1, true));
        assert_eq!(f[0].last_error.as_deref(), Some("cannot read the artifacts"));
        assert_eq!((f[1].consecutive, f[1].faulted_now, f[1].last_error.clone()), (0, false, None));
        // The wait is over: a is eligible and, ranked higher, goes first again.
        let later = t0 + Duration::from_secs(60);
        assert!(!s.faults_at(later)[0].faulted_now);
        s.claimed = 0;
        assert_eq!(picked(&mut s, later).as_deref(), Some("a"));
    }

    #[test]
    fn faults_in_a_row_double_and_a_completed_quantum_resets_the_count() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = two_targets(dir.path(), None);
        let t0 = Instant::now();
        let err = anyhow::anyhow!("boom").context("cannot start x");
        for want in [60, 120, 240] {
            assert_eq!(s.mark_faulted(0, &err, t0).as_secs(), want);
        }
        assert_eq!(s.faults_at(t0)[0].last_error.as_deref(), Some("cannot start x: boom"));
        assert_eq!((s.faults_at(t0)[0].consecutive, s.faults_at(t0)[0].total), (3, 3));
        // A quantum that completes (here the claim is made by hand) resets the run of faults, not the total.
        let Pick::Run(a) = s.pick_at(t0 + Duration::from_secs(300)) else { panic!() };
        assert_eq!(a.target.id, "a");
        let rec = crate::state::tests::quantum("a", a.seq, 1.0, 0);
        let scan = Scan { artifacts_dir: dir.path(), files: &[], outcome: crate::state::Outcome::Ok, exit: &Default::default(), log_lines: &[] };
        s.complete(&a, rec, &scan).unwrap();
        let f = &s.faults_at(t0 + Duration::from_secs(300))[0];
        assert_eq!((f.consecutive, f.total, f.faulted_now), (0, 3, false));
        assert_eq!(s.mark_faulted(0, &err, t0).as_secs(), 60, "the backoff starts over");
        // A fault at startup is the same one.
        assert_eq!(s.fault_at_start(1, &err).as_secs(), 60);
        assert!(s.faults()[1].faulted_now);
    }

    #[test]
    fn a_quantum_that_ends_in_error_backs_its_target_off_and_a_good_one_resets_it() {
        let dir = tempfile::tempdir().unwrap();
        let mut s = two_targets(dir.path(), None);
        let mut now = Instant::now();
        let run = |s: &mut Sched, now: Instant, id: &str, outcome| {
            let Pick::Run(c) = s.pick_at(now) else { panic!("{id} should be free") };
            assert_eq!(c.target.id, id);
            let mut rec = crate::state::tests::quantum(id, c.seq, 25.0, 0);
            rec.outcome = outcome;
            let scan = Scan { artifacts_dir: dir.path(), files: &[], outcome, exit: &Default::default(), log_lines: &[] };
            s.complete_at(&c, rec, &scan, now).unwrap();
        };
        run(&mut s, now, "a", Outcome::Error);
        let f = &s.faults_at(now)[0];
        assert!(f.faulted_now && f.consecutive == 1, "{f:?}");
        assert!(f.last_error.as_deref().is_some_and(|e| e.contains("ended in error")), "{f:?}");
        // While it waits the other target runs, so no worker sleeps on its account.
        run(&mut s, now + Duration::from_secs(59), "b", Outcome::Ok);
        now += Duration::from_secs(60);
        run(&mut s, now, "a", Outcome::Error);
        assert!(s.faults_at(now + Duration::from_secs(119))[0].faulted_now, "the second error in a row waits two quanta");
        now += Duration::from_secs(120);
        run(&mut s, now, "a", Outcome::Ok);
        let f = &s.faults_at(now)[0];
        assert_eq!((f.consecutive, f.total, f.faulted_now), (0, 2, false));
    }

    #[test]
    fn a_restart_keeps_the_backoff_of_a_target_whose_last_quanta_ended_in_error() {
        let dir = tempfile::tempdir().unwrap();
        let target = |id: &str| {
            let bin = dir.path().join(format!("{id}-bin"));
            std::fs::write(&bin, id).unwrap();
            Target {
                id: id.into(),
                name: id.into(),
                rank: 1,
                start_order: 1,
                complexity: None,
                gap: None,
                blast: None,
                argv: vec![bin.display().to_string()],
                corpus: String::new(),
                artifacts: String::new(),
            }
        };
        let mut st = State::default();
        let q = |id: &str, seq, outcome| {
            let mut q = crate::state::tests::quantum(id, seq, 25.0, 0);
            q.outcome = outcome;
            q
        };
        // a: one good quantum, then two in error; b: an error, then a good one.
        for r in [q("a", 1, Outcome::Ok), q("a", 2, Outcome::Error), q("a", 3, Outcome::Error), q("b", 4, Outcome::Error), q("b", 5, Outcome::Ok)] {
            st.apply_quantum(&r);
        }
        let end = st.stats["a"].last_end.unwrap();
        let cfg = Config { quantum_s: 60.0, starve_every: 1000, limit: None };
        let now = Instant::now();
        // Restarted 30 s after a's last quantum ended: of its 120 s (two errors) 90 are left.
        let s = Sched::new_at(dir.path(), st, vec![target("a"), target("b")], cfg, now, end + 30.0).unwrap();
        let f = s.faults_at(now);
        assert_eq!((f[0].consecutive, f[0].faulted_now), (2, true), "{f:?}");
        assert!(s.faults_at(now + Duration::from_secs(89))[0].faulted_now && !s.faults_at(now + Duration::from_secs(91))[0].faulted_now);
        assert_eq!((f[1].consecutive, f[1].faulted_now), (0, false), "a good last quantum leaves nothing to wait for");
        assert_eq!(f[0].total, 0, "faults_total counts this process's faults only");
    }

    #[test]
    fn the_quanta_budget_ends_the_picking() {
        let dir = tempfile::tempdir().unwrap();
        let p = dir.path().join("t");
        std::fs::write(&p, "x").unwrap();
        let t = Target {
            id: "t".into(),
            name: "t".into(),
            rank: 1,
            start_order: 1,
            complexity: None,
            gap: None,
            blast: None,
            argv: vec![p.display().to_string()],
            corpus: String::new(),
            artifacts: String::new(),
        };
        let mut s = Sched::new(dir.path(), State::default(), vec![t], Config { quantum_s: 1.0, starve_every: 10, limit: Some(2) }).unwrap();
        for _ in 0..2 {
            let Pick::Run(c) = s.pick() else { panic!() };
            s.release(&c);
            s.claimed += 1; // a finished quantum stays counted
            s.busy[0] = false;
        }
        assert!(matches!(s.pick(), Pick::Done));
    }
}

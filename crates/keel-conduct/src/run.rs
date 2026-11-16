//! `keel-conduct run`: plan from every source, consult the store, run what the
//! store cannot answer behind the gate, record, and write the report.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Instant, SystemTime};

use anyhow::{Context, Result, anyhow, bail};
use keel::store::StoredRecord;
use keel::{
    Evidence, Manifest, NetMode, Node, NodeId, Plan, Platform, Record, Report, SCHEMA, Stages,
    Status, StoredPass, Upstream, Verdict,
};

use crate::config::Config;
use crate::model::{Cx, Outcome, Planned, Runner, store_warning, store_warnings};
use crate::pins::{Pins, upstream_roots};
use crate::util::{self, rfc3339};
use crate::{cmd, go, nix, store::Store};

/// Everything `run` is told.
pub struct RunOpts {
    /// The repository checkout.
    pub repo_root: PathBuf,
    /// Revision certified by the report.
    pub revision: String,
    /// Parallel node limit.
    pub jobs: usize,
    /// Run nodes whose upstream failed anyway.
    pub no_block: bool,
    /// The `go` binary, when the Go source is on.
    pub go: Option<PathBuf>,
    /// Scratch directory; a fresh one under the system temp dir when absent.
    pub work_dir: Option<PathBuf>,
    /// Reports of other repositories this run stands on.
    pub upstream: Vec<Report>,
    /// Pins the upstream reports must match.
    pub pins: Option<Pins>,
}

/// What a run produced.
pub struct RunOutput {
    /// The report.
    pub report: Report,
    /// The manifest of the nodes that were planned.
    pub manifest: Manifest,
}

/// The platform of the report; per-node keys carry their own toolchain.
pub fn run_platform() -> Platform {
    Platform::new(
        crate::util::host_triple(),
        format!("keel-conduct {}", env!("CARGO_PKG_VERSION")),
        NetMode::Open,
    )
}

/// Plans every source.
pub fn plan_all(cfg: &Config, repo_root: &Path, go_bin: Option<&Path>) -> Result<Vec<Planned>> {
    let mut all = Vec::new();
    if cfg.go.is_some() || go_bin.is_some() {
        let go = go_bin
            .map(Path::to_path_buf)
            .or_else(|| util::which("go", &std::env::var("PATH").unwrap_or_default()))
            .ok_or_else(|| {
                anyhow!("the config has a [go] table but no `go` binary was found; pass --go <path> or run from a shell that provides Go")
            })?;
        let default = crate::config::GoConfig::default();
        all.extend(go::plan(
            repo_root,
            cfg.go.as_ref().unwrap_or(&default),
            &go,
        )?);
    }
    all.extend(cmd::plan(cfg, repo_root)?);
    all.extend(nix::plan(cfg, repo_root)?);
    Ok(all)
}

/// One finished node.
struct Done {
    record: Record,
    /// Kept apart from the record because a cached record carries none but
    /// consumers of a cached artifact still need its blobs.
    evidence: Vec<Evidence>,
    extra: Vec<Record>,
}

fn record_of(node: &Node, o: &Outcome, cached: Option<&StoredPass>) -> Record {
    Record {
        id: node.id.clone(),
        key: node.key,
        status: o.status,
        reason: o.reason.clone(),
        blocked_by: Vec::new(),
        duration_ms: Some(o.duration_ms),
        attempt: cached.is_none().then_some(1),
        detail: o.detail.clone(),
        evidence: if cached.is_some() {
            Vec::new()
        } else {
            o.evidence.clone()
        },
        cached_from: cached.map(|c| c.run_id.clone()),
    }
}

/// Answers from the store, or runs, then records. Never panics on a store
/// failure: a store that is down costs speed, not correctness.
fn process(p: &Planned, cx: &Cx<'_>, run_id: &str, platform: &Platform) -> Done {
    let node = &p.node;
    let started = Instant::now();
    let finish = |o: Outcome, cached: Option<&StoredPass>| Done {
        record: record_of(node, &o, cached),
        evidence: o.evidence,
        extra: o.extra,
    };

    if let Runner::Nix(n) = &p.runner {
        if let Some(o) = n.probe(node, cx.store) {
            return finish(o, None);
        }
    } else if !node.policy.network {
        match cx.store.get_pass(&node.key) {
            // A stored artifact whose blobs were collected is a miss.
            Ok(Some(pass))
                if node.kind != keel::Kind::Artifact
                    || cmd::artifact_available(cx.store, &pass.evidence) =>
            {
                let o = Outcome {
                    status: Status::Cached,
                    reason: None,
                    detail: None,
                    evidence: pass.evidence.clone(),
                    extra: Vec::new(),
                    duration_ms: started.elapsed().as_millis() as u64,
                };
                return finish(o, Some(&pass));
            }
            Ok(_) => {}
            Err(e) => store_warning(format!(
                "cannot consult the store for {}: {e}; running it",
                node.id
            )),
        }
    }

    let outcome = match &p.runner {
        Runner::Go(g) => g.run(node, cx),
        Runner::Cmd(c) => c.run(node, cx),
        Runner::Nix(n) => n.run(node, cx),
    };
    // Only a conductor-run result is recorded, and failures too: they are
    // history, never a cache hit (§3.9). Network nodes are never stored.
    if !node.policy.network && !matches!(p.runner, Runner::Nix(_)) {
        let rec = StoredRecord {
            key: node.key,
            id: node.id.clone(),
            status: outcome.status,
            run_id: run_id.to_owned(),
            recorded_at: rfc3339(SystemTime::now()),
            platform: platform.clone(),
            evidence: outcome.evidence.clone(),
        };
        if let Err(e) = cx.store.put(&rec) {
            store_warning(format!("result of {} not recorded: {e}", node.id));
        }
    }
    finish(outcome, None)
}

/// A fresh run id: UTC time plus eight hex digits of entropy, all in the
/// alphabet the store accepts for index names.
pub fn new_run_id() -> String {
    let t = rfc3339(SystemTime::now()).replace([':', '-'], "");
    let salt: [u8; 4] = rand::random();
    format!(
        "{}-{}",
        t.trim_end_matches('Z'),
        salt.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}

/// Plans, runs and reports.
pub fn run(cfg: &Config, store: &Store, opts: &RunOpts) -> Result<RunOutput> {
    let started_at = rfc3339(SystemTime::now());
    let t0 = Instant::now();
    let run_id = new_run_id();
    let platform = run_platform();

    // Upstream reports of other repositories, at pinned revisions only.
    let mut foreign: BTreeMap<NodeId, Record> = BTreeMap::new();
    if !opts.upstream.is_empty() {
        let pins = opts.pins.as_ref().ok_or_else(|| {
            anyhow!("--upstream reports were given without --pins; cross-repo results are only trusted at a revision named in a pins file")
        })?;
        for r in &opts.upstream {
            pins.check(r, &format!("upstream report {}", r.run_id), true)?;
            foreign.extend(r.nodes.iter().map(|n| (n.id.clone(), n.clone())));
        }
    }

    let planned = plan_all(cfg, &opts.repo_root, opts.go.as_deref())?;
    let nodes: Vec<Node> = planned.iter().map(|p| p.node.clone()).collect();
    let plan = Plan::new(&nodes).context("the planned nodes do not form a valid hierarchy")?;
    let key_ms = t0.elapsed().as_millis() as u64;
    eprintln!("keel-conduct: planned {} nodes in {key_ms} ms", nodes.len());

    // Edges to nodes of other repositories: resolved from the pinned
    // reports, or reported once and ignored.
    let mut external: BTreeMap<NodeId, Vec<NodeId>> = BTreeMap::new();
    for (id, up) in plan.unresolved() {
        let Upstream::Node(target) = up else {
            eprintln!(
                "keel-conduct: warning: {id} stands on group {up}, which no planned node belongs to; it gates nothing"
            );
            continue;
        };
        match upstream_roots(target, &foreign) {
            Some(roots) => external.entry(id.clone()).or_default().extend(roots),
            None => eprintln!(
                "keel-conduct: warning: {id} stands on {target}, which is neither planned here nor in a pinned --upstream report; it gates nothing"
            ),
        }
    }

    let work = match &opts.work_dir {
        Some(w) => w.clone(),
        None => std::env::temp_dir().join(format!("keel-conduct-{run_id}")),
    };
    std::fs::create_dir_all(&work).with_context(|| {
        format!(
            "cannot create the work directory {}; pass --work-dir",
            work.display()
        )
    })?;

    let index: BTreeMap<&NodeId, usize> = planned
        .iter()
        .enumerate()
        .map(|(i, p)| (&p.node.id, i))
        .collect();
    let order: Vec<usize> = plan.order().into_iter().map(|id| index[id]).collect();
    let ups: Vec<Vec<usize>> = planned
        .iter()
        .map(|p| {
            plan.upstream(&p.node.id)
                .unwrap_or_default()
                .into_iter()
                .map(|u| index[u])
                .collect()
        })
        .collect();

    let mut done: Vec<Option<Done>> = (0..planned.len()).map(|_| None).collect();
    let mut pending: Vec<usize> = order.clone();
    let mut running = 0usize;
    let t_run = Instant::now();
    let jobs = opts.jobs.max(1);

    std::thread::scope(|scope| -> Result<()> {
        let (tx, rx) = mpsc::channel::<(usize, Done)>();
        loop {
            let mut next_pending = Vec::new();
            let mut progressed = false;
            for &i in &pending {
                if running >= jobs || !ups[i].iter().all(|&u| done[u].is_some()) {
                    next_pending.push(i);
                    continue;
                }
                // The roots this node stands on, from in-plan and foreign upstreams.
                let mut roots: BTreeSet<NodeId> = external
                    .get(&planned[i].node.id)
                    .cloned()
                    .unwrap_or_default()
                    .into_iter()
                    .collect();
                for &u in &ups[i] {
                    let d = done[u].as_ref().expect("checked");
                    let r = &d.record;
                    if matches!(r.status, Status::Fail | Status::Timeout | Status::Error)
                        && planned[u].node.policy.blocks
                    {
                        if r.blocked_by.is_empty() {
                            roots.insert(r.id.clone());
                        } else {
                            roots.extend(r.blocked_by.iter().cloned());
                        }
                    } else if r.status == Status::Blocked {
                        roots.extend(r.blocked_by.iter().cloned());
                    }
                }
                if !roots.is_empty() && !opts.no_block {
                    let rec = Record {
                        id: planned[i].node.id.clone(),
                        key: planned[i].node.key,
                        status: Status::Blocked,
                        reason: None,
                        blocked_by: roots.into_iter().collect(),
                        duration_ms: None,
                        attempt: None,
                        detail: None,
                        evidence: Vec::new(),
                        cached_from: None,
                    };
                    eprintln!(
                        "keel-conduct: blocked {} by {}",
                        rec.id,
                        rec.blocked_by
                            .iter()
                            .map(NodeId::as_str)
                            .collect::<Vec<_>>()
                            .join(", ")
                    );
                    done[i] = Some(Done {
                        record: rec,
                        evidence: Vec::new(),
                        extra: Vec::new(),
                    });
                    progressed = true;
                    continue;
                }
                let consumed: BTreeMap<NodeId, Vec<Evidence>> = planned[i]
                    .node
                    .inputs
                    .consumes
                    .iter()
                    .filter_map(|c| {
                        index.get(c).map(|&u| {
                            (
                                c.clone(),
                                done[u].as_ref().expect("checked").evidence.clone(),
                            )
                        })
                    })
                    .collect();
                running += 1;
                let (p, tx, work, run_id, platform) =
                    (&planned[i], tx.clone(), &work, &run_id, &platform);
                let blocked_by: Vec<NodeId> = roots.into_iter().collect();
                scope.spawn(move || {
                    let cx = Cx {
                        store,
                        work,
                        consumed: &consumed,
                    };
                    let mut d = process(p, &cx, run_id, platform);
                    // Under --no-block a failure still names what it would have been blocked by.
                    if matches!(
                        d.record.status,
                        Status::Fail | Status::Timeout | Status::Error
                    ) {
                        d.record.blocked_by = blocked_by;
                    }
                    let _ = tx.send((i, d));
                });
            }
            pending = next_pending;
            // Blocked nodes finished without a thread; their dependents may be ready now.
            if running == 0 {
                if pending.is_empty() {
                    return Ok(());
                }
                if !progressed {
                    bail!(
                        "the scheduler has {} nodes waiting on nodes that can never finish; this is a bug in the plan, report it with the config",
                        pending.len()
                    );
                }
                continue;
            }
            let (i, d) = rx
                .recv()
                .context("a node worker died without reporting; this is a bug")?;
            running -= 1;
            eprintln!(
                "keel-conduct: {:<8} {} ({} ms)",
                format!("{:?}", d.record.status).to_lowercase(),
                d.record.id,
                d.record.duration_ms.unwrap_or(0)
            );
            done[i] = Some(d);
        }
    })?;
    let run_ms = t_run.elapsed().as_millis() as u64;
    if store_warnings() > 0 {
        eprintln!(
            "keel-conduct: {} store operations failed in this process; nothing from this run was (fully) shared",
            store_warnings()
        );
    }
    if opts.work_dir.is_none() {
        let _ = std::fs::remove_dir_all(&work);
    }

    let mut records: Vec<Record> = Vec::new();
    let mut extras: Vec<Record> = Vec::new();
    for &i in &order {
        let d = done[i].take().expect("every node finished");
        records.push(d.record);
        extras.extend(d.extra);
    }
    let planned_ids: BTreeSet<NodeId> = records.iter().map(|r| r.id.clone()).collect();
    for e in extras {
        if planned_ids.contains(&e.id) || records.iter().any(|r| r.id == e.id) {
            eprintln!(
                "keel-conduct: warning: a Nix report names {}, which is also a planned node; keeping the planned record",
                e.id
            );
        } else {
            records.push(e);
        }
    }

    let repo = cfg.repo.clone().unwrap_or_else(|| {
        opts.repo_root
            .canonicalize()
            .ok()
            .and_then(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
            .unwrap_or_else(|| "unknown".to_owned())
    });
    let mut report = Report {
        schema: SCHEMA,
        run_id,
        repo: repo.clone(),
        revision: opts.revision.clone(),
        head: None,
        base: None,
        platform: platform.clone(),
        verdict: Verdict::Pass,
        started_at,
        duration_ms: t0.elapsed().as_millis() as u64,
        budget: None,
        stages: Some(Stages {
            key_ms,
            run_ms,
            ..Stages::default()
        }),
        counts: keel::Counts::default(),
        roots: Vec::new(),
        nodes: records,
        flaky: Vec::new(),
        interactions: Vec::new(),
    };
    // Every planned node must have left a record; one that did not was not verified.
    report.derive_against(&planned_ids.iter().cloned().collect::<Vec<_>>());
    let manifest = Manifest {
        schema: SCHEMA,
        producer: format!("keel-conduct {}", env!("CARGO_PKG_VERSION")),
        repo,
        revision: opts.revision.clone(),
        platform,
        nodes,
    };
    Ok(RunOutput { report, manifest })
}

/// `git rev-parse HEAD` of the checkout.
pub fn git_revision(repo_root: &Path) -> Result<String> {
    let out = std::process::Command::new("git")
        .args(["rev-parse", "HEAD"])
        .current_dir(repo_root)
        .output()
        .context("cannot run `git` to find the revision; pass --revision <40-hex>")?;
    if !out.status.success() {
        bail!(
            "{} is not a git checkout with a commit ({}); pass --revision <rev> so the report says what it certifies",
            repo_root.display(),
            util::tail_text(&out.stderr, 300)
        );
    }
    Ok(String::from_utf8_lossy(&out.stdout).trim().to_owned())
}

/// A short human summary for the terminal.
pub fn summary(report: &Report) -> String {
    let c = &report.counts;
    let mut s = format!(
        "keel-conduct: {} nodes: {} pass, {} cached, {} fail, {} blocked, {} error, {} timeout; verdict {}",
        report.nodes.len(),
        c.pass,
        c.cached,
        c.fail,
        c.blocked,
        c.error,
        c.timeout,
        format!("{:?}", report.verdict).to_lowercase()
    );
    for root in &report.roots {
        s.push_str(&format!("\n  root: {root}"));
    }
    s
}

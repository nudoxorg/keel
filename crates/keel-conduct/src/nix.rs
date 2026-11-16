//! Nix derivations as nodes (`kind: nix-check`).
//!
//! The derivation is the key: Nix already hashed everything the build reads,
//! so the conductor takes the NAR hash of the `.drv` file instead of
//! recomputing anything. A node is `cached` when its output path is already
//! in the Nix store, and building it is the test.

use std::collections::BTreeMap;
use std::path::Path;
use std::time::Instant;

use anyhow::{Context, Result, anyhow, bail};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use keel::store::ResultStore;
use keel::{Detail, Digest, GroupId, Inputs, Kind, Node, Policy, Record, Status};
use serde_json::Value;

use crate::cmd::namespaced;
use crate::config::Config;
use crate::model::{Cx, Outcome, Planned, Runner, evidence_or_skip};
use crate::util::{Spawn, rel_to, run_captured, tail_text};

const FEATURES: [&str; 2] = ["--extra-experimental-features", "nix-command flakes"];

/// What building one derivation needs.
pub struct NixRun {
    drv: String,
    out: String,
    cwd: std::path::PathBuf,
}

fn nix(cwd: &Path, args: &[&str]) -> Result<crate::util::Captured> {
    let mut argv: Vec<String> = vec!["nix".to_owned()];
    argv.extend(FEATURES.map(str::to_owned));
    argv.extend(args.iter().map(|a| (*a).to_owned()));
    let env: BTreeMap<String, String> = std::env::vars().collect();
    run_captured(&Spawn {
        argv: &argv,
        cwd,
        env: &env,
        timeout: None,
    })
    .context("cannot run `nix`; the Nix source needs it on PATH")
}

/// `sha256-<base64>` (the SRI form Nix prints) as a digest.
fn parse_nar_hash(sri: &str) -> Result<Digest> {
    let b64 = sri
        .strip_prefix("sha256-")
        .ok_or_else(|| anyhow!("narHash `{sri}` is not in `sha256-<base64>` form; use a Nix new enough to print SRI hashes"))?;
    let bytes: [u8; 32] = STANDARD
        .decode(b64)?
        .try_into()
        .map_err(|_| anyhow!("narHash `{sri}` is not 32 bytes"))?;
    Ok(Digest::Sha256(bytes))
}

/// Plans every `[[node]] drv = ...`.
pub fn plan(cfg: &Config, repo_root: &Path) -> Result<Vec<Planned>> {
    let mut out = Vec::new();
    for n in cfg.nodes.iter().filter(|n| n.drv.is_some()) {
        let installable = n.drv.as_deref().expect("filtered");
        let id = namespaced(n.id.as_deref().unwrap_or(installable), "nix");
        let info = nix(
            repo_root,
            &["path-info", "--json", "--derivation", installable],
        )?;
        if info.code != Some(0) {
            bail!(
                "`nix path-info --derivation {installable}` failed for node {id}: {}; check the installable evaluates (flake attributes must be git-tracked or `path:`)",
                tail_text(&info.stderr, 1500)
            );
        }
        let info: Value = serde_json::from_slice(&info.stdout).with_context(|| {
            format!("node {id}: `nix path-info --json` printed something that is not JSON")
        })?;
        let entry = info
            .as_array()
            .and_then(|a| a.first())
            .or_else(|| info.as_object().and_then(|o| o.values().next()));
        let drv = entry
            .and_then(|e| e.get("path"))
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("node {id}: `nix path-info --json` has no `path`; the Nix version prints a different shape than this conductor reads"))?
            .to_owned();
        let key = parse_nar_hash(
            entry
                .and_then(|e| e.get("narHash"))
                .and_then(Value::as_str)
                .ok_or_else(|| {
                    anyhow!("node {id}: `nix path-info --json` has no `narHash` for {drv}")
                })?,
        )?;
        let shown = nix(repo_root, &["derivation", "show", &drv])?;
        if shown.code != Some(0) {
            bail!(
                "`nix derivation show {drv}` failed for node {id}: {}",
                tail_text(&shown.stderr, 1500)
            );
        }
        let shown: Value = serde_json::from_slice(&shown.stdout)?;
        let out_path = output_path(&shown, &drv)
            .ok_or_else(|| anyhow!("node {id}: derivation {drv} lists no `out` output path; content-addressed derivations are not supported yet"))?;
        let name = id.as_str().split_once(':').map_or(id.as_str(), |(_, r)| r);
        let group = match &n.group {
            Some(g) => g
                .parse::<GroupId>()
                .map_err(|e| anyhow!("node {id}: {e}"))?,
            None => GroupId::scenario(name),
        };
        let stands_on = n
            .stands_on
            .iter()
            .map(|s| s.parse().map_err(|e| anyhow!("node {id}: {e}")))
            .collect::<Result<_>>()?;
        let node = Node {
            id,
            kind: Kind::NixCheck,
            group,
            stands_on,
            joins: n
                .joins
                .iter()
                .map(|j| j.parse().map_err(|e| anyhow!("{e}")))
                .collect::<Result<_>>()?,
            inputs: Inputs {
                drv: Some(drv.clone()),
                ..Inputs::default()
            },
            produces: Vec::new(),
            via: Some(out_path.clone()),
            key,
            policy: Policy {
                timeout: n.timeout_s,
                blocks: n.blocks.unwrap_or(true),
                ..Policy::default()
            },
        };
        out.push(Planned {
            node,
            runner: Runner::Nix(NixRun {
                drv,
                out: out_path,
                cwd: repo_root.to_path_buf(),
            }),
        });
    }
    Ok(out)
}

/// The `out` path from `nix derivation show`, in both the old shape (a map
/// keyed by drv path) and the newer one (wrapped in `derivations`, store-relative paths).
fn output_path(shown: &Value, drv: &str) -> Option<String> {
    let map = shown.get("derivations").unwrap_or(shown).as_object()?;
    let entry = map.values().next()?;
    let outputs = entry.get("outputs")?.as_object()?;
    let out = outputs.get("out").or_else(|| outputs.values().next())?;
    let p = out.get("path")?.as_str()?;
    if p.starts_with('/') {
        Some(p.to_owned())
    } else {
        let store = Path::new(drv).parent()?;
        Some(store.join(p).to_string_lossy().into_owned())
    }
}

/// Reads `<via>/report.json` if the output has one. `evidence[].ref` entries
/// of the form `file:<path>` are paths inside the output; their bytes go into
/// the store and the reference becomes the blob digest, so a Nix report
/// derivation never needs to write into the store itself.
pub fn read_report(store: &dyn ResultStore, via: &Path) -> Result<Vec<Record>> {
    let file = via.join("report.json");
    let text = match std::fs::read_to_string(&file) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => bail!(
            "cannot read {}: {e}; the output of the derivation must be readable by this user",
            file.display()
        ),
    };
    let mut doc: Value = serde_json::from_str(&text).with_context(|| {
        format!(
            "{} is not JSON; the scenario runner must write the §8.2 report",
            file.display()
        )
    })?;
    let nodes = doc
        .get_mut("nodes")
        .and_then(Value::as_array_mut)
        .ok_or_else(|| {
            anyhow!(
                "{} has no `nodes` array; it must be a keel run report (DESIGN §8.2)",
                file.display()
            )
        })?;
    let canon_via = via.canonicalize()?;
    let mut records = Vec::new();
    for (i, node) in nodes.iter_mut().enumerate() {
        if let Some(evidence) = node.get_mut("evidence").and_then(Value::as_array_mut) {
            for ev in evidence {
                let Some(reference) = ev.get("ref").and_then(Value::as_str) else {
                    continue;
                };
                let Some(rel) = reference.strip_prefix("file:") else {
                    continue;
                };
                let target = canon_via.join(rel).canonicalize().with_context(|| {
                    format!("node #{i} of {} cites evidence file:{rel}, which does not exist in the output", file.display())
                })?;
                // A symlink or `..` must not lead out of the output.
                if rel_to(&canon_via, &target).is_none() {
                    bail!(
                        "node #{i} of {} cites file:{rel}, which resolves outside the output {}; refusing to ingest it",
                        file.display(),
                        via.display()
                    );
                }
                let blob = store.put_blob(&std::fs::read(&target)?)?;
                ev["ref"] = Value::String(blob.to_string());
            }
        }
        records.push(
            serde_json::from_value::<Record>(node.clone()).with_context(|| {
                format!(
                    "node #{i} of {} is not a valid result record (DESIGN §8.2)",
                    file.display()
                )
            })?,
        );
    }
    Ok(records)
}

impl NixRun {
    /// `Some` when the output path is already realised: the derivation was
    /// built before, so its checks ran before.
    pub fn probe(&self, node: &Node, store: &dyn ResultStore) -> Option<Outcome> {
        let started = Instant::now();
        let got = nix(&self.cwd, &["path-info", &self.out]).ok()?;
        if got.code != Some(0) {
            return None;
        }
        Some(self.finish(node, store, Status::Cached, None, started, Vec::new()))
    }

    fn finish(
        &self,
        node: &Node,
        store: &dyn ResultStore,
        status: Status,
        detail: Option<Detail>,
        started: Instant,
        evidence: Vec<keel::Evidence>,
    ) -> Outcome {
        let mut out = Outcome {
            status,
            reason: None,
            detail,
            evidence,
            extra: Vec::new(),
            duration_ms: started.elapsed().as_millis() as u64,
        };
        match read_report(store, Path::new(&self.out)) {
            Ok(records) => {
                for r in records {
                    if r.id == node.id {
                        // The report speaks for the node itself: a failure there wins.
                        if !r.status.gates_as_pass() {
                            out.status = r.status;
                            out.reason = r.reason;
                            out.detail = r.detail;
                            out.evidence.extend(r.evidence);
                        }
                    } else {
                        out.extra.push(r);
                    }
                }
            }
            Err(e) => {
                out.status = Status::Error;
                out.detail = Some(Detail {
                    ran: format!("read {}/report.json", self.out),
                    expected: None,
                    actual: Some(format!("{e:#}")),
                });
            }
        }
        out
    }

    /// Builds the derivation.
    pub fn run(&self, node: &Node, cx: &Cx<'_>) -> Outcome {
        let started = Instant::now();
        let ran = format!("nix build --no-link --print-out-paths {}^out", self.drv);
        let target = format!("{}^out", self.drv);
        let got = match nix(
            &self.cwd,
            &["build", "--no-link", "--print-out-paths", &target],
        ) {
            Ok(g) => g,
            Err(e) => return Outcome::error(format!("{e:#}"), &ran, started),
        };
        let mut evidence = evidence_or_skip(cx.store, "stderr", &got.stderr);
        if got.code != Some(0) {
            let detail = Detail {
                ran,
                expected: Some("the derivation builds".to_owned()),
                actual: Some(tail_text(&got.stderr, 2000)),
            };
            return Outcome {
                status: Status::Fail,
                reason: None,
                detail: Some(detail),
                evidence,
                extra: Vec::new(),
                duration_ms: started.elapsed().as_millis() as u64,
            };
        }
        evidence.extend(evidence_or_skip(cx.store, "stdout", &got.stdout));
        self.finish(node, cx.store, Status::Pass, None, started, evidence)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn nar_hash_is_sri_sha256() {
        let d = parse_nar_hash("sha256-CH8nE3xln6nM2N0PPhKRV4mAaQj014eeckbSS2YYs8g=").unwrap();
        assert!(matches!(d, Digest::Sha256(_)));
        assert!(parse_nar_hash("sha256:1abc").is_err());
        assert!(parse_nar_hash("sha256-AAAA").is_err());
    }

    #[test]
    fn output_path_reads_both_shapes() {
        let old: Value = serde_json::from_str(
            r#"{"/nix/store/h-x.drv":{"outputs":{"out":{"path":"/nix/store/o-x"}}}}"#,
        )
        .unwrap();
        assert_eq!(
            output_path(&old, "/nix/store/h-x.drv").as_deref(),
            Some("/nix/store/o-x")
        );
        let new: Value = serde_json::from_str(
            r#"{"derivations":{"h-x.drv":{"outputs":{"out":{"path":"o-x"}}}},"version":4}"#,
        )
        .unwrap();
        assert_eq!(
            output_path(&new, "/nix/store/h-x.drv").as_deref(),
            Some("/nix/store/o-x")
        );
    }
}

//! The targets file, and its conversion from a continuous-fuzz bundle's metadata.json.

use std::collections::HashSet;
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};

pub const TARGETS_SCHEMA: &str = "keel.judge.targets.v1";
pub const DEFAULT_DURABLE_ROOT: &str = "/durable/fuzz";

#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct TargetsFile {
    pub schema: String,
    #[serde(default)]
    pub source: String,
    pub targets: Vec<Target>,
}

/// Only `id`, `rank`, `argv`, `corpus` and `artifacts` are needed; the rest is carried so
/// that a report can show where a rank came from.
#[derive(Serialize, Deserialize, Debug, Clone)]
pub struct Target {
    pub id: String,
    #[serde(default)]
    pub name: String,
    pub rank: u64,
    #[serde(default)]
    pub start_order: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub complexity: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub gap: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blast: Option<u64>,
    pub argv: Vec<String>,
    pub corpus: String,
    pub artifacts: String,
}

impl TargetsFile {
    pub fn load(path: &Path) -> Result<TargetsFile> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("cannot read {} (the targets file); write one with `keel-judge targets` or fix --targets", path.display()))?;
        let mut f: TargetsFile = serde_json::from_str(&text)
            .with_context(|| format!("cannot parse {} (the targets file, schema {TARGETS_SCHEMA}); regenerate it with `keel-judge targets`", path.display()))?;
        if f.schema != TARGETS_SCHEMA {
            bail!("{} has schema {:?} but this build reads {TARGETS_SCHEMA:?}; regenerate it with `keel-judge targets`", path.display(), f.schema);
        }
        let mut seen = HashSet::new();
        for t in &mut f.targets {
            if t.argv.is_empty() {
                bail!("target {} in {} has an empty argv; argv[0] must be the path of the runner", t.id, path.display());
            }
            if t.name.is_empty() {
                t.name = t.id.clone();
            }
            if !seen.insert(t.id.clone()) {
                bail!("target {} appears twice in {}; ids name state directories and must be unique", t.id, path.display());
            }
        }
        Ok(f)
    }
}

#[derive(Deserialize)]
struct Metadata {
    targets: Vec<Row>,
}

#[derive(Deserialize)]
struct Row {
    id: String,
    kind: Option<String>,
    name: Option<String>,
    schedule: Option<bool>,
    rank: Option<u64>,
    start_order: Option<u64>,
    #[serde(rename = "durableMount")]
    durable_mount: Option<String>,
    complexity: Option<Score>,
    gap: Option<Score>,
    blast: Option<Score>,
}

#[derive(Deserialize)]
struct Score {
    score: Option<u64>,
}

fn score(s: &Option<Score>) -> Option<u64> {
    s.as_ref().and_then(|s| s.score)
}

/// Applies the consumer rules of `metadata.consumers.rank`: scheduled fuzz rows only, the
/// rank recomputed (rank 0 is valid and still runs), `start_order` no part of the rank.
pub fn from_metadata(metadata_json: &str, bundle: &Path, durable_root: &str) -> Result<TargetsFile> {
    let meta: Metadata = serde_json::from_str(metadata_json).with_context(|| {
        format!("cannot parse {}/metadata.json (the continuous-fuzz metadata of the bundle); is this a continuous-fuzz bundle?", bundle.display())
    })?;
    let mut targets = Vec::new();
    for row in meta.targets {
        if row.kind.as_deref() != Some("fuzz") || row.schedule != Some(true) {
            continue;
        }
        let id = row.id;
        let (Some(c), Some(g), Some(b)) = (score(&row.complexity), score(&row.gap), score(&row.blast)) else {
            bail!("target {id}: complexity.score, gap.score and blast.score are not all numbers in {}/metadata.json, so its rank cannot be checked; rebuild the bundle", bundle.display());
        };
        let rank = c
            .checked_mul(g)
            .and_then(|x| x.checked_mul(b))
            .with_context(|| format!("target {id}: complexity.score {c} * gap.score {g} * blast.score {b} overflows; check metadata.json"))?;
        if row.rank != Some(rank) {
            let stated = row.rank.map_or("null".to_string(), |r| r.to_string());
            bail!(
                "target {id}: the row says rank {stated} but complexity.score {c} * gap.score {g} * blast.score {b} = {rank}; the bundle's metadata.json is inconsistent, so rebuild the bundle instead of trusting either number"
            );
        }
        let corpus = format!("{}/{id}/corpus", durable_root.trim_end_matches('/'));
        if durable_root == DEFAULT_DURABLE_ROOT && row.durable_mount.as_deref() != Some(corpus.as_str()) {
            bail!(
                "target {id}: the corpus would be {corpus} but the row's durableMount is {:?}; the runner refuses any other argv[1], so rebuild the bundle or pass the --durable-root it was built for",
                row.durable_mount
            );
        }
        let bin = bundle.join("bin").join(format!("fuzz-{id}"));
        if !bin.exists() {
            bail!("cannot find {} (the runner of target {id} in the bundle); build `.#continuous-fuzz` or fix --bundle", bin.display());
        }
        targets.push(Target {
            name: row.name.unwrap_or_else(|| id.clone()),
            rank,
            start_order: row.start_order.unwrap_or(0),
            complexity: Some(c),
            gap: Some(g),
            blast: Some(b),
            argv: vec![bin.display().to_string(), corpus.clone(), "-print_final_stats=1".into()],
            artifacts: format!("{}/{id}/artifacts", durable_root.trim_end_matches('/')),
            corpus,
            id,
        });
    }
    targets.sort_by(|a, b| (a.start_order, &a.id).cmp(&(b.start_order, &b.id)));
    Ok(TargetsFile { schema: TARGETS_SCHEMA.into(), source: bundle.display().to_string(), targets })
}

pub fn from_bundle(bundle: &Path, durable_root: &str) -> Result<TargetsFile> {
    let bundle: PathBuf = std::path::absolute(bundle).with_context(|| format!("cannot make {} absolute", bundle.display()))?;
    let path = bundle.join("metadata.json");
    let text = std::fs::read_to_string(&path)
        .with_context(|| format!("cannot read {} (the metadata of the continuous-fuzz bundle); build `.#continuous-fuzz` or fix --bundle", path.display()))?;
    from_metadata(&text, &bundle, durable_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn fuzz_row(id: &str, c: u64, g: u64, b: u64, rank: u64, start: u64) -> serde_json::Value {
        json!({
            "id": id, "kind": "fuzz", "name": format!("{id} name"), "engine": "libfuzzer", "schedule": true,
            "rank": rank, "start_order": start,
            "durableMount": format!("/durable/fuzz/{id}/corpus"),
            "complexity": {"score": c, "loc": 1}, "gap": {"score": g}, "blast": {"score": b},
        })
    }

    fn property_row() -> serde_json::Value {
        json!({
            "id": "laws", "kind": "property", "schedule": false, "rank": null, "start_order": null, "durableMount": null,
            "complexity": {"score": null}, "gap": {"score": null}, "blast": {"score": null},
        })
    }

    fn bundle(rows: Vec<serde_json::Value>) -> (tempfile::TempDir, String) {
        let dir = tempfile::tempdir().unwrap();
        std::fs::create_dir_all(dir.path().join("bin")).unwrap();
        for r in &rows {
            if r["kind"] == "fuzz" {
                std::fs::write(dir.path().join("bin").join(format!("fuzz-{}", r["id"].as_str().unwrap())), "").unwrap();
            }
        }
        (dir, json!({"schema": "nudox.continuous-fuzz.v1", "targets": rows}).to_string())
    }

    #[test]
    fn scheduled_fuzz_rows_become_targets_and_rank_zero_stays() {
        let (dir, meta) = bundle(vec![
            fuzz_row("wire", 925, 3, 5, 925 * 3 * 5, 5),
            property_row(),
            fuzz_row("store-raw", 934, 0, 5, 0, 4),
        ]);
        let f = from_metadata(&meta, dir.path(), DEFAULT_DURABLE_ROOT).unwrap();
        assert_eq!(f.targets.iter().map(|t| t.id.as_str()).collect::<Vec<_>>(), vec!["store-raw", "wire"]);
        let t = &f.targets[0];
        assert_eq!((t.rank, t.start_order, t.gap), (0, 4, Some(0)));
        assert_eq!(t.argv[1..], ["/durable/fuzz/store-raw/corpus", "-print_final_stats=1"]);
        assert_eq!(t.argv[0], dir.path().join("bin/fuzz-store-raw").display().to_string());
        assert_eq!((t.corpus.as_str(), t.artifacts.as_str()), ("/durable/fuzz/store-raw/corpus", "/durable/fuzz/store-raw/artifacts"));
        assert_eq!(f.targets[1].rank, 13_875);
        assert_eq!(f.schema, TARGETS_SCHEMA);
    }

    #[test]
    fn a_wrong_rank_is_refused_naming_the_target_and_both_numbers() {
        let (dir, meta) = bundle(vec![fuzz_row("pack", 925, 3, 5, 9999, 1)]);
        let err = from_metadata(&meta, dir.path(), DEFAULT_DURABLE_ROOT).unwrap_err().to_string();
        assert!(err.contains("pack") && err.contains("9999") && err.contains("13875"), "{err}");
    }

    #[test]
    fn a_durable_mount_that_differs_is_refused_only_for_the_default_root() {
        let mut row = fuzz_row("pack", 2, 3, 5, 30, 1);
        row["durableMount"] = json!("/srv/other/pack/corpus");
        let (dir, meta) = bundle(vec![row]);
        let err = from_metadata(&meta, dir.path(), DEFAULT_DURABLE_ROOT).unwrap_err().to_string();
        assert!(err.contains("/durable/fuzz/pack/corpus") && err.contains("/srv/other/pack/corpus"), "{err}");
        let f = from_metadata(&meta, dir.path(), "/tmp/judge-test").unwrap();
        assert_eq!(f.targets[0].corpus, "/tmp/judge-test/pack/corpus");
    }

    #[test]
    fn the_targets_file_round_trips_and_hand_written_files_load() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("t.json");
        std::fs::write(
            &path,
            json!({"schema": TARGETS_SCHEMA, "targets": [{"id": "x", "rank": 4, "argv": ["/bin/true"], "corpus": "/c", "artifacts": "/a"}]}).to_string(),
        )
        .unwrap();
        let f = TargetsFile::load(&path).unwrap();
        assert_eq!((f.targets[0].name.as_str(), f.targets[0].start_order), ("x", 0));
        std::fs::write(&path, json!({"schema": "other", "targets": []}).to_string()).unwrap();
        assert!(TargetsFile::load(&path).is_err());
    }
}

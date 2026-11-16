//! `mutate`: apply one change from BENCH.md section 2 and record which tests
//! must flip. Edits are exact-string replacements against the text `generate`
//! wrote, relative to synth.json; they assume a pristine (or restored) tree.

use crate::model::{Asserts, CrateInfo, Synth};
use crate::rng::Rng;
use anyhow::{Context, Result, bail};
use clap::ValueEnum;
use serde_json::json;
use std::fs;
use std::path::{Path, PathBuf};

#[derive(ValueEnum, Clone, Copy, Debug)]
pub enum Pattern {
    Docs,
    CommentLeaf,
    CommentRoot,
    BodyLeaf,
    BodyRoot,
    Fixture,
    SignatureRoot,
    DepAdd,
    /// A comment line at the top of a level-0 lib.rs that has line-oracle dependents.
    LineShift,
    /// Append one `#[test]` to `tests/bin00.rs` of a crate.
    AddTest,
    /// Rename `t001` in `tests/bin00.rs` of a crate.
    RenameTest,
}

pub struct Opts {
    pub workspace: PathBuf,
    pub pattern: Pattern,
    pub seed: u64,
    pub record: Option<PathBuf>,
    pub force: bool,
}

fn replace_once(ws: &Path, rel: &str, from: &str, to: &str) -> Result<()> {
    let p = ws.join(rel);
    let text = fs::read_to_string(&p)
        .with_context(|| format!("cannot read {rel}; is --workspace a generated workspace?"))?;
    if !text.contains(from) {
        bail!(
            "expected text `{}` not found in {rel}; the workspace was edited after generation, regenerate it",
            from.trim()
        );
    }
    fs::write(&p, text.replacen(from, to, 1)).with_context(|| format!("cannot write {rel}"))
}

fn pick<'a>(rng: &mut Rng, cs: &[&'a CrateInfo], what: &str) -> Result<&'a CrateInfo> {
    if cs.is_empty() {
        bail!("no {what} in this workspace; regenerate with different parameters");
    }
    Ok(cs[rng.below(cs.len())])
}

pub fn run(o: &Opts) -> Result<()> {
    let ws = &o.workspace;
    let default_record = ws.join("mutation.json");
    if default_record.exists() && !o.force {
        bail!(
            "{} exists: this workspace is already mutated; regenerate it, or pass --force after restoring the pristine tree",
            default_record.display()
        );
    }
    let s = Synth::load(ws)?;
    let mut rng = Rng::new(o.seed);
    let max_level = s.crates.iter().map(|c| c.level).max().unwrap_or(0);
    let roots: Vec<&CrateInfo> = s.crates.iter().filter(|c| c.level == 0).collect();
    let top: Vec<&CrateInfo> = s.crates.iter().filter(|c| c.level == max_level).collect();
    let mut changed: Vec<String> = Vec::new();
    let mut flips: Vec<String> = Vec::new();
    let mut target: Option<String> = None;
    // Oracles beyond `expected_flips`, for patterns that change no outcome: tests whose reach
    // key must change, tests whose key must not, and the ids a rename or an addition creates.
    let mut key_changes: Vec<String> = Vec::new();
    let mut key_stable: Vec<String> = Vec::new();
    let mut by_feature = serde_json::Map::new();
    let mut new_tests: Vec<String> = Vec::new();
    let mut renamed = serde_json::Map::new();
    let lib = |c: &CrateInfo| format!("crates/{}/src/lib.rs", c.name);

    match o.pattern {
        Pattern::Docs => {
            let p = ws.join("README.md");
            let mut t =
                fs::read_to_string(&p).context("cannot read README.md at the workspace root")?;
            t.push_str(&format!(
                "\nEdited by the docs mutation (seed {}).\n",
                o.seed
            ));
            fs::write(&p, t)?;
            changed.push("README.md".into());
        }
        Pattern::CommentLeaf | Pattern::CommentRoot => {
            let c = pick(
                &mut rng,
                if matches!(o.pattern, Pattern::CommentLeaf) {
                    &top
                } else {
                    &roots
                },
                "crate at that level",
            )?;
            let rel = lib(c);
            let t = fs::read_to_string(ws.join(&rel))?;
            fs::write(ws.join(&rel), format!("// bench comment\n{t}"))?;
            target = Some(c.name.clone());
            changed.push(rel);
        }
        Pattern::BodyLeaf | Pattern::BodyRoot => {
            let c = pick(
                &mut rng,
                if matches!(o.pattern, Pattern::BodyLeaf) {
                    &top
                } else {
                    &roots
                },
                "crate at that level",
            )?;
            let rel = lib(c);
            replace_once(
                ws,
                &rel,
                &format!("pub fn probe() -> u32 {{ {} }}", c.probe),
                &format!("pub fn probe() -> u32 {{ {} }}", c.probe + 1),
            )?;
            // Every combined() assertion in the crate and in anything that links it.
            let set = s.dependents_closure(&c.name);
            flips = s
                .tests
                .iter()
                .filter(|t| t.asserts == Asserts::Combined && set.contains(&t.krate))
                .map(|t| t.id.clone())
                .collect();
            target = Some(c.name.clone());
            changed.push(rel);
        }
        Pattern::Fixture => {
            let with_f0: Vec<&CrateInfo> = s
                .crates
                .iter()
                .filter(|c| {
                    s.tests
                        .iter()
                        .any(|t| t.krate == c.name && t.fixture == Some(0))
                })
                .collect();
            let c = pick(
                &mut rng,
                &with_f0,
                "crate with an integration test on fixture f0",
            )?;
            let rel = format!("crates/{}/fixtures/f0.txt", c.name);
            let t = fs::read_to_string(ws.join(&rel))?;
            let rest = t.split_once('\n').map_or("", |(_, r)| r);
            fs::write(
                ws.join(&rel),
                format!("fixture {} f0 MUTATED\n{rest}", c.name),
            )?;
            flips = s
                .tests
                .iter()
                .filter(|t| t.krate == c.name && t.fixture == Some(0))
                .map(|t| t.id.clone())
                .collect();
            target = Some(c.name.clone());
            changed.push(rel);
        }
        Pattern::SignatureRoot => {
            let c = pick(&mut rng, &roots, "level-0 crate")?;
            let rel = lib(c);
            // Callers live in this crate's lib.rs and tests; dependents call combined(), not probe().
            let mut files = vec![rel];
            if let Ok(rd) = fs::read_dir(ws.join(format!("crates/{}/tests", c.name))) {
                let mut names: Vec<String> = rd
                    .filter_map(|e| e.ok()?.file_name().into_string().ok())
                    .collect();
                names.sort();
                files.extend(
                    names
                        .into_iter()
                        .map(|n| format!("crates/{}/tests/{n}", c.name)),
                );
            }
            for f in files {
                let t = fs::read_to_string(ws.join(&f))?;
                let t = t
                    .replace("probe()", "probe(0)")
                    .replace("pub fn probe(0) -> u32", "pub fn probe(_salt: u8) -> u32");
                fs::write(ws.join(&f), t)?;
                changed.push(f);
            }
            target = Some(c.name.clone());
        }
        Pattern::DepAdd => {
            let dependents = |c: &CrateInfo| s.crates.iter().any(|d| d.deps.contains(&c.name));
            let leaves: Vec<&CrateInfo> = s
                .crates
                .iter()
                .filter(|c| !dependents(c) && c.unit_tests > 0)
                .collect();
            let c = pick(&mut rng, &leaves, "leaf crate with unit tests")?;
            // serde needs `derive` for #[derive(serde::Serialize)]; serde_json alone
            // does not enable it.
            replace_once(
                ws,
                "Cargo.toml",
                "serde_json = \"1\"\n",
                "serde_json = \"1\"\nserde = { version = \"1\", features = [\"derive\"] }\n",
            )?;
            let cargo = format!("crates/{}/Cargo.toml", c.name);
            replace_once(
                ws,
                &cargo,
                "serde_json.workspace = true\n",
                "serde_json.workspace = true\nserde.workspace = true\n",
            )?;
            let rel = lib(c);
            replace_once(
                ws,
                &rel,
                "#[cfg(test)]\nmod tests {",
                "#[derive(serde::Serialize)]\npub struct Tag {\n    pub n: u32,\n}\n\npub fn serde_tag() -> String {\n    serde_json::to_string(&Tag { n: 1 }).unwrap()\n}\n\n#[cfg(test)]\nmod tests {",
            )?;
            replace_once(
                ws,
                &rel,
                "        // bench:hook\n",
                "        assert_eq!(serde_tag(), r#\"{\"n\":1}\"#);\n",
            )?;
            target = Some(c.name.clone());
            changed.extend(["Cargo.toml".into(), cargo, rel]);
        }
        Pattern::LineShift => {
            let with_dependents: Vec<&CrateInfo> = roots
                .iter()
                .copied()
                .filter(|c| s.tests.iter().any(|t| t.root.as_deref() == Some(c.name.as_str())))
                .collect();
            let c = pick(&mut rng, &with_dependents, "level-0 crate with line-oracle dependents (generate with --line-oracle)")?;
            let rel = lib(c);
            let t = fs::read_to_string(ws.join(&rel))?;
            fs::write(ws.join(&rel), format!("// bench line shift\n{t}"))?;
            for t in s.tests.iter().filter(|t| t.root.as_deref() == Some(c.name.as_str())) {
                let feature = t.feature.as_deref().unwrap_or_default();
                let observes = crate::generate::LINE_FEATURES.iter().find(|(f, _)| *f == feature).is_some_and(|(_, o)| *o);
                if observes {
                    key_changes.push(t.id.clone());
                    by_feature.entry(feature.to_string()).or_insert_with(|| json!([])).as_array_mut().unwrap().push(json!(t.id));
                } else {
                    key_stable.push(t.id.clone());
                }
            }
            target = Some(c.name.clone());
            changed.push(rel);
        }
        Pattern::AddTest | Pattern::RenameTest => {
            let with_bin: Vec<&CrateInfo> = s.crates.iter().filter(|c| c.integration_bins > 0 && c.integration_tests >= 2).collect();
            let c = pick(&mut rng, &with_bin, "crate with an integration binary of at least two tests")?;
            let rel = format!("crates/{}/tests/bin00.rs", c.name);
            let binary = format!("{}::bin00", c.name);
            key_stable = s.tests.iter().filter(|t| t.binary == binary).map(|t| t.id.clone()).collect();
            if matches!(o.pattern, Pattern::AddTest) {
                let t = fs::read_to_string(ws.join(&rel))?;
                fs::write(ws.join(&rel), format!("{t}#[test]\nfn t_added() {{\n    assert_eq!(1 + 1, 2);\n}}\n"))?;
                new_tests.push(format!("{binary} t_added"));
            } else {
                replace_once(ws, &rel, "fn t001() {", "fn t001_renamed() {")?;
                let old = format!("{binary} t001");
                key_stable.retain(|id| *id != old);
                renamed.insert(old, json!(format!("{binary} t001_renamed")));
            }
            target = Some(c.name.clone());
            changed.push(rel);
        }
    }

    let record = json!({
        "pattern": format!("{:?}", o.pattern),
        "pattern_name": o.pattern.to_possible_value().expect("every pattern has a name").get_name().to_string(),
        "seed": o.seed,
        "crate": target,
        "files_changed": changed,
        "expected_flips": flips,
        "expected_key_changes": key_changes,
        "expected_key_changes_by_feature": by_feature,
        "expected_key_stable": key_stable,
        "new_tests": new_tests,
        "renamed": renamed,
    });
    let text = serde_json::to_string_pretty(&record)?;
    let path = o.record.clone().unwrap_or(default_record.clone());
    fs::write(&path, &text).with_context(|| format!("cannot write {}", path.display()))?;
    // The default location doubles as the already-mutated marker.
    if path != default_record {
        fs::write(&default_record, &text)?;
    }
    println!(
        "applied {:?}: {} file(s) changed, {} expected flip(s)",
        o.pattern,
        changed.len(),
        flips.len()
    );
    Ok(())
}

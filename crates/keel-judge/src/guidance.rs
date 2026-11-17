//! Order a complete harness inventory using captured NuDox observations.
//! Graph rows are observations, not a proof of non-reach or of test coverage.
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::{BTreeSet, HashMap, HashSet};
use std::io::Read;
use std::path::Path;

#[derive(Deserialize)]
struct Manifest {
    schema: u64,
    cases: Vec<Case>,
}
#[derive(Deserialize)]
struct Case {
    id: String,
}
/// Paths refer to exact JSON responses, relative to this file. Capture status on
/// both sides of each graph/source pair; never splice snapshots silently.
#[derive(Deserialize)]
struct Inputs {
    schema: u64,
    changes: Vec<String>,
    observations: Vec<Observation>,
}
#[derive(Deserialize)]
struct Observation {
    case: String,
    coordinate: String,
    before: String,
    #[serde(default)]
    graph: Option<String>,
    source: String,
    after: String,
    #[serde(default)]
    related: Vec<String>,
    #[serde(default)]
    related_chains: Vec<crate::related_chain::Chain>,
}
#[derive(Serialize)]
struct Evidence {
    case: String,
    coordinate: String,
    status: &'static str,
    reasons: Vec<String>,
    observed_changed_paths: Vec<String>,
    observed_changed_declarations: Vec<String>,
    dependency_complexity: Option<usize>,
    blast_radius: Option<usize>,
    graph_basis: &'static str,
    related_metrics: Option<crate::related::Metrics>,
    captures_blake3: Vec<String>,
}
#[derive(Serialize)]
pub struct Order {
    schema: u64,
    cases: Vec<String>,
    evidence: Vec<Evidence>,
    note: &'static str,
}
pub(crate) const CAPTURE_LIMIT: u64 = 16 * 1024 * 1024;
pub(crate) fn read_capture(path: &Path) -> Result<Vec<u8>> {
    read_capture_with_limit(path, CAPTURE_LIMIT)
}
pub(crate) fn read_capture_with_limit(path: &Path, limit: u64) -> Result<Vec<u8>> {
    let file = std::fs::File::open(path)?;
    if file.metadata()?.len() > limit {
        bail!("capture exceeds size limit");
    }
    let mut bytes = Vec::new();
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        bail!("capture exceeds size limit");
    }
    Ok(bytes)
}
fn read_json(base: &Path, path: &str) -> Result<(Value, String)> {
    let p = base.join(path);
    let bytes = read_capture(&p).with_context(|| format!("read capture {}", p.display()))?;
    let value =
        serde_json::from_slice(&bytes).with_context(|| format!("parse capture {}", p.display()))?;
    Ok((value, blake3::hash(&bytes).to_hex().to_string()))
}
fn string<'a>(v: &'a Value, p: &str) -> Option<&'a str> {
    v.pointer(p)?.as_str()
}

pub(crate) fn normal_path(path: &str) -> bool {
    !path.is_empty()
        && !Path::new(path).is_absolute()
        && Path::new(path)
            .components()
            .all(|c| matches!(c, std::path::Component::Normal(_)))
}

pub(crate) fn valid_selected_id(text: &str) -> bool {
    text.len() == 64
        && text
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        && text.bytes().any(|b| b != b'0')
}

/// Selected ID is a 64-hex string in the current wire format; older captures
/// carry 32 integer bytes. A name or opaque coordinate is not an identity.
pub(crate) fn selected_id(identity: &Value) -> Option<String> {
    let selected = identity.get("semantic_data")?;
    if selected.get("kind")?.as_str()? != "selected-symbol-id" {
        return None;
    }
    let value = selected.get("value")?;
    if let Some(text) = value.as_str() {
        return valid_selected_id(text).then(|| text.to_owned());
    }
    let bytes = value.as_array()?;
    if bytes.len() != 32 {
        return None;
    }
    let mut result = String::with_capacity(64);
    use std::fmt::Write;
    for value in bytes {
        write!(&mut result, "{:02x}", u8::try_from(value.as_u64()?).ok()?).ok()?;
    }
    valid_selected_id(&result).then_some(result)
}

pub fn order(manifest_path: &Path, inputs_path: &Path) -> Result<Order> {
    let manifest: Manifest = serde_json::from_slice(&read_capture(manifest_path)?)?;
    let inputs: Inputs = serde_json::from_slice(&read_capture(inputs_path)?)?;
    if manifest.schema != 1 || inputs.schema != 1 {
        bail!("manifest and guidance inputs must have schema 1");
    }
    let mut ids = HashSet::new();
    for c in &manifest.cases {
        if c.id.is_empty() || !ids.insert(c.id.clone()) {
            bail!("empty or duplicate case id {:?}", c.id);
        }
    }
    for path in &inputs.changes {
        if !normal_path(path) {
            bail!("changed path must be normalized and project-relative: {path:?}");
        }
    }
    let changed: BTreeSet<_> = inputs.changes.into_iter().collect();
    let mut observations = HashMap::new();
    for o in inputs.observations {
        if !ids.contains(&o.case) {
            bail!("observation names unknown case {}", o.case);
        }
        if observations.insert(o.case.clone(), o).is_some() {
            bail!("duplicate observation for a case");
        }
    }
    let base = inputs_path.parent().unwrap_or(Path::new("."));
    let mut rows = Vec::new();
    for c in manifest.cases {
        let mut e = Evidence {
            case: c.id,
            coordinate: String::new(),
            status: "unknown",
            reasons: Vec::new(),
            observed_changed_paths: Vec::new(),
            observed_changed_declarations: Vec::new(),
            dependency_complexity: None,
            blast_radius: None,
            graph_basis: "untyped declaration records; edges and relation coverage unavailable",
            related_metrics: None,
            captures_blake3: Vec::new(),
        };
        if let Some(o) = observations.remove(&e.case) {
            e.coordinate = o.coordinate.clone();
            let (before, b) = read_json(base, &o.before)?;
            let graph = o
                .graph
                .as_deref()
                .map(|path| read_json(base, path))
                .transpose()?;
            let (source, s) = read_json(base, &o.source)?;
            let (after, a) = read_json(base, &o.after)?;
            e.captures_blake3.push(b);
            if let Some((_, hash)) = &graph {
                e.captures_blake3.push(hash.clone());
            }
            e.captures_blake3.extend([s, a]);
            let same_snapshot = string(&before, "/availability") == Some("available")
                && string(&after, "/availability") == Some("available")
                && string(&before, "/publication") == Some("populated")
                && string(&after, "/publication") == Some("populated")
                && string(&before, "/answer") == Some("status")
                && string(&after, "/answer") == Some("status")
                && string(&before, "/revision").is_some()
                && string(&before, "/revision") == string(&after, "/revision")
                && string(&before, "/source").is_some()
                && string(&before, "/source") == string(&after, "/source");
            let project = string(&source, "/identity/project");
            let graph = graph
                .as_ref()
                .map(|(value, _)| value)
                .unwrap_or(&Value::Null);
            let graph_ok = project.is_some()
                && graph["records"].as_array().is_some_and(|rows| {
                    rows.iter()
                        .any(|r| string(r, "/identity/coordinate") == Some(&o.coordinate))
                        && rows
                            .iter()
                            .all(|r| string(r, "/identity/project") == project)
                })
                && graph["answer"] == "records"
                && graph["query"] == o.coordinate
                && graph["more"] == false
                && graph["coverage"].as_array().is_some_and(|lanes| {
                    lanes
                        .iter()
                        .any(|x| x["lane"] == "graph" && x["state"] == "complete")
                });
            let source_ok = source["answer"] == "page"
                && string(&source, "/identity/coordinate") == Some(&o.coordinate)
                && source["source"]["extent"] == "complete"
                && source["source"]["lines"].as_array().is_some()
                && project.is_some_and(|p| !p.is_empty())
                && string(&source, "/identity/path")
                    .is_some_and(|p| normal_path(p) && string(&source, "/source/path") == Some(p));
            if !same_snapshot {
                e.reasons.push("status snapshots missing or changed".into());
            }
            if !graph_ok {
                e.reasons
                    .push("graph unavailable, truncated, or coordinate mismatch".into());
            }
            if !source_ok {
                e.reasons
                    .push("source unavailable, incomplete, or coordinate mismatch".into());
            }
            if same_snapshot && source_ok {
                if graph_ok {
                    let paths: BTreeSet<_> = graph["records"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|r| string(r, "/identity/path").map(str::to_owned))
                        .collect();
                    e.observed_changed_paths = paths.intersection(&changed).cloned().collect();
                    e.observed_changed_declarations = graph["records"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter(|r| string(r, "/identity/shape") == Some("declaration"))
                        .filter(|r| {
                            string(r, "/identity/path").is_some_and(|p| changed.contains(p))
                        })
                        .filter_map(|r| string(r, "/identity/coordinate").map(str::to_owned))
                        .collect::<BTreeSet<_>>()
                        .into_iter()
                        .collect();
                }
                if !o.related.is_empty() || !o.related_chains.is_empty() {
                    let mut pages = Vec::new();
                    if o.related_chains.is_empty() {
                        for path in &o.related {
                            let (page, hash) = read_json(base, path)?;
                            pages.push(vec![page]);
                            e.captures_blake3.push(hash);
                        }
                    }
                    let mut chain_error = if !o.related.is_empty() && !o.related_chains.is_empty() {
                        Some(anyhow::anyhow!(
                            "mixed related capture modes are unsupported"
                        ))
                    } else {
                        None
                    };
                    let mut verified_groups = Vec::new();
                    let mut chain_budget = 64 * 1024 * 1024u64;
                    for chain in &o.related_chains {
                        if chain_error.is_some() {
                            break;
                        }
                        match crate::related_chain::load(
                            base,
                            manifest_path,
                            chain,
                            &e.case,
                            &o.before,
                            &o.source,
                            &o.after,
                            &mut chain_budget,
                        ) {
                            Ok((group, hashes)) => {
                                verified_groups.push(group);
                                e.captures_blake3.extend(hashes);
                            }
                            Err(err) => {
                                chain_error = Some(err);
                                break;
                            }
                        }
                    }
                    if chain_error.is_none() {
                        if let Err(err) = crate::related_chain::consistent(&verified_groups) {
                            chain_error = Some(err);
                        }
                    }
                    pages.extend(verified_groups);
                    let seed = selected_id(&source["identity"]);
                    let result = match (chain_error, seed) {
                        (Some(err), _) => Err(err),
                        (None, Some(seed)) => crate::related::metrics(
                            &pages,
                            string(&before, "/revision").unwrap(),
                            string(&before, "/source").unwrap(),
                            &o.coordinate,
                            &seed,
                            project.unwrap(),
                            string(&source, "/identity/path").unwrap(),
                            &changed,
                        ),
                        (None, None) => {
                            Err(anyhow::anyhow!("source lacks an exact selected-symbol ID"))
                        }
                    };
                    match result {
                        Ok(m) => {
                            e.graph_basis = "source-bound compiler call edges; global relation coverage unavailable";
                            e.related_metrics = Some(m);
                        }
                        Err(err) => {
                            e.reasons.push(format!("related evidence unknown: {err:#}"));
                            rows.push(e);
                            continue;
                        }
                    }
                }
                if graph_ok && !e.observed_changed_paths.is_empty() {
                    e.status = "observed-match";
                } else if graph_ok {
                    e.reasons
                        .push("no observed changed path; absence is not proof of non-reach".into());
                }
            }
        } else {
            e.reasons.push("no NuDox observation for case".into());
        }
        rows.push(e);
    }
    // More observed changed declarations first. These rows contain no typed edges,
    // so even a complete page is not a dependency graph or a reach proof.
    rows.sort_by(|a, b| {
        (
            b.related_metrics
                .as_ref()
                .map_or(0, |m| m.observed_reachable_changed_nodes),
            b.status == "observed-match",
            b.observed_changed_declarations.len(),
        )
            .cmp(&(
                a.related_metrics
                    .as_ref()
                    .map_or(0, |m| m.observed_reachable_changed_nodes),
                a.status == "observed-match",
                a.observed_changed_declarations.len(),
            ))
            .then_with(|| a.case.cmp(&b.case))
    });
    Ok(Order {
        schema: 1,
        cases: rows.iter().map(|e| e.case.clone()).collect(),
        evidence: rows,
        note: "Ordering only; changed declaration rows are observations, not edges. Dependency complexity, blast radius, confidence and coverage are unknown. Run every case.",
    })
}

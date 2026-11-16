//! Evidence for executable matrix checks. A receipt only binds to a cell when
//! the model explicitly says `run = [ "keel-case" <case-id> ]`.
use crate::{
    model::{CheckCell, Model},
    resolve::Resolution,
};
use anyhow::{Context, Result, bail};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Deserialize)]
struct Manifest {
    schema: u32,
    cases: Vec<ManifestCase>,
}
#[derive(Deserialize)]
struct ManifestCase {
    id: String,
    node: String,
    language: String,
    #[serde(default)]
    requires: Vec<String>,
    steps: Vec<ManifestStep>,
}
#[derive(Deserialize)]
struct ManifestStep {
    id: String,
}
#[derive(Deserialize)]
struct Report {
    schema: u32,
    manifest_sha256: String,
    #[serde(default)]
    driver_sha256: Option<String>,
    binaries: BTreeMap<String, String>,
    cases: Vec<CaseReceipt>,
    #[serde(default)]
    artifact_error: Option<String>,
    #[serde(default)]
    authority_environment: Option<serde_json::Value>,
    #[serde(default)]
    authority_environment_sha256: Option<String>,
    #[serde(default)]
    worlds: Vec<WorldReceipt>,
}
#[derive(Deserialize)]
struct WorldReceipt {
    name: String,
    definition_sha256: String,
    status: String,
    error: String,
}
#[derive(Deserialize)]
struct CaseReceipt {
    id: String,
    node: String,
    language: String,
    status: String,
    steps: Vec<StepReceipt>,
}
#[derive(Deserialize)]
struct StepReceipt {
    id: String,
    status: String,
    #[serde(default)]
    blocked_by: Option<serde_json::Value>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct CheckEvidence {
    pub id: String,
    pub nodes: Vec<String>,
    pub inputs: Vec<crate::model::Selector>,
    pub world: Option<String>,
    pub run: Vec<String>,
    pub case: Option<String>,
    pub definition_sha256: Option<String>,
    pub case_inputs: BTreeMap<String, String>,
    pub artifacts: BTreeMap<String, String>,
    pub state: String,
    #[serde(default)]
    pub blocked_by: Option<String>,
    #[serde(default)]
    pub blocked_by_cases: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct CaseOutcome {
    pub state: String,
    pub definition_sha256: String,
    #[serde(default)]
    pub blocked_by_cases: Vec<String>,
}
#[derive(Serialize, Deserialize, Clone)]
pub struct Evidence {
    pub schema: u32,
    pub manifest_sha256: Option<String>,
    pub authority_environment_sha256: Option<String>,
    #[serde(default)]
    pub driver_sha256: Option<String>,
    #[serde(default)]
    pub driver_verified: bool,
    pub artifacts: BTreeMap<String, String>,
    pub artifacts_verified: bool,
    pub checks: Vec<CheckEvidence>,
    pub roots: BTreeMap<String, Vec<String>>,
    #[serde(default)]
    pub failed_worlds: BTreeMap<String, String>,
    #[serde(default)]
    pub world_definitions: BTreeMap<String, String>,
    #[serde(default)]
    pub case_outcomes: BTreeMap<String, CaseOutcome>,
}
fn digest(bytes: &[u8]) -> String {
    format!("{:x}", Sha256::digest(bytes))
}
fn digest_file(path: &Path) -> Result<String> {
    use std::io::Read;
    let mut file = std::fs::File::open(path).with_context(|| format!("open {}", path.display()))?;
    let mut hash = Sha256::new();
    let mut buffer = [0u8; 64 * 1024];
    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hash.update(&buffer[..n]);
    }
    Ok(format!("{:x}", hash.finalize()))
}
fn case_id(cell: &CheckCell) -> Option<&str> {
    match cell.run.as_slice() {
        [driver, id] if driver == "keel-case" => Some(id),
        _ => None,
    }
}

/// Export all declared checks and merge an optional, identity-checked driver
/// receipt. Missing checks stay unknown; one driver's success never fills a
/// different cell. Artifact files must be supplied to claim a pass or failure.
pub fn evaluate(
    model: &Model,
    res: &Resolution<'_>,
    manifest_path: Option<&Path>,
    report_path: Option<&Path>,
    bin_dir: Option<&Path>,
    driver_binary: Option<&Path>,
) -> Result<Evidence> {
    if manifest_path.is_some() != report_path.is_some() {
        bail!("--manifest and --report must be supplied together");
    }
    let mut manifest_hash = None;
    let mut authority_hash = None;
    let mut driver_hash = None;
    let mut driver_verified = false;
    let mut artifacts = BTreeMap::new();
    let mut verified = false;
    let mut failed_worlds = BTreeMap::new();
    let mut receipts: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut blocked_cases: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut case_outcomes = BTreeMap::new();
    let mut case_inputs: BTreeMap<String, BTreeMap<String, String>> = BTreeMap::new();
    let mut case_artifacts: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    if let (Some(manifest_path), Some(report_path)) = (manifest_path, report_path) {
        let bytes = std::fs::read(manifest_path)
            .with_context(|| format!("read {}", manifest_path.display()))?;
        let raw_manifest: serde_json::Value =
            serde_json::from_slice(&bytes).context("invalid driver manifest")?;
        let manifest: Manifest =
            serde_json::from_value(raw_manifest.clone()).context("invalid driver manifest")?;
        let mut definitions = BTreeMap::new();
        for case in raw_manifest["cases"]
            .as_array()
            .context("manifest cases must be an array")?
        {
            let id = case["id"].as_str().context("manifest case requires id")?;
            definitions.insert(id.to_owned(), digest(&serde_json::to_vec(case)?));
            let mut inputs = BTreeMap::new();
            if let Some(files) = case.get("files") {
                for (path, contents) in files.as_object().context("case files must be an object")? {
                    inputs.insert(
                        path.clone(),
                        digest(
                            contents
                                .as_str()
                                .context("case input must be text")?
                                .as_bytes(),
                        ),
                    );
                }
            }
            case_inputs.insert(id.to_owned(), inputs);
        }
        let report: Report = serde_json::from_slice(
            &std::fs::read(report_path)
                .with_context(|| format!("read {}", report_path.display()))?,
        )
        .context("invalid driver report")?;
        if manifest.schema != 1 || report.schema != 1 {
            bail!("driver manifest and report must use schema 1");
        }
        let hash = digest(&bytes);
        if report.manifest_sha256 != hash {
            bail!("report manifest digest does not match exact manifest bytes");
        }
        if let Some(expected) = report.driver_sha256 {
            if expected.len() != 64
                || !expected
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                bail!("invalid driver identity");
            }
            if let Some(path) = driver_binary {
                if digest_file(path)? != expected {
                    bail!("driver executable digest mismatch");
                }
                driver_verified = true;
            }
            driver_hash = Some(expected);
        }
        match (
            report.authority_environment,
            report.authority_environment_sha256,
        ) {
            (Some(environment), Some(expected)) => {
                if digest(&serde_json::to_vec(&environment)?) != expected {
                    bail!("authority environment digest mismatch");
                }
                authority_hash = Some(expected);
            }
            (None, None) => {}
            _ => bail!("incomplete authority environment identity"),
        }
        if let Some(error) = report.artifact_error {
            bail!("driver rejected artifact: {error}");
        }
        if report.binaries.is_empty() {
            bail!("driver report has no artifact identities");
        }
        for (name, hash) in &report.binaries {
            if name.is_empty()
                || name.contains('/')
                || name == "."
                || name == ".."
                || hash.len() != 64
                || !hash
                    .bytes()
                    .all(|b| b.is_ascii_hexdigit() && !b.is_ascii_uppercase())
            {
                bail!("invalid artifact identity {name:?}");
            }
            if let Some(dir) = bin_dir {
                let actual = digest_file(&dir.join(name))
                    .with_context(|| format!("read artifact {name}"))?;
                if actual != *hash {
                    bail!("artifact digest mismatch for {name}");
                }
            }
        }
        verified = bin_dir.is_some() && driver_verified;
        for observed in report.worlds {
            if observed.status != "fail" || observed.error.is_empty() {
                bail!("world receipt must describe an observed failure");
            }
            let world = model
                .worlds
                .iter()
                .find(|w| w.name == observed.name)
                .with_context(|| format!("unknown world {}", observed.name))?;
            if digest(&serde_json::to_vec(world)?) != observed.definition_sha256 {
                bail!(
                    "world {} definition differs from the evaluated model",
                    observed.name
                );
            }
            if failed_worlds
                .insert(observed.name.clone(), observed.error)
                .is_some()
            {
                bail!("duplicate world receipt {}", observed.name);
            }
        }
        if !verified {
            failed_worlds.clear();
        }
        artifacts = report.binaries;
        let mut cases = BTreeMap::new();
        for case in manifest.cases {
            if cases.insert(case.id.clone(), case).is_some() {
                bail!("duplicate manifest case id");
            }
        }
        for receipt in report.cases {
            let case = cases
                .get(&receipt.id)
                .with_context(|| format!("unknown receipt case {}", receipt.id))?;
            let raw_case = raw_manifest["cases"]
                .as_array()
                .unwrap()
                .iter()
                .find(|c| c["id"].as_str() == Some(&receipt.id))
                .expect("validated case");
            // Process cases explicitly name their executable. For other driver
            // kinds the report's entire verified artifact set is the conservative
            // identity; core does not guess product-specific executable names.
            let mut required = BTreeSet::new();
            let mut needs_full_set = raw_case["daemon"].as_bool() != Some(false);
            for step in raw_case["steps"]
                .as_array()
                .context("case steps must be an array")?
            {
                if step["kind"].as_str() == Some("process") {
                    required.insert(
                        step["binary"]
                            .as_str()
                            .context("process step lacks binary")?
                            .to_owned(),
                    );
                } else {
                    needs_full_set = true;
                }
            }
            if needs_full_set {
                required.extend(artifacts.keys().cloned());
            }
            case_artifacts.insert(receipt.id.clone(), required.clone());
            for binary in required {
                if !artifacts.contains_key(&binary) {
                    bail!(
                        "case {} receipt omits required artifact {binary}",
                        receipt.id
                    );
                }
            }

            if receipt.node != case.node || receipt.language != case.language {
                bail!("case {} node/language differs from manifest", receipt.id);
            }
            if receipt.steps.len() > case.steps.len()
                || receipt
                    .steps
                    .iter()
                    .zip(&case.steps)
                    .any(|(a, b)| a.id != b.id)
            {
                bail!("case {} step identities differ from manifest", receipt.id);
            }
            let mut seen_dependencies = BTreeSet::new();
            let mut blockers = Vec::new();
            for dependency in &case.requires {
                if !seen_dependencies.insert(dependency) || dependency == &receipt.id {
                    bail!("case {} has invalid prerequisites", receipt.id);
                }
                match receipts.get(dependency) {
                    Some(&"pass") => {}
                    Some(&"fail" | &"blocked") => blockers.push(dependency.clone()),
                    Some(_) => bail!("invalid prerequisite status for {dependency}"),
                    None => bail!(
                        "case {} precedes or omits prerequisite {dependency}",
                        receipt.id
                    ),
                }
            }
            let valid_blocked = receipt.status == "blocked"
                && !case.steps.is_empty()
                && !blockers.is_empty()
                && receipt.steps.len() == case.steps.len()
                && receipt.steps.iter().all(|step| {
                    step.status == "blocked"
                        && step
                            .blocked_by
                            .as_ref()
                            .and_then(|v| serde_json::from_value::<Vec<String>>(v.clone()).ok())
                            .as_ref()
                            == Some(&blockers)
                });
            if receipt.status != "blocked" && !blockers.is_empty() {
                bail!("case {} ran despite a failed prerequisite", receipt.id);
            }
            let valid_pass = receipt.status == "pass"
                && receipt.steps.len() == case.steps.len()
                && receipt.steps.iter().all(|s| s.status == "pass");
            let valid_fail = receipt.status == "fail"
                && receipt
                    .steps
                    .iter()
                    .all(|s| ["pass", "fail", "blocked"].contains(&s.status.as_str()));
            if !valid_pass && !valid_fail && !valid_blocked {
                bail!("case {} has inconsistent status", receipt.id);
            }
            let state = if valid_pass {
                "pass"
            } else if valid_fail {
                "fail"
            } else {
                "blocked"
            };
            if valid_blocked {
                blocked_cases.insert(receipt.id.clone(), blockers.clone());
            }
            case_outcomes.insert(
                receipt.id.clone(),
                CaseOutcome {
                    state: state.to_owned(),
                    definition_sha256: definitions[&receipt.id].clone(),
                    blocked_by_cases: blockers,
                },
            );
            if receipts.insert(receipt.id.clone(), state).is_some() {
                bail!("duplicate receipt {}", receipt.id);
            }
        }
        // A case may only bind to a check that names its declared node.
        for group in model.checks.values() {
            for cell in &group.checks {
                if let Some(id) = case_id(cell).filter(|id| receipts.contains_key(*id)) {
                    if let Some(case) = cases.get(id) {
                        let expected = cell
                            .expect
                            .get("definitionSha256")
                            .and_then(serde_json::Value::as_str)
                            .with_context(|| {
                                format!("check for case {id} lacks definitionSha256")
                            })?;
                        if definitions.get(id).map(String::as_str) != Some(expected) {
                            bail!("case {id} definition differs from the evaluated model");
                        }
                        if !cell.on.contains(&case.node) {
                            bail!("case {id} node {} is not on its declared check", case.node);
                        }
                        for node in &cell.on {
                            if res.node_index(node).is_none() {
                                bail!("case {id} refers to unknown node {node}");
                            }
                        }
                    }
                }
            }
        }
        manifest_hash = Some(hash);
    }
    let mut checks = Vec::new();
    let mut bindings = BTreeSet::new();
    for (group, data) in &model.checks {
        for cell in &data.checks {
            let case = case_id(cell);
            if let Some(id) = case {
                if !bindings.insert(id.to_owned()) {
                    bail!("multiple checks bind driver case {id}");
                }
            }
            let blocked_by_cases = if verified {
                case.and_then(|id| blocked_cases.get(id))
                    .cloned()
                    .unwrap_or_default()
            } else {
                Vec::new()
            };
            let mut blocked_by = None;
            let mut cursor = cell.world.as_deref();
            let mut visited = BTreeSet::new();
            while let Some(name) = cursor {
                if !visited.insert(name) {
                    bail!("cyclic world dependency at {name}");
                }
                if verified && failed_worlds.contains_key(name) {
                    blocked_by = Some(name.to_owned());
                    break;
                }
                cursor = model
                    .worlds
                    .iter()
                    .find(|w| w.name == name)
                    .and_then(|w| w.from.as_deref());
            }
            if blocked_by.is_some() && case.is_some_and(|id| receipts.contains_key(id)) {
                bail!(
                    "check {} has a receipt despite a failed prerequisite world",
                    cell.id(group)
                );
            }
            checks.push(CheckEvidence {
                id: cell.id(group),
                nodes: cell.on.clone(),
                inputs: cell.inputs.clone(),
                world: cell.world.clone(),
                run: cell.run.clone(),
                case: case.map(str::to_owned),
                definition_sha256: cell
                    .expect
                    .get("definitionSha256")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned),
                case_inputs: case
                    .and_then(|id| case_inputs.get(id))
                    .cloned()
                    .unwrap_or_default(),
                artifacts: case
                    .and_then(|id| case_artifacts.get(id))
                    .map(|names| {
                        names
                            .iter()
                            .filter_map(|name| {
                                artifacts.get(name).map(|hash| (name.clone(), hash.clone()))
                            })
                            .collect()
                    })
                    .unwrap_or_default(),
                state: if blocked_by.is_some() {
                    "blocked"
                } else if verified {
                    case.and_then(|id| receipts.get(id).copied())
                        .unwrap_or("unknown")
                } else {
                    "unknown"
                }
                .to_owned(),
                blocked_by,
                blocked_by_cases,
            });
        }
    }
    let mut failing: BTreeMap<usize, Vec<String>> = BTreeMap::new();
    for check in checks.iter().filter(|c| c.state == "fail") {
        for node in &check.nodes {
            let index = res
                .node_index(node)
                .with_context(|| format!("check {} names unknown node {node}", check.id))?;
            failing.entry(index).or_default().push(check.id.clone());
        }
    }
    let mut roots = BTreeMap::new();
    for (&n, ids) in &failing {
        if !failing
            .keys()
            .any(|&other| n != other && res.reaches(n, other, None) && !res.reaches(other, n, None))
        {
            roots.insert(res.nodes[n].id.clone(), ids.clone());
        }
    }
    Ok(Evidence {
        schema: 1,
        manifest_sha256: manifest_hash,
        authority_environment_sha256: authority_hash,
        driver_sha256: driver_hash,
        driver_verified,
        artifacts,
        artifacts_verified: bin_dir.is_some(),
        checks,
        roots,
        failed_worlds,
        case_outcomes: if verified {
            case_outcomes
        } else {
            BTreeMap::new()
        },
        world_definitions: model
            .worlds
            .iter()
            .map(|world| Ok((world.name.clone(), digest(&serde_json::to_vec(world)?))))
            .collect::<Result<_>>()?,
    })
}

/// Run a supplied driver against a fresh report path. The caller supplies its
/// arguments explicitly, so this adapter is independent of product-specific CLI.
pub fn execute(
    executable: &Path,
    args: &[String],
    report: &Path,
    timeout: std::time::Duration,
) -> Result<bool> {
    use std::os::unix::process::CommandExt;
    if report.exists() {
        bail!(
            "refusing to reuse existing driver report {}",
            report.display()
        );
    }
    let driver_before = digest_file(executable)?;
    let mut child = std::process::Command::new(executable)
        .args(args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .process_group(0)
        .spawn()
        .with_context(|| format!("start driver {}", executable.display()))?;
    let id = child.id();
    let start = std::time::Instant::now();
    let status = loop {
        match child.try_wait() {
            Ok(Some(status)) => break Some(status),
            Ok(None) if start.elapsed() < timeout => {
                std::thread::sleep(std::time::Duration::from_millis(20))
            }
            Ok(None) => break None,
            Err(e) => {
                let group = kill_group(id);
                let _ = child.kill();
                child.wait().context("reap driver after wait error")?;
                group?;
                return Err(e.into());
            }
        }
    };
    let group = kill_group(id);
    if status.is_none() {
        let _ = child.kill();
        child.wait().context("reap timed-out driver")?;
        group?;
        bail!("driver timed out");
    }
    group?;
    let driver_after = digest_file(executable)?;
    if driver_before != driver_after {
        bail!("driver executable changed during execution");
    }
    // A driver may return nonzero after writing real failing case receipts.
    // Missing or malformed output is rejected by the caller in all cases.
    if !report.is_file() {
        bail!(
            "driver exited {} without producing {}",
            status.unwrap(),
            report.display()
        );
    }
    Ok(status.unwrap().success())
}

fn kill_group(id: u32) -> Result<()> {
    let raw = i32::try_from(id).context("invalid driver process group id")?;
    let pid =
        rustix::process::Pid::from_raw(raw).context("driver process group id must be positive")?;
    match rustix::process::kill_process_group(pid, rustix::process::Signal::KILL) {
        Ok(()) | Err(rustix::io::Errno::SRCH) => Ok(()),
        Err(error) => Err(anyhow::anyhow!("kill driver process group {id}: {error}")),
    }
}

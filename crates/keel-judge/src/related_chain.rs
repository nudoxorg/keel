//! Validate raw paginated captures against a trusted local driver receipt.
//! The unsigned receipt and owner channel are trust inputs, not offline signatures.
use anyhow::{Context, Result, bail};
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest, Sha256};
use std::{
    collections::{BTreeMap, BTreeSet},
    path::Path,
};

#[derive(Deserialize)]
pub(crate) struct Chain {
    pub report: String,
    pub before_step: String,
    pub source_step: String,
    pub after_step: String,
    pub step: String,
    pub pages: Vec<Page>,
}
#[derive(Deserialize)]
pub(crate) struct Page {
    pub request: String,
    pub reply: String,
}

fn read(base: &Path, name: &str) -> Result<(Value, String, String)> {
    let bytes = std::fs::read(base.join(name)).with_context(|| format!("read {name}"))?;
    let v = serde_json::from_slice(&bytes)?;
    Ok((
        v,
        format!("{:x}", Sha256::digest(&bytes)),
        blake3::hash(&bytes).to_hex().to_string(),
    ))
}
fn receipt<'a>(steps: &'a [Value], name: &str) -> Result<(usize, &'a Value)> {
    let matches: Vec<_> = steps
        .iter()
        .enumerate()
        .filter(|(_, step)| step["id"] == name)
        .collect();
    if matches.len() != 1 || matches[0].1["status"] != "pass" {
        bail!("missing, duplicate or failed receipt step {name}");
    }
    Ok(matches[0])
}
fn nonempty(v: &Value) -> bool {
    v.as_str().is_some_and(|s| !s.is_empty())
}

pub(crate) fn consistent(groups: &[Vec<Value>]) -> Result<()> {
    let mut records = BTreeMap::<String, Value>::new();
    let mut claims = BTreeMap::<String, Value>::new();
    let mut scope: Option<Value> = None;
    for page in groups.iter().flatten() {
        if scope
            .as_ref()
            .is_some_and(|prior| *prior != page["related_project_scope"])
        {
            bail!("project scope changed across chains");
        }
        scope = Some(page["related_project_scope"].clone());
        if let Some(rows) = page["records"].as_array() {
            for row in rows {
                if let Some(id) = crate::guidance::selected_id(&row["identity"]) {
                    if records
                        .insert(id, row.clone())
                        .is_some_and(|prior| prior != *row)
                    {
                        bail!("conflicting record across chains");
                    }
                }
            }
        }
        if let Some(rows) = page["related_project_attributions"].as_array() {
            for row in rows {
                let id = row["row_id"]
                    .as_str()
                    .context("claim missing row ID")?
                    .to_owned();
                if claims
                    .insert(id, row.clone())
                    .is_some_and(|prior| prior != *row)
                {
                    bail!("conflicting claim across chains");
                }
            }
        }
    }
    Ok(())
}

pub(crate) fn load(
    base: &Path,
    manifest: &Path,
    c: &Chain,
    case: &str,
    before: &str,
    source: &str,
    after: &str,
) -> Result<(Vec<Value>, Vec<String>)> {
    if c.pages.is_empty() || c.pages.len() > 64 {
        bail!("invalid related chain length");
    }
    let (report, _, mut hashes) = read(base, &c.report).map(|(v, s, b)| (v, s, vec![b]))?;
    let manifest_digest = format!("{:x}", Sha256::digest(std::fs::read(manifest)?));
    if report["schema"] != 1
        || report["status"] != "pass"
        || report["manifest_sha256"] != manifest_digest
        || !report["driver_sha256"]
            .as_str()
            .is_some_and(crate::guidance::valid_selected_id)
    {
        bail!("driver report or manifest binding invalid");
    }
    let cases = report["cases"].as_array().context("missing report cases")?;
    let matches: Vec<_> = cases.iter().filter(|v| v["id"] == case).collect();
    if matches.len() != 1 || matches[0]["status"] != "pass" {
        bail!("missing, duplicate or failed report case");
    }
    let steps = matches[0]["steps"]
        .as_array()
        .context("missing case steps")?;
    let (bi, bs) = receipt(steps, &c.before_step)?;
    let (si, ss) = receipt(steps, &c.source_step)?;
    let (pi, ps) = receipt(steps, &c.step)?;
    let (ai, as_) = receipt(steps, &c.after_step)?;
    if !(bi < si && si < pi && pi < ai) {
        bail!("capture steps are not bracketed");
    }
    for (name, step) in [(before, bs), (source, ss), (after, as_)] {
        let (_, digest, _) = read(base, name)?;
        if step["detail"]["stdout_sha256"] != digest {
            bail!("capture stdout hash mismatch");
        }
    }
    let receipts = ps["detail"]["page_receipts"]
        .as_array()
        .context("missing page receipts")?;
    if receipts.len() != c.pages.len() {
        bail!("page receipt count mismatch");
    }
    let mut pages = Vec::new();
    let mut next: Option<Value> = None;
    let mut process: Option<u64> = None;
    let mut request_ids = BTreeSet::new();
    let mut stable: Option<Vec<Value>> = None;
    let mut scope: Option<Value> = None;
    let mut records = BTreeMap::<String, Value>::new();
    let mut claims = BTreeMap::<String, Value>::new();
    let mut edges = BTreeSet::new();
    for (i, (page, receipt)) in c.pages.iter().zip(receipts).enumerate() {
        let (request, rh, rb) = read(base, &page.request)?;
        let (reply, ph, pb) = read(base, &page.reply)?;
        hashes.extend([rb, pb]);
        let pid = receipt["pid"]
            .as_u64()
            .filter(|n| *n != 0)
            .context("invalid page process")?;
        if process.is_some_and(|p| p != pid) {
            bail!("pages use different processes");
        }
        process = Some(pid);
        if receipt["request_sha256"] != rh
            || receipt["reply_sha256"] != ph
            || request["id"] != receipt["request_id"]
            || reply["id"] != request["id"]
        {
            bail!("page receipt or request identity mismatch");
        }
        if !request_ids.insert(request["id"].to_string())
            || !(request["id"].is_u64() || request["id"].is_string())
            || request["jsonrpc"] != "2.0"
            || reply["jsonrpc"] != "2.0"
            || request["method"] != "tools/call"
            || request["params"]["name"] != "backend.related"
            || reply["result"]["isError"] == true
        {
            bail!("invalid related call");
        }
        if i == 0 {
            if request["params"]["arguments"].get("cursor").is_some() {
                bail!("initial page has cursor");
            }
        } else if next.as_ref() != Some(&request["params"]) {
            bail!("continuation handoff mismatch");
        }
        let p = &reply["result"]["structuredContent"];
        if p["answer"] != "records" || p["related_evidence_withheld"] != false {
            bail!("related evidence withheld");
        }
        let b = &p["related_basis"];
        if request["params"]["arguments"]["coordinate"] != b["coordinate"] {
            bail!("request center does not match page basis");
        }
        let keys = [
            "schema",
            "source_view_root",
            "source_object",
            "branch",
            "log",
            "source_schema",
            "sequence",
            "semantic_revision",
            "center_id",
            "coordinate",
            "relation_coverage",
        ];
        let cur: Vec<_> = keys.iter().map(|k| b[*k].clone()).collect();
        if stable.as_ref().is_some_and(|prior| *prior != cur) {
            bail!("chain basis changed");
        }
        stable = Some(cur);
        if !nonempty(&b["neighborhood_root"]) {
            bail!("missing neighborhood root");
        }
        if scope
            .as_ref()
            .is_some_and(|v| *v != p["related_project_scope"])
        {
            bail!("chain project scope changed");
        }
        scope = Some(p["related_project_scope"].clone());
        for row in p["records"].as_array().context("missing records")? {
            if let Some(id) = crate::guidance::selected_id(&row["identity"]) {
                if records
                    .insert(id, row.clone())
                    .is_some_and(|old| old != *row)
                {
                    bail!("conflicting repeated row");
                }
            }
        }
        if let Some(a) = p["related_project_attributions"].as_array() {
            for claim in a {
                let key = claim["row_id"]
                    .as_str()
                    .context("claim missing row ID")?
                    .to_owned();
                if claims
                    .insert(key, claim.clone())
                    .is_some_and(|old| old != *claim)
                {
                    bail!("conflicting repeated claim");
                }
            }
        }
        for edge in p["edges"].as_array().context("missing edges")? {
            let key = (
                edge["from_id"].to_string(),
                edge["to_id"].to_string(),
                edge["relation"].to_string(),
            );
            if !edges.insert(key) {
                bail!("repeated chain edge");
            }
        }
        if i + 1 == c.pages.len() {
            if p["more"] != false
                || p.get("continuation_call").is_some()
                || p.get("nextCursor").is_some()
            {
                bail!("chain not terminal");
            }
            next = None;
        } else {
            if p["more"] != true || !p["continuation_call"].is_object() {
                bail!("missing continuation");
            }
            if !nonempty(&p["nextCursor"])
                || p["nextCursor"] != p["continuation_call"]["arguments"]["cursor"]
            {
                bail!("continuation cursor mismatch");
            }
            next = Some(p["continuation_call"].clone());
        }
        pages.push(p.clone());
    }
    Ok((pages, hashes))
}

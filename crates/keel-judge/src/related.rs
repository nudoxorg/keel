//! Metrics for the *captured* compiler-call graph, never the whole program.
use anyhow::{Result, bail};
use serde::Serialize;
use serde_json::Value;
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Serialize)]
pub struct Metrics {
    pub basis: &'static str,
    pub view_root: String,
    pub semantic_revision: String,
    pub root_id: String,
    pub observed_nodes: usize,
    pub observed_call_edges: usize,
    pub observed_join_nodes: usize,
    pub direct_callers: usize,
    pub transitive_callers: usize,
    pub observed_cyclic_components: usize,
    pub max_reverse_shortest_depth: usize,
    pub observed_reachable_changed_nodes: usize,
    pub unattributed_related_nodes: usize,
}
fn text<'a>(v: &'a Value, key: &str) -> Result<&'a str> {
    v.get(key)
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| anyhow::anyhow!("missing {key}"))
}
fn id(s: &str) -> bool {
    s.strip_prefix("symbol:")
        .is_some_and(crate::guidance::valid_selected_id)
}
fn hex(s: &str) -> bool {
    s.len() == 64 && s.bytes().all(|c| c.is_ascii_hexdigit())
}
fn witness_hash(v: &Value) -> bool {
    v.as_str().is_some_and(crate::guidance::valid_selected_id)
}

pub(crate) fn metrics(
    pages: &[Vec<Value>],
    source_view: &str,
    source_object: &str,
    coordinate: &str,
    source_id: &str,
    project: &str,
    source_path: &str,
    changed: &BTreeSet<String>,
) -> Result<Metrics> {
    if pages.is_empty() {
        bail!("no related pages");
    }
    let mut basis: Option<Vec<Value>> = None;
    let mut labels = BTreeMap::<String, String>::new();
    let mut centers = BTreeSet::new();
    let mut root = None;
    let mut edges = BTreeSet::<(String, String)>::new();
    let mut rows = Vec::new();
    for group in pages {
        for (page_index, page) in group.iter().enumerate() {
            let b = page
                .get("related_basis")
                .ok_or_else(|| anyhow::anyhow!("missing related basis"))?;
            if b["schema"] != 1
                || page["answer"] != "records"
                || (group.len() == 1 && page["more"] != false)
                || page["related_evidence_withheld"] != false
                || b["relation_coverage"] != "unknown"
                || (group.len() == 1 && page.get("continuation_call").is_some())
                || (group.len() == 1 && page.get("nextCursor").is_some())
            {
                bail!("incomplete or withheld related page");
            }
            let view = text(b, "source_view_root")?;
            if !hex(view) || view != source_view {
                bail!("related view root does not match status");
            }
            if text(b, "source_object")? != source_object {
                bail!("related source object does not match status");
            }
            for k in [
                "source_object",
                "branch",
                "log",
                "semantic_revision",
                "neighborhood_root",
            ] {
                if !hex(text(b, k)?) {
                    bail!("invalid {k}");
                }
            }
            if b["source_schema"].as_u64().is_none() || b["sequence"].as_u64().is_none() {
                bail!("missing source schema/sequence");
            }
            let current: Vec<Value> = [
                "source_view_root",
                "source_object",
                "branch",
                "log",
                "source_schema",
                "sequence",
                "semantic_revision",
            ]
            .iter()
            .map(|k| b[*k].clone())
            .collect();
            if basis.as_ref().is_some_and(|x| x != &current) {
                bail!("related pages have different source or semantic revisions");
            }
            basis = Some(current);
            let center = text(b, "center_id")?;
            let label = text(b, "coordinate")?;
            if !id(center) || (page_index == 0 && !centers.insert(center.to_owned())) {
                bail!("invalid or duplicate center");
            }
            if labels
                .insert(center.into(), label.into())
                .is_some_and(|old| old != label)
            {
                bail!("center label conflict");
            }
            if label == coordinate && page_index == 0 {
                if root.replace(center.to_owned()).is_some() {
                    bail!("duplicate selected root");
                }
            }
            if let Some(records) = page["records"].as_array() {
                rows.extend(records.iter().cloned().map(|row| {
                    (
                        row,
                        page["related_project_scope"].clone(),
                        page["related_project_attributions"].clone(),
                        b["semantic_revision"].clone(),
                    )
                }));
            }
            for edge in page["edges"]
                .as_array()
                .ok_or_else(|| anyhow::anyhow!("missing edges"))?
            {
                let from = text(edge, "from_id")?;
                let to = text(edge, "to_id")?;
                if !id(from) || !id(to) || (from != center && to != center) {
                    bail!("invalid endpoint or non-incident edge");
                }
                for (key, label_key) in [(from, "from"), (to, "to")] {
                    let label = text(edge, label_key)?;
                    if labels
                        .insert(key.into(), label.into())
                        .is_some_and(|old| old != label)
                    {
                        bail!("conflicting endpoint labels");
                    }
                }
                let relation = text(edge, "relation")?;
                if !matches!(
                    relation,
                    "calls"
                        | "method-call"
                        | "type-reference"
                        | "reads"
                        | "writes"
                        | "imports"
                        | "implements"
                        | "overrides"
                        | "reexports"
                        | "inherits"
                        | "documents"
                ) {
                    bail!("invalid relation");
                }
                if edge.get("confidence").is_none() {
                    bail!("missing confidence");
                }
                if !edge["confidence"].is_null()
                    && !matches!(
                        edge["confidence"].as_str(),
                        Some("syntactic" | "heuristic" | "indexed" | "imported" | "compiler")
                    )
                {
                    bail!("invalid confidence");
                }
                if matches!(relation, "calls" | "method-call") && edge["confidence"] == "compiler" {
                    edges.insert((from.into(), to.into()));
                }
            }
        }
    }
    let root =
        root.ok_or_else(|| anyhow::anyhow!("selected coordinate is absent from related centers"))?;
    if root != format!("symbol:{source_id}") {
        bail!("related center identity does not match selected source");
    }
    if labels.len() > 512 || edges.len() > 10000 {
        bail!("captured graph exceeds analysis limit");
    }
    let mut reverse = BTreeMap::<String, Vec<String>>::new();
    for (from, to) in &edges {
        reverse.entry(to.clone()).or_default().push(from.clone());
    }
    let reverse_reach = |start: &str| {
        let mut distances = BTreeMap::from([(start.to_owned(), 0usize)]);
        let mut queue = VecDeque::from([start.to_owned()]);
        while let Some(node) = queue.pop_front() {
            let next = distances[&node] + 1;
            for from in reverse.get(&node).into_iter().flatten() {
                if !distances.contains_key(from) {
                    distances.insert(from.clone(), next);
                    queue.push_back(from.clone());
                }
            }
        }
        distances
    };
    let dist = reverse_reach(&root);
    let direct = edges
        .iter()
        .filter(|(from, to)| *to == root && *from != root)
        .map(|(from, _)| from)
        .collect::<BTreeSet<_>>()
        .len();
    // Mutual reverse reach gives SCCs of the captured graph; no completeness claim.
    let reach: BTreeMap<_, _> = labels
        .keys()
        .map(|node| (node.clone(), reverse_reach(node)))
        .collect();
    let mut unseen: BTreeSet<_> = labels.keys().cloned().collect();
    let mut cyclic = 0;
    while let Some(node) = unseen.iter().next().cloned() {
        let reaching = &reach[&node];
        let component: Vec<_> = unseen
            .iter()
            .filter(|other| reaching.contains_key(*other) && reach[*other].contains_key(&node))
            .cloned()
            .collect();
        if component.len() > 1 || edges.contains(&(node.clone(), node.clone())) {
            cyclic += 1;
        }
        for member in component {
            unseen.remove(&member);
        }
    }
    let mut forward = BTreeMap::<String, Vec<String>>::new();
    for (from, to) in &edges {
        forward.entry(from.clone()).or_default().push(to.clone());
    }
    let mut reachable = BTreeSet::from([root.clone()]);
    let mut queue = VecDeque::from([root.clone()]);
    while let Some(node) = queue.pop_front() {
        for to in forward.get(&node).into_iter().flatten() {
            if reachable.insert(to.clone()) {
                queue.push_back(to.clone());
            }
        }
    }
    // The seed has an independently returned source identity and project.
    // Other endpoints require a matching owner-issued statement on the same page.
    // This checks visible consistency, not the owner's seal or source membership.
    // Opaque coordinate text is never parsed to infer project ownership.
    let mut attributed = BTreeMap::from([(root.clone(), source_path.to_owned())]);
    for (row, scope, claims, semantic_revision) in rows {
        if row.pointer("/identity/project").and_then(Value::as_str) != Some(project) {
            continue;
        }
        let Some(id) = crate::guidance::selected_id(&row["identity"]) else {
            continue;
        };
        let id = format!("symbol:{id}");
        let Some(coordinate) = row.pointer("/identity/coordinate").and_then(Value::as_str) else {
            continue;
        };
        let Some(path) = row.pointer("/identity/path").and_then(Value::as_str) else {
            continue;
        };
        let Some(claims) = claims.as_array() else {
            continue;
        };
        let matching: Vec<_> = claims
            .iter()
            .filter(|claim| claim["row_id"] == id)
            .collect();
        if matching.len() != 1 {
            continue;
        }
        let claim = matching[0];
        if claim["project"] != project
            || claim["path"] != path
            || claim["view_root"] != source_view
            || claim["semantic_revision"] != semantic_revision
            || claim["source_relation_root"] != scope["source_relation_root"]
            || claim["workspace_root"] != scope["workspace_root"]
            || ![
                "project_key",
                "source_fact",
                "image_digest",
                "seal",
                "source_relation_root",
                "workspace_root",
            ]
            .iter()
            .all(|field| witness_hash(&claim[*field]))
            || claim["entity_index"].as_u64().is_none()
        {
            continue;
        }
        if labels.get(&id).is_some_and(|label| label == coordinate)
            && crate::guidance::normal_path(path)
        {
            if attributed
                .insert(id, path.to_owned())
                .is_some_and(|old| old != path)
            {
                bail!("conflicting related endpoint paths");
            }
        }
    }
    let changed_nodes = reachable
        .iter()
        .filter(|id| {
            attributed
                .get(*id)
                .is_some_and(|path| changed.contains(path))
        })
        .count();
    let unattributed_related_nodes = labels
        .keys()
        .filter(|id| !attributed.contains_key(*id))
        .count();
    let basis = basis.unwrap();
    Ok(Metrics {
        basis: "observed subgraph of compiler call edges from source-bound captures; global relation coverage unknown; SCC count and depth are not global lower bounds",
        view_root: source_view.into(),
        semantic_revision: basis[6].as_str().unwrap().into(),
        root_id: root,
        observed_nodes: labels.len(),
        observed_call_edges: edges.len(),
        observed_join_nodes: reverse.values().filter(|sources| sources.len() > 1).count(),
        direct_callers: direct,
        transitive_callers: dist.len().saturating_sub(1),
        observed_cyclic_components: cyclic,
        max_reverse_shortest_depth: dist.values().copied().max().unwrap_or(0),
        observed_reachable_changed_nodes: changed_nodes,
        unattributed_related_nodes,
    })
}

//! Structural aggregation of owner-provided related pages, not an authority proof.
use serde_json::{Value, json};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Default)]
pub(crate) struct RelatedPages {
    basis: Option<Value>,
    scope: Option<Option<Value>>,
    roots: Vec<Value>,
    page_results: Vec<Value>,
    rows: BTreeMap<String, Value>,
    records: Vec<Value>,
    claims_by_row: BTreeMap<String, Value>,
    claims: Vec<Value>,
    edge_keys: BTreeSet<(String, String, String)>,
    edges: Vec<Value>,
}
fn digest(value: &Value) -> bool {
    value.as_str().is_some_and(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
            && s.bytes().any(|b| b != b'0')
    })
}
fn symbol(value: &Value) -> Result<String, String> {
    let key = value
        .as_str()
        .and_then(|s| s.strip_prefix("symbol:"))
        .filter(|s| {
            s.len() == 64
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
                && s.bytes().any(|b| b != b'0')
        })
        .ok_or("related row has invalid selected symbol id")?;
    Ok(format!("symbol:{key}"))
}
impl RelatedPages {
    pub(crate) fn push(&mut self, page: &Value, page_number: usize) -> Result<(), String> {
        let basis = page["related_basis"]
            .as_object()
            .ok_or("related page lacks basis")?;
        let names = [
            "schema",
            "source_view_root",
            "source_object",
            "branch",
            "log",
            "source_schema",
            "sequence",
            "semantic_revision",
            "neighborhood_root",
            "center_id",
            "coordinate",
            "relation_coverage",
        ];
        if names.iter().any(|name| !basis.contains_key(*name)) {
            return Err("related basis incomplete".into());
        }
        if basis["schema"] != 1
            || basis["source_schema"].as_u64().is_none()
            || basis["sequence"].as_u64().is_none()
            || [
                "source_view_root",
                "source_object",
                "branch",
                "log",
                "semantic_revision",
                "neighborhood_root",
            ]
            .iter()
            .any(|key| !digest(&basis[*key]))
            || symbol(&basis["center_id"]).is_err()
            || !basis["coordinate"].as_str().is_some_and(|s| !s.is_empty())
            || !basis["relation_coverage"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
        {
            return Err("related basis malformed".into());
        }
        let root = basis
            .get("neighborhood_root")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty())
            .ok_or("related neighborhood root absent")?;
        self.roots.push(json!(root));
        let mut stable = basis.clone();
        stable.remove("neighborhood_root");
        let stable = Value::Object(stable);
        if self.basis.as_ref().is_some_and(|b| b != &stable) {
            return Err("related basis changed during continuation".into());
        }
        self.basis.get_or_insert(stable);
        let scope = page.get("related_project_scope").cloned();
        if scope.as_ref().is_some_and(|s| {
            !s.is_object() || !digest(&s["workspace_root"]) || !digest(&s["source_relation_root"])
        }) {
            return Err("related project scope malformed".into());
        }
        if self.scope.as_ref().is_some_and(|old| old != &scope) {
            return Err("related project scope changed during continuation".into());
        }
        self.scope.get_or_insert(scope.clone());
        let rows = page["records"].as_array().ok_or("related records absent")?;
        for row in rows {
            let id = &row["identity"]["semantic_data"];
            if id["kind"] != "selected-symbol-id" {
                return Err("related row lacks selected symbol id".into());
            }
            let id = symbol(&json!(format!(
                "symbol:{}",
                id["value"]
                    .as_str()
                    .ok_or("related selected symbol missing value")?
            )))?;
            if !row["identity"]["coordinate"]
                .as_str()
                .is_some_and(|s| !s.is_empty())
            {
                return Err("related row coordinate absent".into());
            }
            match self.rows.get(&id) {
                Some(old) if old != row => {
                    return Err("related symbol id reused for conflicting rows".into());
                }
                Some(_) => {}
                None => {
                    self.rows.insert(id, row.clone());
                    self.records.push(row.clone());
                }
            }
        }
        match (scope, page.get("related_project_attributions")) {
            (Some(_), Some(Value::Array(claims))) => {
                for claim in claims {
                    let id = symbol(&claim["row_id"])?;
                    match self.claims_by_row.get(&id) {
                        Some(old) if old != claim => {
                            return Err("related symbol id reused for conflicting claims".into());
                        }
                        Some(_) => {}
                        None => {
                            self.claims_by_row.insert(id, claim.clone());
                            self.claims.push(claim.clone());
                        }
                    }
                }
            }
            (None, None) => {}
            _ => return Err("related project attributions lack matching scope".into()),
        }
        let edges = page["edges"].as_array().ok_or("related edges absent")?;
        let more = page["more"].as_bool().ok_or("related more flag absent")?;
        let next = page.get("continuation_call");
        let cursor = page
            .get("nextCursor")
            .and_then(Value::as_str)
            .filter(|s| !s.is_empty());
        if more {
            let call = next.ok_or("related more lacks continuation")?;
            if call.as_object().is_none_or(|o| {
                o.len() != 2
                    || !o.get("name").is_some_and(Value::is_string)
                    || !o.get("arguments").is_some_and(Value::is_object)
            }) || cursor.is_none()
                || call["arguments"]["cursor"].as_str() != cursor
            {
                return Err("related continuation does not match opaque cursor".into());
            }
        } else if next.is_some_and(|n| !n.is_null())
            || page.get("nextCursor").is_some_and(|value| !value.is_null())
        {
            return Err("related terminal page has continuation".into());
        }
        if (page_number > 0 || more) && edges.is_empty() {
            return Err("related continuation made no edge progress".into());
        }
        for edge in edges {
            if !edge["confidence"].as_str().is_some_and(|s| !s.is_empty()) {
                return Err("related edge confidence absent".into());
            }
            let from = symbol(&edge["from_id"])?;
            let to = symbol(&edge["to_id"])?;
            let relation = edge["relation"]
                .as_str()
                .filter(|s| !s.is_empty())
                .ok_or("related edge relation absent")?
                .to_owned();
            if !self.edge_keys.insert((from, to, relation)) {
                return Err("related continuation repeated a typed edge".into());
            }
            self.edges.push(edge.clone());
        }
        self.page_results.push(page.clone());
        Ok(())
    }
    pub(crate) fn finish(self, pages: usize, first: Value, last: Value) -> Result<Value, String> {
        let basis = self.basis.as_ref().ok_or("related basis missing")?;
        let center = symbol(&basis["center_id"])?;
        if self
            .rows
            .get(&center)
            .is_none_or(|row| row["identity"]["coordinate"] != basis["coordinate"])
        {
            return Err("related center does not resolve to a row".into());
        }
        for edge in &self.edges {
            for (id, coordinate) in [("from_id", "from"), ("to_id", "to")] {
                let id = symbol(&edge[id])?;
                if self
                    .rows
                    .get(&id)
                    .is_none_or(|row| row["identity"]["coordinate"] != edge[coordinate])
                {
                    return Err("related edge endpoint does not resolve to a row coordinate".into());
                }
            }
        }
        if self
            .claims_by_row
            .keys()
            .any(|id| !self.rows.contains_key(id))
        {
            return Err("related claim has no selected row".into());
        }
        Ok(
            json!({"pages":pages,"records":self.records,"edges":self.edges,"related_project_attributions":self.claims,"neighborhood_roots":self.roots,"page_results":self.page_results,"first":first,"last":last}),
        )
    }
}

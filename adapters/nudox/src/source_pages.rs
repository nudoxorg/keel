//! Byte geometry for owner-provided source ranges; no whole-file completeness claim.
use serde_json::{Value, json};

#[derive(Default)]
pub(crate) struct SourcePages {
    text: String,
    end: u64,
    basis: Option<Value>,
    policies: Vec<Value>,
    pages: Vec<Value>,
}
impl SourcePages {
    pub(crate) fn push(&mut self, page: &Value) -> Result<Option<String>, String> {
        let source = page
            .get("source")
            .and_then(Value::as_object)
            .ok_or("source range missing")?;
        let number = |name: &str| {
            source
                .get(name)
                .and_then(Value::as_u64)
                .filter(|v| *v <= u32::MAX as u64)
                .ok_or_else(|| format!("invalid source {name}"))
        };
        let start = number("start")?;
        let end = number("end")?;
        let total = number("total")?;
        let owner_start = number("owner_start")?;
        let owner_end = number("owner_end")?;
        let text = source
            .get("text")
            .and_then(Value::as_str)
            .ok_or("source text missing")?;
        let scope = source
            .get("scope")
            .and_then(Value::as_str)
            .filter(|s| {
                matches!(
                    *s,
                    "unknown" | "native_primary_declaration" | "structural_declaration"
                )
            })
            .ok_or("source scope invalid")?;
        let identity = source
            .get("source_identity")
            .and_then(Value::as_array)
            .filter(|a| {
                a.len() == 32
                    && a.iter().all(|v| v.as_u64().is_some_and(|v| v <= 255))
                    && a.iter().any(|v| v.as_u64() != Some(0))
            })
            .ok_or("source identity malformed")?;
        if start != self.end
            || end <= start
            || end > total
            || end - start != text.len() as u64
            || text.len() > 4096
            || owner_end.checked_sub(owner_start) != Some(total)
        {
            return Err("source page geometry or progress invalid".into());
        }
        let basis = json!({"scope":scope,"source_identity":identity,"total":total,"owner_start":owner_start,"owner_end":owner_end});
        if self.basis.as_ref().is_some_and(|old| old != &basis) {
            return Err("source page identity or owner scope changed".into());
        }
        self.basis.get_or_insert(basis);
        self.text.push_str(text);
        self.end = end;
        self.policies
            .push(source.get("source_policy").cloned().unwrap_or(Value::Null));
        self.pages.push(page.clone());
        let cursor = match page.get("nextCursor") {
            None | Some(Value::Null) => None,
            Some(Value::String(s)) if !s.is_empty() => Some(s.clone()),
            _ => return Err("source cursor malformed".into()),
        };
        if (end < total) != cursor.is_some() {
            return Err("source cursor does not match frontier".into());
        }
        Ok(cursor)
    }
    pub(crate) fn finish(&self) -> Result<Value, String> {
        let basis = self.basis.as_ref().ok_or("source pages missing")?;
        if self.end != basis["total"].as_u64().ok_or("source total missing")? {
            return Err("source range did not reach its scoped end".into());
        }
        Ok(
            json!({"pages":self.pages.len(),"text":self.text,"bytes":self.text.len(),"scope":basis["scope"],"source_identity":basis["source_identity"],"total":basis["total"],"owner_start":basis["owner_start"],"owner_end":basis["owner_end"],"source_policies":self.policies,"first":self.pages.first(),"last":self.pages.last(),"page_results":self.pages}),
        )
    }
}

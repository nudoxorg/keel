//! Byte geometry for owner-provided source ranges; no whole-file completeness claim.
use serde_json::{Value, json};

fn canonical_hex(value: &Value) -> Option<&str> {
    value.as_str().filter(|s| {
        s.len() == 64
            && s.bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    })
}

// Copy the selected identity's actual bytes; no coordinate-derived fallback.
pub(crate) fn requested_symbol(arguments: &Value) -> Result<Option<String>, String> {
    let Some(selected) = arguments.get("selected_symbol") else {
        return Ok(None);
    };
    if selected["kind"] != "selected-symbol-id" {
        return Err("source requested selected symbol malformed".into());
    }
    let value = &selected["value"];
    let hex = if let Some(hex) = canonical_hex(value) {
        hex.to_owned()
    } else {
        let bytes = value
            .as_array()
            .filter(|a| a.len() == 32)
            .ok_or("source selected symbol must be canonical hex or 32 bytes")?;
        let mut hex = String::with_capacity(64);
        for byte in bytes {
            use std::fmt::Write;
            let byte = byte
                .as_u64()
                .and_then(|n| u8::try_from(n).ok())
                .ok_or("source selected symbol byte invalid")?;
            write!(&mut hex, "{byte:02x}").map_err(|_| "source selected symbol encoding failed")?;
        }
        hex
    };
    if hex.bytes().all(|b| b == b'0') {
        return Err("source selected symbol is zero".into());
    }
    Ok(Some(hex))
}

pub(crate) struct SourcePages {
    expected_selected: Option<String>,
    expected_coordinate: Option<String>,
    cli: bool,
    text: String,
    end: u64,
    basis: Option<Value>,
    policies: Vec<Value>,
    pages: Vec<Value>,
}
impl SourcePages {
    pub(crate) fn new(
        expected_selected: Option<String>,
        expected_coordinate: Option<String>,
        cli: bool,
    ) -> Self {
        Self {
            expected_selected,
            expected_coordinate,
            cli,
            text: String::new(),
            end: 0,
            basis: None,
            policies: Vec::new(),
            pages: Vec::new(),
        }
    }
    pub(crate) fn push(&mut self, page: &Value) -> Result<Option<String>, String> {
        let revision = canonical_hex(&page["revision"]).ok_or("source revision malformed")?;
        let selected = canonical_hex(&page["selected_symbol"])
            .filter(|v| v.bytes().any(|b| b != b'0'))
            .ok_or("source selected symbol malformed")?;
        if self
            .expected_selected
            .as_deref()
            .is_some_and(|expected| expected != selected)
        {
            return Err("source selected symbol differs from request".into());
        }
        if (self.cli && page["verified_at_read"] != true)
            || (!self.cli && page["freshness"] != "verified_at_read")
        {
            return Err("source page is not verified at read".into());
        }
        let coordinate = match page.get("coordinate") {
            None => Value::Null,
            Some(Value::String(s)) if !s.is_empty() => json!(s),
            _ => return Err("source coordinate malformed".into()),
        };
        if self
            .expected_coordinate
            .as_ref()
            .is_some_and(|expected| coordinate.as_str() != Some(expected.as_str()))
        {
            return Err("source coordinate differs from request".into());
        }
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
        let basis = json!({"revision":revision,"selected_symbol":selected,"coordinate":coordinate,"scope":scope,"source_identity":identity,"total":total,"owner_start":owner_start,"owner_end":owner_end});
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
            json!({"pages":self.pages.len(),"text":self.text,"bytes":self.text.len(),"revision":basis["revision"],"selected_symbol":basis["selected_symbol"],"coordinate":basis["coordinate"],"scope":basis["scope"],"source_identity":basis["source_identity"],"total":basis["total"],"owner_start":basis["owner_start"],"owner_end":basis["owner_end"],"source_policies":self.policies,"first":self.pages.first(),"last":self.pages.last(),"page_results":self.pages}),
        )
    }
}

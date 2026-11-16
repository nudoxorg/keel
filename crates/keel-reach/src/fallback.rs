//! Why a test's reach is not trusted: a record callers can count and group, and a
//! sentence for people.
//!
//! The reason used to be one free-text string, which made "which function makes 56
//! tests fall back" a regular-expression exercise over 472 MB of JSON.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

/// How a flagged function came to be in a test's reach.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Via {
    /// The flagged function itself is an atom of the reach.
    Contains,
    /// An atom of the reach has a relocation to the flagged function (or to an import).
    Calls,
}

/// The specific symbol that carried a capability flag, and where it was found.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Culprit {
    pub via: Via,
    /// Demangled name of the symbol whose name carries the flag. When an atom has several
    /// names (merged or aliased functions) this is the one that matched, not the one that
    /// names the atom.
    pub callee: String,
    /// Demangled name of the atom that references the callee; absent for `Contains`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    /// `archive!member` of the caller (of the callee for `Contains`).
    pub object: String,
    /// The naming symbol of the flagged atom when the flagged name is an alias of it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub alias_of: Option<String>,
}

impl Culprit {
    /// What reports group by: the calling function, or the function itself for `Contains`.
    pub fn group(&self) -> &str {
        self.caller.as_deref().unwrap_or(&self.callee)
    }
}

/// A test's key must come from the executable, and why.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Fallback {
    /// The reach can find files beside the running executable or re-execute it.
    CurrentExe(Culprit),
    /// The reach loads code at run time; that code is outside the link and outside the
    /// executable, so the executable key does NOT cover it (`exe_key_sufficient` is false):
    /// the caller must key the library too, or always run the test.
    #[serde(rename = "loads-library")]
    LoadsLibrary(Culprit),
    /// The reach spawns processes. Not a fallback by default (callers add the hashes of the
    /// binaries they spawn), recorded on the test as `spawns`; the variant exists so that a
    /// caller that wants it to be one can say so.
    Command(Culprit),
    /// A symbol in the reach is defined by more than one input with different content, and
    /// the order in which the linker saw them cannot be established, so which copy runs is
    /// unknown. The executable key covers whichever copy was linked.
    DuplicateDefinition {
        symbol: String,
        /// Number of definitions of the strongest kind.
        definitions: usize,
        why: String,
        caller: Option<String>,
        object: String,
    },
    /// No entry point could be established for the test.
    NoEntry {
        test: String,
        /// Symbol paths looked for.
        looked_for: Vec<String>,
        /// Whether a test descriptor naming this test was found, and why it did not give an entry.
        detail: String,
    },
    /// The inputs of the whole binary could not all be read.
    Unverifiable { why: String },
}

impl Fallback {
    pub fn kind(&self) -> &'static str {
        match self {
            Fallback::CurrentExe(_) => "current_exe",
            Fallback::LoadsLibrary(_) => "loads-library",
            Fallback::DuplicateDefinition { .. } => "duplicate-definition",
            Fallback::Command(_) => "command",
            Fallback::NoEntry { .. } => "no_entry",
            Fallback::Unverifiable { .. } => "unverifiable",
        }
    }

    pub fn culprit(&self) -> Option<&Culprit> {
        match self {
            Fallback::CurrentExe(c) | Fallback::LoadsLibrary(c) | Fallback::Command(c) => Some(c),
            _ => None,
        }
    }

    /// What `(kind, caller)` counts group by.
    pub fn group(&self) -> String {
        match self {
            Fallback::NoEntry { .. } => "-".into(),
            Fallback::Unverifiable { .. } => "-".into(),
            Fallback::DuplicateDefinition { symbol, .. } => symbol.clone(),
            f => f.culprit().map_or_else(String::new, |c| c.group().to_string()),
        }
    }

    /// Whether the executable''s key is enough to decide that this test must rerun. It is
    /// not when the test runs code the executable does not contain.
    pub fn exe_key_sufficient(&self) -> bool {
        !matches!(self, Fallback::LoadsLibrary(_) | Fallback::Command(_))
    }

    /// Read the free-text reasons of reports written before this type existed.
    pub fn from_legacy(text: &str) -> Fallback {
        if let Some(why) = text.strip_prefix("unverifiable: ") {
            return Fallback::Unverifiable { why: why.into() };
        }
        let ticks = |s: &str| -> Vec<String> {
            s.split('`').skip(1).step_by(2).map(str::to_string).collect()
        };
        if let Some(rest) = text.strip_prefix("no symbol found for test ") {
            let t = ticks(rest);
            return Fallback::NoEntry {
                test: t.first().cloned().unwrap_or_default(),
                looked_for: t.get(1..).unwrap_or_default().to_vec(),
                detail: String::new(),
            };
        }
        let (via, rest) = if let Some(r) = text.strip_prefix("reach contains ") {
            (Via::Contains, r)
        } else if let Some(r) = text.strip_prefix("reach calls ") {
            (Via::Calls, r)
        } else {
            return Fallback::Unverifiable { why: text.into() };
        };
        let t = ticks(rest);
        let callee = t.first().cloned().unwrap_or_default();
        let object = rest
            .split_once("(from ")
            .and_then(|(_, r)| r.split_once(')'))
            .map(|(p, _)| p.to_string())
            .unwrap_or_default();
        let c = Culprit {
            via,
            caller: (via == Via::Calls).then(|| t.get(1).cloned().unwrap_or_default()),
            callee,
            object,
            alias_of: None,
        };
        if c.callee.contains("current_exe") {
            Fallback::CurrentExe(c)
        } else {
            Fallback::LoadsLibrary(c)
        }
    }
}

impl fmt::Display for Fallback {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Fallback::CurrentExe(c) | Fallback::LoadsLibrary(c) | Fallback::Command(c) => {
                let why = match self {
                    Fallback::Command(_) => "spawns processes",
                    Fallback::LoadsLibrary(_) => "loads a library at run time",
                    _ => "depends on the running executable",
                };
                match c.via {
                    Via::Contains => write!(
                        f,
                        "reach contains `{}` (from {})",
                        c.callee, c.object
                    )?,
                    Via::Calls => write!(
                        f,
                        "reach calls `{}` in `{}` (from {})",
                        c.callee,
                        c.caller.as_deref().unwrap_or("?"),
                        c.object
                    )?,
                }
                if let Some(a) = &c.alias_of {
                    write!(f, ", a second name of `{a}`")?;
                }
                match self {
                    Fallback::LoadsLibrary(_) => write!(
                        f,
                        ", which {why}; the executable key does NOT cover that library, so key the library too or always run this test"
                    ),
                    _ => write!(f, ", which {why}; the executable key decides"),
                }
            }
            Fallback::DuplicateDefinition { symbol, definitions, why, caller, object } => {
                write!(f, "`{symbol}` has {definitions} definitions with different content and {why}")?;
                if let Some(c) = caller {
                    write!(f, " (referenced from `{c}` in {object})")?;
                }
                write!(f, "; the executable key decides")
            }
            Fallback::NoEntry {
                test,
                looked_for,
                detail,
            } => {
                write!(
                    f,
                    "no entry found for test `{test}` (looked for {}",
                    looked_for
                        .iter()
                        .map(|s| format!("`{s}`"))
                        .collect::<Vec<_>>()
                        .join(" and ")
                )?;
                if !detail.is_empty() {
                    write!(f, "; {detail}")?;
                }
                write!(
                    f,
                    "); check --crate-name or list the tests of this binary"
                )
            }
            Fallback::Unverifiable { why } => write!(f, "unverifiable: {why}"),
        }
    }
}

/// Serde adaptor for `Option<Fallback>` fields: accepts the tagged object, and the plain
/// string older reports hold.
pub mod opt {
    use super::*;

    #[derive(Deserialize)]
    #[serde(untagged)]
    enum Wire {
        Tagged(Fallback),
        Text(String),
    }

    pub fn serialize<S: Serializer>(v: &Option<Fallback>, s: S) -> Result<S::Ok, S::Error> {
        v.serialize(s)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<Fallback>, D::Error> {
        Ok(Option::<Wire>::deserialize(d)?.map(|w| match w {
            Wire::Tagged(f) => f,
            Wire::Text(t) => Fallback::from_legacy(&t),
        }))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tagged_round_trip_and_legacy_text() {
        let f = Fallback::CurrentExe(Culprit {
            via: Via::Calls,
            callee: "std::env::current_exe".into(),
            caller: Some("a::b".into()),
            object: "libx.rlib!x.o".into(),
            alias_of: None,
        });
        let j = serde_json::to_value(&f).unwrap();
        assert_eq!(j["kind"], "current_exe");
        assert_eq!(j["callee"], "std::env::current_exe");
        assert_eq!(serde_json::from_value::<Fallback>(j).unwrap(), f);

        let old = "reach calls `std::env::current_exe` (from /t/libx-1.rlib) in `a::b`, which depends on the running executable or on loaded libraries; the executable key decides";
        let g = Fallback::from_legacy(old);
        assert_eq!(g.kind(), "current_exe");
        assert_eq!(g.culprit().unwrap().caller.as_deref(), Some("a::b"));
        assert_eq!(g.culprit().unwrap().object, "/t/libx-1.rlib");
        let n = Fallback::from_legacy("no symbol found for test `m::t` (looked for `c::m::t` and its `::{{closure}}`); check");
        assert!(matches!(n, Fallback::NoEntry { ref test, .. } if test == "m::t"));
        assert!(Fallback::from_legacy("unverifiable: bad").kind() == "unverifiable");
    }

    #[test]
    fn sentence_names_the_flagged_name_and_its_alias() {
        let f = Fallback::LoadsLibrary(Culprit {
            via: Via::Contains,
            callee: "libloading::os::unix::Library::new".into(),
            caller: None,
            object: "liba.rlib!a.o".into(),
            alias_of: Some("alloc::raw_vec::RawVec<T>::grow_one".into()),
        });
        let s = f.to_string();
        assert!(s.contains("libloading::os::unix::Library::new") && s.contains("grow_one"), "{s}");
    }
}

//! Findings: everything the resolver can say is wrong or doubtful about the
//! model, each with the model line that wrote it so a reader can jump there.

use serde::Serialize;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum Severity {
    Error,
    Warning,
    Info,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warning => "warning",
            Severity::Info => "info",
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    /// A stable kebab-case name, so scripts can filter without parsing prose.
    pub code: &'static str,
    /// `file:line` of the model source, when the finding concerns a node.
    pub at: Option<String>,
    pub node: Option<String>,
    pub message: String,
    /// How the text rendering folds this finding into its siblings. Not in the JSON: `message`
    /// already says all of it there, and a script wants every entry whole.
    #[serde(skip)]
    pub shared: Option<Shared>,
}

/// A finding split into what is its own and what every finding of the same kind says. Hundreds
/// of edges can lack the same thing, and one hundred and eighty copies of one sentence hide the
/// three findings that differ.
#[derive(Clone, Debug)]
pub struct Shared {
    /// What this entry is about, short enough to list in a line.
    pub entry: String,
    /// What to do, worded so that it holds for every entry of the kind. Findings of one code and
    /// severity with the same advice are one group.
    pub advice: String,
}

impl Finding {
    pub fn new(severity: Severity, code: &'static str, message: String) -> Finding {
        Finding {
            severity,
            code,
            at: None,
            node: None,
            message,
            shared: None,
        }
    }

    pub fn sharing(mut self, entry: String, advice: String) -> Finding {
        self.shared = Some(Shared { entry, advice });
        self
    }

    pub fn error(code: &'static str, message: String) -> Finding {
        Finding::new(Severity::Error, code, message)
    }

    pub fn warning(code: &'static str, message: String) -> Finding {
        Finding::new(Severity::Warning, code, message)
    }

    pub fn info(code: &'static str, message: String) -> Finding {
        Finding::new(Severity::Info, code, message)
    }

    pub fn of(mut self, node: &str, at: Option<&str>) -> Finding {
        self.node = Some(node.to_owned());
        self.at = at.map(str::to_owned);
        self
    }
}

/// Model positions are absolute; people read them relative to where they stand.
pub fn short_at(at: &str) -> String {
    match std::env::current_dir() {
        Ok(cwd) => at
            .strip_prefix(&format!("{}/", cwd.display()))
            .unwrap_or(at)
            .to_owned(),
        Err(_) => at.to_owned(),
    }
}

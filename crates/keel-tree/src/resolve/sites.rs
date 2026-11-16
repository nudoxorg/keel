//! Where pattern selectors landed: the ranges a `code` pattern owns and the
//! places an `entry` pattern starts from.
//!
//! Path, crate and module selectors own whole files; a pattern owns the lines
//! it matched. The file keeps its own owner for every other line, so a C
//! function can belong to one node while the rest of its file belongs to
//! another, and a pattern, the most specific selector, wins on its lines.

use super::{Compiled, Matcher, Owner, Resolution, Site};
use crate::finding::{Finding, short_at};
use crate::model::Selector;
use crate::pattern::{Failure, Hits, MAX_FILE_BYTES};
use crate::text::{list, num};
use std::collections::{BTreeMap, BTreeSet};

/// What a pattern searched, so a zero or a low count can be read for what it is.
pub(super) fn scanned(h: &Hits) -> String {
    let mut s = format!("It parsed {} of {} tracked {} files", num(h.parsed as u64), num(h.candidates as u64), h.language);
    if !h.prefilter.is_empty() {
        s.push_str(&format!(
            "; {} more were ruled out without parsing because they lack {} that any match contains",
            num(h.prefiltered_out as u64),
            h.prefilter.iter().map(|alt| alt.iter().map(|p| format!("`{p}`")).collect::<Vec<_>>().join(" and ")).collect::<Vec<_>>().join(", or ")
        ));
    }
    if !h.skipped.is_empty() {
        s.push_str(&format!("; {} could not be read (see the pattern-files-skipped finding), so a match there is unknown", h.skipped.len()));
    }
    s.push('.');
    s
}

/// Files a pattern could not read, and files it read only through error recovery.
pub(super) fn pattern_coverage(h: &Hits, sel: &Selector, field: &str) -> Vec<Finding> {
    let mut out = Vec::new();
    if !h.skipped.is_empty() {
        let shown: Vec<String> = h.skipped.iter().take(3).map(|s| format!("{} ({})", s.path, s.reason)).collect();
        out.push(Finding::warning(
            "pattern-files-skipped",
            format!(
                "`{field}` {} did not read {} of {} tracked {} files, so whatever they contain is not in its count: {}{}. \
                 Files over {} bytes are not parsed because they are almost always generated; if one is hand-written, own it with a path selector.",
                sel.describe(),
                h.skipped.len(),
                h.candidates,
                h.language,
                list(&shown),
                if h.skipped.len() > 3 { format!(" and {} more", h.skipped.len() - 3) } else { String::new() },
                num(MAX_FILE_BYTES),
            ),
        ));
    }
    if !h.with_syntax_errors.is_empty() {
        out.push(Finding::info(
            "pattern-syntax-errors",
            format!(
                "`{field}` {} read {} {} files that tree-sitter could parse only by recovering from a syntax error (for example {}); \
                 a match inside the broken region can be missing.",
                sel.describe(),
                h.with_syntax_errors.len(),
                h.language,
                list(&h.with_syntax_errors.iter().take(3).cloned().collect::<Vec<_>>()),
            ),
        ));
    }
    out
}

impl Resolution<'_> {
    pub(super) fn pattern_failure(&self, ni: usize, field: &str, sel: &Selector, why: &Failure, at: Option<&str>) -> Finding {
        let code = match why {
            Failure::UnknownLanguage(_) => "unsupported-selector",
            Failure::Unparsable(_) => "bad-pattern",
        };
        let written = at.map(|a| format!(" (written at {})", short_at(a))).unwrap_or_default();
        Finding::error(code, format!("`{field}` {}{written}: {why}.", sel.describe())).of(&self.model_id(ni), at)
    }

    fn model_id(&self, ni: usize) -> String {
        self.nodes[ni].id.clone()
    }

    /// The keel-index function (innermost) whose lines contain `start..=end`.
    fn item_covering(&self, path: &str, start: u32, end: u32) -> Option<u32> {
        let file = self.file_index(path)?;
        let by_file = self.items_by_file.get_or_init(|| {
            let mut m: std::collections::HashMap<u32, Vec<u32>> = std::collections::HashMap::new();
            for (i, it) in self.index.items.iter().enumerate() {
                m.entry(it.file).or_default().push(i as u32);
            }
            m
        });
        by_file
            .get(&file)?
            .iter()
            .copied()
            .filter(|&i| {
                let it = &self.index.items[i as usize];
                it.start_line <= start && end <= it.end_line
            })
            .min_by_key(|&i| {
                let it = &self.index.items[i as usize];
                it.end_line - it.start_line
            })
    }

    /// Turns the matches of every pattern selector into sites, and gives each
    /// `code` site's lines to its node.
    pub(super) fn assign_pattern_sites(&mut self) {
        let pats: Vec<(usize, std::rc::Rc<Hits>, usize, bool, String)> = self
            .selectors
            .iter()
            .enumerate()
            .filter_map(|(ci, c): (usize, &Compiled)| match &c.matcher {
                Matcher::Pattern(h) => Some((ci, h.clone(), c.node, c.entry, c.glob.clone())),
                _ => None,
            })
            .collect();
        let mut infos = Vec::new();
        for (ci, h, node, entry, desc) in pats {
            let mut in_pkg = false;
            let mut outside: BTreeSet<&str> = BTreeSet::new();
            let first_new = self.sites.len();
            for m in &h.matches {
                let pkg = match self.file_index(&m.path) {
                    Some(f) => self.index.files[f as usize].package,
                    None => self.package_of_path(&m.path),
                };
                in_pkg |= pkg.is_some();
                if pkg.is_none() {
                    outside.insert(&m.path);
                }
                let item = self.item_covering(&m.path, m.start_line, m.end_line);
                self.sites.push(Site {
                    node,
                    entry,
                    path: m.path.clone(),
                    start_line: m.start_line,
                    end_line: m.end_line,
                    enclosing: m.item.clone(),
                    item,
                    key: m.key(),
                    pkg,
                });
            }
            for si in first_new..self.sites.len() {
                let s = &self.sites[si];
                match (s.entry, s.pkg) {
                    (true, Some(p)) => {
                        self.nodes[node].entry_pkgs.insert(p);
                    }
                    (false, Some(p)) => {
                        // Ranges own part of the package, and the index cannot say which
                        // dependencies the range uses, so the node stands on all of them.
                        self.nodes[node].own_pkgs.insert(p);
                        self.pkg_owners[p as usize].insert(node);
                    }
                    _ => {}
                }
                if !s.entry {
                    self.code_sites.entry(s.path.clone()).or_default().push(si as u32);
                }
            }
            let dirs: BTreeSet<String> =
                h.files.iter().take(4).map(|f| f.split('/').take(2).collect::<Vec<_>>().join("/")).collect();
            self.selector_files[ci] = (h.files.len(), in_pkg, dirs, h.files.first().cloned());
            self.selectors[ci].matched = h.files.len();
            let named = h.matches.iter().filter(|m| m.item.as_ref().is_some_and(|i| i.name.is_some())).count();
            infos.push(
                Finding::info(
                    "pattern-matched",
                    format!(
                        "`{}` {desc} matches {} places ({} of {} tracked {} files parsed, {} skipped, {} ms) in {}{}{}; {}",
                        if entry { "entry" } else { "code" },
                        num(h.count() as u64),
                        num(h.parsed as u64),
                        num(h.candidates as u64),
                        h.language,
                        h.skipped.len(),
                        h.millis,
                        {
                            let files = h.files.iter().take(3).cloned().collect::<Vec<_>>();
                            let more = h.files.len().saturating_sub(3);
                            if more > 0 { format!("{} and {more} more files", list(&files)) } else { list(&files) }
                        },
                        if named > 0 { format!(", {named} inside a named item") } else { String::new() },
                        if outside.is_empty() {
                            String::new()
                        } else {
                            format!(
                                "; {} is in no cargo package, so there it adds no package to the cone, only the lines to the node",
                                list(&outside.iter().take(3).map(|s| (*s).to_owned()).collect::<Vec<_>>())
                            )
                        },
                        if entry {
                            "each is a place the feature starts, standing on whoever owns those lines".to_owned()
                        } else {
                            "the node owns those lines, and the rest of each file stays with the file's owner".to_owned()
                        },
                    ),
                )
                .of(&self.nodes[node].id.clone(), self.nodes[node].at.clone().as_deref()),
            );
        }
        self.findings.extend(infos);
        self.report_range_conflicts();
    }

    /// Two nodes whose code patterns match overlapping lines: neither owns them.
    fn report_range_conflicts(&mut self) {
        let mut clashes: BTreeMap<(usize, usize), (usize, Vec<String>)> = BTreeMap::new();
        for ids in self.code_sites.values() {
            let mut v: Vec<&Site> = ids.iter().map(|&i| &self.sites[i as usize]).collect();
            v.sort_by_key(|s| (s.start_line, s.end_line));
            for (i, a) in v.iter().enumerate() {
                for b in &v[i + 1..] {
                    if b.start_line > a.end_line {
                        break;
                    }
                    if a.node != b.node {
                        let e = clashes.entry((a.node.min(b.node), a.node.max(b.node))).or_default();
                        e.0 += 1;
                        if e.1.len() < 3 {
                            e.1.push(format!("{}:{}-{}", a.path, b.start_line, a.end_line.min(b.end_line)));
                        }
                    }
                }
            }
        }
        for ((a, b), (count, examples)) in clashes {
            let (na, nb) = (&self.nodes[a], &self.nodes[b]);
            self.findings.push(
                Finding::error(
                    "ownership-conflict",
                    format!(
                        "nodes `{}` ({}) and `{}` ({}) both claim {count} overlapping ranges at the same specificity (pattern), for example {}. \
                         Neither owns those lines until one pattern is narrowed or one selector is dropped.",
                        na.id,
                        na.at.as_deref().map(short_at).unwrap_or_default(),
                        nb.id,
                        nb.at.as_deref().map(short_at).unwrap_or_default(),
                        examples.join(", ")
                    ),
                )
                .of(&na.id.clone(), na.at.clone().as_deref()),
            );
        }
    }

    /// The code patterns whose ranges contain `line` of `path`.
    pub fn code_sites_at(&self, path: &str, line: u32) -> impl Iterator<Item = &Site> + '_ {
        self.code_sites
            .get(path)
            .into_iter()
            .flatten()
            .map(|&i| &self.sites[i as usize])
            .filter(move |s| s.start_line <= line && line <= s.end_line)
    }

    /// Whether a code pattern claims any lines of `path`.
    pub fn has_ranges(&self, path: &str) -> bool {
        self.code_sites.contains_key(path)
    }

    /// Owner of one line: the code pattern whose range holds it (two nodes at
    /// once is a conflict), else whoever owns the file.
    pub fn owner_at(&self, path: &str, line: u32) -> Owner {
        let owners: BTreeSet<usize> = self.code_sites_at(path, line).map(|s| s.node).collect();
        match owners.len() {
            0 => self.owner_of_tracked(path),
            1 => Owner::Node(*owners.iter().next().expect("one owner")),
            _ => Owner::Conflict,
        }
    }

}

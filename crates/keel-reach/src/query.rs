//! `keel-reach query`: which tests reach a symbol, without `jq` over the whole report.

use crate::model::display_name;
use crate::report::*;
use anyhow::{Context, Result};
use rayon::prelude::*;
use regex::Regex;
use roaring::RoaringBitmap;

pub struct Hit {
    pub test: String,
    pub reaches: bool,
    /// Atoms of the test's full reach (its own plus the harness set) that match.
    pub matching: u64,
    pub total: u64,
    pub fallback: Option<String>,
}

pub struct Answer {
    /// Atoms of the table with a matching name.
    pub matched: RoaringBitmap,
    pub rows: Vec<Hit>,
}

/// Does any name of atom `i`, mangled or demangled, match? With `primary_only`, only the
/// name that names the atom: how an atom was identified before it kept its other names.
fn atom_matches(t: &AtomTable, i: AtomId, re: &Regex, primary_only: bool) -> bool {
    let hit = |n: &str| re.is_match(n) || re.is_match(&display_name(n));
    if primary_only {
        let s = t.symbol(i);
        !s.is_empty() && hit(s)
    } else {
        t.names(i).any(hit)
    }
}

/// Which tests reach an atom with a name matching `pattern`. Several functions that LLVM
/// merged are one atom with several names, so a name match is a match on every test that
/// reaches the atom; `primary_only` matches only the name each atom is known by.
pub fn query(r: &BinaryReach, pattern: &str, primary_only: bool) -> Result<Answer> {
    let re = Regex::new(pattern).with_context(|| {
        format!("`{pattern}` is not a regular expression; see the regex crate's syntax")
    })?;
    let t = &r.atom_table;
    let hits: Vec<u32> = (0..t.len() as u32)
        .into_par_iter()
        .filter(|&i| atom_matches(t, i, &re, primary_only))
        .collect();
    let matched: RoaringBitmap = hits.into_iter().collect();
    let harness_hits = (&r.harness_atoms.0 & &matched).len();
    let rows = r
        .tests
        .par_iter()
        .map(|(name, tr)| {
            let own = (&tr.atoms().0 & &matched).len();
            Hit {
                test: name.clone(),
                reaches: own + harness_hits > 0,
                matching: own + harness_hits,
                total: (tr.atoms().len() + r.harness_atoms.len()) as u64,
                fallback: tr.fallback().map(|f| f.kind().to_string()),
            }
        })
        .collect();
    Ok(Answer { matched, rows })
}

pub fn render(r: &BinaryReach, a: &Answer, examples: usize) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "# test\treaches\tmatching_atoms\treach_atoms\tfallback");
    for h in &a.rows {
        let _ = writeln!(
            s,
            "{}\t{}\t{}\t{}\t{}",
            h.test,
            if h.reaches { "yes" } else { "no" },
            h.matching,
            h.total,
            h.fallback.as_deref().unwrap_or("-")
        );
    }
    let reach = a.rows.iter().filter(|h| h.reaches).count();
    let fall = a.rows.iter().filter(|h| h.fallback.is_some()).count();
    let must = a
        .rows
        .iter()
        .filter(|h| h.reaches || h.fallback.is_some())
        .count();
    let _ = writeln!(
        s,
        "# {} tests; {} reach a matching atom; {} fall back; {} must run (reach or fall back); {} atoms match",
        a.rows.len(),
        reach,
        fall,
        must,
        a.matched.len()
    );
    for i in a.matched.iter().take(examples) {
        let _ = writeln!(s, "# matches: {}", display_name(r.atom_table.names(i).next().unwrap_or("")));
    }
    s
}

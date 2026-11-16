//! `keel-reach compare A B`: the regression oracle for changes to the analyser.
//!
//! Two reports of the same inputs must agree test by test on the key, on whether the
//! test falls back, and on the set of atoms reached. Atoms are not compared by id (ids
//! belong to one report) but by identity: the object they were found in, the set of
//! symbol names they carry, and their hash. A difference is put in the first category
//! that explains it, so that "identical except: ..." says what changed and why.

use crate::fallback::Fallback;
use crate::report::*;
use rayon::prelude::*;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, BTreeSet, HashMap};

/// What a difference is called. Order matters: a test is counted in the first that fits.
pub const CATEGORIES: &[(&str, &str)] = &[
    ("test-set", "a test is in one report and not in the other"),
    ("harness", "the harness key or the harness atom set differs"),
    (
        "entry-resolved",
        "the first report had no entry for the test and the second has one, so its key, fallback and reach are new",
    ),
    (
        "entry-lost",
        "the first report had an entry for the test and the second has none (never expected)",
    ),
    ("fallback-added", "the test falls back in the second report only"),
    ("fallback-removed", "the test falls back in the first report only"),
    (
        "fallback-reason",
        "the test falls back in both, with a different kind or a different flagged function or caller",
    ),
    ("key", "the key differs"),
    ("reach", "the set of atoms reached differs"),
    ("spawns", "whether the test spawns processes differs"),
    (
        "key-partition",
        "with --partition: two tests share a key in one report and not in the other",
    ),
];

#[derive(Default)]
pub struct Comparison {
    pub tests: usize,
    /// Category to the tests in it, with one line of detail each.
    pub differences: BTreeMap<&'static str, Vec<(String, String)>>,
    /// Notes on how the comparison was made.
    pub notes: Vec<String>,
    pub atoms: (usize, usize),
}

impl Comparison {
    pub fn is_identical(&self) -> bool {
        self.differences.is_empty()
    }

    /// Differences outside the categories in `allowed`.
    pub fn unexplained(&self, allowed: &[String]) -> usize {
        self.differences
            .iter()
            .filter(|(c, _)| !allowed.iter().any(|a| a == *c))
            .map(|(_, v)| v.len())
            .sum()
    }
}

/// An atom's identity, stable across reports of the same inputs.
pub fn identities(r: &BinaryReach, with_aliases: bool, with_member: bool) -> Vec<u128> {
    let t = &r.atom_table;
    (0..t.len() as u32)
        .into_par_iter()
        .map(|i| {
            let mut h = blake3::Hasher::new();
            // The file name, not the directory: the same inputs found in two places are the same.
            let archive = t.archive(i);
            h.update(archive.rsplit('/').next().unwrap_or(archive).as_bytes()).update(&[0]);
            if with_member {
                h.update(t.member(i).as_bytes()).update(&[0]);
            }
            let mut names: Vec<&str> = if with_aliases {
                t.names(i).collect()
            } else {
                vec![t.symbol(i)]
            };
            // Labels the compiler invents carry a hash or a counter of the unit they were
            // made in (`l_anon.<hash>.<n>`), which changes whenever the unit does; they name
            // nothing, so they do not take part in an identity.
            let invented = |n: &&str| {
                !["l_anon.", "ltmp", "lCPI", "GCC_except_table", "l_.str", "_anon."]
                    .iter()
                    .any(|p| n.starts_with(p) || n.trim_start_matches('_').starts_with(p))
            };
            let had_names = names.iter().any(|n| !n.is_empty());
            names.retain(|n| invented(n));
            // `.llvm.<module id>` is appended to a symbol when it is promoted for use by
            // another unit, and the id is a hash of the unit.
            let names: Vec<&str> = names
                .iter()
                .map(|n| n.split_once(".llvm.").map_or(*n, |(head, _)| head))
                .collect();
            let mut names = names;
            names.sort_unstable();
            for n in &names {
                h.update(n.as_bytes()).update(&[0]);
            }
            h.update(&t.hash[i as usize].to_be_bytes());
            if !had_names {
                // Nothing else tells two unnamed atoms of one member apart.
                h.update(&t.section[i as usize].to_le_bytes());
                h.update(&t.offset[i as usize].to_le_bytes());
            }
            let d = h.finalize();
            u128::from_le_bytes(d.as_bytes()[..16].try_into().unwrap())
        })
        .collect()
}

fn describe(f: Option<&Fallback>) -> String {
    match f {
        None => "none".into(),
        Some(f) => match f.culprit() {
            Some(c) => format!("{} via `{}` in `{}`", f.kind(), c.callee, c.group()),
            None => f.kind().to_string(),
        },
    }
}

#[derive(Default, Clone, Copy)]
pub struct CompareOptions {
    /// The reports were made with different key formulas, so keys cannot be compared for
    /// equality. Compare what a key is for instead: which tests share one.
    pub partition: bool,
    /// Do not take the object file (codegen unit) an atom is in as part of its identity: the
    /// partition of a crate into units shifts when its source does, and an atom that moved
    /// from one unit to another is the same atom.
    pub ignore_member: bool,
}

pub fn compare(a: &BinaryReach, b: &BinaryReach) -> Comparison {
    compare_with(a, b, CompareOptions::default())
}

/// Tests keyed in both reports, grouped by key: the grouping must be the same.
fn partition_differences(a: &BinaryReach, b: &BinaryReach) -> Vec<(String, String)> {
    let mut class_a: HashMap<&[u8; 32], Vec<&String>> = HashMap::new();
    for (n, t) in &a.tests {
        if let (Some(k), true) = (t.key(), b.tests.get(n).is_some_and(|y| y.key().is_some())) {
            class_a.entry(k).or_default().push(n);
        }
    }
    let mut class_b: HashMap<&[u8; 32], Vec<&String>> = HashMap::new();
    for (n, t) in &b.tests {
        if let (Some(k), true) = (t.key(), a.tests.get(n).is_some_and(|x| x.key().is_some())) {
            class_b.entry(k).or_default().push(n);
        }
    }
    let canon = |m: HashMap<&[u8; 32], Vec<&String>>| -> BTreeSet<Vec<String>> {
        m.into_values()
            .map(|mut v| {
                v.sort();
                v.into_iter().cloned().collect()
            })
            .collect()
    };
    let (pa, pb) = (canon(class_a), canon(class_b));
    let mut out = Vec::new();
    for g in pa.difference(&pb).chain(pb.difference(&pa)) {
        out.push((
            g[0].clone(),
            format!("a group of {} tests that share a key in only one report", g.len()),
        ));
    }
    out
}

pub fn compare_with(a: &BinaryReach, b: &BinaryReach, opts: CompareOptions) -> Comparison {
    let mut out = Comparison {
        atoms: (a.atom_table.len(), b.atom_table.len()),
        ..Default::default()
    };
    let with_aliases = a.format >= 2 && b.format >= 2;
    if !with_aliases {
        out.notes.push(
            "one report predates alias names, so atoms are identified by their naming symbol only"
                .into(),
        );
    }
    // Translate both reports' atom ids into one numbering of identities.
    let mut interner: HashMap<u128, u32> = HashMap::new();
    let mut translate = |r: &BinaryReach| -> Vec<u32> {
        identities(r, with_aliases, !opts.ignore_member)
            .into_iter()
            .map(|k| {
                let n = interner.len() as u32;
                *interner.entry(k).or_insert(n)
            })
            .collect()
    };
    let (ta, tb) = (translate(a), translate(b));
    let map = |t: &[u32], s: &Atoms| -> RoaringBitmap { s.iter().map(|i| t[i as usize]).collect() };
    let (ha, hb) = (map(&ta, &a.harness_atoms), map(&tb, &b.harness_atoms));
    let mut add = |cat: &'static str, test: &str, detail: String| {
        out.differences
            .entry(cat)
            .or_default()
            .push((test.to_string(), detail));
    };
    if a.harness_key != b.harness_key {
        add("harness", "<harness>", "harness keys differ".into());
    }
    if ha != hb {
        add(
            "harness",
            "<harness>",
            format!(
                "harness atoms differ: {} only in first, {} only in second",
                (&ha - &hb).len(),
                (&hb - &ha).len()
            ),
        );
    }
    let names: BTreeSet<&String> = a.tests.keys().chain(b.tests.keys()).collect();
    let mut compared = 0;
    type Row<'a> = (&'a String, Vec<(&'static str, String, Vec<u32>, Vec<u32>)>);
    let rows: Vec<Row> = names
        .par_iter()
        .map(|&name| {
            let (Some(x), Some(y)) = (a.tests.get(name), b.tests.get(name)) else {
                let side = if a.tests.contains_key(name) { "first" } else { "second" };
                return (name, vec![("test-set", format!("only in the {side} report"), vec![], vec![])]);
            };
            let no_entry = |f: Option<&Fallback>| matches!(f, Some(Fallback::NoEntry { .. }));
            if no_entry(x.fallback()) && !no_entry(y.fallback()) {
                return (
                    name,
                    vec![(
                        "entry-resolved",
                        format!(
                            "entry from {:?}, key {}, fallback {}, {} atoms",
                            y.entry,
                            if y.key() == x.key() { "same" } else { "new" },
                            describe(y.fallback()),
                            y.atoms().len()
                        ),
                        vec![],
                        vec![],
                    )],
                );
            }
            if !no_entry(x.fallback()) && no_entry(y.fallback()) {
                return (name, vec![("entry-lost", describe(x.fallback()), vec![], vec![])]);
            }
            // Every category that applies, not the first: a changed reason must not hide
            // a changed key.
            let mut v = Vec::new();
            let (fa, fb) = (x.fallback(), y.fallback());
            if fa.is_none() && fb.is_some() {
                v.push(("fallback-added", describe(fb), vec![], vec![]));
            } else if fa.is_some() && fb.is_none() {
                v.push(("fallback-removed", describe(fa), vec![], vec![]));
            } else if fa.is_some() && describe(fa) != describe(fb) {
                v.push(("fallback-reason", format!("{} -> {}", describe(fa), describe(fb)), vec![], vec![]));
            }
            if !opts.partition && x.key().is_some() && y.key().is_some() && x.key() != y.key() {
                v.push(("key", String::new(), vec![], vec![]));
            }
            if x.spawns_processes != y.spawns_processes {
                v.push(("spawns", format!("{} -> {}", x.spawns_processes, y.spawns_processes), vec![], vec![]));
            }
            let (sa, sb) = (&map(&ta, x.atoms()) | &ha, &map(&tb, y.atoms()) | &hb);
            if sa != sb {
                let (oa, ob) = (&sa - &sb, &sb - &sa);
                v.push((
                    "reach",
                    format!("{} atoms only in first, {} only in second", oa.len(), ob.len()),
                    oa.iter().take(3).collect(),
                    ob.iter().take(3).collect(),
                ));
            }
            (name, v)
        })
        .collect();
    // Name a few of the atoms that differ, so the difference can be checked by eye.
    let label = |r: &BinaryReach, i: u32| -> String {
        let t = &r.atom_table;
        let sym = t.symbol(i);
        let what = if sym.is_empty() {
            format!("{}!{}+{}", t.archive(i).rsplit('/').next().unwrap_or(""), t.member(i), t.offset[i as usize])
        } else {
            crate::model::display_name(sym)
        };
        what.chars().take(110).collect()
    };
    let mut rev: [HashMap<u32, u32>; 2] = Default::default();
    if rows.iter().any(|(_, ds)| ds.iter().any(|d| d.0 == "reach")) {
        for (k, t) in [&ta, &tb].into_iter().enumerate() {
            rev[k] = t.iter().enumerate().map(|(i, &id)| (id, i as u32)).collect();
        }
    }
    for (name, ds) in rows {
        compared += 1;
        for (cat, mut detail, sa, sb) in ds {
            for (k, (samples, r)) in [(sa, a), (sb, b)].into_iter().enumerate() {
                for id in samples {
                    if let Some(&ai) = rev[k].get(&id) {
                        detail += &format!("\n      {} {}", if k == 0 { "-" } else { "+" }, label(r, ai));
                    }
                }
            }
            add(cat, name, detail);
        }
    }
    if opts.partition {
        out.notes.push("keys are compared as partitions of the tests, not for equality".into());
        for (t, d) in partition_differences(a, b) {
            out.differences.entry("key-partition").or_default().push((t, d));
        }
    }
    out.tests = compared;
    out
}

pub fn render(c: &Comparison, show: usize) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    for n in &c.notes {
        let _ = writeln!(s, "note: {n}");
    }
    let _ = writeln!(
        s,
        "{} tests compared; atom tables {} and {} rows",
        c.tests, c.atoms.0, c.atoms.1
    );
    if c.is_identical() {
        let _ = writeln!(s, "identical");
        return s;
    }
    let mut parts = Vec::new();
    for (cat, why) in CATEGORIES {
        let Some(v) = c.differences.get(cat) else {
            continue;
        };
        parts.push(format!("{} {cat}", v.len()));
        let _ = writeln!(s, "\n{cat}: {} ({why})", v.len());
        for (t, d) in v.iter().take(show) {
            let _ = writeln!(s, "  {t}{}", if d.is_empty() { String::new() } else { format!(": {d}") });
        }
        if v.len() > show {
            let _ = writeln!(s, "  ... {} more", v.len() - show);
        }
    }
    let _ = writeln!(s, "\nidentical except: {}", parts.join(", "));
    s
}

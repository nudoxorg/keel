//! `keel-reach atoms` and `keel-reach changed`: what changed between two builds, and what
//! is merely affected by it.
//!
//! A change to one atom changes the Merkle hash of every atom that reaches it, so counting
//! keys that moved says how far a change propagated, not how big it was. The listing keeps the
//! two apart: `local` is what enters the Merkle hash of the atom itself (its bytes and the
//! offset, kind and addend of its relocations), `merkle` is the hash of its whole reach.
//! Two listings compared as multisets by `local` give the atoms whose own content changed;
//! whatever differs in `merkle` and not in `local` is propagation.

use crate::link::{Origin, Program, discover};
use crate::load::{Loader, hex};
use crate::model::*;
use crate::record::LinkInputs;
use anyhow::{Context, Result, bail};
use std::collections::{BTreeMap, HashMap};
use std::io::{BufRead, BufReader, BufWriter, Write};
use std::path::Path;

pub const HEADER: &str =
    "crate\tarchive\tmember\tsection\tclass\tsize\tbytes_hash\treloc_hash\tlocal\tmerkle\tfirst_name";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub crate_name: String,
    /// File name of the archive or object.
    pub archive: String,
    pub member: String,
    pub section: String,
    pub class: String,
    pub size: u64,
    pub bytes_hash: String,
    pub reloc_hash: String,
    pub local: String,
    pub merkle: String,
    pub first_name: String,
}

/// Every atom of every input of a link, reached or not, with the Merkle hash of its reach.
/// Test descriptors get no special treatment here: the listing is about code and data, and
/// reads the same whatever the test list.
pub fn list(loader: &Loader, rec: &LinkInputs, test_crate: &str) -> Result<Vec<Row>> {
    let loaded = loader.load(rec, test_crate);
    if let Some(p) = loaded.problem {
        bail!("the link inputs cannot be read: {p}; fix that first (the same reason makes `analyze` unverifiable)");
    }
    let prog = Program::new(&loaded.units);
    let all: Vec<u32> = (0..prog.total_atoms()).collect();
    let none = std::collections::HashSet::new();
    let disc = discover(&prog, &all, &none, &none);
    let cond = crate::graph::tarjan(&disc.graph);
    let mk = crate::graph::merkle(&disc.graph, &cond);
    let mut rows = Vec::with_capacity(all.len());
    for g in all {
        let (mem, ai) = prog.locate(g);
        let r = prog.mems[mem as usize];
        let (u, m, a) = (
            &prog.units[r.unit as usize],
            prog.member(mem),
            &prog.member(mem).atoms[ai as usize],
        );
        let sec = &m.sections[a.section as usize];
        let n = disc.node_of[g as usize];
        debug_assert!(matches!(disc.origin[n as usize], Origin::Atom(x) if x == g));
        rows.push(Row {
            crate_name: u.crate_name.clone(),
            archive: u
                .path
                .file_name()
                .map_or_else(String::new, |s| s.to_string_lossy().into_owned()),
            member: m.name.clone(),
            section: sec.key.to_string(),
            class: AtomClass::name(AtomClass::of(sec.role, sec.class) as u8).to_string(),
            size: a.size,
            bytes_hash: hex(&a.bytes_hash),
            reloc_hash: hex(&a.reloc_hash),
            local: hex(&a.content[..16]),
            merkle: hex(&mk.node_hash(&cond, n)[..16]),
            first_name: if a.symbol == NONE {
                String::new()
            } else {
                m.names[a.symbol as usize].to_string()
            },
        });
    }
    Ok(rows)
}

/// Write a listing as tab-separated text; zstd-compressed if the name ends in `.zst`.
pub fn write(rows: &[Row], path: &Path) -> Result<()> {
    let f = std::fs::File::create(path).with_context(|| {
        format!("cannot create {}; check the directory exists and is writable", path.display())
    })?;
    let compress = path.extension().is_some_and(|e| e == "zst");
    let mut out: Box<dyn Write> = if compress {
        Box::new(zstd::stream::Encoder::new(BufWriter::new(f), 6)?.auto_finish())
    } else {
        Box::new(BufWriter::new(f))
    };
    writeln!(out, "{HEADER}")?;
    for r in rows {
        writeln!(
            out,
            "{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}\t{}",
            r.crate_name, r.archive, r.member, r.section, r.class, r.size, r.bytes_hash,
            r.reloc_hash, r.local, r.merkle, r.first_name
        )?;
    }
    out.flush()?;
    Ok(())
}

pub fn read(path: &Path) -> Result<Vec<Row>> {
    let f = std::fs::File::open(path).with_context(|| {
        format!("cannot read {}; make it with `keel-reach atoms`", path.display())
    })?;
    let input: Box<dyn BufRead> = if path.extension().is_some_and(|e| e == "zst") {
        Box::new(BufReader::new(zstd::stream::Decoder::new(f)?))
    } else {
        Box::new(BufReader::new(f))
    };
    let mut rows = Vec::new();
    for (i, line) in input.lines().enumerate() {
        let line = line?;
        if i == 0 {
            if line != HEADER {
                bail!("{} is not an atom listing (its first line is not the header); make it with `keel-reach atoms`", path.display());
            }
            continue;
        }
        let c: Vec<&str> = line.splitn(11, '\t').collect();
        if c.len() != 11 {
            bail!("{} line {} has {} columns, not 11; the file is damaged, make it again", path.display(), i + 1, c.len());
        }
        rows.push(Row {
            crate_name: c[0].into(),
            archive: c[1].into(),
            member: c[2].into(),
            section: c[3].into(),
            class: c[4].into(),
            size: c[5].parse().with_context(|| format!("{} line {}: size", path.display(), i + 1))?,
            bytes_hash: c[6].into(),
            reloc_hash: c[7].into(),
            local: c[8].into(),
            merkle: c[9].into(),
            first_name: c[10].into(),
        });
    }
    Ok(rows)
}

#[derive(Debug, Default)]
pub struct Changed {
    pub before: usize,
    pub after: usize,
    /// Atoms of the second listing whose `local` has no counterpart in the first.
    pub new_local: Vec<Row>,
    /// Of those, by class: count and bytes.
    pub by_class: BTreeMap<String, (usize, u64)>,
    /// Text atoms whose bytes are in the first listing: only a relocation moved.
    pub text_addends_only: usize,
    /// Text atoms with bytes not in the first listing.
    pub text_new_bytes: Vec<Row>,
    /// Atoms whose `merkle` differs and whose `local` does not.
    pub propagation: usize,
    /// Atoms whose `merkle` differs at all.
    pub merkle_changed: usize,
}

/// Compare two listings as multisets by `local`, never by name.
pub fn changed(a: &[Row], b: &[Row]) -> Changed {
    let mut locals: HashMap<&str, u32> = HashMap::new();
    let mut merkles: HashMap<&str, u32> = HashMap::new();
    let mut bytes: std::collections::HashSet<&str> = std::collections::HashSet::new();
    for r in a {
        *locals.entry(&r.local).or_default() += 1;
        *merkles.entry(&r.merkle).or_default() += 1;
        bytes.insert(&r.bytes_hash);
    }
    let mut c = Changed {
        before: a.len(),
        after: b.len(),
        ..Default::default()
    };
    for r in b {
        let local_same = match locals.get_mut(r.local.as_str()) {
            Some(n) if *n > 0 => {
                *n -= 1;
                true
            }
            _ => false,
        };
        let merkle_same = match merkles.get_mut(r.merkle.as_str()) {
            Some(n) if *n > 0 => {
                *n -= 1;
                true
            }
            _ => false,
        };
        if !merkle_same {
            c.merkle_changed += 1;
            if local_same {
                c.propagation += 1;
            }
        }
        if local_same {
            continue;
        }
        let e = c.by_class.entry(r.class.clone()).or_default();
        e.0 += 1;
        e.1 += r.size;
        if r.class == "text" {
            if bytes.contains(r.bytes_hash.as_str()) {
                c.text_addends_only += 1;
            } else {
                c.text_new_bytes.push(r.clone());
            }
        }
        c.new_local.push(r.clone());
    }
    c
}

pub fn render(c: &Changed, top: usize) -> String {
    render_with(c, top, 0)
}

/// `render`, and the first `names` text atoms with new bytes, demangled.
pub fn render_with(c: &Changed, top: usize, names: usize) -> String {
    use std::fmt::Write;
    let mut s = String::new();
    let _ = writeln!(s, "atoms: {} before, {} after", c.before, c.after);
    let _ = writeln!(
        s,
        "own content changed (locals in the second listing and not in the first): {}",
        c.new_local.len()
    );
    for (class, (n, bytes)) in &c.by_class {
        let _ = writeln!(s, "  {class:<8} {n:>8} atoms {bytes:>12} bytes");
    }
    let _ = writeln!(
        s,
        "text atoms: {} only moved a relocation (bytes present before), {} have new bytes",
        c.text_addends_only,
        c.text_new_bytes.len()
    );
    let split = |key: &dyn Fn(&Row) -> String| -> Vec<(String, usize)> {
        let mut m: BTreeMap<String, usize> = BTreeMap::new();
        for r in &c.text_new_bytes {
            *m.entry(key(r)).or_default() += 1;
        }
        let mut v: Vec<_> = m.into_iter().collect();
        v.sort_by(|x, y| y.1.cmp(&x.1).then(x.0.cmp(&y.0)));
        v
    };
    let _ = writeln!(s, "new text bytes by defining crate:");
    for (k, n) in split(&|r| r.crate_name.clone()).into_iter().take(top) {
        let _ = writeln!(s, "  {n:>8}  {k}");
    }
    let _ = writeln!(s, "new text bytes by codegen unit (member):");
    for (k, n) in split(&|r| format!("{} / {}", r.crate_name, r.member)).into_iter().take(top) {
        let _ = writeln!(s, "  {n:>8}  {k}");
    }
    if names > 0 {
        let _ = writeln!(s, "text atoms with new bytes:");
        for r in c.text_new_bytes.iter().take(names) {
            let _ = writeln!(s, "  {:>6} bytes  {}", r.size, display_name(&r.first_name));
        }
    }
    let _ = writeln!(
        s,
        "merkle differs for {} atoms; {} of them have the same local content (propagation)",
        c.merkle_changed, c.propagation
    );
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(local: &str, bytes: &str, merkle: &str, class: &str) -> Row {
        Row {
            crate_name: "c".into(),
            archive: "a".into(),
            member: "m".into(),
            section: "s".into(),
            class: class.into(),
            size: 4,
            bytes_hash: bytes.into(),
            reloc_hash: "r".into(),
            local: local.into(),
            merkle: merkle.into(),
            first_name: String::new(),
        }
    }

    #[test]
    fn multisets_by_local_and_propagation() {
        let a = vec![
            row("l1", "b1", "m1", "text"),
            row("l2", "b2", "m2", "text"),
            row("l2", "b2", "m2", "text"),
            row("l3", "b3", "m3", "cstring"),
        ];
        let b = vec![
            row("l1", "b1", "m1x", "text"),  // same content, reach moved: propagation
            row("l2", "b2", "m2", "text"),
            row("l2", "b2", "m2", "text"),
            row("l2", "b2", "m2", "text"),   // a third copy: one more than before
            row("l4", "b2", "m4", "text"),   // new relocation shape on known bytes
            row("l5", "b5", "m5", "text"),   // new bytes
            row("l3", "b3", "m3", "cstring"),
        ];
        let c = changed(&a, &b);
        assert_eq!(c.new_local.len(), 3);
        assert_eq!(c.text_addends_only, 2, "l2's third copy and l4 have bytes seen before");
        assert_eq!(c.text_new_bytes.len(), 1);
        assert_eq!(c.propagation, 1);
        assert_eq!(c.by_class["text"].0, 3);
        assert!(render(&c, 3).contains("1 have new bytes"));
    }
}

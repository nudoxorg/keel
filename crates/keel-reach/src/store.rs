//! Reports on disk.
//!
//! * Full JSON: `BinaryReach` as serde writes it. Fine for small binaries and for tools
//!   that read it with `jq`; 472 MB for the 258 MB engine test binary.
//! * Compact: a small JSON header (stats, harness key, one record per test with its key,
//!   structured fallback and entry source) and a side file next to it that holds what is
//!   big: the atom table in columns, and each test's atoms and crates as roaring bitmaps,
//!   all in one zstd stream with a long window (neighbouring tests reach mostly the same
//!   atoms, which is the repetition the window is for).
//!
//! `read` accepts either and returns the same `BinaryReach`.

use crate::fallback::{self, Culprit, Fallback};
use crate::report::*;
use anyhow::{Context, Result, bail};
use roaring::RoaringBitmap;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufWriter, Read, Write};
use std::path::{Path, PathBuf};

const MAGIC: &[u8; 16] = b"keel-reach-atoms";
const SIDE_VERSION: u8 = 2;
const ZSTD_LEVEL: i32 = 9;
const ZSTD_WINDOW_LOG: u32 = 22;

/// The side file of a header: `R.json` gets `R.atoms`.
pub fn side_path(header: &Path) -> PathBuf {
    header.with_extension("atoms")
}

#[derive(Serialize, Deserialize)]
struct HeaderTest {
    /// Null for a test that falls back.
    #[serde(default, with = "opt_key_hex")]
    key: Option<[u8; 32]>,
    #[serde(with = "fallback::opt", default)]
    fallback: Option<Fallback>,
    #[serde(default)]
    spawns_processes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spawns: Option<Culprit>,
    #[serde(default)]
    entry: EntrySource,
    /// Atoms outside the harness set; the set itself is in the side file.
    n_atoms: u64,
}

mod opt_key_hex {
    use serde::{Deserialize, Deserializer, Serialize, Serializer};
    pub fn serialize<S: Serializer>(k: &Option<[u8; 32]>, s: S) -> Result<S::Ok, S::Error> {
        k.as_ref().map(|k| crate::load::hex(k)).serialize(s)
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<Option<[u8; 32]>, D::Error> {
        let Some(t) = Option::<String>::deserialize(d)? else {
            return Ok(None);
        };
        if t.len() != 64 {
            return Err(serde::de::Error::custom("a key is 64 hex digits"));
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).map_err(serde::de::Error::custom)?;
        }
        Ok(Some(out))
    }
}

mod key_hex {
    use serde::{Deserialize, Deserializer, Serializer};
    pub fn serialize<S: Serializer>(k: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(&crate::load::hex(k))
    }
    pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
        let t = String::deserialize(d)?;
        if t.len() != 64 {
            return Err(serde::de::Error::custom("a key is 64 hex digits"));
        }
        let mut out = [0u8; 32];
        for (i, b) in out.iter_mut().enumerate() {
            *b = u8::from_str_radix(&t[2 * i..2 * i + 2], 16).map_err(serde::de::Error::custom)?;
        }
        Ok(out)
    }
}

#[derive(Serialize, Deserialize)]
struct Compact {
    /// File name of the side file, relative to the header.
    atoms_file: String,
    atoms: u64,
    /// blake3 of the side file, so a header and a side file from different runs are noticed.
    side_blake3: String,
    side_bytes: u64,
}

#[derive(Serialize, Deserialize)]
struct Header {
    format: u32,
    compact: Compact,
    executable: PathBuf,
    verifiable: Result<(), String>,
    #[serde(with = "key_hex")]
    harness_key: [u8; 32],
    tests: BTreeMap<String, HeaderTest>,
    unresolved_imports: Vec<String>,
    stats: Stats,
    harness_atoms: u64,
    missing_tests: Vec<String>,
    notes: Vec<String>,
    #[serde(default)]
    unkeyed_inputs: Vec<String>,
    #[serde(default)]
    section_sets: Vec<SectionSetUse>,
    #[serde(default)]
    timings: Vec<Timing>,
    /// Derived, for people: fallbacks by kind, then by (kind, calling function).
    #[serde(default)]
    fallbacks_by_kind: BTreeMap<String, usize>,
    #[serde(default)]
    fallbacks_by_caller: Vec<(String, String, usize)>,
}

struct W(Vec<u8>);

impl W {
    fn u(&mut self, mut v: u64) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                self.0.push(b);
                return;
            }
            self.0.push(b | 0x80);
        }
    }
    fn bytes(&mut self, b: &[u8]) {
        self.u(b.len() as u64);
        self.0.extend_from_slice(b);
    }
    fn strings(&mut self, v: &[String]) {
        self.u(v.len() as u64);
        for s in v {
            self.u(s.len() as u64);
        }
        for s in v {
            self.0.extend_from_slice(s.as_bytes());
        }
    }
    fn bitmap(&mut self, b: &RoaringBitmap) -> Result<()> {
        let mut tmp = Vec::with_capacity(b.serialized_size());
        b.serialize_into(&mut tmp)?;
        self.bytes(&tmp);
        Ok(())
    }
}

struct R<'a>(&'a [u8]);

impl<'a> R<'a> {
    fn u(&mut self) -> Result<u64> {
        let (mut v, mut shift) = (0u64, 0);
        loop {
            let Some((&b, rest)) = self.0.split_first() else {
                bail!("the atoms file ends in the middle of a number; it is truncated, regenerate the report");
            };
            self.0 = rest;
            v |= u64::from(b & 0x7f) << shift;
            if b & 0x80 == 0 {
                return Ok(v);
            }
            shift += 7;
            if shift > 63 {
                bail!("the atoms file holds an over-long number; it is corrupt, regenerate the report");
            }
        }
    }
    fn raw(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.0.len() < n {
            bail!("the atoms file ends early; it is truncated, regenerate the report");
        }
        let (a, b) = self.0.split_at(n);
        self.0 = b;
        Ok(a)
    }
    fn bytes(&mut self) -> Result<&'a [u8]> {
        let n = self.u()? as usize;
        self.raw(n)
    }
    fn strings(&mut self) -> Result<Vec<String>> {
        let n = self.u()? as usize;
        let lens: Vec<usize> = (0..n).map(|_| self.u().map(|x| x as usize)).collect::<Result<_>>()?;
        lens.into_iter()
            .map(|l| Ok(String::from_utf8_lossy(self.raw(l)?).into_owned()))
            .collect()
    }
    fn col32(&mut self, n: usize) -> Result<Vec<u32>> {
        (0..n).map(|_| self.u().map(|x| x as u32)).collect()
    }
    fn bitmap(&mut self) -> Result<RoaringBitmap> {
        RoaringBitmap::deserialize_from(self.bytes()?).context("a bitmap in the atoms file is corrupt; regenerate the report")
    }
}

fn encode(r: &BinaryReach) -> Result<Vec<u8>> {
    let mut w = W(Vec::new());
    let t = &r.atom_table;
    w.u(t.str_ends.len() as u64);
    let mut prev = 0;
    for &e in &t.str_ends {
        w.u(u64::from(e - prev));
        prev = e;
    }
    w.0.extend_from_slice(&t.str_text);
    let n = t.len();
    w.u(n as u64);
    for c in [&t.archive, &t.member, &t.section, &t.symbol, &t.crate_name] {
        for &x in c {
            w.u(u64::from(x));
        }
    }
    for &x in &t.offset {
        w.u(x);
    }
    w.0.extend(t.own_object.iter().map(|&b| u8::from(b)));
    w.0.extend_from_slice(&t.class);
    for &x in &t.size {
        w.u(x);
    }
    for c in [&t.hash, &t.content, &t.bytes_hash, &t.reloc_hash] {
        for &x in c {
            w.0.extend_from_slice(&x.to_be_bytes());
        }
    }
    for i in 0..n {
        w.u(u64::from(t.alias_start[i + 1] - t.alias_start[i]));
    }
    w.u(t.alias_names.len() as u64);
    for &x in &t.alias_names {
        w.u(u64::from(x));
    }
    // Crates: one table for the report, bitmaps per test.
    let crate_table: Vec<String> = r
        .tests
        .values()
        .flat_map(|t| t.crates.iter().cloned())
        .collect::<BTreeSet<_>>()
        .into_iter()
        .collect();
    let crate_ix: std::collections::HashMap<&str, u32> = crate_table
        .iter()
        .enumerate()
        .map(|(i, s)| (s.as_str(), i as u32))
        .collect();
    w.strings(&crate_table);
    w.bitmap(&r.harness_atoms.0)?;
    w.u(r.tests.len() as u64);
    for t in r.tests.values() {
        w.bitmap(&t.atoms().0)?;
        let cb: RoaringBitmap = t.crates.iter().map(|c| crate_ix[c.as_str()]).collect();
        w.bitmap(&cb)?;
    }
    Ok(w.0)
}

/// Write `header` and its side file. Returns the sizes of the two in bytes.
pub fn write_compact(r: &BinaryReach, header: &Path) -> Result<(u64, u64)> {
    write_compact_at(r, header, ZSTD_LEVEL)
}

/// `write_compact` at a given zstd level (1 to 22).
pub fn write_compact_at(r: &BinaryReach, header: &Path, level: i32) -> Result<(u64, u64)> {
    let side = side_path(header);
    if side == header {
        bail!(
            "cannot write a compact report to {}: its side file would have the same name; use an --out name that does not end in .atoms",
            header.display()
        );
    }
    let payload = encode(r)?;
    let f = std::fs::File::create(&side).with_context(|| {
        format!("cannot create {}; check the directory exists and is writable", side.display())
    })?;
    let mut f = BufWriter::new(f);
    f.write_all(MAGIC)?;
    f.write_all(&[SIDE_VERSION])?;
    let mut enc = zstd::stream::Encoder::new(&mut f, level)?;
    enc.long_distance_matching(true)?;
    enc.window_log(ZSTD_WINDOW_LOG)?;
    enc.write_all(&payload)?;
    enc.finish()?;
    f.flush()?;
    drop(f);
    let side_bytes = std::fs::metadata(&side)?.len();
    let side_hash = {
        let mut h = blake3::Hasher::new();
        h.update_mmap_rayon(&side)
            .with_context(|| format!("cannot hash {}", side.display()))?;
        crate::load::hex(h.finalize().as_bytes())
    };
    let counts = r.fallback_counts();
    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
    for ((k, _), n) in &counts {
        *by_kind.entry(k.clone()).or_default() += n;
    }
    let mut by_caller: Vec<(String, String, usize)> =
        counts.into_iter().map(|((k, c), n)| (k, c, n)).collect();
    by_caller.sort_by(|a, b| b.2.cmp(&a.2).then(a.0.cmp(&b.0)).then(a.1.cmp(&b.1)));
    let h = Header {
        format: FORMAT,
        compact: Compact {
            atoms_file: side
                .file_name()
                .map(|s| s.to_string_lossy().into_owned())
                .unwrap_or_default(),
            atoms: r.atom_table.len() as u64,
            side_blake3: side_hash,
            side_bytes,
        },
        executable: r.executable.clone(),
        verifiable: r.verifiable.clone(),
        harness_key: r.harness_key,
        tests: r
            .tests
            .iter()
            .map(|(n, t)| {
                (
                    n.clone(),
                    HeaderTest {
                        key: t.key().copied(),
                        fallback: t.fallback().cloned(),
                        spawns_processes: t.spawns_processes,
                        spawns: t.spawns.clone(),
                        entry: t.entry,
                        n_atoms: t.atoms().len() as u64,
                    },
                )
            })
            .collect(),
        unresolved_imports: r.unresolved_imports.clone(),
        stats: r.stats.clone(),
        harness_atoms: r.harness_atoms.len() as u64,
        missing_tests: r.missing_tests.clone(),
        notes: r.notes.clone(),
        unkeyed_inputs: r.unkeyed_inputs.clone(),
        section_sets: r.section_sets.clone(),
        timings: r.timings.clone(),
        fallbacks_by_kind: by_kind,
        fallbacks_by_caller: by_caller,
    };
    let mut hf = BufWriter::new(std::fs::File::create(header).with_context(|| {
        format!("cannot create {}; check the directory exists and is writable", header.display())
    })?);
    serde_json::to_writer(&mut hf, &h)?;
    hf.flush()?;
    Ok((std::fs::metadata(header)?.len(), side_bytes))
}

/// The old full JSON, streamed so the report is not held a second time as text.
pub fn write_json(r: &BinaryReach, out: &Path) -> Result<u64> {
    let mut f = BufWriter::new(std::fs::File::create(out).with_context(|| {
        format!("cannot create {}; check the directory exists and is writable", out.display())
    })?);
    serde_json::to_writer(&mut f, r)?;
    f.flush()?;
    Ok(std::fs::metadata(out)?.len())
}

/// Read a report written by either `write_json` or `write_compact`.
pub fn read(path: &Path) -> Result<BinaryReach> {
    let bytes = std::fs::read(path).with_context(|| {
        format!("cannot read {}; run `keel-reach analyze --out` first", path.display())
    })?;
    let v: serde_json::Value = serde_json::from_slice(&bytes)
        .with_context(|| format!("{} is not JSON; regenerate it with `keel-reach analyze`", path.display()))?;
    if v.get("compact").is_none() {
        return serde_json::from_value(v)
            .with_context(|| format!("{} is not a keel-reach report; regenerate it", path.display()));
    }
    let h: Header = serde_json::from_value(v)
        .with_context(|| format!("{} is not a keel-reach report header; regenerate it", path.display()))?;
    let side = path.with_file_name(&h.compact.atoms_file);
    let raw = std::fs::read(&side).with_context(|| {
        format!(
            "cannot read {}, the atoms file of {}; copy the two files together",
            side.display(),
            path.display()
        )
    })?;
    if crate::load::hex(blake3::hash(&raw).as_bytes()) != h.compact.side_blake3 {
        bail!(
            "{} does not match the header {} (its hash differs); the two files come from different runs, regenerate the report",
            side.display(),
            path.display()
        );
    }
    if raw.len() < MAGIC.len() + 1 || &raw[..MAGIC.len()] != MAGIC || raw[MAGIC.len()] != SIDE_VERSION {
        bail!("{} is not an atoms file of this version; regenerate the report", side.display());
    }
    let mut payload = Vec::new();
    let mut dec = zstd::stream::Decoder::new(&raw[MAGIC.len() + 1..])?;
    dec.window_log_max(27)?;
    dec.read_to_end(&mut payload)
        .with_context(|| format!("{} does not decompress; regenerate the report", side.display()))?;
    let mut r = R(&payload);
    let ns = r.u()? as usize;
    let mut str_ends = Vec::with_capacity(ns);
    let mut total = 0u32;
    for _ in 0..ns {
        total = total
            .checked_add(r.u()? as u32)
            .context("the atoms file holds more string bytes than it can address; it is corrupt, regenerate the report")?;
        str_ends.push(total);
    }
    let str_text = r.raw(total as usize)?.to_vec();
    let n = r.u()? as usize;
    if n as u64 != h.compact.atoms {
        bail!("{} holds {} atoms but its header says {}; regenerate the report", side.display(), n, h.compact.atoms);
    }
    let archive = r.col32(n)?;
    let member = r.col32(n)?;
    let section = r.col32(n)?;
    let symbol = r.col32(n)?;
    let crate_name = r.col32(n)?;
    let offset: Vec<u64> = (0..n).map(|_| r.u()).collect::<Result<_>>()?;
    let own_object: Vec<bool> = r.raw(n)?.iter().map(|&b| b != 0).collect();
    let class = r.raw(n)?.to_vec();
    let size: Vec<u64> = (0..n).map(|_| r.u()).collect::<Result<_>>()?;
    let mut cols = Vec::new();
    for _ in 0..4 {
        let b = r.raw(n * 8)?;
        cols.push(
            b.as_chunks::<8>()
                .0
                .iter()
                .map(|c| u64::from_be_bytes(*c))
                .collect::<Vec<u64>>(),
        );
    }
    let reloc_hash = cols.pop().unwrap();
    let bytes_hash = cols.pop().unwrap();
    let content = cols.pop().unwrap();
    let hash = cols.pop().unwrap();
    let mut alias_start = Vec::with_capacity(n + 1);
    alias_start.push(0u32);
    for _ in 0..n {
        let c = r.u()? as u32;
        alias_start.push(alias_start.last().unwrap() + c);
    }
    let na = r.u()? as usize;
    let alias_names = r.col32(na)?;
    let table = AtomTable {
        str_text,
        str_ends,
        archive,
        member,
        section,
        offset,
        symbol,
        crate_name,
        own_object,
        hash,
        content,
        class,
        size,
        bytes_hash,
        reloc_hash,
        alias_start,
        alias_names,
    };
    let crate_table = r.strings()?;
    let harness = Atoms(r.bitmap()?);
    let nt = r.u()? as usize;
    if nt != h.tests.len() {
        bail!("{} holds {} tests but its header lists {}; regenerate the report", side.display(), nt, h.tests.len());
    }
    let mut tests = BTreeMap::new();
    for (name, ht) in h.tests {
        let atoms = Atoms(r.bitmap()?);
        let crates: BTreeSet<String> = r
            .bitmap()?
            .iter()
            .map(|i| crate_table[i as usize].clone())
            .collect();
        tests.insert(
            name,
            TestReach::from_parts(
                ht.key,
                ht.fallback,
                atoms,
                crates,
                ht.spawns_processes,
                ht.spawns,
                ht.entry,
            ),
        );
    }
    Ok(BinaryReach {
        format: h.format,
        executable: h.executable,
        verifiable: h.verifiable,
        harness_key: h.harness_key,
        tests,
        unresolved_imports: h.unresolved_imports,
        stats: h.stats,
        harness_atoms: harness,
        atom_table: table,
        missing_tests: h.missing_tests,
        notes: h.notes,
        unkeyed_inputs: h.unkeyed_inputs,
        section_sets: h.section_sets,
        timings: h.timings,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fallback::Via;

    fn sample() -> BinaryReach {
        let mut b = AtomTableBuilder::default();
        for (i, (sym, al)) in [("_ZN1a1fE", vec!["_ZN1a1gE"]), ("", vec![]), ("_ZN1b1hE", vec![])]
            .into_iter()
            .enumerate()
        {
            b.push(Row {
                archive: "/x/liba-1.rlib",
                member: "a.o",
                section: i as u32,
                offset: 16 * i as u64,
                symbol: sym,
                crate_name: "a",
                own_object: i == 2,
                hash: 0xdead_beef_0000_0000 + i as u64,
                content: 7 + i as u64,
                class: (i % 3) as u8,
                size: 8 * i as u64,
                bytes_hash: 100 + i as u64,
                reloc_hash: 200 + i as u64,
                aliases: &al,
            });
        }
        let mut tests = BTreeMap::new();
        tests.insert(
            "t::one".to_string(),
            TestReach::from_parts(
                None,
                Some(Fallback::LoadsLibrary(Culprit {
                    via: Via::Calls,
                    callee: "dlopen".into(),
                    caller: Some("a::f".into()),
                    object: "/x/liba-1.rlib!a.o".into(),
                    alias_of: None,
                })),
                [1u32, 2].into_iter().collect(),
                ["a".to_string(), "std".to_string()].into(),
                true,
                None,
                EntrySource::Descriptor,
            ),
        );
        tests.insert(
            "t::two".to_string(),
            TestReach::from_parts(
                Some([2; 32]),
                None,
                Atoms::default(),
                BTreeSet::new(),
                false,
                None,
                EntrySource::Name,
            ),
        );
        BinaryReach {
            format: FORMAT,
            executable: "/x/bin".into(),
            verifiable: Ok(()),
            harness_key: [9; 32],
            tests,
            unresolved_imports: vec!["puts".into()],
            stats: Stats::default(),
            harness_atoms: [0u32].into_iter().collect(),
            atom_table: b.finish(),
            missing_tests: vec![],
            notes: vec![],
            unkeyed_inputs: vec!["libz.dylib".into()],            section_sets: vec![],
            timings: vec![],
        }
    }

    #[test]
    fn compact_round_trips_and_notices_a_mismatched_side_file() {
        let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../target/tmp/keel-reach-store");
        std::fs::create_dir_all(&dir).unwrap();
        let (h, other) = (dir.join("r.json"), dir.join("s.json"));
        let r = sample();
        write_compact(&r, &h).unwrap();
        let back = read(&h).unwrap();
        assert_eq!(back.tests, r.tests);
        assert_eq!(back.atom_table, r.atom_table);
        assert_eq!(back.harness_atoms, r.harness_atoms);
        assert_eq!(back.harness_key, r.harness_key);
        // JSON round-trips to the same thing.
        write_json(&r, &other).unwrap();
        let j = read(&other).unwrap();
        assert_eq!(j.tests, r.tests);
        assert_eq!(j.atom_table, r.atom_table);
        // A side file from another run is refused.
        write_compact(&{ let mut x = sample(); x.harness_atoms = Atoms::default(); x }, &dir.join("r2.json")).unwrap();
        std::fs::copy(dir.join("r2.atoms"), dir.join("r.atoms")).unwrap();
        assert!(read(&h).unwrap_err().to_string().contains("different runs"));
    }
}

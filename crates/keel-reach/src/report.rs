//! The serialisable result of analysing one binary, and the diff of two.

use crate::fallback::{Culprit, Fallback};
use roaring::RoaringBitmap;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::path::PathBuf;

/// Index into `BinaryReach::atom_table`. Stable within one report only; the
/// table entry (archive, member, names, hash) is the identity to join on
/// across binaries.
pub type AtomId = u32;

/// Reports written before aliases and structured fallbacks have `format` 0.
pub const FORMAT: u32 = 2;

mod hex32 {
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

/// A set of atom ids. Serialised as a list of numbers, which is what `Vec<AtomId>` was.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Atoms(pub RoaringBitmap);

// A bitmap compares by its members, which is total.
impl Eq for Atoms {}

impl Atoms {
    pub fn len(&self) -> usize {
        self.0.len() as usize
    }
    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = AtomId> + '_ {
        self.0.iter()
    }
    pub fn contains(&self, id: AtomId) -> bool {
        self.0.contains(id)
    }
}

impl FromIterator<AtomId> for Atoms {
    fn from_iter<I: IntoIterator<Item = AtomId>>(i: I) -> Atoms {
        Atoms(i.into_iter().collect())
    }
}

impl Serialize for Atoms {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq(self.0.iter())
    }
}

impl<'de> Deserialize<'de> for Atoms {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Atoms, D::Error> {
        Ok(Atoms(Vec::<u32>::deserialize(d)?.into_iter().collect()))
    }
}

/// One atom of the table, as a value. The table itself is columnar (`AtomTable`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Default)]
pub struct AtomInfo {
    pub archive: String,
    pub member: String,
    pub section: u32,
    pub offset: u64,
    /// Mangled symbol that starts the atom, empty if it has none.
    pub symbol: String,
    /// The crate of the archive (or of the test crate for its own objects).
    pub crate_name: String,
    /// True for the test crate's own objects.
    #[serde(default)]
    pub own_object: bool,
    /// First 16 hex digits of the hash of the atom's component, to see which atoms two builds disagree on.
    #[serde(default)]
    pub hash: String,
    /// The other symbols inside the atom (merged or aliased functions), mangled.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub aliases: Vec<String>,
    /// First 16 hex digits of the atom's own content hash (bytes and relocation shapes): its `local`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub content: String,
    /// `text`, `data`, `literal`, `cstring`, `lsda` or `other`.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub class: String,
    #[serde(default)]
    pub size: u64,
    /// First 16 hex digits of the hash of the atom's bytes alone.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub bytes_hash: String,
    /// First 16 hex digits of the hash of its relocations' offsets, kinds and addends.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub reloc_hash: String,
}

/// Atoms of a report in columns: 590,000 rows with their strings held once.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct AtomTable {
    /// The string pool: every string once, back to back; `str_ends[i]` is where string `i` ends.
    pub str_text: Vec<u8>,
    pub str_ends: Vec<u32>,
    pub archive: Vec<u32>,
    pub member: Vec<u32>,
    pub section: Vec<u32>,
    pub offset: Vec<u64>,
    /// String index of the naming symbol; string 0 is the empty string.
    pub symbol: Vec<u32>,
    pub crate_name: Vec<u32>,
    pub own_object: Vec<bool>,
    /// First 8 bytes of the component hash, big endian.
    pub hash: Vec<u64>,
    /// First 8 bytes of the atom content hash, big endian.
    pub content: Vec<u64>,
    /// `model::AtomClass` as a number.
    pub class: Vec<u8>,
    pub size: Vec<u64>,
    /// First 8 bytes of the hash of the atom's bytes alone, big endian.
    pub bytes_hash: Vec<u64>,
    /// First 8 bytes of the hash of the atom's relocations, big endian.
    pub reloc_hash: Vec<u64>,
    /// `alias_names[alias_start[i]..alias_start[i + 1]]` are the string indices of atom i's aliases.
    pub alias_start: Vec<u32>,
    pub alias_names: Vec<u32>,
}

/// Row values for `AtomTableBuilder::push`.
pub struct Row<'a> {
    pub archive: &'a str,
    pub member: &'a str,
    pub section: u32,
    pub offset: u64,
    pub symbol: &'a str,
    pub crate_name: &'a str,
    pub own_object: bool,
    pub hash: u64,
    pub content: u64,
    pub class: u8,
    pub size: u64,
    pub bytes_hash: u64,
    pub reloc_hash: u64,
    pub aliases: &'a [&'a str],
}

pub struct AtomTableBuilder {
    t: AtomTable,
    /// String hash to index. A hash that is taken by another string is probed past, so a
    /// collision costs a second lookup, never a wrong name.
    index: HashMap<u64, u32>,
}

impl Default for AtomTableBuilder {
    fn default() -> Self {
        let mut b = AtomTableBuilder {
            t: AtomTable::default(),
            index: HashMap::new(),
        };
        b.intern("");
        b.t.alias_start.push(0);
        b
    }
}

impl AtomTableBuilder {
    /// Room for about `atoms` rows, so the pool does not grow by doubling (which briefly
    /// holds two copies of tens of megabytes).
    pub fn with_capacity(atoms: usize) -> AtomTableBuilder {
        let mut b = AtomTableBuilder::default();
        b.t.str_text.reserve(atoms * 120);
        b.t.str_ends.reserve(atoms + 16);
        b.index.reserve(atoms + 16);
        for v in [&mut b.t.archive, &mut b.t.member, &mut b.t.section, &mut b.t.symbol, &mut b.t.crate_name, &mut b.t.alias_start] {
            v.reserve(atoms);
        }
        b.t.offset.reserve(atoms);
        b.t.own_object.reserve(atoms);
        b.t.hash.reserve(atoms);
        b.t.content.reserve(atoms);
        b
    }

    fn intern(&mut self, s: &str) -> u32 {
        let mut key = u64::from_le_bytes(blake3::hash(s.as_bytes()).as_bytes()[..8].try_into().unwrap());
        while let Some(&i) = self.index.get(&key) {
            if self.t.s(i) == s {
                return i;
            }
            key = key.wrapping_add(1);
        }
        let i = self.t.str_ends.len() as u32;
        self.t.str_text.extend_from_slice(s.as_bytes());
        self.t.str_ends.push(self.t.str_text.len() as u32);
        self.index.insert(key, i);
        i
    }

    pub fn push(&mut self, r: Row) {
        let (a, m, s, c) = (
            self.intern(r.archive),
            self.intern(r.member),
            self.intern(r.symbol),
            self.intern(r.crate_name),
        );
        let t = &mut self.t;
        t.archive.push(a);
        t.member.push(m);
        t.section.push(r.section);
        t.offset.push(r.offset);
        t.symbol.push(s);
        t.crate_name.push(c);
        t.own_object.push(r.own_object);
        t.hash.push(r.hash);
        t.content.push(r.content);
        t.class.push(r.class);
        t.size.push(r.size);
        t.bytes_hash.push(r.bytes_hash);
        t.reloc_hash.push(r.reloc_hash);
        for al in r.aliases {
            let i = self.intern(al);
            self.t.alias_names.push(i);
        }
        let n = self.t.alias_names.len() as u32;
        self.t.alias_start.push(n);
    }

    pub fn finish(self) -> AtomTable {
        self.t
    }
}

pub fn hash16(h: u64) -> String {
    format!("{h:016x}")
}

struct ClassName;

impl ClassName {
    fn code(s: &str) -> u8 {
        (0..=5)
            .find(|&b| crate::model::AtomClass::name(b) == s)
            .unwrap_or(5)
    }
}

fn parse_hash16(s: &str) -> u64 {
    u64::from_str_radix(s, 16).unwrap_or(0)
}

impl AtomTable {
    pub fn len(&self) -> usize {
        self.archive.len()
    }

    pub fn is_empty(&self) -> bool {
        self.archive.is_empty()
    }

    pub fn s(&self, ix: u32) -> &str {
        let start = if ix == 0 { 0 } else { self.str_ends[ix as usize - 1] as usize };
        std::str::from_utf8(&self.str_text[start..self.str_ends[ix as usize] as usize]).unwrap_or("<invalid utf-8>")
    }

    pub fn symbol(&self, i: AtomId) -> &str {
        self.s(self.symbol[i as usize])
    }

    pub fn archive(&self, i: AtomId) -> &str {
        self.s(self.archive[i as usize])
    }

    pub fn member(&self, i: AtomId) -> &str {
        self.s(self.member[i as usize])
    }

    pub fn crate_name(&self, i: AtomId) -> &str {
        self.s(self.crate_name[i as usize])
    }

    /// The other mangled names inside the atom.
    pub fn aliases(&self, i: AtomId) -> impl Iterator<Item = &str> {
        let (a, b) = (
            self.alias_start[i as usize] as usize,
            self.alias_start[i as usize + 1] as usize,
        );
        self.alias_names[a..b].iter().map(|&x| self.s(x))
    }

    /// Every mangled name of the atom: the naming symbol first (if any), then the aliases.
    pub fn names(&self, i: AtomId) -> impl Iterator<Item = &str> {
        let sym = self.symbol(i);
        (!sym.is_empty())
            .then_some(sym)
            .into_iter()
            .chain(self.aliases(i))
    }

    pub fn get(&self, i: AtomId) -> AtomInfo {
        let u = i as usize;
        AtomInfo {
            archive: self.archive(i).into(),
            member: self.member(i).into(),
            section: self.section[u],
            offset: self.offset[u],
            symbol: self.symbol(i).into(),
            crate_name: self.crate_name(i).into(),
            own_object: self.own_object[u],
            hash: hash16(self.hash[u]),
            aliases: self.aliases(i).map(str::to_string).collect(),
            content: if self.content[u] == 0 {
                String::new()
            } else {
                hash16(self.content[u])
            },
            class: crate::model::AtomClass::name(self.class[u]).to_string(),
            size: self.size[u],
            bytes_hash: hash16(self.bytes_hash[u]),
            reloc_hash: hash16(self.reloc_hash[u]),
        }
    }

    pub fn from_infos(v: Vec<AtomInfo>) -> AtomTable {
        let mut b = AtomTableBuilder::default();
        for a in &v {
            let al: Vec<&str> = a.aliases.iter().map(String::as_str).collect();
            b.push(Row {
                archive: &a.archive,
                member: &a.member,
                section: a.section,
                offset: a.offset,
                symbol: &a.symbol,
                crate_name: &a.crate_name,
                own_object: a.own_object,
                hash: parse_hash16(&a.hash),
                content: parse_hash16(&a.content),
                class: ClassName::code(&a.class),
                size: a.size,
                bytes_hash: parse_hash16(&a.bytes_hash),
                reloc_hash: parse_hash16(&a.reloc_hash),
                aliases: &al,
            });
        }
        b.finish()
    }
}

impl Serialize for AtomTable {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_seq((0..self.len() as u32).map(|i| self.get(i)))
    }
}

impl<'de> Deserialize<'de> for AtomTable {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<AtomTable, D::Error> {
        Ok(AtomTable::from_infos(Vec::<AtomInfo>::deserialize(d)?))
    }
}

/// How a test's entry atoms were established.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntrySource {
    /// Not recorded (reports written before entries came from the harness's table).
    #[default]
    Unknown,
    /// The function pointer of a test descriptor that names the test, and the symbol
    /// name guessed from the test path agrees (or found nothing).
    Descriptor,
    /// A descriptor entry plus guessed atoms that the descriptor's function does not reach;
    /// both are roots, which can only widen the reach.
    DescriptorAndName,
    /// Only the symbol guessed from the test path.
    Name,
    None,
}

/// What a test is keyed by. A key and a fallback cannot both be present, and a test that
/// cannot be keyed has no key to mistake for one: a consumer that wants a key has to match
/// on this.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TestResult {
    /// The test is identified by its reach key.
    Keyed { key: [u8; 32], atoms: Atoms },
    /// The test's reach is not trusted, or could not be found; the reason says what to use
    /// instead (`Fallback::exe_key_sufficient`). The atoms are what was reached, if anything.
    Fallback { reason: Fallback, atoms: Atoms },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TestReach {
    pub result: TestResult,
    pub crates: BTreeSet<String>,
    pub spawns_processes: bool,
    /// Where the process spawn was found, when `spawns_processes`.
    pub spawns: Option<Culprit>,
    pub entry: EntrySource,
}

impl TestReach {
    pub fn keyed(key: [u8; 32], atoms: Atoms) -> TestReach {
        TestReach::of(TestResult::Keyed { key, atoms })
    }

    pub fn falling_back(reason: Fallback, atoms: Atoms) -> TestReach {
        TestReach::of(TestResult::Fallback { reason, atoms })
    }

    fn of(result: TestResult) -> TestReach {
        TestReach {
            result,
            crates: BTreeSet::new(),
            spawns_processes: false,
            spawns: None,
            entry: EntrySource::None,
        }
    }

    /// Assemble a result from the parts a file holds. A key only counts when there is no
    /// fallback and it is not all zero (what older reports wrote for tests they could not
    /// key); anything else is a fallback.
    pub fn from_parts(
        key: Option<[u8; 32]>,
        fallback: Option<Fallback>,
        atoms: Atoms,
        crates: BTreeSet<String>,
        spawns_processes: bool,
        spawns: Option<Culprit>,
        entry: EntrySource,
    ) -> TestReach {
        let result = match (fallback, key) {
            (Some(reason), _) => TestResult::Fallback { reason, atoms },
            (None, Some(key)) if key != [0; 32] => TestResult::Keyed { key, atoms },
            (None, _) => TestResult::Fallback {
                reason: Fallback::Unverifiable {
                    why: "the report holds no usable key for this test (missing or all zero)".into(),
                },
                atoms,
            },
        };
        TestReach { result, crates, spawns_processes, spawns, entry }
    }

    /// The test's reach key; `None` for a test that falls back.
    pub fn key(&self) -> Option<&[u8; 32]> {
        match &self.result {
            TestResult::Keyed { key, .. } => Some(key),
            TestResult::Fallback { .. } => None,
        }
    }

    pub fn fallback(&self) -> Option<&Fallback> {
        match &self.result {
            TestResult::Keyed { .. } => None,
            TestResult::Fallback { reason, .. } => Some(reason),
        }
    }

    /// The test's reach minus the harness set, which is common to every test
    /// and stored once in `BinaryReach::harness_atoms`.
    pub fn atoms(&self) -> &Atoms {
        match &self.result {
            TestResult::Keyed { atoms, .. } | TestResult::Fallback { atoms, .. } => atoms,
        }
    }

    pub fn atoms_mut(&mut self) -> &mut Atoms {
        match &mut self.result {
            TestResult::Keyed { atoms, .. } | TestResult::Fallback { atoms, .. } => atoms,
        }
    }
}

/// The JSON form: `key` is null when the test falls back, and `fallback` is null when it
/// is keyed. A record with neither, or with an all-zero key and no fallback (what older
/// reports wrote for tests they could not key), reads back as a fallback.
#[derive(Serialize, Deserialize)]
struct TestWire {
    #[serde(default, with = "opt_hex32")]
    key: Option<[u8; 32]>,
    atoms: Atoms,
    crates: BTreeSet<String>,
    #[serde(with = "crate::fallback::opt", default)]
    fallback: Option<Fallback>,
    #[serde(default)]
    spawns_processes: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    spawns: Option<Culprit>,
    #[serde(default)]
    entry: EntrySource,
}

mod opt_hex32 {
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

impl From<TestReach> for TestWire {
    fn from(t: TestReach) -> TestWire {
        let (key, fallback, atoms) = match t.result {
            TestResult::Keyed { key, atoms } => (Some(key), None, atoms),
            TestResult::Fallback { reason, atoms } => (None, Some(reason), atoms),
        };
        TestWire {
            key,
            atoms,
            crates: t.crates,
            fallback,
            spawns_processes: t.spawns_processes,
            spawns: t.spawns,
            entry: t.entry,
        }
    }
}

impl From<TestWire> for TestReach {
    fn from(w: TestWire) -> TestReach {
        TestReach::from_parts(w.key, w.fallback, w.atoms, w.crates, w.spawns_processes, w.spawns, w.entry)
    }
}

impl Serialize for TestReach {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        TestWire::from(self.clone()).serialize(s)
    }
}

impl<'de> Deserialize<'de> for TestReach {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<TestReach, D::Error> {
        Ok(TestWire::deserialize(d)?.into())
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Stats {
    pub objects: usize,
    pub archives: usize,
    pub atoms: usize,
    pub relocations: usize,
    pub sccs: usize,
    pub wall_ms: u64,
    /// Atoms reached from any root (nodes of the analysed graph).
    #[serde(default)]
    pub reached_atoms: usize,
    /// Archive contents parsed (not served from the loader's cache) during this call.
    #[serde(default)]
    #[serde(alias = "archives_parsed")]
    pub members_parsed: usize,
    /// Archive members read from the on-disk cache instead of being parsed.
    #[serde(default)]
    pub members_from_cache: usize,
    /// Tests whose entry came from a test descriptor.
    #[serde(default)]
    pub entries_from_descriptors: usize,
    /// Tests whose only entry is a guessed symbol name.
    #[serde(default)]
    pub entries_from_names: usize,
    /// Symbol names that more than one input defines with the same strength but different
    /// content, resolved by the lowest content hash (see `Program::lookup`).
    #[serde(default)]
    pub ambiguous_definitions: usize,
    /// Of those, names whose winner could not be established; tests reaching one fall back.
    #[serde(default)]
    pub unestablished_definitions: usize,
    /// Mach-O members without MH_SUBSECTIONS_VIA_SYMBOLS, analysed as one atom per section.
    #[serde(default)]
    pub whole_section_members: usize,
}

/// A section-boundary symbol (`__start_X`, `section$end$SEG$sect`, ...) reached from the
/// graph, and what it pulled in.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct SectionSetUse {
    /// Section key: ELF section name, or `segment,section`.
    pub section: String,
    /// The boundary symbols that were referenced.
    pub symbols: Vec<String>,
    /// Atoms in the section, all of them treated as reached.
    pub atoms: usize,
    /// Of those, atoms that no other path reached first (an upper bound on what the
    /// rule adds, since it depends on discovery order).
    pub first_reached_by_section: usize,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Timing {
    pub span: String,
    pub ms: u64,
    /// Peak resident set of the process at the end of the span.
    #[serde(default)]
    pub peak_rss_mb: u64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BinaryReach {
    #[serde(default)]
    pub format: u32,
    pub executable: PathBuf,
    pub verifiable: Result<(), String>,
    #[serde(with = "hex32")]
    pub harness_key: [u8; 32],
    pub tests: BTreeMap<String, TestReach>,
    /// Undefined names, reached from the roots, that no input defines and the
    /// linker does not synthesise: assumed to be dynamic imports.
    pub unresolved_imports: Vec<String>,
    pub stats: Stats,
    pub harness_atoms: Atoms,
    pub atom_table: AtomTable,
    /// Tests for which no entry symbol was found.
    pub missing_tests: Vec<String>,
    pub notes: Vec<String>,
    /// Inputs the link read that are keyed by name only, not by content: dynamic libraries,
    /// and `-l` names the analyser could not find a static library for.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub unkeyed_inputs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub section_sets: Vec<SectionSetUse>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub timings: Vec<Timing>,
}

pub fn intersects(a: &BTreeSet<AtomId>, b: &BTreeSet<AtomId>) -> bool {
    let (s, l) = if a.len() <= b.len() { (a, b) } else { (b, a) };
    s.iter().any(|x| l.contains(x))
}

/// Fallbacks by kind and, within a kind, by the function that causes them.
pub type FallbackCounts = BTreeMap<(String, String), usize>;

impl BinaryReach {
    /// Atoms in the test's full reach (its own plus the harness set).
    pub fn full_reach(&self, test: &str) -> BTreeSet<AtomId> {
        let t = &self.tests[test];
        self.harness_atoms.iter().chain(t.atoms().iter()).collect()
    }

    /// The part of the test's reach that belongs to the package under test:
    /// atoms from the crates named in `own_crates` (its lib rlib) and from the
    /// test crate's own objects. Empty for an unknown test.
    pub fn exercised(&self, test: &str, own_crates: &[&str]) -> BTreeSet<AtomId> {
        if !self.tests.contains_key(test) {
            return BTreeSet::new();
        }
        self.full_reach(test)
            .into_iter()
            .filter(|&id| {
                self.atom_table.own_object[id as usize]
                    || own_crates.contains(&self.atom_table.crate_name(id))
            })
            .collect()
    }

    /// Identity strings for cross-binary joins: ids differ per report, these do not.
    pub fn identities(&self, ids: &BTreeSet<AtomId>) -> BTreeSet<String> {
        ids.iter()
            .map(|&i| {
                let t = &self.atom_table;
                format!(
                    "{}!{}#{}+{}",
                    t.archive(i),
                    t.member(i),
                    t.section[i as usize],
                    t.offset[i as usize]
                )
            })
            .collect()
    }

    /// Tests whose key must come from the executable, counted by (kind, calling function).
    pub fn fallback_counts(&self) -> FallbackCounts {
        let mut m = FallbackCounts::new();
        for t in self.tests.values() {
            if let Some(f) = t.fallback() {
                *m.entry((f.kind().to_string(), f.group())).or_default() += 1;
            }
        }
        m
    }

    /// Fallbacks by kind alone.
    pub fn fallback_kinds(&self) -> BTreeMap<&'static str, usize> {
        let mut m = BTreeMap::new();
        for t in self.tests.values() {
            if let Some(f) = t.fallback() {
                *m.entry(f.kind()).or_default() += 1;
            }
        }
        m
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Change {
    Changed,
    Same,
    Fallback,
}

pub struct DiffSummary {
    pub rows: Vec<(String, Change)>,
    pub changed: usize,
    pub same: usize,
    pub fallback: usize,
}

/// Tests present in both reports. A test in fallback on either side is
/// `Fallback`: its decision comes from the executable key, not from this one.
pub fn diff(before: &BinaryReach, after: &BinaryReach) -> DiffSummary {
    let mut s = DiffSummary {
        rows: Vec::new(),
        changed: 0,
        same: 0,
        fallback: 0,
    };
    for (name, b) in &before.tests {
        let Some(a) = after.tests.get(name) else {
            continue;
        };
        let c = if a.fallback().is_some() || b.fallback().is_some() {
            s.fallback += 1;
            Change::Fallback
        } else if a.key() != b.key() {
            s.changed += 1;
            Change::Changed
        } else {
            s.same += 1;
            Change::Same
        };
        s.rows.push((name.clone(), c));
    }
    s
}

//! The symbolic link: resolve names across every input, then walk the
//! relocation graph from a set of roots.

use crate::graph::Graph;
use crate::load::Unit;
use crate::model::*;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};

/// Names a linker invents or a C runtime provides; hashed by name.
const SYNTHESISED: &[&str] = &[
    "_GLOBAL_OFFSET_TABLE_",
    "__dso_handle",
    "___dso_handle",
    "__TMC_END__",
    "_DYNAMIC",
    "__ehdr_start",
    "__executable_start",
    "_end",
    "_edata",
    "__bss_start",
    "__tls_get_addr",
    "___tls_get_addr",
    "__stack_chk_guard",
    "___stack_chk_guard",
    "dyld_stub_binder",
    "__mh_execute_header",
];

/// A definition in the symbol table.
#[derive(Clone, Copy)]
struct SymEntry {
    id: [u64; 2],
    gatom: u32,
    off: u32,
    mem: u32,
    weak: bool,
}

#[derive(Clone, Copy)]
pub struct MemRef {
    pub unit: u32,
    pub member: u32,
}

pub struct Program<'a> {
    pub units: &'a [Unit],
    pub mems: Vec<MemRef>,
    /// First global atom index of each member; one extra entry for the total.
    pub base: Vec<u32>,
    /// Every external definition, sorted by name identity (`model::name_id`).
    symtab: Vec<SymEntry>,
    pub objects: usize,
    pub archives: usize,
    pub relocations: usize,
}

/// How firmly a name's definition is known.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dup {
    /// Defined once.
    Unique,
    /// Defined more than once, with the same content: any copy does.
    Equivalent,
    /// Defined with different content, and settled by link order.
    ByOrder { definitions: usize },
    /// Defined with different content and the linker's choice cannot be established.
    Unestablished { definitions: usize },
}

pub enum Resolved {
    Atom {
        gatom: u32,
        off: u32,
        /// See `Program::lookup_ex`.
        dup: Dup,
    },
    /// Every atom of a section (or segment) the linker bounds with a start or end symbol.
    Set(String),
    Import,
    Synthesised,
}

/// Prefix of a `Resolved::Set` key that names a whole Mach-O segment, not one section.
const SEGMENT_KEY: &str = "segment:";

/// The section a linker-defined boundary symbol stands for, as a key that matches
/// `SectionInfo::key`, or `None` if `name` is not a boundary symbol.
///
/// * ELF: `__start_<sec>` and `__stop_<sec>` for a section whose name is a C identifier.
/// * Mach-O: `section$start$<SEG>$<sect>` and `section$end$<SEG>$<sect>`, and
///   `segment$start$<SEG>` / `segment$end$<SEG>` for a whole segment. Rust spells these
///   with a `\x01` prefix so the compiler adds no underscore, but a name that did get one
///   is taken the same way: a boundary that is not recognised is a missed dependency, and
///   one that is recognised needlessly only widens a reach.
pub fn boundary_key(name: &str) -> Option<String> {
    if let Some(k) = name
        .strip_prefix("__start_")
        .or_else(|| name.strip_prefix("__stop_"))
        .filter(|k| !k.is_empty())
    {
        return Some(k.to_string());
    }
    let bare = name.strip_prefix('_').unwrap_or(name);
    for p in ["section$start$", "section$end$"] {
        if let Some(rest) = bare.strip_prefix(p) {
            return Some(rest.replacen('$', ",", 1));
        }
    }
    for p in ["segment$start$", "segment$end$"] {
        if let Some(rest) = bare.strip_prefix(p) {
            return Some(format!("{SEGMENT_KEY}{rest}"));
        }
    }
    None
}

impl<'a> Program<'a> {
    pub fn new(units: &'a [Unit]) -> Program<'a> {
        let mut mems = Vec::new();
        let mut base = Vec::new();
        let mut total = 0u32;
        let (mut objects, mut archives, mut relocations) = (0, 0, 0);
        for (ui, u) in units.iter().enumerate() {
            if u.file.is_archive {
                archives += 1;
            }
            for (mi, m) in u.file.members.iter().enumerate() {
                objects += 1;
                relocations += m.relocs.len();
                mems.push(MemRef {
                    unit: ui as u32,
                    member: mi as u32,
                });
                base.push(total);
                total += m.atoms.len() as u32;
            }
        }
        base.push(total);
        let mut symtab: Vec<SymEntry> = Vec::new();
        for (mi, r) in mems.iter().enumerate() {
            let m = &units[r.unit as usize].file.members[r.member as usize];
            for d in m.defs.iter() {
                symtab.push(SymEntry {
                    id: m.names.id(d.name as usize),
                    gatom: base[mi] + d.atom,
                    off: d.off,
                    mem: mi as u32,
                    weak: d.weak != 0,
                });
            }
        }
        symtab.sort_unstable_by_key(|e| (e.id, e.mem, e.gatom));
        Program {
            units,
            mems,
            base,
            symtab,
            objects,
            archives,
            relocations,
        }
    }

    pub fn member(&self, mem: u32) -> &Member {
        let r = self.mems[mem as usize];
        &self.units[r.unit as usize].file.members[r.member as usize]
    }

    pub fn total_atoms(&self) -> u32 {
        *self.base.last().unwrap()
    }

    /// Member and atom index within it for a global atom index.
    pub fn locate(&self, gatom: u32) -> (u32, u32) {
        let mem = self.base.partition_point(|&b| b <= gatom) - 1;
        (mem as u32, gatom - self.base[mem])
    }

    pub fn atom(&self, gatom: u32) -> (&Unit, &Member, &Atom) {
        let (mem, a) = self.locate(gatom);
        let r = self.mems[mem as usize];
        let m = self.member(mem);
        (&self.units[r.unit as usize], m, &m.atoms[a as usize])
    }

    /// The definition the linker would use. Strong beats weak. Among definitions of equal
    /// strength, one input that is a plain object file beats archive members (objects are
    /// always linked, and first); several objects go by their place on the link line.
    /// When equal-strength definitions differ in content and that does not decide, which
    /// copy runs depends on which archive members the linker pulled in and in what
    /// order, which a record of the link line does not say: the answer is then marked
    /// `Unestablished` and the lowest content hash stands in so the graph is still a
    /// function of the inputs. Tests that reach such a name must not be keyed by reach.
    pub fn lookup(&self, name: &str) -> Option<(u32, u32)> {
        self.lookup_ex(&name_id(name)).map(|(g, o, _)| (g, o))
    }

    fn defs_of(&self, id: &[u64; 2]) -> &[SymEntry] {
        let lo = self.symtab.partition_point(|e| e.id < *id);
        let hi = lo + self.symtab[lo..].partition_point(|e| e.id == *id);
        &self.symtab[lo..hi]
    }

    pub fn lookup_ex(&self, id: &[u64; 2]) -> Option<(u32, u32, Dup)> {
        let cands = self.defs_of(id);
        if let [only] = cands {
            return Some((only.gatom, only.off, Dup::Unique));
        }
        let strongest = cands.iter().map(|d| d.weak).min()?;
        let tier: Vec<&SymEntry> = cands.iter().filter(|d| d.weak == strongest).collect();
        let content = |d: &SymEntry| self.atom(d.gatom).2.content;
        let lowest = tier
            .iter()
            .copied()
            .min_by_key(|d| (content(d), d.mem, d.gatom))
            .expect("tier is non-empty");
        let differs = cands.iter().any(|d| content(d) != content(lowest));
        if !differs {
            return Some((lowest.gatom, lowest.off, Dup::Equivalent));
        }
        // Plain object files: linked first, in order.
        let is_object = |d: &SymEntry| {
            !self.units[self.mems[d.mem as usize].unit as usize]
                .file
                .is_archive
        };
        let order_of = |d: &SymEntry| self.units[self.mems[d.mem as usize].unit as usize].order;
        let objects: Vec<&&SymEntry> = tier.iter().filter(|d| is_object(d)).collect();
        if !objects.is_empty() && objects.iter().all(|d| order_of(d).is_some()) {
            let w = objects
                .iter()
                .min_by_key(|d| (order_of(d), d.mem, d.gatom))
                .expect("non-empty");
            return Some((
                w.gatom,
                w.off,
                Dup::ByOrder {
                    definitions: cands.len(),
                },
            ));
        }
        Some((
            lowest.gatom,
            lowest.off,
            Dup::Unestablished {
                definitions: cands.len(),
            },
        ))
    }

    /// Resolve the undefined name `ni` of member `m`. The name's text is read only when
    /// nothing defines it.
    pub fn resolve_in(&self, m: &MemberData, ni: u32) -> Resolved {
        match self.lookup_ex(&m.names.id(ni as usize)) {
            Some((gatom, off, dup)) => Resolved::Atom { gatom, off, dup },
            None => resolve_undefined(&m.names[ni as usize]),
        }
    }

    /// The atom a relocation of member `mem` points at, if it points at one.
    pub fn reloc_atom(&self, mem: u32, r: &Reloc) -> Option<u32> {
        match r.target() {
            RTarget::Atom(l) => Some(self.base[mem as usize] + l),
            RTarget::Abs => None,
            RTarget::Undef(ni) => match self.resolve_in(self.member(mem), ni) {
                Resolved::Atom { gatom, .. } => Some(gatom),
                _ => None,
            },
        }
    }

    /// Every atom of every input whose section matches `key` (see `boundary_key`).
    fn section_set(&self, key: &str) -> Vec<u32> {
        let seg = key.strip_prefix(SEGMENT_KEY);
        let mut out = Vec::new();
        for (mi, _) in self.mems.iter().enumerate() {
            let m = self.member(mi as u32);
            let hit: Vec<bool> = m
                .sections
                .iter()
                .map(|s| match seg {
                    Some(seg) => s.key.split_once(',').is_some_and(|(g, _)| g == seg),
                    None => &*s.key == key,
                })
                .collect();
            if !hit.iter().any(|&h| h) {
                continue;
            }
            for (ai, a) in m.atoms.iter().enumerate() {
                if hit[a.section as usize] {
                    out.push(self.base[mi] + ai as u32);
                }
            }
        }
        out
    }
}

fn resolve_undefined(name: &str) -> Resolved {
    if let Some(k) = boundary_key(name) {
        return Resolved::Set(k);
    }
    if SYNTHESISED.contains(&name) {
        Resolved::Synthesised
    } else {
        Resolved::Import
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Origin {
    Atom(u32),
    /// A dynamic import or linker-synthesised constant, by name.
    Leaf(String),
    Set(String),
}

/// A section-boundary symbol that something reached referenced.
#[derive(Clone, Debug)]
pub struct SetUse {
    pub key: String,
    pub symbols: BTreeSet<String>,
    pub atoms: usize,
    /// Atoms that nothing had reached before the section's expansion did.
    pub first_reached: usize,
}

/// Facts gathered while resolving names, for the report.
#[derive(Default)]
struct Seen<'a> {
    imports: BTreeSet<String>,
    /// Names defined with different content, settled by link order.
    by_order: BTreeSet<String>,
    /// Names defined with different content whose winner cannot be established.
    unestablished: BTreeMap<String, usize>,
    /// The first unestablished name met while resolving the targets of one atom.
    atom_dup: Option<(&'a str, usize)>,
}

pub struct Discovered {
    pub graph: Graph,
    pub origin: Vec<Origin>,
    /// Global atom index to node, `NONE` if undiscovered.
    pub node_of: Vec<u32>,
    pub imports: BTreeSet<String>,
    /// Validated libtest descriptors reached: the node and the entry atoms it referenced.
    /// Nothing in the graph points at them; each belongs to the reach of the test it names.
    pub descriptors: Vec<(u32, Vec<u32>)>,
    pub sets: Vec<SetUse>,
    /// Names settled by link order although the definitions differ.
    pub by_order: BTreeSet<String>,
    /// Names whose winning definition cannot be established, with their number of definitions.
    pub unestablished: BTreeMap<String, usize>,
    /// Nodes with a relocation to an unestablished name: the first such name and how many
    /// definitions it has.
    pub dup_at: HashMap<u32, (String, usize)>,
}

fn leaf_hash(tag: &str, name: &str) -> Hash {
    *blake3::Hasher::new()
        .update(b"keel-reach/")
        .update(tag.as_bytes())
        .update(b"/1")
        .update(name.as_bytes())
        .finalize()
        .as_bytes()
}

enum T<'a> {
    Atom(u32),
    Leaf(&'a str),
    /// Section key, and the boundary symbol that named it.
    Set(String, &'a str),
}

/// Relocation targets of one atom in relocation order, names resolved.
fn targets_of<'a>(p: &'a Program, g: u32, seen: &mut Seen<'a>) -> Vec<T<'a>> {
    let (mem, ai) = p.locate(g);
    let m = p.member(mem);
    seen.atom_dup = None;
    m.atom_relocs(&m.atoms[ai as usize])
        .iter()
        .map(|r| match r.target() {
            RTarget::Atom(l) => T::Atom(p.base[mem as usize] + l),
            RTarget::Abs => T::Leaf("<absolute>"),
            RTarget::Undef(ni) => {
                let name = &m.names[ni as usize];
                match p.resolve_in(m, ni) {
                    Resolved::Atom { gatom, dup, .. } => {
                        match dup {
                            Dup::ByOrder { .. } if !seen.by_order.contains(name) => {
                                seen.by_order.insert(name.to_string());
                            }
                            Dup::Unestablished { definitions } => {
                                seen.unestablished.insert(name.to_string(), definitions);
                                seen.atom_dup.get_or_insert((name, definitions));
                            }
                            _ => {}
                        }
                        T::Atom(gatom)
                    }
                    Resolved::Set(k) => T::Set(k, name),
                    Resolved::Synthesised => T::Leaf(name),
                    Resolved::Import => {
                        if !seen.imports.contains(name) {
                            seen.imports.insert(name.to_string());
                        }
                        T::Leaf(name)
                    }
                }
            }
        })
        .collect()
}

/// Breadth-first from `roots`. Node numbers follow discovery order, which is a
/// function of the (sorted) roots and relocation order only.
///
/// libtest's own table needs care, or `main` would reach every test through the
/// descriptor table and every key would contain every test. `descs` are the atoms
/// validated as libtest descriptors (`entry::read_descriptors`: a name that is in the test
/// list read back from a `&str`, and one function pointer), `entries` the functions they
/// point at. Only those get the treatment, so a user table of function pointers to tests,
/// and code that walks it, keep their edges and their bytes:
///
/// * A descriptor's edges to its entries are dropped (its other edges, the name string
///   and the `should_panic` message, are part of how that one test behaves and stay).
/// * A *table* is an atom whose every relocation points at a descriptor. Its edges to
///   descriptors are dropped, so descriptors are reachable only as per-test roots, and
///   its own bytes are replaced by a constant: the only things that vary in it are the
///   slice length and the pointers.
/// * Code that references a table is the *generated main*; its bytes are replaced by a
///   constant for the same reason, its edges (into libtest) stay.
///
/// A reference to a section-boundary symbol (`__start_X`, `section$end$SEG$sect`) is an
/// edge to a set node that has an edge to every atom of that section, whether or not
/// anything else reaches them: the linker lays the section out between the two symbols
/// and the referencing code walks all of it.
pub fn discover(
    p: &Program,
    roots: &[u32],
    descs: &HashSet<u32>,
    entries: &HashSet<u32>,
) -> Discovered {
    let mut node_of = vec![NONE; p.total_atoms() as usize];
    let mut content: Vec<Hash> = Vec::new();
    let mut origin: Vec<Origin> = Vec::new();
    let mut unordered: Vec<bool> = Vec::new();
    let mut adj: Vec<Vec<u32>> = Vec::new();
    let mut leaves: HashMap<&str, u32> = HashMap::new();
    let mut sets: HashMap<String, u32> = HashMap::new();
    let mut set_syms: HashMap<String, BTreeSet<String>> = HashMap::new();
    let mut set_uses: Vec<SetUse> = Vec::new();
    let mut seen = Seen::default();
    let mut descriptors = Vec::new();
    let mut dup_at: HashMap<u32, (String, usize)> = HashMap::new();
    let mut pending_sets: Vec<(u32, String)> = Vec::new();
    let mut table_memo: HashMap<u32, bool> = HashMap::new();

    let is_ro = |g: u32| {
        let (_, m, a) = p.atom(g);
        m.sections[a.section as usize].role == Role::RoData
    };
    // Entry atoms a validated descriptor references.
    let desc_entries = |g: u32| -> Vec<u32> {
        if !descs.contains(&g) {
            return vec![];
        }
        let mut scratch = Seen::default();
        targets_of(p, g, &mut scratch)
            .into_iter()
            .filter_map(|t| match t {
                T::Atom(x) if entries.contains(&x) => Some(x),
                _ => None,
            })
            .collect()
    };
    let is_table = |g: u32, table_memo: &mut HashMap<u32, bool>| -> bool {
        *table_memo.entry(g).or_insert_with(|| {
            if !is_ro(g) {
                return false;
            }
            let mut scratch = Seen::default();
            let ts = targets_of(p, g, &mut scratch);
            !ts.is_empty() && ts.iter().all(|t| matches!(t, T::Atom(x) if descs.contains(x)))
        })
    };

    macro_rules! node {
        ($c:expr, $o:expr, $u:expr) => {{
            content.push($c);
            origin.push($o);
            unordered.push($u);
            adj.push(Vec::new());
            (content.len() - 1) as u32
        }};
    }
    let mut roots: Vec<u32> = roots.to_vec();
    roots.sort_unstable();
    roots.dedup();
    let mut queue: Vec<u32> = Vec::new();
    for g in roots {
        if node_of[g as usize] == NONE {
            let (_, _, a) = p.atom(g);
            node_of[g as usize] = node!(a.content, Origin::Atom(g), false);
            queue.push(node_of[g as usize]);
        }
    }
    let mut qi = 0;
    while qi < queue.len() {
        let n = queue[qi];
        qi += 1;
        let Origin::Atom(g) = origin[n as usize].clone() else {
            continue;
        };
        let own_entries = desc_entries(g);
        if !own_entries.is_empty() {
            descriptors.push((n, own_entries.clone()));
        }
        let ts = targets_of(p, g, &mut seen);
        if let Some((name, defs)) = seen.atom_dup {
            dup_at.insert(n, (name.to_string(), defs));
        }
        let table_here = is_table(g, &mut table_memo);
        let mut is_main = false;
        let code = {
            let (_, m, a) = p.atom(g);
            m.sections[a.section as usize].role == Role::Code
        };
        for t in ts {
            let to = match t {
                T::Atom(tg) => {
                    if own_entries.contains(&tg) {
                        continue;
                    }
                    let drop_edge = table_here && descs.contains(&tg);
                    if code && is_ro(tg) && is_table(tg, &mut table_memo) {
                        is_main = true;
                    }
                    if node_of[tg as usize] == NONE {
                        let (_, _, ta) = p.atom(tg);
                        node_of[tg as usize] = node!(ta.content, Origin::Atom(tg), false);
                        queue.push(node_of[tg as usize]);
                    }
                    if drop_edge {
                        // Reachable only as a per-test root, never through the table.
                        continue;
                    }
                    node_of[tg as usize]
                }
                T::Leaf(name) => *leaves.entry(name).or_insert_with(|| {
                    node!(
                        leaf_hash("leaf", name),
                        Origin::Leaf(name.to_string()),
                        false
                    )
                }),
                T::Set(k, sym) => {
                    set_syms
                        .entry(k.clone())
                        .or_default()
                        .insert(sym.to_string());
                    *sets.entry(k.clone()).or_insert_with(|| {
                        let id = node!(leaf_hash("set", &k), Origin::Set(k.clone()), true);
                        pending_sets.push((id, k.clone()));
                        id
                    })
                }
            };
            adj[n as usize].push(to);
        }
        if table_here {
            content[n as usize] = leaf_hash("excluded", "test-table");
        } else if is_main {
            content[n as usize] = leaf_hash("excluded", "test-main");
        }
        // Set nodes expand after the atoms queued so far, still deterministic.
        while let Some((sid, k)) = pending_sets.pop() {
            let mut members = p.section_set(&k);
            members.sort_unstable();
            let mut first = 0;
            for &g in &members {
                if node_of[g as usize] == NONE {
                    let (_, _, ta) = p.atom(g);
                    node_of[g as usize] = node!(ta.content, Origin::Atom(g), false);
                    queue.push(node_of[g as usize]);
                    first += 1;
                }
                adj[sid as usize].push(node_of[g as usize]);
            }
            set_uses.push(SetUse {
                symbols: BTreeSet::new(),
                key: k,
                atoms: members.len(),
                first_reached: first,
            });
        }
    }
    // Every symbol that named a set, including references made after its expansion.
    for s in &mut set_uses {
        if let Some(x) = set_syms.get(&s.key) {
            s.symbols = x.clone();
        }
    }
    set_uses.sort_by(|a, b| a.key.cmp(&b.key));
    Discovered {
        graph: Graph::from_adj(content, adj, unordered),
        origin,
        node_of,
        imports: seen.imports,
        descriptors,
        sets: set_uses,
        by_order: seen.by_order,
        unestablished: seen.unestablished,
        dup_at,
    }
}

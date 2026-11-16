//! From link inputs to per-test reach keys.

use crate::entry::{self, DescriptorTable};
use crate::fallback::{Culprit, Fallback, Via};
use crate::graph::{key_of, merkle, root_key, tarjan};
use crate::link::{Origin, Program, discover};
use crate::load::{Loader, UnitKind};
use crate::model::*;
use crate::record::LinkInputs;
use crate::report::*;
use rayon::prelude::*;
use roaring::RoaringBitmap;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::Path;
use std::time::Instant;

#[derive(Default)]
pub struct Options {
    /// Crate name of the test binary (`_` for `-`).
    pub crate_name: String,
    /// nextest test names, `module::path::name`.
    pub tests: Vec<String>,
    /// Key a test by the hash of every component in its reach, as before roots were used
    /// (`graph::key_of`). Slower; for checking that the two keys tell the same builds apart.
    pub closure_key: bool,
    /// Refuse a record that does not match the disk (`LinkInputs::verify`): the output
    /// relinked since, a preserved object or archive changed. A record from a shim that
    /// predates the output hash is refused too, so this is off unless asked for.
    pub verify_record: bool,
}

/// Symbols the runtime reaches without a relocation from code: the unwinder
/// finds the personality routine through tables the linker consumes.
const RUNTIME_ROOTS: &[&str] = &[
    "rust_eh_personality",
    "_rust_eh_personality",
    "__rust_panic_cleanup",
];

/// The process's peak resident set so far, in MB (0 where it cannot be read).
fn peak_rss_mb() -> u64 {
    // SAFETY: getrusage fills the struct it is given and reads nothing.
    let mut u: libc::rusage = unsafe { std::mem::zeroed() };
    if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut u) } != 0 {
        return 0;
    }
    // Bytes on macOS, kilobytes elsewhere.
    let n = u.ru_maxrss as u64;
    if cfg!(target_os = "macos") { n >> 20 } else { n >> 10 }
}

/// Wall time per phase, in the order the phases ran.
struct Spans {
    last: Instant,
    out: Vec<Timing>,
}

impl Spans {
    fn new() -> Spans {
        let now = Instant::now();
        Spans {
            last: now,
            out: Vec::new(),
        }
    }

    fn lap(&mut self, span: &str) {
        let now = Instant::now();
        self.out.push(Timing {
            span: span.into(),
            ms: now.duration_since(self.last).as_millis() as u64,
            peak_rss_mb: peak_rss_mb(),
        });
        self.last = now;
    }
}

fn unverifiable(exe: &Path, why: String, opts: &Options, t0: Instant) -> BinaryReach {
    let tests = opts
        .tests
        .iter()
        .map(|t| {
            (
                t.clone(),
                TestReach::falling_back(
                    Fallback::Unverifiable { why: why.clone() },
                    Atoms::default(),
                ),
            )
        })
        .collect();
    BinaryReach {
        format: FORMAT,
        executable: exe.into(),
        verifiable: Err(why),
        harness_key: [0; 32],
        tests,
        unresolved_imports: vec![],
        stats: Stats {
            wall_ms: t0.elapsed().as_millis() as u64,
            ..Default::default()
        },
        harness_atoms: Atoms::default(),
        atom_table: AtomTable::default(),
        missing_tests: vec![],
        notes: vec![],
        unkeyed_inputs: vec![],
        section_sets: vec![],
        timings: vec![],
    }
}

/// Read a record and analyse it. Never fails: a record or input that cannot be
/// trusted yields a report whose `verifiable` is an error and whose tests all
/// carry a fallback, which is what callers need in order to use the executable key.
pub fn analyze_record(loader: &Loader, record: &Path, opts: &Options) -> BinaryReach {
    let t0 = Instant::now();
    match LinkInputs::from_record(record) {
        Ok(rec) => {
            if opts.verify_record
                && let Err(e) = rec.verify()
            {
                return unverifiable(&rec.output, e.to_string(), opts, t0);
            }
            analyze(loader, &rec, opts)
        }
        Err(e) => {
            let exe = record
                .to_string_lossy()
                .trim_end_matches(".keel-link.json")
                .to_string();
            unverifiable(Path::new(&exe), e.to_string(), opts, t0)
        }
    }
}

/// What a test starts from.
#[derive(Default)]
struct TestEntry {
    /// Function pointers of validated descriptors that name the test.
    fns: Vec<u32>,
    descs: Vec<u32>,
    /// Atoms whose symbol name spells the test path.
    guessed: Vec<u32>,
}

/// Which capability a note is about.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Cap {
    /// `dlopen`, `dlsym`, `libloading`: code that is not in the link.
    Load = 0,
    /// `current_exe`: the running executable.
    Exe = 1,
    /// `std::process::Command`.
    Spawn = 2,
}

impl Cap {
    const ALL: [Cap; 3] = [Cap::Load, Cap::Exe, Cap::Spawn];

    fn mask(self) -> u8 {
        match self {
            Cap::Load => F_DLOPEN,
            Cap::Exe => F_CURRENT_EXE,
            Cap::Spawn => F_COMMAND,
        }
    }
}

/// How a node's atom, or what it calls, bears on a capability rule. Computed once per
/// node so that judging a test is a minimum over its components, not a walk.
#[derive(Clone, Copy)]
struct Note {
    kind: NoteKind,
    /// `CallsAtom`: the callee's global atom index. `CallsLeaf`: its node.
    callee: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum NoteKind {
    None,
    Contains,
    CallsAtom,
    CallsLeaf,
}

const NO_NOTE: Note = Note {
    kind: NoteKind::None,
    callee: NONE,
};

pub fn analyze(loader: &Loader, rec: &LinkInputs, opts: &Options) -> BinaryReach {
    let t0 = Instant::now();
    let mut sp = Spans::new();
    let parsed_before = loader.parse_count();
    let cached_before = loader.cache_hits();
    let crate_name = opts.crate_name.replace('-', "_");
    let loaded = loader.load(rec, &crate_name);
    sp.lap("load: open, hash, parse or read cache");
    if let Some(p) = loaded.problem {
        return unverifiable(&rec.output, p, opts, t0);
    }
    let prog = Program::new(&loaded.units);
    sp.lap("symbol table");

    // Entries. The harness's own descriptor table is the authority; the symbol names
    // spelled by the test path are a cross-check that can only add roots.
    let wanted: HashSet<&str> = opts.tests.iter().map(String::as_str).collect();
    let table: DescriptorTable = entry::read_descriptors(&prog, &wanted);
    let mut guessed = entry::guess_by_name(&prog, &crate_name, &opts.tests);
    sp.lap("entries: descriptors and names");
    let mut entries: HashMap<&String, TestEntry> = HashMap::new();
    for t in &opts.tests {
        let mut e = TestEntry {
            guessed: guessed.remove(t).unwrap_or_default(),
            ..Default::default()
        };
        for b in table.bound.get(t).into_iter().flatten() {
            if !e.fns.contains(&b.func) {
                e.fns.push(b.func);
            }
            e.descs.push(b.desc);
        }
        if !e.fns.is_empty() || !e.guessed.is_empty() {
            entries.insert(t, e);
        }
    }
    let fn_set: HashSet<u32> = entries.values().flat_map(|e| e.fns.iter()).copied().collect();
    let bound_descs = table.descriptor_atoms();

    // Harness roots.
    let mut roots: Vec<u32> = Vec::new();
    let Some((main, _)) = prog.lookup("main").or_else(|| prog.lookup("_main")) else {
        return unverifiable(
            &rec.output,
            "no `main` or `_main` symbol in the inputs; this is not an executable's link line"
                .into(),
            opts,
            t0,
        );
    };
    roots.push(main);
    for n in RUNTIME_ROOTS {
        if let Some((g, _)) = prog.lookup(n).or_else(|| prog.lookup(&format!("_{n}"))) {
            roots.push(g);
        }
    }
    for (mi, _) in prog.mems.iter().enumerate() {
        roots.extend(prog.member(mi as u32).roots.iter().map(|a| prog.base[mi] + a));
    }
    let harness_roots = roots.clone();
    roots.extend(entries.values().flat_map(|e| e.fns.iter().chain(&e.guessed)));
    roots.extend(&bound_descs);

    let disc = discover(&prog, &roots, &bound_descs, &fn_set);
    // Relocations are not read again; let go of the pages they were read through.
    for u in prog.units {
        for m in &u.file.members {
            m.release_pages();
        }
    }
    sp.lap("discover: relocation graph from the roots");
    let cond = tarjan(&disc.graph);
    sp.lap("strongly connected components");
    let mk = merkle(&disc.graph, &cond);
    sp.lap("merkle hashes");

    let node_roots =
        |gs: &[u32]| -> Vec<u32> { gs.iter().map(|&g| disc.node_of[g as usize]).collect() };
    let mut h_seen = vec![false; cond.count()];
    let mut h_sccs = Vec::new();
    cond.close(
        &disc.graph,
        &node_roots(&harness_roots),
        &mut h_seen,
        &mut h_sccs,
    );
    let harness_key = key_of(h_sccs.iter().map(|&s| mk.scc_hash[s as usize]));

    // Per-node tables, computed once: the atom id of a node, its crate, and the verdict
    // of the capability rules. Atom ids follow the global atom order, so they do not
    // depend on test order.
    let nnodes = disc.graph.len();
    let mut atom_nodes: Vec<(u32, u32)> = disc
        .origin
        .iter()
        .enumerate()
        .filter_map(|(n, o)| match o {
            Origin::Atom(g) => Some((*g, n as u32)),
            _ => None,
        })
        .collect();
    atom_nodes.sort_unstable();
    let mut id_of_node = vec![NONE; nnodes];
    for (i, &(_, n)) in atom_nodes.iter().enumerate() {
        id_of_node[n as usize] = i as u32;
    }
    let mut crate_table: Vec<String> = Vec::new();
    let mut crate_ix: HashMap<String, u32> = HashMap::new();
    let mut crate_of_node = vec![NONE; nnodes];
    for &(g, n) in &atom_nodes {
        let (unit, m, a) = prog.atom(g);
        let code = m.sections[a.section as usize].role == Role::Code;
        let name = if code && a.crate_seg != NONE {
            &*m.crates[a.crate_seg as usize]
        } else if !code {
            unit.crate_name.as_str()
        } else {
            continue;
        };
        let ix = match crate_ix.get(name) {
            Some(&i) => i,
            None => {
                let i = crate_table.len() as u32;
                crate_table.push(name.to_string());
                crate_ix.insert(name.to_string(), i);
                i
            }
        };
        crate_of_node[n as usize] = ix;
    }
    let gatom_of = |n: u32| -> Option<u32> {
        match &disc.origin[n as usize] {
            Origin::Atom(g) => Some(*g),
            _ => None,
        }
    };
    let flags_of = |g: u32| prog.atom(g).2.flags;
    // Notes per node and capability, then the best (lowest atom index) per component.
    let mut notes_of: [Vec<Note>; 3] = std::array::from_fn(|_| vec![NO_NOTE; nnodes]);
    let mut hit = vec![0u8; nnodes];
    for n in 0..nnodes as u32 {
        let Some(g) = gatom_of(n) else { continue };
        let own = flags_of(g);
        let mut h = own;
        let mut nts: [Option<Note>; 3] = Cap::ALL.map(|c| {
            (own & c.mask() != 0).then_some(Note {
                kind: NoteKind::Contains,
                callee: NONE,
            })
        });
        for &t in disc.graph.succ(n) {
            match &disc.origin[t as usize] {
                Origin::Atom(tg) => {
                    let tf = flags_of(*tg);
                    h |= tf;
                    for c in Cap::ALL {
                        if tf & c.mask() != 0 && nts[c as usize].is_none() {
                            nts[c as usize] = Some(Note {
                                kind: NoteKind::CallsAtom,
                                callee: *tg,
                            });
                        }
                    }
                }
                Origin::Leaf(name) if name.contains("dlopen") => {
                    h |= F_DLOPEN;
                    nts[Cap::Load as usize].get_or_insert(Note {
                        kind: NoteKind::CallsLeaf,
                        callee: t,
                    });
                }
                _ => {}
            }
        }
        hit[n as usize] = h;
        for c in Cap::ALL {
            notes_of[c as usize][n as usize] = nts[c as usize].unwrap_or(NO_NOTE);
        }
    }
    sp.lap("per-node tables");
    let nscc = cond.count();
    let mut scc_note: [Vec<u32>; 3] = std::array::from_fn(|_| vec![NONE; nscc]);
    let mut scc_dup = vec![NONE; nscc];
    let mut scc_hit = vec![0u8; nscc];
    for s in 0..nscc as u32 {
        for &n in cond.members(s) {
            scc_hit[s as usize] |= hit[n as usize];
            for c in Cap::ALL {
                if notes_of[c as usize][n as usize].kind != NoteKind::None {
                    let cur = scc_note[c as usize][s as usize];
                    if cur == NONE || gatom_of(n) < gatom_of(cur) {
                        scc_note[c as usize][s as usize] = n;
                    }
                }
            }
            if disc.dup_at.contains_key(&n) {
                let cur = scc_dup[s as usize];
                if cur == NONE || gatom_of(n) < gatom_of(cur) {
                    scc_dup[s as usize] = n;
                }
            }
        }
    }
    // Atom ids and crates of a set of components.
    let atoms_of = |sccs: &[u32]| -> (Atoms, RoaringBitmap) {
        let mut ids: Vec<u32> = Vec::new();
        let mut crates = RoaringBitmap::new();
        for &s in sccs {
            for &n in cond.members(s) {
                let id = id_of_node[n as usize];
                if id != NONE {
                    ids.push(id);
                }
                if crate_of_node[n as usize] != NONE {
                    crates.insert(crate_of_node[n as usize]);
                }
            }
        }
        ids.sort_unstable();
        (
            Atoms(RoaringBitmap::from_sorted_iter(ids).expect("ids of distinct nodes are distinct")),
            crates,
        )
    };
    let (h_atoms, h_crates) = atoms_of(&h_sccs);
    sp.lap("per-component tables");

    let unit_label = |g: u32| -> String {
        let (u, m, _) = prog.atom(g);
        if u.file.is_archive {
            format!("{}!{}", u.path.display(), m.name)
        } else {
            u.path.display().to_string()
        }
    };
    // The first name of atom `g` whose own text carries a flag in `mask`.
    let flagged_name = |g: u32, mask: u8| -> Option<(String, bool)> {
        let (mem, ai) = prog.locate(g);
        let m = prog.member(mem);
        m.names_of(ai)
            .enumerate()
            .find(|&(_, n)| name_flags(&m.names[n as usize]) & mask != 0)
            .map(|(k, n)| (display_name(&m.names[n as usize]), k > 0))
    };
    let naming = |g: u32| -> String {
        let (mem, ai) = prog.locate(g);
        let m = prog.member(mem);
        m.names_of(ai)
            .next()
            .map_or_else(|| "<unnamed>".to_string(), |n| display_name(&m.names[n as usize]))
    };
    let culprit_of = |n: u32, nt: Note, mask: u8| -> Option<Culprit> {
        let g = gatom_of(n)?;
        match nt.kind {
            NoteKind::None => None,
            NoteKind::Contains => {
                let (callee, alias) = flagged_name(g, mask)?;
                Some(Culprit {
                    via: Via::Contains,
                    alias_of: alias.then(|| naming(g)),
                    callee,
                    caller: None,
                    object: unit_label(g),
                })
            }
            NoteKind::CallsAtom => {
                let (callee, alias) = flagged_name(nt.callee, mask)?;
                Some(Culprit {
                    via: Via::Calls,
                    alias_of: alias.then(|| naming(nt.callee)),
                    callee,
                    caller: Some(naming(g)),
                    object: unit_label(g),
                })
            }
            NoteKind::CallsLeaf => {
                let Origin::Leaf(name) = &disc.origin[nt.callee as usize] else {
                    return None;
                };
                Some(Culprit {
                    via: Via::Calls,
                    alias_of: None,
                    callee: name.clone(),
                    caller: Some(naming(g)),
                    object: unit_label(g),
                })
            }
        }
    };
    let best_of = |sccs: &[u32], arr: &[u32]| -> Option<u32> {
        sccs.iter()
            .map(|&s| arr[s as usize])
            .filter(|&n| n != NONE)
            .min_by_key(|&n| gatom_of(n))
    };
    let dup_fallback = |n: u32| -> Option<Fallback> {
        let (symbol, definitions) = disc.dup_at.get(&n)?;
        let g = gatom_of(n)?;
        Some(Fallback::DuplicateDefinition {
            symbol: display_name(symbol),
            definitions: *definitions,
            why: "which copy the linker used cannot be established from the link record (equal-strength definitions in archives, or in objects with no known place on the link line)".into(),
            caller: Some(naming(g)),
            object: unit_label(g),
        })
    };
    // A duplicate in the harness's reach is in every test's.
    let harness_dup = best_of(&h_sccs, &scc_dup).and_then(dup_fallback);

    struct PerTest {
        atoms: Atoms,
        crates: RoaringBitmap,
        key: [u8; 32],
        fallback: Option<Fallback>,
        spawns: Option<Culprit>,
        spawns_processes: bool,
        entry: EntrySource,
        disagreement: Vec<u32>,
    }
    let per_test: Vec<(&String, Option<PerTest>)> = opts
        .tests
        .par_iter()
        .map(|t| {
            let Some(e) = entries.get(t) else {
                return (t, None);
            };
            let mut seen = h_seen.clone();
            let mut sccs = Vec::new();
            let entry_roots = if e.fns.is_empty() {
                node_roots(&e.guessed)
            } else {
                node_roots(&e.fns)
            };
            let desc_roots = node_roots(&e.descs);
            let mut roots = entry_roots.clone();
            roots.extend(&desc_roots);
            cond.close(&disc.graph, &roots, &mut seen, &mut sccs);
            let mut entry = if e.fns.is_empty() {
                EntrySource::Name
            } else {
                EntrySource::Descriptor
            };
            // The cross-check: whatever the guessed names found must be in the reach of
            // the descriptor's function. If not, they are roots too (a wider reach never
            // misses a dependency) and the disagreement is reported.
            let mut disagreement = Vec::new();
            let mut extra_roots = Vec::new();
            if !e.fns.is_empty() {
                let extra: Vec<u32> = e
                    .guessed
                    .iter()
                    .copied()
                    .filter(|&g| {
                        let n = disc.node_of[g as usize];
                        n == NONE || !seen[cond.scc_of[n as usize] as usize]
                    })
                    .collect();
                if !extra.is_empty() {
                    entry = EntrySource::DescriptorAndName;
                    extra_roots = node_roots(&extra);
                    cond.close(&disc.graph, &extra_roots, &mut seen, &mut sccs);
                    disagreement = extra;
                }
            }
            let key = if opts.closure_key {
                key_of(h_sccs.iter().chain(&sccs).map(|&s| mk.scc_hash[s as usize]))
            } else {
                // Each root's hash commits to everything it reaches, so the harness and the
                // roots stand for the whole reach.
                let hs = |ns: &[u32]| ns.iter().map(|&n| mk.node_hash(&cond, n)).collect::<Vec<_>>();
                root_key(
                    &harness_key,
                    &[
                        ("entries", hs(&entry_roots)),
                        ("descriptors", hs(&desc_roots)),
                        ("extra-roots", hs(&extra_roots)),
                    ],
                )
            };
            let (atoms, crates) = atoms_of(&sccs);
            let hit_all = sccs.iter().fold(0u8, |a, &s| a | scc_hit[s as usize]);
            // Order of precedence: running code outside the executable, a definition the
            // linker may have taken from elsewhere, then the executable itself.
            let load = best_of(&sccs, &scc_note[Cap::Load as usize]).and_then(|n| {
                culprit_of(n, notes_of[Cap::Load as usize][n as usize], F_DLOPEN)
                    .map(Fallback::LoadsLibrary)
            });
            let dup = harness_dup
                .clone()
                .or_else(|| best_of(&sccs, &scc_dup).and_then(dup_fallback));
            let exe = best_of(&sccs, &scc_note[Cap::Exe as usize]).and_then(|n| {
                culprit_of(n, notes_of[Cap::Exe as usize][n as usize], F_CURRENT_EXE)
                    .map(Fallback::CurrentExe)
            });
            let fallback = load.or(dup).or(exe);
            let spawns = best_of(&sccs, &scc_note[Cap::Spawn as usize])
                .and_then(|n| culprit_of(n, notes_of[Cap::Spawn as usize][n as usize], F_COMMAND));
            (
                t,
                Some(PerTest {
                    atoms,
                    crates,
                    key,
                    fallback,
                    spawns,
                    spawns_processes: hit_all & F_COMMAND != 0,
                    entry,
                    disagreement,
                }),
            )
        })
        .collect();
    sp.lap("per-test closures, keys and fallbacks");

    let mut builder = AtomTableBuilder::with_capacity(atom_nodes.len());
    let unit_paths: Vec<String> = prog
        .units
        .iter()
        .map(|u| u.path.display().to_string())
        .collect();
    let mut last_mem = u32::MAX;
    for &(g, n) in &atom_nodes {
        let (mem, ai) = prog.locate(g);
        if mem != last_mem {
            // Atoms are in global order, so a member's rows are contiguous.
            if last_mem != u32::MAX {
                prog.member(last_mem).release_pages();
            }
            last_mem = mem;
        }
        let r = prog.mems[mem as usize];
        let (u, m, a) = (
            &prog.units[r.unit as usize],
            prog.member(mem),
            &prog.member(mem).atoms[ai as usize],
        );
        let aliases: Vec<&str> = m
            .aliases_of(ai)
            .iter()
            .map(|x| &m.names[x.name as usize])
            .collect();
        let sh = &mk.scc_hash[cond.scc_of[n as usize] as usize];
        builder.push(Row {
            archive: &unit_paths[r.unit as usize],
            member: &m.name,
            section: a.section,
            offset: a.offset,
            symbol: if a.symbol == NONE {
                ""
            } else {
                &m.names[a.symbol as usize]
            },
            crate_name: &u.crate_name,
            own_object: u.kind == UnitKind::TestObject,
            hash: u64::from_be_bytes(sh[..8].try_into().unwrap()),
            content: u64::from_be_bytes(a.content[..8].try_into().unwrap()),
            class: AtomClass::of(m.sections[a.section as usize].role, m.sections[a.section as usize].class) as u8,
            size: a.size,
            bytes_hash: u64::from_be_bytes(a.bytes_hash[..8].try_into().unwrap()),
            reloc_hash: u64::from_be_bytes(a.reloc_hash[..8].try_into().unwrap()),
            aliases: &aliases,
        });
    }
    let atom_table = builder.finish();
    sp.lap("atom table");

    let names_of_crates = |b: &RoaringBitmap| -> BTreeSet<String> {
        b.iter().map(|i| crate_table[i as usize].clone()).collect()
    };
    let mut tests = BTreeMap::new();
    let mut missing = Vec::new();
    let mut notes = loaded.notes;
    let (mut from_desc, mut from_name) = (0, 0);
    let mut disagree: Vec<String> = Vec::new();
    for (t, r) in per_test {
        let tr = match r {
            None => {
                missing.push(t.clone());
                let detail = if table.candidates == 0 {
                    "no test descriptor table was found in the test crate's objects".to_string()
                } else if table.bound.is_empty() {
                    format!(
                        "{} descriptors were read and none names a test of this list",
                        table.shaped
                    )
                } else {
                    format!(
                        "{} descriptors were read, {} bound to tests, none names this one",
                        table.shaped,
                        table.bound.len()
                    )
                };
                TestReach::falling_back(
                    Fallback::NoEntry {
                        test: t.clone(),
                        looked_for: vec![
                            format!("{crate_name}::{t}"),
                            format!("{crate_name}::{t}::{{{{closure}}}}"),
                        ],
                        detail,
                    },
                    Atoms::default(),
                )
            }
            Some(p) => {
                match p.entry {
                    EntrySource::Name => from_name += 1,
                    _ => from_desc += 1,
                }
                if !p.disagreement.is_empty() {
                    disagree.push(t.clone());
                }
                let mut crates = names_of_crates(&h_crates);
                crates.extend(names_of_crates(&p.crates));
                let mut tr = match p.fallback {
                    Some(reason) => TestReach::falling_back(reason, p.atoms),
                    None => TestReach::keyed(p.key, p.atoms),
                };
                tr.spawns_processes = p.spawns_processes;
                tr.spawns = p.spawns;
                tr.entry = p.entry;
                tr.crates = crates;
                tr
            }
        };
        tests.insert(t.clone(), tr);
    }
    if !disagree.is_empty() {
        notes.push(format!(
            "{} tests have a symbol named by their path that their descriptor's function does not reach; it is a root too (first: {})",
            disagree.len(),
            disagree.iter().take(3).cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    if table.ambiguous > 0 {
        notes.push(format!(
            "{} descriptors name two tests of the list and were not used as entries",
            table.ambiguous
        ));
    }
    if !disc.unestablished.is_empty() {
        notes.push(format!(
            "{} symbols are defined with different content by inputs whose link order cannot be established; tests that reach them fall back (first: {})",
            disc.unestablished.len(),
            disc.unestablished.keys().take(3).cloned().collect::<Vec<_>>().join(", ")
        ));
    }
    let whole = prog
        .mems
        .iter()
        .filter(|r| {
            // `lib.rmeta` members are Mach-O wrappers around metadata, with no flag and no atoms.
            let m = &prog.units[r.unit as usize].file.members[r.member as usize];
            m.whole_sections && !m.atoms.is_empty()
        })
        .count();
    if whole > 0 {
        notes.push(format!(
            "{whole} Mach-O objects lack MH_SUBSECTIONS_VIA_SYMBOLS and are analysed as one atom per section"
        ));
    }
    sp.lap("assemble report");
    let atoms_total: usize = prog.total_atoms() as usize;
    let reached = atom_nodes.len();
    BinaryReach {
        format: FORMAT,
        executable: rec.output.clone(),
        verifiable: Ok(()),
        harness_key,
        tests,
        unresolved_imports: disc.imports.iter().cloned().collect(),
        stats: Stats {
            objects: prog.objects,
            archives: prog.archives,
            atoms: atoms_total,
            relocations: prog.relocations,
            sccs: cond.count(),
            wall_ms: t0.elapsed().as_millis() as u64,
            reached_atoms: reached,
            members_parsed: loader.parse_count() - parsed_before,
            members_from_cache: loader.cache_hits() - cached_before,
            entries_from_descriptors: from_desc,
            entries_from_names: from_name,
            ambiguous_definitions: disc.by_order.len() + disc.unestablished.len(),
            unestablished_definitions: disc.unestablished.len(),
            whole_section_members: whole,
        },
        harness_atoms: h_atoms,
        atom_table,
        missing_tests: missing,
        notes,
        unkeyed_inputs: loaded.unkeyed,
        section_sets: disc
            .sets
            .iter()
            .map(|s| SectionSetUse {
                section: s.key.clone(),
                symbols: s.symbols.iter().cloned().collect(),
                atoms: s.atoms,
                first_reached_by_section: s.first_reached,
            })
            .collect(),
        timings: sp.out,
    }
}

/// The test path an entry symbol stands for: the function itself
/// (`c::m::t`), or the closure the harness calls through, in either mangling
/// (`c::m::t::{{closure}}` legacy, `c::m::t::{closure#0}` v0), possibly as the
/// self type of a call shim (`<c::m::t::{closure#0} as FnOnce<()>>::call_once`).
pub fn entry_path(demangled: &str) -> Option<&str> {
    let s = demangled.strip_prefix('<').unwrap_or(demangled);
    match s.find("::{") {
        Some(i) if s[i..].starts_with("::{{closure}}") || s[i..].starts_with("::{closure#") => {
            Some(&s[..i])
        }
        Some(_) => None,
        None if demangled.starts_with('<') => None,
        None => Some(s),
    }
}

#[cfg(test)]
mod tests {
    use super::entry_path;

    #[test]
    fn entry_paths() {
        assert_eq!(entry_path("c000::tests::a"), Some("c000::tests::a"));
        assert_eq!(
            entry_path("c000::tests::a::{{closure}}"),
            Some("c000::tests::a")
        );
        assert_eq!(
            entry_path("c000::tests::a::{closure#0}"),
            Some("c000::tests::a")
        );
        assert_eq!(
            entry_path(
                "<c000::tests::a::{closure#0} as core::ops::function::FnOnce<()>>::call_once"
            ),
            Some("c000::tests::a")
        );
        assert_eq!(entry_path("c000::tests::a::{impl#0}::f"), None);
        assert_eq!(entry_path("<c000::T as core::fmt::Debug>::fmt"), None);
    }
}

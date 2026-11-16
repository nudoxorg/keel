//! Where each test starts.
//!
//! libtest links a static array of test descriptors. Each one holds the test's name (a
//! `&'static str`: a pointer and a length) and the test function (a function pointer,
//! `StaticTestFn`). In the object files both are relocations out of one read-only data
//! atom, and the length is the 8 bytes after the name's pointer. That table is what the
//! harness runs, so it is the authority for what a test's entry is; a symbol name
//! guessed from the test path is only a cross-check (it misses tests whose function
//! lives at a path the test name does not spell, and whose closure was merged with
//! another).
//!
//! The layout is not part of any stable interface, so nothing here is assumed beyond
//! what is checked on each descriptor: exactly one relocation to code (the function
//! pointer), and a `(pointer, length)` pair, whose length field carries no relocation and
//! whose bytes read back as UTF-8 equal to a name in the list. A descriptor for which
//! that does not hold is not used, and the reason is counted.

use crate::link::Program;
use crate::load::UnitKind;
use crate::model::*;
use std::collections::{BTreeMap, HashMap, HashSet};

/// A descriptor that names a wanted test.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Bound {
    /// The descriptor's atom.
    pub desc: u32,
    /// The atom its function pointer points at (the closure the harness calls).
    pub func: u32,
}

#[derive(Debug, Default)]
pub struct DescriptorTable {
    pub bound: BTreeMap<String, Vec<Bound>>,
    /// Read-only atoms of the test objects with a relocation to code.
    pub candidates: usize,
    /// Of those, ones with exactly one code relocation (the shape of a descriptor).
    pub shaped: usize,
    /// Shaped atoms that name no wanted test (ignored by this run, benches, or a layout
    /// this reader does not understand), and ones that name two.
    pub unbound: usize,
    pub ambiguous: usize,
}

impl DescriptorTable {
    /// Every descriptor atom that was bound to some test.
    pub fn descriptor_atoms(&self) -> HashSet<u32> {
        self.bound.values().flatten().map(|b| b.desc).collect()
    }
}

fn u64_at(b: &[u8], off: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(off..off + 8)?.try_into().ok()?))
}

/// The string a `(pointer, length)` pair at `field` of descriptor `desc` stands for,
/// where `target` is the atom the pointer's relocation names.
fn read_str<'a>(
    prog: &'a Program,
    desc: u32,
    reloc_offset: u32,
    target: u32,
    addend: i64,
) -> Option<&'a str> {
    let (du, dm, da) = prog.atom(desc);
    let atom_bytes = |g: u32| -> Option<&'a [u8]> {
        let (mem, ai) = prog.locate(g);
        let r = prog.mems[mem as usize];
        let unit = &prog.units[r.unit as usize];
        unit.file.atom_bytes(r.member as usize, &unit.file.members[r.member as usize].atoms[ai as usize])
    };
    // The length field must be plain data: a relocation there would make this no `&str`.
    let len_at = reloc_offset.checked_add(8)?;
    if dm.atom_relocs(da).iter().any(|r| r.offset == len_at) {
        return None;
    }
    let _ = du;
    let len = usize::try_from(u64_at(atom_bytes(desc)?, len_at as usize)?).ok()?;
    let bytes = atom_bytes(target)?;
    let start = usize::try_from(addend).ok()?;
    std::str::from_utf8(bytes.get(start..start.checked_add(len)?)?).ok()
}

/// Read the descriptors of the test crate's own objects and bind those that name a test
/// in `wanted`.
pub fn read_descriptors(prog: &Program, wanted: &HashSet<&str>) -> DescriptorTable {
    let units = prog.units;
    let mut t = DescriptorTable::default();
    for (mi, r) in prog.mems.iter().enumerate() {
        if units[r.unit as usize].kind != UnitKind::TestObject {
            continue;
        }
        let m = prog.member(mi as u32);
        for (ai, a) in m.atoms.iter().enumerate() {
            if m.sections[a.section as usize].role != Role::RoData {
                continue;
            }
            let desc = prog.base[mi] + ai as u32;
            let targets: Vec<(&Reloc, Option<u32>)> = m
                .atom_relocs(a)
                .iter()
                .map(|r| (r, prog.reloc_atom(mi as u32, r)))
                .collect();
            let is_code = |g: u32| {
                let (_, tm, ta) = prog.atom(g);
                tm.sections[ta.section as usize].role == Role::Code
            };
            let code: Vec<u32> = targets
                .iter()
                .filter_map(|(_, g)| g.filter(|&g| is_code(g)))
                .collect();
            if code.is_empty() {
                continue;
            }
            t.candidates += 1;
            if code.len() != 1 {
                continue;
            }
            t.shaped += 1;
            let mut names: Vec<&str> = Vec::new();
            for (r, g) in &targets {
                let Some(g) = g.filter(|&g| !is_code(g)) else {
                    continue;
                };
                if let Some(s) = read_str(prog, desc, r.offset, g, r.addend)
                    && wanted.contains(s)
                    && !names.contains(&s)
                {
                    names.push(s);
                }
            }
            match names.as_slice() {
                [] => t.unbound += 1,
                [name] => t.bound.entry(name.to_string()).or_default().push(Bound {
                    desc,
                    func: code[0],
                }),
                _ => t.ambiguous += 1,
            }
        }
    }
    t
}

/// The atoms whose symbol (any of its names) is the test's function or the closure the
/// harness calls it through: the old way of finding entries, now the cross-check.
pub fn guess_by_name(
    prog: &Program,
    crate_name: &str,
    tests: &[String],
) -> HashMap<String, Vec<u32>> {
    let units = prog.units;
    let wanted: HashMap<String, &String> = tests
        .iter()
        .map(|t| (format!("{crate_name}::{t}"), t))
        .collect();
    let mut out: HashMap<String, Vec<u32>> = HashMap::new();
    for (mi, r) in prog.mems.iter().enumerate() {
        if units[r.unit as usize].kind != UnitKind::TestObject {
            continue;
        }
        let m = prog.member(mi as u32);
        for (ai, a) in m.atoms.iter().enumerate() {
            if m.sections[a.section as usize].role != Role::Code {
                continue;
            }
            for n in m.names_of(ai as u32) {
                let Some((text, _)) = symbol_facts(&m.names[n as usize]) else {
                    continue;
                };
                if let Some(t) = crate::reach::entry_path(&text).and_then(|p| wanted.get(p)) {
                    let v = out.entry((*t).clone()).or_default();
                    let g = prog.base[mi] + ai as u32;
                    if !v.contains(&g) {
                        v.push(g);
                    }
                }
            }
        }
    }
    out
}

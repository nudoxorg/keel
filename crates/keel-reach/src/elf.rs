//! ELF objects to atoms: one atom per allocated section, which is how rustc
//! lays out functions and data items (`-Z function-sections` is the default).
//!
//! Written against `object`'s portable API and exercised on hand-built ELF
//! objects; the acceptance run covers it with zig-linked x86_64 binaries.

use crate::model::*;
use object::{
    Architecture, Object, ObjectSection, ObjectSymbol, RelocationFlags, RelocationKind,
    RelocationTarget, SectionFlags, SectionKind, SymbolKind, SymbolSection,
};
use std::collections::HashMap;

const SHF_ALLOC: u64 = 0x2;
const SHF_EXECINSTR: u64 = 0x4;
const SHF_TLS: u64 = 0x400;
const SHF_MERGE: u64 = 0x10;
const SHF_STRINGS: u64 = 0x20;

/// The class of a section and where its atoms start. The linker splits and merges the pieces
/// of `SHF_MERGE` sections (C strings, `.rodata.cstN` constants) itself, so each piece is an
/// atom, as on Mach-O. The piece size is not in the generic section API, so it is read from
/// the name LLVM gives these sections: `.rodata.str<width>.<align>` and `.rodata.cst<size>`.
/// Wide strings and merge sections named otherwise are left whole.
fn pieces(name: &str, sh_flags: u64, bytes: &[u8], size: u64) -> (SecClass, Vec<u64>) {
    let whole = vec![0];
    if name.starts_with(".gcc_except_table") {
        return (SecClass::Lsda, whole);
    }
    if sh_flags & SHF_MERGE == 0 {
        return (SecClass::Plain, whole);
    }
    let digits = |after: &str| -> Option<u64> {
        let rest = name.split(after).nth(1)?;
        rest.chars().take_while(char::is_ascii_digit).collect::<String>().parse().ok()
    };
    if sh_flags & SHF_STRINGS != 0 {
        if digits(".str") != Some(1) {
            return (SecClass::Plain, whole);
        }
        let mut starts = vec![0];
        starts.extend(
            bytes
                .iter()
                .enumerate()
                .filter(|&(i, &b)| b == 0 && (i as u64) + 1 < size)
                .map(|(i, _)| i as u64 + 1),
        );
        return (SecClass::CString, starts);
    }
    match digits(".cst") {
        Some(w) if w > 0 && size.is_multiple_of(w) => {
            (SecClass::Literal, (0..size).step_by(w as usize).collect())
        }
        _ => (SecClass::Plain, whole),
    }
}

enum Sym {
    Skip,
    Defined { sec: usize, value: u64 },
    Undef(u32),
    Abs(u64),
    Bad(&'static str),
}

fn skipped(name: &str) -> bool {
    [
        ".eh_frame",
        ".note",
        ".debug",
        ".llvm",
        ".stack_sizes",
        ".comment",
    ]
    .iter()
    .any(|p| name.starts_with(p))
}

fn role(name: &str, sh_flags: u64, nobits: bool) -> Role {
    if [
        ".init_array",
        ".ctors",
        ".preinit_array",
        ".fini_array",
        ".dtors",
    ]
    .iter()
    .any(|p| name.starts_with(p))
    {
        Role::Init
    } else if sh_flags & SHF_TLS != 0 {
        Role::Tls
    } else if nobits {
        Role::Bss
    } else if sh_flags & SHF_EXECINSTR != 0 {
        Role::Code
    } else if name.starts_with(".rodata") || name.starts_with(".data.rel.ro") {
        Role::RoData
    } else {
        Role::Data
    }
}

/// Relocation types `object` leaves as `Unknown` but that are ordinary
/// symbol-plus-addend relocations (thread-local storage models).
fn tls_ok(arch: Architecture, r_type: u32) -> bool {
    match arch {
        Architecture::X86_64 => matches!(r_type, 17..=23 | 34 | 35),
        Architecture::Aarch64 => (0x200..=0x23f).contains(&r_type),
        _ => false,
    }
}

pub fn parse<'d, O: Object<'d>>(file: &O, m: &mut MemberBuild) -> Result<(), String> {
    let arch = file.architecture();
    let le = file.is_little_endian();
    let mut names = Interner::default();
    let mut secs: Vec<SecBuild> = Vec::new();
    let mut ours: HashMap<usize, usize> = HashMap::new();
    let mut kept = Vec::new();
    for s in file.sections() {
        let name = s.name().map_err(|e| format!("ELF section name: {e}"))?;
        let SectionFlags::Elf { sh_flags } = s.flags() else {
            continue;
        };
        if sh_flags & SHF_ALLOC == 0 || skipped(name) || s.size() == 0 {
            continue;
        }
        let nobits = matches!(
            s.kind(),
            SectionKind::UninitializedData | SectionKind::UninitializedTls
        );
        let (file_off, bytes) = if nobits {
            (None, Vec::new())
        } else {
            let (o, _) = s
                .file_range()
                .ok_or_else(|| format!("ELF section {name} has no file range"))?;
            (
                Some(o),
                s.data()
                    .map_err(|e| format!("ELF section {name}: {e}"))?
                    .to_vec(),
            )
        };
        ours.insert(s.index().0, secs.len());
        kept.push(s.index());
        let (class, starts) = pieces(name, sh_flags, &bytes, s.size());
        secs.push(SecBuild {
            info: SectionInfo {
                key: name.into(),
                role: role(name, sh_flags, nobits),
                class,
            },
            size: s.size(),
            align: 0,
            file_off,
            bytes,
            starts,
            relocs: Vec::new(),
            syms: Vec::new(),
        });
    }

    let mut syms: Vec<Sym> = Vec::new();
    let mut defs: Vec<(u32, u32, u64, bool)> = Vec::new();
    for sym in file.symbols() {
        let ix = sym.index().0;
        if syms.len() <= ix {
            syms.resize_with(ix + 1, || Sym::Skip);
        }
        if matches!(sym.kind(), SymbolKind::File) {
            continue;
        }
        syms[ix] = match sym.section() {
            SymbolSection::Section(i) => match ours.get(&i.0) {
                Some(&si) => {
                    if !matches!(sym.kind(), SymbolKind::Section) {
                        let n = names.intern_lossy(
                            sym.name_bytes()
                                .map_err(|e| format!("ELF symbol name: {e}"))?,
                        );
                        secs[si].syms.push((sym.address(), n, !sym.is_local()));
                        if !sym.is_local() {
                            defs.push((n, si as u32, sym.address(), sym.is_weak()));
                        }
                    }
                    Sym::Defined {
                        sec: si,
                        value: sym.address(),
                    }
                }
                None => Sym::Skip,
            },
            SymbolSection::Undefined => Sym::Undef(
                names.intern_lossy(
                    sym.name_bytes()
                        .map_err(|e| format!("ELF symbol name: {e}"))?,
                ),
            ),
            SymbolSection::Absolute => Sym::Abs(sym.address()),
            SymbolSection::Common => Sym::Bad("common symbol"),
            _ => Sym::Skip,
        };
    }

    // On x86 a pc-relative field's addend carries an adjustment for the field's own size and
    // for any immediate after it, so an offset into a split section cannot be read from it.
    // A split section that is the target of one stays whole.
    if matches!(arch, Architecture::X86_64 | Architecture::I386) {
        for id in &kept {
            let sec = file.section_by_index(*id).map_err(|e| e.to_string())?;
            for (_, r) in sec.relocations() {
                if !matches!(
                    r.kind(),
                    RelocationKind::Relative | RelocationKind::GotRelative | RelocationKind::PltRelative
                ) {
                    continue;
                }
                let target = match r.target() {
                    RelocationTarget::Symbol(i) => match syms.get(i.0) {
                        Some(Sym::Defined { sec, .. }) => Some(*sec),
                        _ => None,
                    },
                    RelocationTarget::Section(i) => ours.get(&i.0).copied(),
                    _ => None,
                };
                if let Some(t) = target {
                    secs[t].starts = vec![0];
                }
            }
        }
    }
    let mut base = Vec::with_capacity(secs.len());
    let mut n = 0u32;
    for s in &secs {
        base.push(n);
        n += s.starts.len() as u32;
    }
    // The atom of section `sec` that holds `offset`, and the offset within it.
    let atom_at = |secs: &[SecBuild], sec: usize, offset: i64| -> (u32, i64) {
        let s = &secs[sec];
        if s.starts.len() == 1 || offset < 0 || offset as u64 >= s.size {
            return (base[sec], offset.max(0));
        }
        let k = s.starts.partition_point(|&x| x <= offset as u64) - 1;
        (base[sec] + k as u32, offset - s.starts[k] as i64)
    };

    for (si, id) in kept.iter().enumerate() {
        let sec = file.section_by_index(*id).map_err(|e| e.to_string())?;
        let here = secs[si].info.key.clone();
        for (off, r) in sec.relocations() {
            let RelocationFlags::Elf { r_type } = r.flags() else {
                return Err(format!("relocation in {here} is not an ELF relocation"));
            };
            if r.kind() == RelocationKind::Unknown && !tls_ok(arch, r_type) {
                return Err(format!(
                    "unknown ELF relocation type {r_type} at {off:#x} in {here}"
                ));
            }
            let bits = u32::from(r.size());
            let len = bits.div_ceil(8) as usize;
            let mut addend = r.addend();
            if r.has_implicit_addend() {
                let b = secs[si]
                    .bytes
                    .get(off as usize..off as usize + len)
                    .ok_or_else(|| format!("relocation at {off:#x} lies outside {here}"))?;
                if !le || !matches!(len, 4 | 8) {
                    return Err(format!(
                        "implicit-addend relocation of {bits} bits in {here} is not supported"
                    ));
                }
                addend = if len == 4 {
                    i64::from(i32::from_le_bytes(b.try_into().unwrap()))
                } else {
                    i64::from_le_bytes(b.try_into().unwrap())
                };
            }
            let target = match r.target() {
                RelocationTarget::Symbol(i) => match syms.get(i.0) {
                    Some(Sym::Defined { sec, value }) => {
                        // A split section is entered by symbol plus offset: resolve the sum.
                        let (a, off) = atom_at(&secs, *sec, *value as i64 + addend);
                        addend = if secs[*sec].starts.len() > 1 { off } else { addend + *value as i64 };
                        RTarget::Atom(a)
                    }
                    Some(Sym::Undef(n)) => RTarget::Undef(*n),
                    Some(Sym::Abs(v)) => {
                        addend += *v as i64;
                        RTarget::Abs
                    }
                    Some(Sym::Bad(why)) => {
                        return Err(format!("relocation in {here} targets a {why}"));
                    }
                    _ => {
                        return Err(format!(
                            "relocation in {here} targets a symbol in a section that is not modelled (debug or unwind data)"
                        ));
                    }
                },
                RelocationTarget::Section(i) => match ours.get(&i.0) {
                    Some(&t) => {
                        let (a, off) = atom_at(&secs, t, addend);
                        if secs[t].starts.len() > 1 {
                            addend = off;
                        }
                        RTarget::Atom(a)
                    }
                    None => {
                        return Err(format!(
                            "relocation in {here} targets a section that is not modelled"
                        ));
                    }
                },
                RelocationTarget::Absolute => RTarget::Abs,
                _ => return Err(format!("relocation in {here} has an unsupported target")),
            };
            let mut r_type = r_type;
            // The same partition-dependence as on Mach-O: a local symbol is reached with `lea` /
            // `adrp`+`add`, an external one through the GOT, and both compute its address.
            if let (true, Some(bs)) = (matches!(arch, Architecture::X86_64 | Architecture::Aarch64), secs[si].bytes.get_mut(..)) {
                let at = off as usize;
                match (arch, r_type) {
                    (Architecture::X86_64, 9 | 41 | 42) if at >= 2 && at + 4 <= bs.len() && bs[at - 2] == 0x8b => {
                        bs[at - 2] = 0x8d;
                        r_type = 2;
                    }
                    (Architecture::Aarch64, 311) => r_type = 275,
                    (Architecture::Aarch64, 277 | 312) if at + 4 <= bs.len() => {
                        let w = u32::from_le_bytes(bs[at..at + 4].try_into().unwrap());
                        let add_x = r_type == 277 && w & 0xffc0_0000 == 0x9100_0000;
                        let ldr_x = r_type == 312 && w & 0xffc0_0000 == 0xf940_0000;
                        if add_x || ldr_x {
                            bs[at..at + 4].copy_from_slice(&(w & 0x3ff).to_le_bytes());
                            r_type = ADDR_PAGEOFF;
                        } else if r_type == 312 {
                            return Err(format!("GOT-relative low-12 relocation on something other than a 64-bit ldr in {here}"));
                        }
                    }
                    _ => {}
                }
            }
            // RELA objects hold zero in the patched field already; zeroing whole-byte fields
            // also covers producers that store the addend in place.
            if let (true, Some(b)) = (
                matches!(bits, 8 | 16 | 32 | 64),
                secs[si].bytes.get_mut(off as usize..off as usize + len),
            ) {
                b.fill(0);
            }
            secs[si]
                .relocs
                .push(Reloc::new(off as u32, r_type, len as u8, addend, target));
        }
    }
    // Atoms of a section follow one another; `base` maps sections to their first atom.
    m.names = names.items;
    assemble(m, secs, &defs);
    Ok(())
}

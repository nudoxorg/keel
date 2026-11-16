//! Mach-O (arm64, x86_64) objects to atoms.
//!
//! `object`'s generic relocation iterator reports every arm64 branch and page
//! relocation as `Unknown` and silently skips scattered ones, so this reads the
//! raw entries and keeps its own whitelist: anything not listed makes the
//! member a `problem`, never a guess.

use crate::model::*;
use object::macho;
use object::read::macho::{MachHeader, MachOFile64, Nlist, Section as _};
use object::{Endianness, Object, ReadRef};

#[derive(Clone, Copy, PartialEq)]
enum Arch {
    A64,
    X64,
}

enum Sym {
    Skip,
    Defined { sec: usize, addr: u64 },
    Undef(u32),
    Abs(u64),
    Bad(&'static str),
}

const S_ZEROFILL: u32 = 0x1;
const S_GB_ZEROFILL: u32 = 0xc;
const S_THREAD_LOCAL_ZEROFILL: u32 = 0x12;
const S_MOD_INIT_FUNC_POINTERS: u32 = 0x9;
const S_MOD_TERM_FUNC_POINTERS: u32 = 0xa;
const S_INIT_FUNC_OFFSETS: u32 = 0x16;
const S_ATTR_DEBUG: u32 = 0x0200_0000;
const S_ATTR_CODE: u32 = 0x8000_0400;
const N_ALT_ENTRY: u16 = 0x0200;
const N_WEAK_DEF: u16 = 0x0080;

fn tls_type(t: u32) -> bool {
    (0x11..=0x15).contains(&t)
}

/// Sections whose content is never the target of a relocation from code or
/// data: debug info, unwind tables the linker consumes, embedded bitcode.
fn skipped(seg: &[u8], sect: &[u8], flags: u32) -> bool {
    seg == b"__DWARF"
        || seg == b"__LLVM"
        || flags & S_ATTR_DEBUG != 0
        || matches!(sect, b"__compact_unwind" | b"__eh_frame" | b"__debug_frame")
}

fn role(seg: &[u8], sect: &[u8], flags: u32) -> Role {
    let t = flags & 0xff;
    if tls_type(t) {
        Role::Tls
    } else if matches!(
        t,
        S_MOD_INIT_FUNC_POINTERS | S_MOD_TERM_FUNC_POINTERS | S_INIT_FUNC_OFFSETS
    ) {
        Role::Init
    } else if matches!(t, S_ZEROFILL | S_GB_ZEROFILL) {
        Role::Bss
    } else if flags & S_ATTR_CODE != 0 || sect == b"__text" {
        Role::Code
    } else if sect == b"__const"
        || seg == b"__DATA_CONST"
        || sect == b"__cstring"
        || sect.starts_with(b"__literal")
    {
        Role::RoData
    } else {
        Role::Data
    }
}

const S_CSTRING_LITERALS: u32 = 0x2;
const S_4BYTE_LITERALS: u32 = 0x3;
const S_8BYTE_LITERALS: u32 = 0x4;
const S_16BYTE_LITERALS: u32 = 0xe;

/// The class of a section and where its atoms start before any symbol is looked at.
///
/// The linker splits C-string and fixed-width literal sections into pieces, merges equal
/// pieces and lays them out as it likes, whatever the object says, so nothing can depend on
/// which piece is next to which and each piece is an atom: a string at the end of a codegen
/// unit's pool is no longer part of the atom of every function that uses any string, and
/// adding a string no longer shifts the offsets of the ones after it. The same holds for
/// objects without MH_SUBSECTIONS_VIA_SYMBOLS.
fn literal_pieces(sect: &[u8], flags: u32, bytes: &[u8], size: u64) -> (SecClass, Vec<u64>) {
    let whole = vec![0];
    let fixed = |w: u64| -> Vec<u64> { (0..size).step_by(w as usize).collect() };
    match flags & 0xff {
        S_CSTRING_LITERALS => {
            // A piece ends at its NUL; the next one starts after it.
            let mut starts = vec![0];
            starts.extend(
                bytes
                    .iter()
                    .enumerate()
                    .filter(|&(i, &b)| b == 0 && (i as u64) + 1 < size)
                    .map(|(i, _)| i as u64 + 1),
            );
            (SecClass::CString, starts)
        }
        S_4BYTE_LITERALS => (SecClass::Literal, fixed(4)),
        S_8BYTE_LITERALS => (SecClass::Literal, fixed(8)),
        S_16BYTE_LITERALS => (SecClass::Literal, fixed(16)),
        _ if sect == b"__gcc_except_tab" => (SecClass::Lsda, whole),
        _ => (SecClass::Plain, whole),
    }
}

fn read_le(b: &[u8], off: usize, len: usize) -> Option<i64> {
    let s = b.get(off..off + len)?;
    Some(match len {
        4 => i64::from(i32::from_le_bytes(s.try_into().ok()?)),
        8 => i64::from_le_bytes(s.try_into().ok()?),
        _ => return None,
    })
}

fn zero(b: &mut [u8], off: usize, len: usize, mask: u32) {
    if len == 4 {
        let mut w = u32::from_le_bytes(b[off..off + 4].try_into().unwrap());
        w &= !mask;
        b[off..off + 4].copy_from_slice(&w.to_le_bytes());
    } else {
        b[off..off + len].fill(0);
    }
}

pub fn parse(data: &[u8], m: &mut MemberBuild, assume_subsections: bool) -> Result<(), String> {
    let file = MachOFile64::<Endianness, &[u8]>::parse(data)
        .map_err(|e| format!("unparsable Mach-O object: {e}"))?;
    let endian = file.endian();
    let cputype = file.macho_header().cputype(endian);
    let arch = match cputype {
        macho::CPU_TYPE_ARM64 => Arch::A64,
        macho::CPU_TYPE_X86_64 => Arch::X64,
        other => {
            return Err(format!(
                "Mach-O cpu type {other:#x} is not supported; only arm64 and x86_64 relocations are understood"
            ));
        }
    };
    let mut names = Interner::default();
    // Without MH_SUBSECTIONS_VIA_SYMBOLS the linker does not treat a symbol as the start of
    // an independent piece. Code can then fall through from one symbol into the next, or
    // refer to a neighbour with no relocation (hand-written assembly: ring, psm), so the
    // bytes between two symbols cannot be assumed to be used by that symbol alone. Such a
    // member is one atom per section.
    let subsections = assume_subsections
        || file.macho_header().flags(endian) & macho::MH_SUBSECTIONS_VIA_SYMBOLS != 0;
    m.whole_sections = !subsections;

    // Sections, in Mach-O ordinal order; `ours[ord - 1]` is our index if kept.
    let raw: Vec<_> = file.sections().collect();
    let mut ours: Vec<Option<usize>> = Vec::new();
    let mut secs: Vec<SecBuild> = Vec::new();
    let mut sec_addr: Vec<u64> = Vec::new();
    let mut ord_of: Vec<usize> = Vec::new();
    for (i, s) in raw.iter().enumerate() {
        let ms = s.macho_section();
        let (seg, sect, flags) = (ms.segment_name(), ms.name(), ms.flags(endian));
        let size: u64 = ms.size(endian);
        if skipped(seg, sect, flags) || size == 0 {
            ours.push(None);
            continue;
        }
        let zerofill = matches!(
            flags & 0xff,
            S_ZEROFILL | S_GB_ZEROFILL | S_THREAD_LOCAL_ZEROFILL
        );
        let (file_off, bytes) = if zerofill {
            (None, Vec::new())
        } else {
            let (o, sz) = ms
                .file_range(endian)
                .ok_or("Mach-O section has no file range")?;
            let b = data
                .read_bytes_at(o, sz)
                .map_err(|_| "Mach-O section extends past the end of the file".to_string())?;
            (Some(o), b.to_vec())
        };
        ours.push(Some(secs.len()));
        ord_of.push(i);
        sec_addr.push(ms.addr(endian));
        let key = format!(
            "{},{}",
            String::from_utf8_lossy(seg),
            String::from_utf8_lossy(sect)
        );
        let (class, starts) = literal_pieces(sect, flags, &bytes, size);
        secs.push(SecBuild {
            info: SectionInfo {
                key: key.into(),
                role: role(seg, sect, flags),
                class,
            },
            size,
            align: 1u64 << ms.align(endian).min(15),
            file_off,
            bytes,
            starts,
            relocs: Vec::new(),
            syms: Vec::new(),
        });
    }

    // Symbols.
    let table = file.macho_symbol_table();
    let strings = table.strings();
    let mut syms: Vec<Sym> = Vec::with_capacity(table.len());
    let mut defs: Vec<(u32, u32, u64, bool)> = Vec::new();
    for nl in table.iter() {
        let t = nl.n_type();
        if t & macho::N_STAB != 0 {
            syms.push(Sym::Skip);
            continue;
        }
        let desc = nl.n_desc(endian);
        let value: u64 = nl.n_value(endian);
        let mut name = || -> Result<u32, String> {
            let n = nl
                .name(endian, strings)
                .map_err(|e| format!("Mach-O symbol name: {e}"))?;
            Ok(names.intern_lossy(n))
        };
        match t & macho::N_TYPE {
            macho::N_SECT => {
                let ord = nl.n_sect() as usize;
                let Some(Some(si)) = ord.checked_sub(1).and_then(|o| ours.get(o)).copied() else {
                    // Defined in a section we do not model (debug, unwind): not referenceable.
                    syms.push(Sym::Skip);
                    continue;
                };
                let off = value.wrapping_sub(sec_addr[si]);
                if off >= secs[si].size && !(off == secs[si].size && desc & N_ALT_ENTRY == 0) {
                    syms.push(Sym::Bad("symbol address lies outside its section"));
                    continue;
                }
                let n = name()?;
                let pieces = matches!(secs[si].info.class, SecClass::CString | SecClass::Literal);
                if subsections && !pieces && desc & N_ALT_ENTRY == 0 && off < secs[si].size {
                    secs[si].starts.push(off);
                }
                secs[si].syms.push((off, n, t & macho::N_EXT != 0));
                if t & macho::N_EXT != 0 {
                    defs.push((n, si as u32, off, desc & N_WEAK_DEF != 0));
                }
                syms.push(Sym::Defined {
                    sec: si,
                    addr: value,
                });
            }
            macho::N_UNDF if t & macho::N_EXT != 0 && value != 0 => {
                syms.push(Sym::Bad("common symbol"))
            }
            macho::N_UNDF => syms.push(Sym::Undef(name()?)),
            macho::N_ABS => syms.push(Sym::Abs(value)),
            _ => syms.push(Sym::Bad("indirect or prebound symbol")),
        }
    }
    for s in &mut secs {
        s.starts.sort_unstable();
        s.starts.dedup();
    }

    let mut base = Vec::with_capacity(secs.len());
    let mut n = 0u32;
    for s in &secs {
        base.push(n);
        n += s.starts.len() as u32;
    }
    // Global (within the member) atom index and the offset inside it for a section offset.
    let atom_at = |secs: &[SecBuild], sec: usize, off: u64| -> (u32, i64) {
        let s = &secs[sec];
        let k = s.starts.partition_point(|&x| x <= off).saturating_sub(1);
        (base[sec] + k as u32, (off - s.starts[k]) as i64)
    };

    // Relocations.
    for (si, &ord) in ord_of.iter().enumerate() {
        let ms = raw[ord].macho_section();
        let here = secs[si].info.key.clone();
        let rels = ms
            .relocations(endian, data)
            .map_err(|e| format!("Mach-O relocations of {here}: {e}"))?;
        let mut pending: Option<i64> = None;
        let mut after_sub = false;
        for r in rels {
            if r.r_scattered(endian, cputype) {
                return Err(format!("scattered relocation in {here}"));
            }
            let e = r.info(endian);
            let site = e.r_address as usize;
            let len = 1usize << e.r_length;
            // Whether the relocation names a symbol or a section is an encoding detail that depends
            // on the object's layout, so it is not part of the kind.
            let mut kind = u32::from(e.r_type) | u32::from(e.r_pcrel) << 8 | u32::from(e.r_length) << 9;
            if arch == Arch::A64 && e.r_type == macho::ARM64_RELOC_ADDEND {
                pending = Some(i64::from(e.r_symbolnum).wrapping_shl(40).wrapping_shr(40));
                continue;
            }
            if e.r_type > 9 || !matches!(len, 4 | 8) || site + len > secs[si].bytes.len() {
                return Err(format!(
                    "unknown Mach-O relocation (type {}, length {len}, offset {site:#x}) in {here}",
                    e.r_type
                ));
            }
            // arm64 instruction relocations keep their addend in a preceding ADDEND entry and
            // must leave the immediate bits zero in an object file; the bits are masked, not
            // the whole instruction, so `bl` and `b` stay distinguishable.
            let (mask, insn) = match (arch, e.r_type) {
                (Arch::A64, macho::ARM64_RELOC_BRANCH26) => (0x03ff_ffff, true),
                (Arch::A64, 3 | 5 | 8) => (0x60ff_ffe0, true),
                (Arch::A64, 4 | 6 | 9) => (0x003f_fc00, true),
                _ => (u32::MAX, false),
            };
            let inplace = read_le(&secs[si].bytes, site, len).unwrap_or(0);
            let mut addend = if insn {
                if len != 4
                    || u32::from_le_bytes(secs[si].bytes[site..site + 4].try_into().unwrap()) & mask
                        != 0
                {
                    return Err(format!(
                        "non-zero immediate under an arm64 relocation in {here}"
                    ));
                }
                pending.take().unwrap_or(0)
            } else {
                inplace
            };
            let subtractor = e.r_type
                == if arch == Arch::A64 {
                    macho::ARM64_RELOC_SUBTRACTOR
                } else {
                    macho::X86_64_RELOC_SUBTRACTOR
                };
            let target = if e.r_extern {
                match syms.get(e.r_symbolnum as usize) {
                    Some(Sym::Undef(n)) => RTarget::Undef(*n),
                    Some(Sym::Defined { sec, addr }) => {
                        let at = addr - sec_addr[*sec];
                        // A reference into a literal section is `ltmp<n>` (the start of the
                        // section) plus an offset, which names a piece: resolve the sum, so
                        // that the addend is the offset within the piece. Not for x86-64
                        // pc-relative fields, whose in-place value carries an adjustment.
                        let literal = secs[*sec].info.class != SecClass::Plain
                            && secs[*sec].info.class != SecClass::Lsda
                            && (arch == Arch::A64 || !e.r_pcrel);
                        let total = at as i64 + addend;
                        if literal && total >= 0 && (total as u64) < secs[*sec].size {
                            let (a, off) = atom_at(&secs, *sec, total as u64);
                            addend = off;
                            RTarget::Atom(a)
                        } else {
                            let (a, off) = atom_at(&secs, *sec, at);
                            addend += off;
                            RTarget::Atom(a)
                        }
                    }
                    Some(Sym::Abs(v)) => {
                        addend += *v as i64;
                        RTarget::Abs
                    }
                    Some(Sym::Bad(why)) => {
                        return Err(format!("relocation in {here} targets a {why}"));
                    }
                    _ => {
                        return Err(format!(
                            "relocation in {here} names symbol #{} that is not modelled (debug or unwind section)",
                            e.r_symbolnum
                        ));
                    }
                }
            } else {
                // The in-place value is the target's address inside this object.
                let Some(Some(ts)) = (e.r_symbolnum as usize)
                    .checked_sub(1)
                    .and_then(|o| ours.get(o))
                    .copied()
                else {
                    return Err(format!(
                        "section-relative relocation in {here} targets a section that is not modelled"
                    ));
                };
                if insn || subtractor || after_sub {
                    return Err(format!(
                        "section-relative relocation type {} in {here} is not supported",
                        e.r_type
                    ));
                }
                let mut addr = if len == 4 {
                    inplace as u32 as i64
                } else {
                    inplace
                };
                if e.r_pcrel {
                    let extra = match (arch, e.r_type) {
                        (Arch::X64, 6) => 1,
                        (Arch::X64, 7) => 2,
                        (Arch::X64, 8) => 4,
                        _ => 0,
                    };
                    addr += sec_addr[si] as i64 + site as i64 + len as i64 + extra;
                }
                let (a, off) = atom_at(&secs, ts, (addr as u64).wrapping_sub(sec_addr[ts]));
                addend = off;
                RTarget::Atom(a)
            };
            if after_sub && !e.r_extern {
                return Err(format!(
                    "section-relative minuend of a SUBTRACTOR pair in {here}"
                ));
            }
            if subtractor {
                // The in-place value belongs to the pair and is read from the second entry.
                addend = 0;
                after_sub = true;
            } else {
                zero(&mut secs[si].bytes, site, len, mask);
                canonicalise(arch, &mut secs[si].bytes, site, e.r_type, &mut kind).map_err(|why| format!("{why} in {here}"))?;
                after_sub = false;
            }
            secs[si]
                .relocs
                .push(Reloc::new(site as u32, kind, len as u8, addend, target));
        }
    }

    m.names = names.items;
    assemble(m, secs, &defs);
    Ok(())
}

/// Rewrite the encodings that depend on where the compiler put a symbol relative
/// to its user into one canonical form.
///
/// LLVM reaches a symbol defined in the same module with `adrp` + `add` and one
/// defined in another module (another codegen unit, hence another object) through
/// the GOT: `adrp` + `ldr`. Which one it picks follows the codegen-unit partition,
/// not the program, and both compute the symbol's address, so hashing the
/// instruction would make a key depend on the partition. A load through the symbol
/// itself (`ldr x, [x, sym@PAGEOFF]`) is a different operation and keeps its form.
fn canonicalise(arch: Arch, bytes: &mut [u8], site: usize, ty: u8, kind: &mut u32) -> Result<(), String> {
    match (arch, ty) {
        (Arch::A64, 5) => *kind = (*kind & !0xff) | 3,
        (Arch::A64, 4 | 6) => {
            let w = u32::from_le_bytes(bytes[site..site + 4].try_into().unwrap());
            let add_x = ty == 4 && w & 0xffc0_0000 == 0x9100_0000;
            let got_ldr_x = ty == 6 && w & 0xffc0_0000 == 0xf940_0000;
            if add_x || got_ldr_x {
                *kind = ADDR_PAGEOFF;
                bytes[site..site + 4].copy_from_slice(&(w & 0x3ff).to_le_bytes());
            } else if ty == 6 {
                return Err("GOT_LOAD_PAGEOFF12 on something other than a 64-bit ldr".into());
            }
        }
        (Arch::X64, 3) if site >= 2 && bytes[site - 2] == 0x8b => {
            // `mov sym@GOTPCREL(%rip), %reg` is `lea sym(%rip), %reg` for a local symbol.
            bytes[site - 2] = 0x8d;
            *kind = (*kind & !0xff) | 1;
        }
        _ => {}
    }
    Ok(())
}

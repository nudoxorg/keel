//! The coarse code key of DESIGN.md §3.1: a hash of a test executable's
//! loadable sections, never of the file.
//!
//! Whole-file hashing is not stable across checkout paths: the linker leaks
//! the path into symbol and string tables (§1.2). Those tables are not
//! loaded, so they are not hashed; every section the loader maps is.

use std::path::{Path, PathBuf};

use object::{Object, ObjectSection, SectionFlags, elf, macho, pe};

use crate::digest::Digest;
use crate::frame::Framer;

mod tag {
    pub const SECTION: u8 = 1;
    pub const ZERO_FILL: u8 = 2;
    pub const IMPORTS: u8 = 3;
}

/// Why an executable could not be keyed.
#[derive(Debug, thiserror::Error)]
pub enum ExecutableKeyError {
    /// The file could not be read.
    #[error(
        "cannot read test executable {path}: {source}; check that the build produced it and that this user can read it"
    )]
    Read {
        /// The executable.
        path: PathBuf,
        /// The underlying error.
        source: std::io::Error,
    },
    /// The file is not an object format `object` can parse.
    #[error(
        "{path} is not a parseable ELF, Mach-O or PE executable ({source}); rebuild it or pass the test binary, not a script or archive"
    )]
    Parse {
        /// The executable.
        path: PathBuf,
        /// The underlying error.
        source: object::Error,
    },
    /// A format with no defined notion of loadable sections here.
    #[error(
        "{path} is a {format:?} file; the executable key is defined for ELF, Mach-O and PE only, so this binary must fall back to a declared-inputs key"
    )]
    UnsupportedFormat {
        /// The executable.
        path: PathBuf,
        /// What `object` called it.
        format: object::BinaryFormat,
    },
}

/// What a section contributes to the key.
enum Loaded {
    Skip,
    Bytes,
    /// Occupies address space but has no file contents; only its size counts.
    ZeroFill,
}

/// Sections whose bytes carry build identity rather than behaviour. ELF
/// `.note.*` is allocated, so it must be excluded by name.
fn is_noise(name: &[u8]) -> bool {
    name == b".comment" || name == b".gnu_debuglink" || name.starts_with(b".note")
}

fn classify<'d>(section: &impl ObjectSection<'d>) -> Loaded {
    let name = section.name_bytes().unwrap_or_default();
    if is_noise(name) {
        return Loaded::Skip;
    }
    let uninit = matches!(
        section.kind(),
        object::SectionKind::UninitializedData | object::SectionKind::UninitializedTls
    );
    let kept = if uninit {
        Loaded::ZeroFill
    } else {
        Loaded::Bytes
    };
    match section.flags() {
        SectionFlags::Elf { sh_flags } => {
            if sh_flags & u64::from(elf::SHF_ALLOC) != 0 {
                kept
            } else {
                Loaded::Skip
            }
        }
        SectionFlags::MachO { flags } => {
            // __LINKEDIT holds symbols, strings and the code signature;
            // __DWARF is never mapped.
            let segment = section
                .segment_name_bytes()
                .ok()
                .flatten()
                .unwrap_or_default();
            if segment == b"__LINKEDIT" || segment == b"__DWARF" {
                return Loaded::Skip;
            }
            match flags & macho::SECTION_TYPE {
                macho::S_ZEROFILL | macho::S_GB_ZEROFILL | macho::S_THREAD_LOCAL_ZEROFILL => {
                    Loaded::ZeroFill
                }
                _ => Loaded::Bytes,
            }
        }
        SectionFlags::Coff { characteristics: c } => {
            let content = pe::IMAGE_SCN_CNT_CODE | pe::IMAGE_SCN_CNT_INITIALIZED_DATA;
            // Discardable sections (debug info, relocations) are not kept
            // in the loaded image.
            if c & pe::IMAGE_SCN_MEM_READ != 0
                && c & pe::IMAGE_SCN_MEM_DISCARDABLE == 0
                && c & content != 0
            {
                Loaded::Bytes
            } else {
                Loaded::Skip
            }
        }
        _ => Loaded::Skip,
    }
}

/// Hashes the loadable sections of `path`, then its sorted imported symbols.
///
/// Sections are ordered by (segment, name) so the key does not depend on the
/// linker's layout choices. Uninitialised sections (`.bss`, `__bss`, TLS
/// zero-fill) contribute their name and size: they have no bytes to hash, but
/// a changed size is a changed memory image. The import list is included
/// because the dynamic loader resolves it at run time (§3.1).
///
/// On PE the CodeView debug directory inside `.rdata` embeds the PDB path and
/// a timestamp; that is not stripped here, so PE keys may vary per build path.
/// That is a miss, never a false hit.
pub fn executable_key(path: &Path) -> Result<Digest, ExecutableKeyError> {
    let data = std::fs::read(path).map_err(|source| ExecutableKeyError::Read {
        path: path.into(),
        source,
    })?;
    key_of_image(&data, path)
}

fn key_of_image(data: &[u8], path: &Path) -> Result<Digest, ExecutableKeyError> {
    let parse = |source| ExecutableKeyError::Parse {
        path: path.into(),
        source,
    };
    let file = object::File::parse(data).map_err(parse)?;
    if !matches!(
        file.format(),
        object::BinaryFormat::Elf
            | object::BinaryFormat::MachO
            | object::BinaryFormat::Pe
            | object::BinaryFormat::Coff
    ) {
        return Err(ExecutableKeyError::UnsupportedFormat {
            path: path.into(),
            format: file.format(),
        });
    }

    struct Picked<'d> {
        segment: Vec<u8>,
        name: Vec<u8>,
        /// `None` for zero-fill sections.
        bytes: Option<&'d [u8]>,
        size: u64,
    }
    let mut picked = Vec::new();
    for section in file.sections() {
        let bytes = match classify(&section) {
            Loaded::Skip => continue,
            Loaded::Bytes => Some(section.data().map_err(parse)?),
            Loaded::ZeroFill => None,
        };
        picked.push(Picked {
            segment: section
                .segment_name_bytes()
                .ok()
                .flatten()
                .unwrap_or_default()
                .to_vec(),
            name: section.name_bytes().map_err(parse)?.to_vec(),
            bytes,
            size: section.size(),
        });
    }
    // Stable, so same-named sections keep the file's own order.
    picked.sort_by(|a, b| (&a.segment, &a.name).cmp(&(&b.segment, &b.name)));

    let mut f = Framer::new("keel/executable");
    for p in &picked {
        // Segment length first, so `ab`+`c` and `a`+`bc` cannot meet.
        let mut label = Vec::with_capacity(p.segment.len() + p.name.len() + 8);
        label.extend_from_slice(&(p.segment.len() as u64).to_le_bytes());
        label.extend_from_slice(&p.segment);
        label.extend_from_slice(&p.name);
        match p.bytes {
            Some(bytes) => {
                f.field(tag::SECTION, &label);
                f.field_large(tag::SECTION, bytes);
            }
            None => {
                f.field(tag::ZERO_FILL, &label);
                f.field(tag::ZERO_FILL, &p.size.to_le_bytes());
            }
        }
    }

    let mut imports: Vec<&[u8]> = file
        .imports()
        .map_err(parse)?
        .iter()
        .map(|i| i.name())
        .collect();
    imports.sort_unstable();
    f.field(tag::IMPORTS, &(imports.len() as u64).to_le_bytes());
    for name in imports {
        f.field(tag::IMPORTS, name);
    }
    Ok(f.finish())
}

#[cfg(test)]
mod tests {
    use object::write::{Object as Out, Symbol, SymbolSection};
    use object::{
        Architecture, BinaryFormat, Endianness, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
    };

    use super::*;

    type Section<'a> = (&'a str, &'a str, SectionKind, &'a [u8]);

    fn build(format: BinaryFormat, sections: &[Section], symtab_name: &str) -> Vec<u8> {
        let mut obj = Out::new(format, Architecture::X86_64, Endianness::Little);
        for (seg, name, kind, data) in sections {
            let id = obj.add_section(seg.as_bytes().to_vec(), name.as_bytes().to_vec(), *kind);
            obj.append_section_data(id, data, 1);
        }
        // Stands in for the checkout path the linker leaks into the symbol
        // table; it must not matter.
        obj.add_symbol(Symbol {
            name: symtab_name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: SymbolKind::Data,
            scope: SymbolScope::Compilation,
            weak: false,
            section: SymbolSection::Undefined,
            flags: SymbolFlags::None,
        });
        obj.write().unwrap()
    }

    fn key_of(bytes: &[u8]) -> Digest {
        key_of_image(bytes, Path::new("test.o")).unwrap()
    }

    const TEXT: Section = ("", ".text", SectionKind::Text, b"\x90\x90\xc3");

    #[test]
    fn elf_ignores_notes_comment_and_symbol_names() {
        let image = |note: &'static [u8], comment: &'static [u8], sym: &str| {
            build(
                BinaryFormat::Elf,
                &[
                    TEXT,
                    ("", ".note.gnu.build-id", SectionKind::Note, note),
                    ("", ".comment", SectionKind::OtherString, comment),
                    ("", ".gnu_debuglink", SectionKind::Metadata, b"x"),
                ],
                sym,
            )
        };
        let a = image(b"build-id-one", b"rustc 1", "/home/a/proj");
        let b = image(b"build-id-two", b"rustc 2", "/home/bbbbbb/proj");
        assert_ne!(a, b);
        assert_eq!(key_of(&a), key_of(&b));
    }

    #[test]
    fn elf_text_changes_the_key() {
        let a = build(BinaryFormat::Elf, &[TEXT], "s");
        let b = build(
            BinaryFormat::Elf,
            &[("", ".text", SectionKind::Text, b"\x90\x90\xc4")],
            "s",
        );
        let c = build(BinaryFormat::Elf, &[TEXT], "other-symbol");
        assert_ne!(key_of(&a), key_of(&b));
        assert_eq!(key_of(&a), key_of(&c));
    }

    #[test]
    fn elf_section_order_does_not_matter() {
        let data: Section = ("", ".rodata", SectionKind::ReadOnlyData, b"hello");
        let a = build(BinaryFormat::Elf, &[TEXT, data], "s");
        let b = build(BinaryFormat::Elf, &[data, TEXT], "s");
        assert_eq!(key_of(&a), key_of(&b));
    }

    #[test]
    fn macho_ignores_linkedit_but_not_zerofill_size() {
        let image = |linkedit: &'static [u8], bss: u64| {
            let mut obj = Out::new(
                BinaryFormat::MachO,
                Architecture::Aarch64,
                Endianness::Little,
            );
            let t = obj.add_section(b"__TEXT".to_vec(), b"__text".to_vec(), SectionKind::Text);
            obj.append_section_data(t, b"\x1f\x20\x03\xd5", 4);
            let l = obj.add_section(b"__LINKEDIT".to_vec(), b"__sig".to_vec(), SectionKind::Data);
            obj.append_section_data(l, linkedit, 1);
            let z = obj.add_section(
                b"__DATA".to_vec(),
                b"__bss".to_vec(),
                SectionKind::UninitializedData,
            );
            obj.append_section_bss(z, bss, 8);
            obj.write().unwrap()
        };
        let a = image(b"signature-A", 64);
        let b = image(b"signature-BB", 64);
        let c = image(b"signature-A", 128);
        assert_eq!(key_of(&a), key_of(&b));
        assert_ne!(key_of(&a), key_of(&c));
    }

    #[test]
    fn same_bytes_under_a_different_section_name_differ() {
        let a = build(
            BinaryFormat::Elf,
            &[("", ".rodata", SectionKind::ReadOnlyData, b"x")],
            "s",
        );
        let b = build(
            BinaryFormat::Elf,
            &[("", ".rodata.b", SectionKind::ReadOnlyData, b"x")],
            "s",
        );
        assert_ne!(key_of(&a), key_of(&b));
    }

    #[test]
    fn non_object_input_is_a_named_error() {
        let err = key_of_image(b"#!/bin/sh\n", Path::new("script.sh"))
            .unwrap_err()
            .to_string();
        assert!(
            err.contains("script.sh") && err.contains("rebuild"),
            "{err}"
        );
        let err = executable_key(Path::new("/nonexistent/keel-test-binary"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("/nonexistent/keel-test-binary"), "{err}");
    }
}

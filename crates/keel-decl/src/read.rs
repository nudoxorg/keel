use std::fs::File;
use std::path::{Path, PathBuf};

use object::read::ReadCache;
use object::{BinaryFormat, Object, ObjectSection};

use crate::{
    Collector, Declaration, DecodeError, MACHO_SECTION_NAME, MACHO_SEGMENT_NAME, SECTION_NAME,
};

#[derive(Debug, thiserror::Error)]
pub enum ReadError {
    #[error(
        "cannot open {} to read keel declarations: {source}. Pass the path of a test executable \
         that cargo built (see `cargo test --no-run --message-format=json`)",
        path.display()
    )]
    Open {
        path: PathBuf,
        source: std::io::Error,
    },

    #[error(
        "{} is not an ELF, Mach-O or PE/COFF file ({source}). keel reads declarations from the \
         test executable itself, not from archives, scripts or universal (fat) binaries; pass the \
         executable path that cargo reports",
        path.display()
    )]
    UnknownFormat {
        path: PathBuf,
        source: object::Error,
    },

    #[error(
        "cannot read the keel section of {}: {source}. The file looks like an executable but its \
         section data is unreadable; rebuild it, or check that it was not truncated",
        path.display()
    )]
    Section {
        path: PathBuf,
        source: object::Error,
    },

    #[error("{}: {source}", path.display())]
    Decode { path: PathBuf, source: DecodeError },
}

/// Reads the declarations recorded in a built binary without running it.
///
/// The section is `__DATA,__keel` on Mach-O and `.keel` on ELF and PE/COFF.
/// A binary with no such section has no declarations and yields an empty
/// list; that is the normal case for crates that do not use keel-macros.
/// Only the headers and the section are read from disk, so large test
/// executables are cheap.
pub fn read_declarations(path: &Path) -> Result<Vec<Declaration>, ReadError> {
    let file = File::open(path).map_err(|source| ReadError::Open {
        path: path.to_owned(),
        source,
    })?;
    let cache = ReadCache::new(file);
    let obj = object::File::parse(&cache).map_err(|source| ReadError::UnknownFormat {
        path: path.to_owned(),
        source,
    })?;

    let macho = obj.format() == BinaryFormat::MachO;
    let mut collector = Collector::default();
    for section in obj.sections() {
        let is_keel = if macho {
            section.name_bytes() == Ok(MACHO_SECTION_NAME.as_bytes())
                && section.segment_name_bytes() == Ok(Some(MACHO_SEGMENT_NAME.as_bytes()))
        } else {
            section.name_bytes() == Ok(SECTION_NAME.as_bytes())
        };
        if !is_keel {
            continue;
        }
        let data = section.data().map_err(|source| ReadError::Section {
            path: path.to_owned(),
            source,
        })?;
        collector.decode(data).map_err(|source| ReadError::Decode {
            path: path.to_owned(),
            source,
        })?;
    }
    Ok(collector.into_decls())
}

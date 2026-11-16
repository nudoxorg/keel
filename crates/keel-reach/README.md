# keel-reach

Per-test reach keys (DESIGN.md section 3.2): a hash of the machine code and data a
test can reach through the relocation graph of its linked binary, computed from the
object files before linking, so a one-line change in a foundation crate reruns only
the tests that reach that line.

- `keel-linker`: the linker shim. Run rustc with `-C linker=<path to keel-linker>`.
  It records the link inputs to `<out>.keel-link.json`, hard-links (or copies) every
  object into `<out>.keel-objects/` because rustc deletes them, then execs the real
  linker (`KEEL_REAL_LINKER`, else the platform compiler driver). A recording failure
  is reported on stderr and never fails the link; that binary then uses the
  executable key. The name matters: rustc treats a linker called `*-ld` as a bare
  `ld` and passes ld-style arguments, so this one is not. If it is renamed anyway the
  shim forwards ld-style arguments to `ld`.
- `keel-reach analyze | compare | query | diff | list-tests`: the command line over the
  library `keel_reach` (`Loader`, `analyze`, `BinaryReach`, `exercised`, `intersects`).

## What the key covers

For a test, `blake3` over the harness key and the Merkle hashes of the test's roots (the
function pointer in its libtest descriptor, the descriptor, and any symbol named
after the test path that the entry does not reach; see "The key"). The harness set is
everything reachable from `main`, the initialiser and finaliser arrays, thread-local
templates and the unwinder's personality routine. An atom is a function or data item (one ELF section, or the
bytes from one Mach-O symbol to the next); its hash covers its bytes with
relocation fields zeroed, each relocation's kind, size and addend, and the hash of
what it points at. Layout, addresses, symbol names, section names and codegen-unit
partition do not enter the hash, which `tests/synthetic.rs` checks by building with
different codegen-unit counts and with and without incremental compilation.

Not covered, by design: files read at runtime (the files term of the key), the
environment, time, the network. Not covered, by limitation: unwind tables and LSDA
data (they are derived from the code), and the number of genuine trailing zero bytes
of a Mach-O constant within one alignment unit (alignment padding cannot be told
apart from it; see `model::content_hash`).

## `CARGO_MANIFEST_DIR`

`env!("CARGO_MANIFEST_DIR")` expands to an absolute path that is baked into the
binary, and `--remap-path-prefix` does not touch it. A test that uses it therefore has
a different key when built at a different path; in the synthetic workspace this is
the one test per crate that reads its fixture at run time (8 of 435 keys between two
checkouts). The CI design answers this by bind-mounting every job's checkout at the
same fixed path `/build` (DESIGN section 6.2), so keys are comparable across jobs.

## Fallback rules

A test is either keyed (`TestResult::Keyed { key, atoms }`) or falls back
(`TestResult::Fallback { reason, atoms }`); there is no key to read on a test that falls
back, and in JSON `key` is null. The reason is a tagged object (`fallback.rs`):

| kind | when | the executable key is enough? |
|---|---|---|
| `current_exe` | the reach, outside the harness set, contains or calls a function whose demangled name includes `current_exe` | yes |
| `loads-library` | the same for `dlopen`, `dlsym`, `libloading` | **no**: the loaded code is not in the executable |
| `duplicate-definition` | a name in the reach (or the harness) is defined with different content by inputs whose link order cannot be established | yes |
| `no_entry` | no test descriptor and no symbol names the test | yes |
| `unverifiable` | an input could not be read, a relocation is not understood, an input is bitcode, `main` is missing, or the record is stale (`--verify-record`) | yes |

The record names the flagged callee, the calling function and the object. A flag is the
OR over every name of an atom (merged functions carry several), and the record gives the
name that carried it, and the atom's own name if that is another one. A name that is not
Rust-mangled is matched on its raw text. A reach that contains `std::process::Command` is
not a fallback: it is recorded as `spawns` and `spawns_processes`, because callers add
the hashes of `CARGO_BIN_EXE_*` binaries and declared tools. The harness set is never
judged for these (libtest itself reaches `current_exe` and `Command`).

## Reading link inputs

* An archive's objects are parsed once per content, keyed by the blake3 of the object's
  bytes, in memory and (with `--cache DIR`) on disk (`cache.rs`).
* A Mach-O object without `MH_SUBSECTIONS_VIA_SYMBOLS` is one atom per section.
* Equal-strength definitions of one name are settled as the linker would: a plain object
  beats archive members and objects go by their place on the link line; anything else
  that differs in content is `duplicate-definition`.
* `-l` names are resolved from the linker's own list of inputs when the record has one
  (`-dependency_info`, `--dependency-file`); otherwise by searching the `-L`
  directories, and every `-l` and dynamic library with no static library behind it is
  listed in the report as an *unkeyed input*: calls into it are hashed by name.
* A reference to `__start_X`, `__stop_X`, `section$start$SEG$sect`, `section$end$..`,
  `segment$start$SEG` or `segment$end$SEG` reaches every atom of that section or segment.

## Test descriptors

`main` would reach every test through the descriptor table and every key would hold
every test, so descriptors are cut out of the harness. libtest links a static array of
descriptors, each holding the test's name (a `&str`: pointer and length) and its function
pointer; `entry.rs` reads them from the test crate's own objects and accepts a
read-only data atom as a descriptor only when it has exactly one relocation to code, and a
`(pointer, length)` pair whose length field carries no relocation and whose bytes are
a name in the test list. That function pointer is the test's entry; a symbol named after
the test path is only a cross-check, and if it is not in the entry's reach it is a root
too (the report says so). Only validated descriptors get the treatment below; a user's own
table of function pointers to tests, and code that walks it, keep their edges and bytes.

- a descriptor's edges to its entry are dropped; its other edges (the name string, the
  `should_panic` message) stay. It belongs to the reach of the test it names and to no
  other, so renaming a test or editing its attributes changes that test's key only;
- an atom whose every relocation is a validated descriptor is the *table*
  (`&[&TestDescAndFn]`), and code that references the table is the generated `main`. Both
  are traversed for their other edges, but their own bytes are replaced by a constant and
  their edges to descriptors are dropped: the only things that vary in them are the slice
  length and the pointers. Adding a test therefore leaves every existing test's key alone.

## The key

`key = blake3("keel-reach/key/2" | harness key | hashes of the entry, the descriptor and
any extra roots)`. The Merkle hash of a root (`graph::Merkle::node_hash`) commits to
every atom it reaches, cycles included, so this is as sharp as hashing every component
in the reach (`Options::closure_key`, `--closure-key`) and O(1) per test. The test
`the_root_key_tells_the_same_builds_apart_as_the_key_over_every_component` checks that
the two agree on which builds differ.

## Reports

`keel-reach analyze --out R.json` writes a small header and `R.atoms` (the atom table in
columns and each test's atoms as roaring bitmaps, zstd); `--format json` writes the full
JSON. `compare A B` is the regression oracle (key, fallback and the set of atoms reached,
atoms identified by object, names and hash); `query --report R --symbol-regex RE` says
which tests reach a matching atom.

## Not yet

ELF output is exercised on x86_64 only
(through a zig cross linker); Mach-O x86_64 and ELF aarch64 paths are written but
untested.

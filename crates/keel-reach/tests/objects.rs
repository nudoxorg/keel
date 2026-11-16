//! The loader, symbolic link and reach logic on hand-built ELF objects: small
//! enough to state the expected answer exactly, including the cases a real
//! toolchain rarely produces (duplicate definitions, unknown relocations).

use keel_reach::record::SCHEMA;
use keel_reach::{Fallback, LinkInputs, Loader, Options, analyze, intersects};
use object::write::{Object, Relocation, SectionId, Symbol, SymbolId, SymbolSection};
use object::{
    Architecture, BinaryFormat, Endianness, RelocationEncoding, RelocationFlags, RelocationKind,
    SectionFlags, SectionKind, SymbolFlags, SymbolKind, SymbolScope,
};
use std::path::{Path, PathBuf};

const A: &str = "_ZN3app5tests1a17h0123456789abcdefE";
const B: &str = "_ZN3app5tests1b17h0123456789abcdefE";
const A_CLOSURE: &str = "_ZN3app5tests1a28_$u7b$$u7b$closure$u7d$$u7d$17h0123456789abcdefE";
const B_CLOSURE: &str = "_ZN3app5tests1b28_$u7b$$u7b$closure$u7d$$u7d$17h0123456789abcdefE";

struct Obj(Object<'static>);

impl Obj {
    fn new() -> Obj {
        Obj(Object::new(
            BinaryFormat::Elf,
            Architecture::X86_64,
            Endianness::Little,
        ))
    }

    fn sym(&mut self, name: &str, sec: Option<SectionId>, weak: bool) -> SymbolId {
        self.0.add_symbol(Symbol {
            name: name.as_bytes().to_vec(),
            value: 0,
            size: 0,
            kind: if sec.is_some() {
                SymbolKind::Text
            } else {
                SymbolKind::Unknown
            },
            scope: if sec.is_some() {
                SymbolScope::Dynamic
            } else {
                SymbolScope::Unknown
            },
            weak,
            section: sec.map_or(SymbolSection::Undefined, SymbolSection::Section),
            flags: SymbolFlags::None,
        })
    }

    fn undefined(&mut self, name: &str) -> SymbolId {
        self.0
            .symbol_id(name.as_bytes())
            .unwrap_or_else(|| self.sym(name, None, false))
    }

    /// A section `.text.<name>` / `.rodata.<name>` holding `bytes`, defining `name`,
    /// with a 64-bit absolute relocation at offset 0, 8, ... to each target in order.
    fn item(
        &mut self,
        sec_name: &str,
        kind: SectionKind,
        name: &str,
        bytes: &[u8],
        targets: &[&str],
        weak: bool,
    ) -> SymbolId {
        let at: Vec<(u64, &str)> = targets.iter().enumerate().map(|(i, t)| (8 * i as u64, *t)).collect();
        self.item_at(sec_name, kind, name, bytes, &at, weak)
    }

    /// Like `item`, with each relocation at an offset of its own.
    fn item_at(
        &mut self,
        sec_name: &str,
        kind: SectionKind,
        name: &str,
        bytes: &[u8],
        targets: &[(u64, &str)],
        weak: bool,
    ) -> SymbolId {
        let sec = self
            .0
            .add_section(vec![], sec_name.as_bytes().to_vec(), kind);
        self.0.append_section_data(sec, bytes, 8);
        let id = self.sym(name, Some(sec), weak);
        for (off, t) in targets.iter() {
            let target = self.undefined(t);
            self.0
                .add_relocation(
                    sec,
                    Relocation {
                        offset: *off,
                        symbol: target,
                        addend: 0,
                        flags: RelocationFlags::Generic {
                            kind: RelocationKind::Absolute,
                            encoding: RelocationEncoding::Generic,
                            size: 64,
                        },
                    },
                )
                .unwrap();
        }
        id
    }

    fn func(&mut self, name: &str, body: u8, calls: &[&str]) -> SymbolId {
        let mut bytes = vec![0u8; 8 * calls.len().max(1)];
        bytes.push(body);
        self.item(
            &format!(".text.{name}"),
            SectionKind::Text,
            name,
            &bytes,
            calls,
            false,
        )
    }

    fn data(&mut self, name: &str, kind: SectionKind, bytes: &[u8], targets: &[&str]) -> SymbolId {
        let sec_name = match kind {
            SectionKind::ReadOnlyDataWithRel => format!(".data.rel.ro.{name}"),
            SectionKind::ReadOnlyData => format!(".rodata.{name}"),
            _ => format!(".data.{name}"),
        };
        let mut b = bytes.to_vec();
        b.resize(b.len().max(8 * targets.len()), 0);
        self.item(&sec_name, kind, name, &b, targets, false)
    }

    /// A libtest descriptor as the compiler lays it out: the function pointer, then a
    /// `&str` (pointer, length) pair per string; the length is plain data.
    fn descriptor(&mut self, name: &str, testfn: &str, strings: &[(&str, usize)]) -> SymbolId {
        let mut bytes = vec![0u8; 8];
        let mut at = vec![(0u64, testfn)];
        for (i, (sym, len)) in strings.iter().enumerate() {
            at.push((8 + 16 * i as u64, *sym));
            bytes.extend([0u8; 8]);
            bytes.extend((*len as u64).to_le_bytes());
        }
        self.item_at(
            &format!(".data.rel.ro.{name}"),
            SectionKind::ReadOnlyDataWithRel,
            name,
            &bytes,
            &at,
            false,
        )
    }

    fn finish(self) -> Vec<u8> {
        self.0.write().unwrap()
    }
}

/// A GNU-style `ar` archive with short member names.
fn ar(members: &[(&str, Vec<u8>)]) -> Vec<u8> {
    let mut out = b"!<arch>\n".to_vec();
    for (name, data) in members {
        out.extend(
            format!(
                "{:<16}{:<12}{:<6}{:<6}{:<8}{:<10}`\n",
                format!("{name}/"),
                0,
                0,
                0,
                100644,
                data.len()
            )
            .as_bytes(),
        );
        out.extend(data);
        if data.len() % 2 == 1 {
            out.push(b'\n');
        }
    }
    out
}

struct Params {
    helper_a: u8,
    helper_b: u8,
    driver: u8,
    init: u8,
    registry: u8,
}

impl Default for Params {
    fn default() -> Params {
        Params {
            helper_a: 1,
            helper_b: 2,
            driver: 3,
            init: 4,
            registry: 5,
        }
    }
}

const C: &str = "_ZN3app5tests1c17h0123456789abcdefE";
const C_CLOSURE: &str = "_ZN3app5tests1c28_$u7b$$u7b$closure$u7d$$u7d$17h0123456789abcdefE";

struct App {
    /// Source-file string of test a's descriptor.
    file_a: &'static [u8],
    /// A third test, which also changes the table length and `main`.
    extra_test: bool,
}

impl Default for App {
    fn default() -> App {
        App { file_a: b"src/lib.rs", extra_test: false }
    }
}

fn app_object() -> Vec<u8> {
    app_object_with(&App::default())
}

/// The test crate's object: the generated `main` (its body byte stands for the slice
/// length), tests with their closures, descriptors and the descriptor table.
fn app_object_with(app: &App) -> Vec<u8> {
    let mut o = Obj::new();
    let n = if app.extra_test { 3 } else { 2 };
    o.func("main", n, &["driver", "table"]);
    o.func(A, 0, &["helper_a"]);
    o.func(B, 0, &["helper_b"]);
    o.func(A_CLOSURE, 0, &[A]);
    o.func(B_CLOSURE, 0, &[B]);
    o.data("name_a", SectionKind::ReadOnlyData, b"tests::a", &[]);
    o.data("name_b", SectionKind::ReadOnlyData, b"tests::b", &[]);
    o.data("file_a", SectionKind::ReadOnlyData, app.file_a, &[]);
    o.descriptor("desc_a", A_CLOSURE, &[("name_a", 8), ("file_a", app.file_a.len())]);
    o.descriptor("desc_b", B_CLOSURE, &[("name_b", 8)]);
    let mut table = vec!["desc_a", "desc_b"];
    if app.extra_test {
        o.func(C, 0, &["helper_b"]);
        o.func(C_CLOSURE, 0, &[C]);
        o.data("name_c", SectionKind::ReadOnlyData, b"tests::c", &[]);
        o.descriptor("desc_c", C_CLOSURE, &[("name_c", 8)]);
        table.push("desc_c");
    }
    o.data("table", SectionKind::ReadOnlyDataWithRel, &[], &table);
    o.finish()
}

fn lib_object(p: &Params) -> Vec<u8> {
    let mut o = Obj::new();
    o.func("driver", p.driver, &["puts", "__start_keel_reg", "init_fn"]);
    o.func("helper_a", p.helper_a, &["shared"]);
    o.func("helper_b", p.helper_b, &["shared"]);
    o.func("shared", 9, &[]);
    o.func("init_fn", p.init, &[]);
    // Reached only through `.init_array`.
    let init =
        o.0.add_section(vec![], b".init_array".to_vec(), SectionKind::Elf(14));
    o.0.section_mut(init).flags = SectionFlags::Elf { sh_flags: 3 };
    o.0.append_section_data(init, &[0; 8], 8);
    let target = o.undefined("init_fn");
    o.0.add_relocation(
        init,
        Relocation {
            offset: 0,
            symbol: target,
            addend: 0,
            flags: RelocationFlags::Generic {
                kind: RelocationKind::Absolute,
                encoding: RelocationEncoding::Generic,
                size: 64,
            },
        },
    )
    .unwrap();
    // A distributed-slice registry: two atoms in a section named like a C identifier.
    for (i, n) in ["reg_one", "reg_two"].iter().enumerate() {
        let sec =
            o.0.add_section(vec![], b"keel_reg".to_vec(), SectionKind::Data);
        o.0.append_section_data(sec, &[p.registry + i as u8; 8], 8);
        o.sym(n, Some(sec), false);
    }
    o.finish()
}

struct Fixture {
    dir: PathBuf,
}

impl Fixture {
    fn new(name: &str) -> Fixture {
        let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
            .join("keel-reach-objects")
            .join(name);
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        Fixture { dir }
    }

    fn record(&self, objects: &[Vec<u8>], archives: &[Vec<u8>]) -> LinkInputs {
        let mut rec = LinkInputs {
            schema: SCHEMA,
            cwd: self.dir.clone(),
            output: self.dir.join("bin"),
            ..Default::default()
        };
        for (i, o) in objects.iter().enumerate() {
            let p = self.dir.join(format!("obj{i}.o"));
            std::fs::write(&p, o).unwrap();
            rec.objects.push(p);
        }
        for (i, a) in archives.iter().enumerate() {
            let p = self.dir.join(format!("libarch{i}-0123.rlib"));
            std::fs::write(&p, a).unwrap();
            rec.archives.push(p);
        }
        // The link line: objects, then archives, as rustc passes them.
        rec.args = rec
            .objects
            .iter()
            .chain(&rec.archives)
            .map(|p| p.display().to_string())
            .collect();
        rec
    }
}

fn opts() -> Options {
    Options {
        crate_name: "app".into(),
        tests: vec![
            "tests::a".into(),
            "tests::b".into(),
            "tests::missing".into(),
        ],
        ..Default::default()
    }
}

fn lib_archive(p: &Params) -> Vec<u8> {
    ar(&[
        ("lib.rmeta", b"rust metadata, not an object".to_vec()),
        ("helper.o", lib_object(p)),
    ])
}

#[test]
fn descriptor_cut_keeps_tests_apart_and_a_helper_change_moves_only_its_tests() {
    let f = Fixture::new("cut");
    let r1 = analyze(
        &Loader::new(),
        &f.record(&[app_object()], &[lib_archive(&Params::default())]),
        &opts(),
    );
    r1.verifiable.as_ref().unwrap();
    let (a, b) = (&r1.tests["tests::a"], &r1.tests["tests::b"]);
    assert_ne!(*a.key().unwrap(), *b.key().unwrap());
    assert_ne!(*a.key().unwrap(), r1.harness_key);
    assert!(a.fallback().is_none() && b.fallback().is_none());

    // a reaches helper_a but not helper_b, though `main` reaches both through the table.
    let ids = |t: &str| -> Vec<String> {
        r1.tests[t]
            .atoms()
            .iter()
            .map(|i| r1.atom_table.symbol(i).to_string())
            .collect()
    };
    assert!(
        ids("tests::a").contains(&"helper_a".to_string()),
        "{:?}",
        ids("tests::a")
    );
    assert!(!ids("tests::a").contains(&"helper_b".to_string()));
    let harness: Vec<String> = r1
        .harness_atoms
        .iter()
        .map(|i| r1.atom_table.symbol(i).to_string())
        .collect();
    assert!(
        !harness.contains(&"helper_a".to_string()) && !harness.contains(&A.to_string()),
        "descriptor edges to tests are cut: {harness:?}"
    );
    assert!(
        !harness.contains(&"desc_a".to_string()) && harness.contains(&"table".to_string()),
        "descriptors belong to their tests; the table is traversed but its bytes are not hashed: {harness:?}"
    );
    assert!(
        ids("tests::a").contains(&"desc_a".to_string()) && ids("tests::a").contains(&"name_a".to_string()),
        "a test's descriptor and its name string are in its own reach"
    );
    assert!(!ids("tests::a").contains(&"desc_b".to_string()));
    assert!(
        harness.contains(&"init_fn".to_string()),
        ".init_array targets are harness roots"
    );
    assert!(
        harness.contains(&"reg_one".to_string()) && harness.contains(&"reg_two".to_string()),
        "__start_ symbols resolve to the whole section"
    );

    // Change helper_a only.
    let r2 = analyze(
        &Loader::new(),
        &f.record(
            &[app_object()],
            &[lib_archive(&Params {
                helper_a: 77,
                ..Default::default()
            })],
        ),
        &opts(),
    );
    assert_ne!(key(&r2, "tests::a"), *a.key().unwrap());
    assert_eq!(key(&r2, "tests::b"), *b.key().unwrap());
    assert_eq!(r2.harness_key, r1.harness_key);

    // Change something the harness reaches: everything moves.
    for p in [
        Params {
            driver: 77,
            ..Default::default()
        },
        Params {
            init: 77,
            ..Default::default()
        },
        Params {
            registry: 77,
            ..Default::default()
        },
    ] {
        let r3 = analyze(
            &Loader::new(),
            &f.record(&[app_object()], &[lib_archive(&p)]),
            &opts(),
        );
        assert_ne!(r3.harness_key, r1.harness_key);
        assert_ne!(key(&r3, "tests::a"), *a.key().unwrap());
        assert_ne!(key(&r3, "tests::b"), *b.key().unwrap());
    }
}

#[test]
fn reports_what_it_assumed_and_what_it_could_not_find() {
    let f = Fixture::new("report");
    let r = analyze(
        &Loader::new(),
        &f.record(&[app_object()], &[lib_archive(&Params::default())]),
        &opts(),
    );
    assert_eq!(r.unresolved_imports, ["puts"]);
    assert_eq!(r.missing_tests, ["tests::missing"]);
    let m = &r.tests["tests::missing"];
    assert!(
        m.fallback().unwrap().to_string().contains("tests::missing"),
        "{:?}",
        m.fallback()
    );
    assert_eq!(r.stats.archives, 1);
    assert!(r.stats.sccs > 0 && r.stats.relocations > 0);
}

#[test]
fn exercised_code_and_intersection() {
    let f = Fixture::new("exercised");
    let r = analyze(
        &Loader::new(),
        &f.record(&[app_object()], &[lib_archive(&Params::default())]),
        &opts(),
    );
    // The rlib is named libarch0-0123.rlib, so its crate is `arch0`.
    let ex_a = r.exercised("tests::a", &["arch0"]);
    let ex_b = r.exercised("tests::b", &["arch0"]);
    let names = |s: &std::collections::BTreeSet<u32>| -> Vec<String> {
        s.iter()
            .map(|&i| r.atom_table.symbol(i).to_string())
            .collect()
    };
    assert!(
        names(&ex_a).contains(&"helper_a".to_string()) && names(&ex_a).contains(&A.to_string())
    );
    assert!(!names(&ex_a).contains(&"helper_b".to_string()));
    // Both tests reach `shared` and the harness, so their exercised sets overlap.
    assert!(intersects(&ex_a, &ex_b));
    // Without the lib's crate named, only the test crate's own objects count.
    let own = r.exercised("tests::a", &[]);
    assert!(!names(&own).contains(&"helper_a".to_string()) && names(&own).contains(&A.to_string()));
    let only_a: std::collections::BTreeSet<u32> = ex_a.difference(&ex_b).copied().collect();
    let only_b: std::collections::BTreeSet<u32> = ex_b.difference(&ex_a).copied().collect();
    assert!(!intersects(&only_a, &only_b));
}

#[test]
fn result_does_not_depend_on_input_order() {
    let f = Fixture::new("order");
    let loader = Loader::new();
    let extra = ar(&[("x.o", {
        let mut o = Obj::new();
        o.func("unused_extra", 1, &[]);
        o.finish()
    })]);
    let r1 = analyze(
        &loader,
        &f.record(
            &[app_object()],
            &[lib_archive(&Params::default()), extra.clone()],
        ),
        &opts(),
    );
    let r2 = analyze(
        &loader,
        &f.record(&[app_object()], &[extra, lib_archive(&Params::default())]),
        &opts(),
    );
    for t in ["tests::a", "tests::b"] {
        assert_eq!(key(&r1, t), key(&r2, t), "{t}");
    }
    assert_eq!(r1.harness_key, r2.harness_key);
}

#[test]
fn duplicate_definitions_are_settled_by_link_order_or_the_test_falls_back() {
    let dup = |body: u8, weak: bool| -> Vec<u8> {
        let mut o = Obj::new();
        o.item(".text.dup", SectionKind::Text, "dup", &[body], &[], weak);
        o.finish()
    };
    let user_with = |dup_body: Option<u8>| {
        let mut o = Obj::new();
        o.func("main", 0, &[]);
        o.func(A, 0, &["dup"]);
        o.func(A_CLOSURE, 0, &[A]);
        o.func(B, 0, &[]);
        o.func(B_CLOSURE, 0, &[B]);
        if let Some(b) = dup_body {
            o.item(".text.dup", SectionKind::Text, "dup", &[b], &[], false);
        }
        o.finish()
    };
    let run = |name: &str, objects: Vec<Vec<u8>>, archives: Vec<Vec<u8>>| {
        let f = Fixture::new(name);
        let r = analyze(
            &Loader::new(),
            &f.record(&objects, &archives),
            &Options {
                crate_name: "app".into(),
                tests: vec!["tests::a".into(), "tests::b".into()],
                ..Default::default()
            },
        );
        r.verifiable.as_ref().unwrap();
        r
    };
    let falls_back_on_dup = |r: &keel_reach::BinaryReach| {
        matches!(
            r.tests["tests::a"].fallback(),
            Some(Fallback::DuplicateDefinition { symbol, definitions: 2, .. }) if symbol == "dup"
        )
    };

    // Two archives with different definitions of one name: which one the linker took depends
    // on which members it pulled in, which the record does not say. Whatever the strengths
    // and the order, a test that reaches the name falls back, naming it.
    for (i, (first, second)) in [
        (dup(1, false), dup(2, true)),
        (dup(2, true), dup(1, false)),
        (dup(1, true), dup(2, true)),
    ]
    .into_iter()
    .enumerate()
    {
        let r = run(
            &format!("dup-arch{i}"),
            vec![user_with(None)],
            vec![ar(&[("x.o", first)]), ar(&[("y.o", second)])],
        );
        assert!(falls_back_on_dup(&r), "case {i}: {:?}", r.tests["tests::a"].fallback());
        assert_eq!(
            r.tests["tests::a"].fallback().unwrap().kind(),
            "duplicate-definition"
        );
        assert!(
            r.tests["tests::b"].key().is_some(),
            "case {i}: a test that does not reach the name is still keyed"
        );
        assert_eq!(r.stats.unestablished_definitions, 1);
    }

    // A name the harness itself reaches is in every test's reach.
    let harness_user = {
        let mut o = Obj::new();
        o.func("main", 0, &["dup"]);
        o.func(A, 0, &[]);
        o.func(A_CLOSURE, 0, &[A]);
        o.func(B, 0, &[]);
        o.func(B_CLOSURE, 0, &[B]);
        o.finish()
    };
    let r = run("dup-harness", vec![harness_user], vec![ar(&[("x.o", dup(1, true))]), ar(&[("y.o", dup(2, true))])]);
    assert!(r.tests.values().all(|t| t.key().is_none() && t.fallback().is_some()));

    // Identical definitions are interchangeable: keyed, whatever the order.
    let same_ab = run("dup-same1", vec![user_with(None)], vec![ar(&[("x.o", dup(1, true))]), ar(&[("y.o", dup(1, true))])]);
    let same_ba = run("dup-same2", vec![user_with(None)], vec![ar(&[("y.o", dup(1, true))]), ar(&[("x.o", dup(1, true))])]);
    assert_eq!(key(&same_ab, "tests::a"), key(&same_ba, "tests::a"));
    assert_eq!(same_ab.stats.ambiguous_definitions, 0);

    // A plain object file is always linked, and first: its definition stands, and a
    // different one in an archive does not move the key.
    let with_archive = |body| run("dup-obj", vec![user_with(Some(7))], vec![ar(&[("x.o", dup(body, true))])]);
    let (o1, o2) = (with_archive(1), with_archive(2));
    assert_eq!(key(&o1, "tests::a"), key(&o2, "tests::a"));
    assert_ne!(
        key(&o1, "tests::a"),
        key(&run("dup-obj2", vec![user_with(Some(8))], vec![ar(&[("x.o", dup(1, true))])]), "tests::a"),
        "a different object definition is a different key"
    );
    assert_eq!(o1.stats.ambiguous_definitions, 1, "settled by order, and counted");
    assert_eq!(o1.stats.unestablished_definitions, 0);
}

#[test]
fn unknown_relocation_makes_the_binary_unverifiable_naming_the_object() {
    let f = Fixture::new("badreloc");
    let bad = {
        let mut o = Obj::new();
        let sec =
            o.0.add_section(vec![], b".text.bad".to_vec(), SectionKind::Text);
        o.0.append_section_data(sec, &[0; 8], 8);
        o.sym("bad_fn", Some(sec), false);
        let t = o.undefined("elsewhere");
        o.0.add_relocation(
            sec,
            Relocation {
                offset: 0,
                symbol: t,
                addend: 0,
                flags: RelocationFlags::Elf { r_type: 0x7777 },
            },
        )
        .unwrap();
        o.finish()
    };
    let r = analyze(
        &Loader::new(),
        &f.record(
            &[app_object()],
            &[ar(&[("bad.o", bad)]), lib_archive(&Params::default())],
        ),
        &opts(),
    );
    let why = r.verifiable.as_ref().unwrap_err();
    assert!(why.contains("bad.o") && why.contains("relocation"), "{why}");
    assert!(
        r.tests.values().all(|t| t.fallback().is_some()),
        "every test falls back to the executable key"
    );
}

#[test]
fn bitcode_and_missing_inputs_are_unverifiable() {
    let f = Fixture::new("bitcode");
    let r = analyze(
        &Loader::new(),
        &f.record(
            &[app_object()],
            &[ar(&[("lto.o", b"BC\xC0\xDEnot really".to_vec())])],
        ),
        &opts(),
    );
    assert!(r.verifiable.unwrap_err().contains("bitcode"));
    let mut rec = f.record(&[app_object()], &[lib_archive(&Params::default())]);
    rec.archives.push(f.dir.join("gone.rlib"));
    let why = analyze(&Loader::new(), &rec, &opts())
        .verifiable
        .unwrap_err();
    assert!(why.contains("gone.rlib"), "{why}");
}

#[test]
fn spawning_is_flagged_and_exe_identity_falls_back() {
    let f = Fixture::new("capabilities");
    let user = {
        let mut o = Obj::new();
        o.func("main", 0, &[]);
        o.func(A, 0, &["_ZN3std7process7Command3new17h0123456789abcdefE"]);
        o.func(A_CLOSURE, 0, &[A]);
        o.func(B, 0, &["_ZN3std3env11current_exe17h0123456789abcdefE"]);
        o.func(B_CLOSURE, 0, &[B]);
        o.finish()
    };
    let std_like = {
        let mut o = Obj::new();
        o.func("_ZN3std7process7Command3new17h0123456789abcdefE", 1, &[]);
        o.func("_ZN3std3env11current_exe17h0123456789abcdefE", 2, &[]);
        o.finish()
    };
    let r = analyze(
        &Loader::new(),
        &f.record(&[user], &[ar(&[("std.o", std_like)])]),
        &Options {
            crate_name: "app".into(),
            tests: vec!["tests::a".into(), "tests::b".into()],
            ..Default::default()
        },
    );
    r.verifiable.as_ref().unwrap();
    assert!(r.tests["tests::a"].spawns_processes && r.tests["tests::a"].fallback().is_none());
    let b = &r.tests["tests::b"];
    assert!(
        b.fallback().unwrap().to_string().contains("current_exe"),
        "{:?}",
        b.fallback()
    );
    assert!(
        !b.atoms().is_empty(),
        "reach data is still emitted for a fallback test"
    );
    assert!(b.crates.contains("std"));
}

#[test]
fn report_round_trips_through_json() {
    let f = Fixture::new("json");
    let r = analyze(
        &Loader::new(),
        &f.record(&[app_object()], &[lib_archive(&Params::default())]),
        &opts(),
    );
    let back: keel_reach::BinaryReach =
        serde_json::from_slice(&serde_json::to_vec(&r).unwrap()).unwrap();
    assert_eq!(back.tests["tests::a"], r.tests["tests::a"]);
    assert_eq!(back.harness_key, r.harness_key);
    let d = keel_reach::report::diff(&r, &back);
    assert_eq!(
        (d.changed, d.same, d.fallback),
        (0, 2, 1),
        "the missing test is a fallback"
    );
}

#[test]
fn adding_a_test_or_editing_a_descriptor_moves_only_that_tests_key() {
    let f = Fixture::new("add-rename");
    let lib = lib_archive(&Params::default());
    let run = |app: &App| {
        let o = Options { crate_name: "app".into(), tests: vec!["tests::a".into(), "tests::b".into(), "tests::c".into()], ..Default::default() };
        analyze(&Loader::new(), &f.record(&[app_object_with(app)], std::slice::from_ref(&lib)), &o)
    };
    let before = run(&App::default());
    // Adding test c changes the table, its length and `main`'s bytes.
    let added = run(&App { extra_test: true, ..App::default() });
    added.verifiable.as_ref().unwrap();
    assert_eq!(added.harness_key, before.harness_key, "table and main contents are not in the harness hash");
    assert_eq!(key(&added, "tests::a"), key(&before, "tests::a"));
    assert_eq!(key(&added, "tests::b"), key(&before, "tests::b"));
    assert!(added.tests["tests::c"].fallback().is_none(), "the new test has a key");
    assert_eq!(before.missing_tests, ["tests::c"]);
    // Moving a to another source file changes a's descriptor and nothing else.
    let renamed = run(&App { file_a: b"src/other.rs", ..App::default() });
    assert_ne!(key(&renamed, "tests::a"), key(&before, "tests::a"));
    assert_eq!(key(&renamed, "tests::b"), key(&before, "tests::b"));
    assert_eq!(renamed.harness_key, before.harness_key);
}

/// The reach key of a test that is keyed; a test that falls back has none to read.
fn key(r: &keel_reach::BinaryReach, t: &str) -> [u8; 32] {
    *r.tests[t]
        .key()
        .unwrap_or_else(|| panic!("{t} falls back: {:?}", r.tests[t].fallback()))
}

// ---------------------------------------------------------------------------------------
// Hardening pass: aliases, structured fallbacks, entries from descriptors, section
// boundaries, link-order, the key formula, the cache, and Mach-O subsections.

impl Obj {
    /// A second name at the address of `existing`.
    fn alias(&mut self, existing: SymbolId, name: &str) -> SymbolId {
        let SymbolSection::Section(sec) = self.0.symbol(existing).section else {
            panic!("alias of a symbol that is not in a section");
        };
        self.sym(name, Some(sec), false)
    }
}

const GROW_ONE: &str = "_ZN5alloc7raw_vec6RawVec8grow_one17h0123456789abcdefE";
const CURRENT_EXE: &str = "_ZN3std3env11current_exe17h0123456789abcdefE";

fn run_with(name: &str, objects: &[Vec<u8>], archives: &[Vec<u8>], tests: &[&str]) -> keel_reach::BinaryReach {
    let f = Fixture::new(name);
    let r = analyze(
        &Loader::new(),
        &f.record(objects, archives),
        &Options {
            crate_name: "app".into(),
            tests: tests.iter().map(|t| t.to_string()).collect(),
            ..Default::default()
        },
    );
    r.verifiable.as_ref().unwrap();
    r
}

#[test]
fn a_flag_on_a_second_name_of_an_atom_is_judged_and_named_as_such() {
    // Two symbols at one address, as LLVM leaves two functions it merged: the first names the
    // atom and is innocent, the second is `current_exe`. The verdict is the OR over names, and
    // the sentence names the symbol that carried the flag, not the one that names the atom.
    for flagged_first in [false, true] {
        let std_like = {
            let mut o = Obj::new();
            let (first, second) = if flagged_first { (CURRENT_EXE, GROW_ONE) } else { (GROW_ONE, CURRENT_EXE) };
            let id = o.func(first, 1, &[]);
            o.alias(id, second);
            o.finish()
        };
        let user = {
            let mut o = Obj::new();
            o.func("main", 0, &[]);
            // The caller references the atom by whichever name it has first.
            o.func(A, 0, &[if flagged_first { CURRENT_EXE } else { GROW_ONE }]);
            o.func(A_CLOSURE, 0, &[A]);
            o.func(B, 0, &[]);
            o.func(B_CLOSURE, 0, &[B]);
            o.finish()
        };
        let r = run_with(
            &format!("alias{flagged_first}"),
            &[user],
            &[ar(&[("std.o", std_like)])],
            &["tests::a", "tests::b"],
        );
        let Some(Fallback::CurrentExe(c)) = r.tests["tests::a"].fallback() else {
            panic!("{flagged_first}: {:?}", r.tests["tests::a"].fallback());
        };
        assert_eq!(c.callee, "std::env::current_exe");
        assert_eq!(
            c.alias_of.as_deref(),
            (!flagged_first).then_some("alloc::raw_vec::RawVec::grow_one"),
            "the atom's own name is given only when the flagged name is another one"
        );
        assert!(r.tests["tests::b"].key().is_some(), "an innocent neighbour is keyed");
        // Every name is kept in the report.
        let id = (0..r.atom_table.len() as u32)
            .find(|&i| r.atom_table.names(i).any(|n| n == CURRENT_EXE))
            .unwrap();
        assert_eq!(r.atom_table.names(id).count(), 2);
        assert_eq!(r.atom_table.aliases(id).count(), 1);
        // A query sees both names, or only the one the atom is known by.
        let any = keel_reach::query::query(&r, "current_exe", false).unwrap();
        let primary = keel_reach::query::query(&r, "current_exe", true).unwrap();
        assert_eq!(any.matched.len(), 1);
        assert_eq!(primary.matched.len(), u64::from(flagged_first));
    }
}

#[test]
fn fallbacks_are_structured_and_loading_a_library_says_the_executable_key_is_not_enough() {
    let user = {
        let mut o = Obj::new();
        o.func("main", 0, &[]);
        o.func(A, 0, &["dlopen"]);
        o.func(A_CLOSURE, 0, &[A]);
        o.func(B, 0, &[CURRENT_EXE]);
        o.func(B_CLOSURE, 0, &[B]);
        o.func(C, 0, &[]);
        o.func(C_CLOSURE, 0, &[C]);
        o.finish()
    };
    let std_like = {
        let mut o = Obj::new();
        o.func(CURRENT_EXE, 2, &[]);
        o.finish()
    };
    let r = run_with(
        "kinds",
        &[user],
        &[ar(&[("std.o", std_like)])],
        &["tests::a", "tests::b", "tests::c", "tests::gone"],
    );
    let kind = |t: &str| r.tests[t].fallback().map(Fallback::kind);
    assert_eq!(kind("tests::a"), Some("loads-library"));
    assert_eq!(kind("tests::b"), Some("current_exe"));
    assert_eq!(kind("tests::c"), None);
    assert_eq!(kind("tests::gone"), Some("no_entry"));
    let a = r.tests["tests::a"].fallback().unwrap();
    assert!(!a.exe_key_sufficient(), "a loaded library is outside the executable");
    assert!(a.to_string().contains("does NOT cover"), "{a}");
    assert!(r.tests["tests::b"].fallback().unwrap().exe_key_sufficient());
    // The record is a tagged object that names the callee and the caller.
    let j = serde_json::to_value(&r.tests["tests::b"]).unwrap();
    assert_eq!(j["fallback"]["kind"], "current_exe");
    assert_eq!(j["fallback"]["callee"], "std::env::current_exe");
    assert_eq!(j["fallback"]["caller"], "app::tests::b");
    assert!(j["key"].is_null(), "a test that falls back has no key to read: {j}");
    // Counts by (kind, caller).
    let counts = r.fallback_counts();
    assert_eq!(counts[&("current_exe".to_string(), "app::tests::b".to_string())], 1);
    assert_eq!(counts[&("loads-library".to_string(), "app::tests::a".to_string())], 1);
    assert_eq!(counts[&("no_entry".to_string(), "-".to_string())], 1);
}

#[test]
fn a_test_that_cannot_be_keyed_has_no_key_in_memory_or_on_disk() {
    let r = run_with("nokey", &[app_object()], &[lib_archive(&Params::default())], &["tests::a", "tests::missing"]);
    let m = &r.tests["tests::missing"];
    assert!(m.key().is_none() && m.fallback().is_some());
    // A report written by the old tool had an all-zero key beside a reason (or none).
    let mut j = serde_json::to_value(&r.tests["tests::a"]).unwrap();
    j["key"] = serde_json::json!("0".repeat(64));
    let back: keel_reach::TestReach = serde_json::from_value(j.clone()).unwrap();
    assert!(back.key().is_none(), "an all-zero key is never read as a key");
    assert_eq!(back.fallback().unwrap().kind(), "unverifiable");
    j["key"] = serde_json::Value::Null;
    let back: keel_reach::TestReach = serde_json::from_value(j).unwrap();
    assert!(back.key().is_none() && back.fallback().is_some(), "a record with neither is a fallback");
    // The compact form keeps the distinction too.
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("keel-reach-nokey");
    std::fs::create_dir_all(&dir).unwrap();
    keel_reach::store::write_compact(&r, &dir.join("r.json")).unwrap();
    let c = keel_reach::store::read(&dir.join("r.json")).unwrap();
    assert!(c.tests["tests::missing"].key().is_none());
    assert_eq!(c.tests["tests::a"].key(), r.tests["tests::a"].key());
    assert_eq!(c.tests["tests::missing"].fallback(), r.tests["tests::missing"].fallback());
}

/// The app of `app_object_with`, plus a test whose function and closure carry names that no
/// path spells, which only its descriptor can find.
fn app_with_unspellable_test(stray_symbol: bool) -> Vec<u8> {
    let mut o = Obj::new();
    o.func("main", 2, &["driver", "table"]);
    o.func(A, 0, &["helper_a"]);
    o.func(A_CLOSURE, 0, &[A]);
    o.data("name_a", SectionKind::ReadOnlyData, b"tests::a", &[]);
    o.descriptor("desc_a", A_CLOSURE, &[("name_a", 8)]);
    o.func("hidden_body", 5, &["helper_b"]);
    o.func("hidden_shim", 6, &["hidden_body"]);
    o.data("name_w", SectionKind::ReadOnlyData, b"tests::weird", &[]);
    o.descriptor("desc_w", "hidden_shim", &[("name_w", 12)]);
    if stray_symbol {
        // A function that the test path spells but the descriptor's function does not reach.
        o.func("_ZN3app5tests5weird17h0123456789abcdefE", 7, &["shared"]);
    }
    o.data("table", SectionKind::ReadOnlyDataWithRel, &[], &["desc_a", "desc_w"]);
    o.finish()
}

#[test]
fn entries_come_from_descriptors_and_the_path_spelled_name_is_a_cross_check() {
    let lib = lib_archive(&Params::default());
    let tests = ["tests::a", "tests::weird"];
    let r = run_with("entry", &[app_with_unspellable_test(false)], std::slice::from_ref(&lib), &tests);
    assert!(r.missing_tests.is_empty(), "{:?}", r.missing_tests);
    let w = &r.tests["tests::weird"];
    assert_eq!(w.entry, keel_reach::EntrySource::Descriptor);
    assert_eq!(r.stats.entries_from_descriptors, 2);
    let names: Vec<String> = w.atoms().iter().map(|i| r.atom_table.symbol(i).to_string()).collect();
    assert!(
        ["hidden_shim", "hidden_body", "helper_b", "desc_w", "name_w"].iter().all(|n| names.contains(&n.to_string())),
        "{names:?}"
    );
    assert!(!names.contains(&"helper_a".to_string()), "its own reach only: {names:?}");
    assert!(!r.harness_atoms.iter().any(|i| r.atom_table.symbol(i) == "hidden_body"), "the table does not reach the tests");

    // A function the path spells that the descriptor's function does not reach is a root
    // as well, and the disagreement is reported.
    let r = run_with("entry2", &[app_with_unspellable_test(true)], std::slice::from_ref(&lib), &tests);
    let w = &r.tests["tests::weird"];
    assert_eq!(w.entry, keel_reach::EntrySource::DescriptorAndName);
    assert!(w.atoms().iter().any(|i| r.atom_table.symbol(i).contains("5weird")));
    assert!(r.notes.iter().any(|n| n.contains("does not reach")), "{:?}", r.notes);
    // Not a test of the list: no descriptor, no guess, no entry.
    let r = run_with("entry3", &[app_with_unspellable_test(false)], &[lib], &["tests::a", "tests::weird", "tests::nope"]);
    assert_eq!(r.missing_tests, ["tests::nope"]);
    let Some(Fallback::NoEntry { detail, .. }) = r.tests["tests::nope"].fallback() else { panic!() };
    assert!(detail.contains("descriptors were read"), "{detail}");
}

#[test]
fn only_validated_libtest_descriptors_get_the_table_treatment() {
    // A user table of function pointers to tests, and code that walks it. Neither is
    // libtest's: the table has no (pointer, length) names, so nothing is cut, and the
    // walker keeps its bytes and its edges.
    let user = |walker_body: u8| {
        let mut o = Obj::new();
        o.func("main", 2, &["driver", "walker"]);
        o.func("walker", walker_body, &["user_table"]);
        o.func(A, 0, &["helper_a"]);
        o.func(A_CLOSURE, 0, &[A]);
        o.func(B, 0, &["helper_b"]);
        o.func(B_CLOSURE, 0, &[B]);
        o.data("name_a", SectionKind::ReadOnlyData, b"tests::a", &[]);
        o.data("name_b", SectionKind::ReadOnlyData, b"tests::b", &[]);
        o.descriptor("desc_a", A_CLOSURE, &[("name_a", 8)]);
        o.descriptor("desc_b", B_CLOSURE, &[("name_b", 8)]);
        // The user's own table points straight at the test functions.
        o.data("user_table", SectionKind::ReadOnlyDataWithRel, &[], &[A_CLOSURE, B_CLOSURE]);
        o.data("table", SectionKind::ReadOnlyDataWithRel, &[], &["desc_a", "desc_b"]);
        o.finish()
    };
    let lib = lib_archive(&Params::default());
    let r1 = run_with("usertable1", &[user(1)], std::slice::from_ref(&lib), &["tests::a", "tests::b"]);
    let harness: Vec<String> = r1.harness_atoms.iter().map(|i| r1.atom_table.symbol(i).to_string()).collect();
    assert!(
        harness.contains(&"helper_a".to_string()) && harness.contains(&"helper_b".to_string()),
        "the walker reaches both tests through the user's table: {harness:?}"
    );
    // The walker's bytes are in the key of every test.
    let r2 = run_with("usertable2", &[user(2)], &[lib], &["tests::a", "tests::b"]);
    assert_ne!(r1.harness_key, r2.harness_key);
    assert_ne!(key(&r1, "tests::a"), key(&r2, "tests::a"));
}

#[test]
fn a_reference_to_a_section_boundary_reaches_every_atom_of_the_section_and_only_for_its_reachers() {
    // `reg_one` and `reg_two` sit in section `keel_reg`; only test a's helper refers to the
    // boundary. Tests that cannot reach the reference do not reach the section.
    let app = || {
        let mut o = Obj::new();
        o.func("main", 2, &["table"]);
        o.func(A, 0, &["scanner"]);
        o.func(A_CLOSURE, 0, &[A]);
        o.func(B, 0, &[]);
        o.func(B_CLOSURE, 0, &[B]);
        o.data("name_a", SectionKind::ReadOnlyData, b"tests::a", &[]);
        o.data("name_b", SectionKind::ReadOnlyData, b"tests::b", &[]);
        o.descriptor("desc_a", A_CLOSURE, &[("name_a", 8)]);
        o.descriptor("desc_b", B_CLOSURE, &[("name_b", 8)]);
        o.data("table", SectionKind::ReadOnlyDataWithRel, &[], &["desc_a", "desc_b"]);
        o.finish()
    };
    let lib = |registry: u8| {
        let mut o = Obj::new();
        o.func("scanner", 3, &["__start_keel_reg", "__stop_keel_reg"]);
        for (i, n) in ["reg_one", "reg_two"].iter().enumerate() {
            let sec = o.0.add_section(vec![], b"keel_reg".to_vec(), SectionKind::Data);
            o.0.append_section_data(sec, &[registry + i as u8; 8], 8);
            o.sym(n, Some(sec), false);
        }
        ar(&[("lib.o", o.finish())])
    };
    let r1 = run_with("bounds1", &[app()], &[lib(5)], &["tests::a", "tests::b"]);
    let names = |t: &str| -> Vec<String> {
        r1.tests[t].atoms().iter().map(|i| r1.atom_table.symbol(i).to_string()).collect()
    };
    assert!(names("tests::a").contains(&"reg_one".to_string()) && names("tests::a").contains(&"reg_two".to_string()));
    assert!(!names("tests::b").contains(&"reg_one".to_string()));
    assert!(!r1.harness_atoms.iter().any(|i| r1.atom_table.symbol(i) == "reg_one"));
    let s = &r1.section_sets[0];
    assert_eq!((s.section.as_str(), s.atoms), ("keel_reg", 2));
    assert!(s.symbols.contains(&"__start_keel_reg".to_string()) && s.symbols.contains(&"__stop_keel_reg".to_string()));
    // Changing a registered atom changes a's key and not b's.
    let r2 = run_with("bounds2", &[app()], &[lib(9)], &["tests::a", "tests::b"]);
    assert_ne!(key(&r1, "tests::a"), key(&r2, "tests::a"));
    assert_eq!(key(&r1, "tests::b"), key(&r2, "tests::b"));
}

#[test]
fn boundary_symbols_of_both_formats_name_their_sections() {
    use keel_reach::link::boundary_key;
    assert_eq!(boundary_key("__start_keel_reg").as_deref(), Some("keel_reg"));
    assert_eq!(boundary_key("__stop_keel_reg").as_deref(), Some("keel_reg"));
    assert_eq!(boundary_key("section$start$__DATA$__linkme").as_deref(), Some("__DATA,__linkme"));
    assert_eq!(boundary_key("section$end$__DATA$__linkme").as_deref(), Some("__DATA,__linkme"));
    // A leading underscore, which a compiler that does not know the symbol is special adds.
    assert_eq!(boundary_key("_section$start$__DATA$__linkme").as_deref(), Some("__DATA,__linkme"));
    assert_eq!(boundary_key("segment$start$__DATA").as_deref(), Some("segment:__DATA"));
    assert_eq!(boundary_key("_malloc"), None);
    assert_eq!(boundary_key("__start_"), None);
}

#[test]
fn the_root_key_tells_the_same_builds_apart_as_the_key_over_every_component() {
    // Mutate one reachable atom at a time; every test's key under both formulas must change
    // together or not at all, across every pair of builds.
    let tests = ["tests::a", "tests::b", "tests::missing"];
    let variants = [
        Params::default(),
        Params { helper_a: 77, ..Default::default() },
        Params { helper_b: 77, ..Default::default() },
        Params { driver: 77, ..Default::default() },
        Params { init: 77, ..Default::default() },
        Params { registry: 77, ..Default::default() },
    ];
    let mut roots = Vec::new();
    let mut closure = Vec::new();
    for (i, p) in variants.iter().enumerate() {
        for (flag, out) in [(false, &mut roots), (true, &mut closure)] {
            let f = Fixture::new(&format!("keyform{i}{flag}"));
            let r = analyze(
                &Loader::new(),
                &f.record(&[app_object()], &[lib_archive(p)]),
                &Options {
                    crate_name: "app".into(),
                    tests: tests.iter().map(|t| t.to_string()).collect(),
                    closure_key: flag,
                    ..Default::default()
                },
            );
            out.push(
                ["tests::a", "tests::b"].map(|t| key(&r, t)),
            );
        }
    }
    for i in 0..variants.len() {
        for j in 0..variants.len() {
            for t in 0..2 {
                assert_eq!(
                    roots[i][t] == roots[j][t],
                    closure[i][t] == closure[j][t],
                    "builds {i} and {j}, test {t}: the two formulas disagree about whether the key moved"
                );
            }
        }
    }
    // And the mutations themselves are seen: helper_a moves a and not b; the driver moves both.
    assert_ne!(roots[0][0], roots[1][0]);
    assert_eq!(roots[0][1], roots[1][1]);
    assert_ne!(roots[0][0], roots[3][0]);
    assert_ne!(roots[0][1], roots[3][1]);
}

#[test]
fn the_cache_serves_unchanged_objects_and_survives_damage() {
    let f = Fixture::new("cache");
    let cache = f.dir.join("cache");
    let rec = f.record(&[app_object()], &[lib_archive(&Params::default())]);
    let o = opts();
    let uncached = analyze(&Loader::new(), &rec, &o);
    let first = Loader::with_cache(cache.clone()).unwrap();
    let cold = analyze(&first, &rec, &o);
    assert!(cold.stats.members_parsed > 0 && cold.stats.members_from_cache == 0);
    let second = Loader::with_cache(cache.clone()).unwrap();
    let warm = analyze(&second, &rec, &o);
    assert_eq!(warm.stats.members_parsed, 0, "nothing is parsed twice");
    assert!(warm.stats.members_from_cache > 0);
    for r in [&cold, &warm] {
        assert_eq!(r.harness_key, uncached.harness_key);
        for t in o.tests.iter() {
            assert_eq!(r.tests[t], uncached.tests[t], "{t}");
        }
        assert_eq!(r.atom_table, uncached.atom_table);
    }
    // A damaged entry is a miss: the object is parsed again and the entry replaced.
    let victim = walk(&cache).into_iter().find(|p| p.is_file()).unwrap();
    let mut bytes = std::fs::read(&victim).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    std::fs::write(&victim, &bytes).unwrap();
    let third = Loader::with_cache(cache.clone()).unwrap();
    let repaired = analyze(&third, &rec, &o);
    assert_eq!(repaired.stats.members_parsed, 1);
    assert_eq!(repaired.tests, warm.tests);
    let fourth = Loader::with_cache(cache).unwrap();
    assert_eq!(analyze(&fourth, &rec, &o).stats.members_parsed, 0, "the entry was rewritten");
}

fn walk(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    for e in std::fs::read_dir(dir).unwrap().flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk(&p));
        } else {
            out.push(p);
        }
    }
    out
}

#[test]
fn compare_names_what_changed_and_query_finds_symbols() {
    let a = run_with("cmp-a", &[app_object()], &[lib_archive(&Params::default())], &["tests::a", "tests::b"]);
    let same = run_with("cmp-a", &[app_object()], &[lib_archive(&Params::default())], &["tests::a", "tests::b"]);
    assert!(keel_reach::compare::compare(&a, &same).is_identical());
    let b = run_with(
        "cmp-a",
        &[app_object()],
        &[lib_archive(&Params { helper_a: 77, ..Default::default() })],
        &["tests::a", "tests::b"],
    );
    let c = keel_reach::compare::compare(&a, &b);
    let keys: Vec<&str> = c.differences["key"].iter().map(|d| d.0.as_str()).collect();
    assert_eq!(keys, ["tests::a"], "{:?}", c.differences.keys().collect::<Vec<_>>());
    let reach: Vec<&str> = c.differences["reach"].iter().map(|d| d.0.as_str()).collect();
    assert_eq!(reach, ["tests::a"]);
    assert!(c.differences["reach"][0].1.contains("atoms only in first"), "{:?}", c.differences["reach"]);
    assert_eq!(c.unexplained(&["key".into(), "reach".into()]), 0);
    assert!(c.unexplained(&["key".into()]) > 0);
    // Query: which tests reach `helper_a`.
    let q = keel_reach::query::query(&a, "^helper_a$", false).unwrap();
    let hit = |t: &str| q.rows.iter().find(|h| h.test == t).unwrap().reaches;
    assert!(hit("tests::a") && !hit("tests::b"));
    assert_eq!(q.matched.len(), 1);
    assert!(keel_reach::query::query(&a, "(", false).is_err());
}

// ---- Mach-O ---------------------------------------------------------------------------

/// An arm64 Mach-O object with two functions in `__text`, the first falling through into
/// the second, and a section-boundary reference from the first.
fn macho_object(subsections: bool) -> Vec<u8> {
    let mut o = object::write::Object::new(BinaryFormat::MachO, Architecture::Aarch64, Endianness::Little);
    // The writer leaves the flag off unless asked.
    o.flags = object::FileFlags::MachO {
        flags: if subsections { object::macho::MH_SUBSECTIONS_VIA_SYMBOLS } else { 0 },
    };
    let text = o.section_id(object::write::StandardSection::Text);
    o.append_section_data(text, &[0x1f, 0x20, 0x03, 0xd5, 0xc0, 0x03, 0x5f, 0xd6], 4);
    for (name, value) in [("_first", 0u64), ("_second", 4)] {
        o.add_symbol(Symbol {
            name: name.into(),
            value,
            size: 4,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
    }
    o.write().unwrap()
}

#[test]
fn a_mach_o_object_without_subsections_is_one_atom_per_section() {
    let dir = Fixture::new("macho").dir;
    for (subsections, atoms) in [(true, 2), (false, 1)] {
        let p = dir.join(format!("m{subsections}.o"));
        std::fs::write(&p, macho_object(subsections)).unwrap();
        let file = Loader::new().open(&p, false, None, false).unwrap();
        assert!(file.problem.is_none());
        let m = &file.members[0];
        assert_eq!(m.atoms.len(), atoms, "subsections {subsections}");
        assert_eq!(m.whole_sections, !subsections);
        if !subsections {
            // Both names are still there, one of them an alias of the whole.
            assert_eq!(m.aliases_of(0).len(), 1);
            assert_eq!(m.atoms[0].size, 8);
        }
    }
    // The oracle switch splits it anyway.
    let p = dir.join("mfalse.o");
    let mut l = Loader::new();
    l.assume_subsections = true;
    assert_eq!(l.open(&p, false, None, false).unwrap().members[0].atoms.len(), 2);
}

#[test]
fn the_linkers_own_list_of_inputs_decides_what_dash_l_named() {
    // `-lfoo` is a static library the compiler driver found on its own (no -L directory
    // has it), and `-lSystem` a dynamic one. Searching the -L directories would call both
    // dynamic imports; the linker's list says otherwise.
    let f = Fixture::new("deps");
    let mut rec = f.record(&[app_object()], &[]);
    let foo = f.dir.join("libfoo.a");
    std::fs::write(&foo, lib_archive(&Params::default())).unwrap();
    rec.libs = vec!["foo".into(), "System".into()];
    let deps = f.dir.join("bin.keel-deps");
    let mut bytes = vec![0x00];
    bytes.extend(b"ld 1.0\0");
    for (op, p) in [(0x10u8, foo.display().to_string()), (0x10, "/usr/lib/libSystem.tbd".to_string())] {
        bytes.push(op);
        bytes.extend(p.as_bytes());
        bytes.push(0);
    }
    std::fs::write(&deps, bytes).unwrap();
    rec.dependency_file = Some(deps);
    rec.dependency_flavour = "ld64".into();
    let with = analyze(&Loader::new(), &rec, &opts());
    with.verifiable.as_ref().unwrap();
    assert_eq!(with.stats.archives, 1, "libfoo.a was read by the linker");
    assert!(key(&with, "tests::a") != [0; 32]);
    assert_eq!(with.unkeyed_inputs.len(), 1);
    assert!(with.unkeyed_inputs[0].contains("libSystem.tbd"), "{:?}", with.unkeyed_inputs);
    // Without the list the same record reports each `-l` it could not find as an unkeyed input.
    rec.dependency_file = None;
    let without = analyze(&Loader::new(), &rec, &opts());
    assert_eq!(without.stats.archives, 0);
    assert_eq!(without.unkeyed_inputs.len(), 2);
    assert!(without.unkeyed_inputs.iter().any(|u| u.starts_with("-lfoo")));
}

#[test]
fn an_unbound_record_is_refused_when_verification_is_asked_for() {
    let f = Fixture::new("verify");
    let rec = f.record(&[app_object()], &[lib_archive(&Params::default())]);
    let path = keel_reach::record::record_path(&rec.output);
    std::fs::write(&path, serde_json::to_vec(&rec).unwrap()).unwrap();
    let mut o = opts();
    let loader = Loader::new();
    assert!(keel_reach::analyze_record(&loader, &path, &o).verifiable.is_ok(), "not asked: not checked");
    o.verify_record = true;
    let r = keel_reach::analyze_record(&loader, &path, &o);
    let why = r.verifiable.unwrap_err();
    assert!(why.contains("relink with keel-linker") || why.contains("no output hash"), "{why}");
    assert!(r.tests.values().all(|t| t.key().is_none() && t.fallback().is_some()));
}

// ---- literal sections -----------------------------------------------------------------

/// A test crate whose tests `a` and `b` each point at one string of a merge-strings section.
/// `lead` is text put before both, to move them.
fn string_app(lead: &[u8], body_a: u8) -> Vec<u8> {
    let mut o = Obj::new();
    o.func("main", 0, &[]);
    let strs = o.0.add_section(vec![], b".rodata.str1.1".to_vec(), SectionKind::ReadOnlyString);
    let mut pool = lead.to_vec();
    let (off_a, off_b) = (pool.len() as u64, (pool.len() + 6) as u64);
    pool.extend(b"alpha\0beta\0");
    o.0.append_section_data(strs, &pool, 1);
    let sym = o.0.section_symbol(strs);
    for (name, off, body) in [(A, off_a, body_a), (B, off_b, 2)] {
        let sec = o.0.add_section(vec![], format!(".text.{name}").into_bytes(), SectionKind::Text);
        o.0.append_section_data(sec, &[0, 0, 0, 0, 0, 0, 0, 0, body], 8);
        o.sym(name, Some(sec), false);
        o.0.add_relocation(
            sec,
            Relocation {
                offset: 0,
                symbol: sym,
                addend: off as i64,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::Absolute,
                    encoding: RelocationEncoding::Generic,
                    size: 64,
                },
            },
        )
        .unwrap();
    }
    o.func(A_CLOSURE, 0, &[A]);
    o.func(B_CLOSURE, 0, &[B]);
    o.finish()
}

#[test]
fn adding_a_string_before_two_others_changes_neither_function_nor_key() {
    let tests = ["tests::a", "tests::b"];
    let before = run_with("lit1", &[string_app(b"", 1)], &[], &tests);
    let after = run_with("lit2", &[string_app(b"new\0", 1)], &[], &tests);
    for t in tests {
        assert_eq!(key(&before, t), key(&after, t), "{t}: its string did not change");
    }
    let content = |r: &keel_reach::BinaryReach, name: &str| {
        let t = &r.atom_table;
        let i = (0..t.len() as u32).find(|&i| t.symbol(i) == name).unwrap();
        (t.content[i as usize], t.bytes_hash[i as usize], t.reloc_hash[i as usize])
    };
    for f in [A, B] {
        assert_eq!(content(&before, f), content(&after, f), "{f}: addend is the offset within the string");
    }
    let strings = |r: &keel_reach::BinaryReach| (0..r.atom_table.len()).filter(|&i| r.atom_table.class[i] == 3).count();
    assert_eq!((strings(&before), strings(&after)), (2, 2), "only the strings a test reaches are in a reach");
    // Changing the string a test points at changes that test and not the other.
    let changed = run_with("lit3", &[string_app(b"", 1)], &[], &tests);
    assert_eq!(key(&before, "tests::a"), key(&changed, "tests::a"));
    let edit = {
        let mut o = Obj::new();
        o.func("main", 0, &[]);
        let strs = o.0.add_section(vec![], b".rodata.str1.1".to_vec(), SectionKind::ReadOnlyString);
        o.0.append_section_data(strs, b"alpha\0BETA\0", 1);
        let sym = o.0.section_symbol(strs);
        for (name, off) in [(A, 0i64), (B, 6)] {
            let sec = o.0.add_section(vec![], format!(".text.{name}").into_bytes(), SectionKind::Text);
            o.0.append_section_data(sec, &[0, 0, 0, 0, 0, 0, 0, 0, if name == A { 1 } else { 2 }], 8);
            o.sym(name, Some(sec), false);
            o.0.add_relocation(sec, Relocation {
                offset: 0, symbol: sym, addend: off,
                flags: RelocationFlags::Generic { kind: RelocationKind::Absolute, encoding: RelocationEncoding::Generic, size: 64 },
            }).unwrap();
        }
        o.func(A_CLOSURE, 0, &[A]);
        o.func(B_CLOSURE, 0, &[B]);
        o.finish()
    };
    let edited = run_with("lit4", &[edit], &[], &tests);
    assert_eq!(key(&before, "tests::a"), key(&edited, "tests::a"));
    assert_ne!(key(&before, "tests::b"), key(&edited, "tests::b"));
}

#[test]
fn the_atom_listing_tells_a_changed_atom_from_the_ones_it_only_affects() {
    let list = |name: &str, obj: Vec<u8>| {
        let f = Fixture::new(name);
        let rec = f.record(&[obj], &[]);
        keel_reach::atoms::list(&Loader::new(), &rec, "app").unwrap()
    };
    let a = list("atoms1", string_app(b"", 1));
    // A new string moves nothing that already existed.
    let b = list("atoms2", string_app(b"new\0", 1));
    let c = keel_reach::atoms::changed(&a, &b);
    assert_eq!(c.new_local.len(), 1, "{:?}", c.new_local);
    assert_eq!(c.new_local[0].class, "cstring");
    assert_eq!(c.propagation, 0);
    // A new body for `a`: its own bytes changed, and what reaches it is only affected.
    let d = list("atoms3", string_app(b"", 9));
    let c = keel_reach::atoms::changed(&a, &d);
    assert_eq!(c.by_class["text"].0, 1);
    assert_eq!(c.text_new_bytes.len(), 1);
    assert_eq!(c.text_addends_only, 0);
    assert!(c.propagation >= 1, "the closure that calls it changed only by reach");
    assert!(keel_reach::atoms::render(&c, 3).contains("1 have new bytes"));
    // The listing round-trips through its file form.
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join("keel-reach-atoms");
    std::fs::create_dir_all(&dir).unwrap();
    for name in ["l.tsv", "l.tsv.zst"] {
        keel_reach::atoms::write(&a, &dir.join(name)).unwrap();
        assert_eq!(keel_reach::atoms::read(&dir.join(name)).unwrap(), a);
    }
}

/// An arm64 Mach-O object: `_f` and `_g` point into one `__cstring` by section-relative
/// relocation, `_h` by a symbol at the section start plus an offset (the `ltmp<n>` form).
fn macho_strings(lead: &[u8]) -> Vec<u8> {
    let mut o = object::write::Object::new(BinaryFormat::MachO, Architecture::Aarch64, Endianness::Little);
    o.flags = object::FileFlags::MachO { flags: object::macho::MH_SUBSECTIONS_VIA_SYMBOLS };
    let strs = o.section_id(object::write::StandardSection::ReadOnlyString);
    let mut pool = lead.to_vec();
    let base = pool.len() as i64;
    pool.extend(b"alpha\0beta\0gamma\0");
    o.append_section_data(strs, &pool, 1);
    let sec_sym = o.section_symbol(strs);
    let start = o.add_symbol(Symbol {
        name: b"ltmp0".to_vec(),
        value: 0,
        size: 0,
        kind: SymbolKind::Data,
        scope: SymbolScope::Compilation,
        weak: false,
        section: SymbolSection::Section(strs),
        flags: SymbolFlags::None,
    });
    let text = o.section_id(object::write::StandardSection::Text);
    let mut at = 0u64;
    for (name, sym, add) in [("_f", sec_sym, base), ("_g", sec_sym, base + 6), ("_h", start, base + 11)] {
        o.append_section_data(text, &[0u8; 8], 8);
        o.add_symbol(Symbol {
            name: name.into(),
            value: at,
            size: 8,
            kind: SymbolKind::Text,
            scope: SymbolScope::Dynamic,
            weak: false,
            section: SymbolSection::Section(text),
            flags: SymbolFlags::None,
        });
        o.add_relocation(
            text,
            Relocation {
                offset: at,
                symbol: sym,
                addend: add,
                flags: RelocationFlags::Generic {
                    kind: RelocationKind::Absolute,
                    encoding: RelocationEncoding::Generic,
                    size: 64,
                },
            },
        )
        .unwrap();
        at += 8;
    }
    o.write().unwrap()
}

#[test]
fn mach_o_literals_are_one_atom_per_string_and_ltmp_plus_offset_names_the_string() {
    let dir = Fixture::new("macho-lit").dir;
    let load = |name: &str, lead: &[u8]| {
        let p = dir.join(name);
        std::fs::write(&p, macho_strings(lead)).unwrap();
        let file = Loader::new().open(&p, false, None, false).unwrap();
        assert!(file.problem.is_none(), "{:?}", file.problem);
        file.members[0].data.clone()
    };
    let (m1, m2) = (load("a.o", b""), load("b.o", b"new\0"));
    let strings = |m: &keel_reach::model::MemberData| {
        m.atoms
            .iter()
            .filter(|a| m.sections[a.section as usize].class == keel_reach::model::SecClass::CString)
            .count()
    };
    assert_eq!((strings(&m1), strings(&m2)), (3, 4));
    // The three functions are the three text atoms; each one's hashes ignore the new string
    // and each addend is the offset within its own string (0), whichever form it was written in.
    let text = |m: &keel_reach::model::MemberData| -> Vec<_> {
        m.atoms
            .iter()
            .filter(|a| m.sections[a.section as usize].role == keel_reach::model::Role::Code)
            .map(|a| (a.content, m.atom_relocs(a).iter().map(|r| r.addend).collect::<Vec<_>>()))
            .collect()
    };
    let (t1, t2) = (text(&m1), text(&m2));
    assert_eq!(t1.len(), 3);
    assert_eq!(t1, t2);
    assert!(t1.iter().all(|(_, addends)| addends == &[0]), "{t1:?}");
}

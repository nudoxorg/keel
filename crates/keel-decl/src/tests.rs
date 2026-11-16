use super::*;
use proptest::prelude::*;

fn decl(m: &str, f: &str, s: &[&str], j: &[&str]) -> Declaration {
    Declaration {
        module_path: m.into(),
        test_fn: f.into(),
        stands_on: s.iter().map(|x| x.to_string()).collect(),
        joins: j.iter().map(|x| x.to_string()).collect(),
    }
}

fn ident() -> impl Strategy<Value = String> {
    "[a-zA-Z_][a-zA-Z0-9_]{0,12}"
}

fn entry() -> impl Strategy<Value = String> {
    // `=` and `:` are legal inside entries; only NUL, newline and comma are not.
    "[a-zA-Z0-9_()=:-]{1,20}"
}

fn declaration() -> impl Strategy<Value = Declaration> {
    (
        prop::collection::vec(ident(), 1..5),
        ident(),
        prop::collection::vec(entry(), 0..4),
        prop::collection::vec(entry(), 0..4),
    )
        .prop_map(|(path, test_fn, stands_on, joins)| Declaration {
            module_path: path.join("::"),
            test_fn,
            stands_on,
            joins,
        })
}

proptest! {
    #[test]
    fn single_record_round_trips(d in declaration()) {
        let bytes = encode(&d);
        prop_assert_eq!(decode_section(bytes.as_bytes()).unwrap(), vec![d]);
    }

    #[test]
    fn concatenated_padded_records_round_trip(
        decls in prop::collection::vec(declaration(), 0..8),
        pads in prop::collection::vec(0usize..9, 9),
    ) {
        // Distinct names: same-name records are the duplicate/conflict cases.
        let decls: Vec<_> = decls.into_iter().enumerate().map(|(i, mut d)| {
            d.test_fn = format!("{}_{i}", d.test_fn);
            d
        }).collect();
        let mut bytes = vec![0u8; pads[8]];
        for (d, pad) in decls.iter().zip(&pads) {
            bytes.extend_from_slice(encode(d).as_bytes());
            bytes.resize(bytes.len() + pad, 0);
        }
        prop_assert_eq!(decode_section(&bytes).unwrap(), decls);
    }

    #[test]
    fn any_cut_inside_a_record_is_reported_at_its_offset(d in declaration(), cut in 1usize..1000) {
        let first = encode(&d);
        let second = encode(&Declaration { test_fn: format!("{}_2", d.test_fn), ..d.clone() });
        let cut = cut % (second.len() - 1) + 1; // keep at least one byte, never the whole record
        let mut bytes = first.clone().into_bytes();
        bytes.extend_from_slice(&second.as_bytes()[..cut]);
        prop_assert_eq!(
            decode_section(&bytes),
            Err(DecodeError::TruncatedRecord { offset: first.len() })
        );
    }

    #[test]
    fn nextest_name_drops_exactly_the_root(d in declaration()) {
        let root = d.module_path.split("::").next().unwrap().to_owned();
        let name = try_nextest_test_name(&d, &root).unwrap();
        let rest: Vec<&str> = d.module_path.split("::").skip(1).collect();
        let expected: Vec<&str> = rest.into_iter().chain([d.test_fn.as_str()]).collect();
        prop_assert_eq!(name, expected.join("::"));
    }
}

#[test]
fn matches_the_verified_macro_snippet_plus_terminator() {
    let rec = concat!(
        "m::a::test_fn",
        "\0",
        "stands_on=unit(backend-version),unit(backend-platform)",
        "\0",
        "joins=backend-store,backend-flow",
        "\0",
        "\n"
    );
    let d = decl(
        "m::a",
        "test_fn",
        &["unit(backend-version)", "unit(backend-platform)"],
        &["backend-store", "backend-flow"],
    );
    assert_eq!(encode(&d), rec);
    assert_eq!(decode_section(rec.as_bytes()).unwrap(), vec![d]);
}

#[test]
fn keys_in_any_order_and_absent_keys_are_empty() {
    let swapped = b"m::f\0joins=x\0stands_on=unit(y)\0\n";
    assert_eq!(
        decode_section(swapped).unwrap(),
        vec![decl("m", "f", &["unit(y)"], &["x"])]
    );
    let bare = b"m::f\0\n";
    assert_eq!(
        decode_section(bare).unwrap(),
        vec![decl("m", "f", &[], &[])]
    );
    let only_joins = b"m::f\0joins=x,y\0\n";
    assert_eq!(
        decode_section(only_joins).unwrap(),
        vec![decl("m", "f", &[], &["x", "y"])]
    );
}

#[test]
fn empty_and_all_zero_sections_are_empty() {
    assert_eq!(decode_section(b"").unwrap(), vec![]);
    assert_eq!(decode_section(&[0; 64]).unwrap(), vec![]);
}

#[test]
fn zero_padding_anywhere_between_records_is_skipped() {
    let a = encode(&decl("m", "a", &[], &["x"]));
    let b = encode(&decl("m", "b", &["unit(y)"], &[]));
    let mut bytes = vec![0; 3];
    bytes.extend(a.as_bytes());
    bytes.extend([0; 7]);
    bytes.extend(b.as_bytes());
    bytes.extend([0; 5]);
    let got = decode_section(&bytes).unwrap();
    assert_eq!(
        got.iter().map(|d| d.test_fn.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
}

#[test]
fn trailing_partial_record_names_its_offset() {
    let a = encode(&decl("m", "a", &[], &[]));
    let mut bytes = a.clone().into_bytes();
    bytes.extend([0; 3]);
    let partial_at = bytes.len();
    bytes.extend(b"m::b\0stands_on=unit(x");
    let err = decode_section(&bytes).unwrap_err();
    assert_eq!(err, DecodeError::TruncatedRecord { offset: partial_at });
    assert!(
        err.to_string()
            .contains(&format!("byte offset {partial_at}"))
    );
}

#[test]
fn exact_duplicates_keep_the_first() {
    let a = encode(&decl("m", "a", &["unit(x)"], &[]));
    let b = encode(&decl("m", "b", &[], &[]));
    let bytes = format!("{a}{b}{a}{b}{a}");
    let got = decode_section(bytes.as_bytes()).unwrap();
    assert_eq!(
        got.iter().map(|d| d.test_fn.as_str()).collect::<Vec<_>>(),
        ["a", "b"]
    );
}

#[test]
fn same_name_with_different_edges_is_an_error_not_a_silent_pick() {
    let a = encode(&decl("m", "a", &["unit(x)"], &[]));
    let b = encode(&decl("m", "a", &["unit(z)"], &[]));
    let err = decode_section(format!("{a}{b}").as_bytes()).unwrap_err();
    assert_eq!(
        err,
        DecodeError::ConflictingRecords {
            name: "m::a".into(),
            first: 0,
            second: a.len()
        }
    );
}

#[test]
fn corruption_is_reported_with_the_record_offset() {
    let good = encode(&decl("m", "a", &[], &[]));
    let cases: &[(&[u8], &str)] = &[
        (b"no_separator\0\n", "not `<module path>::<fn>`"),
        (b"m::f\0stands_on=x\n", "does not end with a NUL"),
        (b"m::f\0bogus=1\0\n", "unknown key `bogus`"),
        (b"m::f\0stands_on\0\n", "not `key=value`"),
        (b"m::f\0joins=a,,b\0\n", "empty entry"),
        (b"m::f\0joins=a\0joins=b\0\n", "appears twice"),
        (b"m::f\0joins=\xff\0\n", "not valid UTF-8"),
        (b"::f\0\n", "not `<module path>::<fn>`"),
        (b"m::\0\n", "not `<module path>::<fn>`"),
    ];
    for (bad, needle) in cases {
        let mut bytes = good.clone().into_bytes();
        bytes.extend(*bad);
        match decode_section(&bytes) {
            Err(DecodeError::MalformedRecord { offset, reason }) => {
                assert_eq!(offset, good.len(), "{needle}");
                assert!(reason.contains(needle), "{reason} should mention {needle}");
            }
            other => panic!("expected MalformedRecord for {needle}, got {other:?}"),
        }
    }
}

#[test]
fn encode_refuses_what_decode_could_not_recover() {
    for bad in [
        decl("", "f", &[], &[]),
        decl("m", "", &[], &[]),
        decl("m", "a::b", &[], &[]),
        decl("m\0", "f", &[], &[]),
        decl("m", "f", &["a,b"], &[]),
        decl("m", "f", &[], &[""]),
        decl("m", "f", &["a\nb"], &[]),
    ] {
        assert!(try_encode(&bad).is_err(), "{bad:?}");
    }
}

#[test]
fn stands_on_forms() {
    for ok in [
        "unit(backend-store)",
        "integration(backend_flow)",
        "rust:backend-store::wal::replays_torn_tail",
        "a::b",
    ] {
        assert_eq!(validate_stands_on(ok), Ok(()), "{ok}");
    }
    for bad in [
        "",
        "unit()",
        "unit(Backend)",
        "unit(a b)",
        "units(a)",
        "unit(a",
        "backend-store",
        "unit(a::b)",
        "a::b,c::d",
        "a:: b",
        "e2e(a)",
    ] {
        let err = validate_stands_on(bad).unwrap_err();
        assert!(err.contains("accepted forms"), "{bad}: {err}");
    }
}

#[test]
fn join_forms() {
    for ok in ["backend-store", "backend_store", "a1"] {
        assert_eq!(validate_join(ok), Ok(()), "{ok}");
    }
    for bad in ["", "Backend", "a b", "a::b", "a,b", "a.b"] {
        assert!(validate_join(bad).is_err(), "{bad}");
    }
}

#[test]
fn nextest_names() {
    let lib = decl("backend_store::wal::tests", "replays_torn_tail", &[], &[]);
    assert_eq!(
        nextest_test_name(&lib, "backend-store"),
        "wal::tests::replays_torn_tail"
    );
    let root = decl("backend_store", "smoke", &[], &[]);
    assert_eq!(nextest_test_name(&root, "backend-store"), "smoke");
    let wrong = decl("other::t", "f", &[], &[]);
    assert_eq!(try_nextest_test_name(&wrong, "backend-store"), None);
}

#[cfg(debug_assertions)]
#[test]
#[should_panic(expected = "does not belong to binary")]
fn nextest_name_panics_in_debug_on_a_foreign_declaration() {
    nextest_test_name(&decl("other::t", "f", &[], &[]), "backend-store");
}

mod reader {
    //! The reader is exercised on real object files produced by `object`'s
    //! writer for each container format, because the fixture test below only
    //! covers the host platform.
    use super::*;
    use object::write::Object as Out;
    use object::{Architecture, BinaryFormat, Endianness, SectionKind};
    use std::path::PathBuf;

    fn temp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("keel-decl-tests-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir.join(name)
    }

    fn write_object(
        file: &str,
        format: BinaryFormat,
        arch: Architecture,
        segment: &str,
        section: &str,
        data: &[u8],
    ) -> PathBuf {
        let mut o = Out::new(format, arch, Endianness::Little);
        let id = o.add_section(segment.into(), section.into(), SectionKind::Data);
        o.append_section_data(id, data, 8);
        let path = temp(file);
        std::fs::write(&path, o.write().unwrap()).unwrap();
        path
    }

    fn payload() -> (Vec<u8>, Vec<Declaration>) {
        let a = decl("t::a", "x", &["unit(p)"], &["p", "q"]);
        let b = decl("t::b", "y", &[], &["q"]);
        let mut bytes = encode(&a).into_bytes();
        bytes.extend([0; 3]); // alignment padding between records
        bytes.extend(encode(&b).as_bytes());
        (bytes, vec![a, b])
    }

    #[test]
    fn elf_section_is_read() {
        let (bytes, want) = payload();
        let p = write_object(
            "a.elf",
            BinaryFormat::Elf,
            Architecture::X86_64,
            "",
            ".keel",
            &bytes,
        );
        assert_eq!(read_declarations(&p).unwrap(), want);
    }

    #[test]
    fn macho_section_is_read_only_in_the_data_segment() {
        let (bytes, want) = payload();
        let p = write_object(
            "a.macho",
            BinaryFormat::MachO,
            Architecture::Aarch64,
            "__DATA",
            "__keel",
            &bytes,
        );
        assert_eq!(read_declarations(&p).unwrap(), want);
        // Same section name in another segment is not ours.
        let p = write_object(
            "b.macho",
            BinaryFormat::MachO,
            Architecture::Aarch64,
            "__TEXT",
            "__keel",
            &bytes,
        );
        assert_eq!(read_declarations(&p).unwrap(), vec![]);
    }

    #[test]
    fn coff_section_is_read() {
        let (bytes, want) = payload();
        let p = write_object(
            "a.obj",
            BinaryFormat::Coff,
            Architecture::X86_64,
            "",
            ".keel",
            &bytes,
        );
        assert_eq!(read_declarations(&p).unwrap(), want);
    }

    #[test]
    fn binary_without_the_section_has_no_declarations() {
        let p = write_object(
            "none.elf",
            BinaryFormat::Elf,
            Architecture::X86_64,
            "",
            ".data",
            b"zz",
        );
        assert_eq!(read_declarations(&p).unwrap(), vec![]);
        let p = write_object(
            "none.macho",
            BinaryFormat::MachO,
            Architecture::Aarch64,
            "__DATA",
            "__other",
            b"zz",
        );
        assert_eq!(read_declarations(&p).unwrap(), vec![]);
    }

    #[test]
    fn corrupt_section_error_names_the_file_and_offset() {
        let p = write_object(
            "bad.elf",
            BinaryFormat::Elf,
            Architecture::X86_64,
            "",
            ".keel",
            b"t::a\0joins=p",
        );
        let msg = read_declarations(&p).unwrap_err().to_string();
        assert!(
            msg.contains("bad.elf") && msg.contains("byte offset 0"),
            "{msg}"
        );
    }

    #[test]
    fn unknown_format_names_the_file() {
        let p = temp("script.sh");
        std::fs::write(&p, "#!/bin/sh\necho hi\n").unwrap();
        let err = read_declarations(&p).unwrap_err();
        assert!(matches!(err, ReadError::UnknownFormat { .. }));
        assert!(err.to_string().contains("script.sh"));
    }

    #[test]
    fn missing_file_names_the_file() {
        let err = read_declarations(&temp("does-not-exist")).unwrap_err();
        assert!(matches!(err, ReadError::Open { .. }));
        assert!(err.to_string().contains("does-not-exist"));
    }
}

#[test]
fn applies_to_is_equality_or_a_double_colon_prefix() {
    let yes = [
        ("tests::param", "tests::param"),
        ("tests::param", "tests::param::case_1"),
        ("tests::param", "tests::param::case_2::label_x"),
        ("smoke", "smoke"),
        ("smoke", "smoke::case_1"),
    ];
    for (decl, test) in yes {
        assert!(applies_to(decl, test), "{decl} should cover {test}");
    }
    let no = [
        ("tests::param", "tests::param_other"),
        ("tests::param", "tests::par"),
        ("tests::param", "tests"),
        ("tests::param", "other::tests::param"),
        ("tests::param", "tests::param:case"),
        ("smoke", ""),
    ];
    for (decl, test) in no {
        assert!(!applies_to(decl, test), "{decl} should not cover {test}");
    }
}

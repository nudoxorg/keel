//! Scanner behaviour on small sources: paths, attributes, complexity, hashes.

use keel_index::parse::{RawItem, scan_source};

fn items(src: &str) -> Vec<RawItem> {
    let scan = scan_source(src);
    assert_eq!(scan.parse_error, None, "fixture must parse");
    scan.items
}

fn find<'a>(items: &'a [RawItem], path: &str) -> &'a RawItem {
    items.iter().find(|i| i.path == path).unwrap_or_else(|| {
        panic!(
            "no item {path}; have {:?}",
            items.iter().map(|i| &i.path).collect::<Vec<_>>()
        )
    })
}

#[test]
fn module_paths_impls_and_trait_defaults() {
    let it = items(
        r#"
pub fn free() {}
mod wal {
    pub mod tests {
        pub fn replays_torn_tail() {}
    }
}
pub struct Ledger;
impl Ledger {
    pub fn open() {}
}
impl<T> Wrapper<T> where T: Copy {
    fn get(&self) {}
}
impl std::fmt::Display for Ledger {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { Ok(()) }
}
impl std::fmt::Debug for Ledger {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result { Ok(()) }
}
trait Shape {
    fn required(&self);
    fn provided(&self) { }
}
"#,
    );
    let paths: Vec<&str> = it.iter().map(|i| i.path.as_str()).collect();
    assert_eq!(
        paths,
        [
            "free",
            "wal::tests::replays_torn_tail",
            "Ledger::open",
            "Wrapper::get",
            "<Ledger as Display>::fmt",
            "<Ledger as Debug>::fmt",
            "Shape::provided",
        ]
    );
}

#[test]
fn nested_fns_and_closures_are_not_items() {
    let it = items("fn outer() { fn inner() {} let c = || { 1 }; c(); inner(); }");
    assert_eq!(it.len(), 1);
    assert_eq!(it[0].path, "outer");
}

#[test]
fn test_attribute_variants() {
    let it = items(
        r#"
#[test] fn plain() {}
#[tokio::test] async fn tokio_style() {}
#[tokio::test(flavor = "multi_thread")] async fn tokio_args() {}
#[rstest] fn rstest_style() {}
#[test_case(1)] fn test_case_style() {}
#[proptest] fn proptest_style() {}
#[some::framework::test] fn custom_test() {}
#[test] #[ignore] fn ignored_one() {}
#[test] #[ignore = "slow"] fn ignored_with_reason() {}
fn helper() {}
#[cfg(test)] fn cfg_helper() {}
#[inline] fn attr_but_not_test() {}
"#,
    );
    for n in [
        "plain",
        "tokio_style",
        "tokio_args",
        "rstest_style",
        "test_case_style",
        "proptest_style",
        "custom_test",
        "ignored_one",
        "ignored_with_reason",
    ] {
        assert!(find(&it, n).is_test, "{n} should be a test");
    }
    for n in ["helper", "cfg_helper", "attr_but_not_test"] {
        assert!(!find(&it, n).is_test, "{n} should not be a test");
    }
    assert!(find(&it, "ignored_one").ignored);
    assert!(find(&it, "ignored_with_reason").ignored);
    assert!(!find(&it, "plain").ignored);
}

#[test]
fn cfg_test_detection() {
    let it = items(
        r#"
fn plain() {}
#[cfg(test)] mod tests { #[test] fn inside() {} mod deeper { fn deep() {} } }
#[cfg(all(test, feature = "x"))] mod all_test { fn a() {} }
#[cfg(not(test))] mod not_test { fn b() {} }
#[cfg(any(test, feature = "x"))] mod any_test { fn c() {} }
#[cfg(test)] fn gated_fn() {}
#[cfg(test)] impl S { fn gated_method() {} }
"#,
    );
    let t = |n: &str| find(&it, n).cfg_test;
    assert!(!t("plain"));
    assert!(t("tests::inside"));
    assert!(t("tests::deeper::deep"));
    assert!(t("all_test::a"));
    assert!(!t("not_test::b"));
    assert!(
        !t("any_test::c"),
        "any(test, other) also compiles outside tests"
    );
    assert!(t("gated_fn"));
    assert!(t("S::gated_method"));
}

#[test]
fn branch_count_matches_a_hand_count() {
    let it = items(
        r#"
pub fn busy(a: i32, v: Vec<i32>) -> Option<i32> {
    if a > 0 && a < 10 {
        return None;
    } else if a == 3 || a == 4 {
        return Some(1);
    }
    let _m = match a { 1 => 1, 2 => 2, _ => 3 };
    while a < 0 {}
    for _x in &v {}
    loop { break; }
    let first = v.first()?;
    let c = |z: bool| if z { 1 } else { 2 };
    fn inner(q: bool) -> bool { if q { true } else { false } }
    println!("{}", if a > 1 { 1 } else { 2 });
    Some(*first + c(true) + i32::from(inner(true)))
}
"#,
    );
    // if, &&                      = 2
    // else-if, ||                 = 2  (4)
    // match with 3 arms           = 2  (6)
    // while, for, loop, ?         = 4  (10)
    // closure's if                = 1  (11)
    // nested fn's if              = 1  (12)
    // the if inside println!      = 0, macro bodies are opaque
    assert_eq!(it[0].branches, 12);
}

#[test]
fn doc_comment_edit_changes_tokens_and_ordinary_comment_edits_do_not() {
    // A doc comment is code to rustdoc (a doctest), so it is part of the item's tokens; the
    // signature is what callers can write, and rewording prose does not change it.
    let a = items("/// old words\nfn f(x: i32) -> i32 {\n    // note\n    x + 1\n}\n");
    let b = items(
        "/// completely different\n/// and longer\nfn f(x: i32) -> i32 {\n\n    x + 1 // other note\n}\n",
    );
    assert_ne!(a[0].tokens, b[0].tokens);
    assert_eq!(a[0].signature, b[0].signature);
    let c = items("/// old words\nfn f(x: i32) -> i32 {\n\n    x + 1 // another note\n}\n");
    assert_eq!(a[0].tokens, c[0].tokens, "ordinary comments and whitespace are still not tokens");
    assert_ne!(
        a[0].end_line, b[0].end_line,
        "positions move; hashes must not"
    );
}

#[test]
fn body_edit_changes_tokens_not_signature() {
    let a = items("fn f(x: i32) -> i32 { x + 1 }");
    let b = items("fn f(x: i32) -> i32 { x + 2 }");
    assert_ne!(a[0].tokens, b[0].tokens);
    assert_eq!(a[0].signature, b[0].signature);
}

#[test]
fn signature_edit_changes_both() {
    let a = items("fn f(x: i32) -> i32 { x + 1 }");
    let b = items("fn f(x: i64) -> i32 { x + 1 }");
    assert_ne!(a[0].tokens, b[0].tokens);
    assert_ne!(a[0].signature, b[0].signature);
    let c = items("#[inline] fn f(x: i32) -> i32 { x + 1 }");
    assert_ne!(
        a[0].signature, c[0].signature,
        "attributes are part of the signature"
    );
}

#[test]
fn lines_cover_attributes_and_body() {
    let it = items("\n\n#[test]\n/// doc\nfn f() {\n    let a = 1;\n}\n");
    assert_eq!((it[0].start_line, it[0].end_line), (3, 7));
}

#[test]
fn syntax_error_is_reported_not_fatal() {
    let scan = scan_source("fn broken( {");
    assert!(scan.parse_error.is_some());
    assert!(scan.items.is_empty());
}

#[test]
fn proptest_macro_items_are_found() {
    let it = items(
        r#"
proptest! {
    #![proptest_config(ProptestConfig::with_cases(8))]
    #[test]
    fn roundtrips(x in 0..100i32, y in any::<u8>()) {
        if x > 5 { prop_assert!(true); }
    }
    #[test] #[ignore]
    fn second(s in "[a-z]+") -> Result<(), TestCaseError> { Ok(()) }
}
mod m {
    proptest! { #[test] fn nested(x in 0..3) { } }
}
"#,
    );
    assert!(find(&it, "roundtrips").is_test);
    assert_eq!(find(&it, "roundtrips").branches, 1);
    assert!(find(&it, "second").ignored);
    assert!(find(&it, "m::nested").is_test);
}

#[test]
fn unparseable_proptest_macro_is_ignored() {
    let it = items("proptest! { this is not the shape }\nfn after() {}");
    assert_eq!(it.len(), 1);
}

#[test]
fn outside_hash_ignores_fn_bodies_but_not_other_items() {
    let base = scan_source("use a::b;\nconst N: u32 = 1;\nfn f() { 1 }\n").outside;
    let body = scan_source("use a::b;\nconst N: u32 = 1;\nfn f() { 2 }\nfn g() {}\n").outside;
    let konst = scan_source("use a::b;\nconst N: u32 = 2;\nfn f() { 1 }\n").outside;
    let useline = scan_source("use a::c;\nconst N: u32 = 1;\nfn f() { 1 }\n").outside;
    assert_eq!(base, body);
    assert_ne!(base, konst);
    assert_ne!(base, useline);
}

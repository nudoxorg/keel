//! Compile-level behaviour of the attributes: what is accepted, and the text
//! of what is refused. Regenerate expected errors with `TRYBUILD=overwrite`
//! after reading the diff.

#[test]
fn ui() {
    let t = trybuild::TestCases::new();
    t.pass("tests/ui/pass/*.rs");
    t.compile_fail("tests/ui/fail/*.rs");
}

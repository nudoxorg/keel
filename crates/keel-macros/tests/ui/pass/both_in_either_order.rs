// Two attributes on one fn must yield one record (a second would be a
// duplicate-definition error), whichever is outermost. #[test] is not used here
// because it deletes the fn when not compiling with --test; the fixture crate
// covers #[test] in every position.
use keel_macros::{joins, stands_on};

#[stands_on("unit(backend-store)", "integration(backend-flow)")]
#[joins(backend_store, backend_flow)]
#[test]
fn stands_on_outer() {}

#[joins(backend_store, "backend-flow")]
#[test]
#[stands_on("unit(backend-store)", "integration(backend-flow)")]
#[allow(dead_code)]
fn joins_outer() {}

fn record(bytes: &[u8]) -> keel_decl::Declaration {
    let mut all = keel_decl::decode_section(bytes).unwrap();
    assert_eq!(all.len(), 1);
    all.remove(0)
}

fn main() {
    for (name, bytes) in [
        ("stands_on_outer", &__KEEL_DECL_stands_on_outer[..]),
        ("joins_outer", &__KEEL_DECL_joins_outer[..]),
    ] {
        let d = record(bytes);
        assert_eq!(d.test_fn, name);
        assert_eq!(d.module_path, module_path!());
        assert_eq!(d.stands_on, ["unit(backend-store)", "integration(backend-flow)"]);
        assert_eq!(d.joins, ["backend-store", "backend-flow"]);
    }
}

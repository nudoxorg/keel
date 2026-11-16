use keel_macros::{joins, stands_on};

#[test]
#[stands_on("unit(keel-fixture)")]
#[joins(keel_fixture, backend_flow)]
fn top_level() {}

mod cases {
    use keel_macros::stands_on;

    #[test]
    #[stands_on("integration(keel-fixture)")]
    fn inside_module() {}
}

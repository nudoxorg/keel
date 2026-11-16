#[cfg(test)]
use keel_macros::stands_on;

pub fn double(x: u32) -> u32 {
    x * 2
}

#[cfg(test)]
mod tests {
    use super::*;
    use keel_macros::{joins, stands_on};

    // Both attributes, stands_on outermost, #[test] first.
    #[test]
    #[stands_on("unit(backend-version)", "unit(backend-platform)")]
    #[joins(backend_store, backend_flow)]
    fn both_stands_on_first() {
        assert_eq!(double(2), 4);
    }

    // Both attributes, joins outermost, #[test] last, other attributes between.
    /// A doc comment is an attribute too.
    #[joins(backend_store, "backend-flow")]
    #[stands_on("integration(backend-flow)")]
    #[allow(clippy::eq_op)]
    #[test]
    fn both_joins_first() {
        assert_eq!(double(1), 2);
    }

    #[test]
    #[stands_on("unit(backend-version)")]
    fn only_stands_on() {}

    #[joins(backend_store)]
    #[test]
    fn only_joins() {}

    // #[test] outside the keel attribute: it expands first.
    #[test]
    #[should_panic]
    #[stands_on("rust:backend-store::wal::replays_torn_tail")]
    fn node_id_and_should_panic() {
        panic!("expected");
    }

    #[test]
    fn undeclared() {}

    // Async: the retention reference goes inside the generated runtime body.
    #[tokio::test]
    #[stands_on("unit(backend-version)")]
    async fn async_tokio_outer() {
        tokio::task::yield_now().await;
    }

    #[stands_on("unit(backend-version)")]
    #[tokio::test]
    #[should_panic(expected = "boom")]
    async fn async_keel_outer_should_panic() {
        panic!("boom");
    }

    // rstest turns one fn into `param::case_1`, `param::case_2`.
    #[stands_on("unit(backend-version)")]
    #[rstest::rstest]
    #[case(1)]
    #[case(2)]
    fn param(#[case] x: u32) {
        assert!(x > 0);
    }

    // Same fn name in sibling modules must yield two distinct records.
    mod a {
        #[test]
        #[super::stands_on("unit(a)")]
        fn t() {}
    }
    mod b {
        #[test]
        #[super::stands_on("unit(b)")]
        fn t() {}
    }

    mod nested {
        #[test]
        #[super::stands_on("unit(backend-version)")]
        fn deep() {}
    }
}

#[cfg(test)]
#[test]
#[stands_on("unit(backend-platform)")]
fn at_crate_root() {}

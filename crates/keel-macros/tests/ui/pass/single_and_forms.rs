// Either attribute alone, node ids, raw identifiers, async and pub fns, and
// other attributes carried through unchanged.
use keel_macros::{joins, stands_on};

#[stands_on("rust:backend-store::wal::replays_torn_tail")]
fn node_id() {}

#[joins(backend_store)]
/// docs survive
#[must_use]
pub fn only_joins() -> u8 {
    1
}

#[keel_macros::stands_on("unit(backend-store)")]
async fn is_async() {}

#[stands_on("unit(a)")]
fn r#match() {}

fn main() {
    let d = keel_decl::decode_section(&__KEEL_DECL_node_id).unwrap().remove(0);
    assert_eq!((d.stands_on.len(), d.joins.len()), (1, 0));

    let d = keel_decl::decode_section(&__KEEL_DECL_only_joins).unwrap().remove(0);
    assert_eq!((d.stands_on.len(), d.joins.as_slice()), (0, &["backend-store".to_string()][..]));
    assert_eq!(only_joins(), 1);

    let _ = is_async();
    assert_eq!(keel_decl::decode_section(&__KEEL_DECL_match).unwrap()[0].test_fn, "match");
}

use keel_macros::stands_on;

#[stands_on("backend-store")]
fn bare_crate_name() {}

#[stands_on("unit(Backend Store)")]
fn bad_crate_inside_group() {}

fn main() {}

use keel_macros::{joins, stands_on};

#[stands_on("unit(a)")]
#[stands_on("unit(b)")]
fn two_stands_on() {}

#[joins(a)]
#[test]
#[joins(b)]
fn two_joins() {}

fn main() {}

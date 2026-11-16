//! Serde adapter: a 32-byte hash as 64 hex digits. A JSON array of 32 numbers
//! is five times larger and an index holds hundreds of thousands of hashes.

use serde::{Deserialize, Deserializer, Serializer, de::Error};

const DIGITS: &[u8; 16] = b"0123456789abcdef";

pub fn to_hex(h: &[u8; 32]) -> String {
    let mut s = String::with_capacity(64);
    for b in h {
        s.push(DIGITS[(b >> 4) as usize] as char);
        s.push(DIGITS[(b & 15) as usize] as char);
    }
    s
}

pub fn from_hex(s: &str) -> Option<[u8; 32]> {
    let b = s.as_bytes();
    if b.len() != 64 {
        return None;
    }
    let nib = |c: u8| match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        _ => None,
    };
    let mut out = [0u8; 32];
    for (i, o) in out.iter_mut().enumerate() {
        *o = nib(b[2 * i])? << 4 | nib(b[2 * i + 1])?;
    }
    Some(out)
}

pub fn serialize<S: Serializer>(h: &[u8; 32], s: S) -> Result<S::Ok, S::Error> {
    // Stack buffer: this runs hundreds of thousands of times per save.
    let mut buf = [0u8; 64];
    for (i, b) in h.iter().enumerate() {
        buf[2 * i] = DIGITS[(b >> 4) as usize];
        buf[2 * i + 1] = DIGITS[(b & 15) as usize];
    }
    s.serialize_str(std::str::from_utf8(&buf).map_err(serde::ser::Error::custom)?)
}

pub fn deserialize<'de, D: Deserializer<'de>>(d: D) -> Result<[u8; 32], D::Error> {
    let s = <std::borrow::Cow<'de, str>>::deserialize(d)?;
    from_hex(&s).ok_or_else(|| D::Error::custom("expected 64 lowercase hex digits"))
}

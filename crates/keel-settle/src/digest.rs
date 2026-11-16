//! A 32-byte blake3 digest, written as 64 lowercase hex characters.

use serde::{Deserialize, Deserializer, Serialize, Serializer};
use std::fmt;

#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Digest([u8; 32]);

impl Digest {
    pub fn of(domain: &str, bytes: &[u8]) -> Digest {
        // The domain is framed with a NUL so no domain is a prefix of another's input.
        let mut h = blake3::Hasher::new();
        h.update(domain.as_bytes());
        h.update(&[0]);
        h.update(bytes);
        Digest(*h.finalize().as_bytes())
    }

    pub fn parse(s: &str) -> Result<Digest, String> {
        if s.len() != 64 || !s.bytes().all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)) {
            return Err(format!("{s:?} is not a digest: expected 64 lowercase hex characters"));
        }
        let mut out = [0u8; 32];
        for (i, o) in out.iter_mut().enumerate() {
            *o = u8::from_str_radix(&s[2 * i..2 * i + 2], 16).map_err(|e| e.to_string())?;
        }
        Ok(Digest(out))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for b in self.0 {
            write!(f, "{b:02x}")?;
        }
        Ok(())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Digest({self})")
    }
}

impl Serialize for Digest {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.collect_str(self)
    }
}

impl<'de> Deserialize<'de> for Digest {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Digest, D::Error> {
        let s = String::deserialize(d)?;
        Digest::parse(&s).map_err(serde::de::Error::custom)
    }
}

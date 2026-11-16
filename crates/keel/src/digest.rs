//! Content digests as they appear in manifests, keys and the store.

use std::fmt;
use std::str::FromStr;

/// A 32-byte content digest tagged with the algorithm that produced it.
///
/// Everything Keel computes is blake3. SHA-256 exists only so a Nix node can
/// carry the derivation hash it was handed (`sha256:<drv hash>`) without
/// re-hashing it: the conductor cannot recompute a hash the Nix store
/// already vouches for. The text form is `<algorithm>:<64 lowercase hex>`.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub enum Digest {
    /// A blake3 digest, the only algorithm Keel produces itself.
    Blake3([u8; 32]),
    /// A SHA-256 digest taken from a Nix derivation, never computed here.
    Sha256([u8; 32]),
}

/// Why a string is not a [`Digest`].
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DigestParseError {
    /// There was no `algorithm:` prefix or the algorithm is not supported.
    #[error("digest `{0}` must start with `blake3:` or `sha256:` followed by 64 hex digits")]
    Algorithm(String),
    /// The hex part was not exactly 64 lowercase or uppercase hex digits.
    #[error("digest `{0}` must carry exactly 64 hex digits after the algorithm prefix")]
    Hex(String),
}

impl Digest {
    /// Hashes `bytes` with blake3.
    pub fn of(bytes: &[u8]) -> Self {
        Digest::Blake3(*blake3::hash(bytes).as_bytes())
    }

    /// The algorithm prefix used in the text form.
    pub fn algorithm(&self) -> &'static str {
        match self {
            Digest::Blake3(_) => "blake3",
            Digest::Sha256(_) => "sha256",
        }
    }

    /// The raw 32 bytes.
    pub fn as_bytes(&self) -> &[u8; 32] {
        match self {
            Digest::Blake3(b) | Digest::Sha256(b) => b,
        }
    }

    /// The 64-character lowercase hex of the raw bytes (no algorithm prefix).
    pub fn to_hex(&self) -> String {
        const HEX: &[u8; 16] = b"0123456789abcdef";
        let mut out = String::with_capacity(64);
        for b in self.as_bytes() {
            out.push(HEX[(b >> 4) as usize] as char);
            out.push(HEX[(b & 15) as usize] as char);
        }
        out
    }

    /// Algorithm tag plus bytes, the form fed into key hashing so a blake3
    /// and a SHA-256 digest with equal bytes cannot be confused.
    pub(crate) fn framed(&self) -> [u8; 33] {
        let mut out = [0u8; 33];
        out[0] = match self {
            Digest::Blake3(_) => 1,
            Digest::Sha256(_) => 2,
        };
        out[1..].copy_from_slice(self.as_bytes());
        out
    }
}

fn from_hex(s: &str) -> Option<[u8; 32]> {
    if s.len() != 64 || !s.is_ascii() {
        return None;
    }
    let mut out = [0u8; 32];
    for (i, pair) in s.as_bytes().chunks(2).enumerate() {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out[i] = (hi * 16 + lo) as u8;
    }
    Some(out)
}

impl FromStr for Digest {
    type Err = DigestParseError;

    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let (algo, hex) = s
            .split_once(':')
            .ok_or_else(|| DigestParseError::Algorithm(s.into()))?;
        let make: fn([u8; 32]) -> Digest = match algo {
            "blake3" => Digest::Blake3,
            "sha256" => Digest::Sha256,
            _ => return Err(DigestParseError::Algorithm(s.into())),
        };
        from_hex(hex)
            .map(make)
            .ok_or_else(|| DigestParseError::Hex(s.into()))
    }
}

impl fmt::Display for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}:{}", self.algorithm(), self.to_hex())
    }
}

impl fmt::Debug for Digest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn text_form_round_trips_for_both_algorithms() {
        let d = Digest::of(b"keel");
        assert_eq!(d.to_string().parse::<Digest>().unwrap(), d);
        let s = Digest::Sha256([7; 32]);
        assert!(s.to_string().starts_with("sha256:0707"));
        assert_eq!(s.to_string().parse::<Digest>().unwrap(), s);
    }

    #[test]
    fn rejects_bad_prefix_and_bad_hex() {
        assert!(matches!(
            "md5:00".parse::<Digest>(),
            Err(DigestParseError::Algorithm(_))
        ));
        assert!(matches!(
            "deadbeef".parse::<Digest>(),
            Err(DigestParseError::Algorithm(_))
        ));
        assert!(matches!(
            "blake3:xyz".parse::<Digest>(),
            Err(DigestParseError::Hex(_))
        ));
        let short = format!("blake3:{}", "ab".repeat(31));
        assert!(matches!(
            short.parse::<Digest>(),
            Err(DigestParseError::Hex(_))
        ));
    }

    #[test]
    fn equal_bytes_under_different_algorithms_differ() {
        assert_ne!(Digest::Blake3([1; 32]), Digest::Sha256([1; 32]));
        assert_ne!(
            Digest::Blake3([1; 32]).framed(),
            Digest::Sha256([1; 32]).framed()
        );
    }
}

//! Tagged, length-prefixed hashing shared by every key in the crate.
//!
//! Each field is `tag (1 byte) ‖ length (u64 LE) ‖ bytes`. Because the length
//! precedes the bytes, no two different sequences of fields can produce the
//! same byte stream; because the tag precedes the length, a value cannot
//! migrate from one field to its neighbour.

use crate::digest::Digest;

pub(crate) struct Framer(blake3::Hasher);

impl Framer {
    /// Starts a hash in its own domain so, say, an env key can never equal a
    /// files key over coincidentally equal fields.
    pub(crate) fn new(domain: &str) -> Self {
        let mut f = Framer(blake3::Hasher::new());
        f.field(0, domain.as_bytes());
        f
    }

    pub(crate) fn field(&mut self, tag: u8, bytes: &[u8]) -> &mut Self {
        self.0.update(&[tag]);
        self.0.update(&(bytes.len() as u64).to_le_bytes());
        self.0.update(bytes);
        self
    }

    /// Like [`field`](Self::field) for section-sized inputs: blake3 splits
    /// large buffers across the rayon pool and gives the identical digest.
    pub(crate) fn field_large(&mut self, tag: u8, bytes: &[u8]) -> &mut Self {
        self.0.update(&[tag]);
        self.0.update(&(bytes.len() as u64).to_le_bytes());
        self.0.update_rayon(bytes);
        self
    }

    /// An optional string. `None` and `Some("")` must differ, hence the
    /// presence byte.
    pub(crate) fn opt_str(&mut self, tag: u8, value: Option<&str>) -> &mut Self {
        match value {
            None => self.field(tag, &[0]),
            Some(s) => {
                let mut buf = Vec::with_capacity(s.len() + 1);
                buf.push(1);
                buf.extend_from_slice(s.as_bytes());
                self.field(tag, &buf)
            }
        }
    }

    pub(crate) fn opt_digest(&mut self, tag: u8, value: Option<&Digest>) -> &mut Self {
        match value {
            None => self.field(tag, &[0]),
            Some(d) => {
                let mut buf = [0u8; 34];
                buf[0] = 1;
                buf[1..].copy_from_slice(&d.framed());
                self.field(tag, &buf)
            }
        }
    }

    /// A list of strings as one field: count, then each item length-prefixed.
    pub(crate) fn strings<'a>(
        &mut self,
        tag: u8,
        items: impl IntoIterator<Item = &'a str>,
    ) -> &mut Self {
        let mut buf = Vec::new();
        let mut n = 0u64;
        for s in items {
            n += 1;
            buf.extend_from_slice(&(s.len() as u64).to_le_bytes());
            buf.extend_from_slice(s.as_bytes());
        }
        let mut payload = n.to_le_bytes().to_vec();
        payload.extend_from_slice(&buf);
        self.field(tag, &payload)
    }

    pub(crate) fn finish(&self) -> Digest {
        Digest::Blake3(*self.0.finalize().as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn field_boundaries_cannot_shift() {
        let mut a = Framer::new("t");
        a.field(1, b"ab").field(2, b"c");
        let mut b = Framer::new("t");
        b.field(1, b"a").field(2, b"bc");
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn absent_and_empty_differ() {
        let mut a = Framer::new("t");
        a.opt_str(1, None);
        let mut b = Framer::new("t");
        b.opt_str(1, Some(""));
        assert_ne!(a.finish(), b.finish());
    }

    #[test]
    fn domains_separate() {
        assert_ne!(Framer::new("a").finish(), Framer::new("b").finish());
    }

    #[test]
    fn large_and_small_paths_agree() {
        let data = vec![9u8; 1 << 20];
        let mut a = Framer::new("t");
        a.field(1, &data);
        let mut b = Framer::new("t");
        b.field_large(1, &data);
        assert_eq!(a.finish(), b.finish());
    }
}

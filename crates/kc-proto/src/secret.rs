//! [`SecretBytes`]: an item value. It is wiped when dropped, never printed by
//! `Debug`, and compared in constant time.

use std::fmt;

use serde::de::{self, Deserialize, Deserializer, SeqAccess, Visitor};
use serde::ser::{Serialize, Serializer};
use subtle::ConstantTimeEq;
use zeroize::{ZeroizeOnDrop, Zeroizing};

/// Secret bytes, such as an item value.
///
/// - Dropping it overwrites the buffer.
/// - `Debug` shows only the length. There is no `Display`.
/// - `==` runs in constant time for equal lengths.
/// - Serde encodes it as a byte string (postcard: varint length + bytes).
#[derive(Clone, Default)]
pub struct SecretBytes(Zeroizing<Vec<u8>>);

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> SecretBytes {
        SecretBytes(Zeroizing::new(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> SecretBytes {
        SecretBytes(Zeroizing::new(bytes.to_vec()))
    }

    /// The secret itself. Keep the borrow short and don't copy it into
    /// buffers that aren't wiped.
    pub fn expose(&self) -> &[u8] {
        &self.0
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn into_zeroizing(self) -> Zeroizing<Vec<u8>> {
        self.0
    }
}

impl From<Zeroizing<Vec<u8>>> for SecretBytes {
    fn from(v: Zeroizing<Vec<u8>>) -> SecretBytes {
        SecretBytes(v)
    }
}

impl ZeroizeOnDrop for SecretBytes {}

impl fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretBytes(<{} bytes>)", self.0.len())
    }
}

impl PartialEq for SecretBytes {
    fn eq(&self, other: &SecretBytes) -> bool {
        // Lengths aren't secret; contents are compared in constant time.
        self.0.len() == other.0.len() && bool::from(self.0.as_slice().ct_eq(other.0.as_slice()))
    }
}

impl Eq for SecretBytes {}

impl Serialize for SecretBytes {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(&self.0)
    }
}

impl<'de> Deserialize<'de> for SecretBytes {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<SecretBytes, D::Error> {
        deserializer.deserialize_bytes(SecretVisitor)
    }
}

struct SecretVisitor;

impl<'de> Visitor<'de> for SecretVisitor {
    type Value = SecretBytes;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("a byte string")
    }

    fn visit_bytes<E: de::Error>(self, v: &[u8]) -> Result<SecretBytes, E> {
        // One exact-size allocation, so no reallocation leaves copies behind.
        Ok(SecretBytes::from_slice(v))
    }

    fn visit_byte_buf<E: de::Error>(self, v: Vec<u8>) -> Result<SecretBytes, E> {
        Ok(SecretBytes::new(v))
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<SecretBytes, A::Error> {
        // Self-describing formats (e.g. JSON) send bytes as a sequence. Grow
        // through wiped buffers so a reallocation can't leave a copy behind.
        let mut out = Zeroizing::new(Vec::with_capacity(
            seq.size_hint().unwrap_or(0).min(1 << 20),
        ));
        while let Some(b) = seq.next_element::<u8>()? {
            if out.len() == out.capacity() {
                let mut bigger = Zeroizing::new(Vec::with_capacity((out.capacity() * 2).max(64)));
                bigger.extend_from_slice(&out);
                out = bigger;
            }
            out.push(b);
        }
        Ok(SecretBytes(out))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn debug_shows_only_the_length() {
        let s = SecretBytes::from_slice(b"hunter2");
        assert_eq!(format!("{s:?}"), "SecretBytes(<7 bytes>)");
    }

    #[test]
    fn equality_and_round_trips() {
        let a = SecretBytes::from_slice(b"abc");
        assert_eq!(a, SecretBytes::new(b"abc".to_vec()));
        assert_ne!(a, SecretBytes::from_slice(b"abd"));
        assert_ne!(a, SecretBytes::from_slice(b"ab"));

        let bytes = postcard::to_allocvec(&a).unwrap();
        assert_eq!(bytes, [3, b'a', b'b', b'c']);
        let back: SecretBytes = postcard::from_bytes(&bytes).unwrap();
        assert_eq!(back, a);

        let json = serde_json::to_string(&a).unwrap();
        assert_eq!(json, "[97,98,99]");
        let back: SecretBytes = serde_json::from_str(&json).unwrap();
        assert_eq!(back.expose(), b"abc");
        let long: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
        let back: SecretBytes =
            serde_json::from_str(&serde_json::to_string(&long).unwrap()).unwrap();
        assert_eq!(back.expose(), long.as_slice());
    }
}

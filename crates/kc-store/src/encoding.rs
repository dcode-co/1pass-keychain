//! Stored blob format.
//!
//! Every keychain entry kc writes starts with a one-byte format tag:
//!
//! | tag | entry | rest of the blob |
//! |---|---|---|
//! | `0x01` | `item:<name>` / `sys:<key>` / `#prev` | the value itself (inline) |
//! | `0x02` | `item:<name>` / `sys:<key>` / `#prev` | manifest `{"gen":G,"n":N,"len":L,"sha256":"H"}` |
//! | `0x03` | `…#<gen>.<i>` | chunk `i` of generation `gen` |
//!
//! A value is stored inline when `1 + len <= max_blob_len`; otherwise it is split into
//! `n` chunks of at most `max_blob_len - 1` bytes, written under a fresh generation number,
//! and the manifest is written last. Readers verify the length and sha256 of the reassembled
//! value before returning it.
//!
//! The manifest is JSON in one canonical layout (exactly these keys, in this order, no
//! whitespace). It is read with a strict hand-written parser rather than serde, so that bytes
//! which only look like a manifest (a secret stored under the wrong tag, say) are never copied
//! into error messages or other unwiped memory.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Result, StoreError};

pub(crate) const TAG_INLINE: u8 = 0x01;
pub(crate) const TAG_MANIFEST: u8 = 0x02;
pub(crate) const TAG_CHUNK: u8 = 0x03;

/// Largest value kc stores (1 MiB). The relay can't carry more in one transfer anyway.
pub const MAX_VALUE_LEN: usize = 1 << 20;

/// Points at the chunks of one generation of a large value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Manifest {
    pub generation: u64,
    pub n: u32,
    pub len: u64,
    pub sha256: String,
}

impl Manifest {
    pub(crate) fn for_value(generation: u64, n: u32, value: &[u8]) -> Self {
        Manifest {
            generation,
            n,
            len: value.len() as u64,
            sha256: sha256_hex(value),
        }
    }

    fn validate(&self) -> std::result::Result<(), String> {
        if self.generation == 0 {
            return Err("manifest generation is 0".into());
        }
        if self.len == 0 || self.len > MAX_VALUE_LEN as u64 {
            return Err(format!("manifest length {} is out of range", self.len));
        }
        if self.n == 0 || u64::from(self.n) > self.len {
            return Err(format!(
                "manifest chunk count {} doesn't fit length {}",
                self.n, self.len
            ));
        }
        if self.sha256.len() != 64
            || !self
                .sha256
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        {
            return Err("manifest sha256 is not 64 lowercase hex digits".into());
        }
        Ok(())
    }

    /// Whether `value` is the value this manifest describes (length and digest).
    pub(crate) fn describes(&self, value: &[u8]) -> bool {
        self.len == value.len() as u64 && self.sha256 == sha256_hex(value)
    }
}

/// A quick look at a stored head blob (`item:<name>`, `#prev` or `sys:<key>`).
pub(crate) enum Head<'a> {
    Inline(&'a [u8]),
    Manifest(Manifest),
    /// Unknown tag or unparsable manifest.
    Unreadable(String),
}

impl Head<'_> {
    pub(crate) fn manifest(&self) -> Option<&Manifest> {
        match self {
            Head::Manifest(m) => Some(m),
            _ => None,
        }
    }
}

pub(crate) fn peek(blob: &[u8]) -> Head<'_> {
    match blob.split_first() {
        Some((&TAG_INLINE, value)) => Head::Inline(value),
        Some((&TAG_MANIFEST, json)) => match parse_manifest(json) {
            Ok(m) => Head::Manifest(m),
            Err(reason) => Head::Unreadable(reason),
        },
        Some((tag, _)) => Head::Unreadable(format!(
            "unknown format tag 0x{tag:02x} (written by a newer kc?)"
        )),
        None => Head::Unreadable("empty entry".into()),
    }
}

fn parse_manifest(json: &[u8]) -> std::result::Result<Manifest, String> {
    const NOT_A_MANIFEST: &str = "not a kc chunk manifest";
    let mut rest = json;
    let generation = number_after(&mut rest, br#"{"gen":"#)?;
    let n = number_after(&mut rest, br#","n":"#)?;
    let len = number_after(&mut rest, br#","len":"#)?;
    expect(&mut rest, br#","sha256":""#)?;
    let (hex, tail) = rest.split_at_checked(64).ok_or(NOT_A_MANIFEST)?;
    if tail != br#""}"#
        || !hex
            .iter()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(b))
    {
        return Err(NOT_A_MANIFEST.into());
    }
    let manifest = Manifest {
        generation,
        n: u32::try_from(n).map_err(|_| "manifest chunk count is out of range".to_owned())?,
        len,
        // Checked above to be 64 lowercase hex digits.
        sha256: hex.iter().map(|&b| char::from(b)).collect(),
    };
    manifest.validate()?;
    Ok(manifest)
}

fn expect(rest: &mut &[u8], literal: &[u8]) -> std::result::Result<(), String> {
    match rest.strip_prefix(literal) {
        Some(tail) => {
            *rest = tail;
            Ok(())
        }
        None => Err("not a kc chunk manifest".into()),
    }
}

/// `literal` followed by a decimal number without sign or leading zeros.
fn number_after(rest: &mut &[u8], literal: &[u8]) -> std::result::Result<u64, String> {
    expect(rest, literal)?;
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    let (number, tail) = rest.split_at(digits);
    if number.is_empty() || number.len() > 20 || (number.len() > 1 && number[0] == b'0') {
        return Err("not a kc chunk manifest".into());
    }
    let mut value: u64 = 0;
    for &digit in number {
        value = value
            .checked_mul(10)
            .and_then(|v| v.checked_add(u64::from(digit - b'0')))
            .ok_or("manifest number is out of range")?;
    }
    *rest = tail;
    Ok(value)
}

pub(crate) fn encode_inline(value: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut blob = Zeroizing::new(Vec::with_capacity(value.len() + 1));
    blob.push(TAG_INLINE);
    blob.extend_from_slice(value);
    blob
}

pub(crate) fn encode_manifest(manifest: &Manifest) -> Vec<u8> {
    let json = format!(
        r#"{{"gen":{},"n":{},"len":{},"sha256":"{}"}}"#,
        manifest.generation, manifest.n, manifest.len, manifest.sha256
    );
    let mut blob = Vec::with_capacity(json.len() + 1);
    blob.push(TAG_MANIFEST);
    blob.extend_from_slice(json.as_bytes());
    blob
}

pub(crate) fn encode_chunk(part: &[u8]) -> Zeroizing<Vec<u8>> {
    let mut blob = Zeroizing::new(Vec::with_capacity(part.len() + 1));
    blob.push(TAG_CHUNK);
    blob.extend_from_slice(part);
    blob
}

/// Strips and checks the chunk tag.
pub(crate) fn chunk_payload<'a>(account: &str, blob: &'a [u8]) -> Result<&'a [u8]> {
    match blob.split_first() {
        Some((&TAG_CHUNK, payload)) if !payload.is_empty() => Ok(payload),
        Some((&TAG_CHUNK, _)) => Err(StoreError::corrupt(account, "empty chunk")),
        Some((tag, _)) => Err(StoreError::corrupt(
            account,
            format!("expected a chunk, found format tag 0x{tag:02x}"),
        )),
        None => Err(StoreError::corrupt(account, "empty chunk entry")),
    }
}

/// Chunk payload size for a given blob limit (one byte goes to the tag).
pub(crate) fn chunk_size(max_blob_len: usize) -> usize {
    max_blob_len - 1
}

/// Whether a value must be chunked under the given blob limit.
pub(crate) fn needs_chunks(value_len: usize, max_blob_len: usize) -> bool {
    value_len + 1 > max_blob_len
}

pub(crate) fn sha256_hex(data: &[u8]) -> String {
    use std::fmt::Write as _;
    let digest = Sha256::digest(data);
    let mut hex = String::with_capacity(64);
    for byte in digest {
        let _ = write!(hex, "{byte:02x}");
    }
    hex
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tags_roundtrip() {
        let inline = encode_inline(b"value");
        assert_eq!(inline[0], TAG_INLINE);
        assert!(matches!(peek(&inline), Head::Inline(b"value")));

        let manifest = Manifest::for_value(3, 2, b"0123456789");
        let blob = encode_manifest(&manifest);
        assert_eq!(blob[0], TAG_MANIFEST);
        assert_eq!(peek(&blob).manifest(), Some(&manifest));
        assert!(manifest.describes(b"0123456789"));
        assert!(!manifest.describes(b"0123456780"));

        let chunk = encode_chunk(b"part");
        assert_eq!(chunk_payload("a", &chunk).unwrap(), b"part");
        assert!(chunk_payload("a", &inline).is_err());
        assert!(chunk_payload("a", &[TAG_CHUNK]).is_err());
        assert!(chunk_payload("a", &[]).is_err());
    }

    #[test]
    fn inline_values_may_look_like_anything() {
        // A value that starts with a tag byte or JSON is still just a value.
        let tricky = encode_manifest(&Manifest::for_value(1, 1, b"x"));
        let blob = encode_inline(&tricky);
        assert!(matches!(peek(&blob), Head::Inline(v) if v == tricky.as_slice()));
    }

    #[test]
    fn rejects_bad_heads() {
        assert!(matches!(peek(&[]), Head::Unreadable(_)));
        assert!(matches!(peek(&[0x7f, 1, 2]), Head::Unreadable(_)));
        assert!(matches!(peek(b"\x02{nope"), Head::Unreadable(_)));
        let bad = [
            r#"{"gen":0,"n":1,"len":1,"sha256":"00"}"#.to_owned(),
            format!(r#"{{"gen":1,"n":0,"len":5,"sha256":"{}"}}"#, "a".repeat(64)),
            format!(r#"{{"gen":1,"n":6,"len":5,"sha256":"{}"}}"#, "a".repeat(64)),
            format!(r#"{{"gen":1,"n":1,"len":0,"sha256":"{}"}}"#, "a".repeat(64)),
            format!(
                r#"{{"gen":1,"n":1,"len":{},"sha256":"{}"}}"#,
                MAX_VALUE_LEN + 1,
                "a".repeat(64)
            ),
            format!(r#"{{"gen":1,"n":1,"len":5,"sha256":"{}"}}"#, "A".repeat(64)),
            format!(
                r#"{{"gen":1,"n":1,"len":5,"sha256":"{}","x":1}}"#,
                "a".repeat(64)
            ),
        ];
        for json in bad {
            let mut blob = vec![TAG_MANIFEST];
            blob.extend_from_slice(json.as_bytes());
            assert!(matches!(peek(&blob), Head::Unreadable(_)), "{json}");
        }
    }

    #[test]
    fn manifest_errors_never_quote_the_stored_bytes() {
        for json in [
            r#"{"gen":"fake-secret-token","n":1,"len":1,"sha256":"x"}"#,
            r#"{"fake-secret-token":1}"#,
            r#"fake-secret-token"#,
            r#"{"gen":1,"n":1,"len":1,"sha256":"fake-secret-token"}"#,
        ] {
            let mut blob = vec![TAG_MANIFEST];
            blob.extend_from_slice(json.as_bytes());
            match peek(&blob) {
                Head::Unreadable(reason) => {
                    assert!(!reason.contains("fake-secret"), "{reason}");
                    let err = StoreError::corrupt("item:x", reason);
                    assert!(!format!("{err} {err:?}").contains("fake-secret"));
                }
                _ => panic!("{json} should be unreadable"),
            }
        }
    }

    #[test]
    fn the_largest_manifest_fits_the_smallest_blob_limit() {
        let manifest = Manifest {
            generation: u64::MAX,
            n: u32::MAX,
            len: MAX_VALUE_LEN as u64,
            sha256: "f".repeat(64),
        };
        let blob = encode_manifest(&manifest);
        assert_eq!(blob.len(), 134);
        assert!(blob.len() <= crate::MIN_MAX_BLOB_LEN);
    }

    #[test]
    fn chunking_threshold() {
        assert!(!needs_chunks(2047, 2048));
        assert!(needs_chunks(2048, 2048));
        assert_eq!(chunk_size(2048), 2047);
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

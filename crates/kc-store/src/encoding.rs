//! Stored blob format (v2).
//!
//! Every entry kc writes is framed so that its **account can be recovered by reading the secret
//! alone** (`GetSecret`/`GetSecrets`), without any `org.freedesktop.DBus.Properties` call:
//! reading a property of a client that has since disconnected crashes gnome-keyring, so on the
//! Secret Service kc issues method calls only. The frame is:
//!
//! | `0x10` | account length (`u16` LE) | account (UTF-8) | body |
//!
//! and the body is one of:
//!
//! | tag | body | entry | holds |
//! |---|---|---|---|
//! | `0x01` | value | `item:<name>` / `sys:<key>` / `#prev` | the value itself (inline) |
//! | `0x02` | manifest JSON | `item:<name>` / `sys:<key>` / `#prev` | manifest `{"gen":G,"n":N,"len":L,"sha256":"H"}` |
//! | `0x03` | chunk bytes | `…#<gen>.<i>` | chunk `i` of generation `gen` |
//!
//! A value is stored inline when it fits the blob limit with its frame; otherwise it is split
//! into chunks written under a fresh generation, and the manifest is written last. Readers
//! verify the length and sha256 of the reassembled value before returning it.
//!
//! The embedded account is redundant for a plain read (the reader looked the entry up by its
//! account), but it lets `reindex` enumerate the keychain and rebuild the index from method
//! calls only. When a head is copied between accounts (`current` ↔ `#prev` ↔ `#swap`) its body
//! is kept and only the account header is rewritten; see [`reframe`].
//!
//! The manifest is JSON in one canonical layout (exactly these keys, in this order, no
//! whitespace). It is read with a strict hand-written parser rather than serde, so that bytes
//! which only look like a manifest (a secret stored under the wrong tag, say) are never copied
//! into error messages or other unwiped memory.

use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::error::{Result, StoreError};

/// Leading byte of every kc entry: the v2 account-framed format.
const FORMAT_V2: u8 = 0x10;

pub(crate) const TAG_INLINE: u8 = 0x01;
pub(crate) const TAG_MANIFEST: u8 = 0x02;
pub(crate) const TAG_CHUNK: u8 = 0x03;

/// Largest value kc stores (1 MiB). The relay can't carry more in one transfer anyway.
pub const MAX_VALUE_LEN: usize = 1 << 20;

/// Bytes the v2 frame adds before the body: format byte, `u16` length, the account.
fn header_len(account_len: usize) -> usize {
    1 + 2 + account_len
}

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

/// Splits a v2 blob into its account and body (`tag` + payload). `None` if it isn't a v2 entry.
fn split(blob: &[u8]) -> Option<(&str, &[u8])> {
    let rest = blob.strip_prefix(&[FORMAT_V2])?;
    let (len, rest) = rest.split_at_checked(2)?;
    let account_len = u16::from_le_bytes([len[0], len[1]]) as usize;
    let (account, body) = rest.split_at_checked(account_len)?;
    Some((std::str::from_utf8(account).ok()?, body))
}

/// The account a v2 blob was written under, recovered from the blob alone. `None` if the blob
/// isn't a v2 entry (an empty placeholder, or written by a different program). Used by the
/// Secret Service backend's enumeration (and its tests); the other platforms learn an entry's
/// account from the native keychain, so this would be dead code there.
#[cfg(any(
    test,
    all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    )
))]
pub(crate) fn account_of(blob: &[u8]) -> Option<String> {
    split(blob).map(|(account, _)| account.to_owned())
}

pub(crate) fn peek(blob: &[u8]) -> Head<'_> {
    let Some((_account, body)) = split(blob) else {
        return Head::Unreadable("not a kc entry (no v2 frame)".into());
    };
    match body.split_first() {
        Some((&TAG_INLINE, value)) => Head::Inline(value),
        Some((&TAG_MANIFEST, json)) => match parse_manifest(json) {
            Ok(m) => Head::Manifest(m),
            Err(reason) => Head::Unreadable(reason),
        },
        Some((tag, _)) => Head::Unreadable(format!(
            "unknown body tag 0x{tag:02x} (written by a newer kc?)"
        )),
        None => Head::Unreadable("empty entry body".into()),
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

/// Frames a body (`tag` + payload) under `account`.
fn frame(account: &str, body_tag: u8, payload: &[u8]) -> Zeroizing<Vec<u8>> {
    let account = account.as_bytes();
    let len = u16::try_from(account.len()).expect("an account name fits in u16 bytes");
    let mut blob = Zeroizing::new(Vec::with_capacity(
        header_len(account.len()) + 1 + payload.len(),
    ));
    blob.push(FORMAT_V2);
    blob.extend_from_slice(&len.to_le_bytes());
    blob.extend_from_slice(account);
    blob.push(body_tag);
    blob.extend_from_slice(payload);
    blob
}

pub(crate) fn encode_inline(account: &str, value: &[u8]) -> Zeroizing<Vec<u8>> {
    frame(account, TAG_INLINE, value)
}

pub(crate) fn encode_manifest(account: &str, manifest: &Manifest) -> Vec<u8> {
    let json = format!(
        r#"{{"gen":{},"n":{},"len":{},"sha256":"{}"}}"#,
        manifest.generation, manifest.n, manifest.len, manifest.sha256
    );
    // The manifest isn't secret, but one allocation keeps the code uniform.
    frame(account, TAG_MANIFEST, json.as_bytes()).to_vec()
}

pub(crate) fn encode_chunk(account: &str, part: &[u8]) -> Zeroizing<Vec<u8>> {
    frame(account, TAG_CHUNK, part)
}

/// Copies a head to a new account, keeping its body and rewriting only the account header. Used
/// when `write`/`restore` move a head between `current`, `#prev` and `#swap` (chunks stay put).
/// A blob that isn't a v2 entry is copied verbatim (it is debris for `reindex` to drop).
pub(crate) fn reframe(blob: &[u8], account: &str) -> Zeroizing<Vec<u8>> {
    match split(blob) {
        Some((_, body)) => {
            let account = account.as_bytes();
            let len = u16::try_from(account.len()).expect("an account name fits in u16 bytes");
            let mut out =
                Zeroizing::new(Vec::with_capacity(header_len(account.len()) + body.len()));
            out.push(FORMAT_V2);
            out.extend_from_slice(&len.to_le_bytes());
            out.extend_from_slice(account);
            out.extend_from_slice(body);
            out
        }
        None => Zeroizing::new(blob.to_vec()),
    }
}

/// The body (tag + payload) of a v2 blob, i.e. the blob without its account header; the whole
/// blob if it isn't a v2 entry. Lets two heads be compared for the same stored value regardless
/// of which account each was framed under.
pub(crate) fn body(blob: &[u8]) -> &[u8] {
    split(blob).map_or(blob, |(_, body)| body)
}

/// The number of leading bytes before an inline value (frame + tag), if `blob` is an inline
/// entry. Lets a reader drop the prefix in place instead of copying the value out.
pub(crate) fn inline_prefix_len(blob: &[u8]) -> Option<usize> {
    let (account, body) = split(blob)?;
    match body.first() {
        Some(&TAG_INLINE) => Some(header_len(account.len()) + 1),
        _ => None,
    }
}

/// Strips the frame and chunk tag, checking both.
pub(crate) fn chunk_payload<'a>(account: &str, blob: &'a [u8]) -> Result<&'a [u8]> {
    let Some((_, body)) = split(blob) else {
        return Err(StoreError::corrupt(account, "not a kc entry (no v2 frame)"));
    };
    match body.split_first() {
        Some((&TAG_CHUNK, payload)) if !payload.is_empty() => Ok(payload),
        Some((&TAG_CHUNK, _)) => Err(StoreError::corrupt(account, "empty chunk")),
        Some((tag, _)) => Err(StoreError::corrupt(
            account,
            format!("expected a chunk, found body tag 0x{tag:02x}"),
        )),
        None => Err(StoreError::corrupt(account, "empty chunk body")),
    }
}

/// Whether a value must be chunked under the given blob limit, given the head's account (the
/// account is part of every blob's frame).
pub(crate) fn needs_chunks(value_len: usize, max_blob_len: usize, account: &str) -> bool {
    value_len + header_len(account.len()) + 1 > max_blob_len
}

/// How many value bytes fit in one chunk of `generation` under `base`. Fixed for the whole
/// value: it reserves room for the frame of the longest chunk account of this generation
/// (`base#generation.<up to 10 index digits>`), so every chunk of the value fits the limit.
pub(crate) fn chunk_size(base: &str, generation: u64, max_blob_len: usize) -> usize {
    // "#" + generation digits + "." + up to 10 digits for a u32 index.
    let longest_account = base.len() + 1 + decimal_len(generation) + 1 + 10;
    max_blob_len.saturating_sub(header_len(longest_account) + 1)
}

fn decimal_len(mut n: u64) -> usize {
    let mut len = 1;
    while n >= 10 {
        n /= 10;
        len += 1;
    }
    len
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
        let inline = encode_inline("item:a", b"value");
        assert_eq!(inline[0], FORMAT_V2);
        assert_eq!(account_of(&inline).as_deref(), Some("item:a"));
        assert!(matches!(peek(&inline), Head::Inline(b"value")));

        let manifest = Manifest::for_value(3, 2, b"0123456789");
        let blob = encode_manifest("item:a", &manifest);
        assert_eq!(blob[0], FORMAT_V2);
        assert_eq!(account_of(&blob).as_deref(), Some("item:a"));
        assert_eq!(peek(&blob).manifest(), Some(&manifest));
        assert!(manifest.describes(b"0123456789"));
        assert!(!manifest.describes(b"0123456780"));

        let chunk = encode_chunk("item:a#3.0", b"part");
        assert_eq!(account_of(&chunk).as_deref(), Some("item:a#3.0"));
        assert_eq!(chunk_payload("item:a#3.0", &chunk).unwrap(), b"part");
        assert!(chunk_payload("a", &inline).is_err());
        assert!(chunk_payload("a", &encode_chunk("x", b"")).is_err());
        assert!(chunk_payload("a", &[]).is_err());
    }

    #[test]
    fn reframe_keeps_the_body_and_swaps_the_account() {
        let manifest = Manifest::for_value(7, 2, b"0123456789");
        let head = encode_manifest("item:a", &manifest);
        let moved = reframe(&head, "item:a#prev");
        assert_eq!(account_of(&moved).as_deref(), Some("item:a#prev"));
        assert_eq!(peek(&moved).manifest(), Some(&manifest));

        let inline = encode_inline("item:a", b"fake-value");
        let moved = reframe(&inline, "item:a#swap");
        assert_eq!(account_of(&moved).as_deref(), Some("item:a#swap"));
        assert!(matches!(peek(&moved), Head::Inline(b"fake-value")));
    }

    #[test]
    fn inline_values_may_look_like_anything() {
        // A value that starts with a tag byte or JSON is still just a value.
        let tricky = encode_manifest("item:a", &Manifest::for_value(1, 1, b"x"));
        let blob = encode_inline("item:a", &tricky);
        assert!(matches!(peek(&blob), Head::Inline(v) if v == tricky.as_slice()));
    }

    #[test]
    fn rejects_bad_heads() {
        assert!(matches!(peek(&[]), Head::Unreadable(_)));
        // v1 (unframed) blobs are no longer readable.
        assert!(matches!(peek(&[TAG_INLINE, 1, 2]), Head::Unreadable(_)));
        assert!(matches!(peek(&[0x7f, 1, 2]), Head::Unreadable(_)));
        assert!(matches!(
            peek(&framed_body(b"\x02{nope")),
            Head::Unreadable(_)
        ));
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
            let mut body = vec![TAG_MANIFEST];
            body.extend_from_slice(json.as_bytes());
            assert!(
                matches!(peek(&framed_body(&body)), Head::Unreadable(_)),
                "{json}"
            );
        }
    }

    /// A v2 blob whose body is exactly `body` (so tests can frame hand-built bodies).
    fn framed_body(body: &[u8]) -> Vec<u8> {
        let mut blob = vec![FORMAT_V2, 6, 0];
        blob.extend_from_slice(b"item:a");
        blob.extend_from_slice(body);
        blob
    }

    #[test]
    fn manifest_errors_never_quote_the_stored_bytes() {
        for json in [
            r#"{"gen":"fake-secret-token","n":1,"len":1,"sha256":"x"}"#,
            r#"{"fake-secret-token":1}"#,
            r#"fake-secret-token"#,
            r#"{"gen":1,"n":1,"len":1,"sha256":"fake-secret-token"}"#,
        ] {
            let mut body = vec![TAG_MANIFEST];
            body.extend_from_slice(json.as_bytes());
            match peek(&framed_body(&body)) {
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
    fn the_largest_manifest_head_fits_the_smallest_blob_limit() {
        let manifest = Manifest {
            generation: u64::MAX,
            n: u32::MAX,
            len: MAX_VALUE_LEN as u64,
            sha256: "f".repeat(64),
        };
        // The longest head account: an item name at the length limit, with the `#prev` suffix.
        let account = format!("item:{}#prev", "a".repeat(crate::name::MAX_NAME_LEN));
        let blob = encode_manifest(&account, &manifest);
        assert!(
            blob.len() <= crate::MIN_MAX_BLOB_LEN,
            "largest manifest head is {} bytes, over MIN_MAX_BLOB_LEN {}",
            blob.len(),
            crate::MIN_MAX_BLOB_LEN
        );
    }

    #[test]
    fn chunking_threshold_and_size() {
        // Inline up to the point the frame no longer fits.
        let account = "item:a";
        let overhead = header_len(account.len()) + 1;
        assert!(!needs_chunks(2048 - overhead, 2048, account));
        assert!(needs_chunks(2048 - overhead + 1, 2048, account));
        // A chunk always fits the limit, even at the longest index of its generation.
        let cap = chunk_size("item:a", 42, 2048);
        let longest = encode_chunk(&format!("item:a#42.{}", u32::MAX), &vec![0u8; cap]);
        assert!(longest.len() <= 2048, "chunk is {} bytes", longest.len());
    }

    #[test]
    fn sha256_known_answer() {
        assert_eq!(
            sha256_hex(b"abc"),
            "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
        );
    }
}

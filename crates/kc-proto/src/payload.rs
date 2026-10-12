//! What travels inside the encryption (PROTOCOL §3), encoded with postcard.
//!
//! Field order is the wire order. Don't reorder fields or enum variants.

use std::collections::HashSet;
use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::device::DevicePublicKey;
use crate::names::{ItemName, Label};
use crate::rng;
use crate::secret::SecretBytes;

/// The `v` field of every structure in this version.
pub const VERSION: u8 = 1;

/// One secret.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Item {
    pub name: ItemName,
    pub value: SecretBytes,
    /// Unix seconds.
    pub updated_at: i64,
}

impl fmt::Debug for Item {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Item")
            .field("name", &self.name)
            .field("value", &self.value)
            .field("updated_at", &self.updated_at)
            .finish()
    }
}

/// What the receiver did with one item.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ItemStatus {
    Stored,
    /// The receiver already had the same value.
    Unchanged,
    /// Not stored because an item with that name exists.
    SkippedConflict,
    /// Stored under another name.
    Renamed(ItemName),
    /// Not stored. The receiver chooses the reason code.
    Rejected(u16),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemResult {
    pub name: ItemName,
    pub status: ItemStatus,
}

/// An inbox id: 16 random bytes. On the HTTP side it is base64url without
/// padding (`kc_wire::InboxCreated::inbox_id`).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct InboxId(pub [u8; 16]);

impl InboxId {
    pub fn from_b64url(s: &str) -> Option<InboxId> {
        let raw = URL_SAFE_NO_PAD.decode(s).ok()?;
        Some(InboxId(raw.try_into().ok()?))
    }

    pub fn to_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }
}

impl fmt::Debug for InboxId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "InboxId({})", self.to_b64url())
    }
}

/// A writer token: 32 random bytes that let a peer post to one of our
/// inboxes. Secret: wiped on drop, hidden from `Debug`.
///
/// The relay only ever sees `writer_token_sha256 = b64url(SHA-256(raw))`
/// at registration and `Bearer b64url(raw)` when the peer posts.
#[derive(Clone, PartialEq, Eq, Zeroize, ZeroizeOnDrop)]
pub struct WriterToken([u8; 32]);

impl WriterToken {
    pub fn generate() -> WriterToken {
        WriterToken(rng::array::<32>())
    }

    pub fn from_bytes(bytes: [u8; 32]) -> WriterToken {
        WriterToken(bytes)
    }

    pub fn from_bearer(b64: &str) -> Option<WriterToken> {
        let raw = Zeroizing::new(URL_SAFE_NO_PAD.decode(b64).ok()?);
        Some(WriterToken(raw.as_slice().try_into().ok()?))
    }

    pub fn expose(&self) -> &[u8; 32] {
        &self.0
    }

    /// The `Authorization: Bearer` value: base64url of the raw bytes.
    pub fn bearer(&self) -> Zeroizing<String> {
        Zeroizing::new(URL_SAFE_NO_PAD.encode(self.0))
    }

    /// `b64url(SHA-256(raw))`, for `POST /v1/inboxes/{id}/writers`.
    pub fn sha256_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(Sha256::digest(self.0))
    }

    pub fn registration(&self) -> kc_wire::WriterRegister {
        kc_wire::WriterRegister {
            writer_token_sha256: self.sha256_b64url(),
        }
    }
}

impl fmt::Debug for WriterToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("WriterToken(<hidden>)")
    }
}

/// Sent inside the channel when pairing: how to reach this device later.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PairOffer {
    pub suggested_label: Label,
    pub device_pk: DevicePublicKey,
    pub inbox_id: InboxId,
    /// Lets the receiver of this offer post to our inbox.
    pub writer_token: WriterToken,
}

/// The sender's `payload` phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelPayload {
    pub v: u8,
    pub items: Vec<Item>,
    pub pair: Option<PairOffer>,
}

impl ChannelPayload {
    pub fn new(items: Vec<Item>, pair: Option<PairOffer>) -> ChannelPayload {
        ChannelPayload {
            v: VERSION,
            items,
            pair,
        }
    }

    /// Checks what serde can't: the version and unique item names.
    pub fn validate(&self) -> Result<(), PayloadError> {
        check_version(self.v)?;
        check_unique_names(&self.items)
    }
}

/// The receiver's `ack` phase.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelAck {
    pub v: u8,
    pub results: Vec<ItemResult>,
    pub pair: Option<PairOffer>,
}

impl ChannelAck {
    pub fn new(results: Vec<ItemResult>, pair: Option<PairOffer>) -> ChannelAck {
        ChannelAck {
            v: VERSION,
            results,
            pair,
        }
    }

    pub fn validate(&self) -> Result<(), PayloadError> {
        check_version(self.v)
    }
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PayloadError {
    #[error("unsupported version {0}")]
    Version(u8),
    #[error("item {0} appears more than once")]
    DuplicateName(String),
}

pub(crate) fn check_version(v: u8) -> Result<(), PayloadError> {
    if v == VERSION {
        Ok(())
    } else {
        Err(PayloadError::Version(v))
    }
}

pub(crate) fn check_unique_names(items: &[Item]) -> Result<(), PayloadError> {
    let mut seen = HashSet::with_capacity(items.len());
    for item in items {
        if !seen.insert(item.name.as_str()) {
            return Err(PayloadError::DuplicateName(item.name.to_string()));
        }
    }
    Ok(())
}

// Fixed-size ids: raw bytes in postcard, base64url in human-readable formats.
impl Serialize for InboxId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_b64url())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for InboxId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<InboxId, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            InboxId::from_b64url(&s)
                .ok_or_else(|| serde::de::Error::custom("expected 16 bytes of base64url"))
        } else {
            Ok(InboxId(<[u8; 16]>::deserialize(deserializer)?))
        }
    }
}

impl Serialize for WriterToken {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.bearer())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for WriterToken {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<WriterToken, D::Error> {
        if deserializer.is_human_readable() {
            let s = Zeroizing::new(String::deserialize(deserializer)?);
            WriterToken::from_bearer(&s)
                .ok_or_else(|| serde::de::Error::custom("expected 32 bytes of base64url"))
        } else {
            let mut raw = <[u8; 32]>::deserialize(deserializer)?;
            let token = WriterToken(raw);
            raw.zeroize();
            Ok(token)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::device::DeviceKeyPair;

    fn item(name: &str, value: &[u8]) -> Item {
        Item {
            name: ItemName::new(name).unwrap(),
            value: SecretBytes::from_slice(value),
            updated_at: 1_700_000_000,
        }
    }

    #[test]
    fn debug_never_shows_values_or_tokens() {
        let token = WriterToken::generate();
        let offer = PairOffer {
            suggested_label: Label::new("mac").unwrap(),
            device_pk: *DeviceKeyPair::generate().public(),
            inbox_id: InboxId([1; 16]),
            writer_token: token.clone(),
        };
        let p = ChannelPayload::new(vec![item("GITHUB_TOKEN", b"ghp_supersecret")], Some(offer));
        let debug = format!("{p:?}");
        assert!(!debug.contains("supersecret"), "{debug}");
        assert!(!debug.contains(token.bearer().as_str()), "{debug}");
        assert!(
            debug.contains("GITHUB_TOKEN") && debug.contains("15 bytes"),
            "{debug}"
        );
    }

    #[test]
    fn postcard_layout_is_stable() {
        let p = ChannelPayload::new(vec![item("A", b"xy")], None);
        let bytes = postcard::to_allocvec(&p).unwrap();
        // v=1, 1 item, name "A", value [2]"xy", updated_at zigzag varint, pair None.
        let mut expected = vec![1, 1, 1, b'A', 2, b'x', b'y'];
        expected.extend_from_slice(&[0x80, 0xc4, 0x9f, 0xd5, 0x0c]);
        expected.push(0);
        assert_eq!(bytes, expected);
        assert_eq!(postcard::from_bytes::<ChannelPayload>(&bytes).unwrap(), p);

        let statuses = [
            (ItemStatus::Stored, vec![0u8]),
            (ItemStatus::Unchanged, vec![1]),
            (ItemStatus::SkippedConflict, vec![2]),
            (
                ItemStatus::Renamed(ItemName::new("B").unwrap()),
                vec![3, 1, b'B'],
            ),
            (ItemStatus::Rejected(300), vec![4, 0xac, 0x02]),
        ];
        for (status, encoded) in statuses {
            assert_eq!(
                postcard::to_allocvec(&status).unwrap(),
                encoded,
                "{status:?}"
            );
        }
    }

    #[test]
    fn decoding_validates_names_labels_and_keys() {
        let p = ChannelPayload::new(vec![item("ok", b"v")], None);
        let mut bytes = postcard::to_allocvec(&p).unwrap();
        bytes[3] = b'.'; // name "ok" -> ".k"
        assert!(postcard::from_bytes::<ChannelPayload>(&bytes).is_err());

        let offer = PairOffer {
            suggested_label: Label::new("mac").unwrap(),
            device_pk: *DeviceKeyPair::generate().public(),
            inbox_id: InboxId([1; 16]),
            writer_token: WriterToken::generate(),
        };
        let mut bytes = postcard::to_allocvec(&offer).unwrap();
        assert_eq!(postcard::from_bytes::<PairOffer>(&bytes).unwrap(), offer);
        bytes[1] = 0x1b; // label "mac" -> "\x1bac"
        assert!(postcard::from_bytes::<PairOffer>(&bytes).is_err());
        let mut weak = postcard::to_allocvec(&offer).unwrap();
        weak[4..36].fill(0); // device_pk -> the zero point
        assert!(postcard::from_bytes::<PairOffer>(&weak).is_err());
    }

    #[test]
    fn validate_checks_version_and_duplicates() {
        assert!(
            ChannelPayload::new(vec![item("a", b"1"), item("b", b"2")], None)
                .validate()
                .is_ok()
        );
        assert_eq!(
            ChannelPayload::new(vec![item("a", b"1"), item("a", b"2")], None).validate(),
            Err(PayloadError::DuplicateName("a".into()))
        );
        let mut p = ChannelPayload::new(vec![], None);
        p.v = 2;
        assert_eq!(p.validate(), Err(PayloadError::Version(2)));
        let mut a = ChannelAck::new(vec![], None);
        a.v = 0;
        assert_eq!(a.validate(), Err(PayloadError::Version(0)));
    }

    #[test]
    fn writer_token_forms() {
        let t = WriterToken::from_bytes([7; 32]);
        assert_eq!(WriterToken::from_bearer(&t.bearer()).unwrap(), t);
        assert_eq!(
            t.sha256_b64url(),
            URL_SAFE_NO_PAD.encode(Sha256::digest([7u8; 32]))
        );
        assert_eq!(t.registration().writer_token_sha256, t.sha256_b64url());
        assert_eq!(WriterToken::from_bearer("AAAA"), None);
        let id = InboxId([9; 16]);
        assert_eq!(InboxId::from_b64url(&id.to_b64url()), Some(id));
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{}\"", id.to_b64url())
        );
    }
}

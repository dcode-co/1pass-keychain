//! Messages to remembered devices (PROTOCOL §4), sent through the relay inbox.
//!
//! ```text
//! InboxEnvelope { v: 1, suite: 1, sender_fp, recipient_fp, enc: [u8; 32], ct: bytes }   (postcard)
//! aad  = postcard(v, suite, sender_fp, recipient_fp)
//! info = "kc1 inbox" || sender_fp || recipient_fp
//! ct   = HPKE auth mode, DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305,
//!        of pad(postcard(InboxPlain { v: 1, msg_id, sender_fp, recipient_fp, created_at, expires_at, items }))
//! ```
//!
//! [`open`] rejects a message when the sender isn't a remembered peer, the
//! recipient isn't us, the outer and inner fingerprints differ, the lifetime
//! is invalid or over, or the `msg_id` was seen before.

use std::fmt;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use hpke::aead::{AeadTag, ChaCha20Poly1305};
use hpke::kdf::HkdfSha256;
use hpke::{Deserializable, OpModeR, OpModeS, Serializable};
use kc_wire::limits::{INBOX_MESSAGE_TTL_SECS, MAX_MESSAGE_BYTES};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use zeroize::Zeroizing;

use crate::device::{DeviceKem, DeviceKeyPair, DevicePublicKey, Fingerprint};
use crate::pad;
use crate::payload::{self, Item, PayloadError};
use crate::rng;

/// `InboxEnvelope.v` and `InboxPlain.v`.
pub const VERSION: u8 = 1;
/// `InboxEnvelope.suite`: DHKEM(X25519, HKDF-SHA256) + HKDF-SHA256 + ChaCha20-Poly1305.
pub const SUITE: u16 = 1;
pub const INFO_PREFIX: &[u8] = b"kc1 inbox";
/// Longest allowed `expires_at - created_at`.
pub const MAX_LIFETIME_SECS: i64 = INBOX_MESSAGE_TTL_SECS as i64;
/// Tolerated clock difference between devices.
pub const CLOCK_SKEW_SECS: i64 = 300;
const TAG_LEN: usize = 16;

type Aead = ChaCha20Poly1305;
type EncappedKey = <DeviceKem as hpke::Kem>::EncappedKey;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum InboxError {
    #[error("the message is malformed")]
    Malformed,
    #[error("unsupported message version {0}")]
    UnsupportedVersion(u8),
    #[error("unsupported cipher suite {0}")]
    UnsupportedSuite(u16),
    #[error("the message is addressed to a different device")]
    WrongRecipient,
    #[error("the message is from a device that isn't paired with this one")]
    UnknownSender,
    #[error("the message failed authentication (tampered, or not from that device)")]
    DecryptFailed,
    #[error("the message header and contents name different devices")]
    FingerprintMismatch,
    #[error("the message has an invalid lifetime")]
    BadLifetime,
    #[error("the message has expired")]
    Expired,
    #[error("the message is dated in the future; check this device's clock")]
    NotYetValid,
    #[error("the message was already received (replay)")]
    Replay,
    #[error("a message lifetime must be between 1 second and 72 hours")]
    InvalidTtl,
    #[error("the message is larger than the relay accepts")]
    TooLarge,
    #[error("invalid items: {0}")]
    InvalidItems(PayloadError),
    #[error("encryption failed")]
    Seal,
}

impl InboxError {
    /// The `kc` exit code for this rejection (`kc_wire::exit`).
    pub fn exit_code(&self) -> i32 {
        use kc_wire::exit;
        match self {
            InboxError::Expired | InboxError::NotYetValid => exit::EXPIRED,
            InboxError::InvalidTtl | InboxError::TooLarge | InboxError::InvalidItems(_) => {
                exit::USAGE
            }
            _ => exit::AUTH_FAILED,
        }
    }
}

/// The sender-chosen end-to-end message id used for replay protection. Not
/// the relay's `msg_id` (that one only names the stored copy).
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct MessageId(pub [u8; 16]);

impl MessageId {
    pub fn to_hex(&self) -> String {
        self.0.iter().map(|b| format!("{b:02x}")).collect()
    }

    pub fn from_hex(s: &str) -> Option<MessageId> {
        if s.len() != 32 || !s.is_ascii() {
            return None;
        }
        let mut out = [0u8; 16];
        for (i, pair) in s.as_bytes().chunks(2).enumerate() {
            out[i] = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
        }
        Some(MessageId(out))
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.to_hex())
    }
}

impl Serialize for MessageId {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for MessageId {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<MessageId, D::Error> {
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            MessageId::from_hex(&s)
                .ok_or_else(|| serde::de::Error::custom("expected 32 hex characters"))
        } else {
            Ok(MessageId(<[u8; 16]>::deserialize(deserializer)?))
        }
    }
}

/// The relay message body (postcard).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxEnvelope {
    pub v: u8,
    pub suite: u16,
    pub sender_fp: Fingerprint,
    pub recipient_fp: Fingerprint,
    /// HPKE encapsulated key.
    pub enc: [u8; 32],
    /// HPKE ciphertext with the 16-byte tag appended.
    #[serde(with = "byte_string")]
    pub ct: Vec<u8>,
}

impl InboxEnvelope {
    /// Decodes a relay message body. Trailing bytes are rejected.
    pub fn decode(body: &[u8]) -> Result<InboxEnvelope, InboxError> {
        match postcard::take_from_bytes::<InboxEnvelope>(body) {
            Ok((envelope, [])) => Ok(envelope),
            _ => Err(InboxError::Malformed),
        }
    }

    pub fn encode(&self) -> Vec<u8> {
        postcard::to_allocvec(self).expect("encoding to a Vec can't fail")
    }

    fn aad(&self) -> Vec<u8> {
        header_aad(self.v, self.suite, &self.sender_fp, &self.recipient_fp)
    }
}

#[derive(Serialize)]
struct Header<'a> {
    v: u8,
    suite: u16,
    sender_fp: &'a Fingerprint,
    recipient_fp: &'a Fingerprint,
}

fn header_aad(v: u8, suite: u16, sender_fp: &Fingerprint, recipient_fp: &Fingerprint) -> Vec<u8> {
    postcard::to_allocvec(&Header {
        v,
        suite,
        sender_fp,
        recipient_fp,
    })
    .expect("encoding to a Vec can't fail")
}

fn info(sender_fp: &Fingerprint, recipient_fp: &Fingerprint) -> Vec<u8> {
    let mut info = Vec::with_capacity(INFO_PREFIX.len() + 64);
    info.extend_from_slice(INFO_PREFIX);
    info.extend_from_slice(sender_fp.as_bytes());
    info.extend_from_slice(recipient_fp.as_bytes());
    info
}

/// The encrypted part of an inbox message.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxPlain {
    pub v: u8,
    pub msg_id: MessageId,
    pub sender_fp: Fingerprint,
    pub recipient_fp: Fingerprint,
    /// Unix seconds.
    pub created_at: i64,
    /// Unix seconds, at most `created_at + 72h`.
    pub expires_at: i64,
    pub items: Vec<Item>,
}

/// Borrowing twin of [`InboxPlain`] with the identical encoding, so sealing
/// never clones item values.
#[derive(Serialize)]
struct InboxPlainRef<'a> {
    v: u8,
    msg_id: &'a MessageId,
    sender_fp: &'a Fingerprint,
    recipient_fp: &'a Fingerprint,
    created_at: i64,
    expires_at: i64,
    items: &'a [Item],
}

/// A sealed message, ready for `POST /v1/inboxes/{id}/messages`.
#[derive(Debug, Clone)]
pub struct SealedMessage {
    pub body: Vec<u8>,
    pub msg_id: MessageId,
    pub created_at: i64,
    pub expires_at: i64,
}

/// Seals `items` from `sender` to `recipient`, valid for `ttl` from `now`
/// (Unix seconds; see [`unix_now`]).
pub fn seal(
    sender: &DeviceKeyPair,
    recipient: &DevicePublicKey,
    items: &[Item],
    ttl: Duration,
    now: i64,
) -> Result<SealedMessage, InboxError> {
    let ttl = i64::try_from(ttl.as_secs()).map_err(|_| InboxError::InvalidTtl)?;
    if !(1..=MAX_LIFETIME_SECS).contains(&ttl) {
        return Err(InboxError::InvalidTtl);
    }
    let expires_at = now.checked_add(ttl).ok_or(InboxError::InvalidTtl)?;
    payload::check_unique_names(items).map_err(InboxError::InvalidItems)?;

    let sender_fp = sender.fingerprint();
    let recipient_fp = recipient.fingerprint();
    let msg_id = MessageId(rng::array::<16>());
    let plain = InboxPlainRef {
        v: VERSION,
        msg_id: &msg_id,
        sender_fp: &sender_fp,
        recipient_fp: &recipient_fp,
        created_at: now,
        expires_at,
        items,
    };
    let mut buf = pad::encode(&plain, &[], TAG_LEN).map_err(|_| InboxError::Seal)?;
    let mode = OpModeS::Auth((sender.kem_private().clone(), sender.public().kem_public()));
    let (enc, tag) = hpke::single_shot_seal_inout_detached::<Aead, HkdfSha256, DeviceKem>(
        &mode,
        &recipient.kem_public(),
        &info(&sender_fp, &recipient_fp),
        (&mut buf[..]).into(),
        &header_aad(VERSION, SUITE, &sender_fp, &recipient_fp),
    )
    .map_err(|_| InboxError::Seal)?;
    buf.extend_from_slice(&tag.to_bytes());

    let envelope = InboxEnvelope {
        v: VERSION,
        suite: SUITE,
        sender_fp,
        recipient_fp,
        enc: enc.to_bytes().into(),
        // The buffer holds ciphertext now.
        ct: std::mem::take(&mut *buf),
    };
    let body = envelope.encode();
    if body.len() > MAX_MESSAGE_BYTES {
        return Err(InboxError::TooLarge);
    }
    Ok(SealedMessage {
        body,
        msg_id,
        created_at: now,
        expires_at,
    })
}

/// A message that passed every check.
#[derive(Debug, Clone)]
pub struct OpenedMessage {
    pub msg_id: MessageId,
    pub sender_fp: Fingerprint,
    pub created_at: i64,
    pub expires_at: i64,
    pub items: Vec<Item>,
}

impl OpenedMessage {
    /// Keep `msg_id` in the seen-set at least until this time (Unix seconds).
    pub fn keep_seen_until(&self) -> i64 {
        self.expires_at.saturating_add(CLOCK_SKEW_SECS)
    }
}

/// Opens a relay message body.
///
/// - `own_keys`: this device's key pairs (the current one, plus the previous
///   one for 72 h after a rotation). The one matching `recipient_fp` is used.
/// - `peer_key`: looks up a remembered peer by fingerprint.
/// - `seen`: whether this `msg_id` was already accepted.
/// - `now`: Unix seconds.
pub fn open(
    body: &[u8],
    own_keys: &[&DeviceKeyPair],
    peer_key: impl Fn(&Fingerprint) -> Option<DevicePublicKey>,
    seen: impl Fn(&MessageId) -> bool,
    now: i64,
) -> Result<OpenedMessage, InboxError> {
    let envelope = InboxEnvelope::decode(body)?;
    if envelope.v != VERSION {
        return Err(InboxError::UnsupportedVersion(envelope.v));
    }
    if envelope.suite != SUITE {
        return Err(InboxError::UnsupportedSuite(envelope.suite));
    }
    let own = own_keys
        .iter()
        .find(|k| k.fingerprint() == envelope.recipient_fp)
        .ok_or(InboxError::WrongRecipient)?;
    let sender_pk = peer_key(&envelope.sender_fp)
        .filter(|pk| pk.fingerprint() == envelope.sender_fp)
        .ok_or(InboxError::UnknownSender)?;

    let tag_at = envelope
        .ct
        .len()
        .checked_sub(TAG_LEN)
        .ok_or(InboxError::Malformed)?;
    let (ciphertext, tag) = envelope.ct.split_at(tag_at);
    let tag = AeadTag::<Aead>::from_bytes(tag).map_err(|_| InboxError::Malformed)?;
    let enc = EncappedKey::from_bytes(&envelope.enc).map_err(|_| InboxError::Malformed)?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    hpke::single_shot_open_inout_detached::<Aead, HkdfSha256, DeviceKem>(
        &OpModeR::Auth(sender_pk.kem_public()),
        own.kem_private(),
        &enc,
        &info(&envelope.sender_fp, &envelope.recipient_fp),
        (&mut buf[..]).into(),
        &envelope.aad(),
        &tag,
    )
    .map_err(|_| InboxError::DecryptFailed)?;

    let plain: InboxPlain = pad::decode(&buf).map_err(|_| InboxError::Malformed)?;
    if plain.v != VERSION {
        return Err(InboxError::UnsupportedVersion(plain.v));
    }
    if plain.sender_fp != envelope.sender_fp || plain.recipient_fp != envelope.recipient_fp {
        return Err(InboxError::FingerprintMismatch);
    }
    let lifetime = plain.expires_at.checked_sub(plain.created_at);
    if !lifetime.is_some_and(|l| (0..=MAX_LIFETIME_SECS).contains(&l)) {
        return Err(InboxError::BadLifetime);
    }
    if now > plain.expires_at.saturating_add(CLOCK_SKEW_SECS) {
        return Err(InboxError::Expired);
    }
    if plain.created_at > now.saturating_add(CLOCK_SKEW_SECS) {
        return Err(InboxError::NotYetValid);
    }
    if seen(&plain.msg_id) {
        return Err(InboxError::Replay);
    }
    payload::check_unique_names(&plain.items).map_err(|_| InboxError::Malformed)?;
    Ok(OpenedMessage {
        msg_id: plain.msg_id,
        sender_fp: plain.sender_fp,
        created_at: plain.created_at,
        expires_at: plain.expires_at,
        items: plain.items,
    })
}

/// The current time in Unix seconds.
pub fn unix_now() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// `Vec<u8>` as a postcard byte string (varint length + bytes).
mod byte_string {
    use serde::{Deserializer, Serializer};

    pub fn serialize<S: Serializer>(v: &[u8], serializer: S) -> Result<S::Ok, S::Error> {
        serializer.serialize_bytes(v)
    }

    pub fn deserialize<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<u8>, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Vec<u8>;
            fn expecting(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                f.write_str("a byte string")
            }
            fn visit_bytes<E: serde::de::Error>(self, v: &[u8]) -> Result<Vec<u8>, E> {
                Ok(v.to_vec())
            }
            fn visit_byte_buf<E: serde::de::Error>(self, v: Vec<u8>) -> Result<Vec<u8>, E> {
                Ok(v)
            }
            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Vec<u8>, A::Error> {
                let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(1 << 20));
                while let Some(b) = seq.next_element()? {
                    out.push(b);
                }
                Ok(out)
            }
        }
        deserializer.deserialize_bytes(V)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::names::ItemName;
    use crate::secret::SecretBytes;

    const NOW: i64 = 1_760_000_000;
    const HOUR: Duration = Duration::from_secs(3600);

    struct Setup {
        alice: DeviceKeyPair,
        bob: DeviceKeyPair,
        mallory: DeviceKeyPair,
    }

    fn setup() -> Setup {
        Setup {
            alice: DeviceKeyPair::generate(),
            bob: DeviceKeyPair::generate(),
            mallory: DeviceKeyPair::generate(),
        }
    }

    fn items() -> Vec<Item> {
        vec![
            Item {
                name: ItemName::new("GITHUB_TOKEN").unwrap(),
                value: SecretBytes::from_slice(b"ghp_x"),
                updated_at: NOW - 10,
            },
            Item {
                name: ItemName::new("app.env").unwrap(),
                value: SecretBytes::from_slice(&[0u8; 5000]),
                updated_at: NOW,
            },
        ]
    }

    /// Bob opens with Alice remembered.
    fn bob_opens(s: &Setup, body: &[u8], now: i64) -> Result<OpenedMessage, InboxError> {
        let alice_pk = *s.alice.public();
        open(
            body,
            &[&s.bob],
            |fp| (*fp == alice_pk.fingerprint()).then_some(alice_pk),
            |_| false,
            now,
        )
    }

    #[test]
    fn round_trip() {
        let s = setup();
        let sealed = seal(&s.alice, s.bob.public(), &items(), 2 * HOUR, NOW).unwrap();
        assert_eq!(sealed.expires_at, NOW + 7200);
        assert!(sealed.body.len() < 2 * 4096 + 200);
        let opened = bob_opens(&s, &sealed.body, NOW + 60).unwrap();
        assert_eq!(opened.msg_id, sealed.msg_id);
        assert_eq!(opened.sender_fp, s.alice.fingerprint());
        assert_eq!(opened.items, items());
        assert_eq!(opened.keep_seen_until(), NOW + 7200 + 300);

        let env = InboxEnvelope::decode(&sealed.body).unwrap();
        assert_eq!((env.v, env.suite), (1, 1));
        assert_eq!(env.recipient_fp, s.bob.fingerprint());
        assert_eq!(env.aad().len(), 66);
    }

    #[test]
    fn borrowed_plaintext_encodes_like_the_owned_one() {
        let (s, items) = (setup(), items());
        let owned = InboxPlain {
            v: 1,
            msg_id: MessageId([3; 16]),
            sender_fp: s.alice.fingerprint(),
            recipient_fp: s.bob.fingerprint(),
            created_at: NOW,
            expires_at: NOW + 1,
            items: items.clone(),
        };
        let borrowed = InboxPlainRef {
            v: 1,
            msg_id: &owned.msg_id,
            sender_fp: &owned.sender_fp,
            recipient_fp: &owned.recipient_fp,
            created_at: NOW,
            expires_at: NOW + 1,
            items: &items,
        };
        assert_eq!(
            postcard::to_allocvec(&owned).unwrap(),
            postcard::to_allocvec(&borrowed).unwrap()
        );
    }

    #[test]
    fn rejects_unknown_senders() {
        let s = setup();
        let sealed = seal(&s.mallory, s.bob.public(), &items(), HOUR, NOW).unwrap();
        assert_eq!(
            bob_opens(&s, &sealed.body, NOW).unwrap_err(),
            InboxError::UnknownSender
        );
        // A lookup that returns a key with another fingerprint is not trusted.
        let alice_pk = *s.alice.public();
        let err = open(&sealed.body, &[&s.bob], |_| Some(alice_pk), |_| false, NOW).unwrap_err();
        assert_eq!(err, InboxError::UnknownSender);
    }

    #[test]
    fn rejects_other_recipients() {
        let s = setup();
        let sealed = seal(&s.alice, s.mallory.public(), &items(), HOUR, NOW).unwrap();
        assert_eq!(
            bob_opens(&s, &sealed.body, NOW).unwrap_err(),
            InboxError::WrongRecipient
        );
    }

    #[test]
    fn forged_sender_header_fails_authentication() {
        // Mallory encrypts to Bob but claims to be Alice in the header.
        let s = setup();
        let sealed = seal(&s.mallory, s.bob.public(), &items(), HOUR, NOW).unwrap();
        let mut env = InboxEnvelope::decode(&sealed.body).unwrap();
        env.sender_fp = s.alice.fingerprint();
        assert_eq!(
            bob_opens(&s, &env.encode(), NOW).unwrap_err(),
            InboxError::DecryptFailed
        );
    }

    #[test]
    fn reflected_message_is_rejected() {
        // Static-static DH is symmetric: Alice->Bob uses the same DH secret as
        // Bob->Alice. The recipient fingerprint stops a reflection.
        let s = setup();
        let sealed = seal(&s.alice, s.bob.public(), &items(), HOUR, NOW).unwrap();
        let bob_pk = *s.bob.public();
        let err = open(&sealed.body, &[&s.alice], |_| Some(bob_pk), |_| false, NOW).unwrap_err();
        assert_eq!(err, InboxError::WrongRecipient);
    }

    #[test]
    fn tampering_fails_authentication() {
        let s = setup();
        let body = seal(&s.alice, s.bob.public(), &items(), HOUR, NOW)
            .unwrap()
            .body;
        let env = InboxEnvelope::decode(&body).unwrap();

        let mut ct = env.clone();
        ct.ct[7] ^= 1;
        assert_eq!(
            bob_opens(&s, &ct.encode(), NOW).unwrap_err(),
            InboxError::DecryptFailed
        );
        let mut tag = env.clone();
        *tag.ct.last_mut().unwrap() ^= 1;
        assert_eq!(
            bob_opens(&s, &tag.encode(), NOW).unwrap_err(),
            InboxError::DecryptFailed
        );
        let mut enc = env.clone();
        enc.enc[0] ^= 1;
        assert_eq!(
            bob_opens(&s, &enc.encode(), NOW).unwrap_err(),
            InboxError::DecryptFailed
        );
    }

    #[test]
    fn rejects_bad_versions_suites_and_encodings() {
        let s = setup();
        let body = seal(&s.alice, s.bob.public(), &items(), HOUR, NOW)
            .unwrap()
            .body;
        let env = InboxEnvelope::decode(&body).unwrap();

        let mut v = env.clone();
        v.v = 2;
        assert_eq!(
            bob_opens(&s, &v.encode(), NOW).unwrap_err(),
            InboxError::UnsupportedVersion(2)
        );
        let mut suite = env.clone();
        suite.suite = 7;
        assert_eq!(
            bob_opens(&s, &suite.encode(), NOW).unwrap_err(),
            InboxError::UnsupportedSuite(7)
        );

        let mut trailing = body.clone();
        trailing.push(0);
        assert_eq!(
            bob_opens(&s, &trailing, NOW).unwrap_err(),
            InboxError::Malformed
        );
        assert_eq!(
            bob_opens(&s, &body[..body.len() - 1], NOW).unwrap_err(),
            InboxError::Malformed
        );
        assert_eq!(bob_opens(&s, &[], NOW).unwrap_err(), InboxError::Malformed);
        let mut short = env.clone();
        short.ct.truncate(10);
        assert_eq!(
            bob_opens(&s, &short.encode(), NOW).unwrap_err(),
            InboxError::Malformed
        );
    }

    /// Seals an arbitrary plaintext with a valid header, to reach the checks
    /// that run after decryption.
    fn seal_plain(s: &Setup, plain: &InboxPlain) -> Vec<u8> {
        let (sfp, rfp) = (s.alice.fingerprint(), s.bob.fingerprint());
        let mut buf = pad::encode(plain, &[], TAG_LEN).unwrap();
        let mode = OpModeS::Auth((s.alice.kem_private().clone(), s.alice.public().kem_public()));
        let (enc, tag) = hpke::single_shot_seal_inout_detached::<Aead, HkdfSha256, DeviceKem>(
            &mode,
            &s.bob.public().kem_public(),
            &info(&sfp, &rfp),
            (&mut buf[..]).into(),
            &header_aad(VERSION, SUITE, &sfp, &rfp),
        )
        .unwrap();
        buf.extend_from_slice(&tag.to_bytes());
        InboxEnvelope {
            v: 1,
            suite: 1,
            sender_fp: sfp,
            recipient_fp: rfp,
            enc: enc.to_bytes().into(),
            ct: buf.to_vec(),
        }
        .encode()
    }

    fn plain(s: &Setup) -> InboxPlain {
        InboxPlain {
            v: 1,
            msg_id: MessageId([5; 16]),
            sender_fp: s.alice.fingerprint(),
            recipient_fp: s.bob.fingerprint(),
            created_at: NOW,
            expires_at: NOW + 3600,
            items: items(),
        }
    }

    #[test]
    fn inner_fingerprints_must_match_the_header() {
        let s = setup();
        assert!(bob_opens(&s, &seal_plain(&s, &plain(&s)), NOW).is_ok());
        let mut p = plain(&s);
        p.sender_fp = s.mallory.fingerprint();
        assert_eq!(
            bob_opens(&s, &seal_plain(&s, &p), NOW).unwrap_err(),
            InboxError::FingerprintMismatch
        );
        let mut p = plain(&s);
        p.recipient_fp = s.mallory.fingerprint();
        assert_eq!(
            bob_opens(&s, &seal_plain(&s, &p), NOW).unwrap_err(),
            InboxError::FingerprintMismatch
        );
        let mut p = plain(&s);
        p.v = 9;
        assert_eq!(
            bob_opens(&s, &seal_plain(&s, &p), NOW).unwrap_err(),
            InboxError::UnsupportedVersion(9)
        );
        let mut p = plain(&s);
        p.items.push(p.items[0].clone());
        assert_eq!(
            bob_opens(&s, &seal_plain(&s, &p), NOW).unwrap_err(),
            InboxError::Malformed
        );
    }

    #[test]
    fn lifetime_and_clock_skew() {
        let s = setup();
        let body = seal_plain(&s, &plain(&s)); // valid NOW ..= NOW + 3600
        let exp = NOW + 3600;
        assert!(bob_opens(&s, &body, exp + CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            bob_opens(&s, &body, exp + CLOCK_SKEW_SECS + 1).unwrap_err(),
            InboxError::Expired
        );
        assert!(bob_opens(&s, &body, NOW - CLOCK_SKEW_SECS).is_ok());
        assert_eq!(
            bob_opens(&s, &body, NOW - CLOCK_SKEW_SECS - 1).unwrap_err(),
            InboxError::NotYetValid
        );

        let mut p = plain(&s);
        p.expires_at = p.created_at + MAX_LIFETIME_SECS + 1;
        assert_eq!(
            bob_opens(&s, &seal_plain(&s, &p), NOW).unwrap_err(),
            InboxError::BadLifetime
        );
        let mut p = plain(&s);
        (p.created_at, p.expires_at) = (i64::MIN, i64::MAX); // the difference overflows
        assert_eq!(
            bob_opens(&s, &seal_plain(&s, &p), NOW).unwrap_err(),
            InboxError::BadLifetime
        );
        let mut p = plain(&s);
        p.expires_at = p.created_at - 1;
        assert_eq!(
            bob_opens(&s, &seal_plain(&s, &p), NOW).unwrap_err(),
            InboxError::BadLifetime
        );
    }

    #[test]
    fn replays_are_rejected() {
        let s = setup();
        let sealed = seal(&s.alice, s.bob.public(), &items(), HOUR, NOW).unwrap();
        let alice_pk = *s.alice.public();
        let seen = [sealed.msg_id];
        let err = open(
            &sealed.body,
            &[&s.bob],
            |_| Some(alice_pk),
            |id| seen.contains(id),
            NOW,
        )
        .unwrap_err();
        assert_eq!(err, InboxError::Replay);
    }

    #[test]
    fn rotation_keeps_the_old_key_usable() {
        let s = setup();
        let new_bob = DeviceKeyPair::generate();
        let sealed = seal(&s.alice, s.bob.public(), &items(), HOUR, NOW).unwrap();
        let alice_pk = *s.alice.public();
        assert!(
            open(
                &sealed.body,
                &[&new_bob, &s.bob],
                |_| Some(alice_pk),
                |_| false,
                NOW
            )
            .is_ok()
        );
        assert_eq!(
            open(
                &sealed.body,
                &[&new_bob],
                |_| Some(alice_pk),
                |_| false,
                NOW
            )
            .unwrap_err(),
            InboxError::WrongRecipient
        );
    }

    #[test]
    fn seal_checks_its_inputs() {
        let s = setup();
        let bob = s.bob.public();
        assert_eq!(
            seal(&s.alice, bob, &items(), Duration::ZERO, NOW).unwrap_err(),
            InboxError::InvalidTtl
        );
        assert_eq!(
            seal(&s.alice, bob, &items(), 73 * HOUR, NOW).unwrap_err(),
            InboxError::InvalidTtl
        );
        assert!(seal(&s.alice, bob, &items(), 72 * HOUR, NOW).is_ok());
        let mut dup = items();
        dup.push(dup[0].clone());
        assert!(matches!(
            seal(&s.alice, bob, &dup, HOUR, NOW),
            Err(InboxError::InvalidItems(_))
        ));
        let big = vec![Item {
            name: ItemName::new("big").unwrap(),
            value: SecretBytes::new(vec![1; MAX_MESSAGE_BYTES]),
            updated_at: NOW,
        }];
        assert_eq!(
            seal(&s.alice, bob, &big, HOUR, NOW).unwrap_err(),
            InboxError::TooLarge
        );
        assert_eq!(InboxError::Expired.exit_code(), kc_wire::exit::EXPIRED);
        assert_eq!(InboxError::Replay.exit_code(), kc_wire::exit::AUTH_FAILED);
    }

    #[test]
    fn message_id_forms() {
        let id = MessageId([0xab; 16]);
        assert_eq!(MessageId::from_hex(&id.to_hex()), Some(id));
        assert_eq!(
            serde_json::to_string(&id).unwrap(),
            format!("\"{}\"", id.to_hex())
        );
        assert_eq!(postcard::to_allocvec(&id).unwrap(), [0xab; 16]);
    }
}

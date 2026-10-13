//! Compiled as an inbox unit-test module so fixed HPKE randomness never
//! becomes a production API. All values below are synthetic test secrets.
use super::*;
use crate::names::ItemName;
use crate::secret::SecretBytes;
use crate::sync::{AckResult, Change, ChangeId, DigestEntry, ItemKind, Op, SyncMsg, Vid};

const NOW: i64 = 1_760_000_000;
const TTL: Duration = Duration::from_secs(3600);
const ID: MessageId = MessageId([0x44; 16]);

struct FixedRng;
impl hpke::rand_core::TryRng for FixedRng {
    type Error = std::convert::Infallible;
    fn try_next_u32(&mut self) -> Result<u32, Self::Error> {
        panic!("unexpected RNG call")
    }
    fn try_next_u64(&mut self) -> Result<u64, Self::Error> {
        panic!("unexpected RNG call")
    }
    fn try_fill_bytes(&mut self, dst: &mut [u8]) -> Result<(), Self::Error> {
        assert_eq!(dst.len(), 32);
        dst.fill(0x33);
        Ok(())
    }
}
impl hpke::rand_core::TryCryptoRng for FixedRng {}

fn keys() -> (DeviceKeyPair, DeviceKeyPair) {
    (
        DeviceKeyPair::from_secret_bytes(&[0x11; 32]).unwrap(),
        DeviceKeyPair::from_secret_bytes(&[0x22; 32]).unwrap(),
    )
}
fn name(s: &str) -> ItemName {
    ItemName::new(s).unwrap()
}
fn item() -> Item {
    Item {
        name: name("token"),
        value: SecretBytes::from_slice(b"test-secret"),
        updated_at: NOW - 10,
    }
}
fn hello() -> Body {
    Body::Sync(SyncMsg::Hello {
        features: vec!["sync-v1".into()],
        is_reply: false,
    })
}
fn change() -> Change {
    Change {
        name: name("token"),
        generation: 300,
        new_vid: Vid([0x55; 16]),
        parents: vec![Vid([0x66; 16])],
        lineage: vec![Vid([0x66; 16]), Vid([0x77; 16])],
        op: Op::Put {
            kind: ItemKind::Text,
            value: SecretBytes::from_slice(b"test-secret"),
        },
        approval_ref: Some([0x88; 16]),
    }
}
fn cases() -> Vec<(&'static str, Body)> {
    vec![
        ("hello", hello()),
        (
            "offer",
            Body::Sync(SyncMsg::Offer {
                name: name("config.env"),
                known_generation: 3,
                vid: Vid([0x55; 16]),
                lineage: vec![Vid([0x66; 16])],
                kind: ItemKind::File,
                value: SecretBytes::from_slice(b"TEST=1\n"),
            }),
        ),
        (
            "changes",
            Body::Sync(SyncMsg::Changes {
                changes: vec![
                    change(),
                    Change {
                        name: name("old"),
                        generation: 2,
                        new_vid: Vid([0x99; 16]),
                        parents: vec![],
                        lineage: vec![],
                        op: Op::Retire,
                        approval_ref: None,
                    },
                ],
            }),
        ),
        (
            "ack",
            Body::Sync(SyncMsg::Ack {
                results: [
                    AckResult::Applied,
                    AckResult::Held,
                    AckResult::Conflict,
                    AckResult::StaleGeneration,
                    AckResult::DeferredCapacity,
                    AckResult::Rejected,
                ]
                .into_iter()
                .enumerate()
                .map(|(i, result)| {
                    (
                        ChangeId {
                            name: name("token"),
                            generation: i as u64,
                            new_vid: Vid([i as u8; 16]),
                        },
                        result,
                    )
                })
                .collect(),
            }),
        ),
        (
            "digest",
            Body::Sync(SyncMsg::Digest {
                entries: vec![DigestEntry {
                    name: name("token"),
                    generation: 300,
                    head: Vid([0x55; 16]),
                }],
            }),
        ),
        ("items", Body::Items(vec![item()])),
        (
            "accept",
            Body::Sync(SyncMsg::Accept {
                name: name("token"),
                generation: 300,
            }),
        ),
        (
            "leave",
            Body::Sync(SyncMsg::Leave {
                name: name("token"),
                generation: 300,
            }),
        ),
        (
            "approvals",
            Body::Sync(SyncMsg::Approvals {
                docs: vec![vec![1, 2, 3], vec![]],
            }),
        ),
    ]
}
fn bob_opens(bytes: &[u8], now: i64) -> Result<OpenedAny, InboxError> {
    let (alice, bob) = keys();
    open_any(
        bytes,
        &[&bob],
        |fp| (*fp == alice.fingerprint()).then_some(*alice.public()),
        |_| false,
        now,
    )
}
fn plain(body: Body) -> InboxPlain2 {
    let (alice, bob) = keys();
    InboxPlain2 {
        v: VERSION_V2,
        msg_id: ID,
        sender_fp: alice.fingerprint(),
        recipient_fp: bob.fingerprint(),
        created_at: NOW,
        expires_at: NOW + 3600,
        body,
    }
}
// Intentionally bypass sender validation for adversarial authenticated messages.
fn seal_plain(p: &InboxPlain2, prefix: &[u8]) -> Vec<u8> {
    let (alice, bob) = keys();
    let (sender_fp, recipient_fp) = (alice.fingerprint(), bob.fingerprint());
    let mut buf = pad::encode(p, &[], TAG_LEN).unwrap();
    let (enc, tag) = hpke::single_shot_seal_inout_detached_with_rng::<Aead, HkdfSha256, DeviceKem>(
        &OpModeS::Auth((alice.kem_private().clone(), alice.public().kem_public())),
        &bob.public().kem_public(),
        &info_with_prefix(prefix, &sender_fp, &recipient_fp),
        (&mut buf[..]).into(),
        &header_aad(VERSION_V2, SUITE, &sender_fp, &recipient_fp),
        &mut FixedRng,
    )
    .unwrap();
    buf.extend_from_slice(&tag.to_bytes());
    InboxEnvelope {
        v: VERSION_V2,
        suite: SUITE,
        sender_fp,
        recipient_fp,
        enc: enc.to_bytes().into(),
        ct: std::mem::take(&mut *buf),
    }
    .encode()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn unhex(s: &str) -> Vec<u8> {
    let s: String = s.split_whitespace().collect();
    assert_eq!(s.len() % 2, 0);
    s.as_bytes()
        .chunks(2)
        .map(|p| u8::from_str_radix(std::str::from_utf8(p).unwrap(), 16).unwrap())
        .collect()
}
fn fixture(label: &str, suffix: &str) -> String {
    std::fs::read_to_string(format!(
        "{}/tests/inbox_v2/fixtures/{label}.{suffix}.hex",
        env!("CARGO_MANIFEST_DIR")
    ))
    .unwrap()
}

#[test]
fn golden_vectors_encode_and_open() {
    let (alice, bob) = keys();
    for (label, body) in cases() {
        let sealed =
            seal_v2_with_rng(&alice, bob.public(), &body, TTL, NOW, ID, &mut FixedRng).unwrap();
        let encoded_body = postcard::to_allocvec(&body).unwrap();
        assert_eq!(
            hex(&encoded_body),
            fixture(label, "body").trim(),
            "{label} body"
        );
        let expected = unhex(&fixture(label, "envelope"));
        assert_eq!(sealed.body, expected, "{label} envelope");
        assert_eq!(
            sealed.body,
            seal_plain(&plain(body.clone()), INFO_PREFIX_V2),
            "borrowed encoding"
        );
        let opened = bob_opens(&expected, NOW).unwrap();
        assert_eq!(
            opened,
            OpenedAny {
                msg_id: ID,
                sender_fp: alice.fingerprint(),
                created_at: NOW,
                expires_at: NOW + 3600,
                body
            }
        );
        assert_eq!(opened.keep_seen_until(), NOW + 3600 + CLOCK_SKEW_SECS);
    }
}

#[test]
fn public_seal_v2_round_trips_all_bodies() {
    let (alice, bob) = keys();
    for (label, body) in cases() {
        let sealed = seal_v2(&alice, bob.public(), &body, TTL, NOW).unwrap();
        let opened = bob_opens(&sealed.body, NOW).unwrap();
        assert_eq!(opened.body, body, "{label}");
        assert_eq!(opened.msg_id, sealed.msg_id);
        assert_eq!(opened.sender_fp, alice.fingerprint());
        assert_eq!((opened.created_at, opened.expires_at), (NOW, NOW + 3600));
    }
}

#[test]
fn v1_open_rejects_v2_before_decryption() {
    let (alice, bob) = keys();
    let sealed = seal_v2(&alice, bob.public(), &hello(), TTL, NOW).unwrap();
    let mut envelope = InboxEnvelope::decode(&sealed.body).unwrap();
    assert_eq!(envelope.v, 2);
    for body in [sealed.body, {
        envelope.ct.clear();
        envelope.encode()
    }] {
        assert_eq!(
            open(
                &body,
                &[],
                |_| panic!("peer lookup before version check"),
                |_| panic!("seen lookup before version check"),
                NOW
            )
            .unwrap_err(),
            InboxError::UnsupportedVersion(2)
        );
    }
}

#[test]
fn open_any_maps_v1_to_items() {
    let (alice, bob) = keys();
    let sealed = seal(&alice, bob.public(), &[item()], TTL, NOW).unwrap();
    let opened = bob_opens(&sealed.body, NOW).unwrap();
    assert_eq!(opened.body, Body::Items(vec![item()]));
    assert_eq!(opened.msg_id, sealed.msg_id);
    assert_eq!(opened.sender_fp, alice.fingerprint());
    assert_eq!((opened.created_at, opened.expires_at), (NOW, NOW + 3600));
}

#[test]
fn v2_rejects_inner_v1() {
    let mut p = plain(hello());
    p.v = 1;
    assert_eq!(
        bob_opens(&seal_plain(&p, INFO_PREFIX_V2), NOW).unwrap_err(),
        InboxError::UnsupportedVersion(1)
    );
}

#[test]
fn v2_rejects_v1_info() {
    assert_eq!(
        bob_opens(&seal_plain(&plain(hello()), INFO_PREFIX), NOW).unwrap_err(),
        InboxError::DecryptFailed
    );
}

#[test]
fn lineage_limit_on_decode_validate_and_open() {
    for n in [0, 64, 65] {
        let mut c = change();
        c.lineage = vec![Vid([7; 16]); n];
        let bytes = postcard::to_allocvec(&c).unwrap();
        assert_eq!(postcard::from_bytes::<Change>(&bytes).is_ok(), n <= 64);
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Change>(&json).is_ok(), n <= 64);
        assert_eq!(c.validate().is_ok(), n <= 64);
        let body = Body::Sync(SyncMsg::Changes { changes: vec![c] });
        let result = bob_opens(&seal_plain(&plain(body.clone()), INFO_PREFIX_V2), NOW);
        let (alice, bob) = keys();
        let sealed = seal_v2(&alice, bob.public(), &body, TTL, NOW);
        if n <= 64 {
            assert!(result.is_ok());
            assert!(sealed.is_ok());
        } else {
            assert_eq!(result.unwrap_err(), InboxError::Malformed);
            assert_eq!(sealed.unwrap_err(), InboxError::Malformed);
        }
    }
}

#[test]
fn duplicate_change_and_item_names_are_malformed() {
    let mut other = change();
    other.generation += 1;
    other.new_vid = Vid([0xaa; 16]);
    for body in [
        Body::Sync(SyncMsg::Changes {
            changes: vec![change(), other],
        }),
        Body::Items(vec![item(), item()]),
    ] {
        assert_eq!(
            bob_opens(&seal_plain(&plain(body.clone()), INFO_PREFIX_V2), NOW).unwrap_err(),
            InboxError::Malformed
        );
        let (alice, bob) = keys();
        assert!(seal_v2(&alice, bob.public(), &body, TTL, NOW).is_err());
    }
}

#[test]
fn v2_lifetime_skew_and_replay_checks() {
    let bytes = seal_plain(&plain(hello()), INFO_PREFIX_V2);
    assert!(bob_opens(&bytes, NOW - CLOCK_SKEW_SECS).is_ok());
    assert!(bob_opens(&bytes, NOW + 3600 + CLOCK_SKEW_SECS).is_ok());
    assert_eq!(
        bob_opens(&bytes, NOW - CLOCK_SKEW_SECS - 1).unwrap_err(),
        InboxError::NotYetValid
    );
    assert_eq!(
        bob_opens(&bytes, NOW + 3601 + CLOCK_SKEW_SECS).unwrap_err(),
        InboxError::Expired
    );
    for (created, expires, ok) in [
        (NOW, NOW, true),
        (NOW, NOW + MAX_LIFETIME_SECS, true),
        (NOW, NOW - 1, false),
        (NOW, NOW + MAX_LIFETIME_SECS + 1, false),
        (i64::MIN, i64::MAX, false),
    ] {
        let mut p = plain(hello());
        p.created_at = created;
        p.expires_at = expires;
        let result = bob_opens(&seal_plain(&p, INFO_PREFIX_V2), NOW);
        if ok {
            assert!(result.is_ok());
        } else {
            assert_eq!(result.unwrap_err(), InboxError::BadLifetime);
        }
    }
    let (alice, bob) = keys();
    assert_eq!(
        open_any(
            &bytes,
            &[&bob],
            |_| Some(*alice.public()),
            |id| {
                assert_eq!(*id, ID);
                true
            },
            NOW
        )
        .unwrap_err(),
        InboxError::Replay
    );
    for (ttl, now) in [
        (Duration::ZERO, NOW),
        (Duration::from_secs(MAX_LIFETIME_SECS as u64 + 1), NOW),
        (TTL, i64::MAX),
    ] {
        assert_eq!(
            seal_v2(&alice, bob.public(), &hello(), ttl, now).unwrap_err(),
            InboxError::InvalidTtl
        );
    }
}

#[test]
fn v2_fingerprint_and_authentication_checks() {
    let (alice, bob) = keys();
    for sender in [true, false] {
        let mut p = plain(hello());
        if sender {
            p.sender_fp = bob.fingerprint();
        } else {
            p.recipient_fp = alice.fingerprint();
        }
        assert_eq!(
            bob_opens(&seal_plain(&p, INFO_PREFIX_V2), NOW).unwrap_err(),
            InboxError::FingerprintMismatch
        );
    }
    let bytes = seal_plain(&plain(hello()), INFO_PREFIX_V2);
    assert_eq!(
        open_any(&bytes, &[&alice], |_| Some(*alice.public()), |_| false, NOW).unwrap_err(),
        InboxError::WrongRecipient
    );
    for pk in [None, Some(*bob.public())] {
        assert_eq!(
            open_any(&bytes, &[&bob], |_| pk, |_| false, NOW).unwrap_err(),
            InboxError::UnknownSender
        );
    }
    assert!(
        open_any(
            &bytes,
            &[&alice, &bob],
            |_| Some(*alice.public()),
            |_| false,
            NOW
        )
        .is_ok()
    );
    for field in 0..3 {
        let mut env = InboxEnvelope::decode(&bytes).unwrap();
        match field {
            0 => env.enc[0] ^= 1,
            1 => env.ct[0] ^= 1,
            _ => *env.ct.last_mut().unwrap() ^= 1,
        }
        assert_eq!(
            bob_opens(&env.encode(), NOW).unwrap_err(),
            InboxError::DecryptFailed
        );
    }
}

#[test]
fn v2_size_and_envelope_checks() {
    let (alice, bob) = keys();
    let body = Body::Sync(SyncMsg::Offer {
        name: name("large"),
        known_generation: 0,
        vid: Vid([1; 16]),
        lineage: vec![],
        kind: ItemKind::File,
        value: SecretBytes::from_slice(&vec![0; MAX_MESSAGE_BYTES]),
    });
    assert_eq!(
        seal_v2(&alice, bob.public(), &body, TTL, NOW).unwrap_err(),
        InboxError::TooLarge
    );
    assert_eq!(
        bob_opens(&vec![0; MAX_MESSAGE_BYTES + 1], NOW).unwrap_err(),
        InboxError::TooLarge
    );
    let bytes = seal_plain(&plain(hello()), INFO_PREFIX_V2);
    let mut env = InboxEnvelope::decode(&bytes).unwrap();
    env.v = 3;
    assert_eq!(
        bob_opens(&env.encode(), NOW).unwrap_err(),
        InboxError::UnsupportedVersion(3)
    );
    env.v = 2;
    env.suite = 2;
    assert_eq!(
        bob_opens(&env.encode(), NOW).unwrap_err(),
        InboxError::UnsupportedSuite(2)
    );
    env.suite = 1;
    env.ct.truncate(15);
    assert_eq!(
        bob_opens(&env.encode(), NOW).unwrap_err(),
        InboxError::Malformed
    );
    let mut trailing = bytes.clone();
    trailing.push(0);
    for bad in [vec![], bytes[..bytes.len() - 1].to_vec(), trailing] {
        assert_eq!(bob_opens(&bad, NOW).unwrap_err(), InboxError::Malformed);
    }
}

#[test]
fn vid_serde_and_secret_debug() {
    let vid = Vid([0xab; 16]);
    assert_eq!(postcard::to_allocvec(&vid).unwrap(), vec![0xab; 16]);
    let json = format!("\"{}\"", "ab".repeat(16));
    assert_eq!(serde_json::to_string(&vid).unwrap(), json);
    assert_eq!(serde_json::from_str::<Vid>(&json).unwrap(), vid);
    assert_eq!(
        serde_json::from_str::<Vid>(&json.to_uppercase()).unwrap(),
        vid
    );
    for bad in ["\"00\"", "\"zzzzzzzzzzzzzzzzzzzzzzzzzzzzzzzz\"", "[]"] {
        assert!(serde_json::from_str::<Vid>(bad).is_err());
    }
    let random = Vid::random();
    assert_eq!(
        postcard::from_bytes::<Vid>(&postcard::to_allocvec(&random).unwrap()).unwrap(),
        random
    );
    for (_, body) in cases() {
        let debug = format!("{body:?}");
        assert!(!debug.contains("test-secret"));
        assert!(!debug.contains("TEST=1"));
    }
}

fn assert_sync_validation(msg: SyncMsg, valid: bool) {
    let bytes = postcard::to_allocvec(&msg).unwrap();
    assert_eq!(postcard::from_bytes::<SyncMsg>(&bytes).is_ok(), valid);
    let json = serde_json::to_string(&msg).unwrap();
    assert_eq!(serde_json::from_str::<SyncMsg>(&json).is_ok(), valid);
    assert_eq!(msg.validate().is_ok(), valid);
    if !valid {
        assert_eq!(msg.validate().unwrap_err(), InboxError::Malformed);
    }
    let body = Body::Sync(msg);
    let opened = bob_opens(&seal_plain(&plain(body.clone()), INFO_PREFIX_V2), NOW);
    let (alice, bob) = keys();
    let sealed = seal_v2(&alice, bob.public(), &body, TTL, NOW);
    if valid {
        assert!(opened.is_ok());
        assert!(sealed.is_ok());
    } else {
        assert_eq!(opened.unwrap_err(), InboxError::Malformed);
        assert_eq!(sealed.unwrap_err(), InboxError::Malformed);
    }
}

#[test]
fn offer_lineage_limit_on_decode_validate_seal_and_open() {
    for n in [0, 64, 65] {
        let msg = SyncMsg::Offer {
            name: name("token"),
            known_generation: 0,
            vid: Vid([1; 16]),
            lineage: vec![Vid([7; 16]); n],
            kind: ItemKind::Text,
            value: SecretBytes::from_slice(b"test-secret"),
        };
        let bytes = postcard::to_allocvec(&msg).unwrap();
        assert_eq!(postcard::from_bytes::<SyncMsg>(&bytes).is_ok(), n <= 64);
        let json = serde_json::to_string(&msg).unwrap();
        assert_eq!(serde_json::from_str::<SyncMsg>(&json).is_ok(), n <= 64);
        assert_sync_validation(msg, n <= 64);
    }
}

#[test]
fn change_parents_limit_on_decode_validate_seal_and_open() {
    for n in [0, 64, 65, 66] {
        let mut c = change();
        c.parents = vec![Vid([7; 16]); n];
        let bytes = postcard::to_allocvec(&c).unwrap();
        assert_eq!(postcard::from_bytes::<Change>(&bytes).is_ok(), n <= 65);
        let json = serde_json::to_string(&c).unwrap();
        assert_eq!(serde_json::from_str::<Change>(&json).is_ok(), n <= 65);
        assert_eq!(c.validate().is_ok(), n <= 65);
        assert_sync_validation(SyncMsg::Changes { changes: vec![c] }, n <= 65);
    }
}

#[test]
fn duplicate_digest_names_are_malformed() {
    let entry = DigestEntry {
        name: name("token"),
        generation: 1,
        head: Vid([1; 16]),
    };
    for same_metadata in [true, false] {
        let mut other = entry.clone();
        if !same_metadata {
            other.generation += 1;
            other.head = Vid([2; 16]);
        }
        assert_sync_validation(
            SyncMsg::Digest {
                entries: vec![entry.clone(), other],
            },
            false,
        );
    }
    let mut other = entry.clone();
    other.name = name("other");
    assert_sync_validation(
        SyncMsg::Digest {
            entries: vec![entry, other],
        },
        true,
    );
}

#[test]
fn duplicate_ack_change_ids_are_malformed() {
    let id = ChangeId {
        name: name("token"),
        generation: 1,
        new_vid: Vid([1; 16]),
    };
    for result in [AckResult::Applied, AckResult::Rejected] {
        assert_sync_validation(
            SyncMsg::Ack {
                results: vec![(id.clone(), AckResult::Applied), (id.clone(), result)],
            },
            false,
        );
    }
    for field in 0..3 {
        let mut other = id.clone();
        match field {
            0 => other.name = name("other"),
            1 => other.generation += 1,
            _ => other.new_vid = Vid([2; 16]),
        }
        assert_sync_validation(
            SyncMsg::Ack {
                results: vec![(id.clone(), AckResult::Applied), (other, AckResult::Held)],
            },
            true,
        );
    }
}

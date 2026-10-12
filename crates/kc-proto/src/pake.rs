//! SPAKE2 and the channel key schedule (PROTOCOL §3).
//!
//! ```text
//! pw  = "kc1:" || canonical code        idA = "kc1/receiver"   idB = "kc1/sender"
//! R: start_a(pw, idA, idB) -> msgA      S: start_b(pw, idA, idB) -> msgB      finish -> K
//! T   = SHA-256("kc1-transcript" || u16be(channel) || lp(msgA) || lp(msgB)),  lp(x) = u32be(len x) || x
//! prk = HKDF-Extract(salt = T, ikm = K)
//! kR = Expand(prk, "kc1 confirm R")   kS = Expand(prk, "kc1 confirm S")           (32 bytes each)
//! kS2R = Expand(prk, "kc1 data S2R")  kR2S = Expand(prk, "kc1 data R2S")          (32 bytes each)
//! sas = Expand(prk, "kc1 sas")[..4] -> 4 PGP words
//! confirm MAC = HMAC-SHA256(kR or kS, T), checked in constant time
//! aad = "kc1" || u16be(channel) || phase.byte() || writer_role.byte() || T
//! sealed = nonce(24) || XChaCha20-Poly1305(key, nonce, pad(postcard(value)), aad)
//! ```

use std::fmt;

use hmac::{Hmac, KeyInit, Mac};
use kc_wire::{Phase, Role};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use spake2::{Ed25519Group, Identity, Password, Spake2};
use subtle::ConstantTimeEq;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::aead::{self, NONCE_LEN, TAG_LEN};
use crate::code::{Code, CodeKind};
use crate::pad::{self, PadError};
use crate::words;

/// SPAKE2 identity of side A, the receiver.
pub const ID_A: &[u8] = b"kc1/receiver";
/// SPAKE2 identity of side B, the sender.
pub const ID_B: &[u8] = b"kc1/sender";
pub const TRANSCRIPT_LABEL: &[u8] = b"kc1-transcript";
pub const LABEL_CONFIRM_R: &[u8] = b"kc1 confirm R";
pub const LABEL_CONFIRM_S: &[u8] = b"kc1 confirm S";
pub const LABEL_DATA_S2R: &[u8] = b"kc1 data S2R";
pub const LABEL_DATA_R2S: &[u8] = b"kc1 data R2S";
pub const LABEL_SAS: &[u8] = b"kc1 sas";
pub const AAD_PREFIX: &[u8] = b"kc1";
/// Length of a SPAKE2 message over Ed25519: a side byte and a point.
pub const PAKE_MESSAGE_LEN: usize = 33;
/// Length of a key-confirmation MAC.
pub const CONFIRM_MAC_LEN: usize = 32;

type HmacSha256 = Hmac<Sha256>;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("the other side's key-exchange message is malformed")]
pub struct PakeError;

/// Why a sealed phase message didn't open.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum OpenError {
    /// Authentication failed: tampered, corrupted, or a different key.
    #[error("message failed authentication")]
    Tampered,
    /// Authentic, but the padding or the postcard value is invalid.
    #[error("message is malformed")]
    Malformed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum SealError {
    #[error("this side can't write that phase")]
    WrongPhase,
    #[error("value could not be encoded")]
    Encode,
}

/// One side's SPAKE2 state, between writing its message and reading the peer's.
///
/// Known limitation: `spake2` 0.4 (mandated by PROTOCOL §1, unaudited) keeps
/// its own copy of the password and its secret scalar in plain fields that it
/// doesn't wipe on drop; 0.5.0-pre.0 doesn't either. Our copies (the code, the
/// password buffer we build, `K` and every derived key) are wiped.
pub struct PakeStart {
    role: Role,
    channel: u16,
    kind: CodeKind,
    state: Spake2<Ed25519Group>,
    message: Vec<u8>,
}

impl PakeStart {
    /// Starts SPAKE2 for `role`: the receiver is side A, the sender side B.
    pub fn new(role: Role, code: &Code) -> PakeStart {
        let pw = Password::new(&*code.pake_password());
        let (id_a, id_b) = (Identity::new(ID_A), Identity::new(ID_B));
        let (state, message) = match role {
            Role::Receiver => Spake2::<Ed25519Group>::start_a(&pw, &id_a, &id_b),
            Role::Sender => Spake2::<Ed25519Group>::start_b(&pw, &id_a, &id_b),
        };
        PakeStart {
            role,
            channel: code.channel(),
            kind: code.kind(),
            state,
            message,
        }
    }

    #[cfg(test)]
    pub(crate) fn with_rng(
        role: Role,
        code: &Code,
        rng: impl rand_core_06::RngCore + rand_core_06::CryptoRng,
    ) -> PakeStart {
        let pw = Password::new(&*code.pake_password());
        let (id_a, id_b) = (Identity::new(ID_A), Identity::new(ID_B));
        let (state, message) = match role {
            Role::Receiver => Spake2::<Ed25519Group>::start_a_with_rng(&pw, &id_a, &id_b, rng),
            Role::Sender => Spake2::<Ed25519Group>::start_b_with_rng(&pw, &id_a, &id_b, rng),
        };
        PakeStart {
            role,
            channel: code.channel(),
            kind: code.kind(),
            state,
            message,
        }
    }

    /// Our SPAKE2 message, to `PUT` as the `pake` phase.
    pub fn message(&self) -> &[u8] {
        &self.message
    }

    /// Finishes SPAKE2 with the peer's message and derives the channel keys.
    pub fn finish(self, peer_message: &[u8]) -> Result<ChannelKeys, PakeError> {
        let PakeStart {
            role,
            channel,
            kind,
            state,
            message,
        } = self;
        if peer_message.len() != PAKE_MESSAGE_LEN {
            return Err(PakeError);
        }
        let k = Zeroizing::new(state.finish(peer_message).map_err(|_| PakeError)?);
        let (msg_a, msg_b) = match role {
            Role::Receiver => (message.as_slice(), peer_message),
            Role::Sender => (peer_message, message.as_slice()),
        };
        Ok(ChannelKeys::derive(role, channel, kind, &k, msg_a, msg_b))
    }
}

/// Keys for one channel session, from one side's point of view. Wiped on drop.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct ChannelKeys {
    #[zeroize(skip)]
    role: Role,
    channel: u16,
    #[zeroize(skip)]
    kind: CodeKind,
    transcript: [u8; 32],
    confirm_r: [u8; 32],
    confirm_s: [u8; 32],
    data_s2r: [u8; 32],
    data_r2s: [u8; 32],
    sas: [u8; 4],
}

impl ChannelKeys {
    pub(crate) fn derive(
        role: Role,
        channel: u16,
        kind: CodeKind,
        k: &[u8],
        msg_a: &[u8],
        msg_b: &[u8],
    ) -> ChannelKeys {
        let transcript = transcript_hash(channel, msg_a, msg_b);
        let prk = hkdf_extract(&transcript, k);
        let expand = |label: &[u8], out: &mut [u8]| hkdf_expand(&prk, label, out);
        let mut keys = ChannelKeys {
            role,
            channel,
            kind,
            transcript,
            confirm_r: [0; 32],
            confirm_s: [0; 32],
            data_s2r: [0; 32],
            data_r2s: [0; 32],
            sas: [0; 4],
        };
        expand(LABEL_CONFIRM_R, &mut keys.confirm_r);
        expand(LABEL_CONFIRM_S, &mut keys.confirm_s);
        expand(LABEL_DATA_S2R, &mut keys.data_s2r);
        expand(LABEL_DATA_R2S, &mut keys.data_r2s);
        expand(LABEL_SAS, &mut keys.sas);
        keys
    }

    pub fn role(&self) -> Role {
        self.role
    }

    pub fn channel(&self) -> u16 {
        self.channel
    }

    /// The transcript hash `T`.
    pub fn transcript(&self) -> &[u8; 32] {
        &self.transcript
    }

    /// Our key-confirmation MAC, to `PUT` as the `confirm` phase.
    pub fn confirm_mac(&self) -> [u8; CONFIRM_MAC_LEN] {
        self.mac_for(self.role)
    }

    /// Checks the peer's confirmation MAC in constant time.
    pub fn verify_peer_confirm(&self, mac: &[u8]) -> bool {
        let expected = self.mac_for(self.role.peer());
        mac.len() == CONFIRM_MAC_LEN && bool::from(expected.ct_eq(mac))
    }

    fn mac_for(&self, role: Role) -> [u8; CONFIRM_MAC_LEN] {
        let key = match role {
            Role::Receiver => &self.confirm_r,
            Role::Sender => &self.confirm_s,
        };
        let mut out = [0u8; CONFIRM_MAC_LEN];
        hmac_into(key, &[&self.transcript], &mut out);
        out
    }

    /// The short authentication string both screens show when pairing.
    /// `None` for one-shot transfer codes.
    pub fn sas(&self) -> Option<Sas> {
        (self.kind == CodeKind::Pairing).then_some(Sas(self.sas))
    }

    /// `"kc1" || u16be(channel) || phase.byte() || writer.byte() || T`.
    pub fn aad(&self, phase: Phase, writer: Role) -> [u8; 39] {
        let mut aad = [0u8; 39];
        aad[..3].copy_from_slice(AAD_PREFIX);
        aad[3..5].copy_from_slice(&self.channel.to_be_bytes());
        aad[5] = phase.byte();
        aad[6] = writer.byte();
        aad[7..].copy_from_slice(&self.transcript);
        aad
    }

    fn data_key(&self, writer: Role) -> &[u8; 32] {
        match writer {
            Role::Sender => &self.data_s2r,
            Role::Receiver => &self.data_r2s,
        }
    }

    /// Seals `value` for a phase this side writes (`payload` for the sender,
    /// `ack` for the receiver): `nonce || XChaCha20-Poly1305(pad(postcard(value)))`.
    pub fn seal<T: Serialize + ?Sized>(
        &self,
        phase: Phase,
        value: &T,
    ) -> Result<Vec<u8>, SealError> {
        if !matches!(phase, Phase::Payload | Phase::Ack) || !phase.writable_by(self.role) {
            return Err(SealError::WrongPhase);
        }
        let mut buf =
            pad::encode(value, &[0u8; NONCE_LEN], TAG_LEN).map_err(|_| SealError::Encode)?;
        aead::seal_in_place(
            self.data_key(self.role),
            &self.aad(phase, self.role),
            &mut buf,
        )
        .map_err(|_| SealError::Encode)?;
        // Everything after the nonce is now ciphertext.
        Ok(std::mem::take(&mut *buf))
    }

    /// Opens a phase message written by the peer.
    pub fn open<T: DeserializeOwned>(&self, phase: Phase, body: &[u8]) -> Result<T, OpenError> {
        let writer = self.role.peer();
        if !matches!(phase, Phase::Payload | Phase::Ack) || !phase.writable_by(writer) {
            return Err(OpenError::Malformed);
        }
        let padded = aead::open(self.data_key(writer), &self.aad(phase, writer), body)
            .map_err(|_| OpenError::Tampered)?;
        pad::decode(&padded).map_err(|e: PadError| {
            debug_assert!(matches!(
                e,
                PadError::BadLength | PadError::BadPadding | PadError::Decode
            ));
            OpenError::Malformed
        })
    }
}

impl fmt::Debug for ChannelKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ChannelKeys")
            .field("role", &self.role)
            .field("channel", &self.channel)
            .finish_non_exhaustive()
    }
}

/// HMAC-SHA256 of the concatenated `parts`, truncated to `out.len()` (at
/// most 32). The HMAC state and its output are wiped on drop.
fn hmac_into(key: &[u8], parts: &[&[u8]], out: &mut [u8]) {
    let mut mac = <HmacSha256 as KeyInit>::new_from_slice(key).expect("HMAC takes any key length");
    for part in parts {
        mac.update(part);
    }
    let tag = mac.finalize();
    out.copy_from_slice(&tag.as_bytes()[..out.len()]);
}

/// HKDF-Extract (RFC 5869): `PRK = HMAC-SHA256(salt, IKM)`.
///
/// Written out instead of using the `hkdf` crate so the PRK and every
/// intermediate block stay in wiped buffers.
fn hkdf_extract(salt: &[u8], ikm: &[u8]) -> Zeroizing<[u8; 32]> {
    let mut prk = Zeroizing::new([0u8; 32]);
    hmac_into(salt, &[ikm], &mut prk[..]);
    prk
}

/// HKDF-Expand (RFC 5869) for `L <= 32`, which needs one block:
/// `OKM = first L bytes of T(1) = HMAC-SHA256(PRK, info || 0x01)`.
fn hkdf_expand(prk: &[u8; 32], info: &[u8], out: &mut [u8]) {
    assert!(out.len() <= 32, "one HKDF-SHA256 block is 32 bytes");
    hmac_into(prk, &[info, &[1u8]], out);
}

fn transcript_hash(channel: u16, msg_a: &[u8], msg_b: &[u8]) -> [u8; 32] {
    let lp = |h: &mut Sha256, x: &[u8]| {
        let len = u32::try_from(x.len()).expect("SPAKE2 messages are short");
        h.update(len.to_be_bytes());
        h.update(x);
    };
    let mut h = Sha256::new();
    h.update(TRANSCRIPT_LABEL);
    h.update(channel.to_be_bytes());
    lp(&mut h, msg_a);
    lp(&mut h, msg_b);
    h.finalize().into()
}

/// Four PGP words (even, odd, even, odd) derived from the session keys.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Sas([u8; 4]);

impl Sas {
    pub fn words(&self) -> [&'static str; 4] {
        let w = words::encode(&self.0);
        [w[0], w[1], w[2], w[3]]
    }
}

impl fmt::Display for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.words().join(" "))
    }
}

impl fmt::Debug for Sas {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Sas({self})")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }

    /// Fixed inputs for the golden vector. Expected values were computed
    /// independently in Python (hashlib/hmac) from the PROTOCOL §3 formulas.
    fn golden() -> (Vec<u8>, Vec<u8>, Vec<u8>) {
        let k: Vec<u8> = (0x00..0x20).collect();
        let msg_a: Vec<u8> = std::iter::once(b'A').chain(0x40..0x60).collect();
        let msg_b: Vec<u8> = std::iter::once(b'B').chain(0x80..0xa0).collect();
        (k, msg_a, msg_b)
    }

    #[test]
    fn hkdf_matches_rfc5869() {
        // RFC 5869 A.1 and A.3 (first 32 bytes of the 42-byte OKM).
        let ikm = [0x0bu8; 22];
        let salt: Vec<u8> = (0x00..=0x0c).collect();
        let info: Vec<u8> = (0xf0..=0xf9).collect();
        let prk = hkdf_extract(&salt, &ikm);
        assert_eq!(
            hex(&*prk),
            "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5"
        );
        let mut okm = [0u8; 32];
        hkdf_expand(&prk, &info, &mut okm);
        assert_eq!(
            hex(&okm),
            "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf"
        );

        let prk = hkdf_extract(&[], &ikm);
        assert_eq!(
            hex(&*prk),
            "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04"
        );
        hkdf_expand(&prk, &[], &mut okm);
        assert_eq!(
            hex(&okm),
            "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d"
        );
        let mut short = [0u8; 4];
        hkdf_expand(&prk, &[], &mut short);
        assert_eq!(short, okm[..4]);
    }

    #[test]
    fn golden_key_schedule() {
        let (k, msg_a, msg_b) = golden();
        let r = ChannelKeys::derive(Role::Receiver, 4721, CodeKind::Pairing, &k, &msg_a, &msg_b);
        let s = ChannelKeys::derive(Role::Sender, 4721, CodeKind::Pairing, &k, &msg_a, &msg_b);

        assert_eq!(
            hex(r.transcript()),
            "757662d552f6c351051a8e07ebb4c8f70d0ca7c8fa549d66f8c7ee772250e00c"
        );
        let prk = hkdf_extract(r.transcript(), &k);
        assert_eq!(
            hex(&*prk),
            "d40ab1900156849ef9e0d6e87ba321f85f78b0a98ad2e10fcfb0a757d346a75a"
        );
        assert_eq!(
            hex(&r.confirm_r),
            "72d74e0c2377cd69f79bfc757c11a9e508b2946956585ff1c4e6a51287db1099"
        );
        assert_eq!(
            hex(&r.confirm_s),
            "6291e27c5b98942eca9dc1eba49727bda18775e3afda468384b9ba6b561290bc"
        );
        assert_eq!(
            hex(&r.data_s2r),
            "29b33eb48a41bee33a2f67a797437153a77e8f1bb3fdfe408e7bbbf70a4f9f66"
        );
        assert_eq!(
            hex(&r.data_r2s),
            "272c259399c04cb028a48b7539cf1ff7c4310871f7114fd9fffd92be56fccb9b"
        );
        assert_eq!(hex(&r.sas), "ca0e3a8a");
        assert_eq!(
            r.sas().unwrap().words(),
            ["spellbind", "atlantic", "cleanup", "maverick"]
        );
        assert_eq!(r.sas(), s.sas());

        let mac_r = "4fa1ab5fd419179a957de84dfb11e7dfa282a3ce03a50bb6cd11720ebe48f879";
        let mac_s = "2e521cb43fee96d19aa44955feeb0f7488b7d0a15e0418e67456ca1a65048510";
        assert_eq!(hex(&r.confirm_mac()), mac_r);
        assert_eq!(hex(&s.confirm_mac()), mac_s);
        assert!(r.verify_peer_confirm(&s.confirm_mac()));
        assert!(s.verify_peer_confirm(&r.confirm_mac()));
        assert!(
            !r.verify_peer_confirm(&r.confirm_mac()),
            "a reflected MAC must not verify"
        );
        assert!(!r.verify_peer_confirm(&s.confirm_mac()[..31]));

        assert_eq!(
            hex(&s.aad(Phase::Payload, Role::Sender)),
            "6b633112710373757662d552f6c351051a8e07ebb4c8f70d0ca7c8fa549d66f8c7ee772250e00c"
        );
        assert_eq!(
            hex(&r.aad(Phase::Ack, Role::Receiver)),
            "6b633112710472757662d552f6c351051a8e07ebb4c8f70d0ca7c8fa549d66f8c7ee772250e00c"
        );
        let transfer =
            ChannelKeys::derive(Role::Receiver, 4721, CodeKind::Transfer, &k, &msg_a, &msg_b);
        assert_eq!(transfer.sas(), None);
    }

    /// A deterministic RNG so the whole SPAKE2 exchange can be pinned.
    struct CounterRng(u64);

    impl rand_core_06::RngCore for CounterRng {
        fn next_u32(&mut self) -> u32 {
            rand_core_06::impls::next_u32_via_fill(self)
        }
        fn next_u64(&mut self) -> u64 {
            rand_core_06::impls::next_u64_via_fill(self)
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.chunks_mut(32) {
                self.0 += 1;
                let block = Sha256::digest(self.0.to_be_bytes());
                chunk.copy_from_slice(&block[..chunk.len()]);
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_06::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl rand_core_06::CryptoRng for CounterRng {}

    #[test]
    fn golden_spake2_exchange() {
        // Pins the password ("kc1:" || canonical code), identities and roles.
        let code = Code::parse("4721-absurd-amulet").unwrap();
        let r = PakeStart::with_rng(Role::Receiver, &code, CounterRng(1000));
        let s = PakeStart::with_rng(Role::Sender, &code, CounterRng(2000));
        assert_eq!(r.message()[0], b'A');
        assert_eq!(s.message()[0], b'B');
        let (msg_a, msg_b) = (r.message().to_vec(), s.message().to_vec());
        let rk = r.finish(&msg_b).unwrap();
        let sk = s.finish(&msg_a).unwrap();
        assert_eq!(rk.transcript(), sk.transcript());
        assert!(rk.verify_peer_confirm(&sk.confirm_mac()));
        assert!(sk.verify_peer_confirm(&rk.confirm_mac()));
        assert_eq!(hex(&msg_a), GOLDEN_MSG_A);
        assert_eq!(hex(&msg_b), GOLDEN_MSG_B);
        assert_eq!(hex(rk.transcript()), GOLDEN_T);
        assert_eq!(hex(&rk.confirm_mac()), GOLDEN_MAC_R);
    }

    // Computed once with `CounterRng` and pinned. T was re-derived from these
    // two messages independently in Python.
    const GOLDEN_MSG_A: &str = "41a90b1dfe3fc52b37cf61d04157d30d6aba1dd34e3abd55479e218a5c9a81babc";
    const GOLDEN_MSG_B: &str = "42a85160ae02ec9ca5d5241bb3731060ebb3d8ab51d44a59331a10769313965090";
    const GOLDEN_T: &str = "64b276dab06461804efe21d09bf8b4586e8ab9e4c403621cf679f483b42c01e2";
    const GOLDEN_MAC_R: &str = "9b7cd6aac0bb0305c9b5c98046a0ae075630b7fdd76bb1725ff80f2e6e52f305";

    #[test]
    fn wrong_code_fails_confirmation() {
        let r = PakeStart::new(Role::Receiver, &Code::parse("4721-absurd-amulet").unwrap());
        let s = PakeStart::new(Role::Sender, &Code::parse("4721-absurd-amusement").unwrap());
        let (msg_a, msg_b) = (r.message().to_vec(), s.message().to_vec());
        let rk = r.finish(&msg_b).unwrap();
        let sk = s.finish(&msg_a).unwrap();
        assert!(!rk.verify_peer_confirm(&sk.confirm_mac()));
        assert!(!sk.verify_peer_confirm(&rk.confirm_mac()));
    }

    #[test]
    fn same_code_on_a_different_channel_fails() {
        // The channel is in the password (via the code) and in T.
        let r = PakeStart::new(Role::Receiver, &Code::parse("4721-absurd-amulet").unwrap());
        let s = PakeStart::new(Role::Sender, &Code::parse("4722-absurd-amulet").unwrap());
        let (msg_a, msg_b) = (r.message().to_vec(), s.message().to_vec());
        let rk = r.finish(&msg_b).unwrap();
        let sk = s.finish(&msg_a).unwrap();
        assert!(!rk.verify_peer_confirm(&sk.confirm_mac()));
    }

    #[test]
    fn malformed_and_reflected_messages_are_rejected() {
        let code = Code::parse("4721-absurd-amulet").unwrap();
        let r = PakeStart::new(Role::Receiver, &code);
        let own = r.message().to_vec();
        assert_eq!(
            r.finish(&own).unwrap_err(),
            PakeError,
            "own message reflected back"
        );
        assert_eq!(
            PakeStart::new(Role::Receiver, &code)
                .finish(&[b'B'; 32])
                .unwrap_err(),
            PakeError
        );
        assert_eq!(
            PakeStart::new(Role::Receiver, &code)
                .finish(&[b'B'; 34])
                .unwrap_err(),
            PakeError
        );
        let s = PakeStart::new(Role::Sender, &code);
        let mut bad = s.message().to_vec();
        bad[0] = b'S';
        assert_eq!(
            PakeStart::new(Role::Receiver, &code)
                .finish(&bad)
                .unwrap_err(),
            PakeError
        );
    }

    #[test]
    fn sealed_phases_open_only_where_they_belong() {
        let (k, msg_a, msg_b) = golden();
        let r = ChannelKeys::derive(Role::Receiver, 4721, CodeKind::Transfer, &k, &msg_a, &msg_b);
        let s = ChannelKeys::derive(Role::Sender, 4721, CodeKind::Transfer, &k, &msg_a, &msg_b);
        let value = (1u8, String::from("payload"));

        let body = s.seal(Phase::Payload, &value).unwrap();
        assert_eq!(body.len(), NONCE_LEN + 4096 + TAG_LEN);
        assert_eq!(
            r.open::<(u8, String)>(Phase::Payload, &body).unwrap(),
            value
        );
        // The writer can't read its own message back as if the peer wrote it.
        assert_eq!(
            s.open::<(u8, String)>(Phase::Payload, &body),
            Err(OpenError::Malformed)
        );
        // The phase byte is bound into the AAD.
        assert_eq!(s.seal(Phase::Ack, &value), Err(SealError::WrongPhase));
        assert_eq!(r.seal(Phase::Payload, &value), Err(SealError::WrongPhase));
        assert_eq!(s.seal(Phase::Confirm, &value), Err(SealError::WrongPhase));

        let ack = r.seal(Phase::Ack, &value).unwrap();
        assert_eq!(s.open::<(u8, String)>(Phase::Ack, &ack).unwrap(), value);
        // A payload replayed as an ack (or vice versa) fails authentication.
        assert_eq!(
            s.open::<(u8, String)>(Phase::Ack, &body),
            Err(OpenError::Tampered)
        );

        let mut flipped = body.clone();
        flipped[NONCE_LEN + 10] ^= 0x80;
        assert_eq!(
            r.open::<(u8, String)>(Phase::Payload, &flipped),
            Err(OpenError::Tampered)
        );

        // Keys from another channel or transcript don't open it.
        let other =
            ChannelKeys::derive(Role::Receiver, 4722, CodeKind::Transfer, &k, &msg_a, &msg_b);
        assert_eq!(
            other.open::<(u8, String)>(Phase::Payload, &body),
            Err(OpenError::Tampered)
        );
        // Authentic but the wrong type is malformed, not tampered.
        assert_eq!(
            r.open::<(u64, u64, u64, u64)>(Phase::Payload, &body),
            Err(OpenError::Malformed)
        );
    }
}

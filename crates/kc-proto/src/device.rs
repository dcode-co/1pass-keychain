//! Device identity for remembered devices (PROTOCOL §4): an X25519 key pair
//! and its fingerprint `fp = SHA-256(device_pk)`.

use std::fmt;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use curve25519_dalek::montgomery::MontgomeryPoint;
use curve25519_dalek::scalar::Scalar;
use hpke::{Deserializable, Kem as _, Serializable};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use crate::rng;

/// The HPKE KEM the device key is used with: DHKEM(X25519, HKDF-SHA256).
pub(crate) type DeviceKem = hpke::kem::X25519HkdfSha256;
pub(crate) type KemPrivateKey = <DeviceKem as hpke::Kem>::PrivateKey;
pub(crate) type KemPublicKey = <DeviceKem as hpke::Kem>::PublicKey;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum DeviceKeyError {
    #[error("a device key is 32 bytes")]
    BadLength,
    #[error("not a usable X25519 public key (small-order point)")]
    WeakPublicKey,
    #[error("not valid base64url")]
    BadEncoding,
}

/// This device's X25519 key pair. The secret half is wiped on drop
/// (`hpke` keeps it in a zeroize-on-drop `x25519_dalek::StaticSecret`).
#[derive(Clone)]
pub struct DeviceKeyPair {
    secret: KemPrivateKey,
    public: DevicePublicKey,
}

impl DeviceKeyPair {
    /// A new random key pair.
    pub fn generate() -> DeviceKeyPair {
        let bytes = Zeroizing::new(rng::array::<32>());
        // X25519 clamps the scalar, so its public key is never a weak point.
        DeviceKeyPair::from_secret_bytes(&*bytes)
            .expect("a clamped X25519 scalar gives a valid key")
    }

    /// Restores a key pair from the 32 secret bytes kept in the OS keychain.
    pub fn from_secret_bytes(bytes: &[u8]) -> Result<DeviceKeyPair, DeviceKeyError> {
        if bytes.len() != 32 {
            return Err(DeviceKeyError::BadLength);
        }
        let secret = KemPrivateKey::from_bytes(bytes).map_err(|_| DeviceKeyError::BadLength)?;
        let pk: [u8; 32] = DeviceKem::sk_to_pk(&secret).to_bytes().into();
        Ok(DeviceKeyPair {
            secret,
            public: DevicePublicKey::from_bytes(pk)?,
        })
    }

    /// The 32 secret bytes, for storing in the OS keychain.
    pub fn secret_bytes(&self) -> Zeroizing<[u8; 32]> {
        let mut out = Zeroizing::new([0u8; 32]);
        self.secret.write_exact(&mut out[..]);
        out
    }

    pub fn public(&self) -> &DevicePublicKey {
        &self.public
    }

    pub fn fingerprint(&self) -> Fingerprint {
        self.public.fingerprint()
    }

    pub(crate) fn kem_private(&self) -> &KemPrivateKey {
        &self.secret
    }
}

impl fmt::Debug for DeviceKeyPair {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DeviceKeyPair")
            .field("public", &self.public)
            .finish_non_exhaustive()
    }
}

/// An X25519 public key that isn't a small-order point.
///
/// Serde: 32 raw bytes in binary formats (postcard), base64url (no padding)
/// in human-readable ones (JSON).
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct DevicePublicKey([u8; 32]);

impl DevicePublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Result<DevicePublicKey, DeviceKeyError> {
        if is_small_order(&bytes) {
            return Err(DeviceKeyError::WeakPublicKey);
        }
        Ok(DevicePublicKey(bytes))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<DevicePublicKey, DeviceKeyError> {
        let arr: [u8; 32] = bytes.try_into().map_err(|_| DeviceKeyError::BadLength)?;
        DevicePublicKey::from_bytes(arr)
    }

    pub fn from_b64url(s: &str) -> Result<DevicePublicKey, DeviceKeyError> {
        let raw = URL_SAFE_NO_PAD
            .decode(s)
            .map_err(|_| DeviceKeyError::BadEncoding)?;
        DevicePublicKey::from_slice(&raw)
    }

    pub fn to_b64url(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn fingerprint(&self) -> Fingerprint {
        Fingerprint(Sha256::digest(self.0).into())
    }

    pub(crate) fn kem_public(&self) -> KemPublicKey {
        KemPublicKey::from_bytes(&self.0).expect("32 bytes is a valid X25519 public key encoding")
    }
}

impl fmt::Debug for DevicePublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "DevicePublicKey({})", self.fingerprint().short())
    }
}

/// Whether `[8]P` is the identity, i.e. `P` has small order (on the curve or
/// its twist). Such keys make every Diffie-Hellman output all zero.
fn is_small_order(u: &[u8; 32]) -> bool {
    let eight = Scalar::from(8u8);
    (MontgomeryPoint(*u) * eight).to_bytes() == [0u8; 32]
}

/// `SHA-256(device_pk)`.
///
/// Serde: 32 raw bytes in binary formats, 64 lowercase hex characters in
/// human-readable ones.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Fingerprint([u8; 32]);

impl Fingerprint {
    pub fn from_bytes(bytes: [u8; 32]) -> Fingerprint {
        Fingerprint(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// The display form: the first 8 bytes in lowercase hex, 4 groups joined
    /// by `-`, e.g. `3f2a-91bc-0d4e-77a1`.
    pub fn short(&self) -> String {
        let hex = to_hex(&self.0[..8]);
        format!(
            "{}-{}-{}-{}",
            &hex[0..4],
            &hex[4..8],
            &hex[8..12],
            &hex[12..16]
        )
    }

    /// All 32 bytes in lowercase hex.
    pub fn to_hex(&self) -> String {
        to_hex(&self.0)
    }

    pub fn from_hex(s: &str) -> Option<Fingerprint> {
        if s.len() != 64 || !s.is_ascii() {
            return None;
        }
        let mut out = [0u8; 32];
        for (i, chunk) in s.as_bytes().chunks(2).enumerate() {
            let pair = std::str::from_utf8(chunk).ok()?;
            out[i] = u8::from_str_radix(pair, 16).ok()?;
        }
        Some(Fingerprint(out))
    }
}

fn to_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

impl fmt::Display for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.short())
    }
}

impl fmt::Debug for Fingerprint {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Fingerprint({})", self.short())
    }
}

impl Serialize for DevicePublicKey {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_b64url())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for DevicePublicKey {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<DevicePublicKey, D::Error> {
        use serde::de::Error;
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            DevicePublicKey::from_b64url(&s).map_err(D::Error::custom)
        } else {
            let raw = <[u8; 32]>::deserialize(deserializer)?;
            DevicePublicKey::from_bytes(raw).map_err(D::Error::custom)
        }
    }
}

impl Serialize for Fingerprint {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        if serializer.is_human_readable() {
            serializer.serialize_str(&self.to_hex())
        } else {
            self.0.serialize(serializer)
        }
    }
}

impl<'de> Deserialize<'de> for Fingerprint {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Fingerprint, D::Error> {
        use serde::de::Error;
        if deserializer.is_human_readable() {
            let s = String::deserialize(deserializer)?;
            Fingerprint::from_hex(&s).ok_or_else(|| D::Error::custom("expected 64 hex characters"))
        } else {
            Ok(Fingerprint(<[u8; 32]>::deserialize(deserializer)?))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex32(s: &str) -> [u8; 32] {
        Fingerprint::from_hex(s).unwrap().0
    }

    #[test]
    fn secret_round_trip_and_public_key() {
        let pair = DeviceKeyPair::generate();
        let restored = DeviceKeyPair::from_secret_bytes(&*pair.secret_bytes()).unwrap();
        assert_eq!(restored.public(), pair.public());
        assert_eq!(restored.fingerprint(), pair.fingerprint());
        assert_ne!(DeviceKeyPair::generate().public(), pair.public());
        assert_eq!(
            DeviceKeyPair::from_secret_bytes(&[1u8; 31]).unwrap_err(),
            DeviceKeyError::BadLength
        );
        assert!(!format!("{pair:?}").contains(&to_hex(&*pair.secret_bytes())));
    }

    #[test]
    fn rfc7748_public_key_vector() {
        // RFC 7748 §6.1, Alice's key pair.
        let sk = hex32("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a");
        let pair = DeviceKeyPair::from_secret_bytes(&sk).unwrap();
        assert_eq!(
            to_hex(pair.public().as_bytes()),
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
        );
        assert_eq!(*pair.secret_bytes(), sk);
    }

    #[test]
    fn fingerprint_is_sha256_of_the_key() {
        let pk = DevicePublicKey::from_bytes(hex32(
            "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
        ))
        .unwrap();
        let fp = pk.fingerprint();
        let expected: [u8; 32] = Sha256::digest(pk.as_bytes()).into();
        assert_eq!(fp.as_bytes(), &expected);
        let hex = fp.to_hex();
        assert_eq!(
            fp.short(),
            format!(
                "{}-{}-{}-{}",
                &hex[0..4],
                &hex[4..8],
                &hex[8..12],
                &hex[12..16]
            )
        );
        assert_eq!(Fingerprint::from_hex(&hex), Some(fp));
        assert_eq!(Fingerprint::from_hex("zz"), None);
    }

    #[test]
    fn small_order_points_are_rejected() {
        // libsodium's X25519 blocklist; each was also checked independently
        // with an x-only ladder ([8]P = 0).
        for h in [
            "0000000000000000000000000000000000000000000000000000000000000000",
            "0100000000000000000000000000000000000000000000000000000000000000",
            "e0eb7a7c3b41b8ae1656e3faf19fc46ada098deb9c32b1fd866205165f49b800",
            "5f9c95bca3508c24b1d0b1559c83ef5b04445cc4581c8e86d8224eddd09f1157",
            "ecffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
            "eeffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f",
        ] {
            let mut bytes = hex32(h);
            assert_eq!(
                DevicePublicKey::from_bytes(bytes),
                Err(DeviceKeyError::WeakPublicKey),
                "{h}"
            );
            bytes[31] |= 0x80; // the top bit is ignored by X25519
            assert_eq!(
                DevicePublicKey::from_bytes(bytes),
                Err(DeviceKeyError::WeakPublicKey),
                "{h}"
            );
        }
        let mut nine = [0u8; 32];
        nine[0] = 9;
        assert!(DevicePublicKey::from_bytes(nine).is_ok());
    }

    #[test]
    fn serde_forms() {
        let pk = *DeviceKeyPair::generate().public();
        let json = serde_json::to_string(&pk).unwrap();
        assert_eq!(json, format!("\"{}\"", pk.to_b64url()));
        assert_eq!(serde_json::from_str::<DevicePublicKey>(&json).unwrap(), pk);
        let bin = postcard::to_allocvec(&pk).unwrap();
        assert_eq!(bin.as_slice(), pk.as_bytes());
        assert_eq!(postcard::from_bytes::<DevicePublicKey>(&bin).unwrap(), pk);
        assert!(postcard::from_bytes::<DevicePublicKey>(&[0u8; 32]).is_err());

        let fp = pk.fingerprint();
        assert_eq!(
            serde_json::to_string(&fp).unwrap(),
            format!("\"{}\"", fp.to_hex())
        );
        assert_eq!(
            postcard::to_allocvec(&fp).unwrap().as_slice(),
            fp.as_bytes()
        );
    }
}

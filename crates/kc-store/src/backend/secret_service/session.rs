//! The Secret Service's encrypted session, `dh-ietf1024-sha256-aes128-cbc-pkcs7`, the one
//! gnome-keyring, KeePassXC and libsecret implement:
//!
//! - A Diffie-Hellman exchange in the 1024-bit MODP group of RFC 2409 (the Second Oakley Group,
//!   generator 2). Public values travel as big-endian bytes.
//! - HKDF-SHA256 without salt or info turns the shared secret, left-padded to 128 bytes, into a
//!   128-bit AES key.
//! - Every secret is AES-128-CBC with PKCS#7 padding under a fresh random IV, which travels as
//!   the secret's `parameters`.
//!
//! So values never cross the session bus in the clear. The private exponent, the shared secret,
//! the key and every plaintext live in buffers that are wiped when dropped, and exponentiation
//! takes constant time in the private exponent. Left to the stack, as with the client library
//! this replaces: the working copies crypto-bigint and HKDF make during the one derivation per
//! connection.

use aes::cipher::block_padding::Pkcs7;
use aes::cipher::generic_array::GenericArray;
use aes::cipher::{BlockDecryptMut, BlockEncryptMut, KeyIvInit};
use crypto_bigint::modular::{FixedMontyForm, FixedMontyParams};
use crypto_bigint::{Odd, U1024};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::{Zeroize, Zeroizing};

/// The `OpenSession` algorithm name.
pub(super) const ALGORITHM: &str = "dh-ietf1024-sha256-aes128-cbc-pkcs7";

/// RFC 2409 section 6.2: the 1024-bit MODP group (the Second Oakley Group).
const PRIME: Odd<U1024> = Odd::<U1024>::from_be_hex(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A0879\
     8E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B\
     0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE65381FFFFFFFFFFFFFFFF",
);
const GENERATOR: u32 = 2;
/// The size of the group's numbers, and of the padded shared secret.
const BYTES: usize = 128;
const KEY_BYTES: usize = 16;
const IV_BYTES: usize = 16;

/// Our half of the exchange: a random private exponent and the public value that goes into
/// `OpenSession`.
pub(super) struct Exchange {
    private: Zeroizing<U1024>,
    public: Vec<u8>,
}

impl Exchange {
    pub(super) fn new() -> Self {
        let mut bytes = Zeroizing::new([0u8; BYTES]);
        rand::rng().fill_bytes(bytes.as_mut());
        let private = Zeroizing::new(U1024::from_be_slice(bytes.as_ref()));
        let public = power(&U1024::from_u32(GENERATOR), &private);
        Exchange {
            private,
            public: minimal_be_bytes(&public),
        }
    }

    pub(super) fn public_key(&self) -> &[u8] {
        &self.public
    }

    /// The session key, from the public value `OpenSession` answered with. A value outside
    /// 2..=p-2 (which would pin the shared secret to 0, 1 or ±1) is refused.
    pub(super) fn finish(self, server_public: &[u8]) -> Result<SessionKey, &'static str> {
        const INVALID: &str =
            "the Secret Service answered with an invalid Diffie-Hellman public key";
        let theirs = from_be_bytes(server_public).ok_or(INVALID)?;
        let two = U1024::from_u32(2);
        if theirs < two || theirs > PRIME.get().wrapping_sub(&two) {
            return Err(INVALID);
        }
        let shared = Zeroizing::new(power(&theirs, &self.private));
        let mut ikm = Zeroizing::new([0u8; BYTES]);
        let mut encoded = shared.to_be_bytes();
        ikm.copy_from_slice(encoded.as_ref());
        encoded.as_mut().zeroize();
        let mut key = Zeroizing::new([0u8; KEY_BYTES]);
        Hkdf::<Sha256>::new(None, ikm.as_ref())
            .expand(&[], key.as_mut())
            .map_err(|_| "HKDF refused a 16-byte key")?;
        Ok(SessionKey(key))
    }
}

/// `base ^ exponent mod p`, in constant time in the exponent.
fn power(base: &U1024, exponent: &U1024) -> U1024 {
    // The modulus is public, so its parameters may be computed in variable time.
    let params = FixedMontyParams::new_vartime(PRIME);
    let mut form = FixedMontyForm::new(base, &params).pow(exponent);
    let value = form.retrieve();
    form.zeroize();
    value
}

/// A public value as unsigned big-endian bytes, without leading zeros.
fn minimal_be_bytes(value: &U1024) -> Vec<u8> {
    let bytes = value.to_be_bytes();
    let bytes = bytes.as_ref();
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    bytes[first..].to_vec()
}

/// Unsigned big-endian bytes, possibly with leading zeros, as a number below 2^1024.
fn from_be_bytes(bytes: &[u8]) -> Option<U1024> {
    let first = bytes.iter().position(|&b| b != 0).unwrap_or(bytes.len());
    let significant = &bytes[first..];
    if significant.len() > BYTES {
        return None;
    }
    let mut padded = [0u8; BYTES];
    padded[BYTES - significant.len()..].copy_from_slice(significant);
    Some(U1024::from_be_slice(&padded))
}

/// The AES key of an open session.
pub(super) struct SessionKey(Zeroizing<[u8; KEY_BYTES]>);

impl SessionKey {
    /// `(parameters, value)` for `SetSecret`: a fresh random IV and the ciphertext.
    pub(super) fn encrypt(&self, secret: &[u8]) -> (Vec<u8>, Vec<u8>) {
        let mut iv = [0u8; IV_BYTES];
        rand::rng().fill_bytes(&mut iv);
        // Copies `secret` into the new vector and encrypts it there, in place.
        let value = cbc::Encryptor::<aes::Aes128>::new(
            GenericArray::from_slice(self.0.as_ref()),
            &iv.into(),
        )
        .encrypt_padded_vec_mut::<Pkcs7>(secret);
        (iv.to_vec(), value)
    }

    /// The plaintext of a `GetSecret` answer. Decrypted in place, in a buffer that is wiped
    /// when dropped, also when the padding turns out wrong.
    pub(super) fn decrypt(
        &self,
        parameters: &[u8],
        value: &[u8],
    ) -> Result<Zeroizing<Vec<u8>>, &'static str> {
        let iv: [u8; IV_BYTES] = parameters
            .try_into()
            .map_err(|_| "the Secret Service sent a secret without a 16-byte IV")?;
        let mut plaintext = Zeroizing::new(value.to_vec());
        let len = cbc::Decryptor::<aes::Aes128>::new(
            GenericArray::from_slice(self.0.as_ref()),
            &iv.into(),
        )
        .decrypt_padded_mut::<Pkcs7>(&mut plaintext)
        .map_err(|_| "a secret from the Secret Service did not decrypt")?
        .len();
        plaintext.truncate(len);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_sides_of_an_exchange_derive_the_same_key() {
        let (ours, theirs) = (Exchange::new(), Exchange::new());
        let our_public = ours.public_key().to_vec();
        let a = ours.finish(theirs.public_key()).unwrap();
        let b = theirs.finish(&our_public).unwrap();
        assert_eq!(*a.0, *b.0);
    }

    #[test]
    fn secrets_round_trip_under_fresh_ivs() {
        let (ours, theirs) = (Exchange::new(), Exchange::new());
        let key = ours.finish(theirs.public_key()).unwrap();
        for secret in [&b""[..], b"x", &[7u8; 16], &[0xAB; 1000]] {
            let (iv, value) = key.encrypt(secret);
            assert_eq!(iv.len(), IV_BYTES);
            assert_eq!(value.len() % 16, 0);
            assert_eq!(key.decrypt(&iv, &value).unwrap().as_slice(), secret);
        }
        assert_ne!(key.encrypt(b"same").0, key.encrypt(b"same").0);
    }

    #[test]
    fn degenerate_public_keys_and_bad_ivs_are_refused() {
        let p = PRIME.get().to_be_bytes().as_ref().to_vec();
        let p_minus_1 = PRIME
            .get()
            .wrapping_sub(&U1024::ONE)
            .to_be_bytes()
            .as_ref()
            .to_vec();
        let too_long = [&[1u8][..], &[0; BYTES]].concat();
        for bad in [&[][..], &[0], &[1], &p, &p_minus_1, &too_long] {
            assert!(Exchange::new().finish(bad).is_err());
        }
        // Leading zeros are fine: the value is what counts.
        assert!(Exchange::new().finish(&[0, 0, 2]).is_ok());
        let key = Exchange::new().finish(&[2]).unwrap();
        let (_, value) = key.encrypt(b"secret");
        assert!(key.decrypt(&[0; 15], &value).is_err());
        assert!(key.decrypt(&[0; 16], &value[..15]).is_err());
    }

    #[test]
    fn public_values_round_trip_through_their_encoding() {
        let exchange = Exchange::new();
        let public = exchange.public_key();
        assert!(!public.is_empty() && public.len() <= BYTES && public[0] != 0);
        let value = from_be_bytes(public).unwrap();
        assert_eq!(minimal_be_bytes(&value), public);
    }

    /// The prime byte for byte as the `secret-service` crate, gnome-keyring and libsecret
    /// carry it: RFC 2409's Second Oakley Group.
    #[test]
    fn the_prime_is_the_second_oakley_group() {
        const RFC_2409: [u8; BYTES] = [
            0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xC9, 0x0F, 0xDA, 0xA2, 0x21, 0x68,
            0xC2, 0x34, 0xC4, 0xC6, 0x62, 0x8B, 0x80, 0xDC, 0x1C, 0xD1, 0x29, 0x02, 0x4E, 0x08,
            0x8A, 0x67, 0xCC, 0x74, 0x02, 0x0B, 0xBE, 0xA6, 0x3B, 0x13, 0x9B, 0x22, 0x51, 0x4A,
            0x08, 0x79, 0x8E, 0x34, 0x04, 0xDD, 0xEF, 0x95, 0x19, 0xB3, 0xCD, 0x3A, 0x43, 0x1B,
            0x30, 0x2B, 0x0A, 0x6D, 0xF2, 0x5F, 0x14, 0x37, 0x4F, 0xE1, 0x35, 0x6D, 0x6D, 0x51,
            0xC2, 0x45, 0xE4, 0x85, 0xB5, 0x76, 0x62, 0x5E, 0x7E, 0xC6, 0xF4, 0x4C, 0x42, 0xE9,
            0xA6, 0x37, 0xED, 0x6B, 0x0B, 0xFF, 0x5C, 0xB6, 0xF4, 0x06, 0xB7, 0xED, 0xEE, 0x38,
            0x6B, 0xFB, 0x5A, 0x89, 0x9F, 0xA5, 0xAE, 0x9F, 0x24, 0x11, 0x7C, 0x4B, 0x1F, 0xE6,
            0x49, 0x28, 0x66, 0x51, 0xEC, 0xE6, 0x53, 0x81, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
            0xFF, 0xFF,
        ];
        assert_eq!(PRIME.get().to_be_bytes().as_ref(), &RFC_2409[..]);
    }
}

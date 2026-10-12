//! XChaCha20-Poly1305 for channel phases: `body = nonce(24) || ciphertext || tag(16)`.

use chacha20poly1305::aead::AeadInOut;
use chacha20poly1305::{KeyInit, Tag, XChaCha20Poly1305, XNonce};
use zeroize::Zeroizing;

use crate::rng;

pub(crate) const NONCE_LEN: usize = 24;
pub(crate) const TAG_LEN: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("authenticated decryption failed")]
pub(crate) struct AeadError;

/// Encrypts `buf[NONCE_LEN..]` in place under a fresh random nonce, which is
/// written to `buf[..NONCE_LEN]`, then appends the tag. Reserve `TAG_LEN`
/// bytes of capacity first so the buffer never reallocates.
pub(crate) fn seal_in_place(
    key: &[u8; 32],
    aad: &[u8],
    buf: &mut Vec<u8>,
) -> Result<(), AeadError> {
    if buf.len() < NONCE_LEN {
        return Err(AeadError);
    }
    let nonce = rng::array::<NONCE_LEN>();
    buf[..NONCE_LEN].copy_from_slice(&nonce);
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError)?;
    let tag = cipher
        .encrypt_inout_detached(&XNonce::from(nonce), aad, (&mut buf[NONCE_LEN..]).into())
        .map_err(|_| AeadError)?;
    buf.extend_from_slice(&tag);
    Ok(())
}

/// Opens `nonce || ciphertext || tag` into a wiped buffer.
pub(crate) fn open(
    key: &[u8; 32],
    aad: &[u8],
    body: &[u8],
) -> Result<Zeroizing<Vec<u8>>, AeadError> {
    if body.len() < NONCE_LEN + TAG_LEN {
        return Err(AeadError);
    }
    let (nonce, rest) = body.split_at(NONCE_LEN);
    let (ciphertext, tag) = rest.split_at(rest.len() - TAG_LEN);
    let nonce = XNonce::try_from(nonce).map_err(|_| AeadError)?;
    let tag = Tag::try_from(tag).map_err(|_| AeadError)?;
    let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|_| AeadError)?;
    let mut buf = Zeroizing::new(ciphertext.to_vec());
    cipher
        .decrypt_inout_detached(&nonce, aad, (&mut buf[..]).into(), &tag)
        .map_err(|_| AeadError)?;
    Ok(buf)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sealed(key: &[u8; 32], aad: &[u8], msg: &[u8]) -> Vec<u8> {
        let mut buf = Vec::with_capacity(NONCE_LEN + msg.len() + TAG_LEN);
        buf.resize(NONCE_LEN, 0);
        buf.extend_from_slice(msg);
        seal_in_place(key, aad, &mut buf).unwrap();
        buf
    }

    #[test]
    fn round_trip_and_tamper_detection() {
        let key = [7u8; 32];
        let body = sealed(&key, b"aad", b"secret");
        assert_eq!(body.len(), NONCE_LEN + 6 + TAG_LEN);
        assert_eq!(&*open(&key, b"aad", &body).unwrap(), b"secret");
        assert_eq!(open(&key, b"aaD", &body), Err(AeadError));
        assert_eq!(open(&[8u8; 32], b"aad", &body), Err(AeadError));
        for i in [0, NONCE_LEN, body.len() - 1] {
            let mut bad = body.clone();
            bad[i] ^= 1;
            assert_eq!(open(&key, b"aad", &bad), Err(AeadError), "flip at {i}");
        }
        assert_eq!(
            open(&key, b"aad", &body[..NONCE_LEN + TAG_LEN - 1]),
            Err(AeadError)
        );
        // A fresh nonce each time.
        assert_ne!(
            sealed(&key, b"", b"x")[..NONCE_LEN],
            sealed(&key, b"", b"x")[..NONCE_LEN]
        );
    }

    #[test]
    fn xchacha20poly1305_known_answer() {
        // draft-irtf-cfrg-xchacha-03 §A.3.1.
        let hex = |s: &str| -> Vec<u8> {
            (0..s.len())
                .step_by(2)
                .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
                .collect()
        };
        let key: [u8; 32] = hex("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
            .try_into()
            .unwrap();
        let nonce = hex("404142434445464748494a4b4c4d4e4f5051525354555657");
        let aad = hex("50515253c0c1c2c3c4c5c6c7");
        let msg = b"Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
        let mut body = nonce.clone();
        body.extend_from_slice(&hex(
            "bd6d179d3e83d43b9576579493c0e939572a1700252bfaccbed2902c21396cbb731c7f1b0b4aa6440bf3a82f4eda7e39ae64c6708c54c216cb96b72e1213b4522f8c9ba40db5d945b11b69b982c1bb9e3f3fac2bc369488f76b2383565d3fff921f9664c97637da9768812f615c68b13b52e",
        ));
        body.extend_from_slice(&hex("c0875924c1c7987947deafd8780acf49"));
        assert_eq!(&*open(&key, &aad, &body).unwrap(), &msg[..]);
    }
}

//! Small helpers shared by the stores and the HTTP layer.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::http::{HeaderMap, header};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use rand::RngCore;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

/// Every token (side, owner, writer) is 32 random bytes.
pub const TOKEN_LEN: usize = 32;
/// Inbox, writer and message ids are 16 random bytes.
pub const ID_LEN: usize = 16;

pub type Hash = [u8; 32];
pub type Token = [u8; TOKEN_LEN];
pub type Id = [u8; ID_LEN];

pub fn sha256(data: &[u8]) -> Hash {
    Sha256::digest(data).into()
}

pub fn ct_eq(a: &Hash, b: &Hash) -> bool {
    bool::from(a[..].ct_eq(&b[..]))
}

pub fn random<const N: usize>() -> [u8; N] {
    let mut out = [0u8; N];
    rand::rng().fill_bytes(&mut out);
    out
}

pub fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

/// Decode base64url without padding into exactly `N` bytes. The length is
/// checked before decoding, so oversized input costs nothing.
pub fn b64_exact<const N: usize>(s: &str) -> Option<[u8; N]> {
    if s.len() != base64::encoded_len(N, false)? {
        return None;
    }
    URL_SAFE_NO_PAD.decode(s).ok()?.try_into().ok()
}

/// The raw token from `Authorization: Bearer <b64url(32 bytes)>`. A missing
/// header, a repeated header, another scheme or anything that doesn't decode
/// to exactly 32 bytes gives `None` (the caller answers 401).
pub fn bearer(headers: &HeaderMap) -> Option<Token> {
    let mut values = headers.get_all(header::AUTHORIZATION).iter();
    let value = values.next()?;
    if values.next().is_some() {
        return None;
    }
    let value = value.to_str().ok()?;
    let (scheme, rest) = value.split_once(' ')?;
    if !scheme.eq_ignore_ascii_case("bearer") {
        return None;
    }
    b64_exact::<TOKEN_LEN>(rest.trim())
}

/// SHA-256 of the raw bearer token, which is what the stores keep.
pub fn bearer_hash(headers: &HeaderMap) -> Option<Hash> {
    bearer(headers).map(|t| sha256(&t))
}

pub fn unix_ms(t: SystemTime) -> i64 {
    match t.duration_since(UNIX_EPOCH) {
        Ok(d) => i64::try_from(d.as_millis()).unwrap_or(i64::MAX),
        Err(_) => 0,
    }
}

pub fn now_ms() -> i64 {
    unix_ms(SystemTime::now())
}

pub fn duration_ms(d: Duration) -> i64 {
    i64::try_from(d.as_millis()).unwrap_or(i64::MAX)
}

/// RFC 3339 in UTC with second precision, e.g. `2026-10-12T01:28:00Z`.
pub fn rfc3339(t: SystemTime) -> String {
    humantime::format_rfc3339_seconds(t).to_string()
}

pub fn rfc3339_ms(ms: i64) -> String {
    let ms = u64::try_from(ms).unwrap_or(0);
    rfc3339(UNIX_EPOCH + Duration::from_millis(ms))
}

/// Whole seconds, rounded up, at least 1. Used for `Retry-After`.
pub fn retry_secs(d: Duration) -> u32 {
    let secs = d.as_secs() + u64::from(d.subsec_nanos() > 0);
    u32::try_from(secs.max(1)).unwrap_or(u32::MAX)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::HeaderValue;

    #[test]
    fn exact_decoding() {
        let raw = [7u8; 32];
        let enc = b64(&raw);
        assert_eq!(enc.len(), 43);
        assert_eq!(b64_exact::<32>(&enc), Some(raw));
        assert_eq!(b64_exact::<16>(&enc), None);
        assert_eq!(b64_exact::<32>(&format!("{enc}=")), None);
        assert_eq!(b64_exact::<32>(&enc.replace('B', "+")), None);
        assert_eq!(b64_exact::<32>(""), None);
    }

    #[test]
    fn bearer_parsing() {
        let tok = [9u8; 32];
        let mut h = HeaderMap::new();
        assert!(bearer(&h).is_none());
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", b64(&tok))).unwrap(),
        );
        assert_eq!(bearer(&h), Some(tok));
        assert_eq!(bearer_hash(&h), Some(sha256(&tok)));
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("bearer {}", b64(&tok))).unwrap(),
        );
        assert_eq!(bearer(&h), Some(tok));
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Basic {}", b64(&tok))).unwrap(),
        );
        assert!(bearer(&h).is_none());
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", b64(&[1u8; 31]))).unwrap(),
        );
        assert!(bearer(&h).is_none());
        h.insert(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", b64(&tok))).unwrap(),
        );
        h.append(
            header::AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", b64(&tok))).unwrap(),
        );
        assert!(
            bearer(&h).is_none(),
            "two Authorization headers are refused"
        );
    }

    #[test]
    fn retry_rounding() {
        assert_eq!(retry_secs(Duration::ZERO), 1);
        assert_eq!(retry_secs(Duration::from_millis(1)), 1);
        assert_eq!(retry_secs(Duration::from_millis(1001)), 2);
        assert_eq!(retry_secs(Duration::from_secs(30)), 30);
    }

    #[test]
    fn timestamps() {
        assert_eq!(rfc3339_ms(0), "1970-01-01T00:00:00Z");
        assert_eq!(rfc3339_ms(1_760_232_480_999), "2025-10-12T01:28:00Z");
    }
}

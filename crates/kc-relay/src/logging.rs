//! What the access log may say about a client: an HMAC of its rate-limit key
//! under a random key that lives only in memory and is replaced every UTC day.
//! Tags let an operator see "the same client did this a hundred times today";
//! they can't be reversed or linked across days or restarts. IPs, ids, tokens,
//! user agents and bodies are never logged.

use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::ip::RateKey;
use crate::util::random;

pub struct LogTagger {
    state: Mutex<(u64, [u8; 32])>,
}

impl Default for LogTagger {
    fn default() -> Self {
        LogTagger {
            state: Mutex::new((u64::MAX, [0; 32])),
        }
    }
}

impl LogTagger {
    pub fn tag(&self, key: RateKey, now: SystemTime) -> String {
        let day = now
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs() / 86_400)
            .unwrap_or(0);
        let secret = {
            let mut st = self.state.lock().unwrap_or_else(|p| p.into_inner());
            if st.0 != day {
                *st = (day, random::<32>());
            }
            st.1
        };
        let mut mac =
            <Hmac<Sha256> as Mac>::new_from_slice(&secret).expect("HMAC takes any key length");
        mac.update(&key.to_bytes());
        let digest = mac.finalize().into_bytes();
        digest[..6].iter().map(|b| format!("{b:02x}")).collect()
    }
}

/// Coarse size class for the access log. Exact sizes could fingerprint what
/// was moved; buckets keep enough for capacity planning.
pub fn size_bucket(n: Option<u64>) -> &'static str {
    match n {
        None => "-",
        Some(0) => "0",
        Some(1..=64) => "<=64",
        Some(65..=1024) => "<=1k",
        Some(1025..=16_384) => "<=16k",
        Some(16_385..=65_536) => "<=64k",
        Some(65_537..=262_144) => "<=256k",
        Some(262_145..=1_048_576) => "<=1m",
        Some(_) => ">1m",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn tags_are_stable_within_a_day_and_change_across_days() {
        let t = LogTagger::default();
        let k = RateKey::from_ip("203.0.113.5".parse().unwrap());
        let other = RateKey::from_ip("203.0.113.6".parse().unwrap());
        let day1 = UNIX_EPOCH + Duration::from_secs(20_000 * 86_400 + 10);
        let a = t.tag(k, day1);
        assert_eq!(a.len(), 12);
        assert_eq!(a, t.tag(k, day1 + Duration::from_secs(3600)));
        assert_ne!(a, t.tag(other, day1));
        assert!(!a.contains("203"));
        let next_day = day1 + Duration::from_secs(86_400);
        assert_ne!(a, t.tag(k, next_day));
    }

    #[test]
    fn buckets() {
        assert_eq!(size_bucket(None), "-");
        assert_eq!(size_bucket(Some(0)), "0");
        assert_eq!(size_bucket(Some(64)), "<=64");
        assert_eq!(size_bucket(Some(262_144)), "<=256k");
        assert_eq!(size_bucket(Some(262_145)), "<=1m");
        assert_eq!(size_bucket(Some(5 << 20)), ">1m");
    }
}

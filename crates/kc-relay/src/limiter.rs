//! Rate and concurrency limits, keyed by client address or writer id.
//!
//! Rate limits are token buckets: a key may spend `burst` requests at once,
//! and the bucket refills continuously at `burst / period`. A bucket that has
//! refilled completely is indistinguishable from a fresh one, so `cleanup`
//! drops it; memory therefore tracks only recently active keys, and is capped
//! by `max_keys` on top of that.

use std::collections::HashMap;
use std::hash::Hash;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use tokio::time::Instant;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Quota {
    pub burst: u32,
    pub period: Duration,
}

impl Quota {
    pub const fn new(burst: u32, period: Duration) -> Quota {
        Quota { burst, period }
    }
    pub const fn per_minute(n: u32) -> Quota {
        Quota::new(n, Duration::from_secs(60))
    }
    pub const fn per_hour(n: u32) -> Quota {
        Quota::new(n, Duration::from_secs(3600))
    }
    pub const fn per_day(n: u32) -> Quota {
        Quota::new(n, Duration::from_secs(86_400))
    }

    /// Tokens per second.
    fn rate(self) -> f64 {
        f64::from(self.burst) / self.period.as_secs_f64().max(f64::MIN_POSITIVE)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Denied {
    /// Over the quota; a token is available after this long.
    RetryAfter(Duration),
    /// Too many distinct keys are being tracked. Fail closed.
    Saturated,
}

#[derive(Debug, Clone, Copy)]
struct Bucket {
    tokens: f64,
    at: Instant,
}

pub struct RateLimiter<K> {
    quota: Quota,
    max_keys: usize,
    buckets: Mutex<HashMap<K, Bucket>>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

impl<K: Eq + Hash + Copy> RateLimiter<K> {
    pub fn new(quota: Quota, max_keys: usize) -> Self {
        RateLimiter {
            quota,
            max_keys: max_keys.max(1),
            buckets: Mutex::new(HashMap::new()),
        }
    }

    pub fn quota(&self) -> Quota {
        self.quota
    }

    /// Spend one token for `key`.
    pub fn check(&self, key: K, now: Instant) -> Result<(), Denied> {
        let burst = f64::from(self.quota.burst);
        if self.quota.burst == 0 {
            return Err(Denied::RetryAfter(self.quota.period));
        }
        let rate = self.quota.rate();
        let mut map = lock(&self.buckets);
        if !map.contains_key(&key) && map.len() >= self.max_keys {
            Self::drop_full(&mut map, now, rate, burst);
            if map.len() >= self.max_keys {
                return Err(Denied::Saturated);
            }
        }
        let bucket = map.entry(key).or_insert(Bucket {
            tokens: burst,
            at: now,
        });
        let elapsed = now.saturating_duration_since(bucket.at).as_secs_f64();
        bucket.tokens = (bucket.tokens + elapsed * rate).min(burst);
        bucket.at = now;
        if bucket.tokens >= 1.0 {
            bucket.tokens -= 1.0;
            Ok(())
        } else {
            let wait = (1.0 - bucket.tokens) / rate;
            Err(Denied::RetryAfter(Duration::from_secs_f64(
                wait.min(self.quota.period.as_secs_f64()),
            )))
        }
    }

    /// Drop buckets that have refilled completely. Returns how many remain.
    pub fn cleanup(&self, now: Instant) -> usize {
        let mut map = lock(&self.buckets);
        Self::drop_full(
            &mut map,
            now,
            self.quota.rate(),
            f64::from(self.quota.burst),
        );
        map.len()
    }

    pub fn tracked(&self) -> usize {
        lock(&self.buckets).len()
    }

    fn drop_full(map: &mut HashMap<K, Bucket>, now: Instant, rate: f64, burst: f64) {
        map.retain(|_, b| {
            b.tokens + now.saturating_duration_since(b.at).as_secs_f64() * rate < burst
        });
    }
}

/// At most `max` requests in flight per key. The guard releases its slot when
/// dropped, whichever way the request ends.
pub struct Inflight<K: Eq + Hash + Copy> {
    max: usize,
    counts: Mutex<HashMap<K, usize>>,
}

pub struct InflightGuard<K: Eq + Hash + Copy> {
    owner: Arc<Inflight<K>>,
    key: K,
}

impl<K: Eq + Hash + Copy> Inflight<K> {
    pub fn new(max: usize) -> Arc<Self> {
        Arc::new(Inflight {
            max,
            counts: Mutex::new(HashMap::new()),
        })
    }

    pub fn try_acquire(self: &Arc<Self>, key: K) -> Option<InflightGuard<K>> {
        let mut counts = lock(&self.counts);
        let n = counts.entry(key).or_insert(0);
        if *n >= self.max {
            if *n == 0 {
                counts.remove(&key);
            }
            return None;
        }
        *n += 1;
        Some(InflightGuard {
            owner: Arc::clone(self),
            key,
        })
    }

    pub fn in_flight(&self, key: &K) -> usize {
        lock(&self.counts).get(key).copied().unwrap_or(0)
    }

    pub fn tracked(&self) -> usize {
        lock(&self.counts).len()
    }
}

impl<K: Eq + Hash + Copy> Drop for InflightGuard<K> {
    fn drop(&mut self) {
        let mut counts = lock(&self.owner.counts);
        if let Some(n) = counts.get_mut(&self.key) {
            *n -= 1;
            if *n == 0 {
                counts.remove(&self.key);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bucket_spends_burst_then_refills() {
        let lim = RateLimiter::new(Quota::per_minute(3), 10);
        let t0 = Instant::now();
        for _ in 0..3 {
            assert_eq!(lim.check(1u8, t0), Ok(()));
        }
        let Err(Denied::RetryAfter(wait)) = lim.check(1u8, t0) else {
            panic!("should be limited")
        };
        assert!(
            wait > Duration::from_secs(19) && wait <= Duration::from_secs(20),
            "{wait:?}"
        );
        // Other keys are independent.
        assert_eq!(lim.check(2u8, t0), Ok(()));
        // One token back after 20 s.
        assert_eq!(lim.check(1u8, t0 + Duration::from_secs(20)), Ok(()));
        assert!(lim.check(1u8, t0 + Duration::from_secs(20)).is_err());
    }

    #[test]
    fn cleanup_drops_refilled_buckets_and_caps_keys() {
        let lim = RateLimiter::new(Quota::per_minute(2), 2);
        let t0 = Instant::now();
        assert!(lim.check(1u8, t0).is_ok());
        assert!(lim.check(2u8, t0).is_ok());
        assert_eq!(lim.check(3u8, t0), Err(Denied::Saturated));
        assert_eq!(lim.cleanup(t0 + Duration::from_secs(5)), 2);
        assert_eq!(lim.cleanup(t0 + Duration::from_secs(31)), 0);
        assert!(lim.check(3u8, t0 + Duration::from_secs(31)).is_ok());
    }

    #[test]
    fn zero_quota_always_denies() {
        let lim = RateLimiter::new(Quota::per_hour(0), 10);
        assert!(matches!(
            lim.check(1u8, Instant::now()),
            Err(Denied::RetryAfter(_))
        ));
    }

    #[test]
    fn inflight_guard_releases_on_drop() {
        let inf = Inflight::new(2);
        let a = inf.try_acquire(7u8).unwrap();
        let b = inf.try_acquire(7u8).unwrap();
        assert!(inf.try_acquire(7u8).is_none());
        assert!(inf.try_acquire(8u8).is_some());
        drop(a);
        assert_eq!(inf.in_flight(&7), 1);
        let _c = inf.try_acquire(7u8).unwrap();
        drop(b);
        drop(_c);
        assert_eq!(inf.tracked(), 0);
        let zero = Inflight::new(0);
        assert!(zero.try_acquire(1u8).is_none());
        assert_eq!(zero.tracked(), 0);
    }
}

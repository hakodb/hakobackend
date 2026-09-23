//! hakobackend-ratelimit: per-key token bucket, in-process, zero dependencies.
//!
//! Deliberately hand-rolled (not tower-governor): hot-reloadable numbers, exact 429
//! semantics, per-route exemptions at the server level, and deterministically tested via a fake clock.
//! Honest limitation: each instance counts on its own (single-instance).
//! Multi-instance needs an external aggregator (Redis) — out of scope.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// One limit layer: N requests per minute + burst.
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    /// Tokens per second (from per-minute / 60).
    pub rate_per_sec: f64,
    pub burst: f64,
}

impl Quota {
    pub fn per_minute(n: u32, burst: u32) -> Self {
        Self { rate_per_sec: n as f64 / 60.0, burst: burst.max(1) as f64 }
    }
}

struct Bucket {
    tokens: f64,
    last: Instant,
}

/// Clock that can be faked in tests (production: `Instant::now`).
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;
use std::sync::Arc;

pub struct Limiter {
    quota: std::sync::RwLock<Quota>,
    buckets: std::sync::Mutex<HashMap<String, Bucket>>,
    clock: Clock,
    /// Memory bound: maximum number of distinct keys.
    cap: usize,
}

impl Limiter {
    pub fn new(quota: Quota) -> Self {
        Self::with_clock(quota, Arc::new(Instant::now))
    }

    pub fn with_clock(quota: Quota, clock: Clock) -> Self {
        Self { quota: std::sync::RwLock::new(quota), buckets: std::sync::Mutex::new(HashMap::new()), clock, cap: 50_000 }
    }

    /// Hot-reload the numbers without restart (used by /api/admin/reload).
    pub fn set_quota(&self, quota: Quota) {
        *self.quota.write().unwrap() = quota;
    }

    /// `Ok(())` = pass; `Err(seconds)` = reject + honest Retry-After.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let quota = *self.quota.read().unwrap();
        let now = (self.clock)();
        let mut g = self.buckets.lock().unwrap();
        // Lazy eviction: keys idle > 10 min are dropped when a newcomer arrives.
        if !g.contains_key(key) && g.len() >= self.cap {
            g.retain(|_, b| now.duration_since(b.last) < Duration::from_secs(600));
        }
        let b = g.entry(key.to_string()).or_insert(Bucket { tokens: quota.burst, last: now });
        let elapsed = now.duration_since(b.last).as_secs_f64().max(0.0);
        b.tokens = (b.tokens + elapsed * quota.rate_per_sec).min(quota.burst);
        b.last = now;
        if b.tokens >= 1.0 {
            b.tokens -= 1.0;
            Ok(())
        } else {
            // Seconds until 1 full token (ceil so we never under-report).
            Err(((1.0 - b.tokens) / quota.rate_per_sec).ceil().max(1.0) as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Deterministic manual clock (no sleep/flaky).
    #[derive(Clone)]
    struct Manual {
        t: Arc<Mutex<Instant>>,
    }

    impl Manual {
        fn new() -> Self {
            Self { t: Arc::new(Mutex::new(Instant::now())) }
        }
        fn advance(&self, d: Duration) {
            *self.t.lock().unwrap() += d;
        }
        fn clock(&self) -> Clock {
            let t = self.t.clone();
            Arc::new(move || *t.lock().unwrap())
        }
    }

    #[test]
    fn burst_lalu_refill() {
        let m = Manual::new();
        let l = Limiter::with_clock(Quota::per_minute(60, 2), m.clock());
        assert!(l.check("ip").is_ok());
        assert!(l.check("ip").is_ok());
        // Burst spent → reject with an honest Retry-After (60/min = 1 token/sec).
        assert_eq!(l.check("ip"), Err(1));
        // Other IPs are unaffected.
        assert!(l.check("lain").is_ok());
        // 1 second → 1 token again.
        m.advance(Duration::from_secs(1));
        assert!(l.check("ip").is_ok());
        assert_eq!(l.check("ip"), Err(1));
    }

    #[test]
    fn token_menumpuk_maks_burst() {
        let m = Manual::new();
        let l = Limiter::with_clock(Quota::per_minute(60, 2), m.clock());
        m.advance(Duration::from_secs(3600));
        // No matter how long idle: capped at burst, not unlimited.
        assert!(l.check("ip").is_ok());
        assert!(l.check("ip").is_ok());
        assert!(l.check("ip").is_err());
    }

    #[test]
    fn quota_hot_reload() {
        let m = Manual::new();
        let l = Limiter::with_clock(Quota::per_minute(60, 1), m.clock());
        assert!(l.check("ip").is_ok());
        assert!(l.check("ip").is_err());
        l.set_quota(Quota::per_minute(6000, 10));
        // Old tokens spent; a 100/sec refill tops up again after 1 sec.
        m.advance(Duration::from_secs(1));
        assert!(l.check("ip").is_ok());
    }

    #[test]
    fn eviksi_cap() {
        let m = Manual::new();
        let mut l = Limiter::with_clock(Quota::per_minute(60, 1), m.clock());
        l.cap = 2;
        assert!(l.check("a").is_ok());
        assert!(l.check("b").is_ok());
        m.advance(Duration::from_secs(601));
        // a,b idle → evicted, c admitted.
        assert!(l.check("c").is_ok());
    }
}

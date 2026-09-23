//! ub-ratelimit: token-bucket per kunci, in-process, nol dependensi.
//!
//! Sengaja hand-rolled (bukan tower-governor): angka hot-reload, semantik 429
//! eksak, exempt per-route di level server, dan deterministik diuji via jam palsu.
//! Batasan jujur: tiap instans menghitung sendiri (single-instance).
//! Multi-instance butuh agregator eksternal (Redis) — di luar scope.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// Batas satu lapis: N request per menit + burst.
#[derive(Debug, Clone, Copy)]
pub struct Quota {
    /// Token per detik (dari per-menit / 60).
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

/// Jam yang bisa dipalsukan di test (produksi: `Instant::now`).
pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;
use std::sync::Arc;

pub struct Limiter {
    quota: std::sync::RwLock<Quota>,
    buckets: std::sync::Mutex<HashMap<String, Bucket>>,
    clock: Clock,
    /// Batas memori: jumlah kunci berbeda maksimum.
    cap: usize,
}

impl Limiter {
    pub fn new(quota: Quota) -> Self {
        Self::with_clock(quota, Arc::new(Instant::now))
    }

    pub fn with_clock(quota: Quota, clock: Clock) -> Self {
        Self { quota: std::sync::RwLock::new(quota), buckets: std::sync::Mutex::new(HashMap::new()), clock, cap: 50_000 }
    }

    /// Hot-reload angka tanpa restart (dipakai /api/admin/reload).
    pub fn set_quota(&self, quota: Quota) {
        *self.quota.write().unwrap() = quota;
    }

    /// `Ok(())` = lolos; `Err(detik)` = tolak + Retry-After jujur.
    pub fn check(&self, key: &str) -> Result<(), u64> {
        let quota = *self.quota.read().unwrap();
        let now = (self.clock)();
        let mut g = self.buckets.lock().unwrap();
        // Eviksi malas: kunci idle > 10 mnt dibuang saat ada pendatang baru.
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
            // Detik sampai 1 token penuh (ceil agar tak under-report).
            Err(((1.0 - b.tokens) / quota.rate_per_sec).ceil().max(1.0) as u64)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    /// Jam manual deterministik (tanpa sleep/flaky).
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
        // Burst habis → tolak dengan Retry-After jujur (60/mnt = 1 token/dtk).
        assert_eq!(l.check("ip"), Err(1));
        // IP lain tak terdampak.
        assert!(l.check("lain").is_ok());
        // 1 detik → 1 token lagi.
        m.advance(Duration::from_secs(1));
        assert!(l.check("ip").is_ok());
        assert_eq!(l.check("ip"), Err(1));
    }

    #[test]
    fn token_menumpuk_maks_burst() {
        let m = Manual::new();
        let l = Limiter::with_clock(Quota::per_minute(60, 2), m.clock());
        m.advance(Duration::from_secs(3600));
        // Tak peduli idle lama: maks burst, bukan tak terbatas.
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
        // Token lama habis; refill 100/dtk mengisi lagi setelah 1 dtk.
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
        // a,b idle → dieviksi, c masuk.
        assert!(l.check("c").is_ok());
    }
}

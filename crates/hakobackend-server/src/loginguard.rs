//! Per-account login lockout: consecutive failures within a window lock
//! the login for a fixed duration — even the right password is rejected
//! while locked (uniform PermissionDenied downstream, no oracle beyond
//! the 429 itself). Complements the per-IP rate limiter (rotating IPs
//! don't help against this) and saves Argon2 CPU under password spray:
//! locked attempts never reach verification.
//!
//! In-process like the rate limiter (each instance counts on its own;
//! multi-instance needs an external aggregator — out of scope). Memory
//! bounded (50k entries, lazy eviction of cold ones). `max_attempts = 0`
//! disables entirely (yesterday's unlimited behavior, byte for byte).

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

/// Memory bound: distinct logins remembered (matches the rate limiter).
const CAP: usize = 50_000;

struct Entry {
    fails: u32,
    last: Instant,
    locked_until: Option<Instant>,
}

/// Clock that can be faked in tests (production: `Instant::now`).
pub type Clock = std::sync::Arc<dyn Fn() -> Instant + Send + Sync>;

/// Consecutive-failure lockout. `max_attempts` failures with the last two
/// inside `window` lock the login until `last + window` (`window` doubles
/// as the counting window and the lock duration — one knob pair, no
/// third clock to misconfigure).
pub struct LoginGuard {
    max_attempts: u32,
    window: Duration,
    entries: Mutex<HashMap<String, Entry>>,
    clock: Clock,
}

impl LoginGuard {
    pub fn new(max_attempts: u32, lockout_secs: u64) -> Self {
        Self::with_clock(max_attempts, lockout_secs, std::sync::Arc::new(Instant::now))
    }

    pub fn with_clock(max_attempts: u32, lockout_secs: u64, clock: Clock) -> Self {
        Self {
            max_attempts,
            window: Duration::from_secs(lockout_secs.max(1)),
            entries: Mutex::new(HashMap::new()),
            clock,
        }
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    pub fn is_off(&self) -> bool {
        self.max_attempts == 0
    }

    /// Seconds until retry when locked, None when free. Locked attempts
    /// must not reach password verification (CPU + timing).
    pub fn locked_secs(&self, login: &str) -> Option<u64> {
        if self.is_off() {
            return None;
        }
        let now = self.now();
        self.entries
            .lock()
            .unwrap()
            .get(login)
            .and_then(|e| e.locked_until)
            .filter(|until| *until > now)
            .map(|until| (until - now).as_secs().max(1))
    }

    /// Record a failed attempt (wrong password, unknown user, DPoP fail —
    /// all uniform: recording unknowns too avoids a lock oracle).
    pub fn fail(&self, login: &str) {
        if self.is_off() {
            return;
        }
        let now = self.now();
        let mut g = self.entries.lock().unwrap();
        // Lazy eviction under pressure: drop entries whose window passed.
        if !g.contains_key(login) && g.len() >= CAP {
            g.retain(|_, e| now.duration_since(e.last) < self.window);
        }
        let e = g.entry(login.to_string()).or_insert(Entry {
            fails: 0,
            last: now,
            locked_until: None,
        });
        // Window slid past: fresh count (a typo a year ago is not a strike).
        if now.duration_since(e.last) >= self.window {
            e.fails = 0;
            e.locked_until = None;
        }
        e.fails += 1;
        e.last = now;
        if e.fails >= self.max_attempts.max(1) {
            e.locked_until = Some(now + self.window);
        }
    }

    /// Success clears (a correct login proves humanity for this account).
    pub fn clear(&self, login: &str) {
        if self.is_off() {
            return;
        }
        self.entries.lock().unwrap().remove(login);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex as StdMutex;

    /// Manual clock (deterministic lockout edges, no sleeps).
    #[derive(Clone)]
    struct Manual {
        t: std::sync::Arc<StdMutex<Instant>>,
    }

    impl Manual {
        fn new() -> Self {
            Self { t: std::sync::Arc::new(StdMutex::new(Instant::now())) }
        }
        fn advance(&self, d: Duration) {
            *self.t.lock().unwrap() += d;
        }
        fn clock(&self) -> Clock {
            let t = self.t.clone();
            std::sync::Arc::new(move || *t.lock().unwrap())
        }
    }

    fn guard(m: &Manual) -> LoginGuard {
        LoginGuard::with_clock(3, 60, m.clock())
    }

    #[test]
    fn off_means_unlimited() {
        let g = LoginGuard::new(0, 60);
        assert!(g.is_off());
        for _ in 0..100 {
            g.fail("u");
        }
        assert_eq!(g.locked_secs("u"), None);
    }

    #[test]
    fn three_strikes_locks_then_expires() {
        let m = Manual::new();
        let g = guard(&m);
        assert_eq!(g.locked_secs("u"), None);
        g.fail("u");
        g.fail("u");
        assert_eq!(g.locked_secs("u"), None, "2 < 3");
        g.fail("u");
        let s = g.locked_secs("u").expect("locked");
        assert!((1..=60).contains(&s));
        // Correct password during lock still denied (caller checks first).
        assert!(g.locked_secs("u").is_some());
        // Window passes: free again, count reset.
        m.advance(Duration::from_secs(61));
        assert_eq!(g.locked_secs("u"), None);
        g.fail("u");
        assert_eq!(g.locked_secs("u"), None, "old strikes forgotten");
    }

    #[test]
    fn success_clears_strikes() {
        let m = Manual::new();
        let g = guard(&m);
        g.fail("u");
        g.fail("u");
        g.clear("u");
        g.fail("u");
        assert_eq!(g.locked_secs("u"), None);
    }

    #[test]
    fn unknown_logins_tracked_without_oracle() {
        // Unknown names record like known ones (no behavior difference
        // for an enumerator to observe beyond the uniform 429).
        let m = Manual::new();
        let g = guard(&m);
        g.fail("ghost");
        g.fail("ghost");
        g.fail("ghost");
        assert!(g.locked_secs("ghost").is_some());
        // Other accounts unaffected.
        assert_eq!(g.locked_secs("real"), None);
    }
}

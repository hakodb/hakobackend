//! Resolved-token cache: verify once (HS256/RS256/HTTPS), reuse the
//! `AuthContext` until the token's own `exp` — with sliding idle expiry for
//! active users and a short negative TTL for rejects.
//!
//! Scope discipline (what stays OUTSIDE, per request):
//! - DPoP proofs (signature + single-use jti) still run in `enforce_dpop`
//!   downstream of every cache hit — this caches only `chain.resolve` output.
//! - OAuth single-use codes/states never enter (they aren't bearer tokens).
//! - Loopback service keys never enter (hash-compare path, already ~ns).
//!
//! TTL policy: JWT `exp` parsed without verification (no crypto — the cached
//! value was verified when first resolved), clamped to `MAX_TTL`; opaque or
//! unparseable tokens get `FIXED_TTL`; rejects get `NEG_TTL` (garbage
//! tokens must not become an outbound HTTPS flood via github verify).
//! Idle: a hit refreshes `last`; entries idle past `IDLE` read stale and
//! re-resolve. `remove` (logout) + `clear` (reload) for explicit invalidation.

use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use hakobackend_core::AuthContext;

/// Hard cap on a cached positive entry (revocation window bound — the
/// verifiers themselves check no revocation list today, so this only
/// extends the existing window, documented).
const MAX_TTL: Duration = Duration::from_secs(3600);
/// Opaque/unparseable tokens (github opaque, malformed JWT): short fuse.
const FIXED_TTL: Duration = Duration::from_secs(60);
/// Rejects: cheap to re-check, expensive to let flood (network verify).
const NEG_TTL: Duration = Duration::from_secs(30);
/// Sliding idle window: active users stay cached, the quiet fall out.
const IDLE: Duration = Duration::from_secs(300);
/// Memory bound (split over shards, like the rate limiter).
const CAP: usize = 50_000;
/// Shard count: one global Mutex would serialize all workers at 20k+ RPS.
const SHARDS: usize = 16;

struct Entry {
    ctx: Option<AuthContext>,
    /// Hard expiry from TTL policy at insert.
    exp_at: Instant,
    /// Last hit (sliding idle).
    last: Instant,
}

fn shard(key: &[u8; 32]) -> usize {
    // First byte is plenty uniform for SHA256 output.
    key[0] as usize % SHARDS
}

fn token_key(token: &str) -> [u8; 32] {
    use sha2::{Digest, Sha256};
    Sha256::digest(token.as_bytes()).into()
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

/// `exp` from a JWT without verification (std-only base64url, no new dep).
/// None = not a parseable JWT (opaque token or garbage).
fn jwt_exp(token: &str) -> Option<u64> {
    let payload = token.split('.').nth(1)?;
    let raw = b64url_decode(payload)?;
    let v: serde_json::Value = serde_json::from_slice(&raw).ok()?;
    v.get("exp")?.as_u64()
}

fn b64val(c: u8) -> Option<u8> {
    match c {
        b'A'..=b'Z' => Some(c - b'A'),
        b'a'..=b'z' => Some(c - b'a' + 26),
        b'0'..=b'9' => Some(c - b'0' + 52),
        b'-' => Some(62),
        b'_' => Some(63),
        _ => None,
    }
}

fn b64url_decode(s: &str) -> Option<Vec<u8>> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() * 3 / 4 + 3);
    let mut buf: u32 = 0;
    let mut nbits = 0;
    for &c in bytes {
        if c == b'=' {
            break; // padding: stop, leftover bits are zero
        }
        buf = (buf << 6) | u32::from(b64val(c)?);
        nbits += 6;
        if nbits >= 8 {
            nbits -= 8;
            out.push((buf >> nbits) as u8 & 0xFF);
            buf &= (1 << nbits) - 1;
        }
    }
    Some(out)
}

pub type Clock = Arc<dyn Fn() -> Instant + Send + Sync>;

pub struct TokenCache {
    shards: [Mutex<HashMap<[u8; 32], Entry>>; SHARDS],
    clock: Clock,
}

impl TokenCache {
    pub fn new() -> Self {
        Self::with_clock(Arc::new(Instant::now))
    }

    pub fn with_clock(clock: Clock) -> Self {
        Self {
            shards: std::array::from_fn(|_| Mutex::new(HashMap::new())),
            clock,
        }
    }

    fn now(&self) -> Instant {
        (self.clock)()
    }

    /// Cache hit → resolved context (Some) or known reject (None).
    /// Expired-by-TTL or idle entries read as misses (re-resolve below).
    pub fn get(&self, token: &str) -> Option<Option<AuthContext>> {
        let key = token_key(token);
        let now = self.now();
        let mut g = self.shards[shard(&key)].lock().unwrap();
        let e = g.get_mut(&key)?;
        if now >= e.exp_at || now.duration_since(e.last) >= IDLE {
            g.remove(&key);
            return None;
        }
        e.last = now;
        Some(e.ctx.clone())
    }

    /// Store a resolve outcome. Positive TTL = token's own `exp` clamped to
    /// `MAX_TTL` (opaque/unparseable → `FIXED_TTL`); rejects → `NEG_TTL`.
    /// Already-expired positives are not stored.
    pub fn put(&self, token: &str, ctx: Option<AuthContext>) {
        let ttl = match &ctx {
            Some(_) => match jwt_exp(token) {
                Some(exp) => {
                    let now = now_unix();
                    if exp <= now {
                        return;
                    }
                    Duration::from_secs(exp - now).min(MAX_TTL)
                }
                None => FIXED_TTL,
            },
            None => NEG_TTL,
        };
        let key = token_key(token);
        let now = self.now();
        let mut g = self.shards[shard(&key)].lock().unwrap();
        // Lazy eviction under pressure: drop long-idle entries first.
        if !g.contains_key(&key) && g.len() >= (CAP / SHARDS).max(1) {
            g.retain(|_, e| now.duration_since(e.last) < Duration::from_secs(600));
        }
        g.insert(key, Entry { ctx, exp_at: now + ttl, last: now });
    }

    /// Explicit revoke (logout): the token dies now, TTL notwithstanding.
    pub fn remove(&self, token: &str) {
        let key = token_key(token);
        self.shards[shard(&key)].lock().unwrap().remove(&key);
    }

    /// Flush all (auth reload: chain/mapping changed, old contexts stale).
    pub fn clear(&self) {
        for s in &self.shards {
            s.lock().unwrap().clear();
        }
    }

    #[cfg(test)]
    fn len(&self) -> usize {
        self.shards.iter().map(|s| s.lock().unwrap().len()).sum()
    }
}

impl Default for TokenCache {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Manual clock (ms precision is enough for TTL/idle edges).
    #[derive(Clone)]
    struct Manual {
        t: Arc<std::sync::Mutex<Instant>>,
    }

    impl Manual {
        fn new() -> Self {
            Self { t: Arc::new(std::sync::Mutex::new(Instant::now())) }
        }
        fn advance(&self, d: Duration) {
            *self.t.lock().unwrap() += d;
        }
        fn clock(&self) -> Clock {
            let t = self.t.clone();
            Arc::new(move || *t.lock().unwrap())
        }
    }

    /// Minimal JWT with a chosen exp (header/payload/sig — signature never
    /// verified by the cache; resolution verified it before storing).
    fn jwt(exp: u64) -> String {
        fn b64(data: &[u8]) -> String {
            const ALPHA: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
            let mut out = String::new();
            let mut buf: u32 = 0;
            let mut nbits = 0;
            for &b in data {
                buf = (buf << 8) | u32::from(b);
                nbits += 8;
                while nbits >= 6 {
                    nbits -= 6;
                    out.push(ALPHA[((buf >> nbits) & 63) as usize] as char);
                }
            }
            if nbits > 0 {
                out.push(ALPHA[((buf << (6 - nbits)) & 63) as usize] as char);
            }
            out
        }
        format!(
            "{}.{}.sig",
            b64(br#"{"alg":"HS256"}"#),
            b64(format!(r#"{{"sub":"u1","exp":{exp}}}"#).as_bytes())
        )
    }

    fn ctx() -> AuthContext {
        AuthContext { uid: "local:u1".into(), extra: Default::default() }
    }

    #[test]
    fn positive_hit_until_exp() {
        let m = Manual::new();
        let c = TokenCache::with_clock(m.clock());
        let t = jwt(now_unix() + 100);
        assert!(c.get(&t).is_none());
        c.put(&t, Some(ctx()));
        assert_eq!(c.get(&t).unwrap().unwrap().uid, "local:u1");
        m.advance(Duration::from_secs(99));
        assert!(c.get(&t).is_some(), "still valid at 99s");
        m.advance(Duration::from_secs(2));
        assert!(c.get(&t).is_none(), "expired past exp");
    }

    #[test]
    fn expired_never_stored_opaque_gets_fixed() {
        let m = Manual::new();
        let c = TokenCache::with_clock(m.clock());
        c.put(&jwt(now_unix().saturating_sub(10)), Some(ctx()));
        assert_eq!(c.len(), 0, "already-expired not stored");
        c.put("opaque-token", Some(ctx()));
        assert!(c.get("opaque-token").is_some());
        m.advance(FIXED_TTL - Duration::from_secs(1));
        assert!(c.get("opaque-token").is_some());
        m.advance(Duration::from_secs(2));
        assert!(c.get("opaque-token").is_none());
    }

    #[test]
    fn negative_cached_briefly_and_revoked_by_remove() {
        let m = Manual::new();
        let c = TokenCache::with_clock(m.clock());
        c.put("bad", None);
        assert!(c.get("bad").is_some(), "negative hit (inner None)");
        assert!(c.get("bad").unwrap().is_none());
        m.advance(NEG_TTL + Duration::from_secs(1));
        assert!(c.get("bad").is_none(), "negative expired");
        let t = jwt(now_unix() + 100);
        c.put(&t, Some(ctx()));
        c.remove(&t);
        assert!(c.get(&t).is_none(), "logout revokes");
        c.put(&t, Some(ctx()));
        c.clear();
        assert!(c.get(&t).is_none(), "reload flushes");
    }

    #[test]
    fn idle_evicts_quiet_tokens() {
        let m = Manual::new();
        let c = TokenCache::with_clock(m.clock());
        // Long-lived JWT (clamped to MAX_TTL 3600s) so only idle evicts.
        let t = jwt(now_unix() + 100_000);
        c.put(&t, Some(ctx()));
        // Keep alive with activity inside the window.
        for _ in 0..3 {
            m.advance(IDLE - Duration::from_secs(10));
            assert!(c.get(&t).is_some(), "active stays cached");
        }
        m.advance(IDLE + Duration::from_secs(1));
        assert!(c.get(&t).is_none(), "quiet past idle re-resolves");
    }
}

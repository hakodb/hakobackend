//! Audit log: one JSON object per security-relevant event on stderr,
//! prefixed `audit ` so crowdsec/fail2ban/journald match one pattern.
//! Separate from wstats (perf) and eprintln diagnostics (ops noise):
//! this stream answers "who tried what, when, from where, what happened".
//!
//! Event taxonomy (stable `ev` strings — grep these, never substrings):
//! - `auth.login.ok` — success (login + source ip)
//! - `auth.login.fail` — wrong credentials (locked=false) / locked (true)
//! - `auth.refresh.reuse` — refresh reuse → all sessions revoked (attack
//!   signal; distinct from plain expiry so operators stop confusing it
//!   with lockout 429s)
//! - `auth.refresh.fail` — expired/foreign token, no revocation
//! - `auth.lockout` — guard transitioned open→locked for this login
//! - `auth.register` — self-service signup (ok=false when closed/failed)
//! - `auth.logout` — session killed (body or cookie path noted)
//! - `admin.reload` — config hot-reload (ok + changed surface summary)
//! - `policy.reload` — policy file auto-reload (ok/fail)
//!
//! Fields: `ts` (rfc3339 utc), `ev`, plus event-specific keys. Never
//! passwords/tokens/hashes (login names are operationally necessary and
//! already enumerable via register — see anti-enumeration note in login).

use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};

static ENABLED: AtomicBool = AtomicBool::new(true);
/// Verbosity (config `audit_level`, issue #4): 0 = off (nothing),
/// 1 = auth (auth.* only: login/register/logout/refresh/lockout),
/// 2 = all (default = today: everything incl. reloads).
static LEVEL: AtomicU8 = AtomicU8::new(2);

/// Kill the stream (tests capture it via `capture()` instead).
pub fn set_enabled(on: bool) {
    ENABLED.store(on, Ordering::Relaxed);
}

/// Parse a level name (config file). Unknown names Err (caller warns +
/// falls back to all — never fail boot on a logging typo).
pub fn parse_level(s: &str) -> Result<u8, String> {
    match s {
        "off" => Ok(0),
        "auth" => Ok(1),
        "all" => Ok(2),
        other => Err(format!("audit_level `{other}` unknown (off|auth|all)")),
    }
}

/// Apply a parsed level (boot + /api/admin/reload).
pub fn set_level(level: u8) {
    LEVEL.store(level, Ordering::Relaxed);
}

/// Pure verdict for tests: does `level` admit event `ev`?
pub(crate) fn level_allows(level: u8, ev: &str) -> bool {
    level >= class_of(ev)
}

fn class_of(ev: &str) -> u8 {
    if ev.starts_with("auth.") {
        1
    } else {
        2
    }
}

/// RFC3339 UTC without extra deps (chrono would be a new dep for one line).
fn ts_now() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    // Civil-from-days (Howard Hinnant's algorithm, Gregorian, no tables).
    let days = (secs / 86400) as i64 + 719468;
    let era = if days >= 0 { days } else { days - 146096 } / 146097;
    let doe = (days - era * 146097) as u64;
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe as i64 + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    let (hh, mm, ss) = (secs % 86400 / 3600, secs % 3600 / 60, secs % 60);
    format!("{y:04}-{m:02}-{d:02}T{hh:02}:{mm:02}:{ss:02}Z")
}

/// Client IP for the record (same key rule as the limiter: proxy header
/// only when trusted, else socket peer). "unix" for socket arrivals.
pub fn peer_ip(headers: &axum::http::HeaderMap, trust_proxy: bool, peer: Option<std::net::SocketAddr>) -> String {
    if trust_proxy {
        if let Some(v) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
        {
            if let Some(first) = v.split(',').next().map(str::trim).filter(|s| !s.is_empty()) {
                return first.to_string();
            }
        }
    }
    peer.map(|p| p.ip().to_string()).unwrap_or_else(|| "unix".into())
}

fn emit(ev: &str, fields: &[(&str, String)]) {
    if !ENABLED.load(Ordering::Relaxed) {
        return;
    }
    if !level_allows(LEVEL.load(Ordering::Relaxed), ev) {
        return;
    }
    let mut o = String::from("{\"ts\":\"");
    o.push_str(&ts_now());
    o.push_str("\",\"ev\":\"");
    o.push_str(ev);
    o.push('"');
    for (k, v) in fields {
        o.push_str(",\"");
        o.push_str(k);
        o.push_str("\":\"");
        o.push_str(&v.replace('\\', "\\\\").replace('"', "\\\""));
        o.push('"');
    }
    o.push('}');
    eprintln!("audit {o}");
}

/// Success / failure helpers (thin so call-sites stay one-liners).
pub fn login_ok(login: &str, ip: &str) {
    emit("auth.login.ok", &[("login", login.into()), ("ip", ip.into())]);
}
pub fn login_fail(login: &str, ip: &str, locked: bool) {
    emit(
        "auth.login.fail",
        &[("login", login.into()), ("ip", ip.into()), ("locked", locked.to_string())],
    );
}
pub fn lockout(login: &str, ip: &str, retry_secs: u64) {
    emit(
        "auth.lockout",
        &[("login", login.into()), ("ip", ip.into()), ("retry_secs", retry_secs.to_string())],
    );
}
pub fn refresh_reuse(login: &str, ip: &str) {
    emit("auth.refresh.reuse", &[("login", login.into()), ("ip", ip.into())]);
}
pub fn refresh_fail(ip: &str) {
    emit("auth.refresh.fail", &[("ip", ip.into())]);
}
pub fn register(login: &str, ip: &str, ok: bool, why: &str) {
    emit(
        "auth.register",
        &[("login", login.into()), ("ip", ip.into()), ("ok", ok.to_string()), ("why", why.into())],
    );
}
pub fn logout(login: &str, ip: &str, via: &str) {
    emit(
        "auth.logout",
        &[("login", login.into()), ("ip", ip.into()), ("via", via.into())],
    );
}
pub fn reload(admin: &str, ip: &str, ok: bool, detail: &str) {
    emit(
        "admin.reload",
        &[("admin", admin.into()), ("ip", ip.into()), ("ok", ok.to_string()), ("detail", detail.into())],
    );
}
pub fn policy_reload(path: &str, ok: bool) {
    emit(
        "policy.reload",
        &[("path", path.into()), ("ok", ok.to_string())],
    );
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_parse_and_filter() {
        assert_eq!(parse_level("off"), Ok(0));
        assert_eq!(parse_level("auth"), Ok(1));
        assert_eq!(parse_level("all"), Ok(2));
        assert!(parse_level("verbose").is_err());
        // off admits nothing; auth admits auth.* only; all admits all.
        for ev in ["auth.login.ok", "auth.register", "auth.lockout"] {
            assert!(!level_allows(0, ev));
            assert!(level_allows(1, ev));
            assert!(level_allows(2, ev));
        }
        for ev in ["admin.reload", "policy.reload"] {
            assert!(!level_allows(0, ev));
            assert!(!level_allows(1, ev));
            assert!(level_allows(2, ev));
        }
    }

    #[test]
    fn ts_shape_and_peer_ip() {        let t = ts_now();
        assert_eq!(t.len(), 20);
        assert!(t.ends_with('Z') && t.contains('T'));
        let h = axum::http::HeaderMap::new();
        assert_eq!(peer_ip(&h, false, None), "unix");
        let peer: std::net::SocketAddr = "10.0.0.9:1234".parse().unwrap();
        assert_eq!(peer_ip(&h, false, Some(peer)), "10.0.0.9");
        let mut px = axum::http::HeaderMap::new();
        px.insert("x-forwarded-for", "9.9.9.9, 1.1.1.1".parse().unwrap());
        assert_eq!(peer_ip(&px, false, Some(peer)), "10.0.0.9");
        assert_eq!(peer_ip(&px, true, Some(peer)), "9.9.9.9");
    }
}

//! hakobackend-auth-github: GitHub token verifier-only (no OAuth flow).
//!
//! Tokens are checked via `GET {api}/user` (60s cache) → `uid = "github:<id>"`.
//! The full OAuth login flow (server-side code exchange, BFF pattern) follows in phase E.
//! Config via env: `UB_GITHUB_API` (optional, defaults to api.github.com,
//! override for tests). No secret — the OAuth secret is only needed in phase E.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use hakobackend_core::{AppError, AuthProvider, Claims};

const GITHUB_API: &str = "https://api.github.com";
const CACHE_TTL: Duration = Duration::from_secs(60);

pub struct GithubVerifier {
    api_base: String,
    client: reqwest::Client,
    /// Token → claims. In-memory only, 60s; never persisted/logged.
    cache: tokio::sync::RwLock<HashMap<String, (Claims, Instant)>>,
}

impl GithubVerifier {
    pub fn from_env() -> Arc<dyn AuthProvider> {
        let api_base = std::env::var("UB_GITHUB_API").unwrap_or_else(|_| GITHUB_API.into());
        Self::with_api_base(api_base)
    }

    pub fn with_api_base(api_base: String) -> Arc<dyn AuthProvider> {
        Arc::new(Self {
            api_base,
            client: reqwest::Client::new(),
            cache: tokio::sync::RwLock::new(HashMap::new()),
        })
    }

    async fn cached(&self, token: &str) -> Option<Claims> {
        let g = self.cache.read().await;
        match g.get(token) {
            Some((c, t)) if t.elapsed() < CACHE_TTL => Some(c.clone()),
            _ => None,
        }
    }
}

#[async_trait::async_trait]
impl AuthProvider for GithubVerifier {
    fn name(&self) -> &'static str {
        "github"
    }

    async fn verify(&self, token: &str) -> Result<Claims, AppError> {
        if let Some(c) = self.cached(token).await {
            return Ok(c);
        }
        let user: HashMap<String, serde_json::Value> = self
            .client
            .get(format!("{}/user", self.api_base))
            .bearer_auth(token)
            .header("Accept", "application/vnd.github+json")
            .header("User-Agent", "universalbackend")
            .send()
            .await
            .map_err(|_| AppError::PermissionDenied)?
            .error_for_status()
            .map_err(|_| AppError::PermissionDenied)?
            .json()
            .await
            .map_err(|_| AppError::PermissionDenied)?;
        let id = user.get("id").and_then(|v| v.as_u64()).ok_or(AppError::PermissionDenied)?;
        let claims = Claims {
            provider: "github",
            uid: id.to_string(),
            email: user.get("email").and_then(|v| v.as_str()).map(str::to_string),
            extra: user,
        };
        self.cache.write().await.insert(token.to_string(), (claims.clone(), Instant::now()));
        Ok(claims)
    }
}

// --- Full OAuth login, BFF pattern (phase E) ---
//
// Browser only sees redirects + session cookie; code↔token happens on the server.
// Internal pending collection `__oauth_pending` (`__` prefix, never exposed over HTTP).
// Secret ONLY via env (`UB_GITHUB_CLIENT_SECRET`), never in config files/logs.

const GITHUB_AUTHORIZE: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
const PENDING_COLLECTION: &str = "__oauth_pending";
/// Pending state+verifier lifetime (seconds).
const PENDING_TTL_SECS: u64 = 600;

pub struct GithubOAuth {
    client_id: String,
    secret: String,
    redirect_uri: String,
    authorize_url: String,
    token_url: String,
    after_login: String,
    verifier: Arc<dyn AuthProvider>,
    client: reqwest::Client,
    db: Arc<dyn hakobackend_core::Database>,
}

impl GithubOAuth {
    /// `Ok(None)` = feature disabled (no client id); `Err` = lopsided config (fail-closed).
    pub fn from_env(db: Arc<dyn hakobackend_core::Database>) -> Result<Option<Arc<Self>>, String> {
        let Some(client_id) = env_nonempty("UB_GITHUB_CLIENT_ID") else {
            return Ok(None);
        };
        let Some(secret) = env_nonempty("UB_GITHUB_CLIENT_SECRET") else {
            return Err("UB_GITHUB_CLIENT_ID is set but UB_GITHUB_CLIENT_SECRET is empty".to_string());
        };
        let Some(public) = env_nonempty("UB_PUBLIC_URL") else {
            return Err("OAuth github requires UB_PUBLIC_URL (callback origin https://…)".to_string());
        };
        let api_base = std::env::var("UB_GITHUB_API").unwrap_or_else(|_| GITHUB_API.into());
        let token_url = std::env::var("UB_GITHUB_TOKEN_URL").unwrap_or_else(|_| GITHUB_TOKEN.into());
        let authorize_url = std::env::var("UB_GITHUB_AUTHORIZE_URL").unwrap_or_else(|_| GITHUB_AUTHORIZE.into());
        let after_login = std::env::var("UB_GITHUB_AFTER_LOGIN").unwrap_or_else(|_| "/".into());
        // Open-redirect guard: the post-login landing must be a same-origin
        // path (`/app`), never `//evil` or a full URL (fail-closed at boot).
        if !(after_login.starts_with('/') && !after_login.starts_with("//")) {
            return Err("UB_GITHUB_AFTER_LOGIN must be a same-origin path (e.g. /)".to_string());
        }
        Ok(Some(Self::new(client_id, secret, public, api_base, token_url, authorize_url, after_login, db)))
    }

    /// Explicit constructor (used by tests — no env, hermetic).
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        client_id: String,
        secret: String,
        public_base: String,
        api_base: String,
        token_url: String,
        authorize_url: String,
        after_login: String,
        db: Arc<dyn hakobackend_core::Database>,
    ) -> Arc<Self> {
        Arc::new(Self {
            client_id,
            secret,
            redirect_uri: format!("{}/api/auth/github/callback", public_base.trim_end_matches('/')),
            authorize_url,
            token_url,
            after_login,
            verifier: GithubVerifier::with_api_base(api_base),
            client: reqwest::Client::new(),
            db,
        })
    }

    pub fn after_login(&self) -> &str {
        &self.after_login
    }

    /// Redirect URL to github.com + store pending state/PKCE (single-use, 10 min).
    /// Returns (url, browser_nonce): the caller must set the nonce as an
    /// HttpOnly cookie — the callback requires it back, binding the flow to
    /// the browser that started it (login-CSRF protection).
    pub async fn login_url(&self) -> Result<(String, String), AppError> {
        let state = rand_hex(16);
        let verifier = rand_hex(64);
        let nonce = rand_hex(16);
        let doc = hakobackend_core::Doc {
            id: state.clone(),
            data: [
                ("provider".to_string(), serde_json::Value::String("github".into())),
                ("verifier".to_string(), serde_json::Value::String(verifier.clone())),
                ("nonce".to_string(), serde_json::Value::String(sha_hex(&nonce))),
                ("created_at".to_string(), serde_json::Value::from(now_secs())),
            ]
            .into_iter()
            .collect(),
        };
        self.db.insert(PENDING_COLLECTION, doc).await.map_err(|_| AppError::Internal("oauth store error".into()))?;
        Ok((
            format!(
                "{}?client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
                self.authorize_url,
                urlenc(&self.client_id),
                urlenc(&self.redirect_uri),
                urlenc("read:user user:email"),
                urlenc(&state),
                urlenc(&pkce_challenge(&verifier)),
            ),
            nonce,
        ))
    }

    /// Callback result: (namespaced uid, email, github login). Sessions are issued
    /// server-side via `LocalAuth::login_external` (kept separate to avoid a circular crate).
    /// `nonce` is the browser cookie from login: mismatch = login CSRF, rejected.
    pub async fn callback(
        &self,
        code: &str,
        state: &str,
        nonce: Option<&str>,
    ) -> Result<(String, Option<String>, Option<String>), AppError> {
        let pending = self.db.get(PENDING_COLLECTION, state).await.map_err(|_| AppError::Internal("oauth store error".into()))?
            .ok_or(AppError::PermissionDenied)?;
        // Single-use + expiry (fail-closed; stale entries discarded).
        self.db.delete(PENDING_COLLECTION, state).await.map_err(|_| AppError::Internal("oauth store error".into()))?;
        let fresh = pending
            .data
            .get("created_at")
            .and_then(|v| v.as_u64())
            .is_some_and(|t| t + PENDING_TTL_SECS > now_secs());
        let verifier = pending.data.get("verifier").and_then(|v| v.as_str()).unwrap_or("");
        let nonce_ok = match (pending.data.get("nonce").and_then(|v| v.as_str()), nonce) {
            (Some(expected), Some(got)) => timing_safe_eq(expected, &sha_hex(got)),
            // Legacy pending entries (pre-nonce) are rejected, not grandfathered.
            _ => false,
        };
        if !fresh || verifier.is_empty() || !nonce_ok || pending.data.get("provider").and_then(|v| v.as_str()) != Some("github") {
            return Err(AppError::PermissionDenied);
        }
        let token = self.exchange(code, verifier).await?;
        let claims = self.verifier.verify(&token).await?;
        let login = claims.extra.get("login").and_then(|v| v.as_str()).map(str::to_string);
        Ok((claims.namespaced(), claims.email, login))
    }

    async fn exchange(&self, code: &str, verifier: &str) -> Result<String, AppError> {
        // Secret never goes into error messages (anti-leak).
        let body: HashMap<String, serde_json::Value> = self
            .client
            .post(&self.token_url)
            .header("Accept", "application/json")
            .form(&[
                ("client_id", self.client_id.as_str()),
                ("client_secret", self.secret.as_str()),
                ("code", code),
                ("redirect_uri", self.redirect_uri.as_str()),
                ("code_verifier", verifier),
            ])
            .send()
            .await
            .map_err(|_| AppError::BadRequest("code exchange failed".into()))?
            .json()
            .await
            .map_err(|_| AppError::BadRequest("code exchange failed".into()))?;
        if body.get("error").is_some() {
            return Err(AppError::PermissionDenied);
        }
        body.get("access_token").and_then(|v| v.as_str()).map(str::to_string).ok_or(AppError::PermissionDenied)
    }
}

fn rand_hex(nbytes: usize) -> String {
    use rand::RngCore;
    let mut buf = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

fn pkce_challenge(verifier: &str) -> String {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
    use sha2::{Digest, Sha256};
    B64.encode(Sha256::digest(verifier.as_bytes()))
}

fn sha_hex(s: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

/// Timing-safe string compare (nonces, hashes — never `==` on secrets).
fn timing_safe_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Minimal percent-encoding for OAuth queries (no extra crate).
fn urlenc(s: &str) -> String {
    let mut out = String::with_capacity(s.len());
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.' | b'~') {
            out.push(b as char);
        } else {
            out.push_str(&format!("%{b:02X}"));
        }
    }
    out
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn env_nonempty(key: &str) -> Option<String> {
    std::env::var(key).ok().filter(|s| !s.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use std::io::{Read, Write};
    use std::net::TcpListener;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Read one full HTTP request (headers + body per Content-Length).
    /// Single-read risks TCP partial reads (flaky source); correct framing here.
    fn read_request(s: &mut std::net::TcpStream) -> String {
        use std::io::Read;
        let mut raw = Vec::new();
        let mut buf = [0u8; 4096];
        loop {
            match s.read(&mut buf) {
                Ok(0) | Err(_) => break,
                Ok(n) => {
                    raw.extend_from_slice(&buf[..n]);
                    if let Some(hend) = find_headers_end(&raw) {
                        let headers: String = String::from_utf8_lossy(&raw[..hend]).into_owned();
                        let need = content_length(&headers);
                        if raw.len() >= hend + need {
                            break;
                        }
                    }
                    if raw.len() > 65536 {
                        break;
                    }
                }
            }
        }
        String::from_utf8_lossy(&raw).into_owned()
    }

    fn find_headers_end(raw: &[u8]) -> Option<usize> {
        raw.windows(4).position(|w| w == b"\r\n\r\n").map(|p| p + 4)
    }

    fn content_length(headers: &str) -> usize {
        headers
            .lines()
            .find_map(|l| {
                let (k, v) = l.split_once(':')?;
                (k.trim().eq_ignore_ascii_case("content-length")).then(|| v.trim().parse().unwrap_or(0))
            })
            .unwrap_or(0)
    }

    /// Mock api.github.com: `/user` valid for "tok-bagus", 401 for the rest.
    /// Counts hits to prove caching; stops via a flag.
    fn mock_github() -> (String, Arc<AtomicUsize>, Arc<std::sync::atomic::AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let hits = Arc::new(AtomicUsize::new(0));
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let (h2, s2) = (hits.clone(), stop.clone());
        let handle = std::thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        // Accepted sockets inherit nonblocking mode from the listener —
                        // switch back to blocking so read_request never sees WouldBlock.
                        let _ = s.set_nonblocking(false);
                        let req = read_request(&mut s);
                        let (status, body) = if req.contains("Bearer tok-bagus") {
                            h2.fetch_add(1, Ordering::SeqCst);
                            ("200 OK", json!({"id": 42, "login": "octo", "email": "o@x.io"}).to_string())
                        } else {
                            ("401 Unauthorized", json!({"message": "bad"}).to_string())
                        };
                        let resp = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes());
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
        });
        (url, hits, stop, handle)
    }

    #[tokio::test]
    async fn verify_cache_and_reject() {
        let (url, hits, stop, server) = mock_github();
        // Explicit constructor — no env, hermetic across parallel tests.
        let v = GithubVerifier::with_api_base(url);

        let c = v.verify("tok-bagus").await.unwrap();
        assert_eq!((c.provider, c.uid.as_str()), ("github", "42"));
        assert_eq!(c.email.as_deref(), Some("o@x.io"));
        // Second call served from cache (hits stays 1).
        let c2 = v.verify("tok-bagus").await.unwrap();
        assert_eq!(c2.uid, "42");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // Unknown token → Err (chain continues to the next provider).
        assert!(v.verify("tok-jelek").await.is_err());

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
    }

    /// Minimal fake DB: the pending store needs working get/insert/delete.
    struct FakeDb {
        store: std::sync::Mutex<HashMap<String, HashMap<String, hakobackend_core::Doc>>>,
    }

    #[async_trait::async_trait]
    impl hakobackend_core::Database for FakeDb {
        fn capabilities(&self) -> hakobackend_core::Capabilities {
            hakobackend_core::Capabilities { driver: "fake", supports_watch: false, supports_transactions: false, supports_composite: false, supports_fts: false, supports_drop_index: false, supports_unique: false, supports_named_index: false }
        }
        async fn ensure_collection(&self, _p: &str) -> Result<(), hakobackend_core::AppError> {
            Ok(())
        }
        async fn list_collections(&self) -> Result<Vec<String>, hakobackend_core::AppError> {
            Ok(vec![])
        }
        async fn get(&self, c: &str, id: &str) -> Result<Option<hakobackend_core::Doc>, hakobackend_core::AppError> {
            Ok(self.store.lock().unwrap().get(c).and_then(|t| t.get(id)).cloned())
        }
        async fn list(&self, _c: &str, _q: &hakobackend_core::QueryOptions) -> Result<Vec<hakobackend_core::Doc>, hakobackend_core::AppError> {
            Ok(vec![])
        }
        async fn insert(&self, c: &str, doc: hakobackend_core::Doc) -> Result<hakobackend_core::Doc, hakobackend_core::AppError> {
            self.store.lock().unwrap().entry(c.into()).or_default().insert(doc.id.clone(), doc.clone());
            Ok(doc)
        }
        async fn set(&self, c: &str, id: &str, doc: hakobackend_core::Doc, _m: bool) -> Result<hakobackend_core::Doc, hakobackend_core::AppError> {
            self.store.lock().unwrap().entry(c.into()).or_default().insert(id.into(), doc.clone());
            Ok(doc)
        }
        async fn delete(&self, c: &str, id: &str) -> Result<Option<hakobackend_core::Doc>, hakobackend_core::AppError> {
            Ok(self.store.lock().unwrap().get_mut(c).and_then(|t| t.remove(id)))
        }
        async fn count(&self, _c: &str, _q: &hakobackend_core::QueryOptions) -> Result<u64, hakobackend_core::AppError> {
            Ok(0)
        }
        async fn subscribe(&self, _c: &str) -> Result<tokio::sync::broadcast::Receiver<hakobackend_core::Change>, hakobackend_core::AppError> {
            Ok(tokio::sync::broadcast::channel(1).0.subscribe())
        }
        async fn create_index(&self, _c: &str, _s: &hakobackend_core::IndexSpec) -> Result<hakobackend_core::IndexInfo, hakobackend_core::AppError> {
            Err(hakobackend_core::AppError::BadRequest("fake without index".into()))
        }
        async fn list_indexes(&self, _c: &str) -> Result<Vec<hakobackend_core::IndexInfo>, hakobackend_core::AppError> {
            Ok(vec![])
        }
        async fn drop_index(&self, _c: &str, _n: &str) -> Result<(), hakobackend_core::AppError> {
            Err(hakobackend_core::AppError::BadRequest("fake without index".into()))
        }
    }

    /// Mock OAuth server: token endpoint (POST) + /user (GET) in one server.
    fn mock_oauth() -> (String, Arc<std::sync::atomic::AtomicBool>, std::thread::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        listener.set_nonblocking(true).unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let stop = Arc::new(std::sync::atomic::AtomicBool::new(false));
        let s2 = stop.clone();
        let handle = std::thread::spawn(move || {
            while !s2.load(Ordering::SeqCst) {
                match listener.accept() {
                    Ok((mut s, _)) => {
                        let _ = s.set_nonblocking(false);
                        let req = read_request(&mut s);
                        let body = if req.starts_with("POST") && req.contains("code=good-code") {
                            json!({"access_token": "tok-oauth", "token_type": "bearer"}).to_string()
                        } else if req.starts_with("POST") {
                            json!({"error": "bad_verification_code"}).to_string()
                        } else if req.contains("Bearer tok-oauth") {
                            json!({"id": 7, "login": "octocat", "email": null}).to_string()
                        } else {
                            json!({"message": "bad"}).to_string()
                        };
                        let status = if body.contains("bad") || body.contains("error") { "401 Unauthorized" } else { "200 OK" };
                        let resp = format!(
                            "HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",
                            body.len()
                        );
                        let _ = s.write_all(resp.as_bytes());
                    }
                    Err(_) => std::thread::sleep(std::time::Duration::from_millis(20)),
                }
            }
        });
        (url, stop, handle)
    }

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn oauth_handle(base: &str, db: Arc<dyn hakobackend_core::Database>) -> Arc<GithubOAuth> {
        GithubOAuth::new(
            "cid-123".into(),
            "do-not-leak-secret".into(),
            "https://app.example.test".into(),
            base.into(),
            format!("{base}/login/oauth/access_token"),
            "https://github.com/login/oauth/authorize".into(),
            "/".into(),
            db,
        )
    }

    fn state_of(url: &str) -> String {
        url.split("state=").nth(1).unwrap().split('&').next().unwrap().to_string()
    }

    #[tokio::test]
    async fn oauth_login_url_and_callback() {
        let (base, stop, server) = mock_oauth();
        let db: Arc<dyn hakobackend_core::Database> = Arc::new(FakeDb { store: std::sync::Mutex::new(HashMap::new()) });
        let h = oauth_handle(&base, db);

        let (url, nonce) = h.login_url().await.unwrap();
        assert!(url.contains("client_id=cid-123"));
        assert!(url.contains("code_challenge=") && url.contains("code_challenge_method=S256"));
        assert!(url.contains("state="));
        assert!(!url.contains("do-not-leak-secret"), "secret must not leak into URL");

        // Happy-path callback: good code + correct state + browser nonce.
        let (uid, email, login) = h.callback("good-code", &state_of(&url), Some(&nonce)).await.unwrap();
        assert_eq!(uid, "github:7");
        assert_eq!(email, None);
        assert_eq!(login.as_deref(), Some("octocat"));

        // Single-use state: retry → rejected.
        assert!(h.callback("good-code", &state_of(&url), Some(&nonce)).await.is_err());
        // Unknown state / bad code → rejected.
        assert!(h.callback("good-code", "state-asing", Some(&nonce)).await.is_err());
        // Wrong or missing browser nonce → rejected (login CSRF).
        let (url3, _) = h.login_url().await.unwrap();
        assert!(h.callback("good-code", &state_of(&url3), Some("wrong-nonce")).await.is_err());
        assert!(h.callback("good-code", &state_of(&url3), None).await.is_err());
        let (url2, nonce2) = h.login_url().await.unwrap();
        assert!(h.callback("bad-code", &state_of(&url2), Some(&nonce2)).await.is_err());

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn oauth_pending_expired_rejected() {
        let (base, stop, server) = mock_oauth();
        let db: Arc<dyn hakobackend_core::Database> = Arc::new(FakeDb { store: std::sync::Mutex::new(HashMap::new()) });
        let h = oauth_handle(&base, db.clone());
        // Plant a stale pending entry manually (created_at 1 hour ago).
        db.insert(
            "__oauth_pending",
            hakobackend_core::Doc {
                id: "state-basi".into(),
                data: [
                    ("provider".to_string(), json!("github")),
                    ("verifier".to_string(), json!("v")),
                    ("created_at".to_string(), json!(now_secs() - 3600)),
                ]
                .into_iter()
                .collect(),
            },
        )
        .await
        .unwrap();
        assert!(h.callback("good-code", "state-basi", Some("whatever")).await.is_err());
        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
    }

    #[test]
    fn oauth_from_env_fail_closed() {
        let _g = ENV_LOCK.lock().unwrap();
        for k in ["UB_GITHUB_CLIENT_ID", "UB_GITHUB_CLIENT_SECRET", "UB_PUBLIC_URL"] {
            std::env::remove_var(k);
        }
        let db: Arc<dyn hakobackend_core::Database> = Arc::new(FakeDb { store: std::sync::Mutex::new(HashMap::new()) });
        // No client id = feature disabled (not an error).
        assert!(GithubOAuth::from_env(db.clone()).unwrap().is_none());
        // Id without secret, or without public URL = clear error.
        std::env::set_var("UB_GITHUB_CLIENT_ID", "x");
        assert!(GithubOAuth::from_env(db.clone()).is_err());
        std::env::set_var("UB_GITHUB_CLIENT_SECRET", "y");
        assert!(GithubOAuth::from_env(db).is_err());
        for k in ["UB_GITHUB_CLIENT_ID", "UB_GITHUB_CLIENT_SECRET"] {
            std::env::remove_var(k);
        }
    }
}

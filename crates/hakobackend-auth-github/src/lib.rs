//! hakobackend-auth-github: verifier-only token GitHub (tanpa alur OAuth).
//!
//! Token dicek ke `GET {api}/user` (cache 60 dtk) → `uid = "github:<id>"`.
//! Alur login OAuth penuh (code exchange di server, pola BFF) menyusul fase E.
//! Konfig via env: `UB_GITHUB_API` (opsional, default api.github.com,
//! override untuk test). Tanpa secret — secret OAuth hanya dibutuhkan fase E.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};
use hakobackend_core::{AppError, AuthProvider, Claims};

const GITHUB_API: &str = "https://api.github.com";
const CACHE_TTL: Duration = Duration::from_secs(60);

pub struct GithubVerifier {
    api_base: String,
    client: reqwest::Client,
    /// Token → klaim. Memori saja, 60 dtk; tidak pernah dipersisten/di-log.
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

// --- OAuth login penuh, pola BFF (fase E) ---
//
// Browser hanya melihat redirect + session cookie; code↔token terjadi di server.
// Koleksi pending internal `__oauth_pending` (prefix `__`, tak diekspos HTTP).
// Secret HANYA via env (`UB_GITHUB_CLIENT_SECRET`), tak pernah di file config/log.

const GITHUB_AUTHORIZE: &str = "https://github.com/login/oauth/authorize";
const GITHUB_TOKEN: &str = "https://github.com/login/oauth/access_token";
const PENDING_COLLECTION: &str = "__oauth_pending";
/// Umur state+verifier pending (detik).
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
    /// `Ok(None)` = fitur mati (tanpa client id); `Err` = konfigurasi timpang (fail-closed).
    pub fn from_env(db: Arc<dyn hakobackend_core::Database>) -> Result<Option<Arc<Self>>, String> {
        let Some(client_id) = env_nonempty("UB_GITHUB_CLIENT_ID") else {
            return Ok(None);
        };
        let Some(secret) = env_nonempty("UB_GITHUB_CLIENT_SECRET") else {
            return Err("UB_GITHUB_CLIENT_ID terisi tapi UB_GITHUB_CLIENT_SECRET kosong".to_string());
        };
        let Some(public) = env_nonempty("UB_PUBLIC_URL") else {
            return Err("OAuth github butuh UB_PUBLIC_URL (asal callback https://…)".to_string());
        };
        let api_base = std::env::var("UB_GITHUB_API").unwrap_or_else(|_| GITHUB_API.into());
        let token_url = std::env::var("UB_GITHUB_TOKEN_URL").unwrap_or_else(|_| GITHUB_TOKEN.into());
        let authorize_url = std::env::var("UB_GITHUB_AUTHORIZE_URL").unwrap_or_else(|_| GITHUB_AUTHORIZE.into());
        let after_login = std::env::var("UB_GITHUB_AFTER_LOGIN").unwrap_or_else(|_| "/".into());
        Ok(Some(Self::new(client_id, secret, public, api_base, token_url, authorize_url, after_login, db)))
    }

    /// Konstruktor eksplisit (dipakai test — tanpa env, hermetis).
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

    /// URL redirect ke github.com + simpan state/PKCE pending (sekali pakai, 10 mnt).
    pub async fn login_url(&self) -> Result<String, AppError> {
        let state = rand_hex(16);
        let verifier = rand_hex(64);
        let doc = hakobackend_core::Doc {
            id: state.clone(),
            data: [
                ("provider".to_string(), serde_json::Value::String("github".into())),
                ("verifier".to_string(), serde_json::Value::String(verifier.clone())),
                ("created_at".to_string(), serde_json::Value::from(now_secs())),
            ]
            .into_iter()
            .collect(),
        };
        self.db.insert(PENDING_COLLECTION, doc).await.map_err(|_| AppError::Internal("oauth store error".into()))?;
        Ok(format!(
            "{}?client_id={}&redirect_uri={}&scope={}&state={}&code_challenge={}&code_challenge_method=S256",
            self.authorize_url,
            urlenc(&self.client_id),
            urlenc(&self.redirect_uri),
            urlenc("read:user user:email"),
            urlenc(&state),
            urlenc(&pkce_challenge(&verifier)),
        ))
    }

    /// Hasil callback: (uid-namespaced, email, login-github). Sesi diterbitkan
    /// server via `LocalAuth::login_external` (terpisah agar crate tak sirkular).
    pub async fn callback(&self, code: &str, state: &str) -> Result<(String, Option<String>, Option<String>), AppError> {
        let pending = self.db.get(PENDING_COLLECTION, state).await.map_err(|_| AppError::Internal("oauth store error".into()))?
            .ok_or(AppError::PermissionDenied)?;
        // Sekali pakai + kedaluwarsa (fail-closed; stale dibuang).
        self.db.delete(PENDING_COLLECTION, state).await.map_err(|_| AppError::Internal("oauth store error".into()))?;
        let fresh = pending
            .data
            .get("created_at")
            .and_then(|v| v.as_u64())
            .is_some_and(|t| t + PENDING_TTL_SECS > now_secs());
        let verifier = pending.data.get("verifier").and_then(|v| v.as_str()).unwrap_or("");
        if !fresh || verifier.is_empty() || pending.data.get("provider").and_then(|v| v.as_str()) != Some("github") {
            return Err(AppError::PermissionDenied);
        }
        let token = self.exchange(code, verifier).await?;
        let claims = self.verifier.verify(&token).await?;
        let login = claims.extra.get("login").and_then(|v| v.as_str()).map(str::to_string);
        Ok((claims.namespaced(), claims.email, login))
    }

    async fn exchange(&self, code: &str, verifier: &str) -> Result<String, AppError> {
        // Secret tak pernah masuk pesan error (anti bocor).
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
            .map_err(|_| AppError::BadRequest("tukar code gagal".into()))?
            .json()
            .await
            .map_err(|_| AppError::BadRequest("tukar code gagal".into()))?;
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

/// Persen-encode minimal untuk query OAuth (tanpa crate tambahan).
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

    /// Baca satu request HTTP utuh (header + body sesuai Content-Length).
    /// Single-read rawan partial-read TCP (sumber flaky); framing benar di sini.
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

    /// Mock api.github.com: `/user` valid untuk "tok-bagus", 401 untuk lainnya.
    /// Menghitung hit agar cache terbukti; berhenti via flag.
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
                        // Soket hasil accept mewarisi nonblocking dari listener —
                        // kembalikan ke blocking agar read_request tak pernah WouldBlock.
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
    async fn verify_cache_dan_tolak() {
        let (url, hits, stop, server) = mock_github();
        // Konstruktor eksplisit — tanpa env, hermetis antar-test paralel.
        let v = GithubVerifier::with_api_base(url);

        let c = v.verify("tok-bagus").await.unwrap();
        assert_eq!((c.provider, c.uid.as_str()), ("github", "42"));
        assert_eq!(c.email.as_deref(), Some("o@x.io"));
        // Panggilan kedua dari cache (hits tetap 1).
        let c2 = v.verify("tok-bagus").await.unwrap();
        assert_eq!(c2.uid, "42");
        assert_eq!(hits.load(Ordering::SeqCst), 1);
        // Token asing → Err (chain lanjut ke provider berikut).
        assert!(v.verify("tok-jelek").await.is_err());

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
    }

    /// Fake DB minimal: pending store butuh get/insert/delete sungguhan.
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
            Err(hakobackend_core::AppError::BadRequest("fake tanpa index".into()))
        }
        async fn list_indexes(&self, _c: &str) -> Result<Vec<hakobackend_core::IndexInfo>, hakobackend_core::AppError> {
            Ok(vec![])
        }
        async fn drop_index(&self, _c: &str, _n: &str) -> Result<(), hakobackend_core::AppError> {
            Err(hakobackend_core::AppError::BadRequest("fake tanpa index".into()))
        }
    }

    /// Mock server OAuth: token endpoint (POST) + /user (GET) dalam satu server.
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
            "sekret-jangan-bocor".into(),
            "https://app.contoh.id".into(),
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
    async fn oauth_login_url_dan_callback() {
        let (base, stop, server) = mock_oauth();
        let db: Arc<dyn hakobackend_core::Database> = Arc::new(FakeDb { store: std::sync::Mutex::new(HashMap::new()) });
        let h = oauth_handle(&base, db);

        let url = h.login_url().await.unwrap();
        assert!(url.contains("client_id=cid-123"));
        assert!(url.contains("code_challenge=") && url.contains("code_challenge_method=S256"));
        assert!(url.contains("state="));
        assert!(!url.contains("sekret-jangan-bocor"), "secret tak boleh bocor ke URL");

        // Callback bahagia: code baik + state benar → triple identitas.
        let (uid, email, login) = h.callback("good-code", &state_of(&url)).await.unwrap();
        assert_eq!(uid, "github:7");
        assert_eq!(email, None);
        assert_eq!(login.as_deref(), Some("octocat"));

        // State sekali pakai: ulangi → tolak.
        assert!(h.callback("good-code", &state_of(&url)).await.is_err());
        // State asing / code jelek → tolak.
        assert!(h.callback("good-code", "state-asing").await.is_err());
        let url2 = h.login_url().await.unwrap();
        assert!(h.callback("bad-code", &state_of(&url2)).await.is_err());

        stop.store(true, Ordering::SeqCst);
        server.join().unwrap();
    }

    #[tokio::test]
    async fn oauth_pending_kedaluwarsa_ditolak() {
        let (base, stop, server) = mock_oauth();
        let db: Arc<dyn hakobackend_core::Database> = Arc::new(FakeDb { store: std::sync::Mutex::new(HashMap::new()) });
        let h = oauth_handle(&base, db.clone());
        // Tanam pending basi manual (created_at 1 jam lalu).
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
        assert!(h.callback("good-code", "state-basi").await.is_err());
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
        // Tanpa client id = fitur mati (bukan error).
        assert!(GithubOAuth::from_env(db.clone()).unwrap().is_none());
        // Id tanpa secret, atau tanpa public URL = error jelas.
        std::env::set_var("UB_GITHUB_CLIENT_ID", "x");
        assert!(GithubOAuth::from_env(db.clone()).is_err());
        std::env::set_var("UB_GITHUB_CLIENT_SECRET", "y");
        assert!(GithubOAuth::from_env(db).is_err());
        for k in ["UB_GITHUB_CLIENT_ID", "UB_GITHUB_CLIENT_SECRET"] {
            std::env::remove_var(k);
        }
    }
}

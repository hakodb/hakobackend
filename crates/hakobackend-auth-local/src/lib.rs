//! hakobackend-auth-local: the sole issuer (phase C). Verifier + local account manager.
//!
//! Dual-token BFF pattern: short-lived access JWT + per-use rotating opaque refresh,
//! both HttpOnly (`__Host-`, Secure, SameSite=Strict). Browser JS never
//! sees tokens. Refresh reuse → revoke all user sessions (fail-closed).
//! Argon2id passwords; sessions in the internal `__sessions` collection (see SECURITY_RULES §4).
//! Env: `UB_LOCAL_JWT_SECRET` (required), `UB_LOCAL_USERS` (default `users`),
//! `UB_LOCAL_DEFAULT_ROLE` (optional), `UB_LOCAL_ACCESS_TTL` (secs, default 600),
//! `UB_LOCAL_REFRESH_TTL` (secs, default 30 days).

use argon2::{Argon2, PasswordHash, PasswordHasher, PasswordVerifier, password_hash::SaltString};
use argon2::password_hash::rand_core::OsRng;
use rand::RngCore;use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::sync::Arc;
use hakobackend_core::{AppError, AuthContext, AuthProvider, Claims, Database, Doc, Filter, FilterOp, QueryOptions, SessionIssuer};
use hakobackend_policy::Identity;

pub mod dpop;
pub use dpop::{DpopMode, DpopRequest};

pub const NAME: &str = "local";
/// Access JWT cookie: Path=/ so it is sent to all APIs.
pub const ACCESS_COOKIE: &str = "__Host-ub_at";
/// Opaque refresh cookie: Path=/ (`__Host-` prefix requirement; only read at
/// the refresh endpoint). Both HttpOnly + Secure + SameSite=Strict.
pub const REFRESH_COOKIE: &str = "__Host-ub_rt";
/// Internal session collection — `__` prefix, never exposed over HTTP (SECURITY_RULES §4).
pub const SESSIONS_COLLECTION: &str = "__sessions";
const PASSWORD_FIELD: &str = "password_hash";
const ISSUER: &str = "universalbackend";
const AUDIENCE: &str = "ub";

#[derive(Debug, Clone)]
pub struct LocalConfig {
    pub jwt_secret: Vec<u8>,
    pub access_ttl_secs: u64,
    pub refresh_ttl_secs: u64,
    pub default_role: Option<String>,
}

impl LocalConfig {
    pub fn from_env() -> Result<Self, String> {
        let jwt_secret = std::env::var("UB_LOCAL_JWT_SECRET")
            .map_err(|_| "auth local requires env UB_LOCAL_JWT_SECRET (min 32 random characters)".to_string())?;
        if jwt_secret.len() < 32 {
            return Err("UB_LOCAL_JWT_SECRET too short (min 32 characters)".into());
        }
        let num = |k: &str, d: u64| {
            std::env::var(k).ok().and_then(|v| v.parse().ok()).unwrap_or(d)
        };
        Ok(Self {
            jwt_secret: jwt_secret.into_bytes(),
            access_ttl_secs: num("UB_LOCAL_ACCESS_TTL", 600),
            refresh_ttl_secs: num("UB_LOCAL_REFRESH_TTL", 30 * 86400),
            default_role: std::env::var("UB_LOCAL_DEFAULT_ROLE").ok(),
        })
    }
}

pub struct SessionTokens {
    pub access_jwt: String,
    pub refresh_opaque: String,
}

pub struct LocalAuth {
    cfg: LocalConfig,
    db: Arc<dyn Database>,
    identity: Identity,
    dpop_mode: std::sync::Mutex<DpopMode>,
    dpop_replay: std::sync::Mutex<dpop::ReplayCache>,
    /// Tenant this provider serves (per-tenant instances). Bound into JWTs
    /// and forced into contexts; None = global provider.
    forced_tenant: Option<String>,
}

impl LocalAuth {
    /// `users_collection` comes from the `[identity]` policy (user's choice).
    /// Returns the concrete type (server needs the register/login/refresh methods);
    /// coercion to `Arc<dyn AuthProvider>` for the chain lives in the server.
    pub fn build(db: Arc<dyn Database>, identity: Identity) -> Result<Arc<Self>, String> {
        Ok(Arc::new(Self {
            cfg: LocalConfig::from_env()?,
            db,
            identity,
            dpop_mode: std::sync::Mutex::new(DpopMode::from_env()),
            dpop_replay: std::sync::Mutex::new(dpop::ReplayCache::default()),
            forced_tenant: None,
        }))
    }

    /// Scope this provider to one tenant: user store lookups, minted JWTs,
    /// and contexts all carry it. Consumes nothing else — same handle shape.
    pub fn with_tenant(self: &Arc<Self>, tenant: &str) -> Arc<Self> {
        Arc::new(Self {
            cfg: self.cfg.clone(),
            db: self.db.clone(),
            identity: self.identity.clone(),
            dpop_mode: std::sync::Mutex::new(self.dpop_mode()),
            dpop_replay: std::sync::Mutex::new(dpop::ReplayCache::default()),
            forced_tenant: Some(tenant.into()),
        })
    }

    /// Effective DPoP mode (env `UB_LOCAL_DPOP`, overridable via `dpop` in custom.toml).
    pub fn dpop_mode(&self) -> DpopMode {
        *self.dpop_mode.lock().unwrap()
    }

    pub fn set_dpop_mode(&self, mode: DpopMode) {
        *self.dpop_mode.lock().unwrap() = mode;
    }

    fn users(&self) -> &str {
        &self.identity.users_collection
    }

    /// Cookie lifetime (secs) — used by the HTTP layer when setting Set-Cookie.
    pub fn access_ttl(&self) -> u64 {
        self.cfg.access_ttl_secs
    }
    pub fn refresh_ttl(&self) -> u64 {
        self.cfg.refresh_ttl_secs
    }

    async fn find_user(&self, login: &str) -> Result<Doc, AppError> {
        if let Some(d) = self.db.get(self.users(), login).await.map_err(internal)? {
            return Ok(d);
        }
        let mut q = QueryOptions::default();
        q.filters.push(Filter {
            field: "email".into(),
            op: FilterOp::Eq,
            value: serde_json::Value::String(login.into()),
        });
        q.limit = Some(2);
        let rows = self.db.list(self.users(), &q).await.map_err(internal)?;
        // Exactly 1 hit; 0/2+ = disguised as wrong credentials (anti-enumeration).
        if rows.len() == 1 {
            Ok(rows.into_iter().next().unwrap())
        } else {
            Err(AppError::PermissionDenied)
        }
    }

    async fn mint(
        &self,
        uid: &str,
        ctx_uid: &str,
        email: Option<String>,
        cnf: Option<String>,
    ) -> Result<(SessionTokens, String), AppError> {
        let now = now_secs();
        let access_jwt = self.mint_access(uid, email, cnf)?;
        let refresh_opaque = rand_hex(32);
        let session_id = rand_hex(16);
        let session = Doc {
            id: session_id.clone(),
            data: [
                ("uid".to_string(), serde_json::Value::String(uid.into())),
                ("ctx_uid".to_string(), serde_json::Value::String(ctx_uid.into())),
                ("refresh_hash".to_string(), serde_json::Value::String(sha_hex(&refresh_opaque))),
                ("created_at".to_string(), serde_json::Value::from(now)),
                ("expires_at".to_string(), serde_json::Value::from(now + self.cfg.refresh_ttl_secs)),
            ]
            .into_iter()
            .collect(),
        };
        self.db.insert(SESSIONS_COLLECTION, session).await.map_err(internal)?;
        Ok((SessionTokens { access_jwt, refresh_opaque }, session_id))
    }

    fn ctx_of(&self, uid: &str, doc: &Doc) -> AuthContext {
        // Tenant comes from the admin-managed user doc (never from login
        // input); invalid slugs are dropped so they can never namespace.
        // A forced provider tenant wins over the doc field.
        let tenant = self.forced_tenant.clone().or_else(|| {
            doc.data
                .get("tenant")
                .and_then(|v| v.as_str())
                .filter(|t| hakobackend_core::tenant::is_valid_tenant_slug(t))
                .map(str::to_string)
        });
        AuthContext {
            uid: uid.into(),
            roles: self.identity.roles_of(doc),
            tenant,
            extra: match doc.data.get("email").and_then(|v| v.as_str()) {
                Some(e) => [("email".to_string(), serde_json::Value::String(e.into()))].into_iter().collect(),
                None => HashMap::new(),
            },
        }
    }

    /// Self-service registration: `role`/`password_hash` from the body are ALWAYS discarded
    /// (anti self-escalation); roles only come from `UB_LOCAL_DEFAULT_ROLE` when set.
    pub async fn register(
        &self,
        id: Option<String>,
        email: Option<String>,
        password: &str,
        profile: HashMap<String, serde_json::Value>,
    ) -> Result<Doc, AppError> {
        let id = id.or(email.clone()).filter(|s| !s.is_empty()).ok_or_else(|| AppError::BadRequest("id/email required".into()))?;
        if password.len() < 8 {
            return Err(AppError::BadRequest("password must be at least 8 characters".into()));
        }
        if self.db.get(self.users(), &id).await.map_err(internal)?.is_some() {
            return Err(AppError::AlreadyExists);
        }
        // Email must be unique: login accepts id-or-email and errors on
        // ambiguity, so a second account on the same email would lock the
        // victim out of email login. Fail-closed at registration.
        if let Some(e) = email.clone().filter(|s| !s.is_empty()) {
            let mut q = hakobackend_core::QueryOptions::default();
            q.filters.push(hakobackend_core::Filter {
                field: "email".into(),
                op: hakobackend_core::FilterOp::Eq,
                value: serde_json::Value::String(e),
            });
            let clash = self
                .db
                .list(self.users(), &q)
                .await
                .map_err(internal)?
                .into_iter()
                .any(|d| d.id != id);
            if clash {
                return Err(AppError::AlreadyExists);
            }
        }
        let hash = hash_password(password.to_string()).await?;
        let mut data = profile;
        data.remove(PASSWORD_FIELD);
        data.remove(&self.identity.role_field);
        data.remove("roles");
        data.insert(PASSWORD_FIELD.into(), serde_json::Value::String(hash));
        if let Some(e) = email {
            data.insert("email".into(), serde_json::Value::String(e));
        }
        if let Some(r) = &self.cfg.default_role {
            data.insert(self.identity.role_field.clone(), serde_json::Value::String(r.clone()));
        }
        self.db.insert(self.users(), Doc { id, data }).await.map_err(internal)
    }

    pub async fn login(
        &self,
        login: &str,
        password: &str,
        dpop: Option<DpopRequest<'_>>,
    ) -> Result<(AuthContext, SessionTokens), AppError> {
        let doc = self.find_user(login).await?;
        let stored = doc.data.get(PASSWORD_FIELD).and_then(|v| v.as_str()).ok_or(AppError::PermissionDenied)?.to_string();
        if !verify_password(password.to_string(), stored).await {
            return Err(AppError::PermissionDenied);
        }
        let email = doc.data.get("email").and_then(|v| v.as_str()).map(str::to_string);
        let ctx_uid = format!("{NAME}:{}", doc.id);
        let (tokens, _) = self.mint(&doc.id, &ctx_uid, email, self.bind_dpop(dpop)?).await?;
        Ok((self.ctx_of(&ctx_uid, &doc), tokens))
    }

    /// Refresh rotation. An old token showing up again = reuse → revoke ALL user sessions.
    pub async fn refresh(
        &self,
        presented: &str,
        dpop: Option<DpopRequest<'_>>,
    ) -> Result<(AuthContext, SessionTokens), AppError> {
        let h = sha_hex(presented);
        if let Some(sess) = self.session_by("refresh_hash", &h).await? {
            let uid = sess.data.get("uid").and_then(|v| v.as_str()).ok_or(AppError::PermissionDenied)?.to_string();
            if expired(&sess, now_secs()) {
                self.db.delete(SESSIONS_COLLECTION, &sess.id).await.map_err(internal)?;
                return Err(AppError::PermissionDenied);
            }
            // Rotation: keep the old hash as a reuse trap.
            let new_refresh = rand_hex(32);
            let mut data = sess.data.clone();
            data.insert("prev_hash".into(), serde_json::Value::String(h));
            data.insert("refresh_hash".into(), serde_json::Value::String(sha_hex(&new_refresh)));
            self.db.set(SESSIONS_COLLECTION, &sess.id, Doc { id: sess.id.clone(), data }, true).await.map_err(internal)?;
            let doc = self.db.get(self.users(), &uid).await.map_err(internal)?.ok_or(AppError::PermissionDenied)?;
            let email = doc.data.get("email").and_then(|v| v.as_str()).map(str::to_string);
            let access = self.mint_access(&uid, email, self.bind_dpop(dpop)?)?;
            let ctx_uid = sess.data.get("ctx_uid").and_then(|v| v.as_str()).unwrap_or(&uid).to_string();
            return Ok((self.ctx_of(&ctx_uid, &doc), SessionTokens { access_jwt: access, refresh_opaque: new_refresh }));
        }
        if let Some(sess) = self.session_by("prev_hash", &h).await? {
            let uid = sess.data.get("uid").and_then(|v| v.as_str()).unwrap_or("").to_string();
            self.revoke_user(&uid).await?;
            return Err(AppError::PermissionDenied);
        }
        Err(AppError::PermissionDenied)
    }

    pub async fn logout(&self, presented: &str) -> Result<(), AppError> {
        if let Some(sess) = self.session_by("refresh_hash", &sha_hex(presented)).await? {
            self.db.delete(SESSIONS_COLLECTION, &sess.id).await.map_err(internal)?;
        }
        Ok(())
    }

    /// Login via an external provider (OAuth result): find-or-create the user document
    /// with a namespaced id (`github:7`), then issue a local session (BFF).
    /// Provisioned WITHOUT roles (fail-closed; admin assigns via CRUD).
    /// No auto-merge by email (prevents takeover via unverified email).
    pub async fn login_external(
        &self,
        provider_uid: &str,
        email: Option<String>,
        profile: HashMap<String, serde_json::Value>,
    ) -> Result<(AuthContext, SessionTokens), AppError> {
        let doc = match self.db.get(self.users(), provider_uid).await.map_err(internal)? {
            Some(d) => d,
            None => {
                let mut data = profile;
                data.remove(PASSWORD_FIELD);
                data.remove(&self.identity.role_field);
                data.remove("roles");
                if let Some(e) = email.clone() {
                    data.insert("email".into(), serde_json::Value::String(e));
                }
                self.db
                    .insert(self.users(), Doc { id: provider_uid.into(), data })
                    .await
                    .map_err(internal)?
            }
        };
        let email = email.or_else(|| doc.data.get("email").and_then(|v| v.as_str()).map(str::to_string));
        let (tokens, _) = self.mint(&doc.id, &doc.id, email, None).await?;
        Ok((self.ctx_of(&doc.id, &doc), tokens))
    }

    async fn session_by(&self, field: &str, hash: &str) -> Result<Option<Doc>, AppError> {
        let mut q = QueryOptions::default();
        q.filters.push(Filter {
            field: field.into(),
            op: FilterOp::Eq,
            value: serde_json::Value::String(hash.into()),
        });
        q.limit = Some(1);
        Ok(self.db.list(SESSIONS_COLLECTION, &q).await.map_err(internal)?.into_iter().next())
    }

    async fn revoke_user(&self, uid: &str) -> Result<(), AppError> {
        let mut q = QueryOptions::default();
        q.filters.push(Filter {
            field: "uid".into(),
            op: FilterOp::Eq,
            value: serde_json::Value::String(uid.into()),
        });
        for s in self.db.list(SESSIONS_COLLECTION, &q).await.map_err(internal)? {
            self.db.delete(SESSIONS_COLLECTION, &s.id).await.map_err(internal)?;
        }
        Ok(())
    }

    fn mint_access(&self, uid: &str, email: Option<String>, cnf: Option<String>) -> Result<String, AppError> {
        let now = now_secs();
        let access = AccessClaims {
            sub: uid.into(),
            email,
            iss: ISSUER.into(),            aud: AUDIENCE.into(),
            exp: now + self.cfg.access_ttl_secs,
            iat: now,
            cnf: cnf.map(|jkt| Cnf { jkt }),
            tenant: self.forced_tenant.clone(),
        };
        jsonwebtoken::encode(
            &jsonwebtoken::Header::new(jsonwebtoken::Algorithm::HS256),
            &access,
            &jsonwebtoken::EncodingKey::from_secret(&self.cfg.jwt_secret),
        )
        .map_err(internal)
    }

    /// cnf.jkt of this token (None = plain bearer). Decode ONCE with full verification.
    pub fn bound_jkt(&self, access_token: &str) -> Result<Option<String>, AppError> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&[ISSUER]);
        let data: jsonwebtoken::TokenData<AccessClaims> = jsonwebtoken::decode(
            access_token,
            &jsonwebtoken::DecodingKey::from_secret(&self.cfg.jwt_secret),
            &validation,
        )
        .map_err(|_| AppError::PermissionDenied)?;
        Ok(data.claims.cnf.map(|c| c.jkt))
    }

    /// Enforce the DPoP proof for one resource request. Off mode = pass through directly.
    pub fn check_dpop(
        &self,
        proof: &str,
        method: &str,
        uri: &str,
        access_token: &str,
        expected_jkt: Option<&str>,
    ) -> Result<(), AppError> {
        if self.dpop_mode() == DpopMode::Off {
            return Ok(());
        }
        let v = dpop::verify_proof(proof, method, uri, Some(access_token))
            .map_err(|_| AppError::PermissionDenied)?;
        if let Some(exp) = expected_jkt {
            if !timing_safe_eq(&v.jkt, exp) {
                return Err(AppError::PermissionDenied);
            }
        }
        self.dpop_replay.lock().unwrap().check(&v.jti).map_err(|_| AppError::PermissionDenied)
    }

    /// Validate the proof at issuance (login/refresh) → jkt to bind into cnf.
    fn bind_dpop(&self, dpop: Option<DpopRequest<'_>>) -> Result<Option<String>, AppError> {
        match dpop {
            None => Ok(None),
            Some(d) => {
                let v = dpop::verify_proof(d.proof, d.method, d.uri, None)
                    .map_err(|_| AppError::PermissionDenied)?;
                self.dpop_replay.lock().unwrap().check(&v.jti).map_err(|_| AppError::PermissionDenied)?;
                Ok(Some(v.jkt))
            }
        }
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct Cnf {
    jkt: String,
}

#[derive(Debug, Serialize, Deserialize)]
struct AccessClaims {
    sub: String,
    email: Option<String>,
    iss: String,
    aud: String,
    exp: u64,
    iat: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    cnf: Option<Cnf>,
    /// Tenant bound at issuance (per-tenant providers). Absent = global.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    tenant: Option<String>,
}

#[async_trait::async_trait]
impl AuthProvider for LocalAuth {
    fn name(&self) -> &'static str {
        NAME
    }

    async fn verify(&self, token: &str) -> Result<Claims, AppError> {
        let mut validation = jsonwebtoken::Validation::new(jsonwebtoken::Algorithm::HS256);
        validation.set_audience(&[AUDIENCE]);
        validation.set_issuer(&[ISSUER]);
        let data: jsonwebtoken::TokenData<AccessClaims> = jsonwebtoken::decode(
            token,
            &jsonwebtoken::DecodingKey::from_secret(&self.cfg.jwt_secret),
            &validation,
        )
        .map_err(|_| AppError::PermissionDenied)?;
        Ok(Claims {
            provider: NAME,
            uid: data.claims.sub,
            email: data.claims.email,
            extra: HashMap::new(),
            tenant: data.claims.tenant,
        })
    }
}

#[async_trait::async_trait]
impl SessionIssuer for LocalAuth {
    async fn login(&self, user: &str, secret: &str) -> Result<AuthContext, AppError> {
        Ok(self.login(user, secret, None).await?.0)
    }

    async fn refresh(&self, refresh_token: &str) -> Result<AuthContext, AppError> {
        Ok(self.refresh(refresh_token, None).await?.0)
    }

    async fn logout(&self, ctx: &AuthContext) -> Result<(), AppError> {
        // Logout needs the refresh token (held by the HTTP layer); ctx alone is not enough.
        // revoke_user is used internally when reuse is detected.
        let _ = ctx;
        Err(AppError::BadRequest("logout via POST /api/auth/logout".into()))
    }
}

fn internal(_: impl std::fmt::Display) -> AppError {
    // ponytail: hide internal DB/crypto details — always a generic 500.
    AppError::Internal("auth store error".into())
}

fn now_secs() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn expired(sess: &Doc, now: u64) -> bool {
    sess.data.get("expires_at").and_then(|v| v.as_u64()).is_some_and(|e| e <= now)
}

fn sha_hex(s: &str) -> String {
    format!("{:x}", Sha256::digest(s.as_bytes()))
}

fn rand_hex(nbytes: usize) -> String {
    let mut buf = vec![0u8; nbytes];
    rand::thread_rng().fill_bytes(&mut buf);
    buf.iter().map(|b| format!("{b:02x}")).collect()
}

async fn hash_password(password: String) -> Result<String, AppError> {
    // Argon2id (~19 MiB, t=2) is deliberately CPU/RAM-heavy: cap concurrent
    // hashes process-wide so a login flood can't saturate the pool (the
    // per-IP rate limit is the first line; this is the second).
    static HASH_SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    let sem = HASH_SEM.get_or_init(|| tokio::sync::Semaphore::new(4));
    let _permit = sem.acquire().await.map_err(|_| AppError::Internal("hash failed".into()))?;
    tokio::task::spawn_blocking(move || {
        let salt = SaltString::generate(&mut OsRng);
        Argon2::default()
            .hash_password(password.as_bytes(), &salt)
            .map(|h| h.to_string())
            .map_err(|_| AppError::Internal("hash failed".into()))
    })
    .await
    .map_err(|_| AppError::Internal("hash failed".into()))?
}

async fn verify_password(password: String, hash: String) -> bool {
    // Same semaphore as hashing: verification burns identical CPU.
    static VERIFY_SEM: std::sync::OnceLock<tokio::sync::Semaphore> = std::sync::OnceLock::new();
    let sem = VERIFY_SEM.get_or_init(|| tokio::sync::Semaphore::new(8));
    let _permit = match sem.acquire().await {
        Ok(p) => p,
        Err(_) => return false,
    };
    tokio::task::spawn_blocking(move || {
        PasswordHash::new(&hash)
            .map(|p| Argon2::default().verify_password(password.as_bytes(), &p).is_ok())
            .unwrap_or(false)
    })
    .await
    .unwrap_or(false)
}

/// Timing-safe string compare (jkts, hashes — never `==` on secrets).
fn timing_safe_eq(a: &str, b: &str) -> bool {
    let (a, b) = (a.as_bytes(), b.as_bytes());
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b.iter()).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

#[cfg(test)]
mod tests {
    use super::*;
    use hakobackend_core::{Capabilities, Change, Doc};

    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Minimal fake DB for auth tests (CRUD + Eq filter + limit).
    struct FakeDb {
        store: std::sync::Mutex<HashMap<String, HashMap<String, Doc>>>,
    }

    impl FakeDb {
        fn new() -> Self {
            Self {
                store: std::sync::Mutex::new(HashMap::new()),
            }
        }
        fn filtered(&self, c: &str, q: &QueryOptions) -> Vec<Doc> {
            let g = self.store.lock().unwrap();
            let mut v: Vec<Doc> = g
                .get(c)
                .map(|t| {
                    t.values()
                        .filter(|d| {
                            q.filters.iter().all(|f| match f.op {
                                FilterOp::Eq => d.data.get(&f.field) == Some(&f.value),
                                _ => false,
                            })
                        })
                        .cloned()
                        .collect()
                })
                .unwrap_or_default();
            if let Some(n) = q.limit {
                v.truncate(n);
            }
            v
        }
    }

    #[async_trait::async_trait]
    impl Database for FakeDb {
        fn capabilities(&self) -> Capabilities {
            Capabilities { driver: "fake", supports_watch: false, supports_transactions: false, supports_composite: false, supports_fts: false, supports_drop_index: false, supports_unique: false, supports_named_index: false, supports_native_aggregation: false }
        }
        async fn ensure_collection(&self, _p: &str) -> Result<(), AppError> {
            Ok(())
        }
        async fn list_collections(&self) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        async fn get(&self, c: &str, id: &str) -> Result<Option<Doc>, AppError> {
            Ok(self.store.lock().unwrap().get(c).and_then(|t| t.get(id)).cloned())
        }
        async fn list(&self, c: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
            Ok(self.filtered(c, q))
        }
        async fn insert(&self, c: &str, mut doc: Doc) -> Result<Doc, AppError> {
            if doc.id.is_empty() {
                doc.id = "gen".into();
            }
            self.set(c, &doc.id.clone(), doc, false).await
        }
        async fn set(&self, c: &str, id: &str, doc: Doc, merge: bool) -> Result<Doc, AppError> {
            let mut g = self.store.lock().unwrap();
            let t = g.entry(c.into()).or_default();
            let mut data = if merge { t.get(id).map(|o| o.data.clone()).unwrap_or_default() } else { HashMap::new() };
            data.extend(doc.data);
            let out = Doc { id: id.into(), data };
            t.insert(id.into(), out.clone());
            Ok(out)
        }
        async fn delete(&self, c: &str, id: &str) -> Result<Option<Doc>, AppError> {
            Ok(self.store.lock().unwrap().get_mut(c).and_then(|t| t.remove(id)))
        }
        async fn count(&self, c: &str, q: &QueryOptions) -> Result<u64, AppError> {
            Ok(self.filtered(c, q).len() as u64)
        }
        async fn subscribe(&self, _c: &str) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
            Ok(tokio::sync::broadcast::channel(1).0.subscribe())
        }
        async fn create_index(&self, _c: &str, _s: &hakobackend_core::IndexSpec) -> Result<hakobackend_core::IndexInfo, AppError> {
            Err(AppError::BadRequest("fake without index".into()))
        }
        async fn list_indexes(&self, _c: &str) -> Result<Vec<hakobackend_core::IndexInfo>, AppError> {
            Ok(vec![])
        }
        async fn drop_index(&self, _c: &str, _n: &str) -> Result<(), AppError> {
            Err(AppError::BadRequest("fake without index".into()))
        }
    }

    fn local(db: Arc<dyn Database>) -> Arc<LocalAuth> {
        // Process-global env — hold the lock + no await inside (same pattern as other verifiers).
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("UB_LOCAL_JWT_SECRET", "0123456789abcdef0123456789abcdef");
        let cfg = LocalConfig::from_env().unwrap();
        std::env::remove_var("UB_LOCAL_JWT_SECRET");
        Arc::new(LocalAuth {
            cfg,
            db,
            identity: Identity::default(),
            dpop_mode: std::sync::Mutex::new(DpopMode::Off),
            dpop_replay: std::sync::Mutex::new(dpop::ReplayCache::default()),
            forced_tenant: None,
        })
    }

    #[tokio::test]
    async fn register_login_verify() {
        let db: Arc<dyn Database> = Arc::new(FakeDb::new());
        let a = local(db);
        // role from the body is discarded; empty default_role → no roles.
        let mut profile = HashMap::new();
        profile.insert("role".into(), serde_json::Value::String("admin".into()));
        profile.insert("nick".into(), serde_json::Value::String("budi".into()));
        let doc = a.register(Some("budi".into()), Some("b@x.id".into()), "rahasia123", profile).await.unwrap();
        assert!(doc.data.get("role").is_none());
        assert_eq!(doc.data.get("nick").unwrap(), "budi");
        assert!(doc.data.get(PASSWORD_FIELD).unwrap().as_str().unwrap().starts_with("$argon2"));
        // Duplicates rejected; short passwords rejected.
        assert!(a.register(Some("budi".into()), None, "rahasia123", HashMap::new()).await.is_err());
        assert!(a.register(Some("x".into()), None, "pendek", HashMap::new()).await.is_err());

        let (ctx, tokens) = a.login("budi", "rahasia123", None).await.unwrap();
        assert_eq!(ctx.uid, "local:budi");
        // Email login also works; wrong passwords are disguised.
        assert!(a.login("b@x.id", "rahasia123", None).await.is_ok());
        assert!(a.login("budi", "salah", None).await.is_err());
        assert!(a.login("tak-ada", "rahasia123", None).await.is_err());
        // Access JWT verified by its own provider.
        let claims = a.verify(&tokens.access_jwt).await.unwrap();
        assert_eq!(claims.uid, "budi");
    }

    #[tokio::test]
    async fn refresh_rotation_and_reuse_revoked() {
        let db: Arc<dyn Database> = Arc::new(FakeDb::new());
        let a = local(db);
        a.register(Some("siti".into()), None, "rahasia123", HashMap::new()).await.unwrap();
        let (_, t1) = a.login("siti", "rahasia123", None).await.unwrap();

        // Rotation: the new refresh is valid, the old one becomes a trap.
        let (_, t2) = a.refresh(&t1.refresh_opaque, None).await.unwrap();
        assert_ne!(t1.refresh_opaque, t2.refresh_opaque);
        assert!(a.verify(&t2.access_jwt).await.is_ok());

        // Reusing the old token = reuse → all sessions revoked + rejected.
        assert!(a.refresh(&t1.refresh_opaque, None).await.is_err());
        // The rotated token dies too (sessions already revoked).
        assert!(a.refresh(&t2.refresh_opaque, None).await.is_err());
    }

    #[tokio::test]
    async fn logout_revokes_session() {
        let db: Arc<dyn Database> = Arc::new(FakeDb::new());
        let a = local(db);
        a.register(Some("agus".into()), None, "rahasia123", HashMap::new()).await.unwrap();
        let (_, t) = a.login("agus", "rahasia123", None).await.unwrap();
        a.logout(&t.refresh_opaque).await.unwrap();
        assert!(a.refresh(&t.refresh_opaque, None).await.is_err());
    }

    #[tokio::test]
    async fn oauth_provision_without_roles_idempotent() {
        let db: Arc<dyn Database> = Arc::new(FakeDb::new());
        let a = local(db);
        let mut profile = HashMap::new();
        profile.insert("login".into(), serde_json::Value::String("octocat".into()));
        profile.insert("role".into(), serde_json::Value::String("admin".into()));
        let (ctx1, _) = a.login_external("github:7", None, profile).await.unwrap();
        // Roles from the profile are discarded; namespaced uid.
        assert_eq!(ctx1.uid, "github:7");
        assert!(ctx1.roles.is_empty());
        // Second login: the document is reused (not duplicated/overwritten).
        let (ctx2, _) = a.login_external("github:7", None, HashMap::new()).await.unwrap();
        assert_eq!(ctx2.uid, "github:7");
    }

    #[test]
    fn short_secret_rejected() {
        let _g = ENV_LOCK.lock().unwrap();
        std::env::set_var("UB_LOCAL_JWT_SECRET", "pendek");
        assert!(LocalConfig::from_env().is_err());
        std::env::remove_var("UB_LOCAL_JWT_SECRET");
        assert!(LocalConfig::from_env().is_err());
    }

    /// Static test RSA key (same pair as in firebase/oidc).
    const TEST_PRIV_PEM: &str = "-----BEGIN PRIVATE KEY-----\nMIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDrSl/9ysN280jm\naQgcJNcPJSvJHk+dW7BNOj2fPjYBIfbfjTfnXE7i1WeEBgL/5UfhoC2MP9UeqOe7\nDoJ3DRGgMNZVrJ8P/kUGKKCrwMk1P1S0zG3xhWmSfX9u0z/Gli1eGTX9RRN7fX/+\nutyhhbtZZq4kdzg0FXA46Xnk8k9RD6qkiv+WnyR7TmuSDdJIYHeZvSDgU2OieIVj\nSGhZ5WBvjTfNw9yG7KbsOh1CNs1jLQONHNhgnZs+EDaQK1nhF7Y9nYUCu4+TWdOn\npWgt+z16EwBu1jXbwoPvEesg2/5Mrk4Km3b+sHDmOs5feQmj6veOQ3FLfTweSHVX\nyQCj4EoxAgMBAAECggEAff9zDf5B0/YN6Mz/+cpEnCiknOutaK/L5l801ozC8LJW\neHowIKYO3Gu5Jjrt6kjGyG01VvBr2SJMDaCEfuoxsR3V+UUaXL8mCVlCSRdQ6EHE\nw5jhmz99PGQWFKvtcBPFsalAfyM5fpzDKQ65zYlGvWY+BOsO3t1IHkHw84hKrzX0\nfNZS4Ppxug2PylXP9cDsUUcjMmZpTAYeWKcOprMIRMutjnJmf0e+n1ldL+643fHV\nZHuQ0NX9k7Bmm4jcy2eonWStj00Hw5M99u9XdhSjLjO2PDBrwUmbDXeQYJJ9QjfX\naneV3krMJ1+BFXKfN+MsSQMaDEn4QAf6w5oV3j12bQKBgQD+hKdpHluCN9curPw4\n1401n8W8NkrQ6eQmSHYBtW4CcTMHDdtM/xPPFRmELRe3u4l5rVygVfD0PNMW169c\nn/RXqrw6qH7L1qax+WW3f6UZat/KF8soaI55Dn3u6cJdLgdXlCadtREGcX15z2Pm\nRfeWw2iJ64eqOX42zuUXm2Zd2wKBgQDsqRAuWJiybomg37A1Yqrf+xf9Iw1HwJ11\nLfeK0Uztljdzlo5qcqPkphYrlTLchQG8sx+dMQBF+dXEI4rF1haYvVbP78NChoQo\njt2c5w7FCuWncvRSxYpzU5QUyDXWoH5KlnjQhUAS2vPRGhitrI2gRIY4v9DjqFii\nV0gVAHyD4wKBgQCWDcNdeCZfOWjF/fqd0IdSLCY59pBZZuu5nlLkYwC+s9pvuD2o\nwWH+XuQyRxuKmShN8mV/qetrM0kIWJTsuOknnmNm+dv3dU/F8dGEQ98kgxv5W9nM\nswf8WwzoBC0xHmf5vECgDhZBhDuDyz+MjYeQ/Rfu6EuNkmPVEFmEd3v8rQKBgQDH\nxA28kVyTgWr7ONZsudSzLCibrLLRFm3TM/H4Y6QkCODV2QhuIkbmAqxELbS5ICzP\nNARDk9E/QByJa9cAGC8KzwgwjZqs1Q9JjQ7UGtYEzaX9KrPCCq1LnAkrYbTQbrks\nDMf+e/wR7nBQ2U5ri3QhDLafwIp7IOdwYWyfDcINMQKBgB8ZkBiNiMngr59o2Y7/\nTF2sD5CSZmWd0SGhJivzcxlWWUVtZGpXgO0h6cAyTIAQJCNxox5IMNCnbtnVmQzV\nZeS8kwffcMXV7LBYEHgYlJo5gtBzPadXkXtKAQqT9jxZGjAziI7iKjr4U2vIcblm\n8mM8f3Z5FfbC828Q4rYaROLf\n-----END PRIVATE KEY-----\n";
    const TEST_JWK: &str = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"60pf_crDdvNI5mkIHCTXDyUryR5PnVuwTTo9nz42ASH2340351xO4tVnhAYC_-VH4aAtjD_VHqjnuw6Cdw0RoDDWVayfD_5FBiigq8DJNT9UtMxt8YVpkn1_btM_xpYtXhk1_UUTe31__rrcoYW7WWauJHc4NBVwOOl55PJPUQ-qpIr_lp8ke05rkg3SSGB3mb0g4FNjoniFY0hoWeVgb403zcPchuym7DodQjbNYy0DjRzYYJ2bPhA2kCtZ4Re2PZ2FAruPk1nTp6VoLfs9ehMAbtY128KD7xHrINv-TK5OCpt2_rBw5jrOX3kJo-r3jkNxS308Hkh1V8kAo-BKMQ\"}";

    /// Build a manual RS256 DPoP proof (header embeds jwk — beyond the reach of
    /// jsonwebtoken::encode, so sign the RSA directly).
    fn dpop_sign(jwk_json: &str, htm: &str, htu: &str, ath: Option<&str>, jti: &str) -> String {
        use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD as B64};
        use rsa::pkcs1v15::SigningKey;
        use rsa::pkcs8::DecodePrivateKey;
        use rsa::signature::{SignatureEncoding, Signer};
        use sha2::Sha256;
        let now = super::now_secs();
        let header = format!("{{\"typ\":\"dpop+jwt\",\"alg\":\"RS256\",\"jwk\":{jwk_json}}}");
        let payload = serde_json::json!({
            "jti": jti, "htm": htm, "htu": htu, "iat": now,
            "ath": ath,
        })
        .to_string();
        // ath: None → null; proof issuance does not use ath — drop the key.
        let payload = if ath.is_none() {
            let mut v: serde_json::Value = serde_json::from_str(&payload).unwrap();
            v.as_object_mut().unwrap().remove("ath");
            v.to_string()
        } else {
            payload
        };
        let input = format!("{}.{}", B64.encode(header.as_bytes()), B64.encode(payload.as_bytes()));
        let key = rsa::RsaPrivateKey::from_pkcs8_pem(TEST_PRIV_PEM).unwrap();
        let sig = SigningKey::<Sha256>::new(key).sign(input.as_bytes());
        format!("{input}.{}", B64.encode(sig.to_bytes()))
    }

    #[tokio::test]
    async fn dpop_bind_and_enforce() {
        let db: Arc<dyn Database> = Arc::new(FakeDb::new());
        let a = local(db);
        a.set_dpop_mode(DpopMode::Require);
        a.register(Some("dpop".into()), None, "rahasia123", HashMap::new()).await.unwrap();

        // Login includes an issuance proof → bound access (cnf.jkt).
        let issue = dpop_sign(TEST_JWK, "POST", "http://t/api/auth/login", None, "jti-issue-1");
        let (_, t) = a
            .login("dpop", "rahasia123", Some(DpopRequest { proof: &issue, method: "POST", uri: "http://t/api/auth/login" }))
            .await
            .unwrap();
        let jkt = a.bound_jkt(&t.access_jwt).unwrap();
        assert!(jkt.is_some());

        // Valid access: fresh proof + matching ath + matching jkt.
        let p1 = dpop_sign(TEST_JWK, "GET", "http://t/api/collections/posts", Some(&dpop::ath(&t.access_jwt)), "jti-use-1");
        assert!(a.check_dpop(&p1, "GET", "http://t/api/collections/posts", &t.access_jwt, jkt.as_deref()).is_ok());

        // Same-proof replay → rejected. Wrong htm → rejected. Wrong ath → rejected.
        assert!(a.check_dpop(&p1, "GET", "http://t/api/collections/posts", &t.access_jwt, jkt.as_deref()).is_err());
        let p2 = dpop_sign(TEST_JWK, "POST", "http://t/api/collections/posts", Some(&dpop::ath(&t.access_jwt)), "jti-use-2");
        assert!(a.check_dpop(&p2, "GET", "http://t/api/collections/posts", &t.access_jwt, jkt.as_deref()).is_err());
        let p3 = dpop_sign(TEST_JWK, "GET", "http://t/api/collections/posts", Some("salah"), "jti-use-3");
        assert!(a.check_dpop(&p3, "GET", "http://t/api/collections/posts", &t.access_jwt, jkt.as_deref()).is_err());

        // Stolen token used with another key → jkt mismatch → rejected.
        let other_jwk = "{\"e\":\"AQAB\",\"kty\":\"RSA\",\"n\":\"AAAA\"}";
        let p4 = dpop_sign(other_jwk, "GET", "http://t/api/collections/posts", Some(&dpop::ath(&t.access_jwt)), "jti-use-4");
        // Fake n → invalid key → signature verification fails.
        assert!(a.check_dpop(&p4, "GET", "http://t/api/collections/posts", &t.access_jwt, jkt.as_deref()).is_err());

        // Plain token (no cnf) still passes the check when expected is None (accept mode).
        a.set_dpop_mode(DpopMode::Accept);
        let (_, tp) = a.login("dpop", "rahasia123", None).await.unwrap();
        assert!(a.bound_jkt(&tp.access_jwt).unwrap().is_none());
    }
}

//! Per-tenant auth bundles (phase A): shareable profiles + live credentials.
//!
//! - `__auth_profiles/{id}` docs: `{owner_tenant: string|null,
//!   shared: bool, spec: "local"|"chain:a,b"|..., config: {...}}`.
//!   `owner_tenant: null` = org-global (admin-managed); otherwise the owner
//!   tenant manages it, and other tenants may use it only when shared.
//! - `__tenants/{slug}` gains optional `auth_profile: <profile-id>`.
//! - A bundle = chain + local + github built FOR one tenant: local runs
//!   over `TenantDb` (users/sessions auto-namespaced), firebase/oidc/github
//!   take credentials from the profile (literals or `env:NAME` refs —
//!   resolved values never hit logs), DPoP mode per profile.
//! - Cached 5 s (same staleness contract as tenant policies). Credential
//!   rotation = edit the profile doc; sessions already minted stay valid
//!   until expiry (use revoke-all to cut them early).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hakobackend_auth_core::{AuthChain, AuthSpec, ClaimMapping};
use hakobackend_auth_github::GithubOAuth;
use hakobackend_auth_local::{DpopMode, LocalAuth};
use hakobackend_core::{tenant_db::TenantDb, Database};
use hakobackend_policy::Identity;

/// Registry collections (covered by the `__*` HTTP deny like internals).
pub const AUTH_PROFILES_COLLECTION: &str = "__auth_profiles";

/// Bundle refresh cadence.
pub const AUTH_TTL: Duration = Duration::from_secs(5);

pub struct TenantBundle {
    pub chain: Arc<AuthChain>,
    pub local: Option<Arc<LocalAuth>>,
    pub github: Option<Arc<GithubOAuth>>,
}

pub struct TenantAuths {
    db: Arc<tokio::sync::RwLock<Arc<dyn Database>>>,
    identity: Identity,
    cache: std::sync::Mutex<HashMap<String, (Arc<TenantBundle>, Instant)>>,
}

impl TenantAuths {
    pub fn new(db: Arc<tokio::sync::RwLock<Arc<dyn Database>>>, identity: Identity) -> Self {
        Self { db, identity, cache: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Bundle for a tenant, or None when it has no `auth_profile` (caller
    /// falls back to the global chain).
    pub async fn get(&self, tenant: &str) -> Option<Arc<TenantBundle>> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some((b, at)) = cache.get(tenant) {
                if at.elapsed() < AUTH_TTL {
                    return Some(b.clone());
                }
            }
        }
        let bundle = self.build(tenant).await?;
        self.cache.lock().unwrap().insert(tenant.into(), (bundle.clone(), Instant::now()));
        Some(bundle)
    }

    /// Forget one tenant (called after profile/tenant edits for immediacy;
    /// TTL covers the rest).
    pub fn invalidate(&self, tenant: &str) {
        self.cache.lock().unwrap().remove(tenant);
    }

    /// Forget everything (profile edits affect unknown tenant sets).
    pub fn invalidate_all(&self) {
        self.cache.lock().unwrap().clear();
    }

    async fn build(&self, tenant: &str) -> Option<Arc<TenantBundle>> {
        let db = self.db.read().await.clone();
        let tdoc = db.get(hakobackend_core::tenant::TENANTS_COLLECTION, tenant).await.ok()??;
        let profile_id = tdoc.data.get("auth_profile")?.as_str()?;
        let pdoc = db.get(AUTH_PROFILES_COLLECTION, profile_id).await.ok()??;
        // Sharing rule: org-global profiles are always usable; owned ones
        // only when shared (or by the owner itself).
        let owner = pdoc.data.get("owner_tenant").and_then(|v| v.as_str());
        let shared = pdoc.data.get("shared").and_then(|v| v.as_bool()).unwrap_or(false);
        if owner != Some(tenant) && !(owner.is_none() || shared) {
            eprintln!("[tenant-auth] {tenant}: profile {profile_id} not shared; ignoring");
            return None;
        }
        let spec_str = pdoc.data.get("spec").and_then(|v| v.as_str()).unwrap_or("off");
        let cfg = pdoc.data.get("config").and_then(|v| v.as_object()).cloned().unwrap_or_default();
        let spec = AuthSpec::parse(spec_str);
        let names: Vec<String> = match &spec {
            AuthSpec::Off => return None,
            AuthSpec::Named(n) => n.clone(),
            AuthSpec::File(_) => {
                eprintln!("[tenant-auth] {tenant}: file specs stay global-only; ignoring");
                return None;
            }
        };
        let tdb: Arc<dyn Database> = Arc::new(TenantDb::new(db.clone(), tenant));
        let mut providers: Vec<Arc<dyn hakobackend_core::AuthProvider>> = Vec::new();
        let mut local = None;
        let mut github = None;
        for n in &names {
            match n.as_str() {
                "local" => {
                    let l = LocalAuth::build(tdb.clone(), self.identity.clone()).ok()?;
                    if let Some(d) = cfg.get("dpop").and_then(|v| v.as_str()) {
                        l.set_dpop_mode(DpopMode::parse(d).ok()?);
                    }
                    let l = l.with_tenant(tenant);
                    providers.push(l.clone() as Arc<dyn hakobackend_core::AuthProvider>);
                    local = Some(l);
                }
                "firebase" => providers.push(hakobackend_auth_firebase::FirebaseVerifier::with_url(
                    resolve_param(cfg.get("firebase_project"))?,
                    cfg.get("firebase_jwks_url")
                        .and_then(|v| v.as_str())
                        .map(str::to_string)
                        .unwrap_or_else(|| "https://www.googleapis.com/oauth2/v3/certs".into()),
                )),
                "oidc" => providers.push(hakobackend_auth_oidc::OidcVerifier::with_config(
                    resolve_param(cfg.get("oidc_issuer"))?,
                    resolve_param(cfg.get("oidc_audience")),
                    cfg.get("oidc_jwks_url").and_then(|v| v.as_str()).map(str::to_string),
                )),
                "github" => {
                    providers.push(hakobackend_auth_github::GithubVerifier::from_env());
                }
                other => {
                    eprintln!("[tenant-auth] {tenant}: unknown provider `{other}`; ignoring bundle");
                    return None;
                }
            }
        }
        if providers.is_empty() {
            return None;
        }
        // Full OAuth object for the login/callback handlers (per-tenant creds).
        if names.iter().any(|n| n == "github") {
            github = Some(GithubOAuth::new(
                resolve_param(cfg.get("github_client_id"))?,
                resolve_param(cfg.get("github_client_secret"))?,
                resolve_param(cfg.get("github_public_url"))
                    .unwrap_or_else(|| "http://localhost:8080".into()),
                cfg.get("github_api")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "https://api.github.com".into()),
                cfg.get("github_token_url")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "https://github.com/login/oauth/access_token".into()),
                cfg.get("github_authorize_url")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "https://github.com/login/oauth/authorize".into()),
                cfg.get("github_after_login")
                    .and_then(|v| v.as_str())
                    .map(str::to_string)
                    .unwrap_or_else(|| "/".into()),
                tdb.clone(),
            ));
        }
        Some(Arc::new(TenantBundle {
            chain: Arc::new(AuthChain { providers, mapping: ClaimMapping::default(), rules: vec![] }),
            local,
            github,
        }))
    }
}

/// Literal or `env:NAME` reference (resolved values never logged).
fn resolve_param(v: Option<&serde_json::Value>) -> Option<String> {
    let s = v?.as_str()?;
    if let Some(name) = s.strip_prefix("env:") {
        std::env::var(name).ok().filter(|v| !v.is_empty())
    } else if s.is_empty() {
        None
    } else {
        Some(s.into())
    }
}

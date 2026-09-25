//! hakobackend-auth-core: `--auth` resolution + verifier chain + declarative mapping.
//!
//! Core binds no provider except the contract (`hakobackend_core::AuthProvider`).
//! External providers are verifier-only; only `local` acts as issuer (phase C).
//! User roles & collections belong to the user via `hakobackend_policy::Identity`; final roles =
//! **union** of claim roles + user-doc roles.

use serde::Deserialize;
use std::collections::HashMap;
use std::sync::Arc;
use hakobackend_core::{AuthContext, AuthProvider, Claims, Database};
use hakobackend_policy::Identity;

// --- `--auth` spec ---

/// Parse result of an `--auth` value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AuthSpec {
    /// No auth (today's dev behavior).
    Off,
    /// One provider / chain (`local`, `chain:github,local`).
    Named(Vec<String>),
    /// Declarative mapping file (`./custom.toml`).
    File(String),
}

impl AuthSpec {
    pub fn parse(value: &str) -> Self {
        let v = value.trim();
        if v.is_empty() || v == "off" || v == "none" {
            AuthSpec::Off
        } else if let Some(rest) = v.strip_prefix("chain:") {
            AuthSpec::Named(rest.split(',').map(|s| s.trim().to_string()).filter(|s| !s.is_empty()).collect())
        } else if v.ends_with(".toml") {
            AuthSpec::File(v.to_string())
        } else {
            AuthSpec::Named(vec![v.to_string()])
        }
    }
}

// --- Declarative mapping file (`--auth ./custom.toml`) ---

/// One claim → user-owned free-form role rule.
#[derive(Debug, Clone, Deserialize)]
pub struct RoleRule {
    pub claim: String,
    pub equals: String,
    pub role: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct ClaimMapping {
    /// Claim in `extra` used as uid/email (default: provider default).
    pub uid_field: Option<String>,
    pub email_field: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct CustomAuth {
    /// Chained providers (available builtins).
    #[serde(default)]
    pub providers: Vec<String>,
    #[serde(default)]
    pub mapping: ClaimMapping,
    #[serde(default)]
    pub rules: Vec<RoleRule>,
    /// DPoP mode for the `local` chain member (off|accept|require).
    /// Typo = load error (fail-closed). Without it: env UB_LOCAL_DPOP.
    pub dpop: Option<String>,
}

impl CustomAuth {
    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }

    /// Roles from claims: match when a string claim == equals or an array contains it.
    pub fn roles_from_claims(&self, claims: &Claims) -> Vec<String> {
        self.rules
            .iter()
            .filter(|r| match claims.extra.get(&r.claim) {
                Some(serde_json::Value::String(s)) => s == &r.equals,
                Some(serde_json::Value::Array(a)) => a.iter().any(|v| v.as_str() == Some(&r.equals)),
                _ => false,
            })
            .map(|r| r.role.clone())
            .collect()
    }
}

// --- Resolver: verify → mapping → user-doc role union ---

/// Opened verifier chain (order = priority).
pub struct AuthChain {
    pub providers: Vec<Arc<dyn AuthProvider>>,
    pub mapping: ClaimMapping,
    pub rules: Vec<RoleRule>,
}

impl AuthChain {
    /// First valid claim wins; all fail → None (anonymous).
    /// When `db` is present, user-doc roles (`identity`) are unioned (deduped).
    /// User-doc lookup key = namespaced uid (`github:123`).
    pub async fn resolve(
        &self,
        identity: &Identity,
        db: Option<&dyn Database>,
        token: &str,
    ) -> Option<AuthContext> {
        for p in &self.providers {
            if let Ok(claims) = p.verify(token).await {
                return Some(self.to_context(identity, db, &claims).await);
            }
        }
        None
    }

    async fn to_context(&self, identity: &Identity, db: Option<&dyn Database>, claims: &Claims) -> AuthContext {
        let custom = CustomAuth {
            providers: vec![],
            mapping: self.mapping.clone(),
            rules: self.rules.clone(),
            dpop: None,
        };
        let mut roles = custom.roles_from_claims(claims);
        let uid = field(&claims.extra, self.mapping.uid_field.as_deref())
            .map(|v| format!("{}:{v}", claims.provider))
            .unwrap_or_else(|| claims.namespaced());
        if let Some(db) = db {
            let mut hit = db.get(&identity.users_collection, &uid).await.ok().flatten();
            if hit.is_none() && claims.provider == "local" {
                // Local registers store RAW ids (`root`, not `local:root`) while
                // oauth provision stores namespaced docs. Fall back to the raw
                // claim id — scoped to provider `local` only, so a github uid
                // can never inherit roles from an unrelated local doc.
                hit = db.get(&identity.users_collection, &claims.uid).await.ok().flatten();
            }
            if let Some(doc) = hit {
                roles.extend(identity.roles_of(&doc));
            }
        }
        roles.sort();
        roles.dedup();
        let email = field(&claims.extra, self.mapping.email_field.as_deref()).or_else(|| claims.email.clone());
        let mut extra = HashMap::new();
        // Provider marker for DPoP enforcement in middleware (not for rules).
        extra.insert("provider".to_string(), serde_json::Value::String(claims.provider.into()));
        if let Some(e) = email {
            extra.insert("email".to_string(), serde_json::Value::String(e));
        }
        AuthContext { uid, roles, tenant: claims.tenant.clone(), extra }
    }
}

fn field(extra: &HashMap<String, serde_json::Value>, name: Option<&str>) -> Option<String> {
    name.and_then(|n| extra.get(n)).and_then(|v| v.as_str()).map(|s| s.to_string())
}

/// Open a builtin provider. One arm per provider (mirrors `open_driver`).
/// `local` follows in phase C; unknown names are rejected with a clear message (fail-closed).
pub fn open_builtin(name: &str) -> Result<Arc<dyn AuthProvider>, String> {
    match name {
        "firebase" => hakobackend_auth_firebase::FirebaseVerifier::from_env(),
        "github" => Ok(hakobackend_auth_github::GithubVerifier::from_env()),
        "oidc" => hakobackend_auth_oidc::OidcVerifier::from_env(),
        "local" => Err("provider `local` not available (phase C: BFF session manager)".into()),
        other => Err(format!("provider `{other}` unknown (see AUTH_CONTRACT.md §6)")),
    }
}

/// Build a chain from `AuthSpec`. `local` cannot be opened without a db handle,
/// so the server injects it (built from the active driver + `[identity]`);
/// other callers (test/CLI validate) pass `None` → the `local` name is clearly rejected.
pub fn open_chain(
    spec: &AuthSpec,
    custom: Option<&CustomAuth>,
    local: Option<Arc<dyn AuthProvider>>,
) -> Result<AuthChain, String> {
    let (names, mapping, rules) = match spec {
        AuthSpec::Off => return Ok(AuthChain {
            providers: vec![],
            mapping: ClaimMapping::default(),
            rules: vec![],
        }),
        AuthSpec::Named(names) => (names.clone(), ClaimMapping::default(), vec![]),
        AuthSpec::File(_) => {
            let c = custom.ok_or("File spec requires loaded CustomAuth")?;
            (c.providers.clone(), c.mapping.clone(), c.rules.clone())
        }
    };
    if names.iter().any(|n| n == "off" || n == "none") || names.is_empty() {
        return Err("empty chain — use explicit `off` for no auth".into());
    }
    let mut providers = Vec::with_capacity(names.len());
    for n in &names {
        if n == "local" {
            providers.push(local.clone().ok_or(
                "provider `local` requires db handle — only the server can open it".to_string(),
            )?);
        } else {
            providers.push(open_builtin(n)?);
        }
    }
    Ok(AuthChain { providers, mapping, rules })
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;
    use hakobackend_core::{AppError, Doc, QueryOptions};

    struct Fake {
        name: &'static str,
        expect: &'static str,
        uid: &'static str,
        groups: Vec<String>,
        fail: bool,
    }

    #[async_trait::async_trait]
    impl AuthProvider for Fake {
        fn name(&self) -> &'static str {
            self.name
        }
        async fn verify(&self, token: &str) -> Result<Claims, AppError> {
            if self.fail || token != self.expect {
                return Err(AppError::PermissionDenied);
            }
            Ok(Claims {
                provider: self.name,
                uid: self.uid.into(),
                email: None,
                extra: [("groups".to_string(), json!(self.groups))].into_iter().collect(),
                tenant: None,
            })
        }
    }

    fn chain() -> AuthChain {
        AuthChain {
            providers: vec![
                Arc::new(Fake { name: "github", expect: "gh-tok", uid: "123", groups: vec!["ops".into()], fail: false }),
                Arc::new(Fake { name: "local", expect: "loc-tok", uid: "abc", groups: vec![], fail: false }),
            ],
            mapping: ClaimMapping::default(),
            rules: vec![RoleRule { claim: "groups".into(), equals: "ops".into(), role: "pengurus".into() }],
        }
    }

    fn identity() -> Identity {
        Identity::default()
    }

    #[tokio::test]
    async fn chain_fallback_and_namespace() {
        let c = chain();
        // First provider with a matching token wins.
        let a = c.resolve(&identity(), None, "loc-tok").await.unwrap();
        assert_eq!(a.uid, "local:abc");
        let b = c.resolve(&identity(), None, "gh-tok").await.unwrap();
        assert_eq!(b.uid, "github:123");
        assert_eq!(b.roles, vec!["pengurus"]);
        // Token unknown to all → anonymous.
        assert!(c.resolve(&identity(), None, "bukan-token").await.is_none());
    }

    #[tokio::test]
    async fn union_peran_user_doc() {
        // Minimal fake DB: only get() is used for enrichment.
        struct FakeDb {
            doc: hakobackend_core::Doc,
        }
        #[async_trait::async_trait]
        impl Database for FakeDb {
            fn capabilities(&self) -> hakobackend_core::Capabilities {
                hakobackend_core::Capabilities { driver: "fake", supports_watch: false, supports_transactions: false, supports_composite: false, supports_fts: false, supports_drop_index: false, supports_unique: false, supports_named_index: false, supports_native_aggregation: false }
            }
            async fn ensure_collection(&self, _p: &str) -> Result<(), AppError> {
                Ok(())
            }
            async fn list_collections(&self) -> Result<Vec<String>, AppError> {
                Ok(vec![])
            }
            async fn get(&self, _c: &str, id: &str) -> Result<Option<Doc>, AppError> {
                Ok((id == self.doc.id).then(|| self.doc.clone()))
            }
            async fn list(&self, _c: &str, _q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
                Ok(vec![])
            }
            async fn insert(&self, _c: &str, doc: Doc) -> Result<Doc, AppError> {
                Ok(doc)
            }
            async fn set(&self, _c: &str, id: &str, doc: Doc, _m: bool) -> Result<Doc, AppError> {
                Ok(Doc { id: id.into(), data: doc.data })
            }
            async fn delete(&self, _c: &str, _id: &str) -> Result<Option<Doc>, AppError> {
                Ok(None)
            }
            async fn count(&self, _c: &str, _q: &QueryOptions) -> Result<u64, AppError> {
                Ok(0)
            }
            async fn subscribe(&self, _c: &str) -> Result<tokio::sync::broadcast::Receiver<hakobackend_core::Change>, AppError> {
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
        let db = FakeDb {
            doc: Doc {
                // Lookup key = namespaced uid.
                id: "github:123".into(),
                data: [("role".to_string(), json!(["penulis"]))].into_iter().collect(),
            },
        };
        let c = chain();
        let ctx = c.resolve(&identity(), Some(&db), "gh-tok").await.unwrap();
        // Union + dedup: pengurus (claims) + penulis (document).
        assert_eq!(ctx.roles, vec!["pengurus", "penulis"]);
    }

    #[test]
    fn spec_parse() {
        assert_eq!(AuthSpec::parse("off"), AuthSpec::Off);
        assert_eq!(AuthSpec::parse(""), AuthSpec::Off);
        assert_eq!(AuthSpec::parse("local"), AuthSpec::Named(vec!["local".into()]));
        assert_eq!(
            AuthSpec::parse("chain:github,local"),
            AuthSpec::Named(vec!["github".into(), "local".into()])
        );
        assert_eq!(AuthSpec::parse("./custom.toml"), AuthSpec::File("./custom.toml".into()));
    }

    #[test]
    fn builtin_registry() {
        // github without a secret → always openable; firebase/oidc need env.
        assert_eq!(open_builtin("github").unwrap().name(), "github");
        assert!(open_builtin("local").is_err());
        assert!(open_builtin("entah").is_err());
        assert!(open_chain(&AuthSpec::Off, None, None).unwrap().providers.is_empty());
        assert!(open_chain(&AuthSpec::Named(vec!["github".into()]), None, None).unwrap().providers.len() == 1);
        // local without injection is clearly rejected (not bypassed).
        assert!(open_chain(&AuthSpec::Named(vec!["local".into()]), None, None).is_err());
    }

    #[test]
    fn custom_toml_mapping() {
        let c: CustomAuth = toml::from_str(
            r#"
            providers = ["github", "local"]
            [mapping]
            uid_field = "sub"
            [[rules]]
            claim = "groups"
            equals = "ops"
            role = "pengurus"
            "#,
        )
        .unwrap();
        assert_eq!(c.providers, vec!["github", "local"]);
        assert_eq!(c.mapping.uid_field.as_deref(), Some("sub"));
        let claims = Claims {
            provider: "github",
            uid: "x".into(),
            email: None,
            extra: [("groups".to_string(), json!(["dev", "ops"]))].into_iter().collect(),
            tenant: None,
        };
        assert_eq!(c.roles_from_claims(&claims), vec!["pengurus"]);
    }
}

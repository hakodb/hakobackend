//! hakobackend-auth-core: `--auth` resolution + verifier chain + declarative mapping.
//!
//! Core binds no provider except the contract (`hakobackend_core::AuthProvider`).
//! External providers are verifier-only; only `local` acts as issuer (phase C).
//! Identity mapping (uid/email fields) belongs to the user via
//! `hakobackend_policy::Identity`; contexts carry uid + provider marker only
//! (roles were removed with the tenant system).

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
    /// DPoP mode for the `local` chain member (off|accept|require).
    /// Typo = load error (fail-closed). Without it: env UB_LOCAL_DPOP.
    pub dpop: Option<String>,
}

impl CustomAuth {
    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }
}

// --- Resolver: verify → mapping (uid/email + provider marker) ---

/// Opened verifier chain (order = priority).
pub struct AuthChain {
    pub providers: Vec<Arc<dyn AuthProvider>>,
    pub mapping: ClaimMapping,
}

impl AuthChain {
    /// First valid claim wins; all fail → None (anonymous).
    /// User-doc lookup key = namespaced uid (`github:123`).
    pub async fn resolve(
        &self,
        identity: &Identity,
        db: Option<&dyn Database>,
        token: &str,
    ) -> Option<AuthContext> {
        let _ = (identity, db);
        for p in &self.providers {
            if let Ok(claims) = p.verify(token).await {
                return Some(self.to_context(&claims).await);
            }
        }
        None
    }

    async fn to_context(&self, claims: &Claims) -> AuthContext {
        let uid = field(&claims.extra, self.mapping.uid_field.as_deref())
            .map(|v| format!("{}:{v}", claims.provider))
            .unwrap_or_else(|| claims.namespaced());
        let email = field(&claims.extra, self.mapping.email_field.as_deref()).or_else(|| claims.email.clone());
        let mut extra = HashMap::new();
        // Provider marker for DPoP enforcement in middleware (not for rules).
        extra.insert("provider".to_string(), serde_json::Value::String(claims.provider.into()));
        if let Some(e) = email {
            extra.insert("email".to_string(), serde_json::Value::String(e));
        }
        AuthContext { uid, extra }
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
    let (names, mapping) = match spec {
        AuthSpec::Off => return Ok(AuthChain {
            providers: vec![],
            mapping: ClaimMapping::default(),
        }),
        AuthSpec::Named(names) => (names.clone(), ClaimMapping::default()),
        AuthSpec::File(_) => {
            let c = custom.ok_or("File spec requires loaded CustomAuth")?;
            (c.providers.clone(), c.mapping.clone())
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
    Ok(AuthChain { providers, mapping })
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
        // Token unknown to all → anonymous.
        assert!(c.resolve(&identity(), None, "bukan-token").await.is_none());
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
            "#,
        )
        .unwrap();
        assert_eq!(c.providers, vec!["github", "local"]);
        assert_eq!(c.mapping.uid_field.as_deref(), Some("sub"));
    }
}

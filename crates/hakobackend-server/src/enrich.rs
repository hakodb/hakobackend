//! Server-side claim enrichment (issue #68, option B): after the verifier
//! chain resolves a token, copy the allowlisted `[identity].attrs` fields
//! from the caller's user doc (`[identity].users_collection`, keyed by the
//! namespaced uid) into the `AuthContext`.
//!
//! Precedence: doc wins per allowlisted field (server-minted, same
//! discipline as the local issuer); token claims outside the allowlist pass
//! through untouched; no doc / no field = no change (no auto-provisioning).
//! The IDP custom-claim path (Firebase Admin SDK etc.) keeps working as is —
//! both sources coexist, docs win when they carry the field.
//!
//! Lives here, not inside `AuthChain::resolve`: the middleware token cache
//! holds a resolved context until the token's own `exp`, so enrichment there
//! would freeze db values for the token's whole life. A short TTL cache
//! bounds this at one user-doc read per minute per user.
//!
//! `local` tokens are skipped: the issuer already minted allowlisted attrs
//! at login/refresh, and local user docs are keyed by the raw login name,
//! not the namespaced uid.

use std::collections::HashMap;
use std::time::{Duration, Instant};

use hakobackend_core::{AuthContext, Database};
use hakobackend_policy::Identity;

type Fields = HashMap<String, serde_json::Value>;
type Snapshot = std::sync::Mutex<HashMap<String, (Fields, Instant)>>;

/// How long one user-doc snapshot feeds contexts (dynamic role/status take
/// effect within this window, no token re-issue needed).
const TTL: Duration = Duration::from_secs(60);
/// Hard cap: at cap, expired entries are swept; beyond that enrichment goes
/// uncached (a db read per request, still correct, never blocks).
const CAP: usize = 100_000;

#[derive(Default)]
pub struct EnrichCache {
    map: Snapshot,
}

impl EnrichCache {
    pub fn new() -> Self {
        Self::default()
    }
    /// Reload invalidates: the policy (allowlist) may have changed.
    pub fn clear(&self) {
        self.map.lock().unwrap().clear();
    }
}

/// Best-effort enrichment: verify already succeeded, so a db hiccup must
/// never fail the request — the context just keeps its token claims.
pub async fn apply(db: &dyn Database, identity: &Identity, ctx: &mut AuthContext, cache: &EnrichCache) {
    if identity.attrs.is_empty() || ctx.extra.get("provider").and_then(|v| v.as_str()) == Some("local") {
        return;
    }
    let now = Instant::now();
    let fresh = {
        let m = cache.map.lock().unwrap();
        m.get(&ctx.uid).is_some_and(|(_, at)| now.duration_since(*at) < TTL)
    };
    if !fresh {
        let fields = fetch(db, identity, &ctx.uid).await;
        let mut m = cache.map.lock().unwrap();
        if m.len() >= CAP {
            m.retain(|_, (_, at)| now.duration_since(*at) < TTL);
        }
        if m.len() < CAP {
            m.insert(ctx.uid.clone(), (fields, now));
        }
    }
    let fields = cache.map.lock().unwrap().get(&ctx.uid).map(|(f, _)| f.clone()).unwrap_or_default();
    // Doc wins per allowlisted field; absent = keep the token claim.
    ctx.extra.extend(fields);
}

async fn fetch(db: &dyn Database, identity: &Identity, uid: &str) -> Fields {
    let mut out = Fields::new();
    if let Ok(Some(doc)) = db.get(&identity.users_collection, uid).await {
        for f in &identity.attrs {
            if let Some(v) = doc.data.get(f) {
                out.insert(f.clone(), v.clone());
            }
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use hakobackend_core::{AppError, Doc, QueryOptions};

    /// One-doc in-memory db (positive + negative path).
    struct OneDoc(Option<Doc>);

    #[async_trait::async_trait]
    impl Database for OneDoc {
        fn capabilities(&self) -> hakobackend_core::Capabilities {
            hakobackend_core::Capabilities {
                driver: "test",
                supports_watch: false,
                supports_transactions: false,
                supports_composite: false,
                supports_fts: false,
                supports_drop_index: false,
                supports_unique: false,
                supports_named_index: false,
                supports_native_aggregation: false,
                supports_vector: false,
                supports_soft_delete: false,
            }
        }
        async fn ensure_collection(&self, _p: &str) -> Result<(), AppError> {
            Ok(())
        }
        async fn list_collections(&self) -> Result<Vec<String>, AppError> {
            Ok(vec![])
        }
        async fn get(&self, _c: &str, _i: &str) -> Result<Option<Doc>, AppError> {
            Ok(self.0.clone())
        }
        async fn list(&self, _c: &str, _q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
            Ok(self.0.iter().cloned().collect())
        }
        async fn insert(&self, _c: &str, doc: Doc) -> Result<Doc, AppError> {
            Ok(doc)
        }
        async fn set(&self, _c: &str, _i: &str, doc: Doc, _m: bool) -> Result<Doc, AppError> {
            Ok(doc)
        }
        async fn delete(&self, _c: &str, _i: &str) -> Result<Option<Doc>, AppError> {
            Ok(None)
        }
        async fn count(&self, _c: &str, _q: &QueryOptions) -> Result<u64, AppError> {
            Ok(0)
        }
        async fn subscribe(
            &self,
            _c: &str,
        ) -> Result<tokio::sync::broadcast::Receiver<hakobackend_core::Change>, AppError> {
            Ok(tokio::sync::broadcast::channel(1).0.subscribe())
        }
        async fn create_index(&self, _c: &str, _s: &hakobackend_core::IndexSpec) -> Result<hakobackend_core::IndexInfo, AppError> {
            Err(AppError::BadRequest("test db".into()))
        }
        async fn list_indexes(&self, _c: &str) -> Result<Vec<hakobackend_core::IndexInfo>, AppError> {
            Ok(vec![])
        }
        async fn drop_index(&self, _c: &str, _n: &str) -> Result<(), AppError> {
            Err(AppError::BadRequest("test db".into()))
        }
    }

    fn identity(attrs: &[&str]) -> Identity {
        Identity { users_collection: "users".into(), attrs: attrs.iter().map(|s| s.to_string()).collect() }
    }

    fn ctx(provider: &str, uid: &str, claims: &[(&str, &str)]) -> AuthContext {
        AuthContext {
            uid: uid.into(),
            extra: claims
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                .chain([("provider".into(), serde_json::Value::String(provider.into()))])
                .collect(),
        }
    }

    fn doc(id: &str, fields: &[(&str, &str)]) -> Doc {
        Doc {
            id: id.into(),
            data: fields
                .iter()
                .map(|(k, v)| (k.to_string(), serde_json::Value::String(v.to_string())))
                .collect(),
        }
    }

    static ENV: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    #[tokio::test]
    async fn doc_wins_per_allowlisted_field() {
        let _g = ENV.lock().await;
        let db = OneDoc(Some(doc(
            "firebase:42",
            &[("role", "admin"), ("status", "active"), ("email", "a@b.c")],
        )));
        let id = identity(&["role", "status"]);
        let mut c = ctx("firebase", "firebase:42", &[("role", "viewer"), ("scope", "x")]);
        apply(&db, &id, &mut c, &EnrichCache::new()).await;
        assert_eq!(c.extra.get("role").unwrap(), "admin"); // doc wins
        assert_eq!(c.extra.get("status").unwrap(), "active"); // doc-only field rides
        assert_eq!(c.extra.get("scope").unwrap(), "x"); // non-allowlisted token claim passes
        assert!(!c.extra.contains_key("email")); // doc field outside the allowlist never rides
    }

    #[tokio::test]
    async fn no_doc_or_missing_field_keeps_token_claims() {
        let _g = ENV.lock().await;
        let id = identity(&["role"]);
        let mut c = ctx("oidc", "oidc:7", &[("role", "guest")]);
        apply(&OneDoc(None), &id, &mut c, &EnrichCache::new()).await;
        assert_eq!(c.extra.get("role").unwrap(), "guest"); // absent doc = token claim stands

        let mut c2 = ctx("oidc", "oidc:7", &[("role", "guest")]);
        apply(&OneDoc(Some(doc("oidc:7", &[("nick", "n")]))), &id, &mut c2, &EnrichCache::new()).await;
        assert_eq!(c2.extra.get("role").unwrap(), "guest"); // doc lacks the field = token claim stands
    }

    #[tokio::test]
    async fn local_tokens_and_empty_allowlist_skip() {
        let _g = ENV.lock().await;
        let db = OneDoc(Some(doc("alice", &[("role", "admin")])));
        let id = identity(&["role"]);
        // local: issuer already minted attrs; enrichment would need a different lookup key.
        let mut c = ctx("local", "local:alice", &[("role", "staf")]);
        apply(&db, &id, &mut c, &EnrichCache::new()).await;
        assert_eq!(c.extra.get("role").unwrap(), "staf");
        // empty allowlist: zero reads, nothing changes.
        let mut c2 = ctx("firebase", "firebase:42", &[("role", "x")]);
        apply(&db, &Identity::default(), &mut c2, &EnrichCache::new()).await;
        assert_eq!(c2.extra.get("role").unwrap(), "x");
    }

    #[tokio::test]
    async fn cache_serves_within_ttl_and_clear_frees() {
        let _g = ENV.lock().await;
        let cache = EnrichCache::new();
        let id = identity(&["role"]);
        let mut c = ctx("firebase", "firebase:42", &[]);
        apply(&OneDoc(Some(doc("firebase:42", &[("role", "admin")]))), &id, &mut c, &cache).await;
        assert_eq!(c.extra.get("role").unwrap(), "admin");
        // Flip the doc: within TTL the cached snapshot still wins...
        let mut c2 = ctx("firebase", "firebase:42", &[]);
        apply(&OneDoc(Some(doc("firebase:42", &[("role", "demoted")]))), &id, &mut c2, &cache).await;
        assert_eq!(c2.extra.get("role").unwrap(), "admin");
        // ...and clear (reload) drops it.
        cache.clear();
        let mut c3 = ctx("firebase", "firebase:42", &[]);
        apply(&OneDoc(Some(doc("firebase:42", &[("role", "demoted")]))), &id, &mut c3, &cache).await;
        assert_eq!(c3.extra.get("role").unwrap(), "demoted");
    }
}

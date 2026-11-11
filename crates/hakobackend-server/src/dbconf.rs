//! `__backend` reserved collection: config sections stored as docs
//! (issue #68, study 2) — policy, path aliases and service keys live in the
//! database instead of (or on top of) the config file.
//!
//! Doc shapes (one doc per section, default database only):
//! ```json
//! { "id": "policy",  "toml": "<policy.toml content>" }
//! { "id": "aliases", "decl": [ { "pattern": "/x/:id", "target_path": "/api/collections/x", "target_query": "" } ] }
//! { "id": "service", "keys": ["<hex>"], "allow": ["coll:read"] }
//! ```
//!
//! Precedence: a DB section that is present AND valid wins over the file
//! for that section; the file stays the bootstrap source (server listen,
//! driver/path and the auth chain must remain file/env — the DB cannot
//! hold its own connection info). Secrets stay env-only. `admin_uids`
//! stays file-only: a DB policy would make the policy self-amending.
//! Fail-closed: a malformed section is skipped with a loud WARN (boot
//! falls back to the file, reload fails with 400 and the old config is
//! fully retained — the discipline of every other config source here).
//!
//! Reloading: `/api/admin/reload` re-reads the docs (boot does too). The
//! policy file's per-request mtime watch keeps working for file mode;
//! once a DB policy is adopted, the file watch is disabled and the DB
//! section owns the policy until the next reload says otherwise.

use hakobackend_core::{Database, Doc};
use serde_json::Value;

pub const COLL: &str = "__backend";

#[derive(Debug, Default, Clone)]
pub struct DbConfig {
    /// Raw `[policy]` TOML from the `policy` doc (validated by the caller
    /// through `PolicyFile::load_str`).
    pub policy_toml: Option<String>,
    /// Alias declarations from the `aliases` doc.
    pub aliases: Vec<crate::config::AliasDecl>,
    /// Service keys + scope allow from the `service` doc.
    pub service_keys: Vec<String>,
    pub service_allow: Vec<String>,
}

impl DbConfig {
}

/// Read the three section docs. Absent docs / read errors = section absent
/// (a fresh DB boots clean); a present-but-malformed doc = WARN + skipped
/// (fail-closed: the file value stays in charge).
pub async fn load(db: &dyn Database) -> DbConfig {
    let mut out = DbConfig::default();
    if let Some(doc) = get(db, "policy").await {
        match doc.data.get("toml").and_then(Value::as_str) {
            Some(t) if !t.trim().is_empty() => out.policy_toml = Some(t.to_string()),
            _ => eprintln!("[ub] WARN: __backend/policy doc has no `toml` string; using file policy"),
        }
    }
    if let Some(doc) = get(db, "aliases").await {
        match doc.data.get("decl").cloned() {
            Some(v) => match serde_json::from_value::<Vec<crate::config::AliasDecl>>(v) {
                Ok(a) => out.aliases = a,
                Err(e) => eprintln!("[ub] WARN: __backend/aliases doc malformed ({e}); using file aliases"),
            },
            None => eprintln!("[ub] WARN: __backend/aliases doc has no `decl` array; using file aliases"),
        }
    }
    if let Some(doc) = get(db, "service").await {
        for (field, target) in [("keys", &mut out.service_keys), ("allow", &mut out.service_allow)] {
            match doc.data.get(field) {
                // Absent field = section not touched, keep the file value (no WARN).
                None => {}
                Some(v) => match serde_json::from_value::<Vec<String>>(v.clone()) {
                    Ok(a) => *target = a,
                    Err(e) => eprintln!("[ub] WARN: __backend/service `{field}` malformed ({e}); using file value"),
                },
            }
        }
    }
    out
}

async fn get(db: &dyn Database, id: &str) -> Option<Doc> {
    // Missing collection / driver hiccup = section absent, no WARN: a
    // fresh database would otherwise nag at every boot.
    db.get(COLL, id).await.ok().flatten()
}

/// Compile DB alias declarations into the router table. Duplicate patterns
/// or bad targets = Err (reload 400 / boot fallback to file aliases).
pub fn compile_aliases(decls: &[crate::config::AliasDecl]) -> Result<Vec<crate::alias::Alias>, String> {
    crate::alias::compile_all(
        &decls
            .iter()
            .map(|a| (a.pattern.clone(), a.target_path.clone(), a.target_query.clone()))
            .collect::<Vec<_>>(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use hakobackend_core::{AppError, QueryOptions};
    use std::collections::HashMap;

    /// In-memory db over a fixed doc map (the __backend sections).
    struct MapDb(HashMap<String, Doc>);

    #[async_trait::async_trait]
    impl Database for MapDb {
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
        async fn get(&self, _c: &str, id: &str) -> Result<Option<Doc>, AppError> {
            Ok(self.0.get(id).cloned())
        }
        async fn list(&self, _c: &str, _q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
            Ok(self.0.values().cloned().collect())
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

    fn doc(id: &str, data: serde_json::Value) -> Doc {
        Doc { id: id.into(), data: serde_json::from_value(data).unwrap() }
    }

    #[tokio::test]
    async fn loads_all_sections() {
        let mut m = HashMap::new();
        m.insert(
            "policy".into(),
            doc("policy", serde_json::json!({ "toml": "[defaults]\nread = \"public\"\n" })),
        );
        m.insert(
            "aliases".into(),
            doc("aliases", serde_json::json!({ "decl": [ { "pattern": "/api/alias/x/:id", "target_path": "/api/collections/x", "target_query": "" } ] })),
        );
        m.insert(
            "service".into(),
            doc("service", serde_json::json!({ "keys": ["ab"], "allow": ["posts:read"] })),
        );
        let dbc = load(&MapDb(m)).await;
        assert_eq!(dbc.policy_toml.as_deref(), Some("[defaults]\nread = \"public\"\n"));
        assert_eq!(dbc.aliases.len(), 1);
        assert_eq!(dbc.aliases[0].pattern, "/api/alias/x/:id");
        assert_eq!(dbc.service_keys, vec!["ab".to_string()]);
        assert_eq!(dbc.service_allow, vec!["posts:read".to_string()]);

    }

    #[tokio::test]
    async fn absent_db_is_all_sections_absent() {
        let dbc = load(&MapDb(HashMap::new())).await;
        assert!(dbc.policy_toml.is_none() && dbc.aliases.is_empty() && dbc.service_keys.is_empty());

    }

    #[tokio::test]
    async fn malformed_sections_are_skipped_not_fatal() {
        let mut m = HashMap::new();
        m.insert("policy".into(), doc("policy", serde_json::json!({ "toml": 123 })));
        m.insert("aliases".into(), doc("aliases", serde_json::json!({ "decl": "nope" })));
        m.insert("service".into(), doc("service", serde_json::json!({ "keys": "nope" })));
        let _dbc = load(&MapDb(m)).await;
    }

    #[tokio::test]
    async fn alias_compile_and_duplicates() {
        let ok = vec![crate::config::AliasDecl { pattern: "/api/alias/x/:id".into(), target_path: "/api/collections/x".into(), target_query: String::new() }];
        assert_eq!(compile_aliases(&ok).unwrap().len(), 1);
        let dup = vec![ok[0].clone(), ok[0].clone()];
        assert!(compile_aliases(&dup).is_err());
    }
}

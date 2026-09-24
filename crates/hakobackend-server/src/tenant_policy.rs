//! Per-tenant policy files (T1): `__tenant_policies/{slug}` docs carrying
//! `{policy_toml, version}`. A tenant with a doc uses it INSTEAD of the
//! global file (replace semantics, never merge); without one the global
//! policy applies. Hot-reload via version polling (5 s TTL, same staleness
//! contract as the global mtime watch): writers bump `version`, readers
//! refresh on TTL expiry, parse failures keep the last good copy.
//!
//! Reserved like other internals: covered by the `__*` HTTP deny.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use hakobackend_core::Database;
use hakobackend_policy::PolicyFile;

/// Registry collection for tenant policy docs.
pub const TENANT_POLICIES_COLLECTION: &str = "__tenant_policies";

/// Refresh cadence for cached tenant policies.
pub const POLICY_TTL: Duration = Duration::from_secs(5);

pub struct TenantPolicies {
    db: Arc<tokio::sync::RwLock<Arc<dyn Database>>>,
    cache: std::sync::Mutex<HashMap<String, (u64, Arc<PolicyFile>, Instant)>>,
}

impl TenantPolicies {
    pub fn new(db: Arc<tokio::sync::RwLock<Arc<dyn Database>>>) -> Self {
        Self { db, cache: std::sync::Mutex::new(HashMap::new()) }
    }

    /// Policy for a tenant, or None when it has no doc (caller falls back
    /// to global). Parse failures keep the stale copy (fail-closed-safe).
    pub async fn get(&self, slug: &str) -> Option<Arc<PolicyFile>> {
        {
            let cache = self.cache.lock().unwrap();
            if let Some((_, p, at)) = cache.get(slug) {
                if at.elapsed() < POLICY_TTL {
                    return Some(p.clone());
                }
            }
        }
        let db = self.db.read().await.clone();
        let doc = db.get(TENANT_POLICIES_COLLECTION, slug).await.ok()??;
        let raw = doc.data.get("policy_toml")?.as_str()?;
        let version = doc.data.get("version").and_then(|v| v.as_u64()).unwrap_or(0);
        match PolicyFile::load_str(raw) {
            Ok(f) => {
                let p = Arc::new(f);
                self.cache.lock().unwrap().insert(slug.into(), (version, p.clone(), Instant::now()));
                Some(p)
            }
            Err(e) => {
                eprintln!("[tenant-policy] {slug}: parse failed ({e}); keeping previous");
                self.cache.lock().unwrap().get(slug).map(|(_, p, _)| p.clone())
            }
        }
    }

    /// Validate + store a tenant policy (admin). Returns the new version.
    /// Parse failure rejects the write (never persist a broken policy).
    pub async fn put(&self, slug: &str, toml: &str) -> Result<u64, String> {
        let parsed: PolicyFile =
            PolicyFile::load_str(toml).map_err(|e| format!("parse policy: {e}"))?;
        let db = self.db.read().await.clone();
        let current: u64 = db
            .get(TENANT_POLICIES_COLLECTION, slug)
            .await
            .map_err(|e| e.to_string())?
            .and_then(|d| d.data.get("version")?.as_u64())
            .unwrap_or(0);
        let version = current + 1;
        let mut data = HashMap::new();
        data.insert("policy_toml".to_string(), serde_json::Value::String(toml.into()));
        data.insert("version".to_string(), serde_json::Value::from(version));
        db.set(
            TENANT_POLICIES_COLLECTION,
            slug,
            hakobackend_core::Doc { id: slug.into(), data },
            false,
        )
        .await
        .map_err(|e| e.to_string())?;
        self.cache
            .lock()
            .unwrap()
            .insert(slug.into(), (version, Arc::new(parsed), Instant::now()));
        Ok(version)
    }

    /// Raw (version, toml) for the admin read path.
    pub async fn get_raw(&self, slug: &str) -> Option<(u64, String)> {
        let db = self.db.read().await.clone();
        let doc = db.get(TENANT_POLICIES_COLLECTION, slug).await.ok()??;
        Some((
            doc.data.get("version")?.as_u64()?,
            doc.data.get("policy_toml")?.as_str()?.to_string(),
        ))
    }
}

/// Starter policy for a self-registered tenant: the tenant-admin role
/// runs the whole tenant, everything else is denied until the owner
/// extends it via PUT. Written through `put` like any policy (validated).
pub fn starter_policy(tenant_admin_role: &str) -> String {
    format!(
        "# Starter policy (open-mode registration): `{r}` administers this tenant.\n\
         [defaults]\n\
         read = \"role:{r}\"\n\
         write = \"role:{r}\"\n",
        r = tenant_admin_role
    )
}

//! Tenant-scoped database view: prefix decorator over any driver.
//!
//! `TenantDb<D>` rewrites every collection name through
//! [`tenant::resolve_collection`] before delegating, so a provider built on
//! top (e.g. per-tenant `LocalAuth`) gets full namespace isolation — users,
//! sessions, and data alike — with zero driver changes. Listing filters +
//! strips to logical names, mirroring the gateway behavior.

use super::{AppError, Capabilities, Change, Database, Doc, IndexInfo, IndexSpec, QueryOptions};
use super::tenant;

pub struct TenantDb {
    inner: std::sync::Arc<dyn Database>,
    tenant: String,
}

impl TenantDb {
    pub fn new(inner: std::sync::Arc<dyn Database>, tenant: &str) -> Self {
        Self { inner, tenant: tenant.into() }
    }

    fn stored(&self, logical: &str) -> String {
        tenant::resolve_collection(Some(&self.tenant), logical)
    }
}

#[async_trait::async_trait]
impl Database for TenantDb {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    async fn ensure_collection(&self, path: &str) -> Result<(), AppError> {
        self.inner.ensure_collection(&self.stored(path)).await
    }
    async fn list_collections(&self) -> Result<Vec<String>, AppError> {
        Ok(tenant::visible_collections(self.inner.list_collections().await?, Some(&self.tenant))
            .into_iter()
            .map(|(_, logical)| logical)
            .collect())
    }
    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        self.inner.get(&self.stored(collection), id).await
    }
    async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
        self.inner.list(&self.stored(collection), q).await
    }
    async fn insert(&self, collection: &str, doc: Doc) -> Result<Doc, AppError> {
        self.inner.insert(&self.stored(collection), doc).await
    }
    async fn set(&self, collection: &str, id: &str, doc: Doc, merge: bool) -> Result<Doc, AppError> {
        self.inner.set(&self.stored(collection), id, doc, merge).await
    }
    async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        self.inner.delete(&self.stored(collection), id).await
    }
    async fn count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError> {
        self.inner.count(&self.stored(collection), q).await
    }
    async fn subscribe(
        &self,
        collection: &str,
    ) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
        self.inner.subscribe(&self.stored(collection)).await
    }
    async fn create_index(&self, collection: &str, spec: &IndexSpec) -> Result<IndexInfo, AppError> {
        self.inner.create_index(&self.stored(collection), spec).await
    }
    async fn list_indexes(&self, collection: &str) -> Result<Vec<IndexInfo>, AppError> {
        self.inner.list_indexes(&self.stored(collection)).await
    }
    async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError> {
        self.inner.drop_index(&self.stored(collection), name).await
    }
    async fn run_transaction(&self, ops: Vec<super::TxOp>) -> Result<Vec<super::TxOut>, AppError> {
        let ops = ops
            .into_iter()
            .map(|mut op| {
                op.collection = self.stored(&op.collection);
                op
            })
            .collect();
        self.inner.run_transaction(ops).await
    }
    async fn sweep_expired(&self, per_collection_cap: usize) -> Result<(usize, usize), AppError> {
        self.inner.sweep_expired(per_collection_cap).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Database as _;

    struct Rec {
        calls: std::sync::Mutex<Vec<String>>,
    }

    #[async_trait::async_trait]
    impl Database for Rec {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                driver: "rec",
                supports_watch: false,
                supports_transactions: false,
                supports_composite: false,
                supports_fts: false,
                supports_drop_index: false,
                supports_unique: false,
                supports_named_index: false,
            }
        }
        async fn ensure_collection(&self, p: &str) -> Result<(), AppError> {
            self.calls.lock().unwrap().push(format!("ensure:{p}"));
            Ok(())
        }
        async fn list_collections(&self) -> Result<Vec<String>, AppError> {
            Ok(vec!["users".into(), "acme__users".into(), "__tenants".into(), "b__x".into()])
        }
        async fn get(&self, c: &str, id: &str) -> Result<Option<Doc>, AppError> {
            self.calls.lock().unwrap().push(format!("get:{c}/{id}"));
            Ok(None)
        }
        async fn list(&self, c: &str, _q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
            self.calls.lock().unwrap().push(format!("list:{c}"));
            Ok(vec![])
        }
        async fn insert(&self, c: &str, doc: Doc) -> Result<Doc, AppError> {
            self.calls.lock().unwrap().push(format!("insert:{c}"));
            Ok(doc)
        }
        async fn set(&self, _c: &str, _id: &str, doc: Doc, _m: bool) -> Result<Doc, AppError> {
            Ok(doc)
        }
        async fn delete(&self, _c: &str, _id: &str) -> Result<Option<Doc>, AppError> {
            Ok(None)
        }
        async fn count(&self, _c: &str, _q: &QueryOptions) -> Result<u64, AppError> {
            Ok(0)
        }
        async fn subscribe(&self, _c: &str) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
            Ok(tokio::sync::broadcast::channel(16).0.subscribe())
        }
        async fn create_index(&self, _c: &str, _s: &IndexSpec) -> Result<IndexInfo, AppError> {
            Err(AppError::BadRequest("no".into()))
        }
        async fn list_indexes(&self, _c: &str) -> Result<Vec<IndexInfo>, AppError> {
            Ok(vec![])
        }
        async fn drop_index(&self, _c: &str, _n: &str) -> Result<(), AppError> {
            Ok(())
        }
    }

    #[tokio::test]
    async fn tenant_db_prefixes_and_filters() {
        let rec = std::sync::Arc::new(Rec { calls: std::sync::Mutex::new(Vec::new()) });
        let db = TenantDb::new(rec.clone() as std::sync::Arc<dyn Database>, "acme");
        assert_eq!(db.list_collections().await.unwrap(), vec!["users".to_string()]);
        db.get("users", "a").await.unwrap();
        db.list("posts/x/y", &QueryOptions::default()).await.unwrap();
        let calls = rec.calls.lock().unwrap();
        assert!(calls.contains(&"get:acme__users/a".to_string()));
        assert!(calls.contains(&"list:acme__posts/x/y".to_string()));
    }
}

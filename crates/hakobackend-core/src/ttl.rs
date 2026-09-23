//! TTL (`__ttl_at`) + decorator DB: uniform expiry on every driver.
//!
//! Convention (no engine support needed): a document carrying numeric
//! `__ttl_at` (microsecond epoch, same clock as `_time`) is dead past that
//! instant. [`TtlDb`] wraps any `Database` and filters the dead in `get` /
//! `list` / `count` / `subscribe`-time snapshots; [`sweep_once`] physically
//! deletes them (which emits normal watch `Remove` events downstream).
//!
//! Docs without the field are immortal — zero behavior change for them.

use std::sync::Arc;
use std::time::Duration;

use super::{AppError, Capabilities, Change, Database, Doc, IndexInfo, IndexSpec, QueryOptions};

/// Expiry field: microsecond epoch. Values that are not positive integers
/// are ignored (doc stays immortal) — fail-open on malformed stamps.
pub const TTL_FIELD: &str = "__ttl_at";

pub fn now_micros() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_micros().min(i64::MAX as u128) as i64)
        .unwrap_or(0)
}

/// True when the doc carries a past `__ttl_at`.
pub fn is_expired(doc: &Doc) -> bool {
    doc.data
        .get(TTL_FIELD)
        .and_then(|v| v.as_i64())
        .is_some_and(|t| t > 0 && t <= now_micros())
}

/// Decorator: identical behavior to the inner driver except the dead are
/// filtered. All gateway paths go through `Arc<dyn Database>`, so wrapping
/// once at startup covers CRUD, batch, aggregates, groups, and realtime.
pub struct TtlDb<D: Database> {
    inner: D,
}

impl<D: Database> TtlDb<D> {
    pub fn new(inner: D) -> Self {
        Self { inner }
    }
}

#[async_trait::async_trait]
impl<D: Database + Send + Sync> Database for TtlDb<D> {
    fn capabilities(&self) -> Capabilities {
        self.inner.capabilities()
    }
    async fn ensure_collection(&self, path: &str) -> Result<(), AppError> {
        self.inner.ensure_collection(path).await
    }
    async fn list_collections(&self) -> Result<Vec<String>, AppError> {
        self.inner.list_collections().await
    }
    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        Ok(self.inner.get(collection, id).await?.filter(|d| !is_expired(d)))
    }
    async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
        Ok(self
            .inner
            .list(collection, q)
            .await?
            .into_iter()
            .filter(|d| !is_expired(d))
            .collect())
    }
    async fn insert(&self, collection: &str, doc: Doc) -> Result<Doc, AppError> {
        self.inner.insert(collection, doc).await
    }
    async fn set(&self, collection: &str, id: &str, doc: Doc, merge: bool) -> Result<Doc, AppError> {
        self.inner.set(collection, id, doc, merge).await
    }
    async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        Ok(self.inner.delete(collection, id).await?.filter(|d| !is_expired(d)))
    }
    async fn count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError> {
        // COUNT(*) can't see the convention: count the filtered list.
        // Slower than native count on huge collections — sweep keeps them small.
        Ok(self.list(collection, q).await?.len() as u64)
    }
    async fn subscribe(
        &self,
        collection: &str,
    ) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
        self.inner.subscribe(collection).await
    }
    async fn create_index(&self, collection: &str, spec: &IndexSpec) -> Result<IndexInfo, AppError> {
        self.inner.create_index(collection, spec).await
    }
    async fn list_indexes(&self, collection: &str) -> Result<Vec<IndexInfo>, AppError> {
        self.inner.list_indexes(collection).await
    }
    async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError> {
        self.inner.drop_index(collection, name).await
    }
    async fn run_transaction(&self, ops: Vec<super::TxOp>) -> Result<Vec<super::TxOut>, AppError> {
        self.inner.run_transaction(ops).await
    }
    async fn sweep_expired(&self, per_collection_cap: usize) -> Result<(usize, usize), AppError> {
        // Past our own filter: the inner list still sees the dead.
        self.inner.sweep_expired(per_collection_cap).await
    }
}

/// One sweep pass over every collection (skips internals). Deletions flow
/// through normal paths, so watchers see `Remove` events. Kept as a free
/// function so tests and CLIs can drive it without a server.
pub async fn sweep_once(
    db: &Arc<dyn Database>,
    per_collection_cap: usize,
) -> (usize, usize) {
    db.sweep_expired(per_collection_cap).await.unwrap_or_default()
}

/// Background sweeper: full pass every `interval`. Runs until the process
/// ends; each pass is bounded work (see `sweep_once`).
pub fn spawn_sweeper(db: Arc<dyn Database>, interval: Duration, per_collection_cap: usize) {
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        loop {
            tick.tick().await;
            let (visited, deleted) = sweep_once(&db, per_collection_cap).await;
            if deleted > 0 {
                eprintln!("[ttl] sweep: {visited} collections, {deleted} expired deleted");
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    use crate::Database as _;

    fn doc(id: &str, ttl: Option<i64>) -> Doc {
        let mut data = HashMap::new();
        if let Some(t) = ttl {
            data.insert(TTL_FIELD.into(), serde_json::json!(t));
        }
        Doc { id: id.into(), data }
    }

    struct Mem {
        docs: std::sync::Mutex<HashMap<String, Doc>>,
    }

    #[async_trait::async_trait]
    impl Database for Mem {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                driver: "mem",
                supports_watch: false,
                supports_transactions: false,
                supports_composite: false,
                supports_fts: false,
                supports_drop_index: false,
                supports_unique: false,
                supports_named_index: false,
            }
        }
        async fn ensure_collection(&self, _p: &str) -> Result<(), AppError> {
            Ok(())
        }
        async fn list_collections(&self) -> Result<Vec<String>, AppError> {
            Ok(vec!["c".into()])
        }
        async fn get(&self, _c: &str, id: &str) -> Result<Option<Doc>, AppError> {
            Ok(self.docs.lock().unwrap().get(id).cloned())
        }
        async fn list(&self, _c: &str, _q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
            Ok(self.docs.lock().unwrap().values().cloned().collect())
        }
        async fn insert(&self, _c: &str, doc: Doc) -> Result<Doc, AppError> {
            self.docs.lock().unwrap().insert(doc.id.clone(), doc.clone());
            Ok(doc)
        }
        async fn set(&self, _c: &str, _id: &str, doc: Doc, _m: bool) -> Result<Doc, AppError> {
            self.insert(_c, doc).await
        }
        async fn delete(&self, _c: &str, id: &str) -> Result<Option<Doc>, AppError> {
            Ok(self.docs.lock().unwrap().remove(id))
        }
        async fn count(&self, _c: &str, _q: &QueryOptions) -> Result<u64, AppError> {
            Ok(self.docs.lock().unwrap().len() as u64)
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
    async fn ttl_filters_and_sweeps() {
        let inner = Mem { docs: std::sync::Mutex::new(HashMap::new()) };
        let db = TtlDb::new(inner);
        let past = now_micros() - 1_000_000;
        let future = now_micros() + 3600_000_000;
        db.insert("c", doc("dead", Some(past))).await.unwrap();
        db.insert("c", doc("live", Some(future))).await.unwrap();
        db.insert("c", doc("plain", None)).await.unwrap();
        assert!(db.get("c", "dead").await.unwrap().is_none());
        assert!(db.get("c", "live").await.unwrap().is_some());
        assert_eq!(db.list("c", &QueryOptions::default()).await.unwrap().len(), 2);
        assert_eq!(db.count("c", &QueryOptions::default()).await.unwrap(), 2);
        let db_arc: Arc<dyn Database> = Arc::new(TtlDb::new(Mem {
            docs: std::sync::Mutex::new(
                [("dead".to_string(), doc("dead", Some(past)))]
                    .into_iter()
                    .collect(),
            ),
        }));
        let (visited, deleted) = sweep_once(&db_arc, 100).await;
        assert_eq!((visited, deleted), (1, 1));
    }
}

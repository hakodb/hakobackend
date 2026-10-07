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

use super::{agg_number, AppError, Capabilities, Change, Database, Doc, Filter, FilterOp, IndexInfo, IndexSpec, QueryOptions, RawDoc};

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

/// Byte scan for the quoted expiry key inside pre-serialized JSON. The key
/// is engine-emitted adjacent to its colon (`"__ttl_at":`), so a plain
/// window search is exact for real fields; a string *value* containing the
/// same text only triggers the safe fallback.
fn contains_ttl_key(json: &[u8]) -> bool {
    const NEEDLE: &[u8] = b"\"__ttl_at\"";
    json.windows(NEEDLE.len()).any(|w| w == NEEDLE)
}

/// Aggregates ignore paging at the trait level too (the server clears it,
/// but direct callers may not — a limit must never shrink a total).
fn unpaged(q: &QueryOptions) -> QueryOptions {
    let mut q = q.clone();
    q.limit = None;
    q.offset = None;
    q
}

/// Expired-candidate subset: caller's filters AND positive-int `__ttl_at`
/// <= now. Candidates are ALWAYS re-verified in Rust via [`is_expired`]
/// (exact): malformed stamps that happen to match natively (floats,
/// numeric strings, bools) are immortal, so they stay in the total —
/// exactly as the convention demands.
fn expired_query(q: &QueryOptions) -> QueryOptions {
    let mut eq = unpaged(q);
    eq.filters.push(Filter { field: TTL_FIELD.into(), op: FilterOp::Gt, value: serde_json::json!(0) });
    eq.filters.push(Filter {
        field: TTL_FIELD.into(),
        op: FilterOp::Lte,
        value: serde_json::json!(now_micros()),
    });
    eq
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

    /// Exact expired-doc count for the subset: fetch the (sweep-kept-small)
    /// candidates, verify each in Rust via [`is_expired`]. Malformed stamps
    /// matching natively stay out of this number (they're immortal).
    async fn expired_count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError> {
        Ok(self
            .inner
            .list(collection, &expired_query(q))
            .await?
            .iter()
            .filter(|d| is_expired(d))
            .count() as u64)
    }

    /// Exact (expired numeric sum, expired count) for sum/avg correction.
    async fn expired_stats(
        &self,
        collection: &str,
        field: &str,
        q: &QueryOptions,
    ) -> Result<(f64, u64), AppError> {
        let mut sum = 0.0;
        let mut n = 0u64;
        for d in self.inner.list(collection, &expired_query(q)).await? {
            if is_expired(&d) {
                n += 1;
                sum += d.data.get(field).and_then(agg_number).unwrap_or(0.0);
            }
        }
        Ok((sum, n))
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
    /// Raw fast path with the TTL gate preserved: docs carrying the expiry
    /// field fall back to the filtered `get` (rare by design); the immortal
    /// common case streams through untouched. Substring match is exact on
    /// the quoted key (`"__ttl_at"`), so a false positive only costs a slow
    /// path, never a wrong body. `doc_version` stays None here: an expired
    /// doc never bumps its version, so a pre-fetch 304 could resurrect the
    /// dead — post-fetch ETags (from `RawDoc.version`) are still served.
    async fn get_json(&self, collection: &str, id: &str) -> Result<Option<RawDoc>, AppError> {
        let raw = self.inner.get_json(collection, id).await?;
        Ok(raw.filter(|r| !contains_ttl_key(&r.json_inner)))
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
        // COUNT(*) can't see the convention — unless the inner driver does
        // native aggregation, in which case total−expired (both native, no
        // doc fetch; exact — see expired_query). Otherwise count the
        // filtered list. Slower on huge collections — sweep keeps them small.
        if !self.inner.capabilities().supports_native_aggregation {
            return Ok(self.list(collection, q).await?.len() as u64);
        }
        let total = self.inner.count(collection, &unpaged(q)).await?;
        Ok(total.saturating_sub(self.expired_count(collection, q).await?))
    }
    /// Native sum minus the exact expired subset (see `expired_query` below).
    /// Legacy drivers take the trait default (list + reduce, unchanged).
    async fn sum(&self, collection: &str, field: &str, q: &QueryOptions) -> Result<f64, AppError> {
        if !self.inner.capabilities().supports_native_aggregation {
            return Ok(self
                .list(collection, q)
                .await?
                .iter()
                .filter_map(|d| d.data.get(field).and_then(agg_number))
                .sum());
        }
        let total = self.inner.sum(collection, field, &unpaged(q)).await?;
        let (exp_sum, _) = self.expired_stats(collection, field, q).await?;
        Ok(total - exp_sum)
    }
    async fn avg(&self, collection: &str, field: &str, q: &QueryOptions) -> Result<f64, AppError> {
        if !self.inner.capabilities().supports_native_aggregation {
            let nums: Vec<f64> = self
                .list(collection, q)
                .await?
                .iter()
                .filter_map(|d| d.data.get(field).and_then(agg_number))
                .collect();
            return Ok(if nums.is_empty() {
                0.0
            } else {
                nums.iter().sum::<f64>() / nums.len() as f64
            });
        }
        let n_total = self.inner.count(collection, &unpaged(q)).await?;
        let sum_total = self.inner.sum(collection, field, &unpaged(q)).await?;
        let (exp_sum, n_exp) = self.expired_stats(collection, field, q).await?;
        let denom = n_total.saturating_sub(n_exp);
        Ok(if denom == 0 {
            0.0
        } else {
            (sum_total - exp_sum) / denom as f64
        })
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
    async fn relocate(&self, src: &str, dst: &str, ids: &[String]) -> Result<(Vec<String>, Vec<String>), AppError> {
        self.inner.relocate(src, dst, ids).await
    }
    async fn load_collection(&self, collection: &str) -> Result<(), AppError> {
        self.inner.load_collection(collection).await
    }
    async fn unload_collection(&self, collection: &str) -> Result<(), AppError> {
        self.inner.unload_collection(collection).await
    }
    async fn unloaded_collections(&self) -> Result<Vec<String>, AppError> {
        self.inner.unloaded_collections().await
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
                supports_native_aggregation: false,
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

    #[test]
    fn ttl_key_scan_exact_and_safe() {
        // Real field → detected (slow fallback).
        assert!(contains_ttl_key(br#"{"a":1,"__ttl_at":123}"#));
        // Absent → fast path.
        assert!(!contains_ttl_key(br#"{"a":1,"_time":5}"#));
        // Looks-alike without quotes → not a field, fast path stays.
        assert!(!contains_ttl_key(br#"{"note":"see __ttl_at docs"}"#));
    }

    #[tokio::test]
    async fn raw_passthrough_keeps_ttl_gate() {
        struct Raw {
            version: u64,
            inner: Vec<u8>,
        }
        #[async_trait::async_trait]
        impl Database for Raw {
            fn capabilities(&self) -> Capabilities {
                Capabilities {
                    driver: "raw",
                    supports_watch: false,
                    supports_transactions: false,
                    supports_composite: false,
                    supports_fts: false,
                    supports_drop_index: false,
                    supports_unique: false,
                    supports_named_index: false,
                    supports_native_aggregation: false,
                }
            }
            async fn ensure_collection(&self, _p: &str) -> Result<(), AppError> {
                Ok(())
            }
            async fn list_collections(&self) -> Result<Vec<String>, AppError> {
                Ok(vec![])
            }
            async fn get(&self, _c: &str, _i: &str) -> Result<Option<Doc>, AppError> {
                Ok(None)
            }
            async fn list(&self, _c: &str, _q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
                Ok(vec![])
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
            async fn doc_version(&self, _c: &str, _i: &str) -> Result<Option<u64>, AppError> {
                Ok(Some(self.version))
            }
            async fn get_json(&self, _c: &str, _i: &str) -> Result<Option<RawDoc>, AppError> {
                Ok(Some(RawDoc { version: Some(self.version), json_inner: self.inner.clone() }))
            }
        }
        // Immortal doc streams through with its version.
        let live = TtlDb::new(Raw { version: 7, inner: br#"{"_time":1,"a":2}"#.to_vec() });
        let got = live.get_json("c", "x").await.unwrap().unwrap();
        assert_eq!(got.version, Some(7));
        // TTL-carrying doc falls back (None → filtered get), even alive.
        let ttl = TtlDb::new(Raw {
            version: 9,
            inner: format!(r#"{{"_time":1,"{}":9999999999999999}}"#, TTL_FIELD).into_bytes(),
        });
        assert!(ttl.get_json("c", "x").await.unwrap().is_none());
        // And pre-fetch versions stay off through the wrapper (no stale 304).
        assert!(live.doc_version("c", "x").await.unwrap().is_none());
    }
}

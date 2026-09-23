//! hakobackend-db-hako: HakoDB adapter (the default hakobackend driver).
//!
//! HakoDB is used as a direct Rust dependency (`rlib`), not via FFI.
//! Its API is synchronous → every op is wrapped in `spawn_blocking`; `watch_collection`
//! is bridged to `tokio::sync::broadcast` so async Axum handlers can use it.

use std::sync::Arc;
use hakobackend_core::{AppError, Change, Database, Doc, QueryOptions};

pub struct HakoDb {
    inner: Arc<hakodb::Hako>,
    // ponytail: one broadcast per collection created lazily; most
    // collections are never watched, so don't allocate up front.
    channels: tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::broadcast::Sender<Change>>>,
    /// Unique-enforced fields per collection (from `create_index(unique)`).
    /// std mutex: read inside spawn_blocking threads where await is illegal.
    unique: std::sync::Mutex<std::collections::HashMap<String, Vec<String>>>,
}

/// Schema registry + unique shadows live here (covered by the `__*` HTTP
/// deny like other internals).
const SCHEMA_COLLECTION: &str = "__schema";

/// Shadow collection holding one doc per unique value: id = `{field}\0{key}`,
/// body = holder doc id. Checked + staged inside the same serializable tx
/// as the main write, so concurrent duplicates cannot both commit.
fn uniq_collection(coll: &str) -> String {
    format!("__uniq_{coll}")
}

/// Canonical key for a unique value. Missing/null exempt (SQL parity).
fn uniq_key(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(b) => Some(format!("b:{b}")),
        serde_json::Value::Number(n) => Some(format!("n:{n}")),
        serde_json::Value::String(s) => Some(format!("s:{s}")),
        other => Some(format!("j:{other}")),
    }
}

impl HakoDb {
    pub fn open(path: &str) -> Result<Self, AppError> {
        let db = hakodb::Hako::open(path, hakodb::config::HakoConfig::default())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        let this = Self {
            inner: Arc::new(db),
            channels: tokio::sync::Mutex::new(std::collections::HashMap::new()),
            unique: std::sync::Mutex::new(std::collections::HashMap::new()),
        };
        this.load_unique_registry();
        Ok(this)
    }

    /// Best-effort load of persisted unique declarations (fresh DB: none).
    fn load_unique_registry(&self) {
        let Ok(rows) = self.inner.query(hakodb::query::query::Query::new(SCHEMA_COLLECTION)) else {
            return;
        };
        let mut map = self.unique.lock().unwrap();
        for (id, doc) in rows {
            if let Some(suffix) = id.strip_prefix("uniq:") {
                if let Some(fields) = doc.get("fields") {
                    let list: Vec<String> = match fields {
                        hakodb::document::value::Value::Array(items) => items
                            .iter()
                            .filter_map(|v| match v {
                                hakodb::document::value::Value::String(s) => Some(s.to_string()),
                                _ => None,
                            })
                            .collect(),
                        _ => Vec::new(),
                    };
                    if !list.is_empty() {
                        map.insert(suffix.to_string(), list);
                    }
                }
            }
        }
    }

    fn unique_fields(&self, collection: &str) -> Vec<String> {
        self.unique.lock().unwrap().get(collection).cloned().unwrap_or_default()
    }

    fn to_doc(id: String, hako: hakodb::document::hako_doc::HakoDoc) -> Doc {
        // HakoDoc::to_json() -> serde_json::Value::Object; take its map directly.
        let data = match hako.to_json() {
            serde_json::Value::Object(m) => m.into_iter().collect(),
            other => {
                let mut data = std::collections::HashMap::new();
                data.insert("_value".to_string(), other);
                data
            }
        };
        Doc { id, data }
    }

    fn to_hako(doc: &Doc) -> hakodb::document::hako_doc::HakoDoc {
        let mut hako = hakodb::document::hako_doc::HakoDoc::default();
        for (k, v) in &doc.data {
            hako.insert(k, json_to_value(v));
        }
        hako
    }
}

fn json_to_value(v: &serde_json::Value) -> hakodb::document::value::Value {
    use hakodb::document::value::Value as HV;
    match v {
        serde_json::Value::Null => HV::Null,
        serde_json::Value::Bool(b) => HV::Bool(*b),
        serde_json::Value::Number(n) => {
            if let Some(i) = n.as_i64() {
                HV::Int(i)
            } else if let Some(f) = n.as_f64() {
                HV::Float(f)
            } else {
                HV::String(n.to_string())
            }
        }
        serde_json::Value::String(s) => HV::String(s.clone()),
        serde_json::Value::Array(a) => HV::Array(a.iter().map(json_to_value).collect()),
        serde_json::Value::Object(m) => {
            let map = m
                .into_iter()
                .map(|(k, val)| (Arc::<str>::from(k.as_str()), json_to_value(&val)))
                .collect();
            HV::Map(map)
        }
    }
}

fn map_filter(f: &hakobackend_core::Filter) -> Result<hakodb::query::filter::Filter, AppError> {
    use hakodb::query::filter::Operator as HO;
    let op = match f.op {
        hakobackend_core::FilterOp::Eq => HO::Eq,
        hakobackend_core::FilterOp::Ne => HO::Ne,
        hakobackend_core::FilterOp::Gt => HO::Gt,
        hakobackend_core::FilterOp::Lt => HO::Lt,
        hakobackend_core::FilterOp::Gte => HO::Gte,
        hakobackend_core::FilterOp::Lte => HO::Lte,
        hakobackend_core::FilterOp::ArrayContains => HO::ArrayContains,
        hakobackend_core::FilterOp::ArrayContainsAny => HO::ArrayContainsAny,
        hakobackend_core::FilterOp::In => HO::In,
    };
    Ok(hakodb::query::filter::Filter {
        field: f.field.clone(),
        op,
        value: json_to_value(&f.value),
    })
}

#[async_trait::async_trait]
impl Database for HakoDb {
    fn capabilities(&self) -> hakobackend_core::Capabilities {
        hakobackend_core::Capabilities {
            driver: "hako",
            supports_watch: true,
            supports_transactions: true,
            supports_composite: true,
            supports_fts: true,
            // HakoDB has no drop-index API — reject clearly.
            supports_drop_index: false,
            // Unique via shadow registry + serializable tx (see SCHEMA_COLLECTION).
            supports_unique: true,
            // HakoDB doesn't store custom names — always auto (documented).
            supports_named_index: false,
        }
    }

    async fn ensure_collection(&self, _path: &str) -> Result<(), AppError> {
        // HakoDB is schemaless: collections form on first write. No-op.
        Ok(())
    }

    async fn list_collections(&self) -> Result<Vec<String>, AppError> {
        let db = self.inner.clone();
        tokio::task::spawn_blocking(move || {
            db.list_collections()
                .map_err(|e| AppError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
    }

    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let db = self.inner.clone();
        let (c, i) = (collection.to_string(), id.to_string());
        tokio::task::spawn_blocking(move || {
            db.get(&c, &i)
                .map(|opt| opt.map(|h| Self::to_doc(i.clone(), h)))
                .map_err(|e| AppError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
    }

    async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
        // Two native HakoDB semantic traps (found via the conformance suite):
        // 1. Cursor operates on sorted KEYS (ids), not order-field values.
        // 2. Full-scan pushes limit into the scan BEFORE manual sort
        //    (planner.rs:286-297, assuming "unordered may take any TOP-N").
        // With a cursor OR order_by: fetch the full set (natively sorted),
        // then apply cursor+offset+limit via the contract helper (parity guaranteed).
        let emulate = q.start_at.is_some()
            || q.start_after.is_some()
            || q.end_at.is_some()
            || q.end_before.is_some()
            || !q.order_by.is_empty();
        let mut query = hakodb::query::query::Query::new(collection);
        for f in &q.filters {
            let hf = map_filter(f)?;
            query = query.where_filter(&hf.field, hf.op, hf.value);
        }
        for o in &q.order_by {
            query = query.order_by(&o.field, matches!(o.direction, hakobackend_core::Direction::Asc));
        }
        if !emulate {
            if let Some(n) = q.limit {
                query = query.limit(n);
            }
            if let Some(n) = q.offset {
                query = query.offset(n);
            }
        }
        let db = self.inner.clone();
        let docs: Vec<Doc> = tokio::task::spawn_blocking(move || {
            db.query(query)
                .map(|rows| rows.into_iter().map(|(id, h)| Self::to_doc(id, h)).collect())
                .map_err(|e| AppError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
        if emulate {
            // Native already filters+sorts correctly; apply cursor+offset+limit via the contract.
            Ok(hakobackend_core::conformance::apply_offset_limit(
                hakobackend_core::conformance::apply_cursor(docs, q),
                q,
            ))
        } else {
            Ok(docs)
        }
    }

    async fn insert(&self, collection: &str, mut doc: Doc) -> Result<Doc, AppError> {
        if doc.id.is_empty() {
            doc.id = uuid_like();
        }
        // Contract: explicit id that already exists = AlreadyExists (matches
        // the SQL drivers' ON CONFLICT DO NOTHING). Structural uniqueness
        // (e.g. tenant provisioning) depends on this.
        if self.get(collection, &doc.id).await?.is_some() {
            return Err(AppError::AlreadyExists);
        }
        self.set(collection, &doc.id.clone(), doc, false).await
    }

    async fn set(&self, collection: &str, id: &str, doc: Doc, merge: bool) -> Result<Doc, AppError> {
        // Unique-enforced collections go through the serializable tx (shadow
        // checks); the plain path stays a single put.
        if !self.unique_fields(collection).is_empty() {
            let mut out = self
                .run_transaction(vec![hakobackend_core::TxOp {
                    collection: collection.to_string(),
                    id: id.to_string(),
                    kind: hakobackend_core::TxOpKind::Put { merge, must_exist: false },
                    doc: Some(doc),
                }])
                .await?;
            return out.pop().and_then(|o| o.doc).ok_or_else(|| AppError::Internal("tx without output".into()));
        }
        // Contract: merge=true = shallow top-level merge (read-merge-write).
        let data = if merge {
            let mut base = self
                .get(collection, id)
                .await?
                .map(|old| old.data)
                .unwrap_or_default();
            base.extend(doc.data);
            base
        } else {
            doc.data
        };
        let merged = Doc { id: id.to_string(), data };
        let db = self.inner.clone();
        let hako = Self::to_hako(&merged);
        let (c, i) = (collection.to_string(), id.to_string());
        tokio::task::spawn_blocking(move || {
            db.put(&c, &i, &hako)
                .map_err(|e| AppError::Internal(e.to_string()))?;
            Ok::<_, AppError>(Doc { id: i, data: merged.data })
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        // Unique shadows must be unlinked atomically with the doc.
        if !self.unique_fields(collection).is_empty() {
            let mut out = self
                .run_transaction(vec![hakobackend_core::TxOp {
                    collection: collection.to_string(),
                    id: id.to_string(),
                    kind: hakobackend_core::TxOpKind::Delete,
                    doc: None,
                }])
                .await?;
            return Ok(out.pop().and_then(|o| o.doc));
        }
        let prev = self.get(collection, id).await?;
        let db = self.inner.clone();
        let (c, i) = (collection.to_string(), id.to_string());
        tokio::task::spawn_blocking(move || {
            db.delete(&c, &i)
                .map_err(|e| AppError::Internal(e.to_string()))
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))??;
        Ok(prev)
    }

    async fn count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError> {
        Ok(self.list(collection, q).await?.len() as u64)
    }

    async fn subscribe(
        &self,
        collection: &str,
    ) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
        use std::collections::hash_map::Entry;
        let mut channels = self.channels.lock().await;
        // Lazy both ways: prune bridges whose last receiver is gone (their
        // thread exits on its own within one idle tick — see spawn_bridge),
        // then share or spawn.
        channels.retain(|_, tx| tx.receiver_count() > 0);
        match channels.entry(collection.to_string()) {
            Entry::Occupied(e) => Ok(e.into_mut().subscribe()),
            Entry::Vacant(v) => {
                let (tx, _) = tokio::sync::broadcast::channel(256);
                let rx = tx.subscribe();
                // The bridge lives only while receivers exist (lazy teardown).
                spawn_bridge(self.inner.clone(), v.key().clone(), tx.clone());
                v.insert(tx);
                Ok(rx)
            }
        }
    }

    async fn create_index(&self, collection: &str, spec: &hakobackend_core::IndexSpec) -> Result<hakobackend_core::IndexInfo, AppError> {
        hakobackend_core::conformance::validate_spec(self.capabilities(), spec)?;
        // Unique on hako = engine index (lookup speed) + shadow registry
        // (enforcement). Single-field simple only; composite/FTS unique
        // stays a clear rejection like the SQL drivers' FTS rule.
        if spec.unique {
            if spec.kind != hakobackend_core::IndexKind::Simple || spec.fields.len() != 1 {
                return Err(AppError::BadRequest("hako unique needs exactly one simple field".into()));
            }
            let field = spec.fields[0].clone();
            let db = self.inner.clone();
            let c = collection.to_string();
            let f2 = field.clone();
            tokio::task::spawn_blocking(move || {
                db.create_index(&c, &f2).map_err(|e| AppError::Internal(e.to_string()))
            })
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
            let mut doc = hakodb::document::hako_doc::HakoDoc::default();
            doc.insert(
                "fields",
                hakodb::document::value::Value::Array(vec![hakodb::document::value::Value::String(
                    field.clone().into(),
                )]),
            );
            let db = self.inner.clone();
            let c = collection.to_string();
            tokio::task::spawn_blocking(move || {
                db.put(SCHEMA_COLLECTION, &format!("uniq:{c}"), &doc)
                    .map_err(|e| AppError::Internal(e.to_string()))
            })
            .await
            .map_err(|e| AppError::Internal(e.to_string()))??;
            self.unique.lock().unwrap().insert(collection.to_string(), vec![field.clone()]);
            let logical = spec.name.clone().unwrap_or(field.clone());
            return Ok(hakobackend_core::IndexInfo {
                name: logical,
                fields: vec![field],
                unique: true,
                kind: hakobackend_core::IndexKind::Simple,
            });
        }
        let db = self.inner.clone();
        let (c, spec) = (collection.to_string(), spec.clone());
        tokio::task::spawn_blocking(move || {
            match spec.kind {
                hakobackend_core::IndexKind::Simple => {
                    let f = spec
                        .fields
                        .into_iter()
                        .next()
                        .ok_or_else(|| AppError::BadRequest("index spec needs at least one field".into()))?;
                    db.create_index(&c, &f).map_err(|e| AppError::Internal(e.to_string()))?;
                    // Auto name = field name (hako has no naming; documented).
                    Ok(hakobackend_core::IndexInfo { name: f.clone(), fields: vec![f], unique: false, kind: hakobackend_core::IndexKind::Simple })
                }
                hakobackend_core::IndexKind::Composite => {
                    let fields: Vec<(String, hakodb::index::composite::definition::SortDirection)> = spec
                        .fields
                        .iter()
                        .map(|f| (f.clone(), hakodb::index::composite::definition::SortDirection::Asc))
                        .collect();
                    let names = fields.iter().map(|(f, _)| f.clone()).collect::<Vec<_>>();
                    let _id = db.create_composite_index(&c, fields).map_err(|e| AppError::Internal(e.to_string()))?;
                    // Contract logical name (HakoDB names by id; the adapter normalizes).
                    let logical = spec.name.clone().unwrap_or_else(|| hakobackend_core::conformance::auto_index_name(&spec));
                    Ok(hakobackend_core::IndexInfo {
                        name: logical,
                        fields: names,
                        unique: false,
                        kind: hakobackend_core::IndexKind::Composite,
                    })
                }
                hakobackend_core::IndexKind::FullText => {
                    let logical = spec.name.clone().unwrap_or_else(|| hakobackend_core::conformance::auto_index_name(&spec));
                    let f = spec
                        .fields
                        .into_iter()
                        .next()
                        .ok_or_else(|| AppError::BadRequest("index spec needs at least one field".into()))?;
                    db.create_fts_index(&c, &f).map_err(|e| AppError::Internal(e.to_string()))?;
                    Ok(hakobackend_core::IndexInfo {
                        name: logical,
                        fields: vec![f],
                        unique: false,
                        kind: hakobackend_core::IndexKind::FullText,
                    })
                }
            }
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
    }

    async fn list_indexes(&self, collection: &str) -> Result<Vec<hakobackend_core::IndexInfo>, AppError> {
        let db = self.inner.clone();
        let c = collection.to_string();
        let uniq = self.unique_fields(&c);
        tokio::task::spawn_blocking(move || {
            let list = db.list_indexes(Some(c.as_str()));
            let mut out = Vec::new();
            for fields in list.simple.values().chain(list.secondary.values()).flat_map(|v| v.iter()) {
                out.push(hakobackend_core::IndexInfo {
                    name: fields.clone(),
                    fields: vec![fields.clone()],
                    unique: uniq.iter().any(|f| f == fields),
                    kind: hakobackend_core::IndexKind::Simple,
                });
            }
            for fields in list.fts.values().flat_map(|v| v.iter()) {
                out.push(hakobackend_core::IndexInfo {
                    name: format!("fts({fields})"),
                    fields: vec![fields.clone()],
                    unique: false,
                    kind: hakobackend_core::IndexKind::FullText,
                });
            }
            for comp in &list.composite {
                let fields: Vec<String> = comp.fields.iter().map(|f| f.field.clone()).collect();
                // Contract logical name reconstructed from fields (consistent with create).
                let logical = hakobackend_core::conformance::auto_index_name(&hakobackend_core::IndexSpec {
                    name: None,
                    fields: fields.clone(),
                    unique: false,
                    kind: hakobackend_core::IndexKind::Composite,
                });
                out.push(hakobackend_core::IndexInfo {
                    name: logical,
                    fields,
                    unique: false,
                    kind: hakobackend_core::IndexKind::Composite,
                });
            }
            Ok::<_, AppError>(out)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
    }

    async fn drop_index(&self, _collection: &str, _name: &str) -> Result<(), AppError> {
        Err(AppError::BadRequest("hako driver has no drop-index API".into()))
    }

    async fn run_transaction(&self, ops: Vec<hakobackend_core::TxOp>) -> Result<Vec<hakobackend_core::TxOut>, AppError> {
        use hakobackend_core::{TxOpKind, TxOut};
        let db = self.inner.clone();
        let uniq_map = self.unique.lock().unwrap().clone();
        tokio::task::spawn_blocking(move || {
            let mut tx = db.begin_serializable_transaction();
            let mut out = Vec::with_capacity(ops.len());
            // Overlay of this batch's own writes: staged puts are invisible
            // to tx.get (it reads committed state), but later ops in the
            // same batch must observe earlier ones (legacy parity).
            let mut staged: std::collections::HashMap<(String, String), Option<Doc>> =
                std::collections::HashMap::new();
            let read = |tx: &mut hakodb::engine::SerializableTransaction,
                        db: &Arc<hakodb::Hako>,
                        staged: &std::collections::HashMap<(String, String), Option<Doc>>,
                        collection: &str,
                        id: &str| {
                if let Some(hit) = staged.get(&(collection.to_string(), id.to_string())) {
                    return Ok::<_, AppError>(hit.clone());
                }
                tx.get(db, collection, id)
                    .map_err(|e| AppError::Internal(e.to_string()))
                    .map(|h| h.map(|d| HakoDb::to_doc(id.to_string(), d)))
            };
            // Unique enforcement inside the same tx: shadow `__uniq_{coll}`
            // docs (`{field}\0{key}` → holder id) are checked + staged
            // atomically with the main write, so concurrent duplicates
            // cannot both commit. Old keys are unlinked on overwrite/delete.
            let claim = |tx: &mut hakodb::engine::SerializableTransaction,
                             db: &Arc<hakodb::Hako>,
                             staged: &mut std::collections::HashMap<(String, String), Option<Doc>>,
                             collection: &str,
                             id: &str,
                             old: &Option<Doc>,
                             new: &Option<Doc>| {
                let fields = uniq_map.get(collection).cloned().unwrap_or_default();
                if fields.is_empty() {
                    return Ok::<_, AppError>(());
                }
                let keys_of = |d: &Doc| {
                    fields
                        .iter()
                        .filter_map(|f| d.data.get(f).and_then(uniq_key).map(|k| (f.clone(), k)))
                        .collect::<Vec<_>>()
                };
                let scol = uniq_collection(collection);
                if let Some(prev) = old {
                    for (f, k) in keys_of(prev) {
                        let sid = format!("{f}\0{k}");
                        let keep = new.as_ref().is_some_and(|n| {
                            n.data.get(&f).and_then(uniq_key).as_deref() == Some(k.as_str())
                        });
                        if !keep {
                            tx.delete(&scol, &sid);
                            staged.insert((scol.clone(), sid), None);
                        }
                    }
                }
                if let Some(next) = new {
                    for (f, k) in keys_of(next) {
                        let sid = format!("{f}\0{k}");
                        let holder = read(tx, db, staged, &scol, &sid)?.and_then(|d| {
                            d.data.get("holder").and_then(|v| v.as_str()).map(str::to_string)
                        });
                        if holder.as_deref().is_some_and(|h| h != id) {
                            return Err(AppError::AlreadyExists);
                        }
                        let mut sdata = std::collections::HashMap::new();
                        sdata.insert("holder".to_string(), serde_json::Value::String(id.to_string()));
                        let sdoc = Doc { id: sid.clone(), data: sdata };
                        tx.put(&scol, &sid, Self::to_hako(&sdoc));
                        staged.insert((scol.clone(), sid), Some(sdoc));
                    }
                }
                Ok(())
            };
            for op in ops {
                let key = (op.collection.clone(), op.id.clone());
                match op.kind {
                    TxOpKind::Read => {
                        let doc = read(&mut tx, &db, &staged, &op.collection, &op.id)?;
                        out.push(TxOut { existed: doc.is_some(), doc });
                    }
                    TxOpKind::Put { merge, must_exist } => {
                        let old = read(&mut tx, &db, &staged, &op.collection, &op.id)?;
                        if must_exist && old.is_none() {
                            return Err(AppError::NotFound);
                        }
                        let body = op.doc.map(|d| d.data).unwrap_or_default();
                        let existed = old.is_some();
                        let mut data = if merge {
                            old.as_ref().map(|d| d.data.clone()).unwrap_or_default()
                        } else {
                            Default::default()
                        };
                        data.extend(body);
                        let doc = Doc { id: op.id.clone(), data };
                        tx.put(&op.collection, &op.id, Self::to_hako(&doc));
                        staged.insert(key, Some(doc.clone()));
                        claim(&mut tx, &db, &mut staged, &op.collection, &op.id, &old, &Some(doc.clone()))?;
                        out.push(TxOut { existed, doc: Some(doc) });
                    }
                    TxOpKind::Delete => {
                        let old = read(&mut tx, &db, &staged, &op.collection, &op.id)?;
                        tx.delete(&op.collection, &op.id);
                        staged.insert(key, None);
                        claim(&mut tx, &db, &mut staged, &op.collection, &op.id, &old, &None)?;
                        out.push(TxOut { existed: old.is_some(), doc: old });
                    }
                }
            }
            tx.commit(&db).map_err(|e| AppError::Internal(e.to_string()))?;
            Ok(out)
        })
        .await
        .map_err(|e| AppError::Internal(e.to_string()))?
    }
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_nanos())
        .unwrap_or(0);
    format!("{:x}{:x}", nanos, std::process::id())
}

/// Fan-out HakoDB `watch_collection` into a broadcast channel: one OS thread
/// per watched collection, living only while receivers exist. Add/Change
/// classification is deliberately coarse (every Put crosses as `Change`):
/// the server re-derives the true transition from its own snapshot, so the
/// bridge skips both the O(n) seeding scan and the per-id `seen` set.
fn spawn_bridge(db: Arc<hakodb::Hako>, collection: String, tx: tokio::sync::broadcast::Sender<Change>) {
    std::thread::spawn(move || {
        let rx = db.watch_collection(&collection);
        loop {
            match rx.recv_timeout(std::time::Duration::from_millis(500)) {
                Ok(ev) => {
                    // No listeners left: skip the point-get; the idle branch
                    // below reaps this thread within one tick.
                    if tx.receiver_count() == 0 {
                        continue;
                    }
                    let id = ev.path.to_string();
                    match ev.kind {
                        hakodb::engine::ChangeKind::Put => {
                            if let Ok(Some(hako)) = db.get(&collection, &id) {
                                let doc = HakoDb::to_doc(id.clone(), hako);
                                let _ = tx.send(Change {
                                    collection: collection.clone(),
                                    id,
                                    kind: hakobackend_core::ChangeKind::Change,
                                    old: None,
                                    new: Some(doc),
                                });
                            }
                        }
                        hakodb::engine::ChangeKind::Delete => {
                            let _ = tx.send(Change {
                                collection: collection.clone(),
                                id,
                                kind: hakobackend_core::ChangeKind::Remove,
                                old: None,
                                new: None,
                            });
                        }
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Timeout) => {
                    if tx.receiver_count() == 0 {
                        return; // last receiver gone: entry pruned on next subscribe
                    }
                }
                Err(std::sync::mpsc::RecvTimeoutError::Disconnected) => return,
            }
        }
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use hakobackend_core::Database as _;

    /// Lazy teardown: dropping the last receiver reaps the bridge thread
    /// (within one idle tick) and prunes the entry, so a later subscribe
    /// respawns cleanly and still delivers.
    #[tokio::test]
    async fn subscribe_teardown_and_respawn() {
        let dir = std::env::temp_dir().join(format!("hakobackend_sub_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = HakoDb::open(dir.to_string_lossy().as_ref()).unwrap();

        let rx1 = db.subscribe("events").await.unwrap();
        drop(rx1);
        tokio::time::sleep(std::time::Duration::from_millis(700)).await;

        let mut rx2 = db.subscribe("events").await.unwrap();
        // Watch has no backlog: retry with fresh ids until a put lands
        // after the respawned bridge starts listening.
        let mut landed: Option<hakobackend_core::Change> = None;
        for i in 0..8 {
            let id = if i == 0 { "a".to_string() } else { format!("a{i}") };
            db.set(
                "events",
                &id,
                hakobackend_core::Doc { id: id.clone(), data: Default::default() },
                false,
            )
            .await
            .unwrap();
            if let Ok(got) =
                tokio::time::timeout(std::time::Duration::from_secs(1), rx2.recv()).await
            {
                landed = Some(got.unwrap());
                break;
            }
        }
        let change = landed.expect("respawned bridge delivers");
        assert_eq!(change.kind, hakobackend_core::ChangeKind::Change);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Unique enforcement: duplicate values rejected, freed values reusable,
    /// composite/FTS unique stays a clear rejection.
    #[tokio::test]
    async fn unique_shadow_registry() {
        use hakobackend_core::{IndexKind, IndexSpec};
        let dir = std::env::temp_dir().join(format!("hakobackend_uniq_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db = HakoDb::open(dir.to_string_lossy().as_ref()).unwrap();
        let spec = IndexSpec { name: None, fields: vec!["email".into()], unique: true, kind: IndexKind::Simple };
        let info = db.create_index("users", &spec).await.unwrap();
        assert!(info.unique);

        let d = |id: &str, email: &str| hakobackend_core::Doc {
            id: id.into(),
            data: [("email".to_string(), serde_json::json!(email))].into_iter().collect(),
        };
        db.set("users", "u1", d("u1", "a@x.id"), false).await.unwrap();
        // Same value, other id → AlreadyExists (not silent overwrite).
        let dup = db.set("users", "u2", d("u2", "a@x.id"), false).await;
        assert!(matches!(dup, Err(AppError::AlreadyExists)));
        // Same id, same value → fine (idempotent rewrite).
        db.set("users", "u1", d("u1", "a@x.id"), false).await.unwrap();
        // Delete frees the value for reuse.
        db.delete("users", "u1").await.unwrap();
        db.set("users", "u2", d("u2", "a@x.id"), false).await.unwrap();
        // Missing values are exempt (SQL NULL parity).
        db.set("users", "u3", hakobackend_core::Doc { id: "u3".into(), data: Default::default() }, false)
            .await
            .unwrap();
        db.set("users", "u4", hakobackend_core::Doc { id: "u4".into(), data: Default::default() }, false)
            .await
            .unwrap();
        // Non-simple unique stays rejected.
        let bad = IndexSpec { name: None, fields: vec!["a".into(), "b".into()], unique: true, kind: IndexKind::Composite };
        assert!(db.create_index("users", &bad).await.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Must pass before the driver may be registered (DRIVER_CONTRACT.md §4).
    /// Heavy (pulls in HakoDB) — run on full builds, not every edit.
    #[tokio::test]
    #[ignore = "requires a full HakoDB build; run on release builds"]
    async fn conformance_hako() {        let dir = std::env::temp_dir().join(format!("hakobackend_conform_{}", std::process::id()));
        let db = HakoDb::open(dir.to_string_lossy().as_ref()).unwrap();
        hakobackend_core::conformance::run_conformance_suite(&db).await;
        // Drop is unsupported by hako → the index suite asserts its clear rejection.
        hakobackend_core::conformance::run_index_suite(&db).await;
        let _ = std::fs::remove_dir_all(dir);
    }
}

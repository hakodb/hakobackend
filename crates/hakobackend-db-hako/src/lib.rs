//! hakobackend-db-hako: adapter HakoDB (driver default hakobackend).
//!
//! HakoDB dipakai sebagai dependensi Rust langsung (`rlib`), bukan via FFI.
//! API-nya sinkron → setiap op dibungkus `spawn_blocking`; `watch_collection`
//! di-bridge ke `tokio::sync::broadcast` agar bisa dipakai handler Axum async.

use std::sync::Arc;
use hakobackend_core::{AppError, Change, Database, Doc, QueryOptions};

pub struct HakoDb {
    inner: Arc<hakodb::Hako>,
    // ponytail: satu broadcast per koleksi dibuat malas (lazy); kebanyakan
    // koleksi tidak pernah di-watch, jadi jangan alokasi di depan.
    channels: tokio::sync::Mutex<std::collections::HashMap<String, tokio::sync::broadcast::Sender<Change>>>,
}

impl HakoDb {
    pub fn open(path: &str) -> Result<Self, AppError> {
        let db = hakodb::Hako::open(path, hakodb::config::HakoConfig::default())
            .map_err(|e| AppError::Internal(e.to_string()))?;
        Ok(Self {
            inner: Arc::new(db),
            channels: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        })
    }

    fn to_doc(id: String, hako: hakodb::document::hako_doc::HakoDoc) -> Doc {
        // HakoDoc::to_json() -> serde_json::Value::Object; ambil map-nya langsung.
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
            // HakoDB tak punya API hapus index maupun constraint unik — tolak jelas.
            supports_drop_index: false,
            supports_unique: false,
            // HakoDB tak menyimpan nama custom — selalu auto (didokumentasikan).
            supports_named_index: false,
        }
    }

    async fn ensure_collection(&self, _path: &str) -> Result<(), AppError> {
        // HakoDB schemaless: koleksi terbentuk saat tulis pertama. Nul-op.
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
        // Dua jebakan semantik HakoDB native (ditemukan via suite konformansi):
        // 1. Cursor bekerja pada sorted KEYS (id), bukan nilai field order.
        // 2. Full-scan mendorong limit ke scan SEBELUM sort manual
        //    (planner.rs:286-297, asumsi "unordered boleh TOP-N sembarang").
        // Bila ada cursor ATAU order_by: ambil himpunan penuh (terurut native),
        // lalu cursor+offset+limit via helper kontrak (paritas terjamin).
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
            // Native sudah filter+urut benar; terapkan cursor+offset+limit via kontrak.
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
        self.set(collection, &doc.id.clone(), doc, false).await
    }

    async fn set(&self, collection: &str, id: &str, doc: Doc, merge: bool) -> Result<Doc, AppError> {
        // Kontrak: merge=true = gabung dangkal level-atas (baca-gabung-tulis).
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
        match channels.entry(collection.to_string()) {
            Entry::Occupied(e) => Ok(e.into_mut().subscribe()),
            Entry::Vacant(v) => {
                let (tx, _) = tokio::sync::broadcast::channel(256);
                let rx = tx.subscribe();
                // Bridge watch→broadcast hidup selama proses (satu thread per koleksi).
                spawn_bridge(self.inner.clone(), v.key().clone(), tx.clone());
                v.insert(tx);
                Ok(rx)
            }
        }
    }

    async fn create_index(&self, collection: &str, spec: &hakobackend_core::IndexSpec) -> Result<hakobackend_core::IndexInfo, AppError> {
        hakobackend_core::conformance::validate_spec(self.capabilities(), spec)?;
        if spec.unique {
            // ponytail: HakoDB tak punya constraint unik — tolak jelas, bukan diam.
            return Err(AppError::BadRequest("driver hako tanpa unique index".into()));
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
                    // Nama auto = nama field (hako tanpa penamaan; terdokumentasi).
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
                    // Nama logis kontrak (HakoDB menamai by id; adapter menyeragamkan).
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
        tokio::task::spawn_blocking(move || {
            let list = db.list_indexes(Some(c.as_str()));
            let mut out = Vec::new();
            for fields in list.simple.values().chain(list.secondary.values()).flat_map(|v| v.iter()) {
                out.push(hakobackend_core::IndexInfo {
                    name: fields.clone(),
                    fields: vec![fields.clone()],
                    unique: false,
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
                // Nama logis kontrak direkonstruksi dari fields (konsisten dengan create).
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
        Err(AppError::BadRequest("driver hako tanpa API hapus index".into()))
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

/// Fan-out `watch_collection` HakoDB ke broadcast channel (satu thread OS per
/// koleksi yang di-watch, hidup selama proses). Klasifikasi add/change kasar
/// via himpunan id terlihat (seed sekali dari list); server memverifikasi ulang
/// via snapshot-nya sendiri sehingga klasifikasi akhir SELALU konsisten.
fn spawn_bridge(db: Arc<hakodb::Hako>, collection: String, tx: tokio::sync::broadcast::Sender<Change>) {
    std::thread::spawn(move || {
        let rx = db.watch_collection(&collection);
        let mut seen: std::collections::HashSet<String> = db
            .collection(&collection)
            .all()
            .get()
            .map(|rows| rows.into_iter().map(|(id, _)| id).collect())
            .unwrap_or_default();
        for ev in rx {
            let id = ev.path.to_string();
            match ev.kind {
                hakodb::engine::ChangeKind::Put => {
                    if let Ok(Some(hako)) = db.get(&collection, &id) {
                        let doc = HakoDb::to_doc(id.clone(), hako);
                        let kind = if seen.insert(id.clone()) {
                            hakobackend_core::ChangeKind::Add
                        } else {
                            hakobackend_core::ChangeKind::Change
                        };
                        let _ = tx.send(Change {
                            collection: collection.clone(),
                            id,
                            kind,
                            old: None,
                            new: Some(doc),
                        });
                    }
                }
                hakodb::engine::ChangeKind::Delete => {
                    seen.remove(&id);
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
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Wajib lolos sebelum driver boleh diregistrasi (DRIVER_CONTRACT.md §4).
    /// Berat (menarik HakoDB) — dijalankan saat build penuh, bukan tiap edit.
    #[tokio::test]
    #[ignore = "butuh build HakoDB penuh; jalankan saat build release"]
    async fn conformance_hako() {
        let dir = std::env::temp_dir().join(format!("hakobackend_conform_{}", std::process::id()));
        let db = HakoDb::open(dir.to_string_lossy().as_ref()).unwrap();
        hakobackend_core::conformance::run_conformance_suite(&db).await;
        // Drop tak didukung hako → suite index menegaskan penolakan jelasnya.
        hakobackend_core::conformance::run_index_suite(&db).await;
        let _ = std::fs::remove_dir_all(dir);
    }
}

//! hakobackend-db-hakocluster: `Database` driver over an in-process
//! hakocluster (single dataset, N engine instances).
//!
//! Point reads and queries fan out across lock domains (the measured
//! mixed-load isolation win); everything else routes to the designated
//! writer — including the full HakoDb logic (unique tx, watch bridge,
//! aggregates) reused verbatim via one HakoDb per member sharing the
//! cluster's Arcs (opening the same data dir twice would fork the WAL,
//! so members are built with `HakoDb::from_db`, never `open`).
//!
//! `data` is comma-separated Hako dirs (`"a.ub,b.ub"`); one dir is a
//! degenerate single (works everywhere, including non-unix). N > 1 needs
//! unix — socket_sync peering fails closed there, same rule as the engine.
//!
//! Exactness rule: counts/aggregates/metadata read from the writer (the
//! source of truth); point reads and queries may trail by the socket tail
//! interval (documented lag SLA, same as the cluster).

use hakobackend_core::{
    AppError, Capabilities, Change, Doc, IndexInfo, IndexSpec, QueryOptions, TxOp, TxOut,
};

pub struct ClusterDb {
    cluster: hakocluster::Cluster,
    members: Vec<hakobackend_db_hako::HakoDb>,
}

impl ClusterDb {
    pub fn open(dirs: &str) -> Result<Self, AppError> {
        let paths: Vec<&str> = dirs
            .split(',')
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .collect();
        if paths.is_empty() {
            return Err(AppError::Internal("cluster driver needs ≥1 data dir".into()));
        }
        let cluster =
            hakocluster::Cluster::open(&paths).map_err(|e| AppError::Internal(e))?;
        let members = cluster
            .instances()
            .into_iter()
            .map(hakobackend_db_hako::HakoDb::from_db)
            .collect();
        Ok(Self { cluster, members })
    }

    /// Designated writer (all mutations + exact reads route here).
    fn writer(&self) -> &hakobackend_db_hako::HakoDb {
        &self.members[self.cluster.writer_index()]
    }

    /// Member count.
    pub fn instance_count(&self) -> usize {
        self.members.len()
    }

    /// Reads served per instance (fan-out accounting for ops).
    pub fn read_counts(&self) -> Vec<u64> {
        self.cluster.read_counts()
    }
}

#[async_trait::async_trait]
impl hakobackend_core::Database for ClusterDb {
    fn capabilities(&self) -> Capabilities {
        self.writer().capabilities()
    }

    async fn ensure_collection(&self, path: &str) -> Result<(), AppError> {
        self.writer().ensure_collection(path).await
    }

    async fn list_collections(&self) -> Result<Vec<String>, AppError> {
        self.writer().list_collections().await
    }

    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let index = self.cluster.read_index();
        let out = self.members[index].get(collection, id).await;
        if out.is_ok() {
            // Fan-out accounting lives here (member handles carry no
            // counters of their own).
            self.cluster.note_read(index);
        }
        out
    }

    async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
        let index = self.cluster.read_index();
        let out = self.members[index].list(collection, q).await;
        if out.is_ok() {
            self.cluster.note_read(index);
        }
        out
    }

    async fn insert(&self, collection: &str, doc: Doc) -> Result<Doc, AppError> {
        self.writer().insert(collection, doc).await
    }

    async fn set(
        &self,
        collection: &str,
        id: &str,
        doc: Doc,
        merge: bool,
    ) -> Result<Doc, AppError> {
        self.writer().set(collection, id, doc, merge).await
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        self.writer().delete(collection, id).await
    }

    async fn count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError> {
        self.writer().count(collection, q).await
    }

    async fn subscribe(
        &self,
        collection: &str,
    ) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
        self.writer().subscribe(collection).await
    }

    async fn create_index(
        &self,
        collection: &str,
        spec: &IndexSpec,
    ) -> Result<IndexInfo, AppError> {
        // ponytail: DDL fans out to every member — socket_sync replicates
        // data ops, never index definitions, so writer-only DDL would leave
        // replicas planning full scans. First member's answer is returned
        // (identical shape everywhere).
        let mut out = None;
        for m in &self.members {
            let info = m.create_index(collection, spec).await?;
            if out.is_none() {
                out = Some(info);
            }
        }
        out.ok_or_else(|| AppError::Internal("no cluster members".into()))
    }

    async fn list_indexes(&self, collection: &str) -> Result<Vec<IndexInfo>, AppError> {
        self.writer().list_indexes(collection).await
    }

    async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError> {
        // Same DDL fan-out rule as create_index.
        for m in &self.members {
            m.drop_index(collection, name).await?;
        }
        Ok(())
    }

    async fn run_transaction(&self, ops: Vec<TxOp>) -> Result<Vec<TxOut>, AppError> {
        self.writer().run_transaction(ops).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hakobackend_core::Database;

    fn tmp(label: &str) -> String {
        let nanos = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir()
            .join(format!("hakoclusterdrv-{label}-{nanos}-{}", std::process::id()))
            .to_string_lossy()
            .into_owned()
    }

    fn doc(id: &str) -> Doc {
        let mut data = std::collections::HashMap::new();
        data.insert("v".to_string(), serde_json::json!(id));
        Doc { id: id.to_string(), data }
    }

    #[test]
    fn open_rejects_empty_dirs() {
        assert!(ClusterDb::open("").is_err());
        assert!(ClusterDb::open("  , ").is_err());
    }

    #[tokio::test]
    async fn single_node_roundtrip() {
        let dir = tmp("solo");
        let db = ClusterDb::open(&dir).unwrap();
        assert_eq!(db.instance_count(), 1);
        db.insert("c", doc("k1")).await.unwrap();
        let got = db.get("c", "k1").await.unwrap().unwrap();
        assert_eq!(got.id, "k1");
        assert_eq!(db.count("c", &Default::default()).await.unwrap(), 1);
        assert_eq!(db.read_counts(), vec![1]);
        db.delete("c", "k1").await.unwrap();
        assert!(db.get("c", "k1").await.unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Fan-out serves reads across members (distribution, not just
    /// correctness — the whole point of the driver).
    #[cfg(unix)]
    #[tokio::test]
    async fn fanout_spreads_reads() {
        let a = tmp("f-a");
        let b = tmp("f-b");
        let db = ClusterDb::open(&format!("{a},{b}")).unwrap();
        assert_eq!(db.instance_count(), 2);
        db.insert("c", doc("k1")).await.unwrap();
        // Immediate on the writer (routing, no sync wait).
        assert!(db.get("c", "k1").await.unwrap().is_some());
        for _ in 0..30 {
            assert!(db.get("c", "k1").await.unwrap().is_some());
        }
        let counts = db.read_counts();
        assert_eq!(counts.iter().sum::<u64>(), 31);
        assert!(counts.iter().all(|&c| c > 0), "reads spread: {counts:?}");
        let _ = std::fs::remove_dir_all(&a);
        let _ = std::fs::remove_dir_all(&b);
    }
}

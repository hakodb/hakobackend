//! realtime: WS + SSE fan-out over `Database::subscribe` (watch) or polling.
//!
//! The single source of truth for add/change/remove classification is the
//! per-subscription SNAPSHOT + full option matching (filter + cursor) — the
//! legacy `changeHandler` pattern. Driver watch is only a trigger; polling covers
//! drivers without watch. Policy: `List` gate at subscribe, per-document `Get`
//! at delivery (unknown document = rule with None resource).

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;
use hakobackend_core::{AppError, AuthContext, ChangeKind, Database, Doc, Method, QueryOptions};
use hakobackend_policy::PolicyFile;

/// Polling interval for drivers without watch (single-instance; Redis fan-out follows).
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Subscription limit per WS connection (legacy backend parity).
pub const MAX_SUBS_PER_SOCKET: usize = 100;

#[derive(Debug, Clone, Deserialize)]
pub struct SubSpec {
    pub collection: String,
    #[serde(default)]
    pub options: QueryOptions,
    #[serde(default)]
    pub group: bool,
}

#[derive(Debug, Clone)]
pub struct OutEvent {
    pub kind: ChangeKind,
    pub doc: Option<Doc>,
}

/// Wire shape to WS/SSE (kind as string).
#[derive(Debug, Clone, Serialize)]
pub struct WireEvent {
    pub kind: &'static str,
    pub doc: Option<Doc>,
}

impl OutEvent {
    pub fn wire(&self) -> WireEvent {
        WireEvent {
            kind: match self.kind {
                ChangeKind::Add => "add",
                ChangeKind::Change => "change",
                ChangeKind::Remove => "remove",
            },
            doc: self.doc.clone(),
        }
    }
}

pub struct Subscription {
    pub rx: tokio::sync::mpsc::UnboundedReceiver<OutEvent>,
    handle: tokio::task::JoinHandle<()>,
}

impl Drop for Subscription {
    fn drop(&mut self) {
        self.handle.abort();
    }
}

/// `posts_revisions` / `posts/revisions` match group `revisions`
/// (legacy `matchesGroupTable` parity).
pub fn matches_group(table: &str, target: &str) -> bool {
    table == target || table.ends_with(&format!("/{target}")) || table.ends_with(&format!("_{target}"))
}

fn matches_full(doc: &Doc, q: &QueryOptions) -> bool {
    hakobackend_core::conformance::doc_matches(doc, &q.filters) && hakobackend_core::conformance::matches_cursor(doc, q)
}

/// Options for snapshot: filters only (no limit/cursor/offset — diff needs the universe).
fn snapshot_options(q: &QueryOptions) -> QueryOptions {
    QueryOptions { filters: q.filters.clone(), ..Default::default() }
}

/// Transition classification (legacy changeHandler parity): (old_match, new_match).
fn transition(old_match: bool, new_match: bool) -> Option<ChangeKind> {
    match (old_match, new_match) {
        (false, true) => Some(ChangeKind::Add),
        (true, false) => Some(ChangeKind::Remove),
        (true, true) => Some(ChangeKind::Change),
        (false, false) => None,
    }
}

/// Open subscription: List gate → snapshot → per-collection watch/poll source.
pub async fn subscribe(
    db: Arc<dyn Database>,
    policy: Arc<PolicyFile>,
    auth: Option<AuthContext>,
    spec: SubSpec,
) -> Result<Subscription, AppError> {
    if !policy.allow(auth.as_ref(), &spec.collection, Method::List, None) {
        return Err(AppError::PermissionDenied);
    }
    let mut collections = if spec.group {
        let all = db.list_collections().await?;
        all.into_iter().filter(|t| matches_group(t, &spec.collection)).collect::<Vec<_>>()
    } else {
        vec![spec.collection.clone()]
    };
    if collections.is_empty() {
        collections.push(spec.collection.clone());
    }
    // Initial snapshot (no burst to client — client GETs first like legacy).
    let snap_q = snapshot_options(&spec.options);
    let mut snapshot: HashMap<String, Doc> = HashMap::new();
    for coll in &collections {
        let _ = db.ensure_collection(coll).await;
        for doc in db.list(coll, &snap_q).await? {
            snapshot.insert(format!("{coll}\0{}", doc.id), doc);
        }
    }

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let watch = db.capabilities().supports_watch;
    let handle = tokio::spawn(run_source(db, policy, auth, spec.options, collections, snapshot, watch, tx));
    Ok(Subscription { rx, handle })
}

#[allow(clippy::too_many_arguments)]
async fn run_source(
    db: Arc<dyn Database>,
    policy: Arc<PolicyFile>,
    auth: Option<AuthContext>,
    options: QueryOptions,
    collections: Vec<String>,
    mut snapshot: HashMap<String, Doc>,
    watch: bool,
    tx: tokio::sync::mpsc::UnboundedSender<OutEvent>,
) {
    if watch {
        // One receiver per collection; round-robin select (contract: watch = push engine).
        let mut rxs = Vec::new();
        for coll in &collections {
            if let Ok(rx) = db.subscribe(coll).await {
                rxs.push((coll.clone(), rx));
            }
        }
        if rxs.is_empty() {
            return;
        }
        loop {
            let mut got: Option<(usize, hakobackend_core::Change)> = None;
            // Non-blocking round-robin poll across receivers (no dynamic select! macro).
            for (i, (_, rx)) in rxs.iter_mut().enumerate() {
                match rx.try_recv() {
                    Ok(change) => {
                        got = Some((i, change));
                        break;
                    }
                    Err(tokio::sync::broadcast::error::TryRecvError::Closed) => return,
                    Err(tokio::sync::broadcast::error::TryRecvError::Empty) => {}
                    Err(tokio::sync::broadcast::error::TryRecvError::Lagged(_)) => {}
                }
            }
            match got {
                Some((i, change)) => {
                    let coll = rxs[i].0.clone();
                    ingest_change(&policy, auth.as_ref(), &options, &mut snapshot, &coll, change, &tx).await;
                }
                None => tokio::time::sleep(Duration::from_millis(50)).await,
            }
        }
    } else {
        let snap_q = snapshot_options(&options);
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        loop {
            tick.tick().await;
            let mut fresh: HashMap<String, Doc> = HashMap::new();
            for coll in &collections {
                if let Ok(docs) = db.list(coll, &snap_q).await {
                    for doc in docs {
                        fresh.insert(format!("{coll}\0{}", doc.id), doc);
                    }
                }
            }
            // Diff: adds/changes + removals.
            for (key, doc) in &fresh {
                let coll = key.split('\0').next().unwrap_or("");
                let old = snapshot.get(key);
                let old_match = old.map(|d| matches_full(d, &options)).unwrap_or(false);
                let new_match = matches_full(doc, &options);
                if old.map(|d| &d.data) != Some(&doc.data) || !old_match || !new_match {
                    deliver_in(&policy, auth.as_ref(), coll, old, Some(doc), old_match, new_match, &tx).await;
                }
            }
            for (key, old) in &snapshot {
                if !fresh.contains_key(key) {
                    let coll = key.split('\0').next().unwrap_or("");
                    if matches_full(old, &options) {
                        deliver_in(&policy, auth.as_ref(), coll, Some(old), None, true, false, &tx).await;
                    }
                }
            }
            snapshot = fresh;
            if tx.is_closed() {
                return;
            }
        }
    }
}

/// Apply one watch change to the snapshot + send on match.
async fn ingest_change(
    policy: &PolicyFile,
    auth: Option<&AuthContext>,
    options: &QueryOptions,
    snapshot: &mut HashMap<String, Doc>,
    collection: &str,
    change: hakobackend_core::Change,
    tx: &tokio::sync::mpsc::UnboundedSender<OutEvent>,
) {
    // Snapshot key includes the collection (multi-collection groups safe).
    let key = format!("{collection}\0{}", change.id);
    match change.kind {
        ChangeKind::Remove => {
            if let Some(old) = snapshot.remove(&key) {
                if matches_full(&old, options) {
                    deliver_in(policy, auth, collection, Some(&old), None, true, false, tx).await;
                }
            }
        }
        ChangeKind::Add | ChangeKind::Change => {
            if let Some(doc) = change.new {
                let old = snapshot.get(&key);
                let old_match = old.map(|d| matches_full(d, options)).unwrap_or(false);
                let new_match = matches_full(&doc, options);
                deliver_in(policy, auth, collection, old, Some(&doc), old_match, new_match, tx).await;
                snapshot.insert(key, doc);
            }
        }
    }
}

/// Collection-aware deliver wrapper (for hierarchical rule resolution).
pub async fn deliver_in(
    policy: &PolicyFile,
    auth: Option<&AuthContext>,
    collection: &str,
    old: Option<&Doc>,
    new: Option<&Doc>,
    old_match: bool,
    new_match: bool,
    tx: &tokio::sync::mpsc::UnboundedSender<OutEvent>,
) {
    let Some(kind) = transition(old_match, new_match) else {
        return;
    };
    let doc = match kind {
        ChangeKind::Add | ChangeKind::Change => new,
        ChangeKind::Remove => old,
    };
    if !policy.allow(auth, collection, Method::Get, doc) {
        return;
    }
    let _ = tx.send(OutEvent { kind, doc: doc.cloned() });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(id: &str, age: i64) -> Doc {
        Doc {
            id: id.into(),
            data: [("age".to_string(), serde_json::json!(age))].into_iter().collect(),
        }
    }

    fn opts() -> QueryOptions {
        QueryOptions {
            filters: vec![hakobackend_core::Filter {
                field: "age".into(),
                op: hakobackend_core::FilterOp::Gte,
                value: serde_json::json!(18),
            }],
            ..Default::default()
        }
    }

    #[test]
    fn transition_add_change_remove_skip() {
        assert_eq!(transition(false, true), Some(ChangeKind::Add));
        assert_eq!(transition(true, false), Some(ChangeKind::Remove));
        assert_eq!(transition(true, true), Some(ChangeKind::Change));
        assert_eq!(transition(false, false), None);
    }

    #[test]
    fn group_cocok_legacy() {
        assert!(matches_group("revisions", "revisions"));
        assert!(matches_group("posts/p1/revisions", "revisions"));
        assert!(matches_group("posts_revisions", "revisions"));
        assert!(!matches_group("posts", "revisions"));
    }

    #[test]
    fn full_match_filter_and_cursor() {
        let q = opts();
        assert!(matches_full(&doc("a", 20), &q));
        assert!(!matches_full(&doc("b", 10), &q));
        let mut qc = opts();
        qc.order_by.push(hakobackend_core::OrderBy {
            field: "age".into(),
            direction: hakobackend_core::Direction::Asc,
        });
        qc.start_after = Some(serde_json::json!(20));
        assert!(!matches_full(&doc("a", 20), &qc));
        assert!(matches_full(&doc("c", 30), &qc));
    }
}

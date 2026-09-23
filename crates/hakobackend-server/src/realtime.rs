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
use tokio_stream::wrappers::BroadcastStream;
use tokio_stream::StreamExt;

/// One poller task per (db, collection), shared by all polling
/// subscriptions: a single `list` per tick no matter how many watchers.
/// Registry entry; the task prunes itself once the last receiver is gone.
static POLLERS: std::sync::OnceLock<std::sync::Mutex<HashMap<String, tokio::sync::broadcast::Sender<Vec<Doc>>>>> =
    std::sync::OnceLock::new();

/// Subscribe to the shared poller for one collection, spawning it on first
/// use. Each tick carries the FULL doc list (unfiltered — subscribers apply
/// their own filters when diffing), so a missed tick self-heals on the next.
async fn shared_poll_stream(
    db: Arc<dyn Database>,
    collection: &str,
) -> tokio::sync::broadcast::Receiver<Vec<Doc>> {
    let key = format!("{:p}/{collection}", Arc::as_ptr(&db));
    {
        let reg = POLLERS.get_or_init(Default::default).lock().unwrap();
        if let Some(tx) = reg.get(&key) {
            if tx.receiver_count() > 0 {
                return tx.subscribe();
            }
        }
    }
    let (tx, rx0) = tokio::sync::broadcast::channel(4);
    let txc = tx.clone();
    let dbc = db.clone();
    let coll = collection.to_string();
    let keyc = key.clone();
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(POLL_INTERVAL);
        loop {
            tick.tick().await;
            if txc.receiver_count() == 0 {
                if let Some(reg) = POLLERS.get() {
                    reg.lock().unwrap().remove(&keyc);
                }
                return;
            }
            let docs = dbc.list(&coll, &QueryOptions::default()).await.unwrap_or_default();
            let _ = txc.send(docs);
        }
    });
    POLLERS
        .get_or_init(Default::default)
        .lock()
        .unwrap()
        .insert(key, tx);
    rx0
}

/// Polling interval for drivers without watch (single-instance; Redis fan-out follows).
pub const POLL_INTERVAL: Duration = Duration::from_secs(2);
/// Subscription limit per WS connection (legacy backend parity).
pub const MAX_SUBS_PER_SOCKET: usize = 100;
/// Snapshot guard: a filtered universe bigger than this is rejected so one
/// greedy subscription can't OOM the server (narrow with filters instead).
pub const MAX_SNAPSHOT_DOCS: usize = 5000;
/// Fan-out guard: deliveries per subscription per second; overflow resyncs
/// the snapshot instead of queueing unboundedly.
pub const MAX_EVENTS_PER_SEC: u64 = 200;
/// Subscription budget per WS connection: 100 subs × 5000-doc snapshots
/// would be ~500k docs on one socket without this.
pub const MAX_CONN_SNAPSHOT_DOCS: usize = 20_000;
/// Batch/transaction op cap (cloudserver parity: batch ≤ 1000).
pub const MAX_BATCH_OPS: usize = 1000;
/// Aggregate reduce guard: sum/avg list into RAM — refuse past this.
pub const MAX_AGG_SCAN_DOCS: u64 = 50_000;

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
    /// Snapshot size at subscribe time (per-connection budgeting).
    pub snapshot_docs: usize,
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

/// Flood guard: counts deliveries per 1 s window; when the cap trips the
/// caller resyncs the snapshot (drop the burst, keep consistency).
struct RateGate {
    window: tokio::time::Instant,
    count: u64,
}

impl RateGate {
    fn new() -> Self {
        Self { window: tokio::time::Instant::now(), count: 0 }
    }

    fn observe(&mut self, n: u64) -> bool {
        let now = tokio::time::Instant::now();
        if now.duration_since(self.window) >= Duration::from_secs(1) {
            self.window = now;
            self.count = 0;
        }
        self.count += n;
        self.count > MAX_EVENTS_PER_SEC
    }
}

/// Re-list one collection into the snapshot (lag/flood recovery).
async fn resync_collection(
    db: &Arc<dyn Database>,
    snap_q: &QueryOptions,
    snapshot: &mut HashMap<String, Doc>,
    coll: &str,
) {
    if let Ok(docs) = db.list(coll, snap_q).await {
        let prefix = format!("{coll}\0");
        snapshot.retain(|k, _| !k.starts_with(&prefix));
        for doc in docs {
            snapshot.insert(format!("{coll}\0{}", doc.id), doc);
        }
    }
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

/// Stored collection name → logical name for policy evaluation.
fn logical_name<'a>(map: &'a HashMap<String, String>, stored: &'a str) -> &'a str {
    map.get(stored).map(|s| s.as_str()).unwrap_or(stored)
}

/// Open subscription: List gate → snapshot → per-collection watch/poll source.
/// Tenant-aware: gates and group matching run on LOGICAL names; storage and
/// snapshot keys use STORED (prefixed) names. Tenantless callers keep the
/// legacy unprefixed namespace.
pub async fn subscribe(
    db: Arc<dyn Database>,
    policy: Arc<PolicyFile>,
    auth: Option<AuthContext>,
    spec: SubSpec,
) -> Result<Subscription, AppError> {
    use hakobackend_core::tenant;
    if !hakobackend_core::valid_collection_path(&spec.collection) {
        return Err(AppError::BadRequest("invalid collection name".into()));
    }
    let owned_tenant = tenant::tenant_of(auth.as_ref());
    let tenant = owned_tenant.as_deref();
    if !policy.allow(auth.as_ref(), &spec.collection, Method::List, None) {
        return Err(AppError::PermissionDenied);
    }
    // (stored, logical) pairs downstream; policy always sees logical.
    let pairs: Vec<(String, String)> = if spec.group {
        let all = db.list_collections().await?;
        tenant::visible_collections(all, tenant)
            .into_iter()
            .filter(|(_, logical)| matches_group(logical, &spec.collection))
            .collect()
    } else {
        let stored = tenant::resolve_collection(tenant, &spec.collection);
        vec![(stored, spec.collection.clone())]
    };
    let mut collections: Vec<String> = pairs.iter().map(|(s, _)| s.clone()).collect();
    let mut logical_of: HashMap<String, String> = pairs.into_iter().collect();
    if collections.is_empty() {
        let stored = tenant::resolve_collection(tenant, &spec.collection);
        logical_of.insert(stored.clone(), spec.collection.clone());
        collections.push(stored);
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
    if snapshot.len() > MAX_SNAPSHOT_DOCS {
        return Err(AppError::BadRequest(
            "collection too large for realtime: narrow with filters".into(),
        ));
    }

    let (tx, rx) = tokio::sync::mpsc::unbounded_channel();
    let watch = db.capabilities().supports_watch;
    let snapshot_docs = snapshot.len();
    let handle = tokio::spawn(run_source(
        db, policy, auth, spec.options, collections, logical_of, snapshot, watch, tx,
    ));
    Ok(Subscription { rx, handle, snapshot_docs })
}

#[allow(clippy::too_many_arguments)]
async fn run_source(
    db: Arc<dyn Database>,
    policy: Arc<PolicyFile>,
    auth: Option<AuthContext>,
    options: QueryOptions,
    collections: Vec<String>,
    logical_of: HashMap<String, String>,
    mut snapshot: HashMap<String, Doc>,
    watch: bool,
    tx: tokio::sync::mpsc::UnboundedSender<OutEvent>,
) {
    // Policy sees logical names; storage/snapshot use stored names.
    let lf = &logical_of;
    if watch {
        // One stream per collection in a StreamMap: true push (no polling
        // sleep, no added latency), keyed so a lagged collection resyncs
        // from a fresh list instead of drifting on a skipped change.
        use tokio_stream::StreamMap;
        let mut map = StreamMap::new();
        for coll in &collections {
            if let Ok(rx) = db.subscribe(coll).await {
                map.insert(coll.clone(), BroadcastStream::new(rx));
            }
        }
        if map.is_empty() {
            return;
        }
        let snap_q = snapshot_options(&options);
        let mut gate = RateGate::new();
        loop {
            match map.next().await {
                // (collection, Ok(change)): normal path.
                Some((coll, Ok(change))) => {
                    let sent = ingest_change(
                        &policy,
                        auth.as_ref(),
                        &options,
                        &mut snapshot,
                        &coll,
                        logical_name(lf, &coll),
                        change,
                        &tx,
                    )
                    .await;
                    // Flood: drop the burst, resync, keep consistency.
                    if sent && gate.observe(1) {
                        resync_collection(&db, &snap_q, &mut snapshot, &coll).await;
                    }
                }
                // Lagged: we missed broadcasts; resync instead of drifting.
                Some((coll, Err(_))) => {
                    resync_collection(&db, &snap_q, &mut snapshot, &coll).await;
                }
                // All streams closed (bridges torn down): nothing left to hear.
                None => return,
            }
            if tx.is_closed() {
                return;
            }
        }
    } else {
        // Shared pollers (one list per collection per tick) merged back
        // into per-subscription diffs: N watchers cost 1 list, not N.
        use tokio_stream::StreamMap;
        let mut gate = RateGate::new();
        let mut map = StreamMap::new();
        for coll in &collections {
            map.insert(coll.clone(), BroadcastStream::new(shared_poll_stream(db.clone(), coll).await));
        }
        loop {
            match map.next().await {
                Some((coll, Ok(docs))) => {
                    let sent =
                        apply_diff(&policy, auth.as_ref(), &options, &mut snapshot, &logical_of, {
                            let mut fresh: HashMap<String, Doc> = HashMap::new();
                            for doc in docs {
                                fresh.insert(format!("{coll}\0{}", doc.id), doc);
                            }
                            fresh
                        }, &tx)
                        .await;
                    // Flood: the next tick carries full state, so just reset
                    // the window — the diff below already self-heals.
                    if gate.observe(sent) {
                        gate = RateGate::new();
                    }
                }
                // Lagged tick: skipped on purpose — the next tick carries
                // the full state, so the diff below self-heals.
                Some((_, Err(_))) => {}
                None => return,
            }
            if tx.is_closed() {
                return;
            }
        }
    }
}

/// Diff a fresh full-state list against the subscription snapshot,
/// delivering Add/Change/Remove per the subscription's own filters.
/// Snapshot keys are stored names; policy sees logical names.
/// Returns the number of delivered events (for the flood guard).
async fn apply_diff(
    policy: &PolicyFile,
    auth: Option<&AuthContext>,
    options: &QueryOptions,
    snapshot: &mut HashMap<String, Doc>,
    logical_of: &HashMap<String, String>,
    fresh: HashMap<String, Doc>,
    tx: &tokio::sync::mpsc::UnboundedSender<OutEvent>,
) -> u64 {
    let mut sent = 0u64;
    for (key, doc) in &fresh {
        let coll = key.split('\0').next().unwrap_or("");
        let old = snapshot.get(key);
        let old_match = old.map(|d| matches_full(d, options)).unwrap_or(false);
        let new_match = matches_full(doc, options);
        if old.map(|d| &d.data) != Some(&doc.data) || !old_match || !new_match {
            if deliver_in(policy, auth, logical_name(logical_of, coll), old, Some(doc), old_match, new_match, tx).await {
                sent += 1;
            }
        }
    }
    for (key, old) in snapshot.iter() {
        if !fresh.contains_key(key) {
            let coll = key.split('\0').next().unwrap_or("");
            if matches_full(old, options) {
                if deliver_in(policy, auth, logical_name(logical_of, coll), Some(old), None, true, false, tx).await {
                    sent += 1;
                }
            }
        }
    }
    *snapshot = fresh;
    sent
}

/// Apply one watch change to the snapshot + send on match.
/// `collection` is the stored name (snapshot keys); `policy_coll` is the
/// logical name policy rules are written against. Returns true when an
/// event was actually delivered.
async fn ingest_change(
    policy: &PolicyFile,
    auth: Option<&AuthContext>,
    options: &QueryOptions,
    snapshot: &mut HashMap<String, Doc>,
    collection: &str,
    policy_coll: &str,
    change: hakobackend_core::Change,
    tx: &tokio::sync::mpsc::UnboundedSender<OutEvent>,
) -> bool {
    // Snapshot key includes the collection (multi-collection groups safe).
    let key = format!("{collection}\0{}", change.id);
    match change.kind {
        ChangeKind::Remove => {
            if let Some(old) = snapshot.remove(&key) {
                if matches_full(&old, options) {
                    return deliver_in(policy, auth, policy_coll, Some(&old), None, true, false, tx).await;
                }
            }
            false
        }
        ChangeKind::Add | ChangeKind::Change => {
            if let Some(doc) = change.new {
                let old = snapshot.get(&key);
                let old_match = old.map(|d| matches_full(d, options)).unwrap_or(false);
                let new_match = matches_full(&doc, options);
                let sent =
                    deliver_in(policy, auth, policy_coll, old, Some(&doc), old_match, new_match, tx).await;
                snapshot.insert(key, doc);
                return sent;
            }
            false
        }
    }
}

/// Collection-aware deliver wrapper (for hierarchical rule resolution).
/// Returns true when the event reached the subscriber.
pub async fn deliver_in(
    policy: &PolicyFile,
    auth: Option<&AuthContext>,
    collection: &str,
    old: Option<&Doc>,
    new: Option<&Doc>,
    old_match: bool,
    new_match: bool,
    tx: &tokio::sync::mpsc::UnboundedSender<OutEvent>,
) -> bool {
    let Some(kind) = transition(old_match, new_match) else {
        return false;
    };
    let doc = match kind {
        ChangeKind::Add | ChangeKind::Change => new,
        ChangeKind::Remove => old,
    };
    if !policy.allow(auth, collection, Method::Get, doc) {
        return false;
    }
    tx.send(OutEvent { kind, doc: doc.cloned() }).is_ok()
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
    fn group_match_legacy() {
        assert!(matches_group("revisions", "revisions"));
        assert!(matches_group("posts/p1/revisions", "revisions"));
        assert!(matches_group("posts_revisions", "revisions"));
        assert!(!matches_group("posts", "revisions"));
    }

    /// End-to-end through the hako bridge: a Put crosses as `Change`, yet
    /// the server still emits `Add` for a first-seen id (transition comes
    /// from the server snapshot, never from the bridge kind); a delete
    /// emits `Remove`.
    #[tokio::test]
    async fn watch_end_to_end_add_then_remove() {        use hakobackend_db_hako::HakoDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_rte_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let db: Arc<dyn Database> =
            Arc::new(HakoDb::open(dir.to_string_lossy().as_ref()).unwrap());
        let policy = Arc::new(PolicyFile::open());
        let mut sub = subscribe(
            db.clone(),
            policy,
            None,
            SubSpec { collection: "rt".into(), options: QueryOptions::default(), group: false },
        )
        .await
        .unwrap();

        // Watch has no backlog: a put that lands before the bridge thread
        // starts listening is lost. Retry with fresh ids until one lands,
        // then delete that same id.
        let mut landed: Option<String> = None;
        for i in 0..8 {
            let id = if i == 0 { "a".to_string() } else { format!("a{i}") };
            db.set("rt", &id, Doc { id: id.clone(), data: Default::default() }, false)
                .await
                .unwrap();
            if let Ok(got) = tokio::time::timeout(std::time::Duration::from_secs(1), sub.rx.recv()).await {
                let ev = got.unwrap();
                assert_eq!(ev.kind, ChangeKind::Add);
                landed = Some(id);
                break;
            }
        }
        let landed = landed.expect("watch delivers the put");

        db.delete("rt", &landed).await.unwrap();
        let ev = tokio::time::timeout(std::time::Duration::from_secs(5), sub.rx.recv())
            .await
            .expect("watch delivers the delete")
            .unwrap();
        assert_eq!(ev.kind, ChangeKind::Remove);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Polling path through the shared poller (sqlite has no watch): two
    /// subscriptions on one collection share a single list per tick, and
    /// both still observe the Add.
    #[tokio::test]
    async fn poll_shared_two_subscribers_one_list() {
        use hakobackend_db_sqlite::SqliteDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_poll_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("t.db");
        let db: Arc<dyn Database> = Arc::new(SqliteDb::open(path.to_string_lossy().as_ref()).await.unwrap());
        let policy = Arc::new(PolicyFile::open());
        let spec = SubSpec { collection: "ev".into(), options: QueryOptions::default(), group: false };
        let mut s1 = subscribe(db.clone(), policy.clone(), None, spec.clone()).await.unwrap();
        let mut s2 = subscribe(db.clone(), policy, None, spec).await.unwrap();

        db.set("ev", "a", Doc { id: "a".into(), data: Default::default() }, false)
            .await
            .unwrap();
        for rx in [&mut s1.rx, &mut s2.rx] {
            let ev = tokio::time::timeout(std::time::Duration::from_secs(10), rx.recv())
                .await
                .expect("shared poller delivers to every subscriber")
                .unwrap();
            assert_eq!(ev.kind, ChangeKind::Add);
        }
        let _ = std::fs::remove_dir_all(&dir);
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

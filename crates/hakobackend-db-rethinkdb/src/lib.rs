//! RethinkDB addon driver (SPIKE): [`RethinkDb`] implements
//! [`hakobackend_core::Database`] over [`unreql`] (ReQL).
//!
//! Design (mirrors the sqlite addon, ReQL edition):
//! - one RethinkDB database per deployment (`data` DSN), one TABLE per
//!   collection. Table names allow `[A-Za-z0-9_]` only, so stored names
//!   go through a bijective codec (`-` → `_d`, `/` → `_s`, `_` → `_u`).
//!   All queries are explicitly `db`-scoped (no reliance on the session
//!   default beyond connect).
//! - documents keep a string `id` primary key; `Doc { id, data }` maps to
//!   `{id, ..data}` and back.
//! - lists push exact-set shapes to ReQL (all-eq-scalar filters as an
//!   object predicate; skip/limit on unordered non-cursor shapes) and keep
//!   driver-side filter/cursor/sort/truncate for the rest (contract §5
//!   allows this; order pushdown waits on a missing-field parity study).
//! - `set` ensures the table, then read + shallow-extend + replace
//!   (exact, like sqlite); the server already pre-merges, so the extend
//!   is idempotent.
//! - watch is a real push feed (`table.changes()` → broadcast).
//! - NO multi-doc transactions exist in RethinkDB: `run_transaction`
//!   stays at the trait default (clear reject) and
//!   `supports_transactions` is false — `/api/batch` + `/api/transaction`
//!   400 on this driver by design.
//! - secondary indexes are never unique in RethinkDB: `unique: true` is
//!   rejected clearly; field maps live in `__ub_indexes` (server
//!   `index_list` is names-only).
//!
//! Live verification against a real server is PENDING (no server in this
//! environment): the crate compiles, pure logic is unit-tested, and the
//! shared conformance suite is wired `#[ignore]` like hako's.

use std::collections::HashMap;

use hakobackend_core::{
    AppError, Capabilities, Change, ChangeKind, Database, Doc, IndexInfo, IndexKind, IndexSpec,
    QueryOptions,
};
use unreql::{cmd::connect::Options, r};

/// Index registry table (field maps; server index_list is names-only).
const INDEX_REGISTRY: &str = "__ub_indexes";

/// Tables starting with `__` never surface in `list_collections`
/// (registry + server internals, same rule as the sqlite addon).
fn is_visible_table(t: &str) -> bool {
    !t.starts_with("__")
}

pub struct RethinkDb {
    /// Reconnect recipe (never logged: carries the password).
    opts: Options,
    session: tokio::sync::Mutex<unreql::Session>,
    db: String,
    feeds: std::sync::Mutex<HashMap<String, tokio::sync::broadcast::Sender<Change>>>,
}

/// `rethinkdb://[user[:pass]@]host[:port][/db]` or bare
/// `host[:port][/db]` (default `localhost:28015`). User/password also
/// come from `RETHINKDB_USER` / `RETHINKDB_PASSWORD` (env wins).
#[derive(Debug, PartialEq)]
struct Dsn {
    host: String,
    port: u16,
    db: String,
    user: String,
    password: String,
}

fn parse_dsn(raw: &str) -> Result<Dsn, String> {
    let raw = raw.trim();
    if raw.is_empty() {
        return Err("empty rethinkdb DSN (try rethinkdb://host/db)".into());
    }
    let rest = raw.strip_prefix("rethinkdb://").unwrap_or(raw);
    let (userinfo, rest) = match rest.rsplit_once('@') {
        Some((u, tail)) => (Some(u), tail),
        None => (None, rest),
    };
    let (hostport, db) = match rest.split_once('/') {
        Some((h, d)) if !d.is_empty() => (h, d.to_string()),
        _ => (rest, String::new()),
    };
    if hostport.is_empty() {
        return Err("rethinkdb DSN needs a host".into());
    }
    let (host, port) = match hostport.rsplit_once(':') {
        Some((h, p)) => {
            let port: u16 = p.parse().map_err(|_| format!("bad rethinkdb port in `{raw}`"))?;
            (h.to_string(), port)
        }
        None => (hostport.to_string(), 28015),
    };
    if host.is_empty() {
        return Err("rethinkdb DSN needs a host".into());
    }
    let (mut user, mut password) = (String::from("admin"), String::new());
    if let Some(u) = userinfo {
        let (u, p) = match u.split_once(':') {
            Some((u, p)) => (u, p),
            None => (u, ""),
        };
        user = u.to_string();
        password = p.to_string();
    }
    if let Ok(u) = std::env::var("RETHINKDB_USER") {
        if !u.is_empty() {
            user = u;
        }
    }
    if let Ok(p) = std::env::var("RETHINKDB_PASSWORD") {
        password = p;
    }
    Ok(Dsn { host, port, db, user, password })
}

/// Bijective table codec: RethinkDB allows `[A-Za-z0-9_]` only.
/// `_` → `_u`, `-` → `_d`, `/` → `_s`; everything else passes through.
fn encode_table(stored: &str) -> String {
    let mut out = String::with_capacity(stored.len());
    for c in stored.chars() {
        match c {
            '_' => out.push_str("_u"),
            '-' => out.push_str("_d"),
            '/' => out.push_str("_s"),
            _ => out.push(c),
        }
    }
    out
}

fn decode_table(table: &str) -> Option<String> {
    let mut out = String::with_capacity(table.len());
    let mut chars = table.chars();
    while let Some(c) = chars.next() {
        if c == '_' {
            match chars.next() {
                Some('u') => out.push('_'),
                Some('d') => out.push('-'),
                Some('s') => out.push('/'),
                _ => return None,
            }
        } else {
            out.push(c);
        }
    }
    Some(out)
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("rt{nanos:x}{:x}", std::process::id())
}

fn to_rethink(doc: &Doc) -> serde_json::Value {
    let mut map: serde_json::Map<String, serde_json::Value> =
        doc.data.clone().into_iter().collect();
    map.insert("id".into(), serde_json::Value::String(doc.id.clone()));
    serde_json::Value::Object(map)
}

fn from_rethink(v: serde_json::Value) -> Option<Doc> {
    let mut map = v.as_object()?.clone();
    let id = map.remove("id")?.as_str()?.to_string();
    Some(Doc { id, data: map.into_iter().collect() })
}

/// Eq-subset the server can push: top-level, non-dotted field + non-null
/// scalar (number/string/bool). ReQL object predicates match exactly the
/// contract's Eq on such shapes (a missing field never matches either
/// side). Excluded (stay driver-side): null/array/object values (ReQL
/// null-equivalence differs), dotted paths (object predicates are
/// top-level only), every other operator.
fn pushable_eq(f: &hakobackend_core::Filter) -> Option<(String, serde_json::Value)> {
    use hakobackend_core::FilterOp;
    if !matches!(f.op, FilterOp::Eq) {
        return None;
    }
    if f.field.is_empty() || f.field.contains('.') {
        return None;
    }
    match &f.value {
        serde_json::Value::Number(_)
        | serde_json::Value::String(_)
        | serde_json::Value::Bool(_) => Some((f.field.clone(), f.value.clone())),
        _ => None,
    }
}

/// Any cursor bound present (contract cursors filter post-fetch).
fn has_cursor(q: &QueryOptions) -> bool {
    q.start_at.is_some()
        || q.start_after.is_some()
        || q.end_at.is_some()
        || q.end_before.is_some()
}

fn write_err(context: &str, v: &serde_json::Value) -> AppError {
    let errors = v.get("errors").and_then(|e| e.as_u64()).unwrap_or(1);
    if errors == 0 {
        return AppError::Internal(format!("rethinkdb: unexpected {context} result"));
    }
    let first = v.get("first_error").and_then(|e| e.as_str()).unwrap_or("write failed");
    if first.contains("Duplicate primary key") {
        return AppError::AlreadyExists;
    }
    AppError::BadRequest(format!("rethinkdb {context}: {first}"))
}

fn op_err(e: unreql::Error) -> AppError {
    let msg = e.to_string();
    if msg.contains("does not exist") {
        return AppError::NotFound;
    }
    AppError::Internal("db error".into())
}

fn missing_table(e: &unreql::Error) -> bool {
    e.to_string().contains("does not exist")
}

/// One applied write to undo (emulated-transaction rollback log entry).
struct RollbackStep {
    collection: String,
    id: String,
    prev: Option<Doc>,
}

impl RethinkDb {
    pub async fn open(data: &str) -> Result<Self, AppError> {
        let dsn = parse_dsn(data).map_err(AppError::BadRequest)?;
        let mut opts = Options::default();
        opts.host = dsn.host.clone().into();
        opts.port = dsn.port;
        if !dsn.db.is_empty() {
            opts.db = dsn.db.clone().into();
        }
        opts.user = dsn.user.clone().into();
        opts.password = dsn.password.clone().into();
        let session = r
            .connect(opts.clone())
            .await
            .map_err(|_| AppError::Internal("rethinkdb connect failed".into()))?;
        let db = if dsn.db.is_empty() { "test".to_string() } else { dsn.db };
        // Ensure the database exists (idempotent; race = harmless error).
        let created: Result<serde_json::Value, _> = r.db_create(db.clone()).exec(&session).await;
        if let Err(e) = created {
            if !e.to_string().contains("already exists") {
                return Err(AppError::Internal("rethinkdb db_create failed".into()));
            }
        }
        let this = Self {
            opts: opts.clone(),
            session: tokio::sync::Mutex::new(session),
            db,
            feeds: std::sync::Mutex::new(HashMap::new()),
        };
        this.ensure_registry().await;
        Ok(this)
    }
}

/// Transport failures (broken pipe, I/O) get one reconnect-and-retry;
/// ReQL logic errors never retry (they would fail identically).
fn is_conn_err(e: &unreql::Error) -> bool {
    matches!(
        e,
        unreql::Error::Driver(unreql::Driver::ConnectionBroken)
            | unreql::Error::Driver(unreql::Driver::Io(..))
    )
}

impl RethinkDb {
    /// One query connection from the shared session.
    async fn conn(&self) -> Result<unreql::Connection, unreql::Error> {
        self.session.lock().await.clone().connection()
    }

    /// Swap in a fresh session (transport died); returns a connection on it.
    async fn reconnect(&self) -> Result<unreql::Connection, unreql::Error> {
        let fresh = r.connect(self.opts.clone()).await?;
        *self.session.lock().await = fresh;
        self.session.lock().await.clone().connection()
    }

    /// Run one single-result query, reconnecting once on transport
    /// failure. ReQL logic errors never retry (identical failure).
    async fn exec_one<T>(&self, q: unreql::Command) -> Result<T, unreql::Error>
    where
        T: Unpin + serde::de::DeserializeOwned,
    {
        match q.clone().exec(self.conn().await?).await {
            Err(e) if is_conn_err(&e) => q.exec(self.reconnect().await?).await,
            other => other,
        }
    }

    /// Same for sequence queries (exec_to_vec shape).
    async fn exec_all<T>(&self, q: unreql::Command) -> Result<Vec<T>, unreql::Error>
    where
        T: Unpin + serde::de::DeserializeOwned,
    {
        match q.clone().exec_to_vec(self.conn().await?).await {
            Err(e) if is_conn_err(&e) => q.exec_to_vec(self.reconnect().await?).await,
            other => other,
        }
    }

    /// Feeds get their OWN session: a dying changefeed must never poison
    /// queries (proven live: a closed feed killed the shared session —
    /// unreql marks feed-used sessions, so sharing was never viable).
    async fn feed_session(&self) -> Result<unreql::Session, AppError> {
        r.connect(self.opts.clone())
            .await
            .map_err(|_| AppError::Internal("rethinkdb feed connect failed".into()))
    }

    /// Raw table write used by the emulated transaction (no gate, no
    /// merge recompute — the caller prepared the final body).
    async fn raw_put(&self, collection: &str, id: &str, doc: &Doc, existed: bool) -> Result<(), AppError> {
        let table = encode_table(collection);
        let body = to_rethink(doc);
        let res: serde_json::Value = if existed {
            self.exec_one(
                r.db(self.db.clone()).table(table.clone()).get(id.to_string()).replace(body),
            )
            .await
            .map_err(|_| AppError::Internal("db error".into()))?
        } else {
            self.exec_one(r.db(self.db.clone()).table(table.clone()).insert(body))
                .await
                .map_err(|_| AppError::Internal("db error".into()))?
        };
        if res.get("errors").and_then(|e| e.as_u64()).unwrap_or(0) > 0 {
            return Err(write_err("tx put", &res));
        }
        Ok(())
    }

    async fn raw_delete(&self, collection: &str, id: &str) -> Result<(), AppError> {
        let table = encode_table(collection);
        let id = id.to_string();
        let res: serde_json::Value = self
            .exec_one(r.db(self.db.clone()).table(table.clone()).get(id.clone()).delete(()))
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        if res.get("errors").and_then(|e| e.as_u64()).unwrap_or(0) > 0 {
            return Err(write_err("tx delete", &res));
        }
        Ok(())
    }

    /// Best-effort inverse rollback (fire and forget the failures —
    /// the original error is what the caller sees).
    async fn rollback(&self, done: Vec<RollbackStep>) {
        for d in done.into_iter().rev() {
            match d.prev {
                // Restore: replace-or-insert (the apply phase may itself
                // have deleted the doc before failing).
                Some(doc) => {
                    let table = encode_table(&d.collection);
                    let body = to_rethink(&doc);
                    let resp: Result<serde_json::Value, _> = self
                        .exec_one(
                            r.db(self.db.clone())
                                .table(table.clone())
                                .get(d.id.clone())
                                .replace(body.clone()),
                        )
                        .await;
                    if resp.is_err() {
                        let _: Result<serde_json::Value, _> = self
                            .exec_one(r.db(self.db.clone()).table(table.clone()).insert(body))
                            .await;
                    }
                }
                None => {
                    let _ = self.raw_delete(&d.collection, &d.id).await;
                }
            }
        }
    }
}

#[async_trait::async_trait]
impl Database for RethinkDb {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            driver: "rethinkdb",
            supports_watch: true,
            // Emulated (see run_transaction): validation + sequential
            // apply + best-effort rollback. Atomic except under
            // concurrent conflicting writes mid-batch.
            supports_transactions: true,
            supports_composite: false,
            supports_fts: false,
            supports_drop_index: true,
            supports_unique: false,
            supports_named_index: true,
            supports_native_aggregation: false,
        }
    }

    async fn ensure_collection(&self, path: &str) -> Result<(), AppError> {
        let table = encode_table(path);
        let res: Result<serde_json::Value, _> =
            self.exec_one(r.db(self.db.clone()).table_create(table.clone())).await;
        match res {
            Ok(_) => Ok(()),
            Err(e) if e.to_string().contains("already exists") => Ok(()),
            Err(_) => Err(AppError::Internal("db error".into())),
        }
    }

    async fn list_collections(&self) -> Result<Vec<String>, AppError> {
        // Sequence queries stream items one by one: exec_to_vec, never
        // exec (exec takes only the first item and mangles the rest).
        let tables: Vec<String> = self
            .exec_all(r.db(self.db.clone()).table_list())
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        Ok(tables
            .into_iter()
            .filter(|t| is_visible_table(t))
            .filter_map(|t| decode_table(&t))
            .collect())
    }

    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let table = encode_table(collection);
        let id = id.to_string();
        match self
            .exec_one::<Option<serde_json::Value>>(
                r.db(self.db.clone()).table(table.clone()).get(id.clone()),
            )
            .await
        {
            Ok(v) => Ok(v.and_then(from_rethink)),
            Err(e) if missing_table(&e) => Ok(None),
            Err(_) => Err(AppError::Internal("db error".into())),
        }
    }

    async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
        use hakobackend_core::conformance::{doc_matches, matches_cursor, sort_and_limit};
        let table = encode_table(collection);
        // Exact-set pushdown: eq scalars narrow server-side. Partial is
        // safe (superset fetch; the driver still filters every row below).
        // Paging pushes only with no cursor and no order: cursors filter
        // post-fetch, and ReQL-vs-contract ordering parity on
        // missing/mixed-type fields is unverified — the driver re-sorts +
        // truncates instead (same rows, contract order guaranteed).
        let mut pushed = serde_json::Map::new();
        for f in &q.filters {
            if let Some((k, v)) = pushable_eq(f) {
                pushed.insert(k, v);
            }
        }
        let push_page = !has_cursor(q) && q.order_by.is_empty();
        let mut cmd = r.db(self.db.clone()).table(table.clone());
        if !pushed.is_empty() {
            cmd = cmd.filter(serde_json::Value::Object(pushed));
        }
        if push_page {
            if let Some(n) = q.offset {
                cmd = cmd.skip(n);
            }
            if let Some(n) = q.limit {
                cmd = cmd.limit(n);
            }
        }
        let rows: Vec<serde_json::Value> = match self.exec_all(cmd).await {
            Ok(v) => v,
            Err(e) if missing_table(&e) => return Ok(vec![]),
            Err(_) => return Err(AppError::Internal("db error".into())),
        };
        let docs: Vec<Doc> = rows
            .into_iter()
            .filter_map(from_rethink)
            .filter(|d| doc_matches(d, &q.filters) && matches_cursor(d, q))
            .collect();
        Ok(sort_and_limit(docs, q))
    }

    async fn insert(&self, collection: &str, mut doc: Doc) -> Result<Doc, AppError> {
        if doc.id.is_empty() {
            doc.id = uuid_like();
        }
        // The conformance suite inserts into fresh collections without a
        // prior ensure (like the other drivers): create on demand.
        self.ensure_collection(collection).await?;
        let table = encode_table(collection);
        let res: serde_json::Value = self
            .exec_one(r.db(self.db.clone()).table(table.clone()).insert(to_rethink(&doc)))
            .await
            .map_err(|e| {
                if missing_table(&e) {
                    AppError::BadRequest(format!("collection `{collection}` does not exist"))
                } else {
                    AppError::Internal("db error".into())
                }
            })?;
        // RethinkDB reports conflicts in-band (errors/first_error), not as throws.
        if res.get("errors").and_then(|e| e.as_u64()).unwrap_or(0) > 0 {
            return Err(write_err("insert", &res));
        }
        Ok(doc)
    }

    async fn set(&self, collection: &str, id: &str, doc: Doc, merge: bool) -> Result<Doc, AppError> {
        // Like sqlite: the table exists before we touch it.
        self.ensure_collection(collection).await?;
        let table = encode_table(collection);
        let prev = self.get(collection, id).await?;
        let existed = prev.is_some();
        let data = match prev {
            Some(p) if merge => {
                // Shallow top-level merge (contract §3); the server already
                // pre-merges, so this extend is idempotent, not a second merge.
                let mut base = p.data;
                base.extend(doc.data);
                base
            }
            Some(_) => doc.data,
            None => doc.data,
        };
        let final_doc = Doc { id: id.to_string(), data };
        let body = to_rethink(&final_doc);
        // Replace when present (insert would conflict), insert when absent.
        let res: serde_json::Value = if existed {
            self.exec_one(
                r.db(self.db.clone())
                    .table(table.clone())
                    .get(id.to_string())
                    .replace(body.clone()),
            )
            .await
            .map_err(|_| AppError::Internal("db error".into()))?
        } else {
            self.exec_one(r.db(self.db.clone()).table(table.clone()).insert(body.clone()))
                .await
                .map_err(|_| AppError::Internal("db error".into()))?
        };
        // A conflict here is a concurrent write racing our read — surface
        // it instead of silently winning.
        if res.get("errors").and_then(|e| e.as_u64()).unwrap_or(0) > 0 {
            return Err(write_err("set", &res));
        }
        Ok(final_doc)
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let prev = self.get(collection, id).await?;
        if prev.is_none() {
            return Ok(None);
        }
        let table = encode_table(collection);
        let id = id.to_string();
        let res: serde_json::Value = self
            .exec_one(r.db(self.db.clone()).table(table.clone()).get(id.clone()).delete(()))
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        if res.get("errors").and_then(|e| e.as_u64()).unwrap_or(0) > 0 {
            return Err(write_err("delete", &res));
        }
        Ok(prev)
    }

    async fn count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError> {
        // Native count with the same eq pushdown — but unlike list(),
        // partial is NOT safe (nothing narrows after a count). All filters
        // pushable (or none) + no cursor + no paging, else the legacy path.
        // Missing tables count 0 (legacy list().len() parity).
        if has_cursor(q) || q.limit.is_some() || q.offset.is_some() {
            return Ok(self.list(collection, q).await?.len() as u64);
        }
        let mut pushed = serde_json::Map::new();
        for f in &q.filters {
            match pushable_eq(f) {
                Some((k, v)) => {
                    pushed.insert(k, v);
                }
                None => return Ok(self.list(collection, q).await?.len() as u64),
            }
        }
        let table = encode_table(collection);
        let mut cmd = r.db(self.db.clone()).table(table.clone());
        if !pushed.is_empty() {
            cmd = cmd.filter(serde_json::Value::Object(pushed));
        }
        match self.exec_one::<u64>(cmd.count(())).await {
            Ok(n) => Ok(n),
            Err(e) if missing_table(&e) => Ok(0),
            Err(_) => Err(AppError::Internal("db error".into())),
        }
    }

    /// Emulated transaction (RethinkDB has no multi-doc transactions):
    /// validate everything first (must_exist aborts before anything is
    /// applied), then apply sequentially with an overlay so reads observe
    /// the batch's own writes. An apply-phase failure triggers
    /// best-effort inverse rollback and returns the original error.
    /// Truly atomic except under concurrent conflicting writes mid-batch
    /// (documented in driver.toml + capabilities).
    async fn run_transaction(&self, ops: Vec<hakobackend_core::TxOp>) -> Result<Vec<hakobackend_core::TxOut>, AppError> {
        use hakobackend_core::{TxOpKind, TxOut};
        use std::collections::hash_map::Entry;
        // Phase 1: gather current state (also fails fast on missing tables
        // for must_exist — reads tolerate absence).
        struct Seen {
            prev: Option<Doc>,
        }
        let mut seen: HashMap<(String, String), Seen> = HashMap::new();
        for op in &ops {
            let key = (op.collection.clone(), op.id.clone());
            if let Entry::Vacant(e) = seen.entry(key) {
                let prev = self.get(&op.collection, &op.id).await?;
                if matches!(op.kind, TxOpKind::Put { must_exist: true, .. }) && prev.is_none() {
                    return Err(AppError::NotFound);
                }
                e.insert(Seen { prev });
            }
        }
        // Phase 2: apply in order over an overlay.
        // Tables first (phase-1 reads tolerate absence; writes don't).
        {
            let mut tables: Vec<&str> = vec![];
            for op in &ops {
                if !tables.contains(&op.collection.as_str()) {
                    tables.push(&op.collection);
                }
            }
            for t in tables {
                self.ensure_collection(t).await?;
            }
        }
        let mut overlay: HashMap<(String, String), Option<Doc>> = HashMap::new();
        // Inverse log for best-effort rollback.
        let mut done: Vec<RollbackStep> = Vec::new();
        let mut outs: Vec<TxOut> = Vec::with_capacity(ops.len());
        let at = |overlay: &HashMap<(String, String), Option<Doc>>, seen: &HashMap<(String, String), Seen>, coll: &str, id: &str| -> Option<Doc> {
            let key = (coll.to_string(), id.to_string());
            match overlay.get(&key) {
                Some(v) => v.clone(),
                None => seen.get(&key).and_then(|s| s.prev.clone()),
            }
        };
        for op in &ops {
            match &op.kind {
                TxOpKind::Read => {
                    let doc = at(&overlay, &seen, &op.collection, &op.id);
                    outs.push(TxOut { existed: doc.is_some(), doc });
                }
                TxOpKind::Delete => {
                    let prev = at(&overlay, &seen, &op.collection, &op.id);
                    if prev.is_some() {
                        if let Err(e) = self.raw_delete(&op.collection, &op.id).await {
                            self.rollback(done).await;
                            return Err(e);
                        }
                        done.push(RollbackStep { collection: op.collection.clone(), id: op.id.clone(), prev: prev.clone() });
                    }
                    outs.push(TxOut { existed: prev.is_some(), doc: prev });
                }
                TxOpKind::Put { merge, .. } => {
                    let mut id = op.id.clone();
                    if id.is_empty() {
                        id = uuid_like();
                    }
                    let base = at(&overlay, &seen, &op.collection, &id).map(|d| d.data).unwrap_or_default();
                    let raw = op.doc.as_ref().map(|d| d.data.clone()).unwrap_or_default();
                    let mut data = if *merge {
                        let mut m = base;
                        m.extend(raw);
                        m
                    } else {
                        raw
                    };
                    // Stamps like the single-write paths (server preprocesses
                    // too; belt and suspenders for direct driver use).
                    data = hakobackend_core::atomics::stamp_update(data, None);
                    let prev = at(&overlay, &seen, &op.collection, &id);
                    let existed = prev.is_some();
                    let final_doc = Doc { id: id.clone(), data };
                    if let Err(e) = self.raw_put(&op.collection, &id, &final_doc, existed).await {
                        self.rollback(done).await;
                        return Err(e);
                    }
                    done.push(RollbackStep { collection: op.collection.clone(), id: id.clone(), prev });
                    overlay.insert((op.collection.clone(), id.clone()), Some(final_doc.clone()));
                    outs.push(TxOut { existed, doc: Some(final_doc) });
                }
            }
        }
        Ok(outs)
    }

    async fn subscribe(&self, collection: &str) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
        use std::collections::hash_map::Entry;
        let table = encode_table(collection);
        let logical = collection.to_string();
        if let Some(tx) = self.feeds.lock().unwrap().get(&table).cloned() {
            return Ok(tx.subscribe());
        }
        // Dedicated session BEFORE taking the lock (feed death must never
        // touch the query session, and no lock is held across await).
        let session = self.feed_session().await?;
        let (tx, _rx) = tokio::sync::broadcast::channel::<Change>(256);
        match self.feeds.lock().unwrap().entry(table.clone()) {
            Entry::Vacant(e) => {
                e.insert(tx.clone());
            }
            // Raced with another subscriber: use theirs, drop ours.
            Entry::Occupied(e) => return Ok(e.get().subscribe()),
        }
        let db = self.db.clone();
        let feed_tx = tx.clone();
        tokio::spawn(async move {
            use futures::StreamExt;
            let mut feed = r.db(db.clone()).table(table.clone()).changes(()).run::<_, serde_json::Value>(&session);
            while let Some(item) = feed.next().await {
                let ev = match item {
                    Ok(v) => v,
                    Err(e) => {
                        eprintln!("[rethinkdb] changefeed for {table} failed: {e}");
                        break;
                    }
                };
                let obj = match ev.as_object() {
                    Some(o) => o,
                    None => continue,
                };
                if obj.contains_key("state") {
                    continue;
                }
                let val = |k: &str| {
                    obj.get(k).and_then(|v| {
                        if v.is_null() {
                            None
                        } else {
                            from_rethink(v.clone())
                        }
                    })
                };
                let (kind, id) = match (val("old_val"), val("new_val")) {
                    (None, Some(n)) => (ChangeKind::Add, n.id.clone()),
                    (Some(o), None) => (ChangeKind::Remove, o.id.clone()),
                    (Some(_), Some(n)) => (ChangeKind::Change, n.id.clone()),
                    (None, None) => continue,
                };
                let _ = feed_tx.send(Change {
                    collection: logical.clone(),
                    id,
                    kind,
                    old: val("old_val"),
                    new: val("new_val"),
                });
            }
            eprintln!("[rethinkdb] changefeed for {table} ended");
        });
        Ok(tx.subscribe())
    }

    async fn create_index(&self, collection: &str, spec: &IndexSpec) -> Result<IndexInfo, AppError> {
        hakobackend_core::conformance::validate_spec(self.capabilities(), spec)?;
        if spec.unique {
            return Err(AppError::BadRequest("rethinkdb secondary indexes are never unique".into()));
        }
        if spec.kind != IndexKind::Simple {
            return Err(AppError::BadRequest("rethinkdb spike supports simple indexes only".into()));
        }
        let field = spec.fields.first().cloned().unwrap_or_default();
        let table = encode_table(collection);
        self.ensure_collection(collection).await?;
        let name =
            spec.name.clone().unwrap_or_else(|| hakobackend_core::conformance::auto_index_name(spec));
        // Bare index_create(name) indexes the same-named field (ReQL default).
        let res: serde_json::Value = self
            .exec_one(r.db(self.db.clone()).table(table.clone()).index_create(name.clone()))
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        if res.get("errors").and_then(|e| e.as_u64()).unwrap_or(0) > 0 {
            return Err(write_err("index_create", &res));
        }
        let info = IndexInfo {
            name: name.clone(),
            fields: vec![field.clone()],
            unique: false,
            kind: IndexKind::Simple,
        };
        self.registry_put(&table, &info).await?;
        Ok(info)
    }

    async fn list_indexes(&self, collection: &str) -> Result<Vec<IndexInfo>, AppError> {
        let table = encode_table(collection);
        let server: Vec<String> = match self
            .exec_all(r.db(self.db.clone()).table(table.clone()).index_list())
            .await
        {
                Ok(v) => v,
                Err(e) if missing_table(&e) => return Ok(vec![]),
                Err(_) => return Err(AppError::Internal("db error".into())),
            };
        // Intersect the registry with what the server actually has
        // (out-of-band drops vanish instead of lingering).
        let mut out = Vec::new();
        for name in server {
            if let Some(info) = self.registry_get(&table, &name).await? {
                out.push(info);
            }
        }
        Ok(out)
    }

    async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError> {
        let table = encode_table(collection);
        let name = name.to_string();
        let res: Result<serde_json::Value, _> = self
            .exec_one(r.db(self.db.clone()).table(table.clone()).index_drop(name.clone()))
            .await;
        match res {
            Ok(v) if v.get("errors").and_then(|e| e.as_u64()).unwrap_or(0) > 0 => {
                return Err(write_err("index_drop", &v))
            }
            Err(e) => return Err(op_err(e)),
            _ => {}
        }
        self.registry_del(&table, &name).await?;
        Ok(())
    }
}

impl RethinkDb {
    /// Index field registry (`__ub_indexes` table): server index_list is
    /// names-only, so the field map lives here. Best-effort: registry
    /// failures never fail the index op itself (the server stays
    /// authoritative for existence; list just loses field detail).
    async fn registry_put(&self, table: &str, info: &IndexInfo) -> Result<(), AppError> {
        let doc = Doc {
            id: format!("{table}/{}", info.name),
            data: [
                ("table".to_string(), serde_json::Value::String(table.into())),
                ("name".to_string(), serde_json::Value::String(info.name.clone())),
                (
                    "fields".to_string(),
                    serde_json::Value::Array(
                        info.fields.iter().map(|f| serde_json::Value::String(f.clone())).collect(),
                    ),
                ),
            ]
            .into_iter()
            .collect(),
        };
        let body = to_rethink(&doc);
        // Upsert: read-then-write (registry rows are operator-owned, low contention).
        let existing: Option<serde_json::Value> = self
            .exec_one::<Option<serde_json::Value>>(
                r.db(self.db.clone()).table(INDEX_REGISTRY.to_string()).get(doc.id.clone()),
            )
            .await
            .unwrap_or(None);
        let res: serde_json::Value = if existing.is_some() {
            self.exec_one(
                r.db(self.db.clone())
                    .table(INDEX_REGISTRY.to_string())
                    .get(doc.id.clone())
                    .replace(body.clone()),
            )
            .await
            .map_err(|_| AppError::Internal("db error".into()))?
        } else {
            self.exec_one(
                r.db(self.db.clone()).table(INDEX_REGISTRY.to_string()).insert(body.clone()),
            )
            .await
            .map_err(|_| AppError::Internal("db error".into()))?
        };
        if res.get("errors").and_then(|e| e.as_u64()).unwrap_or(0) > 0 {
            return Err(write_err("index registry", &res));
        }
        Ok(())
    }

    async fn registry_get(&self, table: &str, name: &str) -> Result<Option<IndexInfo>, AppError> {
        let id = format!("{table}/{name}");
        let v: Option<serde_json::Value> = self
            .exec_one::<Option<serde_json::Value>>(
                r.db(self.db.clone()).table(INDEX_REGISTRY.to_string()).get(id.clone()),
            )
            .await
            .unwrap_or(None);
        Ok(v.and_then(|v| {
            let o = v.as_object()?;
            Some(IndexInfo {
                name: name.to_string(),
                fields: o
                    .get("fields")?
                    .as_array()?
                    .iter()
                    .filter_map(|f| f.as_str().map(str::to_string))
                    .collect(),
                unique: false,
                kind: IndexKind::Simple,
            })
        }))
    }

    async fn registry_del(&self, table: &str, name: &str) -> Result<(), AppError> {
        let id = format!("{table}/{name}");
        let _: serde_json::Value = self
            .exec_one(
                r.db(self.db.clone())
                    .table(INDEX_REGISTRY.to_string())
                    .get(id.clone())
                    .delete(()),
            )
            .await
            .unwrap_or(serde_json::Value::Null);
        Ok(())
    }

    /// Best-effort registry bootstrap (missing table = first index op).
    async fn ensure_registry(&self) {
        let res: Result<serde_json::Value, _> =
            self.exec_one(r.db(self.db.clone()).table_create(INDEX_REGISTRY)).await;
        if let Err(e) = res {
            if !e.to_string().contains("already exists") {
                eprintln!("[rethinkdb] registry bootstrap failed: {e}");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn table_codec_roundtrip() {
        for s in ["users", "acme__users", "acme-1__posts", "posts/rev/2", "a_b-c/d"] {
            let enc = encode_table(s);
            assert!(enc.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'), "{enc}");
            assert_eq!(decode_table(&enc).as_deref(), Some(s));
        }
        assert_eq!(encode_table("acme__users"), "acme_u_uusers");
        assert_eq!(decode_table("nope__x"), None);
    }

    #[test]
    fn dsn_shapes() {
        let full = parse_dsn("rethinkdb://u:p@db.internal:28016/hako").unwrap();
        assert_eq!(
            full,
            Dsn {
                host: "db.internal".into(),
                port: 28016,
                db: "hako".into(),
                user: "u".into(),
                password: "p".into()
            }
        );
        let bare = parse_dsn("db.internal/hako").unwrap();
        assert_eq!(bare.port, 28015);
        assert_eq!(bare.db, "hako");
        let host_only = parse_dsn("localhost").unwrap();
        assert_eq!((host_only.port, host_only.db.as_str()), (28015, ""));
        assert!(parse_dsn("").is_err());
        assert!(parse_dsn("rethinkdb://h:notaport/db").is_err());
    }

    #[test]
    fn doc_conversion_roundtrip() {
        let doc = Doc {
            id: "a".into(),
            data: [("x".to_string(), serde_json::json!(1))].into_iter().collect(),
        };
        let v = to_rethink(&doc);
        assert_eq!(v.get("id"), Some(&serde_json::json!("a")));
        assert_eq!(from_rethink(v).unwrap().id, "a");
        assert!(from_rethink(serde_json::Value::Null).is_none());
    }

    #[test]
    fn pushable_eq_shapes() {
        use hakobackend_core::{Filter, FilterOp};
        let f = |field: &str, op: FilterOp, value: serde_json::Value| Filter {
            field: field.into(),
            op,
            value,
        };
        // Pushable: top-level eq scalars (id included).
        assert_eq!(
            pushable_eq(&f("age", FilterOp::Eq, serde_json::json!(30))),
            Some(("age".into(), serde_json::json!(30)))
        );
        assert!(pushable_eq(&f("id", FilterOp::Eq, serde_json::json!("a"))).is_some());
        assert!(pushable_eq(&f("ok", FilterOp::Eq, serde_json::json!(true))).is_some());
        // Not pushable: other ops, null/array/object, dotted paths, empty field.
        assert!(pushable_eq(&f("age", FilterOp::Gt, serde_json::json!(30))).is_none());
        assert!(pushable_eq(&f("age", FilterOp::In, serde_json::json!([30]))).is_none());
        assert!(pushable_eq(&f("age", FilterOp::Eq, serde_json::Value::Null)).is_none());
        assert!(pushable_eq(&f("age", FilterOp::Eq, serde_json::json!([1]))).is_none());
        assert!(pushable_eq(&f("a.b", FilterOp::Eq, serde_json::json!(1))).is_none());
        assert!(pushable_eq(&f("", FilterOp::Eq, serde_json::json!(1))).is_none());
        // Cursor detection.
        let mut q = QueryOptions::default();
        assert!(!has_cursor(&q));
        q.start_after = Some(serde_json::json!(1));
        assert!(has_cursor(&q));
    }

    #[test]
    fn write_result_mapping() {
        assert!(matches!(
            write_err("insert", &serde_json::json!({"errors": 1, "first_error": "Duplicate primary key `a`"})),
            AppError::AlreadyExists
        ));
        assert!(matches!(
            write_err("insert", &serde_json::json!({"errors": 1, "first_error": "nope"})),
            AppError::BadRequest(_)
        ));
    }

    /// Shared conformance suite — needs a live server (same `#[ignore]`
    /// convention as the hako addon). DSN via `RDB_DSN` env
    /// (e.g. `rethinkdb://admin:secret@localhost/testdb`).
    #[tokio::test]
    #[ignore]
    async fn conformance_live() {
        let dsn = std::env::var("RDB_DSN").unwrap_or_else(|_| "localhost/hakobackend_spike".into());
        let db = RethinkDb::open(&dsn).await.unwrap();
        hakobackend_core::conformance::run_conformance_suite(&db).await;
        hakobackend_core::conformance::run_index_suite(&db).await;
    }
}

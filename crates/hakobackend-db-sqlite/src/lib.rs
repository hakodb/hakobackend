//! hakobackend-db-sqlite: SQLite addon via sqlx (file or :memory:).
//!
//! Postgres-pattern diffusion: generic JSON table per collection (flat name),
//! subcollections + `_collectionPath`, index registry `__ub_indexes`.
//! Dialect: `json_extract`, `?` placeholders, FTS5 external-content + triggers.

use std::collections::{HashMap, HashSet};
use hakobackend_core::{AppError, Capabilities, Change, Database, Direction, Doc, Filter, FilterOp, IndexInfo, IndexKind, IndexSpec, QueryOptions};

const PATH_FIELD: &str = "_collectionPath";

pub struct SqliteDb {
    pool: sqlx::SqlitePool,
    verified: tokio::sync::Mutex<HashSet<String>>,
}

impl SqliteDb {
    pub async fn open(path: &str) -> Result<Self, AppError> {
        use sqlx::sqlite::SqliteConnectOptions;
        use std::str::FromStr;
        let opts = SqliteConnectOptions::from_str(if path.is_empty() { ":memory:" } else { path })
            .map_err(|_| AppError::BadRequest("invalid sqlite DSN".into()))?
            .create_if_missing(true);
        // :memory: = 1 connection (each pool connection owns its own DB!).
        let max = if path.is_empty() || path == ":memory:" { 1 } else { 5 };
        let pool = sqlx::sqlite::SqlitePoolOptions::new()
            .max_connections(max)
            .connect_with(opts)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        let db = Self { pool, verified: tokio::sync::Mutex::new(HashSet::new()) };
        db.ensure_registry().await?;
        Ok(db)
    }

    async fn ensure_registry(&self) -> Result<(), AppError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS \"__ub_indexes\" (collection TEXT NOT NULL, name TEXT NOT NULL, fields TEXT NOT NULL, \"unique\" INTEGER NOT NULL DEFAULT 0, kind TEXT NOT NULL, ddl TEXT NOT NULL DEFAULT '', PRIMARY KEY (collection, name))",
        )
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::Internal("db error".into()))?;
        // Tolerant migration: legacy tables without the ddl column.
        let sql: String = sqlx::query("SELECT sql FROM sqlite_master WHERE name = '__ub_indexes'")
            .fetch_one(&self.pool)
            .await
            .map_err(|_| AppError::Internal("db error".into()))
            .map(|r| {
                use sqlx::Row;
                r.get("sql")
            })?;
        if !sql.contains("ddl") {
            sqlx::query("ALTER TABLE \"__ub_indexes\" ADD COLUMN ddl TEXT NOT NULL DEFAULT ''")
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
        }
        Ok(())
    }

    async fn ensure_table(&self, table: &str) -> Result<(), AppError> {
        {
            let g = self.verified.lock().await;
            if g.contains(table) {
                return Ok(());
            }
        }
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data TEXT NOT NULL DEFAULT '{{}}')",
            table = qi(table)
        ))
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::Internal("db error".into()))?;
        self.verified.lock().await.insert(table.to_string());
        Ok(())
    }
}

// --- Pure SQL helpers (unit-tested without a DB) ---

fn qi(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// JSON path: "a.b" → `json_extract(data, '$."a"."b"')`.
fn jpath(field: &str) -> String {
    let segs: Vec<String> = field.split('.').map(|s| format!("\"{}\"", s.replace('"', "\"\""))).collect();
    format!("json_extract(data, '$.{}')", segs.join("."))
}

/// Bound param: number→REAL, string→TEXT, bool→INTEGER, null→special IS NULL.
enum P {
    F(f64),
    T(String),
    I(i64),
}

fn to_param(v: &serde_json::Value) -> Option<P> {
    match v {
        serde_json::Value::Null => None,
        serde_json::Value::Bool(b) => Some(P::I(*b as i64)),
        serde_json::Value::Number(n) => Some(P::F(n.as_f64().unwrap_or(0.0))),
        serde_json::Value::String(s) => Some(P::T(s.clone())),
        serde_json::Value::Array(_) | serde_json::Value::Object(_) => None,
    }
}

fn push_filter(sql: &mut String, f: &Filter, params: &mut Vec<P>) -> Result<(), AppError> {
    let col = jpath(&f.field);
    match f.op {
        FilterOp::Eq => match to_param(&f.value) {
            Some(p) => {
                sql.push_str(&format!("{col} = ?"));
                params.push(p);
            }
            // Eq null/object: NULL is never == ; objects/arrays lack comparison support.
            None if f.value.is_null() => sql.push_str(&format!("{col} IS NULL")),
            None => sql.push_str("FALSE"),
        },
        // Contract parity: a missing field = true for Ne (SQL NULL needs an explicit OR).
        FilterOp::Ne => match to_param(&f.value) {
            Some(p) => {
                sql.push_str(&format!("({col} <> ? OR {col} IS NULL)"));
                params.push(p);
            }
            None => sql.push_str(&format!("{col} IS NOT NULL")),
        },
        FilterOp::Gt => {
            let Some(p) = to_param(&f.value) else {
                return Err(AppError::BadRequest("comparison needs a scalar".into()));
            };
            sql.push_str(&format!("{col} > ?"));
            params.push(p);
        }
        FilterOp::Gte => {
            let Some(p) = to_param(&f.value) else {
                return Err(AppError::BadRequest("comparison needs a scalar".into()));
            };
            sql.push_str(&format!("{col} >= ?"));
            params.push(p);
        }
        FilterOp::Lt => {
            let Some(p) = to_param(&f.value) else {
                return Err(AppError::BadRequest("comparison needs a scalar".into()));
            };
            sql.push_str(&format!("{col} < ?"));
            params.push(p);
        }
        FilterOp::Lte => {
            let Some(p) = to_param(&f.value) else {
                return Err(AppError::BadRequest("comparison needs a scalar".into()));
            };
            sql.push_str(&format!("{col} <= ?"));
            params.push(p);
        }
        FilterOp::In => {
            let arr = f.value.as_array().ok_or_else(|| AppError::BadRequest("in needs an array".into()))?;
            let mut parts = Vec::new();
            for v in arr {
                match to_param(v) {
                    Some(p) => {
                        parts.push(format!("{col} = ?"));
                        params.push(p);
                    }
                    None => parts.push(format!("{col} IS NULL")),
                }
            }
            if parts.is_empty() {
                sql.push_str("FALSE");
            } else {
                sql.push_str(&format!("({})", parts.join(" OR ")));
            }
        }
        // json_each: uniform across all scalar types (no string assumption).
        FilterOp::ArrayContains => {
            let Some(p) = to_param(&f.value) else {
                return Err(AppError::BadRequest("array-contains needs a scalar".into()));
            };
            sql.push_str(&format!("EXISTS (SELECT 1 FROM json_each(data, '$.{field}') WHERE value = ?)", field = f.field.replace('\'', "''")));
            params.push(p);
        }
        FilterOp::ArrayContainsAny => {
            let arr = f.value.as_array().ok_or_else(|| AppError::BadRequest("array-contains-any needs an array".into()))?;
            if arr.is_empty() {
                sql.push_str("FALSE");
                return Ok(());
            }
            let mut parts = Vec::new();
            for v in arr {
                let Some(p) = to_param(v) else {
                    return Err(AppError::BadRequest("array-contains-any needs scalars".into()));
                };
                parts.push(format!("EXISTS (SELECT 1 FROM json_each(data, '$.{field}') WHERE value = ?)", field = f.field.replace('\'', "''")));
                params.push(p);
            }
            sql.push_str(&format!("({})", parts.join(" OR ")));
        }
    }
    Ok(())
}

fn build_where(collection: &str, q: &QueryOptions) -> Result<(String, Vec<P>), AppError> {
    let mut filters = Vec::new();
    let mut params = Vec::new();
    if collection.contains('/') {
        filters.push(format!("json_extract(data, '$.\"{PATH_FIELD}\"') = ?"));
        params.push(P::T(collection.into()));
    }
    for f in &q.filters {
        let mut frag = String::new();
        push_filter(&mut frag, f, &mut params)?;
        filters.push(frag);
    }
    push_cursor(&mut filters, q, &mut params);
    let where_ = if filters.is_empty() { String::new() } else { format!(" WHERE {}", filters.join(" AND ")) };
    Ok((where_, params))
}

/// Cursor fragment: typed bounds like filters (REAL/TEXT/INTEGER).
/// Null/object bounds → FALSE (incomparable = drop everything, contract parity).
fn push_cursor(filters: &mut Vec<String>, q: &QueryOptions, params: &mut Vec<P>) {
    let field = hakobackend_core::conformance::cursor_field(q);
    let mut bound = |op: &str, v: &serde_json::Value| {
        if field == "id" {
            match v.as_str() {
                Some(s) => {
                    filters.push(format!("id {op} ?"));
                    params.push(P::T(s.into()));
                }
                None => filters.push("FALSE".into()),
            }
            return;
        }
        match to_param(v) {
            Some(p) => {
                filters.push(format!("{} {op} ?", jpath(field)));
                params.push(p);
            }
            None => filters.push("FALSE".into()),
        }
    };
    if let Some(v) = &q.start_at {
        bound(">=", v);
    }
    if let Some(v) = &q.start_after {
        bound(">", v);
    }
    if let Some(v) = &q.end_at {
        bound("<=", v);
    }
    if let Some(v) = &q.end_before {
        bound("<", v);
    }
}

/// LIMIT/OFFSET for SQLite: OFFSET needs LIMIT (use -1 = unbounded).
fn build_page(q: &QueryOptions) -> String {
    match (q.limit, q.offset) {
        (Some(n), Some(o)) => format!(" LIMIT {n} OFFSET {o}"),
        (Some(n), None) => format!(" LIMIT {n}"),
        (None, Some(o)) => format!(" LIMIT -1 OFFSET {o}"),
        (None, None) => String::new(),
    }
}

fn build_order(q: &QueryOptions) -> String {
    if q.order_by.is_empty() {
        return String::new();
    }
    let parts: Vec<String> = q
        .order_by
        .iter()
        .map(|o| {
            format!(
                "{} {}",
                jpath(&o.field),
                match o.direction {
                    Direction::Asc => "ASC",
                    Direction::Desc => "DESC",
                }
            )
        })
        .collect();
    format!(" ORDER BY {}", parts.join(", "))
}

fn to_doc(id: String, mut data: HashMap<String, serde_json::Value>) -> Doc {
    data.remove(PATH_FIELD);
    Doc { id, data }
}

fn inject_path(data: &mut HashMap<String, serde_json::Value>, collection: &str) {
    if collection.contains('/') {
        data.insert(PATH_FIELD.into(), serde_json::Value::String(collection.into()));
    }
}

fn parse_data(text: &str) -> HashMap<String, serde_json::Value> {
    serde_json::from_str::<serde_json::Value>(text)
        .ok()
        .and_then(|v| v.as_object().cloned())
        .map(|m| m.into_iter().collect())
        .unwrap_or_default()
}

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("sq{nanos:x}{:x}", std::process::id())
}

fn safe_index_name(table: &str, spec: &IndexSpec) -> String {
    // FTS tables use the internal `__fts_` prefix to stay hidden from list_collections.
    let base = spec.name.clone().unwrap_or_else(|| match spec.kind {
        IndexKind::Simple => format!("idx_{}_{}", table, spec.fields.join("_")),
        IndexKind::Composite => format!("idx_{}_{}", table, spec.fields.join("_")),
        // One FTS table per field (deterministic name, internal prefix to stay hidden).
        IndexKind::FullText => format!("__fts_{}_{}", table, spec.fields.join("_")),
    });
    base.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect()
}

macro_rules! bind_params {
    ($q:ident, $params:expr) => {
        for p in $params {
            $q = match p {
                P::F(f) => $q.bind(f),
                P::T(s) => $q.bind(s),
                P::I(i) => $q.bind(i),
            };
        }
    };
}

impl SqliteDb {
    /// Transactional variants: same SQL as the pool methods, but every
    /// statement runs on `&mut Transaction` (reborrowed per statement).
    /// Tables are ensured by the caller, never here.
    async fn get_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        collection: &str,
        id: &str,
    ) -> Result<Option<Doc>, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        let mut sql = format!("SELECT id, data FROM {} WHERE id = ?1", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND json_extract(data, '$.\"{PATH_FIELD}\"') = ?2"));
        }
        let mut q = sqlx::query(&sql).bind(id);
        if collection.contains('/') {
            q = q.bind(collection);
        }
        let row: Option<(String, String)> = q
            .fetch_optional(&mut **tx)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?
            .map(|r| {
                use sqlx::Row;
                (r.get::<String, _>("id"), r.get::<String, _>("data"))
            });
        Ok(row.map(|(id, text)| to_doc(id, parse_data(&text))))
    }

    async fn insert_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        collection: &str,
        mut doc: Doc,
    ) -> Result<Doc, AppError> {
        if doc.id.is_empty() {
            doc.id = uuid_like();
        }
        let table = hakobackend_core::flat_table_name(collection);
        inject_path(&mut doc.data, collection);
        let text = serde_json::Value::Object(doc.data.clone().into_iter().collect()).to_string();
        let r = sqlx::query(&format!("INSERT INTO {} (id, data) VALUES (?1, ?2) ON CONFLICT (id) DO NOTHING", qi(&table)))
            .bind(&doc.id)
            .bind(&text)
            .execute(&mut **tx)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        if r.rows_affected() == 0 {
            return Err(AppError::AlreadyExists);
        }
        doc.data.remove(PATH_FIELD);
        Ok(doc)
    }

    /// Returns the written doc plus whether it existed before this op.
    async fn set_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        collection: &str,
        id: &str,
        body: std::collections::HashMap<String, serde_json::Value>,
        merge: bool,
        must_exist: bool,
    ) -> Result<(Doc, bool), AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        let old = Self::get_tx(&mut *tx, collection, id).await?;
        if must_exist && old.is_none() {
            return Err(AppError::NotFound);
        }
        let existed = old.is_some();
        let mut data = if merge { old.map(|d| d.data).unwrap_or_default() } else { Default::default() };
        data.extend(body);
        inject_path(&mut data, collection);
        let text = serde_json::Value::Object(data.clone().into_iter().collect()).to_string();
        if merge {
            let mut sql = format!("UPDATE {} SET data = ?1 WHERE id = ?2", qi(&table));
            let mut q = sqlx::query(&sql).bind(&text).bind(id);
            if collection.contains('/') {
                sql.push_str(&format!(" AND json_extract(data, '$.\"{PATH_FIELD}\"') = ?3"));
                q = sqlx::query(&sql).bind(&text).bind(id).bind(collection);
            }
            let r = q.execute(&mut **tx).await.map_err(|_| AppError::Internal("db error".into()))?;
            if r.rows_affected() == 0 {
                let doc = Self::insert_tx(&mut *tx, collection, Doc { id: id.into(), data }).await?;
                return Ok((doc, existed));
            }
        } else {
            sqlx::query(&format!(
                "INSERT INTO {} (id, data) VALUES (?1, ?2) ON CONFLICT (id) DO UPDATE SET data = excluded.data",
                qi(&table)
            ))
            .bind(id)
            .bind(&text)
            .execute(&mut **tx)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        }
        data.remove(PATH_FIELD);
        Ok((Doc { id: id.into(), data }, existed))
    }

    async fn delete_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::Sqlite>,
        collection: &str,
        id: &str,
    ) -> Result<Option<Doc>, AppError> {
        let prev = Self::get_tx(&mut *tx, collection, id).await?;
        if prev.is_none() {
            return Ok(None);
        }
        let table = hakobackend_core::flat_table_name(collection);
        let mut sql = format!("DELETE FROM {} WHERE id = ?1", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND json_extract(data, '$.\"{PATH_FIELD}\"') = ?2"));
        }
        let mut q = sqlx::query(&sql).bind(id);
        if collection.contains('/') {
            q = q.bind(collection);
        }
        q.execute(&mut **tx).await.map_err(|_| AppError::Internal("db error".into()))?;
        Ok(prev)
    }
}

#[async_trait::async_trait]
impl Database for SqliteDb {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            driver: "sqlite",
            supports_watch: false,
            supports_transactions: true,
            supports_composite: true,
            supports_fts: true,
            supports_drop_index: true,
            supports_unique: true,
            supports_named_index: true,
        }
    }

    async fn ensure_collection(&self, path: &str) -> Result<(), AppError> {
        self.ensure_table(&hakobackend_core::flat_table_name(path)).await
    }

    async fn list_collections(&self) -> Result<Vec<String>, AppError> {
        // Internal `__*` collections (sessions, registry, FTS tables) are not exposed over HTTP.
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE '\\_%' ESCAPE '\\' AND name NOT LIKE 'sqlite_%'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::Internal("db error".into()))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        let mut sql = format!("SELECT id, data FROM {} WHERE id = ?1", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND json_extract(data, '$.\"{PATH_FIELD}\"') = ?2"));
        }
        let mut q = sqlx::query(&sql).bind(id);
        if collection.contains('/') {
            q = q.bind(collection);
        }
        let row: Option<(String, String)> = q
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?
            .map(|r| {
                use sqlx::Row;
                (r.get::<String, _>("id"), r.get::<String, _>("data"))
            });
        Ok(row.map(|(id, text)| to_doc(id, parse_data(&text))))
    }

    async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        let (where_, params) = build_where(collection, q)?;
        let mut sql = format!("SELECT id, data FROM {}{}", qi(&table), where_);
        sql.push_str(&build_order(q));
        sql.push_str(&build_page(q));
        let mut query = sqlx::query(&sql);
        bind_params!(query, params);
        let rows = query.fetch_all(&self.pool).await.map_err(|_| AppError::Internal("db error".into()))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                use sqlx::Row;
                let id: String = r.get("id");
                let text: String = r.get("data");
                to_doc(id, parse_data(&text))
            })
            .collect())
    }

    async fn insert(&self, collection: &str, mut doc: Doc) -> Result<Doc, AppError> {
        if doc.id.is_empty() {
            doc.id = uuid_like();
        }
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        inject_path(&mut doc.data, collection);
        let text = serde_json::Value::Object(doc.data.clone().into_iter().collect()).to_string();
        let r = sqlx::query(&format!("INSERT INTO {} (id, data) VALUES (?1, ?2) ON CONFLICT (id) DO NOTHING", qi(&table)))
            .bind(&doc.id)
            .bind(&text)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        if r.rows_affected() == 0 {
            return Err(AppError::AlreadyExists);
        }
        doc.data.remove(PATH_FIELD);
        Ok(doc)
    }

    async fn set(&self, collection: &str, id: &str, mut doc: Doc, merge: bool) -> Result<Doc, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        inject_path(&mut doc.data, collection);
        if merge {
            // Shallow top-level merge in Rust (json_patch = deep-merge, wrong semantics).
            let mut base = self
                .get(collection, id)
                .await?
                .map(|old| old.data)
                .unwrap_or_default();
            base.extend(doc.data);
            doc.data = base;
        }
        let text = serde_json::Value::Object(doc.data.clone().into_iter().collect()).to_string();
        if merge {
            let mut sql = format!("UPDATE {} SET data = ?1 WHERE id = ?2", qi(&table));
            let mut q = sqlx::query(&sql).bind(&text).bind(id);
            if collection.contains('/') {
                sql.push_str(&format!(" AND json_extract(data, '$.\"{PATH_FIELD}\"') = ?3"));
                q = sqlx::query(&sql).bind(&text).bind(id).bind(collection);
            }
            let r = q.execute(&self.pool).await.map_err(|_| AppError::Internal("db error".into()))?;
            if r.rows_affected() == 0 {
                return self.insert(collection, Doc { id: id.into(), data: doc.data }).await;
            }
        } else {
            let text = serde_json::Value::Object(doc.data.clone().into_iter().collect()).to_string();
            sqlx::query(&format!(
                "INSERT INTO {} (id, data) VALUES (?1, ?2) ON CONFLICT (id) DO UPDATE SET data = excluded.data",
                qi(&table)
            ))
            .bind(id)
            .bind(&text)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        }
        doc.data.remove(PATH_FIELD);
        Ok(Doc { id: id.into(), data: doc.data })
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let prev = self.get(collection, id).await?;
        if prev.is_none() {
            return Ok(None);
        }
        let table = hakobackend_core::flat_table_name(collection);
        let mut sql = format!("DELETE FROM {} WHERE id = ?1", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND json_extract(data, '$.\"{PATH_FIELD}\"') = ?2"));
        }
        let mut q = sqlx::query(&sql).bind(id);
        if collection.contains('/') {
            q = q.bind(collection);
        }
        q.execute(&self.pool).await.map_err(|_| AppError::Internal("db error".into()))?;
        Ok(prev)
    }

    async fn run_transaction(&self, ops: Vec<hakobackend_core::TxOp>) -> Result<Vec<hakobackend_core::TxOut>, AppError> {
        use hakobackend_core::{TxOpKind, TxOut};
        // Tables first (DDL outside the tx; sqlite allows it inside, but one
        // code path for all three SQL drivers beats per-driver cleverness).
        for op in &ops {
            self.ensure_table(&hakobackend_core::flat_table_name(&op.collection)).await?;
        }
        let mut tx = self.pool.begin().await.map_err(|_| AppError::Internal("db error".into()))?;
        let mut out = Vec::with_capacity(ops.len());
        for op in ops {
            match op.kind {
                TxOpKind::Read => {
                    let doc = Self::get_tx(&mut tx, &op.collection, &op.id).await?;
                    out.push(TxOut { existed: doc.is_some(), doc });
                }
                TxOpKind::Put { merge, must_exist } => {
                    let body = op.doc.map(|d| d.data).unwrap_or_default();
                    let (doc, existed) =
                        Self::set_tx(&mut tx, &op.collection, &op.id, body, merge, must_exist).await?;
                    out.push(TxOut { existed, doc: Some(doc) });
                }
                TxOpKind::Delete => {
                    let old = Self::delete_tx(&mut tx, &op.collection, &op.id).await?;
                    out.push(TxOut { existed: old.is_some(), doc: old });
                }
            }
        }
        tx.commit().await.map_err(|_| AppError::Internal("db error".into()))?;
        Ok(out)
    }


    async fn count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        let (where_, params) = build_where(collection, q)?;
        let sql = format!("SELECT COUNT(*) as c FROM {}{}", qi(&table), where_);
        let mut query = sqlx::query(&sql);
        bind_params!(query, params);
        let row = query.fetch_one(&self.pool).await.map_err(|_| AppError::Internal("db error".into()))?;
        use sqlx::Row;
        Ok(row.get::<i64, _>("c") as u64)
    }

    async fn subscribe(&self, _collection: &str) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
        Ok(tokio::sync::broadcast::channel(256).0.subscribe())
    }

    async fn create_index(&self, collection: &str, spec: &IndexSpec) -> Result<IndexInfo, AppError> {
        hakobackend_core::conformance::validate_spec(self.capabilities(), spec)?;
        if spec.unique && spec.kind == IndexKind::FullText {
            return Err(AppError::BadRequest("fts cannot be unique".into()));
        }
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        // Logical name (contract, deterministic across drivers) vs physical (DDL per table).
        let logical = spec.name.clone().unwrap_or_else(|| hakobackend_core::conformance::auto_index_name(spec));
        let physical = safe_index_name(&table, spec);
        let unique = if spec.unique { "UNIQUE " } else { "" };
        match spec.kind {
            IndexKind::Simple | IndexKind::Composite => {
                let exprs: Vec<String> = spec.fields.iter().map(|f| jpath(f)).collect();
                sqlx::query(&format!(
                    "CREATE {unique}INDEX IF NOT EXISTS {name} ON {table} ({exprs})",
                    name = qi(&physical),
                    table = qi(&table),
                    exprs = exprs.join(", ")
                ))
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
            }
            IndexKind::FullText => {
                // FTS5 external-content: 1 field; triggers keep it in sync.
                let f = &spec.fields[0];
                let path = format!("$.\"{}\"", f.replace('"', "\"\""));
                sqlx::query(&format!("CREATE VIRTUAL TABLE IF NOT EXISTS {name} USING fts5(content, content={table}, content_rowid=\"rowid\")", name = qi(&physical), table = qi(&table)))
                    .execute(&self.pool)
                    .await
                    .map_err(|_| AppError::Internal("db error (fts5 needs an fts-enabled sqlite build)".into()))?;
                for (trg, when, body) in [
                    ("ai", "AFTER INSERT", format!("INSERT INTO {name}(rowid, content) VALUES (new.rowid, json_extract(new.data, '{path}'))", name = qi(&physical))),
                    ("ad", "AFTER DELETE", format!("INSERT INTO {name}({name}, rowid, content) VALUES ('delete', old.rowid, json_extract(old.data, '{path}'))", name = qi(&physical))),
                    ("au", "AFTER UPDATE", format!("INSERT INTO {name}({name}, rowid, content) VALUES ('delete', old.rowid, json_extract(old.data, '{path}')); INSERT INTO {name}(rowid, content) VALUES (new.rowid, json_extract(new.data, '{path}'))", name = qi(&physical))),
                ] {
                    let tname = format!("{physical}_{trg}");
                    sqlx::query(&format!(
                        "CREATE TRIGGER IF NOT EXISTS {tname} {when} ON {table} BEGIN {body}; END",
                        tname = qi(&tname),
                        table = qi(&table)
                    ))
                    .execute(&self.pool)
                    .await
                    .map_err(|_| AppError::Internal("db error".into()))?;
                }
            }
        }
        let fields_json = serde_json::Value::Array(spec.fields.iter().map(|f| serde_json::Value::String(f.clone())).collect())
            .to_string();
        let kind = match spec.kind {
            IndexKind::Simple => "simple",
            IndexKind::Composite => "composite",
            IndexKind::FullText => "fts",
        };
        sqlx::query("INSERT INTO \"__ub_indexes\" (collection, name, fields, \"unique\", kind, ddl) VALUES (?1,?2,?3,?4,?5,?6) ON CONFLICT (collection, name) DO UPDATE SET fields = excluded.fields, \"unique\" = excluded.\"unique\", kind = excluded.kind, ddl = excluded.ddl")
            .bind(collection)
            .bind(&logical)
            .bind(&fields_json)
            .bind(if spec.unique { 1 } else { 0 })
            .bind(kind)
            .bind(&physical)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        Ok(IndexInfo { name: logical, fields: spec.fields.clone(), unique: spec.unique, kind: spec.kind })
    }

    async fn list_indexes(&self, collection: &str) -> Result<Vec<IndexInfo>, AppError> {
        self.ensure_registry().await?;
        let rows = sqlx::query("SELECT name, fields, \"unique\", kind FROM \"__ub_indexes\" WHERE collection = ?1")
            .bind(collection)
            .fetch_all(&self.pool)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        use sqlx::Row;
        Ok(rows
            .into_iter()
            .map(|r| {
                let kind = match r.get::<String, _>("kind").as_str() {
                    "composite" => IndexKind::Composite,
                    "fts" => IndexKind::FullText,
                    _ => IndexKind::Simple,
                };
                let fields: Vec<String> = serde_json::from_str::<serde_json::Value>(&r.get::<String, _>("fields"))
                    .ok()
                    .and_then(|v| v.as_array().cloned())
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                IndexInfo { name: r.get("name"), fields, unique: r.get::<i64, _>("unique") != 0, kind }
            })
            .collect())
    }

    async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError> {
        self.ensure_registry().await?;
        let row: Option<(String, String)> = sqlx::query("SELECT kind, ddl FROM \"__ub_indexes\" WHERE collection = ?1 AND name = ?2")
            .bind(collection)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?
            .map(|r| {
                use sqlx::Row;
                (r.get("kind"), r.get("ddl"))
            });
        let (kind, ddl) = match row {
            Some((k, d)) if !d.is_empty() => (k, d),
            _ => return Err(AppError::NotFound),
        };
        if kind == "fts" {
            for t in ["ai", "ad", "au"] {
                sqlx::query(&format!("DROP TRIGGER IF EXISTS {}", qi(&format!("{ddl}_{t}"))))
                    .execute(&self.pool)
                    .await
                    .map_err(|_| AppError::Internal("db error".into()))?;
            }
            sqlx::query(&format!("DROP TABLE IF EXISTS {}", qi(&ddl)))
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
        } else {
            sqlx::query(&format!("DROP INDEX IF EXISTS {}", qi(&ddl)))
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
        }
        sqlx::query("DELETE FROM \"__ub_indexes\" WHERE collection = ?1 AND name = ?2")
            .bind(collection)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(field: &str, op: FilterOp, value: serde_json::Value) -> Filter {
        Filter { field: field.into(), op, value }
    }

    fn frag(f: &Filter) -> (String, Vec<String>) {
        let mut sql = String::new();
        let mut params = Vec::new();
        push_filter(&mut sql, f, &mut params).unwrap();
        let dbg: Vec<String> = params
            .iter()
            .map(|p| match p {
                P::F(x) => format!("F({x})"),
                P::T(s) => format!("T({s})"),
                P::I(i) => format!("I({i})"),
            })
            .collect();
        (sql, dbg)
    }

    #[test]
    fn filter_sqlite_parity() {
        // Numbers bind REAL (30 = 30.0), strings TEXT, bools INTEGER.
        let (s, p) = frag(&filter("age", FilterOp::Eq, serde_json::json!(30)));
        assert_eq!(s, "json_extract(data, '$.\"age\"') = ?");
        assert_eq!(p, vec!["F(30)"]);
        let (s, p) = frag(&filter("aktif", FilterOp::Eq, serde_json::json!(true)));
        assert_eq!(p, vec!["I(1)"]);
        assert!(s.ends_with("= ?"));
        // Ne over a missing field = true via OR IS NULL (contract parity).
        let (s, _) = frag(&filter("x", FilterOp::Ne, serde_json::json!(1)));
        assert!(s.contains("OR") && s.contains("IS NULL"));
        // Eq null → IS NULL; array-contains via uniform json_each.
        let (s, _) = frag(&filter("x", FilterOp::Eq, serde_json::json!(null)));
        assert!(s.contains("IS NULL"));
        let (s, p) = frag(&filter("tags", FilterOp::ArrayContains, serde_json::json!("a")));
        assert!(s.starts_with("EXISTS") && p == vec!["T(a)"]);
        let (s, p) = frag(&filter("n", FilterOp::In, serde_json::json!([1, "x"])));
        assert!(s.contains(" OR "));
        assert_eq!(p, vec!["F(1)", "T(x)"]);
    }

    #[test]
    fn identifier_quoted() {
        assert_eq!(qi("a\"b"), "\"a\"\"b\"");
        assert_eq!(jpath("a.b"), "json_extract(data, '$.\"a\".\"b\"')");
    }

    /// Full conformance needs live sqlite (file/:memory:) — runs without a server.
    #[tokio::test]
    async fn conformance_sqlite_memory() {
        let db = SqliteDb::open(":memory:").await.unwrap();
        hakobackend_core::conformance::run_conformance_suite(&db).await;
        hakobackend_core::conformance::run_index_suite(&db).await;
    }
}

//! hakobackend-db-mysql: MySQL/MariaDB addon via sqlx (pool).
//!
//! Postgres-pattern diffusion: generic JSON table per collection (flat name).
//! Dialect: `JSON_EXTRACT(data, path) = CAST(? AS JSON)` comparison
//! (type-strict across numbers/strings/bools — contract parity).
//! FTS via generated STORED columns + FULLTEXT (managed by the driver, `__fts_` prefix).

use std::collections::{HashMap, HashSet};
use hakobackend_core::{AppError, Capabilities, Change, Database, Direction, Doc, Filter, FilterOp, IndexInfo, IndexKind, IndexSpec, QueryOptions};

const PATH_FIELD: &str = "_collectionPath";

pub struct MysqlDb {
    pool: sqlx::MySqlPool,
    verified: tokio::sync::Mutex<HashSet<String>>,
}

impl MysqlDb {
    pub async fn open(dsn: &str) -> Result<Self, AppError> {
        let pool = sqlx::mysql::MySqlPoolOptions::new()
            .max_connections(10)
            .connect(dsn)
            .await
            .map_err(|_| AppError::Internal("db error".into()))?;
        let db = Self { pool, verified: tokio::sync::Mutex::new(HashSet::new()) };
        db.ensure_registry().await?;
        Ok(db)
    }

    async fn ensure_registry(&self) -> Result<(), AppError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS `__ub_indexes` (collection VARCHAR(255) NOT NULL, name VARCHAR(191) NOT NULL, fields TEXT NOT NULL, `unique` BOOLEAN NOT NULL DEFAULT FALSE, kind VARCHAR(16) NOT NULL, ddl VARCHAR(191) NOT NULL DEFAULT '', PRIMARY KEY (collection(191), name))",
        )
        .execute(&self.pool)
        .await
        .map_err(|_| AppError::Internal("db error".into()))?;
        // Tolerant migration: legacy tables without the ddl column.
        let has: Option<String> = sqlx::query(
            "SELECT COLUMN_NAME FROM INFORMATION_SCHEMA.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = '__ub_indexes' AND COLUMN_NAME = 'ddl'",
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AppError::Internal("db error".into()))?
        .map(|r| {
            use sqlx::Row;
            r.get("COLUMN_NAME")
        });
        if has.is_none() {
            sqlx::query("ALTER TABLE `__ub_indexes` ADD COLUMN ddl VARCHAR(191) NOT NULL DEFAULT ''")
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
        }
        Ok(())
    }

    /// Find an index by logical name (used for idempotent create).
    async fn find_index(&self, collection: &str, name: &str) -> Result<Option<IndexInfo>, AppError> {
        self.ensure_registry().await?;
        let row: Option<(String, String, i8, String)> =
            sqlx::query("SELECT name, fields, `unique`, kind FROM `__ub_indexes` WHERE collection = ? AND name = ?")
                .bind(collection)
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?
                .map(|r| {
                    use sqlx::Row;
                    (r.get("name"), r.get("fields"), r.get("unique"), r.get("kind"))
                });
        Ok(row.map(|(name, fields_json, unique, kind_s)| {
            let kind = match kind_s.as_str() {
                "composite" => IndexKind::Composite,
                "fts" => IndexKind::FullText,
                _ => IndexKind::Simple,
            };
            let fields: Vec<String> = serde_json::from_str::<serde_json::Value>(&fields_json)
                .ok()
                .and_then(|v| v.as_array().cloned())
                .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                .unwrap_or_default();
            IndexInfo { name, fields, unique: unique != 0, kind }
        }))
    }

    async fn ensure_table(&self, table: &str) -> Result<(), AppError> {
        {
            let g = self.verified.lock().await;
            if g.contains(table) {
                return Ok(());
            }
        }
        sqlx::query(&format!(
            "CREATE TABLE IF NOT EXISTS {table} (id VARCHAR(255) PRIMARY KEY, data JSON NOT NULL, createdAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP, updatedAt TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)",
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
    format!("`{}`", name.replace('`', "``"))
}

/// JSON path: "a.b" → `$."a"."b"`. Backslashes escaped first so a
/// hostile field can't smuggle path escapes (`\"` collapsing).
fn jpath(field: &str) -> String {
    let segs: Vec<String> = field
        .split('.')
        .map(|s| format!("\"{}\"", s.replace('\\', "\\\\").replace('"', "\\\"")))
        .collect();
    format!("$.{}", segs.join("."))
}

/// Extraction: `JSON_EXTRACT(data, '$."a"."b"')`.
fn jcol(field: &str) -> String {
    format!("JSON_EXTRACT(data, '{}')", jpath(field).replace('\'', "''"))
}

/// Value as JSON text for `CAST(? AS JSON)` (type-strict comparison).
fn json_text(v: &serde_json::Value) -> Option<String> {
    match v {
        serde_json::Value::Null | serde_json::Value::Array(_) | serde_json::Value::Object(_) => None,
        _ => Some(v.to_string()),
    }
}

fn push_filter(sql: &mut String, f: &Filter, params: &mut Vec<String>) -> Result<(), AppError> {
    let col = jcol(&f.field);
    let cmp = |sql: &mut String, op: &str, v: &serde_json::Value, params: &mut Vec<String>| {
        sql.push_str(&format!("{col} {op} CAST(? AS JSON)"));
        params.push(v.to_string());
    };
    match f.op {
        FilterOp::Eq => match json_text(&f.value) {
            Some(_) => cmp(sql, "=", &f.value, params),
            // Eq null/object: NULL is never == ; objects/arrays lack comparison support.
            None if f.value.is_null() => sql.push_str(&format!("{col} IS NULL")),
            None => sql.push_str("FALSE"),
        },
        // Contract parity: a missing field = true for Ne.
        FilterOp::Ne => match json_text(&f.value) {
            Some(_) => {
                sql.push_str(&format!("({col} <> CAST(? AS JSON) OR {col} IS NULL)"));
                params.push(f.value.to_string());
            }
            None => sql.push_str(&format!("{col} IS NOT NULL")),
        },
        FilterOp::Gt => {
            json_text(&f.value).ok_or_else(|| AppError::BadRequest("comparison needs a scalar".into()))?;
            cmp(sql, ">", &f.value, params);
        }
        FilterOp::Gte => {
            json_text(&f.value).ok_or_else(|| AppError::BadRequest("comparison needs a scalar".into()))?;
            cmp(sql, ">=", &f.value, params);
        }
        FilterOp::Lt => {
            json_text(&f.value).ok_or_else(|| AppError::BadRequest("comparison needs a scalar".into()))?;
            cmp(sql, "<", &f.value, params);
        }
        FilterOp::Lte => {
            json_text(&f.value).ok_or_else(|| AppError::BadRequest("comparison needs a scalar".into()))?;
            cmp(sql, "<=", &f.value, params);
        }
        FilterOp::In => {
            let arr = f.value.as_array().ok_or_else(|| AppError::BadRequest("in needs an array".into()))?;
            let mut parts = Vec::new();
            for v in arr {
                match json_text(v) {
                    Some(_) => {
                        parts.push(format!("{col} = CAST(? AS JSON)"));
                        params.push(v.to_string());
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
        // Uniform JSON_CONTAINS (no string assumption).
        FilterOp::ArrayContains => {
            json_text(&f.value).ok_or_else(|| AppError::BadRequest("array-contains needs a scalar".into()))?;
            sql.push_str(&format!("JSON_CONTAINS({col}, CAST(? AS JSON))"));
            params.push(f.value.to_string());
        }
        FilterOp::ArrayContainsAny => {
            let arr = f.value.as_array().ok_or_else(|| AppError::BadRequest("array-contains-any needs an array".into()))?;
            if arr.is_empty() {
                sql.push_str("FALSE");
                return Ok(());
            }
            let mut parts = Vec::new();
            for v in arr {
                json_text(v).ok_or_else(|| AppError::BadRequest("array-contains-any needs scalars".into()))?;
                parts.push(format!("JSON_CONTAINS({col}, CAST(? AS JSON))"));
                params.push(v.to_string());
            }
            sql.push_str(&format!("({})", parts.join(" OR ")));
        }
    }
    Ok(())
}

fn build_where(collection: &str, q: &QueryOptions) -> Result<(String, Vec<String>), AppError> {
    let mut filters = Vec::new();
    let mut params = Vec::new();
    if collection.contains('/') {
        filters.push(format!("JSON_UNQUOTE(JSON_EXTRACT(data, '$.\"{PATH_FIELD}\"')) = ?"));
        params.push(collection.to_string());
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

/// Cursor fragment: `col OP CAST(? AS JSON)` (type-strict, contract parity).
/// Null/object bounds → FALSE. `id` = a plain text column.
fn push_cursor(filters: &mut Vec<String>, q: &QueryOptions, params: &mut Vec<String>) {
    let field = hakobackend_core::conformance::cursor_field(q);
    let mut bound = |op: &str, v: &serde_json::Value| {
        if field == "id" {
            match v.as_str() {
                Some(s) => {
                    filters.push(format!("id {op} ?"));
                    params.push(s.to_string());
                }
                None => filters.push("FALSE".into()),
            }
            return;
        }
        match json_text(v) {
            Some(_) => {
                filters.push(format!("{} {op} CAST(? AS JSON)", jcol(field)));
                params.push(v.to_string());
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

/// LIMIT/OFFSET for MySQL: without count use 2^64-1 (unbounded).
fn build_page(q: &QueryOptions) -> String {
    match (q.limit, q.offset) {
        (Some(n), Some(o)) => format!(" LIMIT {n} OFFSET {o}"),
        (Some(n), None) => format!(" LIMIT {n}"),
        (None, Some(o)) => format!(" LIMIT 18446744073709551615 OFFSET {o}"),
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
            // `id` is a real column (never inside the JSON body).
            let col = if o.field == "id" { "id".to_string() } else { jcol(&o.field) };
            format!(
                "{} {}",
                col,
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
    format!("my{nanos:x}{:x}", std::process::id())
}

/// Safe physical name (<=60 chars). FTS uses a `__fts_*` generated column per index.
fn safe_index_name(table: &str, spec: &IndexSpec) -> String {
    let base = spec.name.clone().unwrap_or_else(|| match spec.kind {
        IndexKind::Simple => format!("idx_{}_{}", table, spec.fields.join("_")),
        IndexKind::Composite => format!("idx_{}_{}", table, spec.fields.join("_")),
        IndexKind::FullText => format!("ft_{}_{}", table, spec.fields.join("_")),
    });
    base.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).take(60).collect::<String>()
}

fn fts_column(physical: &str) -> String {
    format!("__fts_{physical}")
}

/// Unique-violation mapping: concurrent same-value writes race past any
/// read-check, so the DB constraint is the arbiter — translate it back.
fn constraint_err(e: sqlx::Error) -> AppError {
    let conflict = matches!(e, sqlx::Error::Database(ref d) if d.code().as_deref() == Some("1062"));
    if conflict {
        AppError::AlreadyExists
    } else {
        AppError::Internal("db error".into())
    }
}

impl MysqlDb {
    async fn get_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        collection: &str,
        id: &str,
    ) -> Result<Option<Doc>, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        let mut sql = format!("SELECT id, CAST(data AS CHAR) as data FROM {} WHERE id = ?", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.\"{PATH_FIELD}\"')) = ?"));
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
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        collection: &str,
        mut doc: Doc,
    ) -> Result<Doc, AppError> {
        if doc.id.is_empty() {
            doc.id = uuid_like();
        }
        let table = hakobackend_core::flat_table_name(collection);
        inject_path(&mut doc.data, collection);
        let text = serde_json::Value::Object(doc.data.clone().into_iter().collect()).to_string();
        let r = sqlx::query(&format!("INSERT IGNORE INTO {} (id, data) VALUES (?, ?)", qi(&table)))
            .bind(&doc.id)
            .bind(&text)
            .execute(&mut **tx)
            .await
            .map_err(constraint_err)?;
        if r.rows_affected() == 0 {
            return Err(AppError::AlreadyExists);
        }
        doc.data.remove(PATH_FIELD);
        Ok(doc)
    }

    /// Returns the written doc plus whether it existed before this op.
    async fn set_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
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
            let mut sql = format!("UPDATE {} SET data = ? WHERE id = ?", qi(&table));
            let mut q = sqlx::query(&sql).bind(&text).bind(id);
            if collection.contains('/') {
                sql.push_str(&format!(" AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.\"{PATH_FIELD}\"')) = ?"));
                q = sqlx::query(&sql).bind(&text).bind(id).bind(collection);
            }
            let r = q.execute(&mut **tx).await.map_err(constraint_err)?;
            if r.rows_affected() == 0 {
                let doc = Self::insert_tx(&mut *tx, collection, Doc { id: id.into(), data }).await?;
                return Ok((doc, existed));
            }
        } else {
            sqlx::query(&format!(
                "INSERT INTO {} (id, data) VALUES (?, ?) ON DUPLICATE KEY UPDATE data = VALUES(data)",
                qi(&table)
            ))
            .bind(id)
            .bind(&text)
            .execute(&mut **tx)
            .await
            .map_err(constraint_err)?;
        }
        data.remove(PATH_FIELD);
        Ok((Doc { id: id.into(), data }, existed))
    }

    async fn delete_tx(
        tx: &mut sqlx::Transaction<'_, sqlx::MySql>,
        collection: &str,
        id: &str,
    ) -> Result<Option<Doc>, AppError> {
        let prev = Self::get_tx(&mut *tx, collection, id).await?;
        if prev.is_none() {
            return Ok(None);
        }
        let table = hakobackend_core::flat_table_name(collection);
        let mut sql = format!("DELETE FROM {} WHERE id = ?", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.\"{PATH_FIELD}\"')) = ?"));
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
impl Database for MysqlDb {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            driver: "mysql",
            supports_watch: false,
            supports_transactions: true,
            supports_composite: true,
            supports_fts: true,
            supports_drop_index: true,
            supports_unique: true,
            supports_named_index: true,
            supports_native_aggregation: false,
        }
    }

    async fn ensure_collection(&self, path: &str) -> Result<(), AppError> {
        self.ensure_table(&hakobackend_core::flat_table_name(path)).await
    }

    async fn list_collections(&self) -> Result<Vec<String>, AppError> {
        // Internal `__*` collections are not exposed over HTTP.
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT TABLE_NAME FROM INFORMATION_SCHEMA.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME NOT LIKE '!_%' ESCAPE '!'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|_| AppError::Internal("db error".into()))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        let mut sql = format!("SELECT id, CAST(data AS CHAR) as data FROM {} WHERE id = ?", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.\"{PATH_FIELD}\"')) = ?"));
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
        let mut sql = format!("SELECT id, CAST(data AS CHAR) as data FROM {}{}", qi(&table), where_);
        sql.push_str(&build_order(q));
        sql.push_str(&build_page(q));
        let mut query = sqlx::query(&sql);
        for p in params {
            query = query.bind(p);
        }
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
        let r = sqlx::query(&format!("INSERT IGNORE INTO {} (id, data) VALUES (?, ?)", qi(&table)))
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
            // Shallow merge in Rust (exact contract semantics).
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
            let mut sql = format!("UPDATE {} SET data = ? WHERE id = ?", qi(&table));
            let mut q = sqlx::query(&sql).bind(&text).bind(id);
            if collection.contains('/') {
                sql.push_str(&format!(" AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.\"{PATH_FIELD}\"')) = ?"));
                q = sqlx::query(&sql).bind(&text).bind(id).bind(collection);
            }
            let r = q.execute(&self.pool).await.map_err(|_| AppError::Internal("db error".into()))?;
            if r.rows_affected() == 0 {
                return self.insert(collection, Doc { id: id.into(), data: doc.data }).await;
            }
        } else {
            sqlx::query(&format!(
                "INSERT INTO {} (id, data) VALUES (?, ?) ON DUPLICATE KEY UPDATE data = VALUES(data)",
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
        let mut sql = format!("DELETE FROM {} WHERE id = ?", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND JSON_UNQUOTE(JSON_EXTRACT(data, '$.\"{PATH_FIELD}\"')) = ?"));
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
        for p in params {
            query = query.bind(p);
        }
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
        // Idempotent: a logical name that already exists → return the stored info (no DDL rerun).
        let logical_want = spec.name.clone().unwrap_or_else(|| hakobackend_core::conformance::auto_index_name(spec));
        if let Some(info) = self.find_index(collection, &logical_want).await? {
            return Ok(info);
        }
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        let logical = spec.name.clone().unwrap_or_else(|| hakobackend_core::conformance::auto_index_name(spec));
        let physical = safe_index_name(&table, spec);
        let unique = if spec.unique { "UNIQUE " } else { "" };
        match spec.kind {
            IndexKind::Simple | IndexKind::Composite => {
                // Functional key CAST CHAR(255) to fit the index length limit.
                sqlx::query(&format!(
                    "CREATE {unique}INDEX {name} ON {table} ({exprs})",
                    name = qi(&physical),
                    table = qi(&table),
                    exprs = spec
                        .fields
                        .iter()
                        .map(|f| format!("(CAST(JSON_UNQUOTE(JSON_EXTRACT(data, '{}')) AS CHAR(255)))", jpath(f).replace('\'', "''")))
                        .collect::<Vec<_>>()
                        .join(", ")
                ))
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
            }
            IndexKind::FullText => {
                // FULLTEXT needs a STORED generated column (managed by the driver, internal prefix).
                let f = &spec.fields[0];
                let col = fts_column(&physical);
                sqlx::query(&format!(
                    "ALTER TABLE {table} ADD COLUMN {col} TEXT GENERATED ALWAYS AS (JSON_UNQUOTE(JSON_EXTRACT(data, '{path}'))) STORED",
                    table = qi(&table),
                    col = qi(&col),
                    path = jpath(f).replace('\'', "''")
                ))
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error (generated columns need MySQL 5.7+/MariaDB 10.2+)".into()))?;
                sqlx::query(&format!("CREATE FULLTEXT INDEX {name} ON {table} ({col})", name = qi(&physical), table = qi(&table), col = qi(&col)))
                    .execute(&self.pool)
                    .await
                    .map_err(|_| AppError::Internal("db error".into()))?;
            }
        }
        let fields_json = serde_json::Value::Array(spec.fields.iter().map(|f| serde_json::Value::String(f.clone())).collect())
            .to_string();
        let kind = match spec.kind {
            IndexKind::Simple => "simple",
            IndexKind::Composite => "composite",
            IndexKind::FullText => "fts",
        };
        sqlx::query("INSERT INTO `__ub_indexes` (collection, name, fields, `unique`, kind, ddl) VALUES (?,?,?,?,?,?) ON DUPLICATE KEY UPDATE fields = VALUES(fields), `unique` = VALUES(`unique`), kind = VALUES(kind), ddl = VALUES(ddl)")
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
        let rows = sqlx::query("SELECT name, fields, `unique`, kind FROM `__ub_indexes` WHERE collection = ?")
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
                IndexInfo { name: r.get("name"), fields, unique: r.get::<i8, _>("unique") != 0, kind }
            })
            .collect())
    }

    async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError> {
        self.ensure_registry().await?;
        let row: Option<(String, String)> = sqlx::query("SELECT kind, ddl FROM `__ub_indexes` WHERE collection = ? AND name = ?")
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
            // Drop the index first, then its generated column.
            sqlx::query(&format!("ALTER TABLE {} DROP INDEX {}", qi(&hakobackend_core::flat_table_name(collection)), qi(&ddl)))
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
            sqlx::query(&format!("ALTER TABLE {} DROP COLUMN {}", qi(&hakobackend_core::flat_table_name(collection)), qi(&fts_column(&ddl))))
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
        } else {
            sqlx::query(&format!("DROP INDEX {} ON {}", qi(&ddl), qi(&hakobackend_core::flat_table_name(collection))))
                .execute(&self.pool)
                .await
                .map_err(|_| AppError::Internal("db error".into()))?;
        }
        sqlx::query("DELETE FROM `__ub_indexes` WHERE collection = ? AND name = ?")
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
        (sql, params)
    }

    /// `id` orders by the real column (never the JSON body, which has none).
    #[test]
    fn build_order_id_uses_column() {
        use hakobackend_core::{Direction, OrderBy, QueryOptions};
        let mut q = QueryOptions::default();
        q.order_by.push(OrderBy { field: "id".into(), direction: Direction::Asc });
        assert!(build_order(&q).contains("id ASC"));
        let mut q = QueryOptions::default();
        q.order_by.push(OrderBy { field: "id".into(), direction: Direction::Desc });
        q.order_by.push(OrderBy { field: "age".into(), direction: Direction::Asc });
        let s = build_order(&q);
        assert!(s.contains("id DESC"), "{s}");
        assert!(s.contains("JSON_EXTRACT"), "{s}");
    }

    #[test]
    fn filter_mysql_parity() {
        // JSON vs CAST(? AS JSON) comparison: type-strict across types.
        let (s, p) = frag(&filter("age", FilterOp::Eq, serde_json::json!(30)));
        assert_eq!(s, "JSON_EXTRACT(data, '$.\"age\"') = CAST(? AS JSON)");
        assert_eq!(p, vec!["30"]);
        // Strings stay JSON strings ("x" with quotes).
        let (s, p) = frag(&filter("n", FilterOp::Eq, serde_json::json!("x")));
        assert_eq!(p, vec!["\"x\""]);
        assert!(s.contains("CAST(? AS JSON)"));
        // Ne over a missing field = true.
        let (s, _) = frag(&filter("x", FilterOp::Ne, serde_json::json!(1)));
        assert!(s.contains("OR") && s.contains("IS NULL"));
        // Array-contains via uniform JSON_CONTAINS.
        let (s, p) = frag(&filter("tags", FilterOp::ArrayContains, serde_json::json!("a")));
        assert_eq!(s, "JSON_CONTAINS(JSON_EXTRACT(data, '$.\"tags\"'), CAST(? AS JSON))");
        assert_eq!(p, vec!["\"a\""]);
        // Bools take the CAST path too (false → "false").
        let (s, p) = frag(&filter("b", FilterOp::Gt, serde_json::json!(false)));
        assert!(s.contains(">"));
        assert_eq!(p, vec!["false"]);
    }

    #[test]
    fn identifier_quoted() {
        assert_eq!(qi("a`b"), "`a``b`");
        assert_eq!(jpath("a.b"), "$.\"a\".\"b\"");
    }

    /// Full conformance needs live MySQL/MariaDB — via env UB_MYSQL_DSN, ignored by default.
    #[tokio::test]
    #[ignore = "needs live MySQL (UB_MYSQL_DSN)"]
    async fn conformance_mysql() {
        let dsn = std::env::var("UB_MYSQL_DSN").expect("UB_MYSQL_DSN");
        let db = MysqlDb::open(&dsn).await.unwrap();
        hakobackend_core::conformance::run_conformance_suite(&db).await;
        hakobackend_core::conformance::run_index_suite(&db).await;
    }
}

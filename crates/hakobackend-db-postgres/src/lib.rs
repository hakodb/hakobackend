//! hakobackend-db-postgres: addon PostgreSQL via sqlx (async native, pool).
//!
//! Pola tabel JSON generik (diport dari `sql.ts` backend lama):
//! satu tabel per koleksi (flat name) — `id TEXT PK, data JSONB`.
//! Subkoleksi diflatten + `_collectionPath` di JSON (dilepas saat baca).

use std::collections::{HashMap, HashSet};
use hakobackend_core::{AppError, Capabilities, Change, Database, Direction, Doc, Filter, FilterOp, IndexInfo, IndexKind, IndexSpec, QueryOptions};

const PATH_FIELD: &str = "_collectionPath";

pub struct PgDb {
    pool: sqlx::PgPool,
    verified: tokio::sync::Mutex<HashSet<String>>,
}

impl PgDb {
    pub async fn open(dsn: &str) -> Result<Self, AppError> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(10)
            .connect(dsn)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        let db = Self { pool, verified: tokio::sync::Mutex::new(HashSet::new()) };
        db.ensure_registry().await?;
        Ok(db)
    }

    async fn ensure_registry(&self) -> Result<(), AppError> {
        sqlx::query(
            "CREATE TABLE IF NOT EXISTS \"__ub_indexes\" (collection TEXT NOT NULL, name TEXT NOT NULL, fields JSONB NOT NULL, \"unique\" BOOLEAN NOT NULL DEFAULT FALSE, kind TEXT NOT NULL, ddl TEXT NOT NULL DEFAULT '', PRIMARY KEY (collection, name))",
        )
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        // Migrasi toleran: tabel lama tanpa kolom ddl.
        sqlx::query("ALTER TABLE \"__ub_indexes\" ADD COLUMN IF NOT EXISTS ddl TEXT NOT NULL DEFAULT ''")
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?;
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
            "CREATE TABLE IF NOT EXISTS {table} (id TEXT PRIMARY KEY, data JSONB NOT NULL DEFAULT '{{}}', \"createdAt\" TIMESTAMPTZ DEFAULT now(), \"updatedAt\" TIMESTAMPTZ DEFAULT now())",
            table = qi(table)
        ))
        .execute(&self.pool)
        .await
        .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        self.verified.lock().await.insert(table.to_string());
        Ok(())
    }
}

// --- Helper SQL murni (diuji unit tanpa DB) ---

/// Kutip identifier (kebal injeksi via kutip-ganda).
fn qi(name: &str) -> String {
    format!("\"{}\"", name.replace('"', "\"\""))
}

/// Akses JSON: "a.b" → `(data#>'{a,b}')` (perbandingan jsonb, type-strict).
fn jpath(field: &str) -> String {
    let segs: Vec<String> = field.split('.').map(|s| format!("\"{}\"", s.replace('"', "\"\""))).collect();
    format!("(data#>'{{{}}}')", segs.join(","))
}

fn push_filter(sql: &mut String, f: &Filter, n: &mut i32, params: &mut Vec<serde_json::Value>) -> Result<(), AppError> {
    let col = jpath(&f.field);
    let mut ph = || {
        *n += 1;
        format!("${}", *n)
    };
    match f.op {
        FilterOp::Eq => {
            sql.push_str(&format!("{col} = {}", ph()));
            params.push(f.value.clone());
        }
        FilterOp::Ne => {
            sql.push_str(&format!("{col} <> {}", ph()));
            params.push(f.value.clone());
        }
        FilterOp::Gt => {
            sql.push_str(&format!("{col} > {}", ph()));
            params.push(f.value.clone());
        }
        FilterOp::Gte => {
            sql.push_str(&format!("{col} >= {}", ph()));
            params.push(f.value.clone());
        }
        FilterOp::Lt => {
            sql.push_str(&format!("{col} < {}", ph()));
            params.push(f.value.clone());
        }
        FilterOp::Lte => {
            sql.push_str(&format!("{col} <= {}", ph()));
            params.push(f.value.clone());
        }
        FilterOp::In => {
            let arr = f.value.as_array().ok_or_else(|| AppError::BadRequest("in butuh array".into()))?;
            if arr.is_empty() {
                sql.push_str("FALSE");
                return Ok(());
            }
            let list: Vec<String> = arr.iter().map(|_| ph()).collect();
            sql.push_str(&format!("{col} IN ({})", list.join(",")));
            params.extend(arr.iter().cloned());
        }
        FilterOp::ArrayContains => {
            sql.push_str(&format!("{col} @> {}", ph()));
            params.push(f.value.clone());
        }
        FilterOp::ArrayContainsAny => {
            let arr = f.value.as_array().ok_or_else(|| AppError::BadRequest("array-contains-any butuh array".into()))?;
            if arr.is_empty() {
                sql.push_str("FALSE");
                return Ok(());
            }
            // OR @> seragam (tanpa asumsi string seperti ?|) — selalu tepat.
            let parts: Vec<String> = arr.iter().map(|_| format!("{col} @> {}", ph())).collect();
            sql.push_str(&format!("({})", parts.join(" OR ")));
            params.extend(arr.iter().cloned());
        }
    }
    Ok(())
}

/// Fragmen cursor: bound pada field acuan (order_by[0] atau id) — paritas kontrak.
/// `id` adalah kolom; lainnya JSON (param serde_json terikat langsung sebagai jsonb).
/// NULL gugur otomatis (jsonb NULL → baris hilang).
fn push_cursor(filters: &mut Vec<String>, q: &QueryOptions, n: &mut i32, params: &mut Vec<serde_json::Value>) {
    let field = hakobackend_core::conformance::cursor_field(q);
    let col = if field == "id" { "id".to_string() } else { jpath(field) };
    let mut bound = |op: &str, v: &serde_json::Value| {
        *n += 1;
        filters.push(format!("{col} {op} ${}", *n));
        params.push(v.clone());
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

/// Bangun klausa WHERE (+params jsonb): scope path + filter + cursor.
fn build_where(collection: &str, q: &QueryOptions) -> Result<(String, Vec<serde_json::Value>), AppError> {
    let mut filters = Vec::new();
    let mut params = Vec::new();
    let mut n = 0i32;
    if collection.contains('/') {
        n += 1;
        filters.push(format!("(data#>>'{{{PATH_FIELD}}}') = ${n}"));
        params.push(serde_json::Value::String(collection.into()));
    }
    for f in &q.filters {
        let mut frag = String::new();
        push_filter(&mut frag, f, &mut n, &mut params)?;
        filters.push(frag);
    }
    push_cursor(&mut filters, q, &mut n, &mut params);
    let where_ = if filters.is_empty() { String::new() } else { format!(" WHERE {}", filters.join(" AND ")) };
    Ok((where_, params))
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

/// Samarkan detail koneksi (DSN/password tak boleh bocor ke respons).
fn safe_db_err(e: sqlx::Error) -> String {
    match e.as_database_error() {
        Some(d) => format!("db error {}", d.code().map(|c| c.to_string()).unwrap_or_default()),
        None => "db error".into(),
    }
}

fn is_conflict(e: &sqlx::Error) -> bool {
    e.as_database_error().and_then(|d| d.code()).as_deref() == Some("23505")
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

fn uuid_like() -> String {
    use std::time::{SystemTime, UNIX_EPOCH};
    let nanos = SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_nanos()).unwrap_or(0);
    format!("pg{nanos:x}{:x}", std::process::id())
}

/// Nama index aman (<=60 char, alnum+underscore).
fn safe_index_name(table: &str, spec: &IndexSpec) -> String {
    let base = spec.name.clone().unwrap_or_else(|| match spec.kind {
        IndexKind::Simple => format!("idx_{}_{}", table, spec.fields.join("_")),
        IndexKind::Composite => format!("idx_{}_{}", table, spec.fields.join("_")),
        IndexKind::FullText => format!("fts_{}_{}", table, spec.fields.join("_")),
    });
    let clean: String = base.chars().map(|c| if c.is_ascii_alphanumeric() { c } else { '_' }).collect();
    clean.chars().take(60).collect()
}

#[async_trait::async_trait]
impl Database for PgDb {
    fn capabilities(&self) -> Capabilities {
        Capabilities {
            driver: "postgres",
            supports_watch: false, // polling oleh core (LISTEN/NOTIFY menyusul)
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
        // Koleksi internal `__*` (registry, sesi) tak diekspos HTTP.
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT tablename FROM pg_tables WHERE schemaname = 'public' AND tablename NOT LIKE '\\_%' ESCAPE '\\'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        Ok(rows.into_iter().map(|r| r.0).collect())
    }

    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        let mut sql = format!("SELECT id, data FROM {} WHERE id = $1", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND (data#>>'{{{PATH_FIELD}}}') = $2"));
        }
        let mut q = sqlx::query(&sql).bind(id);
        if collection.contains('/') {
            q = q.bind(collection);
        }
        let row: Option<(String, serde_json::Value)> = q
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?
            .map(|r| {
                use sqlx::Row;
                (r.get::<String, _>("id"), r.get::<serde_json::Value, _>("data"))
            });
        Ok(row.map(|(id, v)| {
            let data = v.as_object().map(|m| m.clone().into_iter().collect()).unwrap_or_default();
            to_doc(id, data)
        }))
    }

    async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        let (where_, params) = build_where(collection, q)?;
        let mut sql = format!("SELECT id, data FROM {}{}", qi(&table), where_);
        sql.push_str(&build_order(q));
        if let Some(n) = q.offset {
            sql.push_str(&format!(" OFFSET {n}"));
        }
        if let Some(n) = q.limit {
            sql.push_str(&format!(" LIMIT {n}"));
        }
        let mut query = sqlx::query(&sql);
        for p in params {
            query = query.bind(p);
        }
        let rows = query.fetch_all(&self.pool).await.map_err(|e| AppError::Internal(safe_db_err(e)))?;
        Ok(rows
            .into_iter()
            .map(|r| {
                use sqlx::Row;
                let id: String = r.get("id");
                let v: serde_json::Value = r.get("data");
                let data = v.as_object().map(|m| m.clone().into_iter().collect()).unwrap_or_default();
                to_doc(id, data)
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
        let data = serde_json::Value::Object(doc.data.clone().into_iter().collect());
        let r = sqlx::query(&format!("INSERT INTO {} (id, data) VALUES ($1, $2) ON CONFLICT (id) DO NOTHING", qi(&table)))
            .bind(&doc.id)
            .bind(&data)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?;
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
        let data = serde_json::Value::Object(doc.data.clone().into_iter().collect());
        if merge {
            let mut sql = format!(
                "UPDATE {} SET data = data || $1, \"updatedAt\" = now() WHERE id = $2",
                qi(&table)
            );
            let mut q = sqlx::query(&sql).bind(&data).bind(id);
            if collection.contains('/') {
                sql.push_str(&format!(" AND (data#>>'{{{PATH_FIELD}}}') = $3"));
                q = sqlx::query(&sql).bind(&data).bind(id).bind(collection);
            }
            let r = q.execute(&self.pool).await.map_err(|e| AppError::Internal(safe_db_err(e)))?;
            if r.rows_affected() == 0 {
                return self.insert(collection, Doc { id: id.into(), data: doc.data }).await;
            }
        } else {
            sqlx::query(&format!(
                "INSERT INTO {} (id, data) VALUES ($1, $2) ON CONFLICT (id) DO UPDATE SET data = EXCLUDED.data, \"updatedAt\" = now()",
                qi(&table)
            ))
            .bind(id)
            .bind(&data)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        }
        doc.data.remove(PATH_FIELD);
        Ok(Doc { id: id.into(), data: doc.data })
    }

    async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        let mut sql = format!("DELETE FROM {} WHERE id = $1", qi(&table));
        if collection.contains('/') {
            sql.push_str(&format!(" AND (data#>>'{{{PATH_FIELD}}}') = $2 RETURNING data"));
        } else {
            sql.push_str(" RETURNING data");
        }
        let mut q = sqlx::query(&sql).bind(id);
        if collection.contains('/') {
            q = q.bind(collection);
        }
        let row: Option<serde_json::Value> = q
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?
            .map(|r| {
                use sqlx::Row;
                r.get("data")
            });
        Ok(row.map(|v| {
            let data = v.as_object().map(|m| m.clone().into_iter().collect()).unwrap_or_default();
            to_doc(id.into(), data)
        }))
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
        let row = query.fetch_one(&self.pool).await.map_err(|e| AppError::Internal(safe_db_err(e)))?;
        use sqlx::Row;
        Ok(row.get::<i64, _>("c") as u64)
    }

    async fn subscribe(&self, _collection: &str) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
        // ponytail: polling oleh core sampai LISTEN/NOTIFY mendarat.
        Ok(tokio::sync::broadcast::channel(256).0.subscribe())
    }

    async fn create_index(&self, collection: &str, spec: &IndexSpec) -> Result<IndexInfo, AppError> {
        hakobackend_core::conformance::validate_spec(self.capabilities(), spec)?;
        if spec.unique && spec.kind == IndexKind::FullText {
            return Err(AppError::BadRequest("fts tak bisa unique".into()));
        }
        let table = hakobackend_core::flat_table_name(collection);
        self.ensure_table(&table).await?;
        // Nama logis (kontrak) vs fisik (DDL per tabel).
        let logical = spec.name.clone().unwrap_or_else(|| hakobackend_core::conformance::auto_index_name(spec));
        let physical = safe_index_name(&table, spec);
        let unique = if spec.unique { "UNIQUE " } else { "" };
        let ddl = match spec.kind {
            IndexKind::Simple => {
                let f = &spec.fields[0];
                format!("CREATE {unique}INDEX IF NOT EXISTS {name} ON {table} ((data#>'{{{f}}}'))", name = qi(&physical), table = qi(&table), f = f.replace('\'', "''"))
            }
            IndexKind::Composite => {
                let exprs: Vec<String> =
                    spec.fields.iter().map(|f| format!("(data#>'{{{}}}')", f.replace('\'', "''"))).collect();
                format!("CREATE {unique}INDEX IF NOT EXISTS {name} ON {table} ({exprs})", name = qi(&physical), table = qi(&table), exprs = exprs.join(", "))
            }
            IndexKind::FullText => {
                let f = &spec.fields[0];
                format!(
                    "CREATE INDEX IF NOT EXISTS {name} ON {table} USING gin (to_tsvector('simple', data#>>'{{{f}}}'))",
                    name = qi(&physical),
                    table = qi(&table),
                    f = f.replace('\'', "''")
                )
            }
        };
        sqlx::query(&ddl).execute(&self.pool).await.map_err(|e| {
            if is_conflict(&e) {
                AppError::AlreadyExists
            } else {
                AppError::Internal(safe_db_err(e))
            }
        })?;
        let fields_json = serde_json::Value::Array(spec.fields.iter().map(|f| serde_json::Value::String(f.clone())).collect());
        let kind = match spec.kind {
            IndexKind::Simple => "simple",
            IndexKind::Composite => "composite",
            IndexKind::FullText => "fts",
        };
        sqlx::query("INSERT INTO \"__ub_indexes\" (collection, name, fields, \"unique\", kind, ddl) VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT (collection, name) DO UPDATE SET fields = EXCLUDED.fields, \"unique\" = EXCLUDED.\"unique\", kind = EXCLUDED.kind, ddl = EXCLUDED.ddl")
            .bind(collection)
            .bind(&logical)
            .bind(&fields_json)
            .bind(spec.unique)
            .bind(kind)
            .bind(&physical)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        Ok(IndexInfo { name: logical, fields: spec.fields.clone(), unique: spec.unique, kind: spec.kind })
    }

    async fn list_indexes(&self, collection: &str) -> Result<Vec<IndexInfo>, AppError> {
        self.ensure_registry().await?;
        let rows = sqlx::query("SELECT name, fields, \"unique\", kind FROM \"__ub_indexes\" WHERE collection = $1")
            .bind(collection)
            .fetch_all(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        use sqlx::Row;
        Ok(rows
            .into_iter()
            .map(|r| {
                let kind = match r.get::<String, _>("kind").as_str() {
                    "composite" => IndexKind::Composite,
                    "fts" => IndexKind::FullText,
                    _ => IndexKind::Simple,
                };
                let fields: Vec<String> = r
                    .get::<serde_json::Value, _>("fields")
                    .as_array()
                    .map(|a| a.iter().filter_map(|v| v.as_str().map(str::to_string)).collect())
                    .unwrap_or_default();
                IndexInfo { name: r.get("name"), fields, unique: r.get("unique"), kind }
            })
            .collect())
    }

    async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError> {
        self.ensure_registry().await?;
        let ddl: Option<String> = sqlx::query("SELECT ddl FROM \"__ub_indexes\" WHERE collection = $1 AND name = $2")
            .bind(collection)
            .bind(name)
            .fetch_optional(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?
            .map(|r| {
                use sqlx::Row;
                r.get("ddl")
            });
        let ddl = match ddl {
            Some(d) if !d.is_empty() => d,
            _ => return Err(AppError::NotFound),
        };
        sqlx::query(&format!("DROP INDEX IF EXISTS {}", qi(&ddl)))
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        sqlx::query("DELETE FROM \"__ub_indexes\" WHERE collection = $1 AND name = $2")
            .bind(collection)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| AppError::Internal(safe_db_err(e)))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn filter(field: &str, op: FilterOp, value: serde_json::Value) -> Filter {
        Filter { field: field.into(), op, value }
    }

    fn frag(f: &Filter) -> (String, Vec<serde_json::Value>) {
        let mut sql = String::new();
        let mut n = 0;
        let mut params = Vec::new();
        push_filter(&mut sql, f, &mut n, &mut params).unwrap();
        (sql, params)
    }

    #[test]
    fn filter_sql_parity() {
        // jsonb type-strict: angka tetap angka ($n = jsonb), bukan teks.
        let (s, p) = frag(&filter("age", FilterOp::Eq, serde_json::json!(30)));
        assert_eq!(s, "(data#>'{\"age\"}') = $1");
        assert_eq!(p, vec![serde_json::json!(30)]);
        // Nested dot-notation → operator #>.
        let (s, _) = frag(&filter("a.b", FilterOp::Gt, serde_json::json!(1)));
        assert_eq!(s, "(data#>'{\"a\",\"b\"}') > $1");
        // In berekspansi placeholder per elemen.
        let (s, p) = frag(&filter("age", FilterOp::In, serde_json::json!([1, 2])));
        assert_eq!(s, "(data#>'{\"age\"}') IN ($1,$2)");
        assert_eq!(p.len(), 2);
        // Array-contains via @> (uniform, tanpa asumsi string).
        let (s, _) = frag(&filter("tags", FilterOp::ArrayContains, serde_json::json!("x")));
        assert_eq!(s, "(data#>'{\"tags\"}') @> $1");
        let (s, p) = frag(&filter("tags", FilterOp::ArrayContainsAny, serde_json::json!(["x", "y"])));
        assert!(s.starts_with('(') && s.contains(" OR "));
        assert_eq!(p.len(), 2);
    }

    #[test]
    fn where_scope_dan_cursor() {
        let mut q = QueryOptions::default();
        let (w, p) = build_where("posts/1/revisions", &q).unwrap();
        assert!(w.contains(PATH_FIELD) && p.len() == 1);
        let (w2, _) = build_where("posts", &q).unwrap();
        assert!(w2.is_empty());
        // Cursor: bound pada order_by[0], NULL gugur otomatis (tanpa patch IS NULL).
        q.order_by.push(hakobackend_core::OrderBy { field: "age".into(), direction: hakobackend_core::Direction::Asc });
        q.start_after = Some(serde_json::json!(25));
        q.end_at = Some(serde_json::json!(35));
        let (w3, p3) = build_where("posts", &q).unwrap();
        assert!(w3.contains('>') && w3.contains("<=") && p3.len() == 2);
        // Acuan id = kolom (bukan JSON).
        let mut qi = QueryOptions::default();
        qi.start_at = Some(serde_json::json!("abc"));
        let (w4, _) = build_where("posts", &qi).unwrap();
        assert!(w4.contains("id >="));
    }

    #[test]
    fn identifier_dikutip() {
        assert_eq!(qi("weird\"name"), "\"weird\"\"name\"");
        assert_eq!(jpath("a.b"), "(data#>'{\"a\",\"b\"}')");
    }

    /// Konformansi penuh butuh Postgres live — via env UB_PG_DSN, ignore default.
    #[tokio::test]
    #[ignore = "butuh Postgres live (UB_PG_DSN)"]
    async fn conformance_pg() {
        let dsn = std::env::var("UB_PG_DSN").expect("UB_PG_DSN");
        let db = PgDb::open(&dsn).await.unwrap();
        hakobackend_core::conformance::run_conformance_suite(&db).await;
        hakobackend_core::conformance::run_index_suite(&db).await;
    }
}

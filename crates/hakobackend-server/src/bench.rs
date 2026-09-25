//! Internal per-driver benchmark (`--benchmark` flag or `benchmark = true`
//! in config): fixed shapes against the ACTIVE driver+config, auto-clean
//! seeds, then the process exits (no serving, no auth/policy in the loop).
//!
//! Comparability contract (hakobench is the reference, minus durability
//! tuning — this runs the deployment default): sequential ops, fixed N,
//! same seed shape (`{age, tag}`, bench4-compatible), same collection every
//! run, full cleanup verified (final count == 0) or the run FAILS loudly.
//! TTL wrapper stays on (it is what prod serves through).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Instant;

use hakobackend_core::{
    Database, Direction, Doc, Filter, FilterOp, IndexKind, IndexSpec, OrderBy, QueryOptions, TxOp,
    TxOpKind,
};

/// Fixed seed volume (bench4-compatible). Same every run, every driver.
pub const N: usize = 2000;
/// Collection is internal (`__*` deny covers it over HTTP anyway).
const COLL: &str = "__benchmark";
const QUERY_ITERS: usize = 200;
const BATCH_OPS: usize = 100;
const CURSOR_PAGE: usize = 200;

pub struct Row {
    pub name: &'static str,
    pub ops: usize,
    pub secs: f64,
    pub note: &'static str,
}

fn doc(id: String, i: usize) -> Doc {
    let mut data = HashMap::new();
    data.insert("age".to_string(), serde_json::json!(18 + (i % 70) as i64));
    data.insert("tag".to_string(), serde_json::json!(format!("t{}", i % 32)));
    Doc { id, data }
}

fn bid(i: usize) -> String {
    format!("b{i:05}")
}

async fn timed<F, T, E>(f: F) -> Result<(T, f64), E>
where
    F: std::future::Future<Output = Result<T, E>>,
{
    let t = Instant::now();
    let out = f.await?;
    Ok((out, t.elapsed().as_secs_f64()))
}

fn eq_age(v: i64) -> Filter {
    Filter { field: "age".into(), op: FilterOp::Eq, value: serde_json::json!(v) }
}

fn age_asc() -> Vec<OrderBy> {
    vec![OrderBy { field: "age".into(), direction: Direction::Asc }]
}

async fn seed_puts(db: &Arc<dyn Database>, n: usize) -> Result<(), String> {
    for i in 0..n {
        db.set(COLL, &bid(i), doc(bid(i), i), false)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn put_overwrites(db: &Arc<dyn Database>, n: usize) -> Result<(), String> {
    for i in 0..n {
        db.set(COLL, &bid(i), doc(bid(i), i + 1), false)
            .await
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn post_creates(db: &Arc<dyn Database>, n: usize) -> Result<(), String> {
    for i in 0..n {
        let id = format!("p{i:05}");
        db.insert(COLL, doc(id, i)).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn post_teardown(db: &Arc<dyn Database>, n: usize) -> Result<(), String> {
    // Timed separately above; removed here so later shapes see the same
    // dataset (seeds + batch only).
    for i in 0..n {
        db.delete(COLL, &format!("p{i:05}")).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn patch_merges(db: &Arc<dyn Database>, n: usize) -> Result<(), String> {
    for i in 0..n {
        let mut d = doc(bid(i), i);
        d.data.insert("tag".to_string(), serde_json::json!("patched"));
        db.set(COLL, &bid(i), d, true).await.map_err(|e| e.to_string())?;
    }
    Ok(())
}

async fn get_roundrobin(db: &Arc<dyn Database>, n: usize) -> Result<(), String> {
    for i in 0..n {
        let d = db.get(COLL, &bid(i)).await.map_err(|e| e.to_string())?;
        if d.is_none() {
            return Err(format!("get miss {}", bid(i)));
        }
    }
    Ok(())
}

async fn query_loop(db: &Arc<dyn Database>, q: &QueryOptions) -> Result<(), String> {
    for _ in 0..QUERY_ITERS {
        let r = db.list(COLL, q).await.map_err(|e| e.to_string())?;
        if r.is_empty() {
            return Err("query-idx empty".to_string());
        }
    }
    Ok(())
}

async fn count_loop(db: &Arc<dyn Database>, q: &QueryOptions) -> Result<(), String> {
    for _ in 0..QUERY_ITERS {
        let c = db.count(COLL, q).await.map_err(|e| e.to_string())?;
        if c == 0 {
            return Err("count zero".to_string());
        }
    }
    Ok(())
}

async fn offset_loop(db: &Arc<dyn Database>, q: &QueryOptions) -> Result<(), String> {
    for _ in 0..QUERY_ITERS {
        let r = db.list(COLL, q).await.map_err(|e| e.to_string())?;
        if r.len() != 100 {
            return Err(format!("offset page {}", r.len()));
        }
    }
    Ok(())
}

async fn cursor_walk(db: &Arc<dyn Database>) -> Result<usize, String> {
    let mut total = 0usize;
    let mut after: Option<serde_json::Value> = None;
    loop {
        let mut q = QueryOptions::default();
        q.order_by = vec![OrderBy { field: "id".into(), direction: Direction::Asc }];
        q.limit = Some(CURSOR_PAGE);
        q.start_after = after.clone();
        let rows = db.list(COLL, &q).await.map_err(|e| e.to_string())?;
        if rows.is_empty() {
            break;
        }
        after = Some(serde_json::json!(rows.last().unwrap().id.clone()));
        total += rows.len();
        if rows.len() < CURSOR_PAGE {
            break;
        }
    }
    if total == 0 {
        return Err("cursor walk empty".to_string());
    }
    Ok(total)
}

async fn cleanup_all(db: &Arc<dyn Database>) -> Result<(), String> {
    let all = db.list(COLL, &QueryOptions::default()).await.map_err(|e| e.to_string())?;
    let n_all = all.len();
    for d in all {
        db.delete(COLL, &d.id).await.map_err(|e| e.to_string())?;
    }
    let left = db.count(COLL, &QueryOptions::default()).await.map_err(|e| e.to_string())?;
    if left != 0 {
        return Err(format!("cleanup left {left}/{n_all}"));
    }
    Ok(())
}

/// Full matrix. Returns per-shape rows; Err aborts loudly (a benchmark that
/// silently degrades is worse than none).
pub async fn run(db: &Arc<dyn Database>, n: usize) -> Result<Vec<Row>, String> {
    let mut rows: Vec<Row> = Vec::new();

    let ((), dt) = timed(seed_puts(db, n)).await?;
    let c = db.count(COLL, &QueryOptions::default()).await.map_err(|e| e.to_string())?;
    if c as usize != n {
        return Err(format!("seed count {c} != {n}"));
    }
    rows.push(Row { name: "seed-put", ops: n, secs: dt, note: "" });

    let ((), dt) = timed(put_overwrites(db, n)).await?;
    rows.push(Row { name: "put", ops: n, secs: dt, note: "" });

    let ((), dt) = timed(post_creates(db, n)).await?;
    let c = db.count(COLL, &QueryOptions::default()).await.map_err(|e| e.to_string())?;
    if c as usize != 2 * n {
        return Err(format!("post count {c} != {}", 2 * n));
    }
    rows.push(Row { name: "post", ops: n, secs: dt, note: "" });
    post_teardown(db, n).await?;

    let ((), dt) = timed(patch_merges(db, n)).await?;
    rows.push(Row { name: "patch", ops: n, secs: dt, note: "" });

    if db.capabilities().supports_transactions {
        let ops: Vec<TxOp> = (0..BATCH_OPS)
            .map(|i| {
                let id = format!("x{i:05}");
                TxOp {
                    collection: COLL.to_string(),
                    id: id.clone(),
                    kind: TxOpKind::Put { merge: false, must_exist: false },
                    doc: Some(doc(id, i)),
                }
            })
            .collect();
        let (_, dt) = timed(db.run_transaction(ops)).await.map_err(|e| e.to_string())?;
        rows.push(Row { name: "batch", ops: BATCH_OPS, secs: dt, note: "1 tx" });
    } else {
        rows.push(Row { name: "batch", ops: 0, secs: 0.0, note: "unsupported" });
    }

    let ((), dt) = timed(get_roundrobin(db, n)).await?;
    rows.push(Row { name: "get", ops: n, secs: dt, note: "" });

    let (r, dt) = timed(db.list(COLL, &QueryOptions::default())).await.map_err(|e| e.to_string())?;
    let walked = r.len();
    if walked == 0 {
        return Err("walk returned nothing".into());
    }
    rows.push(Row { name: "walk", ops: walked, secs: dt, note: "full scan" });

    let indexed = db
        .create_index(
            COLL,
            &IndexSpec { name: None, fields: vec!["age".into()], unique: false, kind: IndexKind::Simple },
        )
        .await
        .is_ok();
    rows.push(Row {
        name: "index",
        ops: usize::from(indexed),
        secs: 0.0,
        note: if indexed { "setup" } else { "unsupported" },
    });
    if !indexed {
        for name in ["query-idx", "count", "offset-idx", "cursor-idx"] {
            rows.push(Row { name, ops: 0, secs: 0.0, note: "no index" });
        }
    } else {
        let mut q = QueryOptions::default();
        q.filters.push(eq_age(30));
        q.order_by = age_asc();
        q.limit = Some(100);
        let (_, dt) = timed(query_loop(db, &q)).await?;
        rows.push(Row { name: "query-idx", ops: QUERY_ITERS, secs: dt, note: "eq+order+limit100" });

        let mut qc = QueryOptions::default();
        qc.filters.push(eq_age(30));
        let (_, dt) = timed(count_loop(db, &qc)).await?;
        rows.push(Row { name: "count", ops: QUERY_ITERS, secs: dt, note: "eq filter" });

        let mut qo = QueryOptions::default();
        qo.order_by = age_asc();
        qo.offset = Some(n / 2);
        qo.limit = Some(100);
        let (_, dt) = timed(offset_loop(db, &qo)).await?;
        rows.push(Row { name: "offset-idx", ops: QUERY_ITERS, secs: dt, note: "order+offset+limit100" });

        let (total, dt) = timed(cursor_walk(db)).await?;
        rows.push(Row { name: "cursor-idx", ops: total, secs: dt, note: "id-order pages" });
    }

    let ((), dt) = timed(cleanup_all(db)).await?;
    rows.push(Row { name: "cleanup", ops: 0, secs: dt, note: "verified 0" });

    Ok(rows)
}

/// hakobench-style table (per-driver runs compare row by row).
pub fn print_table(driver: &str, n: usize, rows: &[Row]) {
    println!("[__benchmark] driver={driver} n={n} (sequential, deployment durability)");
    println!("{:<12}{:>8}{:>10}{:>12}  note", "shape", "ops", "secs", "ops/s");
    for r in rows {
        let rate = if r.secs > 0.0 { r.ops as f64 / r.secs } else { 0.0 };
        println!("{:<12}{:>8}{:>10.3}{:>12.0}  {}", r.name, r.ops, r.secs, rate, r.note);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Full matrix on sqlite-memory at small N: every shape runs, the table
    /// fills, and cleanup leaves zero docs behind.
    #[tokio::test]
    async fn benchmark_autoclean() {
        use hakobackend_db_sqlite::SqliteDb;
        let db: Arc<dyn Database> = Arc::new(SqliteDb::open("").await.expect("mem open"));
        let rows = run(&db, 50).await.expect("bench runs");
        let names: Vec<_> = rows.iter().map(|r| r.name).collect();
        for want in [
            "seed-put", "put", "post", "patch", "batch", "get", "walk", "index", "query-idx",
            "count", "offset-idx", "cursor-idx", "cleanup",
        ] {
            assert!(names.contains(&want), "missing {want}");
        }
        let put = rows.iter().find(|r| r.name == "put").unwrap();
        assert!(put.secs > 0.0 && put.ops == 50);
        let left = db.count(COLL, &QueryOptions::default()).await.unwrap();
        assert_eq!(left, 0, "seeds not cleaned");
    }
}

//! Opt-in PATCH coalescing (`--coalesce-writes`): rapid PATCHes to the same
//! document merge into one stored write per window (default 100 ms).
//!
//! Exactness contract: only ELIGIBLE bodies coalesce — top-level plain keys
//! (no dot-paths) and no `__type__` sentinels anywhere. For those, folding
//! bodies by shallow-extend then applying once is exactly equivalent to
//! sequential application (distinct keys commute; duplicate keys last-win).
//! Anything else (atomics, dot-paths) bypasses to a direct write.
//!
//! Tradeoffs (documented, hence opt-in): the client is acked at merge time,
//! so a driver failure surfaces in logs (and a retry budget), not in the
//! response; SIGKILL can lose at most one window. GETs overlay pending
//! bodies, so read-your-write holds inside the window.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

/// How long a pending entry waits for more merges before flushing.
pub const COALESCE_WINDOW: Duration = Duration::from_millis(100);
/// Flush cadence + give-up budget for persistently failing entries.
const FLUSH_TICK: Duration = Duration::from_millis(50);
const MAX_FLUSH_FAILS: u32 = 10;

#[derive(Debug)]
struct Pending {
    body: HashMap<String, serde_json::Value>,
    first_at: Instant,
    fails: u32,
}

#[derive(Debug, Default)]
pub struct Coalescer {
    pending: std::sync::Mutex<HashMap<(String, String), Pending>>,
}

impl Coalescer {
    /// Eligible when every top-level key is plain and no sentinel appears
    /// anywhere in the payload (string scan: cheap, conservative).
    pub fn eligible(body: &serde_json::Value) -> bool {
        let obj = match body.as_object() {
            Some(o) => o,
            None => return false,
        };
        if obj.keys().any(|k| k.contains('.')) {
            return false;
        }
        !serde_json::to_string(body).is_ok_and(|s| s.contains("__type__"))
    }

    /// Merge a PATCH body into the pending entry. Returns true when merged
    /// (caller acks); false when the body is ineligible (caller writes direct).
    pub fn merge(&self, collection: &str, id: &str, body: HashMap<String, serde_json::Value>) -> bool {
        let mut pending = self.pending.lock().unwrap();
        let e = pending
            .entry((collection.to_string(), id.to_string()))
            .or_insert_with(|| Pending { body: HashMap::new(), first_at: Instant::now(), fails: 0 });
        e.body.extend(body);
        true
    }

    /// Overlay pending bodies over a stored doc (GET path). Returns the
    /// merged view, or None when nothing is pending for this doc.
    pub fn overlay(
        &self,
        collection: &str,
        id: &str,
        stored: Option<HashMap<String, serde_json::Value>>,
    ) -> Option<HashMap<String, serde_json::Value>> {
        let pending = self.pending.lock().unwrap();
        pending.get(&(collection.to_string(), id.to_string())).map(|p| {
            let mut base = stored.unwrap_or_default();
            base.extend(p.body.clone());
            base
        })
    }

    /// Flush entries older than the window through `write`. Drops entries
    /// that fail persistently (logged). Returns flushed count.
    pub async fn flush_due<F, Fut>(&self, write: F) -> usize
    where
        F: Fn(String, String, HashMap<String, serde_json::Value>) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let due: Vec<(String, String, HashMap<String, serde_json::Value>)> = {
            let mut pending = self.pending.lock().unwrap();
            let now = Instant::now();
            let mut due = Vec::new();
            pending.retain(|key, p| {
                if now.duration_since(p.first_at) >= COALESCE_WINDOW {
                    due.push((key.0.clone(), key.1.clone(), std::mem::take(&mut p.body)));
                    false
                } else {
                    true
                }
            });
            due
        };
        let mut flushed = 0;
        for (coll, id, body) in due {
            if body.is_empty() {
                continue;
            }
            let key = (coll.clone(), id.clone());
            match write(coll, id, body.clone()).await {
                Ok(()) => flushed += 1,
                Err(e) => {
                    eprintln!("[coalesce] flush {}/{} failed ({e}); requeued", key.0, key.1);
                    let mut pending = self.pending.lock().unwrap();
                    if let Some(p) = pending.get_mut(&key) {
                        p.fails += 1;
                        if p.fails <= MAX_FLUSH_FAILS {
                            // Merge back what we took (newer merges win on clash).
                            let mut back = body;
                            back.extend(std::mem::take(&mut p.body));
                            p.body = back;
                            continue;
                        }
                    }
                    eprintln!("[coalesce] dropping {}/{} after {MAX_FLUSH_FAILS} failures", key.0, key.1);
                }
            }
        }
        flushed
    }

    /// Flush everything now (reload/shutdown paths).
    pub async fn flush_all<F, Fut>(&self, write: F) -> usize
    where
        F: Fn(String, String, HashMap<String, serde_json::Value>) -> Fut,
        Fut: std::future::Future<Output = Result<(), String>>,
    {
        let all: Vec<(String, String, HashMap<String, serde_json::Value>)> = {
            let mut pending = self.pending.lock().unwrap();
            pending
                .drain()
                .filter(|(_, p)| !p.body.is_empty())
                .map(|(k, p)| (k.0, k.1, p.body))
                .collect()
        };
        let mut n = 0;
        for (coll, id, body) in all {
            if write(coll, id, body).await.is_ok() {
                n += 1;
            }
        }
        n
    }

    /// Background flusher: every tick, store due entries via `write`.
    /// `db` is read fresh per entry so driver reloads keep working.
    pub fn spawn_flusher(
        self: &Arc<Self>,
        db: Arc<tokio::sync::RwLock<Arc<dyn hakobackend_core::Database>>>,
    ) {
        let this = self.clone();
        tokio::spawn(async move {
            let mut tick = tokio::time::interval(FLUSH_TICK);
            loop {
                tick.tick().await;
                let dbh = db.read().await.clone();
                this.flush_due(|coll, id, body| {
                    let dbh = dbh.clone();
                    async move {
                        // createdAt survives (merge keeps existing fields);
                        // updatedAt refreshes here since we bypass write_doc.
                        let mut body = body;
                        body.insert(
                            "updatedAt".to_string(),
                            serde_json::Value::String(
                                hakobackend_core::atomics::now_iso(),
                            ),
                        );
                        dbh.set(
                            &coll,
                            &id,
                            hakobackend_core::Doc { id: id.clone(), data: body },
                            true,
                        )
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                    }
                })
                .await;
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn map(pairs: &[(&str, i64)]) -> HashMap<String, serde_json::Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), serde_json::json!(v))).collect()
    }

    #[test]
    fn eligibility() {
        assert!(Coalescer::eligible(&serde_json::json!({"a": 1})));
        assert!(!Coalescer::eligible(&serde_json::json!({"a.b": 1})));
        assert!(!Coalescer::eligible(&serde_json::json!({"a": {"__type__": "increment"}})));
        assert!(!Coalescer::eligible(&serde_json::json!([1])));
    }

    #[tokio::test]
    async fn merge_overlay_flush_roundtrip() {
        let c = Coalescer::default();
        assert!(c.merge("w", "a", map(&[("x", 1)])));
        assert!(c.merge("w", "a", map(&[("x", 2), ("y", 3)])));
        // Overlay: pending wins over stored.
        let view = c.overlay("w", "a", Some(map(&[("x", 0), ("z", 9)]))).unwrap();
        assert_eq!(view.get("x"), Some(&serde_json::json!(2)));
        assert_eq!(view.get("y"), Some(&serde_json::json!(3)));
        assert_eq!(view.get("z"), Some(&serde_json::json!(9)));
        // Flush delivers the merged body once.
        let seen = Arc::new(std::sync::Mutex::new(Vec::new()));
        let s2 = seen.clone();
        let n = c
            .flush_due(|coll, id, body| {
                let s2 = s2.clone();
                async move {
                    s2.lock().unwrap().push((coll, id, body));
                    Ok(())
                }
            })
            .await;
        assert_eq!(n, 0, "window not elapsed yet");
        tokio::time::sleep(COALESCE_WINDOW + Duration::from_millis(20)).await;
        let n = c
            .flush_due(|coll, id, body| {
                let s2 = s2.clone();
                async move {
                    s2.lock().unwrap().push((coll, id, body));
                    Ok(())
                }
            })
            .await;
        assert_eq!(n, 1);
        let got = seen.lock().unwrap();
        assert_eq!(got.len(), 1);
        assert_eq!(got[0].2.get("x"), Some(&serde_json::json!(2)));
    }
}

//! FieldValue atomics + timestamp stamping, driver-agnostic (legacy
//! `resolveAtomicOperations` / `applyAtomicOperations` parity, rdb.ts).
//!
//! Wire encoding is unchanged from the legacy backend so old SDKs keep
//! working: a sentinel is `{"__type__": <op>, ...}` where op is one of
//! `serverTimestamp | increment | arrayUnion | arrayRemove | deleteField`.
//! Top-level update keys may be dot-paths (`"a.b.c"`).
//!
//! Two entry points, mirroring the legacy split:
//! - [`resolve_for_create`]: insert / full-replace path. Sentinels collapse
//!   to plain values (`increment` → `n`, `arrayUnion` → `elements`,
//!   `arrayRemove` → `[]`, `deleteField` → dropped).
//! - [`apply_update`]: merge path over an existing body. Sentinels execute
//!   against current values (`increment` adds, union/remove dedup by JSON,
//!   `deleteField` removes, plain values set via dot-path).

use std::collections::HashMap;

/// Current UTC time as `YYYY-MM-DDTHH:MM:SSZ` (hand-rolled: one stamp
/// function is not worth a date crate dependency).
pub fn now_iso() -> String {
    format_iso(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0),
    )
}

/// Second-precision cache: output-identical to `now_iso` (the format has
/// no sub-second digits), minus the clock read + format machinery on
/// repeat calls inside the same second. Stamps call this, not `now_iso`.
pub fn now_iso_cached() -> String {
    static CACHED: std::sync::Mutex<(u64, String)> = std::sync::Mutex::new((u64::MAX, String::new()));
    let secs = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    let mut g = CACHED.lock().unwrap();
    if g.0 != secs {
        *g = (secs, format_iso(secs));
    }
    g.1.clone()
}

fn format_iso(secs: u64) -> String {
    // Days → civil date (Hinnant algorithm), seconds → clock.
    let days = (secs / 86_400) as i64;
    let sod = (secs % 86_400) as i64;
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1_460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!("{y:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z", m, d, sod / 3_600, sod % 3_600 / 60, sod % 60)
}

fn is_sentinel(v: &serde_json::Value) -> bool {
    v.as_object().is_some_and(|o| o.get("__type__").and_then(|t| t.as_str()).is_some())
}

/// Borrowed deep scan: does this value contain ANY sentinel (top-level
/// or nested)? No allocation — the fast path gate for the resolvers.
fn has_sentinel(v: &serde_json::Value) -> bool {
    match v {
        serde_json::Value::Array(items) => items.iter().any(has_sentinel),
        serde_json::Value::Object(map) => {
            map.get("__type__").and_then(|t| t.as_str()).is_some() || map.values().any(has_sentinel)
        }
        _ => false,
    }
}

fn op_of(v: &serde_json::Value) -> Option<&str> {
    v.as_object()?.get("__type__")?.as_str()
}

/// Deep-resolve sentinels inside a plain value (arrays + nested objects),
/// for the create path and for non-sentinel update values.
fn resolve_deep(v: serde_json::Value, ts: &str) -> Option<serde_json::Value> {
    match v {
        serde_json::Value::Array(items) => Some(serde_json::Value::Array(
            items.into_iter().filter_map(|i| resolve_deep(i, ts)).collect(),
        )),
        serde_json::Value::Object(map) => {
            if op_of(&serde_json::Value::Object(map.clone())).is_some() {
                return resolve_sentinel(
                    &map.into_iter().collect::<serde_json::Map<String, serde_json::Value>>(),
                    ts,
                );
            }
            let out: serde_json::Map<String, serde_json::Value> = map
                .into_iter()
                .filter_map(|(k, v)| resolve_deep(v, ts).map(|r| (k, r)))
                .collect();
            Some(serde_json::Value::Object(out))
        }
        other => Some(other),
    }
}

fn resolve_sentinel(
    map: &serde_json::Map<String, serde_json::Value>,
    ts: &str,
) -> Option<serde_json::Value> {
    match map.get("__type__").and_then(|t| t.as_str()) {
        Some("serverTimestamp") => Some(serde_json::Value::String(ts.to_string())),
        Some("increment") => Some(map.get("n").cloned().unwrap_or(serde_json::json!(0))),
        Some("arrayUnion") => Some(map.get("elements").cloned().unwrap_or(serde_json::json!([]))),
        Some("arrayRemove") => Some(serde_json::json!([])),
        Some("deleteField") => None,
        _ => {
            // Unknown __type__: pass through resolved (legacy parity).
            let out: serde_json::Map<String, serde_json::Value> = map
                .clone()
                .into_iter()
                .filter_map(|(k, v)| resolve_deep(v, ts).map(|r| (k, r)))
                .collect();
            Some(serde_json::Value::Object(out))
        }
    }
}

/// Insert / full-replace path: collapse sentinels to plain values.
pub fn resolve_for_create(data: HashMap<String, serde_json::Value>) -> HashMap<String, serde_json::Value> {
    // Fast path (the 99% case): no sentinel anywhere → zero allocs.
    if !data.values().any(has_sentinel) {
        return data;
    }
    let ts = now_iso_cached();
    data.into_iter()
        .filter_map(|(k, v)| {
            if is_sentinel(&v) {
                let map = v.as_object().unwrap().clone();
                resolve_sentinel(&map, &ts).map(|r| (k, r))
            } else {
                resolve_deep(v, &ts).map(|r| (k, r))
            }
        })
        .collect()
}

fn get_path<'a>(data: &'a serde_json::Value, path: &str) -> Option<&'a serde_json::Value> {
    let mut cur = data;
    for part in path.split('.') {
        cur = cur.as_object()?.get(part)?;
    }
    Some(cur)
}

fn set_path(data: &mut serde_json::Value, path: &str, value: serde_json::Value) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let last = parts.pop().unwrap_or(path);
    let mut cur = data;
    for part in parts {
        if !cur.is_object() {
            *cur = serde_json::json!({});
        }
        let obj = cur.as_object_mut().unwrap();
        if !obj.get(part).is_some_and(|v| v.is_object()) {
            obj.insert(part.to_string(), serde_json::json!({}));
        }
        cur = obj.get_mut(part).unwrap();
    }
    if let Some(obj) = cur.as_object_mut() {
        obj.insert(last.to_string(), value);
    }
}

fn delete_path(data: &mut serde_json::Value, path: &str) {
    let mut parts: Vec<&str> = path.split('.').collect();
    let Some(last) = parts.pop() else { return };
    let mut cur = data;
    for part in parts {
        match cur.as_object_mut().and_then(|o| o.get_mut(part)) {
            Some(next) => cur = next,
            None => return,
        }
    }
    if let Some(obj) = cur.as_object_mut() {
        obj.remove(last);
    }
}

/// Merge path over an existing body: sentinels execute, plain values set
/// via dot-path (nested sentinels inside them resolve deep, like legacy).
pub fn apply_update(
    base: HashMap<String, serde_json::Value>,
    updates: HashMap<String, serde_json::Value>,
) -> HashMap<String, serde_json::Value> {
    let ts = now_iso_cached();
    let mut root = serde_json::Value::Object(base.into_iter().collect());
    for (path, value) in updates {
        if is_sentinel(&value) {
            let map = value.as_object().unwrap().clone();
            match op_of(&value) {
                Some("serverTimestamp") => set_path(&mut root, &path, serde_json::Value::String(ts.clone())),
                Some("increment") => {
                    let n = map.get("n").and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let cur = get_path(&root, &path).and_then(|v| v.as_f64()).unwrap_or(0.0);
                    let sum = cur + n;
                    // Keep ints integral (legacy Number() semantics).
                    let v = if n.fract() == 0.0 && cur.fract() == 0.0 {
                        serde_json::json!(sum as i64)
                    } else {
                        serde_json::json!(sum)
                    };
                    set_path(&mut root, &path, v);
                }
                Some("arrayUnion") => {
                    let mut arr: Vec<serde_json::Value> = match get_path(&root, &path) {
                        Some(serde_json::Value::Array(a)) => a.clone(),
                        _ => Vec::new(),
                    };
                    if let Some(els) = map.get("elements").and_then(|e| e.as_array()) {
                        let have: Vec<String> = arr.iter().map(|i| i.to_string()).collect();
                        for el in els {
                            if !have.contains(&el.to_string()) {
                                arr.push(el.clone());
                            }
                        }
                    }
                    set_path(&mut root, &path, serde_json::Value::Array(arr));
                }
                Some("arrayRemove") => {
                    let arr: Vec<serde_json::Value> = match get_path(&root, &path) {
                        Some(serde_json::Value::Array(a)) => a.clone(),
                        _ => Vec::new(),
                    };
                    let gone: Vec<String> = map
                        .get("elements")
                        .and_then(|e| e.as_array())
                        .map(|els| els.iter().map(|i| i.to_string()).collect())
                        .unwrap_or_default();
                    let kept: Vec<serde_json::Value> =
                        arr.into_iter().filter(|i| !gone.contains(&i.to_string())).collect();
                    set_path(&mut root, &path, serde_json::Value::Array(kept));
                }
                Some("deleteField") => delete_path(&mut root, &path),
                _ => {
                    if let Some(r) = resolve_deep(serde_json::Value::Object(map), &ts) {
                        set_path(&mut root, &path, r);
                    }
                }
            }
        } else if !has_sentinel(&value) {
            // Fast path: plain value needs no resolve (still goes through
            // set_path for dot-path keys).
            set_path(&mut root, &path, value);
        } else if let Some(r) = resolve_deep(value, &ts) {
            set_path(&mut root, &path, r);
        }
    }
    match root {
        serde_json::Value::Object(m) => m.into_iter().collect(),
        _ => HashMap::new(), // unreachable: root starts as Object
    }
}

/// Stamp a brand-new document: user-supplied stamps win, else now.
pub fn stamp_new(mut data: HashMap<String, serde_json::Value>) -> HashMap<String, serde_json::Value> {
    let ts = serde_json::Value::String(now_iso_cached());
    data.entry("createdAt".to_string()).or_insert_with(|| ts.clone());
    data.entry("updatedAt".to_string()).or_insert(ts);
    data
}

/// Stamp a rewrite: `createdAt` preserved when present, `updatedAt` refreshed.
pub fn stamp_update(
    mut data: HashMap<String, serde_json::Value>,
    created_at: Option<serde_json::Value>,
) -> HashMap<String, serde_json::Value> {
    if let Some(c) = created_at {
        data.entry("createdAt".to_string()).or_insert(c);
    }
    data.insert("updatedAt".to_string(), serde_json::Value::String(now_iso_cached()));
    data
}

#[cfg(test)]
mod tests {
    use super::*;

    fn doc(pairs: &[(&str, serde_json::Value)]) -> HashMap<String, serde_json::Value> {
        pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect()
    }

    #[test]
    fn timestamp_format_sane() {
        let ts = now_iso();
        assert_eq!(ts.len(), 20);
        assert!(ts.ends_with('Z'));
        assert_eq!(&ts[10..11], "T");
    }

    #[test]
    fn timestamp_cache_matches_primitive() {
        // Output-identical to now_iso (second granularity): the cached
        // value always formats either the pre- or post-call second.
        let secs = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0)
        };
        let before = secs();
        let _ = now_iso_cached(); // refresh: cache now holds `before`'s second (or newer)
        let c = now_iso_cached();
        let after = secs();
        assert!(c == format_iso(before) || c == format_iso(after));
        assert_eq!(c.len(), 20);
    }

    #[test]
    fn has_sentinel_finds_nested() {
        assert!(!has_sentinel(&serde_json::json!({"a": 1, "b": [1, {"c": "x"}]})));
        assert!(!has_sentinel(&serde_json::json!("__type__")));
        assert!(has_sentinel(&serde_json::json!({"__type__": "increment", "n": 1})));
        assert!(has_sentinel(&serde_json::json!({"a": {"b": {"__type__": "deleteField"}}})));
    }

    #[test]
    fn create_resolves_sentinels() {
        let out = resolve_for_create(doc(&[
            ("n", serde_json::json!({"__type__": "increment", "n": 5})),
            ("t", serde_json::json!({"__type__": "serverTimestamp"})),
            ("u", serde_json::json!({"__type__": "arrayUnion", "elements": [1]})),
            ("r", serde_json::json!({"__type__": "arrayRemove", "elements": [1]})),
            ("d", serde_json::json!({"__type__": "deleteField"})),
        ]));
        assert_eq!(out.get("n"), Some(&serde_json::json!(5)));
        assert!(out.get("t").and_then(|v| v.as_str()).is_some());
        assert_eq!(out.get("u"), Some(&serde_json::json!([1])));
        assert_eq!(out.get("r"), Some(&serde_json::json!([])));
        assert!(!out.contains_key("d"));
    }

    #[test]
    fn update_executes_atomics_and_dot_paths() {
        let base = doc(&[
            ("n", serde_json::json!(10)),
            ("tags", serde_json::json!(["a"])),
            ("gone", serde_json::json!(1)),
            ("deep", serde_json::json!({"x": 1})),
        ]);
        let out = apply_update(
            base,
            doc(&[
                ("n", serde_json::json!({"__type__": "increment", "n": 2})),
                ("tags", serde_json::json!({"__type__": "arrayUnion", "elements": ["a", "b"]})),
                ("tags2", serde_json::json!({"__type__": "arrayRemove", "elements": ["a"]})),
                ("gone", serde_json::json!({"__type__": "deleteField"})),
                ("deep.y", serde_json::json!(2)),
            ]),
        );
        assert_eq!(out.get("n"), Some(&serde_json::json!(12)));
        assert_eq!(out.get("tags"), Some(&serde_json::json!(["a", "b"])));
        assert_eq!(out.get("tags2"), Some(&serde_json::json!([])));
        assert!(!out.contains_key("gone"));
        assert_eq!(out.get("deep"), Some(&serde_json::json!({"x": 1, "y": 2})));
    }

    #[test]
    fn stamps_preserve_user_values() {
        let out = stamp_new(doc(&[("createdAt", serde_json::json!("kept"))]));
        assert_eq!(out.get("createdAt"), Some(&serde_json::json!("kept")));
        assert!(out.get("updatedAt").and_then(|v| v.as_str()).is_some());
        let out = stamp_update(doc(&[]), Some(serde_json::json!("c0")));
        assert_eq!(out.get("createdAt"), Some(&serde_json::json!("c0")));
    }
}

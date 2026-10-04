//! Managed file endpoints (issue #11): byte files + metadata docs.
//!
//! Bytes live content-addressed under `file_dir` (`{hh}/{sha256}` —
//! dedup is free, traversal impossible since only hex hits the fs).
//! Metadata is an ordinary doc in the addressed user collection, so
//! policy slots, indexes and aliases apply with zero new machinery.
//! Crash ordering is `pending` meta -> bytes -> `ready` meta; the
//! sweeper below reaps temp files, stale pendings and orphan bytes.
//! DELETE removes the metadata only — bytes are reclaimed by the
//! sweeper (no refcounting; see the ceiling note on spawn).

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::extract::{multipart::Field, Extension, Multipart, Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::Json;
use hakobackend_core::{atomics, AuthContext, Change, ChangeKind, Database, Doc, Method};
use hakobackend_policy::PolicyFile;
use sha2::{Digest, Sha256};

use super::{
    denied_internal, deny_if_read_only, err, forbidden, realtime, stored, valid_names, wstats, AppState,
    WSAMP,
};

/// Boot-time file config (restart to change, same discipline as
/// body_limit — reload ignores it).
#[derive(Debug, Clone)]
pub struct FileConf {
    /// None = feature off (uploads 503).
    pub dir: Option<String>,
    /// Per-file byte cap (defaults to body_limit_mb; that layer
    /// hard-ceilings regardless).
    pub max_bytes: u64,
    /// Batch part cap (default 1).
    pub max_batch: u64,
    /// MIME allowlist.
    pub mime_allow: Arc<Vec<String>>,
    /// Signed-URL HMAC secret (empty = signed URLs off).
    pub sign_secret: Vec<u8>,
}

impl FileConf {
    pub fn from_cfg(
        dir: Option<String>,
        max_mb: u64,
        max_batch: u64,
        mime_allow: Vec<String>,
        sign_secret: String,
    ) -> Self {
        FileConf {
            dir,
            max_bytes: max_mb.saturating_mul(1024 * 1024),
            max_batch,
            mime_allow: Arc::new(mime_allow),
            sign_secret: sign_secret.into_bytes(),
        }
    }

    fn on(&self) -> bool {
        self.dir.is_some()
    }
}

// --- Pure helpers (unit-tested below) ---

/// HMAC-SHA256, hand-rolled over sha2.
/// ponytail: a new hmac crate for one call site is heavier than the
/// 15-line standard construct; sha2 is already a dep. Correctness
/// rests on the textbook ipad/opad form, covered by RFC 4231 vectors.
fn hmac_sha256(key: &[u8], msg: &[u8]) -> [u8; 32] {
    let mut kb = [0u8; 64];
    if key.len() > 64 {
        kb[..32].copy_from_slice(&Sha256::digest(key));
    } else {
        kb[..key.len()].copy_from_slice(key);
    }
    let (mut ipad, mut opad) = ([0x36u8; 64], [0x5cu8; 64]);
    for i in 0..64 {
        ipad[i] ^= kb[i];
        opad[i] ^= kb[i];
    }
    let inner = Sha256::new().chain_update(ipad).chain_update(msg).finalize();
    Sha256::new().chain_update(opad).chain_update(inner).finalize().into()
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

fn sig_msg(collection: &str, id: &str, field: &str, exp: u64) -> String {
    format!("{collection}\n{id}\n{field}\n{exp}")
}

fn mint_sig(secret: &[u8], collection: &str, id: &str, field: &str, exp: u64) -> String {
    hex(&hmac_sha256(secret, sig_msg(collection, id, field, exp).as_bytes()))
}

fn verify_sig(secret: &[u8], collection: &str, id: &str, field: &str, exp: u64, sig: &str) -> bool {
    if secret.is_empty() || now_secs() > exp {
        return false;
    }
    let want = mint_sig(secret, collection, id, field, exp);
    // ponytail: byte loop instead of the subtle crate — one call site,
    // and == on Strings would early-exit (timing oracle on the MAC).
    want.len() == sig.len() && want.bytes().zip(sig.bytes()).fold(0u8, |a, (x, y)| a | (x ^ y)) == 0
}

fn now_secs() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
}

fn now_micros() -> u64 {
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_micros() as u64).unwrap_or(0)
}

/// Single `bytes=A-B` / `bytes=A-` / `bytes=-N`. Malformed -> None
/// (serve 200); start >= size is reported by the caller as 416.
fn parse_range(header: &str, size: u64) -> Option<(u64, u64)> {
    let spec = header.strip_prefix("bytes=")?.trim();
    let (a, b) = spec.split_once('-')?;
    if a.is_empty() {
        let n: u64 = b.parse().ok()?;
        if n == 0 || size == 0 {
            return None;
        }
        let n = n.min(size);
        Some((size - n, size - 1))
    } else {
        let start: u64 = a.parse().ok()?;
        let end: u64 = if b.is_empty() { size.saturating_sub(1) } else { b.parse().ok()? };
        if end < start {
            return None;
        }
        Some((start, end.min(size.saturating_sub(1))))
    }
}

/// Magic agreement for declared types with known signatures. Unknown
/// DECLARED types fall back to allowlist-trust (documented ceiling):
/// every default-allowlist member has known magic, so lying is always
/// caught on defaults; custom types are the operator's risk to allow.
fn magic_ok(mime: &str, head: &[u8]) -> bool {
    match mime.to_ascii_lowercase().as_str() {
        "image/png" => head.starts_with(b"\x89PNG\r\n\x1a\n"),
        "image/jpeg" => head.starts_with(b"\xff\xd8\xff"),
        "image/gif" => head.starts_with(b"GIF87a") || head.starts_with(b"GIF89a"),
        "image/webp" => head.len() >= 12 && head.starts_with(b"RIFF") && &head[8..12] == b"WEBP",
        "application/pdf" => head.starts_with(b"%PDF-"),
        _ => true,
    }
}

/// Recognize a file-meta object: the sweeper + handlers key off this
/// shape, never off key names alone.
fn as_file_meta(v: &serde_json::Value) -> Option<&str> {
    let o = v.as_object()?;
    let sha = o.get("sha256")?.as_str()?;
    if o.get("state")?.as_str().is_some_and(|s| s == "ready" || s == "pending")
        && sha.len() == 64
        && sha.bytes().all(|c| c.is_ascii_hexdigit())
    {
        Some(sha)
    } else {
        None
    }
}

// --- Path + guard plumbing ---

/// `/api/files/{*path}` segments: [coll] batch, [coll, id] single,
/// [coll.., id, field] explicit field. Deterministic: with 3+ segs the
/// last is ALWAYS the field (a doc at coll "a/b" id "c" is metadata-
/// addressable via normal routes, not here).
enum FileTarget {
    Batch { collection: String },
    Single { collection: String, id: String, field: String },
}

fn parse_target(path: &str) -> Result<FileTarget, Response> {
    let segs: Vec<&str> = path.trim_matches('/').split('/').filter(|s| !s.is_empty()).collect();
    let (collection, id, field) = match segs.len() {
        1 => (segs[0].to_string(), String::new(), String::new()),
        2 => (segs[0].to_string(), segs[1].to_string(), "file".to_string()),
        n if n >= 3 => (
            segs[..n - 2].join("/"),
            segs[n - 2].to_string(),
            segs[n - 1].to_string(),
        ),
        _ => return Err(err(StatusCode::BAD_REQUEST, "path needs collection[/id[/field]]")),
    };
    if collection.is_empty() {
        return Err(err(StatusCode::BAD_REQUEST, "path needs collection[/id[/field]]"));
    }
    if let Some(r) = denied_internal(&collection) {
        return Err(r);
    }
    if id.is_empty() {
        if let Some(r) = valid_names(&collection, None) {
            return Err(r);
        }
        return Ok(FileTarget::Batch { collection });
    }
    if let Some(r) = valid_names(&collection, Some(&id)) {
        return Err(r);
    }
    if !hakobackend_core::valid_collection_path(field.as_str()) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid field name"));
    }
    Ok(FileTarget::Single { collection, id, field })
}

fn file_off() -> Response {
    err(StatusCode::SERVICE_UNAVAILABLE, "files not configured (file_dir unset)")
}

fn bytes_path(dir: &str, sha: &str) -> std::path::PathBuf {
    std::path::Path::new(dir).join(&sha[..2]).join(sha)
}

fn uploader(auth: &Option<AuthContext>) -> String {
    auth.as_ref().map(|a| a.uid.clone()).unwrap_or_else(|| "-".into())
}

fn meta_value(
    name: String,
    mime: String,
    size: u64,
    sha: String,
    state: &str,
    who: String,
    created: Option<serde_json::Value>,
) -> serde_json::Value {
    // ponytail: HashMap from the start — stamp_* speak HashMap, and the
    // serde_json::Map detour bought nothing but conversions.
    let mut m: HashMap<String, serde_json::Value> = HashMap::new();
    m.insert("name".into(), name.into());
    m.insert("mime".into(), mime.into());
    m.insert("size".into(), size.into());
    m.insert("sha256".into(), sha.into());
    m.insert("state".into(), state.into());
    m.insert("pendingSince".into(), now_micros().into());
    m.insert("uploader".into(), who.into());
    let stamped = if state == "ready" {
        atomics::stamp_update(m, created)
    } else {
        atomics::stamp_new(m)
    };
    serde_json::Value::Object(stamped.into_iter().collect())
}

// --- Upload ---

struct Part {
    name: String,
    mime: String,
    bytes_path_tmp: std::path::PathBuf,
    size: u64,
    sha: String,
}

/// Stream one multipart part to a temp file (bounded RAM: chunked),
/// enforcing the byte cap + declared-type allowlist + magic agreement.
async fn store_part(conf: &FileConf, dir: &str, mut field: Field<'_>) -> Result<Part, Response> {
    let name: String = field.file_name().unwrap_or("upload").chars().take(256).collect();
    let mime = field.content_type().map(|m| m.to_string()).unwrap_or_default();
    // Declared type must be allowlisted (exact, case-insensitive).
    // ponytail: no mime-crate parse — unparseable garbage is simply not
    // in the allowlist, so it 415s here either way.
    if !conf.mime_allow.iter().any(|a| a.eq_ignore_ascii_case(&mime)) {
        return Err(err(StatusCode::UNSUPPORTED_MEDIA_TYPE, format!("mime `{mime}` not allowed")));
    }
    let tmp = std::path::Path::new(dir).join(format!(".tmp-{}-{}", std::process::id(), now_micros()));
    let mut f = tokio::fs::File::create(&tmp)
        .await
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, format!("file store unwritable: {e}")))?;
    let mut hasher = Sha256::new();
    let mut size = 0u64;
    let mut head = Vec::with_capacity(12);
    use tokio::io::AsyncWriteExt;
    while let Some(chunk) = field
        .chunk()
        .await
        .map_err(|e| err(StatusCode::BAD_REQUEST, format!("multipart read: {e}")))?
    {
        size += chunk.len() as u64;
        if size > conf.max_bytes {
            let _ = tokio::fs::remove_file(&tmp).await;
            return Err(err(
                StatusCode::PAYLOAD_TOO_LARGE,
                format!("file exceeds file_max_mb ({} bytes in)", conf.max_bytes),
            ));
        }
        if head.len() < 12 {
            head.extend_from_slice(&chunk[..chunk.len().min(12 - head.len())]);
        }
        hasher.update(&chunk);
        f.write_all(&chunk)
            .await
            .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, format!("file store write: {e}")))?;
    }
    f.flush().await.map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, format!("file store flush: {e}")))?;
    drop(f);
    if !magic_ok(&mime, &head) {
        let _ = tokio::fs::remove_file(&tmp).await;
        return Err(err(
            StatusCode::UNSUPPORTED_MEDIA_TYPE,
            format!("content does not match declared {mime}"),
        ));
    }
    Ok(Part { name, mime, bytes_path_tmp: tmp, size, sha: hex(&hasher.finalize()) })
}

/// Promote temp -> content-addressed final (dedup: existing wins).
async fn promote(dir: &str, tmp: &std::path::Path, sha: &str) -> Result<(), Response> {
    let final_p = bytes_path(dir, sha);
    if tokio::fs::try_exists(&final_p)
        .await
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, format!("file store stat: {e}")))?
    {
        let _ = tokio::fs::remove_file(tmp).await;
        return Ok(());
    }
    if let Some(parent) = final_p.parent() {
        tokio::fs::create_dir_all(parent)
            .await
            .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, format!("file store mkdir: {e}")))?;
    }
    tokio::fs::rename(tmp, &final_p)
        .await
        .map_err(|e| err(StatusCode::SERVICE_UNAVAILABLE, format!("file store rename: {e}")))
}

/// Shared single-file commit: pending meta -> bytes -> ready meta.
/// `existing` is None on the batch path (fresh insert).
async fn commit_file(
    s: &AppState,
    auth: &Option<AuthContext>,
    collection: &str,
    stored_coll: &str,
    id: &str,
    field: &str,
    part: Part,
    existing: Option<Doc>,
    policy: &Arc<PolicyFile>,
    db: &Arc<dyn Database>,
) -> Result<(String, serde_json::Value), Response> {
    let conf = s.files.clone();
    let dir = conf.dir.clone().unwrap_or_default();
    let need = if existing.is_some() { Method::Update } else { Method::Create };
    // pre-bytes shell check: fail-closed before touching disk.
    let shell = Doc { id: id.to_string(), data: Default::default() };
    if !policy.allow(auth.as_ref(), collection, need, Some(&shell)) {
        let _ = tokio::fs::remove_file(&part.bytes_path_tmp).await;
        return Err(forbidden());
    }
    let created = existing
        .as_ref()
        .and_then(|d| d.data.get("createdAt").cloned())
        .or_else(|| {
            existing.as_ref().and_then(|d| {
                d.data
                    .get(field)
                    .and_then(|v| v.get("createdAt").cloned())
            })
        });
    let pending = meta_value(part.name.clone(), part.mime.clone(), part.size, part.sha.clone(), "pending", uploader(auth), None);
    let doc_id = if existing.is_some() {
        // Merge-write the pending marker (user fields untouched).
        let mut data = existing.map(|d| d.data).unwrap_or_default();
        data.insert(field.to_string(), pending);
        let doc = Doc { id: id.to_string(), data };
        db.set(stored_coll, id, doc, false)
            .await
            .map_err(|e| err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()))?;
        id.to_string()
    } else {
        let mut data = HashMap::new();
        data.insert(field.to_string(), pending);
        // Single path carries the URL id (unlike batch auto-ids):
        // insert honors explicit ids (same as POST create with body id).
        let doc = Doc { id: id.to_string(), data };
        let back = db
            .insert(stored_coll, doc)
            .await
            .map_err(|e| err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()))?;
        back.id.clone()
    };
    if let Err(r) = promote(&dir, &part.bytes_path_tmp, &part.sha).await {
        // Bytes failed: roll the pending marker back so the sweeper
        // never has to reason about it (best-effort; bytes are absent).
        let _ = remove_field(db, stored_coll, &doc_id, field).await;
        return Err(r);
    }
    let ready = meta_value(part.name, part.mime, part.size, part.sha.clone(), "ready", uploader(auth), created);
    let got = db
        .get(stored_coll, &doc_id)
        .await
        .map_err(|e| err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()))?;
    let mut data = got.map(|d| d.data).unwrap_or_default();
    data.insert(field.to_string(), ready.clone());
    let saved = db
        .set(stored_coll, &doc_id, Doc { id: doc_id.clone(), data }, false)
        .await
        .map_err(|e| err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()))?;
    realtime::emit(
        stored_coll,
        Change {
            collection: stored_coll.to_string(),
            id: doc_id.clone(),
            kind: ChangeKind::Change,
            old: None,
            new: Some(saved),
        },
    );
    Ok((doc_id, ready))
}

/// POST /api/files/{coll}/{id}[/{field}] (single replace) and
/// POST /api/files/{coll} (batch, auto ids, `file` parts x N).
pub async fn upload(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    mut mp: Multipart,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    if !s.files.on() {
        return file_off();
    }
    let target = match parse_target(&path) {
        Ok(t) => t,
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let samp = WSAMP.try_get().unwrap_or(false);
    let mut ws_t = std::time::Instant::now();
    // Dir ensured per request (boot does it too; tests bypass boot).
    // Idempotent, one syscall on a cold path.
    let dir = s.files.dir.clone().unwrap_or_default();
    if let Err(e) = tokio::fs::create_dir_all(&dir).await {
        return err(StatusCode::SERVICE_UNAVAILABLE, format!("file store unwritable: {e}"));
    }
    // Collect `file` parts only (other form fields ignored, documented).
    let mut parts = Vec::new();
    loop {
        let f = match mp.next_field().await {
            Ok(Some(f)) => f,
            // Truncated/errored bodies fail the request, never silently
            // drop to a confusing "needs >= 1 part".
            Ok(None) => break,
            Err(e) => return err(StatusCode::BAD_REQUEST, format!("multipart read: {e}")),
        };
        if f.name() != Some("file") {
            continue;
        }
        if parts.len() as u64 >= s.files.max_batch {
            return err(
                StatusCode::BAD_REQUEST,
                format!("too many file parts (file_max_batch={})", s.files.max_batch),
            );
        }
        match store_part(&s.files, &dir, f).await {            Ok(p) => parts.push(p),
            Err(r) => return r,
        }
    }
    if parts.is_empty() {
        return err(StatusCode::BAD_REQUEST, "multipart needs >= 1 `file` part");
    }
    if samp {
        wstats::add(&wstats::B[0], ws_t.elapsed().as_nanos() as u64);
        ws_t = std::time::Instant::now();
    }
    let out = match target {
        FileTarget::Batch { collection } => {
            let stored_coll = stored(&collection);
            let _ = hot.db.ensure_collection(&stored_coll).await;
            let mut out = Vec::with_capacity(parts.len());
            for p in parts {
                match commit_file(&s, &auth, &collection, &stored_coll, "", "file", p, None, &hot.policy, &hot.db).await {
                    Ok((id, meta)) => out.push(serde_json::json!({"id": id, "file": meta})),
                    Err(r) => return r,
                }
            }
            Json(serde_json::Value::Array(out)).into_response()
        }
        FileTarget::Single { collection, id, field } => {
            // Single replace owns exactly one part (multipart with one).
            if parts.len() > 1 {
                for p in &parts {
                    let _ = tokio::fs::remove_file(&p.bytes_path_tmp).await;
                }
                return err(StatusCode::BAD_REQUEST, "single-file route takes 1 `file` part (batch via collection route)");
            }
            let stored_coll = stored(&collection);
            let _ = hot.db.ensure_collection(&stored_coll).await;
            let existing = hot.db.get(&stored_coll, &id).await.ok().flatten();
            let p = parts.into_iter().next().unwrap();
            match commit_file(&s, &auth, &collection, &stored_coll, &id, &field, p, existing, &hot.policy, &hot.db).await {
                // ponytail: manual map insert — json! takes literal keys,
                // so a dynamic field name needs the real Map.
                Ok((doc_id, meta)) => {
                    let mut o = serde_json::Map::new();
                    o.insert("id".into(), doc_id.into());
                    o.insert(field, meta);
                    Json(serde_json::Value::Object(o)).into_response()
                }
                Err(r) => r,
            }
        }
    };
    if samp {
        wstats::add(&wstats::B[1], ws_t.elapsed().as_nanos() as u64);
    }
    out
}

// --- Download ---

/// GET /api/files/{coll}/{id}[/{field}]: bytes, or `?sign=<secs>` to
/// mint a signed URL (needs Get, same as downloading), or `?exp=&sig=`
/// to consume one anonymously.
pub async fn download(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    if !s.files.on() {
        return file_off();
    }
    let (collection, id, field) = match parse_target(&path) {
        Ok(FileTarget::Single { collection, id, field }) => (collection, id, field),
        Ok(FileTarget::Batch { .. }) => {
            return err(StatusCode::BAD_REQUEST, "GET needs collection/id[/field]")
        }
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let samp = WSAMP.try_get().unwrap_or(false);
    let mut ws_t = std::time::Instant::now();
    let stored_coll = stored(&collection);
    let doc = hot.db.get(&stored_coll, &id).await.ok().flatten();
    // ponytail: shell check on missing docs, exactly like get_or_list —
    // public+absent is 404, deny is 403 either way. AuthZ first,
    // existence second, same as the document surface.
    let mut allowed = match &doc {
        Some(d) => hot.policy.allow(auth.as_ref(), &collection, Method::Get, Some(d)),
        None => {
            let shell = Doc { id: id.clone(), data: Default::default() };
            hot.policy.allow(auth.as_ref(), &collection, Method::Get, Some(&shell))
        }
    };
    // Signed-URL consume: anonymous iff MAC valid + fresh + feature on.
    if !allowed {
        if let (Some(exp), Some(sig)) = (q.get("exp"), q.get("sig")) {
            if let Ok(exp) = exp.parse::<u64>() {
                allowed = verify_sig(&s.files.sign_secret, &collection, &id, &field, exp, sig);
            }
        }
    }
    // Signed-URL mint: caller must already be allowed (same as download).
    if let Some(secs) = q.get("sign") {
        if !allowed {
            return forbidden();
        }
        if s.files.sign_secret.is_empty() {
            return err(StatusCode::SERVICE_UNAVAILABLE, "signed URLs off (file_sign_secret unset)");
        }
        let secs: u64 = secs.parse().unwrap_or(0);
        if secs == 0 || secs > 3600 {
            return err(StatusCode::BAD_REQUEST, "sign needs 1..=3600 seconds");
        }
        let exp = now_secs() + secs;
        let sig = mint_sig(&s.files.sign_secret, &collection, &id, &field, exp);
        let url = format!("/api/files/{}/{}{}?exp={exp}&sig={sig}", collection, id, field_suffix(&field));
        return Json(serde_json::json!({"url": url, "exp": exp})).into_response();
    }
    if !allowed {
        return forbidden();
    }
    if samp {
        wstats::add(&wstats::B[2], ws_t.elapsed().as_nanos() as u64);
        ws_t = std::time::Instant::now();
    }
    let meta = doc.as_ref().and_then(|d| d.data.get(&field)).cloned();
    let meta = match meta {
        Some(m) => m,
        None => return err(StatusCode::NOT_FOUND, "no such file"),
    };
    if meta.get("state").and_then(|v| v.as_str()) != Some("ready") {
        return err(StatusCode::NOT_FOUND, "no such file");
    }
    let (sha, mime, size) = match (
        meta.get("sha256").and_then(|v| v.as_str()),
        meta.get("mime").and_then(|v| v.as_str()),
        meta.get("size").and_then(|v| v.as_u64()),
    ) {
        (Some(a), Some(b), Some(c)) => (a.to_string(), b.to_string(), c),
        _ => return err(StatusCode::NOT_FOUND, "no such file"),
    };
    if as_file_meta(&meta).is_none() {
        return err(StatusCode::NOT_FOUND, "no such file");
    }
    let fpath = bytes_path(s.files.dir.as_deref().unwrap_or(""), &sha);
    let file = match tokio::fs::File::open(&fpath).await {
        Ok(f) => f,
        // Metadata without bytes: visible 404 + loud log (repair signal,
        // never silent). The sweeper cannot fix this direction.
        Err(_) => {
            eprintln!("[ub] files: metadata without bytes {collection}/{id}/{field} sha={sha}");
            return err(StatusCode::NOT_FOUND, "no such file");
        }
    };
    let etag = format!("\"{sha}\"");
    if headers
        .get(axum::http::header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|v| v.split(',').any(|t| t.trim() == etag || t.trim() == "*"))
    {
        return StatusCode::NOT_MODIFIED.into_response();
    }
    // Single range only; malformed -> full 200, unsatisfiable -> 416.
    // ponytail: no multipart/byteranges (unevidenced; players retry with
    // a single range, which is what this serves).
    let (start, end, status) = match headers
        .get(axum::http::header::RANGE)
        .and_then(|v| v.to_str().ok())
    {
        None => (0, size.saturating_sub(1), StatusCode::OK),
        Some(h) => match parse_range(h, size) {
            // Present but unparseable -> full 200 per RFC 9110 §14.2.
            None => (0, size.saturating_sub(1), StatusCode::OK),
            Some((a, _b)) if a >= size => {
                return (
                    StatusCode::RANGE_NOT_SATISFIABLE,
                    [(axum::http::header::CONTENT_RANGE, format!("bytes */{size}"))],
                )
                    .into_response();
            }
            Some((a, b)) => (a, b, StatusCode::PARTIAL_CONTENT),
        },
    };
    let len = end.saturating_sub(start) + 1;
    let stream = futures::stream::unfold((file, start, len), |(mut f, pos, left)| async move {
        if left == 0 {
            return None;
        }
        use tokio::io::{AsyncReadExt, AsyncSeekExt};
        if f.seek(std::io::SeekFrom::Start(pos)).await.is_err() {
            return None;
        }
        let mut buf = vec![0u8; left.min(64 * 1024) as usize];
        match f.read(&mut buf).await {
            Ok(0) | Err(_) => None,
            Ok(n) => {
                buf.truncate(n);
                Some((Ok::<_, std::io::Error>(axum::body::Bytes::from(buf)), (f, pos + n as u64, left - n as u64)))
            }
        }
    });
    let mut resp = (
        status,
        [
            (axum::http::header::CONTENT_TYPE, mime),
            (axum::http::header::CONTENT_LENGTH, len.to_string()),
            (axum::http::header::ETAG, etag),
            (axum::http::header::ACCEPT_RANGES, "bytes".to_string()),
        ],
        axum::body::Body::from_stream(stream),
    )
        .into_response();
    if status == StatusCode::PARTIAL_CONTENT {
        resp.headers_mut().insert(
            axum::http::header::CONTENT_RANGE,
            format!("bytes {start}-{end}/{size}").parse().unwrap(),
        );
    }
    if samp {
        wstats::add(&wstats::B[3], ws_t.elapsed().as_nanos() as u64);
    }
    resp
}

fn field_suffix(field: &str) -> String {
    if field == "file" {
        String::new()
    } else {
        format!("/{field}")
    }
}

// --- Delete ---

/// Remove one metadata field (full read-modify-write: merge=true would
/// NOT drop the key). Doc emptied -> whole doc deleted. Bytes are left
/// for the sweeper (no refcounting).
async fn remove_field(
    db: &Arc<dyn Database>,
    stored_coll: &str,
    id: &str,
    field: &str,
) -> Result<(), String> {
    let cur = db.get(stored_coll, id).await.map_err(|e| e.to_string())?;
    let mut doc = match cur {
        Some(d) => d,
        None => return Ok(()),
    };
    if doc.data.remove(field).is_none() {
        return Ok(());
    }
    if doc.data.is_empty() {
        db.delete(stored_coll, id).await.map_err(|e| e.to_string()).map(|_| ())
    } else {
        db.set(stored_coll, id, doc, false).await.map_err(|e| e.to_string()).map(|_| ())
    }
}

/// DELETE /api/files/{coll}/{id}[/{field}]: metadata only, bytes via
/// the sweeper.
pub async fn remove(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    if !s.files.on() {
        return file_off();
    }
    let (collection, id, field) = match parse_target(&path) {
        Ok(FileTarget::Single { collection, id, field }) => (collection, id, field),
        Ok(FileTarget::Batch { .. }) => {
            return err(StatusCode::BAD_REQUEST, "DELETE needs collection/id[/field]")
        }
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let stored_coll = stored(&collection);
    let doc = hot.db.get(&stored_coll, &id).await.ok().flatten();
    // Same shell-on-missing discipline as download (see above).
    let allowed = match &doc {
        Some(d) => hot.policy.allow(auth.as_ref(), &collection, Method::Delete, Some(d)),
        None => {
            let shell = Doc { id: id.clone(), data: Default::default() };
            hot.policy.allow(auth.as_ref(), &collection, Method::Delete, Some(&shell))
        }
    };
    if !allowed {
        return forbidden();
    }
    if doc.as_ref().is_none_or(|d| !d.data.contains_key(&field)) {
        return err(StatusCode::NOT_FOUND, "no such file");
    }
    match remove_field(&hot.db, &stored_coll, &id, &field).await {
        Ok(()) => {
            realtime::emit(
                &stored_coll,
                Change {
                    collection: stored_coll.clone(),
                    id: id.clone(),
                    kind: ChangeKind::Change,
                    old: None,
                    new: hot.db.get(&stored_coll, &id).await.ok().flatten(),
                },
            );
            Json(serde_json::json!({"ok": true})).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e),
    }
}

// --- Sweeper ---

/// Background reaper (spawned once at boot; follows reloads by reading
/// the hot snapshot each pass, so a reload-swapped driver can never
/// orphan-scan stale data):
/// temp files > 1h, `pending` metas > 1h (field-removed, doc dropped
/// when emptied), bytes unreferenced by any doc (mtime > 10 min guard
/// against in-flight promote->ready windows).
pub fn spawn(state: AppState, interval: Duration) {
    let dir = match state.files.dir.clone() {
        Some(d) => d,
        None => return,
    };
    tokio::spawn(async move {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            sweep_once(&state, &dir).await;
        }
    });
}

async fn sweep_once(s: &AppState, dir: &str) {
    let hot = s.hot().await;
    let cutoff = now_micros().saturating_sub(3_600_000_000);
    // Temp files from crashed uploads.
    if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
        use tokio::fs::DirEntry;
        async fn old_tmp(e: &DirEntry, cutoff_file: bool) -> bool {
            let n = e.file_name().to_string_lossy().into_owned();
            if !n.starts_with(".tmp-") {
                return false;
            }
            if !cutoff_file {
                return true;
            }
            e.metadata()
                .await
                .ok()
                .and_then(|m| m.modified().ok())
                .and_then(|t| t.elapsed().ok())
                .is_some_and(|d| d > Duration::from_secs(3600))
        }
        while let Ok(Some(e)) = rd.next_entry().await {
            if old_tmp(&e, true).await {
                let _ = tokio::fs::remove_file(e.path()).await;
            }
        }
    }
    // Referenced shas + stale pendings across every collection.
    let mut referenced = std::collections::HashSet::new();
    let mut stale: Vec<(String, String, String)> = Vec::new();
    if let Ok(colls) = hot.db.list_collections().await {
        for c in colls {
            if c.split('/').next().is_some_and(|x| x.starts_with("__")) {
                continue;
            }
            let mut offset = 0usize;
            loop {
                let opts = hakobackend_core::QueryOptions {
                    limit: Some(500),
                    offset: Some(offset),
                    ..Default::default()
                };
                let docs = hot.db.list(&c, &opts).await.unwrap_or_default();
                if docs.is_empty() {
                    break;
                }
                let n = docs.len();
                for d in &docs {
                    for (k, v) in &d.data {
                        if v.get("state").and_then(|x| x.as_str()) == Some("pending")
                            && v.get("pendingSince").and_then(|x| x.as_u64()).is_some_and(|t| t < cutoff)
                            && v.get("sha256").and_then(|x| x.as_str()).is_some()
                        {
                            stale.push((c.clone(), d.id.clone(), k.clone()));
                        }
                        if let Some(sha) = as_file_meta(v) {
                            if v.get("state").and_then(|x| x.as_str()) == Some("ready") {
                                referenced.insert(sha.to_lowercase());
                            }
                        }
                    }
                }
                offset += n;
                if n < 500 {
                    break;
                }
            }
        }
    }
    for (c, id, field) in stale {
        let _ = remove_field(&hot.db, &c, &id, &field).await;
    }
    // Orphan bytes: walk shards, delete unreferenced (mtime-guarded).
    // ponytail: only exact 64-hex names under 2-hex shards are ever
    // touched — anything else in the dir is left alone (fail-closed).
    if let Ok(mut rd) = tokio::fs::read_dir(dir).await {
        while let Ok(Some(shard)) = rd.next_entry().await {
            let sn = shard.file_name().to_string_lossy().into_owned();
            if sn.len() != 2 || !sn.bytes().all(|c| c.is_ascii_hexdigit()) || !shard.path().is_dir() {
                continue;
            }
            if let Ok(mut files) = tokio::fs::read_dir(shard.path()).await {
                while let Ok(Some(f)) = files.next_entry().await {
                    let n = f.file_name().to_string_lossy().into_owned();
                    if n.len() != 64 || !n.bytes().all(|c| c.is_ascii_hexdigit()) {
                        continue;
                    }
                    if referenced.contains(&n.to_lowercase()) {
                        continue;
                    }
                    let fresh = f
                        .metadata()
                        .await
                        .ok()
                        .and_then(|m| m.modified().ok())
                        .and_then(|t| t.elapsed().ok())
                        .is_some_and(|d| d < Duration::from_secs(600));
                    if !fresh {
                        let _ = tokio::fs::remove_file(f.path()).await;
                    }
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hmac_rfc4231_vector() {
        // RFC 4231 case 1: key 20x 0x0b, data "Hi There".
        let mac = hmac_sha256(&[0x0bu8; 20], b"Hi There");
        assert_eq!(
            hex(&mac),
            "b0344c61d8db38535ca8afceaf0bf12b881dc200c9833da726e9376c2e32cff7"
        );
    }

    #[test]
    fn sig_roundtrip_and_expiry() {
        let secret = b"test-secret";
        let exp = now_secs() + 60;
        let sig = mint_sig(secret, "avatars", "u1", "file", exp);
        assert!(verify_sig(secret, "avatars", "u1", "file", exp, &sig));
        assert!(!verify_sig(secret, "avatars", "u1", "file", exp, "00"));
        assert!(!verify_sig(secret, "avatars", "u2", "file", exp, &sig));
        assert!(!verify_sig(secret, "avatars", "u1", "file", now_secs() - 1, &mint_sig(secret, "avatars", "u1", "file", now_secs() - 1)));
        assert!(!verify_sig(b"", "avatars", "u1", "file", exp, &sig));
    }

    #[test]
    fn range_shapes() {
        assert_eq!(parse_range("bytes=0-99", 1000), Some((0, 99)));
        assert_eq!(parse_range("bytes=100-", 1000), Some((100, 999)));
        assert_eq!(parse_range("bytes=-100", 1000), Some((900, 999)));
        assert_eq!(parse_range("bytes=0-9999", 1000), Some((0, 999)));
        assert_eq!(parse_range("bytes=5-3", 1000), None);
        assert_eq!(parse_range("items=0-99", 1000), None);
        // Start past end still parses; the caller 416s it.
        assert_eq!(parse_range("bytes=5000-6000", 1000), Some((5000, 999)));
    }

    #[test]
    fn magic_table() {
        assert!(magic_ok("image/png", b"\x89PNG\r\n\x1a\nxxxx"));
        assert!(magic_ok("image/jpeg", b"\xff\xd8\xff1234"));
        assert!(magic_ok("image/gif", b"GIF89a...."));
        assert!(magic_ok("image/webp", b"RIFF....WEBP"));
        assert!(magic_ok("application/pdf", b"%PDF-1.7..."));
        assert!(!magic_ok("image/png", b"not a png at all"));
        assert!(!magic_ok("image/png", b"\xff\xd8\xff1234"));
        // Unknown declared type: allowlist-trust (operator's risk).
        assert!(magic_ok("image/svg+xml", b"anything at all"));
    }
}

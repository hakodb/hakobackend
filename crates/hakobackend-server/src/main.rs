//! hakobackend-server: universal HTTP gateway (Axum).
//! Wire protocol compatible with rethink-firestore/backend so legacy SDKs keep working.
//!
//! Plug-and-play database: driver selected in `hakobackend.toml` (`database.driver`).
//! Swap/plug-unplug DB = edit config + `POST /api/admin/reload` (no rebuild).
//! Add a new driver = a `hakobackend-db-*` crate impl'ing `hakobackend_core::Database` + 1 arm in `open_driver`.
//!
//! Endpoint flexibility: automatic wildcard (zero-config) + `policy.toml` that
//! **hot-reloads** (mtime checked on each request; file edits take effect immediately, no restart).

mod coalesce;
mod config;
mod bench;
mod realtime;
mod tokcache;
mod loginguard;
mod audit;
mod alias;
mod files;

use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response, sse},
    routing::{any, get, post},
};
use axum::extract::{ConnectInfo, Request, ws};
// Unix-listener plumbing only (no tokio UDS on Windows; the flag
// fail-closes there instead).
#[cfg(unix)]
use axum::extract::connect_info::Connected;
#[cfg(unix)]
use axum::serve::{IncomingStream, Listener};
use clap::Parser;
use config::{Args, DEFAULT_CONFIG_TEMPLATE, resolve, validate, validate_local_modes};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use hakobackend_auth_core::{AuthChain, AuthSpec, CustomAuth, open_chain};
use hakobackend_auth_github::GithubOAuth;
use hakobackend_auth_local::{ACCESS_COOKIE, DpopMode, DpopRequest, LocalAuth, REFRESH_COOKIE};
use hakobackend_core::{AuthContext, AuthProvider, Change, ChangeKind, Database, Doc, Method, PathKind, QueryOptions, parse_collection_path};
use hakobackend_db_hako::HakoDb;
use hakobackend_db_hakocluster::ClusterDb;
use hakobackend_db_postgres::PgDb;
use hakobackend_db_sqlite::SqliteDb;
use hakobackend_db_mysql::MysqlDb;
use hakobackend_db_rethinkdb::RethinkDb;
use hakobackend_policy::{Identity, PolicyFile};
use hakobackend_ratelimit::{Limiter, Quota};
use sha2::{Digest, Sha256};
use tower_http::compression::predicate::Predicate;

// Profiling showed allocator churn (malloc/free/memmove) as the top
// user-space cost: jemalloc replaces the system allocator process-wide
// (one line, no API change) on Unix. MSVC builds keep the system
// allocator (jemalloc upstream is untested there).
#[cfg(not(windows))]
#[global_allocator]
static GLOBAL: tikv_jemallocator::Jemalloc = tikv_jemallocator::Jemalloc;

#[derive(Clone)]
struct AppState {
    /// DB router: collection -> driver. Today 1 driver for all collections;
    /// this map is what enables per-collection overrides (`routes` in hakobackend.toml, phase 3).
    db: Arc<tokio::sync::RwLock<Arc<dyn Database>>>,
    /// Named database handles (issue #13): `default` mirrors `db`.
    /// Reload swaps the whole map; Hot snapshots it per SNAP_TTL.
    dbs: Arc<tokio::sync::RwLock<Arc<std::collections::HashMap<String, Arc<dyn Database>>>>>,
    policy: Arc<PolicyHot>,
    /// Verifier chain (empty = dev mode without auth; resolve always None).
    auth: Arc<tokio::sync::RwLock<Arc<AuthChain>>>,
    /// Concrete local provider for /api/auth/* endpoints (None when `local` is unused).
    local: Arc<tokio::sync::RwLock<Option<Arc<LocalAuth>>>>,
    /// GitHub OAuth flow (None without client id). Endpoints return 400 when disabled.
    github: Arc<tokio::sync::RwLock<Option<Arc<GithubOAuth>>>>,
    /// Two-layer flood protection (hot-reload via /api/admin/reload).
    limits: Arc<LimitLayers>,
    /// TLS enabled (https scheme for DPoP htu + HSTS).
    tls: bool,
    /// Admin UIDs allowed to call /api/admin/* (single-user backend: UIDs,
    /// not roles — see tenant-removal notes). Arc: AppState clones per
    /// accepted connection (2.9% of bench profile); the list itself never
    /// changes at runtime, so don't copy it per connection.
    admin_uids: Arc<Vec<String>>,
    /// CLI flags for reload (file re-read, flags still win). Arc for the
    /// same per-connection clone reason as admin_uids.
    cli: Arc<Args>,
    /// PATCH coalescer (active only with --coalesce-writes).
    coalescer: Arc<coalesce::Coalescer>,
    /// Whether the coalescer accepts merges (snapshot of the flag at boot).
    coalesce_on: bool,
    /// Loopback service keys (hot-reload via /api/admin/reload for rotation).
    service: Arc<tokio::sync::RwLock<Arc<ServiceAuth>>>,
    /// Resolved-token cache (verify once, reuse to exp/idle; flushed on
    /// reload, revoked on logout; DPoP still enforced per request).
    tokcache: Arc<tokcache::TokenCache>,
    /// Hot snapshot of the five per-request Arcs (see hot()).
    hot_cache: Arc<HotCache>,
    /// CORS strict allowlist (empty = legacy echo-any). Boot-time.
    cors_allowed: Arc<Vec<String>>,
    /// Session cookie flags (boot-time, fail-closed validation).
    cookies: Arc<CookieConf>,
    /// Max body bytes (boot-time). Scalars ride AppState by value —
    /// AppState clones per connection, Arcs only for heap data.
    body_limit: u64,
    hsts_max_age: u64,
    /// Gzip floor in bytes (tower takes u16; larger clamps — past 64 KB
    /// compression is off in practice anyway).
    compress_min_bytes: u16,
    ws_max_msg: usize,
    ws_max_subs: usize,
    /// CSRF Origin-vs-Host gate on (boot-time, config).
    csrf_check: bool,
    /// Per-account login lockout (brute-force backstop behind the IP
    /// limiter; rotating IPs don't help against this).
    login_guard: Arc<loginguard::LoginGuard>,
    /// Self-service registration open (closed = admin-created users only).
    local_register: bool,
    /// Maintenance mode: data-plane writes 503 (migrations/backups).
    /// Reads, health and session flows stay up. Atomic: reload swaps it.
    read_only: Arc<std::sync::atomic::AtomicBool>,
    /// Batch/transaction op cap (larger payloads 400). Atomic: reload swaps it.
    max_batch_ops: Arc<std::sync::atomic::AtomicU64>,
    /// Managed-file config (issue #11). Arc: heap data, not per-connection
    /// copies. Boot-time like body_limit (reload ignores it).
    files: Arc<files::FileConf>,
    /// Realtime guards (snapshot/event/poll/conn caps). RwLock: reload
    /// swaps it; already-running pollers keep their spawn-time interval.
    rt_caps: Arc<std::sync::RwLock<realtime::RtCaps>>,
    /// Firebase-style issuance: also return tokens in the JSON body.
    local_token_response: bool,
    /// Set session cookies (false = pure-token mode, no Set-Cookie).
    local_cookies: bool,
    /// Path alias table (compiled at boot/reload; empty = off).
    /// Interior mutability (no lock in the hot path): the table is an
    /// Arc-swap like the hot snapshot's contents, not a RwLock — readers
    /// clone the Arc (~20 ns), reload swaps it.
    aliases: Arc<std::sync::RwLock<Arc<alias::AliasTable>>>,
    /// Bare route table (no layers) for alias redispatch (issue #5).
    /// Router::layer wraps endpoints post-match, so a rewrite middleware
    /// can never affect routing; the alias *route* therefore rewrites the
    /// URI and re-enters here. Gates already ran on the outer pass (once);
    /// handlers self-gate on the rewritten target. First install wins
    /// (rebuilds produce the identical table).
    bare: Arc<std::sync::OnceLock<Router>>,
}

/// Session cookie flags (config-file driven, boot-time). Defaults mirror
/// the old hardcoded `Secure; HttpOnly; SameSite=Strict; Path=/`.
#[derive(Debug, Clone)]
struct CookieConf {
    secure: bool,
    samesite: String,
    path: String,
    domain: Option<String>,
}

impl CookieConf {
    fn build(cfg: &config::UbConfig) -> Self {
        // Fail closed at boot (typos in security flags must never silently
        // weaken to a default).
        let samesite = cfg.cookie_samesite.clone();
        if !["Strict", "Lax", "None"].contains(&samesite.as_str()) {
            panic!("[ub] cookie_samesite must be Strict|Lax|None, got `{samesite}`");
        }
        if samesite == "None" && !cfg.cookie_secure {
            panic!("[ub] cookie_samesite=None requires cookie_secure=true (browsers reject None without Secure)");
        }
        Self {
            secure: cfg.cookie_secure,
            samesite,
            path: cfg.cookie_path.clone(),
            domain: cfg.cookie_domain.clone(),
        }
    }

    fn pair(&self, name: &str, value: &str, age: u64) -> String {
        let mut v = format!("{name}={value}; Path={}; Max-Age={age}; HttpOnly", self.path);
        if let Some(d) = &self.domain {
            v.push_str(&format!("; Domain={d}"));
        }
        if self.secure {
            v.push_str("; Secure");
        }
        v.push_str(&format!("; SameSite={}", self.samesite));
        v
    }
}

/// Loopback service-key state: sha256 hashes (keys never compared raw) +
/// scope slots copied from config. Empty hashes = feature off.
#[derive(Clone, Default)]
struct ServiceAuth {
    hashes: Vec<[u8; 32]>,
    scopes: Vec<String>,
}

/// Unix-domain socket marker: inserted as ConnectInfo by the uds listener
/// (axum has no SocketAddr there). Local by construction. Unix-only
/// (tokio:net::unix is cfg(unix); Windows has no AF_UNIX there).
#[cfg(unix)]
#[derive(Clone, Copy, Debug)]
struct UnixPeer;

#[cfg(unix)]
impl Connected<IncomingStream<'_, UdsListener>> for UnixPeer {
    fn connect_info(_: IncomingStream<'_, UdsListener>) -> Self {
        Self
    }
}

/// Unix listener newtype: axum's own `Listener for UnixListener` is
/// cfg(unix)-gated, which would fork the flag per OS. This delegates
/// straight through, so --sock behaves identically on Windows (where
/// AF_UNIX exists since 1809; only the chmod step stays cfg(unix)).
#[cfg(unix)]
struct UdsListener(tokio::net::UnixListener);

#[cfg(unix)]
impl Listener for UdsListener {
    type Io = tokio::net::UnixStream;
    type Addr = tokio::net::unix::SocketAddr;

    async fn accept(&mut self) -> (Self::Io, Self::Addr) {
        loop {
            match self.0.accept().await {
                Ok(tup) => return tup,
                Err(e) => match e.kind() {
                    std::io::ErrorKind::ConnectionRefused
                    | std::io::ErrorKind::ConnectionAborted
                    | std::io::ErrorKind::ConnectionReset => {}
                    _ => {
                        eprintln!("[ub] uds accept error: {e}");
                        tokio::time::sleep(std::time::Duration::from_secs(1)).await;
                    }
                },
            }
        }
    }

    fn local_addr(&self) -> std::io::Result<Self::Addr> {
        self.0.local_addr()
    }
}

/// h2c glue: hyper speaks `Request<Incoming>`, the Router wants
/// `Request<axum Body>`. One map step (plus the ConnectInfo insert the
/// axum path gets from into_make_service_with_connect_info).
#[derive(Clone)]
struct H2Svc {
    inner: Router,
    peer: std::net::SocketAddr,
}

impl hyper::service::Service<Request<hyper::body::Incoming>> for H2Svc {
    type Response = axum::response::Response;
    type Error = std::convert::Infallible;
    type Future = std::pin::Pin<
        Box<dyn std::future::Future<Output = Result<Self::Response, Self::Error>> + Send>,
    >;

    fn call(&self, req: Request<hyper::body::Incoming>) -> Self::Future {
        let inner = self.inner.clone();
        let peer = self.peer;
        Box::pin(async move {
            let (mut parts, body) = req.into_parts();
            parts.extensions.insert(ConnectInfo(peer));
            let req = Request::from_parts(parts, axum::body::Body::new(body));
            tower::ServiceExt::oneshot(inner, req).await
        })
    }
}

/// Plain-TCP HTTP/2 (h2c, prior knowledge): accept loop + one h2
/// connection task per socket, drained on shutdown like the other
/// listeners. Same Router (same middleware, policy, auth) — only the
/// framing changes, so responses are byte-identical to h1.
async fn serve_h2c(
    listener: tokio::net::TcpListener,
    app: Router,
) -> Result<(), String> {
    let mut conns = tokio::task::JoinSet::new();
    loop {
        tokio::select! {
            biased;
            _ = shutdown_signal() => break,
            res = listener.accept() => {
                let (stream, peer) = res.map_err(|e| format!("[ub] h2c accept: {e}"))?;
                let svc = H2Svc { inner: app.clone(), peer };
                conns.spawn(async move {
                    let io = hyper_util::rt::TokioIo::new(stream);
                    let _ = hyper::server::conn::http2::Builder::new(
                        hyper_util::rt::TokioExecutor::new(),
                    )
                    .serve_connection(io, svc)
                    .await;
                });
            }
        }
    }
    while conns.join_next().await.is_some() {}
    Ok(())
}

/// Shared shutdown trigger (Ctrl+C / SIGTERM): one instance per server
/// so the TCP and unix listeners drain on the same signal independently.
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        let mut term = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
            .expect("SIGTERM handler installs");
        tokio::select! {
            _ = tokio::signal::ctrl_c() => {},
            _ = term.recv() => {},
        }
    }
    #[cfg(not(unix))]
    {
        let _ = tokio::signal::ctrl_c().await;
    }
    eprintln!("[ub] shutdown: draining connections");
}

impl ServiceAuth {
    fn build(keys: &[String], allow: &[String]) -> Arc<Self> {
        Arc::new(Self {
            hashes: keys.iter().map(|k| hash_key(k)).collect(),
            scopes: allow.to_vec(),
        })
    }
}

fn hash_key(k: &str) -> [u8; 32] {
    Sha256::digest(k.trim().as_bytes()).into()
}

/// Constant-time match (XOR fold — no early exit, no length oracle beyond
/// the fixed 32-byte digest). High-entropy keys make this belt-and-braces.
fn svc_key_match(hashes: &[[u8; 32]], token: &str) -> bool {
    let cand = hash_key(token);
    let mut hit = false;
    for h in hashes {
        let mut diff = 0u8;
        for (a, b) in h.iter().zip(cand.iter()) {
            diff |= a ^ b;
        }
        hit |= diff == 0;
    }
    hit
}

/// Loopback = socket peer (ConnectInfo), NEVER Host/X-Forwarded-For.
/// Behind nginx on the same host the peer is 127.0.0.1; a remote key
/// thief still fails this check.
fn loopback_peer(req: &Request) -> bool {
    // Unix-socket arrivals carry the marker instead of a TCP peer —
    // local by construction (stronger than loopback: filesystem, not IP).
    #[cfg(unix)]
    if req.extensions().get::<ConnectInfo<UnixPeer>>().is_some() {
        return true;
    }
    req.extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .is_some_and(|ConnectInfo(peer)| peer.ip().is_loopback())
}

/// Service identity for the policy arm (uid prefix + config-copied scope).
fn svc_context(scopes: &[String]) -> AuthContext {
    AuthContext {
        uid: "svc:loopback".into(),
        extra: [(hakobackend_core::SVC_SCOPE.into(), serde_json::json!(scopes))]
            .into_iter()
            .collect(),
    }
}

impl AppState {
    /// Global policy (single-user backend: one policy file, no overlays).
    /// Cold path only now (snapshot refresh + tests) — hot paths use hot().
    pub async fn policy(&self) -> Arc<PolicyFile> {
        self.policy.get().await
    }

    /// Hot snapshot: policy + db + auth + service + local Arcs, refreshed
    /// at most once per SNAP_TTL. Replaces the per-request mtime stat +
    /// 3-5 contended tokio locks (~8µs, the old authz stage) with one
    /// uncontended mutex + Arc clones (~200 ns). File edits land within
    /// SNAP_TTL; /api/admin/reload invalidates immediately.
    pub async fn hot(&self) -> Hot {
        self.hot_cache.get(self).await
    }
}

/// One snapshot fetch: all hot Arcs, cloned out together.
#[derive(Clone)]
struct Hot {
    policy: Arc<PolicyFile>,
    db: Arc<dyn Database>,
    /// Named databases (issue #13): `default` is `db` (same Arc);
    /// extras from `[databases]`. Snapshot with the rest so reload
    /// swaps the whole map atomically.
    dbs: Arc<std::collections::HashMap<String, Arc<dyn Database>>>,
    auth: Arc<AuthChain>,
    service: Arc<ServiceAuth>,
    local: Option<Arc<LocalAuth>>,
}

impl Hot {
    /// Handle lookup (issue #13): unknown = 404; non-default on a
    /// single-db deployment = 400 (teaches single-namespace instead
    /// of a confusing 404).
    fn db_for(&self, db: &str) -> Result<Arc<dyn Database>, Response> {
        if let Some(h) = self.dbs.get(db) {
            return Ok(h.clone());
        }
        if self.dbs.len() <= 1 {
            return Err(err(StatusCode::BAD_REQUEST, "single-database deployment (default only)"));
        }
        Err(err(StatusCode::NOT_FOUND, "unknown database"))
    }
}

/// `?db=` resolution (issue #13): absent = default; illegal = 400.
/// Uniform channel on every route, all verbs — bodies never carry db.
fn resolve_db_name(q: &HashMap<String, String>) -> Result<String, Response> {
    let db = q.get("db").map(|s| s.as_str()).unwrap_or("default");
    if !hakobackend_core::valid_db_name(db) {
        return Err(err(StatusCode::BAD_REQUEST, "invalid db name"));
    }
    Ok(db.to_string())
}

/// Policy namespace: default stays bare (existing policy files keep
/// working); named DBs dot-prefix. Dots are illegal in collection
/// segments (charset gate), so no subcollection collision. Driver
/// calls ALWAYS use the bare collection — dotted is policy-only.
fn dotted(db: &str, collection: &str) -> String {
    if db == "default" {
        collection.to_string()
    } else {
        format!("{db}.{collection}")
    }
}

/// Refresh cadence for the hot snapshot. Policy/file edits apply within
/// this window on hot paths (reload is still immediate via invalidate).
const SNAP_TTL: std::time::Duration = std::time::Duration::from_secs(1);

struct HotSnap {
    at: Option<std::time::Instant>,
    hot: Hot,
}

/// std RwLock, NOT tokio Mutex: the fast path takes a SHARED read guard
/// (readers proceed in parallel, ~20 ns, no executor involvement). A tokio
/// Mutex serializes all 20k+ acq/s through one exclusive queue and convoys
/// past 800µs under load (measured 0.2.24). Refresh takes the write guard
/// briefly with no await inside; the fresh fetch happens outside any guard
/// (double-checked publish below), so the 1/sec writer never stalls readers
/// past a microsecond.
struct HotCache {
    inner: std::sync::RwLock<HotSnap>,
}

impl HotCache {
    fn new(hot: Hot) -> Self {
        Self {
            inner: std::sync::RwLock::new(HotSnap { at: Some(std::time::Instant::now()), hot }),
        }
    }

    async fn get(&self, s: &AppState) -> Hot {
        {
            let g = self.inner.read().unwrap();
            if g.at.is_some_and(|t| t.elapsed() < SNAP_TTL) {
                return g.hot.clone();
            }
        }
        // Stale: fetch with no guard held (awaits), then publish only if
        // still stale (a concurrent refresh may have beaten us).
        let hot = Hot {
            policy: s.policy.get().await,
            db: s.db.read().await.clone(),
            dbs: s.dbs.read().await.clone(),
            auth: s.auth.read().await.clone(),
            service: s.service.read().await.clone(),
            local: s.local.read().await.clone(),
        };
        let mut g = self.inner.write().unwrap();
        if g.at.is_some_and(|t| t.elapsed() < SNAP_TTL) {
            return g.hot.clone();
        }
        g.at = Some(std::time::Instant::now());
        g.hot = hot.clone();
        hot
    }

    async fn invalidate(&self) {
        self.inner.write().unwrap().at = None;
    }
}

/// Two token buckets: loose global + strict auth. Cheap clone (Arc inside).
#[derive(Clone)]
struct LimitLayers {
    global: Arc<Limiter>,
    auth: Arc<Limiter>,
    trust_proxy: bool,
}

/// Self-reloading policy when the file changes (checks mtime each request — 1 stat call).
struct PolicyHot {
    path: Option<String>,
    cached: tokio::sync::RwLock<(Option<SystemTime>, Arc<PolicyFile>)>,
}

impl PolicyHot {
    fn new(path: Option<String>) -> Self {
        match path {
            None => {
                // ponytail: no policy file = open dev mode + loud WARN.
                // No token = anonymous; policy rules decide (fail-closed
                // when a policy file exists). Full SessionIssuer follows (phase C).
                eprintln!("[ub] WARN: without policy file — all endpoints OPEN (dev mode). Set `policy_file` in hakobackend.toml for production.");
                Self {
                    path: None,
                    cached: tokio::sync::RwLock::new((None, Arc::new(PolicyFile::open()))),
                }
            }
            Some(p) => {
                let file = PolicyFile::load(&p).unwrap_or_else(|e| {
                    eprintln!("[ub] WARN: {e}; using open policy temporarily");
                    PolicyFile::open()
                });
                let m = mtime(&p);
                Self {
                    path: Some(p),
                    cached: tokio::sync::RwLock::new((m, Arc::new(file))),
                }
            }
        }
    }

    async fn get(&self) -> Arc<PolicyFile> {        let Some(path) = &self.path else {
            return self.cached.read().await.1.clone();
        };
        let current = mtime(path);
        // Reload only when mtime changes (user edits take effect immediately).
        if self.cached.read().await.0 != current {
            let mut w = self.cached.write().await;
            if w.0 != current {
                match PolicyFile::load(path) {
                    Ok(f) => {
                        eprintln!("[ub] policy reload: {path}");
                        audit::policy_reload(path, true);
                        *w = (current, Arc::new(f));
                    }
                    Err(e) => {
                        eprintln!("[ub] policy reload FAILED ({e}); keeping old policy");
                        audit::policy_reload(path, false);
                    }
                }
            }
            return w.1.clone();
        }
        self.cached.read().await.1.clone()
    }

    /// `[identity]` snapshot for provider construction (reload-safe: policy
    /// hot-reloads independently, providers rebuilt on /api/admin/reload).
    fn identity_snapshot(&self) -> Identity {
        self.cached.try_read().map(|g| g.1.identity.clone()).unwrap_or_default()
    }
}

fn mtime(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// The only place that knows the driver list. New driver = 1 new arm.
/// Unimplemented drivers return a clear message, not a panic.
async fn open_driver(
    driver: &str,
    path: &str,
    sync_serve: Option<String>,
    sync_peer: Vec<String>,
    ttl_sweep_secs: u64,
) -> Result<Arc<dyn Database>, String> {
    use hakobackend_core::ttl::TtlDb;
    // Every driver is wrapped once: TTL expiry filters uniformly, and the
    // sweeper below owns the wrapped handle (reload swaps it too).
    let db: Arc<dyn Database> = match driver {
        "hako" => {
            // ponytail: socket_sync lives ONLY in the hako arm (sync is
            // per hako driver — the hakocluster driver meshes itself).
            let hako = HakoDb::open(path).map_err(|e| e.to_string())?;
            hako
                .enable_socket_sync(sync_serve, sync_peer)
                .await
                .map_err(|e| e.to_string())?;
            Arc::new(TtlDb::new(hako)) as Arc<dyn Database>
        }
        "hakocluster" => {
            // In-process cluster: comma-separated Hako dirs, mesh + fan-out
            // inside one backend process. Sync flags are refused here —
            // peering is the cluster's own business (its default sock dir),
            // not per-socket knobs on top.
            if sync_serve.is_some() || !sync_peer.is_empty() {
                return Err("sync_serve/sync_peer are hako-driver only; the hakocluster driver meshes itself".into());
            }
            let cluster =
                ClusterDb::open(path).map_err(|e| e.to_string())?;
            Arc::new(TtlDb::new(cluster)) as Arc<dyn Database>
        }
        "postgres" | "sqlite" | "mysql" | "rethinkdb" => {
            if sync_serve.is_some() || !sync_peer.is_empty() {
                return Err("sync_serve/sync_peer need driver `hako`".into());
            }
            match driver {
                "postgres" => PgDb::open(path).await.map(|db| Arc::new(TtlDb::new(db)) as Arc<dyn Database>).map_err(|e| e.to_string())?,
                "sqlite" => SqliteDb::open(path).await.map(|db| Arc::new(TtlDb::new(db)) as Arc<dyn Database>).map_err(|e| e.to_string())?,
                "mysql" => MysqlDb::open(path).await.map(|db| Arc::new(TtlDb::new(db)) as Arc<dyn Database>).map_err(|e| e.to_string())?,
                // Spike: compiles + maps the trait; live conformance pending a server.
                "rethinkdb" => RethinkDb::open(path).await.map(|db| Arc::new(TtlDb::new(db)) as Arc<dyn Database>).map_err(|e| e.to_string())?,
                _ => unreachable!("outer match guards driver names"),
            }
        }
        other => {
            return Err(format!(
                "driver `{other}` not available yet. Available choices: {}.",
                crate::config::KNOWN_DRIVERS.join(", ")
            ))
        }
    };
    // One sweeper per open (reloads are rare; the old task idles on the
    // swapped-out handle and exits with the process). 0 = off (docs
    // without __ttl_at are immortal anyway).
    if ttl_sweep_secs > 0 {
        hakobackend_core::ttl::spawn_sweeper(
            db.clone(),
            std::time::Duration::from_secs(ttl_sweep_secs),
            100,
        );
    }
    Ok(db)
}

/// Open `default` (`data`) + every `[databases]` entry (issue #13)
/// through the SAME driver. Each open spawns its own TTL sweeper
/// (inside open_driver) — expiry stays per-database, never shared.
async fn open_dbs(
    driver: &str,
    data: &str,
    extra: &std::collections::HashMap<String, String>,
    sync_serve: Option<String>,
    sync_peer: Vec<String>,
    ttl_sweep_secs: u64,
) -> Result<std::collections::HashMap<String, Arc<dyn Database>>, String> {
    let mut m = std::collections::HashMap::new();
    m.insert(
        "default".to_string(),
        open_driver(driver, data, sync_serve.clone(), sync_peer.clone(), ttl_sweep_secs).await?,
    );
    let mut names: Vec<&String> = extra.keys().collect();
    names.sort();
    for n in names {
        m.insert(
            n.clone(),
            open_driver(driver, &extra[n], sync_serve.clone(), sync_peer.clone(), ttl_sweep_secs)
                .await
                .map_err(|e| format!("database `{n}`: {e}"))?,
        );
    }
    Ok(m)
}

/// Full HTTP surface: routes + every layer, exactly as served.
/// Extracted from main() (pure code motion) so tests can oneshot the
/// production stack byte-for-byte.
fn build_router(state: AppState, allowed_hosts: Vec<String>, compress_cfg: bool) -> Router {
    // Layered flood protection (before any expensive work):
    // /health open (LB probes), /api/auth/* strict, rest loose global.
    let global = LimitScope { limiter: state.limits.global.clone(), trust_proxy: state.limits.trust_proxy };
    let strict = LimitScope { limiter: state.limits.auth.clone(), trust_proxy: state.limits.trust_proxy };
    // Bare route table (no layers): alias redispatch lands here. Gates
    // already ran on the outer pass; handlers self-gate on the target.
    let api_routes = Router::new()
        .route("/api/collections", get(list_collections).post(create_collection))
        .route(
            "/api/collections/{*path}",
            get(get_or_list).post(create).put(put).patch(patch).delete(remove),
        )
        .route("/api/indexes", post(index_create).get(index_list).delete(index_drop))
        .route("/api/batch", post(batch))
        .route("/api/transaction", post(transaction))
        // Archive moves + lazy residency (issue #21): static paths win
        // over /api/collections/{*path}, so alias targets reaching the
        // bare table hit these exactly like direct calls.
        .route("/api/relocate", post(relocate))
        .route("/api/collections/load", post(collection_load))
        .route("/api/collections/unload", post(collection_unload))
        .route("/api/collections/unloaded", get(unloaded_list))
        // Managed files (issue #11): bytes on disk, metadata docs in the
        // addressed collection. In the bare table too, so /api/alias/*
        // targets reach them exactly like direct calls.
        .route("/api/files/{*path}", post(files::upload).get(files::download).delete(files::remove))
        .route("/api/collectionGroup/{name}", get(collection_group))
        .route("/api/aggregate/{*path}", post(aggregate))
        .route("/api/admin/reload", post(reload))
        .route("/ws", get(ws_handler))
        .route("/api/stream/{*path}", get(sse_handler));
    let api = api_routes
        .clone()
        // Path aliases (issue #5): owner-declared rewrites. The handler
        // rewrites the URI and re-enters routing via the bare table, so
        // downstream (auth/policy/limits) sees the TARGET exactly like a
        // direct call. any(): targets span every REST method; realtime
        // lanes are refused at load (see compile).
        .route("/api/alias/{*path}", any(alias_dispatch))
        .layer(middleware::from_fn_with_state(global, limit_mw));
    let auth_routes_only = Router::new()
        .route("/api/auth/register", post(auth_register))
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/refresh", post(auth_refresh))
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/auth/me", get(auth_me))
        .route("/api/auth/github/login", get(github_login))
        .route("/api/auth/github/callback", get(github_callback));
    let auth_routes = auth_routes_only
        .clone()
        .layer(middleware::from_fn_with_state(strict.clone(), limit_mw));

    // ponytail: health/ready merge AFTER auth_mw — both are open by
    // policy and neither reads the auth context (health is static JSON,
    // ready takes State only). Skips hint parsing, cookie/token reads,
    // DPoP checks and 2-3 String allocs per probe. wstats stays under
    // auth (operational surface, unchanged behavior).
    let open = Router::new()
        .route("/api/health", get(health))
        .route("/api/ready", get(ready));
    // Bare table install (once per state): alias redispatch re-enters
    // routing here, past the already-run gates, straight at the handlers.
    let bare = Router::new()
        .route("/api/__wstats", get(wstats_dump))
        .merge(api_routes)
        .merge(auth_routes_only)
        .merge(open.clone())
        .with_state(state.clone());
    // First install wins; rebuilds (tests) produce the identical table.
    let _ = state.bare.set(bare);
    // ponytail: host gate wraps api + auth only (health/ready in `open`
    // stay ungated). host_mw is outermost (added last): off-domain
    // traffic dies before CORS/limit/auth do any work. Legit preflights
    // pass the gate, then cors_mw attaches headers / short-circuits 204.
    let hosts = Arc::new(allowed_hosts);
    let gated = Router::new()
        .merge(api)
        .merge(auth_routes)
        .layer(middleware::from_fn_with_state(state.cors_allowed.clone(), cors_mw))
        .layer(middleware::from_fn_with_state(hosts, host_mw));
    // Gzip is OFF by default (`compress`, flag/config): this is a realtime
    // backend (latency + CPU first) and compression cost 6.5x throughput
    // on 8 KB docs (measured 20.5k identity vs 3.2k gzip). Bandwidth is
    // the edge proxy's job when one fronts this. Opt-in only.
    let compress = compress_cfg;
    if compress {
        eprintln!("[ub] compress on: gzip responses above 1 KB");
    }
    // Gzip is OFF by default (`compress`, flag/config): this is a realtime
    // backend (latency + CPU first) and compression cost 6.5x throughput
    // on 8 KB docs (measured 20.5k identity vs 3.2k gzip). Bandwidth is
    // the edge proxy's job when one fronts this. Opt-in only.
    let compress = compress_cfg;
    if compress {
        eprintln!(
            "[ub] compress on: gzip responses above {} bytes",
            state.compress_min_bytes
        );
    }
    let body_limit = state.body_limit;
    maybe_compress(
        Router::new()
            .route("/api/__wstats", get(wstats_dump))
            .merge(gated)
            .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
            .merge(open),
        compress,
        state.compress_min_bytes,
    )
    // Body cap (legacy 8 MB json-limit parity); larger payloads 413.
    .layer(axum::extract::DefaultBodyLimit::max(
        body_limit as usize,
    ))
    // Outermost: total-latency clock + sample flag (front_mw runs first).
    .layer(middleware::from_fn(front_mw))
    .with_state(state)
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Args::parse();
    if cli.print_default_config {
        println!("{DEFAULT_CONFIG_TEMPLATE}");
        return Ok(());
    }
    let cfg = resolve(&cli);
    if cli.validate {
        return match validate(&cfg) {
            Ok(msg) => {
                println!("[ub] {msg}");
                Ok(())
            }
            Err(e) => Err(e.into()),
        };
    }
    // Fail closed before opening anything (useless/broken issuance shapes).
    validate_local_modes(&cfg).map_err(|e| format!("[ub] {e}"))?;
    let dbs_map = open_dbs(&cfg.driver, &cfg.data, &cfg.databases, cfg.sync_serve.clone(), cfg.sync_peer.clone(), cfg.ttl_sweep_secs).await.expect("open database");
    let db: Arc<dyn Database> = dbs_map["default"].clone();
    println!("[ub] driver={} data={} config={} databases=[{}]", cfg.driver, cfg.data, if cfg.source.is_empty() { "(default+flag)" } else { &cfg.source }, {
        let mut n: Vec<&String> = dbs_map.keys().collect();
        n.sort();
        n.into_iter().map(|s| s.as_str()).collect::<Vec<_>>().join(",")
    });
    // Flags are read here: `cli` moves into AppState below.
    let wstats_flag = cli.wstats;
    let benchmark_flag = cli.benchmark;
    // Internal benchmark: fixed shapes against the ACTIVE driver+config,
    // auto-clean seeds, then exit (no serving, no auth/policy involved).
    if benchmark_flag || cfg.benchmark {
        return match bench::run(&db, bench::N).await {
            Ok(rows) => {
                bench::print_table(&cfg.driver, bench::N, &rows);
                Ok(())
            }
            Err(e) => Err(e.into()),
        };
    }
    // Env wins over flag/file for the public URL (consistent with other secrets);
    // filled from config only when env is empty. Once at startup/reload.
    if let Some(p) = &cfg.public_url {
        if std::env::var("UB_PUBLIC_URL").is_err() {
            std::env::set_var("UB_PUBLIC_URL", p);
        }
    }

    let policy = Arc::new(PolicyHot::new(cfg.rules.clone()));
    bridge_local_env(&cfg);
    // Audit verbosity (unknown values warn + fall back to all — never
    // fail boot on a logging typo).
    match audit::parse_level(&cfg.audit_level) {
        Ok(level) => audit::set_level(level),
        Err(e) => eprintln!("[ub] WARN: {e}; using all"),
    }
    let (chain, local, github) = open_auth(cfg.auth.as_deref(), db.clone(), policy.identity_snapshot());
    auto_provision_all(&dbs_map, &policy.get().await, &cfg.indexes).await;

    let limits = Arc::new(LimitLayers {
        global: Arc::new(Limiter::new(Quota::per_minute(cfg.limit_global.0, cfg.limit_global.1))),
        auth: Arc::new(Limiter::new(Quota::per_minute(cfg.limit_auth.0, cfg.limit_auth.1))),
        trust_proxy: cfg.trust_proxy,
    });

    let tls = config::tls_pair(&cfg).map_err(|e| format!("[ub] {e}"))?.is_some();
    if tls {
        println!("[ub] TLS active (HSTS + https scheme)");
    }

    let db_handle: Arc<tokio::sync::RwLock<Arc<dyn Database>>> =
        Arc::new(tokio::sync::RwLock::new(db));
    let dbs_handle: Arc<tokio::sync::RwLock<Arc<std::collections::HashMap<String, Arc<dyn Database>>>>> =
        Arc::new(tokio::sync::RwLock::new(Arc::new(dbs_map)));
    let auth_handle = Arc::new(tokio::sync::RwLock::new(Arc::new(chain)));
    let local_handle: Arc<tokio::sync::RwLock<Option<Arc<LocalAuth>>>> =
        Arc::new(tokio::sync::RwLock::new(local));
    let service_handle = Arc::new(tokio::sync::RwLock::new(ServiceAuth::build(
        &cfg.service_keys,
        &cfg.service_allow,
    )));
    // Snapshot seeds from the same handles the state moves below.
    let hot_cache = Arc::new(HotCache::new(Hot {
        policy: policy.get().await,
        db: db_handle.read().await.clone(),
        dbs: dbs_handle.read().await.clone(),
        auth: auth_handle.read().await.clone(),
        service: service_handle.read().await.clone(),
        local: local_handle.read().await.clone(),
    }));
    let state = AppState {
        db: db_handle.clone(),
        dbs: dbs_handle.clone(),
        policy,
        auth: auth_handle,
        local: local_handle,        github: Arc::new(tokio::sync::RwLock::new(github)),
        limits: limits.clone(),
        tls,
        admin_uids: Arc::new(cfg.admin_uids.clone()),
        cli: Arc::new(cli),
        coalescer: Arc::new(coalesce::Coalescer::default()),
        coalesce_on: cfg.coalesce_writes,
        service: service_handle,
        tokcache: Arc::new(tokcache::TokenCache::new()),
        hot_cache,
        cors_allowed: Arc::new(cfg.cors_allowed_origins.clone()),
        cookies: Arc::new(CookieConf::build(&cfg)),
        body_limit: cfg.body_limit_mb.saturating_mul(1024 * 1024),
        hsts_max_age: cfg.hsts_max_age_secs,
        compress_min_bytes: cfg.compress_min_bytes.min(u16::MAX as u64) as u16,
        ws_max_msg: cfg.ws_max_msg_kb.saturating_mul(1024) as usize,
        ws_max_subs: cfg.ws_max_subs as usize,
        csrf_check: cfg.csrf_origin_check,
        login_guard: Arc::new(loginguard::LoginGuard::new(
            cfg.login_max_attempts,
            cfg.login_lockout_secs,
        )),
        local_register: cfg.local_register,
        read_only: Arc::new(std::sync::atomic::AtomicBool::new(cfg.read_only)),
        max_batch_ops: Arc::new(std::sync::atomic::AtomicU64::new(cfg.max_batch_ops)),
        files: Arc::new(files::FileConf::from_cfg(
            cfg.file_dir.clone(),
            cfg.file_max_mb,
            cfg.file_max_batch,
            cfg.file_mime_allow.clone(),
            cfg.file_sign_secret.clone(),
        )),
        rt_caps: Arc::new(std::sync::RwLock::new(realtime::RtCaps {
            snapshot_docs: cfg.realtime_snapshot_docs as usize,
            events_per_sec: cfg.realtime_events_per_sec,
            poll_secs: cfg.realtime_poll_secs,
            max_conn_docs: cfg.realtime_max_conn_docs as usize,
        })),
        local_token_response: cfg.local_token_response,
        local_cookies: cfg.local_cookies,
        aliases: Arc::new(std::sync::RwLock::new(Arc::new(alias::AliasTable::new(
            cfg.aliases.clone(),
        )))),
        bare: Arc::new(std::sync::OnceLock::new()),
    };
    if cfg.coalesce_writes {
        state.coalescer.spawn_flusher(state.dbs.clone());
    }
    // Managed files (issue #11): dir must exist before serving; the
    // sweeper follows reloads via the hot snapshot (no respawn needed).
    if let Some(dir) = &cfg.file_dir {
        std::fs::create_dir_all(dir).map_err(|e| format!("[ub] file_dir {dir} unwritable: {e}"))?;
        let sweep_secs = if cfg.ttl_sweep_secs > 0 { cfg.ttl_sweep_secs } else { 300 };
        files::spawn(state.clone(), std::time::Duration::from_secs(sweep_secs));
    }

    // main() continues: TLS/bind/serve below share this router.
    let hsts_max_age = state.hsts_max_age;
    let mut app = build_router(state, cfg.allowed_hosts.clone(), cfg.compress);
    if tls && hsts_max_age > 0 {
        // HSTS only meaningful via TLS (no effect on plain http).
        let hsts = format!("max-age={hsts_max_age}; includeSubDomains");
        app = app.layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_str(&hsts)
                .unwrap_or_else(|_| header::HeaderValue::from_static("max-age=31536000; includeSubDomains")),
        ));
    }

    // Hostnames resolve here (IPs bind as-is): generic listen like any
    // other service — `host` accepts "0.0.0.0", "127.0.0.1",
    // "api.example.com", ...; DNS failure fails boot, loudly.
    // Multi-bind: comma-separated hosts (IPs or DNS names), one listener
    // per resolved address. Fail-closed before serving anything.
    let bind_ips = resolve_bind_ips(&cfg.host)
        .await
        .map_err(|e| format!("[ub] {e}"))?;
    let mut listeners = Vec::with_capacity(bind_ips.len());
    for ip in &bind_ips {
        // ponytail: SocketAddr::new, not string formatting — v6 needs
        // brackets ("[::1]:3999") and format! gets it wrong.
        let a = std::net::SocketAddr::new(*ip, cfg.port);
        // Pre-bind every address up front: a typo'd IP or occupied port
        // fails boot loudly instead of surfacing inside a spawned task.
        listeners.push(
            tokio::net::TcpListener::bind(a)
                .await
                .map_err(|e| format!("[ub] cannot bind {a}: {e}"))?,
        );
    }
    // Stage profiler: flag/config/env (any one wins), restart to toggle.
    if wstats_flag
        || cfg.wstats
        || std::env::var("UB_WSTATS").map(|v| v == "1").unwrap_or(false)
    {
        wstats::set_enabled(true);
        eprintln!("[ub] wstats on: GET /api/__wstats (1/16 sampling)");
    }
    // Optional unix-domain socket: same app, local-only, next to TCP.
    // Absent = TCP only (yesterday's behavior, byte for byte). Listener
    // shape is boot-time (hot-reload ignores it); the socket file from a
    // crash would bind AddrInUse, so clear it best-effort first.
    // Unix-only: tokio has no net::unix on Windows, so a Windows build
    // fails closed here instead of silently ignoring the flag.
    #[cfg(unix)]
    let uds_handle: Option<tokio::task::JoinHandle<()>> = if let Some(sock) = cfg.sock.clone() {
        let _ = std::fs::remove_file(&sock);
        let uds = tokio::net::UnixListener::bind(&sock)
            .map_err(|e| format!("[ub] cannot bind unix socket {sock}: {e}"))?;
        {
            use std::os::unix::fs::PermissionsExt;
            std::fs::set_permissions(&sock, std::fs::Permissions::from_mode(0o777))
                .map_err(|e| format!("[ub] cannot chmod unix socket {sock}: {e}"))?;
        }
        println!("[ub] listening (unix) on {sock}");
        let uds_svc = app.clone().into_make_service_with_connect_info::<UnixPeer>();
        Some(tokio::spawn(async move {
            if let Err(e) = axum::serve(UdsListener(uds), uds_svc)
                .with_graceful_shutdown(shutdown_signal())
                .await
            {
                eprintln!("[ub] unix socket serve error: {e}");
            }
        }))
    } else {
        None
    };
    #[cfg(not(unix))]
    let uds_handle: Option<tokio::task::JoinHandle<()>> = if cfg.sock.is_some() {
        return Err("[ub] sock listener is Unix-only (this Windows build ignores it — refusing to start half-configured)".into());
    } else {
        None
    };
    // Graceful drain on Ctrl+C / SIGTERM: in-flight requests finish, then
    // sockets close. Subscriptions abort with their tasks (client resubscribes).
    // SIGTERM matters: it is what systemd sends, and without this arm the
    // process dies instantly — Hako's Drop (WAL snapshot rewrite + flush)
    // never runs and Interval-mode buffered writes die with it (data loss
    // on every `systemctl restart`; see insiden-hako-wal-20260928).
    let shutdown = async {
        shutdown_signal().await;
    };
    // ConnectInfo required so the rate-limit key = real peer IP.
    // (One boot-time clone: the h2c branch below needs the Router itself.)
    let svc = app.clone().into_make_service_with_connect_info::<std::net::SocketAddr>();
    // Plain-loopback companion handle (spawned in the TLS branch below,
    // joined with uds at the end).
    let mut plain_handle: Option<tokio::task::JoinHandle<()>> = None;
    if tls {
        if cfg.http2 {
            eprintln!("[ub] WARN: http2 flag ignored under TLS (ALPN already serves h2 there)");
        }
        // rustls 0.23 + two providers in the tree (aws-lc + ring) = ambiguous;
        // pin aws-lc explicitly once at startup (idempotent).
        let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());
        let (cert, key) = config::tls_pair(&cfg).map_err(|e| format!("[ub] {e}"))?.unwrap();
        let rustls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| format!("[ub] TLS failed to load: {e}"))?;
        for a in listeners
            .iter()
            .map(|l| l.local_addr().expect("bound listener has addr"))
        {
            println!("[ub] listening (TLS) on https://{a}");
        }
        // Plain-HTTP loopback companion (see plain_companion_for): same
        // app, loopback-only, same graceful drain. Spawned (not awaited)
        // so both listeners run together; joined with uds below.
        plain_handle =
            if let Some(paddr) = plain_companion_for(true, cfg.plain_loopback, &bind_ips, cfg.port) {
                let plistener = tokio::net::TcpListener::bind(paddr).await.map_err(|e| {
                    format!("[ub] cannot bind plain loopback {paddr}: {e}")
                })?;
                println!("[ub] listening (plain loopback) on http://{paddr}");
                let plain_svc =
                    app.clone().into_make_service_with_connect_info::<std::net::SocketAddr>();
                Some(tokio::spawn(async move {
                    if let Err(e) = axum::serve(plistener, plain_svc)
                        .with_graceful_shutdown(shutdown_signal())
                        .await
                    {
                        eprintln!("[ub] plain loopback serve error: {e}");
                    }
                }))
            } else {
                None
            };
        let handle = axum_server::Handle::new();
        let drain = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            drain.graceful_shutdown(None);
        });
        // ponytail: spawn-all + join-all (no new deps). All listeners
        // share one shutdown handle; the first serve error returned after
        // join fails boot like the old single-listener `?` did.
        let mut tls_tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let std_listener = listener
                .into_std()
                .map_err(|e| format!("[ub] listener into_std: {e}"))?;
            let h = handle.clone();
            let r = rustls.clone();
            let t = svc.clone();
            tls_tasks.push(tokio::spawn(async move {
                axum_server::from_tcp_rustls(std_listener, r)
                    .handle(h)
                    .serve(t)
                    .await
            }));
        }
        for t in tls_tasks {
            t.await
                .map_err(|e| format!("[ub] TLS listener panicked: {e}"))?
                .map_err(|e| format!("[ub] TLS serve error: {e}"))?;
        }
    } else {
        let http2 = cfg.http2;
        let mut plain_tasks = Vec::with_capacity(listeners.len());
        for listener in listeners {
            let a = listener.local_addr().expect("bound listener has addr");
            if http2 {
                println!("[ub] listening (h2c) on http://{a}");
                let app_c = app.clone();
                plain_tasks.push(tokio::spawn(async move {
                    serve_h2c(listener, app_c).await.map_err(|e| e.to_string())
                }));
            } else {
                println!("[ub] listening on http://{a}");
                let svc_c = svc.clone();
                let shut = shutdown_signal();
                plain_tasks.push(tokio::spawn(async move {
                    axum::serve(listener, svc_c)
                        .with_graceful_shutdown(shut)
                        .await
                        .map_err(|e| e.to_string())
                }));
            }
        }
        for t in plain_tasks {
            t.await
                .map_err(|e| format!("[ub] listener panicked: {e}"))?
                .map_err(|e| format!("[ub] serve error: {e}"))?;
        }
    }
    // Both listeners drain on the same signal; the unix task ends with its
    // own graceful drain, so await it instead of orphaning in-flight locals.
    if let Some(h) = uds_handle {
        let _ = h.await;
    }
    if let Some(h) = plain_handle {
        let _ = h.await;
    }
    Ok(())
}

/// Single rate-limit layer scope (limiter + proxy trust).
#[derive(Clone)]
struct LimitScope {
    limiter: Arc<Limiter>,
    trust_proxy: bool,
}

/// Key = peer IP, or first X-Forwarded-For when trust_proxy.
/// XFF trusted only behind a sanitizing proxy (spoofable when direct).
fn client_key(headers: &HeaderMap, peer: std::net::SocketAddr, trust_proxy: bool) -> String {
    if trust_proxy {
        if let Some(first) = headers
            .get("x-forwarded-for")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.split(',').next())
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            return first.to_string();
        }
    }
    peer.ip().to_string()
}

async fn limit_mw(
    State(s): State<LimitScope>,
    req: Request,
    next: Next,
) -> Response {
    let ws_t0 = std::time::Instant::now();
    // `0` rate = layer off: bypass before any key alloc, hash, or lock.
    // (A tiny-but-nonzero quota still enforces; off is explicit.)
    if s.limiter.is_off() {
        return next.run(req).await;
    }
    // Peer from extensions by hand (not the ConnectInfo extractor): unix
    // arrivals carry UnixPeer instead of a TCP peer, and the extractor
    // would 500-reject them. Unix = one shared local bucket (all of it is
    // loopback-equivalent by construction).
    let key = req
        .extensions()
        .get::<ConnectInfo<std::net::SocketAddr>>()
        .map(|ConnectInfo(p)| client_key(req.headers(), *p, s.trust_proxy))
        .unwrap_or_else(|| "unix".to_string());
    match s.limiter.check(&key) {
        Ok(()) => {
            if WSAMP.try_get().unwrap_or(false) {
                wstats::add(&wstats::F[2], ws_t0.elapsed().as_nanos() as u64);
            }
            next.run(req).await
        }
        Err(retry_secs) => {
            let mut h = HeaderMap::new();
            h.insert(header::RETRY_AFTER, retry_secs.to_string().parse().unwrap());
            (StatusCode::TOO_MANY_REQUESTS, h, "rate limit exceeded").into_response()
        }
    }
}

/// Ready-to-use auto-create (legacy autoCreateTablesFromRules pattern,
/// extended to indexes): collections from policy keys + `[[indexes]]` config.
/// Per-item failure = WARN, not fatal (manual endpoints stay available).
async fn auto_provision(db: &Arc<dyn Database>, collections: &[String], indexes: &[config::IndexDecl]) {
    for collection in collections {
        if let Err(e) = db.ensure_collection(collection).await {
            eprintln!("[ub] auto-create collection {collection} failed: {e}");
        }
    }
    for decl in indexes {
        let spec = match decl.validate() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ub] [[indexes]] skipped: {e}");
                continue;
            }
        };
        if let Err(e) = db.ensure_collection(&decl.collection).await {
            eprintln!("[ub] auto-create collection {} failed: {e}", decl.collection);
            continue;
        }
        match db.create_index(&decl.collection, &spec).await {
            Ok(info) => println!("[ub] index ready: {} → {}", decl.collection, info.name),
            Err(e) => eprintln!("[ub] index {} failed: {e}", decl.collection),
        }
    }
}

/// Split policy keys + index decls across databases (issue #13):
/// a `db.rest` first-dot prefix selects the db (dots are illegal in
/// collection segments, so the split is safe); bare names land on
/// default. Unknown-db prefixes WARN + skip (fail-closed: never
/// provision into a typo).
async fn auto_provision_all(
    dbs: &std::collections::HashMap<String, Arc<dyn Database>>,
    policy: &Arc<PolicyFile>,
    indexes: &[config::IndexDecl],
) {
    let split = |name: &str| match name.split_once('.') {
        Some((db, rest)) if dbs.contains_key(db) => (db.to_string(), rest.to_string()),
        Some((db, _)) => {
            eprintln!("[ub] WARN: unknown database `{db}` in `{name}` (skipped)");
            (String::new(), String::new())
        }
        None => ("default".to_string(), name.to_string()),
    };
    let mut cols: std::collections::HashMap<String, Vec<String>> = std::collections::HashMap::new();
    for c in policy.collections.keys() {
        let (db, rest) = split(c);
        if db.is_empty() {
            continue;
        }
        cols.entry(db).or_default().push(rest);
    }
    // ponytail: index decls filtered per db inline (dbs × decls, boot
    // only) — no cloned vecs, no signature churn for one loop.
    let mut names: Vec<&String> = dbs.keys().collect();
    names.sort();
    for db in names {
        let handle = &dbs[db];
        let mine: Vec<String> = cols.get(db).cloned().unwrap_or_default();
        // Filter decls without cloning: temporary owned decls with the
        // prefix stripped (IndexDecl is small; boot/reload only).
        let mut scoped: Vec<config::IndexDecl> = Vec::new();
        for d in indexes {
            let (ddb, rest) = split(&d.collection);
            if ddb.is_empty() || ddb != *db {
                continue;
            }
            let mut one = d.clone();
            one.collection = rest;
            scoped.push(one);
        }
        auto_provision(handle, &mine, &scoped).await;
    }
}

/// Build the auth chain + local concrete provider. `local` needs a db handle + `[identity]`,
/// so it is built here (server), not in `open_builtin`. Fail fast on
/// invalid name/file/secret (fail-closed).
fn open_auth(
    value: Option<&str>,
    db: Arc<dyn Database>,
    identity: Identity,
) -> (AuthChain, Option<Arc<LocalAuth>>, Option<Arc<GithubOAuth>>) {
    open_auth_result(value, db, identity).unwrap_or_else(|e| panic!("[ub] auth: {e}"))
}

/// Config-file → env bridge for local-auth knobs (env wins when set;
/// same precedent as `UB_PUBLIC_URL`). Runs at boot AND reload so file
/// values apply without restart. Env set once wins forever after (even
/// if the file key is later removed) — documented, consistent.
fn bridge_local_env(cfg: &config::UbConfig) {
    let set = |k: &str, v: Option<String>| {
        if std::env::var(k).is_err() {
            if let Some(val) = v {
                std::env::set_var(k, val);
            }
        }
    };
    set("UB_LOCAL_PASSWORD_MIN", Some(cfg.local_password_min_length.to_string()));
    set("UB_LOCAL_ACCESS_TTL", Some(cfg.local_access_ttl_secs.to_string()));
    set("UB_LOCAL_REFRESH_TTL", Some(cfg.local_refresh_ttl_secs.to_string()));
    set("UB_LOCAL_ARGON2_M_KB", Some(cfg.local_argon2_m_kb.to_string()));
    set("UB_LOCAL_ARGON2_T_COST", Some(cfg.local_argon2_t_cost.to_string()));
    set("UB_LOCAL_ARGON2_P_COST", Some(cfg.local_argon2_p_cost.to_string()));
}

fn open_auth_result(
    value: Option<&str>,
    db: Arc<dyn Database>,
    identity: Identity,
) -> Result<(AuthChain, Option<Arc<LocalAuth>>, Option<Arc<GithubOAuth>>), String> {
    // Panic-free version for /api/admin/reload (error → 400, old config retained).
    let spec = AuthSpec::parse(value.unwrap_or("off"));
    let custom = match &spec {
        AuthSpec::File(path) => Some(CustomAuth::load(path)?),
        _ => None,
    };
    let names: &[String] = match &spec {
        AuthSpec::Off => &[],
        AuthSpec::Named(n) => n,
        AuthSpec::File(_) => &custom.as_ref().unwrap().providers,
    };
    let local = names
        .iter()
        .any(|n| n == hakobackend_auth_local::NAME)
        .then(|| LocalAuth::build(db.clone(), identity))
        .transpose()?;
    if let (Some(d), Some(l)) = (custom.as_ref().and_then(|c| c.dpop.as_deref()), &local) {
        // custom.toml `dpop` wins over env; typo = error (fail-closed).
        l.set_dpop_mode(hakobackend_auth_local::DpopMode::parse(d)?);
    }
    let chain = open_chain(
        &spec,
        custom.as_ref(),
        local.clone().map(|l| l as Arc<dyn AuthProvider>),
    )?;
    // OAuth independent of the chain: active when its env credentials are complete.
    let github = GithubOAuth::from_env(db)?;
    Ok((chain, local, github))
}

/// Pure DPoP decision (unit-tested): Off / non-local token = pass;
/// Require without proof = strip (anonymous → policy decides); proof present = must verify;
/// Accept without proof = bearer fallback.
#[derive(Debug, PartialEq, Eq)]
enum DpopAction {
    Keep,
    Strip,
    MustVerify,
}

fn dpop_action(mode: DpopMode, is_local_token: bool, has_proof: bool) -> DpopAction {
    match (mode, is_local_token, has_proof) {
        (DpopMode::Off, _, _) | (_, false, _) => DpopAction::Keep,
        (DpopMode::Require, true, false) => DpopAction::Strip,
        (_, true, true) => DpopAction::MustVerify,
        (DpopMode::Accept, true, false) => DpopAction::Keep,
    }
}

/// Resolve one token → AuthContext (used by middleware, WS, SSE).
/// The token cache sits in front: a hit skips the provider chain (crypto
/// + HTTPS) AND the Arc snapshots below. DPoP/CSRF enforcement stays
/// downstream, untouched by caching.
async fn resolve_token(s: &AppState, token: &str) -> Option<AuthContext> {
    if let Some(hit) = s.tokcache.get(token) {
        return hit;
    }
    // One snapshot fetch serves policy + db + auth (a single mutex, not
    // three contended locks + a stat call).
    let hot = s.hot().await;
    let db_ref: &dyn Database = &*hot.db;
    let ctx = hot.auth.resolve(&hot.policy.identity, Some(db_ref), token).await;
    s.tokcache.put(token, ctx.clone());
    ctx
}

/// DPoP enforcement shared by HTTP middleware, WS upgrade, and SSE open:
/// returns the context only when the token survives the mode check.
/// No token / DPoP failure = anonymous (policy rules decide, not this fn).
async fn enforce_dpop(
    s: &AppState,
    headers: &HeaderMap,
    method: &str,
    uri: &str,
    token: Option<String>,
    mut ctx: Option<AuthContext>,
) -> Option<AuthContext> {
    // Fast paths first (identical outcomes, no crypto): no token or no
    // local provider means nothing to enforce; DPoP Off keeps everything.
    let Some(tok) = token else { return ctx };
    let Some(local) = s.hot().await.local.clone() else { return ctx };
    if local.dpop_mode() == DpopMode::Off {
        return ctx;
    }
    let dpop_proof = headers.get("DPoP").and_then(|v| v.to_str().ok()).map(str::to_string);
    let is_local = ctx
        .as_ref()
        .and_then(|c| c.extra.get("provider"))
        .and_then(|v| v.as_str())
        == Some(hakobackend_auth_local::NAME);
    let ok = match dpop_action(local.dpop_mode(), is_local, dpop_proof.is_some()) {
        DpopAction::Keep => true,
        DpopAction::Strip => false,
        // The JWT decode (bound_jkt) runs ONLY here — the one arm that
        // needs the binding. Previously it ran on every authed request.
        DpopAction::MustVerify => {
            let binding = local.bound_jkt(&tok).ok().flatten();
            dpop_proof
                .as_deref()
                .is_some_and(|p| local.check_dpop(p, method, uri, &tok, binding.as_deref()).is_ok())
        }
    };
    if !ok {
        ctx = None;
    }
    ctx
}

/// Host allowlist gate (domain-designated backends): requests whose Host
/// is outside the list are refused with 421 before limiter/auth/policy.
/// Empty list = off (yesterday's default). Loopback (localhost, 127.0.0.1,
/// ::1) ALWAYS passes — infra-local traffic (probes, loopback svc, dev)
/// is never gated. Matching is case-insensitive and port-stripped,
/// zero-alloc on the hot path. Health/ready live on the ungated `open`
/// router as a second layer of probe safety.
fn strip_host_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        // [v6] or [v6]:port.
        match rest.find(']') {
            Some(i) => &rest[..i],
            None => h,
        }
    } else {
        match h.rsplit_once(':') {
            // Single colon = host:port; multiple = bare IPv6, no port.
            Some((host, _)) if !host.contains(':') => host,
            _ => h,
        }
    }
}

fn host_allowed(allowed: &[String], host: Option<&str>) -> bool {
    if allowed.is_empty() {
        return true;
    }
    match host {
        Some(h) => {
            let bare = strip_host_port(h);
            // ponytail: loopback bypass first (exact, no alloc) — the
            // common local-probe shape never touches the list scan.
            bare == "localhost" || bare == "127.0.0.1" || bare == "::1"
                || allowed.iter().any(|a| a.eq_ignore_ascii_case(bare))
        }
        None => false,
    }
}

/// Host source that works on both transports: h1 carries a Host header,
/// h2 carries :authority (hyper does NOT synthesize a Host header for
/// h2 — headers alone would 421 every h2 request).
fn request_host(req: &Request) -> Option<&str> {
    req.headers()
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .or_else(|| req.uri().authority().map(|a| a.as_str()))
}

async fn host_mw(
    State(allowed): State<Arc<Vec<String>>>,
    req: Request,
    next: Next,
) -> Response {
    if host_allowed(&allowed, request_host(&req)) {
        next.run(req).await
    } else {
        // ponytail: cheapest correct refusal — empty 421 + close, no JSON
        // body to build, no keep-alive slot held for scanners. A true
        // silent drop would only buy retry storms (clients re-send what
        // they never got an answer to); this is the resource floor.
        (
            StatusCode::MISDIRECTED_REQUEST,
            [(header::CONNECTION, "close")],
            "",
        )
            .into_response()
    }
}

/// CORS parity with the nginx edge this replaces (map $http_origin):
/// echo any http(s) Origin + credentials. Pure + tested; the middleware
/// applies it to responses and short-circuits preflights with 204.
/// `allowed` empty = legacy echo-any (today's behavior); non-empty =
/// strict allowlist (exact match, unlisted origins get no CORS headers).
fn cors_headers(origin: Option<&str>, allowed: &[String]) -> Option<HeaderMap> {
    let o = origin?;
    if !(o.starts_with("http://") || o.starts_with("https://")) {
        return None;
    }
    if !allowed.is_empty() && !allowed.iter().any(|a| a == o) {
        return None;
    }
    let mut h = HeaderMap::new();
    // ponytail: typed insertions (no parse() fallibility); origin is
    // echoed verbatim like nginx did — validated prefix above is the
    // whole check, same as the nginx map.
    h.insert(
        header::ACCESS_CONTROL_ALLOW_ORIGIN,
        header::HeaderValue::from_str(o).ok()?,
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_METHODS,
        header::HeaderValue::from_static("GET, POST, PUT, DELETE, OPTIONS, PATCH"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_HEADERS,
        header::HeaderValue::from_static("Authorization, Content-Type, Accept, Origin, X-Requested-With"),
    );
    h.insert(
        header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
        header::HeaderValue::from_static("true"),
    );
    // Strictly better than the nginx edge (which omitted it): caches must
    // key on Origin or one site's CORS headers poison another's.
    h.insert(header::VARY, header::HeaderValue::from_static("Origin"));
    Some(h)
}

async fn cors_mw(
    State(allowed): State<Arc<Vec<String>>>,
    req: Request,
    next: Next,
) -> Response {
    let headers = cors_headers(
        req.headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok()),
        &allowed,
    );
    if req.method() == axum::http::Method::OPTIONS {
        // Preflight short-circuit (nginx returned 204 the same way).
        let mut resp = StatusCode::NO_CONTENT.into_response();
        if let Some(h) = headers {
            resp.headers_mut().extend(h);
        }
        return resp;
    }
    let mut resp = next.run(req).await;
    if let Some(h) = headers {
        resp.headers_mut().extend(h);
    }
    resp
}

/// Resolve the listen host like common services do: IP literals bind
/// as-is (no DNS touched); anything else resolves via DNS at startup and
/// binds the first address. Unknown names fail closed (refuse to boot
/// half-configured) instead of falling back to an unintended interface.
async fn resolve_bind_ip(host: &str) -> Result<std::net::IpAddr, String> {
    let bare = host.strip_prefix('[').and_then(|s| s.strip_suffix(']')).unwrap_or(host);
    if bare.eq_ignore_ascii_case("localhost") {
        return Ok(std::net::IpAddr::from([127, 0, 0, 1]));
    }
    if let Ok(ip) = bare.parse() {
        return Ok(ip);
    }
    let mut addrs = tokio::net::lookup_host(format!("{bare}:1"))
        .await
        .map_err(|e| format!("[ub] cannot resolve host `{host}`: {e}"))?;
    addrs
        .next()
        .map(|a| a.ip())
        .ok_or_else(|| format!("[ub] host `{host}` resolved to nothing"))
}

/// Split a listen-host value into entries: comma-separated, trimmed,
/// empties dropped ("somehost.com,10.10.8.8" -> ["somehost.com",
/// "10.10.8.8"]). Pure for testing; DNS happens in resolve_bind_ips.
fn split_hosts(host: &str) -> Vec<String> {
    host.split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}

/// Resolve every listen entry (IP literals bind as-is, hostnames via DNS
/// at startup), deduped, order kept. Unknown names fail closed.
async fn resolve_bind_ips(host: &str) -> Result<Vec<std::net::IpAddr>, String> {
    let mut out = Vec::new();
    for h in split_hosts(host) {
        let ip = resolve_bind_ip(&h).await?;
        if !out.contains(&ip) {
            out.push(ip);
        }
    }
    if out.is_empty() {
        return Err("[ub] host resolved to nothing".into());
    }
    Ok(out)
}

/// Plain-HTTP loopback companion address: when TLS is on and NONE of the
/// bound addresses covers loopback, also serve plaintext on
/// 127.0.0.1:<same port> (testing, debugging, local microservices and
/// reverse proxies). A single companion max no matter how many binds.
/// None = no companion (TLS off serves plain already, some bind covers
/// loopback, or plain_loopback = false). Loopback-only by construction.
fn plain_companion_for(
    tls: bool,
    plain_loopback: bool,
    bind_ips: &[std::net::IpAddr],
    port: u16,
) -> Option<std::net::SocketAddr> {
    if !tls || !plain_loopback {
        return None;
    }
    if bind_ips.iter().any(|ip| ip.is_loopback() || ip.is_unspecified()) {
        return None;
    }
    format!("127.0.0.1:{port}").parse().ok()
}

/// Auth middleware: Bearer (API clients) else access cookie (browser BFF) →
/// chain resolve → DPoP enforcement (local tokens) → `Extension<Option<AuthContext>>`.
/// No token / DPoP failure = anonymous (policy rules decide, not middleware).
async fn auth_mw(State(s): State<AppState>, mut req: Request, next: Next) -> Response {
    let ws_t0 = std::time::Instant::now();
    let from_cookie = read_cookie(req.headers(), ACCESS_COOKIE);
    let token = bearer(req.headers()).or_else(|| from_cookie.clone());
    // Service key BEFORE the chain: loopback + key match = server-minted
    // svc context (skips resolve/DPoP/CSRF — none apply to a static key).
    // Anything else falls through to the normal paths, unchanged.
    if let Some(t) = &token {
        let svc = s.hot().await.service.clone();
        if !svc.hashes.is_empty() && loopback_peer(&req) && svc_key_match(&svc.hashes, t) {
            req.extensions_mut().insert(Some(svc_context(&svc.scopes)));
            if WSAMP.try_get().unwrap_or(false) {
                wstats::add(&wstats::F[1], ws_t0.elapsed().as_nanos() as u64);
            }
            return next.run(req).await;
        }
    }
    // ponytail: anonymous fast path — no credentials means no resolution,
    // DPoP, or CSRF work. Policy decides public/deny downstream from the
    // None context (identical outcome); skips 2 String allocs + async hop
    // per public read/write. The token-bearing path below is untouched.
    if token.is_none() && from_cookie.is_none() {
        req.extensions_mut().insert(None::<AuthContext>);
        if WSAMP.try_get().unwrap_or(false) {
            wstats::add(&wstats::F[1], ws_t0.elapsed().as_nanos() as u64);
        }
        return next.run(req).await;
    }
    let method = req.method().to_string();
    let uri = base_uri(s.tls, req.headers(), req.uri().path());
    let ctx = match &token {
        Some(t) => resolve_token(&s, t).await,
        None => None,
    };
    let mut ctx = enforce_dpop(&s, req.headers(), &method, &uri, token, ctx).await;
    // CSRF: cookie-authenticated state-changing requests must prove origin.
    // Browsers always send Origin/Referer; its absence (curl) is allowed,
    // a mismatch is not — the context drops to anonymous (policy denies).
    // Host comparison strips ports on BOTH sides: portal on :443 talking
    // to API on :3000 (same host, ports differ) is legitimate same-site
    // traffic (field report: port-strict comparison killed all such writes).
    if s.csrf_check
        && from_cookie.is_some()
        && ctx.is_some()
        && matches!(req.method(), &axum::http::Method::POST | &axum::http::Method::PUT | &axum::http::Method::PATCH | &axum::http::Method::DELETE)
    {
        let origin_ok = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok());
        let host = req
            .headers()
            .get(header::HOST)
            .and_then(|v| v.to_str().ok());
        if !csrf_origin_ok(host, origin_ok, &s.cors_allowed) {
            ctx = None;
        }
    }
    req.extensions_mut().insert(ctx);
    if WSAMP.try_get().unwrap_or(false) {
        wstats::add(&wstats::F[1], ws_t0.elapsed().as_nanos() as u64);
    }
    next.run(req).await
}

/// Pure CSRF verdict (field report: same host, split ports): same host
/// passes with ports stripped on both sides (portal :443 -> API :3000);
/// an Origin exactly matching the CORS allowlist passes too (operator-
/// trusted web origin, issue #4); anything else fails; absent
/// Origin (curl/scripts) passes. Tested below; auth_mw only threads it.
fn csrf_origin_ok(host: Option<&str>, origin: Option<&str>, trusted: &[String]) -> bool {
    let Some(o) = origin else { return true };
    if trusted.iter().any(|t| t == o) {
        return true;
    }
    let o = o.trim_start_matches("https://").trim_start_matches("http://");
    let o_host = o.split('/').next().unwrap_or("");
    strip_port(o_host).eq_ignore_ascii_case(strip_port(host.unwrap_or("")))
}

/// Host without port for the Origin-vs-Host CSRF gate:
/// "a.com:3000" -> "a.com", "[::1]:3000" -> "[::1]". Bare hosts/IPs and
/// malformed multi-colon values pass through (fail-closed downstream:
/// they won't match a legitimate peer either).
fn strip_port(h: &str) -> &str {
    if let Some(rest) = h.strip_prefix('[') {
        // Bracketed v6: cut after "]" (Origin keeps brackets too).
        match rest.find(']') {
            Some(i) => &h[..i + 1],
            None => h,
        }
    } else if h.matches(':').count() == 1 {
        h.split(':').next().unwrap_or(h)
    } else {
        h
    }
}

/// `?token=` fallback is a URL-leak vector: honor it only over TLS or
/// loopback (dev), ignore it on plain LAN traffic.
fn query_token_allowed(tls: bool, headers: &HeaderMap) -> bool {
    if tls {
        return true;
    }
    headers
        .get(header::HOST)
        .and_then(|v| v.to_str().ok())
        .map(|h| {
            let host = h.split(':').next().unwrap_or("");
            host == "localhost" || host == "127.0.0.1" || host == "[::1]"
        })
        .unwrap_or(false)
}

fn bearer(headers: &HeaderMap) -> Option<String> {
    headers
        .get(axum::http::header::AUTHORIZATION)?
        .to_str()
        .ok()?
        .strip_prefix("Bearer ")
        .map(|s| s.to_string())
}
fn read_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get(header::COOKIE)?.to_str().ok()?.split(';').find_map(|p| {
        let (k, v) = p.split_once('=')?;
        (k.trim() == name).then(|| v.trim().to_string())
    })
}

/// Absolute origin scheme: https when TLS is on (DPoP htu must match the scheme exactly).
fn base_uri(tls: bool, headers: &HeaderMap, path: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    format!(
        "{scheme}://{}{}",
        headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("unknown"),
        path
    )
}

fn forbidden() -> Response {
    (
        StatusCode::FORBIDDEN,
        static_json(r#"{"error":"Permission denied by policy"}"#),
    )
        .into_response()
}

fn unauthorized() -> Response {
    (
        StatusCode::UNAUTHORIZED,
        static_json(r#"{"error":"authentication required"}"#),
    )
        .into_response()
}

/// Legacy wire shape: every failure is JSON `{error}` (writes add `code`).
fn err(status: StatusCode, msg: impl ToString) -> Response {
    (status, Json(serde_json::json!({ "error": msg.to_string() }))).into_response()
}

/// Maintenance gate (config `read_only`, issue #4): data-plane writes
/// 503 with Retry-After while migrations/backups run. Reads, health and
/// session flows never check this. Handlers call it first and return the
/// response when Some.
fn deny_if_read_only(s: &AppState) -> Option<Response> {
    if s.read_only.load(std::sync::atomic::Ordering::Relaxed) {
        let mut h = HeaderMap::new();
        h.insert(header::RETRY_AFTER, "60".parse().unwrap());
        Some(
            (
                StatusCode::SERVICE_UNAVAILABLE,
                h,
                static_json(r#"{"error":"read-only mode: writes paused for maintenance"}"#),
            )
                .into_response(),
        )
    } else {
        None
    }
}

/// 500 without driver internals: DB errors carry table/DSN hints an
/// unauthenticated prober must never see (S3 audit). Validation messages
/// stay specific; only the opaque Internal variant is scrubbed here.
fn err_internal() -> Response {
    (
        StatusCode::INTERNAL_SERVER_ERROR,
        static_json(r#"{"error":"internal error"}"#),
    )
        .into_response()
}

/// Constant JSON bodies, pre-serialized (see health): `serde_json` emits
/// these byte-identical (compact, sorted keys), so skip the Value build +
/// serialize per response. Only for bodies that NEVER vary — dynamic
/// payloads (docs, errors with details) keep the normal path.
fn static_json(body: &'static str) -> impl IntoResponse {
    ([(header::CONTENT_TYPE, "application/json")], body)
}

/// Every write ack on the wire (`{"success":true}`).
fn ok_true() -> Response {
    static_json(r#"{"success":true}"#).into_response()
}

fn err_code(status: StatusCode, msg: impl ToString, code: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": msg.to_string(), "code": code })),
    )
        .into_response()
}

/// Admin = UID allowlist (single-user backend, no roles).
fn is_admin(auth: Option<&AuthContext>, admin_uids: &[String]) -> bool {
    auth.as_ref().is_some_and(|a| admin_uids.iter().any(|u| u == &a.uid))
}

/// Single-user backend: collection names pass through unchanged (no tenant prefix).
fn stored(logical: &str) -> String {
    logical.to_string()
}

/// Claim strips applied to final write data (anti-escalation without
/// read-before-write). No-op unless a claim rule names strips.
fn strip_write(
    policy: &Arc<PolicyFile>,
    collection: &str,
    method: Method,
    mut data: HashMap<String, serde_json::Value>,
) -> HashMap<String, serde_json::Value> {
    for f in policy.strip_fields(collection, method) {
        data.remove(&f);
    }
    data
}

/// Internal collections (`__*`) are never addressable
/// over HTTP — fail-closed even under an open policy (S1 audit).
fn denied_internal(logical: &str) -> Option<Response> {
    if logical.split('/').next().is_some_and(|s| s.starts_with("__")) {
        // Explicit reservation (issue #11): the `__` prefix is the
        // server's namespace. User collections must not use it; names
        // created out-of-band 403 here by design, not by accident.
        Some(err(StatusCode::FORBIDDEN, "reserved __ prefix"))
    } else {
        None
    }
}

/// Name charset gate (table-flood + traversal): applied to the LOGICAL
/// path before tenant resolution. Legacy names with dots/spaces/unicode
/// are rejected — documented tightening, see HTTP_CONTRACT.
fn valid_names(collection: &str, id: Option<&str>) -> Option<Response> {
    if !hakobackend_core::valid_collection_path(collection) {
        return Some(err(StatusCode::BAD_REQUEST, "invalid collection name"));
    }
    if let Some(i) = id {
        if !hakobackend_core::valid_doc_id(i) {
            return Some(err(StatusCode::BAD_REQUEST, "invalid document id"));
        }
    }
    None
}

async fn health() -> impl IntoResponse {
    // ponytail: pre-serialized static bytes — this endpoint is the LB +
    // bench hot path; building + serializing a Value per request was pure
    // malloc/memmove with zero information. Bytes identical to before.
    (
        [(header::CONTENT_TYPE, "application/json")],
        r#"{"db":"hakodb","status":"ok"}"#,
    )
}

/// Readiness (LBs/K8s + browser dashboards): the driver answers, not
/// just the socket. Hardcoded `Access-Control-Allow-Origin: *` (per
/// field monitoring report): the body is a public boolean (no auth,
/// no credentials, nothing to leak), and probes must not depend on the
/// CORS allowlist. health stays header-clean (hottest path, non-browser
/// probes only).
async fn ready(State(s): State<AppState>) -> impl IntoResponse {
    let body = match s.hot().await.db.list_collections().await {
        Ok(_) => Json(serde_json::json!({ "ready": true })).into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
    };
    (
        [(header::ACCESS_CONTROL_ALLOW_ORIGIN, "*")],
        body,
    )
        .into_response()
}

/// Re-read config + driver + auth chain. "Hot-swap while running":
/// edit the file, POST here (admin role), done — CLI flags still win.
/// Failure at any step = 400 and the old config is fully retained.
async fn reload(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>, headers: HeaderMap) -> impl IntoResponse {
    let admin = auth.as_ref().map(|a| a.uid.clone()).unwrap_or_else(|| "-".into());
    let ip = audit_ip(&headers, s.limits.trust_proxy);
    if !is_admin(auth.as_ref(), &s.admin_uids) {
        audit::reload(&admin, &ip, false, "forbidden");
        return forbidden();
    }
    let cfg = resolve(&s.cli);
    if let Some(p) = &cfg.public_url {
        if std::env::var("UB_PUBLIC_URL").is_err() {
            std::env::set_var("UB_PUBLIC_URL", p);
        }
    }
    let dbs_map = match open_dbs(&cfg.driver, &cfg.data, &cfg.databases, cfg.sync_serve.clone(), cfg.sync_peer.clone(), cfg.ttl_sweep_secs).await {
        Ok(m) => m,
        Err(e) => {
            audit::reload(&admin, &ip, false, &e);
            return err(StatusCode::BAD_REQUEST, e);
        }
    };
    let db: Arc<dyn Database> = dbs_map["default"].clone();
    let identity = s.hot().await.policy.identity.clone();
    bridge_local_env(&cfg);
    match audit::parse_level(&cfg.audit_level) {
        Ok(level) => audit::set_level(level),
        Err(e) => eprintln!("[ub] WARN: {e}; using all"),
    }
    let (chain, local, github) = match open_auth_result(cfg.auth.as_deref(), db.clone(), identity) {
        Ok(v) => v,
        Err(e) => {
            audit::reload(&admin, &ip, false, &e);
            return err(StatusCode::BAD_REQUEST, e);
        }
    };
    *s.db.write().await = db;
    *s.dbs.write().await = Arc::new(dbs_map);
    *s.auth.write().await = Arc::new(chain);
    *s.local.write().await = local;
    *s.github.write().await = github;
    // Chain/mapping may have changed: cached contexts reference the old
    // world (uid mapping, provider set). Flush; clients re-resolve once.
    s.tokcache.clear();
    // Hot snapshot may hold pre-reload Arcs (policy/db/auth/service/local):
    // expire it so the next request refetches. ≤1s staleness otherwise.
    s.hot_cache.invalidate().await;
    // Drain coalesced PATCHes into the fresh driver before serving it.
    // Keys are dotted (db.collection) since writes; split on the first
    // dot against the FRESH map (unknown prefix = default + full key,
    // same rule as provisioning — a stale map cannot strand entries
    // anywhere else).
    {
        let hot = s.hot().await;
        s.coalescer
            .flush_all(|coll, id, body| {
                let hot = hot.clone();
                async move {
                    let (dbname, stored) = match coll.split_once('.') {
                        Some((d, rest)) if hot.dbs.contains_key(d) => (d.to_string(), rest.to_string()),
                        _ => ("default".to_string(), coll.clone()),
                    };
                    let dbh = match hot.db_for(&dbname) {
                        Ok(h) => h,
                        Err(_) => return Err(format!("drain: unknown database for {coll}")),
                    };
                    let out = dbh.set(&stored, &id, Doc { id: id.clone(), data: body }, true).await;
                    // Bus parity with the live flusher (full doc, below).
                    if let Ok(doc) = dbh.get(&stored, &id).await {
                        if let Some(doc) = doc {
                            realtime::emit(
                                &coll,
                                Change {
                                    collection: coll.clone(),
                                    id: id.clone(),
                                    kind: ChangeKind::Change,
                                    old: None,
                                    new: Some(doc),
                                },
                            );
                        }
                    }
                    out.map(|_| ()).map_err(|e| e.to_string())
                }
            })
            .await;
    }
    // Rate-limit numbers + auto-provision hot-reload too (no restart).
    s.limits.global.set_quota(Quota::per_minute(cfg.limit_global.0, cfg.limit_global.1));
    s.limits.auth.set_quota(Quota::per_minute(cfg.limit_auth.0, cfg.limit_auth.1));
    // Service keys rotate the same way (add new, reload, drop old).
    *s.service.write().await = ServiceAuth::build(&cfg.service_keys, &cfg.service_allow);
    // Alias table swaps atomically (Arc): in-flight requests keep the old
    // table, new ones get the new — same discipline as the hot snapshot.
    *s.aliases.write().unwrap() = Arc::new(alias::AliasTable::new(cfg.aliases.clone()));
    // Scalar ops knobs (issue #4) ride the same reload, no restart.
    // (Sweep interval rides via open_driver above; already-running
    // pollers keep their spawn-time interval until churn.)
    s.read_only.store(cfg.read_only, std::sync::atomic::Ordering::Relaxed);
    s.max_batch_ops
        .store(cfg.max_batch_ops, std::sync::atomic::Ordering::Relaxed);
    *s.rt_caps.write().unwrap() = realtime::RtCaps {
        snapshot_docs: cfg.realtime_snapshot_docs as usize,
        events_per_sec: cfg.realtime_events_per_sec,
        poll_secs: cfg.realtime_poll_secs,
        max_conn_docs: cfg.realtime_max_conn_docs as usize,
    };
    // ponytail: one snapshot fetch (each hot() clones Arcs; two
    // fetches would just double that for zero freshness gain).
    let hot = s.hot().await;
    auto_provision_all(&hot.dbs, &hot.policy, &cfg.indexes).await;
    let msg = format!("reload ok: driver={} data={} auth={}", cfg.driver, cfg.data, cfg.auth.as_deref().unwrap_or("off"));
    eprintln!("[ub] {msg}");
    audit::reload(&admin, &ip, true, &msg);
    msg.into_response()
}

async fn list_collections(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    match dbh.list_collections().await {
        Ok(c) => Json(c).into_response(),
        Err(_) => err_internal(),
    }
}

/// Explicit collection creation (legacy `POST /api/collections {name}`).
/// Gated Create; drivers create lazily anyway, so this is a checked no-op
/// that fails closed instead of 405.
async fn create_collection(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "body requires {name}"),
    };
    if denied_internal(&name).is_some() {
        return err(StatusCode::FORBIDDEN, "reserved __ prefix");
    }
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    // ponytail: dotted policy name, bare driver name — the firewall.
    // `stored()` never sees the db; drivers stay single-namespace.
    let pol = dotted(&dbname, &name);
    if !hot.policy.allow(auth.as_ref(), &pol, Method::Create, None) {
        return forbidden();
    }
    match dbh.ensure_collection(&stored(&name)).await {
        Ok(()) => ok_true(),
                Err(_) => err_internal(),
    }
}


fn parse_options(q: &HashMap<String, String>) -> Result<QueryOptions, String> {
    match q.get("options") {
        None => Ok(QueryOptions::default()),
        Some(raw) => serde_json::from_str(raw).map_err(|_| "malformed \"options\" query parameter".to_string()),
    }
}

// Gateway stage profiler (hakobench-style accumulators, cf. PERFORMANCE_NOTE
// §7 where the v0.1.1 baseline tables live). Permanent since v0.1.1 so any
// future optimization re-measures handler stages without a rebuild: set
// UB_WSTATS=1, exercise the paths, GET /api/__wstats (404 when disabled).
// Cost when off: one atomic load per request; when on: 1/16 sampling.
mod wstats {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    static ENABLED: AtomicBool = AtomicBool::new(false);
    pub fn set_enabled(on: bool) {
        ENABLED.store(on, Ordering::Relaxed);
    }
    pub fn enabled() -> bool {
        ENABLED.load(Ordering::Relaxed)
    }
    pub struct T {
        pub n: AtomicU64,
        pub ns: AtomicU64,
    }
    impl T {
        pub const fn new() -> T {
            T { n: AtomicU64::new(0), ns: AtomicU64::new(0) }
        }
    }
    static REQ: AtomicU64 = AtomicU64::new(0);
    #[inline]
    pub fn sampled() -> bool {
        if !enabled() {
            return false;
        }
        REQ.fetch_add(1, Ordering::Relaxed) % 16 == 0
    }
    #[inline]
    pub fn add(t: &T, ns: u64) {
        t.n.fetch_add(1, Ordering::Relaxed);
        t.ns.fetch_add(ns, Ordering::Relaxed);
    }
    // PUT: authz / get_old / allow / preproc / eng_set / emit / serdom
    pub static W: [T; 7] = [T::new(), T::new(), T::new(), T::new(), T::new(), T::new(), T::new()];
    // GET-single: authz / eng_get / overlay / allow / ser
    pub static G: [T; 5] = [T::new(), T::new(), T::new(), T::new(), T::new()];
    // LIST: authz / eng_list / filter / serdom
    pub static L: [T; 4] = [T::new(), T::new(), T::new(), T::new()];
    // FILES (issue #11): upload stream+store / upload meta-commit /
    // download meta+authz / download response build (the byte send
    // streams after the handler returns, so this is headers+open).
    pub static B: [T; 4] = [T::new(), T::new(), T::new(), T::new()];
    // Per-shape LIST split (same 3 inner stages): order / filter /
    // filter-order / cursor / paged / plain. L stays as the blended total
    // (recorded baselines keep comparing); S isolates the shape.
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub enum ListShape {
        Order,
        Filter,
        FilterOrder,
        Cursor,
        Paged,
        Plain,
    }
    pub struct ShapeStats {
        pub eng: T,
        pub filter: T,
        pub serdom: T,
    }
    impl ShapeStats {
        pub const fn new() -> ShapeStats {
            ShapeStats { eng: T::new(), filter: T::new(), serdom: T::new() }
        }
    }
    pub static S: [ShapeStats; 6] = [
        ShapeStats::new(),
        ShapeStats::new(),
        ShapeStats::new(),
        ShapeStats::new(),
        ShapeStats::new(),
        ShapeStats::new(),
    ];
    const SHAPE_LABELS: [&str; 6] = ["order", "filter", "filter-order", "cursor", "paged", "plain"];
    pub fn classify(q: &hakobackend_core::QueryOptions) -> ListShape {
        let cursor = q.start_at.is_some()
            || q.start_after.is_some()
            || q.end_at.is_some()
            || q.end_before.is_some();
        if cursor {
            ListShape::Cursor
        } else if !q.order_by.is_empty() && !q.filters.is_empty() {
            ListShape::FilterOrder
        } else if !q.order_by.is_empty() {
            ListShape::Order
        } else if !q.filters.is_empty() {
            ListShape::Filter
        } else if q.limit.is_some() || q.offset.is_some() {
            ListShape::Paged
        } else {
            ListShape::Plain
        }
    }
    // FRONT (packet-in to handler): total / mw_auth / mw_limit / collect / parse
    pub static F: [T; 5] = [T::new(), T::new(), T::new(), T::new(), T::new()];
    fn row(l: &str, t: &T) -> (String, u64) {
        let n = t.n.load(Ordering::Relaxed);
        let ns = t.ns.load(Ordering::Relaxed);
        let t10 = if n == 0 { 0 } else { ns.saturating_mul(10) / n.max(1) / 1000 };
        (format!("  {l:<10}{}.{}us/req   (n={n})\n", t10 / 10, t10 % 10), t10)
    }
    fn tab(name: &str, labels: &[&str], t: &[&T]) -> String {
        let mut o = format!("\n[GWSTATS {name}]\n");
        let mut tot10 = 0u64;
        for (i, l) in labels.iter().enumerate() {
            let (r, t10) = row(l, t[i]);
            o += &r;
            tot10 += t10;
        }
        o + &format!("  {:<10}{}.{}us/req   (approx total)\n", "total", tot10 / 10, tot10 % 10)
    }
    pub fn render() -> String {
        let mut o = tab(
            "put",
            &["authz", "get_old", "allow", "preproc", "eng_set", "emit", "serdom"],
            &[&W[0], &W[1], &W[2], &W[3], &W[4], &W[5], &W[6]],
        ) + &tab(
            "get",
            &["authz", "eng_get", "overlay", "allow", "ser"],
            &[&G[0], &G[1], &G[2], &G[3], &G[4]],
        ) + &tab(
            "list",
            &["authz", "eng_list", "filter", "serdom"],
            &[&L[0], &L[1], &L[2], &L[3]],
        ) + &tab(
            "file",
            &["up_stream", "up_meta", "dn_meta", "dn_send"],
            &[&B[0], &B[1], &B[2], &B[3]],
        ) + &tab(
            "front",
            &["total", "mw_auth", "mw_limit", "collect", "parse"],
            &[&F[0], &F[1], &F[2], &F[3], &F[4]],
        );
        for (i, s) in S.iter().enumerate() {
            o += &tab(
                &format!("shape-{}", SHAPE_LABELS[i]),
                &["eng", "filter", "serdom"],
                &[&s.eng, &s.filter, &s.serdom],
            );
        }
        o
    }
}

// Per-request sample flag, set by the outermost timing layer and read by
// middlewares, extractors and handlers with zero signature changes.
// Absent (tests, direct calls) = unsampled.
tokio::task_local! {
    pub(crate) static WSAMP: bool;
}

/// Outermost timing layer (registered last = runs first): total server-side
/// latency per sampled request + the sample flag for everything inside.
/// Streams (WS/SSE) and the endpoint itself are excluded: for streams the
/// handler return is not the response end.
async fn front_mw(req: Request, next: Next) -> Response {
    if !wstats::enabled() {
        return next.run(req).await;
    }
    let path = req.uri().path().to_string();
    let samp = wstats::sampled();
    let t0 = std::time::Instant::now();
    let resp = WSAMP.scope(samp, next.run(req)).await;
    if samp
        && !path.starts_with("/ws")
        && !path.starts_with("/api/stream")
        && path != "/api/__wstats"
    {
        wstats::add(&wstats::F[0], t0.elapsed().as_nanos() as u64);
    }
    resp
}

/// Body extractor that splits body-collect vs JSON-parse into the FRONT
/// table. Behavior is axum's `Json` exactly: same content-type rule (same
/// `mime` logic), same `Bytes` collection (same errors), same
/// `Json::from_bytes` classification (same 400/415/422). A parity test
/// below pins the status codes.
struct TimedJson<T>(T);

/// axum's content-type rule, verbatim (axum 0.8 `json.rs`): application/json
/// or any application/*+json suffix. Kept in sync by the parity test.
fn json_content_type(headers: &HeaderMap) -> bool {
    let Some(content_type) = headers.get(header::CONTENT_TYPE) else {
        return false;
    };
    let Ok(content_type) = content_type.to_str() else {
        return false;
    };
    let Ok(mime) = content_type.parse::<mime::Mime>() else {
        return false;
    };
    mime.type_() == "application"
        && (mime.subtype() == "json" || mime.suffix().is_some_and(|name| name == "json"))
}

impl<S, T> axum::extract::FromRequest<S> for TimedJson<T>
where
    T: serde::de::DeserializeOwned + std::fmt::Debug,
    S: Send + Sync,
{
    type Rejection = <axum::Json<T> as axum::extract::FromRequest<S>>::Rejection;
    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        if !json_content_type(req.headers()) {
            // Reproduce axum's exact rejection (status+body) via a bodyless
            // clone: same headers, so axum fails on the same check without
            // touching a body. Pinned by the parity test below.
            let (parts, _) = req.into_parts();
            let bare = Request::from_parts(parts, axum::body::Body::empty());
            return Err(axum::Json::<T>::from_request(bare, state).await.unwrap_err());
        }
        let samp = WSAMP.try_get().unwrap_or(false);
        let t0 = std::time::Instant::now();
        let bytes = axum::body::Bytes::from_request(req, state).await?;
        if samp {
            wstats::add(&wstats::F[3], t0.elapsed().as_nanos() as u64);
            // Re-anchor: parse time excludes collection.
        }
        let t1 = std::time::Instant::now();
        let v = axum::Json::<T>::from_bytes(&bytes)?;
        if samp {
            wstats::add(&wstats::F[4], t1.elapsed().as_nanos() as u64);
        }
        Ok(TimedJson(v.0))
    }
}

async fn wstats_dump() -> Response {
    if !wstats::enabled() {
        return err(StatusCode::NOT_FOUND, "not found");
    }
    wstats::render().into_response()
}

fn etag_of(version: u64) -> String {
    format!("\"{version}\"")
}

/// If-None-Match against a version ETag: `*` or an exact (strong or weak)
/// match. Auth/allow run first, so a 304 never leaks existence to the
/// unauthorized — the check order in the handler guarantees it.
fn etag_match(headers: &HeaderMap, version: u64) -> bool {
    let strong = etag_of(version);
    let weak = format!("W/{strong}");
    headers
        .get(header::IF_NONE_MATCH)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| {
            s.split(',').any(|t| {
                let t = t.trim();
                t == "*" || t == strong || t == weak
            })
        })
}

fn not_modified(version: u64) -> Response {
    let mut h = HeaderMap::new();
    if let Ok(v) = header::HeaderValue::from_str(&etag_of(version)) {
        h.insert(header::ETAG, v);
    }
    (StatusCode::NOT_MODIFIED, h, "").into_response()
}

fn raw_json(body: Vec<u8>, version: Option<u64>) -> Response {
    let mut h = HeaderMap::new();
    h.insert(
        header::CONTENT_TYPE,
        header::HeaderValue::from_static("application/json"),
    );
    if let Some(v) = version {
        if let Ok(ev) = header::HeaderValue::from_str(&etag_of(v)) {
            h.insert(header::ETAG, ev);
        }
    }
    (h, body).into_response()
}

/// Owned GET fallback: drivers without pre-serialized reads, docs with
/// pending coalesced PATCHes, and TTL-carrying docs (filtered here).
/// Same bytes as before, only reached off the fast path.
#[allow(clippy::too_many_arguments)]
async fn get_owned(
    s: AppState,
    policy: Arc<PolicyFile>,
    auth: Option<AuthContext>,
    collection: String,
    stored: String,
    id: String,
    db: Arc<dyn Database>,
    samp: bool,
    mut ws_t: std::time::Instant,
) -> Response {
    // `collection` arrives dotted (policy namespace); `stored` stays
    // bare (driver namespace). `db` is the selected handle — never
    // re-derived here (one snapshot per request, from the caller).
    // allow was already checked on the shell; re-check on the real doc is
    // free here (µs) and keeps one authorization rule for both paths.
    match db.get(&stored, &id).await {
        Ok(maybe_doc) => {
            if samp {
                wstats::add(&wstats::G[1], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            let overlaid = s.coalescer.overlay(
                &collection,
                &id,
                maybe_doc.as_ref().map(|d| d.data.clone()),
            );
            let doc = match overlaid {
                Some(data) => Some(Doc { id: id.clone(), data }),
                None => maybe_doc,
            };
            if samp {
                wstats::add(&wstats::G[2], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            match doc {
                Some(doc) => {
                    if !policy.allow(auth.as_ref(), &collection, Method::Get, Some(&doc)) {
                        return forbidden();
                    }
                    if samp {
                        wstats::add(&wstats::G[3], ws_t.elapsed().as_nanos() as u64);
                        ws_t = std::time::Instant::now();
                    }
                    // ponytail: serialize Doc straight to bytes; the old
                    // to_value() built a throwaway Value DOM first.
                    let r = Json(doc).into_response();
                    if samp {
                        wstats::add(&wstats::G[4], ws_t.elapsed().as_nanos() as u64);
                    }
                    r
                }
                None => err(StatusCode::NOT_FOUND, "Document not found"),
            }
        }
        Err(_) => err_internal(),
    }
}

/// Conditional gzip: one expression (the app builder below must stay a
/// single `let` chain — splitting it into statements breaks Router<S>
/// inference on this axum version and surfaces as bogus AppState errors
/// at the listener sites). `on=false` returns the router untouched.
fn maybe_compress<S>(router: Router<S>, on: bool, min_bytes: u16) -> Router<S>
where
    S: Clone + Send + Sync + 'static,
{
    if !on {
        return router;
    }
    // gzip JSON responses, but never the live streams: compressing
    // SSE would buffer flushes and add event latency for little gain
    // (stream frames are already tiny; WS upgrades carry no body).
    // min_bytes (default 1024): gzip below ~1 KB costs more than it saves
    // (measured 13-33% overhead on small docs when clients compress).
    // Binary (SSE + file bytes) never compresses: re-gzipping
    // already-compressed bytes burns CPU for zero or negative gain.
    // ponytail: prefix match, not an allowlist copy — custom file MIME
    // types stay excluded too, with no list to keep in sync.
    router.layer(
        tower_http::compression::CompressionLayer::new().compress_when(
            tower_http::compression::predicate::SizeAbove::new(min_bytes)
                .and(tower_http::compression::predicate::NotForContentType::new("text/event-stream"))
                .and(NoBinary),
        ),
    )
}

/// Compression predicate: skip already-compressed / streaming bytes.
#[derive(Clone, Copy)]
struct NoBinary;
impl tower_http::compression::predicate::Predicate for NoBinary {
    fn should_compress<B>(&self, response: &axum::http::Response<B>) -> bool {
        let t = response
            .headers()
            .get(axum::http::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        !(t.starts_with("image/")
            || t.starts_with("video/")
            || t.starts_with("audio/")
            || t == "application/octet-stream"
            || t == "application/pdf"
            || t == "application/zip"
            || t == "application/gzip")
    }
}

async fn get_or_list(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let samp = WSAMP.try_get().unwrap_or(false);
    let mut ws_t = std::time::Instant::now();
    // One snapshot fetch serves policy + db (a single mutex for the
    // hottest endpoint; other handlers fetch per access, ~100 ns each).
    let hot = s.hot().await;
    // Multidatabase (issue #13): one resolution up front; `pol` is the
    // policy namespace (dotted), `stored` stays the driver namespace.
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    match parse_collection_path(&path) {
        PathKind::Document { collection, id } => {
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, Some(&id)) {
                return r;
            }
            let stored = stored(&collection);
            let pol = dotted(&dbname, &collection);
            // Coalescer keys are driver-namespace + db (default bare):
            // same stored+id in two DBs must not share entries.
            let ckey = dotted(&dbname, &stored);
            if samp {
                wstats::add(&wstats::G[0], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            // ponytail: shell doc for the allow check. Read slots only ever
            // inspect the id (UidSelf); Fields passes on reads and the rest
            // ignore the resource — so no decode is needed to authorize.
            let shell = Doc { id: id.clone(), data: Default::default() };
            if !hot.policy.allow(auth.as_ref(), &pol, Method::Get, Some(&shell)) {
                return forbidden();
            }
            if samp {
                wstats::add(&wstats::G[3], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            // ETag pre-check (version probe only, no fetch): equality means
            // unchanged, so polling clients get a 304 without any decode.
            if let Ok(Some(v)) = dbh.doc_version(&stored, &id).await {
                if etag_match(&headers, v) {
                    return not_modified(v);
                }
            }
            // Coalescer overlay: pending PATCHes merge over storage, so
            // read-your-write holds inside the window. Pending docs take
            // the owned path (merge needs the real body); everything else
            // streams pre-serialized bytes with zero DOM.
            if !s.coalescer.is_empty() && s.coalescer.has(&ckey, &id) {
                return get_owned(
                    s.clone(),
                    hot.policy.clone(),
                    auth,
                    pol,
                    stored,
                    id,
                    dbh.clone(),
                    samp,
                    ws_t,
                )
                .await;
            }
            match dbh.get_json(&stored, &id).await {
                Ok(Some(raw)) => {
                    if samp {
                        wstats::add(&wstats::G[1], ws_t.elapsed().as_nanos() as u64);
                        ws_t = std::time::Instant::now();
                    }
                    let body = hakobackend_core::frame_doc_json(&id, &raw.json_inner);
                    if samp {
                        wstats::add(&wstats::G[4], ws_t.elapsed().as_nanos() as u64);
                    }
                    if let Some(v) = raw.version {
                        if etag_match(&headers, v) {
                            return not_modified(v);
                        }
                        return raw_json(body, Some(v));
                    }
                    raw_json(body, None)
                }
                // Driver can't pre-serialize (or doc missing): owned fallback.
                _ => {
                    get_owned(s.clone(), hot.policy.clone(), auth, pol, stored, id, dbh.clone(), samp, ws_t).await
                }
            }
        }
        PathKind::Collection { collection } => {
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, None) {
                return r;
            }
            let stored = stored(&collection);
            let pol = dotted(&dbname, &collection);
            match parse_options(&q) {
                Err(msg) => err(StatusCode::BAD_REQUEST, msg),
                Ok(opts) => {
                    if samp {
                        wstats::add(&wstats::L[0], ws_t.elapsed().as_nanos() as u64);
                        ws_t = std::time::Instant::now();
                    }
                    let shape = wstats::classify(&opts) as usize;
                    match dbh.list(&stored, &opts).await {
                    // Per-doc filter (replacement for the server.ts:233 loop): documents
                    // failing the rule are excluded from the response, with no extra N+1
                    // queries when drivers push rules into queries (phase 3).
                    // Policy sees logical names: one file serves all tenants.
                    Ok(docs) => {
                        if samp {
                            wstats::add(&wstats::L[1], ws_t.elapsed().as_nanos() as u64);
                            wstats::add(&wstats::S[shape].eng, ws_t.elapsed().as_nanos() as u64);
                            ws_t = std::time::Instant::now();
                        }
                        let visible: Vec<_> = docs
                            .into_iter()
                            .filter(|d| hot.policy.allow(auth.as_ref(), &pol, Method::Get, Some(d)))
                            .collect();
                        if samp {
                            wstats::add(&wstats::L[2], ws_t.elapsed().as_nanos() as u64);
                            wstats::add(&wstats::S[shape].filter, ws_t.elapsed().as_nanos() as u64);
                            ws_t = std::time::Instant::now();
                        }
                        // ponytail: direct serialization, no intermediate Value DOM.
                        let r = Json(visible).into_response();
                        if samp {
                            wstats::add(&wstats::L[3], ws_t.elapsed().as_nanos() as u64);
                            wstats::add(&wstats::S[shape].serdom, ws_t.elapsed().as_nanos() as u64);
                        }
                        r
                    }
                    Err(_) => err_internal(),
                    }
                }
            }
        }
    }
}

fn incoming_doc(id: &str, body: serde_json::Value) -> Doc {
    let mut data: std::collections::HashMap<String, serde_json::Value> = match body {
        serde_json::Value::Object(m) => m.into_iter().collect(),
        _ => HashMap::new(),
    };
    // ponytail: honor an explicit body id on create (id == "") — same
    // validity rule as URL ids — and remove it from data so stored JSON
    // never carries duplicate id keys (POST storms with one id used to
    // multiply docs instead of conflicting). Non-empty id (PUT/batch
    // paths) keeps existing behavior: URL id wins, body untouched.
    let doc_id = if id.is_empty() {
        match data.get("id").and_then(|v| v.as_str()).map(|s| s.to_string()) {
            Some(bid) if hakobackend_core::valid_doc_id(&bid) => {
                data.remove("id");
                bid
            }
            _ => id.to_string(),
        }
    } else {
        id.to_string()
    };
    Doc { id: doc_id, data }
}

// --- Index (HTTP_CONTRACT.md §index): manage simple/composite/FTS ---
//
// New shape: POST/GET/DELETE /api/indexes (+collection as field/query).
// Legacy shape (POST /api/collections/<coll>/index) handled by the shim in create().
// Policy gate: Update (schema ops = write), except list = List.

/// Detect the legacy shim: ".../`<coll>`/index" → Some(coll). Plain "index" (a real
/// collection named index) → None so it stays a document operation.
fn legacy_index_collection(path: &str) -> Option<String> {
    path.trim_matches('/').strip_suffix("/index").map(|s| s.to_string())
}

fn parse_index_spec(body: &serde_json::Value) -> Result<hakobackend_core::IndexSpec, String> {
    serde_json::from_value(body.clone()).map_err(|_| "body requires {collection, fields[], name?, unique?, kind?}".to_string())
}

async fn index_create(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let collection = match body.get("collection").and_then(|v| v.as_str()) {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "collection required"),
    };
    index_create_inner(s, auth, collection, body, &dbname).await
}

/// Legacy shim: body {name, fields} (+optional kind/unique), response {success:true}.
async fn index_create_legacy(
    s: AppState,
    auth: Option<AuthContext>,
    collection: String,
    body: serde_json::Value,
    dbname: &str,
) -> Response {
    index_create_inner(s, auth, collection, body, dbname).await
}

async fn index_create_inner(
    s: AppState,
    auth: Option<AuthContext>,
    collection: String,
    body: serde_json::Value,
    dbname: &str,
) -> Response {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    if denied_internal(&collection).is_some() {
        return err(StatusCode::FORBIDDEN, "reserved __ prefix");
    }
    if let Some(r) = valid_names(&collection, None) {
        return r;
    }
    let spec = match parse_index_spec(&body) {
        Ok(spec) => spec,
        Err(msg) => return err(StatusCode::BAD_REQUEST, msg),
    };
    let hot = s.hot().await;
    let dbh = match hot.db_for(dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let pol = dotted(dbname, &collection);
    if !hot.policy.allow(auth.as_ref(), &pol, Method::Update, None) {
        return forbidden();
    }
    let stored = stored(&collection);
    let _ = dbh.ensure_collection(&stored).await;
    match dbh.create_index(&stored, &spec).await {
        Ok(info) => Json(serde_json::json!({ "success": true, "index": info })).into_response(),
        Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
    }
}

async fn index_list(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let collection = match q.get("collection").map(|s| s.as_str()) {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "query ?collection= required"),
    };
    if denied_internal(&collection).is_some() {
        return err(StatusCode::FORBIDDEN, "reserved __ prefix");
    }
    if let Some(r) = valid_names(&collection, None) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let pol = dotted(&dbname, &collection);
    if !hot.policy.allow(auth.as_ref(), &pol, Method::List, None) {
        return forbidden();
    }
    match dbh.list_indexes(&stored(&collection)).await {
        Ok(indexes) => Json(indexes).into_response(),
                Err(_) => err_internal(),
    }
}

async fn index_drop(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let (collection, name) = match (q.get("collection"), q.get("name")) {
        (Some(c), Some(n)) if !c.is_empty() && !n.is_empty() => (c.clone(), n.clone()),
        _ => return err(StatusCode::BAD_REQUEST, "query ?collection= & ?name= required"),
    };
    if denied_internal(&collection).is_some() {
        return err(StatusCode::FORBIDDEN, "reserved __ prefix");
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let pol = dotted(&dbname, &collection);
    if !hot.policy.allow(auth.as_ref(), &pol, Method::Update, None) {
        return forbidden();
    }
    match dbh.drop_index(&stored(&collection), &name).await {
        Ok(()) => ok_true(),
        Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
    }
}

async fn create(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    TimedJson(body): TimedJson<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    // Legacy compat shim: POST /api/collections/<coll>/index {name, fields}
    // (legacy backend, server.ts:193). New shape: POST /api/indexes.
    // Collections actually named "index" are accessed via the new shape.
    if let Some(collection) = legacy_index_collection(&path) {
        return index_create_legacy(s, auth, collection, body, &dbname).await;
    }
    match parse_collection_path(&path) {
        PathKind::Document { .. } => (
            StatusCode::BAD_REQUEST,
            "POST requests must target collection endpoints, not document routes.",
        )
            .into_response(),
        PathKind::Collection { collection } => {
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, None) {
                return r;
            }
            let hot = s.hot().await;
            let dbh = match hot.db_for(&dbname) {
                Ok(h) => h,
                Err(r) => return r,
            };
            let pol = dotted(&dbname, &collection);
            let incoming = incoming_doc("", body);
            if !hot.policy.allow(auth.as_ref(), &pol, Method::Create, Some(&incoming)) {
                return forbidden();
            }
            let stored = stored(&collection);
            let _ = dbh.ensure_collection(&stored).await;
            // Atomics collapse (legacy parity) + createdAt/updatedAt stamping.
            let incoming = Doc {
                id: incoming.id,
                data: strip_write(
                    &hot.policy,
                    &pol,
                    Method::Create,
                    hakobackend_core::atomics::stamp_new(
                        hakobackend_core::atomics::resolve_for_create(incoming.data),
                    ),
                ),
            };
            if !hot.policy.allow_fields(auth.as_ref(), &pol, Method::Create, &incoming.data) {
                return forbidden();
            }
            match dbh.insert(&stored, incoming).await {
                Ok(doc) => {
                    // Gateway bus (instant lane; poller reconciles foreign writes).
                    // Dotted emit: realtime lanes partition by database.
                    realtime::emit(
                        &pol,
                        Change {
                            collection: pol.clone(),
                            id: doc.id.clone(),
                            kind: ChangeKind::Change,
                            old: None,
                            new: Some(doc.clone()),
                        },
                    );
                    Json(doc).into_response()
                }
                Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
            }
        }
    }
}

async fn put(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    TimedJson(body): TimedJson<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    write_doc(s, auth, path, body, false, skip_hint(&headers), &dbname).await
}

async fn patch(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    headers: HeaderMap,
    TimedJson(body): TimedJson<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    // ponytail: merge=true uses the same path as PUT; no manual read-modify-write.
    write_doc(s, auth, path, body, true, skip_hint(&headers), &dbname).await
}

/// Per-request read-before-write skip hint (advisory perf only, never
/// authZ): `X-Hako-Skip-RBW: 1|true`. Safe by construction — `allow` with
/// `None` decides identically for every non-Owner rule, and Owner-governed
/// writes always read (the hint is ignored there, see write_doc). Only
/// observable effect: PUT-overwrite resets `createdAt`. Header (any API
/// caller) beats cookie here: BFF cookies are browser-only, and a
/// server-set cookie would add state for zero extra trust (the hint is
/// client-asserted either way and harmless by the argument above).
fn skip_hint(headers: &HeaderMap) -> bool {
    headers
        .get("x-hako-skip-rbw")
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| s == "1" || s.eq_ignore_ascii_case("true"))
}

async fn write_doc(
    s: AppState,
    auth: Option<AuthContext>,
    path: String,
    body: serde_json::Value,
    merge: bool,
    skip_hint: bool,
    dbname: &str,
) -> Response {
    let samp = WSAMP.try_get().unwrap_or(false);
    let mut ws_t = std::time::Instant::now();
    match parse_collection_path(&path) {
        PathKind::Collection { .. } => (
            StatusCode::BAD_REQUEST,
            "PUT/PATCH requests must target explicit document endpoints.",
        )
            .into_response(),
        PathKind::Document { collection, id } => {
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, Some(&id)) {
                return r;
            }
            let hot = s.hot().await;
            let dbh = match hot.db_for(dbname) {
                Ok(h) => h,
                Err(r) => return r,
            };
            let pol = dotted(dbname, &collection);
            let stored = stored(&collection);
            let ckey = dotted(dbname, &stored);
            // Policy-level read-before-write skip (PUT only): with no Owner
            // rule governing the write the old doc is pure overhead (~115us).
            // The per-request header hint joins the policy flag; both lose
            // to Owner (authZ-neutral by construction, see skip_hint).
            // PATCH merge always reads (needs the base + missing→404).
            if samp {
                wstats::add(&wstats::W[0], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            let skip_rbw = !merge
                && !hot.policy.needs_existing(&pol, Method::Update)
                && (skip_hint || hot.policy.skip_read_before_write(&pol, Method::Update));
            let existing = if skip_rbw {
                None
            } else {
                dbh.get(&stored, &id).await.ok().flatten()
            };
            if samp {
                wstats::add(&wstats::W[1], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            // Owner rule evaluated against the existing document (who owns this data?).
            if !hot.policy.allow(auth.as_ref(), &pol, Method::Update, existing.as_ref()) {
                return forbidden();
            }
            if samp {
                wstats::add(&wstats::W[2], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            // Legacy parity: PATCH on a missing doc is 404 (use PUT to create).
            if merge && existing.is_none() {
                return err(StatusCode::NOT_FOUND, "Document not found");
            }
            // Opt-in coalescing: eligible PATCH bodies merge into the pending
            // entry and ack now; the flusher stores once per window.
            // Atomics/dot-paths bypass (exactness, see coalesce.rs).
            if merge && s.coalesce_on {
                // No strip bypass: collections with claim strips skip the
                // coalescer (its flusher stores without re-gating).
                if hot.policy.strip_fields(&pol, Method::Update).is_empty() {
                    if let Some(obj) = body.as_object() {
                        let map: HashMap<String, serde_json::Value> =
                            obj.clone().into_iter().collect();
                        if coalesce::Coalescer::eligible(&body)
                            && s.coalescer.merge(&ckey, &id, map)
                        {
                            return ok_true();
                        }
                    }
                }
            }
            let _ = dbh.ensure_collection(&stored).await;
            let created_at = existing.as_ref().and_then(|d| d.data.get("createdAt").cloned());
            let is_new = existing.is_none();
            let body = incoming_doc(&id, body).data;
            let data = if merge {
                hakobackend_core::atomics::apply_update(
                    existing.map(|d| d.data).unwrap_or_default(),
                    body,
                )
            } else {
                hakobackend_core::atomics::resolve_for_create(body)
            };
            // New doc (PUT-create): both stamps. Rewrite: preserve createdAt.
            let data = if is_new {
                hakobackend_core::atomics::stamp_new(data)
            } else {
                hakobackend_core::atomics::stamp_update(data, created_at)
            };
            // Claim strips (anti-escalation without read-before-write).
            let data = strip_write(&hot.policy, &pol, Method::Update, data);
            // Field conditionals on the final data (incoming/merged — no read).
            if !hot.policy.allow_fields(auth.as_ref(), &pol, Method::Update, &data) {
                return forbidden();
            }
            // Merge already applied above; store the final body as-is.
            if samp {
                wstats::add(&wstats::W[3], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            match dbh.set(&stored, &id, Doc { id: id.clone(), data }, false).await {
                Ok(doc) => {
                    // Gateway bus: instant lane for subscribers (the shared
                    // poller stays as reconciler for foreign writes).
                    // Wire shape unchanged ({success:true}).
                    if samp {
                        wstats::add(&wstats::W[4], ws_t.elapsed().as_nanos() as u64);
                        ws_t = std::time::Instant::now();
                    }
                    realtime::emit(
                        &pol,
                        Change {
                            collection: pol.clone(),
                            id: id.clone(),
                            kind: ChangeKind::Change,
                            old: None,
                            new: Some(doc),
                        },
                    );
                    if samp {
                        wstats::add(&wstats::W[5], ws_t.elapsed().as_nanos() as u64);
                        ws_t = std::time::Instant::now();
                    }
                    let r = ok_true();
                    if samp {
                        wstats::add(&wstats::W[6], ws_t.elapsed().as_nanos() as u64);
                    }
                    r
                }
                Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
            }
        }
    }
}

async fn remove(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    match parse_collection_path(&path) {
        PathKind::Collection { .. } => (
            StatusCode::BAD_REQUEST,
            "DELETE requests must target explicit document endpoints.",
        )
            .into_response(),
        PathKind::Document { collection, id } => {
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, Some(&id)) {
                return r;
            }
            let hot = s.hot().await;
            let dbh = match hot.db_for(&dbname) {
                Ok(h) => h,
                Err(r) => return r,
            };
            let pol = dotted(&dbname, &collection);
            let stored = stored(&collection);
            let existing = dbh.get(&stored, &id).await.ok().flatten();
            if !hot.policy.allow(auth.as_ref(), &pol, Method::Delete, existing.as_ref()) {
                return forbidden();
            }
            let _ = dbh.ensure_collection(&stored).await;
            match dbh.delete(&stored, &id).await {
                Ok(_) => {
                    // Gateway bus (subscriber snapshot supplies the old doc).
                    realtime::emit(
                        &pol,
                        Change {
                            collection: pol.clone(),
                            id: id.clone(),
                            kind: ChangeKind::Remove,
                            old: None,
                            new: None,
                        },
                    );
                    ok_true()
                }
                Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
            }
        }
    }
}

// --- Batch + transaction (legacy server.ts:392-603 parity) ---
//
// One op = `{type, collection, id?, data?, options?}`. Gates run per op
// (method mapped like legacy, collection created only after the gate),
// then the whole write set applies in ONE driver transaction: all or none.
// `add` forces merge (upsert path); `set` honors `options.merge`
// (merge on a missing doc creates — Firestore parity); `update` errors
// when absent; unknown types are rejected in batch, mapped by existence
// in transaction (legacy compat).

#[derive(Debug, serde::Deserialize)]
struct BatchOpBody {
    #[serde(rename = "type")]
    op_type: String,
    collection: String,
    id: Option<String>,
    data: Option<serde_json::Value>,
    options: Option<BatchOpOptions>,
}

#[derive(Debug, serde::Deserialize, Default)]
struct BatchOpOptions {
    #[serde(default)]
    merge: bool,
}

fn op_method(op_type: &str, existed: bool, is_tx: bool) -> Method {
    match op_type {
        "get" => Method::Get,
        "delete" => Method::Delete,
        "update" => Method::Update,
        "set" => {
            if existed {
                Method::Update
            } else {
                Method::Create
            }
        }
        _ if is_tx => {
            if existed {
                Method::Update
            } else {
                Method::Create
            }
        }
        _ => Method::Create, // 'add' and anything else in batch mode
    }
}

/// Shared runner. Batch shapes: every op → `{id, success}`. Transaction
/// shapes: `get` → doc-or-null, writes → `{success: true}`.
///
/// Result items are small `Value`s except tx-`get` hits, which carry their
/// pre-serialized bytes (`Raw`): the response assembler writes them once
/// instead of building a throwaway Value DOM per doc + re-serializing.
/// `into_value` (re-parse) exists only for tests; production never parses.
enum OpOut {
    V(serde_json::Value),
    Raw(String),
}

impl OpOut {
    fn into_value(self) -> serde_json::Value {
        match self {
            OpOut::V(v) => v,
            OpOut::Raw(s) => serde_json::from_str(&s).unwrap_or(serde_json::Value::Null),
        }
    }
}

/// `{success:true, results:[...]}` with `Raw` fragments spliced verbatim.
/// All-small batches take the single-`Json` path exactly as before.
fn render_results(results: Vec<OpOut>) -> Response {
    if results.iter().all(|r| matches!(r, OpOut::V(_))) {
        let vs: Vec<serde_json::Value> = results.into_iter().map(OpOut::into_value).collect();
        return Json(serde_json::json!({ "success": true, "results": vs })).into_response();
    }
    let mut b = String::from("{\"success\":true,\"results\":[");
    for (i, r) in results.into_iter().enumerate() {
        if i > 0 {
            b.push(',');
        }
        match r {
            OpOut::V(v) => b.push_str(&serde_json::to_string(&v).unwrap_or_else(|_| "null".into())),
            OpOut::Raw(s) => b.push_str(&s),
        }
    }
    b.push_str("]}");
    ([(header::CONTENT_TYPE, "application/json")], b).into_response()
}

async fn run_ops(
    db: &Arc<dyn Database>,
    policy: &Arc<PolicyFile>,
    auth: Option<&AuthContext>,
    ops: Vec<BatchOpBody>,
    is_tx: bool,
    dbname: &str,
) -> Result<Vec<OpOut>, (StatusCode, String, &'static str)> {
    use hakobackend_core::{TxOp, TxOpKind};
    // Phase 1: resolve + gate each op (reads tolerate missing tables).
    // Unknown op types are rejected outright (fail-closed: an unknown type
    // must never silently become a write, e.g. dodging an Update-deny via
    // the legacy create-fallback).
    const KNOWN: &[&str] = &["get", "set", "add", "update", "delete", "create"];
    struct Gated {
        body: BatchOpBody,
        id: String,
        existed: bool,
        existing: Option<Doc>,
        stored: String,
        pol: String,
        method: Method,
    }
    let mut gated = Vec::with_capacity(ops.len());
    for op in ops {
        let t = op.op_type.to_ascii_lowercase();
        // Transaction maps any other string by existence (legacy compat);
        // batch is strict.
        let mapped_unknown = is_tx && !KNOWN.contains(&t.as_str());
        if !KNOWN.contains(&t.as_str()) && !mapped_unknown {
            return Err((
                StatusCode::BAD_REQUEST,
                format!("unknown op type: {}", op.op_type),
                "bad-request",
            ));
        }
        let id = op
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or((StatusCode::BAD_REQUEST, "op requires id".to_string(), "bad-request"))?;
        if denied_internal(&op.collection).is_some() {
            return Err((StatusCode::FORBIDDEN, "reserved __ prefix".to_string(), "permission-denied"));
        }
        if !hakobackend_core::valid_collection_path(&op.collection) {
            return Err((StatusCode::BAD_REQUEST, "invalid collection name".to_string(), "bad-request"));
        }
        if !hakobackend_core::valid_doc_id(&id) {
            return Err((StatusCode::BAD_REQUEST, "invalid document id".to_string(), "bad-request"));
        }
        let pol = dotted(dbname, &op.collection);
        let stored = stored(&op.collection);
        let existing = db.get(&stored, &id).await.ok().flatten();
        let existed = existing.is_some();
        let method = op_method(&t, existed, is_tx);
        if !policy.allow(auth, &pol, method, existing.as_ref()) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Permission denied: {method:?} on {pol}/{id}"),
                "permission-denied",
            ));
        }
        let _ = db.ensure_collection(&stored).await;
        gated.push(Gated { body: op, id, existed, existing, stored, pol, method });
    }
    // Phase 2: one atomic transaction.
    if !db.capabilities().supports_transactions {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("driver {} has no transaction support", db.capabilities().driver),
            "bad-request",
        ));
    }
    // Phase 2: one atomic transaction. Put bodies are preprocessed first
    // (atomics + stamps, same as the single-write paths), so drivers store
    // exactly what they receive — no second merge inside the tx.
    // Field gates need the final data, so this loop is fallible (403
    // aborts the batch before anything is written).
    let mut tx_ops: Vec<TxOp> = Vec::with_capacity(gated.len());
    for g in &gated {
        let t = g.body.op_type.to_ascii_lowercase();
            let merge = match t.as_str() {
                "add" | "update" => true,
                "set" => g.body.options.as_ref().is_some_and(|o| o.merge),
                _ => g.existed,
            };
            let raw = g.body.data.as_ref().map(|v| incoming_doc(&g.id, v.clone()).data).unwrap_or_default();
            let created_at = g.existing.as_ref().and_then(|d| d.data.get("createdAt").cloned());
            let data = if t == "get" || t == "delete" {
                raw
            } else if merge {
                hakobackend_core::atomics::stamp_update(
                    hakobackend_core::atomics::apply_update(
                        g.existing.as_ref().map(|d| d.data.clone()).unwrap_or_default(),
                        raw,
                    ),
                    created_at,
                )
            } else if g.existed {
                hakobackend_core::atomics::stamp_update(
                    hakobackend_core::atomics::resolve_for_create(raw),
                    created_at,
                )
            } else {
                // Brand-new doc inside the batch: both stamps, like POST.
                hakobackend_core::atomics::stamp_new(hakobackend_core::atomics::resolve_for_create(raw))
            };
            // Claim strips on final data (get/delete carry no data).
            let data = if t == "get" || t == "delete" {
                data
            } else {
                strip_write(&policy, &g.pol, g.method, data)
            };
            // Field conditionals on final data (no read); fail-closed 403.
            if t != "get" && t != "delete"
                && !policy.allow_fields(auth, &g.pol, g.method, &data)
            {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("Permission denied: fields on {}/{}", g.pol, g.id),
                    "permission-denied",
                ));
            }
            let kind = match t.as_str() {
                "get" => TxOpKind::Read,
                "delete" => TxOpKind::Delete,
                "update" => TxOpKind::Put { merge: false, must_exist: true },
                _ if is_tx && g.existed && t != "set" && t != "add" => TxOpKind::Put { merge: false, must_exist: true },
                _ => TxOpKind::Put { merge: false, must_exist: false },
            };
            tx_ops.push(TxOp {
                collection: g.stored.clone(),
                id: g.id.clone(),
                kind,
                doc: Some(Doc { id: g.id.clone(), data }),
            });
        }
    // Reads resolve against the batch's own writes (driver overlay/tx reads).
    // (Cloned: the emit walk below reuses the preprocessed bodies.)
    let outs = db
        .run_transaction(tx_ops.clone())
        .await
        .map_err(|e| {
            (
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                e.to_string(),
                e.code(),
            )
        })?;
    // Gateway bus: instant lane for subscribers. Puts carry the final
    // preprocessed body, deletes only the id — subscriber snapshots
    // supply the old docs, so no extra reads here.
    for (g, t) in gated.iter().zip(tx_ops.iter()) {
        match t.kind {
            TxOpKind::Read => {}
            TxOpKind::Delete => {
                realtime::emit(
                    &g.pol,
                    Change {
                        collection: g.pol.clone(),
                        id: g.id.clone(),
                        kind: ChangeKind::Remove,
                        old: None,
                        new: None,
                    },
                );
            }
            TxOpKind::Put { .. } => {
                realtime::emit(
                    &g.pol,
                    Change {
                        collection: g.pol.clone(),
                        id: g.id.clone(),
                        kind: ChangeKind::Change,
                        old: None,
                        new: t.doc.clone(),
                    },
                );
            }
        }
    }
    // Phase 3: legacy result shapes — batch: every op → `{id, success}`;
    // transaction: `get` → doc-or-null, writes → `{success: true}`.
    // tx-get hits serialize once into Raw (no intermediate Value DOM).
    Ok(gated
        .into_iter()
        .zip(outs)
        .map(|(g, o)| {
            let t = g.body.op_type.to_ascii_lowercase();
            if !is_tx {
                OpOut::V(serde_json::json!({ "id": g.id, "success": true }))
            } else {
                match t.as_str() {
                    "get" => match o.doc {
                        Some(d) => OpOut::Raw(
                            serde_json::to_string(&d).unwrap_or_else(|_| "null".into()),
                        ),
                        None => OpOut::V(serde_json::Value::Null),
                    },
                    _ => OpOut::V(serde_json::json!({ "success": true })),
                }
            }
        })
        .collect())
}

async fn batch(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    // Legacy quirk preserved: batch failures are always 500, no code.
    let ops: Vec<BatchOpBody> = match serde_json::from_value(body.get("operations").cloned().unwrap_or_default()) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "body requires {operations[]}"),
    };
    let max_ops = s.max_batch_ops.load(std::sync::atomic::Ordering::Relaxed) as usize;
    if ops.len() > max_ops {
        return err(
            StatusCode::INTERNAL_SERVER_ERROR,
            format!("too many ops (max {max_ops})"),
        );
    }
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    match run_ops(&dbh, &hot.policy, auth.as_ref(), ops, false, &dbname).await {
        Ok(results) => render_results(results),
        Err((StatusCode::INTERNAL_SERVER_ERROR, msg, _)) => err(StatusCode::INTERNAL_SERVER_ERROR, msg),
        Err((_, msg, _)) => err(StatusCode::INTERNAL_SERVER_ERROR, msg),
    }
}

async fn transaction(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let ops: Vec<BatchOpBody> = match serde_json::from_value(body.get("operations").cloned().unwrap_or_default()) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "body requires {operations[]}"),
    };
    let max_ops = s.max_batch_ops.load(std::sync::atomic::Ordering::Relaxed) as usize;
    if ops.len() > max_ops {
        return err_code(
            StatusCode::BAD_REQUEST,
            format!("too many ops (max {max_ops})"),
            "bad-request",
        );
    }
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    match run_ops(&dbh, &hot.policy, auth.as_ref(), ops, true, &dbname).await {
        Ok(results) => render_results(results),
        Err((status, msg, code)) => err_code(status, msg, code),
    }
}

/// Move docs between collections (archive/restore).
/// POST /api/relocate {src, dst, ids[]} -> {moved[], missing[]}.
/// Policy per id: src needs Get+Delete, dst needs Create (moved docs are
/// new homes; overwrite is operator-explicit). The engine re-checks its
/// own gate (sync-excluded/local-only/lazy-unloaded → 400, never 500).
async fn relocate(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = deny_if_read_only(&s) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let src = match body.get("src").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "body requires {src, dst, ids[]}"),
    };
    let dst = match body.get("dst").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "body requires {src, dst, ids[]}"),
    };
    let ids: Vec<String> = body
        .get("ids")
        .and_then(|v| v.as_array())
        .map(|a| a.iter().filter_map(|v| v.as_str().map(|x| x.to_string())).collect())
        .unwrap_or_default();
    let max_ops = s.max_batch_ops.load(std::sync::atomic::Ordering::Relaxed) as usize;
    if ids.len() > max_ops {
        return err(StatusCode::BAD_REQUEST, format!("too many ids (max {max_ops})"));
    }
    for col in [&src, &dst] {
        if denied_internal(col).is_some() {
            return err(StatusCode::FORBIDDEN, "reserved __ prefix");
        }
        if valid_names(col, None).is_some() {
            return err(StatusCode::BAD_REQUEST, "invalid collection name");
        }
    }
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let (stored_src, stored_dst) = (stored(&src), stored(&dst));
    let (pol_src, pol_dst) = (dotted(&dbname, &src), dotted(&dbname, &dst));
    for id in &ids {
        if valid_names(&src, Some(id)).is_some() {
            return err(StatusCode::BAD_REQUEST, "invalid doc id");
        }
        // ponytail: shell doc for the allow check (same as single-doc
        // reads: slots only inspect the id, no decode needed).
        let shell = Doc { id: id.clone(), data: Default::default() };
        if !hot.policy.allow(auth.as_ref(), &pol_src, Method::Get, Some(&shell)) {
            return forbidden();
        }
        if !hot.policy.allow(auth.as_ref(), &pol_src, Method::Delete, Some(&shell)) {
            return forbidden();
        }
        if !hot.policy.allow(auth.as_ref(), &pol_dst, Method::Create, Some(&shell)) {
            return forbidden();
        }
    }
    match dbh.relocate(&stored_src, &stored_dst, &ids).await {
        Ok((moved, missing)) => Json(serde_json::json!({ "moved": moved, "missing": missing })).into_response(),
        Err(e) => driver_err(e),
    }
}

/// Explicit load of one (usually lazy archive) collection.
/// POST /api/collections/load {collection} -> {ok}. Get gate: residency
/// management needs no more trust than reading the collection.
async fn collection_load(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    residency_op(s, auth, q, body, false).await
}

/// Explicit evict of one lazy collection (refuses non-lazy).
/// POST /api/collections/unload {collection} -> {ok}. Get gate.
async fn collection_unload(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    residency_op(s, auth, q, body, true).await
}

async fn residency_op(
    s: AppState,
    auth: Option<AuthContext>,
    q: HashMap<String, String>,
    body: serde_json::Value,
    unload: bool,
) -> Response {
    if unload {
        if let Some(r) = deny_if_read_only(&s) {
            return r;
        }
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let name = match body.get("collection").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "body requires {collection}"),
    };
    if denied_internal(&name).is_some() {
        return err(StatusCode::FORBIDDEN, "reserved __ prefix");
    }
    if valid_names(&name, None).is_some() {
        return err(StatusCode::BAD_REQUEST, "invalid collection name");
    }
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let (stored_col, pol) = (stored(&name), dotted(&dbname, &name));
    let shell = Doc { id: String::new(), data: Default::default() };
    if !hot.policy.allow(auth.as_ref(), &pol, Method::Get, Some(&shell)) {
        return forbidden();
    }
    let r = if unload {
        dbh.unload_collection(&stored_col).await
    } else {
        dbh.load_collection(&stored_col).await
    };
    match r {
        Ok(()) => Json(serde_json::json!({ "ok": true })).into_response(),
        Err(e) => driver_err(e),
    }
}

/// Archive-group collections present but not loaded.
/// GET /api/collections/unloaded -> [names]. No gate beyond routing
/// (names only, same visibility as the collection list).
async fn unloaded_list(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    match dbh.unloaded_collections().await {
        Ok(c) => Json(c).into_response(),
        Err(_) => err_internal(),
    }
}

/// Driver errors to HTTP: refusal-style BadRequest stays 400 (never
/// 500), permission stays 403, everything else is a server fault.
fn driver_err(e: hakobackend_core::AppError) -> Response {
    use hakobackend_core::AppError::*;
    match e {
        BadRequest(m) => err(StatusCode::BAD_REQUEST, m),
        PermissionDenied => forbidden(),
        NotFound => err(StatusCode::NOT_FOUND, "not found"),
        AlreadyExists => err(StatusCode::BAD_REQUEST, "already exists"),
        Internal(m) => err(StatusCode::INTERNAL_SERVER_ERROR, m),
    }
}

// --- Collection group (legacy server.ts:325-362 parity) ---
//
// `GET /api/collectionGroup/:name`: every collection whose name matches the
// group (exact, path suffix, or `_` suffix) lists under a List gate, then
// each doc passes its own Get gate (resolved against the real parent path
// when the doc carries one).

async fn collection_group(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(name): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let opts = match parse_options(&q) {
        Err(msg) => return err(StatusCode::BAD_REQUEST, msg),
        Ok(o) => o,
    };
    if let Some(r) = valid_names(&name, None) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let collections = match dbh.list_collections().await {
        Ok(c) => c,
        Err(_) => return err_internal(),
    };
    let mut out = Vec::new();
    for stored in collections {
        let logical = stored.clone();
        if !realtime::matches_group(&logical, &name) {
            continue;
        }
        if !hot.policy.allow(auth.as_ref(), &dotted(&dbname, &logical), Method::List, None) {
            continue;
        }
        let docs = match dbh.list(&stored, &opts).await {
            Ok(d) => d,
            Err(_) => continue,
        };
        for doc in docs {
            let doc_coll = doc
                .data
                .get("_collectionPath")
                .and_then(|v| v.as_str())
                .unwrap_or(&logical);
            // Same-db bare path (docs came from this handle) → dotted.
            if hot.policy.allow(auth.as_ref(), &dotted(&dbname, doc_coll), Method::Get, Some(&doc)) {
                out.push(doc);
            }
        }
    }
    Json(out).into_response()
}

// --- Aggregates (legacy POST /api/aggregate/* parity) ---
//
// Body `{options?, aggregations: [{type: count|sum|avg, field?, alias?}]}`.
// Key = alias, else `{type}_{field|'count'}`. Gateway-side reduce (uniform
// across drivers; pushdown is a driver optimization for later).

#[derive(Debug, serde::Deserialize)]
struct AggBody {
    #[serde(default)]
    options: QueryOptions,
    #[serde(default)]
    aggregations: Vec<AggSpec>,
}

#[derive(Debug, serde::Deserialize)]
struct AggSpec {
    #[serde(rename = "type")]
    agg_type: String,
    field: Option<String>,
    alias: Option<String>,
}

async fn aggregate(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
    Json(body): Json<AggBody>,
) -> impl IntoResponse {
    let collection = path.trim_matches('/').to_string();
    if collection.is_empty() {
        return err(StatusCode::BAD_REQUEST, "aggregate needs a collection path");
    }
    if denied_internal(&collection).is_some() {
        return err(StatusCode::FORBIDDEN, "reserved __ prefix");
    }
    if let Some(r) = valid_names(&collection, None) {
        return r;
    }
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let pol = dotted(&dbname, &collection);
    if !hot.policy.allow(auth.as_ref(), &pol, Method::List, None) {
        return forbidden();
    }
    let stored = stored(&collection);
    // Aggregates ignore paging (legacy passes options through to count/sum/avg).
    let mut opts = body.options.clone();
    opts.limit = None;
    opts.offset = None;
    let mut result = serde_json::Map::new();
    for agg in body.aggregations {
        let t = agg.agg_type.to_ascii_lowercase();
        let key = agg.alias.clone().unwrap_or_else(|| match t.as_str() {
            "count" => "count_count".to_string(),
            _ => format!("{t}_{}", agg.field.as_deref().unwrap_or("count")),
        });
        let value = match t.as_str() {
            "count" => match dbh.count(&stored, &opts).await {
                Ok(n) => serde_json::json!(n),
                Err(e) => return err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()),
            },
            "sum" | "avg" => {
                let field = match agg.field.as_deref().filter(|f| !f.is_empty()) {
                    Some(f) => f,
                    None => return err(StatusCode::BAD_REQUEST, format!("{t} needs a field")),
                };
                // Reduce guard: legacy drivers list into RAM — refuse past the cap.
                // (Drivers with native aggregation never fetch; the guard is
                // still correct — it bounds the legacy path only.)
                match dbh.count(&stored, &opts).await {
                    Ok(n) if n > realtime::MAX_AGG_SCAN_DOCS => {
                        return err(
                            StatusCode::BAD_REQUEST,
                            "collection too large to reduce: narrow with filters",
                        )
                    }
                    Err(e) => return err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()),
                    _ => {}
                }
                let r = if t == "sum" {
                    dbh.sum(&stored, field, &opts).await
                } else {
                    dbh.avg(&stored, field, &opts).await
                };
                match r {
                    Ok(n) => serde_json::json!(n),
                    Err(e) => return err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()),
                }
            }
            _ => return err(StatusCode::BAD_REQUEST, format!("unknown aggregation: {}", agg.agg_type)),
        };
        result.insert(key, value);
    }
    Json(serde_json::Value::Object(result)).into_response()
}
// --- Local auth (BFF): two HttpOnly cookies, browser never holds tokens ---

fn session_cookies(
    local: &LocalAuth,
    tokens: &hakobackend_auth_local::SessionTokens,
    conf: &CookieConf,
) -> HeaderMap {
    let mut h = HeaderMap::new();
    let pair = [
        (ACCESS_COOKIE, &tokens.access_jwt, local.access_ttl()),
        (REFRESH_COOKIE, &tokens.refresh_opaque, local.refresh_ttl()),
    ];
    for (name, value, age) in pair {
        // __Host- shape when defaulted (Secure + Path=/ + no Domain);
        // deployers opting into Domain/SameSite=None own the consequence.
        h.append(header::SET_COOKIE, conf.pair(name, value, age).parse().unwrap());
    }
    h
}

fn clear_cookies(conf: &CookieConf) -> HeaderMap {
    let mut h = HeaderMap::new();
    for name in [ACCESS_COOKIE, REFRESH_COOKIE] {
        h.append(header::SET_COOKIE, conf.pair(name, "", 0).parse().unwrap());
    }
    h
}

/// Issuance rendering (Firebase-style dual-mode, all config-gated):
/// cookies per `cookies_on`, JSON body tokens per `token_response`.
/// Default (cookies on, tokens off): cookies only, body `{uid}` —
/// byte-identical to the old shape. Pure function, tested below.
fn render_issuance(
    conf: &CookieConf,
    local: &LocalAuth,
    tokens: &hakobackend_auth_local::SessionTokens,
    uid: &str,
    token_response: bool,
    cookies_on: bool,
) -> (HeaderMap, serde_json::Value) {
    let h = if cookies_on {
        session_cookies(local, tokens, conf)
    } else {
        HeaderMap::new()
    };
    let mut body = serde_json::json!({ "uid": uid });
    if token_response {
        body["access_token"] = tokens.access_jwt.clone().into();
        body["refresh_token"] = tokens.refresh_opaque.clone().into();
        body["expires_in"] = local.access_ttl().into();
        body["token_type"] = "Bearer".into();
    }
    (h, body)
}

async fn local_or_400(s: &AppState) -> Result<Arc<LocalAuth>, Response> {
    s.hot().await.local.clone().ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "local auth is not active (see --auth)").into_response()
    })
}

fn str_field(body: &HashMap<String, serde_json::Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| body.get(*k)).and_then(|v| v.as_str()).map(|s| s.to_string())
}

async fn issuance_local(s: &AppState) -> Result<Arc<LocalAuth>, Response> {
    local_or_400(s).await
}

/// Client IP for audit records without an extractor: axum's
/// `ConnectInfo` is only available to handlers that declare it, and the
/// auth handlers deliberately don't (unix arrivals would 500 — the peer
/// there is UnixPeer, not SocketAddr; see limit_mw). So: trusted proxy
/// header when enabled, else the client-facing port's own address is
/// unknowable here — record "direct". Proxy deployments set trust_proxy
/// and get the real client; direct deployments share one box anyway.
fn audit_ip(headers: &HeaderMap, trust_proxy: bool) -> String {
    audit::peer_ip(headers, trust_proxy, None).replace("unix", "direct")
}

async fn auth_register(
    State(s): State<AppState>,
    headers: HeaderMap,
    Extension(auth): Extension<Option<AuthContext>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // No ConnectInfo extractor (unix arrivals would 500 — see limit_mw):
    // audit peer falls back to "unix" when no TCP peer is present.
    let ip = audit_ip(&headers, s.limits.trust_proxy);
    // Settled deployments close self-service — but admins can still
    // create users ("admin-created users only", Temuan #5 fixed).
    // Anonymous + closed = 403; admin + closed = through (audited why).
    let admin = is_admin(auth.as_ref(), &s.admin_uids);
    if !s.local_register && !admin {
        audit::register("-", &ip, false, "closed");
        return err(StatusCode::FORBIDDEN, "registration closed by administrator");
    }
    let local = match issuance_local(&s).await {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut body = match body.as_object() {
        Some(m) => m.clone().into_iter().collect::<HashMap<_, _>>(),
        None => return err(StatusCode::BAD_REQUEST, "JSON object body required"),
    };
    let id = body.remove("id").and_then(|v| v.as_str().map(str::to_string));
    let email = body.remove("email").and_then(|v| v.as_str().map(str::to_string));
    let password = match body.remove("password").and_then(|v| v.as_str().map(str::to_string)) {
        Some(p) => p,
        None => return err(StatusCode::BAD_REQUEST, "password required"),
    };
    match local.register(id.clone(), email, &password, body).await {
        Ok(doc) => {
            audit::register(&doc.id, &ip, true, if admin && !s.local_register { "admin" } else { "ok" });
            // Gateway bus: user creates are CRUD events too.
            let users = s.hot().await.policy.identity.users_collection.clone();
            let stored = stored(&users);
            realtime::emit(
                &stored,
                Change {
                    collection: stored.clone(),
                    id: doc.id.clone(),
                    kind: ChangeKind::Change,
                    old: None,
                    new: Some(doc.clone()),
                },
            );
            (StatusCode::CREATED, Json(serde_json::json!({ "id": doc.id }))).into_response()
        }
        Err(e) => {
            audit::register(id.as_deref().unwrap_or("-"), &ip, false, &e.to_string());
            err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code())
        }
    }
}

/// Path-alias endpoint (issue #5): `GET|POST|PUT|PATCH|DELETE /api/alias/*`.
///
/// Owner-declared rewrites for regular endpoints (htaccess-RewriteRule
/// spirit, not a script engine). The handler rewrites the URI to the
/// TARGET and re-enters routing via the bare table, so downstream (auth,
/// policy, limits, wstats) sees the call exactly like a direct one and
/// policy evaluates the TARGET (one rule surface).
///
/// Why a route and not middleware: axum's `Router::layer` wraps endpoints
/// post-match, so a rewrite middleware can never affect routing (the
/// request would already have missed). The route matches first; the
/// redispatch routes again on the rewritten URI.
///
/// Gates run once, on the outer pass (limit/auth/host/cors are
/// path-independent anyway); the bare redispatch carries method/headers/
/// body plus the auth context, so handlers self-gate on the target.
/// Unmatched alias = empty 404 (same as an unknown route).
async fn alias_dispatch(State(s): State<AppState>, req: Request) -> Response {
    // The router matched `/api/alias/{*path}`; patterns compile WITHOUT
    // the prefix (see compile), so strip it before matching.
    let path = req.uri().path().to_string();
    let sub = path.strip_prefix("/api/alias").unwrap_or(&path);
    let table = s.aliases.read().unwrap().clone();
    if table.is_empty() {
        // No aliases declared: an /api/alias/* path matches nothing.
        return StatusCode::NOT_FOUND.into_response();
    }
    let Some((target_path, target_q)) = table.rewrite(sub) else {
        return StatusCode::NOT_FOUND.into_response();
    };
    let merged = alias::merge_query(&target_q, req.uri().query());
    let pq = if merged.is_empty() {
        target_path
    } else {
        format!("{target_path}?{merged}")
    };
    // Targets carry JSON in the query (options={...}): `{`, `}`, `"`,
    // `[`, `]`, spaces are legal after axum decodes the query but NOT in
    // a raw Uri string (InvalidUriChar -> worker crash, empty reply).
    // Re-encode the query side (path side is already slot-encoded).
    // allow: unreserved + sub-delims + :@/? (RFC 3986 query) + `%`
    // (slot-encoded %XX from capture substitution, never double-encoded).
    // Everything else (notably `{`, `}`, `"`) becomes %XX; downstream
    // Query decoding restores the exact JSON bytes.
    let pq = reencode_query(&pq);
    let (mut parts, body) = req.into_parts();
    // Fresh request, cherry-picked extensions. Rationale: axum APPENDS
    // route params (UrlParams) on every match instead of replacing, so
    // forwarding the outer match's extensions would poison the inner
    // `Path` extractor ("expected 1 but got 2"). Carried: auth context
    // (handlers require it; note axum's `Extension<T>` extractor reads
    // the BARE `T`, so carry `Option<AuthContext>` unwrapped),
    // OriginalUri (still the client-facing URI). Left behind: UrlParams
    // + MatchedPath (inner match re-inserts both), ConnectInfo (no inner
    // consumer; audit is header-based).
    let auth = parts.extensions.remove::<Option<AuthContext>>();
    let original_uri = parts
        .extensions
        .get::<axum::extract::OriginalUri>()
        .cloned();
    let mut fresh = Request::new(body);
    *fresh.method_mut() = parts.method;
    *fresh.uri_mut() = pq.parse().expect("alias target re-encodes to valid URI");
    *fresh.version_mut() = parts.version;
    *fresh.headers_mut() = parts.headers;
    if let Some(auth) = auth {
        fresh.extensions_mut().insert(auth);
    }
    if let Some(original_uri) = original_uri {
        fresh.extensions_mut().insert(original_uri);
    }
    let bare = s.bare.get().expect("bare router installs at boot").clone();
    tower::ServiceExt::oneshot(bare, fresh)
        .await
        .unwrap()
}

/// Percent-encode a `path?query` string's query side for Uri parsing.
/// Path passes through (slot-encoded at rewrite); every query byte
/// outside the allowed set becomes %XX.
fn reencode_query(pq: &str) -> String {
    let Some(qi) = pq.find('?') else {
        return pq.to_string();
    };
    let (path, query) = pq.split_at(qi);
    let query = &query[1..]; // skip the `?` itself (split_at keeps it)
    let mut out = String::with_capacity(pq.len() + 16);
    out.push_str(path);
    out.push('?');
    for b in query.as_bytes() {
        match b {
            b'0'..=b'9' | b'A'..=b'Z' | b'a'..=b'z'
            | b'-' | b'_' | b'.' | b'~' | b'!' | b'$' | b'&' | b'\'' | b'(' | b')'
            | b'*' | b'+' | b',' | b';' | b'=' | b':' | b'@' | b'/' | b'?' | b'%' => {
                out.push(*b as char)
            }
            _ => out.push_str(&format!("%{b:02X}")),
        }
    }
    out
}

/// DPoP proof components for issuance (login/refresh): htu = absolute URI of this endpoint.
/// Missing Host / broken proof → fails in bind_dpop (fail-closed).
fn issuance_parts(s: &AppState, headers: &HeaderMap, path: &str) -> (Option<String>, String) {
    let uri = base_uri(s.tls, headers, path);
    let proof = headers.get("DPoP").and_then(|v| v.to_str().ok()).map(str::to_string);
    (proof, uri)
}

async fn auth_login(
    State(s): State<AppState>,
    headers: HeaderMap,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let ip = audit_ip(&headers, s.limits.trust_proxy);
    let local = match issuance_local(&s).await {
        Ok(l) => l,
        Err(e) => return e,
    };
    let map = match body.as_object() {
        Some(m) => m,
        None => return err(StatusCode::BAD_REQUEST, "JSON object body required"),
    };
    let owned: HashMap<String, serde_json::Value> = map.clone().into_iter().collect();
    let login = str_field(&owned, &["login", "id", "email", "username"]);
    let password = str_field(&owned, &["password"]);
    match (login, password) {
        (Some(l), Some(p)) => {
            // Per-account lockout BEFORE verification: locked attempts
            // never burn Argon2 CPU, and the 429 (with Retry-After) is
            // uniform whether or not the account exists.
            if let Some(retry) = s.login_guard.locked_secs(&l) {
                let mut h = HeaderMap::new();
                h.insert(header::RETRY_AFTER, retry.to_string().parse().unwrap());
                audit::login_fail(&l, &ip, true);
                return (StatusCode::TOO_MANY_REQUESTS, h, "too many login attempts").into_response();
            }
            let (proof, uri) = issuance_parts(&s, &headers, "/api/auth/login");
            let dpop = proof.as_deref().map(|proof| DpopRequest { proof, method: "POST", uri: &uri });
            match local.login(&l, &p, dpop).await {
                Ok((ctx, tokens)) => {
                    s.login_guard.clear(&l);
                    audit::login_ok(&l, &ip);
                    let (headers, body) = render_issuance(
                        &s.cookies,
                        &local,
                        &tokens,
                        &ctx.uid,
                        s.local_token_response,
                        s.local_cookies,
                    );
                    (StatusCode::OK, headers, Json(body)).into_response()
                }
                // Obfuscate: wrong login vs password vs dpop are not distinguished (anti-enumeration).
                Err(_) => {
                    // Transition edge only: one `auth.lockout` per lock
                    // (fail() returns Some exactly on open→locked).
                    if let Some(retry) = s.login_guard.fail(&l) {
                        audit::lockout(&l, &ip, retry);
                    }
                    audit::login_fail(&l, &ip, false);
                    err(StatusCode::UNAUTHORIZED, "invalid credentials")
                }
            }
        }
        _ => err(StatusCode::BAD_REQUEST, "login + password required"),
    }
}

async fn auth_refresh(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    let ip = audit_ip(&headers, s.limits.trust_proxy);
    let local = match issuance_local(&s).await {
        Ok(l) => l,
        Err(e) => return e,
    };
    // Cookie first; JSON body `{refresh_token}` when the token-response
    // knob is on (Firebase-style, no-cookie clients). Bytes (not Json):
    // malformed bodies must stay 401, never 422 — identical to before
    // when the knob is off (the body is not even looked at).
    let mut presented = read_cookie(&headers, REFRESH_COOKIE);
    if presented.is_none() && s.local_token_response {
        presented = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("refresh_token").and_then(|t| t.as_str()).map(str::to_string));
    }
    let presented = match presented {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (proof, uri) = issuance_parts(&s, &headers, "/api/auth/refresh");
    let dpop = proof.as_deref().map(|proof| DpopRequest { proof, method: "POST", uri: &uri });
    match local.refresh_classified(&presented, dpop).await {
        Ok((ctx, tokens)) => {
            let (h, body) = render_issuance(
                &s.cookies,
                &local,
                &tokens,
                &ctx.uid,
                s.local_token_response,
                s.local_cookies,
            );
            (StatusCode::OK, h, Json(body)).into_response()
        }
        // Reuse (revocation + revoke-all) audits distinctly from plain
        // expiry: the former is an attack signal, the latter routine.
        // Both fail closed identically (401 + cleared cookies).
        Err(hakobackend_auth_local::RefreshDeny::ReuseRevoked) => {
            audit::refresh_reuse("-", &ip);
            let h = if s.local_cookies {
                clear_cookies(&s.cookies)
            } else {
                HeaderMap::new()
            };
            (StatusCode::UNAUTHORIZED, h, Json(serde_json::json!({ "error": "invalid session" }))).into_response()
        }
        Err(hakobackend_auth_local::RefreshDeny::Gone) => {
            audit::refresh_fail(&ip);
            let h = if s.local_cookies {
                clear_cookies(&s.cookies)
            } else {
                HeaderMap::new()
            };
            (StatusCode::UNAUTHORIZED, h, Json(serde_json::json!({ "error": "invalid session" }))).into_response()
        }
    }
}

async fn auth_logout(
    State(s): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> impl IntoResponse {
    // Best-effort revoke; clearing cookies is the real logout. Body token
    // accepted under the same knob as refresh (pure-token clients hold no
    // cookies); Bearer access token evicted from the resolve cache either
    // way (cookie and header share the key space).
    let mut presented = read_cookie(&headers, REFRESH_COOKIE);
    if presented.is_none() && s.local_token_response {
        presented = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v.get("refresh_token").and_then(|t| t.as_str()).map(str::to_string));
    }
    if let Some(t) = presented {
        if let Some(local) = s.hot().await.local.clone() {
            let _ = local.logout(&t).await;
        }
        // The access token may be cached: kill it now, TTL notwithstanding.
        // (Refresh-token logout above kills future issuance; this kills the
        // live bearer. Cookie tokens share the same cache key space.)
        if let Some(a) = read_cookie(&headers, ACCESS_COOKIE).or_else(|| bearer(&headers)) {
            s.tokcache.remove(&a);
        }
        audit::logout("-", &audit_ip(&headers, s.limits.trust_proxy), "refresh");
    }
    let h = if s.local_cookies {
        clear_cookies(&s.cookies)
    } else {
        HeaderMap::new()
    };
    (StatusCode::OK, h, Json(serde_json::json!({ "success": true }))).into_response()
}

async fn auth_me(Extension(auth): Extension<Option<AuthContext>>) -> impl IntoResponse {
    match auth {
        Some(ctx) => Json(serde_json::to_value(ctx).unwrap()).into_response(),
        None => unauthorized(),
    }
}

// --- Realtime: two-way WS + one-way SSE (HTTP_CONTRACT.md §realtime) ---
//
// WS:  -> {"type":"subscribe","key","collection","options"?, "group"?, "token"?}
//      -> {"type":"unsubscribe","key"} | {"type":"ping"} | {"type":"auth","token"}
//      <- {"type":"ready","key"} | {"type":"change","key","kind","doc"}
//      <- {"type":"error","key"?,"message"} | {"type":"pong"}
// SSE: GET /api/stream/<coll>?options=&token= → event: change, data: {kind,doc}.
// Token via Bearer/cookie preferred; ?token= fallback (logged in URL —
// recommended only via TLS; see TLS phase). 100 subs/WS connection limit.

// WS caps live on AppState (ws_max_msg_kb / ws_max_subs); the old
// `WS_MAX_MSG` const is retired. Over-budget subscribes are rejected,
// never silently dropped (see the error above).
async fn ws_handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
    ws: ws::WebSocketUpgrade,
) -> Response {
    let init = bearer(&headers)
        .or_else(|| read_cookie(&headers, ACCESS_COOKIE))
        .or_else(|| {
            if query_token_allowed(s.tls, &headers) {
                q.get("token").cloned()
            } else {
                None
            }
        });
    let uri = base_uri(s.tls, &headers, "/ws");
    let mut auth = None;
    if let Some(t) = init.clone() {
        auth = resolve_token(&s, &t).await;
    }
    // DPoP-bound tokens must prove at upgrade (per-message proofs don't
    // exist on WS); failure degrades to anonymous like HTTP.
    auth = enforce_dpop(&s, &headers, "GET", &uri, init, auth).await;
    ws.on_upgrade(move |socket| ws_loop(s, socket, auth))
}

async fn ws_send(socket: &mut ws::WebSocket, value: serde_json::Value) -> bool {
    socket.send(ws::Message::Text(value.to_string().into())).await.is_ok()
}

fn ws_err(key: Option<&str>, message: &str) -> serde_json::Value {
    match key {
        Some(k) => serde_json::json!({"type": "error", "key": k, "message": message}),
        None => serde_json::json!({"type": "error", "message": message}),
    }
}

async fn ws_loop(s: AppState, mut socket: ws::WebSocket, mut auth: Option<AuthContext>) {
    let mut subs: HashMap<String, realtime::Subscription> = HashMap::new();
    loop {
        // Single task: socket messages + drain all subscriptions (no dynamic select!).
        let msg = tokio::select! {
            m = socket.recv() => m,
            _ = tokio::time::sleep(std::time::Duration::from_millis(50)) => None,
        };
        if let Some(msg) = msg {
            let text = match msg {
                Ok(ws::Message::Text(t)) => {
                    if t.len() > s.ws_max_msg {
                        break;
                    }
                    t.to_string()
                }
                Ok(ws::Message::Close(_)) | Err(_) => break,
                _ => continue,
            };
            let v: serde_json::Value = match serde_json::from_str(&text) {
                Ok(v) => v,
                Err(_) => {
                    if !ws_send(&mut socket, ws_err(None, "message is not JSON")).await {
                        break;
                    }
                    continue;
                }
            };
            match v.get("type").and_then(|t| t.as_str()) {
                Some("ping") => {
                    if !ws_send(&mut socket, serde_json::json!({"type": "pong"})).await {
                        break;
                    }
                }
                Some("auth") => {
                    let token = v.get("token").and_then(|t| t.as_str()).unwrap_or("");
                    let mut next = resolve_token(&s, token).await;
                    // No headers mid-socket: a DPoP-bound token can't prove
                    // here, so Require/MustVerify degrades it to anonymous.
                    if let Some(local) = s.hot().await.local.clone() {
                        let is_local = next
                            .as_ref()
                            .and_then(|c| c.extra.get("provider"))
                            .and_then(|vv| vv.as_str())
                            == Some(hakobackend_auth_local::NAME);
                        if !matches!(dpop_action(local.dpop_mode(), is_local, false), DpopAction::Keep) {
                            next = None;
                        }
                    }
                    auth = next;
                    let ok = auth.is_some();
                    if !ws_send(&mut socket, serde_json::json!({"type": "auth", "ok": ok})).await {
                        break;
                    }
                }
                Some("subscribe") => {
                    let key = v.get("key").and_then(|k| k.as_str()).unwrap_or("").to_string();
                    let collection = v.get("collection").and_then(|c| c.as_str()).unwrap_or("").to_string();
                    if key.is_empty() || collection.is_empty() {
                        if !ws_send(&mut socket, ws_err(None, "key + collection required")).await {
                            break;
                        }
                        continue;
                    }
                    // Multidatabase (issue #13): per-message `db` (absent =
                    // default), validated like the URL channel.
                    let dbname = match v
                        .get("db")
                        .and_then(|d| d.as_str())
                        .map(|d| {
                            if d.is_empty() || !hakobackend_core::valid_db_name(d) {
                                Err(())
                            } else {
                                Ok(d.to_string())
                            }
                        })
                        .unwrap_or_else(|| Ok("default".to_string()))
                    {
                        Ok(d) => d,
                        Err(()) => {
                            if !ws_send(&mut socket, ws_err(Some(&key), "invalid db name")).await {
                                break;
                            }
                            continue;
                        }
                    };
                    if subs.len() >= s.ws_max_subs && !subs.contains_key(&key) {
                        if !ws_send(&mut socket, ws_err(Some(&key), "subscription limit exceeded")).await {
                            break;
                        }
                        continue;
                    }
                    let spec = realtime::SubSpec {
                        collection,
                        options: v
                            .get("options")
                            .map(|o| serde_json::from_value(o.clone()).unwrap_or_default())
                            .unwrap_or_default(),
                        group: v.get("group").and_then(|g| g.as_bool()).unwrap_or(false),
                        db: dbname.clone(),
                    };
                    // Per-subscribe token (legacy authData pattern) overrides connection auth.
                    // Same DPoP rule as the `auth` message: no proof possible here.
                    let mut sub_auth = match v.get("token").and_then(|t| t.as_str()) {
                        Some(t) => resolve_token(&s, t).await,
                        None => auth.clone(),
                    };
                    if v.get("token").is_some() {
                        if let Some(local) = s.hot().await.local.clone() {
                            let is_local = sub_auth
                                .as_ref()
                                .and_then(|c| c.extra.get("provider"))
                                .and_then(|vv| vv.as_str())
                                == Some(hakobackend_auth_local::NAME);
                            if !matches!(dpop_action(local.dpop_mode(), is_local, false), DpopAction::Keep) {
                                sub_auth = None;
                            }
                        }
                    }
                    let hot = s.hot().await;
                    let dbh = match hot.db_for(&dbname) {
                        Ok(h) => h,
                        Err(_) => {
                            if !ws_send(&mut socket, ws_err(Some(&key), "unknown database")).await {
                                break;
                            }
                            continue;
                        }
                    };
                    let policy = hot.policy;
                    let caps = *s.rt_caps.read().unwrap();
                    match realtime::subscribe(dbh, policy, sub_auth, spec, caps).await {
                        Ok(sub) => {
                            // Per-connection snapshot budget (anti memory-bomb).
                            let total: usize =
                                subs.values().map(|s| s.snapshot_docs).sum::<usize>() + sub.snapshot_docs;
                            if total > caps.max_conn_docs {
                                drop(sub);
                                if !ws_send(&mut socket, ws_err(Some(&key), "connection snapshot budget exceeded")).await {
                                    break;
                                }
                                continue;
                            }
                            subs.insert(key.clone(), sub);
                            if !ws_send(&mut socket, serde_json::json!({"type": "ready", "key": key})).await {
                                break;
                            }
                        }
                        Err(e) => {
                            let msg = if matches!(e, hakobackend_core::AppError::PermissionDenied) {
                                "Permission denied by policy"
                            } else {
                                "subscribe failed"
                            };
                            if !ws_send(&mut socket, ws_err(Some(&key), msg)).await {
                                break;
                            }
                        }
                    }
                }
                Some("unsubscribe") => {
                    if let Some(k) = v.get("key").and_then(|k| k.as_str()) {
                        subs.remove(k);
                    }
                }
                _ => {
                    if !ws_send(&mut socket, ws_err(None, "unknown type")).await {
                        break;
                    }
                }
            }
        }
        // Drain all subscriptions to the socket.
        let mut dead = false;
        for (key, sub) in subs.iter_mut() {
            while let Ok(ev) = sub.rx.try_recv() {
                let w = ev.wire();
                let msg = serde_json::json!({"type": "change", "key": key, "kind": w.kind, "doc": w.doc});
                if !ws_send(&mut socket, msg).await {
                    dead = true;
                    break;
                }
            }
            if dead {
                break;
            }
        }
        if dead {
            break;
        }
    }
}

async fn sse_handler(
    State(s): State<AppState>,
    headers: HeaderMap,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> Response {
    let collection = match parse_collection_path(&path) {
        PathKind::Collection { collection } if !collection.is_empty() => collection,
        _ => return err(StatusCode::BAD_REQUEST, "SSE only supports collection endpoints"),
    };
    let token = bearer(&headers)
        .or_else(|| read_cookie(&headers, ACCESS_COOKIE))
        .or_else(|| {
            if query_token_allowed(s.tls, &headers) {
                q.get("token").cloned()
            } else {
                None
            }
        });
    let uri = base_uri(s.tls, &headers, &format!("/api/stream/{path}"));
    let auth = match token.clone() {
        Some(t) => resolve_token(&s, &t).await,
        None => None,
    };
    // SSE is a GET: the DPoP proof (if any) rides the handshake headers.
    let auth = enforce_dpop(&s, &headers, "GET", &uri, token, auth).await;
    let options = match parse_options(&q) {
        Ok(o) => o,
        Err(msg) => return err(StatusCode::BAD_REQUEST, msg),
    };
    let group = matches!(q.get("group").map(|g| g.as_str()), Some("1") | Some("true"));
    let dbname = match resolve_db_name(&q) {
        Ok(d) => d,
        Err(r) => return r,
    };
    let hot = s.hot().await;
    let dbh = match hot.db_for(&dbname) {
        Ok(h) => h,
        Err(r) => return r,
    };
    let policy = hot.policy;
    let caps = *s.rt_caps.read().unwrap();
    let sub = match realtime::subscribe(dbh, policy, auth, realtime::SubSpec { collection, options, group, db: dbname }, caps).await {
        Ok(sub) => sub,
        Err(e) if matches!(e, hakobackend_core::AppError::PermissionDenied) => return forbidden(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Bridge: Subscription (source-task owner) lives in the forwarder task; when
    // the client disconnects, send fails → task stops → source aborted (clean chain).
    let (tx, rx) = tokio::sync::mpsc::unbounded_channel::<Result<sse::Event, std::convert::Infallible>>();
    tokio::spawn(async move {
        let mut sub = sub;
        while let Some(ev) = sub.rx.recv().await {
            let w = ev.wire();
            match sse::Event::default().event("change").json_data(w) {
                Ok(e) => {
                    if tx.send(Ok(e)).is_err() {
                        break;
                    }
                }
                Err(_) => break,
            }
        }
    });
    sse::Sse::new(tokio_stream::wrappers::UnboundedReceiverStream::new(rx))
        .keep_alive(sse::KeepAlive::new().interval(std::time::Duration::from_secs(15)).text("keep-alive"))
        .into_response()
}

// --- GitHub OAuth, BFF pattern: browser redirect, tokens never reach the browser ---

async fn github_login(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let _ = q;
    let g = match s.github.read().await.clone() {
        Some(g) => g,
        None => return err(StatusCode::BAD_REQUEST, "github oauth is not configured"),
    };
    match g.login_url_for(None).await {
            Ok((url, nonce)) => {
                // Browser-binding nonce for the callback (login-CSRF guard).
                let mut h = HeaderMap::new();
                h.append(
                    header::SET_COOKIE,
                    format!("__Host-gh_nonce={nonce}; Path=/; Max-Age=600; Secure; HttpOnly; SameSite=Lax")
                        .parse()
                        .unwrap(),
                );
                (StatusCode::FOUND, h, Redirect::to(&url)).into_response()
            }
            Err(_) => err_internal(),
        }
}

async fn github_callback(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let (code, state) = match (q.get("code").cloned(), q.get("state").cloned()) {
        (Some(c), Some(st)) => (c, st),
        _ => return err(StatusCode::BAD_REQUEST, "code + state required"),
    };
    // Global flow only (single-user backend, no tenant bundles).
    let (g, local) = match (s.github.read().await.clone(), s.hot().await.local.clone()) {
        (Some(g), Some(l)) => (g, l),
        _ => return err(StatusCode::BAD_REQUEST, "github oauth requires env credentials + `local` in the chain"),
    };
    // Obfuscate all failures (bad code, stale state, github down).
    let nonce = read_cookie(&headers, "__Host-gh_nonce");
    let (uid, email, login) = match g.callback(&code, &state, nonce.as_deref()).await {
        Ok(v) => v,
        Err(_) => return err(StatusCode::UNAUTHORIZED, "github verification failed"),
    };
    let mut profile = HashMap::new();
    if let Some(l) = login {
        profile.insert("login".to_string(), serde_json::Value::String(l));
    }
    match local.login_external(&uid, email, profile).await {
        Ok((_ctx, tokens)) => {
            let mut h = session_cookies(&local, &tokens, &s.cookies);
            // Single-use nonce: consume the cookie too.
            h.append(
                header::SET_COOKIE,
                "__Host-gh_nonce=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Lax".parse().unwrap(),
            );
            // BFF: browser returns to the app with a session cookie; no tokens in URL.
            h.insert(header::LOCATION, g.after_login().parse().unwrap());
            (StatusCode::FOUND, h).into_response()
        }
                Err(_) => err_internal(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpop_decision_table() {
        use DpopAction::*;
        // Off / non-local always passes.
        assert_eq!(dpop_action(DpopMode::Off, true, true), Keep);
        assert_eq!(dpop_action(DpopMode::Require, false, false), Keep);
        // Require without proof = strip; with proof = verify.
        assert_eq!(dpop_action(DpopMode::Require, true, false), Strip);
        assert_eq!(dpop_action(DpopMode::Require, true, true), MustVerify);
        // Accept: bearer fallback without proof, verify when proof is present.
        assert_eq!(dpop_action(DpopMode::Accept, true, false), Keep);
        assert_eq!(dpop_action(DpopMode::Accept, true, true), MustVerify);
    }
    #[test]
    fn host_allowlist_matching() {
        // Empty = off (yesterday's default: everything passes).
        assert!(host_allowed(&[], Some("api.example.com")));
        assert!(host_allowed(&[], None));
        let allowed = vec!["api.example.com".to_string()];
        // Exact, case-insensitive, port-stripped.
        assert!(host_allowed(&allowed, Some("api.example.com")));
        assert!(host_allowed(&allowed, Some("API.EXAMPLE.COM")));
        assert!(host_allowed(&allowed, Some("api.example.com:3010")));
        // Loopback ALWAYS passes (local probes, loopback svc, dev) even
        // with a list set — infra-local traffic is never gated.
        assert!(host_allowed(&allowed, Some("127.0.0.1:3005")));
        assert!(host_allowed(&allowed, Some("localhost")));
        assert!(host_allowed(&allowed, Some("[::1]:3005")));
        // Wrong host or missing Host header = refuse.
        assert!(!host_allowed(&allowed, Some("evil.example")));
        assert!(!host_allowed(&allowed, Some("other.internal:9")));
        assert!(!host_allowed(&allowed, None));
    }

    #[test]
    fn request_host_prefers_header_falls_back_to_authority() {
        // h1 shape: Host header wins.
        let req = Request::builder()
            .uri("https://127.0.0.1:3005/api/ready")
            .header(header::HOST, "evil.example")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(request_host(&req), Some("evil.example"));
        // h2 shape: no Host header, :authority from the URI.
        let req = Request::builder()
            .uri("https://api.example.com:3005/api/ready")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(request_host(&req), Some("api.example.com:3005"));
        // Neither: refuse path (host_allowed handles).
        let req = Request::builder()
            .uri("/api/ready")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(request_host(&req), None);
    }

    #[test]
    fn plain_companion_only_when_tls_leaves_loopback_plain() {
        use std::net::{IpAddr, SocketAddr};
        let lo4: IpAddr = "127.0.0.1".parse().unwrap();
        let any4: IpAddr = "0.0.0.0".parse().unwrap();
        let pub4: IpAddr = "203.0.113.237".parse().unwrap();
        let lo6: IpAddr = "::1".parse().unwrap();
        // TLS off: plain is already served wherever it binds - no companion.
        assert_eq!(plain_companion_for(false, true, &[pub4], 3005), None);
        // Opted out: none even with TLS on a public IP.
        assert_eq!(plain_companion_for(true, false, &[pub4], 3005), None);
        // Any bind covering loopback suppresses the companion (one check
        // across the whole multi-bind set - a single companion max).
        for ips in [vec![any4], vec![lo4], vec![lo6], vec!["::".parse().unwrap()], vec![pub4, lo4]] {
            assert_eq!(plain_companion_for(true, true, &ips, 3005), None);
        }
        // TLS on public IP(s) only: one plain companion on loopback.
        assert_eq!(
            plain_companion_for(true, true, &[pub4], 3010),
            Some("127.0.0.1:3010".parse::<SocketAddr>().unwrap())
        );
        assert_eq!(
            plain_companion_for(true, true, &[pub4, "10.10.8.8".parse().unwrap()], 3010),
            Some("127.0.0.1:3010".parse::<SocketAddr>().unwrap())
        );
    }

    #[test]
    fn host_list_splits_trims_and_drops_empties() {
        assert_eq!(split_hosts("0.0.0.0"), vec!["0.0.0.0".to_string()]);
        assert_eq!(
            split_hosts("somehost.com,10.10.8.8"),
            vec!["somehost.com".to_string(), "10.10.8.8".to_string()]
        );
        assert_eq!(
            split_hosts("  a.com ,, b.com, "),
            vec!["a.com".to_string(), "b.com".to_string()]
        );
        assert!(split_hosts("  , ").is_empty());
    }

    #[test]
    fn cors_echoes_http_origins_only() {
        // Mirrors the nginx map it replaces: echo any http(s) Origin.
        let open: Vec<String> = vec![];
        let h = cors_headers(Some("https://app.example.com"), &open).unwrap();
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.example.com"
        );
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).unwrap(),
            "true"
        );
        assert!(h.contains_key(header::VARY));
        assert!(cors_headers(Some("http://localhost:3000"), &open).is_some());
        // Non-http, null, missing = no CORS headers.
        assert!(cors_headers(Some("ftp://x"), &open).is_none());
        assert!(cors_headers(Some("null"), &open).is_none());
        assert!(cors_headers(None, &open).is_none());
    }

    #[test]
    fn cors_allowlist_is_exact() {
        let allowed = vec!["https://app.example.com".to_string()];
        assert!(cors_headers(Some("https://app.example.com"), &allowed).is_some());
        // Subdomain, scheme, port, and prefix games all miss.
        assert!(cors_headers(Some("https://evil.example.com"), &allowed).is_none());
        assert!(cors_headers(Some("http://app.example.com"), &allowed).is_none());
        assert!(cors_headers(Some("https://app.example.com:8443"), &allowed).is_none());
        assert!(cors_headers(Some("https://app.example.com.evil.com"), &allowed).is_none());
    }

    #[test]
    fn cookie_pair_shapes_flags() {
        let strict = CookieConf {
            secure: true,
            samesite: "Strict".into(),
            path: "/".into(),
            domain: None,
        };
        assert_eq!(
            strict.pair("ub_access", "tok", 600),
            "ub_access=tok; Path=/; Max-Age=600; HttpOnly; Secure; SameSite=Strict"
        );
        let lax = CookieConf {
            secure: false,
            samesite: "Lax".into(),
            path: "/api".into(),
            domain: Some("example.com".into()),
        };
        assert_eq!(
            lax.pair("n", "", 0),
            "n=; Path=/api; Max-Age=0; HttpOnly; Domain=example.com; SameSite=Lax"
        );
    }

    #[test]
    fn csrf_strips_ports_both_sides() {
        let none: &[String] = &[];
        // Cross-port same-host: app :443 -> API :3000. Origin as
        // browsers send it (default port omitted) vs Host with port.
        assert!(csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://api.example.com"),
            none
        ));
        // Exact same + explicit port both sides.
        assert!(csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://api.example.com:3000"),
            none
        ));
        // True cross-site still fails (with and without ports).
        assert!(!csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://evil.example.com"),
            none
        ));
        assert!(!csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://evil.example.com:3000"),
            none
        ));
        // Subdomain games fail.
        assert!(!csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://api.example.com.evil.com"),
            none
        ));
        // Absent Origin (curl/scripts) passes; absent Host fails closed
        // against any Origin.
        assert!(csrf_origin_ok(Some("h:3000"), None, none));
        assert!(!csrf_origin_ok(None, Some("https://h"), none));
        // Bracketed v6 with ports.
        assert!(csrf_origin_ok(Some("[::1]:3000"), Some("http://[::1]:3000"), none));
        assert!(csrf_origin_ok(Some("[::1]:3000"), Some("http://[::1]"), none));
        assert!(!csrf_origin_ok(Some("[::1]:3000"), Some("http://[::2]:3000"), none));
    }

    #[test]
    fn csrf_trusts_cors_allowlist() {
        // Issue #4: an Origin exactly on the CORS allowlist passes even
        // when the Host differs (operator-trusted web origin).
        let allow = vec!["https://app.example.com".to_string()];
        assert!(csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://app.example.com"),
            &allow
        ));
        // Exact match only: scheme, suffix and substring games fail.
        assert!(!csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("http://app.example.com"),
            &allow
        ));
        assert!(!csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://app.example.com.evil.com"),
            &allow
        ));
        assert!(!csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://evil.example.com"),
            &allow
        ));
        // Empty allowlist = yesterday's behavior (host match only).
        let none: &[String] = &[];
        assert!(!csrf_origin_ok(
            Some("api.example.com:3000"),
            Some("https://app.example.com"),
            none
        ));
    }

    #[test]
    fn reencode_query_keeps_json() {
        // options={...} must survive Uri parsing (the #5 crash vector:
        // `{`, `}`, `"` are InvalidUriChar raw) and decode back byte-identical.
        let pq = "/api/collections/s?options={\"filters\":[],\"limit\":1}";
        let out = reencode_query(pq);
        // Structural chars are encoded, never raw.
        assert!(out.contains("%7B") && out.contains("%7D") && out.contains("%22"));
        // The encoded form parses as a Uri (this panicked before the fix).
        let uri: axum::http::Uri = out.parse().expect("re-encoded alias target parses");
        assert_eq!(uri.path(), "/api/collections/s");
        // Spaces encode; paths without query pass through.
        assert_eq!(reencode_query("/a?x=a b"), "/a?x=a%20b");
        assert_eq!(reencode_query("/a"), "/a");
    }

    #[test]
    fn alias_e2e_transform() {
        // Full middleware transform (minus tower): the exact pq the router sees.
        let table = alias::AliasTable::new(
            alias::compile_all(&[(
                "/api/alias/students/:sid/:pin".into(),
                "/api/collections/students".into(),
                "options={\"filters\":[{\"field\":\"sid\",\"op\":\"==\",\"value\":\"{sid}\"},{\"field\":\"pin\",\"op\":\"==\",\"value\":\"{pin}\"}],\"limit\":1}".into(),
            )])
            .unwrap(),
        );
        let sub = "/students/S1/987";
        let (target_path, target_q) = table.rewrite(sub).expect("match");
        let merged = alias::merge_query(&target_q, None);
        let pq = format!("{target_path}?{merged}");
        let pq = reencode_query(&pq);
        let uri: axum::http::Uri = pq.parse().expect("parses");
        assert_eq!(uri.path(), "/api/collections/students");
        // The decoded query must equal the direct-call query byte-for-byte.
        let decoded: String = percent_decode(uri.query().unwrap());
        assert_eq!(
            decoded,
            "options={\"filters\":[{\"field\":\"sid\",\"op\":\"==\",\"value\":\"S1\"},{\"field\":\"pin\",\"op\":\"==\",\"value\":\"987\"}],\"limit\":1}"
        );
    }

    /// Full-stack alias proof (issue #5): alias and direct call travel
    /// the production router + all layers and return byte-identical bodies.
    #[tokio::test]
    async fn alias_routes_end_to_end() {
        use tower::ServiceExt;
        let (st, raw) = rbw_state("[defaults]\nread = \"public\"\nwrite = \"public\"\n", "alias_stack").await;
        raw.set(
            "students",
            "S1",
            incoming_doc("S1", serde_json::json!({"sid": "S1", "pin": "987"})),
            false,
        )
        .await
        .unwrap();
        *st.aliases.write().unwrap() = Arc::new(alias::AliasTable::new(
            alias::compile_all(&[(
                "/api/alias/students/:sid/:pin".into(),
                "/api/collections/students".into(),
                "options={\"filters\":[{\"field\":\"sid\",\"op\":\"==\",\"value\":\"{sid}\"},{\"field\":\"pin\",\"op\":\"==\",\"value\":\"{pin}\"}],\"limit\":1}".into(),
            )])
            .unwrap(),
        ));
        async fn get(app: Router, uri: &str) -> (StatusCode, Vec<u8>) {
            let req = Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap();
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), 8 * 1024 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        }
        // Raw `{ } "` never hit the wire: clients percent-encode, exactly
        // like reencode_query does for rewritten targets.
        let direct_uri = reencode_query("/api/collections/students?options={\"filters\":[{\"field\":\"sid\",\"op\":\"==\",\"value\":\"S1\"},{\"field\":\"pin\",\"op\":\"==\",\"value\":\"987\"}],\"limit\":1}");
        // SAME router instance for every call below.
        let app = build_router(st.clone(), vec![], false);
        let (as_, via_alias) = get(app.clone(), "/api/alias/students/S1/987").await;
        let (ds, direct) = get(app.clone(), &direct_uri).await;
        assert_eq!(as_, StatusCode::OK);
        assert_eq!(ds, StatusCode::OK);
        assert_eq!(via_alias, direct);
        // Wrong pin: same shape, empty result (never a leak, never an error).
        let (ws, wrong) = get(app.clone(), "/api/alias/students/S1/000").await;
        assert_eq!(ws, StatusCode::OK);
        assert_eq!(wrong, b"[]");
        // Unmatched alias pattern: empty 404, like an unknown route.
        let (ns, _) = get(app, "/api/alias/students/only-one").await;
        assert_eq!(ns, StatusCode::NOT_FOUND);
    }

    /// Ops knobs end-to-end (issue #4): read_only 503s writes with
    /// Retry-After while reads pass; max_batch_ops caps batch/transaction.
    #[tokio::test]
    async fn ops_knobs_end_to_end() {
        use tower::ServiceExt;
        let (st, _raw) = rbw_state("[defaults]\nread = \"public\"\nwrite = \"public\"\n", "ops_knobs").await;
        async fn call(
            app: Router,
            method: &str,
            uri: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
            let b = Request::builder().method(method).uri(uri);
            let req = match body {
                Some(v) => b
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(v.to_string()))
                    .unwrap(),
                None => b.body(axum::body::Body::empty()).unwrap(),
            };
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let headers = res.headers().clone();
            let body = axum::body::to_bytes(res.into_body(), 8 * 1024 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, headers, body)
        }
        let app = build_router(st.clone(), vec![], false);
        // Seed with the gate open.
        let (s, _, _) = call(app.clone(), "PUT", "/api/collections/m/a", Some(serde_json::json!({"z": 1}))).await;
        assert_eq!(s, StatusCode::OK);
        // Maintenance on: writes 503 + Retry-After, reads pass.
        st.read_only.store(true, std::sync::atomic::Ordering::Relaxed);
        let (s, h, _) = call(app.clone(), "PUT", "/api/collections/m/a", Some(serde_json::json!({"z": 2}))).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        assert!(h.contains_key("retry-after"));
        let (s, _, _) = call(app.clone(), "DELETE", "/api/collections/m/a", None).await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        let (s, _, _) = call(
            app.clone(),
            "POST",
            "/api/batch",
            Some(serde_json::json!({"operations": []})),
        )
        .await;
        assert_eq!(s, StatusCode::SERVICE_UNAVAILABLE);
        let (s, body) = {
            let (s, _, b) = call(app.clone(), "GET", "/api/collections/m/a", None).await;
            (s, b)
        };
        assert_eq!(s, StatusCode::OK);
        // The blocked overwrite never landed (still z:1, not z:2).
        assert!(String::from_utf8_lossy(&body).contains("\"z\":1"));
        // Gate off, cap tightened: oversized batch/tx refuse.
        st.read_only.store(false, std::sync::atomic::Ordering::Relaxed);
        st.max_batch_ops.store(1, std::sync::atomic::Ordering::Relaxed);
        let two = serde_json::json!({"operations": [
            {"type": "get", "collection": "m", "id": "a"},
            {"type": "get", "collection": "m", "id": "a"},
        ]});
        let (s, _, b) = call(app.clone(), "POST", "/api/batch", Some(two.clone())).await;
        // Legacy quirk preserved: batch failures are always 500, no code.
        assert_eq!(s, StatusCode::INTERNAL_SERVER_ERROR);
        assert!(String::from_utf8_lossy(&b).contains("too many ops (max 1)"));
        let (s, _, b) = call(app.clone(), "POST", "/api/transaction", Some(two)).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&b).contains("too many ops (max 1)"));
    }

    /// Archive moves + lazy residency over HTTP (issue #21 A): relocate
    /// roundtrip + refusals, load/unload/unloaded, and the non-hako
    /// rejection. Hako-backed (sqlite rejects archive ops by design).
    #[tokio::test]
    async fn relocate_and_residency_end_to_end() {
        use tower::ServiceExt;
        async fn call(
            app: Router,
            method: &str,
            uri: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, Vec<u8>) {
            let b = Request::builder().method(method).uri(uri);
            let req = match body {
                Some(v) => b
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(v.to_string()))
                    .unwrap(),
                None => b.body(axum::body::Body::empty()).unwrap(),
            };
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), 8 * 1024 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        }
        let dir = std::env::temp_dir().join(format!("hakobackend_rbw_reloc_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pol = dir.join("policy.toml");
        std::fs::write(&pol, "[defaults]\nread = \"public\"\nwrite = \"public\"\n").unwrap();
        let raw: Arc<dyn Database> =
            Arc::new(HakoDb::open(dir.join("h.ub").to_string_lossy().as_ref()).unwrap());
        let policy_hot = Arc::new(PolicyHot::new(Some(pol.to_string_lossy().into_owned())));
        let chain_root: Arc<AuthChain> =
            Arc::new(open_chain(&AuthSpec::Off, None, None).expect("off chain builds"));
        let dbs: HashMap<String, Arc<dyn Database>> =
            HashMap::from([("default".to_string(), raw.clone())]);
        let st = finish_state(raw.clone(), dbs, policy_hot, chain_root, dir).await;
        let app = build_router(st.clone(), vec![], false);
        // Seed, move, verify both sides.
        let (s, _) = call(app.clone(), "PUT", "/api/collections/m/a", Some(serde_json::json!({"z": 1}))).await;
        assert_eq!(s, StatusCode::OK);
        let (s, b) = call(app.clone(), "POST", "/api/relocate",
            Some(serde_json::json!({"src": "m", "dst": "m2", "ids": ["a", "ghost"]}))).await;
        assert_eq!(s, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        assert_eq!(v["moved"], serde_json::json!(["a"]));
        assert_eq!(v["missing"], serde_json::json!(["ghost"]));
        let (s, _) = call(app.clone(), "GET", "/api/collections/m/a", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, b) = call(app.clone(), "GET", "/api/collections/m2/a", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(String::from_utf8_lossy(&b).contains("\"z\":1"));
        // Refusals: same-side 400, reserved prefix 403, oversize 400.
        let (s, _) = call(app.clone(), "POST", "/api/relocate",
            Some(serde_json::json!({"src": "m", "dst": "m", "ids": ["a"]}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, _) = call(app.clone(), "POST", "/api/relocate",
            Some(serde_json::json!({"src": "__x", "dst": "m", "ids": ["a"]}))).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        // Residency: load ok, unload of non-lazy 400, unloaded list empty.
        let (s, b) = call(app.clone(), "POST", "/api/collections/load",
            Some(serde_json::json!({"collection": "m2"}))).await;
        assert_eq!(s, StatusCode::OK);
        assert!(String::from_utf8_lossy(&b).contains("\"ok\":true"));
        let (s, _) = call(app.clone(), "POST", "/api/collections/unload",
            Some(serde_json::json!({"collection": "m2"}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        let (s, b) = call(app.clone(), "GET", "/api/collections/unloaded", None).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(serde_json::from_slice::<serde_json::Value>(&b).unwrap(), serde_json::json!([]));
        // Non-hako driver rejects clearly (sqlite state).
        let (st2, _raw2) = rbw_state("[defaults]\nread = \"public\"\nwrite = \"public\"\n", "reloc").await;
        let app2 = build_router(st2.clone(), vec![], false);
        let (s, b) = call(app2.clone(), "POST", "/api/relocate",
            Some(serde_json::json!({"src": "m", "dst": "m2", "ids": ["a"]}))).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        assert!(String::from_utf8_lossy(&b).contains("no relocate support"));
    }

    /// Files end-to-end (issue #11): upload -> metadata -> bytes ->
    /// range/etag -> signed URL -> delete, plus the 415/400/403 edges.
    #[tokio::test]
    async fn files_end_to_end() {
        use tower::ServiceExt;
        let (st, _raw) = rbw_state("[defaults]\nread = \"public\"\nwrite = \"public\"\n", "files_e2e").await;
        fn part(boundary: &str, mime: &str, bytes: &[u8]) -> Vec<u8> {
            let mut o = format!(
                "--{boundary}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\nContent-Type: {mime}\r\n\r\n"
            )
            .into_bytes();
            o.extend_from_slice(bytes);
            o.extend_from_slice(format!("\r\n--{boundary}--\r\n").as_bytes());
            o
        }
        async fn call(
            app: Router,
            method: &str,
            uri: &str,
            content_type: Option<&str>,
            body: Vec<u8>,
            headers: Vec<(&str, &str)>,
        ) -> (StatusCode, axum::http::HeaderMap, Vec<u8>) {
            let mut b = Request::builder().method(method).uri(uri);
            if let Some(ct) = content_type {
                b = b.header("content-type", ct);
            }
            for (k, v) in headers {
                b = b.header(k, v);
            }
            let req = b.body(axum::body::Body::from(body)).unwrap();
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let h = res.headers().clone();
            let body = axum::body::to_bytes(res.into_body(), 64 * 1024 * 1024).await.unwrap().to_vec();
            (status, h, body)
        }
        let app = build_router(st.clone(), vec![], false);
        let png: Vec<u8> = b"\x89PNG\r\n\x1a\n".iter().chain(std::iter::repeat(&7u8).take(100)).copied().collect();
        let bd = "BOUNDARY";
        let ct = format!("multipart/form-data; boundary={bd}");
        // Upload single.
        let (s, _, b) = call(app.clone(), "POST", "/api/files/avatars/u1", Some(&ct), part(bd, "image/png", &png), vec![]).await;
        assert_eq!(s, StatusCode::OK);
        let v: serde_json::Value = serde_json::from_slice(&b).unwrap();
        let sha = v["file"]["sha256"].as_str().unwrap().to_string();
        assert_eq!(v["file"]["state"], "ready");
        assert_eq!(v["file"]["size"], png.len() as u64);
        // Metadata readable as an ordinary doc.
        let (s, _, b) = call(app.clone(), "GET", "/api/collections/avatars/u1", None, vec![], vec![]).await;
        assert_eq!(s, StatusCode::OK);
        assert!(String::from_utf8_lossy(&b).contains(&sha));
        // Bytes back, byte-identical, with ETag.
        let (s, h, b) = call(app.clone(), "GET", "/api/files/avatars/u1", None, vec![], vec![]).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b, png);
        assert_eq!(h["content-type"], "image/png");
        let etag = h["etag"].to_str().unwrap().to_string();
        assert!(etag.contains(&sha));
        // Conditional + range.
        let (s, _, _) = call(app.clone(), "GET", "/api/files/avatars/u1", None, vec![], vec![("if-none-match", &etag)]).await;
        assert_eq!(s, StatusCode::NOT_MODIFIED);
        let (s, h, b) = call(app.clone(), "GET", "/api/files/avatars/u1", None, vec![], vec![("range", "bytes=0-7")]).await;
        assert_eq!(s, StatusCode::PARTIAL_CONTENT);
        assert_eq!(b, &png[..8]);
        assert!(h["content-range"].to_str().unwrap().starts_with("bytes 0-7/"));
        // Signed URL mint + consume (parses + verifies; policy here is
        // public so the MAC leg is also proven by the tamper case in
        // files::tests::sig_roundtrip_and_expiry).
        let (s, _, b) = call(app.clone(), "GET", "/api/files/avatars/u1?sign=60", None, vec![], vec![]).await;
        assert_eq!(s, StatusCode::OK);
        let url = serde_json::from_slice::<serde_json::Value>(&b).unwrap()["url"].as_str().unwrap().to_string();
        assert!(url.contains("exp=") && url.contains("sig="));
        let (s, _, b) = call(app.clone(), "GET", &url, None, vec![], vec![]).await;
        assert_eq!(s, StatusCode::OK);
        assert_eq!(b, png);
        // Edges: unlisted mime, lying magic, batch cap (test max_batch=4).
        let (s, _, _) = call(app.clone(), "POST", "/api/files/avatars/u2", Some(&ct), part(bd, "text/plain", b"hi"), vec![]).await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let (s, _, _) = call(app.clone(), "POST", "/api/files/avatars/u2", Some(&ct), part(bd, "image/png", b"not a png at all"), vec![]).await;
        assert_eq!(s, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        let mut big = Vec::new();
        for _ in 0..5 {
            big.extend_from_slice(format!("--{bd}\r\nContent-Disposition: form-data; name=\"file\"; filename=\"a.png\"\r\nContent-Type: image/png\r\n\r\n").as_bytes());
            big.extend_from_slice(&png);
            big.extend_from_slice(b"\r\n");
        }
        big.extend_from_slice(format!("--{bd}--\r\n").as_bytes());
        let (s, _, _) = call(app.clone(), "POST", "/api/files/many", Some(&ct), big, vec![]).await;
        assert_eq!(s, StatusCode::BAD_REQUEST);
        // Delete: bytes 404 after, metadata-only doc dropped entirely.
        let (s, _, _) = call(app.clone(), "DELETE", "/api/files/avatars/u1", None, vec![], vec![]).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = call(app.clone(), "GET", "/api/files/avatars/u1", None, vec![], vec![]).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _, _) = call(app.clone(), "GET", "/api/collections/avatars/u1", None, vec![], vec![]).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        // Deny policy: bytes 403 without a signature.
        let (st2, _r2) = rbw_state("[defaults]\nread = \"deny\"\nwrite = \"public\"\n", "files_deny").await;
        let app2 = build_router(st2.clone(), vec![], false);
        let (s, _, _) = call(app2.clone(), "POST", "/api/files/avatars/u1", Some(&ct), part(bd, "image/png", &png), vec![]).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _, _) = call(app2.clone(), "GET", "/api/files/avatars/u1", None, vec![], vec![]).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
    }

    /// Multidatabase end-to-end (issue #13): cluster-backed default +
    /// app1. Isolation both directions, dotted policy, unknown → 404,
    /// batch inside a db, bare default untouched.
    #[tokio::test]
    async fn multidb_end_to_end() {
        use tower::ServiceExt;
        let st = rbw_cluster_state(
            "[defaults]\nread = \"public\"\nwrite = \"public\"\n[collections.\"app1.secret\"]\nread = \"deny\"\n",
            "multidb",
            &[("default", "db0"), ("app1", "db1")],
        )
        .await;
        async fn call(
            app: Router,
            method: &str,
            uri: &str,
            body: Option<serde_json::Value>,
        ) -> (StatusCode, Vec<u8>) {
            let b = Request::builder().method(method).uri(uri);
            let req = match body {
                Some(v) => b
                    .header("content-type", "application/json")
                    .body(axum::body::Body::from(v.to_string()))
                    .unwrap(),
                None => b.body(axum::body::Body::empty()).unwrap(),
            };
            let res = app.oneshot(req).await.unwrap();
            let status = res.status();
            let body = axum::body::to_bytes(res.into_body(), 8 * 1024 * 1024)
                .await
                .unwrap()
                .to_vec();
            (status, body)
        }
        let app = build_router(st.clone(), vec![], false);
        let doc = Some(serde_json::json!({"z": 1}));
        // Same id, both databases, independent.
        let (s, _) = call(app.clone(), "PUT", "/api/collections/m/a", doc.clone()).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = call(app.clone(), "PUT", "/api/collections/m/a?db=app1", doc.clone()).await;
        assert_eq!(s, StatusCode::OK);
        let (s, b) = call(app.clone(), "GET", "/api/collections/m/a", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(String::from_utf8_lossy(&b).contains("\"z\":1"));
        let (s, b) = call(app.clone(), "GET", "/api/collections/m/a?db=app1", None).await;
        assert_eq!(s, StatusCode::OK);
        assert!(String::from_utf8_lossy(&b).contains("\"z\":1"));
        // Isolation: app1-only doc invisible on default and vice versa.
        let (s, _) = call(app.clone(), "PUT", "/api/collections/only/b?db=app1", doc.clone()).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = call(app.clone(), "GET", "/api/collections/only/b", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, b) = call(app.clone(), "GET", "/api/collections?db=app1", None).await;
        assert_eq!(s, StatusCode::OK);
        let lists = String::from_utf8_lossy(&b);
        assert!(lists.contains("\"only\"") && lists.contains("\"m\""), "got: {lists}");
        // Dotted policy: app1.secret denied, bare secret (default) open.
        let (s, _) = call(app.clone(), "PUT", "/api/collections/secret/s?db=app1", doc.clone()).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = call(app.clone(), "GET", "/api/collections/secret/s?db=app1", None).await;
        assert_eq!(s, StatusCode::FORBIDDEN);
        let (s, _) = call(app.clone(), "PUT", "/api/collections/secret/s", doc.clone()).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = call(app.clone(), "GET", "/api/collections/secret/s", None).await;
        assert_eq!(s, StatusCode::OK);
        // Unknown database: 404 (never a silent default).
        let (s, _) = call(app.clone(), "GET", "/api/collections/m/a?db=nope", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        // Batch stays inside its db (structural, single ?db=).
        let two = serde_json::json!({"operations": [
            {"type": "set", "collection": "m", "id": "b1", "data": {"z": 2}},
        ]});
        let (s, _) = call(app.clone(), "POST", "/api/batch?db=app1", Some(two)).await;
        assert_eq!(s, StatusCode::OK);
        let (s, _) = call(app.clone(), "GET", "/api/collections/m/b1", None).await;
        assert_eq!(s, StatusCode::NOT_FOUND);
        let (s, _) = call(app.clone(), "GET", "/api/collections/m/b1?db=app1", None).await;
        assert_eq!(s, StatusCode::OK);
    }

    /// Single-db deployments serve `default` only (issue #13): explicit
    /// non-default is 400 (teaches the rule), absent is today's paths.
    #[tokio::test]
    async fn multidb_single_db_400() {
        use tower::ServiceExt;
        let (st, _raw) = rbw_state("[defaults]\nread = \"public\"\nwrite = \"public\"\n", "multidb400").await;
        let app = build_router(st.clone(), vec![], false);
        async fn get(app: Router, uri: &str) -> StatusCode {
            let req = Request::builder().uri(uri).body(axum::body::Body::empty()).unwrap();
            app.oneshot(req).await.unwrap().status()
        }
        assert_eq!(get(app.clone(), "/api/collections?db=x").await, StatusCode::BAD_REQUEST);
        assert_eq!(get(app.clone(), "/api/collections?db=default").await, StatusCode::OK);
        assert_eq!(get(app.clone(), "/api/collections").await, StatusCode::OK);
    }

    /// Minimal percent-decoder for the transform test (no new deps).
    fn percent_decode(s: &str) -> String {
        let mut out = Vec::with_capacity(s.len());
        let b = s.as_bytes();
        let mut i = 0;
        while i < b.len() {
            if b[i] == b'%' && i + 2 < b.len() {
                if let (Some(h), Some(l)) = (hex(b[i + 1]), hex(b[i + 2])) {
                    out.push(h << 4 | l);
                    i += 3;
                    continue;
                }
            }
            out.push(b[i]);
            i += 1;
        }
        String::from_utf8(out).unwrap()
    }

    fn hex(c: u8) -> Option<u8> {
        match c {
            b'0'..=b'9' => Some(c - b'0'),
            b'A'..=b'F' => Some(c - b'A' + 10),
            b'a'..=b'f' => Some(c - b'a' + 10),
            _ => None,
        }
    }

    #[test]
    fn render_issuance_matrix() {
        // render_issuance needs a LocalAuth for access_ttl; build one over
        // the auth crate's empty test db (no env, no behavior).
        let conf = CookieConf {
            secure: true,
            samesite: "Strict".into(),
            path: "/".into(),
            domain: None,
        };
        let local = LocalAuth::build_test();
        let tokens = || hakobackend_auth_local::SessionTokens {
            access_jwt: "ACC".into(),
            refresh_opaque: "REF".into(),
        };
        // Default: cookies only, body {uid} — byte-identical to the old shape.
        let (h, b) = render_issuance(&conf, &local, &tokens(), "u1", false, true);
        assert_eq!(b, serde_json::json!({ "uid": "u1" }));
        assert!(h.contains_key(header::SET_COOKIE));
        // Dual-mode: cookies + body tokens.
        let (h2, b2) = render_issuance(&conf, &local, &tokens(), "u1", true, true);
        assert!(h2.contains_key(header::SET_COOKIE));
        assert_eq!(b2["access_token"], serde_json::json!("ACC"));
        assert_eq!(b2["refresh_token"], serde_json::json!("REF"));
        assert_eq!(b2["token_type"], serde_json::json!("Bearer"));
        assert!(b2["expires_in"].as_u64().is_some());
        // Pure-token: body tokens, NO cookies.
        let (h3, b3) = render_issuance(&conf, &local, &tokens(), "u1", true, false);
        assert!(!h3.contains_key(header::SET_COOKIE));
        assert_eq!(b3["access_token"], serde_json::json!("ACC"));
    }

    #[test]
    fn incoming_doc_honors_explicit_body_id() {

        // create() passes "": a valid body id becomes the primary id and
        // leaves data (no duplicate id keys downstream).
        let d = incoming_doc("", serde_json::json!({"id": "k1", "v": 1}));
        assert_eq!(d.id, "k1");
        assert!(!d.data.contains_key("id"));
        // Invalid body id: fall back to generated (lenient, no new 400).
        let d = incoming_doc("", serde_json::json!({"id": "", "v": 1}));
        assert!(d.id.is_empty());
        // Non-empty id (PUT/batch paths): body id never overrides.
        let d = incoming_doc("url-id", serde_json::json!({"id": "body-id"}));
        assert_eq!(d.id, "url-id");
    }

    #[test]
    fn shim_legacy_index() {
        assert_eq!(legacy_index_collection("posts/index").as_deref(), Some("posts"));        assert_eq!(
            legacy_index_collection("/posts/p1/revisions/index/").as_deref(),
            Some("posts/p1/revisions")
        );
        // A real collection named "index" is not hijacked.
        assert_eq!(legacy_index_collection("index"), None);
        assert_eq!(legacy_index_collection("posts"), None);
    }

    #[test]
    fn svc_key_match_and_loopback() {
        use std::net::SocketAddr;
        let key = "abcdef0123456789abcdef0123456789abcdef0123456789abcdef0123456789";
        let svc = ServiceAuth::build(&[key.into()], &["ai_configs:read".into()]);
        assert!(svc_key_match(&svc.hashes, key));
        assert!(!svc_key_match(&svc.hashes, "wrong"));
        assert!(!svc_key_match(&[], key), "no keys = feature off");
        // Loopback reads the socket peer, never headers.
        let mut spoof = HeaderMap::new();
        spoof.insert("x-forwarded-for", "127.0.0.1".parse().unwrap());
        spoof.insert(header::HOST, "127.0.0.1".parse().unwrap());
        let mut req = Request::builder().uri("/").body(axum::body::Body::empty()).unwrap();
        assert!(!loopback_peer(&req), "no peer info = deny");
        req.extensions_mut().insert(ConnectInfo("10.0.0.1:5".parse::<SocketAddr>().unwrap()));
        assert!(!loopback_peer(&req), "remote + spoofed headers = deny");
        req.extensions_mut().insert(ConnectInfo("127.0.0.1:5".parse::<SocketAddr>().unwrap()));
        assert!(loopback_peer(&req));
        req.extensions_mut().insert(ConnectInfo("[::1]:5".parse::<SocketAddr>().unwrap()));
        assert!(loopback_peer(&req));
    }

    #[test]
    fn svc_scope_arm_beats_deny() {
        let pol = PolicyFile::load_str("[collections.ai_configs]\nread = \"deny\"\nwrite = \"deny\"\n").unwrap();
        let ctx = svc_context(&["ai_configs:read".to_string()]);
        assert!(pol.allow(Some(&ctx), "ai_configs", Method::Get, None));
        assert!(pol.allow(Some(&ctx), "ai_configs", Method::List, None));
        assert!(!pol.allow(Some(&ctx), "ai_configs", Method::Update, None), "read != write");
        assert!(!pol.allow(Some(&ctx), "other", Method::Get, None), "scope is per-collection");
        assert!(!pol.allow(None, "ai_configs", Method::Get, None), "anon still denied");
    }

    #[test]
    fn svc_config_validation() {
        assert!(config::valid_svc_key(&"ab".repeat(32)));
        assert!(!config::valid_svc_key("short"));
        assert!(!config::valid_svc_key(&"zz".repeat(32)));
        assert!(config::parse_svc_scope("ai_configs:read"));
        assert!(config::parse_svc_scope("ai_configs:write"));
        assert!(!config::parse_svc_scope("ai_configs"));
        assert!(!config::parse_svc_scope("ai_configs:admin"));
        assert!(!config::parse_svc_scope(":read"));
    }

    // Unix arrivals carry UnixPeer instead of a TCP peer: loopback_peer
    // must accept the marker (unix-only: type exists only there).
    #[cfg(unix)]
    #[test]
    fn uds_marker_counts_as_loopback() {
        let mut req = Request::builder().uri("/").body(axum::body::Body::empty()).unwrap();
        assert!(!loopback_peer(&req));
        req.extensions_mut().insert(ConnectInfo(UnixPeer));
        assert!(loopback_peer(&req));
    }

    #[test]
    fn rate_limit_key() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let peer: SocketAddr = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234).into();
        let plain = HeaderMap::new();
        // Without trust_proxy: always peer IP (spoofed XFF ignored).
        let mut spoof = HeaderMap::new();
        spoof.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(client_key(&spoof, peer, false), "10.0.0.1");
        assert_eq!(client_key(&plain, peer, false), "10.0.0.1");
        // With trust_proxy: first XFF entry.
        assert_eq!(client_key(&spoof, peer, true), "1.2.3.4");
        // Empty/broken XFF → peer fallback.
        assert_eq!(client_key(&plain, peer, true), "10.0.0.1");
    }

    #[test]
    fn schema_base_uri_follows_tls() {        let mut h = HeaderMap::new();
        h.insert(header::HOST, "api.x.id:8080".parse().unwrap());
        assert_eq!(base_uri(false, &h, "/api/auth/login"), "http://api.x.id:8080/api/auth/login");
        assert_eq!(base_uri(true, &h, "/api/auth/login"), "https://api.x.id:8080/api/auth/login");
        // Missing Host → "unknown" (fail-closed in htu verification).
        assert_eq!(base_uri(true, &HeaderMap::new(), "/x"), "https://unknown/x");
    }

        #[test]
    fn op_method_mapping() {        use Method::*;
        assert_eq!(op_method("get", false, false), Get);
        assert_eq!(op_method("delete", true, true), Delete);
        assert_eq!(op_method("update", true, false), Update);
        assert_eq!(op_method("set", false, false), Create);
        assert_eq!(op_method("set", true, false), Update);
        assert_eq!(op_method("add", false, false), Create);
        assert_eq!(op_method("bogus", true, true), Update);
        assert_eq!(op_method("bogus", false, true), Create);
        assert_eq!(op_method("bogus", true, false), Create);
    }

    fn batch_op(t: &str, collection: &str, id: &str, data: serde_json::Value) -> BatchOpBody {
        BatchOpBody {
            op_type: t.into(),
            collection: collection.into(),
            id: Some(id.into()),
            data: Some(data),
            options: None,
        }
    }

    /// Batch shapes + atomicity on sqlite: set/add/update/delete roundtrip,
    /// unknown-type-as-create, and must_exist abort rolling everything back.
    /// Claim rules end to end: uid-self gates by doc id, role strips drop
    /// without a read, claim:role matches token attrs. No RBW added.
    #[tokio::test]
    async fn claim_self_strip_role_sqlite() {
        use hakobackend_db_sqlite::SqliteDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_claim_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db: Arc<dyn Database> =
            Arc::new(SqliteDb::open(dir.join("t.db").to_string_lossy().as_ref()).await.unwrap());
        let policy = Arc::new(PolicyFile::load_str(
            "[collections.profiles]\nread = \"auth\"\nupdate = \"claim:uid=self !role\"\n",
        ).unwrap());
        let me = || {
            Some(AuthContext { uid: "local:u1".into(), extra: Default::default() })
        };
        let other = || {
            Some(AuthContext { uid: "local:u2".into(), extra: Default::default() })
        };
        // Seed own profile directly (setup, not policy-gated).
        db.set("profiles", "local:u1", Doc {
            id: "local:u1".into(),
            data: [("nick".to_string(), serde_json::json!("u1"))].into_iter().collect(),
        }, false).await.unwrap();
        // Self update with an escalation attempt: allowed, role stripped.
        let res = run_ops(
            &db,
            &policy,
            me().as_ref(),
            vec![batch_op("update", "profiles", "local:u1",
                serde_json::json!({"nick": "uno", "role": "admin"}))],
            false,
            "default",
        )
        .await
        .unwrap();
        assert!(vals(res).iter().all(|r| r.get("success") == Some(&serde_json::json!(true))));
        let doc = db.get("profiles", "local:u1").await.unwrap().unwrap();
        assert_eq!(doc.data.get("nick").and_then(|v| v.as_str()), Some("uno"));
        assert!(doc.data.get("role").is_none(), "escalation field stripped");
        // Cross-user update: denied.
        let denied = run_ops(
            &db,
            &policy,
            other().as_ref(),
            vec![batch_op("update", "profiles", "local:u1", serde_json::json!({"nick": "x"}))],
            false,
            "default",
        )
        .await;
        assert!(denied.is_err());
        // Anonymous: denied.
        let denied = run_ops(
            &db,
            &policy,
            None,
            vec![batch_op("update", "profiles", "local:u1", serde_json::json!({"nick": "x"}))],
            false,
            "default",
        )
        .await;
        assert!(denied.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// claim:role matches token attrs (minted at login, zero per-request reads).
    #[tokio::test]
    async fn claim_role_attrs_sqlite() {
        use hakobackend_db_sqlite::SqliteDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_claimrole_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db: Arc<dyn Database> =
            Arc::new(SqliteDb::open(dir.join("t.db").to_string_lossy().as_ref()).await.unwrap());
        let policy = Arc::new(PolicyFile::load_str(
            "[collections.posts]\nread = \"public\"\ndelete = \"claim:role=maintainer\"\n",
        ).unwrap());
        let staff = || {
            Some(AuthContext {
                uid: "local:s".into(),
                extra: [("role".to_string(), serde_json::json!("staf"))].into_iter().collect(),
            })
        };
        let boss = || {
            Some(AuthContext {
                uid: "local:b".into(),
                extra: [("role".to_string(), serde_json::json!(["staf", "maintainer"]))].into_iter().collect(),
            })
        };
        db.set("posts", "p1", Doc {
            id: "p1".into(),
            data: [("t".to_string(), serde_json::json!(1))].into_iter().collect(),
        }, false).await.unwrap();
        // Staff without the role: denied.
        assert!(run_ops(&db, &policy, staff().as_ref(),
            vec![batch_op("delete", "posts", "p1", serde_json::json!({}))], false, "default").await.is_err());
        // Maintainer (array member): allowed.
        run_ops(&db, &policy, boss().as_ref(),
            vec![batch_op("delete", "posts", "p1", serde_json::json!({}))], false, "default").await.unwrap();
        assert!(db.get("posts", "p1").await.unwrap().is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn batch_end_to_end_sqlite() {        use hakobackend_db_sqlite::SqliteDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_batch_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db: Arc<dyn Database> =
            Arc::new(SqliteDb::open(dir.join("t.db").to_string_lossy().as_ref()).await.unwrap());
        let policy = Arc::new(PolicyFile::open());
        let d = |age: i64| serde_json::json!({"age": age});

        let res = run_ops(
            &db,
            &policy,
            None,
            vec![
                batch_op("set", "w", "a", d(1)),
                batch_op("add", "w", "b", d(2)),
                batch_op("create", "w", "c", d(3)),
                batch_op("get", "w", "a", d(0)),
            ],
            false,
            "default",
        )
        .await
        .unwrap();
        let res = vals(res);
        assert_eq!(res.len(), 4);
        assert!(res.iter().all(|r| r.get("success") == Some(&serde_json::json!(true))));
        assert_eq!(res[0].get("id"), Some(&serde_json::json!("a")));
        // Unknown op types are rejected, never silently created.
        let bad_type = run_ops(&db, &policy, None, vec![batch_op("bogus", "w", "z", d(0))], false, "default").await;
        assert!(bad_type.is_err());

        // must_exist failure aborts the whole batch (d is untouched).
        let bad = run_ops(
            &db,
            &policy,
            None,
            vec![batch_op("set", "w", "d", d(4)), batch_op("update", "w", "ghost", d(5))],
            false,
            "default",
        )
        .await;
        assert!(bad.is_err());
        assert!(db.get("w", "d").await.unwrap().is_none());

        // Transaction shapes: get → doc, writes → {success}.
        let res = vals(
            run_ops(&db, &policy, None, vec![batch_op("get", "w", "a", d(0))], true, "default")
                .await
                .unwrap(),
        );
        assert_eq!(res[0].get("age"), Some(&serde_json::json!(1)));

        // Atomics + stamps flow through batch writes (legacy __type__ wire).
        let res = run_ops(
            &db,
            &policy,
            None,
            vec![batch_op(
                "update",
                "w",
                "a",
                serde_json::json!({
                    "age": {"__type__": "increment", "n": 5},
                    "nick": {"__type__": "serverTimestamp"},
                    "gone": {"__type__": "deleteField"},
                    "profile.city": "bdg",
                }),
            )],
            false,
            "default",
        )
        .await
        .unwrap();
        let res = vals(res);
        assert_eq!(res[0].get("success"), Some(&serde_json::json!(true)));
        let a = db.get("w", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("age"), Some(&serde_json::json!(6)));
        assert!(a.data.get("nick").and_then(|v| v.as_str()).is_some());
        assert!(!a.data.contains_key("gone"));
        assert_eq!(
            a.data.get("profile"),
            Some(&serde_json::json!({"city": "bdg"})),
        );
        assert!(a.data.get("createdAt").and_then(|v| v.as_str()).is_some());
        assert!(a.data.get("updatedAt").and_then(|v| v.as_str()).is_some());
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn rbw_state(policy_toml: &str, tag: &str) -> (AppState, Arc<dyn Database>) {
        use hakobackend_db_sqlite::SqliteDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_rbw_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pol = dir.join("policy.toml");
        std::fs::write(&pol, policy_toml).unwrap();
        let raw: Arc<dyn Database> =
            Arc::new(SqliteDb::open(dir.join("t.db").to_string_lossy().as_ref()).await.unwrap());
        let policy_hot = Arc::new(PolicyHot::new(Some(pol.to_string_lossy().into_owned())));
        let chain_root: Arc<AuthChain> =
            Arc::new(open_chain(&AuthSpec::Off, None, None).expect("off chain builds"));
        // Single-db (default only); multidb coverage gets its own state below.
        let dbs: HashMap<String, Arc<dyn Database>> =
            HashMap::from([("default".to_string(), raw.clone())]);
        let st = finish_state(raw.clone(), dbs, policy_hot, chain_root, dir).await;
        (st, raw)
    }

    /// Multidatabase state (issue #13): hakocluster-backed, one single-dir
    /// cluster per database (N=1: no mesh needed, works everywhere).
    /// `dbs` maps names (the first is `default`) to data dirs.
    async fn rbw_cluster_state(
        policy_toml: &str,
        tag: &str,
        dbs: &[(&str, &str)],
    ) -> AppState {
        use hakobackend_db_hakocluster::ClusterDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_rbw_{tag}_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pol = dir.join("policy.toml");
        std::fs::write(&pol, policy_toml).unwrap();
        let policy_hot = Arc::new(PolicyHot::new(Some(pol.to_string_lossy().into_owned())));
        let chain_root: Arc<AuthChain> =
            Arc::new(open_chain(&AuthSpec::Off, None, None).expect("off chain builds"));
        let mut map: HashMap<String, Arc<dyn Database>> = HashMap::new();
        let mut raw = None;
        for (name, sub) in dbs {
            let d = dir.join(sub);
            std::fs::create_dir_all(&d).unwrap();
            let h: Arc<dyn Database> = Arc::new(
                ClusterDb::open(d.to_string_lossy().as_ref()).map_err(|e| e.to_string()).unwrap(),
            );
            if name == &"default" {
                raw = Some(h.clone());
            }
            map.insert(name.to_string(), h);
        }
        finish_state(raw.expect("need a default database"), map, policy_hot, chain_root, dir).await
    }

    /// Shared AppState construction for test states (single source for
    /// the literal: new AppState fields land here once, not per helper).
    async fn finish_state(
        raw: Arc<dyn Database>,
        dbs: HashMap<String, Arc<dyn Database>>,
        policy_hot: Arc<PolicyHot>,
        chain_root: Arc<AuthChain>,
        dir: std::path::PathBuf,
    ) -> AppState {
        let dbh = Arc::new(tokio::sync::RwLock::new(raw.clone()));
        let dbs_arc = Arc::new(dbs);
        let st = AppState {
            db: dbh.clone(),
            dbs: Arc::new(tokio::sync::RwLock::new(dbs_arc.clone())),
            policy: policy_hot.clone(),
            auth: Arc::new(tokio::sync::RwLock::new(chain_root.clone())),
            local: Arc::new(tokio::sync::RwLock::new(None)),
            github: Arc::new(tokio::sync::RwLock::new(None)),
            limits: Arc::new(LimitLayers {
                global: Arc::new(Limiter::new(Quota::per_minute(600, 100))),
                auth: Arc::new(Limiter::new(Quota::per_minute(20, 5))),
                trust_proxy: false,
            }),
            tls: false,
            admin_uids: Arc::new(vec![]),
            cli: Arc::new(Args {
                config: None, driver: None, data: None, rules: None, auth: None,
                host: None, port: None, admin_uids: vec![],
                public_url: None, limit_global: None,
                limit_global_burst: None, limit_auth: None, limit_auth_burst: None,
                trust_proxy: false, tls_cert: None, tls_key: None, validate: false,
                print_default_config: false, coalesce_writes: false,
                compress: false, body_limit_mb: None, cors_allowed_origins: vec![],
                no_local_register: false, read_only: false,
                wstats: false, benchmark: false, sock: None, http2: false,
                sync_serve: None, sync_peer: vec![], allowed_hosts: vec![],
            }),
            coalescer: Arc::new(coalesce::Coalescer::default()),
            coalesce_on: false,
            service: Arc::new(tokio::sync::RwLock::new(ServiceAuth::build(&[], &[]))),
            tokcache: Arc::new(tokcache::TokenCache::new()),
            hot_cache: Arc::new(HotCache::new(Hot {
                policy: policy_hot.get().await,
                db: raw.clone(),
                dbs: dbs_arc.clone(),
                auth: chain_root.clone(),
                service: ServiceAuth::build(&[], &[]),
                local: None,
            })),
            cors_allowed: Arc::new(vec![]),
            cookies: Arc::new(CookieConf {
                secure: true,
                samesite: "Strict".into(),
                path: "/".into(),
                domain: None,
            }),
            body_limit: 8 * 1024 * 1024,
            hsts_max_age: 31_536_000,
            compress_min_bytes: 1024,
            ws_max_msg: 1024 * 1024,
            ws_max_subs: 100,
            csrf_check: true,
            login_guard: Arc::new(loginguard::LoginGuard::new(0, 300)),
            local_register: true,
            read_only: Arc::new(std::sync::atomic::AtomicBool::new(false)),
            max_batch_ops: Arc::new(std::sync::atomic::AtomicU64::new(1000)),
            rt_caps: Arc::new(std::sync::RwLock::new(realtime::RtCaps::default())),
            local_token_response: false,
            local_cookies: true,
            aliases: Arc::new(std::sync::RwLock::new(Arc::new(alias::AliasTable::default()))),
            bare: Arc::new(std::sync::OnceLock::new()),
            // Files on with a temp dir (per-test tag dir above); small
            // caps keep the suite fast, secret enables the signed-URL leg.
            files: Arc::new(files::FileConf::from_cfg(
                Some(dir.join("files").to_string_lossy().into_owned()),
                8,
                4,
                vec!["image/png".into(), "image/jpeg".into()],
                "test-secret".into(),
            )),
        };
        st
    }

    fn ok_put(r: Response) {
        assert_eq!(r.status(), StatusCode::OK);
    }

    /// run_ops yields OpOut (Raw for tx-get hits); tests assert on Values.
    fn vals(res: Vec<OpOut>) -> Vec<serde_json::Value> {
        res.into_iter().map(OpOut::into_value).collect()
    }

    /// ListShape classification drives the per-shape wstats tables.
    #[test]
    fn list_shape_classify() {
        use hakobackend_core::{Direction, Filter, FilterOp, OrderBy, QueryOptions};
        use wstats::ListShape;
        let f = || Filter { field: "age".into(), op: FilterOp::Eq, value: serde_json::json!(1) };
        let o = || OrderBy { field: "age".into(), direction: Direction::Asc };
        let q = QueryOptions::default();
        assert_eq!(wstats::classify(&q), ListShape::Plain);
        let mut q = QueryOptions::default();
        q.limit = Some(10);
        assert_eq!(wstats::classify(&q), ListShape::Paged);
        let mut q = QueryOptions::default();
        q.filters.push(f());
        assert_eq!(wstats::classify(&q), ListShape::Filter);
        let mut q = QueryOptions::default();
        q.order_by.push(o());
        assert_eq!(wstats::classify(&q), ListShape::Order);
        let mut q = QueryOptions::default();
        q.filters.push(f());
        q.order_by.push(o());
        assert_eq!(wstats::classify(&q), ListShape::FilterOrder);
        let mut q = QueryOptions::default();
        q.start_after = Some(serde_json::json!(1));
        q.order_by.push(o());
        assert_eq!(wstats::classify(&q), ListShape::Cursor);
    }

    /// TimedJson rejects exactly like axum's Json (415/400 pinned here;
    /// 422 flows from the same `from_bytes` both use).
    #[tokio::test]
    async fn timed_json_parity() {
        use axum::extract::FromRequest;
        async fn code(ct: Option<&str>, body: &'static str) -> StatusCode {
            let mut b = axum::http::Request::builder().uri("/x").method("PUT");
            if let Some(c) = ct {
                b = b.header("content-type", c);
            }
            let req = b.body(axum::body::Body::from(body)).unwrap();
            match TimedJson::<serde_json::Value>::from_request(req, &()).await {
                Ok(_) => StatusCode::OK,
                Err(e) => axum::response::IntoResponse::into_response(e).status(),
            }
        }
        assert_eq!(code(Some("application/json"), "{\"a\":1}").await, StatusCode::OK);
        assert_eq!(
            code(Some("application/cloudevents+json"), "{\"a\":1}").await,
            StatusCode::OK
        );
        assert_eq!(
            code(Some("text/json"), "{\"a\":1}").await,
            StatusCode::UNSUPPORTED_MEDIA_TYPE
        );
        assert_eq!(code(None, "{\"a\":1}").await, StatusCode::UNSUPPORTED_MEDIA_TYPE);
        assert_eq!(code(Some("application/json"), "{nope").await, StatusCode::BAD_REQUEST);
    }

    /// Field conditionals end to end (no extra reads): PUT evaluates the
    /// incoming body, PATCH the merged doc; violations deny.
    #[tokio::test]
    async fn fields_gate_write_paths() {
        let (st, db) = rbw_state(
            "[collections.docs]\nread = \"public\"\ncreate = \"fields:unit=auth.unit,score=int:0..100\"\nupdate = \"fields:unit=auth.unit,score=int:0..100\"\n",
            "fields",
        )
        .await;
        let staff = || {
            Some(AuthContext {
                uid: "local:s".into(),
                extra: [("unit".to_string(), serde_json::json!("ops"))].into_iter().collect(),
            })
        };
        // PUT-create with matching fields: allowed.
        ok_put(
            write_doc(st.clone(), staff(), "docs/d1".into(),
                serde_json::json!({"unit": "ops", "score": 10}), false, false, "default").await,
        );
        // PUT-create with wrong unit: denied.
        let r = write_doc(st.clone(), staff(), "docs/d2".into(),
            serde_json::json!({"unit": "hr", "score": 10}), false, false, "default").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(db.get("docs", "d2").await.unwrap().is_none());
        // PATCH merged eval: patch only score, unit comes from the base.
        let r = write_doc(st.clone(), staff(), "docs/d1".into(),
            serde_json::json!({"score": 99}), true, false, "default").await;
        assert_eq!(r.status(), StatusCode::OK);
        // PATCH breaking the range: denied, stored doc untouched.
        let r = write_doc(st.clone(), staff(), "docs/d1".into(),
            serde_json::json!({"score": 101}), true, false, "default").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let d1 = db.get("docs", "d1").await.unwrap().unwrap();
        assert_eq!(d1.data.get("score").and_then(|v| v.as_i64()), Some(99));
        // Anonymous: auth.* unresolvable → denied.
        let r = write_doc(st.clone(), None, "docs/d3".into(),
            serde_json::json!({"unit": "ops", "score": 1}), false, false, "default").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    /// Raw fragments splice verbatim; all-small takes the Json fast path.
    #[tokio::test]
    async fn render_results_splices_raw() {
        let doc = Doc {
            id: "a".into(),
            data: [("v".to_string(), serde_json::json!(1))].into_iter().collect(),
        };
        let raw = serde_json::to_string(&doc).unwrap();
        let resp = render_results(vec![
            OpOut::Raw(raw),
            OpOut::V(serde_json::json!({ "success": true })),
        ]);
        assert_eq!(resp.headers()["content-type"], "application/json");
        let body = axum::body::to_bytes(resp.into_body(), 65536).await.unwrap();
        let v: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(v["success"], serde_json::json!(true));
        assert_eq!(v["results"][0]["v"], serde_json::json!(1));
        assert_eq!(v["results"][0]["id"], serde_json::json!("a"));
        assert_eq!(v["results"][1]["success"], serde_json::json!(true));
        let resp2 = render_results(vec![OpOut::V(serde_json::json!({ "success": true }))]);
        let b2 = axum::body::to_bytes(resp2.into_body(), 65536).await.unwrap();
        let v2: serde_json::Value = serde_json::from_slice(&b2).unwrap();
        assert_eq!(v2["results"][0]["success"], serde_json::json!(true));
    }

    /// Policy-level read-before-write skip (perf opt-in): public PUT skips
    /// the old-doc lookup (overwrite resets createdAt — documented tradeoff);
    /// Owner-governed writes ignore the flag (a stranger stays 403). The
    /// `X-Hako-Skip-RBW` header does the same per request; also Owner-bound.
    #[tokio::test]
    async fn put_skip_read_before_write() {
        let (st, db) = rbw_state(
            "[defaults]\nread = \"public\"\nwrite = \"public\"\n[performance]\nskip_read_before_write = true\n",
            "skip",
        )
        .await;
        ok_put(
            write_doc(
                st.clone(),
                None,
                "w/d1".into(),
                serde_json::json!({"v": 1, "createdAt": "orig"}),
                false,
                false,
                "default",
            )
            .await,
        );
        ok_put(write_doc(st, None, "w/d1".into(), serde_json::json!({"v": 2}), false, false, "default").await);
        let d = db.get("w", "d1").await.unwrap().unwrap();
        assert_eq!(d.data.get("v"), Some(&serde_json::json!(2)));
        // Skip = stamp_new on overwrite: no old doc to preserve createdAt from.
        assert_ne!(d.data.get("createdAt").and_then(|v| v.as_str()), Some("orig"));

        // Control: flag off → createdAt preserved on overwrite.
        let (st2, db2) = rbw_state("[defaults]\nread = \"public\"\nwrite = \"public\"\n", "keep").await;
        ok_put(
            write_doc(
                st2.clone(),
                None,
                "w/d1".into(),
                serde_json::json!({"v": 1, "createdAt": "orig"}),
                false,
                false,
                "default",
            )
            .await,
        );
        ok_put(write_doc(st2, None, "w/d1".into(), serde_json::json!({"v": 2}), false, false, "default").await);
        let d2 = db2.get("w", "d1").await.unwrap().unwrap();
        assert_eq!(d2.data.get("createdAt").and_then(|v| v.as_str()), Some("orig"));

        // Header hint without the policy flag: same skip, per request.
        let (st4, db4) = rbw_state("[defaults]\nread = \"public\"\nwrite = \"public\"\n", "hint").await;
        assert!(!st4.policy.get().await.performance.skip_read_before_write);
        ok_put(
            write_doc(
                st4.clone(),
                None,
                "w/d1".into(),
                serde_json::json!({"v": 1, "createdAt": "orig"}),
                false,
                true,
                "default",
            )
            .await,
        );
        ok_put(write_doc(st4, None, "w/d1".into(), serde_json::json!({"v": 2}), false, true, "default").await);
        let d4 = db4.get("w", "d1").await.unwrap().unwrap();
        assert_ne!(d4.data.get("createdAt").and_then(|v| v.as_str()), Some("orig"));
        // Header parsing itself: 1/true yes, everything else no.
        let mut h = HeaderMap::new();
        assert!(!skip_hint(&h));
        h.insert("x-hako-skip-rbw", "1".parse().unwrap());
        assert!(skip_hint(&h));
        h.insert("x-hako-skip-rbw", "true".parse().unwrap());
        assert!(skip_hint(&h));
        h.insert("x-hako-skip-rbw", "0".parse().unwrap());
        assert!(!skip_hint(&h));

        // Auth-only policy + flag: stranger (anonymous) stays 403.
        let (st3, db3) = rbw_state(
            "[defaults]\nread = \"public\"\nwrite = \"auth\"\n[performance]\nskip_read_before_write = true\n",
            "owner",
        )
        .await;
        db3
            .set(
                "w",
                "d9",
                Doc {
                    id: "d9".into(),
                    data: [("ownerId".to_string(), serde_json::json!("u1"))]
                        .into_iter()
                        .collect(),
                },
                false,
            )
            .await
            .unwrap();
        let stranger: Option<hakobackend_core::AuthContext> = None;
        let r = write_doc(st3.clone(), stranger.clone(), "w/d9".into(), serde_json::json!({"v": 2}), false, false, "default").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        // Header hint under Owner: also ignored, still 403.
        let r = write_doc(st3, stranger, "w/d9".into(), serde_json::json!({"v": 2}), false, true, "default").await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
    }

    fn merge_op(t: &str, id: &str, data: serde_json::Value) -> BatchOpBody {
        BatchOpBody {
            op_type: t.into(),
            collection: "m".into(),
            id: Some(id.into()),
            data: Some(data),
            options: Some(BatchOpOptions { merge: true }),
        }
    }

    /// merge=true evaluation, locked: `set`+merge creates when missing and
    /// merges when present; plain `set` replaces; `update`/`add` keep
    /// their must-exist/upsert shapes; tx unknown types map by existence.
    #[tokio::test]
    async fn merge_semantics_sqlite() {
        use hakobackend_db_sqlite::SqliteDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_merge_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db: Arc<dyn Database> =
            Arc::new(SqliteDb::open(dir.join("t.db").to_string_lossy().as_ref()).await.unwrap());
        let policy = Arc::new(PolicyFile::open());

        // set+merge on a missing doc creates (Firestore parity).
        run_ops(&db, &policy, None, vec![merge_op("set", "a", serde_json::json!({"x": 1}))], false, "default")
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("x"), Some(&serde_json::json!(1)));

        // set+merge on a present doc merges (old keys survive).
        run_ops(&db, &policy, None, vec![merge_op("set", "a", serde_json::json!({"y": 2}))], false, "default")
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("x"), Some(&serde_json::json!(1)));
        assert_eq!(a.data.get("y"), Some(&serde_json::json!(2)));

        // Plain set on a present doc replaces (old keys gone).
        run_ops(&db, &policy, None, vec![batch_op("set", "m", "a", serde_json::json!({"z": 3}))], false, "default")
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("z"), Some(&serde_json::json!(3)));
        assert!(!a.data.contains_key("x"));

        // update on a missing doc aborts the whole batch.
        let bad = run_ops(&db, &policy, None, vec![batch_op("update", "m", "ghost", serde_json::json!({"q": 1}))], false, "default").await;
        assert!(bad.is_err());
        assert!(db.get("m", "ghost").await.unwrap().is_none());

        // add upserts: merge over present, create when missing.
        run_ops(&db, &policy, None, vec![batch_op("add", "m", "a", serde_json::json!({"w": 9}))], false, "default")
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("z"), Some(&serde_json::json!(3)));
        assert_eq!(a.data.get("w"), Some(&serde_json::json!(9)));

        // Transaction unknown types map by existence (merge when present).
        run_ops(&db, &policy, None, vec![batch_op("frobnicate", "m", "a", serde_json::json!({"u": 7}))], true, "default")
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("u"), Some(&serde_json::json!(7)));
        assert_eq!(a.data.get("w"), Some(&serde_json::json!(9)));
        let _ = std::fs::remove_dir_all(&dir);
    }

}

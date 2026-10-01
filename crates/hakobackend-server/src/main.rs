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

use axum::{
    Json, Router,
    extract::{Extension, Path, Query, State},
    http::{HeaderMap, StatusCode, header},
    middleware::{self, Next},
    response::{IntoResponse, Redirect, Response, sse},
    routing::{get, post},
};
use axum::extract::{ConnectInfo, Request, ws};
// Unix-listener plumbing only (no tokio UDS on Windows; the flag
// fail-closes there instead).
#[cfg(unix)]
use axum::extract::connect_info::Connected;
#[cfg(unix)]
use axum::serve::{IncomingStream, Listener};
use clap::Parser;
use config::{Args, DEFAULT_CONFIG_TEMPLATE, resolve, validate};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use hakobackend_auth_core::{AuthChain, AuthSpec, CustomAuth, open_chain};
use hakobackend_auth_github::GithubOAuth;
use hakobackend_auth_local::{ACCESS_COOKIE, DpopMode, DpopRequest, LocalAuth, REFRESH_COOKIE};
use hakobackend_core::{AuthContext, AuthProvider, Change, ChangeKind, Database, Doc, Method, PathKind, QueryOptions, parse_collection_path};
use hakobackend_db_hako::HakoDb;
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
    pub async fn policy(&self) -> Arc<PolicyFile> {
        self.policy.get().await
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
                        *w = (current, Arc::new(f));
                    }
                    Err(e) => eprintln!("[ub] policy reload FAILED ({e}); keeping old policy"),
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
) -> Result<Arc<dyn Database>, String> {
    use hakobackend_core::ttl::TtlDb;
    // Every driver is wrapped once: TTL expiry filters uniformly, and the
    // sweeper below owns the wrapped handle (reload swaps it too).
    let db: Arc<dyn Database> = match driver {
        "hako" => {
            // ponytail: socket_sync lives ONLY in the hako arm (sync is
            // per hako driver — other drivers fail closed below). A
            // hakocluster driver comes later; it does not belong here.
            let hako = HakoDb::open(path).map_err(|e| e.to_string())?;
            hako
                .enable_socket_sync(sync_serve, sync_peer)
                .await
                .map_err(|e| e.to_string())?;
            Arc::new(TtlDb::new(hako)) as Arc<dyn Database>
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
    // swapped-out handle and exits with the process).
    hakobackend_core::ttl::spawn_sweeper(db.clone(), std::time::Duration::from_secs(300), 100);
    Ok(db)
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
    let db: Arc<dyn Database> = open_driver(&cfg.driver, &cfg.data, cfg.sync_serve.clone(), cfg.sync_peer.clone()).await.expect("open database");
    println!("[ub] driver={} data={} config={}", cfg.driver, cfg.data, if cfg.source.is_empty() { "(default+flag)" } else { &cfg.source });
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
    let (chain, local, github) = open_auth(cfg.auth.as_deref(), db.clone(), policy.identity_snapshot());
    auto_provision(&db, &policy.get().await, &cfg.indexes).await;

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
    let state = AppState {
        db: db_handle.clone(),
        policy,
        auth: Arc::new(tokio::sync::RwLock::new(Arc::new(chain))),
        local: Arc::new(tokio::sync::RwLock::new(local)),        github: Arc::new(tokio::sync::RwLock::new(github)),
        limits: limits.clone(),
        tls,
        admin_uids: Arc::new(cfg.admin_uids.clone()),
        cli: Arc::new(cli),
        coalescer: Arc::new(coalesce::Coalescer::default()),
        coalesce_on: cfg.coalesce_writes,
        service: Arc::new(tokio::sync::RwLock::new(ServiceAuth::build(&cfg.service_keys, &cfg.service_allow))),
    };
    if cfg.coalesce_writes {
        state.coalescer.spawn_flusher(state.db.clone());
    }

    // Layered flood protection (before any expensive work):
    // /health open (LB probes), /api/auth/* strict, rest loose global.
    let global = LimitScope { limiter: limits.global.clone(), trust_proxy: limits.trust_proxy };
    let strict = LimitScope { limiter: limits.auth.clone(), trust_proxy: limits.trust_proxy };
    let api = Router::new()
        .route("/api/collections", get(list_collections).post(create_collection))
        .route(
            "/api/collections/{*path}",
            get(get_or_list).post(create).put(put).patch(patch).delete(remove),
        )
        .route("/api/indexes", post(index_create).get(index_list).delete(index_drop))
        .route("/api/batch", post(batch))
        .route("/api/transaction", post(transaction))
        .route("/api/collectionGroup/{name}", get(collection_group))
        .route("/api/aggregate/{*path}", post(aggregate))
        .route("/api/admin/reload", post(reload))
        .route("/ws", get(ws_handler))
        .route("/api/stream/{*path}", get(sse_handler))
        .layer(middleware::from_fn_with_state(global, limit_mw));
    let auth_routes = Router::new()
        .route("/api/auth/register", post(auth_register))
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/refresh", post(auth_refresh))
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/auth/me", get(auth_me))
        .route("/api/auth/github/login", get(github_login))
        .route("/api/auth/github/callback", get(github_callback))
        .layer(middleware::from_fn_with_state(strict.clone(), limit_mw));

    // ponytail: health/ready merge AFTER auth_mw — both are open by
    // policy and neither reads the auth context (health is static JSON,
    // ready takes State only). Skips hint parsing, cookie/token reads,
    // DPoP checks and 2-3 String allocs per probe. wstats stays under
    // auth (operational surface, unchanged behavior).
    let open = Router::new()
        .route("/api/health", get(health))
        .route("/api/ready", get(ready));
    // ponytail: host gate wraps api + auth only (health/ready in `open`
    // stay ungated). host_mw is outermost (added last): off-domain
    // traffic dies before CORS/limit/auth do any work. Legit preflights
    // pass the gate, then cors_mw attaches headers / short-circuits 204.
    let hosts = Arc::new(cfg.allowed_hosts.clone());
    let gated = Router::new()
        .merge(api)
        .merge(auth_routes)
        .layer(middleware::from_fn(cors_mw))
        .layer(middleware::from_fn_with_state(hosts, host_mw));
    let mut app = Router::new()
        .route("/api/__wstats", get(wstats_dump))
        .merge(gated)
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .merge(open)
        // gzip JSON responses, but never the live streams: compressing
        // SSE would buffer flushes and add event latency for little gain
        // (stream frames are already tiny; WS upgrades carry no body).
        // SizeAbove(1024): gzip below ~1 KB costs more than it saves
        // (measured 13-33% overhead on small docs when clients compress).
        .layer(
            tower_http::compression::CompressionLayer::new().compress_when(
                tower_http::compression::predicate::SizeAbove::new(1024).and(
                    tower_http::compression::predicate::NotForContentType::new("text/event-stream"),
                ),
            ),
        )
        // 8 MB bodies (legacy json-limit parity); larger payloads 413.
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        // Outermost: total-latency clock + sample flag (front_mw runs first).
        .layer(middleware::from_fn(front_mw))
        .with_state(state);
    if tls {
        // HSTS only meaningful via TLS (no effect on plain http).
        app = app.layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));
    }

    // Hostnames resolve here (IPs bind as-is): generic listen like any
    // other service — `host` accepts "0.0.0.0", "127.0.0.1",
    // "api.chemedu.site", ...; DNS failure fails boot, loudly.
    // Multi-bind: comma-separated hosts (IPs or DNS names), one listener
    // per resolved address. Fail-closed before serving anything.
    let bind_ips = resolve_bind_ips(&cfg.host)
        .await
        .map_err(|e| format!("[ub] {e}"))?;
    let mut listeners = Vec::with_capacity(bind_ips.len());
    for ip in &bind_ips {
        let a: std::net::SocketAddr = format!("{ip}:{}", cfg.port)
            .parse()
            .map_err(|e| format!("[ub] invalid listen address: {e}"))?;
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
async fn auto_provision(db: &Arc<dyn Database>, policy: &Arc<PolicyFile>, indexes: &[config::IndexDecl]) {
    for collection in policy.collections.keys() {
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
async fn resolve_token(s: &AppState, token: &str) -> Option<AuthContext> {
    let policy = s.policy.get().await;
    let db = s.db.read().await.clone();
    let chain = s.auth.read().await.clone();
    let db_ref: &dyn Database = &*db;
    chain.resolve(&policy.identity, Some(db_ref), token).await
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
    let Some(local) = s.local.read().await.clone() else { return ctx };
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
fn cors_headers(origin: Option<&str>) -> Option<HeaderMap> {
    let o = origin?;
    if !(o.starts_with("http://") || o.starts_with("https://")) {
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

async fn cors_mw(req: Request, next: Next) -> Response {
    let headers = cors_headers(
        req.headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok()),
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
        let svc = s.service.read().await.clone();
        if !svc.hashes.is_empty() && loopback_peer(&req) && svc_key_match(&svc.hashes, t) {
            req.extensions_mut().insert(Some(svc_context(&svc.scopes)));
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
    if from_cookie.is_some() && ctx.is_some() && matches!(req.method(), &axum::http::Method::POST | &axum::http::Method::PUT | &axum::http::Method::PATCH | &axum::http::Method::DELETE) {
        let host = req.headers().get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("");
        let origin_ok = req
            .headers()
            .get(header::ORIGIN)
            .and_then(|v| v.to_str().ok())
            .map(|o| {
                let o = o.trim_start_matches("https://").trim_start_matches("http://");
                let o_host = o.split('/').next().unwrap_or("");
                o_host.eq_ignore_ascii_case(host)
            })
            .unwrap_or(true);
        if !origin_ok {
            ctx = None;
        }
    }
    req.extensions_mut().insert(ctx);
    if WSAMP.try_get().unwrap_or(false) {
        wstats::add(&wstats::F[1], ws_t0.elapsed().as_nanos() as u64);
    }
    next.run(req).await
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
        Some(err(StatusCode::FORBIDDEN, "internal collection"))
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

/// Readiness (LBs/K8s): the driver answers, not just the socket.
async fn ready(State(s): State<AppState>) -> impl IntoResponse {
    match s.db.read().await.list_collections().await {
        Ok(_) => Json(serde_json::json!({ "ready": true })).into_response(),
        Err(e) => err(StatusCode::SERVICE_UNAVAILABLE, e.to_string()),
    }
}

/// Re-read config + driver + auth chain. "Hot-swap while running":
/// edit the file, POST here (admin role), done — CLI flags still win.
/// Failure at any step = 400 and the old config is fully retained.
async fn reload(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>) -> impl IntoResponse {
    if !is_admin(auth.as_ref(), &s.admin_uids) {
        return forbidden();
    }
    let cfg = resolve(&s.cli);
    if let Some(p) = &cfg.public_url {
        if std::env::var("UB_PUBLIC_URL").is_err() {
            std::env::set_var("UB_PUBLIC_URL", p);
        }
    }
    let db: Arc<dyn Database> = match open_driver(&cfg.driver, &cfg.data, cfg.sync_serve.clone(), cfg.sync_peer.clone()).await {
        Ok(db) => db,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    let identity = s.policy.get().await.identity.clone();
    let (chain, local, github) = match open_auth_result(cfg.auth.as_deref(), db.clone(), identity) {
        Ok(v) => v,
        Err(e) => return err(StatusCode::BAD_REQUEST, e),
    };
    *s.db.write().await = db;
    *s.auth.write().await = Arc::new(chain);
    *s.local.write().await = local;
    *s.github.write().await = github;
    // Drain coalesced PATCHes into the fresh driver before serving it.
    {
        let dbh = s.db.read().await.clone();
        s.coalescer
            .flush_all(|coll, id, body| {
                let dbh = dbh.clone();
                async move {
                    let out = dbh.set(&coll, &id, Doc { id: id.clone(), data: body }, true).await;
                    // Bus parity with the live flusher (full doc, below).
                    if let Ok(doc) = dbh.get(&coll, &id).await {
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
    auto_provision(&s.db.read().await.clone(), &s.policy.get().await, &cfg.indexes).await;
    let msg = format!("reload ok: driver={} data={} auth={}", cfg.driver, cfg.data, cfg.auth.as_deref().unwrap_or("off"));
    eprintln!("[ub] {msg}");
    msg.into_response()
}

async fn list_collections(
    State(s): State<AppState>,
) -> impl IntoResponse {
    match s.db.read().await.list_collections().await {
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
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let name = match body.get("name").and_then(|v| v.as_str()) {
        Some(n) if !n.is_empty() => n.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "body requires {name}"),
    };
    if denied_internal(&name).is_some() {
        return err(StatusCode::FORBIDDEN, "internal collection");
    }
    let policy = s.policy().await;
    if !policy.allow(auth.as_ref(), &name, Method::Create, None) {
        return forbidden();
    }
    match s.db.read().await.ensure_collection(&stored(&name)).await {
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
    // GET-single: authz / eng_get / overlay / allow_ser
    pub static G: [T; 4] = [T::new(), T::new(), T::new(), T::new()];
    // LIST: authz / eng_list / filter / serdom
    pub static L: [T; 4] = [T::new(), T::new(), T::new(), T::new()];
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
            &["authz", "eng_get", "overlay", "allow_ser"],
            &[&G[0], &G[1], &G[2], &G[3]],
        ) + &tab(
            "list",
            &["authz", "eng_list", "filter", "serdom"],
            &[&L[0], &L[1], &L[2], &L[3]],
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
    static WSAMP: bool;
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

async fn get_or_list(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let samp = WSAMP.try_get().unwrap_or(false);
    let mut ws_t = std::time::Instant::now();
    let policy = s.policy().await;
    let db = s.db.read().await.clone();
    match parse_collection_path(&path) {
        PathKind::Document { collection, id } => {
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, Some(&id)) {
                return r;
            }
            let stored = stored(&collection);
            if samp {
                wstats::add(&wstats::G[0], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            match db.get(&stored, &id).await {
                Ok(maybe_doc) => {
                    // Coalescer overlay: pending PATCHes merge over storage
                    // so read-your-write holds inside the window.
                    if samp {
                        wstats::add(&wstats::G[1], ws_t.elapsed().as_nanos() as u64);
                        ws_t = std::time::Instant::now();
                    }
                    let overlaid = s.coalescer.overlay(
                        &stored,
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
                            // ponytail: serialize Doc straight to bytes; the old
                            // to_value() built a throwaway Value DOM first.
                            let r = Json(doc).into_response();
                            if samp {
                                wstats::add(&wstats::G[3], ws_t.elapsed().as_nanos() as u64);
                            }
                            r
                        }
                        None => err(StatusCode::NOT_FOUND, "Document not found"),
                    }
                }
                Err(_) => err_internal(),
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
            match parse_options(&q) {
                Err(msg) => err(StatusCode::BAD_REQUEST, msg),
                Ok(opts) => {
                    if samp {
                        wstats::add(&wstats::L[0], ws_t.elapsed().as_nanos() as u64);
                        ws_t = std::time::Instant::now();
                    }
                    let shape = wstats::classify(&opts) as usize;
                    match db.list(&stored, &opts).await {
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
                            .filter(|d| policy.allow(auth.as_ref(), &collection, Method::Get, Some(d)))
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
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let collection = match body.get("collection").and_then(|v| v.as_str()) {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return err(StatusCode::BAD_REQUEST, "collection required"),
    };
    index_create_inner(s, auth, collection, body).await
}

/// Legacy shim: body {name, fields} (+optional kind/unique), response {success:true}.
async fn index_create_legacy(
    s: AppState,
    auth: Option<AuthContext>,
    collection: String,
    body: serde_json::Value,
) -> Response {
    index_create_inner(s, auth, collection, body).await
}

async fn index_create_inner(
    s: AppState,
    auth: Option<AuthContext>,
    collection: String,
    body: serde_json::Value,
) -> Response {
    if denied_internal(&collection).is_some() {
        return err(StatusCode::FORBIDDEN, "internal collection");
    }
    if let Some(r) = valid_names(&collection, None) {
        return r;
    }
    let spec = match parse_index_spec(&body) {
        Ok(spec) => spec,
        Err(msg) => return err(StatusCode::BAD_REQUEST, msg),
    };
    let policy = s.policy().await;
    if !policy.allow(auth.as_ref(), &collection, Method::Update, None) {
        return forbidden();
    }
    let db = s.db.read().await.clone();
    let stored = stored(&collection);
    let _ = db.ensure_collection(&stored).await;
    match db.create_index(&stored, &spec).await {
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
        return err(StatusCode::FORBIDDEN, "internal collection");
    }
    if let Some(r) = valid_names(&collection, None) {
        return r;
    }
    let policy = s.policy().await;
    if !policy.allow(auth.as_ref(), &collection, Method::List, None) {
        return forbidden();
    }
    match s.db.read().await.list_indexes(&stored(&collection)).await {
        Ok(indexes) => Json(indexes).into_response(),
                Err(_) => err_internal(),
    }
}

async fn index_drop(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let (collection, name) = match (q.get("collection"), q.get("name")) {
        (Some(c), Some(n)) if !c.is_empty() && !n.is_empty() => (c.clone(), n.clone()),
        _ => return err(StatusCode::BAD_REQUEST, "query ?collection= & ?name= required"),
    };
    if denied_internal(&collection).is_some() {
        return err(StatusCode::FORBIDDEN, "internal collection");
    }
    let policy = s.policy().await;
    if !policy.allow(auth.as_ref(), &collection, Method::Update, None) {
        return forbidden();
    }
    match s.db.read().await.drop_index(&stored(&collection), &name).await {
        Ok(()) => ok_true(),
        Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
    }
}

async fn create(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    TimedJson(body): TimedJson<serde_json::Value>,
) -> impl IntoResponse {
    // Legacy compat shim: POST /api/collections/<coll>/index {name, fields}
    // (legacy backend, server.ts:193). New shape: POST /api/indexes.
    // Collections actually named "index" are accessed via the new shape.
    if let Some(collection) = legacy_index_collection(&path) {
        return index_create_legacy(s, auth, collection, body).await;
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
            let policy = s.policy().await;
            let incoming = incoming_doc("", body);
            if !policy.allow(auth.as_ref(), &collection, Method::Create, Some(&incoming)) {
                return forbidden();
            }
            let db = s.db.read().await.clone();
            let stored = stored(&collection);
            let _ = db.ensure_collection(&stored).await;
            // Atomics collapse (legacy parity) + createdAt/updatedAt stamping.
            let incoming = Doc {
                id: incoming.id,
                data: strip_write(
                    &policy,
                    &collection,
                    Method::Create,
                    hakobackend_core::atomics::stamp_new(
                        hakobackend_core::atomics::resolve_for_create(incoming.data),
                    ),
                ),
            };
            if !policy.allow_fields(auth.as_ref(), &collection, Method::Create, &incoming.data) {
                return forbidden();
            }
            match db.insert(&stored, incoming).await {
                Ok(doc) => {
                    // Gateway bus (instant lane; poller reconciles foreign writes).
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
    headers: HeaderMap,
    TimedJson(body): TimedJson<serde_json::Value>,
) -> impl IntoResponse {
    write_doc(s, auth, path, body, false, skip_hint(&headers)).await
}

async fn patch(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    headers: HeaderMap,
    TimedJson(body): TimedJson<serde_json::Value>,
) -> impl IntoResponse {
    // ponytail: merge=true uses the same path as PUT; no manual read-modify-write.
    write_doc(s, auth, path, body, true, skip_hint(&headers)).await
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
            let policy = s.policy().await;
            let db = s.db.read().await.clone();
            let stored = stored(&collection);
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
                && !policy.needs_existing(&collection, Method::Update)
                && (skip_hint || policy.skip_read_before_write(&collection, Method::Update));
            let existing = if skip_rbw {
                None
            } else {
                db.get(&stored, &id).await.ok().flatten()
            };
            if samp {
                wstats::add(&wstats::W[1], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            // Owner rule evaluated against the existing document (who owns this data?).
            if !policy.allow(auth.as_ref(), &collection, Method::Update, existing.as_ref()) {
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
                if policy.strip_fields(&collection, Method::Update).is_empty() {
                    if let Some(obj) = body.as_object() {
                        let map: HashMap<String, serde_json::Value> =
                            obj.clone().into_iter().collect();
                        if coalesce::Coalescer::eligible(&body)
                            && s.coalescer.merge(&stored, &id, map)
                        {
                            return ok_true();
                        }
                    }
                }
            }
            let _ = db.ensure_collection(&stored).await;
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
            let data = strip_write(&policy, &collection, Method::Update, data);
            // Field conditionals on the final data (incoming/merged — no read).
            if !policy.allow_fields(auth.as_ref(), &collection, Method::Update, &data) {
                return forbidden();
            }
            // Merge already applied above; store the final body as-is.
            if samp {
                wstats::add(&wstats::W[3], ws_t.elapsed().as_nanos() as u64);
                ws_t = std::time::Instant::now();
            }
            match db.set(&stored, &id, Doc { id: id.clone(), data }, false).await {
                Ok(doc) => {
                    // Gateway bus: instant lane for subscribers (the shared
                    // poller stays as reconciler for foreign writes).
                    // Wire shape unchanged ({success:true}).
                    if samp {
                        wstats::add(&wstats::W[4], ws_t.elapsed().as_nanos() as u64);
                        ws_t = std::time::Instant::now();
                    }
                    realtime::emit(
                        &stored,
                        Change {
                            collection: stored.clone(),
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
) -> impl IntoResponse {
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
            let policy = s.policy().await;
            let db = s.db.read().await.clone();
            let stored = stored(&collection);
            let existing = db.get(&stored, &id).await.ok().flatten();
            if !policy.allow(auth.as_ref(), &collection, Method::Delete, existing.as_ref()) {
                return forbidden();
            }
            let _ = db.ensure_collection(&stored).await;
            match db.delete(&stored, &id).await {
                Ok(_) => {
                    // Gateway bus (subscriber snapshot supplies the old doc).
                    realtime::emit(
                        &stored,
                        Change {
                            collection: stored.clone(),
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
) -> Result<Vec<OpOut>, (StatusCode, String, &'static str)> {
    use hakobackend_core::{TxOp, TxOpKind};
    // Phase 1: resolve + gate each op (reads tolerate missing tables).
    // Unknown op types are rejected outright (fail-closed: an unknown type
    // must never silently become a write, e.g. dodging an Update-deny via
    // the legacy create-fallback).
    const KNOWN: &[&str] = &["get", "set", "add", "update", "delete", "create"];
    if ops.len() > realtime::MAX_BATCH_OPS {
        return Err((
            StatusCode::BAD_REQUEST,
            format!("too many ops (max {})", realtime::MAX_BATCH_OPS),
            "bad-request",
        ));
    }
    struct Gated {
        body: BatchOpBody,
        id: String,
        existed: bool,
        existing: Option<Doc>,
        stored: String,
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
            return Err((StatusCode::FORBIDDEN, "internal collection".to_string(), "permission-denied"));
        }
        if !hakobackend_core::valid_collection_path(&op.collection) {
            return Err((StatusCode::BAD_REQUEST, "invalid collection name".to_string(), "bad-request"));
        }
        if !hakobackend_core::valid_doc_id(&id) {
            return Err((StatusCode::BAD_REQUEST, "invalid document id".to_string(), "bad-request"));
        }
        let stored = stored(&op.collection);
        let existing = db.get(&stored, &id).await.ok().flatten();
        let existed = existing.is_some();
        let method = op_method(&t, existed, is_tx);
        if !policy.allow(auth, &op.collection, method, existing.as_ref()) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Permission denied: {method:?} on {}/{}", op.collection, id),
                "permission-denied",
            ));
        }
        let _ = db.ensure_collection(&stored).await;
        gated.push(Gated { body: op, id, existed, existing, stored, method });
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
                strip_write(&policy, &g.body.collection, g.method, data)
            };
            // Field conditionals on final data (no read); fail-closed 403.
            if t != "get" && t != "delete"
                && !policy.allow_fields(auth, &g.body.collection, g.method, &data)
            {
                return Err((
                    StatusCode::FORBIDDEN,
                    format!("Permission denied: fields on {}/{}", g.body.collection, g.id),
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
                    &g.stored,
                    Change {
                        collection: g.stored.clone(),
                        id: g.id.clone(),
                        kind: ChangeKind::Remove,
                        old: None,
                        new: None,
                    },
                );
            }
            TxOpKind::Put { .. } => {
                realtime::emit(
                    &g.stored,
                    Change {
                        collection: g.stored.clone(),
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
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Legacy quirk preserved: batch failures are always 500, no code.
    let ops: Vec<BatchOpBody> = match serde_json::from_value(body.get("operations").cloned().unwrap_or_default()) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "body requires {operations[]}"),
    };
    let db = s.db.read().await.clone();
    let policy = s.policy().await;
    match run_ops(&db, &policy, auth.as_ref(), ops, false).await {
        Ok(results) => render_results(results),
        Err((StatusCode::INTERNAL_SERVER_ERROR, msg, _)) => err(StatusCode::INTERNAL_SERVER_ERROR, msg),
        Err((_, msg, _)) => err(StatusCode::INTERNAL_SERVER_ERROR, msg),
    }
}

async fn transaction(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let ops: Vec<BatchOpBody> = match serde_json::from_value(body.get("operations").cloned().unwrap_or_default()) {
        Ok(v) => v,
        Err(_) => return err(StatusCode::BAD_REQUEST, "body requires {operations[]}"),
    };
    let db = s.db.read().await.clone();
    let policy = s.policy().await;
    match run_ops(&db, &policy, auth.as_ref(), ops, true).await {
        Ok(results) => render_results(results),
        Err((status, msg, code)) => err_code(status, msg, code),
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
    let policy = s.policy().await;
    let db = s.db.read().await.clone();
    let collections = match db.list_collections().await {
        Ok(c) => c,
        Err(_) => return err_internal(),
    };
    let mut out = Vec::new();
    for stored in collections {
        let logical = stored.clone();
        if !realtime::matches_group(&logical, &name) {
            continue;
        }
        if !policy.allow(auth.as_ref(), &logical, Method::List, None) {
            continue;
        }
        let docs = match db.list(&stored, &opts).await {
            Ok(d) => d,
            Err(_) => continue,
        };
        for doc in docs {
            let doc_coll = doc
                .data
                .get("_collectionPath")
                .and_then(|v| v.as_str())
                .unwrap_or(&logical);
            if policy.allow(auth.as_ref(), doc_coll, Method::Get, Some(&doc)) {
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
    Json(body): Json<AggBody>,
) -> impl IntoResponse {
    let collection = path.trim_matches('/').to_string();
    if collection.is_empty() {
        return err(StatusCode::BAD_REQUEST, "aggregate needs a collection path");
    }
    if denied_internal(&collection).is_some() {
        return err(StatusCode::FORBIDDEN, "internal collection");
    }
    if let Some(r) = valid_names(&collection, None) {
        return r;
    }
    let policy = s.policy().await;
    if !policy.allow(auth.as_ref(), &collection, Method::List, None) {
        return forbidden();
    }
    let db = s.db.read().await.clone();
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
            "count" => match db.count(&stored, &opts).await {
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
                match db.count(&stored, &opts).await {
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
                    db.sum(&stored, field, &opts).await
                } else {
                    db.avg(&stored, field, &opts).await
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

fn session_cookies(local: &LocalAuth, tokens: &hakobackend_auth_local::SessionTokens) -> HeaderMap {
    let mut h = HeaderMap::new();
    let pair = [
        (ACCESS_COOKIE, &tokens.access_jwt, local.access_ttl()),
        (REFRESH_COOKIE, &tokens.refresh_opaque, local.refresh_ttl()),
    ];
    for (name, value, age) in pair {
        // __Host-: Secure + Path=/ + no Domain (required; localhost counts as secure context).
        let v = format!("{name}={value}; Path=/; Max-Age={age}; Secure; HttpOnly; SameSite=Strict");
        h.append(header::SET_COOKIE, v.parse().unwrap());
    }
    h
}

fn clear_cookies() -> HeaderMap {
    let mut h = HeaderMap::new();
    for name in [ACCESS_COOKIE, REFRESH_COOKIE] {
        let v = format!("{name}=; Path=/; Max-Age=0; Secure; HttpOnly; SameSite=Strict");
        h.append(header::SET_COOKIE, v.parse().unwrap());
    }
    h
}

async fn local_or_400(s: &AppState) -> Result<Arc<LocalAuth>, Response> {
    s.local.read().await.clone().ok_or_else(|| {
        (StatusCode::BAD_REQUEST, "local auth is not active (see --auth)").into_response()
    })
}

fn str_field(body: &HashMap<String, serde_json::Value>, keys: &[&str]) -> Option<String> {
    keys.iter().find_map(|k| body.get(*k)).and_then(|v| v.as_str()).map(|s| s.to_string())
}

async fn issuance_local(s: &AppState) -> Result<Arc<LocalAuth>, Response> {
    local_or_400(s).await
}

async fn auth_register(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
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
    match local.register(id, email, &password, body).await {
        Ok(doc) => {
            // Gateway bus: user creates are CRUD events too.
            let users = s.policy.get().await.identity.users_collection.clone();
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
        Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
    }
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
            let (proof, uri) = issuance_parts(&s, &headers, "/api/auth/login");
            let dpop = proof.as_deref().map(|proof| DpopRequest { proof, method: "POST", uri: &uri });
            match local.login(&l, &p, dpop).await {
                Ok((ctx, tokens)) => {
                    let headers = session_cookies(&local, &tokens);
                    (StatusCode::OK, headers, Json(serde_json::json!({ "uid": ctx.uid }))).into_response()
                }
                // Obfuscate: wrong login vs password vs dpop are not distinguished (anti-enumeration).
                Err(_) => err(StatusCode::UNAUTHORIZED, "invalid credentials"),
            }
        }
        _ => err(StatusCode::BAD_REQUEST, "login + password required"),
    }
}

async fn auth_refresh(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    let local = match issuance_local(&s).await {
        Ok(l) => l,
        Err(e) => return e,
    };
    let presented = match read_cookie(&headers, REFRESH_COOKIE) {
        Some(t) => t,
        None => return unauthorized(),
    };
    let (proof, uri) = issuance_parts(&s, &headers, "/api/auth/refresh");
    let dpop = proof.as_deref().map(|proof| DpopRequest { proof, method: "POST", uri: &uri });
    match local.refresh(&presented, dpop).await {
        Ok((ctx, tokens)) => {
            let h = session_cookies(&local, &tokens);
            (StatusCode::OK, h, Json(serde_json::json!({ "uid": ctx.uid }))).into_response()
        }
        // Reuse/expired/foreign: clear cookies + reject (fail-closed).
        Err(_) => (StatusCode::UNAUTHORIZED, clear_cookies(), Json(serde_json::json!({ "error": "invalid session" }))).into_response(),
    }
}

async fn auth_logout(
    State(s): State<AppState>,
    headers: HeaderMap,
) -> impl IntoResponse {
    // Best-effort revoke; clearing cookies is the real logout.
    if let Some(t) = read_cookie(&headers, REFRESH_COOKIE) {
        if let Some(local) = s.local.read().await.clone() {
            let _ = local.logout(&t).await;
        }
    }
    (StatusCode::OK, clear_cookies(), Json(serde_json::json!({ "success": true }))).into_response()
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

/// Inbound WS message size limit (anti frame-flood).
const WS_MAX_MSG: usize = 1024 * 1024;

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
                    if t.len() > WS_MAX_MSG {
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
                    if let Some(local) = s.local.read().await.clone() {
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
                    if subs.len() >= realtime::MAX_SUBS_PER_SOCKET && !subs.contains_key(&key) {
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
                    };
                    // Per-subscribe token (legacy authData pattern) overrides connection auth.
                    // Same DPoP rule as the `auth` message: no proof possible here.
                    let mut sub_auth = match v.get("token").and_then(|t| t.as_str()) {
                        Some(t) => resolve_token(&s, t).await,
                        None => auth.clone(),
                    };
                    if v.get("token").is_some() {
                        if let Some(local) = s.local.read().await.clone() {
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
                    let db = s.db.read().await.clone();
                    let policy = s.policy().await;
                    match realtime::subscribe(db, policy, sub_auth, spec).await {
                        Ok(sub) => {
                            // Per-connection snapshot budget (anti memory-bomb).
                            let total: usize =
                                subs.values().map(|s| s.snapshot_docs).sum::<usize>() + sub.snapshot_docs;
                            if total > realtime::MAX_CONN_SNAPSHOT_DOCS {
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
    let db = s.db.read().await.clone();
    let policy = s.policy().await;
    let sub = match realtime::subscribe(db, policy, auth, realtime::SubSpec { collection, options, group }).await {
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
    let (g, local) = match (s.github.read().await.clone(), s.local.read().await.clone()) {
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
            let mut h = session_cookies(&local, &tokens);
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
        assert!(host_allowed(&[], Some("api.chemedu.site")));
        assert!(host_allowed(&[], None));
        let allowed = vec!["api.chemedu.site".to_string()];
        // Exact, case-insensitive, port-stripped.
        assert!(host_allowed(&allowed, Some("api.chemedu.site")));
        assert!(host_allowed(&allowed, Some("API.CHEMEDU.SITE")));
        assert!(host_allowed(&allowed, Some("api.chemedu.site:3010")));
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
            .uri("https://api.chemedu.site:3005/api/ready")
            .body(axum::body::Body::empty())
            .unwrap();
        assert_eq!(request_host(&req), Some("api.chemedu.site:3005"));
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
        let pub4: IpAddr = "203.24.51.237".parse().unwrap();
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
        let h = cors_headers(Some("https://app.chemedu.site")).unwrap();
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_ORIGIN).unwrap(),
            "https://app.chemedu.site"
        );
        assert_eq!(
            h.get(header::ACCESS_CONTROL_ALLOW_CREDENTIALS).unwrap(),
            "true"
        );
        assert!(h.contains_key(header::VARY));
        assert!(cors_headers(Some("http://localhost:3000")).is_some());
        // Non-http, null, missing = no CORS headers.
        assert!(cors_headers(Some("ftp://x")).is_none());
        assert!(cors_headers(Some("null")).is_none());
        assert!(cors_headers(None).is_none());
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
            vec![batch_op("delete", "posts", "p1", serde_json::json!({}))], false).await.is_err());
        // Maintainer (array member): allowed.
        run_ops(&db, &policy, boss().as_ref(),
            vec![batch_op("delete", "posts", "p1", serde_json::json!({}))], false).await.unwrap();
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
        )
        .await
        .unwrap();
        let res = vals(res);
        assert_eq!(res.len(), 4);
        assert!(res.iter().all(|r| r.get("success") == Some(&serde_json::json!(true))));
        assert_eq!(res[0].get("id"), Some(&serde_json::json!("a")));
        // Unknown op types are rejected, never silently created.
        let bad_type = run_ops(&db, &policy, None, vec![batch_op("bogus", "w", "z", d(0))], false).await;
        assert!(bad_type.is_err());

        // must_exist failure aborts the whole batch (d is untouched).
        let bad = run_ops(
            &db,
            &policy,
            None,
            vec![batch_op("set", "w", "d", d(4)), batch_op("update", "w", "ghost", d(5))],
            false,
        )
        .await;
        assert!(bad.is_err());
        assert!(db.get("w", "d").await.unwrap().is_none());

        // Transaction shapes: get → doc, writes → {success}.
        let res = vals(
            run_ops(&db, &policy, None, vec![batch_op("get", "w", "a", d(0))], true)
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
        let dbh = Arc::new(tokio::sync::RwLock::new(raw.clone()));
        let st = AppState {
            db: dbh.clone(),
            policy: Arc::new(PolicyHot::new(Some(pol.to_string_lossy().into_owned()))),
            auth: Arc::new(tokio::sync::RwLock::new(Arc::new(
                open_chain(&AuthSpec::Off, None, None).expect("off chain builds"),
            ))),
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
                wstats: false, benchmark: false, sock: None, http2: false,
                sync_serve: None, sync_peer: vec![], allowed_hosts: vec![],
            }),
            coalescer: Arc::new(coalesce::Coalescer::default()),
            coalesce_on: false,
            service: Arc::new(tokio::sync::RwLock::new(ServiceAuth::build(&[], &[]))),
        };
        (st, raw)
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
                serde_json::json!({"unit": "ops", "score": 10}), false, false).await,
        );
        // PUT-create with wrong unit: denied.
        let r = write_doc(st.clone(), staff(), "docs/d2".into(),
            serde_json::json!({"unit": "hr", "score": 10}), false, false).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        assert!(db.get("docs", "d2").await.unwrap().is_none());
        // PATCH merged eval: patch only score, unit comes from the base.
        let r = write_doc(st.clone(), staff(), "docs/d1".into(),
            serde_json::json!({"score": 99}), true, false).await;
        assert_eq!(r.status(), StatusCode::OK);
        // PATCH breaking the range: denied, stored doc untouched.
        let r = write_doc(st.clone(), staff(), "docs/d1".into(),
            serde_json::json!({"score": 101}), true, false).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        let d1 = db.get("docs", "d1").await.unwrap().unwrap();
        assert_eq!(d1.data.get("score").and_then(|v| v.as_i64()), Some(99));
        // Anonymous: auth.* unresolvable → denied.
        let r = write_doc(st.clone(), None, "docs/d3".into(),
            serde_json::json!({"unit": "ops", "score": 1}), false, false).await;
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
            )
            .await,
        );
        ok_put(write_doc(st, None, "w/d1".into(), serde_json::json!({"v": 2}), false, false).await);
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
            )
            .await,
        );
        ok_put(write_doc(st2, None, "w/d1".into(), serde_json::json!({"v": 2}), false, false).await);
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
            )
            .await,
        );
        ok_put(write_doc(st4, None, "w/d1".into(), serde_json::json!({"v": 2}), false, true).await);
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
        let r = write_doc(st3.clone(), stranger.clone(), "w/d9".into(), serde_json::json!({"v": 2}), false, false).await;
        assert_eq!(r.status(), StatusCode::FORBIDDEN);
        // Header hint under Owner: also ignored, still 403.
        let r = write_doc(st3, stranger, "w/d9".into(), serde_json::json!({"v": 2}), false, true).await;
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
        run_ops(&db, &policy, None, vec![merge_op("set", "a", serde_json::json!({"x": 1}))], false)
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("x"), Some(&serde_json::json!(1)));

        // set+merge on a present doc merges (old keys survive).
        run_ops(&db, &policy, None, vec![merge_op("set", "a", serde_json::json!({"y": 2}))], false)
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("x"), Some(&serde_json::json!(1)));
        assert_eq!(a.data.get("y"), Some(&serde_json::json!(2)));

        // Plain set on a present doc replaces (old keys gone).
        run_ops(&db, &policy, None, vec![batch_op("set", "m", "a", serde_json::json!({"z": 3}))], false)
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("z"), Some(&serde_json::json!(3)));
        assert!(!a.data.contains_key("x"));

        // update on a missing doc aborts the whole batch.
        let bad = run_ops(&db, &policy, None, vec![batch_op("update", "m", "ghost", serde_json::json!({"q": 1}))], false).await;
        assert!(bad.is_err());
        assert!(db.get("m", "ghost").await.unwrap().is_none());

        // add upserts: merge over present, create when missing.
        run_ops(&db, &policy, None, vec![batch_op("add", "m", "a", serde_json::json!({"w": 9}))], false)
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("z"), Some(&serde_json::json!(3)));
        assert_eq!(a.data.get("w"), Some(&serde_json::json!(9)));

        // Transaction unknown types map by existence (merge when present).
        run_ops(&db, &policy, None, vec![batch_op("frobnicate", "m", "a", serde_json::json!({"u": 7}))], true)
            .await
            .unwrap();
        let a = db.get("m", "a").await.unwrap().unwrap();
        assert_eq!(a.data.get("u"), Some(&serde_json::json!(7)));
        assert_eq!(a.data.get("w"), Some(&serde_json::json!(9)));
        let _ = std::fs::remove_dir_all(&dir);
    }

}

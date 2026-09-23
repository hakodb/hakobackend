//! hakobackend-server: universal HTTP gateway (Axum).
//! Wire protocol compatible with rethink-firestore/backend so legacy SDKs keep working.
//!
//! Plug-and-play database: driver selected in `hakobackend.toml` (`database.driver`).
//! Swap/plug-unplug DB = edit config + `POST /api/admin/reload` (no rebuild).
//! Add a new driver = a `hakobackend-db-*` crate impl'ing `hakobackend_core::Database` + 1 arm in `open_driver`.
//!
//! Endpoint flexibility: automatic wildcard (zero-config) + `policy.toml` that
//! **hot-reloads** (mtime checked on each request; file edits take effect immediately, no restart).

mod config;
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
use clap::Parser;
use config::{Args, DEFAULT_CONFIG_TEMPLATE, resolve, validate};
use std::collections::HashMap;
use std::sync::Arc;
use std::time::SystemTime;
use hakobackend_auth_core::{AuthChain, AuthSpec, CustomAuth, open_chain};
use hakobackend_auth_github::GithubOAuth;
use hakobackend_auth_local::{ACCESS_COOKIE, DpopMode, DpopRequest, LocalAuth, REFRESH_COOKIE};
use hakobackend_core::{AuthContext, AuthProvider, Database, Doc, Method, PathKind, QueryOptions, parse_collection_path};
use hakobackend_db_hako::HakoDb;
use hakobackend_db_postgres::PgDb;
use hakobackend_db_sqlite::SqliteDb;
use hakobackend_db_mysql::MysqlDb;
use hakobackend_policy::{Identity, PolicyFile};
use hakobackend_ratelimit::{Limiter, Quota};

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
    /// Free-form user role name allowed to call /api/admin/*.
    admin_role: String,
    /// CLI flags for reload (file re-read, flags still win).
    cli: Args,
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
async fn open_driver(driver: &str, path: &str) -> Result<Arc<dyn Database>, String> {
    match driver {
        "hako" => HakoDb::open(path).map(|db| Arc::new(db) as Arc<dyn Database>).map_err(|e| e.to_string()),
        "postgres" => PgDb::open(path).await.map(|db| Arc::new(db) as Arc<dyn Database>).map_err(|e| e.to_string()),
        "sqlite" => SqliteDb::open(path).await.map(|db| Arc::new(db) as Arc<dyn Database>).map_err(|e| e.to_string()),
        "mysql" => MysqlDb::open(path).await.map(|db| Arc::new(db) as Arc<dyn Database>).map_err(|e| e.to_string()),
        other => Err(format!(
            "driver `{other}` not available yet (duckdb follows if requested). Available choices: {}.",
            crate::config::KNOWN_DRIVERS.join(", ")
        )),
    }
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
    let db: Arc<dyn Database> = open_driver(&cfg.driver, &cfg.data).await.expect("open database");
    println!("[ub] driver={} data={} config={}", cfg.driver, cfg.data, if cfg.source.is_empty() { "(default+flag)" } else { &cfg.source });

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

    let state = AppState {
        db: Arc::new(tokio::sync::RwLock::new(db)),
        policy,
        auth: Arc::new(tokio::sync::RwLock::new(Arc::new(chain))),
        local: Arc::new(tokio::sync::RwLock::new(local)),
        github: Arc::new(tokio::sync::RwLock::new(github)),
        limits: limits.clone(),
        tls,
        admin_role: cfg.admin_role.clone(),
        cli,
    };

    // Layered flood protection (before any expensive work):
    // /health open (LB probes), /api/auth/* strict, rest loose global.
    let global = LimitScope { limiter: limits.global.clone(), trust_proxy: limits.trust_proxy };
    let strict = LimitScope { limiter: limits.auth.clone(), trust_proxy: limits.trust_proxy };
    let api = Router::new()
        .route("/api/collections", get(list_collections))
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
        .layer(middleware::from_fn_with_state(strict, limit_mw));

    let mut app = Router::new()
        .route("/api/health", get(health))
        .merge(api)
        .merge(auth_routes)
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        .with_state(state);
    if tls {
        // HSTS only meaningful via TLS (no effect on plain http).
        app = app.layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));
    }

    let addr = cfg.listen();
    // ConnectInfo required so the rate-limit key = real peer IP.
    let svc = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    if tls {
        // rustls 0.23 + two providers in the tree (aws-lc + ring) = ambiguous;
        // pin aws-lc explicitly once at startup (idempotent).
        let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());
        let (cert, key) = config::tls_pair(&cfg).map_err(|e| format!("[ub] {e}"))?.unwrap();
        let rustls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| format!("[ub] TLS failed to load: {e}"))?;
        println!("[ub] listening (TLS) on https://{addr}");
        axum_server::bind_rustls(addr.parse().map_err(|e| format!("[ub] invalid listen address: {e}"))?, rustls)
            .serve(svc)
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!("[ub] listening on http://{addr}");
        axum::serve(listener, svc).await?;
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
    ConnectInfo(peer): ConnectInfo<std::net::SocketAddr>,
    req: Request,
    next: Next,
) -> Response {
    match s.limiter.check(&client_key(req.headers(), peer, s.trust_proxy)) {
        Ok(()) => next.run(req).await,
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

/// Auth middleware: Bearer (API clients) else access cookie (browser BFF) →
/// chain resolve → DPoP enforcement (local tokens) → `Extension<Option<AuthContext>>`.
/// No token / DPoP failure = anonymous (policy rules decide, not middleware).
async fn auth_mw(State(s): State<AppState>, mut req: Request, next: Next) -> Response {
    let token = bearer(req.headers()).or_else(|| read_cookie(req.headers(), ACCESS_COOKIE));
    let dpop_proof = req.headers().get("DPoP").and_then(|v| v.to_str().ok()).map(str::to_string);
    let method = req.method().to_string();
    let uri = base_uri(s.tls, req.headers(), req.uri().path());
    let mut ctx = match &token {
        Some(t) => resolve_token(&s, t).await,
        None => None,
    };
    if let (Some(local), Some(tok)) = (s.local.read().await.clone(), &token) {
        let is_local = ctx
            .as_ref()
            .and_then(|c| c.extra.get("provider"))
            .and_then(|v| v.as_str())
            == Some(hakobackend_auth_local::NAME);
        let binding = local.bound_jkt(tok).ok().flatten();
        let ok = match dpop_action(local.dpop_mode(), is_local, dpop_proof.is_some()) {
            DpopAction::Keep => true,
            DpopAction::Strip => false,
            DpopAction::MustVerify => dpop_proof
                .as_deref()
                .is_some_and(|p| local.check_dpop(p, &method, &uri, tok, binding.as_deref()).is_ok()),
        };
        if !ok {
            ctx = None;
        }
    }
    req.extensions_mut().insert(ctx);
    next.run(req).await
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
    err(StatusCode::FORBIDDEN, "Permission denied by policy")
}

fn unauthorized() -> Response {
    err(StatusCode::UNAUTHORIZED, "authentication required")
}

/// Legacy wire shape: every failure is JSON `{error}` (writes add `code`).
fn err(status: StatusCode, msg: impl ToString) -> Response {
    (status, Json(serde_json::json!({ "error": msg.to_string() }))).into_response()
}

fn err_code(status: StatusCode, msg: impl ToString, code: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": msg.to_string(), "code": code })),
    )
        .into_response()
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "db": "hakodb" }))
}

/// Re-read config + driver + auth chain. "Hot-swap while running":
/// edit the file, POST here (admin role), done — CLI flags still win.
/// Failure at any step = 400 and the old config is fully retained.
async fn reload(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>) -> impl IntoResponse {
    if !auth.as_ref().is_some_and(|a| a.roles.iter().any(|r| r == &s.admin_role)) {
        return forbidden();
    }
    let cfg = resolve(&s.cli);
    if let Some(p) = &cfg.public_url {
        if std::env::var("UB_PUBLIC_URL").is_err() {
            std::env::set_var("UB_PUBLIC_URL", p);
        }
    }
    let db: Arc<dyn Database> = match open_driver(&cfg.driver, &cfg.data).await {
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
    // Rate-limit numbers + auto-provision hot-reload too (no restart).
    s.limits.global.set_quota(Quota::per_minute(cfg.limit_global.0, cfg.limit_global.1));
    s.limits.auth.set_quota(Quota::per_minute(cfg.limit_auth.0, cfg.limit_auth.1));
    auto_provision(&s.db.read().await.clone(), &s.policy.get().await, &cfg.indexes).await;
    let msg = format!("reload ok: driver={} data={} auth={}", cfg.driver, cfg.data, cfg.auth.as_deref().unwrap_or("off"));
    eprintln!("[ub] {msg}");
    msg.into_response()
}

async fn list_collections(State(s): State<AppState>) -> impl IntoResponse {
    match s.db.read().await.list_collections().await {
        Ok(c) => Json(serde_json::json!(c)).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    }
}

fn parse_options(q: &HashMap<String, String>) -> Result<QueryOptions, String> {
    match q.get("options") {
        None => Ok(QueryOptions::default()),
        Some(raw) => serde_json::from_str(raw).map_err(|_| "malformed \"options\" query parameter".to_string()),
    }
}

async fn get_or_list(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let policy = s.policy.get().await;
    let db = s.db.read().await.clone();
    match parse_collection_path(&path) {
        PathKind::Document { collection, id } => match db.get(&collection, &id).await {
            Ok(Some(doc)) => {
                if !policy.allow(auth.as_ref(), &collection, Method::Get, Some(&doc)) {
                    return forbidden();
                }
                Json(serde_json::to_value(doc).unwrap()).into_response()
            }
            Ok(None) => err(StatusCode::NOT_FOUND, "Document not found"),
            Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        },
        PathKind::Collection { collection } => match parse_options(&q) {
            Err(msg) => err(StatusCode::BAD_REQUEST, msg),
            Ok(opts) => match db.list(&collection, &opts).await {
                // Per-doc filter (replacement for the server.ts:233 loop): documents
                // failing the rule are excluded from the response, with no extra N+1
                // queries when drivers push rules into queries (phase 3).
                Ok(docs) => {
                    let visible: Vec<_> = docs
                        .into_iter()
                        .filter(|d| policy.allow(auth.as_ref(), &collection, Method::Get, Some(d)))
                        .collect();
                    Json(serde_json::to_value(visible).unwrap()).into_response()
                }
                Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
            },
        },
    }
}

fn incoming_doc(id: &str, body: serde_json::Value) -> Doc {
    let data = match body {
        serde_json::Value::Object(m) => m.into_iter().collect(),
        _ => HashMap::new(),
    };
    Doc { id: id.to_string(), data }
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
    let spec = match parse_index_spec(&body) {
        Ok(spec) => spec,
        Err(msg) => return err(StatusCode::BAD_REQUEST, msg),
    };
    let policy = s.policy.get().await;
    if !policy.allow(auth.as_ref(), &collection, Method::Update, None) {
        return forbidden();
    }
    let db = s.db.read().await.clone();
    let _ = db.ensure_collection(&collection).await;
    match db.create_index(&collection, &spec).await {
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
    let policy = s.policy.get().await;
    if !policy.allow(auth.as_ref(), &collection, Method::List, None) {
        return forbidden();
    }
    match s.db.read().await.list_indexes(&collection).await {
        Ok(indexes) => Json(serde_json::to_value(indexes).unwrap()).into_response(),
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
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
    let policy = s.policy.get().await;
    if !policy.allow(auth.as_ref(), &collection, Method::Update, None) {
        return forbidden();
    }
    match s.db.read().await.drop_index(&collection, &name).await {
        Ok(()) => Json(serde_json::json!({ "success": true })).into_response(),
        Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
    }
}

async fn create(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Json(body): Json<serde_json::Value>,
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
            let policy = s.policy.get().await;
            let incoming = incoming_doc("", body);
            if !policy.allow(auth.as_ref(), &collection, Method::Create, Some(&incoming)) {
                return forbidden();
            }
            let db = s.db.read().await.clone();
            let _ = db.ensure_collection(&collection).await;
            // Atomics collapse (legacy parity) + createdAt/updatedAt stamping.
            let incoming = Doc {
                id: incoming.id,
                data: hakobackend_core::atomics::stamp_new(
                    hakobackend_core::atomics::resolve_for_create(incoming.data),
                ),
            };
            match db.insert(&collection, incoming).await {
                Ok(doc) => Json(serde_json::to_value(doc).unwrap()).into_response(),
                Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
            }
        }
    }
}

async fn put(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    write_doc(s, auth, path, body, false).await
}

async fn patch(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // ponytail: merge=true uses the same path as PUT; no manual read-modify-write.
    write_doc(s, auth, path, body, true).await
}

async fn write_doc(s: AppState, auth: Option<AuthContext>, path: String, body: serde_json::Value, merge: bool) -> Response {
    match parse_collection_path(&path) {
        PathKind::Collection { .. } => (
            StatusCode::BAD_REQUEST,
            "PUT/PATCH requests must target explicit document endpoints.",
        )
            .into_response(),
        PathKind::Document { collection, id } => {
            let policy = s.policy.get().await;
            let db = s.db.read().await.clone();
            let existing = db.get(&collection, &id).await.ok().flatten();
            // Owner rule evaluated against the existing document (who owns this data?).
            if !policy.allow(auth.as_ref(), &collection, Method::Update, existing.as_ref()) {
                return forbidden();
            }
            // Legacy parity: PATCH on a missing doc is 404 (use PUT to create).
            if merge && existing.is_none() {
                return err(StatusCode::NOT_FOUND, "Document not found");
            }
            let _ = db.ensure_collection(&collection).await;
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
            // Merge already applied above; store the final body as-is.
            match db.set(&collection, &id, Doc { id: id.clone(), data }, false).await {
                Ok(_) => Json(serde_json::json!({ "success": true })).into_response(),
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
            let policy = s.policy.get().await;
            let db = s.db.read().await.clone();
            let existing = db.get(&collection, &id).await.ok().flatten();
            if !policy.allow(auth.as_ref(), &collection, Method::Delete, existing.as_ref()) {
                return forbidden();
            }
            let _ = db.ensure_collection(&collection).await;
            match db.delete(&collection, &id).await {
                Ok(_) => Json(serde_json::json!({ "success": true })).into_response(),
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
// `add` forces merge (create path); `set` honors `options.merge`;
// `update` errors when absent; unknown types map by existence (transaction
// only — batch treats them as creates, like legacy).

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
async fn run_ops(
    db: &Arc<dyn Database>,
    policy: &Arc<PolicyFile>,
    auth: Option<&AuthContext>,
    ops: Vec<BatchOpBody>,
    is_tx: bool,
) -> Result<Vec<serde_json::Value>, (StatusCode, String, &'static str)> {
    use hakobackend_core::{TxOp, TxOpKind};
    // Phase 1: resolve + gate each op (reads tolerate missing tables).
    struct Gated {
        body: BatchOpBody,
        id: String,
        existed: bool,
        existing: Option<Doc>,
    }
    let mut gated = Vec::with_capacity(ops.len());
    for op in ops {
        let id = op
            .id
            .clone()
            .filter(|s| !s.is_empty())
            .ok_or((StatusCode::BAD_REQUEST, "op requires id".to_string(), "bad-request"))?;
        let existing = db.get(&op.collection, &id).await.ok().flatten();
        let existed = existing.is_some();
        let method = op_method(&op.op_type.to_ascii_lowercase(), existed, is_tx);
        if !policy.allow(auth, &op.collection, method, existing.as_ref()) {
            return Err((
                StatusCode::FORBIDDEN,
                format!("Permission denied: {method:?} on {}/{}", op.collection, id),
                "permission-denied",
            ));
        }
        let _ = db.ensure_collection(&op.collection).await;
        gated.push(Gated { body: op, id, existed, existing });
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
    let tx_ops: Vec<TxOp> = gated
        .iter()
        .map(|g| {
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
            let kind = match t.as_str() {
                "get" => TxOpKind::Read,
                "delete" => TxOpKind::Delete,
                "update" => TxOpKind::Put { merge: false, must_exist: true },
                _ if is_tx && g.existed && t != "set" && t != "add" => TxOpKind::Put { merge: false, must_exist: true },
                _ => TxOpKind::Put { merge: false, must_exist: false },
            };
            TxOp {
                collection: g.body.collection.clone(),
                id: g.id.clone(),
                kind,
                doc: Some(Doc { id: g.id.clone(), data }),
            }
        })
        .collect();
    // Reads resolve against the batch's own writes (driver overlay/tx reads).
    let outs = db
        .run_transaction(tx_ops)
        .await
        .map_err(|e| {
            (
                StatusCode::from_u16(e.status_code()).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                e.to_string(),
                e.code(),
            )
        })?;
    // Phase 3: legacy result shapes — batch: every op → `{id, success}`;
    // transaction: `get` → doc-or-null, writes → `{success: true}`.
    Ok(gated
        .into_iter()
        .zip(outs)
        .map(|(g, o)| {
            let t = g.body.op_type.to_ascii_lowercase();
            if !is_tx {
                serde_json::json!({ "id": g.id, "success": true })
            } else {
                match t.as_str() {
                    "get" => o.doc.map(|d| serde_json::to_value(d).unwrap()).unwrap_or(serde_json::Value::Null),
                    _ => serde_json::json!({ "success": true }),
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
    let policy = s.policy.get().await;
    match run_ops(&db, &policy, auth.as_ref(), ops, false).await {
        Ok(results) => Json(serde_json::json!({ "success": true, "results": results })).into_response(),
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
    let policy = s.policy.get().await;
    match run_ops(&db, &policy, auth.as_ref(), ops, true).await {
        Ok(results) => Json(serde_json::json!({ "success": true, "results": results })).into_response(),
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
    let policy = s.policy.get().await;
    let db = s.db.read().await.clone();
    let collections = match db.list_collections().await {
        Ok(c) => c,
        Err(e) => return err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
    };
    let mut out = Vec::new();
    for coll in collections {
        if !realtime::matches_group(&coll, &name) {
            continue;
        }
        if !policy.allow(auth.as_ref(), &coll, Method::List, None) {
            continue;
        }
        let docs = match db.list(&coll, &opts).await {
            Ok(d) => d,
            Err(_) => continue,
        };
        for doc in docs {
            let doc_coll = doc
                .data
                .get("_collectionPath")
                .and_then(|v| v.as_str())
                .unwrap_or(&coll);
            if policy.allow(auth.as_ref(), doc_coll, Method::Get, Some(&doc)) {
                out.push(doc);
            }
        }
    }
    Json(serde_json::to_value(out).unwrap()).into_response()
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

fn agg_number(v: &serde_json::Value) -> Option<f64> {
    match v {
        serde_json::Value::Number(n) => n.as_f64(),
        _ => None,
    }
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
    let policy = s.policy.get().await;
    if !policy.allow(auth.as_ref(), &collection, Method::List, None) {
        return forbidden();
    }
    let db = s.db.read().await.clone();
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
            "count" => match db.count(&collection, &opts).await {
                Ok(n) => serde_json::json!(n),
                Err(e) => return err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()),
            },
            "sum" | "avg" => {
                let field = match agg.field.as_deref().filter(|f| !f.is_empty()) {
                    Some(f) => f,
                    None => return err(StatusCode::BAD_REQUEST, format!("{t} needs a field")),
                };
                let docs = match db.list(&collection, &opts).await {
                    Ok(d) => d,
                    Err(e) => return err(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()),
                };
                let nums: Vec<f64> = docs.iter().filter_map(|d| d.data.get(field).and_then(agg_number)).collect();
                if t == "sum" {
                    serde_json::json!(nums.iter().sum::<f64>())
                } else if nums.is_empty() {
                    serde_json::json!(0.0)
                } else {
                    serde_json::json!(nums.iter().sum::<f64>() / nums.len() as f64)
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

async fn auth_register(State(s): State<AppState>, Json(body): Json<serde_json::Value>) -> impl IntoResponse {
    let local = match local_or_400(&s).await {
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
        Ok(doc) => (StatusCode::CREATED, Json(serde_json::json!({ "id": doc.id }))).into_response(),
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
    let local = match local_or_400(&s).await {
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
                    (StatusCode::OK, headers, Json(serde_json::json!({ "uid": ctx.uid, "roles": ctx.roles }))).into_response()
                }
                // Obfuscate: wrong login vs password vs dpop are not distinguished (anti-enumeration).
                Err(_) => err(StatusCode::UNAUTHORIZED, "invalid credentials"),
            }
        }
        _ => err(StatusCode::BAD_REQUEST, "login + password required"),
    }
}

async fn auth_refresh(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    let local = match local_or_400(&s).await {
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
            (StatusCode::OK, h, Json(serde_json::json!({ "uid": ctx.uid, "roles": ctx.roles }))).into_response()
        }
        // Reuse/expired/foreign: clear cookies + reject (fail-closed).
        Err(_) => (StatusCode::UNAUTHORIZED, clear_cookies(), Json(serde_json::json!({ "error": "invalid session" }))).into_response(),
    }
}

async fn auth_logout(State(s): State<AppState>, headers: HeaderMap) -> impl IntoResponse {
    if let Some(local) = s.local.read().await.clone() {
        if let Some(t) = read_cookie(&headers, REFRESH_COOKIE) {
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
        .or_else(|| q.get("token").cloned());
    let mut auth = None;
    if let Some(t) = init {
        auth = resolve_token(&s, &t).await;
    }
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
                    auth = resolve_token(&s, token).await;
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
                    let sub_auth = match v.get("token").and_then(|t| t.as_str()) {
                        Some(t) => resolve_token(&s, t).await,
                        None => auth.clone(),
                    };
                    let db = s.db.read().await.clone();
                    let policy = s.policy.get().await;
                    match realtime::subscribe(db, policy, sub_auth, spec).await {
                        Ok(sub) => {
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
    let auth = match bearer(&headers)
        .or_else(|| read_cookie(&headers, ACCESS_COOKIE))
        .or_else(|| q.get("token").cloned())
    {
        Some(t) => resolve_token(&s, &t).await,
        None => None,
    };
    let options = match parse_options(&q) {
        Ok(o) => o,
        Err(msg) => return err(StatusCode::BAD_REQUEST, msg),
    };
    let group = matches!(q.get("group").map(|g| g.as_str()), Some("1") | Some("true"));
    let db = s.db.read().await.clone();
    let policy = s.policy.get().await;
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

async fn github_login(State(s): State<AppState>) -> impl IntoResponse {
    match s.github.read().await.clone() {
        None => err(StatusCode::BAD_REQUEST, "github oauth is not configured"),
        Some(g) => match g.login_url().await {
            Ok(url) => Redirect::to(&url).into_response(),
            Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
        },
    }
}

async fn github_callback(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let (g, local) = match (s.github.read().await.clone(), s.local.read().await.clone()) {
        (Some(g), Some(l)) => (g, l),
        _ => return err(StatusCode::BAD_REQUEST, "github oauth requires env credentials + `local` in the chain"),
    };
    let (code, state) = match (q.get("code").cloned(), q.get("state").cloned()) {
        (Some(c), Some(st)) => (c, st),
        _ => return err(StatusCode::BAD_REQUEST, "code + state required"),
    };
    // Obfuscate all failures (bad code, stale state, github down).
    let (uid, email, login) = match g.callback(&code, &state).await {
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
            // BFF: browser returns to the app with a session cookie; no tokens in URL.
            h.insert(header::LOCATION, g.after_login().parse().unwrap());
            (StatusCode::FOUND, h).into_response()
        }
        Err(e) => err(StatusCode::INTERNAL_SERVER_ERROR, e.to_string()),
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
    fn shim_legacy_index() {        assert_eq!(legacy_index_collection("posts/index").as_deref(), Some("posts"));
        assert_eq!(
            legacy_index_collection("/posts/p1/revisions/index/").as_deref(),
            Some("posts/p1/revisions")
        );
        // A real collection named "index" is not hijacked.
        assert_eq!(legacy_index_collection("index"), None);
        assert_eq!(legacy_index_collection("posts"), None);
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
    fn op_method_mapping() {
        use Method::*;
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
    #[tokio::test]
    async fn batch_end_to_end_sqlite() {
        use hakobackend_db_sqlite::SqliteDb;
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
                batch_op("bogus", "w", "c", d(3)),
                batch_op("get", "w", "a", d(0)),
            ],
            false,
        )
        .await
        .unwrap();
        assert_eq!(res.len(), 4);
        assert!(res.iter().all(|r| r.get("success") == Some(&serde_json::json!(true))));
        assert_eq!(res[0].get("id"), Some(&serde_json::json!("a")));

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
        let res = run_ops(&db, &policy, None, vec![batch_op("get", "w", "a", d(0))], true)
            .await
            .unwrap();
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
}

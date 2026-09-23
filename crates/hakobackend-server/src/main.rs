//! hakobackend-server: gateway HTTP universal (Axum).
//! Wire-protocol kompatibel dengan rethink-firestore/backend agar SDK lama tetap jalan.
//!
//! Plug-and-play database: driver dipilih di `hakobackend.toml` (`database.driver`).
//! Ganti/pasang-lepas DB = edit config + `POST /api/admin/reload` (tanpa rebuild).
//! Tambah driver baru = crate `hakobackend-db-*` yang impl `hakobackend_core::Database` + 1 arm di `open_driver`.
//!
//! Fleksibilitas endpoint: wildcard otomatis (nol-config) + `policy.toml` yang
//! **hot-reload** (mtime dipantau tiap request; edit file langsung berlaku, tanpa restart).

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
    /// Router DB: koleksi -> driver. Hari ini 1 driver untuk semua koleksi;
    /// peta ini yang memungkinkan override per-koleksi (`routes` di hakobackend.toml, fase 3).
    db: Arc<tokio::sync::RwLock<Arc<dyn Database>>>,
    policy: Arc<PolicyHot>,
    /// Rantai verifier (kosong = mode dev tanpa auth; resolve selalu None).
    auth: Arc<tokio::sync::RwLock<Arc<AuthChain>>>,
    /// Konkret lokal untuk endpoint /api/auth/* (None bila `local` tak dipakai).
    local: Arc<tokio::sync::RwLock<Option<Arc<LocalAuth>>>>,
    /// Alur OAuth GitHub (None bila tanpa client id). Endpoint 400 bila mati.
    github: Arc<tokio::sync::RwLock<Option<Arc<GithubOAuth>>>>,
    /// Flood protection 2 lapis (hot-reload via /api/admin/reload).
    limits: Arc<LimitLayers>,
    /// TLS aktif (skema https untuk htu DPoP + HSTS).
    tls: bool,
    /// Nama peran bebas milik user yang boleh memanggil /api/admin/*.
    admin_role: String,
    /// Flag CLI untuk reload (file dibaca ulang, flag tetap menang).
    cli: Args,
}

/// Dua bucket token: global longgar + auth ketat. Clone murah (Arc di dalam).
#[derive(Clone)]
struct LimitLayers {
    global: Arc<Limiter>,
    auth: Arc<Limiter>,
    trust_proxy: bool,
}

/// Policy yang reload sendiri saat file berubah (cek mtime tiap request — 1 stat call).
struct PolicyHot {
    path: Option<String>,
    cached: tokio::sync::RwLock<(Option<SystemTime>, Arc<PolicyFile>)>,
}

impl PolicyHot {
    fn new(path: Option<String>) -> Self {
        match path {
            None => {
                // ponytail: tanpa policy file = mode dev terbuka + WARN keras.
                // Tanpa token = anonim; aturan policy yang menentukan (fail-closed
                // bila policy file ada). SessionIssuer penuh menyusul (fase C).
                eprintln!("[ub] WARN: tanpa policy file — semua endpoint TERBUKA (mode dev). Isi `policy_file` di hakobackend.toml untuk produksi.");
                Self {
                    path: None,
                    cached: tokio::sync::RwLock::new((None, Arc::new(PolicyFile::open()))),
                }
            }
            Some(p) => {
                let file = PolicyFile::load(&p).unwrap_or_else(|e| {
                    eprintln!("[ub] WARN: {e}; pakai policy terbuka sementara");
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
        // Reload hanya bila mtime berubah (edit user langsung berlaku).
        if self.cached.read().await.0 != current {
            let mut w = self.cached.write().await;
            if w.0 != current {
                match PolicyFile::load(path) {
                    Ok(f) => {
                        eprintln!("[ub] policy reload: {path}");
                        *w = (current, Arc::new(f));
                    }
                    Err(e) => eprintln!("[ub] policy reload GAGAL ({e}); policy lama tetap dipakai"),
                }
            }
            return w.1.clone();
        }
        self.cached.read().await.1.clone()
    }

    /// Snapshot `[identity]` untuk konstruksi provider (reload-safe: policy
    /// hot-reload independen, provider dibangun ulang saat /api/admin/reload).
    fn identity_snapshot(&self) -> Identity {
        self.cached.try_read().map(|g| g.1.identity.clone()).unwrap_or_default()
    }
}

fn mtime(path: &str) -> Option<SystemTime> {
    std::fs::metadata(path).and_then(|m| m.modified()).ok()
}

/// Satu-satunya tempat yang tahu daftar driver. Driver baru = 1 arm baru.
/// Driver yang belum diimplementasi mengembalikan pesan jelas, bukan panic.
async fn open_driver(driver: &str, path: &str) -> Result<Arc<dyn Database>, String> {
    match driver {
        "hako" => HakoDb::open(path).map(|db| Arc::new(db) as Arc<dyn Database>).map_err(|e| e.to_string()),
        "postgres" => PgDb::open(path).await.map(|db| Arc::new(db) as Arc<dyn Database>).map_err(|e| e.to_string()),
        "sqlite" => SqliteDb::open(path).await.map(|db| Arc::new(db) as Arc<dyn Database>).map_err(|e| e.to_string()),
        "mysql" => MysqlDb::open(path).await.map(|db| Arc::new(db) as Arc<dyn Database>).map_err(|e| e.to_string()),
        other => Err(format!(
            "driver `{other}` belum tersedia (duckdb menyusul bila diminta). Pilihan hari ini: {}.",
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

    // Env menang atas flag/file untuk URL publik (konsisten dengan secret lain);
    // diisi dari config hanya bila env kosong. Sekali saat startup/reload.
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
        println!("[ub] TLS aktif (HSTS + skema https)");
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

    // Flood protection berlapis (sebelum kerja mahal apa pun):
    // /health terbuka (probe LB), /api/auth/* ketat, sisanya global longgar.
    let global = LimitScope { limiter: limits.global.clone(), trust_proxy: limits.trust_proxy };
    let strict = LimitScope { limiter: limits.auth.clone(), trust_proxy: limits.trust_proxy };
    let api = Router::new()
        .route("/api/collections", get(list_collections))
        .route(
            "/api/collections/{*path}",
            get(get_or_list).post(create).put(put).patch(patch).delete(remove),
        )
        .route("/api/indexes", post(index_create).get(index_list).delete(index_drop))
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
        // HSTS hanya bermakna via TLS (tanpa efek di http biasa).
        app = app.layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));
    }

    let addr = cfg.listen();
    // ConnectInfo wajib agar kunci rate-limit = IP peer asli.
    let svc = app.into_make_service_with_connect_info::<std::net::SocketAddr>();
    if tls {
        // rustls 0.23 + dua provider di tree (aws-lc + ring) = ambigu;
        // tetapkan aws-lc eksplisit sekali saat startup (idempoten).
        let _ = rustls::crypto::CryptoProvider::install_default(rustls::crypto::aws_lc_rs::default_provider());
        let (cert, key) = config::tls_pair(&cfg).map_err(|e| format!("[ub] {e}"))?.unwrap();
        let rustls = axum_server::tls_rustls::RustlsConfig::from_pem_file(cert, key)
            .await
            .map_err(|e| format!("[ub] TLS gagal dimuat: {e}"))?;
        println!("[ub] listening (TLS) on https://{addr}");
        axum_server::bind_rustls(addr.parse().map_err(|e| format!("[ub] listen salah: {e}"))?, rustls)
            .serve(svc)
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!("[ub] listening on http://{addr}");
        axum::serve(listener, svc).await?;
    }
    Ok(())
}

/// Scope satu lapis rate-limit (limiter + kepercayaan proxy).
#[derive(Clone)]
struct LimitScope {
    limiter: Arc<Limiter>,
    trust_proxy: bool,
}

/// Kunci = IP peer, atau X-Forwarded-For pertama bila trust_proxy.
/// XFF hanya dipercaya di belakang proxy yang membersihkannya (spoofable bila langsung).
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

/// Auto-create siap pakai (pola autoCreateTablesFromRules backend lama,
/// diperluas ke index): koleksi dari kunci policy + `[[indexes]]` config.
/// Gagal per item = WARN, bukan fatal (endpoint manual tetap tersedia).
async fn auto_provision(db: &Arc<dyn Database>, policy: &Arc<PolicyFile>, indexes: &[config::IndexDecl]) {
    for collection in policy.collections.keys() {
        if let Err(e) = db.ensure_collection(collection).await {
            eprintln!("[ub] auto-create koleksi {collection} gagal: {e}");
        }
    }
    for decl in indexes {
        let spec = match decl.validate() {
            Ok(s) => s,
            Err(e) => {
                eprintln!("[ub] [[indexes]] dilewati: {e}");
                continue;
            }
        };
        if let Err(e) = db.ensure_collection(&decl.collection).await {
            eprintln!("[ub] auto-create koleksi {} gagal: {e}", decl.collection);
            continue;
        }
        match db.create_index(&decl.collection, &spec).await {
            Ok(info) => println!("[ub] index siap: {} → {}", decl.collection, info.name),
            Err(e) => eprintln!("[ub] index {} gagal: {e}", decl.collection),
        }
    }
}

/// Bangun rantai auth + konkret lokal. `local` butuh db handle + `[identity]`,
/// jadi dibangun di sini (server), bukan di `open_builtin`. Gagal cepat bila
/// nama/file/secret tak valid (fail-closed).
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
    // Versi tanpa panic untuk /api/admin/reload (error → 400, konfigurasi lama bertahan).
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
        // custom.toml `dpop` menang atas env; typo = error (fail-closed).
        l.set_dpop_mode(hakobackend_auth_local::DpopMode::parse(d)?);
    }
    let chain = open_chain(
        &spec,
        custom.as_ref(),
        local.clone().map(|l| l as Arc<dyn AuthProvider>),
    )?;
    // OAuth independen dari rantai: aktif bila kredensial env-nya lengkap.
    let github = GithubOAuth::from_env(db)?;
    Ok((chain, local, github))
}

/// Keputusan DPoP murni (diuji unit): Off / token non-lokal = lolos;
/// Require tanpa proof = strip (anonim → policy bicara); proof ada = wajib verifikasi;
/// Accept tanpa proof = bearer fallback.
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

/// Resolve satu token → AuthContext (dipakai middleware, WS, SSE).
async fn resolve_token(s: &AppState, token: &str) -> Option<AuthContext> {
    let policy = s.policy.get().await;
    let db = s.db.read().await.clone();
    let chain = s.auth.read().await.clone();
    let db_ref: &dyn Database = &*db;
    chain.resolve(&policy.identity, Some(db_ref), token).await
}

/// Middleware auth: Bearer (klien API) else cookie access (browser BFF) →
/// resolve rantai → enforcement DPoP (token lokal) → `Extension<Option<AuthContext>>`.
/// Tanpa token / gagal DPoP = anonim (aturan policy yang menentukan, bukan middleware).
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

/// Skema asal absolut: https bila TLS aktif (DPoP htu wajib cocok skema persis).
fn base_uri(tls: bool, headers: &HeaderMap, path: &str) -> String {
    let scheme = if tls { "https" } else { "http" };
    format!(
        "{scheme}://{}{}",
        headers.get(header::HOST).and_then(|v| v.to_str().ok()).unwrap_or("unknown"),
        path
    )
}

fn forbidden() -> Response {
    (StatusCode::FORBIDDEN, "Permission denied by policy").into_response()
}

fn unauthorized() -> Response {
    (StatusCode::UNAUTHORIZED, "authentication required").into_response()
}

async fn health() -> impl IntoResponse {
    Json(serde_json::json!({ "status": "ok", "db": "hakodb" }))
}

/// Baca ulang config + driver + rantai auth. "Pasang-lepas saat jalan":
/// edit file, POST ke sini (peran admin), selesai — flag CLI tetap menang.
/// Gagal di langkah mana pun = 400 dan konfigurasi lama bertahan seluruhnya.
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
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    let identity = s.policy.get().await.identity.clone();
    let (chain, local, github) = match open_auth_result(cfg.auth.as_deref(), db.clone(), identity) {
        Ok(v) => v,
        Err(e) => return (StatusCode::BAD_REQUEST, e).into_response(),
    };
    *s.db.write().await = db;
    *s.auth.write().await = Arc::new(chain);
    *s.local.write().await = local;
    *s.github.write().await = github;
    // Angka rate-limit + auto-provision ikut hot-reload (tanpa restart).
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
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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
            Ok(None) => (StatusCode::NOT_FOUND, "Document not found").into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
        PathKind::Collection { collection } => match parse_options(&q) {
            Err(msg) => (StatusCode::BAD_REQUEST, msg).into_response(),
            Ok(opts) => match db.list(&collection, &opts).await {
                // Filter per-doc (pengganti loop server.ts:233): dokumen yang
                // tidak lolos rule tidak ikut dalam respons, tanpa N+1 query
                // tambahan bila driver mendorong rule ke query (fase 3).
                Ok(docs) => {
                    let visible: Vec<_> = docs
                        .into_iter()
                        .filter(|d| policy.allow(auth.as_ref(), &collection, Method::Get, Some(d)))
                        .collect();
                    Json(serde_json::to_value(visible).unwrap()).into_response()
                }
                Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
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

// --- Index (HTTP_CONTRACT.md §index): kelola simple/composite/FTS ---
//
// Bentuk baru: POST/GET/DELETE /api/indexes (+collection sebagai field/query).
// Bentuk legacy (POST /api/collections/<coll>/index) ditangani shim di create().
// Gate policy: Update (operasi skema = write), kecuali list = List.

/// Deteksi shim legacy: ".../<coll>/index" → Some(coll). "index" polos (koleksi
/// sungguhan bernama index) → None agar tetap menjadi operasi dokumen.
fn legacy_index_collection(path: &str) -> Option<String> {
    path.trim_matches('/').strip_suffix("/index").map(|s| s.to_string())
}

fn parse_index_spec(body: &serde_json::Value) -> Result<hakobackend_core::IndexSpec, String> {
    serde_json::from_value(body.clone()).map_err(|_| "body butuh {collection, fields[], name?, unique?, kind?}".to_string())
}

async fn index_create(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    let collection = match body.get("collection").and_then(|v| v.as_str()) {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return (StatusCode::BAD_REQUEST, "collection wajib").into_response(),
    };
    index_create_inner(s, auth, collection, body).await
}

/// Shim legacy: body {name, fields} (+kind/unique opsional), respons {success:true}.
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
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let policy = s.policy.get().await;
    if !policy.allow(auth.as_ref(), &collection, Method::Update, None) {
        return forbidden();
    }
    let db = s.db.read().await.clone();
    let _ = db.ensure_collection(&collection).await;
    match db.create_index(&collection, &spec).await {
        Ok(info) => Json(serde_json::json!({ "success": true, "index": info })).into_response(),
        Err(e) => (StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()).into_response(),
    }
}

async fn index_list(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let collection = match q.get("collection").map(|s| s.as_str()) {
        Some(c) if !c.is_empty() => c.to_string(),
        _ => return (StatusCode::BAD_REQUEST, "query ?collection= wajib").into_response(),
    };
    let policy = s.policy.get().await;
    if !policy.allow(auth.as_ref(), &collection, Method::List, None) {
        return forbidden();
    }
    match s.db.read().await.list_indexes(&collection).await {
        Ok(indexes) => Json(serde_json::to_value(indexes).unwrap()).into_response(),
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

async fn index_drop(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let (collection, name) = match (q.get("collection"), q.get("name")) {
        (Some(c), Some(n)) if !c.is_empty() && !n.is_empty() => (c.clone(), n.clone()),
        _ => return (StatusCode::BAD_REQUEST, "query ?collection= & ?name= wajib").into_response(),
    };
    let policy = s.policy.get().await;
    if !policy.allow(auth.as_ref(), &collection, Method::Update, None) {
        return forbidden();
    }
    match s.db.read().await.drop_index(&collection, &name).await {
        Ok(()) => Json(serde_json::json!({ "success": true })).into_response(),
        Err(e) => (StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()).into_response(),
    }
}

async fn create(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(path): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Shim kompatibilitas legacy: POST /api/collections/<coll>/index {name, fields}
    // (backend lama, server.ts:193). Bentuk baru: POST /api/indexes.
    // Koleksi yang benar-benar bernama "index" diakses via bentuk baru.
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
            match db.insert(&collection, incoming).await {
                Ok(doc) => Json(serde_json::to_value(doc).unwrap()).into_response(),
                Err(e) => (StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()).into_response(),
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
    // ponytail: merge=true memakai path yang sama dengan PUT; tanpa baca-tulis manual.
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
            // Rule owner dinilai terhadap dokumen existing (milik siapa data ini?).
            if !policy.allow(auth.as_ref(), &collection, Method::Update, existing.as_ref()) {
                return forbidden();
            }
            let _ = db.ensure_collection(&collection).await;
            match db.set(&collection, &id, incoming_doc(&id, body), merge).await {
                Ok(_) => Json(serde_json::json!({ "success": true })).into_response(),
                Err(e) => (StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()).into_response(),
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
                Err(e) => (StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()).into_response(),
            }
        }
    }
}

// --- Auth lokal (BFF): dua cookie HttpOnly, browser tak pegang token ---

fn session_cookies(local: &LocalAuth, tokens: &hakobackend_auth_local::SessionTokens) -> HeaderMap {
    let mut h = HeaderMap::new();
    let pair = [
        (ACCESS_COOKIE, &tokens.access_jwt, local.access_ttl()),
        (REFRESH_COOKIE, &tokens.refresh_opaque, local.refresh_ttl()),
    ];
    for (name, value, age) in pair {
        // __Host-: Secure + Path=/ + tanpa Domain (wajib; localhost dihitung secure context).
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
        (StatusCode::BAD_REQUEST, "auth local tidak aktif (lihat --auth)").into_response()
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
        None => return (StatusCode::BAD_REQUEST, "body JSON object wajib").into_response(),
    };
    let id = body.remove("id").and_then(|v| v.as_str().map(str::to_string));
    let email = body.remove("email").and_then(|v| v.as_str().map(str::to_string));
    let password = match body.remove("password").and_then(|v| v.as_str().map(str::to_string)) {
        Some(p) => p,
        None => return (StatusCode::BAD_REQUEST, "password wajib").into_response(),
    };
    match local.register(id, email, &password, body).await {
        Ok(doc) => (StatusCode::CREATED, Json(serde_json::json!({ "id": doc.id }))).into_response(),
        Err(e) => (StatusCode::from_u16(e.status_code()).unwrap(), e.to_string()).into_response(),
    }
}

/// Komponen proof DPoP untuk penerbitan (login/refresh): htu = URI absolut endpoint ini.
/// Host hilang / proof rusak → gagal di bind_dpop (fail-closed).
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
        None => return (StatusCode::BAD_REQUEST, "body JSON object wajib").into_response(),
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
                // Samarkan: login vs password vs dpop salah tak dibedakan (anti enumerasi).
                Err(_) => (StatusCode::UNAUTHORIZED, "kredensial salah").into_response(),
            }
        }
        _ => (StatusCode::BAD_REQUEST, "login + password wajib").into_response(),
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
        // Reuse/expired/asing: cabut cookie + tolak (fail-closed).
        Err(_) => (StatusCode::UNAUTHORIZED, clear_cookies(), "sesi tidak valid").into_response(),
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

// --- Realtime: WS dua-arah + SSE satu-arah (HTTP_CONTRACT.md §realtime) ---
//
// WS:  -> {"type":"subscribe","key","collection","options"?, "group"?, "token"?}
//      -> {"type":"unsubscribe","key"} | {"type":"ping"} | {"type":"auth","token"}
//      <- {"type":"ready","key"} | {"type":"change","key","kind","doc"}
//      <- {"type":"error","key"?,"message"} | {"type":"pong"}
// SSE: GET /api/stream/<coll>?options=&token= → event: change, data: {kind,doc}.
// Token via Bearer/cookie diutamakan; ?token= fallback (tercatat di URL —
// disarankan hanya via TLS; lihat fase TLS). Batas 100 subs/koneksi WS.

/// Batas ukuran pesan WS masuk (anti banjir frame).
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
        // Satu tugas: pesan soket + drain semua subscription (tanpa select! dinamis).
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
                    if !ws_send(&mut socket, ws_err(None, "pesan bukan JSON")).await {
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
                        if !ws_send(&mut socket, ws_err(None, "key + collection wajib")).await {
                            break;
                        }
                        continue;
                    }
                    if subs.len() >= realtime::MAX_SUBS_PER_SOCKET && !subs.contains_key(&key) {
                        if !ws_send(&mut socket, ws_err(Some(&key), "batas subscription")).await {
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
                    // Token per-subscribe (pola legacy authData) mengalahkan auth koneksi.
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
                                "subscribe gagal"
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
                    if !ws_send(&mut socket, ws_err(None, "type tak dikenal")).await {
                        break;
                    }
                }
            }
        }
        // Drain semua subscription ke soket.
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
        _ => return (StatusCode::BAD_REQUEST, "SSE hanya untuk endpoint koleksi").into_response(),
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
        Err(msg) => return (StatusCode::BAD_REQUEST, msg).into_response(),
    };
    let group = matches!(q.get("group").map(|g| g.as_str()), Some("1") | Some("true"));
    let db = s.db.read().await.clone();
    let policy = s.policy.get().await;
    let sub = match realtime::subscribe(db, policy, auth, realtime::SubSpec { collection, options, group }).await {
        Ok(sub) => sub,
        Err(e) if matches!(e, hakobackend_core::AppError::PermissionDenied) => return forbidden(),
        Err(e) => return (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    };
    // Bridge: Subscription (pemilik task sumber) hidup di tugas penerus; bila
    // klien putus, send gagal → tugas berhenti → sumber di-abort (rantai rapi).
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

// --- OAuth GitHub, pola BFF: browser redirect, token tak pernah ke browser ---

async fn github_login(State(s): State<AppState>) -> impl IntoResponse {
    match s.github.read().await.clone() {
        None => (StatusCode::BAD_REQUEST, "oauth github tidak dikonfigurasi").into_response(),
        Some(g) => match g.login_url().await {
            Ok(url) => Redirect::to(&url).into_response(),
            Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
        },
    }
}

async fn github_callback(
    State(s): State<AppState>,
    Query(q): Query<HashMap<String, String>>,
) -> impl IntoResponse {
    let (g, local) = match (s.github.read().await.clone(), s.local.read().await.clone()) {
        (Some(g), Some(l)) => (g, l),
        _ => return (StatusCode::BAD_REQUEST, "oauth github butuh kredensial env + `local` dalam rantai").into_response(),
    };
    let (code, state) = match (q.get("code").cloned(), q.get("state").cloned()) {
        (Some(c), Some(st)) => (c, st),
        _ => return (StatusCode::BAD_REQUEST, "code + state wajib").into_response(),
    };
    // Samarkan semua kegagalan (code jelek, state basi, github down).
    let (uid, email, login) = match g.callback(&code, &state).await {
        Ok(v) => v,
        Err(_) => return (StatusCode::UNAUTHORIZED, "verifikasi github gagal").into_response(),
    };
    let mut profile = HashMap::new();
    if let Some(l) = login {
        profile.insert("login".to_string(), serde_json::Value::String(l));
    }
    match local.login_external(&uid, email, profile).await {
        Ok((_ctx, tokens)) => {
            let mut h = session_cookies(&local, &tokens);
            // BFF: browser kembali ke app dengan cookie sesi; tanpa token di URL.
            h.insert(header::LOCATION, g.after_login().parse().unwrap());
            (StatusCode::FOUND, h).into_response()
        }
        Err(e) => (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()).into_response(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn dpop_tabel_keputusan() {
        use DpopAction::*;
        // Off / non-lokal selalu lolos.
        assert_eq!(dpop_action(DpopMode::Off, true, true), Keep);
        assert_eq!(dpop_action(DpopMode::Require, false, false), Keep);
        // Require tanpa proof = strip; dengan proof = verifikasi.
        assert_eq!(dpop_action(DpopMode::Require, true, false), Strip);
        assert_eq!(dpop_action(DpopMode::Require, true, true), MustVerify);
        // Accept: bearer fallback tanpa proof, verifikasi bila ada proof.
        assert_eq!(dpop_action(DpopMode::Accept, true, false), Keep);
        assert_eq!(dpop_action(DpopMode::Accept, true, true), MustVerify);
    }

    #[test]
    fn shim_legacy_index() {        assert_eq!(legacy_index_collection("posts/index").as_deref(), Some("posts"));
        assert_eq!(
            legacy_index_collection("/posts/p1/revisions/index/").as_deref(),
            Some("posts/p1/revisions")
        );
        // Koleksi sungguhan bernama "index" tidak dibajak.
        assert_eq!(legacy_index_collection("index"), None);
        assert_eq!(legacy_index_collection("posts"), None);
    }

    #[test]
    fn kunci_rate_limit() {
        use std::net::{IpAddr, Ipv4Addr, SocketAddr};
        let peer: SocketAddr = (IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), 1234).into();
        let plain = HeaderMap::new();
        // Tanpa trust_proxy: selalu IP peer (XFF spoof diabaikan).
        let mut spoof = HeaderMap::new();
        spoof.insert("x-forwarded-for", "1.2.3.4".parse().unwrap());
        assert_eq!(client_key(&spoof, peer, false), "10.0.0.1");
        assert_eq!(client_key(&plain, peer, false), "10.0.0.1");
        // Dengan trust_proxy: entri pertama XFF.
        assert_eq!(client_key(&spoof, peer, true), "1.2.3.4");
        // XFF kosong/rusak → fallback peer.
        assert_eq!(client_key(&plain, peer, true), "10.0.0.1");
    }

    #[test]
    fn skema_base_uri_mengikuti_tls() {
        let mut h = HeaderMap::new();
        h.insert(header::HOST, "api.x.id:8080".parse().unwrap());
        assert_eq!(base_uri(false, &h, "/api/auth/login"), "http://api.x.id:8080/api/auth/login");
        assert_eq!(base_uri(true, &h, "/api/auth/login"), "https://api.x.id:8080/api/auth/login");
        // Host hilang → "unknown" (fail-closed di verifikasi htu).
        assert_eq!(base_uri(true, &HeaderMap::new(), "/x"), "https://unknown/x");
    }
}

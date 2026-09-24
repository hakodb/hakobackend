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
mod realtime;
mod tenant_auth;
mod tenant_policy;

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
use config::{Args, DEFAULT_CONFIG_TEMPLATE, ServiceMode, resolve, validate};
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
    /// Service mode (phase B): managed | open | single.
    mode: ServiceMode,
    /// Pinned tenant in single mode (None otherwise).
    service_tenant: Option<String>,
    /// Role scoped to administer one tenant (default "tenant-admin").
    tenant_admin_role: String,
    /// CLI flags for reload (file re-read, flags still win).
    cli: Args,
    /// PATCH coalescer (active only with --coalesce-writes).
    coalescer: Arc<coalesce::Coalescer>,
    /// Whether the coalescer accepts merges (snapshot of the flag at boot).
    coalesce_on: bool,
    /// Per-tenant policy docs (`__tenant_policies`), cached with TTL.
    tenant_policies: Arc<tenant_policy::TenantPolicies>,
    /// Per-tenant auth bundles (chains built from `__auth_profiles`).
    tenant_auths: Arc<tenant_auth::TenantAuths>,
}

impl AppState {
    /// Policy for this caller: the tenant's own doc when present, else global.
    pub async fn policy_for(&self, auth: Option<&AuthContext>) -> Arc<PolicyFile> {
        if let Some(t) = self.effective_tenant(auth) {
            if let Some(p) = self.tenant_policies.get(&t).await {
                return p;
            }
        }
        self.policy.get().await
    }

    /// Tenant scope for data + policy. Single mode pins EVERY caller
    /// (even anonymous) to the deployment tenant; otherwise the caller's
    /// verified claim decides (never the raw hint).
    fn effective_tenant(&self, auth: Option<&AuthContext>) -> Option<String> {
        if self.mode == ServiceMode::Single {
            return self.service_tenant.clone();
        }
        caller_tenant(auth)
    }

    /// Hint after mode pinning: single mode ignores client hints.
    fn pin_hint(&self, hint: Option<String>) -> Option<String> {
        pin_hint_for(self.mode, self.service_tenant.as_deref(), hint)
    }

    /// Org admin, or a tenant admin bound to THIS tenant. The binding is
    /// the verified JWT claim (phase A attribution), never the request hint.
    fn tenant_scoped_admin(&self, auth: Option<&AuthContext>, slug: &str) -> bool {
        tenant_scoped_admin_for(&self.admin_role, &self.tenant_admin_role, auth, slug)
    }

    /// Registry endpoints make no sense pinned: single mode serves one tenant.
    fn single_registry_guard(&self) -> Option<Response> {
        (self.mode == ServiceMode::Single)
            .then(|| err(StatusCode::FORBIDDEN, "single-tenant mode: no tenant registry"))
    }
}

/// Pure core for tests: single mode pins, other modes pass through.
fn pin_hint_for(mode: ServiceMode, pinned: Option<&str>, hint: Option<String>) -> Option<String> {
    match mode {
        ServiceMode::Single => pinned.map(str::to_string),
        _ => hint,
    }
}

/// Pure core for tests: global admin role, or the tenant role + matching claim.
fn tenant_scoped_admin_for(
    admin_role: &str,
    tenant_admin_role: &str,
    auth: Option<&AuthContext>,
    slug: &str,
) -> bool {
    let Some(a) = auth else { return false };
    if a.roles.iter().any(|r| r == admin_role) {
        return true;
    }
    a.tenant.as_deref() == Some(slug) && a.roles.iter().any(|r| r == tenant_admin_role)
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

/// Single-mode bootstrap: pinned tenant doc + owned local profile.
/// Insert-only (existing docs win — operator edits stay authoritative).
async fn ensure_single_tenant(db: &Arc<dyn Database>, pinned: &str) {
    use hakobackend_core::tenant::TENANTS_COLLECTION;
    let mut pdata = HashMap::new();
    pdata.insert("owner_tenant".to_string(), serde_json::Value::String(pinned.into()));
    pdata.insert("shared".to_string(), serde_json::Value::Bool(false));
    pdata.insert("spec".to_string(), serde_json::Value::String("local".into()));
    pdata.insert("config".to_string(), serde_json::Value::Object(Default::default()));
    let p = db
        .insert(
            tenant_auth::AUTH_PROFILES_COLLECTION,
            Doc { id: pinned.into(), data: pdata },
        )
        .await;
    let mut tdata = HashMap::new();
    tdata.insert("auth_profile".to_string(), serde_json::Value::String(pinned.into()));
    let t = db.insert(TENANTS_COLLECTION, Doc { id: pinned.into(), data: tdata }).await;
    // Insert-only: AlreadyExists is the expected steady state; anything
    // else is real (boot fails loudly downstream, but say it here too).
    let real_err = [&p, &t].iter().any(|r| {
        matches!(r, Err(e) if !matches!(e, hakobackend_core::AppError::AlreadyExists))
    });
    if real_err {
        eprintln!("[ub] WARN single mode: could not ensure tenant `{pinned}` ({p:?} / {t:?})");
    } else if p.is_ok() || t.is_ok() {
        eprintln!("[ub] single mode: provisioned tenant `{pinned}` + owned local profile");
    }
}

/// The only place that knows the driver list. New driver = 1 new arm.
/// Unimplemented drivers return a clear message, not a panic.
async fn open_driver(driver: &str, path: &str) -> Result<Arc<dyn Database>, String> {
    use hakobackend_core::ttl::TtlDb;
    // Every driver is wrapped once: TTL expiry filters uniformly, and the
    // sweeper below owns the wrapped handle (reload swaps it too).
    let db: Arc<dyn Database> = match driver {
        "hako" => HakoDb::open(path).map(|db| Arc::new(TtlDb::new(db)) as Arc<dyn Database>).map_err(|e| e.to_string())?,
        "postgres" => PgDb::open(path).await.map(|db| Arc::new(TtlDb::new(db)) as Arc<dyn Database>).map_err(|e| e.to_string())?,
        "sqlite" => SqliteDb::open(path).await.map(|db| Arc::new(TtlDb::new(db)) as Arc<dyn Database>).map_err(|e| e.to_string())?,
        "mysql" => MysqlDb::open(path).await.map(|db| Arc::new(TtlDb::new(db)) as Arc<dyn Database>).map_err(|e| e.to_string())?,
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
    let db: Arc<dyn Database> = open_driver(&cfg.driver, &cfg.data).await.expect("open database");
    println!("[ub] driver={} data={} config={} mode={}{}", cfg.driver, cfg.data, if cfg.source.is_empty() { "(default+flag)" } else { &cfg.source }, cfg.service_mode.as_str(), cfg.service_tenant.as_deref().map(|t| format!(" tenant={t}")).unwrap_or_default());
    // Single mode has no registry: the pinned tenant + its owned local
    // profile are ensured at boot (idempotent; existing docs untouched).
    if cfg.service_mode == ServiceMode::Single {
        if let Some(pinned) = cfg.service_tenant.as_deref() {
            ensure_single_tenant(&db, pinned).await;
        }
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
    let tenant_identity = policy.identity_snapshot();
    let state = AppState {
        db: db_handle.clone(),
        policy,
        auth: Arc::new(tokio::sync::RwLock::new(Arc::new(chain))),
        local: Arc::new(tokio::sync::RwLock::new(local)),        github: Arc::new(tokio::sync::RwLock::new(github)),
        limits: limits.clone(),
        tls,
        admin_role: cfg.admin_role.clone(),
        mode: cfg.service_mode,
        service_tenant: cfg.service_tenant.clone(),
        tenant_admin_role: cfg.tenant_admin_role.clone(),
        cli,
        coalescer: Arc::new(coalesce::Coalescer::default()),
        coalesce_on: cfg.coalesce_writes,
        tenant_policies: Arc::new(tenant_policy::TenantPolicies::new(db_handle.clone())),
        tenant_auths: Arc::new(tenant_auth::TenantAuths::new(db_handle, tenant_identity)),
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
        .route("/api/tenants", post(tenant_create).get(tenant_list))
        .route("/api/tenants/{slug}", get(tenant_get))
        .route("/api/auth-profiles", get(auth_profile_list))
        .route("/api/auth-profiles/{id}", axum::routing::put(auth_profile_put))
        .route("/api/tenants/{slug}/policy", axum::routing::put(tenant_policy_put).get(tenant_policy_get))
        .route("/api/admin/reload", post(reload))
        .route("/ws", get(ws_handler))
        .route("/api/stream/{*path}", get(sse_handler))
        .layer(middleware::from_fn_with_state(global, limit_mw));
    let auth_routes = Router::new()
        .route("/api/auth/register", post(auth_register))
        .route("/api/tenants/register", post(tenant_register))
        .route("/api/auth/login", post(auth_login))
        .route("/api/auth/refresh", post(auth_refresh))
        .route("/api/auth/logout", post(auth_logout))
        .route("/api/auth/me", get(auth_me))
        .route("/api/auth/github/login", get(github_login))
        .route("/api/auth/github/callback", get(github_callback))
        .layer(middleware::from_fn_with_state(strict, limit_mw));

    let mut app = Router::new()
        .route("/api/health", get(health))
        .route("/api/ready", get(ready))
        .merge(api)
        .merge(auth_routes)
        .layer(middleware::from_fn_with_state(state.clone(), auth_mw))
        // gzip JSON responses, but never the live streams: compressing
        // SSE would buffer flushes and add event latency for little gain
        // (stream frames are already tiny; WS upgrades carry no body).
        .layer(
            tower_http::compression::CompressionLayer::new().compress_when(
                tower_http::compression::predicate::NotForContentType::new("text/event-stream"),
            ),
        )
        // 8 MB bodies (legacy json-limit parity); larger payloads 413.
        .layer(axum::extract::DefaultBodyLimit::max(8 * 1024 * 1024))
        .with_state(state);
    if tls {
        // HSTS only meaningful via TLS (no effect on plain http).
        app = app.layer(tower_http::set_header::SetResponseHeaderLayer::overriding(
            header::STRICT_TRANSPORT_SECURITY,
            header::HeaderValue::from_static("max-age=31536000; includeSubDomains"),
        ));
    }

    let addr = cfg.listen();
    // Graceful drain on Ctrl+C / SIGTERM: in-flight requests finish, then
    // sockets close. Subscriptions abort with their tasks (client resubscribes).
    let shutdown = async {
        let _ = tokio::signal::ctrl_c().await;
        eprintln!("[ub] shutdown: draining connections");
    };
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
        let handle = axum_server::Handle::new();
        let drain = handle.clone();
        tokio::spawn(async move {
            shutdown.await;
            drain.graceful_shutdown(None);
        });
        axum_server::bind_rustls(addr.parse().map_err(|e| format!("[ub] invalid listen address: {e}"))?, rustls)
            .handle(handle)
            .serve(svc)
            .await?;
    } else {
        let listener = tokio::net::TcpListener::bind(&addr).await?;
        println!("[ub] listening on http://{addr}");
        axum::serve(listener, svc).with_graceful_shutdown(shutdown).await?;
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

/// Resolve one token, tenant-aware: with a hint, verify against that
/// tenant's bundle exclusively and bind the result to the hint —
/// cross-tenant replay dies here. Without a hint, legacy global resolve.
async fn resolve_token_for_tenant(
    s: &AppState,
    hint: Option<&str>,
    token: &str,
) -> Option<AuthContext> {
    let hint = hint?;
    let bundle = s.tenant_auths.get(hint).await?;
    // Verify against the tenant chain.
    let mut claims = None;
    for p in &bundle.chain.providers {
        if let Ok(c) = p.verify(token).await {
            claims = Some(c);
            break;
        }
    }
    let claims = claims?;
    let db = s.db.read().await.clone();
    // Bind: local JWTs must carry this tenant; external identities must
    // exist in the tenant user store (uid namespaced per provider).
    match claims.provider {
        "local" => {
            if claims.tenant.as_deref() != Some(hint) {
                return None;
            }
            // Role union must read the TENANT user store (not global):
            // tenant users live in `{hint}__users`, invisible globally.
            let tdb = hakobackend_core::tenant_db::TenantDb::new(db.clone(), hint);
            bundle.chain.resolve(&bundle_identity(s), Some(&tdb), token).await
        }
        _ => {
            let tdb = hakobackend_core::tenant_db::TenantDb::new(db.clone(), hint);
            let uid = format!("{}:{}", claims.provider, claims.uid);
            let ident = bundle_identity(s);
            let hit = tdb.get(&ident.users_collection, &uid).await.ok()??;
            let mut ctx = bundle.chain.resolve(&ident, Some(&tdb), token).await?;
            // Belt and suspenders: the chain resolved, but confirm the
            // membership record is really this tenant's (namespace confusion).
            if hit.id != uid {
                return None;
            }
            ctx.tenant = Some(hint.into());
            Some(ctx)
        }
    }
}

/// Identity snapshot for tenant chains (global policy identity for v1).
fn bundle_identity(s: &AppState) -> hakobackend_policy::Identity {
    s.policy.identity_snapshot()
}

/// Hintless token that carries a tenant claim belongs to that tenant:
/// re-resolve through its bundle so roles come from the tenant store
/// (the global store can't see `{tenant}__users`). Explicit hints already
/// went exclusive in the caller — this only fills the gap when the token
/// itself knows where it belongs. Bundle failure keeps the claim-tagged
/// global ctx (roleless → policy denies).
async fn adopt_claim_tenant(s: &AppState, ctx: Option<AuthContext>, token: &str) -> Option<AuthContext> {
    let t = ctx.as_ref().and_then(|c| c.tenant.clone())?;
    if !hakobackend_core::tenant::is_valid_tenant_slug(&t) {
        return ctx;
    }
    resolve_token_for_tenant(s, Some(&t), token).await.or(ctx)
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
    let dpop_proof = headers.get("DPoP").and_then(|v| v.to_str().ok()).map(str::to_string);
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
                .is_some_and(|p| local.check_dpop(p, method, uri, tok, binding.as_deref()).is_ok()),
        };
        if !ok {
            ctx = None;
        }
    }
    ctx
}

/// Auth middleware: Bearer (API clients) else access cookie (browser BFF) →
/// chain resolve → DPoP enforcement (local tokens) → `Extension<Option<AuthContext>>`.
/// No token / DPoP failure = anonymous (policy rules decide, not middleware).
async fn auth_mw(State(s): State<AppState>, mut req: Request, next: Next) -> Response {
    // Tenant hint (header/query) selects the auth bundle BEFORE verification.
    // Single mode pins the deployment tenant: client hints are ignored.
    let hint = s.pin_hint(
        req.headers()
            .get("x-tenant")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| {
                req.uri().query().and_then(|q| {
                    q.split('&').find_map(|pair| {
                        let (k, v) = pair.split_once('=')?;
                        (k == "tenant").then(|| v.to_string())
                    })
                })
            })
            .map(|h| h.trim().to_string())
            .filter(|h| hakobackend_core::tenant::is_valid_tenant_slug(h)),
    );
    let from_cookie = read_cookie(req.headers(), ACCESS_COOKIE);
    let token = bearer(req.headers()).or_else(|| from_cookie.clone());
    let method = req.method().to_string();
    let uri = base_uri(s.tls, req.headers(), req.uri().path());
    let ctx = match &token {
        // Tenant hint (if any) selects the bundle exclusively; without one
        // the legacy global chain resolves, then a tenant claim (if the
        // token carries one) adopts into its bundle for role resolution.
        Some(t) => match hint.as_deref() {
            Some(h) => resolve_token_for_tenant(&s, Some(h), t).await,
            None => {
                let c = resolve_token(&s, t).await;
                adopt_claim_tenant(&s, c, t).await
            }
        },
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
    err(StatusCode::FORBIDDEN, "Permission denied by policy")
}

fn unauthorized() -> Response {
    err(StatusCode::UNAUTHORIZED, "authentication required")
}

/// Legacy wire shape: every failure is JSON `{error}` (writes add `code`).
fn err(status: StatusCode, msg: impl ToString) -> Response {
    (status, Json(serde_json::json!({ "error": msg.to_string() }))).into_response()
}

/// 500 without driver internals: DB errors carry table/DSN hints an
/// unauthenticated prober must never see (S3 audit). Validation messages
/// stay specific; only the opaque Internal variant is scrubbed here.
fn err_internal() -> Response {
    err(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
}

fn err_code(status: StatusCode, msg: impl ToString, code: &str) -> Response {
    (
        status,
        Json(serde_json::json!({ "error": msg.to_string(), "code": code })),
    )
        .into_response()
}

/// Caller tenant from identity only (never client input); None = legacy ns.
fn caller_tenant(auth: Option<&AuthContext>) -> Option<String> {
    hakobackend_core::tenant::tenant_of(auth)
}

/// Logical path → stored name for this caller.
fn stored(tenant: Option<&str>, logical: &str) -> String {
    hakobackend_core::tenant::resolve_collection(tenant, logical)
}

/// Internal collections (`__*`, incl. `__tenants`) are never addressable
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
    Json(serde_json::json!({ "status": "ok", "db": "hakodb" }))
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
    // Drain coalesced PATCHes into the fresh driver before serving it.
    {
        let dbh = s.db.read().await.clone();
        s.coalescer
            .flush_all(|coll, id, body| {
                let dbh = dbh.clone();
                async move {
                    dbh.set(&coll, &id, Doc { id: id.clone(), data: body }, true)
                        .await
                        .map(|_| ())
                        .map_err(|e| e.to_string())
                }
            })
            .await;
    }
    // Rate-limit numbers + auto-provision hot-reload too (no restart).
    s.limits.global.set_quota(Quota::per_minute(cfg.limit_global.0, cfg.limit_global.1));
    s.limits.auth.set_quota(Quota::per_minute(cfg.limit_auth.0, cfg.limit_auth.1));
    auto_provision(&s.db.read().await.clone(), &s.policy.get().await, &cfg.indexes).await;
    let msg = format!("reload ok: driver={} data={} auth={}", cfg.driver, cfg.data, cfg.auth.as_deref().unwrap_or("off"));
    eprintln!("[ub] {msg}");
    msg.into_response()
}

async fn list_collections(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
) -> impl IntoResponse {
    // Tenant callers see their own namespace as logical names; internals
    // never leak. Tenantless callers keep the legacy full list.
    let tenant = s.effective_tenant(auth.as_ref());
    match s.db.read().await.list_collections().await {
        Ok(c) => {
            let out: Vec<String> = hakobackend_core::tenant::visible_collections(c, tenant.as_deref())
                .into_iter()
                .map(|(_, logical)| logical)
                .collect();
            Json(serde_json::to_value(out).unwrap()).into_response()
        }
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
    let policy = s.policy_for(auth.as_ref()).await;
    if !policy.allow(auth.as_ref(), &name, Method::Create, None) {
        return forbidden();
    }
    let tenant = s.effective_tenant(auth.as_ref());
    match s.db.read().await.ensure_collection(&stored(tenant.as_deref(), &name)).await {
        Ok(()) => Json(serde_json::json!({ "success": true })).into_response(),
                Err(_) => err_internal(),
    }
}

/// Tenant policy docs (`__tenant_policies/{slug}`): validated TOML +
/// version bump. Org admins, or the tenant's own admin (SaaS scoping).
async fn tenant_policy_put(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(slug): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if !s.tenant_scoped_admin(auth.as_ref(), &slug) {
        return forbidden();
    }
    if !hakobackend_core::tenant::is_valid_tenant_slug(&slug) {
        return err(StatusCode::BAD_REQUEST, "invalid tenant slug");
    }
    if s.mode == ServiceMode::Single && Some(slug.as_str()) != s.service_tenant.as_deref() {
        return err(StatusCode::BAD_REQUEST, "single-tenant mode serves only the pinned tenant");
    }
    let toml = match body.get("policy_toml").and_then(|v| v.as_str()) {
        Some(t) => t.to_string(),
        None => return err(StatusCode::BAD_REQUEST, "body requires {policy_toml}"),
    };
    match s.tenant_policies.put(&slug, &toml).await {
        Ok(version) => {
            s.tenant_auths.invalidate(&slug);
            Json(serde_json::json!({ "success": true, "version": version })).into_response()
        }
        Err(e) => err(StatusCode::BAD_REQUEST, e),
    }
}

async fn tenant_policy_get(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    if !s.tenant_scoped_admin(auth.as_ref(), &slug) {
        return forbidden();
    }
    match s.tenant_policies.get_raw(&slug).await {
        Some((version, toml)) => Json(serde_json::json!({ "version": version, "policy_toml": toml })).into_response(),
        None => err(StatusCode::NOT_FOUND, "no tenant policy (global applies)"),
    }
}

/// Auth profiles (`__auth_profiles/{id}`): named, shareable auth bundles.
/// `{owner_tenant: string|null, shared: bool, spec: string, config: {...}}`.
/// Org admins manage all; a tenant admin manages profiles owned by its own
/// tenant (owner_tenant must equal the claim tenant, never null).
async fn auth_profile_put(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(id): Path<String>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = s.single_registry_guard() {
        return r;
    }
    let is_admin = auth.as_ref().is_some_and(|a| a.roles.iter().any(|r| r == &s.admin_role));
    if !is_admin {
        let own = auth.as_ref().and_then(|a| a.tenant.clone());
        let has_role =
            auth.as_ref().is_some_and(|a| a.roles.iter().any(|r| r == &s.tenant_admin_role));
        let target = body.get("owner_tenant").and_then(|v| v.as_str());
        if !(has_role && own.as_deref().is_some_and(|o| Some(o) == target)) {
            return forbidden();
        }
    }
    if id.trim().is_empty() || id.len() > 128 {
        return err(StatusCode::BAD_REQUEST, "invalid profile id");
    }
    let spec = match body.get("spec").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return err(StatusCode::BAD_REQUEST, "body requires {spec}"),
    };
    // Validate the spec grammar now (fail-closed, not at first use).
    match hakobackend_auth_core::AuthSpec::parse(&spec) {
        hakobackend_auth_core::AuthSpec::File(_) => {
            return err(StatusCode::BAD_REQUEST, "file specs stay global-only")
        }
        _ => {}
    }
    let db = s.db.read().await.clone();
    let mut data = HashMap::new();
    data.insert("owner_tenant".into(), body.get("owner_tenant").cloned().unwrap_or(serde_json::Value::Null));
    data.insert("shared".into(), body.get("shared").cloned().unwrap_or(serde_json::json!(false)));
    data.insert("spec".into(), serde_json::Value::String(spec));
    data.insert("config".into(), body.get("config").cloned().unwrap_or(serde_json::json!({})));
    match db
        .set(
            tenant_auth::AUTH_PROFILES_COLLECTION,
            &id,
            Doc { id: id.clone(), data },
            false,
        )
        .await
    {
        Ok(_) => {
            // Profiles fan out to unknown tenant sets: clear all bundles.
            s.tenant_auths.invalidate_all();
            Json(serde_json::json!({ "success": true, "id": id })).into_response()
        }
        Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
    }
}

async fn auth_profile_list(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
) -> impl IntoResponse {
    if let Some(r) = s.single_registry_guard() {
        return r;
    }
    let is_admin = auth.as_ref().is_some_and(|a| a.roles.iter().any(|r| r == &s.admin_role));
    // Tenant admins see their own + org-global profiles (still redacted);
    // anyone else is denied (the shape list is itself sensitive).
    let scope: Option<String> = if is_admin {
        None
    } else {
        let has_role =
            auth.as_ref().is_some_and(|a| a.roles.iter().any(|r| r == &s.tenant_admin_role));
        match (has_role, auth.as_ref().and_then(|a| a.tenant.clone())) {
            (true, Some(o)) => Some(o),
            _ => return forbidden(),
        }
    };
    // Secrets never leave: redact config values, show only value SHAPE.
    match s.db.read().await.list(tenant_auth::AUTH_PROFILES_COLLECTION, &QueryOptions::default()).await {
        Ok(docs) => {
            let out: Vec<_> = docs
                .into_iter()
                .filter(|d| match &scope {
                    None => true,
                    Some(o) => {
                        let owner = d.data.get("owner_tenant").and_then(|v| v.as_str());
                        owner.is_none() || owner == Some(o.as_str())
                    }
                })
                .map(|d| {
                    serde_json::json!({
                        "id": d.id,
                        "owner_tenant": d.data.get("owner_tenant").cloned().unwrap_or(serde_json::Value::Null),
                        "shared": d.data.get("shared").cloned().unwrap_or(serde_json::json!(false)),
                        "spec": d.data.get("spec").cloned().unwrap_or(serde_json::json!("")),
                        "config_keys": d.data.get("config").and_then(|c| c.as_object()).map(|m| {
                            m.keys().cloned().collect::<Vec<_>>()
                        }).unwrap_or_default(),
                    })
                })
                .collect();
            Json(serde_json::to_value(out).unwrap()).into_response()
        }
            Err(_) => err_internal(),
    }
}

// --- Tenants (admin): provision + list. Uniqueness is structural —
// provisioning uses insert (conflict = slug taken). Slugs are validated;
// the stored prefix is the slug itself, so no two tenants can collide.
async fn tenant_create(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if let Some(r) = s.single_registry_guard() {
        return r;
    }
    if !auth.as_ref().is_some_and(|a| a.roles.iter().any(|r| r == &s.admin_role)) {
        return forbidden();
    }
    let slug = match body.get("slug").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return err(StatusCode::BAD_REQUEST, "body requires {slug}"),
    };
    if !hakobackend_core::tenant::is_valid_tenant_slug(&slug) {
        return err(StatusCode::BAD_REQUEST, "slug must match ^[a-z0-9][a-z0-9-]{0,62}$");
    }
    let db = s.db.read().await.clone();
    // Optional link to an auth profile (verified at use time, not here —
    // dangling refs simply fall back to the global chain).
    let mut data = HashMap::new();
    if let Some(p) = body.get("auth_profile").and_then(|v| v.as_str()).filter(|v| !v.is_empty()) {
        data.insert("auth_profile".to_string(), serde_json::Value::String(p.into()));
    }
    match db
        .insert(
            hakobackend_core::tenant::TENANTS_COLLECTION,
            Doc { id: slug.clone(), data },
        )
        .await
    {
        Ok(_) => {
            // New tenant: nothing cached yet, but be explicit.
            s.tenant_auths.invalidate(&slug);
            Json(serde_json::json!({ "success": true, "slug": slug })).into_response()
        }
        Err(e) => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
    }
}

async fn tenant_list(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
) -> impl IntoResponse {
    if let Some(r) = s.single_registry_guard() {
        return r;
    }
    if !auth.as_ref().is_some_and(|a| a.roles.iter().any(|r| r == &s.admin_role)) {
        return forbidden();
    }
    match s
        .db
        .read()
        .await
        .list(hakobackend_core::tenant::TENANTS_COLLECTION, &QueryOptions::default())
        .await
    {
        Ok(docs) => {
            let slugs: Vec<_> = docs.into_iter().map(|d| d.id).collect();
            Json(serde_json::to_value(slugs).unwrap()).into_response()
        }
                Err(_) => err_internal(),
    }
}

/// One tenant's own record (portal + tenant-admin bootstrap): org admins
/// see any, a tenant admin sees its own. Never the full list.
async fn tenant_get(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Path(slug): Path<String>,
) -> impl IntoResponse {
    if !s.tenant_scoped_admin(auth.as_ref(), &slug) {
        return forbidden();
    }
    if !hakobackend_core::tenant::is_valid_tenant_slug(&slug) {
        return err(StatusCode::BAD_REQUEST, "invalid tenant slug");
    }
    match s.db.read().await.get(hakobackend_core::tenant::TENANTS_COLLECTION, &slug).await {
        Ok(Some(doc)) => Json(serde_json::json!({
            "slug": doc.id,
            "auth_profile": doc.data.get("auth_profile").cloned().unwrap_or(serde_json::Value::Null),
        }))
        .into_response(),
        Ok(None) => err(StatusCode::NOT_FOUND, "unknown tenant"),
        Err(_) => err_internal(),
    }
}

// --- Open-mode self-registration: tenant + owned local profile + owner ---
//
// Public (strict auth rate limit applies). Creates, in order: profile
// `__auth_profiles/{slug}` (owner-only, spec local), `__tenants/{slug}`,
// the first user (stamped with the tenant-admin role), and a starter
// policy granting that role full reign. Any failure best-effort rolls
// back what was created (orphans would be admin-surgery otherwise).
async fn tenant_register(
    State(s): State<AppState>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    if s.mode != ServiceMode::Open {
        return err(StatusCode::FORBIDDEN, "self-registration is disabled (open mode only)");
    }
    let slug = match body.get("slug").and_then(|v| v.as_str()) {
        Some(v) => v.to_string(),
        None => return err(StatusCode::BAD_REQUEST, "body requires {slug}"),
    };
    if !hakobackend_core::tenant::is_valid_tenant_slug(&slug) {
        return err(StatusCode::BAD_REQUEST, "slug must match ^[a-z0-9][a-z0-9-]{0,62}$");
    }
    let map = match body.as_object() {
        Some(m) => m,
        None => return err(StatusCode::BAD_REQUEST, "JSON object body required"),
    };
    let id = map.get("id").and_then(|v| v.as_str()).map(str::to_string);
    let email = map.get("email").and_then(|v| v.as_str()).map(str::to_string);
    let password = match map.get("password").and_then(|v| v.as_str()) {
        Some(p) => p.to_string(),
        None => return err(StatusCode::BAD_REQUEST, "password required"),
    };
    let db = s.db.read().await.clone();
    let ident = s.policy.get().await.identity.clone();
    // Best-effort rollback (each step undoes the previous inserts).
    // Cloned handles: the closure must not move `slug`/`s` (used below).
    let slug_c = slug.clone();
    let auths = &s.tenant_auths;
    let users_c = ident.users_collection.clone();
    let rollback = move |db: &Arc<dyn Database>, user: Option<String>| {
        let db = db.clone();
        let users = users_c.clone();
        let slug_c = slug_c.clone();
        async move {
            if let Some(u) = user {
                let tdb = hakobackend_core::tenant_db::TenantDb::new(db.clone(), &slug_c);
                let _ = tdb.delete(&users, &u).await;
            }
            let _ = db.delete(hakobackend_core::tenant::TENANTS_COLLECTION, &slug_c).await;
            let _ = db.delete(tenant_auth::AUTH_PROFILES_COLLECTION, &slug_c).await;
            auths.invalidate(&slug_c);
        }
    };

    let mut pdata = HashMap::new();
    pdata.insert("owner_tenant".to_string(), serde_json::Value::String(slug.clone()));
    pdata.insert("shared".to_string(), serde_json::Value::Bool(false));
    pdata.insert("spec".to_string(), serde_json::Value::String("local".into()));
    pdata.insert("config".to_string(), serde_json::Value::Object(Default::default()));
    if let Err(e) = db
        .insert(tenant_auth::AUTH_PROFILES_COLLECTION, Doc { id: slug.clone(), data: pdata })
        .await
    {
        return match e {
            hakobackend_core::AppError::AlreadyExists => err(StatusCode::BAD_REQUEST, "slug taken"),
            _ => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
        };
    }
    let mut tdata = HashMap::new();
    tdata.insert("auth_profile".to_string(), serde_json::Value::String(slug.clone()));
    if let Err(e) = db
        .insert(
            hakobackend_core::tenant::TENANTS_COLLECTION,
            Doc { id: slug.clone(), data: tdata },
        )
        .await
    {
        rollback(&db, None).await;
        return match e {
            hakobackend_core::AppError::AlreadyExists => err(StatusCode::BAD_REQUEST, "slug taken"),
            _ => err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code()),
        };
    }
    s.tenant_auths.invalidate(&slug);
    let local = match s.tenant_auths.get(&slug).await.and_then(|b| b.local.clone()) {
        Some(l) => l,
        None => {
            rollback(&db, None).await;
            return err(
                StatusCode::INTERNAL_SERVER_ERROR,
                "server cannot mint tenant sessions (UB_LOCAL_JWT_SECRET unset?)",
            );
        }
    };
    let owner = match local.register(id, email, &password, HashMap::new()).await {
        Ok(doc) => doc,
        Err(e) => {
            rollback(&db, None).await;
            return err_code(StatusCode::from_u16(e.status_code()).unwrap(), e.to_string(), e.code());
        }
    };
    // Stamp the owner with the tenant-admin role (register strips roles by
    // design — only the server may grant here, once, at creation).
    let tdb = hakobackend_core::tenant_db::TenantDb::new(db.clone(), &slug);
    let stamped = match tdb.get(&ident.users_collection, &owner.id).await {
        Ok(Some(mut doc)) => {
            doc.data.insert(
                ident.role_field.clone(),
                serde_json::Value::Array(vec![serde_json::Value::String(
                    s.tenant_admin_role.clone(),
                )]),
            );
            tdb.set(&ident.users_collection, &owner.id, doc, false).await.map(|_| ()).map_err(|e| e.to_string())
        }
        Ok(None) => Err("owner doc vanished after register".into()),
        Err(e) => Err(e.to_string()),
    };
    if let Err(e) = stamped {
        rollback(&db, Some(owner.id.clone())).await;
        return err(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    if let Err(e) = s.tenant_policies.put(&slug, &tenant_policy::starter_policy(&s.tenant_admin_role)).await
    {
        rollback(&db, Some(owner.id.clone())).await;
        return err(StatusCode::INTERNAL_SERVER_ERROR, e);
    }
    (StatusCode::CREATED, Json(serde_json::json!({ "slug": slug, "id": owner.id }))).into_response()
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
    let policy = s.policy_for(auth.as_ref()).await;
    let db = s.db.read().await.clone();
    let tenant = s.effective_tenant(auth.as_ref());
    match parse_collection_path(&path) {
        PathKind::Document { collection, id } => {
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, Some(&id)) {
                return r;
            }
            let stored = stored(tenant.as_deref(), &collection);
            match db.get(&stored, &id).await {
                Ok(maybe_doc) => {
                    // Coalescer overlay: pending PATCHes merge over storage
                    // so read-your-write holds inside the window.
                    let overlaid = s.coalescer.overlay(
                        &stored,
                        &id,
                        maybe_doc.as_ref().map(|d| d.data.clone()),
                    );
                    let doc = match overlaid {
                        Some(data) => Some(Doc { id: id.clone(), data }),
                        None => maybe_doc,
                    };
                    match doc {
                        Some(doc) => {
                            if !policy.allow(auth.as_ref(), &collection, Method::Get, Some(&doc)) {
                                return forbidden();
                            }
                            Json(serde_json::to_value(doc).unwrap()).into_response()
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
            let stored = stored(tenant.as_deref(), &collection);
            match parse_options(&q) {
                Err(msg) => err(StatusCode::BAD_REQUEST, msg),
                Ok(opts) => match db.list(&stored, &opts).await {
                    // Per-doc filter (replacement for the server.ts:233 loop): documents
                    // failing the rule are excluded from the response, with no extra N+1
                    // queries when drivers push rules into queries (phase 3).
                    // Policy sees logical names: one file serves all tenants.
                    Ok(docs) => {
                        let visible: Vec<_> = docs
                            .into_iter()
                            .filter(|d| policy.allow(auth.as_ref(), &collection, Method::Get, Some(d)))
                            .collect();
                        Json(serde_json::to_value(visible).unwrap()).into_response()
                    }
                    Err(_) => err_internal(),
                },
            }
        }
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
    let policy = s.policy_for(auth.as_ref()).await;
    if !policy.allow(auth.as_ref(), &collection, Method::Update, None) {
        return forbidden();
    }
    let db = s.db.read().await.clone();
    let tenant = s.effective_tenant(auth.as_ref());
    let stored = stored(tenant.as_deref(), &collection);
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
    let policy = s.policy_for(auth.as_ref()).await;
    if !policy.allow(auth.as_ref(), &collection, Method::List, None) {
        return forbidden();
    }
    let tenant = s.effective_tenant(auth.as_ref());
    match s.db.read().await.list_indexes(&stored(tenant.as_deref(), &collection)).await {
        Ok(indexes) => Json(serde_json::to_value(indexes).unwrap()).into_response(),
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
    let policy = s.policy_for(auth.as_ref()).await;
    if !policy.allow(auth.as_ref(), &collection, Method::Update, None) {
        return forbidden();
    }
    let tenant = s.effective_tenant(auth.as_ref());
    match s.db.read().await.drop_index(&stored(tenant.as_deref(), &collection), &name).await {
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
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, None) {
                return r;
            }
            let policy = s.policy_for(auth.as_ref()).await;
            let tenant = s.effective_tenant(auth.as_ref());
            let incoming = incoming_doc("", body);
            if !policy.allow(auth.as_ref(), &collection, Method::Create, Some(&incoming)) {
                return forbidden();
            }
            let db = s.db.read().await.clone();
            let stored = stored(tenant.as_deref(), &collection);
            let _ = db.ensure_collection(&stored).await;
            // Atomics collapse (legacy parity) + createdAt/updatedAt stamping.
            let incoming = Doc {
                id: incoming.id,
                data: hakobackend_core::atomics::stamp_new(
                    hakobackend_core::atomics::resolve_for_create(incoming.data),
                ),
            };
            match db.insert(&stored, incoming).await {
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
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, Some(&id)) {
                return r;
            }
            let policy = s.policy_for(auth.as_ref()).await;
            let db = s.db.read().await.clone();
            let tenant = s.effective_tenant(auth.as_ref());
            let stored = stored(tenant.as_deref(), &collection);
            let existing = db.get(&stored, &id).await.ok().flatten();
            // Owner rule evaluated against the existing document (who owns this data?).
            if !policy.allow(auth.as_ref(), &collection, Method::Update, existing.as_ref()) {
                return forbidden();
            }
            // Legacy parity: PATCH on a missing doc is 404 (use PUT to create).
            if merge && existing.is_none() {
                return err(StatusCode::NOT_FOUND, "Document not found");
            }
            // Opt-in coalescing: eligible PATCH bodies merge into the pending
            // entry and ack now; the flusher stores once per window.
            // Atomics/dot-paths bypass (exactness, see coalesce.rs).
            if merge && s.coalesce_on {
                if let Some(obj) = body.as_object() {
                    let map: HashMap<String, serde_json::Value> =
                        obj.clone().into_iter().collect();
                    if coalesce::Coalescer::eligible(&body)
                        && s.coalescer.merge(&stored, &id, map)
                    {
                        return Json(serde_json::json!({ "success": true })).into_response();
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
            // Merge already applied above; store the final body as-is.
            match db.set(&stored, &id, Doc { id: id.clone(), data }, false).await {
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
            if let Some(r) = denied_internal(&collection) {
                return r;
            }
            if let Some(r) = valid_names(&collection, Some(&id)) {
                return r;
            }
            let policy = s.policy_for(auth.as_ref()).await;
            let db = s.db.read().await.clone();
            let tenant = s.effective_tenant(auth.as_ref());
            let stored = stored(tenant.as_deref(), &collection);
            let existing = db.get(&stored, &id).await.ok().flatten();
            if !policy.allow(auth.as_ref(), &collection, Method::Delete, existing.as_ref()) {
                return forbidden();
            }
            let _ = db.ensure_collection(&stored).await;
            match db.delete(&stored, &id).await {
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
    tenant: Option<String>,
    ops: Vec<BatchOpBody>,
    is_tx: bool,
) -> Result<Vec<serde_json::Value>, (StatusCode, String, &'static str)> {
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
    }
    let tenant = tenant.or_else(|| caller_tenant(auth));
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
        let stored = stored(tenant.as_deref(), &op.collection);
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
        gated.push(Gated { body: op, id, existed, existing, stored });
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
                collection: g.stored.clone(),
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
    let policy = s.policy_for(auth.as_ref()).await;
    match run_ops(&db, &policy, auth.as_ref(), s.effective_tenant(auth.as_ref()), ops, false).await {
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
    let policy = s.policy_for(auth.as_ref()).await;
    match run_ops(&db, &policy, auth.as_ref(), s.effective_tenant(auth.as_ref()), ops, true).await {
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
    if let Some(r) = valid_names(&name, None) {
        return r;
    }
    let policy = s.policy_for(auth.as_ref()).await;
    let db = s.db.read().await.clone();
    let tenant = s.effective_tenant(auth.as_ref());
    let collections = match db.list_collections().await {
        Ok(c) => c,
        Err(_) => return err_internal(),
    };
    let mut out = Vec::new();
    for (stored, logical) in hakobackend_core::tenant::visible_collections(collections, tenant.as_deref()) {
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
    if denied_internal(&collection).is_some() {
        return err(StatusCode::FORBIDDEN, "internal collection");
    }
    if let Some(r) = valid_names(&collection, None) {
        return r;
    }
    let policy = s.policy_for(auth.as_ref()).await;
    if !policy.allow(auth.as_ref(), &collection, Method::List, None) {
        return forbidden();
    }
    let db = s.db.read().await.clone();
    let tenant = s.effective_tenant(auth.as_ref());
    let stored = stored(tenant.as_deref(), &collection);
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
                // Reduce guard: sum/avg list into RAM — refuse past the cap.
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
                let docs = match db.list(&stored, &opts).await {
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

/// Optional tenant selector for issuance endpoints (`?tenant=` or body field
/// — header `X-Tenant` is read by the caller where headers exist).
/// An explicit hint selects the tenant bundle EXCLUSIVELY: unknown tenant
/// or no local profile → 400, never a silent global fallback (a typo'd
/// tenant must not mint a global user). No hint → global chain, except in
/// single mode where issuance pins to the deployment tenant.
#[derive(serde::Deserialize)]
struct TenantQuery {
    tenant: Option<String>,
}

fn clean_hint(raw: Option<String>) -> Option<String> {
    raw.map(|h| h.trim().to_string())
        .filter(|h| hakobackend_core::tenant::is_valid_tenant_slug(h))
}

async fn issuance_local(s: &AppState, hint: Option<String>) -> Result<Arc<LocalAuth>, Response> {
    // Single mode pins issuance too: a hintless login still mints inside
    // the deployment tenant, never the global chain.
    match s.pin_hint(clean_hint(hint)) {
        Some(h) => match s.tenant_auths.get(&h).await.and_then(|b| b.local.clone()) {
            Some(l) => Ok(l),
            None => Err(err(StatusCode::BAD_REQUEST, "unknown tenant or no local auth configured")),
        },
        None => local_or_400(s).await,
    }
}

async fn auth_register(
    State(s): State<AppState>,
    Query(q): Query<TenantQuery>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Body `tenant` accepted as convenience; query wins when both present.
    let hint = clean_hint(q.tenant).or_else(|| {
        body.get("tenant").and_then(|v| v.as_str()).and_then(|t| clean_hint(Some(t.to_string())))
    });
    let local = match issuance_local(&s, hint).await {
        Ok(l) => l,
        Err(e) => return e,
    };
    let mut body = match body.as_object() {
        Some(m) => m.clone().into_iter().collect::<HashMap<_, _>>(),
        None => return err(StatusCode::BAD_REQUEST, "JSON object body required"),
    };
    let id = body.remove("id").and_then(|v| v.as_str().map(str::to_string));
    let email = body.remove("email").and_then(|v| v.as_str().map(str::to_string));
    // Routing only — the binding lives in the JWT claim, not the doc.
    body.remove("tenant");
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
    Query(q): Query<TenantQuery>,
    Json(body): Json<serde_json::Value>,
) -> impl IntoResponse {
    // Header wins (proxies strip query strings from logs); body as fallback.
    let hint = headers
        .get("x-tenant")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .and_then(|t| clean_hint(Some(t)))
        .or_else(|| clean_hint(q.tenant))
        .or_else(|| {
            body.get("tenant").and_then(|v| v.as_str()).and_then(|t| clean_hint(Some(t.to_string())))
        });
    let local = match issuance_local(&s, hint).await {
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

async fn auth_refresh(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TenantQuery>,
) -> impl IntoResponse {
    // Refresh re-verifies inside the issuing tenant's bundle: a tenant
    // refresh token is meaningless to the global chain and vice versa.
    let hint = headers
        .get("x-tenant")
        .and_then(|v| v.to_str().ok())
        .map(str::to_string)
        .and_then(|t| clean_hint(Some(t)))
        .or_else(|| clean_hint(q.tenant));
    let local = match issuance_local(&s, hint).await {
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

async fn auth_logout(
    State(s): State<AppState>,
    headers: HeaderMap,
    Query(q): Query<TenantQuery>,
) -> impl IntoResponse {
    // Revoke in the issuing scope: tenant hint → tenant bundle, else global.
    // Best-effort either way; clearing cookies is the real logout.
    if let Some(t) = read_cookie(&headers, REFRESH_COOKIE) {
        match clean_hint(q.tenant) {
            Some(h) => {
                if let Some(b) = s.tenant_auths.get(&h).await {
                    if let Some(local) = &b.local {
                        let _ = local.logout(&t).await;
                    }
                }
            }
            None => {
                if let Some(local) = s.local.read().await.clone() {
                    let _ = local.logout(&t).await;
                }
            }
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
    // Same hint sources as HTTP (header/query); selects the tenant bundle.
    // Single mode pins: the upgrade hint is the deployment tenant.
    let hint = s.pin_hint(
        headers
            .get("x-tenant")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| q.get("tenant").cloned())
            .map(|h| h.trim().to_string())
            .filter(|h| hakobackend_core::tenant::is_valid_tenant_slug(h)),
    );
    let uri = base_uri(s.tls, &headers, "/ws");
    let mut auth = None;
    if let Some(t) = init.clone() {
        auth = match hint.as_deref() {
            Some(h) => resolve_token_for_tenant(&s, Some(h), &t).await,
            None => {
                let c = resolve_token(&s, &t).await;
                adopt_claim_tenant(&s, c, &t).await
            }
        };
    }
    // DPoP-bound tokens must prove at upgrade (per-message proofs don't
    // exist on WS); failure degrades to anonymous like HTTP.
    auth = enforce_dpop(&s, &headers, "GET", &uri, init, auth).await;
    ws.on_upgrade(move |socket| ws_loop(s, socket, auth, hint))
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

async fn ws_loop(s: AppState, mut socket: ws::WebSocket, mut auth: Option<AuthContext>, hint: Option<String>) {
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
                    // Connection hint applies: a tenant-hinted socket resolves
                    // exclusively against that tenant's bundle; hintless
                    // tokens adopt their claim tenant (same as HTTP).
                    let mut next = match hint.as_deref() {
                        Some(h) => resolve_token_for_tenant(&s, Some(h), token).await,
                        None => {
                            let c = resolve_token(&s, token).await;
                            adopt_claim_tenant(&s, c, token).await
                        }
                    };
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
                    // Connection hint applies to the resolve as well.
                    let mut sub_auth = match v.get("token").and_then(|t| t.as_str()) {
                        Some(t) => match hint.as_deref() {
                            Some(h) => resolve_token_for_tenant(&s, Some(h), t).await,
                            None => {
                                let c = resolve_token(&s, t).await;
                                adopt_claim_tenant(&s, c, t).await
                            }
                        },
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
                    let policy = s.policy_for(sub_auth.as_ref()).await;
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
    // Same hint sources as HTTP/WS (?tenant= included, already parsed above).
    // Single mode pins: the stream hint is the deployment tenant.
    let hint = s.pin_hint(
        headers
            .get("x-tenant")
            .and_then(|v| v.to_str().ok())
            .map(str::to_string)
            .or_else(|| q.get("tenant").cloned())
            .map(|h| h.trim().to_string())
            .filter(|h| hakobackend_core::tenant::is_valid_tenant_slug(h)),
    );
    let uri = base_uri(s.tls, &headers, &format!("/api/stream/{path}"));
    let auth = match token.clone() {
        Some(t) => match hint.as_deref() {
            Some(h) => resolve_token_for_tenant(&s, Some(h), &t).await,
            None => {
                let c = resolve_token(&s, &t).await;
                adopt_claim_tenant(&s, c, &t).await
            }
        },
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
    let policy = s.policy_for(auth.as_ref()).await;
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
    // Optional ?tenant=: per-tenant OAuth creds when the tenant links a
    // github profile; otherwise the global flow. Single mode pins.
    let hint = s.pin_hint(
        q.get("tenant")
            .map(|h| h.trim().to_string())
            .filter(|h| hakobackend_core::tenant::is_valid_tenant_slug(h)),
    );
    let g = match hint.as_deref() {
        Some(h) => match s.tenant_auths.get(h).await.and_then(|b| b.github.clone()) {
            Some(g) => g,
            None => return err(StatusCode::BAD_REQUEST, "tenant has no github profile"),
        },
        None => match s.github.read().await.clone() {
            Some(g) => g,
            None => return err(StatusCode::BAD_REQUEST, "github oauth is not configured"),
        },
    };
    match g.login_url_for(hint.as_deref()).await {
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
    // Tenant rides inside `state` (`{tenant}:{rand}`) for per-tenant logins;
    // routeback selects that tenant's bundle, else the global flow.
    // (`_tenant_hint` documents the routing; the bundle object carries it.)
    let (mut _tenant_hint, mut g, mut local) = match state.split_once(':') {
        Some((t, _))
            if hakobackend_core::tenant::is_valid_tenant_slug(t) =>
        {
            let b = match s.tenant_auths.get(t).await {
                Some(b) => b,
                None => return err(StatusCode::UNAUTHORIZED, "github verification failed"),
            };
            let g = match b.github.clone() {
                Some(g) => g,
                None => return err(StatusCode::UNAUTHORIZED, "github verification failed"),
            };
            let l = match b.local.clone() {
                Some(l) => l,
                None => return err(StatusCode::UNAUTHORIZED, "github verification failed"),
            };
            (Some(t.to_string()), g, l)
        }
        _ => {
            let (g, l) = match (s.github.read().await.clone(), s.local.read().await.clone()) {
                (Some(g), Some(l)) => (g, l),
                _ => return err(StatusCode::BAD_REQUEST, "github oauth requires env credentials + `local` in the chain"),
            };
            (None, g, l)
        }
    };
    // Single mode pins OAuth too: a state tenant for anyone else is
    // rejected; a global login resolves to the pinned bundle (400 when it
    // has no github profile — same shape as the login endpoint).
    if s.mode == ServiceMode::Single {
        let pinned = match s.service_tenant.clone() {
            Some(p) => p,
            None => return err_internal(),
        };
        if _tenant_hint.as_deref().is_some_and(|t| t != pinned) {
            return err(StatusCode::UNAUTHORIZED, "github verification failed");
        }
        if _tenant_hint.is_none() {
            let b = match s.tenant_auths.get(&pinned).await {
                Some(b) => b,
                None => return err(StatusCode::BAD_REQUEST, "tenant has no github profile"),
            };
            g = match b.github.clone() {
                Some(g) => g,
                None => return err(StatusCode::BAD_REQUEST, "tenant has no github profile"),
            };
            local = match b.local.clone() {
                Some(l) => l,
                None => return err(StatusCode::BAD_REQUEST, "tenant has no github profile"),
            };
            _tenant_hint = Some(pinned);
        }
    }
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
        assert_eq!(res.len(), 4);
        assert!(res.iter().all(|r| r.get("success") == Some(&serde_json::json!(true))));
        assert_eq!(res[0].get("id"), Some(&serde_json::json!("a")));
        // Unknown op types are rejected, never silently created.
        let bad_type = run_ops(&db, &policy, None, None, vec![batch_op("bogus", "w", "z", d(0))], false).await;
        assert!(bad_type.is_err());

        // must_exist failure aborts the whole batch (d is untouched).
        let bad = run_ops(
            &db,
            &policy,
            None,
            None,
            vec![batch_op("set", "w", "d", d(4)), batch_op("update", "w", "ghost", d(5))],
            false,
        )
        .await;
        assert!(bad.is_err());
        assert!(db.get("w", "d").await.unwrap().is_none());

        // Transaction shapes: get → doc, writes → {success}.
        let res = run_ops(&db, &policy, None, None, vec![batch_op("get", "w", "a", d(0))], true)
            .await
            .unwrap();
        assert_eq!(res[0].get("age"), Some(&serde_json::json!(1)));

        // Atomics + stamps flow through batch writes (legacy __type__ wire).
        let res = run_ops(
            &db,
            &policy,
            None,
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

    fn authed(tenant: Option<&str>) -> Option<AuthContext> {
        Some(AuthContext {
            uid: "tester".into(),
            roles: vec![],
            tenant: tenant.map(str::to_string),
            extra: Default::default(),
        })
    }

    /// Tenant isolation on sqlite: same logical `users` in two tenants +
    /// anonymous land in three disjoint namespaces; internal `__tenants`
    /// is unreachable over the resolved paths.
    #[tokio::test]
    async fn tenant_isolation_sqlite() {
        use hakobackend_db_sqlite::SqliteDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_tenant_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db: Arc<dyn Database> =
            Arc::new(SqliteDb::open(dir.join("t.db").to_string_lossy().as_ref()).await.unwrap());
        let policy = Arc::new(PolicyFile::open());
        let d = |v: &str| serde_json::json!({"v": v});
        let set = |t: Option<&str>, id: &str| {
            batch_op("set", "users", id, d(t.unwrap_or("anon")))
        };

        run_ops(&db, &policy, authed(Some("acme")).as_ref(), Some("acme".into()), vec![set(Some("acme"), "a")], false)
            .await
            .unwrap();
        run_ops(&db, &policy, authed(Some("beta")).as_ref(), Some("beta".into()), vec![set(Some("beta"), "a")], false)
            .await
            .unwrap();
        run_ops(&db, &policy, None, None, vec![set(None, "a")], false).await.unwrap();

        // Stored names are namespaced.
        assert!(db.get("acme__users", "a").await.unwrap().is_some());
        assert!(db.get("beta__users", "a").await.unwrap().is_some());
        // Each tenant reads only its own doc back through run_ops.
        let ra = run_ops(&db, &policy, authed(Some("acme")).as_ref(), Some("acme".into()), vec![batch_op("get", "users", "a", d(""))], true)
            .await
            .unwrap();
        assert_eq!(ra[0].get("v"), Some(&serde_json::json!("acme")));
        let rb = run_ops(&db, &policy, authed(Some("beta")).as_ref(), Some("beta".into()), vec![batch_op("get", "users", "a", d(""))], true)
            .await
            .unwrap();
        assert_eq!(rb[0].get("v"), Some(&serde_json::json!("beta")));
        // Tenant callers cannot address internals, even by stored name.
        let evil = run_ops(
            &db,
            &policy,
            authed(Some("acme")).as_ref(),
            Some("acme".into()),
            vec![batch_op("get", "__tenants", "acme", d(""))],
            true,
        )
        .await;
        assert!(evil.is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Tenant policy docs: validated TOML in, version bump out; broken TOML
    /// rejected without touching the stored copy.
    #[tokio::test]
    async fn tenant_policy_put_get() {
        use hakobackend_db_sqlite::SqliteDb;
        let dir = std::env::temp_dir().join(format!("hakobackend_tpol_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db: Arc<dyn Database> =
            Arc::new(SqliteDb::open(dir.join("t.db").to_string_lossy().as_ref()).await.unwrap());
        let tp = tenant_policy::TenantPolicies::new(Arc::new(tokio::sync::RwLock::new(db)));
        assert!(tp.get("acme").await.is_none());

        let toml = "[defaults]\nread = \"deny\"\nwrite = \"deny\"\n";
        let v1 = tp.put("acme", toml).await.unwrap();
        assert_eq!(v1, 1);
        let p = tp.get("acme").await.unwrap();
        assert!(!p.allow(None, "users", Method::Get, None));
        let (v, raw) = tp.get_raw("acme").await.unwrap();
        assert_eq!((v, raw.as_str()), (1, toml));

        // Broken TOML rejected, stored copy untouched.
        assert!(tp.put("acme", "not = [valid").await.is_err());
        assert_eq!(tp.get_raw("acme").await.unwrap().0, 1);
        // Second write bumps the version.
        assert_eq!(tp.put("acme", toml).await.unwrap(), 2);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Per-tenant auth bundles: profile docs build live chains; local runs
    /// namespaced (users land in `{tenant}__users`); JWTs carry the tenant;
    /// unshared profiles are invisible to other tenants.
    #[tokio::test]
    async fn tenant_auth_bundle_local_namespaced() {
        use hakobackend_db_sqlite::SqliteDb;
        std::env::set_var("UB_LOCAL_JWT_SECRET", "0123456789abcdef0123456789abcdef");
        let dir = std::env::temp_dir().join(format!("hakobackend_tauth_{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let raw: Arc<dyn Database> =
            Arc::new(SqliteDb::open(dir.join("t.db").to_string_lossy().as_ref()).await.unwrap());
        let dbh = Arc::new(tokio::sync::RwLock::new(raw.clone()));
        let ident = hakobackend_policy::Identity::default();
        let doc = |pairs: &[(&str, serde_json::Value)]| hakobackend_core::Doc {
            id: String::new(),
            data: pairs.iter().map(|(k, v)| (k.to_string(), v.clone())).collect(),
        };
        // Tenant + org-global shared profile (spec local).
        raw.set(
            hakobackend_core::tenant::TENANTS_COLLECTION,
            "acme",
            {
                let mut d = doc(&[]);
                d.id = "acme".into();
                d.data.insert("auth_profile".into(), serde_json::json!("p1"));
                d
            },
            false,
        )
        .await
        .unwrap();
        raw.set(
            tenant_auth::AUTH_PROFILES_COLLECTION,
            "p1",
            {
                let mut d = doc(&[]);
                d.id = "p1".into();
                d.data.insert("owner_tenant".into(), serde_json::Value::Null);
                d.data.insert("shared".into(), serde_json::json!(true));
                d.data.insert("spec".into(), serde_json::json!("local"));
                d.data.insert("config".into(), serde_json::json!({}));
                d
            },
            false,
        )
        .await
        .unwrap();

        let auths = tenant_auth::TenantAuths::new(dbh, ident);
        let bundle = auths.get("acme").await.expect("bundle builds");
        assert!(bundle.local.is_some());

        // Register through the bundle: user lands namespaced.
        let local = bundle.local.as_ref().unwrap();
        let mut profile = HashMap::new();
        profile.insert("tenant".into(), serde_json::json!("acme"));
        // NB: forced tenant wins even without the doc field; set both.
        local.register(Some("u1".into()), None, "password123", profile).await.unwrap();
        assert!(raw.get("acme__users", "u1").await.unwrap().is_some());
        assert!(raw.get("users", "u1").await.unwrap().is_none());

        // Login mints a tenant-bound JWT; verify surfaces the claim.
        let (ctx, _tokens) = local.login("u1", "password123", None).await.unwrap();
        assert_eq!(ctx.tenant.as_deref(), Some("acme"));

        // Unshared foreign profile is invisible (falls back to global).
        raw.set(
            tenant_auth::AUTH_PROFILES_COLLECTION,
            "p2",
            {
                let mut d = doc(&[]);
                d.id = "p2".into();
                d.data.insert("owner_tenant".into(), serde_json::json!("acme"));
                d.data.insert("shared".into(), serde_json::json!(false));
                d.data.insert("spec".into(), serde_json::json!("local"));
                d.data.insert("config".into(), serde_json::json!({}));
                d
            },
            false,
        )
        .await
        .unwrap();
        raw.set(
            hakobackend_core::tenant::TENANTS_COLLECTION,
            "beta",
            {
                let mut d = doc(&[]);
                d.id = "beta".into();
                d.data.insert("auth_profile".into(), serde_json::json!("p2"));
                d
            },
            false,
        )
        .await
        .unwrap();
        assert!(auths.get("beta").await.is_none());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn ctx(uid: &str, tenant: Option<&str>, roles: &[&str]) -> AuthContext {
        AuthContext {
            uid: uid.into(),
            roles: roles.iter().map(|s| s.to_string()).collect(),
            tenant: tenant.map(str::to_string),
            extra: HashMap::new(),
        }
    }

    /// Single mode pins the hint (client input ignored); other modes pass through.
    #[test]
    fn pin_hint_single_pins() {
        assert_eq!(
            pin_hint_for(ServiceMode::Single, Some("acme"), Some("evil".into())),
            Some("acme".into())
        );
        assert_eq!(pin_hint_for(ServiceMode::Single, Some("acme"), None), Some("acme".into()));
        assert_eq!(
            pin_hint_for(ServiceMode::Managed, None, Some("acme".into())),
            Some("acme".into())
        );
        assert_eq!(pin_hint_for(ServiceMode::Open, None, None), None);
    }

    /// Scoped admin: global admin anywhere; tenant role only with matching claim.
    #[test]
    fn scoped_admin_binding() {
        // Org admin passes for any slug.
        assert!(tenant_scoped_admin_for("admin", "tenant-admin", Some(&ctx("local:root", None, &["admin"])), "acme"));
        // Tenant admin passes only for its own claim tenant.
        assert!(tenant_scoped_admin_for(
            "admin",
            "tenant-admin",
            Some(&ctx("local:boss", Some("acme"), &["tenant-admin"])),
            "acme"
        ));
        assert!(!tenant_scoped_admin_for(
            "admin",
            "tenant-admin",
            Some(&ctx("local:boss", Some("acme"), &["tenant-admin"])),
            "beta"
        ));
        // Right tenant, wrong role.
        assert!(!tenant_scoped_admin_for(
            "admin",
            "tenant-admin",
            Some(&ctx("local:u", Some("acme"), &["user"])),
            "acme"
        ));
        // Claimless global admin-role... has no tenant: only the org role passes.
        assert!(!tenant_scoped_admin_for(
            "admin",
            "tenant-admin",
            Some(&ctx("local:u", None, &["tenant-admin"])),
            "acme"
        ));
        assert!(!tenant_scoped_admin_for("admin", "tenant-admin", None, "acme"));
    }

    /// Starter policy parses and grants the tenant-admin role everything.
    #[test]
    fn starter_policy_parses_and_gates() {
        let toml = tenant_policy::starter_policy("tenant-admin");
        let p = PolicyFile::load_str(&toml).expect("starter must parse");
        let boss = ctx("local:boss", Some("acme"), &["tenant-admin"]);
        let user = ctx("local:u", Some("acme"), &["user"]);
        assert!(p.allow(Some(&boss), "users", Method::Create, None));
        assert!(p.allow(Some(&boss), "posts", Method::Delete, None));
        assert!(!p.allow(Some(&user), "users", Method::List, None));
        assert!(!p.allow(None, "users", Method::List, None));
    }
}

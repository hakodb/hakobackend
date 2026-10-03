//! Config: CLI flags > config file > defaults.
//! `./universalbackend --driver sqlite --data ./app.db --rules ./rules.toml
//! --auth local --host 127.0.0.1 --port 8080`
//! or `./universalbackend --config ./config.toml`.
//! The legacy shape (`[server] listen`, `[database]`, `policy_file`) is still read
//! as deprecated aliases so old configs don't break.

use clap::Parser;

pub const KNOWN_DRIVERS: &[&str] = &["hako", "hakocluster", "postgres", "sqlite", "mysql",
"rethinkdb"];

#[derive(Parser, Debug, Clone)]
#[command(name = "universalbackend", version, about = "1 backend, multi database")]
pub struct Args {
    /// Config file (TOML). Default: ./hakobackend.toml (legacy ./ub.toml) if present.
    #[arg(long)]
    pub config: Option<String>,
    /// Database driver (see KNOWN_DRIVERS).
    #[arg(long)]
    pub driver: Option<String>,
    /// File path (hako/sqlite) or DSN (postgres/mysql).
    #[arg(long)]
    pub data: Option<String>,
    /// Endpoint rules file (TOML, hot-reload).
    #[arg(long)]
    pub rules: Option<String>,
    /// off | local | chain:a,b | ./custom.toml
    #[arg(long)]
    pub auth: Option<String>,
    #[arg(long)]
    pub host: Option<String>,
    #[arg(long)]
    pub port: Option<u16>,
    /// Unix-domain socket path (extra listener next to TCP; absent = TCP
    /// only). Same app, local-only. Nginx: `proxy_pass http://unix:/path`.
    /// Unix-only: a Windows build fails closed when it is set.
    #[arg(long)]
    pub sock: Option<String>,
    /// Host allowlist for domain-designated backends (repeatable flag;
    /// appended to the file list). Requests with other Host values get
    /// 421 before limiter/auth/policy. Empty = off. Loopback
    /// (localhost/127.0.0.1/::1) always passes regardless.
    #[arg(long)]
    pub allowed_hosts: Vec<String>,
    /// CORS strict origin allowlist (repeatable flag; file base + flag
    /// extras, same merge as allowed_hosts). Empty = legacy echo-any
    /// http(s) origin (today's behavior, documented risk).
    #[arg(long)]
    pub cors_allowed_origins: Vec<String>,
    /// Max JSON/body bytes in MB (default 8, legacy json-limit parity).
    #[arg(long)]
    pub body_limit_mb: Option<u64>,
    /// Hako socket_sync: serve this instance on a unix socket so peers can
    /// replicate from it (absent = no serving). Unix-only: fails closed at
    /// startup when set on other platforms.
    #[arg(long)]
    pub sync_serve: Option<String>,
    /// Hako socket_sync peers to dial (repeatable flag; appended to the
    /// file list). Dial retries in the background until peered — boot
    /// order independent, and self-heals across peer restarts.
    #[arg(long)]
    pub sync_peer: Vec<String>,
    /// Admin UIDs allowed to call /api/admin/* (repeatable flag;
    /// single-user backend uses UIDs, not roles).
    #[arg(long)]
    pub admin_uids: Vec<String>,
    /// Public origin URL (for OAuth callbacks). UB_PUBLIC_URL env wins when set.
    #[arg(long)]
    pub public_url: Option<String>,
    /// Global rate limit req/min/IP (default 600) + burst (default 100).
    #[arg(long)]
    pub limit_global: Option<u32>,
    #[arg(long)]
    pub limit_global_burst: Option<u32>,
    /// Strict rate limit for /api/auth/* req/min/IP (default 20) + burst (default 5).
    #[arg(long)]
    pub limit_auth: Option<u32>,
    #[arg(long)]
    pub limit_auth_burst: Option<u32>,
    /// Trust X-Forwarded-For (ONLY behind a sanitizing proxy).
    #[arg(long, default_value_t = false)]
    pub trust_proxy: bool,
    /// TLS: certificate + PEM key paths (both required to enable).
    #[arg(long)]
    pub tls_cert: Option<String>,
    #[arg(long)]
    pub tls_key: Option<String>,
    /// Plain-TCP HTTP/2 (h2c, prior knowledge). Default h1 (yesterday's
    /// behavior). Ignored with a warning under TLS (ALPN already serves
    /// h2 there). Multiplexing + HPACK for header-heavy API traffic.
    #[arg(long, default_value_t = false)]
    pub http2: bool,
    /// Check config + rules + auth without starting the server.
    #[arg(long)]
    pub validate: bool,
    /// Print the default config template and exit.
    #[arg(long)]
    pub print_default_config: bool,
    /// Merge rapid PATCHes to the same doc (100 ms window). Opt-in:
    /// acks at merge time, driver failures surface in logs.
    #[arg(long, default_value_t = false)]
    pub coalesce_writes: bool,
    /// Gzip responses above 1 KB (default OFF: realtime backend optimizes
    /// latency + CPU; bandwidth is the proxy's job when one fronts this).
    #[arg(long, default_value_t = false)]
    pub compress: bool,
    /// Stage profiler (PERFORMANCE_NOTE §7): UB_WSTATS=1 / config / this flag.
    /// 1/16 sampling + GET /api/__wstats (404 when off).
    #[arg(long, default_value_t = false)]
    pub wstats: bool,
    /// Internal per-driver benchmark: fixed shapes, auto-clean seeds, then
    /// exit (no serving). Comparability first: sequential, same N every run.
    #[arg(long, default_value_t = false)]
    pub benchmark: bool,
}
/// Final result after merge (the only one the server uses).
#[derive(Debug, Clone)]
pub struct UbConfig {
    pub host: String,
    pub port: u16,
    pub driver: String,
    pub data: String,
    pub rules: Option<String>,
    pub auth: Option<String>,
    pub admin_uids: Vec<String>,
    /// Unix socket path (None = TCP only). Hot-reload ignores it (listener
    /// shape is boot-time; changing it needs a restart, unlike rules/auth).
    pub sock: Option<String>,
    /// Plain-HTTP loopback companion (file-only, no flag): with TLS on and
    /// the TLS bind outside loopback, also serve plaintext on
    /// 127.0.0.1:<same port>. Default true. Boot-time like listeners.
    pub plain_loopback: bool,
    /// Host allowlist, same semantics as the flag. Set in config like
    /// listen/bind (file base + flag extras). Empty = off.
    pub allowed_hosts: Vec<String>,
    /// CORS strict origin allowlist (file base + flag extras). Empty =
    /// legacy echo-any http(s) origin. Boot-time like listeners.
    pub cors_allowed_origins: Vec<String>,
    /// Session cookie flags (file-only, boot-time): Secure default true
    /// (plain-http dev sets false), SameSite Strict|Lax|None (default
    /// Strict; None requires Secure), Path default "/", Domain unset.
    pub cookie_secure: bool,
    pub cookie_samesite: String,
    pub cookie_path: String,
    pub cookie_domain: Option<String>,
    /// Max JSON/body bytes in MB (default 8). Boot-time like listeners.
    pub body_limit_mb: u64,
    /// HSTS max-age seconds (default 31536000, TLS only). 0 = omit header.
    pub hsts_max_age_secs: u64,
    /// gzip minimum body bytes (default 1024; only with compress on).
    pub compress_min_bytes: u64,
    /// WS caps: max message KB (default 1024) + max subs per socket
    /// (default 100). Boot-time.
    pub ws_max_msg_kb: u64,
    pub ws_max_subs: u64,
    /// CSRF Origin-vs-Host gate on (default true; file-only, boot-time).
    pub csrf_origin_check: bool,
    /// Socket_sync serve path (None = not serving). Boot-time like sock.
    pub sync_serve: Option<String>,
    /// Socket_sync dial peers (empty = dial none; pure serve is valid).
    pub sync_peer: Vec<String>,
    pub public_url: Option<String>,
    pub limit_global: (u32, u32),
    pub limit_auth: (u32, u32),
    pub trust_proxy: bool,
    pub coalesce_writes: bool,
    /// Gzip responses above 1 KB (flag --compress wins when set).
    pub compress: bool,
    /// Stage profiler on (env UB_WSTATS=1 also enables).
    pub wstats: bool,
    /// Run the internal benchmark then exit instead of serving.
    pub benchmark: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Plain-TCP HTTP/2 (boot-time like listeners; hot-reload ignores it).
    pub http2: bool,
    /// Ready-to-use index declarations (created at startup + reload — legacy
    /// autoCreateTablesFromRules pattern, extended to indexes).
    pub indexes: Vec<IndexDecl>,
    /// Loopback service keys (raw hex from `[service]` + `UB_SVC_KEYS` env,
    /// validated). Empty = feature off (zero behavior change).
    pub service_keys: Vec<String>,
    /// Service scope slots (`collection:read|write`, validated).
    pub service_allow: Vec<String>,
    /// Which file it came from (for /api/admin/reload); "" when pure default+flags.
    pub source: String,
}

/// Default for `plain_loopback` (serde default fn): on unless opted out.
fn default_plain_loopback() -> bool {
    true
}

/// Loopback service key for co-hosted consumers (no user identity):
/// static Bearer, socket-peer must be loopback, scope copied from config.
/// Fail-closed: no keys = the whole feature is off.
#[derive(Debug, Default, serde::Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceSection {
    #[serde(default)]
    keys: Vec<String>,
    #[serde(default)]
    allow: Vec<String>,
}

/// Key hygiene: hex, ≥128 bit. Malformed keys fail fast (boot/validate),
/// never silently ignored.
pub fn valid_svc_key(k: &str) -> bool {
    k.len() >= 32 && k.bytes().all(|b| b.is_ascii_hexdigit())
}

/// Scope slot shape: `collection:read|write` (`read` = Get+List).
pub fn parse_svc_scope(s: &str) -> bool {
    match s.split_once(':') {
        Some((c, "read")) | Some((c, "write")) => !c.is_empty(),
        _ => false,
    }
}

/// One `[[indexes]]` declaration: `collection` + `fields[]` (+options).
/// `kind`: simple (default) | composite | fts.
#[derive(Debug, Clone, serde::Deserialize)]
pub struct IndexDecl {
    pub collection: String,
    pub fields: Vec<String>,
    pub name: Option<String>,
    #[serde(default)]
    pub unique: bool,
    #[serde(default = "simple_kind")]
    pub kind: String,
}

fn simple_kind() -> String {
    "simple".into()
}

impl IndexDecl {
    pub fn validate(&self) -> Result<hakobackend_core::IndexSpec, String> {
        if self.collection.is_empty() {
            return Err("[[indexes]] requires collection".into());
        }
        if self.fields.is_empty() {
            return Err(format!("[[indexes]] {} requires >= 1 field", self.collection));
        }
        let kind = match self.kind.as_str() {
            "simple" => hakobackend_core::IndexKind::Simple,
            "composite" => hakobackend_core::IndexKind::Composite,
            "fts" | "fulltext" => hakobackend_core::IndexKind::FullText,
            other => return Err(format!("[[indexes]] kind `{other}` unknown (simple|composite|fts)")),
        };
        Ok(hakobackend_core::IndexSpec {
            name: self.name.clone(),
            fields: self.fields.clone(),
            unique: self.unique,
            kind,
        })
    }
}

impl UbConfig {
    /// First listen address, for display/diagnostics.
    /// (Serving binds every resolved address — see resolve_bind_ips.)
    #[cfg(test)]
    pub fn listen(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

#[derive(Debug, Default, serde::Deserialize)]
struct FileConfig {
    host: Option<String>,
    port: Option<u16>,
    driver: Option<String>,
    data: Option<String>,
    rules: Option<String>,
    auth: Option<String>,
    sock: Option<String>,
    /// Plain-HTTP loopback companion (default true when absent).
    #[serde(default = "default_plain_loopback")]
    plain_loopback: bool,
    #[serde(default)]
    allowed_hosts: Vec<String>,
    /// CORS strict origin allowlist (flag extras append).
    #[serde(default)]
    cors_allowed_origins: Vec<String>,
    /// Session cookie flags (all file-only, boot-time).
    cookie_secure: Option<bool>,
    cookie_samesite: Option<String>,
    cookie_path: Option<String>,
    cookie_domain: Option<String>,
    body_limit_mb: Option<u64>,
    hsts_max_age_secs: Option<u64>,
    compress_min_bytes: Option<u64>,
    ws_max_msg_kb: Option<u64>,
    ws_max_subs: Option<u64>,
    /// CSRF Origin-vs-Host gate for cookie-authed mutations (default on).
    /// Off only for debugging behind a sanitizing gateway (documented risk).
    csrf_origin_check: Option<bool>,
    sync_serve: Option<String>,
    #[serde(default)]
    sync_peer: Vec<String>,
    #[serde(default)]
    admin_uids: Vec<String>,
    public_url: Option<String>,
    limit_global: Option<u32>,
    limit_global_burst: Option<u32>,
    limit_auth: Option<u32>,
    limit_auth_burst: Option<u32>,
    trust_proxy: Option<bool>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    /// Plain-TCP HTTP/2 (flag `--http2` wins when set).
    #[serde(default)]
    http2: bool,
    #[serde(default)]
    coalesce_writes: bool,
    /// Gzip responses above 1 KB (flag --compress wins when set).
    #[serde(default)]
    compress: bool,
    /// Stage profiler (flag `--wstats` wins when set).
    #[serde(default)]
    wstats: bool,
    /// Internal benchmark then exit (flag `--benchmark` wins when set).
    #[serde(default)]
    benchmark: bool,
    #[serde(default)]
    indexes: Vec<IndexDecl>,
    /// Loopback service keys (see `[service]`).
    #[serde(default)]
    service: ServiceSection,
    #[serde(default)]
    server: LegacyServer,
    #[serde(default)]
    database: LegacyDb,
    policy_file: Option<String>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct LegacyServer {
    listen: Option<String>,
    host: Option<String>,
    port: Option<u16>,
}

#[derive(Debug, Default, serde::Deserialize)]
struct LegacyDb {
    driver: Option<String>,
    path: Option<String>,
    // Loose legacy placement: root keys written under
    // [database]/[server] are still read (previously ignored by serde — compat bug).
    data: Option<String>,
    rules: Option<String>,
    policy_file: Option<String>,
}

/// Config path: --config > UB_CONFIG > ./hakobackend.toml > ./ub.toml (legacy) > no file.
pub fn config_path(args: &Args) -> Option<String> {
    if let Some(p) = &args.config {
        return Some(p.clone());
    }
    if let Ok(p) = std::env::var("UB_CONFIG") {
        if !p.is_empty() {
            return Some(p);
        }
    }
    for def in ["./hakobackend.toml", "./ub.toml"] {
        if std::fs::metadata(def).is_ok() {
            return Some(def.to_string());
        }
    }
    None
}

fn load_file(path: &str, explicit: bool) -> FileConfig {
    match std::fs::read_to_string(path) {
        Ok(raw) => match toml::from_str(&raw) {
            Ok(cfg) => cfg,
            Err(e) if explicit => panic!("[ub] failed to parse {path}: {e}"),
            Err(e) => {
                eprintln!("[ub] WARN: failed to parse {path} ({e}); using defaults");
                FileConfig::default()
            }
        },
        Err(_) if explicit => panic!("[ub] could not read config {path}"),
        Err(_) => FileConfig::default(),
    }
}

/// Merge: flags > file > defaults. Legacy aliases trigger WARN once.
pub fn resolve(args: &Args) -> UbConfig {
    let path = config_path(args);
    let explicit = args.config.is_some() || std::env::var("UB_CONFIG").map(|v| !v.is_empty()).unwrap_or(false);
    let file: FileConfig = path.as_deref().map(|p| load_file(p, explicit)).unwrap_or_default();

    if file.server.listen.is_some()
        || file.database.driver.is_some()
        || file.policy_file.is_some()
        || file.database.policy_file.is_some()
    {
        eprintln!("[ub] WARN: legacy keys ([server] listen / [database] / policy_file) are deprecated; use host/port/driver/data/rules (see --print-default-config)");
    }
    let (mut host, mut port) = ("0.0.0.0".to_string(), 3000u16);
    if let Some(listen) = file.server.listen {
        if let Some((h, p)) = listen.rsplit_once(':') {
            host = h.to_string();
            port = p.parse().unwrap_or_else(|_| panic!("[ub] listen `{listen}` has an invalid port"));
        }
    }


    UbConfig {
        host: args.host.clone().or(file.host).or(file.server.host).unwrap_or(host),
        port: args.port.or(file.port).or(file.server.port).unwrap_or(port),
        driver: args
            .driver
            .clone()
            .or(file.driver)
            .or(file.database.driver)
            .unwrap_or_else(|| "hako".into()),
        data: args
            .data
            .clone()
            .or(file.data)
            .or(file.database.data)
            .or(file.database.path)
            .unwrap_or_else(|| "./data/hako.ub".into()),
        rules: args
            .rules
            .clone()
            .or(file.rules)
            .or(file.policy_file)
            .or(file.database.rules)
            .or(file.database.policy_file),
        auth: args.auth.clone().or(file.auth),
        sock: args.sock.clone().or(file.sock),
        plain_loopback: file.plain_loopback,
        allowed_hosts: {
            // File base + flag extras (same append idiom as peers).
            let mut v = file.allowed_hosts;
            v.extend(args.allowed_hosts.clone());
            v
        },
        cors_allowed_origins: {
            let mut v = file.cors_allowed_origins;
            v.extend(args.cors_allowed_origins.clone());
            v
        },
        cookie_secure: file.cookie_secure.unwrap_or(true),
        cookie_samesite: file.cookie_samesite.unwrap_or_else(|| "Strict".into()),
        cookie_path: file.cookie_path.unwrap_or_else(|| "/".into()),
        cookie_domain: file.cookie_domain,
        body_limit_mb: args.body_limit_mb.or(file.body_limit_mb).unwrap_or(8),
        hsts_max_age_secs: file.hsts_max_age_secs.unwrap_or(31_536_000),
        compress_min_bytes: file.compress_min_bytes.unwrap_or(1024),
        ws_max_msg_kb: file.ws_max_msg_kb.unwrap_or(1024),
        ws_max_subs: file.ws_max_subs.unwrap_or(100),
        csrf_origin_check: file.csrf_origin_check.unwrap_or(true),
        sync_serve: args.sync_serve.clone().or(file.sync_serve),
        sync_peer: {
            // ponytail: peers append (file base + flag extras), serve
            // replaces — you dial a SET but serve ONE socket.
            let mut v = file.sync_peer;
            v.extend(args.sync_peer.clone());
            v
        },
        admin_uids: {
            let mut v = file.admin_uids;
            v.extend(args.admin_uids.clone());
            v
        },
        public_url: args.public_url.clone().or(file.public_url),
        limit_global: (
            args.limit_global.or(file.limit_global).unwrap_or(600),
            args.limit_global_burst.or(file.limit_global_burst).unwrap_or(100),
        ),
        limit_auth: (
            args.limit_auth.or(file.limit_auth).unwrap_or(20),
            args.limit_auth_burst.or(file.limit_auth_burst).unwrap_or(5),
        ),
        trust_proxy: args.trust_proxy || file.trust_proxy.unwrap_or(false),
        coalesce_writes: args.coalesce_writes || file.coalesce_writes,
        compress: args.compress || file.compress,
        wstats: args.wstats || file.wstats,
        benchmark: args.benchmark || file.benchmark,
        tls_cert: args.tls_cert.clone().or(file.tls_cert),
        tls_key: args.tls_key.clone().or(file.tls_key),
        http2: args.http2 || file.http2,
        indexes: file.indexes,
        service_keys: {
            let mut keys = file.service.keys;
            // Rotation-friendly secret path: env appends, never logged.
            if let Ok(env) = std::env::var("UB_SVC_KEYS") {
                keys.extend(env.split(',').map(|k| k.trim().to_string()).filter(|k| !k.is_empty()));
            }
            for k in &keys {
                if !valid_svc_key(k) {
                    panic!("[ub] [service] key rejected (need hex, >= 32 chars)");
                }
            }
            keys
        },
        service_allow: {
            for s in &file.service.allow {
                if !parse_svc_scope(s) {
                    panic!("[ub] [service] allow slot `{s}` malformed (want `collection:read|write`)");
                }
            }
            file.service.allow
        },
        source: path.unwrap_or_default(),
    }
}

/// TLS active when BOTH paths are set (clear failure when lopsided).
pub fn tls_pair(cfg: &UbConfig) -> Result<Option<(String, String)>, String> {
    match (&cfg.tls_cert, &cfg.tls_key) {
        (Some(c), Some(k)) => Ok(Some((c.clone(), k.clone()))),
        (None, None) => Ok(None),
        _ => Err("tls requires both tls_cert + tls_key (or leave both empty)".into()),
    }
}

/// Dry validation: known driver + parseable rules + openable auth spec + valid indexes.
pub fn validate(cfg: &UbConfig) -> Result<String, String> {
    if !KNOWN_DRIVERS.contains(&cfg.driver.as_str()) {
        return Err(format!("driver `{}` unknown (choices: {})", cfg.driver, KNOWN_DRIVERS.join(", ")));
    }
    if let Some(r) = &cfg.rules {
        hakobackend_policy::PolicyFile::load(r)?;
    }
    if let Some(a) = &cfg.auth {
        let spec = hakobackend_auth_core::AuthSpec::parse(a);
        if let hakobackend_auth_core::AuthSpec::File(p) = &spec {
            hakobackend_auth_core::CustomAuth::load(p)?;
        }
    }
    for decl in &cfg.indexes {
        decl.validate()?;
    }
    match tls_pair(cfg)? {
        Some((c, k)) => {
            for (label, p) in [("tls_cert", &c), ("tls_key", &k)] {
                std::fs::metadata(p).map_err(|_| format!("{label} unreadable: {p}"))?;
            }
        }
        None => {}
    }
    Ok(format!(
        "ok: {}:{} driver={} data={} rules={} auth={}",
        cfg.host,
        cfg.port,
        cfg.driver,
        cfg.data,
        cfg.rules.as_deref().unwrap_or("-"),
        cfg.auth.as_deref().unwrap_or("off"),
    ))
}

pub const DEFAULT_CONFIG_TEMPLATE: &str = r#"# universalbackend — config template (see --help for CLI flags).
# CLI flags always win over this file.
# host: IP literal binds as-is; a hostname resolves via DNS at startup
# (unknown names refuse to boot). "0.0.0.0", "127.0.0.1",
# "api.example.com" all work — generic listen like any other service.
host = "0.0.0.0"
port = 3000

driver = "hako"          # choices: hako | hakocluster (comma-separated dirs)
data = "./data/hako.ub"  # file path or DSN

rules = "./policy.toml"  # hot-reload; leave empty = open dev mode
auth = "off"             # off | local | chain:github,local | ./custom.toml

# Admin UIDs for /api/admin/* (repeatable; UIDs like "local:root").
# admin_uids = ["local:root"]

# Public origin for OAuth callbacks (or UB_PUBLIC_URL env which wins when set).
# public_url = "https://api.example.com"

# In-process flood protection (without redis): req/min per IP + burst.
# Strict layer just for /api/auth/* (anti credential brute-force).
# A 0 rate turns that layer fully OFF (bypassed, zero hot-path cost).
limit_global = 600
limit_global_burst = 100
limit_auth = 20
limit_auth_burst = 5
# trust_proxy = false  # true ONLY behind a proxy that strips X-Forwarded-For

# CORS strict origin allowlist (same as --cors-allowed-origins, appends).
# Empty (default) = legacy echo-any http(s) Origin + credentials. That is
# INTENTIONALLY loose: one backend serves many apps on many ports, often
# TLS-direct without a proxy to normalize origins. Lock it down only when
# the client set is fixed and known (exact match: scheme + host + port —
# "https://app.example.com" does NOT cover ":8443" or subdomains).
# cors_allowed_origins = ["https://app.example.com"]

# Session cookie flags (defaults = today's behavior). SameSite=None
# requires Secure (boot refuses otherwise); plain-http dev sets
# cookie_secure = false (browsers drop Secure cookies over http).
# cookie_secure = true
# cookie_samesite = "Strict"  # Strict|Lax|None
# cookie_path = "/"
# cookie_domain = "example.com"  # unset = host-only (default)

# Max JSON/body size in MB (default 8, legacy json-limit parity; larger 413).
# body_limit_mb = 8
# HSTS max-age seconds on TLS responses (default 31536000; 0 = omit header).
# hsts_max_age_secs = 31536000
# Gzip minimum body bytes, only with compress on (default 1024).
# compress_min_bytes = 1024
# WS caps: max inbound message KB (default 1024) + max subs per socket
# (default 100, over-budget subscribes are rejected, never silently dropped).
# ws_max_msg_kb = 1024
# ws_max_subs = 100
# CSRF Origin-vs-Host gate for cookie-authed mutations (default on).
# Same-host cross-port (portal :443 -> API :3000) passes: ports strip
# from both sides before compare. Off only behind a sanitizing gateway.
# csrf_origin_check = true

# Stage profiler: same as UB_WSTATS=1 / --wstats (GET /api/__wstats).
# wstats = false
# Internal per-driver benchmark (same as --benchmark): fixed shapes,
# auto-clean seeds, then exit without serving.
# benchmark = false

# TLS (both required; empty = plain http). DPoP scheme + Secure cookies follow automatically.
# tls_cert = "./cert.pem"
# tls_key = "./key.pem"

# Unix-domain socket: extra local-only listener next to TCP (absent = TCP
# only). Same app; nginx: `proxy_pass http://unix:/run/hakobackend/hako.sock;`
# (upstream keepalive works over it). Bypasses the TCP loopback pps cap that
# bounds the proxy path. Created mode 777 (nginx user must write). Unix-only:
# a Windows build refuses to start with sock set (no silent half-config).
# Changing it needs a restart (not hot-reloaded).
# sock = "/run/hakobackend/hako.sock"

# Plain-HTTP loopback companion (file-only, default true): with TLS on and
# the TLS bind outside loopback, plaintext is also served on
# 127.0.0.1:<same port> — testing, debugging, local microservices and
# reverse proxies with no cert flags. Loopback-only by construction, same
# app and gates. `plain_loopback = false` disables.
# plain_loopback = true

# Domain designation: serve ONLY these Host values (plus loopback, which
# always passes). Anything else is refused with 421 before limiter/auth.
# Empty = serve all Hosts (yesterday's default). Boot-time like listen.
# allowed_hosts = ["api.example.com"]

# Hako socket_sync peering (hako driver ONLY; other drivers refuse these
# keys at startup). Serve this instance and/or dial peers over unix
# sockets so N backends hold identical data (LWW converge, echo-safe).
# Dials retry in the background: boot order free, peer restarts self-heal.
# Absent = standalone (yesterday's default). Unix-only: a Windows build
# refuses to start with either set. Changing needs a restart.
# sync_serve = "/run/hakobackend/sync1.sock"
# sync_peer = ["/run/hakobackend/sync2.sock"]

# Gzip responses above 1 KB (same as --compress). Default OFF: this is a
# realtime backend (latency + CPU first); put compression on the edge
# proxy when bandwidth matters. Changing it needs a restart.
# compress = false

# Plain-TCP HTTP/2 (h2c, prior knowledge; default h1 = unchanged). Same app;
# multiplexing + HPACK helps header-heavy API traffic (Bearer JWTs). Ignored
# under TLS (ALPN already serves h2 there). Changing it needs a restart.
# http2 = false

# Loopback service key for a co-hosted consumer without user identity
# (e.g. sibling service reading ai_configs). Static Bearer, accepted ONLY
# from 127.0.0.1/::1 (socket peer, not X-Forwarded-For). Empty = off.
# Keys rotate without restart: edit + POST /api/admin/reload.
# [service]
# keys = ["<64-hex>"]            # or UB_SVC_KEYS env (comma-separated)
# allow = ["ai_configs:read"]    # slots "collection:read|write"; read=Get+List
"#;

#[cfg(test)]
mod tests {
    use super::*;

    fn args() -> Args {
        Args {
            config: None,
            driver: None,
            data: None,
            rules: None,
            auth: None,
            host: None,
            port: None,
            admin_uids: vec![],
            public_url: None,
            limit_global: None,
            limit_global_burst: None,
            limit_auth: None,
            limit_auth_burst: None,
            trust_proxy: false,
            tls_cert: None,
            tls_key: None,
            sock: None,
            allowed_hosts: vec![],
            cors_allowed_origins: vec![],
            body_limit_mb: None,
            sync_serve: None,
            sync_peer: vec![],
            http2: false,
            validate: false,
            print_default_config: false,
            coalesce_writes: false,
            compress: false,
            wstats: false,
            benchmark: false,
        }
    }

    fn write_tmp(name: &str, content: &str) -> String {
        let p = std::env::temp_dir().join(name);
        std::fs::write(&p, content).unwrap();
        p.to_string_lossy().into_owned()
    }

    #[test]
    fn presedensi_flag_menang_atas_file() {
        let f = write_tmp("hakobackend_cli_test.toml", "port = 1111\ndriver = \"hako\"\n");
        let mut a = args();
        a.config = Some(f.clone());
        a.port = Some(8080);
        let cfg = resolve(&a);
        assert_eq!(cfg.port, 8080);
        assert_eq!(cfg.driver, "hako");
        assert_eq!(cfg.host, "0.0.0.0");
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn legacy_alias_still_read() {
        let f = write_tmp(
            "hakobackend_legacy_test.toml",
            // Exact legacy layout (policy_file under [database]).
            "[server]\nlisten = \"127.0.0.1:4040\"\n[database]\ndriver = \"hako\"\npath = \"./x.ub\"\npolicy_file = \"./r.toml\"\n",        );
        let mut a = args();
        a.config = Some(f.clone());
        let cfg = resolve(&a);
        assert_eq!(cfg.listen(), "127.0.0.1:4040");
        assert_eq!(cfg.data, "./x.ub");
        assert_eq!(cfg.rules.as_deref(), Some("./r.toml"));
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn sock_opsional_file_dan_flag() {
        // Absent = TCP only (yesterday's default).
        assert_eq!(resolve(&args()).sock, None);
        // File sets it.
        let f = write_tmp("hakobackend_sock_test.toml", "sock = \"/tmp/hako-test.sock\"\n");
        let mut a = args();
        a.config = Some(f.clone());
        assert_eq!(resolve(&a).sock.as_deref(), Some("/tmp/hako-test.sock"));
        // Flag wins over file.
        a.sock = Some("/tmp/hako-flag.sock".into());
        assert_eq!(resolve(&a).sock.as_deref(), Some("/tmp/hako-flag.sock"));
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn sync_opsional_file_dan_flag() {
        // Absent = no peering (yesterday's default).
        let cfg = resolve(&args());
        assert_eq!(cfg.sync_serve, None);
        assert!(cfg.sync_peer.is_empty());
        // File sets both.
        let f = write_tmp(
            "hakobackend_sync_test.toml",
            "sync_serve = \"/tmp/s1.sock\"\nsync_peer = [\"/tmp/s2.sock\"]\n",
        );
        let mut a = args();
        a.config = Some(f.clone());
        let cfg = resolve(&a);
        assert_eq!(cfg.sync_serve.as_deref(), Some("/tmp/s1.sock"));
        assert_eq!(cfg.sync_peer, vec!["/tmp/s2.sock".to_string()]);
        // Flags win over file (peers append).
        a.sync_serve = Some("/tmp/flag.sock".into());
        a.sync_peer = vec!["/tmp/s3.sock".into()];
        let cfg = resolve(&a);
        assert_eq!(cfg.sync_serve.as_deref(), Some("/tmp/flag.sock"));
        assert_eq!(
            cfg.sync_peer,
            vec!["/tmp/s2.sock".to_string(), "/tmp/s3.sock".to_string()]
        );
        let _ = std::fs::remove_file(f);
    }

    #[test]
    #[should_panic(expected = "failed to parse")]
    fn unknown_service_key_fails_loud_not_silent() {
        // Regression: a misplaced key inside [service] (e.g. sync_serve
        // appended at EOF) used to vanish silently. Explicit configs panic.
        let f = write_tmp(
            "hakobackend_svc_typo_test.toml",
            "[service]\nallow = []\nsync_serve = \"/tmp/x.sock\"\n",
        );
        let mut a = args();
        a.config = Some(f.clone());
        let _ = resolve(&a);
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn allowed_hosts_file_dan_flag_append() {
        // Absent = serve all Hosts.
        assert!(resolve(&args()).allowed_hosts.is_empty());
        let f = write_tmp(
            "hakobackend_hosts_test.toml",
            "allowed_hosts = [\"api.example.com\"]\n",
        );
        let mut a = args();
        a.config = Some(f.clone());
        assert_eq!(resolve(&a).allowed_hosts, vec!["api.example.com".to_string()]);
        // Flags append to the file base.
        a.allowed_hosts = vec!["other.example".into()];
        assert_eq!(
            resolve(&a).allowed_hosts,
            vec!["api.example.com".to_string(), "other.example".to_string()]
        );
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn http2_opsional_default_h1() {
        // Absent = h1 (zero behavior change).
        assert!(!resolve(&args()).http2);
        let f = write_tmp("hakobackend_h2_test.toml", "http2 = true\n");
        let mut a = args();
        a.config = Some(f.clone());
        assert!(resolve(&a).http2);
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn vital_defaults_match_today() {
        // Every new knob defaults to today's hardcoded behavior.
        let cfg = resolve(&args());
        assert!(cfg.cors_allowed_origins.is_empty());
        assert!(cfg.cookie_secure);
        assert_eq!(cfg.cookie_samesite, "Strict");
        assert_eq!(cfg.cookie_path, "/");
        assert!(cfg.cookie_domain.is_none());
        assert_eq!(cfg.body_limit_mb, 8);
        assert_eq!(cfg.hsts_max_age_secs, 31_536_000);
        assert_eq!(cfg.compress_min_bytes, 1024);
        assert_eq!(cfg.ws_max_msg_kb, 1024);
        assert_eq!(cfg.ws_max_subs, 100);
        // File overrides stick.
        let f = write_tmp(
            "hakobackend_vital_test.toml",
            "cors_allowed_origins = [\"https://a.example\"]\ncookie_secure = false\ncookie_samesite = \"Lax\"\nbody_limit_mb = 16\nhsts_max_age_secs = 0\nws_max_subs = 10\n",
        );
        let mut a = args();
        a.config = Some(f.clone());
        let cfg = resolve(&a);
        assert_eq!(cfg.cors_allowed_origins, vec!["https://a.example".to_string()]);
        assert!(!cfg.cookie_secure);
        assert_eq!(cfg.cookie_samesite, "Lax");
        assert_eq!(cfg.body_limit_mb, 16);
        assert_eq!(cfg.hsts_max_age_secs, 0);
        assert_eq!(cfg.ws_max_subs, 10);
        // Flags append (cors) / win (body).
        a.cors_allowed_origins = vec!["https://b.example".into()];
        a.body_limit_mb = Some(32);
        let cfg = resolve(&a);
        assert_eq!(
            cfg.cors_allowed_origins,
            vec!["https://a.example".to_string(), "https://b.example".to_string()]
        );
        assert_eq!(cfg.body_limit_mb, 32);
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn validate_menolak_driver_asing() {
        let mut a = args();
        a.driver = Some("oracle".into());
        a.config = Some(write_tmp("hakobackend_empty_test.toml", ""));
        let cfg = resolve(&a);
        assert!(validate(&cfg).is_err());
    }

    #[test]
    fn wstats_benchmark_flag_file_env() {
        // Defaults off.
        let cfg = resolve(&args());
        assert!(!cfg.wstats && !cfg.benchmark);
        // Flag wins.
        let mut a = args();
        a.wstats = true;
        a.benchmark = true;
        let cfg = resolve(&a);
        assert!(cfg.wstats && cfg.benchmark);
        // File enables when flags off.
        let f = write_tmp("hakobackend_diag_test.toml", "wstats = true\nbenchmark = true\n");
        let mut a = args();
        a.config = Some(f.clone());
        let cfg = resolve(&a);
        assert!(cfg.wstats && cfg.benchmark);
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn indexes_decl_validasi() {
        let f = write_tmp(
            "hakobackend_indexes_test.toml",
            "[[indexes]]\ncollection = \"posts\"\nfields = [\"age\", \"title\"]\nkind = \"composite\"\n\n[[indexes]]\ncollection = \"x\"\nfields = []\n",
        );
        let mut a = args();
        a.config = Some(f.clone());
        let cfg = resolve(&a);
        assert_eq!(cfg.indexes.len(), 2);
        assert!(cfg.indexes[0].validate().is_ok());
        assert_eq!(cfg.indexes[0].validate().unwrap().kind, hakobackend_core::IndexKind::Composite);
        assert!(cfg.indexes[1].validate().is_err());
        assert!(validate(&cfg).is_err());
        let _ = std::fs::remove_file(f);
    }

    #[test]
    fn admin_uids_flag_dan_file() {
        let cfg = resolve(&args());
        assert!(cfg.admin_uids.is_empty());
        let mut a = args();
        a.admin_uids = vec!["local:root".into(), "github:7".into()];
        let cfg = resolve(&a);
        assert_eq!(cfg.admin_uids, vec!["local:root", "github:7"]);
        let f = write_tmp("hakobackend_admin_test.toml", "admin_uids = [\"local:f\"]\n");
        let mut a = args();
        a.config = Some(f.clone());
        a.admin_uids = vec!["local:g".into()];
        let cfg = resolve(&a);
        assert_eq!(cfg.admin_uids, vec!["local:f", "local:g"]);
        let _ = std::fs::remove_file(f);
    }
}

//! Config: CLI flags > config file > defaults.
//! `./universalbackend --driver sqlite --data ./app.db --rules ./rules.toml
//! --auth local --host 127.0.0.1 --port 8080`
//! or `./universalbackend --config ./config.toml`.
//! The legacy shape (`[server] listen`, `[database]`, `policy_file`) is still read
//! as deprecated aliases so old configs don't break.

use clap::Parser;

pub const KNOWN_DRIVERS: &[&str] = &["hako", "postgres", "sqlite", "mysql"];

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
    /// Role allowed to call /api/admin/reload (free-form user role name, default "admin").
    #[arg(long)]
    pub admin_role: Option<String>,
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
    /// Check config + rules + auth without starting the server.
    #[arg(long)]
    pub validate: bool,
    /// Print the default config template and exit.
    #[arg(long)]
    pub print_default_config: bool,
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
    pub admin_role: String,
    pub public_url: Option<String>,
    pub limit_global: (u32, u32),
    pub limit_auth: (u32, u32),
    pub trust_proxy: bool,
    pub tls_cert: Option<String>,
    pub tls_key: Option<String>,
    /// Ready-to-use index declarations (created at startup + reload — legacy
    /// autoCreateTablesFromRules pattern, extended to indexes).
    pub indexes: Vec<IndexDecl>,
    /// Which file it came from (for /api/admin/reload); "" when pure default+flags.
    pub source: String,
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
    admin_role: Option<String>,
    public_url: Option<String>,
    limit_global: Option<u32>,
    limit_global_burst: Option<u32>,
    limit_auth: Option<u32>,
    limit_auth_burst: Option<u32>,
    trust_proxy: Option<bool>,
    tls_cert: Option<String>,
    tls_key: Option<String>,
    #[serde(default)]
    indexes: Vec<IndexDecl>,
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
        admin_role: args.admin_role.clone().or(file.admin_role).unwrap_or_else(|| "admin".into()),
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
        tls_cert: args.tls_cert.clone().or(file.tls_cert),
        tls_key: args.tls_key.clone().or(file.tls_key),
        indexes: file.indexes,
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
host = "0.0.0.0"
port = 3000

driver = "hako"          # choices: hako (others in phase 3)
data = "./data/hako.ub"  # file path or DSN

rules = "./policy.toml"  # hot-reload; leave empty = open dev mode
auth = "off"             # off | local | chain:github,local | ./custom.toml

# Public origin for OAuth callbacks (or UB_PUBLIC_URL env which wins when set).
# public_url = "https://api.example.com"

# In-process flood protection (without redis): req/min per IP + burst.
# Strict layer just for /api/auth/* (anti credential brute-force).
limit_global = 600
limit_global_burst = 100
limit_auth = 20
limit_auth_burst = 5
# trust_proxy = false  # true ONLY behind a proxy that strips X-Forwarded-For

# TLS (both required; empty = plain http). DPoP scheme + Secure cookies follow automatically.
# tls_cert = "./cert.pem"
# tls_key = "./key.pem"
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
            admin_role: None,
            public_url: None,
            limit_global: None,
            limit_global_burst: None,
            limit_auth: None,
            limit_auth_burst: None,
            trust_proxy: false,
            tls_cert: None,
            tls_key: None,
            validate: false,
            print_default_config: false,
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
    fn validate_menolak_driver_asing() {
        let mut a = args();
        a.driver = Some("oracle".into());
        a.config = Some(write_tmp("hakobackend_empty_test.toml", ""));
        let cfg = resolve(&a);
        assert!(validate(&cfg).is_err());
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
}

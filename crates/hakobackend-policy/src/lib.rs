//! hakobackend-policy: single-user policy file.
//!
//! Declarative rules in TOML, **hot-reloaded without restart** (hakobackend-server watches
//! the file mtime). Parse failures / rule typos = fail-closed (deny) + error message,
//! never fail-open.
//!
//! Three rules only: `public` (anyone, no auth), `auth` (any authenticated
//! caller), `deny` (nobody). Owner/role rules were removed with the tenant
//! system: per-user data control is the deployer's job (separate
//! collections, or an external tenant layer). Admin access is a UID
//! allowlist in server config, not a role.
//!
//! ```toml
//! [defaults]
//! read = "public"
//! write = "deny"
//!
//! [collections.posts]
//! read = "public"
//! create = "auth"
//! delete = "deny"
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use hakobackend_core::{AuthContext, Doc, Method};

/// One rule. From a TOML string: `public|auth|deny`.
/// `owner` / `role:*` were removed (single-user backend): they fail LOUD
/// at parse time so stale policies break visibly, never silently open.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Public,
    Auth,
    Deny,
}

impl From<String> for Rule {
    fn from(s: String) -> Self {
        match s.as_str() {
            "public" => Rule::Public,
            "auth" => Rule::Auth,
            // ponytail: unknown incl. removed owner/role = deny (fail-closed).
            _ => Rule::Deny,
        }
    }
}

impl Default for Rule {
    // ponytail: default = Deny (fail-closed).
    fn default() -> Self {
        Rule::Deny
    }
}

impl<'de> Deserialize<'de> for Rule {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        // Removed rules fail LOUD (not silent deny): a stale policy with
        // owner/role must break visibly at load, never lock out silently.
        if s == "owner" || s.starts_with("role:") {
            return Err(serde::de::Error::custom(
                "rule '".to_string() + &s + "' removed: single-user backend has public|auth|deny only",
            ));
        }
        Ok(Rule::from(s))
    }
}

fn deny_default() -> Rule {
    Rule::Deny
}

fn default_users_collection() -> String {
    "users".into()
}

/// Identity owned by the USER, not core: which collection holds user
/// docs. Role/owner fields were removed with the tenant system.
#[derive(Debug, Clone, Deserialize)]
pub struct Identity {
    /// User-document collection. Free-form: `users`, `members`, …
    #[serde(default = "default_users_collection")]
    pub users_collection: String,
}

impl Default for Identity {
    fn default() -> Self {
        Self { users_collection: default_users_collection() }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Defaults {
    #[serde(default = "deny_default")]
    pub read: Rule,
    #[serde(default = "deny_default")]
    pub write: Rule,
}

/// Policy-level performance switches (all default off = legacy behavior).
#[derive(Debug, Clone, Deserialize, Default)]
pub struct Performance {
    /// Skip read-before-write on PUT (~115us saved per PUT: the `existing`
    /// lookup is pure overhead then). Tradeoff: PUT-overwrite resets
    /// `createdAt` (no old doc to preserve it from — use PATCH merge when
    /// that matters). PATCH merge always reads (it needs the base).
    #[serde(default)]
    pub skip_read_before_write: bool,
}
#[derive(Debug, Clone, Deserialize, Default)]
pub struct CollectionPolicy {
    pub get: Option<Rule>,
    pub list: Option<Rule>,
    pub create: Option<Rule>,
    pub update: Option<Rule>,
    pub delete: Option<Rule>,
    pub read: Option<Rule>,
    pub write: Option<Rule>,
}

impl CollectionPolicy {
    fn slot<'a>(&'a self, method: Method, defaults: &'a Defaults) -> &'a Rule {
        let specific = match method {
            Method::Get => self.get.as_ref(),
            Method::List => self.list.as_ref(),
            Method::Create => self.create.as_ref(),
            Method::Update => self.update.as_ref(),
            Method::Delete => self.delete.as_ref(),
        };
        if let Some(r) = specific {
            return r;
        }
        match method {
            Method::Get | Method::List => self.read.as_ref().unwrap_or(&defaults.read),
            Method::Create | Method::Update | Method::Delete => {
                self.write.as_ref().unwrap_or(&defaults.write)
            }
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct PolicyFile {
    /// User-owned identity config (user collection, role/owner fields).
    #[serde(default)]
    pub identity: Identity,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub collections: HashMap<String, CollectionPolicy>,
    /// Performance switches (all default off). See [`Performance`].
    #[serde(default)]
    pub performance: Performance,
}

impl PolicyFile {
    /// Without a policy file (dev mode): everything public + the server must log WARN.
    pub fn open() -> Self {
        Self {
            identity: Identity::default(),
            defaults: Defaults {
                read: Rule::Public,
                write: Rule::Public,
            },
            collections: HashMap::new(),
            performance: Performance::default(),
        }
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        Self::load_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }

    /// Parse from a string (tenant policies stored in the DB, not files).
    pub fn load_str(raw: &str) -> Result<Self, String> {
        toml::from_str(raw).map_err(|e| e.to_string())
    }

    /// Collection resolution: exact (`posts/abc/revisions`) → root
    /// (`posts`) → `[defaults]`. Deliberately NO last-segment fallback: a
    /// permissive generic rule (e.g. open `revisions`) must never silently
    /// cover every hierarchy (S3 audit). Name the full path or the root.
    fn find(&self, collection: &str) -> Option<&CollectionPolicy> {
        if let Some(p) = self.collections.get(collection) {
            return Some(p);
        }
        if collection.contains('/') {
            let segments: Vec<&str> = collection.split('/').collect();
            if let Some(root) = segments.first() {
                if let Some(p) = self.collections.get(*root) {
                    return Some(p);
                }
            }
        }
        None
    }

    /// `resource` is accepted for signature compatibility and ignored:
    /// no remaining rule reads the document.
    pub fn allow(
        &self,
        auth: Option<&AuthContext>,
        collection: &str,
        method: Method,
        resource: Option<&Doc>,
    ) -> bool {
        let _ = resource;
        let empty = CollectionPolicy::default();
        let policy = self.find(collection).unwrap_or(&empty);
        let rule = policy.slot(method, &self.defaults);
        eval(rule, auth)
    }

    /// True when a rule governing `method` on `collection` reads the
    /// existing document. No remaining rule does (Owner did) — kept for
    /// callers; always false.
    pub fn needs_existing(&self, _collection: &str, _method: Method) -> bool {
        false
    }

    /// Policy-level read-before-write skip (perf, opt-in): true when the
    /// flag is set. PATCH merge always reads (it needs the base).
    pub fn skip_read_before_write(&self, _collection: &str, _method: Method) -> bool {
        self.performance.skip_read_before_write
    }
}

fn eval(rule: &Rule, auth: Option<&AuthContext>) -> bool {
    match rule {
        Rule::Public => true,
        Rule::Deny => false,
        Rule::Auth => auth.is_some(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn auth(uid: &str) -> AuthContext {
        AuthContext {
            uid: uid.into(),
            ..Default::default()
        }
    }

    fn doc(owner: &str) -> Doc {
        Doc {
            id: "d1".into(),
            data: [("ownerId".to_string(), json!(owner))].into_iter().collect(),
        }
    }

    fn policy(toml: &str) -> PolicyFile {
        toml::from_str(toml).unwrap()
    }

    #[test]
    fn public_read_auth_write() {
        let p = policy(
            r#"
            [defaults]
            read = "public"
            write = "deny"
            [collections.posts]
            create = "auth"
            "#,
        );
        assert!(p.allow(None, "posts", Method::List, None));
        assert!(!p.allow(None, "posts", Method::Create, None));
        assert!(p.allow(Some(&auth("u1")), "posts", Method::Create, Some(&doc("u1"))));
        // unknown collection -> defaults
        assert!(p.allow(None, "lain", Method::Get, None));
        assert!(!p.allow(Some(&auth("u1")), "lain", Method::Delete, None));
    }

    #[test]
    fn removed_rules_fail_loud() {
        // owner/role were removed: stale policies break visibly at load,
        // never silently open or silently lock.
        assert!(PolicyFile::load_str("[collections.p]\nread = \"owner\"\n").is_err());
        assert!(PolicyFile::load_str("[collections.p]\nread = \"role:x\"\n").is_err());
        assert!(PolicyFile::load_str("[collections.p]\nread = \"auth\"\n").is_ok());
    }

    #[test]
    fn skip_read_before_write_flag() {
        // Off by default: legacy read-before-write everywhere.
        let p = policy("[defaults]\nread = \"public\"\nwrite = \"public\"\n");
        assert!(!p.skip_read_before_write("w", Method::Update));
        // Opt-in: skip allowed (no rule reads the document anymore).
        let p = policy(
            "[defaults]\nread = \"public\"\nwrite = \"public\"\n[performance]\nskip_read_before_write = true\n",
        );
        assert!(p.skip_read_before_write("w", Method::Update));
    }

    #[test]
    fn typo_fails_closed() {
        let p = policy(
            r#"
            [collections.posts]
            read = "public"
            update = "rolee:maintainer"
            "#,
        );
        // typo -> Deny
        assert!(!p.allow(Some(&auth("u1")), "posts", Method::Update, None));
    }

    #[test]
    fn hierarchy_exact_root() {
        let p = policy(
            r#"
            [defaults]
            read = "deny"
            write = "deny"
            [collections.posts]
            read = "public"
            [collections.revisions]
            read = "auth"
            [collections."posts/p1/revisions"]
            read = "public"
            "#,
        );
        // exact wins over everything
        assert!(p.allow(None, "posts/p1/revisions", Method::Get, None));
        // NO last-segment fallback (S3 audit): a generic `revisions` rule
        // must not silently cover hierarchies — root `posts` applies instead.
        assert!(p.allow(None, "posts/p9/revisions", Method::Get, None));
        assert!(p.allow(Some(&auth("u1")), "posts/p9/revisions", Method::Get, None));
        // root for subcollections without their own rule
        assert!(p.allow(None, "posts/p1/comments", Method::Get, None));
        // no match -> defaults (deny)
        assert!(!p.allow(None, "lain/x/y", Method::Get, None));
    }

    #[test]
    fn identity_user_owned() {
        // Only users_collection survives; stale role/owner keys are
        // ignored (serde default), never honored.
        let p: PolicyFile = toml::from_str(
            r#"
            [identity]
            users_collection = "members"
            role_field = "posisi"
            owner_field = "pemilikId"
            [collections.arsip]
            read = "auth"
            "#,
        )
        .unwrap();
        assert_eq!(p.identity.users_collection, "members");
        assert!(p.allow(Some(&auth("u1")), "arsip", Method::Get, None));
        assert!(!p.allow(None, "arsip", Method::Get, None));
    }
}

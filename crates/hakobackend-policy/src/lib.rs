//! hakobackend-policy: the `userrules.ts` replacement.
//!
//! Declarative rules in TOML, **hot-reloaded without restart** (hakobackend-server watches
//! the file mtime). Parse failures / rule typos = fail-closed (deny) + error message,
//! never fail-open.
//!
//! Core does NOT bind role or user-collection names — all of that is yours
//! via `[identity]` (`users_collection`, `role_field`, `owner_field`).
//! `role:<anything>` is free-form; core only compares strings.
//!
//! ```toml
//! [identity]
//! users_collection = "members"   # your user collection (default "users")
//! role_field = "posisi"          # your role field (default "role")
//! owner_field = "pemilikId"      # your owner field (default "ownerId")
//!
//! [defaults]
//! read = "public"
//! write = "deny"
//!
//! [collections.posts]
//! read = "public"
//! create = "auth"
//! delete = "role:pengurus"       # free-form role, defined by you
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use hakobackend_core::{AuthContext, Doc, Method};

/// One rule. From a TOML string: `public|auth|owner|deny|role:<name>`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Rule {
    Public,
    Auth,
    Owner,
    Deny,
    Role(String),
}

impl From<String> for Rule {
    fn from(s: String) -> Self {
        match s.as_str() {
            "public" => Rule::Public,
            "auth" => Rule::Auth,
            "owner" => Rule::Owner,
            "deny" => Rule::Deny,
            _ => match s.strip_prefix("role:") {
                Some(name) if !name.is_empty() => Rule::Role(name.to_string()),
                // ponytail: rule typo = deny (fail-closed), not a startup error.
                _ => Rule::Deny,
            },
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
        Ok(Rule::from(String::deserialize(d)?))
    }
}

fn deny_default() -> Rule {
    Rule::Deny
}

fn default_users_collection() -> String {
    "users".into()
}
fn default_role_field() -> String {
    "role".into()
}
fn default_owner_field() -> String {
    "ownerId".into()
}

/// Identity owned by the USER, not core. Answers: "which collection holds user docs,
/// which field holds the role, which field holds the owner". Core only consumes
/// these values (phase 2: the auth provider loads the user doc from `users_collection`
/// and maps `role_field` into `AuthContext.roles`); core never
/// assumes any particular collection/role name.
#[derive(Debug, Clone, Deserialize)]
pub struct Identity {
    /// User-document collection. Free-form: `users`, `members`, `sc_users`, …
    #[serde(default = "default_users_collection")]
    pub users_collection: String,
    /// Role field on the user doc. Supports a single string (`"admin"`)
    /// or an array (`["admin","staff"]`). Freely replaceable (`posisi`, `level`, …).
    #[serde(default = "default_role_field")]
    pub role_field: String,
    /// Global default owner field; can be overridden per collection.
    #[serde(default = "default_owner_field")]
    pub owner_field: String,
}

impl Default for Identity {
    fn default() -> Self {
        Self {
            users_collection: default_users_collection(),
            role_field: default_role_field(),
            owner_field: default_owner_field(),
        }
    }
}

impl Identity {
    /// Extract roles from a user doc (string or string array).
    /// Ready-made helper for phase-2 auth providers and for tests.
    pub fn roles_of(&self, user_doc: &Doc) -> Vec<String> {
        match user_doc.data.get(&self.role_field) {
            Some(serde_json::Value::String(s)) => vec![s.clone()],
            Some(serde_json::Value::Array(arr)) => arr
                .iter()
                .filter_map(|v| v.as_str().map(|s| s.to_string()))
                .collect(),
            _ => vec![],
        }
    }
}

#[derive(Debug, Clone, Deserialize, Default)]
pub struct Defaults {
    #[serde(default = "deny_default")]
    pub read: Rule,
    #[serde(default = "deny_default")]
    pub write: Rule,
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
    /// Document owner field (default `ownerId`, fallback `uid`).
    pub owner_field: Option<String>,
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
        }
    }

    pub fn load(path: &str) -> Result<Self, String> {
        let raw = std::fs::read_to_string(path).map_err(|e| format!("read {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
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

    /// `resource` = existing doc (get/update/delete), incoming doc (create),
    /// or each listed doc (called per-doc by the server).
    pub fn allow(
        &self,
        auth: Option<&AuthContext>,
        collection: &str,
        method: Method,
        resource: Option<&Doc>,
    ) -> bool {
        let empty = CollectionPolicy::default();
        let policy = self.find(collection).unwrap_or(&empty);
        let rule = policy.slot(method, &self.defaults);
        // owner_field: the per-collection override wins over the user's global default.
        let owner_field = policy.owner_field.as_deref().unwrap_or(&self.identity.owner_field);
        eval(rule, auth, Some(owner_field), resource)
    }
}

fn eval(rule: &Rule, auth: Option<&AuthContext>, owner_field: Option<&str>, resource: Option<&Doc>) -> bool {
    match rule {
        Rule::Public => true,
        Rule::Deny => false,
        Rule::Auth => auth.is_some(),
        Rule::Role(name) => auth.map(|a| a.roles.iter().any(|r| r == name)).unwrap_or(false),
        Rule::Owner => match (auth, resource) {
            (Some(a), Some(doc)) => {
                let fields = [
                    owner_field.unwrap_or("ownerId"),
                    "ownerId",
                    "uid",
                ];
                fields.iter().any(|f| doc.data.get(*f).and_then(|v| v.as_str()) == Some(a.uid.as_str()))
            }
            _ => false,
        },
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
    fn owner_rule() {
        let p = policy(
            r#"
            [collections.profiles]
            read = "owner"
            write = "owner"
            "#,
        );
        let me = auth("u1");
        assert!(p.allow(Some(&me), "profiles", Method::Get, Some(&doc("u1"))));
        assert!(!p.allow(Some(&me), "profiles", Method::Get, Some(&doc("u2"))));
        assert!(!p.allow(None, "profiles", Method::Get, Some(&doc("u1"))));
    }

    #[test]
    fn role_rule_and_typo_fails_closed() {
        let p = policy(
            r#"
            [collections.posts]
            read = "public"
            delete = "role:maintainer"
            update = "rolee:maintainer"
            "#,
        );
        let admin = AuthContext {
            uid: "a".into(),
            roles: vec!["maintainer".into()],
            ..Default::default()
        };
        assert!(p.allow(Some(&admin), "posts", Method::Delete, None));
        assert!(!p.allow(Some(&auth("u1")), "posts", Method::Delete, None));
        // typo -> Deny
        assert!(!p.allow(Some(&admin), "posts", Method::Update, None));
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
        // Free-form roles (not reserved names), custom users_collection & fields.
        let p: PolicyFile = toml::from_str(
            r#"
            [identity]
            users_collection = "members"
            role_field = "posisi"
            owner_field = "pemilikId"
            [collections.arsip]
            read = "owner"
            write = "role:pengurus"
            "#,
        )
        .unwrap();
        assert_eq!(p.identity.users_collection, "members");

        // roles_of: supports a single string or an array, via the custom field.
        let single = Doc {
            id: "u1".into(),
            data: [("posisi".to_string(), json!("pengurus"))].into_iter().collect(),
        };
        let multi = Doc {
            id: "u2".into(),
            data: [("posisi".to_string(), json!(["pengurus", "penulis"]))].into_iter().collect(),
        };
        assert_eq!(p.identity.roles_of(&single), vec!["pengurus"]);
        assert_eq!(p.identity.roles_of(&multi), vec!["pengurus", "penulis"]);

        // owner uses the global pemilikId; the free-form "pengurus" role is honored.
        let owner_doc = Doc {
            id: "d".into(),
            data: [("pemilikId".to_string(), json!("u1"))].into_iter().collect(),
        };
        let me = auth("u1");
        assert!(p.allow(Some(&me), "arsip", Method::Get, Some(&owner_doc)));
        assert!(!p.allow(Some(&auth("u9")), "arsip", Method::Get, Some(&owner_doc)));
        let pengurus = AuthContext {
            uid: "u1".into(),
            roles: vec!["pengurus".into()],
            ..Default::default()
        };
        assert!(p.allow(Some(&pengurus), "arsip", Method::Update, Some(&owner_doc)));
    }

    #[test]
    fn owner_field_per_collection_beats_global() {
        let p: PolicyFile = toml::from_str(
            r#"
            [identity]
            owner_field = "pemilikId"
            [collections.khusus]
            read = "owner"
            owner_field = "ownerUid"
            "#,
        )
        .unwrap();
        let me = auth("u1");
        let via_global = Doc {
            id: "d".into(),
            data: [("pemilikId".to_string(), json!("u1"))].into_iter().collect(),
        };
        let via_override = Doc {
            id: "d".into(),
            data: [("ownerUid".to_string(), json!("u1"))].into_iter().collect(),
        };
        // "khusus" uses the override, not the global.
        assert!(!p.allow(Some(&me), "khusus", Method::Get, Some(&via_global)));
        assert!(p.allow(Some(&me), "khusus", Method::Get, Some(&via_override)));
    }
}

//! hakobackend-policy: pengganti `userrules.ts`.
//!
//! Aturan deklaratif di TOML, **hot-reload tanpa restart** (hakobackend-server memantau
//! mtime file). Gagal parse / typo rule = fail-closed (deny) + pesan error,
//! tidak pernah fail-open.
//!
//! Core TIDAK mengikat nama peran maupun koleksi user — semua milik user
//! via `[identity]` (`users_collection`, `role_field`, `owner_field`).
//! `role:<apapun>` bebas; core hanya membandingkan string.
//!
//! ```toml
//! [identity]
//! users_collection = "members"   # koleksi user versi Anda (default "users")
//! role_field = "posisi"          # field peran versi Anda (default "role")
//! owner_field = "pemilikId"      # field pemilik versi Anda (default "ownerId")
//!
//! [defaults]
//! read = "public"
//! write = "deny"
//!
//! [collections.posts]
//! read = "public"
//! create = "auth"
//! delete = "role:pengurus"       # peran bebas, didefinisikan user
//! ```

use serde::Deserialize;
use std::collections::HashMap;
use hakobackend_core::{AuthContext, Doc, Method};

/// Satu aturan. Dari string TOML: `public|auth|owner|deny|role:<nama>`.
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
                // ponytail: typo rule = deny (fail-closed), bukan error startup.
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

/// Identitas milik USER, bukan core. Menjawab: "dokumen user ada di koleksi
/// mana, field peran yang mana, field pemilik yang mana". Core hanya memakai
/// nilai ini (fase 2: auth provider memuat doc user dari `users_collection`
/// dan memetakan `role_field` menjadi `AuthContext.roles`); core tidak pernah
/// mengasumsikan nama koleksi/peran tertentu.
#[derive(Debug, Clone, Deserialize)]
pub struct Identity {
    /// Koleksi dokumen user. Bebas: `users`, `members`, `sc_users`, …
    #[serde(default = "default_users_collection")]
    pub users_collection: String,
    /// Field peran di dokumen user. Mendukung string tunggal (`"admin"`)
    /// atau array (`["admin","staff"]`). Bebas diganti (`posisi`, `level`, …).
    #[serde(default = "default_role_field")]
    pub role_field: String,
    /// Default field pemilik global; bisa dioverride per koleksi.
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
    /// Ekstrak peran dari dokumen user (string atau array string).
    /// Helper siap pakai untuk auth provider fase 2 dan untuk test.
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
    /// Field dokumen pemilik (default `ownerId`, fallback `uid`).
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
    /// Konfigurasi identitas milik user (koleksi user, field peran/pemilik).
    #[serde(default)]
    pub identity: Identity,
    #[serde(default)]
    pub defaults: Defaults,
    #[serde(default)]
    pub collections: HashMap<String, CollectionPolicy>,
}

impl PolicyFile {
    /// Tanpa file policy (mode dev): semua public + server wajib log WARN.
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
        let raw = std::fs::read_to_string(path).map_err(|e| format!("baca {path}: {e}"))?;
        toml::from_str(&raw).map_err(|e| format!("parse {path}: {e}"))
    }

    /// Resolusi koleksi mengikuti fleksibilitas route (semantik Firestore
    /// "most specific wins", seperti engine lama di `rules.ts:evaluateRule`):
    /// exact (`posts/abc/revisions`) → segmen terakhir (`revisions`) →
    /// root (`posts`) → `[defaults]`.
    fn find(&self, collection: &str) -> Option<&CollectionPolicy> {
        if let Some(p) = self.collections.get(collection) {
            return Some(p);
        }
        if collection.contains('/') {
            let segments: Vec<&str> = collection.split('/').collect();
            if let Some(last) = segments.last() {
                if let Some(p) = self.collections.get(*last) {
                    return Some(p);
                }
            }
            if let Some(root) = segments.first() {
                if let Some(p) = self.collections.get(*root) {
                    return Some(p);
                }
            }
        }
        None
    }

    /// `resource` = dokumen existing (get/update/delete), dokumen incoming (create),
    /// atau tiap dokumen hasil list (dipanggil per-doc oleh server).
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
        // owner_field: override per koleksi menang atas default global milik user.
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
        // koleksi tak dikenal -> defaults
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
    fn hierarchy_exact_last_root() {
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
        // exact menang atas segmen terakhir
        assert!(p.allow(None, "posts/p1/revisions", Method::Get, None));
        // segmen terakhir menang atas root
        assert!(!p.allow(None, "posts/p9/revisions", Method::Get, None));
        assert!(p.allow(Some(&auth("u1")), "posts/p9/revisions", Method::Get, None));
        // root untuk subcollection tanpa aturan sendiri
        assert!(p.allow(None, "posts/p1/comments", Method::Get, None));
        // tanpa kecocokan -> defaults (deny)
        assert!(!p.allow(None, "lain/x/y", Method::Get, None));
    }

    #[test]
    fn identity_milik_user() {
        // Peran bebas (bukan nama cadangan), users_collection & field custom.
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

        // roles_of: dukung string tunggal maupun array, via field custom.
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

        // owner memakai pemilikId global; role bebas "pengurus" dihormati.
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
    fn owner_field_per_koleksi_menang_atas_global() {
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
        // "khusus" memakai override, bukan global.
        assert!(!p.allow(Some(&me), "khusus", Method::Get, Some(&via_global)));
        assert!(p.allow(Some(&me), "khusus", Method::Get, Some(&via_override)));
    }
}

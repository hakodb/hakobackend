//! hakobackend-core: the shared hakobackend contract.
//! Ported from `rethink-firestore/backend/src/lib/{query,rdb}.ts`.
//! All DB drivers (hako, postgres, mysql, sqlite, rethink) implement the [`Database`] trait
//! and must pass the same contract test.

use serde::{Deserialize, Serialize};
use std::collections::HashMap;

// --- Document: id + flexible fields (schemaless, like Firestore) ---

/// One document: identical to the JSON shape used by the legacy wire protocol
/// (`GET /api/collections/<path>/<id>` returns this object + `id`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Doc {
    pub id: String,
    #[serde(flatten)]
    pub data: HashMap<String, serde_json::Value>,
}

// --- Query: ported from FILTER_OPS (query.ts) + RethinkDBOptions (rdb.ts) ---

/// Filter operators supported by the gateway. The HakoDB superset covers all of them
/// (see `hakodb/src/query/filter.rs`); SQL drivers translate them to JSON paths.
/// The wire protocol accepts the legacy SYMBOLIC form (`==`, `>`, `array-contains`, …)
/// as well as words (`eq`, `gt`, …) — both map to the same variant.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FilterOp {
    Eq,
    Ne,
    Gt,
    Lt,
    Gte,
    Lte,
    ArrayContains,
    ArrayContainsAny,
    In,
}

impl FilterOp {
    pub fn as_wire(&self) -> &'static str {
        match self {
            FilterOp::Eq => "==",
            FilterOp::Ne => "!=",
            FilterOp::Gt => ">",
            FilterOp::Lt => "<",
            FilterOp::Gte => ">=",
            FilterOp::Lte => "<=",
            FilterOp::ArrayContains => "array-contains",
            FilterOp::ArrayContainsAny => "array-contains-any",
            FilterOp::In => "in",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        Some(match s {
            "==" | "eq" => FilterOp::Eq,
            "!=" | "ne" => FilterOp::Ne,
            ">" | "gt" => FilterOp::Gt,
            "<" | "lt" => FilterOp::Lt,
            ">=" | "gte" => FilterOp::Gte,
            "<=" | "lte" => FilterOp::Lte,
            "array-contains" => FilterOp::ArrayContains,
            "array-contains-any" => FilterOp::ArrayContainsAny,
            "in" => FilterOp::In,
            _ => return None,
        })
    }
}

impl Serialize for FilterOp {
    fn serialize<S: serde::Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        s.serialize_str(self.as_wire())
    }
}

impl<'de> Deserialize<'de> for FilterOp {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let s = String::deserialize(d)?;
        FilterOp::parse(&s).ok_or_else(|| serde::de::Error::unknown_variant(&s, &["==", "!=", ">", "<", ">=", "<=", "array-contains", "array-contains-any", "in"]))
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Filter {
    pub field: String,
    pub op: FilterOp,
    pub value: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OrderBy {
    pub field: String,
    #[serde(default = "asc_default")]
    pub direction: Direction,
}

fn asc_default() -> Direction {
    Direction::Asc
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Direction {
    Asc,
    Desc,
}

/// List/query options — parsed from `?options=<json>` exactly like the legacy server.
/// Legacy camelCase keys (`orderBy`, `startAt`, …) are accepted via alias.
/// `offset` is a new capability (legacy lacked it; HakoDB/Firestore-style).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct QueryOptions {
    #[serde(default)]
    pub filters: Vec<Filter>,
    #[serde(default)]
    pub fields: Vec<String>,
    #[serde(default, alias = "orderBy")]
    pub order_by: Vec<OrderBy>,
    pub limit: Option<usize>,
    pub offset: Option<usize>,
    #[serde(default, alias = "startAt")]
    pub start_at: Option<serde_json::Value>,
    #[serde(default, alias = "startAfter")]
    pub start_after: Option<serde_json::Value>,
    #[serde(default, alias = "endAt")]
    pub end_at: Option<serde_json::Value>,
    #[serde(default, alias = "endBefore")]
    pub end_before: Option<serde_json::Value>,
}

// --- Path: even/odd rules (server.ts:getPathInfo) ---

/// Parse result of `/api/collections/{*path}`: an even segment count = document.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathKind {
    Document { collection: String, id: String },
    Collection { collection: String },
}

pub fn parse_collection_path(raw: &str) -> PathKind {
    let clean = raw.trim_matches('/');
    let segments: Vec<&str> = clean.split('/').filter(|s| !s.is_empty()).collect();
    if segments.len() % 2 == 0 && !segments.is_empty() {
        PathKind::Document {
            collection: segments[..segments.len() - 1].join("/"),
            id: segments[segments.len() - 1].to_string(),
        }
    } else {
        PathKind::Collection {
            collection: clean.to_string(),
        }
    }
}

/// `posts/123/revisions` -> `posts_revisions` (ported from `getFlatTableName`).
/// SQL drivers use this; HakoDB uses the original hierarchical path.
pub fn flat_table_name(collection_path: &str) -> String {
    if !collection_path.contains('/') {
        return collection_path.to_string();
    }
    collection_path
        .split('/')
        .enumerate()
        .filter(|(i, _)| i % 2 == 0)
        .map(|(_, s)| s)
        .collect::<Vec<_>>()
        .join("_")
}

// --- Auth: uniform context for all providers (replacing Firebase-only auth) ---
//
// Two provider roles (AUTH_CONTRACT.md):
// - Verifier (all providers): only `verify` a foreign token into Claims. Stateless.
// - Issuer (ONLY `local`): issues + manages sessions/tokens (SessionIssuer, phase C).

/// Normalized claims from verification. Providers only fill in this struct;
/// policy never knows which provider was used.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct AuthContext {
    /// Namespaced uid (`github:123`, `local:abc`) so providers never collide.
    pub uid: String,
    #[serde(default)]
    pub roles: Vec<String>,
    #[serde(default)]
    pub tenant: Option<String>,
    #[serde(default)]
    pub extra: HashMap<String, serde_json::Value>,
}

/// Raw token-verification result from one provider, before role mapping + union.
#[derive(Debug, Clone, Default)]
pub struct Claims {
    /// Provider name (`local`, `firebase`, `github`, `oidc`).
    pub provider: &'static str,
    /// Raw uid from the provider (unnamespaced; the resolver adds the namespace).
    pub uid: String,
    pub email: Option<String>,
    pub extra: HashMap<String, serde_json::Value>,
}

impl Claims {
    /// `github:123` — user-doc lookup key + final `AuthContext.uid`.
    pub fn namespaced(&self) -> String {
        format!("{}:{}", self.provider, self.uid)
    }
}

/// Verifier: required impl for all auth providers (including `local` for its own tokens).
#[async_trait::async_trait]
pub trait AuthProvider: Send + Sync {
    fn name(&self) -> &'static str;
    /// `Ok` = valid token owned by this provider; `Err` = not our token / invalid.
    /// The chain tries the next provider on Err — so don't error for a foreign token
    /// that is clearly not yours; only error for your own token failing verification.
    async fn verify(&self, token: &str) -> Result<Claims, AppError>;
}

/// Issuer: ONLY `local` (phase C). External providers never implement this —
/// the backend never issues tokens on behalf of Firebase/GitHub/OIDC.
#[async_trait::async_trait]
pub trait SessionIssuer: AuthProvider {
    async fn login(&self, user: &str, secret: &str) -> Result<AuthContext, AppError>;
    async fn refresh(&self, refresh_token: &str) -> Result<AuthContext, AppError>;
    async fn logout(&self, ctx: &AuthContext) -> Result<(), AppError>;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Method {
    Get,
    List,
    Create,
    Update,
    Delete,
}

// --- Gateway error ---

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("permission denied")]
    PermissionDenied,
    #[error("not found")]
    NotFound,
    #[error("already exists")]
    AlreadyExists,
    #[error("bad request: {0}")]
    BadRequest(String),
    #[error("internal: {0}")]
    Internal(String),
}

impl AppError {
    /// HTTP status — mapped from the legacy server's `mapError`.
    pub fn status_code(&self) -> u16 {
        match self {
            AppError::PermissionDenied => 403,
            AppError::NotFound => 404,
            AppError::AlreadyExists => 400,
            AppError::BadRequest(_) => 400,
            AppError::Internal(_) => 500,
        }
    }

    /// Legacy `mapError` code string for `{error, code}` write failures.
    pub fn code(&self) -> &'static str {
        match self {
            AppError::PermissionDenied => "permission-denied",
            AppError::NotFound => "not-found",
            AppError::AlreadyExists => "already-exists",
            AppError::BadRequest(_) => "bad-request",
            AppError::Internal(_) => "internal",
        }
    }
}

// --- Database trait: the plug-and-play contract (replacing RethinkDBService) ---

/// Document change for realtime fan-out. HakoDB: `ChangeEvent{path, Put|Delete}`;
/// other drivers: RethinkDB changefeed / pg LISTEN / polling.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChangeKind {
    Add,
    Change,
    Remove,
}

#[derive(Debug, Clone)]
pub struct Change {
    pub collection: String,
    /// Document id (always present; Delete carries no body).
    pub id: String,
    pub kind: ChangeKind,
    pub old: Option<Doc>,
    pub new: Option<Doc>,
}

#[async_trait::async_trait]
pub trait Database: Send + Sync {
    /// Driver identity + capabilities (see DRIVER_CONTRACT.md).
    /// Core uses this to decide what to push down vs emulate.
    fn capabilities(&self) -> Capabilities;
    async fn ensure_collection(&self, path: &str) -> Result<(), AppError>;
    async fn list_collections(&self) -> Result<Vec<String>, AppError>;
    async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError>;
    async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError>;
    /// `merge=false` = replace the whole body; `merge=true` = shallow top-level merge.
    async fn insert(&self, collection: &str, doc: Doc) -> Result<Doc, AppError>;
    async fn set(&self, collection: &str, id: &str, doc: Doc, merge: bool) -> Result<Doc, AppError>;
    /// Returns the document before deletion (None when absent).
    async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError>;
    async fn count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError>;
    /// Change stream; bridged to broadcast in hakobackend-server (WS/SSE + Redis fan-out).
    async fn subscribe(&self, collection: &str) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError>;
    /// Create an index (simple/composite/FTS). Unsupported capability → reject clearly.
    async fn create_index(&self, collection: &str, spec: &IndexSpec) -> Result<IndexInfo, AppError>;
    async fn list_indexes(&self, collection: &str) -> Result<Vec<IndexInfo>, AppError>;
    /// Drop an index by name. Drivers without a drop API → reject clearly.
    async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError>;
    /// Atomic multi-op batch (`/api/batch`, `/api/transaction`): all ops
    /// apply or none do. Reads inside observe the batch's own writes.
    /// Default: reject clearly (drivers advertising `supports_transactions`
    /// must override).
    async fn run_transaction(&self, _ops: Vec<TxOp>) -> Result<Vec<TxOut>, AppError> {
        Err(AppError::BadRequest("driver has no transaction support".into()))
    }
}

/// One operation inside `run_transaction`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TxOp {
    pub collection: String,
    pub id: String,
    pub kind: TxOpKind,
    /// Body for Put (ignored for Read/Delete).
    #[serde(default)]
    pub doc: Option<Doc>,
}

/// Operation kind. `Put.must_exist` mirrors the legacy `update` (error when
/// absent); plain `set`/`add` create freely.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum TxOpKind {
    Read,
    Put { merge: bool, must_exist: bool },
    Delete,
}

/// One result, aligned with its op: the doc read/written (None for deletes
/// of absent docs) plus whether the doc existed before this op ran.
#[derive(Debug, Clone)]
pub struct TxOut {
    pub doc: Option<Doc>,
    pub existed: bool,
}

/// Capabilities declared by each addon driver.
#[derive(Debug, Clone)]
pub struct Capabilities {
    /// Driver name, matching `name` in driver.toml (`hako`, `postgres`, …).
    pub driver: &'static str,
    /// Realtime change watch/push (when false, core uses polling).
    pub supports_watch: bool,
    /// Atomic multi-op transactions (batch/transaction endpoint).
    pub supports_transactions: bool,
    /// Multi-field composite index (when false → reject clearly, don't stay silent).
    pub supports_composite: bool,
    /// Full-text search (when false → reject clearly).
    pub supports_fts: bool,
    /// Drop index (when false → reject clearly; e.g. HakoDB has no drop API).
    pub supports_drop_index: bool,
    /// Unique constraint (when false → reject clearly; e.g. HakoDB).
    pub supports_unique: bool,
    /// Custom index names honored (when false → always auto, e.g. HakoDB).
    pub supports_named_index: bool,
}

// --- Index: simple/composite/FTS management contract (HTTP_CONTRACT.md §index) ---

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexKind {
    Simple,
    Composite,
    #[serde(rename = "fts")]
    FullText,
}

fn simple_kind() -> IndexKind {
    IndexKind::Simple
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexSpec {
    /// Free-form name; drivers without naming (HakoDB) ignore it + auto-generate.
    pub name: Option<String>,
    /// 1 field = simple/FTS; >1 = composite (requires supports_composite).
    pub fields: Vec<String>,
    #[serde(default)]
    pub unique: bool,
    #[serde(default = "simple_kind")]
    pub kind: IndexKind,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IndexInfo {
    pub name: String,
    pub fields: Vec<String>,
    pub unique: bool,
    pub kind: IndexKind,
}

// --- Policy trait: replacing userrules.ts ---

/// `resource` = existing document (None for create/list), `incoming` = write body.
pub struct PolicyInput<'a> {
    pub auth: Option<&'a AuthContext>,
    pub collection: &'a str,
    pub method: Method,
    pub resource: Option<&'a Doc>,
    pub incoming: Option<&'a Doc>,
}

#[async_trait::async_trait]
pub trait Policy: Send + Sync {
    async fn allow(&self, input: PolicyInput<'_>) -> bool;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_parity_with_legacy_get_path_info() {
        assert_eq!(
            parse_collection_path("posts"),
            PathKind::Collection {
                collection: "posts".into()
            }
        );
        assert_eq!(
            parse_collection_path("posts/abc"),
            PathKind::Document {
                collection: "posts".into(),
                id: "abc".into()
            }
        );
        assert_eq!(
            parse_collection_path("posts/abc/revisions"),
            PathKind::Collection {
                collection: "posts/abc/revisions".into()
            }
        );
        assert_eq!(
            parse_collection_path("posts/abc/revisions/r1"),
            PathKind::Document {
                collection: "posts/abc/revisions".into(),
                id: "r1".into()
            }
        );
    }

    #[test]
    fn flat_table_parity_with_legacy() {
        assert_eq!(flat_table_name("posts"), "posts");
        assert_eq!(flat_table_name("posts/123/revisions"), "posts_revisions");
    }

    #[test]
    fn filter_op_wire_legacy() {
        // Legacy symbolic (used by the old SDK) + word (new form) → same variant.
        for (wire, word, op) in [
            ("==", "eq", FilterOp::Eq),
            ("!=", "ne", FilterOp::Ne),
            (">", "gt", FilterOp::Gt),
            ("<", "lt", FilterOp::Lt),
            (">=", "gte", FilterOp::Gte),
            ("<=", "lte", FilterOp::Lte),
            ("array-contains", "array-contains", FilterOp::ArrayContains),
            ("array-contains-any", "array-contains-any", FilterOp::ArrayContainsAny),
            ("in", "in", FilterOp::In),
        ] {
            assert_eq!(FilterOp::parse(wire), Some(op));
            assert_eq!(FilterOp::parse(word), Some(op));
            let back: FilterOp = serde_json::from_str(&format!("\"{wire}\"")).unwrap();
            assert_eq!(back, op);
        }
        assert_eq!(FilterOp::parse("!="), Some(FilterOp::Ne));
        assert!(FilterOp::parse("contains").is_none());
        // Full options JSON as sent by the old SDK.
        let q: QueryOptions = serde_json::from_str(
            r#"{"filters":[{"field":"age","op":">","value":20}],"order_by":[{"field":"age","direction":"desc"}],"limit":1}"#,
        )
        .unwrap();
        assert_eq!(q.filters[0].op, FilterOp::Gt);
        assert_eq!(q.limit, Some(1));
        // Legacy camelCase keys are also accepted.
        let qc: QueryOptions = serde_json::from_str(
            r#"{"filters":[],"orderBy":[{"field":"age","direction":"desc"}],"startAt":10,"endBefore":99}"#,
        )
        .unwrap();
        assert_eq!(qc.order_by.len(), 1);
        assert_eq!(qc.start_at, Some(serde_json::json!(10)));
        assert_eq!(qc.end_before, Some(serde_json::json!(99)));
    }
}

/// Driver contract: conformance suite + emulation helpers.
///
/// Every database addon (`hakobackend-db-*`) **must** call
/// [`conformance::run_conformance_suite`] from its own test.
/// Helpers [`conformance::doc_matches`] / [`conformance::sort_and_limit`]
/// are used by drivers without native JSON ops so filter/sort/limit
/// semantics stay **identical** across drivers (see DRIVER_CONTRACT.md).
pub mod conformance {
    use super::*;
    use std::cmp::Ordering;

    fn nested<'a>(data: &'a HashMap<String, serde_json::Value>, field: &str) -> Option<&'a serde_json::Value> {
        let mut cur: Option<&serde_json::Value> = None;
        for (i, part) in field.split('.').enumerate() {
            if i == 0 {
                cur = data.get(part);
            } else {
                cur = cur.and_then(|v| v.as_object()).and_then(|m| m.get(part));
            }
        }
        cur
    }

    fn cmp_json(a: &serde_json::Value, b: &serde_json::Value) -> Option<Ordering> {
        match (a, b) {
            (serde_json::Value::Number(x), serde_json::Value::Number(y)) => {
                x.as_f64()?.partial_cmp(&y.as_f64()?)
            }
            (serde_json::Value::String(x), serde_json::Value::String(y)) => Some(x.cmp(y)),
            (serde_json::Value::Bool(x), serde_json::Value::Bool(y)) => Some(x.cmp(y)),
            _ => (a == b).then_some(Ordering::Equal),
        }
    }

    fn filter_matches(doc: &Doc, f: &Filter) -> bool {
        let v = nested(&doc.data, &f.field);
        match f.op {
            FilterOp::Eq => v == Some(&f.value),
            FilterOp::Ne => v != Some(&f.value),
            FilterOp::Gt => v.and_then(|x| cmp_json(x, &f.value)).is_some_and(|o| o == Ordering::Greater),
            FilterOp::Lt => v.and_then(|x| cmp_json(x, &f.value)).is_some_and(|o| o == Ordering::Less),
            FilterOp::Gte => v
                .and_then(|x| cmp_json(x, &f.value))
                .is_some_and(|o| o != Ordering::Less),
            FilterOp::Lte => v
                .and_then(|x| cmp_json(x, &f.value))
                .is_some_and(|o| o != Ordering::Greater),
            FilterOp::In => f
                .value
                .as_array()
                .is_some_and(|arr| arr.iter().any(|item| Some(item) == v)),
            FilterOp::ArrayContains => v
                .and_then(|x| x.as_array())
                .is_some_and(|arr| arr.contains(&f.value)),
            FilterOp::ArrayContainsAny => match (v.and_then(|x| x.as_array()), f.value.as_array()) {
                (Some(hay), Some(needles)) => needles.iter().any(|n| hay.contains(n)),
                _ => false,
            },
        }
    }

    /// Standard filter predicate. Drivers without a native JSON filter
    /// (or for verification) use this function so results are ALWAYS identical.
    pub fn doc_matches(doc: &Doc, filters: &[Filter]) -> bool {
        filters.iter().all(|f| filter_matches(doc, f))
    }

    /// Cursor reference field: `order_by[0]` or `"id"` (legacy `rdb.ts` parity).
    pub fn cursor_field(q: &QueryOptions) -> &str {
        q.order_by.first().map(|o| o.field.as_str()).unwrap_or("id")
    }

    /// Standard cursor predicate (`rdb.ts:cursorFilter` + legacy ReQL parity):
    /// startAt `>=`, startAfter `>`, endAt `<=`, endBefore `<` on the reference field.
    /// Bound present + missing/null/incomparable value = false.
    /// Sort direction is IGNORED (legacy parity).
    pub fn matches_cursor(doc: &Doc, q: &QueryOptions) -> bool {
        // "id" is not part of data — support it as the fallback reference field.
        let owned;
        let v = match nested(&doc.data, cursor_field(q)) {
            Some(v) => Some(v),
            None if cursor_field(q) == "id" => {
                owned = serde_json::Value::String(doc.id.clone());
                Some(&owned)
            }
            None => None,
        };
        let checks: [(Option<&serde_json::Value>, fn(Ordering) -> bool); 4] = [
            (q.start_at.as_ref(), |o| o != Ordering::Less),
            (q.start_after.as_ref(), |o| o == Ordering::Greater),
            (q.end_at.as_ref(), |o| o != Ordering::Greater),
            (q.end_before.as_ref(), |o| o == Ordering::Less),
        ];
        for (bound, ok) in checks {
            let Some(b) = bound else { continue };
            let Some(x) = v else { return false };
            let Some(o) = cmp_json(x, b) else { return false };
            if !ok(o) {
                return false;
            }
        }
        true
    }

    /// Filter by cursor (applied after sorting, before limit — legacy parity).
    pub fn apply_cursor(docs: Vec<Doc>, q: &QueryOptions) -> Vec<Doc> {
        docs.into_iter().filter(|d| matches_cursor(d, q)).collect()
    }

    /// Slice offset + limit (offset first, then limit — SQL convention).
    pub fn apply_offset_limit(docs: Vec<Doc>, q: &QueryOptions) -> Vec<Doc> {
        let off = q.offset.unwrap_or(0).min(docs.len());
        let mut docs = docs.into_iter().skip(off).collect::<Vec<_>>();
        if let Some(n) = q.limit {
            docs.truncate(n);
        }
        docs
    }

    /// Standard list pipeline: sort → cursor → offset → limit (legacy parity).
    /// Emulating drivers / MemDb use this so results are ALWAYS identical.
    pub fn sort_and_limit(mut docs: Vec<Doc>, q: &QueryOptions) -> Vec<Doc> {
        if !q.order_by.is_empty() {
            docs.sort_by(|a, b| {
                for o in &q.order_by {
                    let ord = match (nested(&a.data, &o.field), nested(&b.data, &o.field)) {
                        (Some(x), Some(y)) => cmp_json(x, y).unwrap_or(Ordering::Equal),
                        (Some(_), None) => Ordering::Greater,
                        (None, Some(_)) => Ordering::Less,
                        (None, None) => Ordering::Equal,
                    };
                    let ord = match o.direction {
                        Direction::Asc => ord,
                        Direction::Desc => ord.reverse(),
                    };
                    if ord != Ordering::Equal {
                        return ord;
                    }
                }
                Ordering::Equal
            });
        }
        apply_offset_limit(apply_cursor(docs, q), q)
    }

    fn mk(data: serde_json::Value) -> Doc {
        Doc {
            id: String::new(),
            data: data.as_object().unwrap().clone().into_iter().collect(),
        }
    }

    /// Conformance suite. Unique collection per run so parallel runs stay isolated.
    /// Failing here = the driver must not be registered yet.
    pub async fn run_conformance_suite(db: &impl Database) {
        assert!(!db.capabilities().driver.is_empty(), "capabilities().driver is required");
        let coll = format!("conf_{}_{}", std::process::id(), nanos());
        let q0 = QueryOptions::default();

        // 1. A fresh collection = empty list.
        assert!(db.list(&coll, &q0).await.unwrap().is_empty());

        // 2. Insert without id -> id filled; get roundtrip.
        let d = db
            .insert(&coll, mk(serde_json::json!({"name": "a", "age": 30, "tags": ["x", "y"]})))
            .await
            .unwrap();
        assert!(!d.id.is_empty(), "insert must fill an empty id");
        let got = db.get(&coll, &d.id).await.unwrap().expect("get after insert");
        assert_eq!(got.data.get("name"), Some(&serde_json::json!("a")));

        // 3. Extra data for queries.
        for (name, age, tags) in [("b", 25, vec!["y"]), ("c", 35, vec!["z"])] {
            db.insert(
                &coll,
                mk(serde_json::json!({"name": name, "age": age, "tags": tags})),
            )
            .await
            .unwrap();
        }
        assert_eq!(db.list(&coll, &q0).await.unwrap().len(), 3);

        // 4. All filter operators.
        let filtered = |op: FilterOp, value: serde_json::Value| {
            let mut q = QueryOptions::default();
            q.filters.push(Filter {
                field: "age".into(),
                op,
                value,
            });
            q
        };
        let n = |q: QueryOptions| {
            let coll = coll.clone();
            async move { db.list(&coll, &q).await.unwrap().len() }
        };
        assert_eq!(n(filtered(FilterOp::Eq, serde_json::json!(25))).await, 1);
        assert_eq!(n(filtered(FilterOp::Ne, serde_json::json!(25))).await, 2);
        assert_eq!(n(filtered(FilterOp::Gt, serde_json::json!(30))).await, 1);
        assert_eq!(n(filtered(FilterOp::Gte, serde_json::json!(30))).await, 2);
        assert_eq!(n(filtered(FilterOp::Lt, serde_json::json!(30))).await, 1);
        assert_eq!(n(filtered(FilterOp::Lte, serde_json::json!(30))).await, 2);

        let mut qi = QueryOptions::default();
        qi.filters.push(Filter {
            field: "age".into(),
            op: FilterOp::In,
            value: serde_json::json!([25, 35]),
        });
        assert_eq!(db.list(&coll, &qi).await.unwrap().len(), 2);

        let mut qt = QueryOptions::default();
        qt.filters.push(Filter {
            field: "tags".into(),
            op: FilterOp::ArrayContains,
            value: serde_json::json!("y"),
        });
        assert_eq!(db.list(&coll, &qt).await.unwrap().len(), 2);

        let mut qa = QueryOptions::default();
        qa.filters.push(Filter {
            field: "tags".into(),
            op: FilterOp::ArrayContainsAny,
            value: serde_json::json!(["x", "z"]),
        });
        assert_eq!(db.list(&coll, &qa).await.unwrap().len(), 2);

        // 5. Order + limit + count.
        let mut qo = QueryOptions::default();
        qo.order_by.push(OrderBy {
            field: "age".into(),
            direction: Direction::Desc,
        });
        qo.limit = Some(2);
        let rows = db.list(&coll, &qo).await.unwrap();
        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].data.get("age"), Some(&serde_json::json!(35)));
        assert_eq!(db.count(&coll, &q0).await.unwrap(), 3);

        // 5b. Cursor (reference = order_by[0]) + offset. rdb.ts:cursorFilter parity.
        let ordered = |cursor: QueryOptions| {
            let mut q = cursor;
            q.order_by.push(OrderBy { field: "age".into(), direction: Direction::Asc });
            q
        };
        let ages = |q: QueryOptions| {
            let coll = coll.clone();
            async move {
                db.list(&coll, &q)
                    .await
                    .unwrap()
                    .into_iter()
                    .map(|d| d.data.get("age").cloned().unwrap_or(serde_json::Value::Null))
                    .collect::<Vec<_>>()
            }
        };
        let mut qc = QueryOptions::default();
        qc.start_after = Some(serde_json::json!(25));
        assert_eq!(ages(ordered(qc)).await, vec![serde_json::json!(30), serde_json::json!(35)]);
        let mut qc2 = QueryOptions::default();
        qc2.start_at = Some(serde_json::json!(30));
        qc2.end_at = Some(serde_json::json!(35));
        assert_eq!(ages(ordered(qc2)).await, vec![serde_json::json!(30), serde_json::json!(35)]);
        let mut qc3 = QueryOptions::default();
        qc3.end_before = Some(serde_json::json!(30));
        assert_eq!(ages(ordered(qc3)).await, vec![serde_json::json!(25)]);
        // Offset after sorting, before limit.
        let mut qoff = QueryOptions::default();
        qoff.order_by.push(OrderBy { field: "age".into(), direction: Direction::Asc });
        qoff.offset = Some(1);
        qoff.limit = Some(1);
        assert_eq!(ages(qoff).await, vec![serde_json::json!(30)]);
        // Documents missing the reference field + an active cursor = excluded (ReQL parity).
        let ageless = db.insert(&coll, mk(serde_json::json!({"name": "d"}))).await.unwrap();
        let mut qnull = QueryOptions::default();
        qnull.order_by.push(OrderBy { field: "age".into(), direction: Direction::Asc });
        qnull.start_after = Some(serde_json::json!(0));
        let got = ages(qnull).await;
        assert!(!got.contains(&serde_json::Value::Null));
        db.delete(&coll, &ageless.id).await.unwrap();

        // 6. set merge=false replaces; merge=true shallow-merges.
        db.set(&coll, &d.id, mk(serde_json::json!({"name": "a2"})), false)
            .await
            .unwrap();
        let r = db.get(&coll, &d.id).await.unwrap().unwrap();
        assert_eq!(r.data.get("name"), Some(&serde_json::json!("a2")));
        assert!(!r.data.contains_key("age"), "replace must drop old fields");

        db.set(&coll, &d.id, mk(serde_json::json!({"city": "bdg"})), true)
            .await
            .unwrap();
        let m = db.get(&coll, &d.id).await.unwrap().unwrap();
        assert_eq!(m.data.get("name"), Some(&serde_json::json!("a2")));
        assert_eq!(m.data.get("city"), Some(&serde_json::json!("bdg")));

        // 7. delete returns prev; get -> None.
        let prev = db.delete(&coll, &d.id).await.unwrap();
        assert!(prev.is_some(), "delete must return the previous document");
        assert!(db.get(&coll, &d.id).await.unwrap().is_none());
        assert!(db.delete(&coll, &d.id).await.unwrap().is_none());

        // 8. subscribe must not error.
        assert!(db.subscribe(&coll).await.is_ok());

        // 9. run_transaction: read-your-writes, must_exist, atomic rollback.
        let txc = format!("{coll}_tx");
        let put = |id: &str, age: i64| TxOp {
            collection: txc.clone(),
            id: id.into(),
            kind: TxOpKind::Put { merge: false, must_exist: false },
            doc: Some(mk(serde_json::json!({"age": age}))),
        };
        let out = db
            .run_transaction(vec![
                put("t1", 1),
                put("t2", 2),
                TxOp {
                    collection: txc.clone(),
                    id: "t1".into(),
                    kind: TxOpKind::Read,
                    doc: None,
                },
            ])
            .await
            .unwrap();
        assert_eq!(out.len(), 3);
        assert!(!out[0].existed && !out[1].existed);
        assert!(out[2].existed);
        assert_eq!(out[2].doc.as_ref().unwrap().data.get("age"), Some(&serde_json::json!(1)));
        // must_exist on a missing doc aborts the whole batch.
        let bad = db
            .run_transaction(vec![
                put("t3", 3),
                TxOp {
                    collection: txc.clone(),
                    id: "ghost".into(),
                    kind: TxOpKind::Put { merge: true, must_exist: true },
                    doc: Some(mk(serde_json::json!({"age": 9}))),
                },
            ])
            .await;
        assert!(matches!(bad, Err(AppError::NotFound)));
        assert!(db.get(&txc, "t3").await.unwrap().is_none(), "abort must roll back t3");
        // Delete reports prev + existed.
        let del = db
            .run_transaction(vec![TxOp {
                collection: txc.clone(),
                id: "t1".into(),
                kind: TxOpKind::Delete,
                doc: None,
            }])
            .await
            .unwrap();
        assert!(del[0].existed && del[0].doc.is_some());
        assert!(db.get(&txc, "t1").await.unwrap().is_none());
    }

    fn nanos() -> u128 {
        use std::time::{SystemTime, UNIX_EPOCH};
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    }

    // --- Index contract: shared validation + suite ---

    /// Standard spec validation against capabilities. Used by all drivers so
    /// rejections are identical (no silent-ignore).
    pub fn validate_spec(caps: Capabilities, spec: &IndexSpec) -> Result<(), AppError> {
        if spec.fields.is_empty() {
            return Err(AppError::BadRequest("index needs >= 1 field".into()));
        }
        match spec.kind {
            IndexKind::Simple | IndexKind::FullText if spec.fields.len() > 1 => {
                return Err(AppError::BadRequest("simple/fts index takes exactly 1 field (multi-field = composite)".into()))
            }
            _ => {}
        }
        if spec.kind == IndexKind::Composite && !caps.supports_composite {
            return Err(AppError::BadRequest(format!("driver {} has no composite index", caps.driver)));
        }
        if spec.kind == IndexKind::FullText && !caps.supports_fts {
            return Err(AppError::BadRequest(format!("driver {} has no full-text index", caps.driver)));
        }
        Ok(())
    }

    /// Deterministic auto name when spec.name is empty / the driver has no naming.
    pub fn auto_index_name(spec: &IndexSpec) -> String {
        let base = spec.fields.join("+");
        match spec.kind {
            IndexKind::Simple => base,
            IndexKind::Composite => format!("composite({base})"),
            IndexKind::FullText => format!("fts({base})"),
        }
    }

    /// Index conformance suite. Conditional on capabilities (composite/FTS/drop).
    pub async fn run_index_suite(db: &impl Database) {
        let caps = db.capabilities();
        let coll = format!("idx_{}_{}", std::process::id(), nanos());
        assert!(db.list_indexes(&coll).await.unwrap().is_empty());

        // An empty spec is always rejected.
        let bad = IndexSpec { name: None, fields: vec![], unique: false, kind: IndexKind::Simple };
        assert!(db.create_index(&coll, &bad).await.is_err());
        // Multi-field simple is rejected (must be composite).
        let bad2 = IndexSpec {
            name: None,
            fields: vec!["a".into(), "b".into()],
            unique: false,
            kind: IndexKind::Simple,
        };
        assert!(db.create_index(&coll, &bad2).await.is_err());

        let simple = db
            .create_index(&coll, &IndexSpec {
                name: Some("by_age".into()),
                fields: vec!["age".into()],
                unique: false,
                kind: IndexKind::Simple,
            })
            .await
            .unwrap();
        // Drivers without naming always go auto (fail-clear, not silent).
        let want_simple = if caps.supports_named_index { "by_age" } else { "age" };
        assert_eq!(simple.fields, vec!["age".to_string()]);
        // Deterministic auto name.
        let auto = db
            .create_index(&coll, &IndexSpec { name: None, fields: vec!["name".into()], unique: true, kind: IndexKind::Simple })
            .await;
        if caps.supports_unique {
            let auto = auto.unwrap();
            assert_eq!(auto.name, "name");
            assert!(auto.unique);
        } else {
            // Without a unique constraint → reject clearly (fail-clear, not silent).
            assert!(auto.is_err());
            // Retry without unique so the collection is ready for the next steps.
            db.create_index(&coll, &IndexSpec { name: None, fields: vec!["name".into()], unique: false, kind: IndexKind::Simple })
                .await
                .unwrap();
        }

        if caps.supports_composite {
            let comp = db
                .create_index(&coll, &IndexSpec {
                    name: None,
                    fields: vec!["a".into(), "b".into()],
                    unique: false,
                    kind: IndexKind::Composite,
                })
                .await
                .unwrap();
            assert_eq!(comp.name, "composite(a+b)");
        }
        if caps.supports_fts {
            let fts = db
                .create_index(&coll, &IndexSpec {
                    name: None,
                    fields: vec!["body".into()],
                    unique: false,
                    kind: IndexKind::FullText,
                })
                .await
                .unwrap();
            assert_eq!(fts.name, "fts(body)");
        }

        let all = db.list_indexes(&coll).await.unwrap();
        assert!(all.iter().any(|i| i.name == want_simple));

        if caps.supports_drop_index {
            db.drop_index(&coll, want_simple).await.unwrap();
            assert!(db.list_indexes(&coll).await.unwrap().iter().all(|i| i.name != want_simple));
            assert!(db.drop_index(&coll, "missing").await.is_err());
        }
    }

    // --- In-memory reference driver: proof the suite is valid + minimal addon example ---

    /// The smallest `Database` implementation that passes the suite.
    /// Used as a hakobackend-core test; prospective driver authors can copy the pattern.
    #[cfg(test)]
    pub struct MemDb {
        store: std::sync::Mutex<HashMap<String, HashMap<String, Doc>>>,
        indexes: std::sync::Mutex<HashMap<String, Vec<IndexInfo>>>,
    }

    #[cfg(test)]
    impl MemDb {
        pub fn new() -> Self {
            Self {
                store: std::sync::Mutex::new(HashMap::new()),
                indexes: std::sync::Mutex::new(HashMap::new()),
            }
        }
    }

    #[cfg(test)]
    #[async_trait::async_trait]
    impl Database for MemDb {
        fn capabilities(&self) -> Capabilities {
            Capabilities {
                driver: "mem",
                supports_watch: false,
                supports_transactions: false,
                supports_composite: true,
                supports_fts: true,
                supports_drop_index: true,
                supports_unique: true,
                supports_named_index: true,
            }
        }
        async fn ensure_collection(&self, _path: &str) -> Result<(), AppError> {
            Ok(())
        }
        async fn list_collections(&self) -> Result<Vec<String>, AppError> {
            Ok(self.store.lock().unwrap().keys().cloned().collect())
        }
        async fn get(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
            Ok(self.store.lock().unwrap().get(collection).and_then(|t| t.get(id)).cloned())
        }
        async fn list(&self, collection: &str, q: &QueryOptions) -> Result<Vec<Doc>, AppError> {
            let docs: Vec<Doc> = self
                .store
                .lock()
                .unwrap()
                .get(collection)
                .map(|t| t.values().filter(|d| doc_matches(d, &q.filters)).cloned().collect())
                .unwrap_or_default();
            Ok(sort_and_limit(docs, q))
        }
        async fn insert(&self, collection: &str, mut doc: Doc) -> Result<Doc, AppError> {
            if doc.id.is_empty() {
                doc.id = format!("m{}", nanos());
            }
            self.set(collection, &doc.id.clone(), doc, false).await
        }
        async fn set(&self, collection: &str, id: &str, doc: Doc, merge: bool) -> Result<Doc, AppError> {
            let mut store = self.store.lock().unwrap();
            let table = store.entry(collection.to_string()).or_default();
            let mut data = if merge {
                table.get(id).map(|old| old.data.clone()).unwrap_or_default()
            } else {
                HashMap::new()
            };
            data.extend(doc.data);
            let out = Doc { id: id.to_string(), data };
            table.insert(id.to_string(), out.clone());
            Ok(out)
        }
        async fn delete(&self, collection: &str, id: &str) -> Result<Option<Doc>, AppError> {
            Ok(self.store.lock().unwrap().get_mut(collection).and_then(|t| t.remove(id)))
        }
        async fn count(&self, collection: &str, q: &QueryOptions) -> Result<u64, AppError> {
            Ok(self.list(collection, q).await?.len() as u64)
        }
        async fn subscribe(
            &self,
            _collection: &str,
        ) -> Result<tokio::sync::broadcast::Receiver<Change>, AppError> {
            Ok(tokio::sync::broadcast::channel(16).0.subscribe())
        }
        async fn create_index(&self, collection: &str, spec: &IndexSpec) -> Result<IndexInfo, AppError> {
            validate_spec(self.capabilities(), spec)?;
            let info = IndexInfo {
                name: spec.name.clone().unwrap_or_else(|| auto_index_name(spec)),
                fields: spec.fields.clone(),
                unique: spec.unique,
                kind: spec.kind,
            };
            self.indexes.lock().unwrap().entry(collection.into()).or_default().push(info.clone());
            Ok(info)
        }
        async fn list_indexes(&self, collection: &str) -> Result<Vec<IndexInfo>, AppError> {
            Ok(self.indexes.lock().unwrap().get(collection).cloned().unwrap_or_default())
        }
        async fn drop_index(&self, collection: &str, name: &str) -> Result<(), AppError> {
            let mut g = self.indexes.lock().unwrap();
            let v = g.entry(collection.into()).or_default();
            let n = v.len();
            v.retain(|i| i.name != name);
            if v.len() == n {
                return Err(AppError::NotFound);
            }
            Ok(())
        }
        async fn run_transaction(&self, ops: Vec<TxOp>) -> Result<Vec<TxOut>, AppError> {
            // In-memory: apply to a scratch clone under one lock hold, swap
            // on success. An error anywhere discards the scratch = rollback.
            let mut store = self.store.lock().unwrap();
            let mut scratch = store.clone();
            let mut out = Vec::with_capacity(ops.len());
            for op in ops {
                let table = scratch.entry(op.collection.clone()).or_default();
                match op.kind {
                    TxOpKind::Read => {
                        let doc = table.get(&op.id).cloned();
                        out.push(TxOut { existed: doc.is_some(), doc });
                    }
                    TxOpKind::Put { merge, must_exist } => {
                        let old = table.get(&op.id).cloned();
                        if must_exist && old.is_none() {
                            return Err(AppError::NotFound);
                        }
                        let existed = old.is_some();
                        let mut data = if merge {
                            old.map(|d| d.data).unwrap_or_default()
                        } else {
                            HashMap::new()
                        };
                        let mut body = op.doc.map(|d| d.data).unwrap_or_default();
                        data.extend(body.drain());
                        let doc = Doc { id: op.id.clone(), data };
                        table.insert(op.id.clone(), doc.clone());
                        out.push(TxOut { existed, doc: Some(doc) });
                    }
                    TxOpKind::Delete => {
                        let old = table.remove(&op.id);
                        out.push(TxOut { existed: old.is_some(), doc: old });
                    }
                }
            }
            *store = scratch;
            Ok(out)
        }
    }

    #[cfg(test)]
    #[tokio::test]
    async fn conformance_memdb() {
        run_conformance_suite(&MemDb::new()).await;
        run_index_suite(&MemDb::new()).await;
    }

    #[cfg(test)]
    #[test]
    fn helpers_parity() {
        let d = mk(serde_json::json!({"a": 1, "tags": ["x"]}));
        assert!(doc_matches(
            &d,
            &[Filter {
                field: "a".into(),
                op: FilterOp::Gte,
                value: serde_json::json!(1)
            }]
        ));
        assert!(!doc_matches(
            &d,
            &[Filter {
                field: "missing".into(),
                op: FilterOp::Eq,
                value: serde_json::json!(1)
            }]
        ));
    }
}

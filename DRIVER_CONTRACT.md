# Database Driver Contract (Addon/Plugin)

Motto: **1 backend, many databases.** No database is bound to
universalbackend — including HakoDB. Every database is an *addon* following
this contract.

## 1. What an addon contains

```text
crates/hakobackend-db-<name>/
  Cargo.toml        # plain crate; free choice of driver deps (sqlx, rethink client, …)
  driver.toml       # manifest (see §2)
  src/lib.rs        # struct implementing hakobackend_core::Database + capabilities()
```

Full example: `crates/hakobackend-db-hako/` (+ the `driver.toml` inside it).

## 2. `driver.toml` manifest

```toml
[driver]
name = "postgres"        # = Capabilities::driver, = database.driver value in hakobackend.toml
version = "0.1.0"
description = "…"

[capabilities]
watch = false            # no push → core falls back to polling
transactions = true

[config]
# document the fields read from database.path / env
path = "postgres://user:pass@host/db"
```

## 3. Behavior contract (`hakobackend_core::Database`)

| Method | Standard rule |
|---|---|
| `capabilities()` | `driver` must match the manifest; be honest about `watch`/`transactions` |
| `insert` without id | driver **must** fill in a unique id (contract, not core) |
| `set` merge=false | **replace the whole body** (old fields disappear) |
| `set` merge=true | **shallow top-level merge** (read-merge-write where the engine lacks it) |
| `delete` | return the **pre-delete** document (`None` when absent) |
| `get` missing document | `Ok(None)`, not an error |
| `list` filter/order/limit | **identical** semantics (§5) on every driver |
| `subscribe` | return a receiver; where the engine has no push, return an empty channel and set `watch=false` so core polls |
| `run_transaction` | **atomic**: all ops apply or none do; reads inside observe the batch's own writes; `Put.must_exist` on a missing doc aborts with `NotFound` |

## 4. Mandatory conformance

Every addon runs the shared suite from its own tests:

```rust
#[tokio::test]
async fn conformance() {
    let db = MyDriver::open("…").unwrap();
    hakobackend_core::conformance::run_conformance_suite(&db).await;
}
```

The suite covers: CRUD roundtrip, all 9 filter operators, order+limit, count,
replace/merge semantics, delete-returns-prev, subscribe. **Fail = not yet
registrable.** (`hakobackend-db-hako` marks its test `#[ignore]` because it needs a full
HakoDB build — run on release builds, not on every edit.)

## 5. Standard query semantics (single source of truth)

`hakobackend_core::conformance::doc_matches` + `sort_and_limit` are the reference
filter/order/limit implementations (ported from the legacy backend's `query.ts:matchesFilter`).
Drivers **with** native JSON filtering (HakoDB, Postgres `jsonb`) translate
operators into their query language; drivers **without** it use these helpers
(fetch → filter in memory). Results are exactly the same on every driver.

Operator contract = 9 legacy symbolic ops (`== != > < >= <= array-contains
array-contains-any in`) + word aliases + cursors (`startAt/startAfter/endAt/endBefore`)
+ `offset`. Extra HakoDB operators (`match`, `contains`, `startsWith`, `notIn`)
are NOT yet contract (reserved; drivers must not expose them over the wire).

## 6. Registration (the only core touchpoint)

1. Add the crate to the workspace (`crates/*` are members automatically).
2. Add 1 arm in `open_driver()` (`crates/hakobackend-server/src/main.rs`).
3. Add 1 row to the Registry table (§7) + a `database.path` example.

That is all. Handlers, policy, and realtime never know which driver is in use.

## 7. Driver registry

| Driver | Crate | Status | Watch | Transactions |
|---|---|---|---|---|
| `hako` | `hakobackend-db-hako` | ✅ default (embedded, zero-setup) | yes | yes |
| `postgres` | `hakobackend-db-postgres` | ✅ via sqlx (pool, JSONB) | polling | yes |
| `sqlite` | `hakobackend-db-sqlite` | ✅ via sqlx (file/`:memory:`, FTS5) | polling | yes |
| `mysql` | `hakobackend-db-mysql` | ✅ via sqlx (pool, JSON, generated FTS) | polling | yes |
| `rethinkdb` | `hakobackend-db-rethinkdb` | 🧪 SPIKE (unreql 0.2; live verification in progress, see RETHINKDB_SPIKE.md) | changefeed push | emulated (validate+apply+rollback; see driver notes) |
| `mongodb` | `hakobackend-db-mongo` | 🔜 next phase (official `mongodb` crate, async) | change stream | yes |

### Next phase: MongoDB

Unlike RethinkDB, MongoDB has a mature official crate (`mongodb`,
async-native, change streams for watch). Same pattern as Postgres:
collection = native collection (no flattening — MongoDB is already hierarchical),
document = BSON↔JSON, string `_id` mapped to `id`, 9-operator filters →
MQL equivalents (`$eq`, `$gt`, `$in`, `$elemMatch`/`$all` for arrays),
native order/limit/offset/cursor, indexes via `create_index` (single/compound/
`text`), FTS via text index (`supports_fts: true`), `__ub_indexes` registry
in the same DB. Light estimate since the contract + suite already exist.

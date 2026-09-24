# RethinkDB driver spike (reql via `unreql`)

## Verdict up front

Viable, with one honest gap: everything compiles and all
server-independent logic is tested, but **no live RethinkDB server
exists in this environment, so the conformance suite has not run.**
The crate is wired `#[ignore]` (same convention as hako) and the
`--driver rethinkdb` arm is live. To verify:

```sh
docker run -d --name rdb -p 28015:28015 rethinkdb:2.4
cargo test -p hakobackend-db-rethinkdb -- --ignored
./hakobackend-server --driver rethinkdb --data localhost/hakobackend
```

## Why `unreql` 0.2, not `reql` 0.11.2

| | `reql` 0.11.2 | `unreql` 0.2.1 |
|---|---|---|
| maintained | no (2023-07, 5% docs) | yes (2026-02, 38% docs) |
| runtime | async-net (dev-dep tokio) | async-net 2 |
| API coverage | full | full (`changes`, options, deadpool) |

Both sit on async-net, not tokio. That is fine inside our runtime
(futures are executor-agnostic; async-io brings its own reactor) but
remains an interop *assumption* until the live run — stated, not hidden.

## What the spike covers (`hakobackend-db-rethinkdb`)

- connect + `db_create` idempotent; DSN `rethinkdb://[user[:pass]@]host[:port][/db]`
  (env `RETHINKDB_USER`/`PASSWORD` win); unit-tested parser.
- tables = collections through a **bijective** codec (`_`→`_u`,
  `-`→`_d`, `/`→`_s`; RethinkDB allows `[A-Za-z0-9_]` only).
  Unit-tested roundtrip.
- CRUD: `get` missing → `None`; reads tolerate missing tables;
  `insert` conflict → `AlreadyExists` (in-band `errors`/`first_error`,
  not throws); `set` = ensure + read + shallow-extend + replace
  (exact, sqlite-style); `delete` returns prev.
- `list`/`count` = table scan + core `doc_matches`/`matches_cursor`/
  `sort_and_limit` (contract §5 permits; ReQL pushdown is later work).
- watch = real `table.changes()` push feed → broadcast (not polling).
- indexes: simple only (named kept); `unique`/`composite`/`fts`
  rejected clearly; field map in `__ub_indexes` (server `index_list`
  is names-only; list intersects registry × server).
- `run_transaction` left at the trait default → `/api/batch` and
  `/api/transaction` 400 on this driver (RethinkDB has no multi-doc
  transactions; single-doc ops stay atomic).

## API gotchas found (for whoever finishes this)

- unreql query args require `'static`: pass **owned** `String`s
  (`table(t.clone())`, `get(id.to_string())`), never borrows.
- write results never throw on conflicts: always inspect
  `errors`/`first_error` (`Duplicate primary key` → `AlreadyExists`).
- `delete(())` / `changes(())` take unit opts; `exec::<_, T>` /
  `exec_to_vec` / `run::<_, T>` (stream) cover all shapes;
  `get`-missing deserializes to `Option<Value>::None`.
- `Session` is `Clone` (Arc inside); one clone per changefeed task.
- bare `index_create(name)` indexes the same-named field (ReQL default).

## Recommendation

Keep the spike wired but **do not depend on it yet**: promote to
supported only after the live conformance run + a soak test of the
changefeed bridge under reconnects. If RethinkDB itself is the goal
(migration tool vs native driver debate), this spike says the native
driver is ~1 live-test away from working, not a rewrite.

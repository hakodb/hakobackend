# RethinkDB driver (was spike, now validated live)

## Verdict up front

PROMOTED: the shared conformance + index suites pass against
RethinkDB 2.4.3 live, plus an 11-point HTTP/SSE verification
(CRUD, PATCH-merge, filtered list, index create/list/drop,
changefeed add+remove, session survival across feeds).
Verify again any time (needs a server + `RDB_DSN`):

```sh
RDB_DSN='rethinkdb://admin:secret@localhost/db' \
  cargo test -p hakobackend-db-rethinkdb -- --ignored
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

Promoted to supported after the live run above: conformance green,
feed bridge soak-verified (add/remove + session survival), reconnect
in place. Remaining watch items (not blockers): changefeed behavior
under server reconnect storms (only unit-covered), and ReQL pushdown
for filtered lists (currently table scan + core helpers — correct,
not fast, on huge tables).

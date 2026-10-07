# HTTP Translation Contract (wire protocol)

The only surface SDKs/clients ever see. Whatever driver sits behind it
must produce exactly the same behavior.

## 1. Path rule: even/odd (legacy backend parity)

`/api/collections/{*path}` — even segment count = document, odd = collection
(`hakobackend_core::parse_collection_path`, parity-tested against the legacy `getPathInfo`).

## 2. Endpoint → policy → driver table

| HTTP | Policy slot | Trait call | Status |
|---|---|---|---|
| `GET` document / collection+`?options=` | Get / List | `get` / `list` + per-doc filter | 200 / 404 / 400 (malformed options) |
| `GET /api/collections` | — (ungated) | `list_collections` | 200 |
| `GET /api/ready` | — (ungated, LB/K8s) | driver answers | 200 `{ready:true}` / 503 |
| `POST` collection | Create | `insert` (empty id filled by driver) | 200 / 400 (wrong route kind) |
| `PUT` document | Update | `set(merge=false)` = full replace | 200 / 400 |
| `PATCH` document | Update | shallow merge; **404 when absent** (use PUT to create) | 200 / 400 / 404 |
| `DELETE` document | Delete | `delete` (returns prev) | 200 / 400 |
| `POST /api/batch {operations[]}` | per-op (see §8) | one `run_transaction` (atomic) | 200 / 400 / 500 `{error}` |
| `POST /api/transaction {operations[]}` | per-op (see §8) | one `run_transaction` (atomic) | 200 / 400 / mapped `{error, code}` |
| `GET /api/collectionGroup/:name?options=` | List + per-doc Get | fan-out over matching collections | 200 / 400 |
| `POST /api/aggregate/{collection} {options?, aggregations[]}` | List | gateway reduce (count/sum/avg) | 200 / 400 |
| Any method `/api/alias/...` (see §14) | TARGET's slot | redispatch to target, same driver call | target's statuses / 404 (no match) |
| Error | — | `AppError::status_code` (403/404/400/500) + `code()` | body `{error}` (`{error, code}` on writes) |

## 8. Batch + transaction (legacy server.ts:392-603 parity)

One op = `{type, collection, id, data?, options?}` (`id` required).
Type mapping: `get`→Get, `delete`→Delete, `update`→Update (errors when
absent), `set`→Create/Update by existence (honors `options.merge`),
`add`→forced merge-create; transaction maps unknown types by existence,
batch treats them as creates. Gates run per op against the existing doc
(or the incoming one for creates); collections are created only after
their gate passes. Then the whole write set applies in ONE driver
`run_transaction`: all or none, reads inside observe the batch's own
writes. Result shapes: batch → every op `{id, success}`; transaction →
`get` returns the doc (or null), writes return `{success: true}`.

## 3. Indexes (§index)

| HTTP | Policy slot | Trait call | Status |
|---|---|---|---|
| `POST /api/indexes {collection, fields[], name?, unique?, kind?}` | Update | `create_index` | 200 `{success, index}` / 400 |
| `GET /api/indexes?collection=` | List | `list_indexes` | 200 / 400 |
| `DELETE /api/indexes?collection=&name=` | Update | `drop_index` | 200 `{success}` / 400 / 404 |
| `POST /api/collections/<coll>/index {name, fields}` (legacy) | Update | `create_index` | 200 `{success: true}` |

- `kind`: `simple` (default, exactly 1 field), `composite` (>1 field, requires
  `supports_composite`), `fts` (1 field, requires `supports_fts`).
- `unique`: honored where the driver supports it; otherwise a clear 400 (never silent).
- `name` optional; drivers without naming (HakoDB) auto-generate deterministically
  (`field`, `composite(a+b)`, `fts(body)`).
- Drivers without a drop API (HakoDB) → clear 400.
- **Query coverage rule (measured, PERFORMANCE_NOTE §8): nothing is
  automatic.** `auto_provision` creates collections + only the `[[indexes]]`
  you declare; no index is ever inferred from query patterns. A filtered or
  ordered query without a matching index is a full scan + full decode
  (~10ms/2000 docs on hako; 224 rps order-only). Declare indexes for every
  field you filter or sort by: `simple` on the sort/filter field (ordered
  scans + point lookups), `composite` with the equality field(s) first and
  the sort field last (filter+order in one walk). Measured: simple index on
  the sort field took order-only 368→2096 rps, eq-filter 1076→2395 rps.
- Legacy-shim exception: a collection genuinely named `index` as the
  last segment is NOT hijacked — use the new `/api/indexes` form.

## 4. FieldValue atomics + stamps (legacy `__type__` wire, unchanged)

A value of `{"__type__": <op>, ...}` is a sentinel, resolved gateway-side
for every driver. Top-level update keys may be dot-paths (`"a.b.c"`).

| Sentinel | Create/replace | Merge (PATCH) |
|---|---|---|
| `{"__type__":"serverTimestamp"}` | ISO-8601 UTC now | set to now |
| `{"__type__":"increment","n":2}` | `2` | current + 2 (ints stay integral) |
| `{"__type__":"arrayUnion","elements":[...]}` | the elements | append missing (JSON deep-equal) |
| `{"__type__":"arrayRemove","elements":[...]}` | `[]` | remove matching (JSON deep-equal) |
| `{"__type__":"deleteField"}` | key dropped | key removed (dot-path aware) |

Nested sentinels (inside objects/arrays of plain values) resolve deep.
Every create stamps `createdAt` + `updatedAt` (user values win); every
rewrite preserves `createdAt` and refreshes `updatedAt` (ISO-8601 UTC).

## 5. Universal query (`?options=` JSON)
`filters[]` (`field`, `op`, `value`), `fields[]`, `orderBy[]`, `limit`, `offset` (new, HakoDB-style),
`startAt/startAfter/endAt/endBefore`. Wire operators = legacy symbolic
(`== != > < >= <= array-contains array-contains-any in`) — word forms
(`eq gt …`) also accepted. Cursors = bound values on `orderBy[0]` (or `id`);
sort direction ignored (legacy parity); missing field + cursor = dropped.
Extra HakoDB operators (`match`, `contains`, `startsWith`, `notIn`) are NOT
yet contract (future reserve). Reference semantics:
`hakobackend_core::conformance::{doc_matches, sort_and_limit, matches_cursor}` —
native drivers translate, the rest emulate with the same helpers
(identical results).

## 6. Auth & admin

`Authorization: Bearer …` else `__Host-ub_at` cookie → `Extension<Option<AuthContext>>`.
No token / failed verification = anonymous (policy speaks; 401 vs 403 see AUTH_CONTRACT).
`/api/admin/reload` is locked behind `admin_uids` (UID allowlist).
`/api/auth/*` see AUTH_CONTRACT (local BFF, GitHub OAuth, DPoP).

## 7. Realtime (WS + SSE)

Three lanes feed the same per-subscription snapshot pipeline (first
event wins, lanes converge idempotently — no duplicates):

- **Bus (fastest):** every committed gateway write emits after commit
  (legacy `triggerLocalChange` pattern — zero DB cost). External or
  foreign writes are invisible here by design. Covers single writes,
  batch/transaction ops, user creates (auth), and coalescer flushes
  (full doc, never partial bodies).
- **Driver push:** hako watch / rethinkdb changefeeds, one per
  collection shared by all watchers; lagged receivers resync.
- **Poll (always on):** one `list` per collection per 2 s tick shared by
  all polling watchers; catches external writes and heals anything the
  faster lanes missed. Candidate-removes are verified with a targeted
  `get` (a stale tick can no longer resurrect-then-drop), and a failed
  `get` keeps the entry (transient driver errors no longer wipe
  snapshots).

- `GET /ws` (upgrade): `subscribe{key, collection, options?, group?, token?}`,
  `unsubscribe{key}`, `ping`, `auth{token}` messages; `ready{key}`,
  `change{key, kind: add|change|remove, doc}`, `error{key?, message}`, `pong` replies.
  100 subs/connection cap; messages >1 MB close the connection.
- `GET /api/stream/<collection>?options=&group=&token=` → `text/event-stream`
  (`event: change`, 15 s keep-alive). Bearer/cookie token preferred;
  `?token=` fallback (lands in the URL — TLS only).
- Delivery semantics = snapshot + full filter/cursor (legacy changeHandler parity);
  `List` gate at subscribe, `Get` per document. No initial burst (clients GET first).
- Realtime guards: snapshot capped at 5.000 docs (400 with a narrow-with-filters
  hint past it); deliveries capped at 200/sub/sec (overflow resyncs, never queues).
- Watch drivers (HakoDB) = push with lagged resync; others = shared poller
  (one list per collection per 2 s tick no matter the watcher count;
  single-instance; Redis fan-out for multi-instance to follow). Groups: `/name` suffix or `_name`.

## 8. TLS
`--tls-cert/--tls-key` (PEM, both required) → rustls + HSTS
(`max-age=31536000; includeSubDomains`). DPoP `htu` scheme + `Secure` cookies
follow automatically. Neither = plain http. Port/listen changes need a restart
(reload covers DB/auth/policy/limits/indexes, not sockets).

## 9. Performance posture

- JSON responses are gzip-compressed, except the live streams (`/api/stream`,
  `/ws` — compression would buffer flushes and add event latency).
- Ctrl+C / SIGTERM drains in-flight requests before sockets close
  (TLS and plain paths alike); subscriptions abort with their tasks.

## 10. Single user (no tenants)

One backend serves one namespace: collection names pass through unchanged.
Policy is one global file evaluated on those names for CRUD,
batch/transaction, indexes, aggregates, collection groups, and WS/SSE
subscriptions. Multi-tenancy (if ever needed) lives OUTSIDE this backend.

- Internal `__*` collections are never addressable over HTTP, even
  under an open policy. The `__` prefix is the server's reserved
  namespace (issue #11): user collections MUST NOT use it. The charset
  gate legally allows the name, so enforcement is a 403 ("reserved __
  prefix") on every verb — names created out-of-band (legacy imports,
  direct driver access) stay unreachable by design, not by accident.
- Admin endpoints (`/api/admin/*`) require a UID in `admin_uids`
  (config/flag, repeatable) — UIDs, not roles.

## 12. Auth model (single-user)

- Callers are anonymous or carry a verified token (`AuthContext.uid`,
  e.g. `local:root`). Policy rules: `public` (anyone), `auth` (any
  authenticated caller), `deny` (nobody).
- Admin: `is_admin` = caller UID in `admin_uids`. No roles, no owner
  checks, no tenant claims anywhere in the stack.

## 13. Browser portal (removed)

The server-rendered portal was deleted with the tenant system. The
JSON API is the only interface; policy is managed via file +
`/api/admin/reload`.

## 11. TTL + unique + coalescing

- **TTL**: a numeric `__ttl_at` (microsecond epoch, same clock as `_time`)
  marks expiry. Expired docs read as missing everywhere (`get`/`list`/
  `count`/subscriptions); a 5-minute sweeper deletes them (emitting normal
  `Remove` events), 100 per collection per pass. Docs without the field
  are immortal — zero behavior change.
- **Unique**: `create_index` with `unique:true` (simple single-field).
  SQL drivers enforce natively (constraint → `already-exists`); hako
  enforces via shadow `__uniq_{coll}` docs inside the same serializable
  tx (concurrent duplicates cannot both commit). Missing values exempt.
- **Coalescing** (opt-in `--coalesce-writes`): eligible PATCH bodies
  (plain top-level keys, no `__type__` sentinels) merge per doc over a
  100 ms window; one stored write per window, GETs overlay pending
  bodies. Atomic PATCHes bypass. Acks happen at merge time; flush
  failures log + retry (10×), SIGKILL can lose one window.
  Full evaluation (exactness argument, measurements, limits):
  `COALESCING_NOTE.md`.

## 14. Path aliases (`/api/alias/...`, issue #5)

Owner-declared rewrites for regular endpoints (no scripts): an alias
maps one client shape onto one target path + query, e.g.
`/api/alias/students/:sid/:pin` → `/api/collections/students` with an
`options={...}` envelope substituting `{sid}`/`{pin}`. Declared in
`[[aliases]]` (config file, hot-reloaded like policy).

- Match: exact segments + `:param` captures only (no regex). Query
  templates substitute `{name}` captures; the request's own query MERGES
  (request wins on collision). First declaration wins.
- The rewritten request re-enters routing, so auth, policy, limits and
  realtime see the TARGET exactly like a direct call (policy evaluates
  the target — one rule surface). Bodies byte-identical to direct.
- Load-time guards (fail-closed, refuse to boot): pattern must start
  with `/api/alias/`; target must stay under `/api/` and must not chain
  into `/api/alias/`; every `{name}` must resolve to a capture;
  duplicates refused. Realtime lanes (`/ws`, `/api/stream/*`) cannot be
  targets (long-lived subscriptions cannot survive a redispatch).
- No match = empty 404 (same as an unknown route).

## 15. Managed files (`/api/files/...`, issue #11)

Byte files on a local volume + metadata docs in the addressed user
collection (no hidden collections, no driver changes). Off without
`file_dir` (uploads 503). One file per doc-id + field (default field
`file`); metadata is an ordinary doc, so policy slots, indexes and
aliases apply unchanged.

- `POST /api/files/{coll}/{id}[/{field}]` — single replace (multipart,
  one `file` part). `POST /api/files/{coll}` — batch (repeated `file`
  parts, auto ids, per-file array back; `file_max_batch`, default 1).
  Upload = Create (new id) or Update (existing) on that collection.
- `GET /api/files/{coll}/{id}[/{field}]` — bytes (Get slot) with ETag
  (content sha), `Accept-Ranges` + single-range 206, 304 on match.
  Metadata needs no new path: `GET /api/collections/{coll}/{id}`.
- `DELETE` — metadata only (Delete slot); bytes reclaimed by the
  sweeper (no refcounting). Emptied docs are deleted whole.
- Signed URLs: `GET ...?sign=<1..=3600>` mints
  `{url, exp}` (needs Get, same as downloading); `?exp=&sig=` consumes
  anonymously (HMAC-SHA256, `file_sign_secret` / `UB_FILE_SIGN_SECRET`;
  off without a secret). TLS-only warning applies, same as the SSE
  `?token=` fallback.
- Guards: per-file cap (`file_max_mb`, default = `body_limit_mb`,
  which hard-ceilings regardless); declared MIME must be allowlisted
  (default images + pdf) AND magic bytes must agree where known;
  `read_only` 503s writes; binary content-types never gzip.
- Crash ordering is pending-meta → bytes → ready-meta; non-ready reads
  404. The sweeper (same interval as TTL) reaps temp files, stale
  pendings and unreferenced bytes (mtime-guarded against in-flight
  uploads). Metadata-without-bytes 404s loudly (repair signal).

## 16. Multidatabase (`?db=`, issue #13)

One backend serves N named databases. `data` is always `default`;
`[databases]` adds extras (name → driver `data`). Absent = single-db,
today's behavior exactly.

- Uniform channel: `?db=` on every route, all verbs (bodies never
  carry db). Absent = `default`. `POST /api/batch?db=akademik` keeps
  today's body shape; cross-db batches are structurally impossible.
- Embedded drivers (hako/sqlite) serve `default` only: explicit
  non-default is 400, unknown on multi-db is 404.
- Policy namespace is dotted (`akademik.mahasiswa`); `default` stays
  bare (existing files keep working). Dots are illegal in collection
  segments, so no subcollection collision. In TOML, quote dotted
  keys: `[collections."akademik.mahasiswa"]`.
- `db` and `?options=` are siblings (envelope stays query-shaping
  only). Alias merge is per-key: `db` = alias-wins (pinned db cannot
  be escaped via the request query), `options` = request-wins.
  Cursors are db-scoped by contract.
- Realtime lanes partition by database (dotted bus names); WS
  subscribe takes a per-message `db`, SSE reads URL `?db=`.
- Files: metadata lives in the addressed db's collection; bytes are
  content-addressed and shared; the sweeper unions all databases.
- Unknown-db auto-create: SQL drivers (operator pre-creates or a
  follow-up CREATEDB convenience); cluster names must pre-exist
  (explicit registry, reload to add).

## 17. Archive moves + lazy residency (issue #21 A)

Hako-driver only; every other driver answers 400 (`driver has no …
support`). `?db=` applies (dotted policy namespace, same as §16).

- `POST /api/relocate {src, dst, ids[]}` → `{moved[], missing[]}`.
  Timestamp-preserving put at dst first, fresh tombstone at src;
  retry with the same ids is idempotent. Policy per id: src needs
  Get+Delete, dst needs Create. Refusals are 400 (same-side,
  engine excluded/local-only/lazy-unloaded sides, unload of
  non-lazy, ids over the batch cap) or 403 (`__` prefix, policy
  deny). Engine-excluded sides can never launder data onto the mesh
  (see hakodb `relocate_refuses_excluded_sides`).
- `POST /api/collections/load {collection}` → `{ok}`. Opens +
  replays + backfills a (usually lazy archive) collection; no-op
  when already loaded. Get gate.
- `POST /api/collections/unload {collection}` → `{ok}`. Flushes
  and evicts one lazy collection (refuses non-lazy with 400).
  Get gate. Data stays on disk; next touch reloads.
- `GET /api/collections/unloaded` → `[names]`. Archive-group
  collections present but not loaded. Names only, ungated like
  the collection list. Static paths win over
  `/api/collections/{*path}`, so alias targets reach these
  exactly like direct calls.

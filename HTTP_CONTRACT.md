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
| `POST /api/tenants {slug}` | admin role | `insert` into `__tenants` (conflict = taken) | 200 / 400 / 403 |
| `GET /api/tenants` | admin role | list `__tenants` ids | 200 / 403 |
| `POST` collection | Create | `insert` (empty id filled by driver) | 200 / 400 (wrong route kind) |
| `PUT` document | Update | `set(merge=false)` = full replace | 200 / 400 |
| `PATCH` document | Update | shallow merge; **404 when absent** (use PUT to create) | 200 / 400 / 404 |
| `DELETE` document | Delete | `delete` (returns prev) | 200 / 400 |
| `POST /api/batch {operations[]}` | per-op (see §8) | one `run_transaction` (atomic) | 200 / 400 / 500 `{error}` |
| `POST /api/transaction {operations[]}` | per-op (see §8) | one `run_transaction` (atomic) | 200 / 400 / mapped `{error, code}` |
| `GET /api/collectionGroup/:name?options=` | List + per-doc Get | fan-out over matching collections | 200 / 400 |
| `POST /api/aggregate/{collection} {options?, aggregations[]}` | List | gateway reduce (count/sum/avg) | 200 / 400 |
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
`/api/admin/reload` is locked behind `--admin-role`.
`/api/auth/*` see AUTH_CONTRACT (local BFF, GitHub OAuth, DPoP).

## 7. Realtime (WS + SSE)

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

## 10. Tenants (prefix design)
One backend serves many consumers: tenant `acme` reads/writes `users`,
stored as `acme__users`. The prefix comes ONLY from the authenticated
identity (`AuthContext.tenant`, e.g. the `tenant` field on local user
docs) — never from client input; no tenant = legacy unprefixed namespace.

- Slugs: `^[a-z0-9][a-z0-9-]{0,62}$` (no underscore, so `__` unambiguously
  marks scoped names). Provision via `POST /api/tenants` (admin);
  uniqueness is structural (`insert` conflicts when taken).
- Policy is evaluated on LOGICAL names: one file serves all tenants.
  Applies uniformly to CRUD, batch/transaction, indexes, aggregates,
  collection groups, and WS/SSE subscriptions.
- Internal `__*` collections (incl. `__tenants`) are never addressable
  over HTTP, even under an open policy.
- Scaling note: collections multiply by tenant count (lazy-created, no
  per-collection background work). Comfortable into the low thousands;
  beyond that, split backends per tenant.

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

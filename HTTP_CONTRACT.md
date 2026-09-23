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
| `POST` collection | Create | `insert` (empty id filled by driver) | 200 / 400 (wrong route kind) |
| `PUT` document | Update | `set(merge=false)` = full replace | 200 / 400 |
| `PATCH` document | Update | `set(merge=true)` = shallow merge | 200 / 400 |
| `DELETE` document | Delete | `delete` (returns prev) | 200 / 400 |
| Error | — | `AppError::status_code` (403/404/400/500) | — |

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

## 4. Universal query (`?options=` JSON)

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

## 5. Auth & admin

`Authorization: Bearer …` else `__Host-ub_at` cookie → `Extension<Option<AuthContext>>`.
No token / failed verification = anonymous (policy speaks; 401 vs 403 see AUTH_CONTRACT).
`/api/admin/reload` is locked behind `--admin-role`.
`/api/auth/*` see AUTH_CONTRACT (local BFF, GitHub OAuth, DPoP).

## 6. Realtime (WS + SSE)

- `GET /ws` (upgrade): `subscribe{key, collection, options?, group?, token?}`,
  `unsubscribe{key}`, `ping`, `auth{token}` messages; `ready{key}`,
  `change{key, kind: add|change|remove, doc}`, `error{key?, message}`, `pong` replies.
  100 subs/connection cap; messages >1 MB close the connection.
- `GET /api/stream/<collection>?options=&group=&token=` → `text/event-stream`
  (`event: change`, 15 s keep-alive). Bearer/cookie token preferred;
  `?token=` fallback (lands in the URL — TLS only).
- Delivery semantics = snapshot + full filter/cursor (legacy changeHandler parity);
  `List` gate at subscribe, `Get` per document. No initial burst (clients GET first).
- Watch drivers (HakoDB) = push; others = 2 s polling (single-instance;
  Redis fan-out for multi-instance to follow). Groups: `/name` suffix or `_name`.

## 7. TLS

`--tls-cert/--tls-key` (PEM, both required) → rustls + HSTS
(`max-age=31536000; includeSubDomains`). DPoP `htu` scheme + `Secure` cookies
follow automatically. Neither = plain http. Port/listen changes need a restart
(reload covers DB/auth/policy/limits/indexes, not sockets).

# Design Notes: Universal Backend (Rust + Axum) — successor to `rethink-firestore/backend`

> Legacy backend status: ~90% mature, in production at `https://api.chemedu.site/api`.
> Problem: rigid security (`userrules.ts` + mandatory Firebase Auth) → hard for general developers to reuse.
> This project's position: `hakodb` org candidate (`hakobackend`) — HakoDB as the default driver,
> but HakoDB is **not** mandatory (other databases are plug-and-play).

## 1. What we keep from the legacy backend (wire-protocol compatible)

| Legacy feature | Location | Port decision |
|---|---|---|
| Wildcard `GET/POST/PUT/PATCH/DELETE /api/collections/*`, even/odd = document/collection | `server.ts:53-65,209-322` | **Keep 1:1.** Axum: `route("/api/collections/{*path}", …)`. Existing SDKs keep working |
| `RethinkDBService` trait + `SQLService` (knex mysql/sqlite), flat `posts_revisions` table, `_collectionPath` + `injectPathFilter` | `rdb.ts:88-108`, `database.ts`, `sql.ts` | **Port to a Rust `trait Database`** — the plugin/addon foundation |
| `FILTER_OPS`: `== != > < >= <= array-contains(-any) in` + `startAt/After/endAt/Before` cursors, `matchesFilter` as source of truth | `query.ts` | Serde `QueryOptions`; each driver translates; in-memory predicate for realtime matching |
| Socket.IO `subscribe` + `appEventBus` + Redis fan-out `database_mutations` | `server.ts:607-725,94-126` | Replace with **native Axum WebSocket + SSE**; Redis Pub/Sub stays (same message protocol) |
| `/api/collectionGroup/:name`, `/api/aggregate/*`, `/api/batch`, `/api/transaction` (per-operation rule checks — already correct) | `server.ts:325-603` | Keep; per-op rule evaluation stays |
| `/api/ai/*`, `/api/tts` + queue + cache | `server.ts:727-1214` | **Out of core** → separate feature/microservice |

## 2. Roots of the legacy security rigidity (what had to change)

1. **`security.ts` = Firebase-only.** Without a service account it falls back to `mock-user`,
   which bypasses nearly every role check (`userrules.ts:93,110,159`). A dev backdoor
   leaking into production patterns.
2. **`userrules.ts` is 1300+ lines of code-as-config.** Every new app = edit the file + restart.
   Helpers (`isMaintainer`, `isBimbinganAdmin`, `scTenantRead/Write`, …) pile up across apps
   in one file — no per-tenant/app isolation.
3. **List evaluation = N+1 JS queries** (`server.ts:233-247`: `getAll` then `evaluateRule`
   per document). In Rust this must be pushed down to the query layer where the pattern is simple.
4. **Bearer-only, `cors({origin:'*'})`, no refresh rotation, no HttpOnly cookies,
   no CSRF.** Fixed below.

## 3. HakoDB (`../hakodb` v0.8.23) — the natural default driver

- **One language, one process:** `crate-type = [cdylib, rlib]` → usable directly
  as a Rust dependency (`Hako::open`, no FFI). No database server to operate.
- **API maps 1:1 to gateway needs:**
  `open/put/get/delete/query/patch/write_batch/begin_serializable_transaction/watch_collection`
  (`engine.rs`). `ChangeEvent{path, kind: Put|Delete}` → maps to `add/change/remove`.
- **Superset operators** (`filter.rs`): `Eq Ne Gt Gte Lt Lte In NotIn ArrayContains
  ArrayContainsAny + Match/Contains/StartsWith` ⊇ legacy `FILTER_OPS`. Mapping is trivial.
- **`Query` already has** collection, filters, or_groups, order_by, limit/offset,
  projection, aggregations (Count/Sum/Avg), cursor bounds — **more complete** than
  the legacy `RethinkDBOptions`. `defer_blobs` comes free for image collections (`sc_images`).
- **Subcollections** are prefix-based — consistent with the flat-table `_collectionPath` pattern.
- **Integration note:** the HakoDB API is **synchronous** → wrap in `tokio::task::spawn_blocking`
  in the adapter; `watch_collection -> Receiver` → bridge to `tokio::sync::broadcast`.
  The engine already ships `SecurityRule{collection_prefix, op, allow}` + audit log —
  used as **layer 0 (coarse deny)**, the gateway policy as layer 1 (roles/owner).
- **Org position:** this repo = `hakobackend`: the universal HTTP gateway; HakoDB = embedded
  default (zero-setup, local-first; throughput TBD — bench before claiming); postgres/mysql/sqlite
  = plugins for centralized deployments.

## 4. Axum as the "FastAPI rival" (video study `oLoQH1xwbW0`)

Video claims confirmed: router + extractors (`State`, `Json<T>`, `Path<T>`) ≈
decorators + `Depends` + Pydantic, but validated at compile time (serde).
The real added value is not syntax, but: errors as `Result<T, AppError>`
(the compiler rejects unhandled error paths), and middleware = the
`tower`/`tower-http` ecosystem (timeout, rate-limit, CORS, compression, tracing — one stack).
FastAPI still wins for fast prototypes + the Python/ML ecosystem.

## 5. Axum/Rust vs Node/Bun performance (honest numbers, I/O-bound CRUD)

| Metric | FastAPI (uvicorn) | Axum (tokio) | Node Express (legacy stack) | Bun (Hono/Elysia) |
|---|---|---|---|---|
| Throughput | ~8–15K rps | ~80–150K rps (**~1.45×** hello-world, k6) | ~18–25K | ~48–110K (~2–4× Node) |
| Latency p50/p95 | 28 / 69 ms | 11 / 27 ms (**~2.5×**) | variable, bad tail | in between |
| Memory | 100–300 MB (1.2 GB under load) | **5–20 MB idle** (~202 MB under load, **~6×**) | 120–240 MB | 46–100 MB |

 User-facing claim: **2–5× throughput, ~2.5× latency, ~6× memory** for real CRUD load
 (I/O-bound workloads shrink the theoretical 10× gap). Bonus: ~15 MB single binary, <50 ms cold start.

## 6. `hakobackend` architecture

```text
crates/
  hakobackend-core/          trait Database, AuthProvider, Policy; Doc; QueryOptions; AppError
  hakobackend-db-hako/       HakoDB adapter (default; spawn_blocking + watch bridge)
  hakobackend-db-postgres/ hakobackend-db-mysql/ hakobackend-db-sqlite/   plugins (to follow)
  hakobackend-auth-core/     AuthContext{uid, roles, tenant}, Claims, Session
  hakobackend-auth-local/ default: argon2id + short-lived JWT access + rotating opaque refresh
  hakobackend-auth-firebase/ optional: JWT verification via Google JWKS (no Admin SDK)
  hakobackend-auth-oidc/     generic OIDC (to follow)
  hakobackend-policy/        declarative policy.toml + escape hatch (to follow: Rhai/WASM)
  hakobackend-server/        Axum router, WS/SSE, main.rs
config/hakobackend.example.toml
```

- **Hybrid endpoints:** Layer 0 is zero-config (wildcard exactly like legacy) + optional declarative
  Layer 1 per resource in TOML (`schema`, `max_limit`, `cache_ttl`). No declaration → still works.
- **Auth (`auth.mode = internal|firebase|oidc|chain:…`):**
  5–15 min access JWT (header) + rotating opaque refresh on every use (argon2 hash in DB,
  `HttpOnly; Secure; SameSite=Lax`, `Path=/api/auth/refresh`) + double-submit CSRF for
  cookie writes + login rate-limit + lockout + `jti` denylist in Redis.
  Firebase/OIDC only verify signatures → map to a uniform `AuthContext`;
  policy never knows which provider was used.
- **Policy replaces `userrules.ts`:** `policy.toml` per collection
  (`rule = "auth.uid == resource.ownerId || 'admin' in auth.roles"`) + 5 s TTL cache
  (legacy cache pattern kept) + push simple filters down to the SQL/Hako query (ends the N+1).
- **P0:** remove the `mock-user` bypass; default deny-closed; `dev_insecure` mode must be explicit opt-in.
- **Realtime:** `GET /api/stream/{*path}` (SSE) + `WS /ws`; Redis fan-out `database_mutations`
  (same protocol as legacy); per-doc auth check on delivery; 100 subs/socket cap.

## 7. Stages

0. Contracts: `hakobackend-core` + shared contract tests (every driver must pass).
1. Core REST: wildcard + sqlite (instant dev) + postgres; bench vs legacy Express.
2. Internal dual-token auth + cookies + CSRF + basic `policy.toml`.
3. mysql/mariadb driver + Redis fan-out.
4. Realtime WS/SSE + per-doc filtering.
5. firebase/oidc providers + chain; `userrules.ts` → `policy.toml` conversion script.
6. Hardening: rate-limit, audit log, batch/tx, distroless image, legacy-SDK e2e.

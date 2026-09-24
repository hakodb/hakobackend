# hakobackend
Universal HTTP backend gateway + plug-and-play databases (Rust + Axum)

> Part of [**HakoDB**](https://github.com/hakodb/hakodb) — embedded Firestore-style document DB in Rust. The engine + C ABI live in `hakodb/hakodb`; this repo holds the universal HTTP backend gateway.

Successor to `rethink-firestore/backend` — wire-protocol compatible so existing SDKs keep working.

- Full design notes: [`KAJIAN.md`](KAJIAN.md)
- Database addon contract: [`DRIVER_CONTRACT.md`](DRIVER_CONTRACT.md) (+ `driver.example.toml`)
- Auth provider contract: [`AUTH_CONTRACT.md`](AUTH_CONTRACT.md) (+ `custom.example.toml`)
- HTTP translation contract: [`HTTP_CONTRACT.md`](HTTP_CONTRACT.md)
- Standard security rules: [`SECURITY_RULES.md`](SECURITY_RULES.md) (+ `policy.standard.toml`)
- Sample config: [`config/hakobackend.example.toml`](config/hakobackend.example.toml)

## Layout

```text
crates/
  hakobackend-core/       contracts: Doc, QueryOptions, Database/Auth traits, Claims, AppError
  hakobackend-db-hako/    HakoDB adapter (default driver; path-dep on ../hakodb)
  hakobackend-db-postgres/  PostgreSQL addon via sqlx (pool, JSONB, GIN FTS)
  hakobackend-db-sqlite/    SQLite addon via sqlx (file/:memory:, FTS5)
  hakobackend-db-mysql/     MySQL/MariaDB addon via sqlx (pool, JSON, generated FTS)
  hakobackend-policy/     user-owned policy.toml + [identity] (hot-reload)
  hakobackend-auth-core/  --auth resolution: chain + custom.toml mapping + role union
  hakobackend-auth-local/ BFF issuer (dual-token, DPoP, argon2)
  hakobackend-auth-firebase|github|oidc/  external verifier-only (+ GitHub OAuth BFF)
  hakobackend-ratelimit/  2-layer in-process token bucket (no redis)
  hakobackend-server/     Axum gateway + CLI + WS/SSE + TLS
```

## Quick start

```powershell
cargo run -p hakobackend-server -- --driver hako --data ./data/hako.ub --rules ./policy.example.toml --port 8080
cargo run -p hakobackend-server -- --config hakobackend.example.toml   # or via file
cargo run -p hakobackend-server -- --config hakobackend.example.toml --validate   # dry-check
cargo run -p hakobackend-server -- --print-default-config     # print template
```

Precedence: CLI flags > config file > defaults. The legacy config shape
(`[server] listen`, `[database]`, `policy_file`) is still read (deprecated).

## Install / deploy (no crates.io)

Library crates are path-only on purpose — publishing 13 crates to
crates.io would be release churn for zero runtime benefit. Ship the binary:

- **Release assets:** tag `v*` → `release.yml` builds
  `hakobackend-<ver>-linux-x86_64.tar.gz` + `-windows-x86_64.zip`
  (binary renamed to `hakobackend`, plus the example config).
- **Docker:** `docker.yml` generates its Dockerfile inline on every run
  (repo policy: no Dockerfile/compose committed) and pushes
  `ghcr.io/hakodb/hakobackend:<tag>` (`:latest`, `:edge`) for
  linux/amd64+arm64. Run with a mounted config + data dir.
- **From source:** `cargo install --git https://github.com/hakodb/hakobackend`
  (or `cargo run -p hakobackend-server` above).

Endpoints (same as the legacy backend):

- `GET /api/health`
- `GET /api/collections` — list collections
- `GET /api/collections/{*path}` — document (even segments) / list + `?options=<json>` (odd)
- `POST /api/collections/{*path}` — add (collections only)
- `PUT /api/collections/{*path}` — set (documents only)
- `PATCH /api/collections/{*path}` — merge (documents only)
- `DELETE /api/collections/{*path}` — remove (documents only)
- `POST /api/indexes {collection, fields[], name?, unique?, kind?}` — create index
- `GET /api/indexes?collection=` — list indexes
- `DELETE /api/indexes?collection=&name=` — drop index
- `GET /ws` — realtime websocket (subscribe/unsubscribe/ping/auth)
- `GET /api/stream/{collection}?options=&group=` — realtime SSE
- TLS: `--tls-cert/--tls-key` (HSTS automatic); DPoP scheme follows

## Build notes

`hakobackend-db-hako` pulls in all of HakoDB plus its C dependencies (`zstd-sys`, `aws-lc-sys`);
the first `cargo check/build` is slow — that is normal, not an error. Current focus is development;
full builds come later.

## Plug-and-play databases & flexible endpoints

- **Swap databases while the server runs:** edit `driver` / `data` in the config,
  then `POST /api/admin/reload`. No rebuild/restart. A new driver is a `hakobackend-db-*`
  crate implementing `hakobackend_core::Database` plus one arm in `open_driver` (`crates/hakobackend-server/src/main.rs`).
  Example: `cp hakobackend.example.toml hakobackend.toml`.
- **Swap auth while the server runs:** edit `auth` (`off | local | chain:a,b | ./custom.toml`)
  then the same reload. Chaining + mapping live in `hakobackend-auth-core`; providers that are
  unavailable fail fast (fail-closed). Example: `custom.example.toml`.
- **`local` (BFF issuer):** `POST /api/auth/register|login|refresh|logout`, `GET /api/auth/me`;
  two `__Host-` cookies, HttpOnly+Secure+SameSite=Strict; refresh rotation + reuse detection;
  DPoP (`UB_LOCAL_DPOP`/`dpop`: off|accept|require, RSA/EC) binds tokens to the client key;
  requires env `UB_LOCAL_JWT_SECRET`. `/api/admin/reload` is locked behind `--admin-role`.
- **GitHub OAuth (BFF):** `GET /api/auth/github/login|callback`; code↔token exchange on the server
  (PKCE S256, single-use state); the browser gets a session cookie + redirect, never a token.
  Env: `UB_GITHUB_CLIENT_ID/SECRET`, `UB_PUBLIC_URL`. Users are provisioned role-less.
- **Change endpoint rules while the server runs:** edit `policy.toml` — takes effect immediately
  (hot-reload via mtime watch, no restart). Values: `public | auth | owner | deny | role:<name>`,
  per slot `get list create update delete` (fallback `read`/`write` → `[defaults]`).
  Typos / parse failures = deny (fail-closed), the old policy stays in force. Example: `policy.example.toml`.
- Lists are filtered per document (replaces the `server.ts:233` loop in the legacy backend).
- **2-layer flood protection (no redis):** loose global + strict `/api/auth/*`,
  honest 429 + `Retry-After`, `/api/health` exempt. Numbers hot-reload via reload.
  Key = peer IP (or first X-Forwarded-For when `--trust-proxy`).

Phase 0 contracts → 1 core REST → 2 internal dual-token auth + `policy.toml` →
3 mysql driver + Redis → 4 WS/SSE realtime → 5 firebase/oidc →
6 hardening. Details in `KAJIAN.md §7`.

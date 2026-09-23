# Universal Backend (`hakobackend`)

Gateway HTTP universal + plug-and-play database, dibangun dengan Rust + Axum.
Penerus `rethink-firestore/backend` — wire-protocol kompatibel agar SDK lama tetap jalan.

- Kajian lengkap: [`KAJIAN.md`](KAJIAN.md)
- Kontrak addon database: [`DRIVER_CONTRACT.md`](DRIVER_CONTRACT.md) (+ `driver.example.toml`)
- Kontrak provider auth: [`AUTH_CONTRACT.md`](AUTH_CONTRACT.md) (+ `custom.example.toml`)
- Kontrak translasi HTTP: [`HTTP_CONTRACT.md`](HTTP_CONTRACT.md)
- Security rules standar: [`SECURITY_RULES.md`](SECURITY_RULES.md) (+ `policy.standard.toml`)
- Contoh config: [`config/ub.example.toml`](config/ub.example.toml)

## Struktur

```text
crates/
  ub-core/       kontrak: Doc, QueryOptions, trait Database/Auth, Claims, AppError
  ub-db-hako/    adapter HakoDB (driver default; path-dep ke ../hakodb)
  ub-db-postgres/  addon PostgreSQL via sqlx (pool, JSONB, FTS GIN)
  ub-db-sqlite/    addon SQLite via sqlx (file/:memory:, FTS5)
  ub-db-mysql/     addon MySQL/MariaDB via sqlx (pool, JSON, FTS generated)
  ub-policy/     policy.toml + [identity] milik user (hot-reload)
  ub-auth-core/  resolusi --auth: chain + custom.toml mapping + union peran
  ub-auth-local/ issuer BFF (dual-token, DPoP, argon2)
  ub-auth-firebase|github|oidc/  verifier-only eksternal (+ OAuth GitHub BFF)
  ub-ratelimit/  token-bucket in-process 2 lapis (tanpa redis)
  ub-server/     gateway Axum + CLI + WS/SSE + TLS
```

## Jalan cepat

```powershell
cargo run -p ub-server -- --driver hako --data ./data/hako.ub --rules ./policy.example.toml --port 8080
cargo run -p ub-server -- --config ub.example.toml   # atau via file
cargo run -p ub-server -- --config ub.example.toml --validate   # cek kering
cargo run -p ub-server -- --print-default-config     # cetak template
```

Prioritas: flag CLI > file config > default. Bentuk config lama
(`[server] listen`, `[database]`, `policy_file`) tetap dibaca (deprecated).

Endpoint (sama seperti backend lama):

- `GET /api/health`
- `GET /api/collections` — daftar koleksi
- `GET /api/collections/{*path}` — dokumen (segmen genap) / list + `?options=<json>` (ganjil)
- `POST /api/collections/{*path}` — tambah (koleksi saja)
- `PUT /api/collections/{*path}` — set (dokumen saja)
- `PATCH /api/collections/{*path}` — merge (dokumen saja)
- `DELETE /api/collections/{*path}` — hapus (dokumen saja)
- `POST /api/indexes {collection, fields[], name?, unique?, kind?}` — buat index
- `GET /api/indexes?collection=` — daftar index
- `DELETE /api/indexes?collection=&name=` — hapus index
- `GET /ws` — websocket realtime (subscribe/unsubscribe/ping/auth)
- `GET /api/stream/{koleksi}?options=&group=` — SSE realtime
- TLS: `--tls-cert/--tls-key` (HSTS otomatis); skema DPoP mengikuti

## Catatan build

`ub-db-hako` menarik seluruh HakoDB + dependensi C-nya (`zstd-sys`, `aws-lc-sys`);
`cargo check/build` pertama lama — itu normal, bukan error. Fokus saat ini pengembangan,
build penuh belakangan.

## Plug-and-play database & endpoint fleksibel

- **Ganti DB saat server jalan:** edit `driver` / `data` di config,
  lalu `POST /api/admin/reload`. Tanpa rebuild/restart. Driver baru = crate `ub-db-*`
  yang mengimpl `ub_core::Database` + 1 arm di `open_driver` (`crates/ub-server/src/main.rs`).
  Contoh: `cp ub.example.toml ub.toml`.
- **Ganti auth saat server jalan:** edit `auth` (`off | local | chain:a,b | ./custom.toml`)
  lalu reload yang sama. Rantai + mapping di `ub-auth-core`; provider yang belum
  tersedia gagal cepat (fail-closed). Contoh: `custom.example.toml`.
- **`local` (issuer BFF):** `POST /api/auth/register|login|refresh|logout`, `GET /api/auth/me`;
  dua cookie `__Host-` HttpOnly+Secure+SameSite=Strict; refresh rotasi + reuse-detection;
  DPoP (`UB_LOCAL_DPOP`/`dpop`: off|accept|require, RSA/EC) mengikat token ke kunci klien;
  butuh env `UB_LOCAL_JWT_SECRET`. `/api/admin/reload` terkunci peran `--admin-role`.
- **OAuth GitHub (BFF):** `GET /api/auth/github/login|callback`; code↔token di server
  (PKCE S256, state sekali-pakai); browser terima cookie sesi + redirect, tanpa token.
  Env: `UB_GITHUB_CLIENT_ID/SECRET`, `UB_PUBLIC_URL`. User terprovisi tanpa peran.
- **Ubah rule endpoint saat server jalan:** edit `policy.toml` — langsung berlaku
  (hot-reload via pantau mtime, tanpa restart). Nilai: `public | auth | owner | deny | role:<nama>`,
  per slot `get list create update delete` (fallback `read`/`write` → `[defaults]`).
  Typo / gagal parse = deny (fail-closed), policy lama tetap dipakai. Contoh: `policy.example.toml`.
- List difilter per-dokumen (pengganti loop `server.ts:233` di backend lama).
- **Flood protection 2 lapis (tanpa redis):** global longgar + `/api/auth/*` ketat,
  429 + `Retry-After` jujur, `/api/health` dikecualikan. Angka hot-reload via reload.
  Kunci = IP peer (atau X-Forwarded-For pertama bila `--trust-proxy`).

Fase 0 kontrak → 1 REST inti → 2 auth internal dual-token + `policy.toml` →
3 driver mysql/rethink + Redis → 4 WS/SSE realtime → 5 firebase/oidc →
6 hardening. Detail di `KAJIAN.md §7`.

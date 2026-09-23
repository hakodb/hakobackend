# Kajian: Universal Backend (Rust + Axum) — penerus `rethink-firestore/backend`

> Status backend lama: ~90% matang, produksi di `https://api.chemedu.site/api`.
> Masalah: security kaku (`userrules.ts` + wajib Firebase Auth) → sulit dipakai developer umum.
> Posisi proyek ini: kandidat `hakodb` org (`hakobackend`) — HakoDB sebagai driver default,
> tetapi **tidak wajib** HakoDB (plug-and-play DB lain).

## 1. Apa yang dipertahankan dari backend lama (wire-protocol kompatibel)

| Fitur lama | Lokasi | Keputusan port |
|---|---|---|
| Wildcard `GET/POST/PUT/PATCH/DELETE /api/collections/*`, genap/ganjil = dokumen/koleksi | `server.ts:53-65,209-322` | **Pertahankan 1:1.** Axum: `route("/api/collections/{*path}", …)`. SDK lama tetap jalan |
| `RethinkDBService` trait + `SQLService` (knex mysql/sqlite), flat table `posts_revisions`, `_collectionPath` + `injectPathFilter` | `rdb.ts:88-108`, `database.ts`, `sql.ts` | **Port jadi Rust `trait Database`** — fondasi plugin/addon |
| `FILTER_OPS`: `== != > < >= <= array-contains(-any) in` + cursor `startAt/After/endAt/Before`, `matchesFilter` sebagai source of truth | `query.ts` | Serde `QueryOptions`; tiap driver menerjemahkan; predikat in-memory untuk realtime-match |
| Socket.IO `subscribe` + `appEventBus` + Redis fan-out `database_mutations` | `server.ts:607-725,94-126` | Ganti **WebSocket asli Axum + SSE**; Redis Pub/Sub tetap (protokol pesan sama) |
| `/api/collectionGroup/:name`, `/api/aggregate/*`, `/api/batch`, `/api/transaction` (cek rule per-operasi — sudah benar) | `server.ts:325-603` | Pertahankan; evaluasi rule per-op tetap |
| `/api/ai/*`, `/api/tts` + antrean + cache | `server.ts:727-1214` | **Keluar dari inti** → feature/microservice terpisah |

## 2. Akar kekakuan security lama (yang harus dibedah)

1. **`security.ts` = Firebase-only.** Tanpa service account → fallback `mock-user`
   yang me-bypass hampir semua role check (`userrules.ts:93,110,159`). Ini backdoor dev
   yang bocor ke pola produksi.
2. **`userrules.ts` 1300+ baris, code-as-config.** Tiap app baru = edit file + restart.
   Helper (`isMaintainer`, `isBimbinganAdmin`, `scTenantRead/Write`…) menumpuk lintas app
   dalam satu file — tidak ada isolasi per-tenant/app.
3. **Evaluasi list = N+1 query JS** (`server.ts:233-247`: `getAll` lalu `evaluateRule`
   per dokumen). Di Rust harus didorong ke query layer bila pola sederhana.
4. **Bearer-only, `cors({origin:'*'})`, tanpa refresh rotation, tanpa HttpOnly cookie,
   tanpa CSRF.** Di bawah ini diperbaiki.

## 3. HakoDB (`../hakodb` v0.8.23) — driver default alami

- **Satu bahasa, satu proses:** `crate-type = [cdylib, rlib]` → bisa dipakai langsung
  sebagai dependensi Rust (`Hako::open`, bukan via FFI). Tidak ada server DB untuk dioperasi.
- **API cocok 1:1 dengan kebutuhan gateway:**
  `open/put/get/delete/query/patch/write_batch/begin_serializable_transaction/watch_collection`
  (`engine.rs`). `ChangeEvent{path, kind: Put|Delete}` → peta ke `add/change/remove`.
- **Operator superset** (`filter.rs`): `Eq Ne Gt Gte Lt Lte In NotIn ArrayContains
  ArrayContainsAny + Match/Contains/StartsWith` ⊇ `FILTER_OPS` lama. Mapping trivial.
- **`Query` sudah punya** collection, filters, or_groups, order_by, limit/offset,
  projection, aggregations (Count/Sum/Avg), cursor bounds — **lebih lengkap** dari
  `RethinkDBOptions` lama. `defer_blobs` gratis untuk koleksi gambar (`sc_images`).
- **Subcollections** prefix-based — sejalan dengan pola flat-table `_collectionPath`.
- **Catatan integrasi:** API HakoDB **sinkron** → bungkus `tokio::task::spawn_blocking`
  di adapter; `watch_collection -> Receiver` → bridge ke `tokio::sync::broadcast`.
  Engine sudah punya `SecurityRule{collection_prefix, op, allow}` + audit log —
  dipakai sebagai **lapisan 0 (deny kasar)**, policy gateway sebagai lapisan 1 (peran/owner).
- **Posisi org:** repo ini = `hakobackend`: gateway HTTP universal; HakoDB = embedded
  default (zero-setup, local-first, 50K+ OPS klaim internal); postgres/mysql/sqlite/rethink
  = plugin untuk deployment sentral.

## 4. Axum sebagai "saingan FastAPI" (kajian video `oLoQH1xwbW0`)

Klaim video terkonfirmasi: router + extractor (`State`, `Json<T>`, `Path<T>`) ≈
decorator + `Depends` + Pydantic, tapi validasi di compile-time (serde).
Nilai tambah riil bukan sintaks, melainkan: error sebagai `Result<T, AppError>`
(compiler menolak error path yang lupa ditangani), dan middleware = ekosistem
`tower`/`tower-http` (timeout, rate-limit, CORS, compression, tracing — satu stack).
FastAPI tetap menang untuk prototipe cepat + ekosistem Python/ML.

## 5. Performa Axum/Rust vs Node/Bun (angka jujur, I/O-bound CRUD)

| Metrik | FastAPI (uvicorn) | Axum (tokio) | Node Express (stack lama) | Bun (Hono/Elysia) |
|---|---|---|---|---|
| Throughput | ~8–15K rps | ~80–150K rps (**~1.45×** hello-world, k6) | ~18–25K | ~48–110K (~2–4× Node) |
| Latency p50/p95 | 28 / 69 ms | 11 / 27 ms (**~2.5×**) | variatif, tail buruk | di tengah |
| Memori | 100–300 MB (1.2 GB saat load) | **5–20 MB idle** (~202 MB load, **~6×**) | 120–240 MB | 46–100 MB |

 Klaim ke user: **2–5× throughput, ~2.5× latency, ~6× memori** untuk beban CRUD riil
 (I/O-bound menyusutkan gap 10× teoretis). Bonus: single binary ~15 MB, cold start <50 ms.

## 6. Arsitektur `hakobackend`

```text
crates/
  ub-core/          trait Database, AuthProvider, Policy; Doc; QueryOptions; AppError
  ub-db-hako/       adapter HakoDB (default; spawn_blocking + watch bridge)
  ub-db-postgres/ ub-db-mysql/ ub-db-sqlite/ ub-db-rethink/   plugin (menyusul)
  ub-auth-core/     AuthContext{uid, roles, tenant}, Claims, Session
  ub-auth-internal/ default: argon2id + JWT akses pendek + refresh opaque rotasi
  ub-auth-firebase/ opsional: verifikasi JWT via JWKS Google (tanpa Admin SDK)
  ub-auth-oidc/     generik OIDC (menyusul)
  ub-policy/        policy.toml declarative + escape-hatch (menyusul: Rhai/WASM)
  ub-server/        Axum router, WS/SSE, main.rs
config/ub.example.toml
```

- **Endpoint hybrid:** Lapisan 0 nol-config (wildcard persis lama) + Lapisan 1 deklarasi
  opsional per-resource di TOML (`schema`, `max_limit`, `cache_ttl`). Tanpa deklarasi → jalan.
- **Auth (`auth.mode = internal|firebase|oidc|chain:…`):**
  access JWT 5–15 mnt (header) + refresh opaque rotasi-tiap-pakai (hash argon2 di DB,
  `HttpOnly; Secure; SameSite=Lax`, `Path=/api/auth/refresh`) + CSRF double-submit untuk
  write via cookie + rate-limit login + lockout + `jti` denylist Redis.
  Firebase/OIDC hanya verifikasi signature → mapping ke `AuthContext` seragam;
  policy tidak tahu provider apa.
- **Policy ganti `userrules.ts`:** `policy.toml` per koleksi
  (`rule = "auth.uid == resource.ownerId || 'admin' in auth.roles"`) + cache TTL 5 dtk
  (pola cache lama dipertahankan) + dorong filter sederhana ke SQL/Hako query (akhiri N+1).
- **P0:** hapus `mock-user` bypass; default deny-closed; mode `dev_insecure` harus opt-in eksplisit.
- **Realtime:** `GET /api/stream/{*path}` (SSE) + `WS /ws`; fan-out Redis `database_mutations`
  (protokol sama dengan lama); cek auth per-doc saat delivery; batas 100 subs/socket.

## 7. Tahapan

0. Kontrak: `ub-core` + shared contract-test (semua driver wajib lolos).
1. Inti REST: wildcard + sqlite (dev instan) + postgres; bench vs Express lama.
2. Auth internal dual-token + cookie + CSRF + `policy.toml` dasar.
3. Driver mysql/mariadb + rethink (changefeed → watch) + Redis fan-out.
4. Realtime WS/SSE + per-doc filter.
5. Provider firebase/oidc + chain; skrip konversi `userrules.ts` → `policy.toml`.
6. Hardening: rate-limit, audit log, batch/tx, image distroless, e2e SDK lama.

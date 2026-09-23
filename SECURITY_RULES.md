# Security Rules Standar

Aturan ini **mengikuti fleksibilitas endpoint** (berlaku untuk wildcard otomatis
maupun resource yang dideklarasikan) dan menjadi acuan semua deployment.
Implementasi: `crates/ub-policy` + `policy.toml` (hot-reload). Contoh siap pakai:
`policy.standard.toml`.

## 1. Prinsip baku

1. **Default-deny.** Tanpa aturan yang mengizinkan → tolak. Tanpa `policy_file`
   (mode dev) server TERBUKA + wajib log WARN — tidak untuk produksi.
2. **Fail-closed.** Typo rule, gagal parse, auth tak dikenal, dokumen tak ada
   untuk rule `owner` → tolak. Tidak pernah fail-open.
3. **Auth seragam.** Provider apa pun (internal/firebase/oidc) hanya mengisi
   `AuthContext{uid, roles, tenant}`; rule tidak tahu provider apa.
4. **Tidak membocorkan alasan.** Respons selalu `403 Permission denied by policy`
   — tanpa menjelaskan rule mana yang gagal (membedakan user-ada/tidak-ada
   adalah celah enumerasi).

## 2. Urutan resolusi (paling spesifik menang)

```
slot metode (get/list/create/update/delete)
  → alias read (get/list) / write (create/update/delete)
    → koleksi exact → segmen terakhir → root → [defaults] → deny
```

Contoh: `posts/p1/revisions` memakai aturan `posts/p1/revisions`, bila tak ada
memakai `revisions`, bila tak ada memakai `posts`, bila tak ada memakai defaults.
(Semantik yang sama dengan engine lama `rules.ts:evaluateRule`.)

## 3. Peran & koleksi user: milik user, bukan core

Core **tidak mengikat** nama peran maupun koleksi user. Semua didefinisikan user
di `[identity]` pada `policy.toml`:

```toml
[identity]
users_collection = "members"  # default "users"; bebas: sc_users, anggota, …
role_field = "posisi"         # default "role"; string tunggal atau array
owner_field = "pemilikId"     # default "ownerId"; override per koleksi bisa
```

- `role:<apapun>` bebas — core hanya membandingkan string peran dokumen user
  (dimuat dari `users_collection` via `role_field`, string atau array) dengan
  nama di rule. Tidak ada nama peran cadangan.
- Contoh peran di dokumen ini (`admin`, `maintainer`, `pengurus`) hanyalah
  **template siap pakai**, bukan ketentuan. Ganti sesukanya.
- `owner_field` global bisa dioverride per koleksi (`collections.X.owner_field`).
  Evaluasi `owner` memakai field terkonfigurasi, fallback kompatibilitas
  `ownerId`/`uid` untuk data lama.

## 4. Kelas akses endpoint standar

| Kelas | Pola policy | Contoh |
|---|---|---|
| Publik-baca | `read = "public"`, `write = "deny"` | `posts`, `pages`, `sc_configs` |
| Terautentikasi-tulis | `create/update = "auth"` | `media`, `tags` |
| Milik-pemilik | `read/write = "owner"` (+ `owner_field`) | `profiles`, notifikasi user |
| Admin-saja | `read/write = "role:admin"` | `ai_configs`, kredensial |
| Koleksi internal | prefix `__` **tidak diekspos** HTTP (kecuali eksplisit) | `__users` (refresh token), audit |

## 5. Konvensi dokumen (default siap pakai, semua bisa diganti)

- Field pemilik default `ownerId` (fallback `uid`); ganti via `[identity].owner_field`
  atau per koleksi. Rule `owner` pada dokumen tanpa field yang cocok → tolak.
- Field terlarang naik-level (`role`, `status`, dsb.) **tidak boleh** diubah
  self-service — proteksi eskalasi seperti `isModifyingRestrictedFields` di backend
  lama menjadi bagian policy fase 2 (`immutable_fields`, `owner_only_fields`).

## 6. Kode error standar (paritas backend lama)

| Situasi | Status | Body |
|---|---|---|
| Tolak policy | 403 | `Permission denied by policy` |
| Dokumen tak ada | 404 | `Document not found` |
| Route salah jenis | 400 | `POST/PUT/PATCH/DELETE … must target …` |
| Duplikat | 400 | `already-exists` |
| Rate-limit / antre penuh | 429 | tanpa detail internal |

## 7. Standar auth (local: terimplementasi fase C; eksternal: verifier-only)

- Dual token pola BFF: access JWT 5–15 mnt + refresh opaque rotasi-tiap-pakai
  (hash di DB `__sessions`, cookie `__Host-` HttpOnly+Secure+SameSite=Strict Path=/).
- Reuse refresh (token lama muncul lagi) → cabut SEMUA sesi user + tolak.
- Register membuang `role`/`password_hash` dari body (anti self-eskalasi);
  login/email salah disamarkan (anti enumerasi).
- Tradeoff: access JWT stateless — logout mencabut refresh, access hidup sampai
  kedaluwarsa (alasan TTL pendek). Tanpa `mock-user` bypass.
- DPoP (RFC 9449, token lokal): `off|accept|require` via `UB_LOCAL_DPOP`/`dpop`
  custom.toml; token curian tanpa private key tak bisa dipakai; replay ditolak.
- `/api/admin/reload` terkunci peran `--admin-role` (default `admin`, nama bebas).

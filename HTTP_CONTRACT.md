# Kontrak Translasi HTTP (wire-protocol)

Satu-satunya permukaan yang dilihat SDK/klien. Driver apa pun di belakangnya
wajib menghasilkan perilaku yang sama persis.

## 1. Aturan path: genap/ganjil (paritas backend lama)

`/api/collections/{*path}` — jumlah segmen genap = dokumen, ganjil = koleksi
(`ub_core::parse_collection_path`, diuji paritas dengan `getPathInfo` lama).

## 2. Tabel endpoint → policy → driver

| HTTP | Method policy | Trait call | Status |
|---|---|---|---|
| `GET` dokumen / koleksi+`?options=` | Get / List | `get` / `list` + filter per-doc | 200 / 404 / 400 (options malformat) |
| `GET /api/collections` | — (tanpa gate) | `list_collections` | 200 |
| `POST` koleksi | Create | `insert` (id kosong diisi driver) | 200 / 400 (salah route) |
| `PUT` dokumen | Update | `set(merge=false)` = ganti total | 200 / 400 |
| `PATCH` dokumen | Update | `set(merge=true)` = gabung dangkal | 200 / 400 |
| `DELETE` dokumen | Delete | `delete` (kembalikan prev) | 200 / 400 |
| Error | — | `AppError::status_code` (403/404/400/500) | — |

## 3. Index (§index)

| HTTP | Method policy | Trait call | Status |
|---|---|---|---|
| `POST /api/indexes {collection, fields[], name?, unique?, kind?}` | Update | `create_index` | 200 `{success, index}` / 400 |
| `GET /api/indexes?collection=` | List | `list_indexes` | 200 / 400 |
| `DELETE /api/indexes?collection=&name=` | Update | `drop_index` | 200 `{success}` / 400 / 404 |
| `POST /api/collections/<coll>/index {name, fields}` (legacy) | Update | `create_index` | 200 `{success: true}` |

- `kind`: `simple` (default, tepat 1 field), `composite` (>1 field, butuh
  `supports_composite`), `fts` (1 field, butuh `supports_fts`).
- `unique`: didukung bila driver mendukung; bila tidak → 400 jelas (tanpa diam).
- `name` opsional; driver tanpa penamaan (HakoDB) auto-generate deterministik
  (`field`, `composite(a+b)`, `fts(body)`).
- Driver tanpa API drop (HakoDB) → 400 jelas.
- Pengecualian shim legacy: koleksi yang benar-benar bernama `index` sebagai
  segmen terakhir TIDAK dibajak — gunakan bentuk baru `/api/indexes`.

## 4. Query universal (`?options=` JSON)

`filters[]` (`field`, `op`, `value`), `fields[]`, `orderBy[]`, `limit`, `offset` (baru, kemampuan HakoDB-style),
`startAt/startAfter/endAt/endBefore`. Operator wire = simbolik legacy
(`== != > < >= <= array-contains array-contains-any in`) — kata
(`eq gt …`) juga diterima. Cursor = nilai batas pada `orderBy[0]` (atau `id`);
arah sort diabaikan (paritas legacy); field hilang + cursor = gugur.
Operator ekstra HakoDB (`match`, `contains`, `startsWith`, `notIn`) BELUM
bagian kontrak (cadangan masa depan). Semantik rujukan:
`ub_core::conformance::{doc_matches, sort_and_limit, matches_cursor}` —
driver native menerjemahkan, sisanya mengemulasi dengan helper yang sama
(hasil identik).

## 5. Auth & admin

`Authorization: Bearer …` else cookie `__Host-ub_at` → `Extension<Option<AuthContext>>`.
Tanpa token / gagal verifikasi = anonim (policy bicara; 401 vs 403 lihat AUTH_CONTRACT).
`/api/admin/reload` terkunci peran `--admin-role`.
`/api/auth/*` lihat AUTH_CONTRACT (local BFF, OAuth GitHub, DPoP).

## 6. Realtime (WS + SSE)

- `GET /ws` (upgrade): pesan `subscribe{key, collection, options?, group?, token?}`,
  `unsubscribe{key}`, `ping`, `auth{token}`; balasan `ready{key}`,
  `change{key, kind: add|change|remove, doc}`, `error{key?, message}`, `pong`.
  Batas 100 subs/koneksi; pesan >1 MB menutup koneksi.
- `GET /api/stream/<koleksi>?options=&group=&token=` → `text/event-stream`
  (`event: change`, keep-alive 15 dtk). Token via Bearer/cookie diutamakan;
  `?token=` fallback (tercatat di URL — pakai hanya via TLS).
- Semantik delivery = snapshot + filter/cursor penuh (paritas changeHandler legacy);
  gate `List` saat subscribe, `Get` per dokumen. Tanpa burst awal (klien GET dulu).
- Driver watch (HakoDB) = push; lainnya = polling 2 dtk (single-instance;
  fan-out Redis multi-instance menyusul). Grup: akhiran `/nama` atau `_nama`.

## 7. TLS

`--tls-cert/--tls-key` (PEM, keduanya wajib) → rustls + HSTS
(`max-age=31536000; includeSubDomains`). Skema `htu` DPoP + cookie `Secure`
mengikuti otomatis. Tanpa keduanya = http biasa. Port/listen berubah = restart
(reload mencakup DB/auth/policy/limit/index, bukan socket).

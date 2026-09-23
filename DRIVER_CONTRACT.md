# Kontrak Driver Database (Addon/Plugin)

Motto: **1 backend, multi database.** Tidak ada database yang terikat ke
universalbackend — termasuk HakoDB. Setiap database adalah *addon* yang mengikuti
kontrak ini.

## 1. Isi sebuah addon

```text
crates/ub-db-<nama>/
  Cargo.toml        # crate biasa; dependensi driver bebas (sqlx, client rethink, …)
  driver.toml       # manifest (lihat §2)
  src/lib.rs        # struct yang mengimpl ub_core::Database + capabilities()
```

Contoh lengkap: `crates/ub-db-hako/` (+ `driver.toml` di dalamnya).

## 2. Manifest `driver.toml`

```toml
[driver]
name = "postgres"        # = Capabilities::driver, = nilai database.driver di ub.toml
version = "0.1.0"
description = "…"

[capabilities]
watch = false            # tanpa push → core memakai polling
transactions = true

[config]
# dokumentasikan field yang dibaca dari database.path / env
path = "postgres://user:pass@host/db"
```

## 3. Kontrak perilaku (`ub_core::Database`)

| Metode | Aturan baku |
|---|---|
| `capabilities()` | `driver` wajib sama dengan manifest; jujur soal `watch`/`transactions` |
| `insert` tanpa id | driver **wajib** mengisi id unik (kontrak, bukan core) |
| `set` merge=false | **ganti seluruh isi** (field lama hilang) |
| `set` merge=true | **gabung dangkal level-atas** (baca-gabung-tulis bila engine tidak mendukung) |
| `delete` | kembalikan dokumen **sebelum** dihapus (`None` bila tak ada) |
| `get` dokumen tak ada | `Ok(None)`, bukan error |
| `list` filter/order/limit | semantik **identik** §5 di semua driver |
| `subscribe` | kembalikan receiver; bila engine tak mendukung push, kembalikan channel kosong dan set `watch=false` agar core polling |

## 4. Konformitas wajib

Setiap addon memanggil suite bersama dari test-nya sendiri:

```rust
#[tokio::test]
async fn conformance() {
    let db = MyDriver::open("…").unwrap();
    ub_core::conformance::run_conformance_suite(&db).await;
}
```

Suite menguji: CRUD roundtrip, semua 9 operator filter, order+limit, count,
semantik replace/merge, delete-mengembalikan-prev, subscribe. **Gagal = belum boleh
diregistrasi.** (`ub-db-hako` menandai testnya `#[ignore]` karena butuh build
HakoDB penuh — dijalankan saat build release, bukan tiap edit.)

## 5. Semantik query baku (sumber kebenaran tunggal)

`ub_core::conformance::doc_matches` + `sort_and_limit` adalah implementasi
rujukan filter/urutan/limit (diport dari `query.ts:matchesFilter` backend lama).
Driver yang **punya** filter JSON native (HakoDB, Postgres `jsonb`) menerjemahkan
operator ke bahasa query-nya; driver yang **tidak punya** memakai helper ini
(ambil → saring di memori). Hasilnya sama persis di semua driver.

Kontrak operator = 9 simbolik legacy (`== != > < >= <= array-contains
array-contains-any in`) + alias kata + cursor (`startAt/startAfter/endAt/endBefore`)
+ `offset`. Operator ekstra HakoDB (`match`, `contains`, `startsWith`, `notIn`)
BELUM bagian kontrak (cadangan; driver tak boleh mengeksposnya via wire).

## 6. Registrasi (satu-satunya titik sentuh core)

1. Tambah crate ke workspace (`crates/*` otomatis anggota).
2. Tambah 1 arm di `open_driver()` (`crates/ub-server/src/main.rs`).
3. Tambah 1 baris di tabel Registry (§7) + contoh `database.path`.

Itu saja. Handler, policy, realtime tidak tahu driver apa yang dipakai.

## 7. Registry driver

| Driver | Crate | Status | Watch | Transaksi |
|---|---|---|---|---|
| `hako` | `ub-db-hako` | ✅ default (embedded, nol-setup) | ya | ya |
| `postgres` | `ub-db-postgres` | ✅ via sqlx (pool, JSONB) | polling | ya |
| `sqlite` | `ub-db-sqlite` | ✅ via sqlx (file/`:memory:`, FTS5) | polling | ya |
| `mysql` | `ub-db-mysql` | ✅ via sqlx (pool, JSON, FTS generated) | polling | ya |
| `mongodb` | `ub-db-mongo` | 🔜 fase berikutnya (crate resmi `mongodb`, async) | change stream | ya |
| `rethink` | `ub-db-rethink` | ⏸️ pending (tanpa driver Rust matang) | changefeed | emulasi |

### Fase berikutnya: MongoDB

Berbeda dengan RethinkDB, MongoDB punya crate resmi yang matang (`mongodb`,
async native, change streams untuk watch). Pola yang sama seperti Postgres:
koleksi = collection native (tanpa flatten — MongoDB sudah hierarchical),
dokumen = BSON↔JSON, `_id` string dipetakan ke `id`, filter 9 operator →
padanan MQL (`$eq`, `$gt`, `$in`, `$elemMatch`/`$all` untuk array),
order/limit/offset/cursor native, index via `create_index` (single/compound/
`text`), FTS via text index (`supports_fts: true`), registry `__ub_indexes`
di DB yang sama. Estimasi ringan karena kontrak + suite sudah ada.
| `mysql` | `ub-db-mysql` | ⬜ peta jalan fase 3 | polling | ya |
| `rethink` | `ub-db-rethink` | ⬜ peta jalan fase 3 (kompatibel SDK lama) | changefeed | emulasi |

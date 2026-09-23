# Kontrak Provider Auth (Addon)

Simetri dengan `DRIVER_CONTRACT.md`: **tidak ada provider auth yang terikat ke
core kecuali kontrak**. Backend untuk provider eksternal hanya *verifier*;
hanya `local` yang menjadi *issuer* (mengelola sesi/token).

## 1. Dua peran (di `hakobackend_core`)

```rust
trait AuthProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn verify(&self, token: &str) -> Result<Claims, AppError>;
}
// HANYA local (fase C):
trait SessionIssuer: AuthProvider {
    async fn login(&self, user: &str, secret: &str) -> Result<AuthContext, AppError>;
    async fn refresh(&self, refresh_token: &str) -> Result<AuthContext, AppError>;
    async fn logout(&self, ctx: &AuthContext) -> Result<(), AppError>;
}
```

- `verify` gagal = "bukan token kami / tidak valid" → chain mencoba provider
  berikut. Jangan error untuk token asing yang formatnya jelas bukan milikmu.
- Provider eksternal **tidak pernah** mengimpl `SessionIssuer`: backend tidak
  menerbitkan token atas nama Firebase/GitHub/OIDC.

## 2. Resolusi `--auth` (di `hakobackend_auth_core`)

`off`/`none`/kosong → tanpa auth (anonim) | `local` → satu provider |
`chain:github,local` → coba berurutan, klaim pertama yang valid menang |
`./custom.toml` → rantai + mapping deklaratif (§4).

Nama yang belum tersedia (fase B/C) **gagal cepat saat startup**, bukan bypass.

## 3. `Claims` → `AuthContext` (resolver tunggal `AuthChain::resolve`)

1. `verify` per provider hingga satu berhasil (semua gagal → anonim).
2. `uid` final = **ber-namespace** (`github:123`, `local:abc`) — anti tabrakan
   antar-provider; juga kunci lookup user-doc.
3. Peran = **union** (dedup): peran dari mapping klaim (§4) + peran dokumen user
   (`[identity].users_collection` via `[identity].role_field`, string/array).
   Tanpa DB / tanpa dokumen → peran klaim saja (verifier murni).
4. `uid_field`/`email_field` opsional mengambil dari klaim `extra`.

## 4. File mapping deklaratif (`--auth ./custom.toml`)

```toml
providers = ["github", "local"]   # builtin yang dirantai
[mapping]
uid_field = "sub"                 # default: uid bawaan provider
email_field = "email"
[[rules]]                         # klaim → peran bebas milik user
claim = "groups"
equals = "ops"
role = "pengurus"
```

Cocok bila klaim string == `equals` atau array klaim memuatnya.
Contoh siap salin: `custom.example.toml`.

## 5. Middleware (`hakobackend-server`)

`Authorization: Bearer …` (klien API) else cookie access (browser BFF) → resolve
→ enforcement DPoP (token lokal) → `Extension<Option<AuthContext>>`.
Tanpa token / gagal DPoP = anonim; **aturan policy yang menentukan**, bukan middleware
(401 vs 403: 401 = token ada tapi tak terverifikasi semua provider —
ditegakkan fase B; kini token tak dikenal = anonim + policy bicara).

## 6. DPoP (RFC 9449, token `local`)

Token curian tak bisa dipakai tanpa private key. Mode via env `UB_LOCAL_DPOP`
atau `dpop` di `custom.toml` (custom menang; typo = error fail-closed):
`off` (default) | `accept` (verifikasi bila proof ada, bearer fallback) |
`require` (tanpa proof valid = anonim).
Penerbitan mengikat bila login/refresh menyertakan header `DPoP`
(`cnf.jkt` di access JWT); batasan: RSA/EC saja, tanpa nonce server
(jendela iat 5 mnt + cache jti), skema htu `http` (TLS menyusul).

## 7. Registry provider

| Provider | Crate | Status | Peran |
|---|---|---|---|
| `local` | `hakobackend-auth-local` | ✅ fase C (satu-satunya issuer, pola BFF) | Issuer |
| `firebase` | `hakobackend-auth-firebase` | ✅ fase B (JWKS Google, `UB_FIREBASE_PROJECT`) | Verifier |
| `github` | `hakobackend-auth-github` | ✅ fase B (token) + E (OAuth BFF: `/api/auth/github/login|callback`) | Verifier |
| `oidc` | `hakobackend-auth-oidc` | ✅ fase B (`UB_OIDC_ISSUER`, `UB_OIDC_AUDIENCE` opsional) | Verifier |
| custom | `custom.toml` | ✅ fase A (mapping + chain) | Mapping |

Secret/param provider via env (tidak di file config): `UB_FIREBASE_PROJECT`,
`UB_FIREBASE_JWKS_URL` (override test), `UB_GITHUB_API` (override test),
`UB_OIDC_ISSUER`, `UB_OIDC_AUDIENCE`, `UB_OIDC_JWKS_URL` (override test),
`UB_LOCAL_JWT_SECRET` (wajib, min 32 char), `UB_LOCAL_USERS` (default `users`),
`UB_LOCAL_DEFAULT_ROLE`, `UB_LOCAL_ACCESS_TTL` (dtk, default 600),
`UB_LOCAL_REFRESH_TTL` (dtk, default 30 hari).

OAuth GitHub (fase E): `UB_GITHUB_CLIENT_ID` (ada = fitur aktif) +
`UB_GITHUB_CLIENT_SECRET`, `UB_PUBLIC_URL` (asal callback), opsional
`UB_GITHUB_AFTER_LOGIN` (default `/`), override test `UB_GITHUB_API`,
`UB_GITHUB_TOKEN_URL`, `UB_GITHUB_AUTHORIZE_URL`. Pending state+PKCE di
`__oauth_pending` (sekali pakai, 10 mnt). Login OAuth menerbitkan sesi lokal
(via `LocalAuth::login_external`, butuh `local` dalam rantai); user terprovisi
TANPA peran, tanpa auto-merge email.

Endpoint `local` (aktif bila rantai memuatnya): `POST /api/auth/register`,
`/api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`, `GET /api/auth/me`.
Dua cookie `__Host-` (HttpOnly+Secure+SameSite=Strict, Path=/). Tradeoff
terdokumentasi: access JWT stateless (logout mencabut refresh; access hidup
≤ TTL-nya) — alasan TTL pendek + refresh rotasi + reuse-detection.

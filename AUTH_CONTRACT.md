# Auth Provider Contract (Addon)

Mirrors `DRIVER_CONTRACT.md`: **no auth provider is bound to
core except through this contract**. The backend is only a *verifier* for external providers;
only `local` is an *issuer* (manages sessions/tokens).

## 1. Two roles (in `hakobackend_core`)

```rust
trait AuthProvider: Send + Sync {
    fn name(&self) -> &'static str;
    async fn verify(&self, token: &str) -> Result<Claims, AppError>;
}
// ONLY local (phase C):
trait SessionIssuer: AuthProvider {
    async fn login(&self, user: &str, secret: &str) -> Result<AuthContext, AppError>;
    async fn refresh(&self, refresh_token: &str) -> Result<AuthContext, AppError>;
    async fn logout(&self, ctx: &AuthContext) -> Result<(), AppError>;
}
```

- A failed `verify` means "not our token / invalid" → the chain tries the next
  provider. Do not error on foreign tokens that are clearly not yours.
- External providers **never** implement `SessionIssuer`: the backend does not
  issue tokens on behalf of Firebase/GitHub/OIDC.

## 2. `--auth` resolution (in `hakobackend_auth_core`)

`off`/`none`/empty → no auth (anonymous) | `local` → single provider |
`chain:github,local` → try in order, first valid claims win |
`./custom.toml` → chain + declarative mapping (§4).

Names that are not available (phases B/C) **fail fast at startup**, never bypass.

## 3. `Claims` → `AuthContext` (single resolver `AuthChain::resolve`)

1. `verify` per provider until one succeeds (all fail → anonymous).
2. Final `uid` is **namespaced** (`github:123`, `local:abc`) — no collisions
   across providers; also the user-doc lookup key.
3. Roles = **union** (deduped): roles from claim mapping (§4) + roles from the user document
   (`[identity].users_collection` via `[identity].role_field`, string/array).
   No DB / no document → claim roles only (pure verifier).
4. Optional `uid_field`/`email_field` pull from the claim `extra`.

## 4. Declarative mapping file (`--auth ./custom.toml`)

```toml
providers = ["github", "local"]   # builtins to chain
[mapping]
uid_field = "sub"                 # default: provider-native uid
email_field = "email"
[[rules]]                         # claim → user-owned free roles
claim = "groups"
equals = "ops"
role = "pengurus"
```

Matches when the string claim == `equals` or the claim array contains it.
Copy-ready example: `custom.example.toml`.

## 5. Middleware (`hakobackend-server`)

`Authorization: Bearer …` (API clients) else access cookie (browser BFF) → resolve
→ DPoP enforcement (local tokens) → `Extension<Option<AuthContext>>`.
No token / failed DPoP = anonymous; **policy rules decide**, not the middleware
(401 vs 403: 401 = a token was present but verified against no provider —
enforced in phase B; currently an unknown token = anonymous + policy speaks).

## 6. DPoP (RFC 9449, `local` tokens)

A stolen token is unusable without the private key. Mode via env `UB_LOCAL_DPOP`
or `dpop` in `custom.toml` (custom wins; typo = fail-closed error):
`off` (default) | `accept` (verify when a proof is present, bearer fallback) |
`require` (no valid proof = anonymous).
Issuance binds when login/refresh include the `DPoP` header
(`cnf.jkt` in the access JWT); limits: RSA/EC only, no server nonce
(5 min iat window + jti cache), `http` htu scheme (TLS to follow).

## 7. Provider registry

| Provider | Crate | Status | Role |
|---|---|---|---|
| `local` | `hakobackend-auth-local` | ✅ phase C (the only issuer, BFF pattern) | Issuer |
| `firebase` | `hakobackend-auth-firebase` | ✅ phase B (Google JWKS, `UB_FIREBASE_PROJECT`) | Verifier |
| `github` | `hakobackend-auth-github` | ✅ phase B (token) + E (OAuth BFF: `/api/auth/github/login|callback`) | Verifier |
| `oidc` | `hakobackend-auth-oidc` | ✅ phase B (`UB_OIDC_ISSUER`, optional `UB_OIDC_AUDIENCE`) | Verifier |
| custom | `custom.toml` | ✅ phase A (mapping + chain) | Mapping |

Provider secrets/params via env (never in config files): `UB_FIREBASE_PROJECT`,
`UB_FIREBASE_JWKS_URL` (test override), `UB_GITHUB_API` (test override),
`UB_OIDC_ISSUER`, `UB_OIDC_AUDIENCE`, `UB_OIDC_JWKS_URL` (test override),
`UB_LOCAL_JWT_SECRET` (required, min 32 chars), `UB_LOCAL_USERS` (default `users`),
`UB_LOCAL_DEFAULT_ROLE`, `UB_LOCAL_ACCESS_TTL` (seconds, default 600),
`UB_LOCAL_REFRESH_TTL` (seconds, default 30 days).

GitHub OAuth (phase E): `UB_GITHUB_CLIENT_ID` (present = feature on) +
`UB_GITHUB_CLIENT_SECRET`, `UB_PUBLIC_URL` (callback origin), optional
`UB_GITHUB_AFTER_LOGIN` (default `/`), test overrides `UB_GITHUB_API`,
`UB_GITHUB_TOKEN_URL`, `UB_GITHUB_AUTHORIZE_URL`. Pending state+PKCE in
`__oauth_pending` (single-use, 10 min). OAuth login issues a local session
(via `LocalAuth::login_external`, requires `local` in the chain); users are provisioned
with NO roles, no email auto-merge.

`local` endpoints (active when the chain includes it): `POST /api/auth/register`,
`/api/auth/login`, `/api/auth/refresh`, `/api/auth/logout`, `GET /api/auth/me`.
Two `__Host-` cookies (HttpOnly+Secure+SameSite=Strict, Path=/). Documented
tradeoff: stateless access JWT (logout revokes refresh; access lives out
its TTL) — hence short TTL + refresh rotation + reuse detection.

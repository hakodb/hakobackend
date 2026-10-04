# Standard Security Rules

These rules **follow endpoint flexibility** (they apply to auto-wildcard
and declared resources alike) and are the reference for all deployments.
Implementation: `crates/hakobackend-policy` + `policy.toml` (hot-reload). Ready-made example:
`policy.standard.toml`.

## 1. Standard principles

1. **Default-deny.** No allowing rule → reject. Without `policy_file`
   (dev mode) the server is OPEN + must log WARN — never for production.
2. **Fail-closed.** Rule typo, parse failure, unknown auth → reject.
   Removed rules (`owner`, `role:*`) fail LOUD at policy load. Never fail open.
3. **Uniform auth.** Any provider (internal/firebase/oidc) only fills
   `AuthContext{uid, extra}`; rules never know which provider.
4. **No reason leakage.** Responses are always `403 Permission denied by policy`
   — never saying which rule failed (distinguishing user-exists/not-exists
   is an enumeration hole).

## 2. Resolution order (most specific wins)

```
method slot (get/list/create/update/delete)
  → alias read (get/list) / write (create/update/delete)
    → exact collection → root → [defaults] → deny
```

Example: `posts/p1/revisions` uses the `posts/p1/revisions` rules; when absent
falls back to `posts`, then defaults. There is deliberately NO last-segment
fallback: a permissive generic rule must never silently cover hierarchies
(S3 audit) — name the full path or the root.

## 3. Identity: user-owned user collection, not core

Core binds **neither** admin names **nor** the user collection. Users define
the user collection in `[identity]` in `policy.toml`:

```toml
[identity]
users_collection = "members"  # default "users"; free choice: members, accounts, …
```

Admin access = caller UID in server `admin_uids` (config/flag). No roles,
no owner checks, no tenant claims anywhere in the stack.

## 4. Standard endpoint access classes

| Class | Policy pattern | Example |
|---|---|---|
| Public-read | `read = "public"`, `write = "deny"` | `posts`, `pages`, `site_configs` |
| Authenticated-write | `create/update = "auth"` | `media`, `tags` |
| Authenticated-only | `read/write = "auth"` | `profiles`, user notifications |
| Claim-gated | `claim:role=editor`, `claim:uid=self !role` | self-edit, role writes |
| Field-validated | `fields:unit=auth.unit,score=int:0..100` | scoped + typed writes |
| Admin-only | `deny` + UID allowlist (`admin_uids`) | `ai_configs`, credentials |
| Internal collections | `__` prefix **not exposed** over HTTP (unless explicit) | `__users` (refresh tokens), audit |

Claim/fields cost contract: attribute match, id-match, strips, and field
conditionals evaluate on in-hand data (token claims + incoming/merged doc)
— no DB read is ever added by a rule. Ownership of *existing* docs needs
no read either (id-match); only true change-detection would, and strip
replaces it. `wstats allow` row must stay ~1µs class.

## 5. Document conventions (working defaults, all replaceable)

- Per-user data separation is the deployer's data modeling (separate
  collections) or an external tenant layer — not rules.

## 6. Performance switches (all default off = legacy behavior)

```toml
[performance]
skip_read_before_write = true  # PUT skips the old-doc lookup (~115us saved)
```

- Applies to PUT only, and only where **no `owner` rule** governs the write
  (only `owner` reads the existing doc; every other rule decides on the auth
  context alone). Owner-governed writes ignore the flag (correctness first).
- Tradeoff: a PUT-overwrite resets `createdAt` (no old doc to preserve it
  from). Use PATCH merge when `createdAt` stability matters — merge always
  reads (it needs the base).
- Per-request form (no policy change): `X-Hako-Skip-RBW: 1` (or `true`).
  Advisory perf hint, never authZ: `allow()` with `None` decides identically
  for every non-`owner` rule, and `owner`-governed writes ignore it (still
  read, stranger still 403). Header (any API caller) was chosen over cookie:
  BFF cookies are browser-only, and a server-set cookie would add state for
  zero extra trust.
- Future: rule-based bypass via header/cookie intercepted at the gateway
  (so hot callers can opt out per request instead of per policy file).

## 7. Standard error codes (legacy backend parity)

| Situation | Status | Body |
|---|---|---|
| Policy reject | 403 | `Permission denied by policy` |
| Document missing | 404 | `Document not found` |
| Wrong route kind | 400 | `POST/PUT/PATCH/DELETE … must target …` |
| Duplicate | 400 | `already-exists` |
| Rate-limit / full queue | 429 | no internal details |

## 8. Auth standards (local: implemented phase C; external: verifier-only)

- Dual-token BFF pattern: 5–15 min access JWT + rotating opaque refresh on every use
  (hash in `__sessions` DB, `__Host-` cookies HttpOnly+Secure+SameSite=Strict Path=/).
- Refresh reuse (an old token showing up again) → revoke ALL user sessions + reject.
- Register drops `password_hash` from the body AND strips claim-bound fields
  (`[identity].attrs`): profile is caller-controlled, attrs become JWT claims
  at login, so accepting them = self-mint (e.g. `role=service`). Privileged
  fields are set later via the update path, never at signup.
  Wrong login/email is disguised (anti enumeration).
- Tradeoff: stateless access JWT — logout revokes refresh, access lives until
  expiry (hence short TTL). No `mock-user` bypass.
- DPoP (RFC 9449, local tokens): `off|accept|require` via `UB_LOCAL_DPOP`/`dpop`
  in custom.toml; a stolen token without the private key is unusable; replays rejected.
- `/api/admin/reload` locked behind `admin_uids` (UID allowlist).

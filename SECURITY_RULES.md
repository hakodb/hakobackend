# Standard Security Rules

These rules **follow endpoint flexibility** (they apply to auto-wildcard
and declared resources alike) and are the reference for all deployments.
Implementation: `crates/hakobackend-policy` + `policy.toml` (hot-reload). Ready-made example:
`policy.standard.toml`.

## 1. Standard principles

1. **Default-deny.** No allowing rule → reject. Without `policy_file`
   (dev mode) the server is OPEN + must log WARN — never for production.
2. **Fail-closed.** Rule typo, parse failure, unknown auth, missing document
   for an `owner` rule → reject. Never fail open.
3. **Uniform auth.** Any provider (internal/firebase/oidc) only fills
   `AuthContext{uid, roles, tenant}`; rules never know which provider.
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

## 3. Roles & user collections: user-owned, not core

Core binds **neither** role names **nor** the user collection. Users define everything
in `[identity]` in `policy.toml`:

```toml
[identity]
users_collection = "members"  # default "users"; free choice: sc_users, members, …
role_field = "posisi"         # default "role"; single string or array
owner_field = "pemilikId"     # default "ownerId"; per-collection override allowed
```

- `role:<anything>` is free-form — core only compares the user document's role string
  (loaded from `users_collection` via `role_field`, string or array) against
  the name in the rule. No reserved role names.
- Role examples in this document (`admin`, `maintainer`, `pengurus`) are just
  **ready-made templates**, not requirements. Rename freely.
- The global `owner_field` can be overridden per collection (`collections.X.owner_field`).
  `owner` evaluation uses the configured field, with `ownerId`/`uid`
  compatibility fallback for legacy data.

## 4. Standard endpoint access classes

| Class | Policy pattern | Example |
|---|---|---|
| Public-read | `read = "public"`, `write = "deny"` | `posts`, `pages`, `sc_configs` |
| Authenticated-write | `create/update = "auth"` | `media`, `tags` |
| Owner-only | `read/write = "owner"` (+ `owner_field`) | `profiles`, user notifications |
| Admin-only | `read/write = "role:admin"` | `ai_configs`, credentials |
| Internal collections | `__` prefix **not exposed** over HTTP (unless explicit) | `__users` (refresh tokens), audit |

## 5. Document conventions (working defaults, all replaceable)

- Default owner field `ownerId` (fallback `uid`); change via `[identity].owner_field`
  or per collection. An `owner` rule on a document lacking the matched field → reject.
- Privilege-escalation fields (`role`, `status`, …) must **not** be
  self-service writable — escalation guards like the legacy backend's
  `isModifyingRestrictedFields` land in phase-2 policy (`immutable_fields`, `owner_only_fields`).

## 6. Standard error codes (legacy backend parity)

| Situation | Status | Body |
|---|---|---|
| Policy reject | 403 | `Permission denied by policy` |
| Document missing | 404 | `Document not found` |
| Wrong route kind | 400 | `POST/PUT/PATCH/DELETE … must target …` |
| Duplicate | 400 | `already-exists` |
| Rate-limit / full queue | 429 | no internal details |

## 7. Auth standards (local: implemented phase C; external: verifier-only)

- Dual-token BFF pattern: 5–15 min access JWT + rotating opaque refresh on every use
  (hash in `__sessions` DB, `__Host-` cookies HttpOnly+Secure+SameSite=Strict Path=/).
- Refresh reuse (an old token showing up again) → revoke ALL user sessions + reject.
- Register drops `role`/`password_hash` from the body (anti self-escalation);
  wrong login/email is disguised (anti enumeration).
- Tradeoff: stateless access JWT — logout revokes refresh, access lives until
  expiry (hence short TTL). No `mock-user` bypass.
- DPoP (RFC 9449, local tokens): `off|accept|require` via `UB_LOCAL_DPOP`/`dpop`
  in custom.toml; a stolen token without the private key is unusable; replays rejected.
- `/api/admin/reload` locked behind `--admin-role` (default `admin`, name is free choice).

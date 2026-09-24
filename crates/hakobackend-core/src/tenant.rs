//! Multi-tenant collection namespacing (prefix design).
//!
//! One backend serves many consumers without collection collisions:
//! tenant `acme` sees `users`, stored as `acme__users`. Rules:
//! - The prefix comes ONLY from the authenticated identity
//!   (`AuthContext.tenant`) — never from client input. No tenant
//!   (`None`) = legacy unprefixed namespace (backward compatible).
//! - Slugs are `[a-z0-9-]` (no underscore): a stored name contains `__`
//!   iff it is tenant-scoped, so parsing is unambiguous. Uniqueness is
//!   structural — provisioning uses `insert` (conflict = taken).
//! - Policy is evaluated on LOGICAL names: one policy file serves all
//!   tenants. Drivers see stored names and need no changes.
//! - Registry lives in the reserved `__tenants` collection (admin-only,
//!   covered by the `__*` hard-deny like other internals).

/// Reserved registry collection: one doc per tenant, id = slug.
pub const TENANTS_COLLECTION: &str = "__tenants";

/// Tenant slug charset: lowercase alnum + dash, 1–63 chars, no underscore
/// (so `__` unambiguously marks a tenant-scoped stored name).
pub fn is_valid_tenant_slug(s: &str) -> bool {
    let b = s.as_bytes();
    !b.is_empty()
        && b.len() <= 63
        && b[0] != b'-'
        && b.iter().all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || *c == b'-')
}

/// Logical path → stored name for this caller.
pub fn resolve_collection(tenant: Option<&str>, logical: &str) -> String {
    match tenant {
        Some(t) => format!("{t}__{logical}"),
        None => logical.to_string(),
    }
}

/// Stored name → (tenant, logical). A name holds a tenant iff the part
/// before the FIRST `__` is a valid slug and the rest is non-empty.
pub fn split_tenant(stored: &str) -> (Option<&str>, &str) {
    match stored.split_once("__") {
        Some((slug, rest)) if !rest.is_empty() && is_valid_tenant_slug(slug) => (Some(slug), rest),
        _ => (None, stored),
    }
}

/// Stored collection list → (stored, logical) pairs visible to this caller:
/// exactly its own namespace (stripped), or everything when tenantless.
/// Internal `__*` names never leak — neither globally nor as a tenant's
/// logical names (tenant stores like `acme____sessions` stay invisible).
pub fn visible_collections(all: Vec<String>, tenant: Option<&str>) -> Vec<(String, String)> {
    all.into_iter()
        .filter_map(|stored| {
            let (t, logical) = split_tenant(&stored);
            if logical.starts_with("__") {
                return None;
            }
            let logical = logical.to_string();
            match (tenant, t) {
                (Some(want), Some(got)) if want == got => Some((stored, logical)),
                (None, None) => Some((stored, logical)),
                _ => None,
            }
        })
        .collect()
}

/// Tenant of a request, from the authenticated identity only.
pub fn tenant_of(auth: Option<&super::AuthContext>) -> Option<String> {
    auth.and_then(|a| a.tenant.clone()).filter(|t| is_valid_tenant_slug(t))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slug_charset() {
        assert!(is_valid_tenant_slug("acme-1"));
        assert!(!is_valid_tenant_slug(""));
        assert!(!is_valid_tenant_slug("Acme"));
        assert!(!is_valid_tenant_slug("ac_me"));
        assert!(!is_valid_tenant_slug("-acme"));
        assert!(!is_valid_tenant_slug(&"a".repeat(64)));
    }

    #[test]
    fn resolve_and_split_roundtrip() {
        assert_eq!(resolve_collection(Some("acme"), "users"), "acme__users");
        assert_eq!(resolve_collection(Some("acme"), "posts/1/rev"), "acme__posts/1/rev");
        assert_eq!(resolve_collection(None, "users"), "users");
        assert_eq!(split_tenant("acme__users"), (Some("acme"), "users"));
        assert_eq!(split_tenant("users"), (None, "users"));
        assert_eq!(split_tenant("__tenants"), (None, "__tenants"));
        assert_eq!(split_tenant("ACME__users"), (None, "ACME__users"));
    }

    #[test]
    fn visibility_isolation() {
        let all = vec!["users".into(), "acme__users".into(), "b__users".into(), "__tenants".into()];
        let a: Vec<_> = visible_collections(all.clone(), Some("acme"))
            .into_iter()
            .map(|(_, l)| l)
            .collect();
        assert_eq!(a, vec!["users"]);
        let anon: Vec<_> = visible_collections(all, None).into_iter().map(|(_, l)| l).collect();
        assert_eq!(anon, vec!["users"]);
    }

    #[test]
    fn visibility_hides_tenanted_internals() {
        // Tenant-namespaced sessions (`acme____sessions`) must never
        // surface as logical `__sessions` — for the owner or anyone else.
        let all = vec!["acme__users".into(), "acme____sessions".into(), "__sessions".into()];
        let a: Vec<_> = visible_collections(all.clone(), Some("acme"))
            .into_iter()
            .map(|(_, l)| l)
            .collect();
        assert_eq!(a, vec!["users"]);
        let anon: Vec<_> = visible_collections(all, None).into_iter().map(|(_, l)| l).collect();
        assert!(anon.is_empty());
    }
}

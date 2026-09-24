//! Browser portal (phase C): server-rendered HTML over the same JSON core.
//!
//! No JS framework, no new deps: plain forms + session cookies (BFF —
//! tokens never reach the browser). Cookie POSTs are already
//! Origin-checked by auth_mw, and every interpolated value goes through
//! `esc`. The JSON API stays the machine interface; the portal is for
//! operators (org admin) and tenant owners (tenant admin).

use super::*;
use axum::extract::Form;
use axum::response::Html;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/portal", get(index))
        .route("/portal/login", get(login_page))
        .route("/portal/logout", post(logout_post))
        .route("/portal/status", get(status_page))
        .route("/portal/register", get(register_page))
        .route("/portal/admin", get(admin_hub))
        .route("/portal/admin/tenants", get(admin_tenants).post(admin_tenants_post))
        .route("/portal/admin/profiles", get(admin_profiles).post(admin_profiles_post))
        .route("/portal/admin/policy", get(admin_policy).post(admin_policy_post))
        .route("/portal/tenant", get(tenant_hub))
        .route("/portal/tenant/users", get(tenant_users).post(tenant_users_post))
        .route("/portal/tenant/users/delete", post(tenant_user_delete))
        .route("/portal/tenant/users/roles", post(tenant_user_roles))
        .route("/portal/tenant/policy", get(tenant_policy_page).post(tenant_policy_post))
        .route("/portal/tenant/profiles", get(tenant_profiles).post(tenant_profiles_post))
}

/// Credential endpoints live under the STRICT auth limiter with the JSON ones.
pub fn strict_routes() -> Router<AppState> {
    Router::new()
        .route("/portal/login", post(login_post))
        .route("/portal/register", post(register_post))
}

// --- HTML plumbing ---

fn esc(s: &str) -> String {
    let mut o = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => o.push_str("&amp;"),
            '<' => o.push_str("&lt;"),
            '>' => o.push_str("&gt;"),
            '"' => o.push_str("&quot;"),
            '\'' => o.push_str("&#39;"),
            _ => o.push(c),
        }
    }
    o
}

fn shell(title: &str, nav: &str, body: &str) -> Html<String> {
    Html(format!(
        "<!DOCTYPE html><html lang=\"en\"><head><meta charset=\"utf-8\">\
         <meta name=\"viewport\" content=\"width=device-width,initial-scale=1\">\
         <title>{t}</title><style>\
         body{{font-family:system-ui,sans-serif;max-width:56rem;margin:2rem auto;padding:0 1rem;color:#111}}\
         nav a{{margin-right:1rem}}table{{border-collapse:collapse;width:100%}}\
         td,th{{border:1px solid #ccc;padding:.35rem .6rem;text-align:left;font-size:.9rem}}\
         input,textarea,select{{font:inherit;padding:.3rem .5rem;max-width:100%}}\
         textarea{{width:100%;min-height:12rem;font-family:monospace}}\
         form.inline{{display:inline}}button{{font:inherit;padding:.3rem .8rem;cursor:pointer}}\
         .err{{background:#fee;border:1px solid #c00;padding:.6rem 1rem}}\
         .ok{{background:#efe;border:1px solid #0a0;padding:.6rem 1rem}}\
         .muted{{color:#666;font-size:.85rem}}</style></head>\
         <body><nav>{n}</nav><h1>{t}</h1>{b}</body></html>",
        t = esc(title),
        n = nav,
        b = body,
    ))
}

fn nav_for(s: &AppState, auth: &Option<AuthContext>) -> String {
    let mut n = String::from("<a href=\"/portal\">portal</a><a href=\"/portal/status\">status</a>");
    if let Some(a) = auth {
        if a.roles.iter().any(|r| r == &s.admin_role) {
            n.push_str("<a href=\"/portal/admin\">admin</a>");
        }
        if let Some(t) = a.tenant.clone() {
            if a.roles.iter().any(|r| r == &s.tenant_admin_role) {
                n.push_str(&format!(" <a href=\"/portal/tenant\">my tenant ({})</a>", esc(&t)));
            }
        }
        n.push_str(&logout_form(auth));
    } else {
        n.push_str("<a href=\"/portal/login\">login</a>");
        if s.mode == ServiceMode::Open {
            n.push_str("<a href=\"/portal/register\">register tenant</a>");
        }
    }
    n
}

fn logout_form(auth: &Option<AuthContext>) -> String {
    // Revocation needs the issuing scope: global or the claim tenant.
    let tenant = auth.as_ref().and_then(|a| a.tenant.clone()).unwrap_or_default();
    format!(
        " <form class=\"inline\" method=\"post\" action=\"/portal/logout\">\
         <input type=\"hidden\" name=\"tenant\" value=\"{}\">\
         <button>logout</button></form>",
        esc(&tenant),
    )
}

fn is_org_admin(s: &AppState, auth: &Option<AuthContext>) -> bool {
    auth.as_ref().is_some_and(|a| a.roles.iter().any(|r| r == &s.admin_role))
}

/// Tenant slug this caller administers (claim-bound + role), else None.
fn own_tenant(s: &AppState, auth: &Option<AuthContext>) -> Option<String> {
    let a = auth.as_ref()?;
    if !a.roles.iter().any(|r| r == &s.tenant_admin_role) {
        return None;
    }
    a.tenant.clone()
}

/// Pull the `{error}` message out of a JSON error Response for display.
async fn resp_message(r: Response) -> String {
    match axum::body::to_bytes(r.into_body(), 64 * 1024).await {
        Ok(b) => serde_json::from_slice::<serde_json::Value>(&b)
            .ok()
            .and_then(|v| v.get("error").and_then(|e| e.as_str()).map(str::to_string))
            .unwrap_or_else(|| "request failed".into()),
        Err(_) => "request failed".into(),
    }
}

fn fail_page(
    s: &AppState,
    auth: &Option<AuthContext>,
    status: StatusCode,
    title: &str,
    msg: &str,
    back: &str,
) -> Response {
    (
        status,
        shell(
            title,
            &nav_for(s, auth),
            &format!("<div class=\"err\">{}</div><p><a href=\"{}\">back</a></p>", esc(msg), back),
        ),
    )
        .into_response()
}

// --- Entry ---

async fn index(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>) -> Response {
    if is_org_admin(&s, &auth) {
        return Redirect::to("/portal/admin").into_response();
    }
    if own_tenant(&s, &auth).is_some() {
        return Redirect::to("/portal/tenant").into_response();
    }
    Redirect::to("/portal/login").into_response()
}

async fn status_page(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>) -> Response {
    let local = s.local.read().await.is_some();
    let github = s.github.read().await.is_some();
    shell(
        "status",
        &nav_for(&s, &auth),
        &format!(
            "<p>mode: <b>{}</b>{}</p><p>local auth: {} · github oauth: {}</p>",
            esc(s.mode.as_str()),
            s.service_tenant.as_deref().map(|t| format!(" (tenant: {})", esc(t))).unwrap_or_default(),
            if local { "on" } else { "off" },
            if github { "on" } else { "off" },
        ),
    )
    .into_response()
}

// --- Login / logout (BFF: cookies set, browser never sees tokens) ---

#[derive(serde::Deserialize)]
struct LoginQuery {
    tenant: Option<String>,
}

async fn login_page(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<LoginQuery>,
) -> Response {
    if auth.is_some() {
        return Redirect::to("/portal").into_response();
    }
    let t = q.tenant.unwrap_or_default();
    shell(
        "login",
        &nav_for(&s, &auth),
        &format!(
            "<form method=\"post\" action=\"/portal/login\">\
             <p><label>login<br><input name=\"login\" required></label></p>\
             <p><label>password<br><input type=\"password\" name=\"password\" required></label></p>\
             <p><label>tenant (optional)<br><input name=\"tenant\" value=\"{}\"></label></p>\
             <p><button>login</button></p></form>",
            esc(&t),
        ),
    )
    .into_response()
}

#[derive(serde::Deserialize)]
struct LoginForm {
    login: String,
    password: String,
    tenant: Option<String>,
}

async fn login_post(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<LoginForm>,
) -> Response {
    let local = match issuance_local(&s, clean_hint(f.tenant)).await {
        Ok(l) => l,
        Err(e) => return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "login", &resp_message(e).await, "/portal/login"),
    };
    // Browser form: no DPoP proof available (same as password-only JSON login).
    match local.login(&f.login, &f.password, None).await {
        Ok((_ctx, tokens)) => {
            let headers = session_cookies(&local, &tokens);
            (StatusCode::FOUND, headers, Redirect::to("/portal")).into_response()
        }
        Err(_) => fail_page(&s, &auth, StatusCode::UNAUTHORIZED, "login", "invalid credentials", "/portal/login"),
    }
}

#[derive(serde::Deserialize)]
struct LogoutForm {
    tenant: Option<String>,
}

async fn logout_post(
    State(s): State<AppState>,
    headers: HeaderMap,
    Form(f): Form<LogoutForm>,
) -> Response {
    // Mirror /api/auth/logout revocation (global or tenant bundle).
    if let Some(t) = read_cookie(&headers, REFRESH_COOKIE) {
        match clean_hint(f.tenant) {
            Some(h) => {
                if let Some(b) = s.tenant_auths.get(&h).await {
                    if let Some(local) = &b.local {
                        let _ = local.logout(&t).await;
                    }
                }
            }
            None => {
                if let Some(local) = s.local.read().await.clone() {
                    let _ = local.logout(&t).await;
                }
            }
        }
    }
    (StatusCode::FOUND, clear_cookies(), Redirect::to("/portal/login")).into_response()
}

// --- Org admin ---

async fn admin_hub(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>) -> Response {
    if !is_org_admin(&s, &auth) {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "admin", "org admin required", "/portal");
    }
    shell(
        "admin",
        &nav_for(&s, &auth),
        "<ul><li><a href=\"/portal/admin/tenants\">tenants</a></li>\
         <li><a href=\"/portal/admin/profiles\">auth profiles</a></li>\
         <li><a href=\"/portal/admin/policy\">tenant policy</a> (pick a tenant first)</li></ul>",
    )
    .into_response()
}

async fn admin_tenants(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
) -> Response {
    if !is_org_admin(&s, &auth) {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "tenants", "org admin required", "/portal");
    }
    if let Some(r) = s.single_registry_guard() {
        return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "tenants", &resp_message(r).await, "/portal/admin");
    }
    let rows = match s.db.read().await.list(hakobackend_core::tenant::TENANTS_COLLECTION, &QueryOptions::default()).await {
        Ok(docs) => docs
            .into_iter()
            .map(|d| {
                format!(
                    "<tr><td>{}</td><td>{}</td>\
                     <td><a href=\"/portal/admin/policy?slug={}\">policy</a></td></tr>",
                    esc(&d.id),
                    esc(d.data.get("auth_profile").and_then(|v| v.as_str()).unwrap_or("—")),
                    esc(&d.id),
                )
            })
            .collect::<String>(),
        Err(_) => return fail_page(&s, &auth, StatusCode::INTERNAL_SERVER_ERROR, "tenants", "internal error", "/portal/admin"),
    };
    shell(
        "tenants",
        &nav_for(&s, &auth),
        &format!(
            "<table><tr><th>slug</th><th>auth_profile</th><th></th></tr>{}</table>\
             <h2>create</h2><form method=\"post\" action=\"/portal/admin/tenants\">\
             <p><label>slug<br><input name=\"slug\" required></label></p>\
             <p><label>auth_profile (optional)<br><input name=\"auth_profile\"></label></p>\
             <p><button>create</button></p></form>",
            rows,
        ),
    )
    .into_response()
}

#[derive(serde::Deserialize)]
struct TenantForm {
    slug: String,
    auth_profile: Option<String>,
}

async fn admin_tenants_post(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<TenantForm>,
) -> Response {
    if !is_org_admin(&s, &auth) {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "tenants", "org admin required", "/portal");
    }
    if let Some(r) = s.single_registry_guard() {
        return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "tenants", &resp_message(r).await, "/portal/admin");
    }
    let profile = f.auth_profile.filter(|v| !v.trim().is_empty());
    match create_tenant_doc(&s, f.slug.trim(), profile.as_deref()).await {
        Ok(()) => Redirect::to("/portal/admin/tenants").into_response(),
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "tenants", &resp_message(e).await, "/portal/admin/tenants"),
    }
}

async fn admin_profiles(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
) -> Response {
    if !is_org_admin(&s, &auth) {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "auth profiles", "org admin required", "/portal");
    }
    if let Some(r) = s.single_registry_guard() {
        return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "auth profiles", &resp_message(r).await, "/portal/admin");
    }
    let rows = match s.db.read().await.list(super::tenant_auth::AUTH_PROFILES_COLLECTION, &QueryOptions::default()).await {
        Ok(docs) => docs
            .into_iter()
            .map(|d| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&d.id),
                    esc(d.data.get("owner_tenant").and_then(|v| v.as_str()).unwrap_or("— (global)")),
                    esc(d.data.get("spec").and_then(|v| v.as_str()).unwrap_or("")),
                    esc(&d.data.get("shared").and_then(|v| v.as_bool()).map(|b| b.to_string()).unwrap_or_default()),
                )
            })
            .collect::<String>(),
        Err(_) => return fail_page(&s, &auth, StatusCode::INTERNAL_SERVER_ERROR, "auth profiles", "internal error", "/portal/admin"),
    };
    shell(
        "auth profiles",
        &nav_for(&s, &auth),
        &format!(
            "<table><tr><th>id</th><th>owner</th><th>spec</th><th>shared</th></tr>{}</table>\
             <h2>create / edit</h2><form method=\"post\" action=\"/portal/admin/profiles\">\
             <p><label>id<br><input name=\"id\" required></label></p>\
             <p><label>owner_tenant (empty = global)<br><input name=\"owner_tenant\"></label></p>\
             <p><label>spec<br><input name=\"spec\" value=\"local\" required></label></p>\
             <p><label><input type=\"checkbox\" name=\"shared\" value=\"true\"> shared</label></p>\
             <p><label>config (JSON)<br><textarea name=\"config\" rows=\"4\">{{}}</textarea></label></p>\
             <p><button>save</button></p></form>\
             <p class=\"muted\">Secrets stay server-side; the list never shows config values.</p>",
            rows,
        ),
    )
    .into_response()
}

#[derive(serde::Deserialize)]
struct ProfileForm {
    id: String,
    owner_tenant: Option<String>,
    spec: String,
    shared: Option<String>,
    config: Option<String>,
}

async fn admin_profiles_post(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<ProfileForm>,
) -> Response {
    if !is_org_admin(&s, &auth) {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "auth profiles", "org admin required", "/portal");
    }
    if let Some(r) = s.single_registry_guard() {
        return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "auth profiles", &resp_message(r).await, "/portal/admin");
    }
    let owner = f.owner_tenant.filter(|v| !v.trim().is_empty());
    let shared = f.shared.is_some();
    let config: serde_json::Value = match f.config.unwrap_or_default().trim() {
        "" => serde_json::json!({}),
        raw => match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "auth profiles", "config is not valid JSON", "/portal/admin/profiles"),
        },
    };
    match put_profile_doc(&s, f.id.trim(), owner.as_deref(), shared, f.spec.trim(), config).await {
        Ok(()) => Redirect::to("/portal/admin/profiles").into_response(),
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "auth profiles", &resp_message(e).await, "/portal/admin/profiles"),
    }
}

#[derive(serde::Deserialize)]
struct PolicyQuery {
    slug: Option<String>,
}

async fn admin_policy(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Query(q): Query<PolicyQuery>,
) -> Response {
    if !is_org_admin(&s, &auth) {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "tenant policy", "org admin required", "/portal");
    }
    let slug = q.slug.unwrap_or_default();
    let (version, toml) = if slug.is_empty() {
        (None, String::new())
    } else {
        match s.tenant_policies.get_raw(&slug).await {
            Some((v, t)) => (Some(v), t),
            None => (None, "# no tenant policy yet (global applies) — save to create v1".into()),
        }
    };
    shell(
        "tenant policy",
        &nav_for(&s, &auth),
        &format!(
            "<form method=\"post\" action=\"/portal/admin/policy\">\
             <p><label>slug<br><input name=\"slug\" value=\"{}\" required></label>{}</p>\
             <p><label>policy_toml<br><textarea name=\"policy_toml\" rows=\"16\">{}</textarea></label></p>\
             <p><button>save</button></p></form>\
             <p class=\"muted\">Validated before store; broken TOML is rejected, never persisted.</p>",
            esc(&slug),
            version.map(|v| format!(" <span class=\"muted\">(v{v})</span>")).unwrap_or_default(),
            esc(&toml),
        ),
    )
    .into_response()
}

#[derive(serde::Deserialize)]
struct PolicyForm {
    slug: String,
    policy_toml: String,
}

async fn admin_policy_post(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<PolicyForm>,
) -> Response {
    if !is_org_admin(&s, &auth) {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "tenant policy", "org admin required", "/portal");
    }
    let slug = f.slug.trim().to_string();
    if !s.tenant_scoped_admin(auth.as_ref(), &slug) {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "tenant policy", "org admin required", "/portal");
    }
    if s.mode == ServiceMode::Single && Some(slug.as_str()) != s.service_tenant.as_deref() {
        return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "tenant policy", "single-tenant mode serves only the pinned tenant", "/portal");
    }
    match s.tenant_policies.put(&slug, &f.policy_toml).await {
        Ok(v) => {
            s.tenant_auths.invalidate(&slug);
            shell(
                "tenant policy",
                &nav_for(&s, &auth),
                &format!("<div class=\"ok\">saved v{v}</div><p><a href=\"/portal/admin/policy?slug={}\">back</a></p>", esc(&slug)),
            )
            .into_response()
        }
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "tenant policy", &e, "/portal/admin/policy"),
    }
}

// --- Tenant portal (claim-bound owner) ---

async fn tenant_hub(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "my tenant", "tenant admin required", "/portal");
    };
    shell(
        &format!("tenant {slug}"),
        &nav_for(&s, &auth),
        "<ul><li><a href=\"/portal/tenant/users\">users</a></li>\
         <li><a href=\"/portal/tenant/policy\">policy</a></li>\
         <li><a href=\"/portal/tenant/profiles\">auth profiles</a></li></ul>",
    )
    .into_response()
}

async fn tenant_db_for(s: &AppState, slug: &str) -> hakobackend_core::tenant_db::TenantDb {
    hakobackend_core::tenant_db::TenantDb::new(s.db.read().await.clone(), slug)
}

async fn tenant_users(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "users", "tenant admin required", "/portal");
    };
    let ident = s.policy.get().await.identity.clone();
    let tdb = tenant_db_for(&s, &slug).await;
    let rows = match tdb.list(&ident.users_collection, &QueryOptions::default()).await {
        Ok(docs) => docs
            .into_iter()
            .map(|d| {
                let roles = d
                    .data
                    .get(&ident.role_field)
                    .map(|v| match v {
                        serde_json::Value::String(r) => r.clone(),
                        _ => v.to_string(),
                    })
                    .unwrap_or_else(|| "—".into());
                format!(
                    "<tr><td>{}</td><td>{}</td>\
                     <td><form class=\"inline\" method=\"post\" action=\"/portal/tenant/users/roles\">\
                     <input type=\"hidden\" name=\"id\" value=\"{}\">\
                     <input name=\"roles\" value=\"{}\" size=\"18\">\
                     <button>set roles</button></form></td>\
                     <td><form class=\"inline\" method=\"post\" action=\"/portal/tenant/users/delete\" \
                     onsubmit=\"return confirm('delete user?')\">\
                     <input type=\"hidden\" name=\"id\" value=\"{}\">\
                     <button>delete</button></form></td></tr>",
                    esc(&d.id),
                    esc(&roles),
                    esc(&d.id),
                    esc(&roles),
                    esc(&d.id),
                )
            })
            .collect::<String>(),
        Err(_) => return fail_page(&s, &auth, StatusCode::INTERNAL_SERVER_ERROR, "users", "internal error", "/portal/tenant"),
    };
    shell(
        &format!("users ({slug})"),
        &nav_for(&s, &auth),
        &format!(
            "<table><tr><th>id</th><th>roles</th><th></th><th></th></tr>{}</table>\
             <h2>create</h2><form method=\"post\" action=\"/portal/tenant/users\">\
             <p><label>id or email<br><input name=\"login\" required></label></p>\
             <p><label>password (min 8)<br><input type=\"password\" name=\"password\" required></label></p>\
             <p><button>create user</button></p></form>\
             <p class=\"muted\">Delete removes the doc; live sessions expire on their own.\
             Stripping your own admin role locks you out (org admin can restore).</p>",
            rows,
        ),
    )
    .into_response()
}

#[derive(serde::Deserialize)]
struct UserForm {
    login: String,
    password: String,
}

async fn tenant_users_post(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<UserForm>,
) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "users", "tenant admin required", "/portal");
    };
    let local = match s.tenant_auths.get(&slug).await.and_then(|b| b.local.clone()) {
        Some(l) => l,
        None => return fail_page(&s, &auth, StatusCode::INTERNAL_SERVER_ERROR, "users", "tenant has no local auth", "/portal/tenant/users"),
    };
    // id-or-email like the JSON endpoint (register decides).
    let (id, email) = if f.login.contains('@') { (None, Some(f.login)) } else { (Some(f.login), None) };
    match local.register(id, email, &f.password, HashMap::new()).await {
        Ok(doc) => {
            let users = s.policy.get().await.identity.users_collection.clone();
            let stored = hakobackend_core::tenant::resolve_collection(Some(&slug), &users);
            super::realtime::emit(
                &stored,
                hakobackend_core::Change {
                    collection: stored.clone(),
                    id: doc.id.clone(),
                    kind: hakobackend_core::ChangeKind::Change,
                    old: None,
                    new: Some(doc),
                },
            );
            Redirect::to("/portal/tenant/users").into_response()
        }
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "users", &e.to_string(), "/portal/tenant/users"),
    }
}

#[derive(serde::Deserialize)]
struct UserIdForm {
    id: String,
}

async fn tenant_user_delete(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<UserIdForm>,
) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "users", "tenant admin required", "/portal");
    };
    let ident = s.policy.get().await.identity.clone();
    let tdb = tenant_db_for(&s, &slug).await;
    match tdb.delete(&ident.users_collection, &f.id).await {
        Ok(_) => {
            let stored = hakobackend_core::tenant::resolve_collection(Some(&slug), &ident.users_collection);
            super::realtime::emit(
                &stored,
                hakobackend_core::Change {
                    collection: stored.clone(),
                    id: f.id.clone(),
                    kind: hakobackend_core::ChangeKind::Remove,
                    old: None,
                    new: None,
                },
            );
            Redirect::to("/portal/tenant/users").into_response()
        }
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "users", &e.to_string(), "/portal/tenant/users"),
    }
}

#[derive(serde::Deserialize)]
struct UserRolesForm {
    id: String,
    roles: String,
}

async fn tenant_user_roles(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<UserRolesForm>,
) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "users", "tenant admin required", "/portal");
    };
    let ident = s.policy.get().await.identity.clone();
    let tdb = tenant_db_for(&s, &slug).await;
    let mut doc = match tdb.get(&ident.users_collection, &f.id).await {
        Ok(Some(d)) => d,
        Ok(None) => return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "users", "unknown user", "/portal/tenant/users"),
        Err(_) => return fail_page(&s, &auth, StatusCode::INTERNAL_SERVER_ERROR, "users", "internal error", "/portal/tenant/users"),
    };
    let roles: Vec<serde_json::Value> = f
        .roles
        .split([',', ' '])
        .filter_map(|r| {
            let r = r.trim();
            (!r.is_empty()).then(|| serde_json::Value::String(r.into()))
        })
        .collect();
    doc.data.insert(ident.role_field.clone(), serde_json::Value::Array(roles));
    match tdb.set(&ident.users_collection, &f.id, doc, false).await {
        Ok(saved) => {
            let stored = hakobackend_core::tenant::resolve_collection(Some(&slug), &ident.users_collection);
            super::realtime::emit(
                &stored,
                hakobackend_core::Change {
                    collection: stored.clone(),
                    id: saved.id.clone(),
                    kind: hakobackend_core::ChangeKind::Change,
                    old: None,
                    new: Some(saved),
                },
            );
            Redirect::to("/portal/tenant/users").into_response()
        }
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "users", &e.to_string(), "/portal/tenant/users"),
    }
}

async fn tenant_policy_page(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "policy", "tenant admin required", "/portal");
    };
    let (version, toml) = match s.tenant_policies.get_raw(&slug).await {
        Some((v, t)) => (format!("v{v}"), t),
        None => ("global applies".into(), "# no tenant policy yet — save to create v1".into()),
    };
    shell(
        &format!("policy ({slug})"),
        &nav_for(&s, &auth),
        &format!(
            "<form method=\"post\" action=\"/portal/tenant/policy\">\
             <input type=\"hidden\" name=\"slug\" value=\"{}\">\
             <p class=\"muted\">current: {}</p>\
             <p><label>policy_toml<br><textarea name=\"policy_toml\" rows=\"16\">{}</textarea></label></p>\
             <p><button>save</button></p></form>",
            esc(&slug),
            esc(&version),
            esc(&toml),
        ),
    )
    .into_response()
}

async fn tenant_policy_post(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<PolicyForm>,
) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "policy", "tenant admin required", "/portal");
    };
    // The slug rides the claim, not the form (a forged slug field can't escape).
    match s.tenant_policies.put(&slug, &f.policy_toml).await {
        Ok(v) => {
            s.tenant_auths.invalidate(&slug);
            shell(
                &format!("policy ({slug})"),
                &nav_for(&s, &auth),
                &format!("<div class=\"ok\">saved v{v}</div><p><a href=\"/portal/tenant/policy\">back</a></p>"),
            )
            .into_response()
        }
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "policy", &e, "/portal/tenant/policy"),
    }
}

async fn tenant_profiles(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "auth profiles", "tenant admin required", "/portal");
    };
    let rows = match s.db.read().await.list(super::tenant_auth::AUTH_PROFILES_COLLECTION, &QueryOptions::default()).await {
        Ok(docs) => docs
            .into_iter()
            .filter(|d| {
                let owner = d.data.get("owner_tenant").and_then(|v| v.as_str());
                owner.is_none() || owner == Some(slug.as_str())
            })
            .map(|d| {
                format!(
                    "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                    esc(&d.id),
                    esc(d.data.get("owner_tenant").and_then(|v| v.as_str()).unwrap_or("— (global)")),
                    esc(d.data.get("spec").and_then(|v| v.as_str()).unwrap_or("")),
                )
            })
            .collect::<String>(),
        Err(_) => return fail_page(&s, &auth, StatusCode::INTERNAL_SERVER_ERROR, "auth profiles", "internal error", "/portal/tenant"),
    };
    shell(
        &format!("auth profiles ({slug})"),
        &nav_for(&s, &auth),
        &format!(
            "<table><tr><th>id</th><th>owner</th><th>spec</th></tr>{}</table>\
             <h2>create / edit (owned by you)</h2>\
             <form method=\"post\" action=\"/portal/tenant/profiles\">\
             <p><label>id<br><input name=\"id\" required></label></p>\
             <p><label>spec<br><input name=\"spec\" value=\"local\" required></label></p>\
             <p><label><input type=\"checkbox\" name=\"shared\" value=\"true\"> shared</label></p>\
             <p><label>config (JSON)<br><textarea name=\"config\" rows=\"4\">{{}}</textarea></label></p>\
             <p><button>save</button></p></form>",
            rows,
        ),
    )
    .into_response()
}

async fn tenant_profiles_post(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<ProfileForm>,
) -> Response {
    let Some(slug) = own_tenant(&s, &auth) else {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "auth profiles", "tenant admin required", "/portal");
    };
    // Owner forced to the claim tenant (a forged owner field can't escape).
    let shared = f.shared.is_some();
    let config: serde_json::Value = match f.config.unwrap_or_default().trim() {
        "" => serde_json::json!({}),
        raw => match serde_json::from_str(raw) {
            Ok(v) => v,
            Err(_) => return fail_page(&s, &auth, StatusCode::BAD_REQUEST, "auth profiles", "config is not valid JSON", "/portal/tenant/profiles"),
        },
    };
    match put_profile_doc(&s, f.id.trim(), Some(&slug), shared, f.spec.trim(), config).await {
        Ok(()) => Redirect::to("/portal/tenant/profiles").into_response(),
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "auth profiles", &resp_message(e).await, "/portal/tenant/profiles"),
    }
}

// --- Public self-registration (open mode only) ---

async fn register_page(State(s): State<AppState>, Extension(auth): Extension<Option<AuthContext>>) -> Response {
    if s.mode != ServiceMode::Open {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "register", "self-registration is disabled", "/portal");
    }
    shell(
        "register tenant",
        &nav_for(&s, &auth),
        "<form method=\"post\" action=\"/portal/register\">\
         <p><label>tenant slug<br><input name=\"slug\" required></label></p>\
         <p><label>owner id or email<br><input name=\"login\" required></label></p>\
         <p><label>password (min 8)<br><input type=\"password\" name=\"password\" required></label></p>\
         <p><button>create tenant</button></p></form>\
         <p class=\"muted\">You become this tenant's admin. Then log in with the tenant filled in.</p>",
    )
    .into_response()
}

#[derive(serde::Deserialize)]
struct RegisterForm {
    slug: String,
    login: String,
    password: String,
}

async fn register_post(
    State(s): State<AppState>,
    Extension(auth): Extension<Option<AuthContext>>,
    Form(f): Form<RegisterForm>,
) -> Response {
    if s.mode != ServiceMode::Open {
        return fail_page(&s, &auth, StatusCode::FORBIDDEN, "register", "self-registration is disabled", "/portal");
    }
    let (id, email) = if f.login.contains('@') { (None, Some(f.login)) } else { (Some(f.login), None) };
    match provision_tenant(&s, f.slug.trim(), id, email, &f.password).await {
        Ok((slug, _)) => Redirect::to(&format!("/portal/login?tenant={slug}")).into_response(),
        Err(e) => fail_page(&s, &auth, StatusCode::BAD_REQUEST, "register", &resp_message(e).await, "/portal/register"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn esc_neutralizes_markup() {
        assert_eq!(esc("<script>alert('x')</script>"), "&lt;script&gt;alert(&#39;x&#39;)&lt;/script&gt;");
        assert_eq!(esc("a&b\"c"), "a&amp;b&quot;c");
        assert_eq!(esc("plain-123"), "plain-123");
    }
}

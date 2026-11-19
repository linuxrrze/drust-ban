//! REST API (`/api/v1`), served over HTTPS only (see https.rs).
//!
//! Authentication, either
//! - `Authorization: Bearer df2bapi1.<secret>` (CLI, scripts). Tokens are
//!   created with `df2b-controller api-token create --name <n> --role <r>`;
//! - or a session cookie (web UI) from `POST /api/v1/session` (local users,
//!   `df2b-controller user add`) or an OpenID Connect login (oidc.rs); see
//!   session.rs for CSRF protection.
//!
//! Roles are `viewer` < `operator` (ban/unban) < `admin` (agents, enrollment
//! tokens, audit log). Every change is written to the audit log with the
//! token or user name and client address.
//!
//! TODO: OpenAPI (utoipa).

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use std::convert::Infallible;

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, Method, StatusCode, Uri};
use axum::response::sse::{Event, KeepAlive, Sse};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{async_trait, Json, Router};
use chrono::Utc;
use df2b_core::{parse_target, AgentId, DecisionKind, Origin, Scope};
use df2b_tls::ApiToken;
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{json, Value};
use tokio::sync::broadcast::error::RecvError;
use tokio_stream::wrappers::ReceiverStream;
use tracing::warn;

use crate::files::{self, Role};
use crate::session;
use crate::state::{Controller, NewDecision};

/// Longest enrollment token lifetime accepted over the API.
const MAX_ENROLL_TTL: Duration = Duration::from_secs(7 * 86400);

// ------------------------------------------------------------------- errors

#[derive(Debug)]
pub struct ApiError {
    status: StatusCode,
    message: String,
}

impl ApiError {
    fn new(status: StatusCode, message: impl Into<String>) -> Self {
        Self {
            status,
            message: message.into(),
        }
    }

    fn bad_request(m: impl Into<String>) -> Self {
        Self::new(StatusCode::BAD_REQUEST, m)
    }

    fn not_found(m: impl Into<String>) -> Self {
        Self::new(StatusCode::NOT_FOUND, m)
    }

    fn internal(e: impl std::fmt::Display) -> Self {
        tracing::error!(error = %e, "API internal error");
        Self::new(StatusCode::INTERNAL_SERVER_ERROR, "internal error")
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let mut r = (self.status, Json(json!({ "error": self.message }))).into_response();
        if self.status == StatusCode::UNAUTHORIZED {
            r.headers_mut()
                .insert(header::WWW_AUTHENTICATE, "Bearer".parse().expect("valid"));
        }
        r
    }
}

type ApiResult<T = Json<Value>> = Result<T, ApiError>;

// ----------------------------------------------------------- authentication

/// How a caller authenticated.
#[derive(Debug, Clone)]
pub enum Auth {
    Token(ApiToken),
    Session {
        secret: String,
        csrf: String,
        oidc: bool,
        /// public session id
        id: String,
    },
}

/// The authenticated caller of a request.
#[derive(Debug, Clone)]
pub struct Caller {
    /// API token name or user name (one namespace).
    pub name: String,
    pub role: Role,
    pub addr: Option<SocketAddr>,
    pub auth: Auth,
    /// Local user with a temporary password (set by an admin).
    pub must_change_password: bool,
}

/// What a session with a temporary password may still do.
fn allowed_before_password_change(method: &Method, path: &str) -> bool {
    matches!(
        (method, path),
        (&Method::GET, "/api/v1/whoami")
            | (&Method::POST, "/api/v1/session/password")
            | (&Method::DELETE, "/api/v1/session")
    )
}

fn unauthorized(m: &str) -> ApiError {
    ApiError::new(StatusCode::UNAUTHORIZED, m)
}

/// The user and role behind a session, if the session is still valid.
/// Blocking.
fn session_user(
    ctl: &Controller,
    secret: &str,
) -> anyhow::Result<Option<(String, Role, bool, session::Session)>> {
    let Some(s) = ctl.sessions.get(secret) else {
        return Ok(None);
    };
    match &s.kind {
        session::Kind::Password {
            password_changed_at,
        } => match files::load_user(&ctl.settings.state_dir, &s.user)? {
            Some(u) if u.password_changed_at == *password_changed_at => {
                Ok(Some((u.name, u.role, u.must_change_password, s)))
            }
            _ => {
                // user deleted or password changed
                ctl.sessions.remove(secret);
                Ok(None)
            }
        },
        session::Kind::Oidc { role, .. } => Ok(Some((s.user.clone(), *role, false, s))),
    }
}

impl Caller {
    fn require(&self, role: Role) -> Result<(), ApiError> {
        if self.role >= role {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::FORBIDDEN,
                format!("requires role {role:?} (you have {:?})", self.role).to_lowercase(),
            ))
        }
    }

    /// Whether the token / session is still valid (long-lived streams).
    /// Blocking.
    fn still_valid(&self, ctl: &Controller) -> bool {
        match &self.auth {
            Auth::Token(t) => files::lookup_api_token(&ctl.settings.state_dir, t).is_some(),
            Auth::Session { secret, .. } => matches!(session_user(ctl, secret), Ok(Some(_))),
        }
    }

    fn origin(&self) -> Origin {
        Origin::User(self.name.clone())
    }

    fn addr(&self) -> Option<String> {
        self.addr.map(|a| a.to_string())
    }
}

#[async_trait]
impl FromRequestParts<Arc<Controller>> for Caller {
    type Rejection = ApiError;

    async fn from_request_parts(
        parts: &mut Parts,
        ctl: &Arc<Controller>,
    ) -> Result<Self, ApiError> {
        let addr = parts
            .extensions
            .get::<ConnectInfo<SocketAddr>>()
            .map(|c| c.0);
        let bearer = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .map(|v| {
                v.strip_prefix("Bearer ")
                    .and_then(|t| t.parse::<ApiToken>().ok())
            });
        let cookie = parts
            .headers
            .get_all(header::COOKIE)
            .iter()
            .filter_map(|v| v.to_str().ok())
            .find_map(session::from_cookie_header)
            .map(str::to_owned);

        // a bearer token wins over a cookie
        if let Some(token) = bearer {
            let Some(token) = token else {
                return Err(unauthorized("malformed bearer token"));
            };
            let dir = ctl.settings.state_dir.clone();
            let t = token.clone();
            let file = tokio::task::spawn_blocking(move || files::lookup_api_token(&dir, &t))
                .await
                .map_err(ApiError::internal)?;
            return match file {
                Some(f) => {
                    ctl.token_used(&f.name);
                    Ok(Caller {
                        name: f.name,
                        role: f.role,
                        addr,
                        auth: Auth::Token(token),
                        must_change_password: false,
                    })
                }
                None => {
                    warn!(?addr, "rejected API request with unknown or expired token");
                    Err(unauthorized("invalid or expired API token"))
                }
            };
        }

        let Some(secret) = cookie else {
            return Err(unauthorized(
                "not logged in (session cookie or bearer token required)",
            ));
        };
        let c = ctl.clone();
        let sec = secret.clone();
        let found = tokio::task::spawn_blocking(move || session_user(&c, &sec))
            .await
            .map_err(ApiError::internal)?
            .map_err(ApiError::internal)?;
        let Some((name, role, must_change, sess)) = found else {
            return Err(unauthorized("session expired, please log in again"));
        };
        // cookies are sent by the browser automatically; the CSRF token
        // proves that the request comes from the UI itself
        if !matches!(parts.method, Method::GET | Method::HEAD) {
            let ok = parts
                .headers
                .get(session::CSRF_HEADER)
                .is_some_and(|v| session::constant_time_eq(v.as_bytes(), sess.csrf.as_bytes()));
            if !ok {
                return Err(ApiError::new(
                    StatusCode::FORBIDDEN,
                    "missing or invalid CSRF token",
                ));
            }
        }
        if must_change && !allowed_before_password_change(&parts.method, parts.uri.path()) {
            return Err(ApiError::new(
                StatusCode::FORBIDDEN,
                "you must change your temporary password first",
            ));
        }
        Ok(Caller {
            name,
            role,
            addr,
            must_change_password: must_change,
            auth: Auth::Session {
                secret,
                csrf: sess.csrf,
                oidc: matches!(sess.kind, session::Kind::Oidc { .. }),
                id: sess.id,
            },
        })
    }
}

/// Runs blocking controller work (fsync) off the async runtime.
async fn blocking<T: Send + 'static>(
    f: impl FnOnce() -> anyhow::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(f)
        .await
        .map_err(ApiError::internal)?
        .map_err(ApiError::internal)
}

// ------------------------------------------------------------------- routes

/// The REST API plus the web UI (everything outside `/api/`).
pub fn router(ctl: Arc<Controller>) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/session", post(login).delete(logout))
        .route("/api/v1/auth-methods", get(auth_methods))
        .route("/api/v1/sessions", get(list_sessions).delete(end_sessions))
        .route("/api/v1/session/password", post(change_own_password))
        .route("/api/v1/users", get(list_users).post(create_user))
        .route("/api/v1/api-tokens", get(list_tokens).post(create_token))
        .route("/api/v1/policies", get(policies))
        .route("/api/v1/correlation", get(list_rules))
        .route(
            "/api/v1/correlation/:name",
            axum::routing::put(set_rule).delete(delete_rule),
        )
        .route("/api/v1/redaction", get(list_redaction))
        .route("/api/v1/redaction/test", post(test_redaction))
        .route(
            "/api/v1/redaction/:name",
            axum::routing::put(set_redaction).delete(delete_redaction),
        )
        .route("/api/v1/filters", get(list_filters))
        .route("/api/v1/filters/test", post(test_filter))
        .route(
            "/api/v1/filters/:name",
            axum::routing::put(set_filter).delete(delete_filter),
        )
        .route("/api/v1/jail-definitions", get(list_jail_defs))
        .route(
            "/api/v1/jail-definitions/:name",
            axum::routing::put(set_jail_def).delete(delete_jail_def),
        )
        .route(
            "/api/v1/policies/propagate",
            axum::routing::put(set_propagate),
        )
        .route(
            "/api/v1/jails/:name/policy",
            axum::routing::put(set_jail_policy).delete(delete_jail_policy),
        )
        .route(
            "/api/v1/allowlist",
            get(list_allow).post(add_allow).delete(remove_allow),
        )
        .route(
            "/api/v1/api-tokens/:name",
            axum::routing::delete(revoke_token),
        )
        .route(
            "/api/v1/users/:name",
            axum::routing::patch(update_user).delete(delete_user),
        )
        .route("/api/v1/users/:name/password", post(reset_password))
        .route("/api/v1/sessions/:id", axum::routing::delete(end_session))
        .route("/api/v1/oidc/login", get(oidc_login))
        .route("/api/v1/oidc/callback", get(oidc_callback))
        .route(crate::oidc::BACKCHANNEL_PATH, post(oidc_backchannel_logout))
        .route(
            crate::oidc::FRONTCHANNEL_PATH,
            get(oidc_frontchannel_logout),
        )
        .route("/api/v1/whoami", get(whoami))
        .route("/api/v1/status", get(status))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/events", get(events))
        .route("/api/v1/history", get(history))
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/agents/:id", get(agent).patch(update_agent))
        .route("/api/v1/agents/:id/revoke", post(revoke_agent))
        .route("/api/v1/enroll-tokens", post(enroll_token))
        .route("/api/v1/decisions", get(decisions))
        .route("/api/v1/bans", post(ban))
        .route("/api/v1/unban", post(unban))
        .route("/api/v1/audit", get(audit))
        .fallback(|uri: Uri| async move {
            if uri.path().starts_with("/api/") {
                ApiError::not_found("no such endpoint").into_response()
            } else {
                crate::ui::serve(uri).await
            }
        })
        .layer(axum::middleware::map_response(crate::ui::security_headers))
        .with_state(ctl)
}

/// Unauthenticated: for load balancers and monitoring.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn whoami(caller: Caller) -> Json<Value> {
    let (auth, method, csrf) = match &caller.auth {
        Auth::Token(_) => ("token", "token", None),
        Auth::Session { csrf, oidc, .. } => (
            "session",
            if *oidc { "oidc" } else { "password" },
            Some(csrf),
        ),
    };
    Json(json!({
        "name": caller.name, "role": caller.role, "auth": auth,
        "method": method, "csrf_token": csrf,
        "must_change_password": caller.must_change_password,
    }))
}

/// Unauthenticated: which login methods the UI offers.
async fn auth_methods(State(ctl): State<Arc<Controller>>) -> Json<Value> {
    let oidc = ctl.settings.oidc.as_ref();
    Json(json!({
        "password": oidc.map_or(true, |o| !o.config.disable_password_login),
        "oidc": oidc.map(|o| json!({ "name": o.config.display_name })),
    }))
}

// ----------------------------------------------------------------- sessions

/// At most this many password checks (argon2: ~20 MiB, tens of ms) at once.
static LOGIN_SLOTS: tokio::sync::Semaphore = tokio::sync::Semaphore::const_new(4);

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct LoginRequest {
    username: String,
    password: String,
}

fn user_agent(h: &axum::http::HeaderMap) -> Option<&str> {
    h.get(header::USER_AGENT).and_then(|v| v.to_str().ok())
}

async fn login(
    State(ctl): State<Arc<Controller>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<LoginRequest>,
) -> Result<Response, ApiError> {
    let ip = Some(addr.ip());
    if ctl
        .settings
        .oidc
        .as_ref()
        .is_some_and(|o| o.config.disable_password_login)
    {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "password login is disabled, use single sign-on",
        ));
    }
    if req.username.len() > 64 || req.password.len() > 1024 {
        return Err(unauthorized("invalid user name or password"));
    }
    if !ctl.sessions.login_allowed(ip, &req.username) {
        warn!(%addr, user = %req.username, "login rate limit reached");
        let mut r = ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many failed logins, try again in 15 minutes",
        )
        .into_response();
        r.headers_mut().insert(
            header::RETRY_AFTER,
            axum::http::HeaderValue::from_static("900"),
        );
        return Ok(r);
    }
    let _slot = LOGIN_SLOTS.acquire().await.map_err(ApiError::internal)?;
    let c = ctl.clone();
    let name = req.username.clone();
    let user = blocking(move || {
        let user = files::load_user(&c.settings.state_dir, &name)?;
        let ok = files::verify_password(
            user.as_ref().map(|u| u.password_hash.as_str()),
            &req.password,
        );
        Ok(user.filter(|_| ok))
    })
    .await?;
    let Some(user) = user else {
        ctl.sessions.login_failed(ip, &req.username);
        warn!(%addr, user = %req.username, "failed login");
        return Err(unauthorized("invalid user name or password"));
    };
    let (secret, sess) = ctl.sessions.create(
        &user.name,
        session::Kind::Password {
            password_changed_at: user.password_changed_at,
        },
        session::MAX_AGE,
        session::Client::new(addr, user_agent(&headers)),
    );
    let c = ctl.clone();
    let name = user.name.clone();
    blocking(move || {
        c.audit(
            &name,
            Some(addr.to_string()),
            "session.login",
            json!({ "method": "password" }),
        )
    })
    .await?;
    Ok((
        [(header::SET_COOKIE, session::set_cookie(&secret))],
        Json(json!({
            "name": user.name, "role": user.role, "auth": "session",
            "method": "password", "csrf_token": sess.csrf,
            "must_change_password": user.must_change_password,
        })),
    )
        .into_response())
}

/// Ends the session. For OIDC sessions the response names the provider's
/// logout page (if it has one), otherwise "Sign in" would log straight in.
async fn logout(caller: Caller, State(ctl): State<Arc<Controller>>) -> Response {
    let mut logout_url = None;
    if let Auth::Session { secret, oidc, .. } = &caller.auth {
        ctl.sessions.remove(secret);
        if let (true, Some(o)) = (*oidc, &ctl.settings.oidc) {
            logout_url = o.logout_url().await;
        }
    }
    (
        [(header::SET_COOKIE, session::clear_cookie())],
        Json(json!({ "logged_out": true, "logout_url": logout_url })),
    )
        .into_response()
}

// ---------------------------------------------------------- users (local)

fn conflict(m: impl Into<String>) -> ApiError {
    ApiError::new(StatusCode::CONFLICT, m)
}

/// Rules that do not need the file system.
fn check_new_password(name: &str, pw: &str) -> Result<(), ApiError> {
    files::check_password(name, pw).map_err(|e| ApiError::bad_request(e.to_string()))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct OwnPasswordChange {
    current_password: String,
    new_password: String,
}

/// Any local user: change the own password (current one required). The
/// session is replaced (new cookie and CSRF token); other sessions end.
async fn change_own_password(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Json(req): Json<OwnPasswordChange>,
) -> Result<Response, ApiError> {
    let Auth::Session { oidc: false, .. } = &caller.auth else {
        return Err(ApiError::bad_request(
            "only local users signed in with a password can change it here",
        ));
    };
    let name = caller.name.clone();
    check_new_password(&name, &req.new_password)?;
    if req.new_password == req.current_password {
        return Err(ApiError::bad_request(
            "the new password must differ from the current one",
        ));
    }
    if req.current_password.len() > files::MAX_PASSWORD_LEN {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "the current password is wrong",
        ));
    }
    let ip = Some(addr.ip());
    if !ctl.sessions.login_allowed(ip, &name) {
        return Err(ApiError::new(
            StatusCode::TOO_MANY_REQUESTS,
            "too many wrong passwords, try again in 15 minutes",
        ));
    }
    let _slot = LOGIN_SLOTS.acquire().await.map_err(ApiError::internal)?;
    let c = ctl.clone();
    let n = name.clone();
    let changed = blocking(move || {
        let dir = &c.settings.state_dir;
        let user = files::load_user(dir, &n)?;
        let ok = files::verify_password(
            user.as_ref().map(|u| u.password_hash.as_str()),
            &req.current_password,
        );
        if !ok {
            return Ok(None);
        }
        let at = files::set_password(dir, &n, &req.new_password, false)?;
        Ok(Some((at, user.map(|u| u.role))))
    })
    .await?;
    let Some((changed_at, role)) = changed else {
        // 403, not 401: the session itself is fine
        ctl.sessions.login_failed(ip, &name);
        warn!(%addr, user = %name, "wrong current password");
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "the current password is wrong",
        ));
    };
    ctl.sessions.end_user(Some(&name));
    let (secret, sess) = ctl.sessions.create(
        &name,
        session::Kind::Password {
            password_changed_at: changed_at,
        },
        session::MAX_AGE,
        session::Client::new(addr, user_agent(&headers)),
    );
    let c = ctl.clone();
    let n = name.clone();
    blocking(move || {
        c.audit(
            &n,
            Some(addr.to_string()),
            "user.password_change",
            json!({}),
        )
    })
    .await?;
    Ok((
        [(header::SET_COOKIE, session::set_cookie(&secret))],
        Json(json!({
            "name": name, "role": role, "auth": "session", "method": "password",
            "csrf_token": sess.csrf, "must_change_password": false,
        })),
    )
        .into_response())
}

/// Admin: local users with their number of live sessions.
async fn list_users(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Admin)?;
    let c = ctl.clone();
    let users = blocking(move || files::list_users(&c.settings.state_dir)).await?;
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for s in ctl.sessions.list() {
        if s.method == "password" {
            *counts.entry(s.user).or_default() += 1;
        }
    }
    let list: Vec<Value> = users
        .iter()
        .map(|u| {
            json!({
                "name": u.name, "role": u.role, "created_at": u.created_at,
                "password_changed_at": u.password_changed_at,
                "must_change_password": u.must_change_password,
                "sessions": counts.get(&u.name).copied().unwrap_or(0),
            })
        })
        .collect();
    Ok(Json(json!({
        "users": list,
        "password_login": ctl.settings.oidc.as_ref().map_or(true, |o| !o.config.disable_password_login),
    })))
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewUser {
    name: String,
    role: Role,
    password: String,
    /// must be changed at the first login (default)
    #[serde(default = "default_true")]
    temporary: bool,
}

/// Admin: creates a local user.
async fn create_user(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<NewUser>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    caller.require(Role::Admin)?;
    if !files::valid_name(&req.name) {
        return Err(ApiError::bad_request(
            "invalid user name (letters, digits, - _ . @; at most 64)",
        ));
    }
    check_new_password(&req.name, &req.password)?;
    let c = ctl.clone();
    let n = req.name.clone();
    let taken = blocking(move || {
        let dir = &c.settings.state_dir;
        Ok(files::load_user(dir, &n)?.is_some()
            || files::list_api_tokens(dir)?.iter().any(|t| t.name == n))
    })
    .await?;
    if taken {
        return Err(conflict(format!(
            "{:?} is already a user or API token name",
            req.name
        )));
    }
    let _slot = LOGIN_SLOTS.acquire().await.map_err(ApiError::internal)?;
    let c = ctl.clone();
    let (name, role, temporary) = (req.name.clone(), req.role, req.temporary);
    blocking(move || {
        files::create_user_with(&c.settings.state_dir, &name, role, &req.password, temporary)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "user.create",
            json!({ "user": name, "role": role, "temporary_password": temporary }),
        )
    })
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "created": req.name, "role": req.role })),
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserUpdate {
    role: Role,
}

async fn load_existing(ctl: &Arc<Controller>, name: &str) -> Result<files::UserFile, ApiError> {
    let c = ctl.clone();
    let n = name.to_owned();
    blocking(move || files::load_user(&c.settings.state_dir, &n))
        .await?
        .ok_or_else(|| ApiError::not_found(format!("no user {name:?}")))
}

/// Admin: changes a user's role (effective on their next request).
async fn update_user(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Json(req): Json<UserUpdate>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let old = load_existing(&ctl, &name).await?;
    if name == caller.name && req.role < Role::Admin {
        return Err(conflict(
            "you cannot lower your own role (ask another admin, or use df2b-controller on the host)",
        ));
    }
    let c = ctl.clone();
    let n = name.clone();
    blocking(move || {
        files::update_user(&c.settings.state_dir, &n, Some(req.role), None)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "user.update",
            json!({ "user": n, "role": req.role, "previous_role": old.role }),
        )
    })
    .await?;
    Ok(Json(json!({ "user": name, "role": req.role })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordReset {
    password: String,
    #[serde(default = "default_true")]
    temporary: bool,
}

/// Admin: sets a new (by default temporary) password; the user's sessions
/// end.
async fn reset_password(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Json(req): Json<PasswordReset>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    load_existing(&ctl, &name).await?;
    if name == caller.name {
        return Err(conflict(
            "change your own password with your current one (account menu)",
        ));
    }
    check_new_password(&name, &req.password)?;
    let _slot = LOGIN_SLOTS.acquire().await.map_err(ApiError::internal)?;
    let c = ctl.clone();
    let n = name.clone();
    let temporary = req.temporary;
    blocking(move || {
        files::set_password(&c.settings.state_dir, &n, &req.password, temporary)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "user.password_reset",
            json!({ "user": n, "temporary_password": temporary }),
        )
    })
    .await?;
    let ended = ctl.sessions.end_user(Some(&name));
    Ok(Json(json!({ "user": name, "sessions_ended": ended })))
}

/// Admin: deletes a local user; their sessions end.
async fn delete_user(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let old = load_existing(&ctl, &name).await?;
    if name == caller.name {
        return Err(conflict(
            "you cannot delete yourself (ask another admin, or use df2b-controller on the host)",
        ));
    }
    let c = ctl.clone();
    let n = name.clone();
    blocking(move || {
        files::delete_user(&c.settings.state_dir, &n)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "user.delete",
            json!({ "user": n, "role": old.role }),
        )
    })
    .await?;
    let ended = ctl.sessions.end_user(Some(&name));
    Ok(Json(json!({ "deleted": name, "sessions_ended": ended })))
}

// -------------------------------------------------------------- allowlist

/// Everybody may read the allowlist (with the number of active bans each
/// entry would lift); only admins change it.
async fn list_allow(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    let active = ctl.active_decisions();
    let entries: Vec<Value> = ctl
        .allowlist()
        .into_iter()
        .map(|e| {
            let overlapping = active
                .iter()
                .filter(|d| d.target.contains(&e.net) || e.net.contains(&d.target))
                .count();
            let mut v = serde_json::to_value(&e).unwrap_or(Value::Null);
            v["active_bans"] = json!(overlapping);
            v
        })
        .collect();
    let current = ctl.allowlist_version();
    let live: Vec<_> = ctl
        .agents()
        .into_iter()
        .filter(|a| a.connected && !a.revoked)
        .collect();
    Ok(Json(json!({
        "entries": entries,
        "version": current,
        "agents": {
            "connected": live.len(),
            "current": live.iter().filter(|a| a.status.allowlist_version == current).count(),
        },
    })))
}

fn default_unban() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewAllow {
    /// address or prefix
    net: String,
    #[serde(default)]
    comment: String,
    /// also lift active bans overlapping the network (default)
    #[serde(default = "default_unban")]
    unban: bool,
    /// temporary entry, e.g. "24h" (at most 30 days); default: permanent
    ttl: Option<String>,
}

/// Longest temporary allowlist entry (admins; operators: `OPERATOR_ALLOW`).
const MAX_ALLOW: Duration = Duration::from_secs(30 * 86400);
/// Longest "allow for" an operator may set with an unban.
const OPERATOR_ALLOW: Duration = Duration::from_secs(7 * 86400);

/// "allow for" targets are single hosts or small networks (like agent
/// reports); broader exemptions belong on the allowlist proper.
fn too_broad_for_temporary(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => n.prefix_len() < 24,
        IpNet::V6(n) => n.prefix_len() < 48,
    }
}

fn expiry(ttl: &str, max: Duration) -> Result<chrono::DateTime<Utc>, ApiError> {
    let d = parse_duration(ttl, "duration")?;
    if d < Duration::from_secs(60) || d > max {
        return Err(ApiError::bad_request(format!(
            "duration must be between 1 minute and {}",
            humantime::format_duration(max)
        )));
    }
    Ok(Utc::now() + chrono::Duration::from_std(d).map_err(ApiError::internal)?)
}

fn allow_error(e: crate::state::AllowError) -> ApiError {
    use crate::state::AllowError as E;
    match e {
        E::Exists(_) | E::Covered(..) | E::Fixed(_) => conflict(e.to_string()),
        E::Missing(_) => ApiError::not_found(e.to_string()),
        E::Store(e) => ApiError::internal(e),
    }
}

/// Admin: adds a network; by default also unbans what it overlaps.
async fn add_allow(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<NewAllow>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    caller.require(Role::Admin)?;
    let net = target(&req.net)?.trunc();
    // a /0 would silently switch banning off
    if too_broad(&net) {
        return Err(ApiError::bad_request(format!(
            "{net} is too broad for the allowlist (at most /8 for IPv4, /16 for IPv6)"
        )));
    }
    let comment: String = req
        .comment
        .chars()
        .filter(|c| !c.is_control())
        .take(200)
        .collect();
    let expires_at = match req.ttl.as_deref() {
        None | Some("never") => None,
        Some(t) => Some(expiry(t, MAX_ALLOW)?),
    };
    let entry = crate::store::AllowEntry {
        net,
        comment: comment.trim().to_owned(),
        created_by: caller.name.clone(),
        created_at: Utc::now(),
        expires_at,
    };
    let c = ctl.clone();
    let unban = req.unban;
    let unbanned = tokio::task::spawn_blocking(move || {
        c.add_allow(entry).map_err(allow_error)?;
        let lifted = if unban {
            c.unban(net, caller.origin(), "allowlisted")
                .map_err(ApiError::internal)?
                .len()
        } else {
            0
        };
        c.audit(
            &caller.name,
            caller.addr(),
            "allowlist.add",
            json!({ "net": net, "comment": comment.trim(), "unbanned": lifted, "expires_at": expires_at }),
        )
        .map_err(ApiError::internal)?;
        Ok::<_, ApiError>(lifted)
    })
    .await
    .map_err(ApiError::internal)??;
    Ok((
        StatusCode::CREATED,
        Json(json!({ "net": net, "unbanned": unbanned, "expires_at": expires_at })),
    ))
}

#[derive(Deserialize)]
struct AllowQuery {
    net: String,
}

/// Admin: removes an entry added through the API (`?net=<prefix>`).
async fn remove_allow(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Query(q): Query<AllowQuery>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let net = target(&q.net)?.trunc();
    let c = ctl.clone();
    tokio::task::spawn_blocking(move || {
        c.remove_allow(&net).map_err(allow_error)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "allowlist.remove",
            json!({ "net": net }),
        )
        .map_err(ApiError::internal)
    })
    .await
    .map_err(ApiError::internal)??;
    Ok(Json(json!({ "removed": net })))
}

// --------------------------------------------------------------- policies

/// Ban propagation and the jail inventory: every jail an agent reports
/// (with its effective settings there) or a policy mentions.
async fn policies(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    let overrides = ctl.jail_overrides();
    let agents: Vec<_> = ctl.agents().into_iter().filter(|a| !a.revoked).collect();
    let mut names: std::collections::BTreeSet<String> =
        overrides.iter().map(|o| o.jail.clone()).collect();
    names.extend(ctl.central().defs.iter().map(|d| d.name.clone()));
    for a in &agents {
        names.extend(a.status.jails.iter().map(|j| j.name.clone()));
    }
    let jails: Vec<Value> = names
        .into_iter()
        .map(|name| {
            // every entry: an agent can run a local jail and report a
            // refused central one of the same name
            let on: Vec<Value> = agents
                .iter()
                .flat_map(|a| {
                    a.status.jails.iter().filter(|j| j.name == name).map(|j| {
                        json!({ "agent": a.record.id, "group": a.record.group, "connected": a.connected, "jail": j })
                    })
                })
                .collect();
            let mut filters: Vec<String> = agents
                .iter()
                .flat_map(|a| a.status.jails.iter().filter(|j| j.name == name && j.error.is_empty()))
                .map(|j| j.filter.clone())
                .collect();
            filters.sort();
            filters.dedup();
            let mut ov: Vec<_> = overrides.iter().filter(|o| o.jail == name).cloned().collect();
            ov.sort_by(|a, b| a.group.cmp(&b.group));
            json!({ "name": name, "filters": filters, "agents": on, "overrides": ov })
        })
        .collect();
    let mut groups: Vec<String> = agents.iter().map(|a| a.record.group.clone()).collect();
    groups.sort();
    groups.dedup();
    Ok(Json(json!({
        "propagate": ctl.propagate(),
        "jails": jails,
        "groups": groups,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PropagateRequest {
    propagate: crate::state::Propagate,
}

/// Admin: what an agent's local ban turns into (global, group, off).
async fn set_propagate(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<PropagateRequest>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let c = ctl.clone();
    let old = blocking(move || {
        let old = c.set_propagate(req.propagate)?;
        if old != req.propagate {
            c.audit(
                &caller.name,
                caller.addr(),
                "policy.propagate",
                json!({ "from": old, "to": req.propagate }),
            )?;
        }
        Ok(old)
    })
    .await?;
    Ok(Json(json!({ "propagate": req.propagate, "previous": old })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JailPolicyRequest {
    /// none: all agents
    group: Option<String>,
    enabled: Option<bool>,
    maxretry: Option<u32>,
    /// durations as text, e.g. "10m"
    findtime: Option<String>,
    bantime: Option<String>,
    bantime_factor: Option<f64>,
    max_bantime: Option<String>,
}

fn jail_scope(name: &str, group: Option<&str>) -> Result<(), ApiError> {
    if !crate::policy::valid_jail(name) {
        return Err(ApiError::bad_request(
            "invalid jail name (letters, digits, - _ .)",
        ));
    }
    if group.is_some_and(|g| !files::valid_group(g)) {
        return Err(ApiError::bad_request("invalid group name"));
    }
    Ok(())
}

/// Admin: replaces the settings for a jail, for all agents or one group.
/// Unset fields keep what is below (the agents' configuration, or the
/// settings for all agents); all fields unset removes the policy.
async fn set_jail_policy(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Json(req): Json<JailPolicyRequest>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let group = req
        .group
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .map(str::to_owned);
    jail_scope(&name, group.as_deref())?;
    let dur =
        |v: &Option<String>, what: &str| v.as_deref().map(|t| parse_duration(t, what)).transpose();
    let settings = crate::policy::JailSettings {
        enabled: req.enabled,
        maxretry: req.maxretry,
        findtime: dur(&req.findtime, "findtime")?,
        bantime: dur(&req.bantime, "bantime")?,
        bantime_factor: req.bantime_factor,
        max_bantime: dur(&req.max_bantime, "max_bantime")?,
    };
    settings.validate().map_err(ApiError::bad_request)?;
    let o = crate::policy::JailOverride {
        jail: name.clone(),
        group: group.clone(),
        settings: settings.clone(),
        updated_by: caller.name.clone(),
        updated_at: Utc::now(),
    };
    let c = ctl.clone();
    let prev = blocking(move || {
        let prev = c.set_jail_override(o)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "jail.policy",
            json!({
                "jail": name, "group": group, "settings": settings,
                "previous": prev.as_ref().map(|p| &p.settings),
            }),
        )?;
        Ok(prev)
    })
    .await?;
    Ok(Json(json!({ "previous": prev.map(|p| p.settings) })))
}

#[derive(Deserialize)]
struct JailPolicyQuery {
    group: Option<String>,
}

/// Admin: removes the settings for a jail (all agents, or `?group=`).
async fn delete_jail_policy(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Query(q): Query<JailPolicyQuery>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    jail_scope(&name, q.group.as_deref())?;
    let exists = ctl
        .jail_overrides()
        .iter()
        .any(|o| o.jail == name && o.group == q.group);
    if !exists {
        return Err(ApiError::not_found("no such jail policy"));
    }
    let c = ctl.clone();
    let group = q.group.clone();
    blocking(move || {
        c.set_jail_override(crate::policy::JailOverride {
            jail: name.clone(),
            group: group.clone(),
            settings: Default::default(),
            updated_by: caller.name.clone(),
            updated_at: Utc::now(),
        })?;
        c.audit(
            &caller.name,
            caller.addr(),
            "jail.policy_remove",
            json!({ "jail": name, "group": group }),
        )
    })
    .await?;
    Ok(Json(json!({ "removed": true })))
}

// ------------------------------------------------------------ correlation

async fn list_rules(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    let c = ctl.correlator.lock().unwrap_or_else(|e| e.into_inner());
    Ok(Json(json!({
        "rules": *ctl.rules(),
        "monitor_hits": c.hits(),
        "tracked_addresses": c.tracked(),
        "propagate": ctl.propagate(),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleBody {
    kind: crate::correlation::RuleKind,
    jail: Option<String>,
    group: Option<String>,
    min_agents: u32,
    #[serde(default)]
    min_failures: u32,
    window: String,
    bantime: String,
    /// repeat offenders: bantime × factor^(offense-1) (default 1: none)
    bantime_factor: Option<f64>,
    max_bantime: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
    #[serde(default)]
    monitor: bool,
}

/// Admin: creates or replaces a correlation rule.
async fn set_rule(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Json(req): Json<RuleBody>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let trim = |v: Option<String>| v.map(|s| s.trim().to_owned()).filter(|s| !s.is_empty());
    let group = trim(req.group);
    if group.as_deref().is_some_and(|g| !files::valid_group(g)) {
        return Err(ApiError::bad_request("invalid group name"));
    }
    let rule = crate::correlation::Rule {
        name: name.clone(),
        kind: req.kind,
        jail: trim(req.jail),
        group,
        min_agents: req.min_agents,
        min_failures: req.min_failures,
        window: parse_duration(&req.window, "window")?,
        bantime: parse_duration(&req.bantime, "bantime")?,
        bantime_factor: req.bantime_factor.unwrap_or(1.0),
        max_bantime: req
            .max_bantime
            .as_deref()
            .filter(|t| !t.trim().is_empty())
            .map(|t| parse_duration(t, "max_bantime"))
            .transpose()?,
        enabled: req.enabled,
        monitor: req.monitor,
        updated_by: caller.name.clone(),
        updated_at: Utc::now(),
    };
    rule.validate().map_err(ApiError::bad_request)?;
    let c = ctl.clone();
    let audit_rule = serde_json::to_value(&rule).map_err(ApiError::internal)?;
    let replaced = blocking(move || {
        let prev = c.set_rule(rule)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "correlation.set",
            json!({ "rule": name, "definition": audit_rule, "replaced": prev.is_some() }),
        )?;
        Ok(prev.is_some())
    })
    .await?;
    Ok(Json(json!({ "replaced": replaced })))
}

async fn delete_rule(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let c = ctl.clone();
    let n = name.clone();
    let found = blocking(move || {
        let found = c.remove_rule(&n)?;
        if found {
            c.audit(
                &caller.name,
                caller.addr(),
                "correlation.remove",
                json!({ "rule": n }),
            )?;
        }
        Ok(found)
    })
    .await?;
    if !found {
        return Err(ApiError::not_found(format!("no rule {name:?}")));
    }
    Ok(Json(json!({ "removed": name })))
}

// ------------------------------------------------- sample line redaction

async fn list_redaction(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    let presets: Vec<Value> = df2b_core::redact::PRESETS
        .iter()
        .map(|(name, description, pattern, replace)| {
            json!({ "name": name, "description": description, "pattern": pattern, "replace": replace })
        })
        .collect();
    // connected agents: applying the current rules, or not accepting them
    let current = ctl.redaction_version();
    let live: Vec<_> = ctl
        .agents()
        .into_iter()
        .filter(|a| a.connected && !a.revoked)
        .collect();
    let count = |f: &dyn Fn(&str) -> bool| {
        live.iter()
            .filter(|a| f(&a.status.redaction_version))
            .count()
    };
    Ok(Json(json!({
        "rules": *ctl.redaction_rules(),
        "version": current,
        "agents": {
            "connected": live.len(),
            "current": count(&|v| v == current),
            "off": count(&|v| v == "off"),
        },
        "presets": presets,
        "default_replace": df2b_core::redact::DEFAULT_REPLACE,
        "max_rules": df2b_core::redact::MAX_RULES,
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedactBody {
    pattern: String,
    replace: Option<String>,
    #[serde(default = "default_true")]
    enabled: bool,
}

/// Admin: creates or replaces a redaction rule. Lines kept so far are
/// redacted at once (memory and database).
async fn set_redaction(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Json(req): Json<RedactBody>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    if !crate::policy::valid_jail(&name) {
        return Err(ApiError::bad_request(
            "invalid rule name (letters, digits, - _ .; at most 64)",
        ));
    }
    let rule = df2b_core::RedactRule {
        name: name.clone(),
        pattern: req.pattern,
        replace: req
            .replace
            .unwrap_or_else(|| df2b_core::redact::DEFAULT_REPLACE.to_owned()),
        enabled: req.enabled,
    };
    df2b_core::redact::compile(&rule.pattern).map_err(ApiError::bad_request)?;
    let rules = ctl.redaction_rules();
    if !rules.iter().any(|r| r.name == name) && rules.len() >= df2b_core::redact::MAX_RULES {
        return Err(ApiError::bad_request(format!(
            "at most {} redaction rules",
            df2b_core::redact::MAX_RULES
        )));
    }
    let c = ctl.clone();
    let audit_rule = serde_json::to_value(&rule).map_err(ApiError::internal)?;
    let (replaced, redacted) = blocking(move || {
        let (prev, changed) = c.set_redaction_rule(rule)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "redaction.set",
            json!({ "rule": name, "definition": audit_rule, "replaced": prev.is_some(), "lines_redacted": changed }),
        )?;
        Ok((prev.is_some(), changed))
    })
    .await?;
    Ok(Json(
        json!({ "replaced": replaced, "lines_redacted": redacted }),
    ))
}

async fn delete_redaction(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let c = ctl.clone();
    let n = name.clone();
    let found = blocking(move || {
        let found = c.remove_redaction_rule(&n)?;
        if found {
            c.audit(
                &caller.name,
                caller.addr(),
                "redaction.remove",
                json!({ "rule": n }),
            )?;
        }
        Ok(found)
    })
    .await?;
    if !found {
        return Err(ApiError::not_found(format!("no redaction rule {name:?}")));
    }
    Ok(Json(json!({ "removed": name })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedactTest {
    /// a rule to try; without one, only the current rules apply
    pattern: Option<String>,
    replace: Option<String>,
    /// the rule being edited (left out of the current rules)
    name: Option<String>,
    lines: Vec<String>,
}

/// Shows what lines look like after the current rules plus (optionally)
/// a rule being edited, without storing anything. `stable`: applying the
/// rules again changes nothing (needed because kept lines are redacted
/// again whenever the rules change).
async fn test_redaction(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<RedactTest>,
) -> ApiResult {
    caller.require(Role::Viewer)?;
    if req.lines.len() > 100 || req.lines.iter().any(|l| l.len() > 4096) {
        return Err(ApiError::bad_request("at most 100 lines of 4 KiB"));
    }
    let mut rules: Vec<df2b_core::RedactRule> = ctl
        .redaction_rules()
        .iter()
        .filter(|r| req.name.as_deref() != Some(r.name.as_str()))
        .cloned()
        .collect();
    if let Some(p) = req.pattern {
        df2b_core::redact::compile(&p).map_err(ApiError::bad_request)?;
        let rule = df2b_core::RedactRule {
            name: req.name.clone().unwrap_or_else(|| "test".into()),
            pattern: p,
            replace: req
                .replace
                .unwrap_or_else(|| df2b_core::redact::DEFAULT_REPLACE.to_owned()),
            enabled: true,
        };
        // an edited rule keeps its place
        match req
            .name
            .as_deref()
            .and_then(|n| ctl.redaction_rules().iter().position(|r| r.name == n))
        {
            Some(i) => rules.insert(i.min(rules.len()), rule),
            None => rules.push(rule),
        }
    }
    let r = df2b_core::Redactor::new(&rules).map_err(ApiError::bad_request)?;
    let results: Vec<Value> = req
        .lines
        .iter()
        .map(|l| {
            let once = df2b_core::sample_line(&r.apply(&df2b_core::sample_line(l)));
            let twice = df2b_core::sample_line(&r.apply(&once));
            json!({ "line": once, "stable": once == twice })
        })
        .collect();
    Ok(Json(json!({ "results": results })))
}

// ----------------------------------------------------------- central jails

async fn list_filters(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    let c = ctl.central();
    let mut list: Vec<Value> = c
        .filters
        .iter()
        .map(|f| {
            let mut v = serde_json::to_value(f).unwrap_or(Value::Null);
            v["used_by"] = json!(c.users_of(&f.name));
            v
        })
        .collect();
    list.sort_by(|a, b| a["name"].as_str().cmp(&b["name"].as_str()));
    Ok(Json(json!({ "filters": list })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilterBody {
    toml: String,
}

/// Admin: creates or replaces a filter (compiled first).
async fn set_filter(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Json(req): Json<FilterBody>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    crate::central::validate_filter(&name, &req.toml).map_err(ApiError::bad_request)?;
    let f = crate::central::CentralFilter {
        name: name.clone(),
        toml: req.toml,
        updated_by: caller.name.clone(),
        updated_at: Utc::now(),
    };
    let c = ctl.clone();
    let replaced = blocking(move || {
        let replaced = c.set_filter(f)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "filter.set",
            json!({ "filter": name, "replaced": replaced }),
        )?;
        Ok(replaced)
    })
    .await?;
    Ok(Json(json!({ "replaced": replaced })))
}

fn central_error(e: crate::state::CentralError) -> ApiError {
    use crate::state::CentralError as E;
    match e {
        E::FilterInUse(..) => conflict(e.to_string()),
        E::Missing(_) => ApiError::not_found(e.to_string()),
        E::Store(e) => ApiError::internal(e),
    }
}

async fn delete_filter(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let c = ctl.clone();
    tokio::task::spawn_blocking(move || {
        c.remove_filter(&name).map_err(central_error)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "filter.remove",
            json!({ "filter": name }),
        )
        .map_err(ApiError::internal)
    })
    .await
    .map_err(ApiError::internal)??;
    Ok(Json(json!({ "removed": true })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FilterTest {
    toml: String,
    lines: Vec<String>,
}

/// Runs a filter (not stored) against sample log lines.
async fn test_filter(caller: Caller, Json(req): Json<FilterTest>) -> ApiResult {
    caller.require(Role::Viewer)?;
    if req.lines.len() > 5000 || req.lines.iter().map(String::len).sum::<usize>() > 2 << 20 {
        return Err(ApiError::bad_request("at most 5000 lines / 2 MiB"));
    }
    crate::central::validate_filter("test", &req.toml).map_err(ApiError::bad_request)?;
    let def = df2b_matcher::FilterDef::from_toml(&req.toml).map_err(ApiError::bad_request_from)?;
    let filter = df2b_matcher::Filter::compile("test", &def).map_err(ApiError::bad_request_from)?;
    let mut matches = Vec::new();
    for (i, line) in req.lines.iter().enumerate() {
        if let Some(m) = filter.match_line(line) {
            matches.push(json!({ "line": i + 1, "ip": m.ip, "pattern": m.pattern }));
        }
    }
    Ok(Json(
        json!({ "lines": req.lines.len(), "matched": matches.len(), "matches": matches }),
    ))
}

async fn list_jail_defs(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    let c = ctl.central();
    let mut defs: Vec<&crate::central::JailDef> = c.defs.iter().collect();
    defs.sort_by(|a, b| (&a.name, &a.group).cmp(&(&b.name, &b.group)));
    let list: Vec<Value> = defs
        .iter()
        .map(|d| {
            let mut v = serde_json::to_value(d).unwrap_or(Value::Null);
            v["filter_is_central"] = json!(c.filters.iter().any(|f| f.name == d.filter));
            v
        })
        .collect();
    Ok(Json(json!({ "definitions": list })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct JailDefBody {
    group: Option<String>,
    filter: String,
    sources: Vec<crate::central::SourceDef>,
    #[serde(default = "default_true")]
    enabled: bool,
    maxretry: u32,
    findtime: String,
    bantime: String,
    bantime_factor: Option<f64>,
    max_bantime: Option<String>,
}

/// Admin: defines a jail for all agents or a group (replacing the same
/// name and scope). The filter may be central or an agent-local one.
async fn set_jail_def(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Json(req): Json<JailDefBody>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let group = req
        .group
        .as_deref()
        .map(str::trim)
        .filter(|g| !g.is_empty())
        .map(str::to_owned);
    if group.as_deref().is_some_and(|g| !files::valid_group(g)) {
        return Err(ApiError::bad_request("invalid group name"));
    }
    let d = crate::central::JailDef {
        name: name.clone(),
        group: group.clone(),
        filter: req.filter.trim().to_owned(),
        sources: req.sources,
        enabled: req.enabled,
        maxretry: req.maxretry,
        findtime: parse_duration(&req.findtime, "findtime")?,
        bantime: parse_duration(&req.bantime, "bantime")?,
        bantime_factor: req.bantime_factor.unwrap_or(1.0),
        max_bantime: req
            .max_bantime
            .as_deref()
            .map(|t| parse_duration(t, "max_bantime"))
            .transpose()?,
        updated_by: caller.name.clone(),
        updated_at: Utc::now(),
    };
    crate::central::validate_def(&d).map_err(ApiError::bad_request)?;
    let filter_is_central = ctl.central().filters.iter().any(|f| f.name == d.filter);
    let c = ctl.clone();
    let audit_def = serde_json::to_value(&d).map_err(ApiError::internal)?;
    let prev = blocking(move || {
        let prev = c.set_jail_def(d)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "jail.define",
            json!({ "jail": name, "group": group, "definition": audit_def, "replaced": prev.is_some() }),
        )?;
        Ok(prev)
    })
    .await?;
    Ok(Json(
        json!({ "replaced": prev.is_some(), "filter_is_central": filter_is_central }),
    ))
}

#[derive(Deserialize)]
struct GroupQuery {
    group: Option<String>,
}

async fn delete_jail_def(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
    Query(q): Query<GroupQuery>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let c = ctl.clone();
    tokio::task::spawn_blocking(move || {
        c.remove_jail_def(&name, q.group.as_deref())
            .map_err(central_error)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "jail.undefine",
            json!({ "jail": name, "group": q.group }),
        )
        .map_err(ApiError::internal)
    })
    .await
    .map_err(ApiError::internal)??;
    Ok(Json(json!({ "removed": true })))
}

// ------------------------------------------------------------- API tokens

/// Longest API token lifetime that can be chosen in the UI/API ("never"
/// is allowed too, but has to be asked for explicitly).
const MAX_TOKEN_TTL: Duration = Duration::from_secs(5 * 365 * 86400);

/// Admin: API tokens (never the secrets: only hashes are stored).
async fn list_tokens(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Admin)?;
    let c = ctl.clone();
    let tokens = blocking(move || files::list_api_tokens(&c.settings.state_dir)).await?;
    let now = Utc::now();
    let own = match &caller.auth {
        Auth::Token(_) => Some(caller.name.as_str()),
        Auth::Session { .. } => None,
    };
    let list: Vec<Value> = tokens
        .iter()
        .map(|t| {
            json!({
                "name": t.name, "role": t.role, "created_at": t.created_at,
                "created_by": t.created_by, "expires_at": t.expires_at,
                "expired": t.expires_at.is_some_and(|e| e <= now),
                "last_used_at": ctl.token_last_used(&t.name),
                "current": own == Some(t.name.as_str()),
            })
        })
        .collect();
    Ok(Json(json!({
        "tokens": list,
        // for the df2bctl configuration shown after creating a token
        "ca_fingerprint": ctl.settings.https_internal_ca.then(|| df2b_tls::hex(&ctl.ca.fingerprint())),
    })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewToken {
    name: String,
    role: Role,
    /// e.g. "90d"; "never" for no expiry
    ttl: String,
}

/// Admin, browser session only: creates a token and returns it once.
/// Tokens cannot create tokens, so a leaked token cannot be used to plant
/// new ones that survive its revocation.
async fn create_token(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<NewToken>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    caller.require(Role::Admin)?;
    if matches!(caller.auth, Auth::Token(_)) {
        return Err(ApiError::new(
            StatusCode::FORBIDDEN,
            "API tokens cannot create API tokens; use the web UI or df2b-controller api-token create",
        ));
    }
    if !files::valid_name(&req.name) {
        return Err(ApiError::bad_request(
            "invalid token name (letters, digits, - _ . @; at most 64)",
        ));
    }
    let ttl = match req.ttl.as_str() {
        "never" => None,
        t => {
            let d = parse_duration(t, "ttl")?;
            if d.is_zero() || d > MAX_TOKEN_TTL {
                return Err(ApiError::bad_request(
                    "ttl must be between 1s and 5 years, or \"never\"",
                ));
            }
            Some(d)
        }
    };
    let c = ctl.clone();
    let n = req.name.clone();
    let taken = blocking(move || {
        let dir = &c.settings.state_dir;
        Ok(files::load_user(dir, &n)?.is_some()
            || files::list_api_tokens(dir)?.iter().any(|t| t.name == n))
    })
    .await?;
    if taken {
        return Err(conflict(format!(
            "{:?} is already a user or API token name",
            req.name
        )));
    }
    let c = ctl.clone();
    let (name, role) = (req.name.clone(), req.role);
    let token = blocking(move || {
        let t = files::create_api_token_by(
            &c.settings.state_dir,
            &name,
            role,
            ttl,
            Some(&caller.name),
        )?;
        let expires_at = ttl
            .and_then(|d| chrono::Duration::from_std(d).ok())
            .map(|d| Utc::now() + d);
        c.audit(
            &caller.name,
            caller.addr(),
            "token.create",
            json!({ "token": name, "role": role, "expires_at": expires_at }),
        )?;
        Ok((t, expires_at))
    })
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "token": token.0.to_string(),
            "name": req.name,
            "role": req.role,
            "expires_at": token.1,
        })),
    ))
}

/// Admin: revokes a token at once (also with a token, e.g. its own).
async fn revoke_token(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(name): Path<String>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let c = ctl.clone();
    let n = name.clone();
    let found = blocking(move || {
        let found = files::revoke_api_token(&c.settings.state_dir, &n)?;
        if found {
            c.audit(
                &caller.name,
                caller.addr(),
                "token.revoke",
                json!({ "token": n }),
            )?;
        }
        Ok(found)
    })
    .await?;
    if !found {
        return Err(ApiError::not_found(format!("no API token {name:?}")));
    }
    Ok(Json(json!({ "revoked": name })))
}

// ------------------------------------------------------ session management

/// Admin: all live browser sessions (API tokens are not sessions).
async fn list_sessions(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Admin)?;
    let own = match &caller.auth {
        Auth::Session { id, .. } => Some(id.clone()),
        Auth::Token(_) => None,
    };
    let mut list = ctl.sessions.list();
    // password sessions: the role is the user's current one
    let c = ctl.clone();
    let names: Vec<String> = list
        .iter()
        .filter(|s| s.role.is_none())
        .map(|s| s.user.clone())
        .collect();
    let roles = blocking(move || {
        let mut m = std::collections::HashMap::new();
        for n in names {
            if let Some(u) = files::load_user(&c.settings.state_dir, &n)? {
                m.insert(n, u.role);
            }
        }
        Ok(m)
    })
    .await?;
    for s in &mut list {
        if s.role.is_none() {
            s.role = roles.get(&s.user).copied();
        }
        s.current = own.as_deref() == Some(s.id.as_str());
    }
    Ok(Json(json!({ "sessions": list })))
}

/// Admin: ends one session by its public id.
async fn end_session(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(id): Path<String>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let user = ctl
        .sessions
        .end_by_id(&id)
        .ok_or_else(|| ApiError::not_found("no such session"))?;
    let c = ctl.clone();
    let u = user.clone();
    let i = id.clone();
    blocking(move || {
        c.audit(
            &caller.name,
            caller.addr(),
            "session.end",
            json!({ "session": i, "user": u }),
        )
    })
    .await?;
    Ok(Json(json!({ "ended": 1, "user": user })))
}

#[derive(Deserialize)]
struct EndSessionsQuery {
    user: Option<String>,
    #[serde(default)]
    all: bool,
}

/// Admin: ends all sessions of `?user=<name>`, or everybody's with
/// `?all=true` (incident response; includes the caller's own).
async fn end_sessions(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Query(q): Query<EndSessionsQuery>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let (target, action) = match (&q.user, q.all) {
        (Some(u), false) => (Some(u.clone()), "session.end_user"),
        (None, true) => (None, "session.end_all"),
        _ => {
            return Err(ApiError::bad_request(
                "give either ?user=<name> or ?all=true",
            ))
        }
    };
    let ended = ctl.sessions.end_user(target.as_deref());
    let c = ctl.clone();
    blocking(move || {
        c.audit(
            &caller.name,
            caller.addr(),
            action,
            json!({ "user": target, "ended": ended }),
        )
    })
    .await?;
    Ok(Json(json!({ "ended": ended })))
}

// --------------------------------------------------------------------- OIDC

fn redirect(to: &str, cookies: &[String]) -> Response {
    let mut r = (StatusCode::SEE_OTHER, [(header::LOCATION, to.to_owned())]).into_response();
    for c in cookies {
        if let Ok(v) = c.parse() {
            r.headers_mut().append(header::SET_COOKIE, v);
        }
    }
    r
}

/// Back to the login page with a message code.
fn login_error(code: &str) -> Response {
    redirect(
        &format!("/#/login-error/{code}"),
        &[crate::oidc::clear_binding_cookie()],
    )
}

/// Starts an OIDC login (a link on the login page).
async fn oidc_login(State(ctl): State<Arc<Controller>>) -> Response {
    let Some(o) = &ctl.settings.oidc else {
        return ApiError::not_found("single sign-on is not configured").into_response();
    };
    match o.begin().await {
        Ok((url, binding)) => redirect(&url, &[crate::oidc::binding_cookie(&binding)]),
        Err(e) => {
            warn!(error = %format!("{e:#}"), "OIDC login could not start");
            login_error("unavailable")
        }
    }
}

#[derive(Deserialize)]
struct CallbackQuery {
    code: Option<String>,
    state: Option<String>,
    error: Option<String>,
    error_description: Option<String>,
}

#[derive(Deserialize)]
struct BackchannelForm {
    logout_token: String,
}

/// Called by the provider (not the browser): ends the sessions named in a
/// signed logout token. 200 also when no session matched; 400 with
/// `invalid_request` for tokens that do not verify.
async fn oidc_backchannel_logout(
    State(ctl): State<Arc<Controller>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    axum::extract::Form(f): axum::extract::Form<BackchannelForm>,
) -> Response {
    let Some(o) = ctl.settings.oidc.clone() else {
        return ApiError::not_found("single sign-on is not configured").into_response();
    };
    let target = match o.verify_logout_token(&f.logout_token).await {
        Ok(t) => t,
        Err(e) => {
            warn!(%addr, error = %format!("{e:#}"), "back-channel logout refused");
            return (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_request", "error_description": "invalid logout token" })),
            )
                .into_response();
        }
    };
    let ended = ctl
        .sessions
        .end_oidc(target.subject.as_deref(), target.sid.as_deref());
    let c = ctl.clone();
    let audited = tokio::task::spawn_blocking(move || {
        c.audit(
            "oidc-provider",
            Some(addr.to_string()),
            "session.backchannel_logout",
            json!({ "subject": target.subject, "sid": target.sid, "sessions_ended": ended }),
        )
    })
    .await;
    if !matches!(audited, Ok(Ok(()))) {
        warn!("back-channel logout: audit log write failed");
    }
    StatusCode::OK.into_response()
}

#[derive(Deserialize)]
struct FrontchannelQuery {
    iss: Option<String>,
    sid: Option<String>,
}

/// Loaded by the provider's logout page in an iframe (user's browser). Not
/// authenticated: acts only on our exact issuer and the `sid` of a live
/// session; only effective logouts are audited, so junk requests cannot
/// fill the audit log.
async fn oidc_frontchannel_logout(
    State(ctl): State<Arc<Controller>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    Query(q): Query<FrontchannelQuery>,
) -> Response {
    let Some(o) = ctl.settings.oidc.clone() else {
        return ApiError::not_found("single sign-on is not configured").into_response();
    };
    // the provider may frame this endpoint, nobody else; never cached
    let headers = [
        (
            header::CONTENT_SECURITY_POLICY,
            format!("default-src 'none'; frame-ancestors {}", o.issuer_origin()),
        ),
        (header::CACHE_CONTROL, "no-cache, no-store".to_owned()),
        (header::PRAGMA, "no-cache".to_owned()),
    ];
    let (Some(iss), Some(sid)) = (q.iss.as_deref(), q.sid.as_deref()) else {
        warn!(%addr, "front-channel logout without iss and sid (configure the provider to send them)");
        return (StatusCode::BAD_REQUEST, headers, "iss and sid required").into_response();
    };
    if !o.is_issuer(iss) || sid.is_empty() || sid.len() > 256 {
        warn!(%addr, "front-channel logout refused: wrong issuer or bad sid");
        return (StatusCode::BAD_REQUEST, headers, "invalid request").into_response();
    }
    let ended = ctl.sessions.end_oidc(None, Some(sid));
    if ended > 0 {
        let c = ctl.clone();
        let s = sid.to_owned();
        let audited = tokio::task::spawn_blocking(move || {
            c.audit(
                "oidc-provider",
                Some(addr.to_string()),
                "session.frontchannel_logout",
                json!({ "sid": s, "sessions_ended": ended }),
            )
        })
        .await;
        if !matches!(audited, Ok(Ok(()))) {
            warn!("front-channel logout: audit log write failed");
        }
    }
    (StatusCode::OK, headers, "").into_response()
}

async fn oidc_callback(
    State(ctl): State<Arc<Controller>>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: axum::http::HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let Some(o) = ctl.settings.oidc.clone() else {
        return ApiError::not_found("single sign-on is not configured").into_response();
    };
    let binding = headers
        .get_all(header::COOKIE)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|h| h.split(';'))
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == crate::oidc::BINDING_COOKIE)
        .map(|(_, v)| v.to_owned());
    let result = match (&q.error, &q.code, &q.state) {
        (Some(e), _, _) => {
            if let Some(s) = &q.state {
                o.forget(s);
            }
            warn!(%addr, error = %e, description = ?q.error_description, "OIDC provider returned an error");
            Err(if e == "access_denied" {
                crate::oidc::LoginError::Cancelled
            } else {
                crate::oidc::LoginError::Failed(anyhow::anyhow!("provider error {e}"))
            })
        }
        (None, Some(code), Some(state)) => o.finish(state, code, binding.as_deref()).await,
        _ => Err(crate::oidc::LoginError::Expired),
    };
    let ident = match result {
        Ok(i) => i,
        Err(e) => {
            warn!(%addr, error = %e, "OIDC login failed");
            return login_error(e.code());
        }
    };
    let dir = ctl.settings.state_dir.clone();
    let name = ident.name.clone();
    match tokio::task::spawn_blocking(move || crate::oidc::check_name(&dir, &name)).await {
        Ok(Ok(())) => {}
        Ok(Err(e)) => {
            warn!(%addr, error = %e, "OIDC login refused");
            return login_error(e.code());
        }
        Err(e) => {
            warn!(error = %e, "OIDC name check");
            return login_error("failed");
        }
    }
    let (secret, _) = ctl.sessions.create(
        &ident.name,
        session::Kind::Oidc {
            role: ident.role,
            subject: ident.subject.clone(),
            sid: ident.sid.clone(),
        },
        o.config.session_lifetime,
        session::Client::new(addr, user_agent(&headers)),
    );
    let c = ctl.clone();
    let i = ident.clone();
    let audited = tokio::task::spawn_blocking(move || {
        c.audit(
            &i.name,
            Some(addr.to_string()),
            "session.login",
            json!({ "method": "oidc", "issuer": i.issuer, "subject": i.subject, "role": i.role }),
        )
    })
    .await;
    if !matches!(audited, Ok(Ok(()))) {
        ctl.sessions.remove(&secret);
        warn!("OIDC login: audit log write failed");
        return login_error("failed");
    }
    redirect(
        "/",
        &[
            session::set_cookie(&secret),
            crate::oidc::clear_binding_cookie(),
        ],
    )
}

// ------------------------------------------------------------ live updates

/// Streams are closed after this and the browser reconnects (EventSource),
/// so an idle tab does not hold a connection forever.
const STREAM_MAX: Duration = Duration::from_secs(3600);
/// How often an open stream re-checks its token / session.
const STREAM_RECHECK: Duration = Duration::from_secs(30);

/// Server-sent events: `decision` for every new decision, `resync` when the
/// client fell behind (reload the lists).
async fn events(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
) -> ApiResult<Sse<ReceiverStream<Result<Event, Infallible>>>> {
    caller.require(Role::Viewer)?;
    let mut rx = ctl.events();
    let (tx, out) = tokio::sync::mpsc::channel(64);
    let hello = Event::default()
        .event("hello")
        .retry(Duration::from_secs(3))
        .json_data(json!({ "last_seq": ctl.last_seq() }))
        .map_err(ApiError::internal)?;
    let _ = tx.try_send(Ok(hello));
    tokio::spawn(async move {
        let deadline = tokio::time::sleep(STREAM_MAX);
        tokio::pin!(deadline);
        let mut recheck = tokio::time::interval(STREAM_RECHECK);
        recheck.tick().await;
        loop {
            let ev = tokio::select! {
                r = rx.recv() => match r {
                    Ok(d) => Event::default().event("decision").json_data(&*d),
                    Err(RecvError::Lagged(_)) => Ok(Event::default().event("resync").data("{}")),
                    Err(RecvError::Closed) => return,
                },
                _ = recheck.tick() => {
                    let (c, who) = (ctl.clone(), caller.clone());
                    let valid = tokio::task::spawn_blocking(move || who.still_valid(&c))
                        .await
                        .unwrap_or(false);
                    if !valid {
                        let _ = tx.send(Ok(Event::default().event("logout").data("{}"))).await;
                        return;
                    }
                    continue;
                }
                () = &mut deadline => return,
                () = tx.closed() => return,
            };
            match ev {
                Ok(ev) => {
                    if tx.send(Ok(ev)).await.is_err() {
                        return;
                    }
                }
                Err(e) => warn!(error = %e, "encoding event"),
            }
        }
    });
    Ok(Sse::new(ReceiverStream::new(out)).keep_alive(KeepAlive::default()))
}

// -------------------------------------------------------------- dashboard

/// IPv4 /16 or IPv6 /32 containing `net` (dashboard grouping).
fn coarse(net: &IpNet) -> IpNet {
    let len = match net {
        IpNet::V4(_) => 16,
        IpNet::V6(_) => 32,
    };
    IpNet::new(net.addr(), len.min(net.prefix_len()))
        .map(|n| n.trunc())
        .unwrap_or(*net)
}

fn top<K: Ord + Clone + serde::Serialize>(items: impl Iterator<Item = K>, n: usize) -> Vec<Value> {
    let mut counts = std::collections::BTreeMap::<K, u64>::new();
    for k in items {
        *counts.entry(k).or_default() += 1;
    }
    let mut v: Vec<(K, u64)> = counts.into_iter().collect();
    v.sort_by_key(|x| std::cmp::Reverse(x.1));
    v.into_iter()
        .take(n)
        .map(|(k, c)| json!({ "key": k, "count": c }))
        .collect()
}

async fn stats(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    let active = ctl.active_decisions();
    let v4 = active.iter().filter(|d| d.target.addr().is_ipv4()).count();
    let hourly: Vec<Value> = ctl
        .bans_per_hour(48)
        .into_iter()
        .map(|(h, c)| json!({ "hour": h, "count": c }))
        .collect();
    let (top_asns, top_countries) = top_geo(&ctl.geo, &active, 8);
    Ok(Json(json!({
        "bans_per_hour": hourly,
        "active": {
            "total": active.len(),
            "ipv4": v4,
            "ipv6": active.len() - v4,
            "permanent": active.iter().filter(|d| d.expires_at.is_none()).count(),
        },
        "top_jails": top(active.iter().map(|d| d.jail.clone().unwrap_or_else(|| "(manual)".into())), 8),
        "top_prefixes": top(active.iter().map(|d| coarse(&d.target).to_string()), 8),
        "top_origins": top(active.iter().map(|d| df2b_proto::origin_string(&d.origin)), 8),
        "geoip": ctl.geo.enabled(),
        "top_asns": top_asns,
        "top_countries": top_countries,
    })))
}

/// Active bans by AS and by country (empty without GeoIP databases).
fn top_geo(
    geo: &crate::geo::Geo,
    active: &[df2b_core::Decision],
    n: usize,
) -> (Vec<Value>, Vec<Value>) {
    if !geo.enabled() {
        return (Vec::new(), Vec::new());
    }
    let mut asns: HashMap<u32, (Option<String>, u64)> = HashMap::new();
    let mut countries: HashMap<String, (Option<String>, u64)> = HashMap::new();
    for d in active
        .iter()
        .filter(|d| matches!(d.kind, DecisionKind::Ban))
    {
        let Some(g) = geo.lookup_net(&d.target) else {
            continue;
        };
        if let Some(a) = g.asn {
            let e = asns.entry(a).or_insert((g.as_org, 0));
            e.1 += 1;
        }
        if let Some(c) = g.country {
            let e = countries.entry(c).or_insert((g.country_name, 0));
            e.1 += 1;
        }
    }
    let mut asns: Vec<_> = asns.into_iter().collect();
    asns.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then(a.0.cmp(&b.0)));
    let mut countries: Vec<_> = countries.into_iter().collect();
    countries.sort_by(|a, b| b.1 .1.cmp(&a.1 .1).then(a.0.cmp(&b.0)));
    (
        asns.into_iter()
            .take(n)
            .map(|(asn, (org, count))| json!({ "asn": asn, "org": org, "count": count }))
            .collect(),
        countries
            .into_iter()
            .take(n)
            .map(|(c, (name, count))| json!({ "country": c, "name": name, "count": count }))
            .collect(),
    )
}

/// ASN/country per distinct target (for lists; empty without databases).
fn geo_map<'a>(
    geo: &crate::geo::Geo,
    targets: impl Iterator<Item = &'a IpNet>,
) -> HashMap<String, crate::geo::GeoInfo> {
    let mut out = HashMap::new();
    if !geo.enabled() {
        return out;
    }
    for t in targets {
        if let std::collections::hash_map::Entry::Vacant(e) = out.entry(t.to_string()) {
            if let Some(g) = geo.lookup_net(t) {
                e.insert(g);
            }
        }
    }
    out
}

#[derive(Deserialize)]
struct HistoryQuery {
    target: String,
    limit: Option<usize>,
}

/// Everything known about an address or prefix.
async fn history(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Query(q): Query<HistoryQuery>,
) -> ApiResult {
    caller.require(Role::Viewer)?;
    let net = target(&q.target)?;
    let limit = q.limit.unwrap_or(200).clamp(1, 1000);
    let active: Vec<_> = ctl
        .active_decisions()
        .into_iter()
        .filter(|d| d.target.contains(&net) || net.contains(&d.target))
        .collect();
    let c = ctl.clone();
    let history = blocking(move || c.history(net, limit)).await?;
    Ok(Json(json!({
        "target": net,
        "geo": ctl.geo.lookup_net(&net),
        "allowlisted": ctl.allowlisted(&net),
        // earlier correlation bans of this exact target (escalation)
        "correlation_offenses": ctl.correlation_offenses(&net),
        "offense_memory": humantime::format_duration(crate::state::OFFENSE_MEMORY).to_string(),
        // log lines agents sent with their reports (latest per host first)
        "samples": ctl
            .correlator
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .samples(&net)
            .into_iter()
            .map(|(jail, key, s)| json!({
                "jail": jail, "key": key, "agent": s.agent, "at": s.at, "line": s.line,
            }))
            .collect::<Vec<_>>(),
        // what agents reported within the longest rule window
        "observations": ctl
            .correlator
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .recent(&net)
            .into_iter()
            .map(|(jail, key, s)| json!({
                "jail": jail, "key": key, "agent": s.agent, "at": s.at,
                "failures": s.failures, "banned": s.banned,
            }))
            .collect::<Vec<_>>(),
        "allow_entries": ctl
            .allowlist()
            .into_iter()
            .filter(|e| e.net.contains(&net) || net.contains(&e.net))
            .collect::<Vec<_>>(),
        "active": active,
        "history": history,
    })))
}

async fn status(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    let agents = ctl.agents();
    Ok(Json(json!({
        "version": env!("CARGO_PKG_VERSION"),
        "agents": {
            "total": agents.len(),
            "connected": agents.iter().filter(|a| a.connected).count(),
            "revoked": agents.iter().filter(|a| a.revoked).count(),
        },
        "active_decisions": ctl.active_decisions().len(),
        "last_seq": ctl.last_seq(),
        "propagate": ctl.propagate(),
        "allowlist": ctl.allowlist().iter().map(|e| e.net).collect::<Vec<_>>(),
        "allowlist_version": ctl.allowlist_version(),
        "redaction_version": ctl.redaction_version(),
        "sessions": ctl.sessions.count(),
        "geoip": ctl.geo.databases(),
    })))
}

async fn agents(caller: Caller, State(ctl): State<Arc<Controller>>) -> ApiResult {
    caller.require(Role::Viewer)?;
    Ok(Json(json!({ "agents": ctl.agents() })))
}

async fn agent(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(id): Path<String>,
) -> ApiResult {
    caller.require(Role::Viewer)?;
    let a = ctl
        .agent(&id)
        .ok_or_else(|| ApiError::not_found(format!("no agent {id:?}")))?;
    Ok(Json(json!({ "agent": a })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AgentUpdate {
    group: String,
}

/// Admin: moves an agent to another group. Bans scoped to the old group
/// are removed from it and those of the new group applied, within seconds
/// if it is connected, else at its next connection.
async fn update_agent(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(id): Path<String>,
    Json(req): Json<AgentUpdate>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let group = req.group.trim().to_owned();
    if !files::valid_group(&group) {
        return Err(ApiError::bad_request(
            "invalid group name (letters, digits, - _ .; at most 64)",
        ));
    }
    if ctl.agent(&id).map_or(true, |a| a.revoked) {
        return Err(ApiError::not_found(format!("no active agent {id:?}")));
    }
    let c = ctl.clone();
    let (i, g) = (id.clone(), group.clone());
    let old = blocking(move || {
        let old = c.set_group(&i, &g)?;
        if let Some(old) = old.as_ref().filter(|o| **o != g) {
            c.audit(
                &caller.name,
                caller.addr(),
                "agent.group",
                json!({ "agent": i, "from": old, "to": g }),
            )?;
        }
        Ok(old)
    })
    .await?
    .ok_or_else(|| ApiError::not_found(format!("no agent {id:?}")))?;
    Ok(Json(
        json!({ "agent": id, "group": group, "previous_group": old, "changed": old != group }),
    ))
}

async fn revoke_agent(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Path(id): Path<String>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    if ctl.agent(&id).is_none() {
        return Err(ApiError::not_found(format!("no agent {id:?}")));
    }
    let c = ctl.clone();
    let agent = id.clone();
    blocking(move || {
        files::revoke(&c.settings.state_dir, &agent)?;
        c.audit(
            &caller.name,
            caller.addr(),
            "agent.revoke",
            json!({ "agent": agent }),
        )
    })
    .await?;
    Ok(Json(json!({ "revoked": id })))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct EnrollTokenRequest {
    #[serde(default = "default_group")]
    group: String,
    /// e.g. "1h" (default), at most 7 days
    #[serde(default)]
    ttl: Option<String>,
}

fn default_group() -> String {
    "default".into()
}

fn parse_duration(s: &str, what: &str) -> Result<Duration, ApiError> {
    humantime::parse_duration(s).map_err(|e| ApiError::bad_request(format!("{what}: {e}")))
}

async fn enroll_token(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<EnrollTokenRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    caller.require(Role::Admin)?;
    let ttl = match &req.ttl {
        Some(t) => parse_duration(t, "ttl")?,
        None => Duration::from_secs(3600),
    };
    if ttl > MAX_ENROLL_TTL || ttl.is_zero() {
        return Err(ApiError::bad_request("ttl must be between 1s and 7d"));
    }
    let c = ctl.clone();
    let group = req.group.clone();
    let token = tokio::task::spawn_blocking(move || {
        files::create_token(&c.settings.state_dir, &group, ttl)
    })
    .await
    .map_err(ApiError::internal)?
    .map_err(|e| ApiError::bad_request(format!("{e:#}")))?;
    let expires_at = Utc::now() + chrono::Duration::from_std(ttl).map_err(ApiError::internal)?;
    let c = ctl.clone();
    let group = req.group.clone();
    blocking(move || {
        c.audit(
            &caller.name,
            caller.addr(),
            "enroll_token.create",
            json!({ "group": group, "expires_at": expires_at }),
        )
    })
    .await?;
    Ok((
        StatusCode::CREATED,
        Json(json!({
            "token": token.to_string(),
            "group": req.group,
            "expires_at": expires_at,
        })),
    ))
}

#[derive(Deserialize)]
struct DecisionQuery {
    /// Address or prefix; matches decisions overlapping it.
    target: Option<String>,
    jail: Option<String>,
}

fn target(s: &str) -> Result<IpNet, ApiError> {
    parse_target(s).map_err(ApiError::bad_request)
}

async fn decisions(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Query(q): Query<DecisionQuery>,
) -> ApiResult {
    caller.require(Role::Viewer)?;
    let t = q.target.as_deref().map(target).transpose()?;
    let list: Vec<_> = ctl
        .active_decisions()
        .into_iter()
        .filter(|d| t.map_or(true, |t| d.target.contains(&t) || t.contains(&d.target)))
        .filter(|d| q.jail.as_ref().map_or(true, |j| d.jail.as_ref() == Some(j)))
        .collect();
    // ASN/country by target, when GeoIP databases are configured
    let geo = geo_map(&ctl.geo, list.iter().map(|d| &d.target));
    Ok(Json(json!({ "decisions": list, "geo": geo })))
}

/// "global", "group:<name>" or "agent:<id>[,<id>...]"
fn parse_scope(s: &str, ctl: &Controller) -> Result<Scope, ApiError> {
    match s.split_once(':') {
        None if s == "global" => Ok(Scope::Global),
        Some(("group", g)) if !g.is_empty() => Ok(Scope::Group(g.to_owned())),
        Some(("agent", ids)) => {
            let ids: Vec<AgentId> = ids
                .split(',')
                .filter(|i| !i.is_empty())
                .map(|i| AgentId(i.to_owned()))
                .collect();
            if ids.is_empty() {
                return Err(ApiError::bad_request("scope agent: needs at least one id"));
            }
            if let Some(unknown) = ids.iter().find(|i| ctl.agent(&i.0).is_none()) {
                return Err(ApiError::bad_request(format!(
                    "unknown agent {:?}",
                    unknown.0
                )));
            }
            Ok(Scope::Agents(ids))
        }
        _ => Err(ApiError::bad_request(
            "scope must be \"global\", \"group:<name>\" or \"agent:<id>[,<id>...]\"",
        )),
    }
}

/// Manual bans broader than this are refused (a /0 would lock out
/// everybody, including the operators).
fn too_broad(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => n.prefix_len() < 8,
        IpNet::V6(n) => n.prefix_len() < 16,
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct BanRequest {
    target: String,
    /// e.g. "24h"; omitted = permanent
    duration: Option<String>,
    /// default "global"
    scope: Option<String>,
    jail: Option<String>,
    reason: Option<String>,
}

async fn ban(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<BanRequest>,
) -> ApiResult<(StatusCode, Json<Value>)> {
    caller.require(Role::Operator)?;
    let net = target(&req.target)?;
    if too_broad(&net) {
        return Err(ApiError::bad_request(format!(
            "{net} is too broad (minimum /8 for IPv4, /16 for IPv6)"
        )));
    }
    if ctl.allowlisted(&net) {
        return Err(ApiError::new(
            StatusCode::CONFLICT,
            format!("{net} overlaps the controller allowlist"),
        ));
    }
    let scope = parse_scope(req.scope.as_deref().unwrap_or("global"), &ctl)?;
    let expires_at = match &req.duration {
        Some(d) => {
            let d = parse_duration(d, "duration")?;
            Some(Utc::now() + chrono::Duration::from_std(d).map_err(ApiError::bad_request_from)?)
        }
        None => None,
    };
    let reason = req.reason.unwrap_or_else(|| "manual".into());
    let new = NewDecision {
        kind: DecisionKind::Ban,
        target: net,
        scope,
        jail: req.jail,
        expires_at,
        origin: caller.origin(),
        reason,
    };
    let c = ctl.clone();
    let appended = blocking(move || {
        let appended = c.append(vec![new])?;
        if let Some(d) = appended.first() {
            c.audit(
                &caller.name,
                caller.addr(),
                "ban",
                json!({ "decision": d.id, "seq": d.seq, "target": d.target, "scope": d.scope, "expires_at": d.expires_at }),
            )?;
        }
        Ok(appended)
    })
    .await?;
    Ok(match appended.first() {
        Some(d) => (StatusCode::CREATED, Json(json!({ "decision": &**d }))),
        None => (
            StatusCode::OK,
            Json(json!({
                "decision": null,
                "message": "already covered by an active ban with the same scope lasting at least as long",
            })),
        ),
    })
}

impl ApiError {
    fn bad_request_from(e: impl std::fmt::Display) -> Self {
        Self::bad_request(e.to_string())
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnbanRequest {
    target: String,
    reason: Option<String>,
    /// then keep the target from being banned again for this long ("24h"):
    /// a temporary allowlist entry, at most 7 days for operators
    allow_for: Option<String>,
}

async fn unban(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<UnbanRequest>,
) -> ApiResult {
    caller.require(Role::Operator)?;
    let net = target(&req.target)?;
    let reason = req.reason.unwrap_or_else(|| "manual unban".into());
    let allow_until = match req.allow_for.as_deref() {
        None => None,
        Some(t) => {
            let max = if caller.role >= Role::Admin {
                MAX_ALLOW
            } else {
                OPERATOR_ALLOW
            };
            let until = expiry(t, max)?;
            if too_broad_for_temporary(&net.trunc()) {
                return Err(ApiError::bad_request(format!(
                    "{net} is too broad for \"allow for\" (at most /24 for IPv4, /48 for IPv6); \
                     use the allowlist"
                )));
            }
            Some(until)
        }
    };
    let c = ctl.clone();
    let (revoked, allowed) = blocking(move || {
        // allow first: agents stop banning before the unbans reach them
        let allowed = match allow_until {
            Some(until) => {
                let entry = crate::store::AllowEntry {
                    net: net.trunc(),
                    comment: format!("after unban: {reason}").chars().take(200).collect(),
                    created_by: caller.name.clone(),
                    created_at: Utc::now(),
                    expires_at: Some(until),
                };
                match c.add_allow(entry) {
                    Ok(_) => Some(until),
                    // already allowed at least as long, or permanently
                    Err(crate::state::AllowError::Exists(_) | crate::state::AllowError::Covered(..)) => None,
                    Err(e) => return Err(anyhow::anyhow!(e.to_string())),
                }
            }
            None => None,
        };
        let revoked = c.unban(net, caller.origin(), &reason)?;
        if !revoked.is_empty() || allowed.is_some() {
            let ids: Vec<_> = revoked
                .iter()
                .filter_map(|d| match d.kind {
                    DecisionKind::Unban { revokes } => Some(revokes),
                    _ => None,
                })
                .collect();
            c.audit(
                &caller.name,
                caller.addr(),
                "unban",
                json!({ "target": net, "revoked": ids, "reason": reason, "allowed_until": allowed }),
            )?;
        }
        Ok((revoked, allowed))
    })
    .await?;
    // nothing to unban is only an error when nothing else was asked for
    if revoked.is_empty() && req.allow_for.is_none() {
        return Err(ApiError::not_found(format!("no active ban overlaps {net}")));
    }
    let list: Vec<_> = revoked.iter().map(|d| &**d).collect();
    Ok(Json(json!({
        "unbans": list,
        "allowed_until": allowed,
        // asked for, but an entry at least as long (or permanent) exists
        "already_allowlisted": req.allow_for.is_some() && allowed.is_none(),
    })))
}

#[derive(Deserialize)]
struct AuditQuery {
    limit: Option<usize>,
    before: Option<u64>,
}

async fn audit(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Query(q): Query<AuditQuery>,
) -> ApiResult {
    caller.require(Role::Admin)?;
    let limit = q.limit.unwrap_or(100).min(1000);
    let before = q.before.unwrap_or(u64::MAX);
    let c = ctl.clone();
    let entries = blocking(move || c.audit_log(limit, before)).await?;
    Ok(Json(json!({ "entries": entries })))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::{Propagate, Settings};
    use crate::store::Store;
    use df2b_core::Allowlist;
    use df2b_tls::transport::{https_client_config, https_server_config, Trust};
    use reqwest::StatusCode as S;

    struct Env {
        base: String,
        http: reqwest::Client,
        dir: std::path::PathBuf,
        ctl: Arc<Controller>,
    }

    impl Env {
        async fn new(tag: &str) -> Self {
            Self::with_geo(tag, crate::geo::Geo::default()).await
        }

        async fn with_geo(tag: &str, geo: crate::geo::Geo) -> Self {
            let dir = std::env::temp_dir().join(format!("df2b-api-{tag}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&dir);
            let ca = files::load_or_create_ca(&dir).unwrap();
            let fp = ca.fingerprint();
            let settings = Settings {
                state_dir: dir.clone(),
                cert_lifetime: Duration::from_secs(3600),
                propagate: Propagate::Global,
                allowlist: Allowlist::new(["10.0.0.0/8".parse().unwrap()]),
                oidc: None,
                https_internal_ca: true,
            };
            let ctl = Arc::new(
                Controller::open(settings, ca, Store::open(&dir).unwrap())
                    .unwrap()
                    .with_geo(geo),
            );
            let (chain, key) = ctl.ca.issue_server(&[]).unwrap();
            let tls = https_server_config(chain, key).unwrap();
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("https://{}", l.local_addr().unwrap());
            tokio::spawn(crate::https::serve(
                l,
                tls,
                router(ctl.clone()),
                std::future::pending(),
            ));
            let http = client(Trust::PinnedCa(fp));
            Self {
                base,
                http,
                dir,
                ctl,
            }
        }

        fn token(&self, name: &str, role: Role) -> String {
            files::create_api_token(&self.dir, name, role, None)
                .unwrap()
                .to_string()
        }

        async fn call(&self, method: &str, path: &str, token: &str, body: Value) -> (S, Value) {
            let url = format!("{}{path}", self.base);
            let req = match method {
                "GET" => self.http.get(url),
                _ => self.http.post(url).json(&body),
            };
            let r = req.bearer_auth(token).send().await.unwrap();
            let status = r.status();
            (status, r.json().await.unwrap_or(Value::Null))
        }
    }

    fn client(trust: Trust) -> reqwest::Client {
        let tls = https_client_config(trust).unwrap();
        reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .build()
            .unwrap()
    }

    #[tokio::test]
    async fn authentication_and_roles() {
        let env = Env::new("auth").await;
        let viewer = env.token("vic", Role::Viewer);
        let operator = env.token("olga", Role::Operator);
        let admin = env.token("ada", Role::Admin);

        // health needs no token; everything else does
        let r = env
            .http
            .get(format!("{}/api/v1/health", env.base))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::OK);
        let r = env
            .http
            .get(format!("{}/api/v1/status", env.base))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::UNAUTHORIZED);
        assert_eq!(r.headers()["www-authenticate"], "Bearer");
        let fake = ApiToken::generate().to_string();
        assert_eq!(
            env.call("GET", "/api/v1/status", &fake, json!({})).await.0,
            S::UNAUTHORIZED
        );
        assert_eq!(
            env.call("GET", "/api/v1/status", "garbage", json!({}))
                .await
                .0,
            S::UNAUTHORIZED
        );

        let (st, v) = env.call("GET", "/api/v1/whoami", &viewer, json!({})).await;
        assert_eq!(
            (st, v["name"].as_str(), v["role"].as_str()),
            (S::OK, Some("vic"), Some("viewer"))
        );

        // role matrix
        let ban = json!({ "target": "203.0.113.0/24", "duration": "1h" });
        for (tok, path, body, want) in [
            (&viewer, "/api/v1/bans", ban.clone(), S::FORBIDDEN),
            (&viewer, "/api/v1/enroll-tokens", json!({}), S::FORBIDDEN),
            (&operator, "/api/v1/enroll-tokens", json!({}), S::FORBIDDEN),
            (
                &operator,
                "/api/v1/agents/x/revoke",
                json!({}),
                S::FORBIDDEN,
            ),
        ] {
            assert_eq!(env.call("POST", path, tok, body).await.0, want, "{path}");
        }
        assert_eq!(
            env.call("GET", "/api/v1/audit", &operator, json!({}))
                .await
                .0,
            S::FORBIDDEN
        );
        assert_eq!(
            env.call("GET", "/api/v1/status", &viewer, json!({}))
                .await
                .0,
            S::OK
        );

        // revoking a token takes effect immediately
        assert!(files::revoke_api_token(&env.dir, "vic").unwrap());
        assert_eq!(
            env.call("GET", "/api/v1/status", &viewer, json!({}))
                .await
                .0,
            S::UNAUTHORIZED
        );

        // admin: enrollment tokens
        let (st, v) = env
            .call(
                "POST",
                "/api/v1/enroll-tokens",
                &admin,
                json!({ "group": "web", "ttl": "2h" }),
            )
            .await;
        assert_eq!(st, S::CREATED);
        assert!(v["token"]
            .as_str()
            .unwrap()
            .parse::<df2b_tls::EnrollToken>()
            .is_ok());
        let (st, _) = env
            .call(
                "POST",
                "/api/v1/enroll-tokens",
                &admin,
                json!({ "ttl": "30d" }),
            )
            .await;
        assert_eq!(st, S::BAD_REQUEST);
        let (st, _) = env
            .call("POST", "/api/v1/agents/nope/revoke", &admin, json!({}))
            .await;
        assert_eq!(st, S::NOT_FOUND);

        // a client pinned to another CA refuses the server
        let other = df2b_tls::Ca::generate("other").unwrap();
        let r = client(Trust::PinnedCa(other.fingerprint()))
            .get(format!("{}/api/v1/health", env.base))
            .send()
            .await;
        assert!(r.is_err());
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    /// A logged-in browser: session cookie + CSRF token.
    async fn login(env: &Env, user: &str, pw: &str) -> (S, String, Value) {
        let r = env
            .http
            .post(format!("{}/api/v1/session", env.base))
            .json(&json!({ "username": user, "password": pw }))
            .send()
            .await
            .unwrap();
        let st = r.status();
        let cookie = r
            .headers()
            .get("set-cookie")
            .map(|c| c.to_str().unwrap().split(';').next().unwrap().to_owned())
            .unwrap_or_default();
        (st, cookie, r.json().await.unwrap_or(Value::Null))
    }

    async fn with_cookie(
        env: &Env,
        method: &str,
        path: &str,
        cookie: &str,
        csrf: Option<&str>,
        body: Value,
    ) -> (S, Value) {
        let url = format!("{}{path}", env.base);
        let mut req = match method {
            "GET" => env.http.get(url),
            "DELETE" => env.http.delete(url),
            _ => env.http.post(url).json(&body),
        }
        .header("cookie", cookie);
        if let Some(c) = csrf {
            req = req.header("x-csrf-token", c);
        }
        let r = req.send().await.unwrap();
        let st = r.status();
        (st, r.json().await.unwrap_or(Value::Null))
    }

    #[tokio::test]
    async fn sessions_csrf_and_live_updates() {
        let env = Env::new("sess").await;
        files::create_user(&env.dir, "olga", Role::Operator, "correct horse battery").unwrap();

        let (st, cookie, _) = login(&env, "olga", "wrong horse battery").await;
        assert_eq!((st, cookie.as_str()), (S::UNAUTHORIZED, ""));
        let (st, _, _) = login(&env, "nobody", "correct horse battery").await;
        assert_eq!(st, S::UNAUTHORIZED);

        let (st, cookie, v) = login(&env, "olga", "correct horse battery").await;
        assert_eq!(st, S::OK, "{v}");
        assert!(cookie.starts_with("__Host-df2b_session="));
        let csrf = v["csrf_token"].as_str().unwrap().to_owned();
        let (st, v) = with_cookie(&env, "GET", "/api/v1/whoami", &cookie, None, json!({})).await;
        assert_eq!(st, S::OK);
        assert_eq!(
            (
                v["name"].as_str(),
                v["auth"].as_str(),
                v["csrf_token"].as_str()
            ),
            (Some("olga"), Some("session"), Some(csrf.as_str()))
        );

        // live updates: subscribe before banning
        let mut sse = env
            .http
            .get(format!("{}/api/v1/events", env.base))
            .header("cookie", &cookie)
            .send()
            .await
            .unwrap();
        assert_eq!(sse.status(), S::OK);
        assert_eq!(sse.headers()["content-type"], "text/event-stream");
        let mut seen = String::new();
        while !seen.contains("event: hello") {
            seen += &String::from_utf8_lossy(&sse.chunk().await.unwrap().unwrap());
        }

        // changes need the CSRF token
        let ban = json!({ "target": "198.51.100.7", "duration": "1h" });
        let (st, v) = with_cookie(&env, "POST", "/api/v1/bans", &cookie, None, ban.clone()).await;
        assert_eq!(st, S::FORBIDDEN, "{v}");
        let (st, _) = with_cookie(
            &env,
            "POST",
            "/api/v1/bans",
            &cookie,
            Some("forged"),
            ban.clone(),
        )
        .await;
        assert_eq!(st, S::FORBIDDEN);
        let (st, v) = with_cookie(
            &env,
            "POST",
            "/api/v1/bans",
            &cookie,
            Some(&csrf),
            ban.clone(),
        )
        .await;
        assert_eq!(st, S::CREATED, "{v}");
        assert_eq!(v["decision"]["origin"]["value"], "olga");

        while !seen.contains("event: decision") {
            seen += &String::from_utf8_lossy(&sse.chunk().await.unwrap().unwrap());
        }
        assert!(seen.contains("198.51.100.7/32"), "{seen}");
        drop(sse);

        // dashboard and IP detail
        let (st, v) = with_cookie(&env, "GET", "/api/v1/stats", &cookie, None, json!({})).await;
        assert_eq!(st, S::OK);
        assert_eq!(v["bans_per_hour"].as_array().unwrap().len(), 48);
        assert_eq!(v["bans_per_hour"][47]["count"], 1);
        assert_eq!(v["active"]["ipv4"], 1);
        assert_eq!(v["top_prefixes"][0]["key"], "198.51.0.0/16");
        let (_, v) = with_cookie(
            &env,
            "POST",
            "/api/v1/unban",
            &cookie,
            Some(&csrf),
            json!({ "target": "198.51.100.7" }),
        )
        .await;
        assert_eq!(v["unbans"].as_array().unwrap().len(), 1);
        let (st, v) = with_cookie(
            &env,
            "GET",
            "/api/v1/history?target=198.51.100.0/24",
            &cookie,
            None,
            json!({}),
        )
        .await;
        assert_eq!(st, S::OK);
        let kinds: Vec<_> = v["history"]
            .as_array()
            .unwrap()
            .iter()
            .map(|d| d["kind"]["kind"].as_str().unwrap())
            .collect();
        assert_eq!(kinds, ["unban", "ban"]);
        assert_eq!(v["active"].as_array().unwrap().len(), 0);
        let (_, v) = with_cookie(
            &env,
            "GET",
            "/api/v1/history?target=10.1.1.1",
            &cookie,
            None,
            json!({}),
        )
        .await;
        assert_eq!(v["allowlisted"], true);

        // a viewer session cannot ban; a role change applies immediately
        files::update_user(&env.dir, "olga", Some(Role::Viewer), None).unwrap();
        let (st, _) = with_cookie(
            &env,
            "POST",
            "/api/v1/bans",
            &cookie,
            Some(&csrf),
            ban.clone(),
        )
        .await;
        assert_eq!(st, S::FORBIDDEN);

        // a new password ends the session
        files::update_user(&env.dir, "olga", None, Some("a brand new password")).unwrap();
        let (st, _) = with_cookie(&env, "GET", "/api/v1/whoami", &cookie, None, json!({})).await;
        assert_eq!(st, S::UNAUTHORIZED);

        // logout
        let (_, cookie, v) = login(&env, "olga", "a brand new password").await;
        let csrf = v["csrf_token"].as_str().unwrap().to_owned();
        let (st, _) =
            with_cookie(&env, "DELETE", "/api/v1/session", &cookie, None, json!({})).await;
        assert_eq!(st, S::FORBIDDEN, "logout needs CSRF too");
        let (st, _) = with_cookie(
            &env,
            "DELETE",
            "/api/v1/session",
            &cookie,
            Some(&csrf),
            json!({}),
        )
        .await;
        assert_eq!(st, S::OK);
        let (st, _) = with_cookie(&env, "GET", "/api/v1/whoami", &cookie, None, json!({})).await;
        assert_eq!(st, S::UNAUTHORIZED);

        // deleting the user ends their sessions
        let (_, cookie, _) = login(&env, "olga", "a brand new password").await;
        files::delete_user(&env.dir, "olga").unwrap();
        let (st, _) = with_cookie(&env, "GET", "/api/v1/whoami", &cookie, None, json!({})).await;
        assert_eq!(st, S::UNAUTHORIZED);

        // the audit log names the user
        let admin = env.token("ada", Role::Admin);
        let (_, v) = env.call("GET", "/api/v1/audit", &admin, json!({})).await;
        let actions: Vec<_> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}:{}",
                    e["actor"].as_str().unwrap(),
                    e["action"].as_str().unwrap()
                )
            })
            .collect();
        assert_eq!(
            actions,
            [
                "olga:session.login",
                "olga:session.login",
                "olga:unban",
                "olga:ban",
                "olga:session.login"
            ]
        );
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn admins_list_and_end_sessions() {
        let env = Env::new("sessmgmt").await;
        files::create_user(&env.dir, "ada", Role::Admin, "correct horse battery").unwrap();
        files::create_user(&env.dir, "olga", Role::Operator, "operator password").unwrap();
        let (_, ada, v) = login(&env, "ada", "correct horse battery").await;
        let ada_csrf = v["csrf_token"].as_str().unwrap().to_owned();
        let (_, olga1, v) = login(&env, "olga", "operator password").await;
        let olga_csrf = v["csrf_token"].as_str().unwrap().to_owned();
        let (_, olga2, _) = login(&env, "olga", "operator password").await;

        // operators may not
        let (st, _) = with_cookie(&env, "GET", "/api/v1/sessions", &olga1, None, json!({})).await;
        assert_eq!(st, S::FORBIDDEN);
        let (st, _) = with_cookie(
            &env,
            "DELETE",
            "/api/v1/sessions?user=ada",
            &olga1,
            Some(&olga_csrf),
            json!({}),
        )
        .await;
        assert_eq!(st, S::FORBIDDEN);

        let (st, v) = with_cookie(&env, "GET", "/api/v1/sessions", &ada, None, json!({})).await;
        assert_eq!(st, S::OK);
        let list = v["sessions"].as_array().unwrap();
        assert_eq!(list.len(), 3);
        let mine: Vec<_> = list.iter().filter(|s| s["current"] == true).collect();
        assert_eq!((mine.len(), mine[0]["user"].as_str()), (1, Some("ada")));
        let olgas: Vec<&Value> = list.iter().filter(|s| s["user"] == "olga").collect();
        assert!(olgas
            .iter()
            .all(|s| s["role"] == "operator" && s["method"] == "password"));
        assert!(olgas[0]["remote_addr"]
            .as_str()
            .unwrap()
            .starts_with("127.0.0.1:"));
        assert!(
            !v.to_string().contains(olga1.split('=').nth(1).unwrap()),
            "no cookie secrets"
        );

        // end one of olga's sessions: needs CSRF like every change
        let id = olgas[0]["id"].as_str().unwrap().to_owned();
        let path = format!("/api/v1/sessions/{id}");
        let (st, _) = with_cookie(&env, "DELETE", &path, &ada, None, json!({})).await;
        assert_eq!(st, S::FORBIDDEN);
        let (st, v) = with_cookie(&env, "DELETE", &path, &ada, Some(&ada_csrf), json!({})).await;
        assert_eq!((st, v["user"].as_str()), (S::OK, Some("olga")));
        let (st, _) = with_cookie(&env, "DELETE", &path, &ada, Some(&ada_csrf), json!({})).await;
        assert_eq!(st, S::NOT_FOUND);
        let alive = |c: String| {
            let env = &env;
            async move {
                with_cookie(env, "GET", "/api/v1/whoami", &c, None, json!({}))
                    .await
                    .0
                    == S::OK
            }
        };
        // most recently used first: olga1 made the refused requests above
        assert_eq!(
            (alive(olga1.clone()).await, alive(olga2.clone()).await),
            (false, true)
        );

        // all of a user's sessions
        let (_, v) = with_cookie(
            &env,
            "DELETE",
            "/api/v1/sessions?user=olga",
            &ada,
            Some(&ada_csrf),
            json!({}),
        )
        .await;
        assert_eq!(v["ended"], 1);
        assert!(!alive(olga2.clone()).await);
        let (st, _) = with_cookie(
            &env,
            "DELETE",
            "/api/v1/sessions",
            &ada,
            Some(&ada_csrf),
            json!({}),
        )
        .await;
        assert_eq!(st, S::BAD_REQUEST, "neither user nor all");

        // an admin API token works too; everybody out (incident response)
        let token = env.token("ops", Role::Admin);
        let (_, v) = env.call("GET", "/api/v1/sessions", &token, json!({})).await;
        assert_eq!(v["sessions"].as_array().unwrap().len(), 1);
        assert_eq!(v["sessions"][0]["current"], false);
        let r = env
            .http
            .delete(format!("{}/api/v1/sessions?all=true", env.base))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap();
        assert_eq!(r.json::<Value>().await.unwrap()["ended"], 1);
        assert!(!alive(ada.clone()).await);

        let (_, v) = env.call("GET", "/api/v1/audit", &token, json!({})).await;
        let actions: Vec<_> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}:{}",
                    e["actor"].as_str().unwrap(),
                    e["action"].as_str().unwrap()
                )
            })
            .filter(|a| a.contains("session.end"))
            .collect();
        assert_eq!(
            actions,
            [
                "ops:session.end_all",
                "ada:session.end_user",
                "ada:session.end"
            ]
        );
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn user_management_and_password_changes() {
        let env = Env::new("users").await;
        files::create_user(&env.dir, "ada", Role::Admin, "correct horse battery").unwrap();
        files::create_user(&env.dir, "otto", Role::Operator, "operator password").unwrap();
        env.token("ci", Role::Viewer);
        let (_, ada, v) = login(&env, "ada", "correct horse battery").await;
        let csrf = v["csrf_token"].as_str().unwrap().to_owned();
        assert_eq!(v["must_change_password"], false);
        let (_, otto, ov) = login(&env, "otto", "operator password").await;
        let otto_csrf = ov["csrf_token"].as_str().unwrap().to_owned();
        let call =
            |m: &'static str, path: String, cookie: String, csrf: Option<String>, body: Value| {
                let env = &env;
                async move { with_cookie(env, m, &path, &cookie, csrf.as_deref(), body).await }
            };

        // operators cannot manage users
        let (st, _) = call("GET", "/api/v1/users".into(), otto.clone(), None, json!({})).await;
        assert_eq!(st, S::FORBIDDEN);
        let (st, _) = call(
            "POST",
            "/api/v1/users".into(),
            otto.clone(),
            Some(otto_csrf.clone()),
            json!({ "name": "x", "role": "admin", "password": "long enough password" }),
        )
        .await;
        assert_eq!(st, S::FORBIDDEN);

        // create: validation, name space, success
        for (body, want) in [
            (
                json!({ "name": "bad/name", "role": "viewer", "password": "long enough password" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "name": "olga", "role": "viewer", "password": "short" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "name": "olga1234567890", "role": "viewer", "password": "OLGA1234567890" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "name": "oidc-provider", "role": "viewer", "password": "long enough password" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "name": "otto", "role": "viewer", "password": "long enough password" }),
                S::CONFLICT,
            ),
            (
                json!({ "name": "ci", "role": "viewer", "password": "long enough password" }),
                S::CONFLICT,
            ),
            (
                json!({ "name": "olga", "role": "operator", "password": "temporary password" }),
                S::CREATED,
            ),
        ] {
            let (st, v) = call(
                "POST",
                "/api/v1/users".into(),
                ada.clone(),
                Some(csrf.clone()),
                body.clone(),
            )
            .await;
            assert_eq!(st, want, "{body} {v}");
        }
        let (_, v) = call("GET", "/api/v1/users".into(), ada.clone(), None, json!({})).await;
        let users: Vec<(String, bool, u64)> = v["users"]
            .as_array()
            .unwrap()
            .iter()
            .map(|u| {
                (
                    u["name"].as_str().unwrap().into(),
                    u["must_change_password"].as_bool().unwrap(),
                    u["sessions"].as_u64().unwrap(),
                )
            })
            .collect();
        assert_eq!(
            users,
            [
                ("ada".into(), false, 1),
                ("olga".into(), true, 0),
                ("otto".into(), false, 1)
            ]
        );
        assert!(
            !v.to_string().contains("argon2"),
            "no password hashes in the API"
        );

        // temporary password: only whoami, password change and logout work
        let (_, olga, v) = login(&env, "olga", "temporary password").await;
        assert_eq!(v["must_change_password"], true);
        let ocsrf = v["csrf_token"].as_str().unwrap().to_owned();
        let (st, v) = call(
            "GET",
            "/api/v1/status".into(),
            olga.clone(),
            None,
            json!({}),
        )
        .await;
        assert_eq!(st, S::FORBIDDEN, "{v}");
        assert_eq!(
            call(
                "GET",
                "/api/v1/events".into(),
                olga.clone(),
                None,
                json!({})
            )
            .await
            .0,
            S::FORBIDDEN
        );
        let (st, v) = call(
            "GET",
            "/api/v1/whoami".into(),
            olga.clone(),
            None,
            json!({}),
        )
        .await;
        assert_eq!(
            (st, v["must_change_password"].as_bool()),
            (S::OK, Some(true))
        );
        let pw = |cur: &str, new: &str| json!({ "current_password": cur, "new_password": new });
        let path = || "/api/v1/session/password".to_string();
        // wrong current password: 403, and the session stays valid
        let (st, _) = call(
            "POST",
            path(),
            olga.clone(),
            Some(ocsrf.clone()),
            pw("wrong password!", "olga's own password"),
        )
        .await;
        assert_eq!(st, S::FORBIDDEN);
        assert_eq!(
            call(
                "GET",
                "/api/v1/whoami".into(),
                olga.clone(),
                None,
                json!({})
            )
            .await
            .0,
            S::OK
        );
        let (st, _) = call(
            "POST",
            path(),
            olga.clone(),
            Some(ocsrf.clone()),
            pw("temporary password", "temporary password"),
        )
        .await;
        assert_eq!(st, S::BAD_REQUEST, "same password");
        let (st, _) = call(
            "POST",
            path(),
            olga.clone(),
            None,
            pw("temporary password", "olga's own password"),
        )
        .await;
        assert_eq!(st, S::FORBIDDEN, "CSRF");
        // success: a new session replaces the old one
        let r = env
            .http
            .post(format!("{}{}", env.base, path()))
            .header("cookie", &olga)
            .header("x-csrf-token", &ocsrf)
            .json(&pw("temporary password", "olga's own password"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::OK);
        let olga2 = r.headers()["set-cookie"]
            .to_str()
            .unwrap()
            .split(';')
            .next()
            .unwrap()
            .to_owned();
        let v: Value = r.json().await.unwrap();
        assert_eq!(v["must_change_password"], false);
        assert_ne!(v["csrf_token"].as_str().unwrap(), ocsrf);
        assert_eq!(
            call(
                "GET",
                "/api/v1/whoami".into(),
                olga.clone(),
                None,
                json!({})
            )
            .await
            .0,
            S::UNAUTHORIZED
        );
        assert_eq!(
            call(
                "GET",
                "/api/v1/status".into(),
                olga2.clone(),
                None,
                json!({})
            )
            .await
            .0,
            S::OK
        );

        // admins cannot lock themselves out
        let u = |n: &str| format!("/api/v1/users/{n}");
        for (m, path, body) in [
            ("PATCH", u("ada"), json!({ "role": "operator" })),
            ("DELETE", u("ada"), json!({})),
            (
                "POST",
                format!("{}/password", u("ada")),
                json!({ "password": "another long password" }),
            ),
        ] {
            let r = env
                .http
                .request(m.parse().unwrap(), format!("{}{path}", env.base))
                .header("cookie", &ada)
                .header("x-csrf-token", &csrf)
                .json(&body)
                .send()
                .await
                .unwrap();
            assert_eq!(r.status(), S::CONFLICT, "{m} {path}");
        }
        // role change applies at once
        let r = env
            .http
            .patch(format!("{}{}", env.base, u("olga")))
            .header("cookie", &ada)
            .header("x-csrf-token", &csrf)
            .json(&json!({ "role": "viewer" }))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::OK);
        let (_, v) = call(
            "GET",
            "/api/v1/whoami".into(),
            olga2.clone(),
            None,
            json!({}),
        )
        .await;
        assert_eq!(v["role"], "viewer");
        // reset: temporary again, sessions end
        let (st, v) = call(
            "POST",
            format!("{}/password", u("olga")),
            ada.clone(),
            Some(csrf.clone()),
            json!({ "password": "new temporary pass" }),
        )
        .await;
        assert_eq!((st, v["sessions_ended"].as_u64()), (S::OK, Some(1)));
        assert_eq!(
            call(
                "GET",
                "/api/v1/whoami".into(),
                olga2.clone(),
                None,
                json!({})
            )
            .await
            .0,
            S::UNAUTHORIZED
        );
        let (_, _, v) = login(&env, "olga", "new temporary pass").await;
        assert_eq!(v["must_change_password"], true);
        // delete
        let (st, v) = call(
            "DELETE",
            u("olga"),
            ada.clone(),
            Some(csrf.clone()),
            json!({}),
        )
        .await;
        assert_eq!((st, v["sessions_ended"].as_u64()), (S::OK, Some(1)));
        assert_eq!(
            call(
                "DELETE",
                u("olga"),
                ada.clone(),
                Some(csrf.clone()),
                json!({})
            )
            .await
            .0,
            S::NOT_FOUND
        );
        assert_eq!(
            call(
                "POST",
                format!("{}/password", u("nobody")),
                ada.clone(),
                Some(csrf.clone()),
                json!({ "password": "long enough password" })
            )
            .await
            .0,
            S::NOT_FOUND
        );

        // API tokens have no password to change
        let tok = env.token("adm", Role::Admin);
        let r = env
            .http
            .post(format!("{}{}", env.base, path()))
            .bearer_auth(&tok)
            .json(&pw("x", "long enough password"))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::BAD_REQUEST);

        // wrong current passwords are rate limited like logins
        for _ in 0..10 {
            call(
                "POST",
                path(),
                otto.clone(),
                Some(otto_csrf.clone()),
                pw("guess guess guess", "whatever whatever"),
            )
            .await;
        }
        let (st, _) = call(
            "POST",
            path(),
            otto.clone(),
            Some(otto_csrf.clone()),
            pw("operator password", "a fresh new password"),
        )
        .await;
        assert_eq!(st, S::TOO_MANY_REQUESTS);

        let (_, v) = env
            .call("GET", "/api/v1/audit?limit=100", &tok, json!({}))
            .await;
        let actions: Vec<_> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}:{}",
                    e["actor"].as_str().unwrap(),
                    e["action"].as_str().unwrap()
                )
            })
            .filter(|a| a.contains(":user."))
            .collect();
        assert_eq!(
            actions,
            [
                "ada:user.delete",
                "ada:user.password_reset",
                "ada:user.update",
                "olga:user.password_change",
                "ada:user.create"
            ]
        );
        assert!(
            !v.to_string().contains("temporary password"),
            "no passwords in the audit log"
        );
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn api_tokens_managed_in_the_ui() {
        let env = Env::new("tokens").await;
        files::create_user(&env.dir, "ada", Role::Admin, "correct horse battery").unwrap();
        files::create_user(&env.dir, "otto", Role::Operator, "operator password").unwrap();
        let (_, ada, v) = login(&env, "ada", "correct horse battery").await;
        let csrf = v["csrf_token"].as_str().unwrap().to_owned();
        let (_, otto, _) = login(&env, "otto", "operator password").await;
        let create = |body: Value| {
            let (env, ada, csrf) = (&env, ada.clone(), csrf.clone());
            async move { with_cookie(env, "POST", "/api/v1/api-tokens", &ada, Some(&csrf), body).await }
        };

        assert_eq!(
            with_cookie(&env, "GET", "/api/v1/api-tokens", &otto, None, json!({}))
                .await
                .0,
            S::FORBIDDEN
        );
        for (body, want) in [
            (
                json!({ "name": "bad name", "role": "viewer", "ttl": "90d" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "name": "ci", "role": "viewer", "ttl": "soon" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "name": "ci", "role": "viewer", "ttl": "3650d" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "name": "ci", "role": "viewer" }),
                S::UNPROCESSABLE_ENTITY,
            ),
            (
                json!({ "name": "otto", "role": "viewer", "ttl": "90d" }),
                S::CONFLICT,
            ),
        ] {
            assert_eq!(create(body.clone()).await.0, want, "{body}");
        }
        let (st, v) = create(json!({ "name": "ci", "role": "operator", "ttl": "90d" })).await;
        assert_eq!(st, S::CREATED, "{v}");
        let ci = v["token"].as_str().unwrap().to_owned();
        assert!(ci.starts_with("df2bapi1."));
        assert!(v["expires_at"].is_string());
        assert_eq!(
            create(json!({ "name": "ci", "role": "viewer", "ttl": "1d" }))
                .await
                .0,
            S::CONFLICT
        );
        let (_, v) = create(json!({ "name": "ops", "role": "admin", "ttl": "never" })).await;
        let ops = v["token"].as_str().unwrap().to_owned();
        assert!(v["expires_at"].is_null());

        // the new tokens work with their roles
        let (st, v) = env.call("GET", "/api/v1/whoami", &ci, json!({})).await;
        assert_eq!((st, v["role"].as_str()), (S::OK, Some("operator")));
        // ... but a token cannot create tokens
        let (st, v) = env
            .call(
                "POST",
                "/api/v1/api-tokens",
                &ops,
                json!({ "name": "x", "role": "admin", "ttl": "1d" }),
            )
            .await;
        assert_eq!(st, S::FORBIDDEN, "{v}");

        files::create_api_token(&env.dir, "old", Role::Viewer, Some(Duration::ZERO)).unwrap();
        let (_, v) = env.call("GET", "/api/v1/api-tokens", &ops, json!({})).await;
        let row = |n: &str| {
            v["tokens"]
                .as_array()
                .unwrap()
                .iter()
                .find(|t| t["name"] == n)
                .unwrap()
                .clone()
        };
        assert_eq!(row("ci")["created_by"], "ada");
        assert!(row("old")["created_by"].is_null(), "created on the host");
        assert_eq!(row("old")["expired"], true);
        assert_eq!(row("ops")["current"], true);
        assert!(row("ci")["last_used_at"].is_string() && row("old")["last_used_at"].is_null());
        assert_eq!(v["ca_fingerprint"].as_str().unwrap().len(), 64);
        let text = v.to_string();
        assert!(
            !text.contains(&ci[9..]) && !text.contains(&ops[9..]),
            "no secrets"
        );

        // revoke from the UI: effective at once
        let (st, _) = with_cookie(
            &env,
            "DELETE",
            "/api/v1/api-tokens/ci",
            &ada,
            None,
            json!({}),
        )
        .await;
        assert_eq!(st, S::FORBIDDEN, "CSRF");
        let (st, _) = with_cookie(
            &env,
            "DELETE",
            "/api/v1/api-tokens/ci",
            &ada,
            Some(&csrf),
            json!({}),
        )
        .await;
        assert_eq!(st, S::OK);
        assert_eq!(
            env.call("GET", "/api/v1/whoami", &ci, json!({})).await.0,
            S::UNAUTHORIZED
        );
        assert_eq!(
            with_cookie(
                &env,
                "DELETE",
                "/api/v1/api-tokens/ci",
                &ada,
                Some(&csrf),
                json!({})
            )
            .await
            .0,
            S::NOT_FOUND
        );
        // a token may revoke itself
        let r = env
            .http
            .delete(format!("{}/api/v1/api-tokens/ops", env.base))
            .bearer_auth(&ops)
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::OK);
        assert_eq!(
            env.call("GET", "/api/v1/whoami", &ops, json!({})).await.0,
            S::UNAUTHORIZED
        );

        let (_, v) = with_cookie(&env, "GET", "/api/v1/audit", &ada, None, json!({})).await;
        let actions: Vec<_> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| {
                format!(
                    "{}:{}:{}",
                    e["actor"].as_str().unwrap(),
                    e["action"].as_str().unwrap(),
                    e["details"]["token"].as_str().unwrap_or("")
                )
            })
            .filter(|a| a.contains(":token."))
            .collect();
        assert_eq!(
            actions,
            [
                "ops:token.revoke:ops",
                "ada:token.revoke:ci",
                "ada:token.create:ops",
                "ada:token.create:ci"
            ]
        );
        assert!(
            !v.to_string().contains("df2bapi1."),
            "no secrets in the audit log"
        );
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn allowlist_editing() {
        let env = Env::new("allow").await;
        let viewer = env.token("vic", Role::Viewer);
        let op = env.token("olga", Role::Operator);
        let admin = env.token("ada", Role::Admin);
        let add = |tok: &str, body: Value| {
            let (env, tok) = (&env, tok.to_owned());
            async move { env.call("POST", "/api/v1/allowlist", &tok, body).await }
        };
        let active = || {
            let env = &env;
            let op = op.clone();
            async move {
                let (_, v) = env.call("GET", "/api/v1/decisions", &op, json!({})).await;
                v["decisions"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|d| d["target"].as_str().unwrap().to_owned())
                    .collect::<Vec<_>>()
            }
        };

        let (st, v) = env
            .call("GET", "/api/v1/allowlist", &viewer, json!({}))
            .await;
        assert_eq!(st, S::OK);
        assert_eq!(
            (
                v["entries"][0]["net"].as_str(),
                v["entries"][0]["source"].as_str()
            ),
            (Some("10.0.0.0/8"), Some("command line"))
        );
        assert_eq!(
            add(&op, json!({ "net": "192.0.2.0/24" })).await.0,
            S::FORBIDDEN
        );

        for t in ["198.51.100.7", "198.51.100.128/25", "203.0.113.5"] {
            assert_eq!(
                env.call(
                    "POST",
                    "/api/v1/bans",
                    &op,
                    json!({ "target": t, "duration": "1h" })
                )
                .await
                .0,
                S::CREATED
            );
        }
        // adding lifts the bans it overlaps
        let (st, v) = add(
            &admin,
            json!({ "net": "198.51.100.77/24", "comment": "partner\u{1b}[31m NOC" }),
        )
        .await;
        assert_eq!(
            (st, v["net"].as_str(), v["unbanned"].as_u64()),
            (S::CREATED, Some("198.51.100.0/24"), Some(2))
        );
        assert_eq!(active().await, ["203.0.113.5/32"]);
        let (st, _) = env
            .call(
                "POST",
                "/api/v1/bans",
                &op,
                json!({ "target": "198.51.100.9" }),
            )
            .await;
        assert_eq!(st, S::CONFLICT, "now allowlisted");
        // ... unless asked not to
        let (_, v) = add(&admin, json!({ "net": "203.0.113.0/24", "unban": false })).await;
        assert_eq!(v["unbanned"], 0);
        assert_eq!(active().await, ["203.0.113.5/32"]);

        for (body, want) in [
            (json!({ "net": "198.51.100.0/24" }), S::CONFLICT),
            (json!({ "net": "198.51.100.64/26" }), S::CONFLICT),
            (json!({ "net": "10.1.0.0/16" }), S::CONFLICT),
            (json!({ "net": "0.0.0.0/4" }), S::BAD_REQUEST),
            (json!({ "net": "2001:db8::/8" }), S::BAD_REQUEST),
            (json!({ "net": "nope" }), S::BAD_REQUEST),
        ] {
            let (st, v) = add(&admin, body.clone()).await;
            assert_eq!(st, want, "{body} {v}");
        }

        let (_, v) = env
            .call("GET", "/api/v1/allowlist", &viewer, json!({}))
            .await;
        let e = &v["entries"];
        assert_eq!(e.as_array().unwrap().len(), 3);
        assert_eq!(
            (e[1]["net"].as_str(), e[1]["created_by"].as_str()),
            (Some("198.51.100.0/24"), Some("ada"))
        );
        assert_eq!(
            e[1]["comment"], "partner[31m NOC",
            "control characters removed"
        );
        assert_eq!(
            (e[2]["net"].as_str(), e[2]["active_bans"].as_u64()),
            (Some("203.0.113.0/24"), Some(1))
        );
        let (_, v) = env
            .call(
                "GET",
                "/api/v1/history?target=198.51.100.9",
                &viewer,
                json!({}),
            )
            .await;
        assert_eq!(v["allowlisted"], true);

        // removing
        let del = |net: &str| {
            let (env, admin) = (&env, admin.clone());
            let url = format!("{}/api/v1/allowlist", env.base);
            let net = net.to_owned();
            async move {
                env.http
                    .delete(url)
                    .query(&[("net", net)])
                    .bearer_auth(admin)
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        assert_eq!(del("10.0.0.0/8").await, S::CONFLICT, "command line entry");
        assert_eq!(del("198.51.100.0/24").await, S::OK);
        assert_eq!(del("198.51.100.0/24").await, S::NOT_FOUND);
        assert_eq!(
            env.call(
                "POST",
                "/api/v1/bans",
                &op,
                json!({ "target": "198.51.100.9" })
            )
            .await
            .0,
            S::CREATED
        );

        let (_, v) = env.call("GET", "/api/v1/audit", &admin, json!({})).await;
        let actions: Vec<_> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["action"].as_str().unwrap().starts_with("allowlist"))
            .map(|e| {
                format!(
                    "{} {} {}",
                    e["action"].as_str().unwrap(),
                    e["details"]["net"].as_str().unwrap(),
                    e["details"]["unbanned"]
                )
            })
            .collect();
        assert_eq!(
            actions,
            [
                "allowlist.remove 198.51.100.0/24 null",
                "allowlist.add 203.0.113.0/24 0",
                "allowlist.add 198.51.100.0/24 2"
            ]
        );
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn change_agent_group() {
        let env = Env::new("group").await;
        env.ctl
            .put_agent(crate::store::AgentRecord {
                id: "web-01-abc".into(),
                hostname: "web-01".into(),
                group: "web".into(),
                enrolled_at: Utc::now(),
                serials: vec![],
                cert_not_after: Utc::now(),
                resync: false,
            })
            .unwrap();
        let op = env.token("olga", Role::Operator);
        let admin = env.token("ada", Role::Admin);
        let patch = |tok: &str, id: &str, body: Value| {
            let (env, tok) = (&env, tok.to_owned());
            let url = format!("{}/api/v1/agents/{id}", env.base);
            async move {
                let r = env
                    .http
                    .patch(url)
                    .bearer_auth(tok)
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                (r.status(), r.json::<Value>().await.unwrap_or(Value::Null))
            }
        };
        assert_eq!(
            patch(&op, "web-01-abc", json!({ "group": "db" })).await.0,
            S::FORBIDDEN
        );
        for (body, want) in [
            (json!({ "group": "" }), S::BAD_REQUEST),
            (json!({ "group": "db servers" }), S::BAD_REQUEST),
            (json!({ "group": "../x" }), S::BAD_REQUEST),
            (
                json!({ "group": "db", "extra": 1 }),
                S::UNPROCESSABLE_ENTITY,
            ),
        ] {
            assert_eq!(
                patch(&admin, "web-01-abc", body.clone()).await.0,
                want,
                "{body}"
            );
        }
        assert_eq!(
            patch(&admin, "ghost", json!({ "group": "db" })).await.0,
            S::NOT_FOUND
        );

        let (st, v) = patch(&admin, "web-01-abc", json!({ "group": " db " })).await;
        assert_eq!(st, S::OK, "{v}");
        assert_eq!(
            (
                v["group"].as_str(),
                v["previous_group"].as_str(),
                v["changed"].as_bool()
            ),
            (Some("db"), Some("web"), Some(true))
        );
        let (_, v) = env
            .call("GET", "/api/v1/agents/web-01-abc", &op, json!({}))
            .await;
        assert_eq!(
            (v["agent"]["group"].as_str(), v["agent"]["resync"].as_bool()),
            (Some("db"), Some(true))
        );
        // unchanged: no audit entry
        let (_, v) = patch(&admin, "web-01-abc", json!({ "group": "db" })).await;
        assert_eq!(v["changed"], false);
        // revoked agents cannot be moved
        files::revoke(&env.dir, "web-01-abc").unwrap();
        assert_eq!(
            patch(&admin, "web-01-abc", json!({ "group": "web" }))
                .await
                .0,
            S::NOT_FOUND
        );

        let (_, v) = env.call("GET", "/api/v1/audit", &admin, json!({})).await;
        let entries: Vec<_> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["action"] == "agent.group")
            .collect();
        assert_eq!(entries.len(), 1);
        assert_eq!(
            (
                entries[0]["details"]["from"].as_str(),
                entries[0]["details"]["to"].as_str()
            ),
            (Some("web"), Some("db"))
        );
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn unban_and_allow_for() {
        let env = Env::new("allowfor").await;
        let op = env.token("olga", Role::Operator);
        let admin = env.token("ada", Role::Admin);
        let ban = |t: &str| {
            let (env, op, t) = (&env, op.clone(), t.to_owned());
            async move {
                env.call(
                    "POST",
                    "/api/v1/bans",
                    &op,
                    json!({ "target": t, "duration": "1h" }),
                )
                .await
                .0
            }
        };
        let unban = |tok: &str, body: Value| {
            let (env, tok) = (&env, tok.to_owned());
            async move { env.call("POST", "/api/v1/unban", &tok, body).await }
        };

        assert_eq!(ban("198.51.100.7").await, S::CREATED);
        let (st, v) = unban(
            &op,
            json!({ "target": "198.51.100.7", "allow_for": "24h", "reason": "false positive" }),
        )
        .await;
        assert_eq!(st, S::OK, "{v}");
        assert_eq!(v["unbans"].as_array().unwrap().len(), 1);
        let until: chrono::DateTime<Utc> = v["allowed_until"].as_str().unwrap().parse().unwrap();
        assert!(
            (until - Utc::now() - chrono::Duration::hours(24))
                .num_seconds()
                .abs()
                < 60
        );
        assert_eq!(v["already_allowlisted"], false);
        // cannot be banned again meanwhile
        assert_eq!(ban("198.51.100.7").await, S::CONFLICT);
        // shown on the allowlist as temporary
        let (_, v) = env.call("GET", "/api/v1/allowlist", &op, json!({})).await;
        let e = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .find(|e| e["net"] == "198.51.100.7/32")
            .unwrap()
            .clone();
        assert!(e["expires_at"].is_string());
        assert_eq!(
            (e["created_by"].as_str(), e["comment"].as_str()),
            (Some("olga"), Some("after unban: false positive"))
        );
        // asking again for less: nothing to do, not an error
        let (st, v) = unban(&op, json!({ "target": "198.51.100.7", "allow_for": "1h" })).await;
        assert_eq!(
            (
                st,
                v["already_allowlisted"].as_bool(),
                v["allowed_until"].is_null()
            ),
            (S::OK, Some(true), true)
        );
        // without allow_for, nothing to unban stays a 404
        assert_eq!(
            unban(&op, json!({ "target": "198.51.100.8" })).await.0,
            S::NOT_FOUND
        );

        // limits: operators 7 days, admins 30; small targets only
        for (tok, body, want) in [
            (
                &op,
                json!({ "target": "192.0.2.1", "allow_for": "8d" }),
                S::BAD_REQUEST,
            ),
            (
                &op,
                json!({ "target": "192.0.2.1", "allow_for": "10s" }),
                S::BAD_REQUEST,
            ),
            (
                &op,
                json!({ "target": "192.0.2.1", "allow_for": "soon" }),
                S::BAD_REQUEST,
            ),
            (
                &op,
                json!({ "target": "192.0.0.0/16", "allow_for": "1h" }),
                S::BAD_REQUEST,
            ),
            (
                &admin,
                json!({ "target": "192.0.2.1", "allow_for": "31d" }),
                S::BAD_REQUEST,
            ),
            (
                &admin,
                json!({ "target": "192.0.2.1", "allow_for": "30d" }),
                S::OK,
            ),
            (
                &op,
                json!({ "target": "2001:db8:1::/48", "allow_for": "7d" }),
                S::OK,
            ),
        ] {
            let (st, v) = unban(tok, body.clone()).await;
            assert_eq!(st, want, "{body} {v}");
        }
        // inside the fixed --allow 10.0.0.0/8: already allowed
        let (_, v) = unban(&op, json!({ "target": "10.1.2.3", "allow_for": "1h" })).await;
        assert_eq!(v["already_allowlisted"], true);

        // temporary entries from the allowlist itself (admin)
        let (st, v) = env
            .call(
                "POST",
                "/api/v1/allowlist",
                &admin,
                json!({ "net": "203.0.113.0/24", "ttl": "2h" }),
            )
            .await;
        assert_eq!(st, S::CREATED, "{v}");
        assert!(v["expires_at"].is_string());
        let (st, _) = env
            .call(
                "POST",
                "/api/v1/allowlist",
                &admin,
                json!({ "net": "203.0.114.0/24", "ttl": "60d" }),
            )
            .await;
        assert_eq!(st, S::BAD_REQUEST);
        // made permanent: replaces the temporary entry
        let (st, v) = env
            .call(
                "POST",
                "/api/v1/allowlist",
                &admin,
                json!({ "net": "203.0.113.0/24" }),
            )
            .await;
        assert_eq!((st, v["expires_at"].is_null()), (S::CREATED, true));

        let (_, v) = env.call("GET", "/api/v1/audit", &admin, json!({})).await;
        let first_unban = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .rev()
            .find(|e| e["action"] == "unban")
            .unwrap()
            .clone();
        assert!(first_unban["details"]["allowed_until"].is_string());
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn policies_and_jail_settings() {
        let env = Env::new("policies").await;
        env.ctl
            .put_agent(crate::store::AgentRecord {
                id: "web-01-abc".into(),
                hostname: "web-01".into(),
                group: "web".into(),
                enrolled_at: Utc::now(),
                serials: vec![],
                cert_not_after: Utc::now(),
                resync: false,
            })
            .unwrap();
        env.ctl.update_status("web-01-abc", |s| {
            s.jails = vec![crate::state::JailView {
                name: "sshd".into(),
                filter: "sshd".into(),
                enabled: true,
                maxretry: 5,
                findtime_secs: 600,
                bantime_secs: 3600,
                bantime_factor: 2.0,
                ..Default::default()
            }];
        });
        let viewer = env.token("vic", Role::Viewer);
        let admin = env.token("ada", Role::Admin);
        let put = |tok: &str, path: &str, body: Value| {
            let (env, tok, url) = (&env, tok.to_owned(), format!("{}{path}", env.base));
            async move {
                let r = env
                    .http
                    .put(url)
                    .bearer_auth(tok)
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                (r.status(), r.json::<Value>().await.unwrap_or(Value::Null))
            }
        };

        let (st, v) = env
            .call("GET", "/api/v1/policies", &viewer, json!({}))
            .await;
        assert_eq!(st, S::OK);
        assert_eq!(
            (v["propagate"].as_str(), v["groups"][0].as_str()),
            (Some("global"), Some("web"))
        );
        assert_eq!(v["jails"][0]["name"], "sshd");
        assert_eq!(v["jails"][0]["agents"][0]["jail"]["maxretry"], 5);

        // ban propagation
        assert_eq!(
            put(
                &viewer,
                "/api/v1/policies/propagate",
                json!({ "propagate": "off" })
            )
            .await
            .0,
            S::FORBIDDEN
        );
        assert_eq!(
            put(
                &admin,
                "/api/v1/policies/propagate",
                json!({ "propagate": "sometimes" })
            )
            .await
            .0,
            S::UNPROCESSABLE_ENTITY
        );
        let (st, v) = put(
            &admin,
            "/api/v1/policies/propagate",
            json!({ "propagate": "group" }),
        )
        .await;
        assert_eq!((st, v["previous"].as_str()), (S::OK, Some("global")));
        assert_eq!(env.ctl.propagate(), crate::state::Propagate::Group);

        // jail settings
        assert_eq!(
            put(
                &viewer,
                "/api/v1/jails/sshd/policy",
                json!({ "maxretry": 3 })
            )
            .await
            .0,
            S::FORBIDDEN
        );
        for (path, body) in [
            ("/api/v1/jails/sshd/policy", json!({ "maxretry": 0 })),
            ("/api/v1/jails/sshd/policy", json!({ "bantime": "10s" })),
            (
                "/api/v1/jails/sshd/policy",
                json!({ "bantime": "2h", "max_bantime": "1h" }),
            ),
            (
                "/api/v1/jails/sshd/policy",
                json!({ "bantime_factor": 50.0 }),
            ),
            ("/api/v1/jails/sshd/policy", json!({ "findtime": "soon" })),
            ("/api/v1/jails/a%20b/policy", json!({ "maxretry": 3 })),
            (
                "/api/v1/jails/sshd/policy",
                json!({ "group": "a b", "maxretry": 3 }),
            ),
        ] {
            let (st, v) = put(&admin, path, body.clone()).await;
            assert_eq!(st, S::BAD_REQUEST, "{path} {body} {v}");
        }
        let (st, v) = put(
            &admin,
            "/api/v1/jails/sshd/policy",
            json!({ "maxretry": 3, "bantime": "2h" }),
        )
        .await;
        assert_eq!((st, v["previous"].is_null()), (S::OK, true));
        let (st, _) = put(
            &admin,
            "/api/v1/jails/sshd/policy",
            json!({ "group": "web", "enabled": false }),
        )
        .await;
        assert_eq!(st, S::OK);
        // replacing: fields not given are no longer overridden
        let (_, v) = put(
            &admin,
            "/api/v1/jails/sshd/policy",
            json!({ "maxretry": 4 }),
        )
        .await;
        assert_eq!(v["previous"]["maxretry"], 3);
        let merged = crate::policy::merged(&env.ctl.jail_overrides(), "web");
        assert_eq!(merged[0].1.maxretry, Some(4));
        assert_eq!(merged[0].1.bantime, None);
        assert_eq!(merged[0].1.enabled, Some(false));
        let (_, v) = env
            .call("GET", "/api/v1/policies", &viewer, json!({}))
            .await;
        assert_eq!(v["jails"][0]["overrides"].as_array().unwrap().len(), 2);
        // a jail no agent has yet can be configured too
        assert_eq!(
            put(
                &admin,
                "/api/v1/jails/nginx-auth/policy",
                json!({ "bantime": "1d" })
            )
            .await
            .0,
            S::OK
        );

        // removing
        let del = |q: &str| {
            let (env, admin, url) = (
                &env,
                admin.clone(),
                format!("{}/api/v1/jails/sshd/policy{q}", env.base),
            );
            async move {
                env.http
                    .delete(url)
                    .bearer_auth(admin)
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        assert_eq!(del("?group=web").await, S::OK);
        assert_eq!(del("?group=web").await, S::NOT_FOUND);
        assert_eq!(del("").await, S::OK);
        assert_eq!(env.ctl.jail_overrides().len(), 1, "only nginx-auth is left");

        let (_, v) = env.call("GET", "/api/v1/audit", &admin, json!({})).await;
        let actions: Vec<_> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["action"].as_str().unwrap().to_owned())
            .filter(|a| a.starts_with("jail.") || a.starts_with("policy."))
            .collect();
        assert_eq!(
            actions,
            [
                "jail.policy_remove",
                "jail.policy_remove",
                "jail.policy",
                "jail.policy",
                "jail.policy",
                "jail.policy",
                "policy.propagate"
            ]
        );
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn central_filters_and_jail_definitions() {
        let env = Env::new("central").await;
        let viewer = env.token("vic", Role::Viewer);
        let admin = env.token("ada", Role::Admin);
        let put = |tok: &str, path: &str, body: Value| {
            let (env, tok, url) = (&env, tok.to_owned(), format!("{}{path}", env.base));
            async move {
                let r = env
                    .http
                    .put(url)
                    .bearer_auth(tok)
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                (r.status(), r.json::<Value>().await.unwrap_or(Value::Null))
            }
        };
        let del = |path: &str| {
            let (env, admin, url) = (&env, admin.clone(), format!("{}{path}", env.base));
            async move {
                env.http
                    .delete(url)
                    .bearer_auth(admin)
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        let toml = "literals = ['login failed']\nfailregex = ['login failed for \\S+ from <HOST>']";

        // filters
        assert_eq!(
            put(&viewer, "/api/v1/filters/app-auth", json!({ "toml": toml }))
                .await
                .0,
            S::FORBIDDEN
        );
        let (st, v) = put(
            &admin,
            "/api/v1/filters/app-auth",
            json!({ "toml": "failregex = ['no tag']" }),
        )
        .await;
        assert_eq!(st, S::BAD_REQUEST);
        assert!(v["error"].as_str().unwrap().contains("HOST"), "{v}");
        let (st, v) = put(&admin, "/api/v1/filters/app-auth", json!({ "toml": toml })).await;
        assert_eq!((st, v["replaced"].as_bool()), (S::OK, Some(false)));
        // try it on sample lines (viewers may test)
        let (st, v) = env.call("POST", "/api/v1/filters/test", &viewer, json!({
            "toml": toml,
            "lines": ["login failed for bob from 192.0.2.7", "login ok for bob from 192.0.2.8", "login failed for eve from 2001:db8::9"],
        })).await;
        assert_eq!((st, v["matched"].as_u64()), (S::OK, Some(2)), "{v}");
        assert_eq!(
            (
                v["matches"][0]["line"].as_u64(),
                v["matches"][0]["ip"].as_str()
            ),
            (Some(1), Some("192.0.2.7"))
        );
        assert_eq!(v["matches"][1]["ip"], "2001:db8::9");

        // jail definitions
        let good = json!({
            "filter": "app-auth",
            "sources": [{ "type": "file", "paths": ["/var/log/app/auth.log"], "start_at_end": true },
                        { "type": "journald", "matches": ["_SYSTEMD_UNIT=app.service"], "start": "10m" }],
            "maxretry": 3, "findtime": "10m", "bantime": "1h", "bantime_factor": 2.0,
        });
        assert_eq!(
            put(&viewer, "/api/v1/jail-definitions/app", good.clone())
                .await
                .0,
            S::FORBIDDEN
        );
        for (what, patch) in [
            (
                "dotdot",
                json!({ "sources": [{ "type": "file", "paths": ["/var/log/../etc/shadow"] }] }),
            ),
            (
                "relative",
                json!({ "sources": [{ "type": "file", "paths": ["app.log"] }] }),
            ),
            ("no sources", json!({ "sources": [] })),
            (
                "match",
                json!({ "sources": [{ "type": "journald", "matches": ["not a match"] }] }),
            ),
            ("maxretry", json!({ "maxretry": 0 })),
            ("bantime", json!({ "bantime": "5s" })),
            ("group", json!({ "group": "a b" })),
        ] {
            let mut body = good.clone();
            for (k, v) in patch.as_object().unwrap() {
                body[k] = v.clone();
            }
            let (st, v) = put(&admin, "/api/v1/jail-definitions/app", body).await;
            assert_eq!(st, S::BAD_REQUEST, "{what}: {v}");
        }
        let (st, v) = put(&admin, "/api/v1/jail-definitions/app", good.clone()).await;
        assert_eq!(
            (st, v["filter_is_central"].as_bool()),
            (S::OK, Some(true)),
            "{v}"
        );
        // an agent-local filter is allowed (the agent reports if it lacks it)
        let mut web = good.clone();
        web["group"] = json!("web");
        web["filter"] = json!("sshd");
        let (_, v) = put(&admin, "/api/v1/jail-definitions/app", web).await;
        assert_eq!(v["filter_is_central"], false);

        let (_, v) = env
            .call("GET", "/api/v1/jail-definitions", &viewer, json!({}))
            .await;
        let defs = v["definitions"].as_array().unwrap();
        assert_eq!(defs.len(), 2);
        assert_eq!(
            (defs[0]["group"].is_null(), defs[0]["findtime"].as_str()),
            (true, Some("10m"))
        );
        let (_, v) = env.call("GET", "/api/v1/filters", &viewer, json!({})).await;
        assert_eq!(v["filters"][0]["used_by"], json!(["app"]));
        let (_, v) = env
            .call("GET", "/api/v1/policies", &viewer, json!({}))
            .await;
        assert_eq!(
            v["jails"][0]["name"], "app",
            "defined jails appear in the inventory"
        );

        // a filter in use cannot be deleted
        assert_eq!(del("/api/v1/filters/app-auth").await, S::CONFLICT);
        assert_eq!(del("/api/v1/jail-definitions/app").await, S::OK);
        assert_eq!(del("/api/v1/jail-definitions/app").await, S::NOT_FOUND);
        assert_eq!(del("/api/v1/jail-definitions/app?group=web").await, S::OK);
        assert_eq!(del("/api/v1/filters/app-auth").await, S::OK);
        assert_eq!(del("/api/v1/filters/app-auth").await, S::NOT_FOUND);

        let (_, v) = env.call("GET", "/api/v1/audit", &admin, json!({})).await;
        let actions: Vec<_> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| e["action"].as_str().unwrap().to_owned())
            .filter(|a| a.starts_with("filter.") || a.starts_with("jail."))
            .collect();
        assert_eq!(
            actions,
            [
                "filter.remove",
                "jail.undefine",
                "jail.undefine",
                "jail.define",
                "jail.define",
                "filter.set"
            ]
        );
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn sample_redaction_rules() {
        let env = Env::new("redact").await;
        let viewer = env.token("vic", Role::Viewer);
        let op = env.token("olga", Role::Operator);
        let admin = env.token("ada", Role::Admin);
        let send = |method: &'static str, tok: &str, path: &str, body: Value| {
            let (env, tok, url) = (&env, tok.to_owned(), format!("{}{path}", env.base));
            async move {
                let req = match method {
                    "PUT" => env.http.put(url).json(&body),
                    _ => env.http.delete(url),
                };
                let r = req.bearer_auth(tok).send().await.unwrap();
                (r.status(), r.json::<Value>().await.unwrap_or(Value::Null))
            }
        };
        // a line kept before any rule (memory and database)
        let key: IpNet = "203.0.113.4/32".parse().unwrap();
        env.ctl.correlator.lock().unwrap().record(
            "sshd",
            key,
            crate::correlation::Seen {
                agent: "web-1".into(),
                group: "web".into(),
                at: Utc::now(),
                failures: 1,
                banned: false,
                sample: Some("Failed password for alice from 203.0.113.4 port 22".into()),
            },
        );
        env.ctl.flush_observations();

        let (st, v) = env
            .call("GET", "/api/v1/redaction", &viewer, json!({}))
            .await;
        assert_eq!(st, S::OK);
        assert_eq!(v["rules"], json!([]));
        assert_eq!(v["presets"][0]["name"], "ssh-user");
        assert_eq!(v["version"], json!(env.ctl.redaction_version()));
        assert_eq!(
            v["agents"],
            json!({ "connected": 0, "current": 0, "off": 0 })
        );
        let rule = json!({ "pattern": r"(for )\S+( from)", "replace": "${1}[user]${2}" });
        assert_eq!(
            send("PUT", &op, "/api/v1/redaction/ssh-user", rule.clone())
                .await
                .0,
            S::FORBIDDEN
        );
        for (name, body, want) in [
            ("bad name", rule.clone(), "rule name"),
            ("x", json!({ "pattern": "(" }), "invalid pattern"),
            ("x", json!({ "pattern": "a*" }), "empty string"),
        ] {
            let (st, v) = send("PUT", &admin, &format!("/api/v1/redaction/{name}"), body).await;
            assert_eq!(st, S::BAD_REQUEST, "{v}");
            assert!(v["error"].as_str().unwrap().contains(want), "{v}");
        }

        // preview (not stored), with the stability check
        let (_, v) = env
            .call(
                "POST",
                "/api/v1/redaction/test",
                &viewer,
                json!({ "pattern": r"(for )\S+( from)", "replace": "${1}[user]${2}", "lines": ["Failed password for bob from x"] }),
            )
            .await;
        assert_eq!(
            v["results"][0],
            json!({ "line": "Failed password for [user] from x", "stable": true })
        );
        let (_, v) = env
            .call(
                "POST",
                "/api/v1/redaction/test",
                &viewer,
                json!({ "pattern": "x", "replace": "xx", "lines": ["x"] }),
            )
            .await;
        assert_eq!(v["results"][0]["stable"], false);

        let (st, v) = send("PUT", &admin, "/api/v1/redaction/ssh-user", rule).await;
        assert_eq!(st, S::OK, "{v}");
        assert_eq!(
            (v["replaced"].as_bool(), v["lines_redacted"].as_u64()),
            (Some(false), Some(2)),
            "the kept line, in memory and in the database"
        );
        let (_, v) = env
            .call(
                "GET",
                "/api/v1/history?target=203.0.113.4",
                &viewer,
                json!({}),
            )
            .await;
        assert_eq!(
            v["samples"][0]["line"],
            "Failed password for [user] from 203.0.113.4 port 22"
        );
        let stored = env
            .ctl
            .store
            .observations(Utc::now() - chrono::Duration::hours(1))
            .unwrap();
        assert_eq!(
            stored[0].sample.as_deref(),
            Some("Failed password for [user] from 203.0.113.4 port 22")
        );
        // without a pattern the test applies the current rules
        let (_, v) = env
            .call(
                "POST",
                "/api/v1/redaction/test",
                &viewer,
                json!({ "lines": ["Failed password for root from y"] }),
            )
            .await;
        assert_eq!(v["results"][0]["line"], "Failed password for [user] from y");

        // disabled, then removed; audited
        let (_, v) = send(
            "PUT",
            &admin,
            "/api/v1/redaction/ssh-user",
            json!({ "pattern": "for", "enabled": false }),
        )
        .await;
        assert_eq!(v["replaced"], true);
        let (_, v) = env
            .call("GET", "/api/v1/redaction", &viewer, json!({}))
            .await;
        assert_eq!(
            (
                v["rules"][0]["enabled"].as_bool(),
                v["rules"][0]["replace"].as_str()
            ),
            (Some(false), Some("[redacted]"))
        );
        assert_eq!(
            send("DELETE", &admin, "/api/v1/redaction/ssh-user", json!({}))
                .await
                .0,
            S::OK
        );
        assert_eq!(
            send("DELETE", &admin, "/api/v1/redaction/ssh-user", json!({}))
                .await
                .0,
            S::NOT_FOUND
        );
        let (_, v) = env.call("GET", "/api/v1/audit", &admin, json!({})).await;
        let actions: Vec<&str> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter_map(|e| e["action"].as_str())
            .filter(|a| a.starts_with("redaction."))
            .collect();
        assert_eq!(
            actions,
            ["redaction.remove", "redaction.set", "redaction.set"]
        );
    }

    #[tokio::test]
    async fn correlation_rule_management() {
        let env = Env::new("corr").await;
        let viewer = env.token("vic", Role::Viewer);
        let admin = env.token("ada", Role::Admin);
        let put = |tok: &str, path: &str, body: Value| {
            let (env, tok, url) = (&env, tok.to_owned(), format!("{}{path}", env.base));
            async move {
                let r = env
                    .http
                    .put(url)
                    .bearer_auth(tok)
                    .json(&body)
                    .send()
                    .await
                    .unwrap();
                (r.status(), r.json::<Value>().await.unwrap_or(Value::Null))
            }
        };
        let good = json!({ "kind": "threshold", "jail": "sshd", "min_agents": 3, "min_failures": 10, "window": "10m", "bantime": "1h" });
        assert_eq!(
            put(&viewer, "/api/v1/correlation/slow", good.clone())
                .await
                .0,
            S::FORBIDDEN
        );
        for (what, patch) in [
            (
                "quorum of one",
                json!({ "kind": "quorum", "min_agents": 1 }),
            ),
            ("no failures", json!({ "min_failures": 0 })),
            ("window", json!({ "window": "3d" })),
            ("bantime", json!({ "bantime": "1s" })),
            ("kind", json!({ "kind": "magic" })),
            ("group", json!({ "group": "a b" })),
        ] {
            let mut body = good.clone();
            for (k, v) in patch.as_object().unwrap() {
                body[k] = v.clone();
            }
            let st = put(&admin, "/api/v1/correlation/slow", body).await.0;
            assert!(
                st == S::BAD_REQUEST || st == S::UNPROCESSABLE_ENTITY,
                "{what}: {st}"
            );
        }
        assert_eq!(
            put(&admin, "/api/v1/correlation/bad%20name", good.clone())
                .await
                .0,
            S::BAD_REQUEST
        );
        let (st, v) = put(&admin, "/api/v1/correlation/slow", good.clone()).await;
        assert_eq!((st, v["replaced"].as_bool()), (S::OK, Some(false)));
        let mut q = json!({ "kind": "quorum", "min_agents": 2, "window": "30m", "bantime": "6h", "monitor": true, "group": "web" });
        assert_eq!(
            put(&admin, "/api/v1/correlation/agree", q.clone()).await.0,
            S::OK
        );
        q["monitor"] = json!(false);
        assert_eq!(
            put(&admin, "/api/v1/correlation/agree", q).await.1["replaced"],
            true
        );

        let (st, v) = env
            .call("GET", "/api/v1/correlation", &viewer, json!({}))
            .await;
        assert_eq!(st, S::OK);
        let rules = v["rules"].as_array().unwrap();
        assert_eq!(
            rules
                .iter()
                .map(|r| r["name"].as_str().unwrap())
                .collect::<Vec<_>>(),
            ["agree", "slow"]
        );
        assert_eq!(
            (
                rules[0]["window"].as_str(),
                rules[0]["monitor"].as_bool(),
                rules[0]["group"].as_str()
            ),
            (Some("30m"), Some(false), Some("web"))
        );
        assert_eq!(rules[1]["jail"], "sshd");

        // observations show on the address page
        env.ctl.correlator.lock().unwrap().record(
            "sshd",
            "203.0.113.4/32".parse().unwrap(),
            crate::correlation::Seen {
                agent: "web-1".into(),
                group: "web".into(),
                at: Utc::now(),
                failures: 3,
                banned: false,
                sample: Some("sshd[1]: Failed password for root from 203.0.113.4".into()),
            },
        );
        let (_, v) = env
            .call(
                "GET",
                "/api/v1/history?target=203.0.113.0/24",
                &viewer,
                json!({}),
            )
            .await;
        assert_eq!(
            (
                v["observations"][0]["agent"].as_str(),
                v["observations"][0]["failures"].as_u64()
            ),
            (Some("web-1"), Some(3))
        );
        assert_eq!(
            (
                v["samples"][0]["agent"].as_str(),
                v["samples"][0]["line"].as_str()
            ),
            (
                Some("web-1"),
                Some("sshd[1]: Failed password for root from 203.0.113.4")
            )
        );

        let del = |n: &str| {
            let (env, admin, url) = (
                &env,
                admin.clone(),
                format!("{}/api/v1/correlation/{n}", env.base),
            );
            async move {
                env.http
                    .delete(url)
                    .bearer_auth(admin)
                    .send()
                    .await
                    .unwrap()
                    .status()
            }
        };
        assert_eq!(del("slow").await, S::OK);
        assert_eq!(del("slow").await, S::NOT_FOUND);
        let (_, v) = env.call("GET", "/api/v1/audit", &admin, json!({})).await;
        let n = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .filter(|e| e["action"].as_str().unwrap().starts_with("correlation."))
            .count();
        assert_eq!(n, 4);
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn login_rate_limit_and_ui_headers() {
        let env = Env::new("limit").await;
        files::create_user(&env.dir, "ada", Role::Admin, "correct horse battery").unwrap();
        for _ in 0..10 {
            assert_eq!(
                login(&env, "ada", "wrong password!!").await.0,
                S::UNAUTHORIZED
            );
        }
        // the right password does not help any more
        let (st, cookie, _) = login(&env, "ada", "correct horse battery").await;
        assert_eq!((st, cookie.as_str()), (S::TOO_MANY_REQUESTS, ""));

        // UI and security headers
        let r = env.http.get(format!("{}/", env.base)).send().await.unwrap();
        assert_eq!(r.status(), S::OK);
        assert!(r.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/html"));
        let csp = r.headers()["content-security-policy"].to_str().unwrap();
        assert!(csp.contains("script-src 'self'") && csp.contains("frame-ancestors 'none'"));
        assert_eq!(r.headers()["x-content-type-options"], "nosniff");
        let r = env
            .http
            .get(format!("{}/api/v1/nope", env.base))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::NOT_FOUND);
        assert_eq!(r.headers()["cache-control"], "no-store");
        let r = env
            .http
            .get(format!("{}/assets/missing.js", env.base))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::NOT_FOUND);
        let _ = std::fs::remove_dir_all(&env.dir);
    }

    #[tokio::test]
    async fn geoip_in_responses() {
        use crate::geo::testdb::{asn, build, country};
        let dbdir = std::env::temp_dir().join(format!("df2b-api-geodb-{}", std::process::id()));
        std::fs::create_dir_all(&dbdir).unwrap();
        let (a, c) = (dbdir.join("asn.mmdb"), dbdir.join("country.mmdb"));
        std::fs::write(
            &a,
            build(
                "GeoLite2-ASN",
                vec![
                    ("203.0.113.0/24", asn(64500, "Example Hosting")),
                    ("198.51.100.0/24", asn(64501, "Example ISP")),
                ],
            ),
        )
        .unwrap();
        std::fs::write(
            &c,
            build(
                "GeoLite2-Country",
                vec![
                    ("203.0.113.0/24", country("DE", "Germany")),
                    ("198.51.100.0/24", country("DE", "Germany")),
                ],
            ),
        )
        .unwrap();
        let env = Env::with_geo("geo", crate::geo::Geo::open(&[a, c]).unwrap()).await;
        let op = env.token("olga", Role::Operator);
        for t in ["203.0.113.9", "203.0.113.10", "198.51.100.1", "192.0.2.1"] {
            let (st, v) = env
                .call("POST", "/api/v1/bans", &op, json!({ "target": t }))
                .await;
            assert_eq!(st, S::CREATED, "{v}");
        }
        let (_, v) = env.call("GET", "/api/v1/decisions", &op, json!({})).await;
        assert_eq!(v["geo"]["203.0.113.9/32"]["asn"], 64500);
        assert_eq!(v["geo"]["203.0.113.9/32"]["country"], "DE");
        assert_eq!(v["geo"]["198.51.100.1/32"]["as_org"], "Example ISP");
        assert!(v["geo"]["192.0.2.1/32"].is_null(), "unknown: left out");

        let (_, v) = env.call("GET", "/api/v1/stats", &op, json!({})).await;
        assert_eq!(v["geoip"], true);
        assert_eq!(
            v["top_asns"],
            json!([
                { "asn": 64500, "org": "Example Hosting", "count": 2 },
                { "asn": 64501, "org": "Example ISP", "count": 1 },
            ])
        );
        assert_eq!(
            v["top_countries"],
            json!([{ "country": "DE", "name": "Germany", "count": 3 }])
        );

        let (_, v) = env
            .call(
                "GET",
                "/api/v1/history?target=203.0.113.0/24",
                &op,
                json!({}),
            )
            .await;
        assert_eq!(v["geo"]["as_org"], "Example Hosting");
        let (_, v) = env.call("GET", "/api/v1/status", &op, json!({})).await;
        assert_eq!(v["geoip"][0]["database_type"], "GeoLite2-ASN");
        assert_eq!(v["geoip"][1]["database_type"], "GeoLite2-Country");

        // without databases: nothing, and no errors
        let plain = Env::new("nogeo").await;
        let op = plain.token("olga", Role::Operator);
        plain
            .call(
                "POST",
                "/api/v1/bans",
                &op,
                json!({ "target": "203.0.113.9" }),
            )
            .await;
        let (_, v) = plain.call("GET", "/api/v1/stats", &op, json!({})).await;
        assert_eq!(
            (v["geoip"].as_bool(), v["top_asns"].as_array().map(Vec::len)),
            (Some(false), Some(0))
        );
        let (_, v) = plain.call("GET", "/api/v1/decisions", &op, json!({})).await;
        assert_eq!(v["geo"], json!({}));
        let _ = std::fs::remove_dir_all(&dbdir);
    }

    #[tokio::test]
    async fn ban_unban_and_audit() {
        let env = Env::new("ban").await;
        let op = env.token("olga", Role::Operator);
        let admin = env.token("ada", Role::Admin);

        let (st, v) = env
            .call(
                "POST",
                "/api/v1/bans",
                &op,
                json!({ "target": "203.0.113.0/24", "duration": "1h", "reason": "scanner" }),
            )
            .await;
        assert_eq!(st, S::CREATED, "{v}");
        let d = &v["decision"];
        assert_eq!(
            (d["seq"].as_u64(), d["origin"]["value"].as_str()),
            (Some(1), Some("olga"))
        );
        // same ban again: covered, nothing new
        let (st, v) = env
            .call(
                "POST",
                "/api/v1/bans",
                &op,
                json!({ "target": "203.0.113.0/24", "duration": "30m" }),
            )
            .await;
        assert_eq!((st, v["decision"].is_null()), (S::OK, true));
        let (st, _) = env
            .call(
                "POST",
                "/api/v1/bans",
                &op,
                json!({ "target": "2001:db8::1", "scope": "group:web" }),
            )
            .await;
        assert_eq!(st, S::CREATED);

        for (body, want) in [
            (json!({ "target": "0.0.0.0/1" }), S::BAD_REQUEST),
            (json!({ "target": "10.1.2.3" }), S::CONFLICT),
            (json!({ "target": "nope" }), S::BAD_REQUEST),
            (
                json!({ "target": "192.0.2.1", "scope": "planet" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "target": "192.0.2.1", "scope": "agent:ghost" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "target": "192.0.2.1", "duration": "soon" }),
                S::BAD_REQUEST,
            ),
            (
                json!({ "target": "192.0.2.1", "bogus": 1 }),
                S::UNPROCESSABLE_ENTITY,
            ),
        ] {
            assert_eq!(
                env.call("POST", "/api/v1/bans", &op, body.clone()).await.0,
                want,
                "{body}"
            );
        }

        let (_, v) = env
            .call(
                "GET",
                "/api/v1/decisions?target=203.0.113.77",
                &op,
                json!({}),
            )
            .await;
        assert_eq!(v["decisions"].as_array().unwrap().len(), 1);
        let (_, v) = env.call("GET", "/api/v1/decisions", &op, json!({})).await;
        assert_eq!(v["decisions"].as_array().unwrap().len(), 2);

        // unbanning one address removes the /24 that contains it
        let (st, v) = env
            .call(
                "POST",
                "/api/v1/unban",
                &op,
                json!({ "target": "203.0.113.77", "reason": "false positive" }),
            )
            .await;
        assert_eq!(st, S::OK, "{v}");
        let u = &v["unbans"][0];
        assert_eq!(
            (u["target"].as_str(), u["kind"]["kind"].as_str()),
            (Some("203.0.113.0/24"), Some("unban"))
        );
        let (st, _) = env
            .call(
                "POST",
                "/api/v1/unban",
                &op,
                json!({ "target": "203.0.113.77" }),
            )
            .await;
        assert_eq!(st, S::NOT_FOUND);
        let (_, v) = env.call("GET", "/api/v1/decisions", &op, json!({})).await;
        assert_eq!(v["decisions"].as_array().unwrap().len(), 1);

        let (st, v) = env
            .call("GET", "/api/v1/audit?limit=10", &admin, json!({}))
            .await;
        assert_eq!(st, S::OK);
        let actions: Vec<(&str, &str)> = v["entries"]
            .as_array()
            .unwrap()
            .iter()
            .map(|e| (e["actor"].as_str().unwrap(), e["action"].as_str().unwrap()))
            .collect();
        assert_eq!(
            actions,
            [("olga", "unban"), ("olga", "ban"), ("olga", "ban")]
        );
        assert!(v["entries"][0]["remote_addr"]
            .as_str()
            .unwrap()
            .starts_with("127.0.0.1:"));
        let _ = std::fs::remove_dir_all(&env.dir);
    }
}

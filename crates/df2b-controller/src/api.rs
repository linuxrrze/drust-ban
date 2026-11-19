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
                Some(f) => Ok(Caller {
                    name: f.name,
                    role: f.role,
                    addr,
                    auth: Auth::Token(token),
                    must_change_password: false,
                }),
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
        .route(
            "/api/v1/users/:name",
            axum::routing::patch(update_user).delete(delete_user),
        )
        .route("/api/v1/users/:name/password", post(reset_password))
        .route("/api/v1/sessions/:id", axum::routing::delete(end_session))
        .route("/api/v1/oidc/login", get(oidc_login))
        .route("/api/v1/oidc/callback", get(oidc_callback))
        .route(crate::oidc::BACKCHANNEL_PATH, post(oidc_backchannel_logout))
        .route("/api/v1/whoami", get(whoami))
        .route("/api/v1/status", get(status))
        .route("/api/v1/stats", get(stats))
        .route("/api/v1/events", get(events))
        .route("/api/v1/history", get(history))
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/agents/:id", get(agent))
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
    })))
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
        "allowlisted": ctl.settings.allowlist.overlaps(&net),
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
        "propagate": ctl.settings.propagate,
        "allowlist": ctl.settings.allowlist.iter().collect::<Vec<_>>(),
        "sessions": ctl.sessions.count(),
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
    Ok(Json(json!({ "decisions": list })))
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
    if ctl.settings.allowlist.overlaps(&net) {
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
}

async fn unban(
    caller: Caller,
    State(ctl): State<Arc<Controller>>,
    Json(req): Json<UnbanRequest>,
) -> ApiResult {
    caller.require(Role::Operator)?;
    let net = target(&req.target)?;
    let reason = req.reason.unwrap_or_else(|| "manual unban".into());
    let c = ctl.clone();
    let revoked = blocking(move || {
        let revoked = c.unban(net, caller.origin(), &reason)?;
        if !revoked.is_empty() {
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
                json!({ "target": net, "revoked": ids, "reason": reason }),
            )?;
        }
        Ok(revoked)
    })
    .await?;
    if revoked.is_empty() {
        return Err(ApiError::not_found(format!("no active ban overlaps {net}")));
    }
    let list: Vec<_> = revoked.iter().map(|d| &**d).collect();
    Ok(Json(json!({ "unbans": list })))
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
    }

    impl Env {
        async fn new(tag: &str) -> Self {
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
            };
            let ctl = Arc::new(Controller::open(settings, ca, Store::open(&dir).unwrap()).unwrap());
            let (chain, key) = ctl.ca.issue_server(&[]).unwrap();
            let tls = https_server_config(chain, key).unwrap();
            let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let base = format!("https://{}", l.local_addr().unwrap());
            tokio::spawn(crate::https::serve(
                l,
                tls,
                router(ctl),
                std::future::pending(),
            ));
            let http = client(Trust::PinnedCa(fp));
            Self { base, http, dir }
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

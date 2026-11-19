//! REST API (`/api/v1`), served over HTTPS only (see https.rs).
//!
//! Authentication: `Authorization: Bearer df2bapi1.<secret>`. Tokens are
//! created with `df2b-controller api-token create --name <n> --role <r>`;
//! roles are `viewer` < `operator` (ban/unban) < `admin` (agents, enrollment
//! tokens, audit log). Every change is written to the audit log with the
//! token name and client address.
//!
//! TODO: browser sessions (users, argon2/OIDC) for the web UI, OpenAPI
//! (utoipa), SSE live updates.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::extract::{ConnectInfo, FromRequestParts, Path, Query, State};
use axum::http::request::Parts;
use axum::http::{header, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use axum::{async_trait, Json, Router};
use chrono::Utc;
use df2b_core::{parse_target, AgentId, DecisionKind, Origin, Scope};
use df2b_tls::ApiToken;
use ipnet::IpNet;
use serde::Deserialize;
use serde_json::{json, Value};
use tracing::warn;

use crate::files::{self, Role};
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

/// The authenticated caller of a request.
#[derive(Debug, Clone)]
pub struct Caller {
    pub name: String,
    pub role: Role,
    pub addr: Option<SocketAddr>,
}

impl Caller {
    fn require(&self, role: Role) -> Result<(), ApiError> {
        if self.role >= role {
            Ok(())
        } else {
            Err(ApiError::new(
                StatusCode::FORBIDDEN,
                format!("requires role {role:?}, token has {:?}", self.role).to_lowercase(),
            ))
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
        let token = parts
            .headers
            .get(header::AUTHORIZATION)
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .and_then(|t| t.parse::<ApiToken>().ok());
        let Some(token) = token else {
            return Err(ApiError::new(
                StatusCode::UNAUTHORIZED,
                "missing or malformed bearer token",
            ));
        };
        let dir = ctl.settings.state_dir.clone();
        let file = tokio::task::spawn_blocking(move || files::lookup_api_token(&dir, &token))
            .await
            .map_err(ApiError::internal)?;
        match file {
            Some(f) => Ok(Caller {
                name: f.name,
                role: f.role,
                addr,
            }),
            None => {
                warn!(?addr, "rejected API request with unknown or expired token");
                Err(ApiError::new(
                    StatusCode::UNAUTHORIZED,
                    "invalid or expired API token",
                ))
            }
        }
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

pub fn router(ctl: Arc<Controller>) -> Router {
    Router::new()
        .route("/api/v1/health", get(health))
        .route("/api/v1/whoami", get(whoami))
        .route("/api/v1/status", get(status))
        .route("/api/v1/agents", get(agents))
        .route("/api/v1/agents/:id", get(agent))
        .route("/api/v1/agents/:id/revoke", post(revoke_agent))
        .route("/api/v1/enroll-tokens", post(enroll_token))
        .route("/api/v1/decisions", get(decisions))
        .route("/api/v1/bans", post(ban))
        .route("/api/v1/unban", post(unban))
        .route("/api/v1/audit", get(audit))
        .fallback(|| async { ApiError::not_found("no such endpoint") })
        .with_state(ctl)
}

/// Unauthenticated: for load balancers and monitoring.
async fn health() -> Json<Value> {
    Json(json!({ "status": "ok" }))
}

async fn whoami(caller: Caller) -> Json<Value> {
    Json(json!({ "name": caller.name, "role": caller.role }))
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

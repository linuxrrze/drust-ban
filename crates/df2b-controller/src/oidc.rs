//! Login with an OpenID Connect provider (Keycloak, Authentik, Entra ID,
//! Google, ...): authorization code flow with PKCE, `state` and `nonce`.
//!
//! 1. `GET /api/v1/oidc/login` remembers (state → nonce, PKCE verifier,
//!    browser binding) for 10 minutes, sets the binding cookie
//!    `__Host-df2b_oidc` (SameSite=Lax: it must survive the redirect back from
//!    the provider) and redirects to the provider.
//! 2. `GET /api/v1/oidc/callback?code&state` requires the same browser (the
//!    binding cookie), uses each state once, exchanges the code with the PKCE
//!    verifier, verifies the ID token (signature from the provider's JWKS,
//!    issuer, audience, expiry, nonce, access token hash) and maps the user's
//!    groups to a role. The result is an ordinary session (session.rs).
//!
//! Configuration: `--oidc-config <file>` (TOML, see `OidcConfig`).
//!
//! The role is taken from the provider at login and kept for the session
//! (`session_lifetime`, default 8 h): removing someone from a group takes
//! effect at their next login.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Mutex;
use std::time::{Duration, Instant};

use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use openidconnect::core::{CoreAuthenticationFlow, CoreClient};
use openidconnect::{
    AccessTokenHash, AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet,
    EndpointNotSet, EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge,
    PkceCodeVerifier, ProviderMetadataWithLogout, RedirectUrl, Scope, TokenResponse,
};
use serde::Deserialize;
use serde_json::Value;
use tracing::{info, warn};

use crate::files::{self, Role};

pub const CALLBACK_PATH: &str = "/api/v1/oidc/callback";
pub const BINDING_COOKIE: &str = "__Host-df2b_oidc";
/// How long a user may take at the provider.
const PENDING_TTL: Duration = Duration::from_secs(600);
const MAX_PENDING: usize = 10_000;
/// Provider metadata and keys are fetched again after this.
const METADATA_TTL: Duration = Duration::from_secs(3600);

fn default_scopes() -> Vec<String> {
    vec!["email".into(), "profile".into()]
}
fn default_username_claim() -> String {
    "preferred_username".into()
}
fn default_groups_claim() -> String {
    "groups".into()
}
fn default_session_lifetime() -> Duration {
    Duration::from_secs(8 * 3600)
}
fn default_display_name() -> String {
    "single sign-on".into()
}

/// Groups (values of `groups_claim`) that grant each role; the highest
/// matching role wins.
#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoleMap {
    #[serde(default)]
    pub admin: Vec<String>,
    #[serde(default)]
    pub operator: Vec<String>,
    #[serde(default)]
    pub viewer: Vec<String>,
}

/// `--oidc-config` file.
///
/// ```toml
/// issuer = "https://sso.example.org/realms/main"
/// client_id = "df2b"
/// client_secret_file = "/etc/df2b/oidc-client-secret"
/// redirect_url = "https://df2b.example.org:7444/api/v1/oidc/callback"
/// display_name = "Example SSO"
/// # username_claim = "preferred_username"   # or "email" (must be verified), "sub"
/// # groups_claim = "groups"                 # dotted path, e.g. "realm_access.roles"
/// [roles]
/// admin = ["df2b-admins"]
/// operator = ["noc"]
/// viewer = ["staff"]
/// ```
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OidcConfig {
    pub issuer: String,
    pub client_id: String,
    pub client_secret: Option<String>,
    pub client_secret_file: Option<PathBuf>,
    /// Must end in `/api/v1/oidc/callback` and be registered at the provider.
    pub redirect_url: String,
    /// In addition to `openid`.
    #[serde(default = "default_scopes")]
    pub scopes: Vec<String>,
    /// Shown on the login button ("Sign in with …").
    #[serde(default = "default_display_name")]
    pub display_name: String,
    #[serde(default = "default_username_claim")]
    pub username_claim: String,
    #[serde(default = "default_groups_claim")]
    pub groups_claim: String,
    #[serde(default)]
    pub roles: RoleMap,
    /// Role for users in none of the groups; default: no access.
    pub default_role: Option<Role>,
    /// CA certificates (PEM) for the provider, e.g. an internal Keycloak;
    /// default: the public roots.
    pub ca_file: Option<PathBuf>,
    #[serde(default = "default_session_lifetime", with = "humantime_serde")]
    pub session_lifetime: Duration,
    /// Where the provider sends the browser after logout (must be registered
    /// there), e.g. "https://df2b.example.org:7444/".
    pub post_logout_redirect_url: Option<String>,
    /// Only allow OIDC in the web UI (API tokens keep working).
    #[serde(default)]
    pub disable_password_login: bool,
}

impl OidcConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let cfg: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        Ok(cfg)
    }

    fn role_for(&self, groups: &[String]) -> Option<Role> {
        let has = |list: &[String]| list.iter().any(|g| groups.contains(g));
        if has(&self.roles.admin) {
            Some(Role::Admin)
        } else if has(&self.roles.operator) {
            Some(Role::Operator)
        } else if has(&self.roles.viewer) {
            Some(Role::Viewer)
        } else {
            self.default_role
        }
    }
}

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

struct Provider {
    client: Client,
    userinfo: Option<String>,
    end_session: Option<String>,
    fetched: Instant,
}

struct Pending {
    nonce: Nonce,
    verifier: PkceCodeVerifier,
    /// SHA-256 of the binding cookie
    browser: [u8; 32],
    created: Instant,
}

/// A user authenticated by the provider.
#[derive(Debug, Clone)]
pub struct Identity {
    pub name: String,
    pub role: Role,
    pub issuer: String,
    pub subject: String,
}

/// Why a login failed; the UI shows a matching message (`code`), details
/// go to the log only.
#[derive(Debug, thiserror::Error)]
pub enum LoginError {
    #[error("login expired or started in another browser")]
    Expired,
    #[error("cancelled at the identity provider")]
    Cancelled,
    #[error("no role for {0:?}")]
    NoRole(String),
    #[error("{0}")]
    Conflict(String),
    #[error("{0:#}")]
    Failed(anyhow::Error),
}

impl LoginError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Expired => "expired",
            Self::Cancelled => "cancelled",
            Self::NoRole(_) => "denied",
            Self::Conflict(_) => "conflict",
            Self::Failed(_) => "failed",
        }
    }
}

impl From<anyhow::Error> for LoginError {
    fn from(e: anyhow::Error) -> Self {
        Self::Failed(e)
    }
}

pub struct Oidc {
    pub config: OidcConfig,
    client_id: ClientId,
    client_secret: Option<ClientSecret>,
    issuer: IssuerUrl,
    redirect: RedirectUrl,
    http: reqwest::Client,
    provider: tokio::sync::Mutex<Option<Provider>>,
    pending: Mutex<HashMap<String, Pending>>,
}

fn hash(s: &str) -> [u8; 32] {
    df2b_tls::sha256(s.as_bytes())
}

/// Value at a dotted path ("realm_access.roles").
fn claim<'a>(v: &'a Value, path: &str) -> Option<&'a Value> {
    path.split('.').try_fold(v, |cur, key| cur.get(key))
}

fn strings(v: Option<&Value>) -> Vec<String> {
    match v {
        Some(Value::Array(a)) => a
            .iter()
            .filter_map(|x| x.as_str().map(str::to_owned))
            .collect(),
        Some(Value::String(s)) => vec![s.clone()],
        _ => Vec::new(),
    }
}

impl Oidc {
    pub fn new(config: OidcConfig) -> anyhow::Result<Self> {
        let issuer = IssuerUrl::new(config.issuer.clone()).context("issuer")?;
        if issuer.url().scheme() != "https" {
            bail!("issuer must be an https URL");
        }
        let redirect = RedirectUrl::new(config.redirect_url.clone()).context("redirect_url")?;
        if redirect.url().scheme() != "https" || redirect.url().path() != CALLBACK_PATH {
            bail!("redirect_url must be https://<controller>{CALLBACK_PATH}");
        }
        let secret = match (&config.client_secret, &config.client_secret_file) {
            (Some(_), Some(_)) => bail!("set client_secret or client_secret_file, not both"),
            (Some(s), None) => Some(s.clone()),
            (None, Some(p)) => Some(
                std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?
                    .trim()
                    .to_owned(),
            ),
            (None, None) => None, // public client: PKCE only
        };
        let trust = match &config.ca_file {
            Some(p) => {
                let pem = std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?;
                df2b_tls::transport::Trust::CaCerts(df2b_tls::pki::certs_from_pem(&pem)?)
            }
            None => df2b_tls::transport::Trust::SystemRoots,
        };
        let tls = df2b_tls::transport::https_client_config(trust)?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .https_only(true)
            // following redirects would allow SSRF via provider responses
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(10))
            .user_agent(concat!("df2b-controller/", env!("CARGO_PKG_VERSION")))
            .build()?;
        if config.roles.admin.is_empty()
            && config.roles.operator.is_empty()
            && config.roles.viewer.is_empty()
            && config.default_role.is_none()
        {
            warn!("OIDC: no [roles] and no default_role, nobody can log in");
        }
        Ok(Self {
            client_id: ClientId::new(config.client_id.clone()),
            client_secret: secret.map(ClientSecret::new),
            issuer,
            redirect,
            http,
            config,
            provider: tokio::sync::Mutex::new(None),
            pending: Mutex::new(HashMap::new()),
        })
    }

    /// Discovery document + keys, cached for an hour (`refresh` forces a
    /// new fetch, e.g. after an unknown signing key).
    async fn provider(
        &self,
        refresh: bool,
    ) -> anyhow::Result<(Client, Option<String>, Option<String>)> {
        let mut p = self.provider.lock().await;
        let stale = p
            .as_ref()
            .map_or(true, |p| refresh || p.fetched.elapsed() > METADATA_TTL);
        if stale {
            let meta = ProviderMetadataWithLogout::discover_async(self.issuer.clone(), &self.http)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("discovery at {}: {}", self.issuer.as_str(), describe(&e))
                })?;
            let userinfo = meta.userinfo_endpoint().map(|u| u.url().to_string());
            let end_session = meta
                .additional_metadata()
                .end_session_endpoint
                .as_ref()
                .map(|u| u.url().to_string());
            let client = CoreClient::from_provider_metadata(
                meta,
                self.client_id.clone(),
                self.client_secret.clone(),
            )
            .set_redirect_uri(self.redirect.clone());
            info!(issuer = %self.issuer.as_str(), "OIDC provider metadata loaded");
            *p = Some(Provider {
                client,
                userinfo,
                end_session,
                fetched: Instant::now(),
            });
        }
        let p = p.as_ref().expect("set above");
        Ok((p.client.clone(), p.userinfo.clone(), p.end_session.clone()))
    }

    /// Fetches the provider metadata once at startup (failures are retried
    /// at the first login).
    pub async fn warm_up(&self) {
        if let Err(e) = self.provider(false).await {
            warn!(error = %format!("{e:#}"), "OIDC provider not reachable yet");
        }
    }

    /// Starts a login: the provider URL and the binding cookie secret.
    pub async fn begin(&self) -> anyhow::Result<(String, String)> {
        let (client, _, _) = self.provider(false).await?;
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let mut req = client.authorize_url(
            CoreAuthenticationFlow::AuthorizationCode,
            CsrfToken::new_random,
            Nonce::new_random,
        );
        for s in &self.config.scopes {
            req = req.add_scope(Scope::new(s.clone()));
        }
        let (url, state, nonce) = req.set_pkce_challenge(challenge).url();
        let browser = URL_SAFE_NO_PAD.encode(df2b_tls::random_bytes::<32>());
        let now = Instant::now();
        let mut pending = self.pending.lock().unwrap_or_else(|e| e.into_inner());
        pending.retain(|_, p| now.duration_since(p.created) < PENDING_TTL);
        if pending.len() >= MAX_PENDING {
            bail!("too many logins in progress");
        }
        pending.insert(
            state.secret().clone(),
            Pending {
                nonce,
                verifier,
                browser: hash(&browser),
                created: now,
            },
        );
        Ok((url.to_string(), browser))
    }

    /// Completes a login from the provider's redirect.
    pub async fn finish(
        &self,
        state: &str,
        code: &str,
        browser: Option<&str>,
    ) -> Result<Identity, LoginError> {
        // each state works once, only in the browser that started the login
        let p = self
            .pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(state)
            .ok_or(LoginError::Expired)?;
        let same_browser =
            browser.is_some_and(|b| crate::session::constant_time_eq(&hash(b), &p.browser));
        if !same_browser || p.created.elapsed() > PENDING_TTL {
            return Err(LoginError::Expired);
        }

        let (client, userinfo, _) = self.provider(false).await?;
        let token = client
            .exchange_code(AuthorizationCode::new(code.to_owned()))
            .context("token endpoint")?
            .set_pkce_verifier(p.verifier)
            .request_async(&self.http)
            .await
            .map_err(|e| anyhow::anyhow!("token request: {}", describe(&e)))?;
        let id_token = token
            .id_token()
            .context("the provider returned no ID token")?;

        // verify; on failure fetch the keys again once (key rotation)
        let verified = {
            let v = client.id_token_verifier();
            match id_token.claims(&v, &p.nonce) {
                Ok(c) => Ok(c.clone()),
                Err(first) => {
                    let (fresh, _, _) = self.provider(true).await?;
                    let v = fresh.id_token_verifier();
                    id_token.claims(&v, &p.nonce).cloned().map_err(|e| {
                        anyhow::anyhow!("ID token rejected: {e} (before key refresh: {first})")
                    })
                }
            }
        }?;
        if let Some(expected) = verified.access_token_hash() {
            let v = client.id_token_verifier();
            let actual = AccessTokenHash::from_token(
                token.access_token(),
                id_token.signing_alg().context("ID token algorithm")?,
                id_token.signing_key(&v).context("ID token key")?,
            )
            .context("access token hash")?;
            if actual != *expected {
                return Err(anyhow::anyhow!("access token does not match the ID token").into());
            }
        }

        // claims: the verified ID token's payload, completed from userinfo
        let jwt = id_token.to_string();
        let payload = jwt.split('.').nth(1).context("malformed ID token")?;
        let mut claims: Value = serde_json::from_slice(
            &URL_SAFE_NO_PAD
                .decode(payload)
                .context("ID token payload encoding")?,
        )
        .context("ID token payload")?;
        let subject = verified.subject().as_str().to_owned();
        let missing = |c: &Value| {
            claim(c, &self.config.username_claim).is_none()
                || claim(c, &self.config.groups_claim).is_none()
        };
        if missing(&claims) {
            if let Some(url) = userinfo {
                let info: Value = self
                    .http
                    .get(&url)
                    .bearer_auth(token.access_token().secret())
                    .header("accept", "application/json")
                    .send()
                    .await
                    .and_then(reqwest::Response::error_for_status)
                    .context("userinfo request")?
                    .json()
                    .await
                    .context("userinfo response (only JSON is supported)")?;
                // OIDC Core 5.3.2: userinfo must be about the same subject
                if info.get("sub").and_then(Value::as_str) != Some(subject.as_str()) {
                    return Err(anyhow::anyhow!("userinfo is about another subject").into());
                }
                if let (Some(c), Some(i)) = (claims.as_object_mut(), info.as_object()) {
                    for (k, v) in i {
                        c.entry(k.clone()).or_insert_with(|| v.clone());
                    }
                }
            }
        }

        let uc = self.config.username_claim.as_str();
        let name = claim(&claims, uc)
            .and_then(Value::as_str)
            .with_context(|| format!("no {uc:?} claim (configure username_claim)"))?
            .to_owned();
        if uc == "email" && claims.get("email_verified").and_then(Value::as_bool) != Some(true) {
            return Err(anyhow::anyhow!("e-mail address {name:?} is not verified").into());
        }
        let groups = strings(claim(&claims, &self.config.groups_claim));
        let role = self
            .config
            .role_for(&groups)
            .ok_or_else(|| LoginError::NoRole(name.clone()))?;
        Ok(Identity {
            name,
            role,
            issuer: self.issuer.as_str().to_owned(),
            subject,
        })
    }

    /// Drops a login in progress (the provider reported an error).
    pub fn forget(&self, state: &str) {
        self.pending
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .remove(state);
    }

    /// The provider's logout URL, if it supports RP-initiated logout.
    pub async fn logout_url(&self) -> Option<String> {
        let (_, _, end) = self.provider(false).await.ok()?;
        let mut url = reqwest::Url::parse(&end?).ok()?;
        url.query_pairs_mut()
            .append_pair("client_id", self.client_id.as_str());
        if let Some(r) = &self.config.post_logout_redirect_url {
            url.query_pairs_mut()
                .append_pair("post_logout_redirect_uri", r);
        }
        Some(url.to_string())
    }
}

/// Error text including the provider's error response.
fn describe<E: std::error::Error>(e: &E) -> String {
    let mut s = e.to_string();
    let mut src = e.source();
    while let Some(c) = src {
        let t = c.to_string();
        if !s.contains(&t) {
            s = format!("{s}: {t}");
        }
        src = c.source();
    }
    s
}

/// Name check shared with local users and API tokens (one name space).
pub fn check_name(dir: &Path, name: &str) -> Result<(), LoginError> {
    if !files::valid_name(name) {
        return Err(LoginError::Conflict(format!(
            "user name {name:?} from the identity provider is not allowed \
             (letters, digits, - _ . @; at most 64)"
        )));
    }
    let local = files::load_user(dir, name).map_err(LoginError::Failed)?;
    let token = files::list_api_tokens(dir)
        .map_err(LoginError::Failed)?
        .iter()
        .any(|t| t.name == name);
    if local.is_some() || token {
        return Err(LoginError::Conflict(format!(
            "{name:?} is also a local user or API token name"
        )));
    }
    Ok(())
}

/// Binding cookie for a login in progress.
pub fn binding_cookie(secret: &str) -> String {
    format!(
        "{BINDING_COOKIE}={secret}; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age={}",
        PENDING_TTL.as_secs()
    )
}

pub fn clear_binding_cookie() -> String {
    format!("{BINDING_COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Lax; Max-Age=0")
}

#[cfg(test)]
#[path = "oidc_tests.rs"]
mod tests;

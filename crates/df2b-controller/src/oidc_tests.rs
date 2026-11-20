//! OIDC login against an in-process mock provider (HTTPS, ES256 tokens).

use std::collections::HashMap;
use std::sync::{Arc, Mutex};

use axum::extract::{Form, State};
use axum::http::{HeaderMap, StatusCode};
use axum::routing::{get, post};
use axum::{Json, Router};
use base64::engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD};
use base64::Engine;
use reqwest::StatusCode as S;
use ring::rand::SystemRandom;
use ring::signature::{EcdsaKeyPair, KeyPair, ECDSA_P256_SHA256_FIXED_SIGNING};
use serde_json::{json, Value};

use super::*;
use crate::files::{self, Role};
use crate::state::{Controller, Propagate, Settings};
use crate::store::Store;
use df2b_core::Allowlist;
use df2b_tls::transport::{https_client_config, https_server_config, Trust};

const CLIENT_ID: &str = "df2b";
const CLIENT_SECRET: &str = "s3cret";

struct Grant {
    nonce: String,
    challenge: String,
    /// merged into (and overriding) the standard ID token claims
    claims: Value,
}

struct Mock {
    base: String,
    key: Mutex<EcdsaKeyPair>,
    /// key the JWKS publishes (differs from `key` to simulate a forgery)
    jwks_key: Mutex<Vec<u8>>,
    grants: Mutex<HashMap<String, Grant>>,
    userinfo: Mutex<Value>,
    discoveries: Mutex<u32>,
}

fn new_key() -> EcdsaKeyPair {
    let rng = SystemRandom::new();
    let pkcs8 = EcdsaKeyPair::generate_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, &rng).unwrap();
    EcdsaKeyPair::from_pkcs8(&ECDSA_P256_SHA256_FIXED_SIGNING, pkcs8.as_ref(), &rng).unwrap()
}

fn b64(d: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(d)
}

async fn discovery(State(m): State<Arc<Mock>>) -> Json<Value> {
    *m.discoveries.lock().unwrap() += 1;
    let b = &m.base;
    Json(json!({
        "issuer": b,
        "authorization_endpoint": format!("{b}/authorize"),
        "token_endpoint": format!("{b}/token"),
        "userinfo_endpoint": format!("{b}/userinfo"),
        "jwks_uri": format!("{b}/jwks"),
        "end_session_endpoint": format!("{b}/logout"),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"],
    }))
}

async fn jwks(State(m): State<Arc<Mock>>) -> Json<Value> {
    let pk = m.jwks_key.lock().unwrap().clone(); // 0x04 || x || y
    Json(json!({ "keys": [{
        "kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": "k1",
        "x": b64(&pk[1..33]), "y": b64(&pk[33..65]),
    }]}))
}

async fn token(
    State(m): State<Arc<Mock>>,
    headers: HeaderMap,
    Form(f): Form<HashMap<String, String>>,
) -> Result<Json<Value>, (StatusCode, Json<Value>)> {
    let bad = |e: &str| (StatusCode::BAD_REQUEST, Json(json!({ "error": e })));
    let auth = format!(
        "Basic {}",
        STANDARD.encode(format!("{CLIENT_ID}:{CLIENT_SECRET}"))
    );
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some(auth.as_str()) {
        return Err((
            StatusCode::UNAUTHORIZED,
            Json(json!({ "error": "invalid_client" })),
        ));
    }
    if f.get("grant_type").map(String::as_str) != Some("authorization_code") {
        return Err(bad("unsupported_grant_type"));
    }
    let g = m
        .grants
        .lock()
        .unwrap()
        .remove(f.get("code").ok_or_else(|| bad("invalid_request"))?)
        .ok_or_else(|| bad("invalid_grant"))?;
    // PKCE S256
    let verifier = f
        .get("code_verifier")
        .ok_or_else(|| bad("invalid_request"))?;
    if b64(&df2b_tls::sha256(verifier.as_bytes())) != g.challenge {
        return Err(bad("invalid_grant"));
    }
    let access = b64(&df2b_tls::random_bytes::<24>());
    let at_hash = b64(&df2b_tls::sha256(access.as_bytes())[..16]);
    let now = chrono::Utc::now().timestamp();
    let mut claims = json!({
        "iss": m.base, "aud": CLIENT_ID, "sub": "user-1", "iat": now, "exp": now + 300,
        "nonce": g.nonce, "at_hash": at_hash,
    });
    for (k, v) in g.claims.as_object().unwrap() {
        if v.is_null() {
            claims.as_object_mut().unwrap().remove(k);
        } else {
            claims[k] = v.clone();
        }
    }
    let header = b64(br#"{"alg":"ES256","typ":"JWT","kid":"k1"}"#);
    let input = format!("{header}.{}", b64(claims.to_string().as_bytes()));
    let sig = m
        .key
        .lock()
        .unwrap()
        .sign(&SystemRandom::new(), input.as_bytes())
        .unwrap();
    Ok(Json(json!({
        "access_token": access, "token_type": "Bearer", "expires_in": 300,
        "id_token": format!("{input}.{}", b64(sig.as_ref())),
    })))
}

impl Mock {
    /// A logout token as the provider would send it; `claims` override the
    /// defaults (null removes a claim), `header` replaces the JOSE header.
    fn logout_token(&self, claims: Value, header: Option<Value>) -> String {
        let now = chrono::Utc::now().timestamp();
        let mut c = json!({
            "iss": self.base, "aud": CLIENT_ID, "iat": now,
            "jti": b64(&df2b_tls::random_bytes::<12>()),
            "events": { "http://schemas.openid.net/event/backchannel-logout": {} },
        });
        for (k, v) in claims.as_object().unwrap() {
            if v.is_null() {
                c.as_object_mut().unwrap().remove(k);
            } else {
                c[k] = v.clone();
            }
        }
        let header = header.unwrap_or(json!({ "alg": "ES256", "typ": "logout+jwt", "kid": "k1" }));
        let input = format!(
            "{}.{}",
            b64(header.to_string().as_bytes()),
            b64(c.to_string().as_bytes())
        );
        let sig = self
            .key
            .lock()
            .unwrap()
            .sign(&SystemRandom::new(), input.as_bytes())
            .unwrap();
        format!("{input}.{}", b64(sig.as_ref()))
    }
}

async fn userinfo(State(m): State<Arc<Mock>>) -> Json<Value> {
    Json(m.userinfo.lock().unwrap().clone())
}

struct Env {
    ctl: Arc<Controller>,
    mock: Arc<Mock>,
    base: String,
    http: reqwest::Client,
    dir: std::path::PathBuf,
}

async fn env(tag: &str, tweak: impl FnOnce(&mut OidcConfig)) -> Env {
    env_with(tag, tweak, std::time::Duration::ZERO).await
}

async fn env_with(
    tag: &str,
    tweak: impl FnOnce(&mut OidcConfig),
    min_refresh: std::time::Duration,
) -> Env {
    let dir = std::env::temp_dir().join(format!("df2b-oidc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // the provider, with its own CA
    let idp_ca = df2b_tls::Ca::generate("idp").unwrap();
    std::fs::write(dir.join("idp-ca.pem"), idp_ca.cert_pem()).unwrap();
    let (chain, key) = idp_ca.issue_server(&["127.0.0.1".into()]).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let idp_base = format!("https://127.0.0.1:{}", l.local_addr().unwrap().port());
    let k = new_key();
    let mock = Arc::new(Mock {
        base: idp_base.clone(),
        jwks_key: Mutex::new(k.public_key().as_ref().to_vec()),
        key: Mutex::new(k),
        grants: Mutex::new(HashMap::new()),
        userinfo: Mutex::new(json!({ "sub": "user-1" })),
        discoveries: Mutex::new(0),
    });
    let idp = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/token", post(token))
        .route("/userinfo", get(userinfo))
        .with_state(mock.clone());
    tokio::spawn(crate::https::serve(
        l,
        https_server_config(chain, key).unwrap(),
        idp,
        std::future::pending(),
    ));

    let mut cfg: OidcConfig = toml::from_str(&format!(
        r#"
        issuer = "{idp_base}"
        client_id = "{CLIENT_ID}"
        client_secret = "{CLIENT_SECRET}"
        redirect_url = "https://df2b.example.org:7444/api/v1/oidc/callback"
        display_name = "Mock SSO"
        ca_file = "{}"
        post_logout_redirect_url = "https://df2b.example.org:7444/"
        [roles]
        admin = ["df2b-admins"]
        operator = ["noc"]
        "#,
        dir.join("idp-ca.pem").display()
    ))
    .unwrap();
    tweak(&mut cfg);

    let ca = crate::files::load_or_create_ca(&dir).unwrap();
    let fp = ca.fingerprint();
    let settings = Settings {
        state_dir: dir.clone(),
        cert_lifetime: std::time::Duration::from_secs(3600),
        propagate: Propagate::Global,
        allowlist: Allowlist::default(),
        oidc: Some(Arc::new({
            let mut o = Oidc::new(cfg).unwrap();
            o.min_refresh = min_refresh;
            o
        })),
        https_internal_ca: true,
    };
    let ctl = Arc::new(Controller::open(settings, ca, Store::open(&dir).unwrap()).unwrap());
    let (chain, key) = ctl.ca.issue_server(&[]).unwrap();
    let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!("https://{}", l.local_addr().unwrap());
    tokio::spawn(crate::https::serve(
        l,
        https_server_config(chain, key).unwrap(),
        crate::api::router(ctl.clone()),
        std::future::pending(),
    ));
    let tls = https_client_config(Trust::PinnedCa(fp)).unwrap();
    let http = reqwest::Client::builder()
        .use_preconfigured_tls((*tls).clone())
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap();
    Env {
        ctl,
        mock,
        base,
        http,
        dir,
    }
}

fn cookies(r: &reqwest::Response) -> Vec<String> {
    r.headers()
        .get_all("set-cookie")
        .iter()
        .map(|c| c.to_str().unwrap().to_owned())
        .collect()
}

fn cookie_value(cs: &[String], name: &str) -> Option<String> {
    cs.iter()
        .filter_map(|c| c.split(';').next())
        .find(|c| c.starts_with(&format!("{name}=")))
        .map(str::to_owned)
}

struct Started {
    state: String,
    nonce: String,
    challenge: String,
    binding: String,
}

impl Env {
    /// The browser clicks "Sign in with …".
    async fn start(&self) -> Started {
        let r = self
            .http
            .get(format!("{}/api/v1/oidc/login", self.base))
            .send()
            .await
            .unwrap();
        assert_eq!(r.status(), S::SEE_OTHER);
        let loc = reqwest::Url::parse(r.headers()["location"].to_str().unwrap()).unwrap();
        assert_eq!(
            loc.as_str().split('?').next(),
            Some(format!("{}/authorize", self.mock.base).as_str())
        );
        let q: HashMap<String, String> = loc.query_pairs().into_owned().collect();
        assert_eq!(q["response_type"], "code");
        assert_eq!(q["client_id"], CLIENT_ID);
        assert_eq!(q["code_challenge_method"], "S256");
        assert_eq!(
            q["redirect_uri"],
            "https://df2b.example.org:7444/api/v1/oidc/callback"
        );
        assert!(
            q["scope"].split(' ').any(|s| s == "openid"),
            "{}",
            q["scope"]
        );
        let cs = cookies(&r);
        assert!(cs[0].contains("SameSite=Lax") && cs[0].contains("HttpOnly"));
        Started {
            state: q["state"].clone(),
            nonce: q["nonce"].clone(),
            challenge: q["code_challenge"].clone(),
            binding: cookie_value(&cs, BINDING_COOKIE).unwrap(),
        }
    }

    /// The provider authenticates the user and redirects back.
    async fn callback(
        &self,
        s: &Started,
        claims: Value,
        cookie: Option<&str>,
    ) -> reqwest::Response {
        let code = b64(&df2b_tls::random_bytes::<12>());
        self.mock.grants.lock().unwrap().insert(
            code.clone(),
            Grant {
                nonce: s.nonce.clone(),
                challenge: s.challenge.clone(),
                claims,
            },
        );
        let mut req = self
            .http
            .get(format!("{}/api/v1/oidc/callback", self.base))
            .query(&[("code", code.as_str()), ("state", s.state.as_str())]);
        if let Some(c) = cookie {
            req = req.header("cookie", c);
        }
        req.send().await.unwrap()
    }

    /// Full login; returns where the browser is sent and the session cookie.
    async fn login(&self, claims: Value) -> (String, Option<String>) {
        let s = self.start().await;
        let r = self.callback(&s, claims, Some(&s.binding)).await;
        assert_eq!(r.status(), S::SEE_OTHER);
        let loc = r.headers()["location"].to_str().unwrap().to_owned();
        (loc, cookie_value(&cookies(&r), crate::session::COOKIE))
    }

    /// The provider calls the back-channel logout endpoint.
    async fn backchannel(&self, token: &str) -> (S, Value) {
        let r = self
            .http
            .post(format!("{}{BACKCHANNEL_PATH}", self.base))
            .form(&[("logout_token", token)])
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }

    async fn get(&self, path: &str, cookie: &str) -> (S, Value) {
        let r = self
            .http
            .get(format!("{}{path}", self.base))
            .header("cookie", cookie)
            .send()
            .await
            .unwrap();
        (r.status(), r.json().await.unwrap_or(Value::Null))
    }
}

#[tokio::test]
async fn login_roles_and_logout() {
    let e = env("ok", |_| {}).await;
    let (st, m) = {
        let r = e
            .http
            .get(format!("{}/api/v1/auth-methods", e.base))
            .send()
            .await
            .unwrap();
        (r.status(), r.json::<Value>().await.unwrap())
    };
    assert_eq!(
        (st, m["password"].as_bool(), m["oidc"]["name"].as_str()),
        (S::OK, Some(true), Some("Mock SSO"))
    );

    let (loc, cookie) = e
        .login(json!({ "preferred_username": "alice", "groups": ["staff", "noc"] }))
        .await;
    assert_eq!(loc, "/");
    let cookie = cookie.expect("session cookie");
    let (st, me) = e.get("/api/v1/whoami", &cookie).await;
    assert_eq!(st, S::OK);
    assert_eq!(
        (
            me["name"].as_str(),
            me["role"].as_str(),
            me["method"].as_str()
        ),
        (Some("alice"), Some("operator"), Some("oidc"))
    );

    // an OIDC session works like any other: ban with the CSRF token
    let r = e
        .http
        .post(format!("{}/api/v1/bans", e.base))
        .header("cookie", &cookie)
        .header("x-csrf-token", me["csrf_token"].as_str().unwrap())
        .json(&json!({ "target": "192.0.2.5", "duration": "1h" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), S::CREATED);
    let d: Value = r.json().await.unwrap();
    assert_eq!(d["decision"]["origin"]["value"], "alice");

    // admin via a dotted claim path is tested elsewhere; here the highest group wins
    let (_, admin) = e
        .login(json!({ "preferred_username": "bob", "groups": ["noc", "df2b-admins"] }))
        .await;
    assert_eq!(
        e.get("/api/v1/whoami", &admin.unwrap()).await.1["role"],
        "admin"
    );

    // logout points to the provider's end_session_endpoint
    let r = e
        .http
        .delete(format!("{}/api/v1/session", e.base))
        .header("cookie", &cookie)
        .header("x-csrf-token", me["csrf_token"].as_str().unwrap())
        .send()
        .await
        .unwrap();
    let v: Value = r.json().await.unwrap();
    let url = v["logout_url"].as_str().unwrap();
    assert!(
        url.starts_with(&format!("{}/logout?client_id=df2b", e.mock.base)),
        "{url}"
    );
    assert!(url.contains("post_logout_redirect_uri=https%3A%2F%2Fdf2b.example.org%3A7444%2F"));
    assert_eq!(e.get("/api/v1/whoami", &cookie).await.0, S::UNAUTHORIZED);

    let audit = e.ctl.audit_log(10, u64::MAX).unwrap();
    let logins: Vec<_> = audit
        .iter()
        .filter(|a| a.action == "session.login")
        .map(|a| {
            (
                a.actor.as_str(),
                a.details["method"].as_str(),
                a.details["role"].as_str(),
            )
        })
        .collect();
    assert_eq!(
        logins,
        [
            ("bob", Some("oidc"), Some("admin")),
            ("alice", Some("oidc"), Some("operator"))
        ]
    );
    assert_eq!(*e.mock.discoveries.lock().unwrap(), 1, "metadata is cached");
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn state_is_single_use_and_bound_to_the_browser() {
    let e = env("bind", |_| {}).await;
    let ok = json!({ "preferred_username": "alice", "groups": ["noc"] });

    // no binding cookie (e.g. a link from an attacker's login): refused
    let s = e.start().await;
    let r = e.callback(&s, ok.clone(), None).await;
    assert_eq!(r.headers()["location"], "/#/login-error/expired");
    assert!(cookie_value(&cookies(&r), crate::session::COOKIE).is_none());
    // ... and the state is gone even for the right browser
    let r = e.callback(&s, ok.clone(), Some(&s.binding)).await;
    assert_eq!(r.headers()["location"], "/#/login-error/expired");

    // another browser's binding cookie
    let a = e.start().await;
    let b = e.start().await;
    let r = e.callback(&a, ok.clone(), Some(&b.binding)).await;
    assert_eq!(r.headers()["location"], "/#/login-error/expired");

    // replay of a successful callback
    let s = e.start().await;
    let r = e.callback(&s, ok.clone(), Some(&s.binding)).await;
    assert_eq!(r.headers()["location"], "/");
    let r = e.callback(&s, ok.clone(), Some(&s.binding)).await;
    assert_eq!(r.headers()["location"], "/#/login-error/expired");

    // unknown state, missing parameters, provider error
    let r = e
        .http
        .get(format!("{}/api/v1/oidc/callback?code=x&state=nope", e.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["location"], "/#/login-error/expired");
    let r = e
        .http
        .get(format!("{}/api/v1/oidc/callback", e.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["location"], "/#/login-error/expired");
    let s = e.start().await;
    let r = e
        .http
        .get(format!(
            "{}/api/v1/oidc/callback?error=access_denied&state={}",
            e.base, s.state
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["location"], "/#/login-error/cancelled");
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn forged_or_mismatched_tokens_are_refused() {
    let e = env("forge", |_| {}).await;
    let base = json!({ "preferred_username": "alice", "groups": ["noc"] });
    let with = |extra: Value| {
        let mut v = base.clone();
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    let now = chrono::Utc::now().timestamp();
    for (what, claims) in [
        ("nonce", with(json!({ "nonce": "attacker-nonce" }))),
        ("audience", with(json!({ "aud": "another-client" }))),
        ("issuer", with(json!({ "iss": "https://evil.example" }))),
        (
            "expired",
            with(json!({ "exp": now - 600, "iat": now - 900 })),
        ),
        (
            "at_hash",
            with(json!({ "at_hash": "AAAAAAAAAAAAAAAAAAAAAA" })),
        ),
        ("no subject", with(json!({ "sub": null }))),
    ] {
        let (loc, cookie) = e.login(claims).await;
        assert_eq!(
            (loc.as_str(), cookie.is_none()),
            ("/#/login-error/failed", true),
            "{what}"
        );
    }

    // signed with a key the provider does not publish: refused, also after
    // fetching the keys again
    let before = *e.mock.discoveries.lock().unwrap();
    *e.mock.key.lock().unwrap() = new_key();
    let (loc, _) = e.login(base.clone()).await;
    assert_eq!(loc, "/#/login-error/failed");
    assert_eq!(
        *e.mock.discoveries.lock().unwrap(),
        before + 1,
        "one key refresh"
    );

    // key rotation at the provider: the refresh picks up the new key
    let k = new_key();
    *e.mock.jwks_key.lock().unwrap() = k.public_key().as_ref().to_vec();
    *e.mock.key.lock().unwrap() = k;
    let (loc, cookie) = e.login(base.clone()).await;
    assert_eq!((loc.as_str(), cookie.is_some()), ("/", true));
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn roles_names_and_userinfo() {
    let e = env("roles", |c| {
        c.groups_claim = "realm_access.roles".into();
    })
    .await;
    // no matching group and no default role
    let (loc, cookie) = e
        .login(json!({ "preferred_username": "guest", "realm_access": { "roles": ["guests"] } }))
        .await;
    assert_eq!(
        (loc.as_str(), cookie.is_none()),
        ("/#/login-error/denied", true)
    );
    // nested claim path
    let (_, cookie) = e
        .login(json!({ "preferred_username": "ada", "realm_access": { "roles": ["df2b-admins"] } }))
        .await;
    assert_eq!(
        e.get("/api/v1/whoami", &cookie.unwrap()).await.1["role"],
        "admin"
    );

    // groups only in userinfo (same subject)
    *e.mock.userinfo.lock().unwrap() =
        json!({ "sub": "user-1", "realm_access": { "roles": ["noc"] } });
    let (_, cookie) = e.login(json!({ "preferred_username": "olga" })).await;
    assert_eq!(
        e.get("/api/v1/whoami", &cookie.unwrap()).await.1["role"],
        "operator"
    );
    // userinfo about someone else
    *e.mock.userinfo.lock().unwrap() =
        json!({ "sub": "user-2", "realm_access": { "roles": ["df2b-admins"] } });
    let (loc, _) = e.login(json!({ "preferred_username": "olga" })).await;
    assert_eq!(loc, "/#/login-error/failed");

    // a name that belongs to a local user or API token
    crate::files::create_user(
        &e.dir,
        "root",
        crate::files::Role::Viewer,
        "correct horse battery",
    )
    .unwrap();
    crate::files::create_api_token(&e.dir, "ci", crate::files::Role::Viewer, None).unwrap();
    for n in ["root", "ci", "bad/name"] {
        let (loc, _) = e
            .login(json!({ "preferred_username": n, "realm_access": { "roles": ["noc"] } }))
            .await;
        assert_eq!(loc, "/#/login-error/conflict", "{n}");
    }

    // a name is bound to the account that used it first ("olga" is
    // user-1's): another account renamed to it at the provider is refused
    *e.mock.userinfo.lock().unwrap() = json!({ "sub": "user-3" });
    let takeover = json!({
        "sub": "user-3", "preferred_username": "olga", "realm_access": { "roles": ["noc"] }
    });
    let (loc, _) = e.login(takeover.clone()).await;
    assert_eq!(loc, "/#/login-error/conflict");
    // nor can the name be taken by a local user or token now
    assert!(crate::files::create_user(
        &e.dir,
        "olga",
        crate::files::Role::Viewer,
        "correct horse battery"
    )
    .is_err());
    assert!(
        crate::files::create_api_token(&e.dir, "olga", crate::files::Role::Viewer, None).is_err()
    );
    let bound = crate::files::list_oidc_names(&e.dir).unwrap();
    assert!(bound
        .iter()
        .any(|n| n.name == "olga" && n.subject == "user-1"));
    // released by the admin: the next account to log in gets it
    assert!(crate::files::release_oidc_name(&e.dir, "olga").unwrap());
    let (loc, cookie) = e.login(takeover).await;
    assert_eq!(loc, "/");
    assert_eq!(
        e.get("/api/v1/whoami", &cookie.unwrap()).await.1["name"],
        "olga"
    );
    let bound = crate::files::list_oidc_names(&e.dir).unwrap();
    assert!(bound
        .iter()
        .any(|n| n.name == "olga" && n.subject == "user-3"));
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn email_claim_default_role_and_password_login_off() {
    let e = env("email", |c| {
        c.username_claim = "email".into();
        c.default_role = Some(crate::files::Role::Viewer);
        c.disable_password_login = true;
    })
    .await;
    let (loc, _) = e
        .login(json!({ "email": "eve@example.org", "email_verified": false }))
        .await;
    assert_eq!(loc, "/#/login-error/failed", "unverified e-mail");
    let (_, cookie) = e
        .login(json!({ "email": "vic@example.org", "email_verified": true }))
        .await;
    let me = e.get("/api/v1/whoami", &cookie.unwrap()).await.1;
    assert_eq!(
        (me["name"].as_str(), me["role"].as_str()),
        (Some("vic@example.org"), Some("viewer"))
    );

    crate::files::create_user(
        &e.dir,
        "local",
        crate::files::Role::Admin,
        "correct horse battery",
    )
    .unwrap();
    let r = e
        .http
        .post(format!("{}/api/v1/session", e.base))
        .json(&json!({ "username": "local", "password": "correct horse battery" }))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), S::FORBIDDEN);
    let m: Value = e
        .http
        .get(format!("{}/api/v1/auth-methods", e.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(m["password"], false);
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[test]
fn example_config_parses() {
    let cfg: OidcConfig =
        toml::from_str(include_str!("../../../config/oidc.example.toml")).unwrap();
    assert_eq!(cfg.roles.operator, ["noc"]);
    assert_eq!(
        cfg.session_lifetime,
        std::time::Duration::from_secs(8 * 3600)
    );
    assert_eq!(
        cfg.role_for(&["staff".into(), "noc".into()]),
        Some(crate::files::Role::Operator)
    );
    assert_eq!(cfg.role_for(&["guests".into()]), None);
}

#[test]
fn config_validation() {
    let cfg = |extra: &str| -> anyhow::Result<Oidc> {
        Oidc::new(toml::from_str(&format!(
            "issuer = \"https://sso.example.org\"\nclient_id = \"x\"\n{extra}"
        ))?)
    };
    assert!(cfg("redirect_url = \"https://h:7444/api/v1/oidc/callback\"").is_ok());
    assert!(cfg("redirect_url = \"http://h:7444/api/v1/oidc/callback\"").is_err());
    assert!(cfg("redirect_url = \"https://h:7444/elsewhere\"").is_err());
    assert!(cfg("redirect_url = \"https://h/api/v1/oidc/callback\"\nclient_secret = \"a\"\nclient_secret_file = \"/x\"").is_err());
    assert!(Oidc::new(
        toml::from_str("issuer = \"http://sso\"\nclient_id = \"x\"\nredirect_url = \"https://h/api/v1/oidc/callback\"").unwrap()
    )
    .is_err());
    assert!(toml::from_str::<OidcConfig>("issuer = \"https://a\"\nclient_id = \"x\"\nredirect_url = \"https://h/api/v1/oidc/callback\"\ntypo = 1").is_err());
}

#[tokio::test]
async fn backchannel_logout_ends_sessions() {
    let e = env("bcl", |_| {}).await;
    let user = |sub: &str, sid: &str| json!({ "sub": sub, "sid": sid, "preferred_username": sub, "groups": ["noc"] });
    let (_, a1) = e.login(user("alice", "s1")).await;
    let (_, a2) = e.login(user("alice", "s2")).await;
    let (_, b1) = e.login(user("bob", "s3")).await;
    let (a1, a2, b1) = (a1.unwrap(), a2.unwrap(), b1.unwrap());
    files::create_user(&e.dir, "local", Role::Admin, "correct horse battery").unwrap();
    let r = e
        .http
        .post(format!("{}/api/v1/session", e.base))
        .json(&json!({ "username": "local", "password": "correct horse battery" }))
        .send()
        .await
        .unwrap();
    let local = cookie_value(&cookies(&r), crate::session::COOKIE).unwrap();
    let alive = |c: &str| {
        let c = c.to_owned();
        let e = &e;
        async move { e.get("/api/v1/whoami", &c).await.0 == S::OK }
    };

    // logout of one provider session (sid): only that browser session ends
    let t = e.mock.logout_token(json!({ "sid": "s1" }), None);
    assert_eq!(e.backchannel(&t).await.0, S::OK);
    assert!(!alive(&a1).await && alive(&a2).await && alive(&b1).await);
    // replay
    let (st, v) = e.backchannel(&t).await;
    assert_eq!(
        (st, v["error"].as_str()),
        (S::BAD_REQUEST, Some("invalid_request"))
    );

    // all sessions of a subject (e.g. user disabled at the provider)
    assert_eq!(
        e.backchannel(&e.mock.logout_token(json!({ "sub": "alice" }), None))
            .await
            .0,
        S::OK
    );
    assert!(!alive(&a2).await && alive(&b1).await && alive(&local).await);
    // nothing matching is still a success
    assert_eq!(
        e.backchannel(&e.mock.logout_token(json!({ "sub": "nobody" }), None))
            .await
            .0,
        S::OK
    );

    let audit = e.ctl.audit_log(20, u64::MAX).unwrap();
    let bcl: Vec<_> = audit
        .iter()
        .filter(|a| a.action == "session.backchannel_logout")
        .map(|a| {
            (
                a.actor.as_str(),
                a.details["sessions_ended"].as_u64().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        bcl,
        [
            ("oidc-provider", 0),
            ("oidc-provider", 1),
            ("oidc-provider", 1)
        ]
    );
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn backchannel_logout_rejects_bad_tokens() {
    let e = env("bclbad", |_| {}).await;
    let (_, bob) = e
        .login(json!({ "sub": "bob", "sid": "s9", "preferred_username": "bob", "groups": ["noc"] }))
        .await;
    let bob = bob.unwrap();
    let m = &e.mock;
    let now = chrono::Utc::now().timestamp();
    let target = json!({ "sub": "bob" });
    let with = |extra: Value| {
        let mut v = target.clone();
        for (k, x) in extra.as_object().unwrap() {
            v[k] = x.clone();
        }
        v
    };
    let unsigned = {
        let t = m.logout_token(target.clone(), Some(json!({ "alg": "none" })));
        format!("{}.", t.rsplit_once('.').unwrap().0)
    };
    let cases: Vec<(&str, String)> = vec![
        (
            "audience",
            m.logout_token(with(json!({ "aud": "other-client" })), None),
        ),
        (
            "issuer",
            m.logout_token(with(json!({ "iss": "https://evil.example" })), None),
        ),
        (
            "nonce (an ID token)",
            m.logout_token(with(json!({ "nonce": "n" })), None),
        ),
        (
            "no events",
            m.logout_token(with(json!({ "events": null })), None),
        ),
        (
            "other event",
            m.logout_token(with(json!({ "events": { "urn:other": {} } })), None),
        ),
        (
            "old",
            m.logout_token(with(json!({ "iat": now - 3600 })), None),
        ),
        (
            "future",
            m.logout_token(with(json!({ "iat": now + 3600 })), None),
        ),
        (
            "expired",
            m.logout_token(with(json!({ "exp": now - 600 })), None),
        ),
        ("no jti", m.logout_token(with(json!({ "jti": null })), None)),
        ("no sub or sid", m.logout_token(json!({}), None)),
        ("alg none", unsigned),
        (
            "HS256",
            m.logout_token(target.clone(), Some(json!({ "alg": "HS256", "kid": "k1" }))),
        ),
        (
            "typ",
            m.logout_token(
                target.clone(),
                Some(json!({ "alg": "ES256", "kid": "k1", "typ": "at+jwt" })),
            ),
        ),
        (
            "crit",
            m.logout_token(
                target.clone(),
                Some(json!({ "alg": "ES256", "kid": "k1", "crit": ["x"] })),
            ),
        ),
        ("garbage", "a.b.c".into()),
        ("JWE", "a.b.c.d.e".into()),
    ];
    for (what, t) in cases {
        assert_eq!(e.backchannel(&t).await.0, S::BAD_REQUEST, "{what}");
    }
    // tampered payload (signature over different claims)
    let t = m.logout_token(json!({ "sub": "alice" }), None);
    let (head, rest) = t.split_once('.').unwrap();
    let (_, sig) = rest.split_once('.').unwrap();
    let forged_payload = b64(
        json!({ "iss": m.base, "aud": CLIENT_ID, "iat": now, "jti": "x",
        "events": { "http://schemas.openid.net/event/backchannel-logout": {} }, "sub": "bob" })
        .to_string()
        .as_bytes(),
    );
    assert_eq!(
        e.backchannel(&format!("{head}.{forged_payload}.{sig}"))
            .await
            .0,
        S::BAD_REQUEST,
        "tampered"
    );
    // signed by a key the provider does not publish
    let real = std::mem::replace(&mut *m.key.lock().unwrap(), new_key());
    assert_eq!(
        e.backchannel(&m.logout_token(target.clone(), None)).await.0,
        S::BAD_REQUEST,
        "foreign key"
    );
    *m.key.lock().unwrap() = real;
    // the ID token-shaped JSON body is not a form
    let r = e
        .http
        .post(format!("{}{BACKCHANNEL_PATH}", e.base))
        .json(&json!({ "logout_token": "x" }))
        .send()
        .await
        .unwrap();
    assert!(r.status().is_client_error());

    assert_eq!(
        e.get("/api/v1/whoami", &bob).await.0,
        S::OK,
        "bob survived all of that"
    );

    // key rotation at the provider: the new key (new kid) is fetched
    let k = new_key();
    *m.jwks_key.lock().unwrap() = k.public_key().as_ref().to_vec();
    *m.key.lock().unwrap() = k;
    assert_eq!(
        e.backchannel(&m.logout_token(target.clone(), None)).await.0,
        S::OK
    );
    assert_eq!(e.get("/api/v1/whoami", &bob).await.0, S::UNAUTHORIZED);
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn junk_tokens_do_not_hammer_the_provider() {
    // production throttle: at most one metadata fetch per minute on request
    let e = env_with("throttle", |_| {}, MIN_REFRESH).await;
    let m = &e.mock;
    let forged = |i: u8| {
        let real = std::mem::replace(&mut *m.key.lock().unwrap(), new_key());
        let t = m.logout_token(json!({ "sub": format!("x{i}") }), None);
        *m.key.lock().unwrap() = real;
        t
    };
    for i in 0..20 {
        assert_eq!(e.backchannel(&forged(i)).await.0, S::BAD_REQUEST);
    }
    assert_eq!(
        *m.discoveries.lock().unwrap(),
        1,
        "only the initial discovery"
    );
    // valid tokens still work
    assert_eq!(
        e.backchannel(&m.logout_token(json!({ "sub": "y" }), None))
            .await
            .0,
        S::OK
    );
    let _ = std::fs::remove_dir_all(&e.dir);
}

#[tokio::test]
async fn frontchannel_logout_by_sid() {
    let e = env("fcl", |_| {}).await;
    let user = |sid: &str| json!({ "sub": "alice", "sid": sid, "preferred_username": "alice", "groups": ["noc"] });
    let (_, s1) = e.login(user("fc-1")).await;
    let (_, s2) = e.login(user("fc-2")).await;
    let (s1, s2) = (s1.unwrap(), s2.unwrap());
    let fcl = |q: Vec<(&'static str, String)>| {
        let e = &e;
        async move {
            e.http
                .get(format!("{}{FRONTCHANNEL_PATH}", e.base))
                .query(&q)
                .send()
                .await
                .unwrap()
        }
    };
    let iss = e.mock.base.clone();

    // what the provider's iframe loads
    let r = fcl(vec![("iss", iss.clone()), ("sid", "fc-1".into())]).await;
    assert_eq!(r.status(), S::OK);
    let h = r.headers();
    assert_eq!(
        h["content-security-policy"],
        format!("default-src 'none'; frame-ancestors {iss}")
    );
    assert!(
        h.get("x-frame-options").is_none(),
        "the provider must be able to frame it"
    );
    assert_eq!(h["cache-control"], "no-cache, no-store");
    assert_eq!(e.get("/api/v1/whoami", &s1).await.0, S::UNAUTHORIZED);
    assert_eq!(
        e.get("/api/v1/whoami", &s2).await.0,
        S::OK,
        "other provider session untouched"
    );

    // refused: another issuer, missing parameters, oversized sid
    for q in [
        vec![
            ("iss", "https://evil.example".to_string()),
            ("sid", "fc-2".into()),
        ],
        vec![("iss", format!("{iss}/")), ("sid", "fc-2".into())],
        vec![("sid", "fc-2".to_string())],
        vec![("iss", iss.clone())],
        vec![("iss", iss.clone()), ("sid", "x".repeat(300))],
    ] {
        assert_eq!(fcl(q.clone()).await.status(), S::BAD_REQUEST, "{q:?}");
    }
    assert_eq!(e.get("/api/v1/whoami", &s2).await.0, S::OK);
    // unknown sid: fine, but nothing to audit
    assert_eq!(
        fcl(vec![("iss", iss.clone()), ("sid", "nope".into())])
            .await
            .status(),
        S::OK
    );

    let n = e
        .ctl
        .audit_log(50, u64::MAX)
        .unwrap()
        .iter()
        .filter(|a| a.action == "session.frontchannel_logout")
        .count();
    assert_eq!(n, 1, "only the effective logout is audited");

    // everything else stays unframable
    let r = e
        .http
        .get(format!("{}/api/v1/health", e.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.headers()["x-frame-options"], "DENY");
    assert!(r.headers()["content-security-policy"]
        .to_str()
        .unwrap()
        .contains("frame-ancestors 'none'"));
    let _ = std::fs::remove_dir_all(&e.dir);
}

/// Regression (security review): anyone could fill the table of pending
/// logins (10 000, kept 10 minutes) and so block single sign-on for
/// everybody.
#[tokio::test]
async fn one_client_cannot_block_logins() {
    let e = env("pending", |_| {}).await;
    for _ in 0..10 {
        e.start().await;
    }
    // the 11th from the same client is refused
    let r = e
        .http
        .get(format!("{}/api/v1/oidc/login", e.base))
        .send()
        .await
        .unwrap();
    assert!(
        r.headers()["location"]
            .to_str()
            .unwrap()
            .contains("login-error"),
        "refused"
    );
    // others still get in
    let o = e.ctl.settings.oidc.as_ref().unwrap();
    assert!(o.begin(Some("198.51.100.7".parse().unwrap())).await.is_ok());
    assert!(o
        .begin(Some("2001:db8:1::5".parse().unwrap()))
        .await
        .is_ok());
    let _ = std::fs::remove_dir_all(&e.dir);
}

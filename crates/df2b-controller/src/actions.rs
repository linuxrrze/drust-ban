//! External actions: the controller tells other systems about decisions
//! (DESIGN.md §5, "controller-side actions").
//!
//! Configured in a TOML file (`--actions`):
//!
//! - `[[webhook]]`: HTTPS POST of each event as JSON, optionally signed
//!   (`X-Df2b-Signature: sha256=<hex>` = HMAC-SHA256 with `secret` over
//!   `"<X-Df2b-Timestamp>.<body>"`); retried twice (after 2 s and 10 s).
//!   Redirects are not followed; TLS 1.3, system roots or `ca_file`.
//! - `[[exec]]`: runs a program (absolute path, no shell, cleared
//!   environment, `timeout`) per event with the event as JSON on stdin and
//!   `DF2B_EVENT`, `DF2B_TARGET`, `DF2B_SCOPE`, `DF2B_EXPIRES_AT`,
//!   `DF2B_STILL_BANNED` in the environment. It also gets a `sync` event
//!   with all active bans at start and every `sync_interval`, so a script
//!   that maintains state elsewhere (BGP blackhole routes, a cloud
//!   firewall) can correct drift, e.g. bans that expired while the
//!   controller was down.
//!
//! Events: `ban`, `unban` and `expire` (a ban ran out; the controller
//! schedules these itself). For `unban` and `expire`, `still_banned` tells
//! whether another active ban covers the same target: only withdraw when it
//! is false. Filters per action: `events`, `scopes` ("global",
//! "group:<name>", "group:*", "agents"), `origins` ("agent",
//! "correlation", "user").
//!
//! Each action has its own bounded queue and worker: a slow receiver never
//! slows the controller; when a queue is full, events are dropped and
//! counted (exec actions then get a `sync` as soon as there is room).
//! Counters per action appear in `GET /api/v1/status`.

use std::collections::{BTreeMap, BinaryHeap, HashSet};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use df2b_core::{Decision, DecisionKind, Origin, Scope};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::sync::{broadcast, mpsc};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::state::Controller;

const QUEUE: usize = 1000;
const RETRIES: [Duration; 2] = [Duration::from_secs(2), Duration::from_secs(10)];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Deserialize, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum EventKind {
    Ban,
    Unban,
    Expire,
}

fn all_events() -> Vec<EventKind> {
    vec![EventKind::Ban, EventKind::Unban, EventKind::Expire]
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct WebhookConfig {
    pub name: String,
    pub url: String,
    pub secret: Option<String>,
    pub secret_file: Option<PathBuf>,
    /// Extra request headers (e.g. an authorization header).
    #[serde(default)]
    pub headers: BTreeMap<String, String>,
    /// Trust these CA certificates (PEM) instead of the system roots.
    pub ca_file: Option<PathBuf>,
    /// Allow plain http:// (only for receivers on the same host or network).
    #[serde(default)]
    pub allow_http: bool,
    #[serde(default = "default_webhook_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    #[serde(default = "all_events")]
    pub events: Vec<EventKind>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub origins: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExecConfig {
    pub name: String,
    /// Program (absolute path) and arguments; no shell.
    pub command: Vec<String>,
    #[serde(default = "default_exec_timeout", with = "humantime_serde")]
    pub timeout: Duration,
    /// How often a `sync` event with all active bans is sent ("0s": only at
    /// start).
    #[serde(default = "default_sync", with = "humantime_serde")]
    pub sync_interval: Duration,
    #[serde(default = "all_events")]
    pub events: Vec<EventKind>,
    #[serde(default)]
    pub scopes: Vec<String>,
    #[serde(default)]
    pub origins: Vec<String>,
}

fn default_webhook_timeout() -> Duration {
    Duration::from_secs(5)
}
fn default_exec_timeout() -> Duration {
    Duration::from_secs(10)
}
fn default_sync() -> Duration {
    Duration::from_secs(3600)
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActionsConfig {
    #[serde(default)]
    pub webhook: Vec<WebhookConfig>,
    #[serde(default)]
    pub exec: Vec<ExecConfig>,
}

/// Which decisions an action wants.
#[derive(Debug, Clone)]
struct Filter {
    events: HashSet<EventKind>,
    scopes: Vec<String>,
    origins: Vec<String>,
}

fn scope_name(s: &Scope) -> String {
    match s {
        Scope::Global => "global".into(),
        Scope::Group(g) => format!("group:{g}"),
        Scope::Agents(_) => "agents".into(),
    }
}

fn origin_name(o: &Origin) -> &'static str {
    match o {
        Origin::Agent(_) => "agent",
        Origin::Correlation(_) => "correlation",
        Origin::User(_) => "user",
    }
}

impl Filter {
    fn new(events: &[EventKind], scopes: &[String], origins: &[String]) -> anyhow::Result<Self> {
        for s in scopes {
            let ok = s == "global"
                || s == "agents"
                || s.strip_prefix("group:")
                    .is_some_and(|g| g == "*" || crate::files::valid_group(g));
            if !ok {
                bail!("scope {s:?}: use global, group:<name>, group:* or agents");
            }
        }
        for o in origins {
            if !["agent", "correlation", "user"].contains(&o.as_str()) {
                bail!("origin {o:?}: use agent, correlation or user");
            }
        }
        Ok(Self {
            events: events.iter().copied().collect(),
            scopes: scopes.to_vec(),
            origins: origins.to_vec(),
        })
    }

    fn wants(&self, kind: EventKind, d: &Decision) -> bool {
        let scope = scope_name(&d.scope);
        self.events.contains(&kind)
            && (self.scopes.is_empty()
                || self
                    .scopes
                    .iter()
                    .any(|s| *s == scope || (s == "group:*" && matches!(d.scope, Scope::Group(_)))))
            && (self.origins.is_empty() || self.origins.iter().any(|o| o == origin_name(&d.origin)))
    }
}

/// One event for the workers.
#[derive(Debug, Clone)]
enum Event {
    Decision {
        kind: EventKind,
        decision: Arc<Decision>,
        still_banned: bool,
    },
    /// All active bans (exec actions).
    Sync(Arc<Vec<Decision>>),
}

impl Event {
    fn name(&self) -> &'static str {
        match self {
            Event::Decision {
                kind: EventKind::Ban,
                ..
            } => "ban",
            Event::Decision {
                kind: EventKind::Unban,
                ..
            } => "unban",
            Event::Decision {
                kind: EventKind::Expire,
                ..
            } => "expire",
            Event::Sync(_) => "sync",
        }
    }

    fn body(&self) -> Value {
        let time = Utc::now();
        match self {
            Event::Decision {
                decision,
                still_banned,
                ..
            } => json!({
                "event": self.name(),
                "time": time,
                "decision": **decision,
                "still_banned": still_banned,
            }),
            Event::Sync(bans) => json!({ "event": "sync", "time": time, "bans": **bans }),
        }
    }
}

/// Delivery counters of one action.
#[derive(Debug, Clone, Default, Serialize)]
pub struct ActionStat {
    pub name: String,
    pub kind: &'static str,
    pub delivered: u64,
    pub failed: u64,
    pub dropped: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_error_at: Option<DateTime<Utc>>,
}

/// Counters of all actions (shown in the status).
#[derive(Debug, Default)]
pub struct Stats(Mutex<Vec<ActionStat>>);

impl Stats {
    pub fn snapshot(&self) -> Vec<ActionStat> {
        self.0.lock().map(|v| v.clone()).unwrap_or_default()
    }

    fn update(&self, i: usize, f: impl FnOnce(&mut ActionStat)) {
        if let Ok(mut v) = self.0.lock() {
            if let Some(s) = v.get_mut(i) {
                f(s);
            }
        }
    }
}

impl ActionsConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        use std::os::unix::fs::PermissionsExt;
        let meta =
            std::fs::metadata(path).with_context(|| format!("reading {}", path.display()))?;
        if meta.permissions().mode() & 0o004 != 0 {
            warn!(path = %path.display(), "the actions file is readable by everyone; it may contain secrets");
        }
        let text = std::fs::read_to_string(path)?;
        let cfg: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        let mut names = HashSet::new();
        for (name, events, scopes, origins) in self
            .webhook
            .iter()
            .map(|w| (&w.name, &w.events, &w.scopes, &w.origins))
            .chain(
                self.exec
                    .iter()
                    .map(|e| (&e.name, &e.events, &e.scopes, &e.origins)),
            )
        {
            if name.is_empty() || !names.insert(name.as_str()) {
                bail!("action names must be unique and not empty ({name:?})");
            }
            Filter::new(events, scopes, origins).with_context(|| format!("action {name}"))?;
        }
        for w in &self.webhook {
            let url =
                reqwest::Url::parse(&w.url).with_context(|| format!("webhook {}: url", w.name))?;
            match url.scheme() {
                "https" => {}
                "http" if w.allow_http => {}
                "http" => bail!("webhook {}: http:// needs allow_http = true", w.name),
                s => bail!("webhook {}: unsupported scheme {s}", w.name),
            }
            if w.secret.is_some() && w.secret_file.is_some() {
                bail!("webhook {}: set secret or secret_file, not both", w.name);
            }
            for (k, v) in &w.headers {
                reqwest::header::HeaderName::from_bytes(k.as_bytes())
                    .with_context(|| format!("webhook {}: header {k:?}", w.name))?;
                reqwest::header::HeaderValue::from_str(v)
                    .with_context(|| format!("webhook {}: header {k:?}", w.name))?;
            }
            if w.timeout.is_zero() || w.timeout > Duration::from_secs(60) {
                bail!("webhook {}: timeout must be between 1s and 60s", w.name);
            }
        }
        for e in &self.exec {
            let Some(program) = e.command.first() else {
                bail!("exec {}: empty command", e.name);
            };
            if !Path::new(program).is_absolute() {
                bail!("exec {}: the program must be an absolute path", e.name);
            }
            if e.timeout.is_zero() || e.timeout > Duration::from_secs(600) {
                bail!("exec {}: timeout must be between 1s and 10m", e.name);
            }
        }
        Ok(())
    }
}

/// A prepared webhook.
struct Webhook {
    url: reqwest::Url,
    secret: Option<Vec<u8>>,
    headers: reqwest::header::HeaderMap,
    http: reqwest::Client,
}

impl Webhook {
    fn new(c: &WebhookConfig) -> anyhow::Result<Self> {
        let secret = match (&c.secret, &c.secret_file) {
            (Some(s), None) => Some(s.as_bytes().to_vec()),
            (None, Some(p)) => Some(
                std::fs::read_to_string(p)
                    .with_context(|| format!("reading {}", p.display()))?
                    .trim()
                    .as_bytes()
                    .to_vec(),
            ),
            _ => None,
        };
        let trust = match &c.ca_file {
            Some(p) => df2b_tls::transport::Trust::CaCerts(df2b_tls::pki::certs_from_pem(
                &std::fs::read_to_string(p).with_context(|| format!("reading {}", p.display()))?,
            )?),
            None => df2b_tls::transport::Trust::SystemRoots,
        };
        let tls = df2b_tls::transport::https_client_config(trust)?;
        let http = reqwest::Client::builder()
            .use_preconfigured_tls((*tls).clone())
            .https_only(!c.allow_http)
            // a redirect could send the event (and its signature) elsewhere
            .redirect(reqwest::redirect::Policy::none())
            .timeout(c.timeout)
            .user_agent(concat!("df2b-controller/", env!("CARGO_PKG_VERSION")))
            .build()?;
        let mut headers = reqwest::header::HeaderMap::new();
        for (k, v) in &c.headers {
            headers.insert(
                reqwest::header::HeaderName::from_bytes(k.as_bytes())?,
                reqwest::header::HeaderValue::from_str(v)?,
            );
        }
        Ok(Self {
            url: reqwest::Url::parse(&c.url)?,
            secret,
            headers,
            http,
        })
    }

    async fn send(&self, e: &Event) -> anyhow::Result<()> {
        let body = serde_json::to_vec(&e.body())?;
        let ts = Utc::now().timestamp().to_string();
        let mut req = self
            .http
            .post(self.url.clone())
            .headers(self.headers.clone())
            .header("content-type", "application/json")
            .header("x-df2b-event", e.name())
            .header("x-df2b-timestamp", &ts);
        if let Some(secret) = &self.secret {
            req = req.header("x-df2b-signature", signature(secret, &ts, &body));
        }
        let r = req.body(body).send().await?;
        if !r.status().is_success() {
            bail!("HTTP {}", r.status());
        }
        Ok(())
    }
}

/// `sha256=<hex>` of HMAC-SHA256(secret, "<timestamp>.<body>").
pub fn signature(secret: &[u8], timestamp: &str, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret);
    let mut ctx = ring::hmac::Context::with_key(&key);
    ctx.update(timestamp.as_bytes());
    ctx.update(b".");
    ctx.update(body);
    format!("sha256={}", df2b_tls::hex(ctx.sign().as_ref()))
}

/// A prepared exec action.
struct Exec {
    command: Vec<String>,
    timeout: Duration,
}

impl Exec {
    async fn run(&self, e: &Event) -> anyhow::Result<()> {
        use tokio::io::AsyncWriteExt;
        let mut cmd = tokio::process::Command::new(&self.command[0]);
        cmd.args(&self.command[1..])
            .env_clear()
            .env(
                "PATH",
                "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
            )
            .env("DF2B_EVENT", e.name())
            .stdin(std::process::Stdio::piped())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        if let Event::Decision {
            decision,
            still_banned,
            ..
        } = e
        {
            // validated values only: a prefix, a scope, a time
            cmd.env("DF2B_TARGET", decision.target.to_string())
                .env("DF2B_SCOPE", scope_name(&decision.scope))
                .env(
                    "DF2B_EXPIRES_AT",
                    decision
                        .expires_at
                        .map(|t| t.to_rfc3339())
                        .unwrap_or_default(),
                )
                .env("DF2B_STILL_BANNED", if *still_banned { "1" } else { "0" });
        }
        let mut child = cmd
            .spawn()
            .with_context(|| format!("starting {}", self.command[0]))?;
        let body = serde_json::to_vec(&e.body())?;
        let mut stdin = child.stdin.take().expect("piped");
        let run = async {
            // a program that does not read stdin must not block us
            let _ = stdin.write_all(&body).await;
            drop(stdin);
            child.wait_with_output().await
        };
        let out = tokio::time::timeout(self.timeout, run)
            .await
            .map_err(|_| anyhow::anyhow!("timed out after {:?}", self.timeout))??;
        if !out.status.success() {
            let err = String::from_utf8_lossy(&out.stderr);
            bail!(
                "{}: {}",
                out.status,
                err.trim().chars().take(300).collect::<String>()
            );
        }
        Ok(())
    }
}

enum Sink {
    Webhook(Webhook),
    Exec(Exec),
}

struct Action {
    name: String,
    filter: Filter,
    tx: mpsc::Sender<Event>,
    /// exec: periodic sync
    sync_interval: Option<Duration>,
    /// exec: an event was dropped, send a sync when possible
    needs_sync: bool,
}

/// Starts the actions. Returns once the workers run.
pub fn spawn(ctl: Arc<Controller>, cfg: ActionsConfig) -> anyhow::Result<()> {
    let mut actions = Vec::new();
    let mut sinks = Vec::new();
    for w in &cfg.webhook {
        sinks.push((
            w.name.clone(),
            "webhook",
            Filter::new(&w.events, &w.scopes, &w.origins)?,
            None,
            Sink::Webhook(Webhook::new(w).with_context(|| format!("webhook {}", w.name))?),
        ));
    }
    for e in &cfg.exec {
        sinks.push((
            e.name.clone(),
            "exec",
            Filter::new(&e.events, &e.scopes, &e.origins)?,
            Some(e.sync_interval),
            Sink::Exec(Exec {
                command: e.command.clone(),
                timeout: e.timeout,
            }),
        ));
    }
    if sinks.is_empty() {
        return Ok(());
    }
    if let Ok(mut s) = ctl.actions.0.lock() {
        *s = sinks
            .iter()
            .map(|(name, kind, ..)| ActionStat {
                name: name.clone(),
                kind,
                ..Default::default()
            })
            .collect();
    }
    for (i, (name, kind, filter, sync, sink)) in sinks.into_iter().enumerate() {
        let (tx, rx) = mpsc::channel(QUEUE);
        info!(action = %name, kind, "external action configured");
        tokio::spawn(worker(ctl.clone(), i, name.clone(), sink, rx));
        actions.push(Action {
            name,
            filter,
            tx,
            sync_interval: sync,
            needs_sync: true, // exec: start with a full sync
        });
    }
    tokio::spawn(dispatch(ctl, actions));
    Ok(())
}

async fn worker(
    ctl: Arc<Controller>,
    i: usize,
    name: String,
    sink: Sink,
    mut rx: mpsc::Receiver<Event>,
) {
    while let Some(e) = rx.recv().await {
        let mut result = Ok(());
        for (attempt, wait) in std::iter::once(Duration::ZERO).chain(RETRIES).enumerate() {
            tokio::time::sleep(wait).await;
            result = match &sink {
                Sink::Webhook(w) => w.send(&e).await,
                // a script is not retried: it may have done half its work
                Sink::Exec(x) => x.run(&e).await,
            };
            if result.is_ok() || matches!(sink, Sink::Exec(_)) {
                break;
            }
            debug!(action = %name, attempt, error = %format!("{:#}", result.as_ref().unwrap_err()), "webhook attempt failed");
        }
        match result {
            Ok(()) => ctl.actions.update(i, |s| s.delivered += 1),
            Err(err) => {
                let err = format!("{err:#}");
                warn!(action = %name, event = e.name(), error = %err, "external action failed");
                ctl.actions.update(i, |s| {
                    s.failed += 1;
                    s.last_error = Some(err);
                    s.last_error_at = Some(Utc::now());
                });
            }
        }
    }
}

/// A scheduled expiry: (when, decision id).
#[derive(PartialEq, Eq, PartialOrd, Ord)]
struct Due(std::cmp::Reverse<DateTime<Utc>>, Uuid);

async fn dispatch(ctl: Arc<Controller>, mut actions: Vec<Action>) {
    let mut events = ctl.events();
    let mut due: BinaryHeap<Due> = BinaryHeap::new();
    let mut pending: std::collections::HashMap<Uuid, Arc<Decision>> = Default::default();
    for d in ctl.active_decisions() {
        if let Some(t) = d.expires_at {
            due.push(Due(std::cmp::Reverse(t), d.id));
            pending.insert(d.id, Arc::new(d));
        }
    }
    let mut tick = tokio::time::interval(Duration::from_secs(1));
    let mut last_sync: Vec<tokio::time::Instant> = vec![tokio::time::Instant::now(); actions.len()];
    loop {
        tokio::select! {
            r = events.recv() => match r {
                Ok(d) => {
                    let (kind, still) = match d.kind {
                        DecisionKind::Ban => {
                            if let Some(t) = d.expires_at {
                                due.push(Due(std::cmp::Reverse(t), d.id));
                                pending.insert(d.id, d.clone());
                            }
                            (EventKind::Ban, true)
                        }
                        DecisionKind::Unban { revokes } => {
                            pending.remove(&revokes);
                            (EventKind::Unban, still_banned(&ctl, &d.target))
                        }
                        DecisionKind::Allow => continue,
                    };
                    let e = Event::Decision { kind, decision: d.clone(), still_banned: still };
                    deliver(&mut actions, &ctl, &e, &d, kind);
                }
                Err(broadcast::error::RecvError::Lagged(n)) => {
                    warn!(missed = n, "external actions fell behind; exec actions get a sync");
                    for a in actions.iter_mut() {
                        a.needs_sync = a.sync_interval.is_some();
                    }
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
            _ = tick.tick() => {
                let now = Utc::now();
                while due.peek().is_some_and(|Due(t, _)| t.0 <= now) {
                    let Due(_, id) = due.pop().expect("peeked");
                    // unbanned meanwhile: no expiry
                    let Some(d) = pending.remove(&id) else { continue };
                    let e = Event::Decision {
                        kind: EventKind::Expire,
                        decision: d.clone(),
                        still_banned: still_banned(&ctl, &d.target),
                    };
                    deliver(&mut actions, &ctl, &e, &d, EventKind::Expire);
                }
                // periodic and catch-up syncs (exec actions)
                let mut bans: Option<Arc<Vec<Decision>>> = None;
                for (i, a) in actions.iter_mut().enumerate() {
                    let Some(every) = a.sync_interval else { continue };
                    let periodic = !every.is_zero() && last_sync[i].elapsed() >= every;
                    if !(a.needs_sync || periodic) {
                        continue;
                    }
                    // all active bans once per tick, then per action's filter
                    let list = bans
                        .get_or_insert_with(|| {
                            let now = Utc::now();
                            let mut v: Vec<Decision> = ctl
                                .active_decisions()
                                .into_iter()
                                .filter(|d| d.is_active(now))
                                .collect();
                            v.sort_by_key(|d| d.seq);
                            Arc::new(v)
                        })
                        .clone();
                    let list = Arc::new(
                        list.iter()
                            .filter(|d| a.filter.wants(EventKind::Ban, d))
                            .cloned()
                            .collect::<Vec<_>>(),
                    );
                    if a.tx.try_send(Event::Sync(list)).is_ok() {
                        a.needs_sync = false;
                        last_sync[i] = tokio::time::Instant::now();
                    }
                }
            }
        }
    }
}

/// Whether an active ban still covers exactly this target.
fn still_banned(ctl: &Controller, target: &ipnet::IpNet) -> bool {
    let now = Utc::now();
    ctl.active_decisions()
        .iter()
        .any(|d| d.target == *target && d.is_active(now))
}

fn deliver(actions: &mut [Action], ctl: &Controller, e: &Event, d: &Decision, kind: EventKind) {
    for (i, a) in actions.iter_mut().enumerate() {
        if !a.filter.wants(kind, d) {
            continue;
        }
        if a.tx.try_send(e.clone()).is_err() {
            if a.sync_interval.is_some() {
                a.needs_sync = true;
            }
            ctl.actions.update(i, |s| s.dropped += 1);
            warn!(action = %a.name, "action queue full, event dropped");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn decision(scope: Scope, origin: Origin) -> Decision {
        Decision {
            seq: 1,
            id: Uuid::new_v4(),
            kind: DecisionKind::Ban,
            target: "192.0.2.1/32".parse().unwrap(),
            scope,
            jail: None,
            created_at: Utc::now(),
            expires_at: None,
            origin,
            reason: String::new(),
        }
    }

    #[test]
    fn filters() {
        let all = Filter::new(&all_events(), &[], &[]).unwrap();
        let d = decision(Scope::Global, Origin::User("ada".into()));
        assert!(all.wants(EventKind::Ban, &d));
        let f = Filter::new(
            &[EventKind::Ban],
            &["group:*".into(), "global".into()],
            &["correlation".into()],
        )
        .unwrap();
        assert!(!f.wants(EventKind::Ban, &d), "origin user");
        let c = decision(Scope::Group("web".into()), Origin::Correlation("r".into()));
        assert!(f.wants(EventKind::Ban, &c));
        assert!(!f.wants(EventKind::Unban, &c), "event");
        let a = decision(Scope::Agents(vec![]), Origin::Correlation("r".into()));
        assert!(!f.wants(EventKind::Ban, &a), "scope agents");
        assert!(Filter::new(&[], &["group:../x".into()], &[]).is_err());
        assert!(Filter::new(&[], &[], &["robot".into()]).is_err());
    }

    #[test]
    fn config_validation() {
        let ok = |s: &str| {
            toml::from_str::<ActionsConfig>(s)
                .map_err(|e| e.to_string())
                .and_then(|c| c.validate().map_err(|e| format!("{e:#}")))
        };
        assert!(ok(r#"
            [[webhook]]
            name = "chat"
            url = "https://hooks.example/x"
            secret = "s"
            headers = { authorization = "Bearer x" }
            [[exec]]
            name = "rtbh"
            command = ["/usr/local/bin/rtbh", "--quiet"]
            scopes = ["global"]
        "#)
        .is_ok());
        for bad in [
            r#"[[webhook]]
               name = "a"
               url = "http://hooks.example/x""#,
            r#"[[webhook]]
               name = "a"
               url = "file:///etc/passwd"
               allow_http = true"#,
            r#"[[exec]]
               name = "a"
               command = ["rtbh"]"#,
            r#"[[exec]]
               name = "a"
               command = []"#,
            r#"[[exec]]
               name = "a"
               command = ["/bin/true"]
               [[webhook]]
               name = "a"
               url = "https://x.example""#,
            r#"[[webhook]]
               name = "a"
               url = "https://x.example"
               headers = { "bad header" = "x" }"#,
            r#"[[exec]]
               name = "a"
               command = ["/bin/true"]
               unknown = 1"#,
        ] {
            assert!(ok(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn signature_format() {
        // RFC 4231 test case 2 key/data shape, our framing
        let s = signature(b"Jefe", "1700000000", b"{}");
        assert!(s.starts_with("sha256=") && s.len() == 7 + 64);
        assert_ne!(
            s,
            signature(b"Jefe", "1700000001", b"{}"),
            "timestamp is signed"
        );
    }

    #[tokio::test]
    async fn webhook_and_exec_get_events() {
        use crate::state::{NewDecision, Propagate, Settings};
        use axum::{extract::State as AxState, http::HeaderMap, routing::post, Router};
        let dir = std::env::temp_dir().join(format!("df2b-actions-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ctl = Arc::new(
            Controller::open(
                Settings {
                    state_dir: dir.clone(),
                    cert_lifetime: Duration::from_secs(3600),
                    propagate: Propagate::Global,
                    allowlist: df2b_core::Allowlist::default(),
                    oidc: None,
                    https_internal_ca: true,
                },
                df2b_tls::pki::Ca::generate("t").unwrap(),
                crate::store::Store::open(&dir).unwrap(),
            )
            .unwrap(),
        );

        // a webhook receiver
        type Seen = Arc<Mutex<Vec<(HeaderMap, Vec<u8>)>>>;
        let seen: Seen = Arc::default();
        let app = Router::new()
            .route(
                "/hook",
                post(
                    |AxState(s): AxState<Seen>, h: HeaderMap, body: axum::body::Bytes| async move {
                        s.lock().unwrap().push((h, body.to_vec()));
                        "ok"
                    },
                ),
            )
            .with_state(seen.clone());
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}/hook", l.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(l, app).await.unwrap() });

        // a script that logs what it gets
        let log = dir.join("exec.log");
        let script = dir.join("hook.sh");
        std::fs::write(
            &script,
            format!(
                "#!/bin/sh\nprintf '%s %s %s %s|' \"$DF2B_EVENT\" \"$DF2B_TARGET\" \"$DF2B_STILL_BANNED\" \"${{HOME:-nohome}}\" >> {log}\ncat >> {log}\necho >> {log}\n",
                log = log.display()
            ),
        )
        .unwrap();
        std::fs::set_permissions(&script, std::os::unix::fs::PermissionsExt::from_mode(0o755))
            .unwrap();

        let cfg: ActionsConfig = toml::from_str(&format!(
            r#"
            [[webhook]]
            name = "hook"
            url = "{url}"
            allow_http = true
            secret = "s3cret"
            [[exec]]
            name = "script"
            command = ["{}"]
            "#,
            script.display()
        ))
        .unwrap();
        cfg.validate().unwrap();
        spawn(ctl.clone(), cfg).unwrap();

        let ban = |t: &str, secs: Option<i64>| NewDecision {
            kind: DecisionKind::Ban,
            target: t.parse().unwrap(),
            scope: Scope::Global,
            jail: None,
            expires_at: secs.map(|s| Utc::now() + chrono::Duration::seconds(s)),
            origin: Origin::User("ada".into()),
            reason: "test".into(),
        };
        tokio::time::sleep(Duration::from_millis(1500)).await; // initial sync
        let out = ctl
            .append(vec![
                ban("192.0.2.1/32", Some(2)),
                ban("192.0.2.2/32", None),
            ])
            .unwrap();
        ctl.append(vec![NewDecision {
            kind: DecisionKind::Unban { revokes: out[1].id },
            ..ban("192.0.2.2/32", None)
        }])
        .unwrap();
        tokio::time::sleep(Duration::from_secs(4)).await;

        let got = seen.lock().unwrap().clone();
        let events: Vec<(String, String, bool)> = got
            .iter()
            .map(|(h, b)| {
                let v: Value = serde_json::from_slice(b).unwrap();
                // the signature checks out
                let ts = h["x-df2b-timestamp"].to_str().unwrap();
                assert_eq!(
                    h["x-df2b-signature"].to_str().unwrap(),
                    signature(b"s3cret", ts, b)
                );
                assert_eq!(
                    h["x-df2b-event"].to_str().unwrap(),
                    v["event"].as_str().unwrap()
                );
                (
                    v["event"].as_str().unwrap().to_owned(),
                    v["decision"]["target"].as_str().unwrap().to_owned(),
                    v["still_banned"].as_bool().unwrap(),
                )
            })
            .collect();
        let e = |a: &str, t: &str, s: bool| (a.to_owned(), t.to_owned(), s);
        assert_eq!(
            events,
            [
                e("ban", "192.0.2.1/32", true),
                e("ban", "192.0.2.2/32", true),
                e("unban", "192.0.2.2/32", false),
                e("expire", "192.0.2.1/32", false),
            ]
        );

        let log = std::fs::read_to_string(&log).unwrap();
        let lines: Vec<&str> = log.lines().collect();
        assert!(lines[0].starts_with("sync   nohome|"), "{log}");
        assert!(lines[0].contains(r#""bans":[]"#), "{log}");
        let heads: Vec<&str> = lines.iter().map(|l| l.split('|').next().unwrap()).collect();
        assert_eq!(
            heads,
            [
                "sync   nohome",
                "ban 192.0.2.1/32 1 nohome",
                "ban 192.0.2.2/32 1 nohome",
                "unban 192.0.2.2/32 0 nohome",
                "expire 192.0.2.1/32 0 nohome",
            ],
            "environment cleared (no HOME); {log}"
        );
        let stats = ctl.actions.snapshot();
        assert_eq!((stats[0].delivered, stats[1].delivered), (4, 5));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

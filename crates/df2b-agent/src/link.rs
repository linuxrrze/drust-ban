//! Connection to the controller (DESIGN.md §4.4).
//!
//! Runs as one background task, never blocks detection: if the controller
//! is unreachable the agent keeps working standalone and reconnects with
//! exponential backoff.
//!
//! - **Enrollment** (first start): generate a key locally, connect with a
//!   verifier pinned to the CA fingerprint in the token, send CSR + token,
//!   store `<state_dir>/tls/{ca.pem, agent.pem, identity.json}`.
//! - **Session**: mutual TLS 1.3; `Subscribe(last_seq)` for decisions,
//!   heartbeats every 10 s, local bans reported every second. Reports not
//!   sent yet are kept in `agent.redb` (see `outbox.rs`).
//! - **Renewal**: after 2/3 of the certificate lifetime a new key + CSR is
//!   sent over the authenticated channel; then the session reconnects with
//!   the new certificate.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use df2b_proto::from_unix_ms;
use df2b_proto::v1::agent_service_client::AgentServiceClient;
use df2b_proto::v1::{self, decision_event::Event};
use df2b_tls::pki::{cert_from_pem, cert_to_pem, key_from_pem};
use df2b_tls::{transport, AgentKey, CertInfo, CertificateDer, ClientConfig, EnrollToken};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use tonic::transport::Channel;
use tonic::Code;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::outbox::Outbox;

const HEARTBEAT: Duration = Duration::from_secs(10);
/// Largest message from the controller (a snapshot of ~450 000 bans).
const MAX_MESSAGE: usize = 64 << 20;
const REPORT_INTERVAL: Duration = Duration::from_secs(1);
const REPORT_BATCH: usize = 1000;
const MAX_BACKOFF: Duration = Duration::from_secs(60);

pub struct LinkConfig {
    /// `host:port`
    pub addr: String,
    pub tls_dir: PathBuf,
    pub enroll_token: Option<EnrollToken>,
    pub firewall_backend: &'static str,
    /// Where unsent reports are kept.
    pub state: crate::state::State,
}

/// Values the main loop publishes for heartbeats.
#[derive(Debug, Default)]
pub struct LinkStats {
    pub active_bans: AtomicU64,
    /// Version of the central allowlist the main loop has applied.
    pub allowlist_version: std::sync::Mutex<String>,
    /// Effective jail settings and the policy version applied.
    pub jails: std::sync::Mutex<Vec<v1::JailStatus>>,
    pub jail_policies_version: std::sync::Mutex<String>,
    pub central_jails_version: std::sync::Mutex<String>,
    pub redaction_version: std::sync::Mutex<String>,
    /// Per-source throughput, lag and errors.
    pub sources: crate::health::SourceHealth,
    pub firewall: Arc<crate::health::FirewallHealth>,
    /// A session with the controller is up.
    pub connected: std::sync::atomic::AtomicBool,
    /// The controller's addresses: never banned here (that would cut the
    /// agent off from the unban).
    pub controller_ips: std::sync::Mutex<Vec<std::net::IpAddr>>,
}

impl LinkStats {
    /// Whether `net` contains one of the controller's addresses.
    pub fn covers_controller(&self, net: &IpNet) -> bool {
        self.controller_ips
            .lock()
            .map(|v| v.iter().any(|ip| net.contains(ip)))
            .unwrap_or(false)
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RemoteKind {
    Ban,
    Unban { revokes: Uuid },
    Allow,
}

/// A decision from the controller, validated.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RemoteDecision {
    pub seq: u64,
    pub id: Uuid,
    pub kind: RemoteKind,
    pub target: IpNet,
    pub expires_at: Option<DateTime<Utc>>,
    /// Created from this agent's own report.
    pub own: bool,
}

#[derive(Debug)]
pub enum FromController {
    /// Replaces all previously received decisions.
    Snapshot(Vec<RemoteDecision>),
    Decision(RemoteDecision),
    /// The complete central allowlist (replaces the previous one).
    Allowlist(crate::state::CentralAllowlist),
    /// Central jail settings for this agent (replace earlier ones).
    JailPolicies(crate::state::JailPolicies),
    /// Jails defined on the controller (replace earlier ones).
    CentralJails(crate::central::CentralJails),
    /// Redaction rules for sample lines (replace earlier ones).
    Redaction(crate::state::CentralRedaction),
}

pub fn parse_redaction(r: v1::RedactionRules) -> crate::state::CentralRedaction {
    crate::state::CentralRedaction {
        version: r.version,
        rules: r
            .rules
            .into_iter()
            .map(|r| df2b_core::RedactRule {
                name: r.name,
                pattern: r.pattern,
                replace: r.replace,
                enabled: true,
            })
            .collect(),
    }
}

/// Converts jail policies; implausible entries are dropped (logged), the
/// rest applies.
pub fn parse_jail_policies(p: v1::JailPolicies) -> crate::state::JailPolicies {
    let dur = |ms: Option<i64>, max: Duration| -> Result<Option<Duration>, ()> {
        match ms {
            None => Ok(None),
            Some(ms) if ms > 0 && Duration::from_millis(ms as u64) <= max => {
                Ok(Some(Duration::from_millis(ms as u64)))
            }
            Some(_) => Err(()),
        }
    };
    use crate::engine::{MAX_BANTIME, MAX_FINDTIME};
    let mut jails = Vec::new();
    for j in p.jails {
        let parsed = (|| {
            if j.maxretry == Some(0) {
                return Err(());
            }
            if j.bantime_factor.is_some_and(|f| !f.is_finite() || f < 1.0) {
                return Err(());
            }
            Ok(crate::engine::JailOverride {
                jail: j.jail.clone(),
                enabled: j.enabled,
                maxretry: j.maxretry,
                findtime: dur(j.findtime_ms, MAX_FINDTIME)?,
                bantime: dur(j.bantime_ms, MAX_BANTIME)?,
                factor: j.bantime_factor,
                max_bantime: dur(j.max_bantime_ms, MAX_BANTIME)?,
            })
        })();
        match parsed {
            Ok(o) => jails.push(o),
            Err(()) => warn!(jail = %j.jail, "ignoring implausible jail policy"),
        }
    }
    crate::state::JailPolicies {
        version: p.version,
        jails,
    }
}

/// Parses an allowlist update; `None` if any entry is malformed (a partial
/// list must not replace a complete one).
pub fn parse_allowlist(a: v1::AllowlistUpdate) -> Option<FromController> {
    let networks = a
        .networks
        .iter()
        .map(|n| n.parse::<IpNet>().map(|n| n.trunc()))
        .collect::<Result<Vec<_>, _>>()
        .ok()?;
    // empty: all permanent; otherwise one expiry per network (0 = never)
    if !a.expires_unix_ms.is_empty() && a.expires_unix_ms.len() != networks.len() {
        return None;
    }
    let expires_at = a
        .expires_unix_ms
        .iter()
        .map(|&ms| from_unix_ms(ms))
        .collect();
    Some(FromController::Allowlist(crate::state::CentralAllowlist {
        version: a.version,
        networks,
        expires_at,
    }))
}

/// Longest pause a controller can ask for.
const MAX_HOLD: Duration = Duration::from_secs(300);

/// For a rate-limited report: how many observations of the batch the
/// controller processed (the rest is sent again) and how long to pause.
fn rate_limited(len: usize, ack: &v1::ReportAck) -> Option<(usize, Duration)> {
    if ack.retry_after_ms == 0 {
        return None;
    }
    // older controllers drop what is over the rate and do not say what
    let consumed = ack.consumed.map_or(len, |c| (c as usize).min(len));
    let wait = Duration::from_millis(ack.retry_after_ms.into()).min(MAX_HOLD);
    Some((consumed, wait))
}

pub struct Link {
    pub reports: mpsc::Sender<v1::Observation>,
    pub events: mpsc::Receiver<FromController>,
    task: tokio::task::JoinHandle<()>,
}

impl Link {
    /// Stops the link and waits (at most `timeout`) until the reports not
    /// sent yet are saved.
    pub async fn shutdown(self, timeout: Duration) {
        let Link {
            reports,
            events,
            task,
        } = self;
        drop((reports, events));
        if tokio::time::timeout(timeout, task).await.is_err() {
            warn!("controller link did not stop in time; recent reports may be lost");
        }
    }
}

pub fn spawn(cfg: LinkConfig, stats: Arc<LinkStats>) -> Link {
    let (report_tx, report_rx) = mpsc::channel(4096);
    let (event_tx, event_rx) = mpsc::channel(1024);
    let outbox = Outbox::open(Some(cfg.state.clone()));
    let task = tokio::spawn(async move {
        let mut task = Task {
            cfg,
            stats,
            reports: report_rx,
            events: event_tx,
            outbox,
            hold_until: None,
            last_seq: 0,
        };
        task.run().await;
        task.drain_and_persist().await;
    });
    Link {
        reports: report_tx,
        events: event_rx,
        task,
    }
}

// ------------------------------------------------------------------ identity

#[derive(Serialize, Deserialize)]
struct IdentityFile {
    agent_id: String,
    group: String,
}

struct Identity {
    agent_id: String,
    group: String,
    ca: CertificateDer<'static>,
    cert: CertificateDer<'static>,
    key_pem: String,
    info: CertInfo,
}

const CA_FILE: &str = "ca.pem";
/// Certificate and key in one file, so renewal replaces both atomically.
const AGENT_FILE: &str = "agent.pem";
const IDENTITY_FILE: &str = "identity.json";

fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension("tmp");
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

impl Identity {
    fn new(
        group: String,
        ca: CertificateDer<'static>,
        cert: CertificateDer<'static>,
        key_pem: String,
    ) -> anyhow::Result<Self> {
        let info = CertInfo::parse(&cert)?;
        key_from_pem(&key_pem)?;
        Ok(Self {
            agent_id: info.common_name.clone(),
            group,
            ca,
            cert,
            key_pem,
            info,
        })
    }

    fn load(dir: &Path) -> anyhow::Result<Option<Self>> {
        let agent = dir.join(AGENT_FILE);
        if !agent.exists() {
            return Ok(None);
        }
        let read = |name: &str| {
            let p = dir.join(name);
            fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))
        };
        let agent_pem = read(AGENT_FILE)?;
        let id: IdentityFile = serde_json::from_str(&read(IDENTITY_FILE)?)?;
        let me = Self::new(
            id.group,
            cert_from_pem(&read(CA_FILE)?)?,
            cert_from_pem(&agent_pem)?,
            agent_pem,
        )?;
        if me.agent_id != id.agent_id {
            bail!(
                "{}: certificate does not match identity.json",
                dir.display()
            );
        }
        Ok(Some(me))
    }

    /// Writes all files; `agent.pem` last, its presence marks "enrolled".
    fn save(&self, dir: &Path) -> anyhow::Result<()> {
        fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
        fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
        write_atomic(&dir.join(CA_FILE), cert_to_pem(&self.ca).as_bytes(), 0o644)?;
        self.save_identity_file(dir)?;
        self.save_cert(dir)
    }

    fn save_identity_file(&self, dir: &Path) -> anyhow::Result<()> {
        let id = IdentityFile {
            agent_id: self.agent_id.clone(),
            group: self.group.clone(),
        };
        write_atomic(
            &dir.join(IDENTITY_FILE),
            &serde_json::to_vec_pretty(&id)?,
            0o644,
        )?;
        Ok(())
    }

    fn save_cert(&self, dir: &Path) -> anyhow::Result<()> {
        let pem = format!("{}{}", cert_to_pem(&self.cert), self.key_pem);
        write_atomic(&dir.join(AGENT_FILE), pem.as_bytes(), 0o600)?;
        Ok(())
    }

    fn client_config(&self) -> anyhow::Result<Arc<ClientConfig>> {
        transport::client_config(&self.ca, self.cert.clone(), key_from_pem(&self.key_pem)?)
    }

    fn needs_renewal(&self, now: DateTime<Utc>) -> bool {
        now >= self.info.renew_at()
    }
}

fn hostname() -> String {
    fs::read_to_string("/proc/sys/kernel/hostname")
        .map(|s| s.trim().to_owned())
        .unwrap_or_default()
}

/// One line, without tonic's metadata dump and without repeating causes
/// that the previous message already contains.
fn fmt_err(e: &anyhow::Error) -> String {
    let mut parts: Vec<String> = Vec::new();
    for cause in e.chain() {
        let msg = match cause.downcast_ref::<tonic::Status>() {
            Some(s) => format!("{:?}: {}", s.code(), s.message()),
            None => cause.to_string(),
        };
        if !parts.last().is_some_and(|p| p.contains(&msg)) {
            parts.push(msg);
        }
    }
    parts.join(": ")
}

fn expired_error(id: &Identity) {
    error!(
        agent = %id.agent_id,
        expired = %id.info.not_after,
        "agent certificate expired (controller unreachable for too long?); \
         re-enroll with a new --enroll-token; running standalone"
    );
}

/// Rejections that retrying cannot fix.
fn is_permanent(e: &anyhow::Error) -> bool {
    e.downcast_ref::<tonic::Status>().is_some_and(|s| {
        matches!(
            s.code(),
            Code::PermissionDenied | Code::InvalidArgument | Code::Unauthenticated
        )
    })
}

/// The controller closed the stream on purpose (group change, lagging
/// stream) and expects an immediate resubscription.
fn is_resubscribe(e: &anyhow::Error) -> bool {
    e.downcast_ref::<tonic::Status>()
        .is_some_and(|s| s.code() == Code::Aborted)
}

pub fn parse_decision(d: v1::Decision, own_origin: &str) -> Option<RemoteDecision> {
    let kind = match d.kind() {
        v1::DecisionKind::Ban => RemoteKind::Ban,
        v1::DecisionKind::Unban => RemoteKind::Unban {
            revokes: d.revokes.parse().ok()?,
        },
        v1::DecisionKind::Allow => RemoteKind::Allow,
        v1::DecisionKind::Unspecified => return None,
    };
    Some(RemoteDecision {
        seq: d.seq,
        id: d.id.parse().ok()?,
        kind,
        target: d.target.parse::<IpNet>().ok()?.trunc(),
        expires_at: from_unix_ms(d.expires_unix_ms),
        own: d.origin == own_origin,
    })
}

// ---------------------------------------------------------------------- task

enum End {
    /// Certificate renewed: reconnect right away.
    Renewed,
    /// The agent is shutting down.
    Shutdown,
}

struct Task {
    cfg: LinkConfig,
    stats: Arc<LinkStats>,
    reports: mpsc::Receiver<v1::Observation>,
    events: mpsc::Sender<FromController>,
    outbox: Outbox,
    /// The controller asked to pause reports until then.
    hold_until: Option<tokio::time::Instant>,
    last_seq: u64,
}

impl Task {
    async fn run(&mut self) {
        let Some(mut identity) = self.identity().await else {
            return;
        };
        info!(agent = %identity.agent_id, group = %identity.group, controller = %self.cfg.addr, "controller link starting");
        let mut backoff = Duration::from_secs(1);
        loop {
            if Utc::now() >= identity.info.not_after {
                expired_error(&identity);
                return;
            }
            let mut connected = false;
            let result = self.session(&mut identity, &mut connected).await;
            self.stats.connected.store(false, Ordering::Relaxed);
            match result {
                Ok(End::Shutdown) => return,
                Ok(End::Renewed) => continue,
                Err(e) => {
                    if connected {
                        backoff = Duration::from_secs(1);
                    }
                    if connected && is_resubscribe(&e) {
                        info!(reason = %fmt_err(&e), "controller asked to resubscribe");
                        continue;
                    }
                    if is_permanent(&e) {
                        error!(error = %fmt_err(&e), "controller rejected this agent");
                        backoff = MAX_BACKOFF;
                    } else {
                        warn!(error = %fmt_err(&e), retry_in = ?backoff, "controller connection failed");
                    }
                }
            }
            if !self.wait(backoff).await {
                return;
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    /// Loads the saved identity or enrolls. `None`: give up (logged).
    async fn identity(&mut self) -> Option<Identity> {
        match Identity::load(&self.cfg.tls_dir) {
            Ok(Some(i)) if Utc::now() < i.info.not_after => return Some(i),
            Ok(Some(i)) => {
                if self.cfg.enroll_token.is_none() {
                    expired_error(&i);
                    return None;
                }
                warn!(old_agent = %i.agent_id, "agent certificate expired, enrolling again");
            }
            Ok(None) => {}
            Err(e) => {
                error!(error = %fmt_err(&e), "cannot load agent certificate; running standalone");
                return None;
            }
        }
        let Some(token) = self.cfg.enroll_token.clone() else {
            error!(
                "not enrolled with the controller: start once with --enroll-token \
                 (df2b-controller enroll-token); running standalone"
            );
            return None;
        };
        let mut backoff = Duration::from_secs(1);
        loop {
            match self.enroll(&token).await {
                Ok(i) => {
                    info!(agent = %i.agent_id, group = %i.group, "enrolled with the controller");
                    return Some(i);
                }
                Err(e) if is_permanent(&e) => {
                    error!(error = %fmt_err(&e), "enrollment rejected; running standalone");
                    return None;
                }
                Err(e) => {
                    warn!(error = %fmt_err(&e), retry_in = ?backoff, "enrollment failed");
                }
            }
            if !self.wait(backoff).await {
                return None;
            }
            backoff = (backoff * 2).min(MAX_BACKOFF);
        }
    }

    async fn enroll(&self, token: &EnrollToken) -> anyhow::Result<Identity> {
        let host = hostname();
        let key = AgentKey::generate(&host)?;
        let tls = transport::enrollment_client_config(token.ca_fingerprint)?;
        let channel = transport::connect(self.cfg.addr.clone(), tls).await?;
        let resp = AgentServiceClient::new(channel)
            .enroll(v1::EnrollRequest {
                token: token.to_string(),
                hostname: host,
                csr_der: key.csr_der,
                agent_version: env!("CARGO_PKG_VERSION").into(),
            })
            .await?
            .into_inner();
        if df2b_tls::pki::fingerprint(&resp.ca_certificate_der) != token.ca_fingerprint {
            bail!("controller returned a CA that does not match the enrollment token");
        }
        let identity = Identity::new(
            resp.group,
            resp.ca_certificate_der.into(),
            resp.certificate_der.into(),
            key.key_pem,
        )?;
        if identity.agent_id != resp.agent_id {
            bail!("certificate does not match the assigned agent id");
        }
        identity.save(&self.cfg.tls_dir)?;
        Ok(identity)
    }

    async fn session(&mut self, id: &mut Identity, connected: &mut bool) -> anyhow::Result<End> {
        if let Ok(addrs) = tokio::net::lookup_host(self.cfg.addr.as_str()).await {
            let ips: Vec<std::net::IpAddr> = addrs.map(|a| a.ip()).collect();
            if let Ok(mut v) = self.stats.controller_ips.lock() {
                *v = ips;
            }
        }
        let channel = transport::connect(self.cfg.addr.clone(), id.client_config()?).await?;
        // a snapshot of many bans exceeds tonic's 4 MiB default
        let mut client = AgentServiceClient::new(channel).max_decoding_message_size(MAX_MESSAGE);
        let mut stream = client
            .subscribe(v1::SubscribeRequest {
                from_seq: self.last_seq,
            })
            .await?
            .into_inner();
        *connected = true;
        self.stats.connected.store(true, Ordering::Relaxed);
        info!(from_seq = self.last_seq, "connected to controller");
        let own_origin = format!("agent:{}", id.agent_id);
        let mut heartbeat = tokio::time::interval(HEARTBEAT);
        let mut flush = tokio::time::interval(REPORT_INTERVAL);
        loop {
            tokio::select! {
                msg = stream.message() => {
                    let Some(ev) = msg? else { bail!("decision stream closed by controller") };
                    let out = match ev.event {
                        Some(Event::Snapshot(s)) => {
                            self.last_seq = s.seq;
                            FromController::Snapshot(
                                s.active.into_iter().filter_map(|d| parse_decision(d, &own_origin)).collect(),
                            )
                        }
                        Some(Event::Decision(d)) => {
                            self.last_seq = self.last_seq.max(d.seq);
                            match parse_decision(d, &own_origin) {
                                Some(d) => FromController::Decision(d),
                                None => { warn!("ignoring malformed decision"); continue; }
                            }
                        }
                        Some(Event::JailPolicies(p)) => FromController::JailPolicies(parse_jail_policies(p)),
                        Some(Event::CentralJails(c)) => FromController::CentralJails(crate::central::from_proto(c)),
                        Some(Event::Redaction(r)) => FromController::Redaction(parse_redaction(r)),
                        Some(Event::Allowlist(a)) => match parse_allowlist(a) {
                            Some(ev) => ev,
                            None => { warn!("ignoring malformed allowlist update, keeping the previous one"); continue; }
                        },
                        None => continue,
                    };
                    if self.events.send(out).await.is_err() {
                        return Ok(End::Shutdown);
                    }
                }
                r = self.reports.recv() => match r {
                    Some(o) => self.outbox.push(o),
                    None => return Ok(End::Shutdown),
                },
                _ = flush.tick() => {
                    let sent = self.flush(&mut client).await;
                    // whatever is left goes to disk
                    self.outbox.persist().await;
                    sent?;
                }
                _ = heartbeat.tick() => {
                    let firewall_error = self.stats.firewall.error();
                    let hb = client.heartbeat(v1::HeartbeatRequest {
                        agent_version: env!("CARGO_PKG_VERSION").into(),
                        agent_time_unix_ms: Utc::now().timestamp_millis(),
                        sources: self.stats.sources.report(),
                        active_bans: self.stats.active_bans.load(Ordering::Relaxed),
                        firewall_backend: self.cfg.firewall_backend.into(),
                        firewall_healthy: firewall_error.is_none(),
                        firewall_error: firewall_error.unwrap_or_default(),
                        last_applied_seq: self.last_seq,
                        allowlist_version: self.stats.allowlist_version.lock().map(|v| v.clone()).unwrap_or_default(),
                        jails: self.stats.jails.lock().map(|v| v.clone()).unwrap_or_default(),
                        jail_policies_version: self.stats.jail_policies_version.lock().map(|v| v.clone()).unwrap_or_default(),
                        central_jails_version: self.stats.central_jails_version.lock().map(|v| v.clone()).unwrap_or_default(),
                        redaction_version: self.stats.redaction_version.lock().map(|v| v.clone()).unwrap_or_default(),
                    }).await?.into_inner();
                    // the controller decides the group (it filters the
                    // decisions); keep the local copy for logs up to date
                    if let Some(g) = hb.groups.first().filter(|g| **g != id.group) {
                        info!(from = %id.group, to = %g, "group changed by the controller");
                        id.group = g.clone();
                        if let Err(e) = id.save_identity_file(&self.cfg.tls_dir) {
                            warn!(error = %format!("{e:#}"), "saving the new group failed");
                        }
                    }
                    if id.needs_renewal(Utc::now()) {
                        self.renew(&mut client, id).await?;
                        return Ok(End::Renewed);
                    }
                }
            }
        }
    }

    async fn renew(
        &self,
        client: &mut AgentServiceClient<Channel>,
        id: &mut Identity,
    ) -> anyhow::Result<()> {
        let key = AgentKey::generate(&hostname())?;
        let resp = client
            .renew(v1::RenewRequest {
                csr_der: key.csr_der,
            })
            .await?
            .into_inner();
        if resp.ca_certificate_der != id.ca.as_ref() {
            bail!("controller CA changed during renewal; refusing");
        }
        let renewed = Identity::new(
            id.group.clone(),
            id.ca.clone(),
            resp.certificate_der.into(),
            key.key_pem,
        )?;
        if renewed.agent_id != id.agent_id {
            bail!("renewed certificate is for another agent");
        }
        renewed.save_cert(&self.cfg.tls_dir)?;
        info!(not_after = %renewed.info.not_after, "agent certificate renewed");
        *id = renewed;
        Ok(())
    }

    async fn flush(&mut self, client: &mut AgentServiceClient<Channel>) -> anyhow::Result<()> {
        if let Some(t) = self.hold_until {
            if tokio::time::Instant::now() < t {
                return Ok(());
            }
            self.hold_until = None;
        }
        while !self.outbox.is_empty() {
            let batch = self.outbox.take(REPORT_BATCH);
            let observations = batch.iter().map(|e| e.obs.clone()).collect();
            let ack = match client.report(v1::ObservationBatch { observations }).await {
                Ok(r) => r.into_inner(),
                Err(e) => {
                    // keep them for the next connection
                    self.outbox.unsent(batch);
                    return Err(e.into());
                }
            };
            let Some((consumed, wait)) = rate_limited(batch.len(), &ack) else {
                self.outbox.sent(batch);
                continue;
            };
            let mut batch = batch;
            let rest = batch.split_off(consumed);
            self.outbox.sent(batch);
            self.outbox.unsent(rest);
            self.hold_until = Some(tokio::time::Instant::now() + wait);
            warn!(
                retry_in = ?wait,
                queued = self.outbox.len(),
                "controller rate limit reached, pausing reports"
            );
            break;
        }
        Ok(())
    }

    /// On shutdown: takes the reports still in the channel and saves all
    /// unsent ones.
    async fn drain_and_persist(&mut self) {
        self.reports.close();
        while let Ok(o) = self.reports.try_recv() {
            self.outbox.push(o);
        }
        self.outbox.persist().await;
        if !self.outbox.is_empty() {
            info!(
                count = self.outbox.len(),
                "unsent reports saved for the next start"
            );
        }
    }

    /// Sleeps while still accepting reports. `false`: shutting down.
    /// Saves new reports to disk once per report interval meanwhile.
    async fn wait(&mut self, d: Duration) -> bool {
        let sleep = tokio::time::sleep(d);
        tokio::pin!(sleep);
        let mut save = tokio::time::interval(REPORT_INTERVAL);
        loop {
            tokio::select! {
                _ = &mut sleep => return true,
                r = self.reports.recv() => match r {
                    Some(o) => self.outbox.push(o),
                    None => return false,
                },
                _ = save.tick() => self.outbox.persist().await,
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_decisions() {
        let id = Uuid::new_v4();
        let d = v1::Decision {
            seq: 3,
            id: id.to_string(),
            kind: v1::DecisionKind::Ban.into(),
            target: "2001:db8::1/64".into(),
            origin: "agent:me".into(),
            ..Default::default()
        };
        let r = parse_decision(d.clone(), "agent:me").unwrap();
        assert_eq!(r.target, "2001:db8::/64".parse::<IpNet>().unwrap());
        assert!(r.own && r.expires_at.is_none());
        assert!(!parse_decision(d.clone(), "agent:other").unwrap().own);
        let bad = v1::Decision {
            kind: v1::DecisionKind::Unban.into(),
            revokes: "nope".into(),
            ..d
        };
        assert!(parse_decision(bad, "").is_none());
    }

    #[test]
    fn identity_roundtrip_and_renewal_window() {
        let dir = std::env::temp_dir().join(format!("df2b-agent-tls-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let ca = df2b_tls::Ca::generate("t").unwrap();
        let key = AgentKey::generate("h").unwrap();
        let cert = ca
            .sign_agent_csr(&key.csr_der, "web-1-abc", Duration::from_secs(30 * 86400))
            .unwrap();
        let id = Identity::new("web".into(), ca.cert_der().clone(), cert, key.key_pem).unwrap();
        id.save(&dir).unwrap();
        let mode = fs::metadata(dir.join(AGENT_FILE))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        let loaded = Identity::load(&dir).unwrap().unwrap();
        assert_eq!(
            (loaded.agent_id.as_str(), loaded.group.as_str()),
            ("web-1-abc", "web")
        );
        loaded.client_config().unwrap();
        assert!(!loaded.needs_renewal(Utc::now()));
        assert!(loaded.needs_renewal(Utc::now() + chrono::Duration::days(21)));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_updates() {
        let ok = parse_allowlist(v1::AllowlistUpdate {
            version: "v1".into(),
            networks: vec!["192.0.2.7/24".into(), "2001:db8::/48".into()],
            ..Default::default()
        });
        let Some(FromController::Allowlist(crate::state::CentralAllowlist {
            version,
            networks,
            ..
        })) = ok
        else {
            panic!()
        };
        assert_eq!(version, "v1");
        assert_eq!(networks[0].to_string(), "192.0.2.0/24", "normalized");
        // one bad entry: the whole update is ignored, not applied partially
        assert!(parse_allowlist(v1::AllowlistUpdate {
            version: "v2".into(),
            networks: vec!["192.0.2.0/24".into(), "nonsense".into()],
            ..Default::default()
        })
        .is_none());
        // expiries: one per network
        let now_ms = Utc::now().timestamp_millis();
        let Some(FromController::Allowlist(t)) = parse_allowlist(v1::AllowlistUpdate {
            version: "v3".into(),
            networks: vec!["192.0.2.0/24".into(), "198.51.100.7/32".into()],
            expires_unix_ms: vec![0, now_ms + 3_600_000],
        }) else {
            panic!()
        };
        assert_eq!(t.expires_at[0], None);
        assert!(t.expires_at[1].is_some());
        assert!(
            parse_allowlist(v1::AllowlistUpdate {
                version: "v4".into(),
                networks: vec!["192.0.2.0/24".into()],
                expires_unix_ms: vec![0, 0],
            })
            .is_none(),
            "mismatched lengths"
        );
    }

    #[test]
    fn jail_policies() {
        let p = parse_jail_policies(v1::JailPolicies {
            version: "v1".into(),
            jails: vec![
                v1::JailPolicy {
                    jail: "sshd".into(),
                    maxretry: Some(3),
                    bantime_ms: Some(7_200_000),
                    ..Default::default()
                },
                v1::JailPolicy {
                    jail: "bad1".into(),
                    maxretry: Some(0),
                    ..Default::default()
                },
                v1::JailPolicy {
                    jail: "bad2".into(),
                    bantime_ms: Some(-5),
                    ..Default::default()
                },
                v1::JailPolicy {
                    jail: "bad3".into(),
                    bantime_factor: Some(f64::NAN),
                    ..Default::default()
                },
                v1::JailPolicy {
                    jail: "nginx".into(),
                    enabled: Some(false),
                    ..Default::default()
                },
            ],
        });
        let names: Vec<_> = p.jails.iter().map(|j| j.jail.as_str()).collect();
        assert_eq!(names, ["sshd", "nginx"], "implausible entries dropped");
        assert_eq!(p.jails[0].bantime, Some(Duration::from_secs(7200)));
        assert_eq!(p.jails[0].findtime, None);
    }

    #[test]
    fn rate_limit_ack() {
        let ack = |retry, consumed| v1::ReportAck {
            accepted: 0,
            retry_after_ms: retry,
            consumed,
        };
        assert_eq!(rate_limited(10, &ack(0, None)), None);
        assert_eq!(
            rate_limited(10, &ack(1500, Some(4))),
            Some((4, Duration::from_millis(1500)))
        );
        // older controller: nothing to send again; implausible values capped
        assert_eq!(
            rate_limited(10, &ack(60_000, None)),
            Some((10, Duration::from_secs(60)))
        );
        assert_eq!(
            rate_limited(10, &ack(u32::MAX, Some(99))),
            Some((10, MAX_HOLD))
        );
    }

    #[test]
    fn controller_address_is_never_banned() {
        let s = LinkStats::default();
        *s.controller_ips.lock().unwrap() = vec!["198.51.100.10".parse().unwrap()];
        assert!(s.covers_controller(&"198.51.100.0/24".parse().unwrap()));
        assert!(!s.covers_controller(&"198.51.101.0/24".parse().unwrap()));
    }

    /// Regression (security review): a huge findtime from the controller
    /// made the tracker's date arithmetic overflow - a panic, and with the
    /// policy saved, a crash loop.
    #[test]
    fn implausible_policies_are_dropped() {
        let p = |findtime_ms: Option<i64>| v1::JailPolicies {
            version: "v".into(),
            jails: vec![v1::JailPolicy {
                jail: "sshd".into(),
                findtime_ms,
                ..Default::default()
            }],
        };
        assert_eq!(parse_jail_policies(p(Some(i64::MAX))).jails.len(), 0);
        assert_eq!(parse_jail_policies(p(Some(8 * 86_400_000))).jails.len(), 0);
        assert_eq!(parse_jail_policies(p(Some(600_000))).jails.len(), 1);
        // and the tracker itself cannot overflow
        let mut t = crate::tracker::Tracker::new(3, std::time::Duration::MAX, 10);
        let now = Utc::now();
        t.record(
            df2b_core::IpKey::from_addr("192.0.2.1".parse().unwrap(), Default::default()),
            now,
            now,
        );
        t.prune(now);
    }
}

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
//!   heartbeats every 10 s, local bans reported every second.
//! - **Renewal**: after 2/3 of the certificate lifetime a new key + CSR is
//!   sent over the authenticated channel; then the session reconnects with
//!   the new certificate.

use std::collections::VecDeque;
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

const HEARTBEAT: Duration = Duration::from_secs(10);
const REPORT_INTERVAL: Duration = Duration::from_secs(1);
const REPORT_BATCH: usize = 1000;
/// Reports kept while the controller is unreachable (oldest dropped first).
/// TODO: persist in redb so a restart does not lose them.
const MAX_PENDING: usize = 10_000;
const MAX_BACKOFF: Duration = Duration::from_secs(60);

pub struct LinkConfig {
    /// `host:port`
    pub addr: String,
    pub tls_dir: PathBuf,
    pub enroll_token: Option<EnrollToken>,
    pub firewall_backend: &'static str,
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
}

/// Converts jail policies; implausible entries are dropped (logged), the
/// rest applies.
pub fn parse_jail_policies(p: v1::JailPolicies) -> crate::state::JailPolicies {
    let dur = |ms: Option<i64>| -> Result<Option<Duration>, ()> {
        match ms {
            None => Ok(None),
            Some(ms) if ms > 0 => Ok(Some(Duration::from_millis(ms as u64))),
            Some(_) => Err(()),
        }
    };
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
                findtime: dur(j.findtime_ms)?,
                bantime: dur(j.bantime_ms)?,
                factor: j.bantime_factor,
                max_bantime: dur(j.max_bantime_ms)?,
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

pub struct Link {
    pub reports: mpsc::Sender<v1::Observation>,
    pub events: mpsc::Receiver<FromController>,
}

pub fn spawn(cfg: LinkConfig, stats: Arc<LinkStats>) -> Link {
    let (report_tx, report_rx) = mpsc::channel(4096);
    let (event_tx, event_rx) = mpsc::channel(1024);
    tokio::spawn(async move {
        let mut task = Task {
            cfg,
            stats,
            reports: report_rx,
            events: event_tx,
            pending: VecDeque::new(),
            dropped: 0,
            last_seq: 0,
        };
        task.run().await;
    });
    Link {
        reports: report_tx,
        events: event_rx,
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
    pending: VecDeque<v1::Observation>,
    dropped: u64,
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
            match self.session(&mut identity, &mut connected).await {
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
        let channel = transport::connect(self.cfg.addr.clone(), id.client_config()?).await?;
        let mut client = AgentServiceClient::new(channel);
        let mut stream = client
            .subscribe(v1::SubscribeRequest {
                from_seq: self.last_seq,
            })
            .await?
            .into_inner();
        *connected = true;
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
                    Some(o) => self.push(o),
                    None => return Ok(End::Shutdown),
                },
                _ = flush.tick() => self.flush(&mut client).await?,
                _ = heartbeat.tick() => {
                    let hb = client.heartbeat(v1::HeartbeatRequest {
                        agent_version: env!("CARGO_PKG_VERSION").into(),
                        agent_time_unix_ms: Utc::now().timestamp_millis(),
                        sources: Vec::new(), // TODO: per-source rate and lag
                        active_bans: self.stats.active_bans.load(Ordering::Relaxed),
                        firewall_backend: self.cfg.firewall_backend.into(),
                        firewall_healthy: true, // TODO: backend health check
                        last_applied_seq: self.last_seq,
                        allowlist_version: self.stats.allowlist_version.lock().map(|v| v.clone()).unwrap_or_default(),
                        jails: self.stats.jails.lock().map(|v| v.clone()).unwrap_or_default(),
                        jail_policies_version: self.stats.jail_policies_version.lock().map(|v| v.clone()).unwrap_or_default(),
                        central_jails_version: self.stats.central_jails_version.lock().map(|v| v.clone()).unwrap_or_default(),
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

    fn push(&mut self, o: v1::Observation) {
        if self.pending.len() >= MAX_PENDING {
            // failure counts go first: ban reports drive propagation and
            // quorum rules
            match self.pending.iter().position(|p| !p.locally_banned) {
                Some(i) => {
                    self.pending.remove(i);
                }
                None => {
                    self.pending.pop_front();
                }
            }
            self.dropped += 1;
            if self.dropped.is_power_of_two() {
                warn!(
                    dropped = self.dropped,
                    "controller unreachable, dropping old reports"
                );
            }
        }
        self.pending.push_back(o);
    }

    async fn flush(&mut self, client: &mut AgentServiceClient<Channel>) -> anyhow::Result<()> {
        while !self.pending.is_empty() {
            let n = self.pending.len().min(REPORT_BATCH);
            let batch: Vec<_> = self.pending.drain(..n).collect();
            if let Err(e) = client
                .report(v1::ObservationBatch {
                    observations: batch.clone(),
                })
                .await
            {
                // keep them for the next connection
                for o in batch.into_iter().rev() {
                    self.pending.push_front(o);
                }
                return Err(e.into());
            }
        }
        Ok(())
    }

    /// Sleeps while still accepting reports. `false`: shutting down.
    async fn wait(&mut self, d: Duration) -> bool {
        let sleep = tokio::time::sleep(d);
        tokio::pin!(sleep);
        loop {
            tokio::select! {
                _ = &mut sleep => return true,
                r = self.reports.recv() => match r {
                    Some(o) => self.push(o),
                    None => return false,
                },
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
}

//! `AgentService` over mutual TLS.
//!
//! The agent identity is taken from the verified client certificate (CN),
//! never from message fields. `Enroll` is the only RPC that accepts a
//! connection without client certificate; it is authenticated by the token.

// tonic::Status is large; boxing it would only fight the framework
#![allow(clippy::result_large_err)]

use std::sync::Arc;
use std::time::Duration;

use chrono::Utc;
use df2b_core::{AgentId, DecisionKind, Origin, Scope};
use df2b_proto::from_unix_ms;
use df2b_proto::v1::agent_service_server::AgentService;
use df2b_proto::v1::{self, decision_event::Event};
use df2b_tls::{CertInfo, EnrollToken};
use ipnet::IpNet;
use tokio::sync::{broadcast, mpsc};
use tokio_stream::wrappers::ReceiverStream;
use tonic::{Request, Response, Status};
use tracing::{info, warn};

use crate::files;
use crate::state::{applies, AuthError, Controller, Initial, NewDecision, Propagate};
use crate::store::AgentRecord;

/// Maximum observations per Report call.
const MAX_REPORT: usize = 10_000;
/// How often open streams re-check revocation.
const REVOCATION_CHECK: Duration = Duration::from_secs(5);

pub struct Service {
    ctl: Arc<Controller>,
}

impl Service {
    pub fn new(ctl: Arc<Controller>) -> Self {
        Self { ctl }
    }

    fn auth<T>(&self, req: &Request<T>) -> Result<(AgentRecord, CertInfo), Status> {
        let certs = req.peer_certs();
        let cert = certs.as_ref().and_then(|c| c.first());
        let record = self
            .ctl
            .authenticate(cert.map(|c| c.as_ref()))
            .map_err(|e| match e {
                AuthError::NoCertificate => Status::unauthenticated(e.to_string()),
                _ => Status::permission_denied(e.to_string()),
            })?;
        let info = CertInfo::parse(cert.expect("authenticated")).map_err(internal)?;
        Ok((record, info))
    }
}

fn internal(e: impl std::fmt::Display) -> Status {
    tracing::error!(error = %e, "internal error");
    Status::internal("internal error")
}

fn invalid_token() -> Status {
    // one message for unknown, used, expired and foreign tokens
    Status::permission_denied("invalid or expired enrollment token")
}

/// Agents report /32 and /64 keys by default; anything much broader from a
/// single agent is suspicious (DESIGN.md §4.5).
/// Decision streams one agent may have open at once.
const MAX_STREAMS_PER_AGENT: u32 = 4;

/// Active bans one agent's reports may hold (a compromised agent must not
/// ban the whole address space).
const MAX_ACTIVE_PER_AGENT: usize = if cfg!(test) { 50 } else { 20_000 };
/// Longest ban an agent report creates (its own escalation may go longer
/// locally; the network-wide decision does not).
const MAX_AGENT_BAN: chrono::TimeDelta = chrono::TimeDelta::days(90);
/// Largest clock difference to an agent that is believed.
const MAX_SKEW_MS: i64 = 86_400_000;

/// A jail name from an agent: valid, or the observation is ignored.
fn agent_jail(j: &str) -> Option<String> {
    crate::policy::valid_jail(j).then(|| j.to_owned())
}

fn too_broad(net: &IpNet) -> bool {
    match net {
        IpNet::V4(n) => n.prefix_len() < 24,
        IpNet::V6(n) => n.prefix_len() < 48,
    }
}

fn event(e: Event) -> v1::DecisionEvent {
    v1::DecisionEvent { event: Some(e) }
}

fn redaction_event(snap: &crate::state::RedactionSnapshot) -> v1::DecisionEvent {
    event(Event::Redaction(v1::RedactionRules {
        version: snap.version.clone(),
        rules: snap
            .rules
            .iter()
            .map(|r| v1::RedactionRule {
                name: r.name.clone(),
                pattern: r.pattern.clone(),
                replace: r.replace.clone(),
            })
            .collect(),
    }))
}

impl Service {
    /// Feeds observations into the correlator and returns the rules that
    /// fired, and how many observations from the start of the batch were
    /// processed: at the first one over the agent's rate it stops (the
    /// agent sends the rest again later).
    fn correlate(
        &self,
        record: &crate::store::AgentRecord,
        batch: &[v1::Observation],
        now: chrono::DateTime<Utc>,
    ) -> (Vec<crate::correlation::Trigger>, usize) {
        use crate::correlation::{Seen, MAX_WINDOW};
        let rules = self.ctl.rules();
        // agent timestamps in controller time (skew from heartbeats)
        let skew = chrono::Duration::milliseconds(self.ctl.clock_skew_ms(&record.id));
        let oldest = now - chrono::Duration::from_std(MAX_WINDOW).unwrap_or_default();
        let redactor = self.ctl.redactor();
        let mut parsed = Vec::new();
        for (i, o) in batch.iter().enumerate() {
            let banned = o.locally_banned;
            if !banned && o.count == 0 {
                continue;
            }
            let Ok(net) = o.key.parse::<IpNet>().map(|n| n.trunc()) else {
                continue;
            };
            if too_broad(&net) || df2b_core::reserved(&net) || self.ctl.allowlisted(&net) {
                continue;
            }
            let Some(jail) = agent_jail(&o.jail) else {
                continue;
            };
            let at = from_unix_ms(o.last_seen_unix_ms)
                .and_then(|t| t.checked_add_signed(skew))
                .map_or(now, |t| t.min(now));
            if at < oldest {
                continue;
            }
            parsed.push((
                i,
                jail,
                net,
                at,
                if banned { 0 } else { o.count },
                banned,
                // untrusted: cleaned, redacted (central rules) and cut again
                (!o.sample.trim().is_empty()).then(|| {
                    df2b_core::sample_line(&redactor.apply(&df2b_core::sample_line(&o.sample)))
                }),
            ));
        }
        let mut c = self
            .ctl
            .correlator
            .lock()
            .unwrap_or_else(|e| e.into_inner());
        let mut triggers = Vec::new();
        let mut consumed = batch.len();
        for (i, jail, net, at, failures, banned, sample) in parsed {
            if !c.admit(&record.id, now) {
                consumed = i;
                break;
            }
            let seen = Seen {
                agent: record.id.clone(),
                group: record.group.clone(),
                at,
                failures,
                banned,
                sample,
            };
            if c.record(&jail, net, seen) {
                // the AS only matters to rules limited to some
                let asn = if rules.iter().any(|r| !r.asns.is_empty()) {
                    self.ctl.geo.lookup_net(&net).and_then(|g| g.asn)
                } else {
                    None
                };
                triggers.extend(c.evaluate(&rules, &jail, net, &record.group, asn, now));
            }
        }
        if consumed < batch.len() {
            warn!(agent = %record.id, deferred = batch.len() - consumed, "observation rate limit reached");
        }
        (triggers, consumed)
    }
}

#[tonic::async_trait]
impl AgentService for Service {
    async fn enroll(
        &self,
        req: Request<v1::EnrollRequest>,
    ) -> Result<Response<v1::EnrollResponse>, Status> {
        let peer = req.remote_addr();
        let r = req.into_inner();
        let token: EnrollToken = r.token.parse().map_err(|_| invalid_token())?;
        if token.ca_fingerprint != self.ctl.ca.fingerprint() {
            return Err(invalid_token());
        }
        // no work (CSR verification, signing) for requests without a
        // token: only the CA fingerprint is needed to get this far
        if !files::token_exists(&self.ctl.settings.state_dir, &token) {
            return Err(invalid_token());
        }
        let ctl = self.ctl.clone();
        let resp = tokio::task::spawn_blocking(move || {
            let hostname: String = r
                .hostname
                .chars()
                .filter(|c| !c.is_control())
                .take(255)
                .collect();
            let version: String = r.agent_version.chars().take(64).collect();
            // 24 random bits: never overwrite an existing agent
            let mut id = files::new_agent_id(&hostname);
            while ctl.agent_group(&id).is_some() {
                id = files::new_agent_id(&hostname);
            }
            // check the CSR before using up the token
            let cert = ctl
                .ca
                .sign_agent_csr(&r.csr_der, &id, ctl.settings.cert_lifetime)
                .map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
            let token_file = files::redeem_token(&ctl.settings.state_dir, &token)
                .map_err(internal)?
                .ok_or_else(invalid_token)?;
            let info = CertInfo::parse(&cert).map_err(internal)?;
            ctl.put_agent(AgentRecord {
                id: id.clone(),
                hostname: hostname.clone(),
                group: token_file.group.clone(),
                enrolled_at: Utc::now(),
                serials: vec![info.serial],
                cert_not_after: info.not_after,
                resync: false,
            })
            .map_err(internal)?;
            info!(agent = %id, group = %token_file.group, ?peer, version = ?version, "agent enrolled");
            ctl.audit(
                &format!("agent:{id}"),
                peer.map(|p| p.to_string()),
                "agent.enroll",
                serde_json::json!({ "group": token_file.group, "hostname": hostname }),
            )
            .map_err(internal)?;
            Ok::<_, Status>(v1::EnrollResponse {
                agent_id: id,
                certificate_der: cert.to_vec(),
                ca_certificate_der: ctl.ca.cert_der().to_vec(),
                group: token_file.group,
            })
        })
        .await
        .map_err(internal)??;
        Ok(Response::new(resp))
    }

    async fn renew(
        &self,
        req: Request<v1::RenewRequest>,
    ) -> Result<Response<v1::RenewResponse>, Status> {
        let (record, used) = self.auth(&req)?;
        let csr = req.into_inner().csr_der;
        let ctl = self.ctl.clone();
        let resp = tokio::task::spawn_blocking(move || {
            let cert = ctl
                .ca
                .sign_agent_csr(&csr, &record.id, ctl.settings.cert_lifetime)
                .map_err(|e| Status::invalid_argument(format!("{e:#}")))?;
            let info = CertInfo::parse(&cert).map_err(internal)?;
            // new certificate + the one used for this call (in case the
            // response is lost); anything older is no longer accepted
            let id = record.id.clone();
            ctl.renewed(&id, vec![info.serial, used.serial], info.not_after)
                .map_err(internal)?;
            info!(agent = %id, not_after = %info.not_after, "agent certificate renewed");
            Ok::<_, Status>(v1::RenewResponse {
                certificate_der: cert.to_vec(),
                ca_certificate_der: ctl.ca.cert_der().to_vec(),
            })
        })
        .await
        .map_err(internal)??;
        Ok(Response::new(resp))
    }

    async fn heartbeat(
        &self,
        req: Request<v1::HeartbeatRequest>,
    ) -> Result<Response<v1::HeartbeatResponse>, Status> {
        let (record, _) = self.auth(&req)?;
        let h = req.into_inner();
        let now_ms = Utc::now().timestamp_millis();
        self.ctl.update_status(&record.id, |s| {
            // strings from the agent: bounded
            let cut = |v: String, n: usize| v.chars().take(n).collect::<String>();
            s.agent_version = cut(h.agent_version, 64);
            s.active_bans = h.active_bans;
            s.clock_skew_ms = now_ms
                .saturating_sub(h.agent_time_unix_ms)
                .clamp(-MAX_SKEW_MS, MAX_SKEW_MS);
            s.firewall_backend = cut(h.firewall_backend, 32);
            s.firewall_healthy = h.firewall_healthy;
            s.firewall_error = h.firewall_error.chars().take(512).collect();
            s.sources = h
                .sources
                .into_iter()
                .take(256)
                .map(|x| crate::state::SourceView {
                    name: x.name.chars().take(64).collect(),
                    lines_per_second: x.lines_per_second,
                    lag_ms: x.lag_ms,
                    backlog_bytes: x.backlog_bytes,
                    error: x.error.chars().take(512).collect(),
                })
                .collect();
            s.last_applied_seq = h.last_applied_seq;
            s.allowlist_version = cut(h.allowlist_version, 64);
            s.jail_policies_version = cut(h.jail_policies_version, 64);
            s.central_jails_version = cut(h.central_jails_version, 64);
            s.redaction_version = h.redaction_version.chars().take(64).collect();
            let secs = |ms: i64| u64::try_from(ms / 1000).unwrap_or(0);
            s.jails = h
                .jails
                .into_iter()
                .take(256)
                .map(|j| crate::state::JailView {
                    name: j.name.chars().take(64).collect(),
                    filter: j.filter.chars().take(64).collect(),
                    enabled: j.enabled,
                    maxretry: j.maxretry,
                    findtime_secs: secs(j.findtime_ms),
                    bantime_secs: secs(j.bantime_ms),
                    bantime_factor: j.bantime_factor,
                    max_bantime_secs: secs(j.max_bantime_ms),
                    overridden: j.overridden.into_iter().take(8).collect(),
                    active_bans: j.active_bans,
                    origin: j.origin.chars().take(16).collect(),
                    error: j.error.chars().take(512).collect(),
                    tracked: j.tracked,
                    evicted: j.evicted,
                })
                .collect();
        });
        Ok(Response::new(v1::HeartbeatResponse {
            controller_time_unix_ms: now_ms,
            groups: vec![record.group],
        }))
    }

    async fn report(
        &self,
        req: Request<v1::ObservationBatch>,
    ) -> Result<Response<v1::ReportAck>, Status> {
        let (record, _) = self.auth(&req)?;
        let batch = req.into_inner().observations;
        if batch.len() > MAX_REPORT {
            return Err(Status::invalid_argument(format!(
                "at most {MAX_REPORT} observations per report"
            )));
        }
        self.ctl.update_status(&record.id, |_| {});
        let now = Utc::now();
        let scope = match self.ctl.propagate() {
            Propagate::Global => Some(Scope::Global),
            Propagate::Group => Some(Scope::Group(record.group.clone())),
            Propagate::Off => None,
        };
        let mut new = Vec::new();
        let (triggers, consumed) = self.correlate(&record, &batch, now);
        let limited = consumed < batch.len();
        // the rest is sent again after `retry_after_ms`
        let batch = &batch[..consumed];
        if !triggers.is_empty() {
            let active = self.ctl.active_decisions();
            for t in triggers {
                let scope = self
                    .ctl
                    .rules()
                    .iter()
                    .find(|r| r.name == t.rule)
                    .and_then(|r| r.group.clone())
                    .map_or(Scope::Global, Scope::Group);
                let what = if t.failures > 0 {
                    format!("{} failures from {} agents", t.failures, t.agents.len())
                } else {
                    format!("banned locally by {} agents", t.agents.len())
                };
                if t.monitor {
                    info!(rule = %t.rule, target = %t.target, jail = %t.jail, agents = ?t.agents, "correlation (monitor): would ban, {what}");
                    continue;
                }
                // already banned there (by anyone): nothing to add
                let covered = active.iter().any(|d| {
                    matches!(d.kind, DecisionKind::Ban)
                        && d.target.contains(&t.target)
                        && (d.scope == Scope::Global || d.scope == scope)
                });
                if covered {
                    continue;
                }
                // repeat offenders: escalated (earlier correlation bans of
                // this address, any rule, within the offense memory)
                let offense = self.ctl.correlation_offenses(&t.target) + 1;
                let bantime = self
                    .ctl
                    .rules()
                    .iter()
                    .find(|r| r.name == t.rule)
                    .map(|r| r.bantime_for(offense))
                    .unwrap_or(Duration::from_secs(3600));
                let nth = if offense > 1 {
                    format!(", offense {offense}")
                } else {
                    String::new()
                };
                let expires_at = chrono::Duration::from_std(bantime).ok().map(|d| now + d);
                // several rules firing for the same address: the longest wins
                if let Some(i) = new
                    .iter()
                    .position(|n: &NewDecision| n.target == t.target && n.scope == scope)
                {
                    if new[i].expires_at >= expires_at {
                        continue;
                    }
                    new.remove(i);
                }
                new.push(NewDecision {
                    kind: DecisionKind::Ban,
                    target: t.target,
                    scope,
                    jail: Some(t.jail.clone()),
                    expires_at,
                    origin: Origin::Correlation(t.rule.clone()),
                    reason: format!(
                        "correlation rule {}: {what} ({}){nth}",
                        t.rule,
                        t.agents.join(", ")
                    ),
                });
            }
        }
        let mut quota = MAX_ACTIVE_PER_AGENT.saturating_sub(
            self.ctl
                .active_by(&Origin::Agent(AgentId(record.id.clone()))),
        );
        for o in batch.iter().filter(|o| o.locally_banned) {
            let Some(scope) = scope.clone() else { break };
            if quota == 0 {
                warn!(agent = %record.id, max = MAX_ACTIVE_PER_AGENT, "agent has too many active bans, ignoring more");
                break;
            }
            let Ok(net) = o.key.parse::<IpNet>().map(|n| n.trunc()) else {
                warn!(agent = %record.id, key = %o.key, "ignoring malformed key");
                continue;
            };
            if too_broad(&net) {
                warn!(agent = %record.id, %net, "ignoring overly broad ban");
                continue;
            }
            if df2b_core::reserved(&net) {
                warn!(agent = %record.id, %net, "ignoring ban of a reserved range");
                continue;
            }
            if self.ctl.allowlisted(&net) {
                warn!(agent = %record.id, %net, "ignoring ban overlapping the allowlist");
                continue;
            }
            // agents always send an expiry: none (0) is not "permanent"
            let Some(expires_at) = from_unix_ms(o.local_ban_expires_unix_ms) else {
                warn!(agent = %record.id, %net, "ignoring ban without expiry");
                continue;
            };
            if expires_at <= now {
                continue;
            }
            let expires_at = expires_at.min(now + MAX_AGENT_BAN);
            let Some(jail) = (if o.jail.is_empty() {
                Some(None)
            } else {
                agent_jail(&o.jail).map(Some)
            }) else {
                warn!(agent = %record.id, "ignoring ban with an invalid jail name");
                continue;
            };
            quota -= 1;
            new.push(NewDecision {
                kind: DecisionKind::Ban,
                target: net,
                scope,
                jail,
                expires_at: Some(expires_at),
                origin: Origin::Agent(AgentId(record.id.clone())),
                reason: format!("local ban on {}: {} failures", record.id, o.count),
            });
        }
        if !new.is_empty() {
            let ctl = self.ctl.clone();
            let appended = tokio::task::spawn_blocking(move || ctl.append(new))
                .await
                .map_err(internal)?
                .map_err(internal)?;
            for d in &appended {
                info!(seq = d.seq, target = %d.target, agent = %record.id, scope = ?d.scope, "decision: ban");
            }
        }
        Ok(Response::new(v1::ReportAck {
            accepted: consumed as u32,
            // over the per-agent rate: slow down
            retry_after_ms: if limited {
                crate::correlation::Correlator::retry_after_ms(now)
            } else {
                0
            },
            consumed: limited.then_some(consumed as u32),
        }))
    }

    type SubscribeStream = ReceiverStream<Result<v1::DecisionEvent, Status>>;

    async fn subscribe(
        &self,
        req: Request<v1::SubscribeRequest>,
    ) -> Result<Response<Self::SubscribeStream>, Status> {
        let (record, used) = self.auth(&req)?;
        // one stream is what an agent needs (a reconnect may overlap)
        if self.ctl.agent_streams(&record.id) >= MAX_STREAMS_PER_AGENT {
            return Err(Status::resource_exhausted(
                "too many open streams for this agent",
            ));
        }
        let not_after = used.not_after;
        let from_seq = req.into_inner().from_seq;
        let ctl = self.ctl.clone();
        let (initial, mut live) = {
            let ctl = ctl.clone();
            let record = record.clone();
            tokio::task::spawn_blocking(move || ctl.subscribe(from_seq, &record))
                .await
                .map_err(internal)?
                .map_err(internal)?
        };
        let (tx, rx) = mpsc::channel(256);
        let mut allow = ctl.allowlist_watch();
        let mut jails = ctl.jail_watch();
        let mut central = ctl.central_watch();
        let mut redaction = ctl.redaction_watch();
        tokio::spawn(async move {
            let id = record.id.clone();
            ctl.update_status(&id, |s| s.streams += 1);
            info!(agent = %id, from_seq, "agent connected");
            let last = match initial {
                Initial::Snapshot { seq, active } => {
                    let snap = v1::Snapshot {
                        seq,
                        active: active.iter().map(Into::into).collect(),
                    };
                    let _ = tx.send(Ok(event(Event::Snapshot(snap)))).await;
                    seq
                }
                Initial::Backlog { seq, decisions } => {
                    for d in &decisions {
                        if tx.send(Ok(event(Event::Decision(d.into())))).await.is_err() {
                            break;
                        }
                    }
                    seq
                }
            };
            // the central allowlist after the decisions, then on every change
            let send_allow = |snap: &crate::state::AllowSnapshot| {
                event(Event::Allowlist(v1::AllowlistUpdate {
                    version: snap.version.clone(),
                    networks: snap.entries.iter().map(|(n, _)| n.to_string()).collect(),
                    expires_unix_ms: snap
                        .entries
                        .iter()
                        .map(|(_, e)| e.map_or(0, |t| t.timestamp_millis()))
                        .collect(),
                }))
            };
            let first = send_allow(&allow.borrow_and_update());
            if tx.send(Ok(first)).await.is_err() {
                ctl.update_status(&id, |s| s.streams = s.streams.saturating_sub(1));
                return;
            }
            // then the jail settings for its group (a group change closes
            // the stream, so `record.group` stays right)
            let group = record.group.clone();
            let jail_event = |list: &[crate::policy::JailOverride]| {
                event(Event::JailPolicies(crate::policy::for_group(list, &group)))
            };
            let mut sent_version = {
                let p = crate::policy::for_group(&jails.borrow_and_update(), &group);
                let v = p.version.clone();
                if tx.send(Ok(event(Event::JailPolicies(p)))).await.is_err() {
                    ctl.update_status(&id, |s| s.streams = s.streams.saturating_sub(1));
                    return;
                }
                v
            };
            // then the central jail definitions for its group
            let mut sent_central = {
                let c = central.borrow_and_update().for_group(&group);
                let v = c.version.clone();
                if tx.send(Ok(event(Event::CentralJails(c)))).await.is_err() {
                    ctl.update_status(&id, |s| s.streams = s.streams.saturating_sub(1));
                    return;
                }
                v
            };
            // then the redaction rules for sample lines (the same for all)
            let first = redaction_event(&redaction.borrow_and_update());
            if tx.send(Ok(first)).await.is_err() {
                ctl.update_status(&id, |s| s.streams = s.streams.saturating_sub(1));
                return;
            }
            let mut check = tokio::time::interval(REVOCATION_CHECK);
            loop {
                tokio::select! {
                    changed = redaction.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let ev = redaction_event(&redaction.borrow_and_update());
                        if tx.send(Ok(ev)).await.is_err() {
                            break;
                        }
                    }
                    changed = central.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let c = central.borrow_and_update().for_group(&group);
                        // other groups' changes do not concern this agent
                        if c.version == sent_central {
                            continue;
                        }
                        sent_central = c.version.clone();
                        if tx.send(Ok(event(Event::CentralJails(c)))).await.is_err() {
                            break;
                        }
                    }
                    changed = jails.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let ev = jail_event(&jails.borrow_and_update());
                        // other groups' changes do not concern this agent
                        let Some(Event::JailPolicies(p)) = &ev.event else { continue };
                        if p.version == sent_version {
                            continue;
                        }
                        sent_version = p.version.clone();
                        if tx.send(Ok(ev)).await.is_err() {
                            break;
                        }
                    }
                    changed = allow.changed() => {
                        if changed.is_err() {
                            break;
                        }
                        let ev = send_allow(&allow.borrow_and_update());
                        if tx.send(Ok(ev)).await.is_err() {
                            break;
                        }
                    }
                    ev = live.recv() => match ev {
                        Ok(d) => {
                            if d.seq <= last || !applies(&d, &record) {
                                continue;
                            }
                            if tx.send(Ok(event(Event::Decision((&*d).into())))).await.is_err() {
                                break;
                            }
                        }
                        Err(broadcast::error::RecvError::Lagged(n)) => {
                            warn!(agent = %id, missed = n, "subscriber lagged, closing stream");
                            let _ = tx.send(Err(Status::aborted("stream lagged; resubscribe"))).await;
                            break;
                        }
                        Err(broadcast::error::RecvError::Closed) => break,
                    },
                    _ = check.tick() => {
                        // the certificate was checked when the stream
                        // opened; it must not outlive it
                        if Utc::now() >= not_after {
                            info!(agent = %id, "certificate expired, closing stream");
                            let _ = tx.send(Err(Status::unauthenticated("certificate expired"))).await;
                            break;
                        }
                        if ctl.is_revoked(&id) {
                            warn!(agent = %id, "agent revoked, closing stream");
                            let _ = tx.send(Err(Status::permission_denied("agent revoked"))).await;
                            break;
                        }
                        // moved to another group: the agent resubscribes
                        // and gets a snapshot for the new group
                        if ctl.agent_group(&id).as_deref() != Some(record.group.as_str()) {
                            info!(agent = %id, "group changed, closing stream for a resync");
                            let _ = tx.send(Err(Status::aborted("group changed; resubscribe"))).await;
                            break;
                        }
                    }
                    _ = tx.closed() => break,
                }
            }
            ctl.update_status(&id, |s| s.streams = s.streams.saturating_sub(1));
            info!(agent = %id, "agent disconnected");
        });
        Ok(Response::new(ReceiverStream::new(rx)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state::Settings;
    use crate::store::Store;
    use df2b_core::Allowlist;
    use df2b_proto::v1::agent_service_client::AgentServiceClient;
    use df2b_proto::v1::agent_service_server::AgentServiceServer;
    use df2b_tls::pki::key_from_pem;
    use df2b_tls::{transport, AgentKey, ClientConfig};
    use tonic::transport::Channel;
    use tonic::Code;

    async fn start(dir: &std::path::Path) -> (String, Arc<Controller>) {
        let ca = files::load_or_create_ca(dir).unwrap();
        let settings = Settings {
            state_dir: dir.to_owned(),
            cert_lifetime: Duration::from_secs(3600),
            propagate: Propagate::Global,
            allowlist: Allowlist::new(["10.0.0.0/8".parse().unwrap()]),
            oidc: None,
            https_internal_ca: true,
        };
        let ctl = Arc::new(Controller::open(settings, ca, Store::open(dir).unwrap()).unwrap());
        let (chain, key) = ctl.ca.issue_server(&[]).unwrap();
        let tls = transport::server_config(ctl.ca.cert_der(), chain, key).unwrap();
        let l = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = l.local_addr().unwrap().to_string();
        tokio::spawn(
            tonic::transport::Server::builder()
                .add_service(AgentServiceServer::new(Service::new(ctl.clone())))
                .serve_with_incoming(transport::incoming(l, tls)),
        );
        (addr, ctl)
    }

    async fn client(addr: &str, cfg: Arc<ClientConfig>) -> AgentServiceClient<Channel> {
        AgentServiceClient::new(transport::connect(addr.into(), cfg).await.unwrap())
    }

    fn agent_cfg(ctl: &Controller, cert: Vec<u8>, key: &AgentKey) -> Arc<ClientConfig> {
        transport::client_config(
            ctl.ca.cert_der(),
            cert.into(),
            key_from_pem(&key.key_pem).unwrap(),
        )
        .unwrap()
    }

    fn obs(key: &str, banned: bool) -> v1::Observation {
        v1::Observation {
            key: key.into(),
            jail: "sshd".into(),
            count: 5,
            locally_banned: banned,
            local_ban_expires_unix_ms: (Utc::now() + chrono::Duration::hours(1)).timestamp_millis(),
            ..Default::default()
        }
    }

    fn heartbeat() -> v1::HeartbeatRequest {
        v1::HeartbeatRequest {
            agent_time_unix_ms: Utc::now().timestamp_millis(),
            ..Default::default()
        }
    }

    /// Enrolls an agent and returns a client for it.
    async fn enrolled(
        addr: &str,
        ctl: &Controller,
        dir: &std::path::Path,
        host: &str,
    ) -> AgentServiceClient<Channel> {
        let token = files::create_token(dir, "web", Duration::from_secs(3600)).unwrap();
        let pinned = transport::enrollment_client_config(token.ca_fingerprint).unwrap();
        let key = AgentKey::generate(host).unwrap();
        let resp = client(addr, pinned)
            .await
            .enroll(v1::EnrollRequest {
                token: token.to_string(),
                hostname: host.into(),
                csr_der: key.csr_der.clone(),
                agent_version: "test".into(),
            })
            .await
            .unwrap()
            .into_inner();
        client(addr, agent_cfg(ctl, resp.certificate_der, &key)).await
    }

    async fn next(s: &mut tonic::Streaming<v1::DecisionEvent>) -> Option<Event> {
        tokio::time::timeout(Duration::from_secs(5), s.message())
            .await
            .expect("event in time")
            .unwrap()
            .unwrap()
            .event
    }

    #[tokio::test]
    async fn allowlist_is_distributed() {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-allow-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let mut a = enrolled(&addr, &ctl, &dir, "host-b").await;
        let mut stream = a
            .subscribe(v1::SubscribeRequest { from_seq: 0 })
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(next(&mut stream).await, Some(Event::Snapshot(_))));
        let Some(Event::Allowlist(first)) = next(&mut stream).await else {
            panic!("allowlist expected")
        };
        assert_eq!(first.networks, ["10.0.0.0/8"]);
        assert!(matches!(
            next(&mut stream).await,
            Some(Event::JailPolicies(_))
        ));
        assert!(matches!(
            next(&mut stream).await,
            Some(Event::CentralJails(_))
        ));
        assert!(matches!(next(&mut stream).await, Some(Event::Redaction(_))));

        // a change reaches open streams at once, as the complete list
        let entry = |net: &str| crate::store::AllowEntry {
            net: net.parse().unwrap(),
            comment: String::new(),
            created_by: "ada".into(),
            created_at: Utc::now(),
            expires_at: None,
        };
        ctl.add_allow(entry("192.0.2.0/24")).unwrap();
        let Some(Event::Allowlist(second)) = next(&mut stream).await else {
            panic!("update expected")
        };
        assert_eq!(second.networks, ["10.0.0.0/8", "192.0.2.0/24"]);
        assert_ne!(second.version, first.version);
        ctl.remove_allow(&"192.0.2.0/24".parse().unwrap()).unwrap();
        let Some(Event::Allowlist(third)) = next(&mut stream).await else {
            panic!("update expected")
        };
        assert_eq!(
            third.version, first.version,
            "the version is a content hash"
        );

        // a resuming agent (backlog instead of snapshot) gets it too
        a.report(v1::ObservationBatch {
            observations: vec![obs("203.0.113.9/32", true)],
        })
        .await
        .unwrap();
        assert_eq!(ctl.last_seq(), 1);
        let mut again = a
            .subscribe(v1::SubscribeRequest {
                from_seq: ctl.last_seq(),
            })
            .await
            .unwrap()
            .into_inner();
        let Some(Event::Allowlist(r)) = again.message().await.unwrap().unwrap().event else {
            panic!("allowlist expected after an empty backlog")
        };
        assert_eq!(r.version, first.version);

        // the agent reports what it applied
        let id = ctl.agents()[0].record.id.clone();
        a.heartbeat(v1::HeartbeatRequest {
            allowlist_version: first.version.clone(),
            ..heartbeat()
        })
        .await
        .unwrap();
        assert_eq!(
            ctl.agent(&id).unwrap().status.allowlist_version,
            first.version
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn redaction_rules_are_distributed() {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-redact-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let mut a = enrolled(&addr, &ctl, &dir, "host-r").await;
        let mut stream = a
            .subscribe(v1::SubscribeRequest { from_seq: 0 })
            .await
            .unwrap()
            .into_inner();
        for _ in 0..4 {
            next(&mut stream).await; // snapshot, allowlist, policies, central jails
        }
        let Some(Event::Redaction(empty)) = next(&mut stream).await else {
            panic!("redaction rules expected")
        };
        assert!(empty.rules.is_empty());

        let rule = |name: &str, pattern: &str, enabled: bool| df2b_core::RedactRule {
            name: name.into(),
            pattern: pattern.into(),
            replace: "[x]".into(),
            enabled,
        };
        // a change reaches open streams at once, as the complete list
        ctl.set_redaction_rule(rule("user", r"user \S+", true))
            .unwrap();
        let Some(Event::Redaction(one)) = next(&mut stream).await else {
            panic!("update expected")
        };
        assert_eq!(one.rules.len(), 1);
        assert_eq!(
            (
                one.rules[0].name.as_str(),
                one.rules[0].pattern.as_str(),
                one.rules[0].replace.as_str()
            ),
            ("user", r"user \S+", "[x]")
        );
        assert_eq!(one.version, ctl.redaction_version());
        assert_ne!(one.version, empty.version);
        // disabled rules are not sent, and adding one changes nothing for
        // agents; enabling it does (in order)
        ctl.set_redaction_rule(rule("mail", r"\S+@\S+", false))
            .unwrap();
        assert_eq!(ctl.redaction_version(), one.version);
        ctl.set_redaction_rule(rule("mail", r"\S+@\S+", true))
            .unwrap();
        let Some(Event::Redaction(two)) = next(&mut stream).await else {
            panic!("update expected")
        };
        let names: Vec<_> = two.rules.iter().map(|r| r.name.as_str()).collect();
        assert_eq!(names, ["user", "mail"]);
        ctl.remove_redaction_rule("mail").unwrap();
        let Some(Event::Redaction(back)) = next(&mut stream).await else {
            panic!("update expected")
        };
        assert_eq!(back.version, one.version, "the version is a content hash");

        // the agent reports what it applies ("off": it does not accept them)
        let id = ctl.agents()[0].record.id.clone();
        for v in [one.version.as_str(), "off"] {
            a.heartbeat(v1::HeartbeatRequest {
                redaction_version: v.into(),
                ..heartbeat()
            })
            .await
            .unwrap();
            assert_eq!(ctl.agent(&id).unwrap().status.redaction_version, v);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn enrollment_authentication_renewal_revocation() {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let token = files::create_token(&dir, "web", Duration::from_secs(3600)).unwrap();

        // enroll over a connection pinned to the CA, without client cert
        let pinned = transport::enrollment_client_config(token.ca_fingerprint).unwrap();
        let mut anon = client(&addr, pinned).await;
        let k1 = AgentKey::generate("host-a").unwrap();
        let req = |csr: Vec<u8>| v1::EnrollRequest {
            token: token.to_string(),
            hostname: "host-a".into(),
            csr_der: csr,
            agent_version: "test".into(),
        };
        let resp = anon
            .enroll(req(k1.csr_der.clone()))
            .await
            .unwrap()
            .into_inner();
        assert_eq!(resp.group, "web");
        assert!(resp.agent_id.starts_with("host-a-"));
        let id = resp.agent_id;

        // without client certificate nothing but Enroll works
        let err = anon.heartbeat(heartbeat()).await.unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        let err = anon
            .subscribe(v1::SubscribeRequest::default())
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::Unauthenticated);
        // tokens are one-time
        let err = anon.enroll(req(k1.csr_der.clone())).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);

        // mutual TLS: identity from the certificate
        let cfg1 = agent_cfg(&ctl, resp.certificate_der, &k1);
        let mut a = client(&addr, cfg1.clone()).await;
        let hb = a
            .heartbeat(v1::HeartbeatRequest {
                firewall_healthy: false,
                firewall_error: "table gone".into(),
                sources: vec![v1::SourceStatus {
                    name: "auth".into(),
                    lines_per_second: 12,
                    backlog_bytes: 4096,
                    error: "x".repeat(2000),
                    ..Default::default()
                }],
                ..heartbeat()
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(hb.groups, vec!["web".to_string()]);
        let st = ctl.agents().into_iter().next().unwrap().status;
        assert_eq!(
            (st.firewall_healthy, st.firewall_error.as_str()),
            (false, "table gone")
        );
        assert_eq!(st.sources.len(), 1);
        assert_eq!(
            (st.sources[0].lines_per_second, st.sources[0].backlog_bytes),
            (12, 4096)
        );
        assert_eq!(st.sources[0].error.len(), 512, "capped");

        let mut stream = a
            .subscribe(v1::SubscribeRequest { from_seq: 0 })
            .await
            .unwrap()
            .into_inner();
        let Some(Event::Snapshot(s)) = stream.message().await.unwrap().unwrap().event else {
            panic!("expected snapshot first")
        };
        assert!(s.active.is_empty());
        // then the central allowlist
        let Some(Event::Allowlist(al)) = stream.message().await.unwrap().unwrap().event else {
            panic!("expected the allowlist after the snapshot")
        };
        assert_eq!(al.networks, ["10.0.0.0/8"]);
        assert_eq!(al.version, ctl.allowlist_version());
        // and the jail settings (none yet)
        let Some(Event::JailPolicies(jp)) = stream.message().await.unwrap().unwrap().event else {
            panic!("expected the jail policies after the allowlist")
        };
        assert!(jp.jails.is_empty());
        let Some(Event::CentralJails(cj)) = stream.message().await.unwrap().unwrap().event else {
            panic!("expected the central jails after the jail policies")
        };
        assert!(cj.jails.is_empty());
        // and the redaction rules (none yet)
        let Some(Event::Redaction(r)) = stream.message().await.unwrap().unwrap().event else {
            panic!("expected the redaction rules after the central jails")
        };
        assert!(r.rules.is_empty());
        assert_eq!(r.version, ctl.redaction_version());

        // local ban → decision; allowlisted, too broad and non-ban ignored
        let ack = a
            .report(v1::ObservationBatch {
                observations: vec![
                    obs("203.0.113.9/32", true),
                    obs("10.1.2.3/32", true),
                    obs("198.51.0.0/16", true),
                    obs("192.0.2.1/32", false),
                ],
            })
            .await
            .unwrap()
            .into_inner();
        assert_eq!(ack.accepted, 4);
        let Some(Event::Decision(d)) = stream.message().await.unwrap().unwrap().event else {
            panic!("expected decision")
        };
        assert_eq!(
            (d.target.as_str(), d.origin.as_str(), d.seq),
            ("203.0.113.9/32", format!("agent:{id}").as_str(), 1)
        );
        assert_eq!(ctl.active_decisions().len(), 1);

        // renewal: the certificate used for the call stays valid ...
        let k2 = AgentKey::generate("host-a").unwrap();
        let r = a
            .renew(v1::RenewRequest {
                csr_der: k2.csr_der.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        let cfg2 = agent_cfg(&ctl, r.certificate_der, &k2);
        a.heartbeat(heartbeat()).await.unwrap();
        let mut b = client(&addr, cfg2).await;
        b.heartbeat(heartbeat()).await.unwrap();
        // ... until the new one renews again: then the first is superseded
        let k3 = AgentKey::generate("host-a").unwrap();
        let r = b
            .renew(v1::RenewRequest {
                csr_der: k3.csr_der.clone(),
            })
            .await
            .unwrap()
            .into_inner();
        let cfg3 = agent_cfg(&ctl, r.certificate_der, &k3);
        let err = client(&addr, cfg1)
            .await
            .heartbeat(heartbeat())
            .await
            .unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        let mut c = client(&addr, cfg3.clone()).await;
        c.heartbeat(heartbeat()).await.unwrap();

        // revocation: new calls refused, open streams closed
        files::revoke(&dir, &id).unwrap();
        let err = c.heartbeat(heartbeat()).await.unwrap_err();
        assert_eq!(err.code(), Code::PermissionDenied);
        let mut s3 = client(&addr, cfg3).await;
        assert!(s3.subscribe(v1::SubscribeRequest::default()).await.is_err());
        let closed = tokio::time::timeout(Duration::from_secs(10), stream.message())
            .await
            .expect("stream closed after revocation");
        assert_eq!(closed.unwrap_err().code(), Code::PermissionDenied);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn group_change_closes_the_stream() {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-group-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let mut a = enrolled(&addr, &ctl, &dir, "host-g").await;
        let id = ctl.agents()[0].record.id.clone();
        let mut stream = a
            .subscribe(v1::SubscribeRequest { from_seq: 0 })
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(next(&mut stream).await, Some(Event::Snapshot(_))));
        assert!(matches!(next(&mut stream).await, Some(Event::Allowlist(_))));
        assert!(matches!(
            next(&mut stream).await,
            Some(Event::JailPolicies(_))
        ));
        assert!(matches!(
            next(&mut stream).await,
            Some(Event::CentralJails(_))
        ));
        assert!(matches!(next(&mut stream).await, Some(Event::Redaction(_))));

        ctl.set_group(&id, "db").unwrap();
        // closed within the check interval (5 s)
        let err = tokio::time::timeout(Duration::from_secs(10), stream.message())
            .await
            .expect("stream closed in time")
            .unwrap_err();
        assert_eq!(err.code(), Code::Aborted);
        // the agent resubscribes where it was and gets a snapshot
        let mut stream = a
            .subscribe(v1::SubscribeRequest {
                from_seq: ctl.last_seq(),
            })
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(next(&mut stream).await, Some(Event::Snapshot(_))));
        let hb = a.heartbeat(heartbeat()).await.unwrap().into_inner();
        assert_eq!(hb.groups, ["db"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn jail_policies_and_propagation() {
        use crate::policy::{JailOverride, JailSettings};
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-jails-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let mut a = enrolled(&addr, &ctl, &dir, "host-j").await; // group "web"
        let mut stream = a
            .subscribe(v1::SubscribeRequest { from_seq: 0 })
            .await
            .unwrap()
            .into_inner();
        assert!(matches!(next(&mut stream).await, Some(Event::Snapshot(_))));
        assert!(matches!(next(&mut stream).await, Some(Event::Allowlist(_))));
        let Some(Event::JailPolicies(empty)) = next(&mut stream).await else {
            panic!("jail policies expected")
        };
        assert!(empty.jails.is_empty());
        assert!(matches!(
            next(&mut stream).await,
            Some(Event::CentralJails(_))
        ));
        assert!(matches!(next(&mut stream).await, Some(Event::Redaction(_))));

        let ov = |group: Option<&str>, maxretry: u32| JailOverride {
            jail: "sshd".into(),
            group: group.map(Into::into),
            settings: JailSettings {
                maxretry: Some(maxretry),
                ..Default::default()
            },
            updated_by: "ada".into(),
            updated_at: Utc::now(),
        };
        // another group's change is not sent; this group's is, merged
        ctl.set_jail_override(ov(Some("db"), 9)).unwrap();
        ctl.set_jail_override(ov(None, 5)).unwrap();
        let Some(Event::JailPolicies(p)) = next(&mut stream).await else {
            panic!("update expected")
        };
        assert_eq!((p.jails.len(), p.jails[0].maxretry), (1, Some(5)));
        ctl.set_jail_override(ov(Some("web"), 3)).unwrap();
        let Some(Event::JailPolicies(p)) = next(&mut stream).await else {
            panic!("update expected")
        };
        assert_eq!(p.jails[0].maxretry, Some(3), "group wins");

        // the agent reports its jails
        a.heartbeat(v1::HeartbeatRequest {
            jails: vec![v1::JailStatus {
                name: "sshd".into(),
                filter: "sshd".into(),
                enabled: true,
                maxretry: 3,
                bantime_ms: 3_600_000,
                overridden: vec!["maxretry".into()],
                ..Default::default()
            }],
            jail_policies_version: p.version.clone(),
            ..heartbeat()
        })
        .await
        .unwrap();
        let st = ctl.agents()[0].status.clone();
        assert_eq!(
            (
                st.jails[0].maxretry,
                st.jails[0].bantime_secs,
                st.jail_policies_version
            ),
            (3, 3600, p.version)
        );

        // propagation off: local bans stay local
        ctl.set_propagate(crate::state::Propagate::Off).unwrap();
        a.report(v1::ObservationBatch {
            observations: vec![obs("203.0.113.50/32", true)],
        })
        .await
        .unwrap();
        assert_eq!(ctl.last_seq(), 0);
        ctl.set_propagate(crate::state::Propagate::Global).unwrap();
        a.report(v1::ObservationBatch {
            observations: vec![obs("203.0.113.51/32", true)],
        })
        .await
        .unwrap();
        assert_eq!(ctl.last_seq(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn central_jails_reach_their_group() {
        use crate::central::{CentralFilter, JailDef, SourceDef};
        let dir =
            std::env::temp_dir().join(format!("df2b-ctl-grpc-central-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let mut a = enrolled(&addr, &ctl, &dir, "host-c").await; // group "web"
        let mut stream = a
            .subscribe(v1::SubscribeRequest { from_seq: 0 })
            .await
            .unwrap()
            .into_inner();
        for _ in 0..3 {
            next(&mut stream).await; // snapshot, allowlist, jail policies
        }
        let Some(Event::CentralJails(c)) = next(&mut stream).await else {
            panic!("central jails expected")
        };
        assert!(c.jails.is_empty());
        assert!(matches!(next(&mut stream).await, Some(Event::Redaction(_))));

        let def = |group: Option<&str>| JailDef {
            name: "app".into(),
            group: group.map(Into::into),
            filter: "app-auth".into(),
            sources: vec![SourceDef::File {
                paths: vec!["/var/log/app.log".into()],
                start_at_end: true,
            }],
            enabled: true,
            maxretry: 3,
            findtime: Duration::from_secs(600),
            bantime: Duration::from_secs(3600),
            bantime_factor: 1.0,
            max_bantime: None,
            updated_by: "ada".into(),
            updated_at: Utc::now(),
        };
        ctl.set_filter(CentralFilter {
            name: "app-auth".into(),
            toml: "failregex = ['failed from <HOST>']".into(),
            updated_by: "ada".into(),
            updated_at: Utc::now(),
        })
        .unwrap();
        // a filter alone changes nothing for this agent (no jail uses it);
        // a definition for another group neither
        ctl.set_jail_def(def(Some("db"))).unwrap();
        ctl.set_jail_def(def(None)).unwrap();
        let Some(Event::CentralJails(c)) = next(&mut stream).await else {
            panic!("update expected")
        };
        assert_eq!((c.jails.len(), c.jails[0].name.as_str()), (1, "app"));
        assert_eq!(c.filters.len(), 1, "with the central filter it uses");
        let Some(v1::source_definition::Kind::File(f)) = &c.jails[0].sources[0].kind else {
            panic!()
        };
        assert_eq!(f.paths, ["/var/log/app.log"]);

        // in use: cannot be deleted
        assert!(matches!(
            ctl.remove_filter("app-auth"),
            Err(crate::state::CentralError::FilterInUse(..))
        ));
        ctl.remove_jail_def("app", None).unwrap();
        let Some(Event::CentralJails(c)) = next(&mut stream).await else {
            panic!("update expected")
        };
        assert!(c.jails.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn correlation_rules() {
        use crate::correlation::{Rule, RuleKind};
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-corr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let mut a = enrolled(&addr, &ctl, &dir, "host-1").await;
        let mut b = enrolled(&addr, &ctl, &dir, "host-2").await;
        let rule =
            |name: &str, kind: RuleKind, min_agents: u32, min_failures: u32, monitor: bool| Rule {
                name: name.into(),
                kind,
                jail: Some("sshd".into()),
                group: None,
                min_agents,
                min_failures,
                window: Duration::from_secs(600),
                bantime: Duration::from_secs(7200),
                bantime_factor: 1.0,
                max_bantime: None,
                enabled: true,
                monitor,
                asns: Vec::new(),
                updated_by: "ada".into(),
                updated_at: Utc::now(),
            };
        let fails = |key: &str, n: u32, ago_secs: i64| v1::Observation {
            key: key.into(),
            jail: "sshd".into(),
            count: n,
            last_seen_unix_ms: (Utc::now() - chrono::Duration::seconds(ago_secs))
                .timestamp_millis(),
            ..Default::default()
        };
        let report = |obs: Vec<v1::Observation>| v1::ObservationBatch { observations: obs };

        // threshold: 4 failures from 2 agents
        ctl.set_rule(rule("distributed", RuleKind::Threshold, 2, 4, false))
            .unwrap();
        a.report(report(vec![fails("203.0.113.9/32", 2, 0)]))
            .await
            .unwrap();
        // b's failures from an hour ago (queued while offline) do not count
        b.report(report(vec![fails("203.0.113.9/32", 2, 3600)]))
            .await
            .unwrap();
        assert_eq!(ctl.last_seq(), 0);
        b.report(report(vec![fails("203.0.113.9/32", 2, 1)]))
            .await
            .unwrap();
        let d = ctl.active_decisions();
        assert_eq!(d.len(), 1);
        assert_eq!(d[0].origin, Origin::Correlation("distributed".into()));
        assert_eq!(
            (d[0].target.to_string(), d[0].scope.clone()),
            ("203.0.113.9/32".into(), Scope::Global)
        );
        assert!(
            d[0].reason.contains("4 failures from 2 agents"),
            "{}",
            d[0].reason
        );
        let left = d[0].expires_at.unwrap() - Utc::now();
        assert!(left > chrono::Duration::minutes(119), "rule bantime");
        // more failures: no second decision
        a.report(report(vec![fails("203.0.113.9/32", 5, 0)]))
            .await
            .unwrap();
        assert_eq!(ctl.last_seq(), 1);
        // sample lines: cleaned and redacted by the central rules on arrival
        ctl.set_redaction_rule(df2b_core::RedactRule {
            name: "ssh-user".into(),
            pattern: r"(for )\S+( from)".into(),
            replace: "${1}[user]${2}".into(),
            enabled: true,
        })
        .unwrap();
        a.report(report(vec![v1::Observation {
            sample: "Failed password for alice from 203.0.113.9 port 22\x1b[0m".into(),
            ..fails("203.0.113.9/32", 1, 0)
        }]))
        .await
        .unwrap();
        let samples = ctl
            .correlator
            .lock()
            .unwrap()
            .samples(&"203.0.113.9/32".parse().unwrap());
        assert_eq!(
            samples[0].2.line,
            "Failed password for [user] from 203.0.113.9 port 22 [0m"
        );
        // allowlisted addresses are never correlated
        a.report(report(vec![fails("10.1.1.1/32", 50, 0)]))
            .await
            .unwrap();
        b.report(report(vec![fails("10.1.1.1/32", 50, 0)]))
            .await
            .unwrap();
        assert_eq!(ctl.last_seq(), 1);

        // quorum with propagation off: one local ban is not enough, two are
        ctl.set_propagate(crate::state::Propagate::Off).unwrap();
        ctl.set_rule(rule("two-agree", RuleKind::Quorum, 2, 0, false))
            .unwrap();
        a.report(report(vec![obs("198.51.100.20/32", true)]))
            .await
            .unwrap();
        assert_eq!(ctl.last_seq(), 1, "a single agent cannot ban");
        b.report(report(vec![obs("198.51.100.20/32", true)]))
            .await
            .unwrap();
        assert_eq!(ctl.last_seq(), 2);
        assert!(ctl
            .active_decisions()
            .iter()
            .any(|d| d.origin == Origin::Correlation("two-agree".into())));

        // escalation: an address banned by correlation before gets
        // bantime × factor (2h × 3 = 6h)
        ctl.set_propagate(crate::state::Propagate::Global).unwrap();
        let mut esc = rule("escalating", RuleKind::Threshold, 2, 4, false);
        esc.bantime_factor = 3.0;
        ctl.set_rule(esc).unwrap();
        ctl.append(vec![NewDecision {
            kind: DecisionKind::Ban,
            target: "192.0.2.77/32".parse().unwrap(),
            scope: Scope::Global,
            jail: Some("sshd".into()),
            expires_at: Some(Utc::now() - chrono::Duration::hours(1)),
            origin: Origin::Correlation("distributed".into()),
            reason: "earlier".into(),
        }])
        .unwrap();
        let before = ctl.last_seq();
        a.report(report(vec![fails("192.0.2.77/32", 2, 0)]))
            .await
            .unwrap();
        b.report(report(vec![fails("192.0.2.77/32", 2, 0)]))
            .await
            .unwrap();
        assert_eq!(ctl.last_seq(), before + 1);
        let d = ctl
            .active_decisions()
            .into_iter()
            .find(|d| d.target.to_string() == "192.0.2.77/32")
            .unwrap();
        let left = d.expires_at.unwrap() - Utc::now();
        assert!(
            left > chrono::Duration::minutes(359) && left <= chrono::Duration::hours(6),
            "{left}"
        );
        assert!(d.reason.ends_with("offense 2"), "{}", d.reason);
        ctl.remove_rule("escalating").unwrap();

        // monitor mode: recorded, not banned
        ctl.remove_rule("distributed").unwrap();
        ctl.set_rule(rule("try-it", RuleKind::Threshold, 1, 3, true))
            .unwrap();
        let before = ctl.last_seq();
        a.report(report(vec![fails("192.0.2.200/32", 3, 0)]))
            .await
            .unwrap();
        assert_eq!(ctl.last_seq(), before);
        let hits = ctl.correlator.lock().unwrap().hits();
        assert_eq!(
            (
                hits.len(),
                hits[0].rule.as_str(),
                hits[0].target.to_string()
            ),
            (1, "try-it", "192.0.2.200/32".into())
        );
        // the address page sees the observations
        let recent = ctl
            .correlator
            .lock()
            .unwrap()
            .recent(&"203.0.113.0/24".parse().unwrap());
        assert!(recent.len() >= 3);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rate_limit_defers_the_rest_of_a_report() {
        use crate::correlation::MAX_PER_AGENT_MINUTE;
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-rate-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let mut a = enrolled(&addr, &ctl, &dir, "host-1").await;
        let obs = |key: String, banned: bool| v1::Observation {
            key,
            jail: "sshd".into(),
            count: 1,
            last_seen_unix_ms: Utc::now().timestamp_millis(),
            locally_banned: banned,
            local_ban_expires_unix_ms: (Utc::now() + chrono::Duration::hours(1)).timestamp_millis(),
            ..Default::default()
        };
        // the rate is per minute: stay within one
        let sec = Utc::now().timestamp().rem_euclid(60);
        if sec >= 45 {
            tokio::time::sleep(Duration::from_secs((61 - sec) as u64)).await;
        }
        let minute = Utc::now().timestamp().div_euclid(60);
        let mut n = 0;
        while n < MAX_PER_AGENT_MINUTE as usize {
            let k = (MAX_PER_AGENT_MINUTE as usize - n).min(MAX_REPORT);
            let batch = (n..n + k)
                .map(|i| obs(format!("198.18.{}.{}/32", i / 256, i % 256), false))
                .collect();
            let ack = a
                .report(v1::ObservationBatch {
                    observations: batch,
                })
                .await
                .unwrap()
                .into_inner();
            assert_eq!(
                (ack.accepted, ack.retry_after_ms, ack.consumed),
                (k as u32, 0, None)
            );
            n += k;
        }
        let ack = a
            .report(v1::ObservationBatch {
                observations: vec![
                    obs("203.0.113.1/32".into(), false),
                    obs("203.0.113.2/32".into(), true),
                ],
            })
            .await
            .unwrap()
            .into_inner();
        if Utc::now().timestamp().div_euclid(60) != minute {
            eprintln!("minute changed during the test; skipping the checks");
            return;
        }
        assert_eq!(ack.consumed, Some(0));
        assert!(ack.retry_after_ms > 0 && ack.retry_after_ms <= 60_000);
        // the deferred ban report made no decision (it comes again)
        assert!(ctl.active_decisions().is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression (security review): agent reports could create permanent
    /// bans (expiry 0), bans of reserved ranges, unbounded jail names (a
    /// multi-MB name made every agent's snapshot undecodable) and any
    /// number of active bans; an absurd clock made the skew overflow.
    #[tokio::test]
    async fn agent_input_is_validated() {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-grpc-input-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let (addr, ctl) = start(&dir).await;
        let mut a = enrolled(&addr, &ctl, &dir, "host-1").await;
        let ban = |key: &str, jail: &str, expires_ms: i64| v1::Observation {
            key: key.into(),
            jail: jail.into(),
            count: 5,
            last_seen_unix_ms: Utc::now().timestamp_millis(),
            locally_banned: true,
            local_ban_expires_unix_ms: expires_ms,
            ..Default::default()
        };
        let hour = (Utc::now() + chrono::Duration::hours(1)).timestamp_millis();
        let year = (Utc::now() + chrono::Duration::days(365)).timestamp_millis();
        a.report(v1::ObservationBatch {
            observations: vec![
                ban("192.0.2.1/32", "sshd", 0),                  // no expiry
                ban("127.0.0.0/24", "sshd", hour),               // reserved
                ban("192.0.2.2/32", &"j".repeat(100_000), hour), // jail
                ban("192.0.2.3/32", "bad name", hour),           // jail
                ban("192.0.2.4/32", "sshd", year),               // capped
            ],
        })
        .await
        .unwrap();
        let d = ctl.active_decisions();
        assert_eq!(d.len(), 1, "{d:?}");
        assert_eq!(d[0].target.to_string(), "192.0.2.4/32");
        let left = d[0].expires_at.unwrap() - Utc::now();
        assert!(left <= chrono::Duration::days(90), "capped at 90 days");

        // quota of active bans per agent
        let many: Vec<_> = (0..200u32)
            .map(|i| {
                ban(
                    &format!("198.51.{}.{}/32", 100 + i / 250, i % 250),
                    "sshd",
                    hour,
                )
            })
            .collect();
        a.report(v1::ObservationBatch { observations: many })
            .await
            .unwrap();
        assert_eq!(ctl.active_decisions().len(), MAX_ACTIVE_PER_AGENT);

        // an absurd clock: no overflow, skew clamped
        a.heartbeat(v1::HeartbeatRequest {
            agent_time_unix_ms: -(1i64 << 62),
            agent_version: "x".repeat(10_000),
            ..heartbeat()
        })
        .await
        .unwrap();
        assert_eq!(ctl.clock_skew_ms(&ctl.agents()[0].record.id), MAX_SKEW_MS);
        a.report(v1::ObservationBatch {
            observations: vec![v1::Observation {
                key: "192.0.2.50/32".into(),
                jail: "sshd".into(),
                count: 1,
                last_seen_unix_ms: i64::MAX,
                ..Default::default()
            }],
        })
        .await
        .unwrap();
        assert_eq!(ctl.agents()[0].status.agent_version.len(), 64);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

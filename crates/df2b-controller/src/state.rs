//! Controller state: enrolled agents, runtime status and the decision log.
//!
//! Appending to the log takes the state lock, writes the new decisions to
//! redb (one transaction), and only then publishes them to subscribers, so a
//! subscriber never sees a decision that is not durable. Subscribing takes
//! the same lock to obtain "broadcast receiver + current sequence number"
//! atomically, so no decision falls between the initial snapshot/backlog and
//! the live stream.

use df2b_core::{RedactRule, Redactor};
use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use chrono::{DateTime, Utc};
use clap::ValueEnum;
use df2b_core::{Allowlist, Decision, DecisionKind, Origin, Scope};
use df2b_tls::{Ca, CertInfo};
use ipnet::IpNet;
use serde::Serialize;
use tokio::sync::broadcast;
use uuid::Uuid;

use crate::files;
use crate::session::Sessions;
use crate::store::{AgentRecord, AllowEntry, AuditEntry, Store};

/// A resuming subscriber further behind than this gets a snapshot instead.
const MAX_BACKLOG: u64 = 10_000;
/// How long the hourly ban counts are kept (dashboard).
const HOURLY_KEEP: i64 = 7 * 24;

/// What happens to an agent's local ban (DESIGN.md §4.2 `propagate_local`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, serde::Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Propagate {
    /// Ban on all agents.
    Global,
    /// Ban on all agents in the reporting agent's group.
    Group,
    /// Record nothing.
    Off,
}

pub struct Settings {
    pub state_dir: PathBuf,
    pub cert_lifetime: Duration,
    /// Initial value; changed at runtime with [`Controller::set_propagate`].
    pub propagate: Propagate,
    /// Fixed entries (`--allow`); more can be added through the API.
    pub allowlist: Allowlist,
    /// Web UI login with an OpenID Connect provider.
    pub oidc: Option<Arc<crate::oidc::Oidc>>,
    /// The REST API uses a certificate from the internal CA (clients pin
    /// its fingerprint), not an operator-provided one.
    pub https_internal_ca: bool,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct AgentStatus {
    pub last_seen: Option<DateTime<Utc>>,
    pub agent_version: String,
    pub active_bans: u64,
    /// controller time - agent time
    pub clock_skew_ms: i64,
    pub firewall_backend: String,
    pub firewall_healthy: bool,
    pub last_applied_seq: u64,
    /// Open decision streams (> 0 = connected).
    pub streams: u32,
    /// Central allowlist version the agent applies ("" = unknown).
    pub allowlist_version: String,
    /// The agent's jails with their effective settings.
    pub jails: Vec<JailView>,
    /// Jail policies version the agent applies ("" = unknown).
    pub jail_policies_version: String,
    /// Central jail definitions version the agent applies.
    pub central_jails_version: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct AgentView {
    #[serde(flatten)]
    pub record: AgentRecord,
    pub connected: bool,
    pub revoked: bool,
    pub status: AgentStatus,
}

/// A decision before it gets its sequence number.
pub struct NewDecision {
    pub kind: DecisionKind,
    pub target: IpNet,
    pub scope: Scope,
    pub jail: Option<String>,
    pub expires_at: Option<DateTime<Utc>>,
    pub origin: Origin,
    pub reason: String,
}

/// What a new subscriber receives before the live stream.
pub enum Initial {
    Snapshot { seq: u64, active: Vec<Decision> },
    Backlog { seq: u64, decisions: Vec<Decision> },
}

#[derive(Debug, thiserror::Error)]
pub enum AuthError {
    #[error("client certificate required")]
    NoCertificate,
    #[error("unknown agent")]
    Unknown,
    #[error("certificate superseded")]
    Superseded,
    #[error("agent revoked")]
    Revoked,
}

#[derive(Default)]
struct Inner {
    last_seq: u64,
    /// Active ban decisions by id.
    active: HashMap<Uuid, Decision>,
    agents: HashMap<String, AgentRecord>,
    status: HashMap<String, AgentStatus>,
    /// New bans per hour (unix time / 3600), for the dashboard.
    hourly: BTreeMap<i64, u32>,
    /// Correlation bans per target (id, created), for escalation; rebuilt
    /// from the log at start. Bans a user lifted are forgiven.
    offenses: HashMap<IpNet, Vec<(Uuid, DateTime<Utc>)>>,
}

/// Correlation bans older than this no longer escalate (like the agents'
/// default `offense_memory`).
pub const OFFENSE_MEMORY: Duration = Duration::from_secs(30 * 86400);

impl Inner {
    fn count(&mut self, d: &Decision) {
        match (&d.kind, &d.origin) {
            (DecisionKind::Ban, origin) => {
                *self
                    .hourly
                    .entry(d.created_at.timestamp().div_euclid(3600))
                    .or_default() += 1;
                if matches!(origin, Origin::Correlation(_)) {
                    self.offenses
                        .entry(d.target)
                        .or_default()
                        .push((d.id, d.created_at));
                }
            }
            // a person lifted it (false positive, allowlisted): forgiven
            (DecisionKind::Unban { revokes }, Origin::User(_)) => {
                if let Some(v) = self.offenses.get_mut(&d.target) {
                    v.retain(|(id, _)| id != revokes);
                }
            }
            _ => {}
        }
    }
}

pub struct Controller {
    pub settings: Settings,
    pub ca: Ca,
    pub(crate) store: Store,
    inner: Mutex<Inner>,
    events: broadcast::Sender<Arc<Decision>>,
    pub sessions: Sessions,
    /// API token name → last request (since the controller started).
    token_last_used: Mutex<HashMap<String, DateTime<Utc>>>,
    /// Allowlist entries added through the API (persisted in the store).
    allow_entries: Mutex<Vec<AllowEntry>>,
    /// The complete allowlist as sent to agents; changes wake up streams.
    allow_tx: tokio::sync::watch::Sender<Arc<AllowSnapshot>>,
    /// Central jail settings; streams send each agent its group's merge.
    jail_tx: tokio::sync::watch::Sender<Arc<Vec<crate::policy::JailOverride>>>,
    /// What an agent's local ban turns into (changeable at runtime).
    propagate: Mutex<Propagate>,
    jail_write: Mutex<()>,
    /// Central filters and jail definitions; streams send each agent its
    /// group's part.
    central_tx: tokio::sync::watch::Sender<Arc<crate::central::CentralConfig>>,
    /// Correlation rules (stored) and what agents observed (memory).
    rules: Mutex<Arc<Vec<crate::correlation::Rule>>>,
    /// Redaction rules for sample log lines, and the compiled enabled ones.
    redaction: Mutex<(Arc<Vec<RedactRule>>, Arc<Redactor>)>,
    pub correlator: Mutex<crate::correlation::Correlator>,
    /// ASN/country databases (optional; display only)
    pub geo: crate::geo::Geo,
}

#[derive(Debug, thiserror::Error)]
pub enum CentralError {
    #[error("filter {0:?} is used by {1}")]
    FilterInUse(String, String),
    #[error("no such {0}")]
    Missing(&'static str),
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

/// A jail as an agent reports it.
#[derive(Debug, Clone, Default, Serialize)]
pub struct JailView {
    pub name: String,
    pub filter: String,
    pub enabled: bool,
    pub maxretry: u32,
    pub findtime_secs: u64,
    pub bantime_secs: u64,
    pub bantime_factor: f64,
    /// 0 = no maximum
    pub max_bantime_secs: u64,
    /// settings that come from a central policy
    pub overridden: Vec<String>,
    pub active_bans: u64,
    /// "local" or "central"
    pub origin: String,
    /// why a central jail does not run
    pub error: String,
}

/// The central allowlist as distributed to agents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AllowSnapshot {
    /// Content hash (16 hex digits): stable across restarts.
    pub version: String,
    /// Network and, for temporary entries, its expiry.
    pub entries: Vec<(IpNet, Option<DateTime<Utc>>)>,
}

/// What `add_allow` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AllowAdded {
    Added,
    /// A temporary entry for the same network now lasts longer.
    Extended,
}

impl AllowSnapshot {
    pub fn new(mut entries: Vec<(IpNet, Option<DateTime<Utc>>)>) -> Self {
        entries.sort();
        entries.dedup_by_key(|e| e.0);
        let text: Vec<String> = entries
            .iter()
            .map(|(n, e)| match e {
                Some(t) => format!("{n} {}", t.timestamp_millis()),
                None => n.to_string(),
            })
            .collect();
        let hash = df2b_tls::sha256(text.join("\n").as_bytes());
        Self {
            version: df2b_tls::hex(&hash[..8]),
            entries,
        }
    }
}

/// Where an allowlist entry comes from.
#[derive(Debug, Clone, Serialize)]
pub struct AllowView {
    pub net: IpNet,
    /// "command line" for `--allow`, else the creator
    pub source: &'static str,
    pub comment: String,
    pub created_by: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
    /// temporary entries
    pub expires_at: Option<DateTime<Utc>>,
}

#[derive(Debug, thiserror::Error)]
pub enum AllowError {
    #[error("{0} is already on the allowlist")]
    Exists(IpNet),
    #[error("{0} is already covered by the allowlist entry {1}")]
    Covered(IpNet, IpNet),
    #[error("{0} comes from --allow on the command line")]
    Fixed(IpNet),
    #[error("{0} is not on the allowlist")]
    Missing(IpNet),
    #[error(transparent)]
    Store(#[from] anyhow::Error),
}

fn apply(active: &mut HashMap<Uuid, Decision>, d: &Decision, now: DateTime<Utc>) {
    match &d.kind {
        DecisionKind::Ban if d.is_active(now) => {
            active.insert(d.id, d.clone());
        }
        DecisionKind::Unban { revokes } => {
            active.remove(revokes);
        }
        _ => {}
    }
}

impl Controller {
    pub fn open(settings: Settings, ca: Ca, store: Store) -> anyhow::Result<Self> {
        let mut inner = Inner::default();
        let now = Utc::now();
        store.for_each(|d| {
            inner.last_seq = inner.last_seq.max(d.seq);
            apply(&mut inner.active, &d, now);
            inner.count(&d);
        })?;
        let allow_entries = store.allow_entries()?;
        for a in store.agents()? {
            inner.agents.insert(a.id.clone(), a);
        }
        tracing::info!(
            agents = inner.agents.len(),
            active_decisions = inner.active.len(),
            last_seq = inner.last_seq,
            "controller state loaded"
        );
        let jail_tx = tokio::sync::watch::channel(Arc::new(store.jail_overrides()?)).0;
        let central_tx = tokio::sync::watch::channel(Arc::new(store.central_config()?)).0;
        let rules = store.rules()?;
        // observations of the last hours (correlation survives restarts)
        let mut correlator = crate::correlation::Correlator::default();
        let keep = crate::correlation::keep_for(&rules);
        let since = now - chrono::Duration::from_std(keep).unwrap_or_default();
        let restored = correlator.restore(
            store.observations(since)?,
            store.setting::<crate::correlation::Meta>("correlation")?,
            now,
            keep,
        );
        if restored > 0 {
            tracing::info!(
                observations = restored,
                addresses = correlator.tracked(),
                "correlation observations restored"
            );
        }
        // stored rules that no longer compile are skipped, not fatal
        let redaction_rules: Vec<RedactRule> = store
            .setting::<Vec<RedactRule>>("redaction")?
            .unwrap_or_default()
            .into_iter()
            .filter(|r| match df2b_core::redact::compile(&r.pattern) {
                Ok(_) => true,
                Err(e) => {
                    tracing::warn!(rule = %r.name, error = %e, "ignoring redaction rule");
                    false
                }
            })
            .collect();
        let redactor = Redactor::new(&redaction_rules).unwrap_or_default();
        // rows written before a rule was added are redacted now
        correlator.redact_samples(&redactor);
        let redaction = Mutex::new((Arc::new(redaction_rules), Arc::new(redactor)));
        let rules = Mutex::new(Arc::new(rules));
        // a stored change wins over the default; an explicit flag is
        // applied by main.rs with set_propagate
        let propagate = store
            .setting::<Propagate>("propagate")?
            .unwrap_or(settings.propagate);
        let allow_tx = tokio::sync::watch::channel(Arc::new(AllowSnapshot::new(
            settings
                .allowlist
                .iter()
                .map(|n| (*n, None))
                .chain(
                    allow_entries
                        .iter()
                        .filter(|e| e.is_live(now))
                        .map(|e| (e.net, e.expires_at)),
                )
                .collect(),
        )))
        .0;
        Ok(Self {
            settings,
            ca,
            store,
            inner: Mutex::new(inner),
            events: broadcast::channel(4096).0,
            sessions: Sessions::default(),
            token_last_used: Mutex::new(HashMap::new()),
            allow_tx,
            allow_entries: Mutex::new(allow_entries),
            jail_tx,
            propagate: Mutex::new(propagate),
            jail_write: Mutex::new(()),
            central_tx,
            rules,
            correlator: Mutex::new(correlator),
            geo: Default::default(),
            redaction,
        })
    }

    pub fn with_geo(mut self, geo: crate::geo::Geo) -> Self {
        self.geo = geo;
        self
    }

    fn lock(&self) -> MutexGuard<'_, Inner> {
        self.inner.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Identifies an agent by its (already TLS-verified) client certificate.
    pub fn authenticate(&self, cert: Option<&[u8]>) -> Result<AgentRecord, AuthError> {
        let info = CertInfo::parse(cert.ok_or(AuthError::NoCertificate)?)
            .map_err(|_| AuthError::NoCertificate)?;
        let record = self
            .lock()
            .agents
            .get(&info.common_name)
            .cloned()
            .ok_or(AuthError::Unknown)?;
        if !record.serials.contains(&info.serial) {
            return Err(AuthError::Superseded);
        }
        if files::is_revoked(&self.settings.state_dir, &record.id) {
            return Err(AuthError::Revoked);
        }
        Ok(record)
    }

    pub fn is_revoked(&self, agent_id: &str) -> bool {
        files::is_revoked(&self.settings.state_dir, agent_id)
    }

    /// Stores a new or updated agent record (blocking).
    pub fn put_agent(&self, record: AgentRecord) -> anyhow::Result<()> {
        self.store.put_agent(&record)?;
        self.lock().agents.insert(record.id.clone(), record);
        Ok(())
    }

    /// Appends decisions (blocking: one fsync). Bans that are already
    /// covered by an active ban for the same target lasting at least as long
    /// are skipped. Returns what was appended.
    pub fn append(&self, new: Vec<NewDecision>) -> anyhow::Result<Vec<Arc<Decision>>> {
        let now = Utc::now();
        let mut inner = self.lock();
        let mut seq = inner.last_seq;
        let mut out: Vec<Decision> = Vec::new();
        for n in new {
            if matches!(n.kind, DecisionKind::Ban) {
                let covered = inner
                    .active
                    .values()
                    .chain(out.iter())
                    .filter(|d| matches!(d.kind, DecisionKind::Ban) && d.is_active(now))
                    .any(|d| {
                        d.target == n.target
                            && d.scope == n.scope
                            && match (d.expires_at, n.expires_at) {
                                (None, _) => true,
                                (Some(_), None) => false,
                                (Some(a), Some(b)) => a >= b,
                            }
                    });
                if covered {
                    continue;
                }
            }
            seq += 1;
            out.push(Decision {
                seq,
                id: Uuid::new_v4(),
                kind: n.kind,
                target: n.target,
                scope: n.scope,
                jail: n.jail,
                created_at: now,
                expires_at: n.expires_at,
                origin: n.origin,
                reason: n.reason,
            });
        }
        if out.is_empty() {
            return Ok(Vec::new());
        }
        self.store.append(&out)?;
        inner.last_seq = seq;
        let mut published = Vec::with_capacity(out.len());
        for d in out {
            apply(&mut inner.active, &d, now);
            inner.count(&d);
            let d = Arc::new(d);
            // no receivers is fine
            let _ = self.events.send(d.clone());
            published.push(d);
        }
        Ok(published)
    }

    /// Starts a subscription for an agent that has applied up to `from_seq`.
    pub fn subscribe(
        &self,
        from_seq: u64,
        agent: &AgentRecord,
    ) -> anyhow::Result<(Initial, broadcast::Receiver<Arc<Decision>>)> {
        let now = Utc::now();
        let (rx, last, snapshot) = {
            let mut inner = self.lock();
            let rx = self.events.subscribe();
            let last = inner.last_seq;
            // the current record: the group may have changed since `agent`
            // was read
            let current = inner.agents.get(&agent.id).cloned();
            let agent = current.as_ref().unwrap_or(agent);
            let need_snapshot =
                from_seq == 0 || from_seq > last || last - from_seq > MAX_BACKLOG || agent.resync;
            if agent.resync {
                // cleared under the lock, so a concurrent group change is
                // never lost
                let mut r = agent.clone();
                r.resync = false;
                self.store.put_agent(&r)?;
                inner.agents.insert(r.id.clone(), r);
            }
            let agent = &inner
                .agents
                .get(&agent.id)
                .cloned()
                .unwrap_or_else(|| agent.clone());
            let snapshot = need_snapshot.then(|| {
                let mut v: Vec<Decision> = inner
                    .active
                    .values()
                    .filter(|d| d.is_active(now) && applies(d, agent))
                    .cloned()
                    .collect();
                v.sort_by_key(|d| d.seq);
                v
            });
            (rx, last, snapshot)
        };
        let initial = match snapshot {
            Some(active) => Initial::Snapshot { seq: last, active },
            None => Initial::Backlog {
                seq: last,
                decisions: self
                    .store
                    .range(from_seq, last)?
                    .into_iter()
                    .filter(|d| applies(d, agent))
                    .collect(),
            },
        };
        Ok((initial, rx))
    }

    /// Moves an agent to another group (blocking: one fsync). Its open
    /// streams close (see grpc.rs) and its next subscription gets a full
    /// snapshot. Returns the previous group.
    pub fn set_group(&self, id: &str, group: &str) -> anyhow::Result<Option<String>> {
        let mut inner = self.lock();
        let Some(mut r) = inner.agents.get(id).cloned() else {
            return Ok(None);
        };
        let old = std::mem::replace(&mut r.group, group.to_owned());
        if old != group {
            r.resync = true;
            self.store.put_agent(&r)?;
            inner.agents.insert(r.id.clone(), r);
        }
        Ok(Some(old))
    }

    /// The agent's current group (`None`: unknown agent).
    pub fn agent_group(&self, id: &str) -> Option<String> {
        self.lock().agents.get(id).map(|a| a.group.clone())
    }

    pub fn update_status(&self, id: &str, f: impl FnOnce(&mut AgentStatus)) {
        let mut inner = self.lock();
        let s = inner.status.entry(id.to_owned()).or_default();
        s.last_seen = Some(Utc::now());
        f(s);
    }

    /// Drops expired bans from the active set.
    pub fn prune(&self) {
        let now = Utc::now();
        let mut inner = self.lock();
        inner.active.retain(|_, d| d.is_active(now));
        let oldest = now.timestamp().div_euclid(3600) - HOURLY_KEEP;
        inner.hourly.retain(|h, _| *h >= oldest);
        let forget = now - chrono::Duration::from_std(OFFENSE_MEMORY).unwrap_or_default();
        inner.offenses.retain(|_, v| {
            v.retain(|(_, at)| *at > forget);
            !v.is_empty()
        });
        drop(inner);
        self.sessions.prune();
        let keep = crate::correlation::keep_for(&self.rules());
        self.correlator
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .prune(now, keep);
        let before = now - chrono::Duration::from_std(keep).unwrap_or_default();
        if let Err(e) = self.store.prune_observations(before) {
            tracing::warn!(error = %format!("{e:#}"), "pruning stored observations failed");
        }
        if let Err(e) = self.prune_allowlist() {
            tracing::warn!(error = %format!("{e:#}"), "pruning the allowlist failed");
        }
    }

    /// Writes the correlation observations accepted since the last call
    /// (every few seconds and at shutdown; blocking).
    pub fn flush_observations(&self) {
        let (obs, meta) = self
            .correlator
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .take_unsaved();
        if obs.is_empty() && meta.is_none() {
            return;
        }
        if let Err(e) = self
            .store
            .append_observations(Utc::now(), &obs, meta.as_ref())
        {
            // memory still has them; only a restart would lose them
            tracing::warn!(
                error = %format!("{e:#}"),
                observations = obs.len(),
                "storing correlation observations failed"
            );
        }
    }

    fn allow_lock(&self) -> MutexGuard<'_, Vec<AllowEntry>> {
        self.allow_entries.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether banning `net` would touch an allowlisted address (fixed and
    /// API entries).
    /// Whether banning `net` would touch an allowlisted address (fixed and
    /// API entries; temporary ones until they expire).
    pub fn allowlisted(&self, net: &IpNet) -> bool {
        let now = Utc::now();
        self.settings.allowlist.overlaps(net)
            || self
                .allow_lock()
                .iter()
                .filter(|e| e.is_live(now))
                .any(|e| e.net.contains(net) || net.contains(&e.net))
    }

    /// All live entries: `--allow` first, then API entries by network.
    pub fn allowlist(&self) -> Vec<AllowView> {
        let now = Utc::now();
        let mut v: Vec<AllowView> = self
            .settings
            .allowlist
            .iter()
            .map(|n| AllowView {
                net: *n,
                source: "command line",
                comment: String::new(),
                created_by: None,
                created_at: None,
                expires_at: None,
            })
            .collect();
        let mut added: Vec<AllowView> = self
            .allow_lock()
            .iter()
            .filter(|e| e.is_live(now))
            .map(|e| AllowView {
                net: e.net,
                source: "api",
                comment: e.comment.clone(),
                created_by: Some(e.created_by.clone()),
                created_at: Some(e.created_at),
                expires_at: e.expires_at,
            })
            .collect();
        added.sort_by_key(|e| e.net);
        v.extend(added);
        v
    }

    /// Adds an entry (blocking: one fsync). Permanent entries replace a
    /// temporary one for the same network; a temporary entry replaces a
    /// shorter one. Refused: an entry that exists (at least as long) or
    /// lies inside a permanent one.
    pub fn add_allow(&self, e: AllowEntry) -> Result<AllowAdded, AllowError> {
        let now = Utc::now();
        let mut entries = self.allow_lock();
        for n in self.settings.allowlist.iter() {
            if *n == e.net {
                return Err(AllowError::Exists(e.net));
            }
            if n.contains(&e.net) {
                return Err(AllowError::Covered(e.net, *n));
            }
        }
        let mut outcome = AllowAdded::Added;
        for x in entries.iter().filter(|x| x.is_live(now)) {
            if x.net == e.net {
                match (x.expires_at, e.expires_at) {
                    (None, _) => return Err(AllowError::Exists(e.net)),
                    (Some(_), None) => {}
                    (Some(old), Some(new)) if old >= new => return Err(AllowError::Exists(e.net)),
                    (Some(_), Some(_)) => outcome = AllowAdded::Extended,
                }
            } else if x.expires_at.is_none() && x.net.contains(&e.net) {
                return Err(AllowError::Covered(e.net, x.net));
            }
        }
        // the store key is the network: this replaces an older entry
        self.store.put_allow(&e)?;
        entries.retain(|x| x.net != e.net);
        entries.push(e);
        self.publish_allowlist(&entries);
        Ok(outcome)
    }

    /// Drops expired temporary entries (housekeeping). Blocking.
    pub fn prune_allowlist(&self) -> anyhow::Result<usize> {
        let now = Utc::now();
        let mut entries = self.allow_lock();
        let expired: Vec<IpNet> = entries
            .iter()
            .filter(|e| !e.is_live(now))
            .map(|e| e.net)
            .collect();
        for net in &expired {
            self.store.delete_allow(net)?;
            tracing::info!(%net, "temporary allowlist entry expired");
        }
        if !expired.is_empty() {
            entries.retain(|e| e.is_live(now));
            self.publish_allowlist(&entries);
        }
        Ok(expired.len())
    }

    fn publish_allowlist(&self, entries: &[AllowEntry]) {
        let now = Utc::now();
        let snap = AllowSnapshot::new(
            self.settings
                .allowlist
                .iter()
                .map(|n| (*n, None))
                .chain(
                    entries
                        .iter()
                        .filter(|e| e.is_live(now))
                        .map(|e| (e.net, e.expires_at)),
                )
                .collect(),
        );
        self.allow_tx.send_replace(Arc::new(snap));
    }

    /// The current allowlist for agents, and a receiver for changes.
    pub fn allowlist_watch(&self) -> tokio::sync::watch::Receiver<Arc<AllowSnapshot>> {
        self.allow_tx.subscribe()
    }

    pub fn allowlist_version(&self) -> String {
        self.allow_tx.borrow().version.clone()
    }

    /// Removes an API entry (blocking).
    pub fn remove_allow(&self, net: &IpNet) -> Result<(), AllowError> {
        if self.settings.allowlist.iter().any(|n| n == net) {
            return Err(AllowError::Fixed(*net));
        }
        let mut entries = self.allow_lock();
        if !self.store.delete_allow(net)? {
            return Err(AllowError::Missing(*net));
        }
        entries.retain(|e| e.net != *net);
        self.publish_allowlist(&entries);
        Ok(())
    }

    pub fn propagate(&self) -> Propagate {
        *self.propagate.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Changes and stores the propagation policy (blocking).
    pub fn set_propagate(&self, p: Propagate) -> anyhow::Result<Propagate> {
        let mut cur = self.propagate.lock().unwrap_or_else(|e| e.into_inner());
        self.store.put_setting("propagate", &p)?;
        Ok(std::mem::replace(&mut cur, p))
    }

    pub fn jail_overrides(&self) -> Arc<Vec<crate::policy::JailOverride>> {
        self.jail_tx.borrow().clone()
    }

    pub fn jail_watch(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<Vec<crate::policy::JailOverride>>> {
        self.jail_tx.subscribe()
    }

    /// Stores an override (replacing the one for the same jail and scope;
    /// an empty one removes it), then publishes it. Blocking. Returns the
    /// previous one.
    pub fn set_jail_override(
        &self,
        o: crate::policy::JailOverride,
    ) -> anyhow::Result<Option<crate::policy::JailOverride>> {
        // one writer at a time: store and published list stay in step
        let _write = self.jail_write.lock().unwrap_or_else(|e| e.into_inner());
        let mut v = (**self.jail_tx.borrow()).clone();
        let prev = v
            .iter()
            .position(|x| x.jail == o.jail && x.group == o.group)
            .map(|i| v.remove(i));
        if o.settings.is_empty() {
            self.store
                .delete_jail_override(&o.jail, o.group.as_deref())?;
        } else {
            self.store.put_jail_override(&o)?;
            v.push(o);
        }
        // only what is stored reaches the agents
        self.jail_tx.send_replace(Arc::new(v));
        Ok(prev)
    }

    pub fn rules(&self) -> Arc<Vec<crate::correlation::Rule>> {
        self.rules.lock().unwrap_or_else(|e| e.into_inner()).clone()
    }

    /// Stores a rule (replacing one with the same name). Blocking.
    pub fn set_rule(
        &self,
        r: crate::correlation::Rule,
    ) -> anyhow::Result<Option<crate::correlation::Rule>> {
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        self.store.put_rule(&r)?;
        let mut v = (**rules).clone();
        let prev = v.iter().position(|x| x.name == r.name).map(|i| v.remove(i));
        v.push(r);
        v.sort_by(|a, b| a.name.cmp(&b.name));
        *rules = Arc::new(v);
        Ok(prev)
    }

    /// False if there is no such rule. Blocking.
    pub fn remove_rule(&self, name: &str) -> anyhow::Result<bool> {
        let mut rules = self.rules.lock().unwrap_or_else(|e| e.into_inner());
        if !self.store.delete_rule(name)? {
            return Ok(false);
        }
        let mut v = (**rules).clone();
        v.retain(|x| x.name != name);
        *rules = Arc::new(v);
        Ok(true)
    }

    pub fn redaction_rules(&self) -> Arc<Vec<RedactRule>> {
        self.redaction
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .0
            .clone()
    }

    /// The enabled redaction rules, compiled.
    pub fn redactor(&self) -> Arc<Redactor> {
        self.redaction
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .1
            .clone()
    }

    /// Changes the redaction rules with `edit` (one writer at a time) and
    /// redacts the sample lines kept so far, in memory and in the database,
    /// so no line that a rule now hides stays anywhere. `edit` returns its
    /// result, or None for "nothing changed". Blocking.
    fn edit_redaction<T>(
        &self,
        edit: impl FnOnce(&mut Vec<RedactRule>) -> Option<T>,
    ) -> anyhow::Result<Option<(T, usize)>> {
        let mut cur = self.redaction.lock().unwrap_or_else(|e| e.into_inner());
        let mut rules = (*cur.0).clone();
        let Some(out) = edit(&mut rules) else {
            return Ok(None);
        };
        let redactor = Redactor::new(&rules).map_err(|e| anyhow::anyhow!(e))?;
        self.store.put_setting("redaction", &rules)?;
        let mut changed = self
            .correlator
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .redact_samples(&redactor);
        changed += self
            .store
            .map_observation_samples(|l| df2b_core::sample_line(&redactor.apply(l)))?;
        *cur = (Arc::new(rules), Arc::new(redactor));
        Ok(Some((out, changed)))
    }

    /// Adds or replaces (in place) a redaction rule; returns the previous
    /// one and how many kept lines changed. Blocking.
    pub fn set_redaction_rule(&self, r: RedactRule) -> anyhow::Result<(Option<RedactRule>, usize)> {
        let done = self.edit_redaction(|v| {
            Some(match v.iter_mut().find(|x| x.name == r.name) {
                Some(x) => Some(std::mem::replace(x, r)),
                None => {
                    v.push(r);
                    None
                }
            })
        })?;
        Ok(done.unwrap_or((None, 0)))
    }

    /// False if there is no such rule. Blocking.
    pub fn remove_redaction_rule(&self, name: &str) -> anyhow::Result<bool> {
        let done = self.edit_redaction(|v| {
            let before = v.len();
            v.retain(|x| x.name != name);
            (v.len() != before).then_some(())
        })?;
        Ok(done.is_some())
    }

    /// Earlier correlation bans of exactly this target within
    /// [`OFFENSE_MEMORY`] (not counting those a user lifted).
    pub fn correlation_offenses(&self, target: &IpNet) -> u32 {
        let since = Utc::now() - chrono::Duration::from_std(OFFENSE_MEMORY).unwrap_or_default();
        self.lock()
            .offenses
            .get(target)
            .map_or(0, |v| v.iter().filter(|(_, at)| *at > since).count() as u32)
    }

    /// controller time - agent time, from the last heartbeat.
    pub fn clock_skew_ms(&self, agent: &str) -> i64 {
        self.lock().status.get(agent).map_or(0, |s| s.clock_skew_ms)
    }

    pub fn central(&self) -> Arc<crate::central::CentralConfig> {
        self.central_tx.borrow().clone()
    }

    pub fn central_watch(
        &self,
    ) -> tokio::sync::watch::Receiver<Arc<crate::central::CentralConfig>> {
        self.central_tx.subscribe()
    }

    /// Stores a filter (replacing one with the same name), then publishes.
    /// Blocking; the caller validated it. True if it replaced one.
    pub fn set_filter(&self, f: crate::central::CentralFilter) -> anyhow::Result<bool> {
        let _write = self.jail_write.lock().unwrap_or_else(|e| e.into_inner());
        let mut c = (**self.central_tx.borrow()).clone();
        self.store.put_filter(&f)?;
        let existed = c.filters.iter().any(|x| x.name == f.name);
        c.filters.retain(|x| x.name != f.name);
        c.filters.push(f);
        self.central_tx.send_replace(Arc::new(c));
        Ok(existed)
    }

    /// Removes a filter no central jail uses. Blocking.
    pub fn remove_filter(&self, name: &str) -> Result<(), CentralError> {
        let _write = self.jail_write.lock().unwrap_or_else(|e| e.into_inner());
        let mut c = (**self.central_tx.borrow()).clone();
        let users = c.users_of(name);
        if !users.is_empty() {
            return Err(CentralError::FilterInUse(name.into(), users.join(", ")));
        }
        if !self.store.delete_filter(name)? {
            return Err(CentralError::Missing("filter"));
        }
        c.filters.retain(|x| x.name != name);
        self.central_tx.send_replace(Arc::new(c));
        Ok(())
    }

    /// Stores a jail definition (replacing the one with the same name and
    /// scope), then publishes. Blocking; the caller validated it. Returns
    /// the previous one.
    pub fn set_jail_def(
        &self,
        d: crate::central::JailDef,
    ) -> anyhow::Result<Option<crate::central::JailDef>> {
        let _write = self.jail_write.lock().unwrap_or_else(|e| e.into_inner());
        let mut c = (**self.central_tx.borrow()).clone();
        self.store.put_jail_def(&d)?;
        let prev = c
            .defs
            .iter()
            .position(|x| x.name == d.name && x.group == d.group)
            .map(|i| c.defs.remove(i));
        c.defs.push(d);
        self.central_tx.send_replace(Arc::new(c));
        Ok(prev)
    }

    pub fn remove_jail_def(&self, name: &str, group: Option<&str>) -> Result<(), CentralError> {
        let _write = self.jail_write.lock().unwrap_or_else(|e| e.into_inner());
        let mut c = (**self.central_tx.borrow()).clone();
        if !self.store.delete_jail_def(name, group)? {
            return Err(CentralError::Missing("jail definition"));
        }
        c.defs
            .retain(|x| !(x.name == name && x.group.as_deref() == group));
        self.central_tx.send_replace(Arc::new(c));
        Ok(())
    }

    pub fn token_used(&self, name: &str) {
        self.token_last_used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .insert(name.to_owned(), Utc::now());
    }

    pub fn token_last_used(&self, name: &str) -> Option<DateTime<Utc>> {
        self.token_last_used
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .get(name)
            .copied()
    }

    /// Live decisions (for the UI); the receiver lags rather than blocks.
    pub fn events(&self) -> broadcast::Receiver<Arc<Decision>> {
        self.events.subscribe()
    }

    /// New bans per hour for the last `hours` hours (oldest first), as
    /// (hour start, count).
    pub fn bans_per_hour(&self, hours: i64) -> Vec<(DateTime<Utc>, u32)> {
        let now = Utc::now().timestamp().div_euclid(3600);
        let inner = self.lock();
        (now - hours + 1..=now)
            .map(|h| {
                (
                    DateTime::from_timestamp(h * 3600, 0).unwrap_or_default(),
                    inner.hourly.get(&h).copied().unwrap_or(0),
                )
            })
            .collect()
    }

    /// Decisions (bans and unbans, active or not) whose target overlaps
    /// `target`, newest first. Blocking: scans the log.
    pub fn history(&self, target: IpNet, limit: usize) -> anyhow::Result<Vec<Decision>> {
        self.store.history(
            |d| d.target.contains(&target) || target.contains(&d.target),
            limit,
        )
    }

    pub fn agents(&self) -> Vec<AgentView> {
        let inner = self.lock();
        let mut v: Vec<AgentView> = inner
            .agents
            .values()
            .map(|r| {
                let status = inner.status.get(&r.id).cloned().unwrap_or_default();
                AgentView {
                    connected: status.streams > 0,
                    revoked: self.is_revoked(&r.id),
                    record: r.clone(),
                    status,
                }
            })
            .collect();
        v.sort_by(|a, b| a.record.id.cmp(&b.record.id));
        v
    }

    /// Revokes every active ban whose target overlaps `target` (so unbanning
    /// an address also removes the /64 ban containing it). Each unban goes to
    /// the same scope as the ban it revokes. Blocking.
    pub fn unban(
        &self,
        target: IpNet,
        origin: Origin,
        reason: &str,
    ) -> anyhow::Result<Vec<Arc<Decision>>> {
        let matching: Vec<Decision> = self
            .active_decisions()
            .into_iter()
            .filter(|d| d.target.contains(&target) || target.contains(&d.target))
            .collect();
        self.append(
            matching
                .into_iter()
                .map(|d| NewDecision {
                    kind: DecisionKind::Unban { revokes: d.id },
                    target: d.target,
                    scope: d.scope,
                    jail: d.jail,
                    expires_at: None,
                    origin: origin.clone(),
                    reason: reason.to_owned(),
                })
                .collect(),
        )
    }

    /// Records an administrative action. Blocking.
    pub fn audit(
        &self,
        actor: &str,
        remote_addr: Option<String>,
        action: &str,
        details: serde_json::Value,
    ) -> anyhow::Result<()> {
        let e = self.store.audit(AuditEntry {
            seq: 0,
            time: Utc::now(),
            actor: actor.to_owned(),
            remote_addr,
            action: action.to_owned(),
            details,
        })?;
        tracing::info!(seq = e.seq, actor, action, details = %e.details, "audit");
        Ok(())
    }

    pub fn audit_log(&self, limit: usize, before: u64) -> anyhow::Result<Vec<AuditEntry>> {
        self.store.audit_log(limit, before)
    }

    pub fn agent(&self, id: &str) -> Option<AgentView> {
        self.agents().into_iter().find(|a| a.record.id == id)
    }

    pub fn last_seq(&self) -> u64 {
        self.lock().last_seq
    }

    pub fn active_decisions(&self) -> Vec<Decision> {
        let now = Utc::now();
        let mut v: Vec<Decision> = self
            .lock()
            .active
            .values()
            .filter(|d| d.is_active(now))
            .cloned()
            .collect();
        v.sort_by_key(|d| d.seq);
        v
    }
}

pub fn applies(d: &Decision, agent: &AgentRecord) -> bool {
    d.applies_to(
        &df2b_core::AgentId(agent.id.clone()),
        std::slice::from_ref(&agent.group),
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctl(tag: &str) -> (Controller, PathBuf) {
        let dir = std::env::temp_dir().join(format!("df2b-ctl-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let settings = Settings {
            state_dir: dir.clone(),
            cert_lifetime: Duration::from_secs(3600),
            propagate: Propagate::Global,
            allowlist: Allowlist::default(),
            oidc: None,
            https_internal_ca: true,
        };
        let c = Controller::open(
            settings,
            Ca::generate("t").unwrap(),
            Store::open(&dir).unwrap(),
        )
        .unwrap();
        (c, dir)
    }

    fn agent(id: &str, group: &str) -> AgentRecord {
        AgentRecord {
            id: id.into(),
            hostname: id.into(),
            group: group.into(),
            enrolled_at: Utc::now(),
            serials: vec![],
            cert_not_after: Utc::now(),
            resync: false,
        }
    }

    fn ban(target: &str, scope: Scope, hours: Option<i64>) -> NewDecision {
        NewDecision {
            kind: DecisionKind::Ban,
            target: target.parse().unwrap(),
            scope,
            jail: Some("sshd".into()),
            // fixed future instant, so equal durations compare equal
            expires_at: hours
                .map(|h| DateTime::from_timestamp(4_000_000_000 + h * 3600, 0).unwrap()),
            origin: Origin::Agent(df2b_core::AgentId("a".into())),
            reason: String::new(),
        }
    }

    #[test]
    fn append_dedupes_and_subscribe_resumes() {
        let (c, dir) = ctl("log");
        let web = agent("web-1", "web");
        let db = agent("db-1", "db");
        let out = c
            .append(vec![
                ban("203.0.113.7/32", Scope::Global, Some(1)),
                ban("203.0.113.7/32", Scope::Global, Some(1)), // duplicate
                ban("198.51.100.0/24", Scope::Group("web".into()), None),
            ])
            .unwrap();
        assert_eq!(out.iter().map(|d| d.seq).collect::<Vec<_>>(), vec![1, 2]);
        // longer ban for a known target is a new decision, shorter is not
        assert_eq!(
            c.append(vec![ban("203.0.113.7/32", Scope::Global, Some(2))])
                .unwrap()
                .len(),
            1
        );
        assert!(c
            .append(vec![ban(
                "198.51.100.0/24",
                Scope::Group("web".into()),
                Some(9)
            )])
            .unwrap()
            .is_empty());

        let Initial::Snapshot { seq, active } = c.subscribe(0, &db).unwrap().0 else {
            panic!("expected snapshot")
        };
        assert_eq!(seq, 3);
        assert_eq!(active.len(), 2, "group-scoped ban not sent to other groups");
        let Initial::Backlog { seq, decisions } = c.subscribe(1, &web).unwrap().0 else {
            panic!("expected backlog")
        };
        assert_eq!((seq, decisions.len()), (3, 2));

        // unban removes from the active set; state survives a reopen
        let revokes = out[0].id;
        c.append(vec![NewDecision {
            kind: DecisionKind::Unban { revokes },
            ..ban("203.0.113.7/32", Scope::Global, None)
        }])
        .unwrap();
        assert_eq!(c.active_decisions().len(), 2);
        drop(c);
        let c2 = Controller::open(
            Settings {
                state_dir: dir.clone(),
                cert_lifetime: Duration::from_secs(1),
                propagate: Propagate::Global,
                allowlist: Allowlist::default(),
                oidc: None,
                https_internal_ca: true,
            },
            Ca::generate("t").unwrap(),
            Store::open(&dir).unwrap(),
        )
        .unwrap();
        assert_eq!(c2.active_decisions().len(), 2);
        assert_eq!(
            c2.append(vec![ban("192.0.2.1/32", Scope::Global, Some(1))])
                .unwrap()[0]
                .seq,
            5
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn live_events_follow_the_initial_state() {
        let (c, dir) = ctl("live");
        let a = agent("web-1", "web");
        c.append(vec![ban("203.0.113.1/32", Scope::Global, Some(1))])
            .unwrap();
        let (Initial::Snapshot { seq, .. }, mut rx) = c.subscribe(0, &a).unwrap() else {
            panic!()
        };
        c.append(vec![ban("203.0.113.2/32", Scope::Global, Some(1))])
            .unwrap();
        let d = rx.recv().await.unwrap();
        assert_eq!(d.seq, seq + 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn allowlist_entries_persist() {
        let (c, dir) = ctl("allow");
        let net: IpNet = "192.0.2.0/24".parse().unwrap();
        let e = AllowEntry {
            net,
            comment: "partner".into(),
            created_by: "ada".into(),
            created_at: Utc::now(),
            expires_at: None,
        };
        c.add_allow(e.clone()).unwrap();
        assert!(matches!(c.add_allow(e), Err(AllowError::Exists(_))));
        assert!(c.allowlisted(&"192.0.2.7/32".parse().unwrap()));
        assert!(
            c.allowlisted(&"192.0.0.0/16".parse().unwrap()),
            "a ban containing it"
        );
        drop(c);
        let settings = Settings {
            state_dir: dir.clone(),
            cert_lifetime: Duration::from_secs(3600),
            propagate: Propagate::Global,
            allowlist: Allowlist::new(["10.0.0.0/8".parse().unwrap()]),
            oidc: None,
            https_internal_ca: true,
        };
        let c = Controller::open(
            settings,
            Ca::generate("t").unwrap(),
            Store::open(&dir).unwrap(),
        )
        .unwrap();
        assert!(
            c.allowlisted(&"192.0.2.7/32".parse().unwrap()),
            "after restart"
        );
        let list = c.allowlist();
        assert_eq!(
            list.iter()
                .map(|e| (e.net.to_string(), e.source))
                .collect::<Vec<_>>(),
            [
                ("10.0.0.0/8".to_string(), "command line"),
                ("192.0.2.0/24".to_string(), "api")
            ]
        );
        assert!(matches!(
            c.remove_allow(&"10.0.0.0/8".parse().unwrap()),
            Err(AllowError::Fixed(_))
        ));
        c.remove_allow(&net).unwrap();
        assert!(matches!(c.remove_allow(&net), Err(AllowError::Missing(_))));
        assert!(!c.allowlisted(&"192.0.2.7/32".parse().unwrap()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn group_change_forces_a_snapshot() {
        let (c, dir) = ctl("group");
        c.put_agent(agent("a1", "web")).unwrap();
        c.append(vec![
            ban("192.0.2.1/32", Scope::Group("web".into()), Some(1)),
            ban("192.0.2.2/32", Scope::Group("db".into()), Some(1)),
            ban("192.0.2.3/32", Scope::Global, Some(1)),
        ])
        .unwrap();
        let targets = |i: &Initial| match i {
            Initial::Snapshot { active, .. } => active
                .iter()
                .map(|d| d.target.to_string())
                .collect::<Vec<_>>(),
            Initial::Backlog { .. } => panic!("expected a snapshot"),
        };
        let rec = |c: &Controller| c.agents()[0].record.clone();
        let (i, _) = c.subscribe(0, &rec(&c)).unwrap();
        assert_eq!(targets(&i), ["192.0.2.1/32", "192.0.2.3/32"]);

        // up to date in "web"; moved to "db": snapshot although nothing is new
        assert_eq!(c.set_group("a1", "db").unwrap().as_deref(), Some("web"));
        assert!(rec(&c).resync);
        let (i, _) = c.subscribe(c.last_seq(), &rec(&c)).unwrap();
        assert_eq!(targets(&i), ["192.0.2.2/32", "192.0.2.3/32"]);
        assert!(!rec(&c).resync, "cleared once sent");
        let (i, _) = c.subscribe(c.last_seq(), &rec(&c)).unwrap();
        assert!(
            matches!(i, Initial::Backlog { .. }),
            "then resuming works normally"
        );

        // the same group again: no resync; unknown agent: None
        assert_eq!(c.set_group("a1", "db").unwrap().as_deref(), Some("db"));
        assert!(!rec(&c).resync);
        assert!(c.set_group("ghost", "db").unwrap().is_none());

        // the flag survives a restart (agent offline during the change)
        c.set_group("a1", "web").unwrap();
        drop(c);
        let settings = Settings {
            state_dir: dir.clone(),
            cert_lifetime: Duration::from_secs(3600),
            propagate: Propagate::Global,
            allowlist: Allowlist::default(),
            oidc: None,
            https_internal_ca: true,
        };
        let c = Controller::open(
            settings,
            Ca::generate("t").unwrap(),
            Store::open(&dir).unwrap(),
        )
        .unwrap();
        assert!(rec(&c).resync && rec(&c).group == "web");
        let (i, _) = c.subscribe(c.last_seq(), &rec(&c)).unwrap();
        assert_eq!(targets(&i), ["192.0.2.1/32", "192.0.2.3/32"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn temporary_allowlist_entries() {
        let (c, dir) = ctl("tempallow");
        let entry = |net: &str, mins: Option<i64>| AllowEntry {
            net: net.parse().unwrap(),
            comment: String::new(),
            created_by: "olga".into(),
            created_at: Utc::now(),
            expires_at: mins.map(|m| Utc::now() + chrono::Duration::minutes(m)),
        };
        let ip: IpNet = "192.0.2.7/32".parse().unwrap();
        let v0 = c.allowlist_version();
        assert_eq!(
            c.add_allow(entry("192.0.2.7/32", Some(60))).unwrap(),
            AllowAdded::Added
        );
        assert!(c.allowlisted(&ip));
        let v1 = c.allowlist_version();
        assert_ne!(v0, v1);
        // shorter: refused; longer: extends (new version)
        assert!(matches!(
            c.add_allow(entry("192.0.2.7/32", Some(30))),
            Err(AllowError::Exists(_))
        ));
        assert_eq!(
            c.add_allow(entry("192.0.2.7/32", Some(120))).unwrap(),
            AllowAdded::Extended
        );
        assert_ne!(c.allowlist_version(), v1, "expiry is part of the version");
        // permanent replaces temporary; temporary inside permanent is covered
        assert_eq!(
            c.add_allow(entry("192.0.2.7/32", None)).unwrap(),
            AllowAdded::Added
        );
        assert_eq!(c.allowlist().iter().filter(|e| e.net == ip).count(), 1);
        assert!(c.allowlist().iter().all(|e| e.expires_at.is_none()));
        c.add_allow(entry("198.51.100.0/24", None)).unwrap();
        assert!(matches!(
            c.add_allow(entry("198.51.100.9/32", Some(60))),
            Err(AllowError::Covered(..))
        ));
        // a temporary /24 does not block a permanent /32 inside it
        c.add_allow(entry("203.0.113.0/24", Some(60))).unwrap();
        c.add_allow(entry("203.0.113.5/32", None)).unwrap();

        // expiry: no longer effective at once, removed by housekeeping
        let short = AllowEntry {
            expires_at: Some(Utc::now() + chrono::Duration::milliseconds(50)),
            ..entry("192.0.2.200/32", None)
        };
        c.add_allow(short).unwrap();
        let before = c.allowlist_version();
        std::thread::sleep(Duration::from_millis(100));
        assert!(!c.allowlisted(&"192.0.2.200/32".parse().unwrap()));
        assert!(c
            .allowlist()
            .iter()
            .all(|e| e.net.to_string() != "192.0.2.200/32"));
        assert_eq!(c.prune_allowlist().unwrap(), 1);
        assert_ne!(c.allowlist_version(), before, "agents get the shorter list");
        assert_eq!(c.prune_allowlist().unwrap(), 0);
        let snap = c.allowlist_watch().borrow().clone();
        let temp: Vec<_> = snap
            .entries
            .iter()
            .filter(|(_, e)| e.is_some())
            .map(|(n, _)| n.to_string())
            .collect();
        assert_eq!(temp, ["203.0.113.0/24"]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn runtime_settings_persist() {
        let (c, dir) = ctl("runtime");
        assert_eq!(c.propagate(), Propagate::Global);
        assert_eq!(c.set_propagate(Propagate::Off).unwrap(), Propagate::Global);
        c.set_jail_override(crate::policy::JailOverride {
            jail: "sshd".into(),
            group: Some("web".into()),
            settings: crate::policy::JailSettings {
                maxretry: Some(3),
                ..Default::default()
            },
            updated_by: "ada".into(),
            updated_at: Utc::now(),
        })
        .unwrap();
        drop(c);
        let settings = Settings {
            state_dir: dir.clone(),
            cert_lifetime: Duration::from_secs(3600),
            propagate: Propagate::Global, // default from the command line
            allowlist: Allowlist::default(),
            oidc: None,
            https_internal_ca: true,
        };
        let c = Controller::open(
            settings,
            Ca::generate("t").unwrap(),
            Store::open(&dir).unwrap(),
        )
        .unwrap();
        assert_eq!(
            c.propagate(),
            Propagate::Off,
            "the stored setting wins over the default"
        );
        assert_eq!(c.jail_overrides().len(), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn correlation_offenses_for_escalation() {
        let (c, dir) = ctl("offenses");
        let t: IpNet = "203.0.113.5/32".parse().unwrap();
        let mk = |origin: Origin, expires: chrono::Duration| NewDecision {
            kind: DecisionKind::Ban,
            target: t,
            scope: Scope::Global,
            jail: Some("sshd".into()),
            expires_at: Some(Utc::now() + expires),
            origin,
            reason: String::new(),
        };
        // an earlier correlation ban that already ended, and other origins
        c.append(vec![mk(
            Origin::Correlation("r".into()),
            chrono::Duration::seconds(-60),
        )])
        .unwrap();
        c.append(vec![mk(
            Origin::Agent(df2b_core::AgentId("a".into())),
            chrono::Duration::hours(1),
        )])
        .unwrap();
        c.append(vec![mk(
            Origin::User("ada".into()),
            chrono::Duration::hours(2),
        )])
        .unwrap();
        assert_eq!(
            c.correlation_offenses(&t),
            1,
            "only correlation bans count, ended ones too"
        );
        assert_eq!(
            c.correlation_offenses(&"203.0.113.6/32".parse().unwrap()),
            0
        );

        // a second one, lifted by a person: forgiven
        let d = c
            .append(vec![mk(
                Origin::Correlation("other".into()),
                chrono::Duration::hours(3),
            )])
            .unwrap();
        assert_eq!(c.correlation_offenses(&t), 2);
        let id = d[0].id;
        c.append(vec![NewDecision {
            kind: DecisionKind::Unban { revokes: id },
            target: t,
            scope: Scope::Global,
            jail: None,
            expires_at: None,
            origin: Origin::User("ada".into()),
            reason: "false positive".into(),
        }])
        .unwrap();
        assert_eq!(c.correlation_offenses(&t), 1);
        // an unban by a rule (e.g. allowlist expiry) would not forgive; and
        // the count survives a restart (rebuilt from the log)
        drop(c);
        let settings = Settings {
            state_dir: dir.clone(),
            cert_lifetime: Duration::from_secs(3600),
            propagate: Propagate::Global,
            allowlist: Allowlist::default(),
            oidc: None,
            https_internal_ca: true,
        };
        let c = Controller::open(
            settings,
            Ca::generate("t").unwrap(),
            Store::open(&dir).unwrap(),
        )
        .unwrap();
        assert_eq!(c.correlation_offenses(&t), 1);
        let _ = std::fs::remove_dir_all(&dir);
    }
    #[test]
    fn observations_survive_a_restart() {
        use crate::correlation::{tests::rule, RuleKind, Seen};
        let (c, dir) = ctl("observations");
        let key: IpNet = "198.51.100.9/32".parse().unwrap();
        let now = Utc::now();
        let mut monitor = rule(RuleKind::Threshold, 2, 4);
        monitor.monitor = true;
        {
            let mut k = c.correlator.lock().unwrap();
            for a in ["a1", "a2"] {
                k.record(
                    "sshd",
                    key,
                    Seen {
                        agent: a.into(),
                        group: "web".into(),
                        at: now,
                        failures: 2,
                        banned: false,
                        sample: None,
                    },
                );
            }
            assert_eq!(
                k.evaluate(&[monitor.clone()], "sshd", key, "web", now)
                    .len(),
                1
            );
        }
        c.flush_observations();
        c.flush_observations(); // nothing new: no write
        let reopen = |dir: &PathBuf| {
            let settings = Settings {
                state_dir: dir.clone(),
                cert_lifetime: Duration::from_secs(3600),
                propagate: Propagate::Global,
                allowlist: Allowlist::default(),
                oidc: None,
                https_internal_ca: true,
            };
            Controller::open(
                settings,
                Ca::generate("t").unwrap(),
                Store::open(dir).unwrap(),
            )
            .unwrap()
        };
        drop(c);
        let c = reopen(&dir);
        {
            let mut k = c.correlator.lock().unwrap();
            assert_eq!(k.recent(&key).len(), 2, "observations restored");
            assert_eq!(k.hits().len(), 1, "monitor hits restored");
            assert!(
                k.evaluate(&[monitor], "sshd", key, "web", now).is_empty(),
                "no second firing after the restart"
            );
        }
        // pruned from the database once older than the longest window
        assert_eq!(
            c.store
                .prune_observations(now - chrono::Duration::minutes(1))
                .unwrap(),
            0
        );
        assert_eq!(
            c.store
                .prune_observations(Utc::now() + chrono::Duration::seconds(1))
                .unwrap(),
            2
        );
        drop(c);
        let c = reopen(&dir);
        assert_eq!(c.correlator.lock().unwrap().tracked(), 0);
        let _ = std::fs::remove_dir_all(&dir);
    }
}

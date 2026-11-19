//! Controller state: enrolled agents, runtime status and the decision log.
//!
//! Appending to the log takes the state lock, writes the new decisions to
//! redb (one transaction), and only then publishes them to subscribers, so a
//! subscriber never sees a decision that is not durable. Subscribing takes
//! the same lock to obtain "broadcast receiver + current sequence number"
//! atomically, so no decision falls between the initial snapshot/backlog and
//! the live stream.

use std::collections::HashMap;
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
use crate::store::{AgentRecord, Store};

/// A resuming subscriber further behind than this gets a snapshot instead.
const MAX_BACKLOG: u64 = 10_000;

/// What happens to an agent's local ban (DESIGN.md §4.2 `propagate_local`).
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize)]
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
    pub propagate: Propagate,
    pub allowlist: Allowlist,
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
}

pub struct Controller {
    pub settings: Settings,
    pub ca: Ca,
    store: Store,
    inner: Mutex<Inner>,
    events: broadcast::Sender<Arc<Decision>>,
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
        })?;
        for a in store.agents()? {
            inner.agents.insert(a.id.clone(), a);
        }
        tracing::info!(
            agents = inner.agents.len(),
            active_decisions = inner.active.len(),
            last_seq = inner.last_seq,
            "controller state loaded"
        );
        Ok(Self {
            settings,
            ca,
            store,
            inner: Mutex::new(inner),
            events: broadcast::channel(4096).0,
        })
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
            let inner = self.lock();
            let rx = self.events.subscribe();
            let last = inner.last_seq;
            let need_snapshot = from_seq == 0 || from_seq > last || last - from_seq > MAX_BACKLOG;
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

    pub fn update_status(&self, id: &str, f: impl FnOnce(&mut AgentStatus)) {
        let mut inner = self.lock();
        let s = inner.status.entry(id.to_owned()).or_default();
        s.last_seen = Some(Utc::now());
        f(s);
    }

    /// Drops expired bans from the active set.
    pub fn prune(&self) {
        let now = Utc::now();
        self.lock().active.retain(|_, d| d.is_active(now));
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
}

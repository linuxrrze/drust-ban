//! Turns log lines into ban actions: jail routing → filter → allowlist →
//! tracker → escalated ban time.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, TimeDelta, Utc};
use df2b_core::{escalated_bantime, Allowlist, IpKey, PrefixPolicy};
use df2b_matcher::{Filter, FilterDef};
use df2b_sources::LogLine;
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use tracing::{debug, warn};

use crate::config::{AgentConfig, JailConfig};
use crate::tracker::Tracker;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanAction {
    pub jail: String,
    pub key: IpKey,
    pub duration: Duration,
    /// 1 for the first ban of this key in this jail.
    pub offense: u32,
    pub until: DateTime<Utc>,
    /// Failures that triggered the ban (the jail's maxretry).
    pub failures: u32,
    /// The line that triggered the ban.
    pub sample: String,
}

impl BanAction {
    pub fn record(&self) -> OffenderRecord {
        OffenderRecord {
            jail: self.jail.clone(),
            key: self.key,
            offenses: self.offense,
            banned_until: self.until,
        }
    }
}

/// Persisted per (jail, key): drives ban escalation and restores active bans.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OffenderRecord {
    pub jail: String,
    pub key: IpKey,
    pub offenses: u32,
    pub banned_until: DateTime<Utc>,
}

#[derive(Debug, Clone, Copy)]
struct Offender {
    offenses: u32,
    banned_until: DateTime<Utc>,
}

/// The tunable settings of a jail.
#[derive(Debug, Clone, PartialEq)]
pub struct JailParams {
    pub enabled: bool,
    pub maxretry: u32,
    pub findtime: Duration,
    pub bantime: Duration,
    pub factor: f64,
    pub max_bantime: Option<Duration>,
}

/// Central overrides for one jail (from the controller); `None` keeps the
/// configured value.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct JailOverride {
    pub jail: String,
    pub enabled: Option<bool>,
    pub maxretry: Option<u32>,
    #[serde(with = "humantime_serde")]
    pub findtime: Option<Duration>,
    #[serde(with = "humantime_serde")]
    pub bantime: Option<Duration>,
    pub factor: Option<f64>,
    #[serde(with = "humantime_serde")]
    pub max_bantime: Option<Duration>,
}

impl JailParams {
    fn with(&self, o: Option<&JailOverride>) -> (Self, Vec<&'static str>) {
        let mut p = self.clone();
        let mut changed = Vec::new();
        let Some(o) = o else { return (p, changed) };
        macro_rules! set {
            ($field:ident, $src:ident, $name:literal) => {
                if let Some(v) = o.$src {
                    p.$field = v;
                    changed.push($name);
                }
            };
        }
        set!(enabled, enabled, "enabled");
        set!(maxretry, maxretry, "maxretry");
        set!(findtime, findtime, "findtime");
        set!(bantime, bantime, "bantime");
        set!(factor, factor, "bantime_factor");
        if let Some(m) = o.max_bantime {
            p.max_bantime = Some(m);
            changed.push("max_bantime");
        }
        (p, changed)
    }
}

/// Failures of one key in one jail during a report interval.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Observed {
    pub failures: u32,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
    /// The latest matching line (if samples are sent).
    pub sample: Option<String>,
}

/// Keys per report interval (memory bound).
const MAX_OBSERVED: usize = 50_000;

/// Longest window and ban the agent accepts from the controller (the
/// controller enforces the same; a huge value would overflow the date
/// arithmetic and crash the agent).
pub const MAX_FINDTIME: Duration = Duration::from_secs(7 * 86400);
pub const MAX_BANTIME: Duration = Duration::from_secs(10 * 365 * 86400);

/// What a configuration reload ended.
#[derive(Debug, Default, PartialEq)]
pub struct Reloaded {
    /// Prefixes whose active bans belonged to removed jails.
    pub ended: Vec<IpNet>,
    /// Offender records of removed jails.
    pub forgotten: Vec<(String, IpKey)>,
}

/// Status of a jail for heartbeats.
#[derive(Debug, Clone, PartialEq)]
pub struct JailStatus {
    pub name: String,
    pub filter: String,
    pub params: JailParams,
    pub overridden: Vec<&'static str>,
    pub active_bans: usize,
    pub origin: &'static str,
    /// why a central jail does not run (then `params` are zero)
    pub error: String,
    /// Keys with counted failures now.
    pub tracked: usize,
    /// Keys forgotten because the tracker was full (since start).
    pub evicted: u64,
}

#[derive(Debug)]
struct Jail {
    name: String,
    filter_name: String,
    sources: Vec<String>,
    filter: Filter,
    /// From the configuration (or the central definition); central
    /// overrides apply on top.
    base: JailParams,
    /// Defined by the controller.
    central: bool,
    enabled: bool,
    overridden: Vec<&'static str>,
    tracker: Tracker,
    bantime: Duration,
    factor: f64,
    max_bantime: Option<Duration>,
    /// Keys this jail has banned: offense count and ban expiry. Failures of a
    /// key that is still banned are not counted, so one burst (e.g. catching
    /// up on a log file) cannot produce repeated bans and inflate the count.
    /// Entries are forgotten `offense_memory` after their ban expired; an
    /// unban decision ends the ban but keeps the offense count.
    offenders: HashMap<IpKey, Offender>,
    maxretry: u32,
    findtime: Duration,
}

#[derive(Debug)]
pub struct Engine {
    jails: Vec<Jail>,
    /// Filters not shipped by the controller are read from here.
    filter_dir: std::path::PathBuf,
    /// Central jails that do not run: (jail, filter, reason).
    central_errors: Vec<(String, String, String)>,
    /// Failures per (jail, key) since the last `take_observations`, for
    /// the controller's correlation (only with a controller).
    observations: Option<HashMap<(String, IpKey), Observed>>,
    /// Keep the latest matching line per observation.
    samples: bool,
    /// `[[redact]]` rules for those lines.
    local_redactor: df2b_core::Redactor,
    /// Those, then the controller's.
    redactor: df2b_core::Redactor,
    /// From the agent's configuration.
    allowlist: Allowlist,
    /// The controller's allowlist (replaced on every update).
    central: Allowlist,
    prefix: PrefixPolicy,
    offense_memory: TimeDelta,
}

/// Local (configuration) or central (controller) allowlist.
fn allowed(local: &Allowlist, central: &Allowlist, ip: &std::net::IpAddr, net: &IpNet) -> bool {
    // loopback, link-local, multicast...: banning them only hurts the host
    df2b_core::reserved(net)
        || [local, central]
            .iter()
            .any(|a| a.contains_addr(ip) || a.overlaps(net))
}

impl Engine {
    /// The configured jails with their filters read and compiled.
    fn local_jails(cfg: &AgentConfig) -> anyhow::Result<Vec<Jail>> {
        cfg.jail
            .iter()
            .map(|j| {
                let path = cfg.agent.filter_dir.join(format!("{}.toml", j.filter));
                let text = std::fs::read_to_string(&path).with_context(|| {
                    format!("jail '{}': reading filter {}", j.name, path.display())
                })?;
                let def = FilterDef::from_toml(&text)
                    .with_context(|| format!("jail '{}': parsing {}", j.name, path.display()))?;
                let filter = Filter::compile(&j.filter, &def).with_context(|| {
                    format!("jail '{}': compiling filter '{}'", j.name, j.filter)
                })?;
                Ok(Jail::new(j, filter))
            })
            .collect()
    }

    /// Applies a changed configuration (reload): local jails are rebuilt
    /// with their filters read again, keeping the offense history and
    /// counted failures of jails that stay; allowlist, redaction rules and
    /// `offense_memory` are replaced. Central jails are left alone (the
    /// caller applies them again). Nothing changes if a filter fails.
    /// The prefix policy is not changed (that needs a restart).
    pub fn reload_local(
        &mut self,
        cfg: &AgentConfig,
        now: DateTime<Utc>,
    ) -> anyhow::Result<Reloaded> {
        let mut fresh = Self::local_jails(cfg)?;
        let local_redactor =
            df2b_core::Redactor::new(&cfg.redact).map_err(|e| anyhow::anyhow!("redact: {e}"))?;
        let (mut old, central): (Vec<Jail>, Vec<Jail>) = std::mem::take(&mut self.jails)
            .into_iter()
            .partition(|j| !j.central);
        for j in &mut fresh {
            let Some(i) = old.iter().position(|o| o.name == j.name) else {
                continue;
            };
            let prev = old.swap_remove(i);
            j.offenders = prev.offenders;
            j.tracker = prev.tracker;
            j.tracker.set_limits(j.maxretry, j.findtime);
            if let Some(c) = cfg.jail.iter().find(|c| c.name == j.name) {
                j.tracker.set_max_keys(c.max_tracked);
            }
        }
        // jails gone: their bans end, their history is forgotten
        let mut out = Reloaded::default();
        for j in old {
            for (key, o) in j.offenders {
                if o.banned_until > now {
                    out.ended.push(key.net());
                }
                out.forgotten.push((j.name.clone(), key));
            }
        }
        self.jails = fresh;
        self.jails.extend(central);
        self.filter_dir = cfg.agent.filter_dir.clone();
        self.local_redactor = local_redactor;
        self.redactor = self.local_redactor.clone();
        self.allowlist = Allowlist::new(cfg.agent.allowlist.iter().copied());
        self.offense_memory =
            TimeDelta::from_std(cfg.agent.offense_memory).unwrap_or(TimeDelta::MAX);
        Ok(out)
    }

    pub fn from_config(cfg: &AgentConfig) -> anyhow::Result<Self> {
        let jails = Self::local_jails(cfg)?;
        let local_redactor =
            df2b_core::Redactor::new(&cfg.redact).map_err(|e| anyhow::anyhow!("redact: {e}"))?;
        Ok(Self {
            jails,
            filter_dir: cfg.agent.filter_dir.clone(),
            central_errors: Vec::new(),
            observations: None,
            samples: false,
            redactor: local_redactor.clone(),
            local_redactor,
            allowlist: Allowlist::new(cfg.agent.allowlist.iter().copied()),
            central: Allowlist::default(),
            prefix: PrefixPolicy {
                v4: cfg.agent.ipv4_prefix,
                v6: cfg.agent.ipv6_prefix,
            },
            offense_memory: TimeDelta::from_std(cfg.agent.offense_memory).unwrap_or(TimeDelta::MAX),
        })
    }

    /// Restores persisted offenders. Returns the bans that are still active,
    /// with their remaining time, so the caller can re-apply them to the
    /// firewall. Records of unknown jails and forgotten offenders are skipped.
    pub fn restore(
        &mut self,
        records: impl IntoIterator<Item = OffenderRecord>,
        now: DateTime<Utc>,
    ) -> Vec<(IpKey, Duration)> {
        let forget_before = now.checked_sub_signed(self.offense_memory);
        let mut active = Vec::new();
        for r in records {
            let Some(jail) = self.jails.iter_mut().find(|j| j.name == r.jail) else {
                warn!(jail = %r.jail, key = %r.key, "saved offender for unknown jail, ignoring");
                continue;
            };
            if forget_before.is_some_and(|t| r.banned_until < t) {
                continue;
            }
            jail.offenders.insert(
                r.key,
                Offender {
                    offenses: r.offenses,
                    banned_until: r.banned_until,
                },
            );
            if r.banned_until > now {
                let remaining = (r.banned_until - now).to_std().unwrap_or(Duration::MAX);
                active.push((r.key, remaining));
            }
        }
        active
    }

    pub fn jail_count(&self) -> usize {
        self.jails.len()
    }

    pub fn process(&mut self, line: &LogLine, now: DateTime<Utc>) -> Vec<BanAction> {
        let ts = line.ts.unwrap_or(now);
        let mut actions = Vec::new();
        for jail in &mut self.jails {
            if !jail.enabled || !jail.sources.iter().any(|s| s.as_str() == &*line.source) {
                continue;
            }
            let Some(m) = jail.filter.match_line(&line.line) else {
                continue;
            };
            let key = IpKey::from_addr(m.ip, self.prefix);
            if jail
                .offenders
                .get(&key)
                .is_some_and(|o| o.banned_until > now)
            {
                continue;
            }
            if allowed(&self.allowlist, &self.central, &m.ip, &key.net()) {
                debug!(ip = %m.ip, jail = %jail.name, "allowlisted, ignoring");
                continue;
            }
            if let Some(obs) = self.observations.as_mut() {
                let k = (jail.name.clone(), key);
                let sample = self
                    .samples
                    .then(|| df2b_core::sample_line(&self.redactor.apply(&line.line)));
                if let Some(o) = obs.get_mut(&k) {
                    o.failures = o.failures.saturating_add(1);
                    o.first = o.first.min(ts);
                    if ts >= o.last && sample.is_some() {
                        o.sample = sample;
                    }
                    o.last = o.last.max(ts);
                } else if obs.len() < MAX_OBSERVED {
                    obs.insert(
                        k,
                        Observed {
                            failures: 1,
                            first: ts,
                            last: ts,
                            sample,
                        },
                    );
                }
            }
            if !jail.tracker.record(key, ts, now) {
                continue;
            }
            let offense = jail.offenders.get(&key).map_or(0, |o| o.offenses) + 1;
            let duration = escalated_bantime(jail.bantime, jail.factor, jail.max_bantime, offense);
            let until = TimeDelta::from_std(duration)
                .ok()
                .and_then(|d| now.checked_add_signed(d))
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
            jail.offenders.insert(
                key,
                Offender {
                    offenses: offense,
                    banned_until: until,
                },
            );
            actions.push(BanAction {
                jail: jail.name.clone(),
                key,
                duration,
                offense,
                until,
                failures: jail.maxretry,
                sample: line.line.clone(),
            });
        }
        actions
    }

    /// True if any jail currently bans exactly `net`.
    pub fn is_banned(&self, net: &IpNet, now: DateTime<Utc>) -> bool {
        self.jails.iter().any(|j| {
            j.offenders
                .iter()
                .any(|(k, o)| k.net() == *net && o.banned_until > now)
        })
    }

    /// Active bans: (jail, key, offense count, until), by jail and key.
    pub fn bans(&self, now: DateTime<Utc>) -> Vec<(String, IpKey, u32, DateTime<Utc>)> {
        let mut out: Vec<_> = self
            .jails
            .iter()
            .flat_map(|j| {
                j.offenders
                    .iter()
                    .filter(|(_, o)| o.banned_until > now)
                    .map(|(k, o)| (j.name.clone(), *k, o.offenses, o.banned_until))
            })
            .collect();
        out.sort_by(|a, b| (&a.0, a.1.to_string()).cmp(&(&b.0, b.1.to_string())));
        out
    }

    /// Whether a ban from the controller must not be applied here: it
    /// overlaps this agent's allowlist (configured or central) or is wider
    /// than /8 (IPv4) or /16 (IPv6). The agent's own allowlist wins over
    /// the controller (management networks; a broken or compromised
    /// controller must not lock the host out).
    pub fn refuses_remote(&self, net: &IpNet) -> bool {
        let too_broad = match net {
            IpNet::V4(n) => n.prefix_len() < 8,
            IpNet::V6(n) => n.prefix_len() < 16,
        };
        too_broad || df2b_core::reserved(net) || self.allowlisted(net)
    }

    /// Whether `net` overlaps the configured or the central allowlist.
    pub fn allowlisted(&self, net: &IpNet) -> bool {
        self.allowlist.overlaps(net) || self.central.overlaps(net)
    }

    /// Number of (jail, key) bans currently active.
    /// Applies the controller's jail settings (replacing earlier ones;
    /// jails without an entry go back to their configuration). Overrides
    /// for jails this agent does not have are ignored. Counted failures
    /// and offense history are kept; a disabled jail stops counting and
    /// banning, its active bans run out.
    pub fn apply_jail_overrides(&mut self, overrides: &[JailOverride]) {
        for j in &mut self.jails {
            let o = overrides.iter().find(|o| o.jail == j.name);
            let (p, changed) = j.base.with(o);
            let current = JailParams {
                enabled: j.enabled,
                maxretry: j.maxretry,
                findtime: j.tracker_findtime(),
                bantime: j.bantime,
                factor: j.factor,
                max_bantime: j.max_bantime,
            };
            if p != current {
                tracing::info!(
                    jail = %j.name,
                    enabled = p.enabled,
                    maxretry = p.maxretry,
                    findtime = ?p.findtime,
                    bantime = ?p.bantime,
                    factor = p.factor,
                    max_bantime = ?p.max_bantime,
                    "jail settings changed by the controller"
                );
            }
            j.enabled = p.enabled;
            j.maxretry = p.maxretry;
            j.tracker.set_limits(p.maxretry, p.findtime);
            j.findtime = p.findtime;
            j.bantime = p.bantime;
            j.factor = p.factor;
            j.max_bantime = p.max_bantime;
            j.overridden = changed;
        }
    }

    /// The controller's redaction rules (applied after the local ones).
    pub fn set_central_redaction(&mut self, central: &df2b_core::Redactor) {
        self.redactor = self.local_redactor.then(central);
    }

    /// A log line as sent to the controller: redacted, cleaned, cut.
    pub fn sample(&self, line: &str) -> String {
        df2b_core::sample_line(&self.redactor.apply(line))
    }

    /// Starts counting failures for the controller; with `samples`, the
    /// latest matching line is kept as well.
    pub fn collect_observations(&mut self, samples: bool) {
        self.observations.get_or_insert_with(HashMap::new);
        self.samples = samples;
    }

    /// Failures counted since the last call.
    pub fn take_observations(&mut self) -> Vec<(String, IpKey, Observed)> {
        match self.observations.as_mut() {
            Some(o) => o.drain().map(|((j, k), v)| (j, k, v)).collect(),
            None => Vec::new(),
        }
    }

    /// Replaces the central jails. `accepted` passed the agent's checks
    /// (paths, journald); `rejected` did not, with the reason. A central
    /// jail with the name of a local one is refused. Filters come from
    /// `filters` (central) or the filter directory. A jail redefined under
    /// the same name keeps its counters and offense history. Returns the
    /// names of the central jails that now run. Call
    /// `apply_jail_overrides` afterwards.
    pub fn set_central_jails(
        &mut self,
        accepted: &[crate::central::CentralJail],
        filters: &[(String, String)],
        rejected: Vec<(String, String, String)>,
    ) -> Vec<String> {
        let mut old: HashMap<String, Jail> = HashMap::new();
        let mut kept = Vec::new();
        for j in std::mem::take(&mut self.jails) {
            if j.central {
                old.insert(j.name.clone(), j);
            } else {
                kept.push(j);
            }
        }
        self.jails = kept;
        // a name clash is the more fundamental reason
        let clash = "a local jail with this name exists (local jails win)";
        let mut errors: Vec<_> = rejected
            .into_iter()
            .map(|(name, filter, reason)| {
                if self.jails.iter().any(|j| j.name == name) {
                    (name, filter, clash.to_owned())
                } else {
                    (name, filter, reason)
                }
            })
            .collect();
        let mut running = Vec::new();
        for def in accepted {
            if self.jails.iter().any(|j| j.name == def.name) {
                errors.push((def.name.clone(), def.filter.clone(), clash.into()));
                continue;
            }
            let filter = match self.load_filter(&def.filter, filters) {
                Ok(f) => f,
                Err(e) => {
                    errors.push((def.name.clone(), def.filter.clone(), format!("{e:#}")));
                    continue;
                }
            };
            let cfg = JailConfig {
                name: def.name.clone(),
                sources: def.source_names(),
                filter: def.filter.clone(),
                maxretry: def.maxretry,
                findtime: def.findtime,
                bantime: def.bantime,
                bantime_factor: def.factor,
                max_bantime: def.max_bantime,
                max_tracked: crate::config::default_max_tracked(),
            };
            let mut jail = Jail::new(&cfg, filter);
            jail.central = true;
            jail.base.enabled = def.enabled;
            jail.enabled = def.enabled;
            if let Some(prev) = old.remove(&def.name) {
                jail.offenders = prev.offenders;
                jail.tracker = prev.tracker;
                jail.tracker.set_limits(def.maxretry, def.findtime);
            }
            running.push(def.name.clone());
            self.jails.push(jail);
        }
        for e in &errors {
            warn!(jail = %e.0, reason = %e.2, "central jail not started");
        }
        self.central_errors = errors;
        running
    }

    fn load_filter(&self, name: &str, central: &[(String, String)]) -> anyhow::Result<Filter> {
        let (text, what) = match central.iter().find(|(n, _)| n == name) {
            Some((_, toml)) => (toml.clone(), "central filter".to_owned()),
            None => {
                let path = self.filter_dir.join(format!("{name}.toml"));
                let text = std::fs::read_to_string(&path).with_context(|| {
                    format!(
                        "filter {name:?} is neither central nor in {}",
                        path.display()
                    )
                })?;
                (text, path.display().to_string())
            }
        };
        let def = FilterDef::from_toml(&text).with_context(|| format!("parsing {what}"))?;
        Filter::compile(name, &def).with_context(|| format!("compiling {what}"))
    }

    /// Effective settings per jail (heartbeats).
    pub fn jail_status(&self, now: DateTime<Utc>) -> Vec<JailStatus> {
        let failed = self
            .central_errors
            .iter()
            .map(|(name, filter, error)| JailStatus {
                name: name.clone(),
                filter: filter.clone(),
                params: JailParams {
                    enabled: false,
                    maxretry: 0,
                    findtime: Duration::ZERO,
                    bantime: Duration::ZERO,
                    factor: 1.0,
                    max_bantime: None,
                },
                overridden: Vec::new(),
                active_bans: 0,
                origin: "central",
                error: error.clone(),
                tracked: 0,
                evicted: 0,
            });
        self.jails
            .iter()
            .map(|j| JailStatus {
                name: j.name.clone(),
                filter: j.filter_name.clone(),
                params: JailParams {
                    enabled: j.enabled,
                    maxretry: j.maxretry,
                    findtime: j.tracker_findtime(),
                    bantime: j.bantime,
                    factor: j.factor,
                    max_bantime: j.max_bantime,
                },
                overridden: j.overridden.clone(),
                active_bans: j
                    .offenders
                    .values()
                    .filter(|o| o.banned_until > now)
                    .count(),
                origin: if j.central { "central" } else { "local" },
                error: String::new(),
                tracked: j.tracker.len(),
                evicted: j.tracker.evicted(),
            })
            .chain(failed)
            .collect()
    }

    pub fn active_bans(&self, now: DateTime<Utc>) -> usize {
        self.jails
            .iter()
            .map(|j| {
                j.offenders
                    .values()
                    .filter(|o| o.banned_until > now)
                    .count()
            })
            .sum()
    }

    /// Ends local bans of keys inside `net` (an unban decision): failures are
    /// counted again from now on, the offense history is kept. Returns the
    /// changed records for the state store.
    /// Replaces the controller's allowlist.
    pub fn set_central_allowlist(&mut self, nets: impl IntoIterator<Item = IpNet>) {
        self.central = Allowlist::new(nets);
    }

    /// Lifts active bans that overlap the controller's or the configured
    /// allowlist (a /64 ban containing an allowlisted address included).
    /// Offense history is kept.
    pub fn lift_allowlisted(&mut self, now: DateTime<Utc>) -> Vec<OffenderRecord> {
        let mut changed = Vec::new();
        for j in &mut self.jails {
            for (key, o) in j.offenders.iter_mut() {
                let net = key.net();
                if o.banned_until > now
                    && (self.central.overlaps(&net) || self.allowlist.overlaps(&net))
                {
                    o.banned_until = now;
                    j.tracker.reset(key);
                    changed.push(OffenderRecord {
                        jail: j.name.clone(),
                        key: *key,
                        offenses: o.offenses,
                        banned_until: now,
                    });
                }
            }
        }
        changed
    }

    pub fn lift(&mut self, net: &IpNet, now: DateTime<Utc>) -> Vec<OffenderRecord> {
        let mut changed = Vec::new();
        for j in &mut self.jails {
            for (key, o) in j.offenders.iter_mut() {
                if o.banned_until > now && net.contains(&key.net()) {
                    o.banned_until = now;
                    j.tracker.reset(key);
                    changed.push(OffenderRecord {
                        jail: j.name.clone(),
                        key: *key,
                        offenses: o.offenses,
                        banned_until: now,
                    });
                }
            }
        }
        changed
    }

    /// Drops expired tracker entries and forgotten offenders. Returns the
    /// forgotten (jail, key) pairs so they can be removed from the state store.
    pub fn prune(&mut self, now: DateTime<Utc>) -> Vec<(String, IpKey)> {
        let forget_before = now.checked_sub_signed(self.offense_memory);
        let mut forgotten = Vec::new();
        for j in &mut self.jails {
            j.tracker.prune(now);
            if let Some(t) = forget_before {
                j.offenders.retain(|key, o| {
                    let keep = o.banned_until >= t;
                    if !keep {
                        forgotten.push((j.name.clone(), *key));
                    }
                    keep
                });
            }
        }
        forgotten
    }
}

impl Jail {
    fn new(cfg: &JailConfig, filter: Filter) -> Self {
        Self {
            name: cfg.name.clone(),
            filter_name: cfg.filter.clone(),
            base: JailParams {
                enabled: true,
                maxretry: cfg.maxretry,
                findtime: cfg.findtime,
                bantime: cfg.bantime,
                factor: cfg.bantime_factor,
                max_bantime: cfg.max_bantime,
            },
            enabled: true,
            central: false,
            overridden: Vec::new(),
            sources: cfg.sources.clone(),
            filter,
            tracker: Tracker::new(cfg.maxretry, cfg.findtime, cfg.max_tracked),
            bantime: cfg.bantime,
            factor: cfg.bantime_factor,
            max_bantime: cfg.max_bantime,
            offenders: HashMap::new(),
            maxretry: cfg.maxretry,
            findtime: cfg.findtime,
        }
    }

    fn tracker_findtime(&self) -> Duration {
        self.findtime
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    fn engine() -> Engine {
        let mut cfg: AgentConfig = toml::from_str(
            r#"
            [agent]
            allowlist = ["10.0.0.0/8"]
            [[source]]
            name = "auth"
            type = "file"
            paths = ["/dev/null"]
            [[jail]]
            name = "sshd"
            sources = ["auth"]
            filter = "sshd"
            maxretry = 2
            findtime = "10m"
            bantime = "1h"
            bantime_factor = 2.0
            "#,
        )
        .unwrap();
        cfg.agent.filter_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../filters").into();
        Engine::from_config(&cfg).unwrap()
    }

    fn line(source: &str, ip: &str) -> LogLine {
        LogLine {
            source: Arc::from(source),
            ts: None,
            line: format!("Failed password for root from {ip} port 22 ssh2"),
        }
    }

    #[test]
    fn bans_after_maxretry_and_escalates() {
        let mut e = engine();
        let now = Utc::now();
        assert!(e.process(&line("auth", "203.0.113.7"), now).is_empty());
        let a = e.process(&line("auth", "203.0.113.7"), now);
        assert_eq!(a.len(), 1);
        assert_eq!(a[0].key.to_string(), "203.0.113.7/32");
        assert_eq!(a[0].duration, Duration::from_secs(3600));

        // after the first ban expires, a new burst escalates
        let later = now + TimeDelta::hours(2);
        e.process(&line("auth", "203.0.113.7"), later);
        let a = e.process(&line("auth", "203.0.113.7"), later);
        assert_eq!(a[0].offense, 2);
        assert_eq!(a[0].duration, Duration::from_secs(7200));
    }

    #[test]
    fn no_rebans_while_banned() {
        let mut e = engine();
        let now = Utc::now();
        let actions: Vec<_> = (0..6)
            .flat_map(|_| e.process(&line("auth", "203.0.113.7"), now))
            .collect();
        assert_eq!(actions.len(), 1, "one burst must yield exactly one ban");
        assert_eq!(actions[0].offense, 1);

        // still banned just before expiry, counting resumes after it
        let almost = now + TimeDelta::minutes(59);
        assert!(e.process(&line("auth", "203.0.113.7"), almost).is_empty());
        assert!(e.process(&line("auth", "203.0.113.7"), almost).is_empty());
        let after = now + TimeDelta::minutes(61);
        assert!(e.prune(after).is_empty(), "offense history is kept");
        e.process(&line("auth", "203.0.113.7"), after);
        let a = e.process(&line("auth", "203.0.113.7"), after);
        assert_eq!(a[0].offense, 2, "counting resumes after expiry");
    }

    #[test]
    fn offense_history_is_forgotten_after_offense_memory() {
        let mut e = engine();
        let now = Utc::now();
        e.process(&line("auth", "203.0.113.7"), now);
        e.process(&line("auth", "203.0.113.7"), now);
        // ban (1h) expired + default offense_memory (30d) passed
        let later = now + TimeDelta::days(31);
        let forgotten = e.prune(later);
        assert_eq!(forgotten.len(), 1);
        assert_eq!(forgotten[0].0, "sshd");
        e.process(&line("auth", "203.0.113.7"), later);
        let a = e.process(&line("auth", "203.0.113.7"), later);
        assert_eq!(a[0].offense, 1, "escalation starts over");
    }

    #[test]
    fn restore_reapplies_active_bans_and_continues_escalation() {
        let now = Utc::now();
        let mut first = engine();
        first.process(&line("auth", "203.0.113.7"), now);
        let rec = first.process(&line("auth", "203.0.113.7"), now)[0].record();
        let expired = OffenderRecord {
            key: IpKey::from_addr("198.51.100.1".parse().unwrap(), PrefixPolicy::default()),
            banned_until: now - TimeDelta::minutes(5),
            ..rec.clone()
        };
        let unknown = OffenderRecord {
            jail: "gone".into(),
            ..rec.clone()
        };

        // "restart" 10 minutes later
        let later = now + TimeDelta::minutes(10);
        let mut e = engine();
        let active = e.restore([rec, expired, unknown], later);
        assert_eq!(active.len(), 1, "only the still-active ban is re-applied");
        assert_eq!(active[0].0.to_string(), "203.0.113.7/32");
        assert_eq!(active[0].1, Duration::from_secs(50 * 60));

        // still banned: no new ban
        for _ in 0..3 {
            assert!(e.process(&line("auth", "203.0.113.7"), later).is_empty());
        }
        // the expired offender escalates to offense 2
        e.process(&line("auth", "198.51.100.1"), later);
        let a = e.process(&line("auth", "198.51.100.1"), later);
        assert_eq!(a[0].offense, 2);
        assert_eq!(a[0].duration, Duration::from_secs(7200));
    }

    #[test]
    fn central_jail_settings() {
        let mut e = engine(); // sshd: maxretry 2, bantime 1h, factor 2
        let now = Utc::now();
        let fails = |e: &mut Engine, ip: &str, n: usize| {
            (0..n)
                .flat_map(|_| e.process(&line("auth", ip), now))
                .collect::<Vec<_>>()
        };
        let o = |f: fn(&mut JailOverride)| {
            let mut o = JailOverride {
                jail: "sshd".into(),
                ..Default::default()
            };
            f(&mut o);
            o
        };

        // stricter threshold, longer ban
        e.apply_jail_overrides(&[
            o(|o| {
                o.maxretry = Some(3);
                o.bantime = Some(Duration::from_secs(7200));
            }),
            JailOverride {
                jail: "unknown".into(),
                enabled: Some(false),
                ..Default::default()
            },
        ]);
        assert!(
            fails(&mut e, "203.0.113.1", 2).is_empty(),
            "2 failures no longer enough"
        );
        let b = fails(&mut e, "203.0.113.1", 1);
        assert_eq!((b.len(), b[0].duration), (1, Duration::from_secs(7200)));
        let st = &e.jail_status(now)[0];
        assert_eq!(
            (st.name.as_str(), st.filter.as_str(), st.params.maxretry),
            ("sshd", "sshd", 3)
        );
        assert_eq!(st.overridden, ["maxretry", "bantime"]);
        assert_eq!(st.active_bans, 1);

        // disabled: nothing is counted or banned; active bans stay
        e.apply_jail_overrides(&[o(|o| o.enabled = Some(false))]);
        assert!(fails(&mut e, "203.0.113.2", 5).is_empty());
        assert!(e.is_banned(&"203.0.113.1/32".parse().unwrap(), now));
        assert!(!e.jail_status(now)[0].params.enabled);

        // no policy: back to the configuration
        e.apply_jail_overrides(&[]);
        let st = &e.jail_status(now)[0];
        assert_eq!(
            (st.params.maxretry, st.params.bantime, st.params.enabled),
            (2, Duration::from_secs(3600), true)
        );
        assert!(st.overridden.is_empty());
        assert_eq!(fails(&mut e, "203.0.113.3", 2).len(), 1);
    }

    fn central_jail(name: &str, filter: &str) -> crate::central::CentralJail {
        crate::central::CentralJail {
            name: name.into(),
            filter: filter.into(),
            sources: vec![crate::central::CentralSource::File {
                paths: vec!["/var/log/x.log".into()],
                start_at_end: true,
            }],
            enabled: true,
            maxretry: 3,
            findtime: Duration::from_secs(600),
            bantime: Duration::from_secs(1800),
            factor: 2.0,
            max_bantime: None,
        }
    }

    #[test]
    fn central_jails() {
        let mut e = engine(); // local jail "sshd" on source "auth"
        let now = Utc::now();
        let filters = vec![(
            "app-auth".to_string(),
            "failregex = ['login failed for .* from <HOST>']".to_string(),
        )];
        let app_line = |ip: &str| LogLine {
            source: Arc::from("central:app:0"),
            ts: None,
            line: format!("login failed for bob from {ip}"),
        };
        let running = e.set_central_jails(
            &[
                central_jail("app", "app-auth"),
                central_jail("sshd", "sshd"), // local name: refused
                central_jail("ghost", "no-such-filter"), // neither central nor on disk
                central_jail("local-filter", "sshd"), // agent's own filter file
            ],
            &filters,
            vec![(
                "web".into(),
                "nginx".into(),
                "outside the allowed directories".into(),
            )],
        );
        assert_eq!(running, ["app", "local-filter"]);
        let st = e.jail_status(now);
        let find = |n: &str| st.iter().find(|s| s.name == n).unwrap().clone();
        assert_eq!(
            (find("sshd").origin, find("app").origin),
            ("local", "central")
        );
        assert!(find("ghost").error.contains("neither central nor"));
        assert!(st
            .iter()
            .any(|s| s.name == "sshd" && s.error.contains("local jail")));
        assert!(find("web").error.contains("outside"));
        // a refused definition named like a local jail reports the clash
        e.set_central_jails(
            &[],
            &filters,
            vec![("sshd".into(), "sshd".into(), "outside".into())],
        );
        assert!(e
            .jail_status(now)
            .iter()
            .any(|s| s.name == "sshd" && s.error.contains("local jail")));
        let running = e.set_central_jails(
            &[
                central_jail("app", "app-auth"),
                central_jail("local-filter", "sshd"),
            ],
            &filters,
            vec![],
        );
        assert_eq!(running.len(), 2);

        // lines of the central source are matched by the central filter
        assert!(e.process(&app_line("198.51.100.4"), now).is_empty());
        e.process(&app_line("198.51.100.4"), now);
        let b = e.process(&app_line("198.51.100.4"), now);
        assert_eq!(
            (b.len(), b[0].jail.as_str(), b[0].duration),
            (1, "app", Duration::from_secs(1800))
        );

        // policies apply to central jails too
        e.apply_jail_overrides(&[JailOverride {
            jail: "app".into(),
            maxretry: Some(1),
            ..Default::default()
        }]);
        assert_eq!(e.process(&app_line("198.51.100.5"), now).len(), 1);

        // redefined: offense history stays
        e.set_central_jails(&[central_jail("app", "app-auth")], &filters, vec![]);
        e.apply_jail_overrides(&[]);
        assert!(e.is_banned(&"198.51.100.4/32".parse().unwrap(), now));
        // removed: the jail is gone, local ones stay
        e.set_central_jails(&[], &filters, vec![]);
        let names: Vec<_> = e.jail_status(now).into_iter().map(|s| s.name).collect();
        assert_eq!(names, ["sshd"]);
    }

    #[test]
    fn observations_for_the_controller() {
        let mut e = engine(); // sshd: maxretry 2
        let now = Utc::now();
        e.process(&line("auth", "203.0.113.1"), now);
        assert!(e.take_observations().is_empty(), "off without a controller");
        e.collect_observations(true);
        e.process(&line("auth", "203.0.113.1"), now); // second failure: ban
        e.process(&line("auth", "203.0.113.1"), now); // banned: not counted
        e.process(&line("auth", "198.51.100.2"), now);
        e.process(&line("auth", "10.0.0.1"), now); // allowlisted
        e.process(&line("nginx", "198.51.100.2"), now); // no jail for it
        let mut obs: Vec<_> = e
            .take_observations()
            .into_iter()
            .map(|(j, k, o)| (j, k.to_string(), o.failures))
            .collect();
        obs.sort();
        assert_eq!(
            obs,
            [
                ("sshd".to_string(), "198.51.100.2/32".to_string(), 1),
                ("sshd".to_string(), "203.0.113.1/32".to_string(), 1),
            ]
        );
        assert!(e.take_observations().is_empty(), "drained");

        // the latest line is the sample; none when samples are off
        e.process(&line("auth", "198.51.100.3"), now);
        let obs = e.take_observations();
        let sample = obs[0].2.sample.as_deref().unwrap();
        assert!(sample.contains("198.51.100.3"), "{sample}");
        e.collect_observations(false);
        e.process(&line("auth", "198.51.100.3"), now);
        assert_eq!(e.take_observations()[0].2.sample, None);

        // [[redact]] rules apply before a line leaves the host
        let rule = |pattern: &str, replace: &str| df2b_core::RedactRule {
            name: String::new(),
            pattern: pattern.into(),
            replace: replace.into(),
            enabled: true,
        };
        e.local_redactor =
            df2b_core::Redactor::new(&[rule(r"for (\S+) from", "for [user] from")]).unwrap();
        e.set_central_redaction(&df2b_core::Redactor::default());
        e.collect_observations(true);
        e.process(&line("auth", "198.51.100.4"), now); // not banned yet
        let s = e.take_observations()[0].2.sample.clone().unwrap();
        assert!(s.contains("for [user] from 198.51.100.4"), "{s}");
        assert!(e
            .sample("Failed password for root from x")
            .contains("[user]"));
        // the controller's rules apply after the local ones, and replace
        // the controller's earlier ones
        let central =
            df2b_core::Redactor::new(&[rule(r"\[user\]", "[u]"), rule("port \\d+", "port [n]")])
                .unwrap();
        e.set_central_redaction(&central);
        assert_eq!(
            e.sample("for root from x port 22"),
            "for [u] from x port [n]"
        );
        e.set_central_redaction(&df2b_core::Redactor::default());
        assert_eq!(
            e.sample("for root from x port 22"),
            "for [user] from x port 22"
        );
    }

    #[test]
    fn central_allowlist() {
        let mut e = engine();
        let now = Utc::now();
        let ban = |e: &mut Engine, ip: &str| {
            e.process(&line("auth", ip), now);
            e.process(&line("auth", ip), now)
        };
        assert_eq!(ban(&mut e, "203.0.113.7").len(), 1);
        assert_eq!(ban(&mut e, "2001:db8::5").len(), 1, "banned as its /64");
        assert_eq!(ban(&mut e, "198.51.100.1").len(), 1);

        // the controller allowlists one address inside the /64 and a /24
        e.set_central_allowlist([
            "2001:db8::7/128".parse().unwrap(),
            "203.0.113.0/24".parse().unwrap(),
        ]);
        let mut lifted: Vec<String> = e
            .lift_allowlisted(now)
            .iter()
            .map(|r| r.key.to_string())
            .collect();
        lifted.sort();
        assert_eq!(lifted, ["2001:db8::/64", "203.0.113.7/32"]);
        assert!(
            e.is_banned(&"198.51.100.1/32".parse().unwrap(), now),
            "others stay"
        );
        assert!(e.lift_allowlisted(now).is_empty(), "nothing left to lift");
        // and nothing new is banned there
        assert!(ban(&mut e, "203.0.113.99").is_empty());
        assert!(ban(&mut e, "2001:db8::1").is_empty());
        assert!(
            ban(&mut e, "10.9.9.9").is_empty(),
            "local allowlist still applies"
        );

        // a new list replaces the old one; offense history was kept
        e.set_central_allowlist([]);
        let again = ban(&mut e, "203.0.113.7");
        assert_eq!((again.len(), again[0].offense), (1, 2));
    }

    #[test]
    fn ignores_other_sources_and_allowlist() {
        let mut e = engine();
        let now = Utc::now();
        for _ in 0..5 {
            assert!(e.process(&line("nginx", "203.0.113.7"), now).is_empty());
            assert!(e.process(&line("auth", "10.1.2.3"), now).is_empty());
        }
    }

    fn cfg(extra: &str) -> AgentConfig {
        let mut cfg: AgentConfig = toml::from_str(&format!(
            r#"
            [agent]
            {extra}
            [[source]]
            name = "auth"
            type = "file"
            paths = ["/dev/null"]
            [[jail]]
            name = "sshd"
            sources = ["auth"]
            filter = "sshd"
            maxretry = 3
            findtime = "10m"
            bantime = "1h"
            "#
        ))
        .unwrap();
        cfg.agent.filter_dir = concat!(env!("CARGO_MANIFEST_DIR"), "/../../filters").into();
        cfg
    }

    #[test]
    fn reload_keeps_history_and_ends_removed_jails() {
        let mut e = engine();
        let now = Utc::now();
        // banned once, one failure counted for another address
        e.process(&line("auth", "203.0.113.7"), now);
        assert_eq!(e.process(&line("auth", "203.0.113.7"), now).len(), 1);
        e.process(&line("auth", "198.51.100.1"), now);

        // same jail, maxretry 3, 198.51.100.0/24 allowlisted now
        let r = e
            .reload_local(&cfg(r#"allowlist = ["198.51.100.0/24"]"#), now)
            .unwrap();
        assert_eq!(r, Reloaded::default());
        assert_eq!(e.jail_status(now)[0].params.maxretry, 3);
        assert_eq!(e.bans(now).len(), 1, "active ban kept");
        assert!(e.allowlisted(&"198.51.100.1/32".parse().unwrap()));
        assert!(
            !e.allowlisted(&"10.1.1.1/32".parse().unwrap()),
            "old allowlist replaced"
        );
        // the counted failure stayed: two more reach 3
        e.process(&line("auth", "192.0.2.5"), now);
        e.process(&line("auth", "192.0.2.5"), now);
        assert_eq!(e.process(&line("auth", "192.0.2.5"), now).len(), 1);

        // a broken filter: nothing changes
        let mut bad = cfg("");
        bad.jail[0].filter = "does-not-exist".into();
        assert!(e.reload_local(&bad, now).is_err());
        assert_eq!(e.bans(now).len(), 2);

        // the jail removed: its bans end, its history is forgotten
        let mut none = cfg("");
        none.jail.clear();
        let r = e.reload_local(&none, now).unwrap();
        assert_eq!(r.ended.len(), 2);
        assert_eq!(r.forgotten.len(), 2);
        assert_eq!(e.jail_count(), 0);
    }

    /// Regression: controller bans bypassed the local allowlist and had no
    /// width limit (a 0.0.0.0/0 ban would lock the host out).
    #[test]
    fn remote_bans_respect_the_local_allowlist() {
        let e = engine(); // allowlist 10.0.0.0/8
        let net = |s: &str| s.parse::<IpNet>().unwrap();
        assert!(e.refuses_remote(&net("0.0.0.0/0")));
        assert!(e.refuses_remote(&net("100.0.0.0/7")));
        assert!(e.refuses_remote(&net("2001::/15")));
        assert!(e.refuses_remote(&net("10.1.2.3/32")), "allowlisted");
        assert!(
            e.refuses_remote(&net("8.0.0.0/6")),
            "contains the allowlist"
        );
        assert!(!e.refuses_remote(&net("203.0.113.0/24")));
        assert!(!e.refuses_remote(&net("2001:db8::/48")));
    }
}

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
    #[allow(dead_code)] // not reported to the controller (privacy) yet
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

/// Status of a jail for heartbeats.
#[derive(Debug, Clone, PartialEq)]
pub struct JailStatus {
    pub name: String,
    pub filter: String,
    pub params: JailParams,
    pub overridden: Vec<&'static str>,
    pub active_bans: usize,
}

#[derive(Debug)]
struct Jail {
    name: String,
    filter_name: String,
    sources: Vec<String>,
    filter: Filter,
    /// From the configuration; central overrides apply on top.
    base: JailParams,
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
    /// From the agent's configuration.
    allowlist: Allowlist,
    /// The controller's allowlist (replaced on every update).
    central: Allowlist,
    prefix: PrefixPolicy,
    offense_memory: TimeDelta,
}

/// Local (configuration) or central (controller) allowlist.
fn allowed(local: &Allowlist, central: &Allowlist, ip: &std::net::IpAddr, net: &IpNet) -> bool {
    [local, central]
        .iter()
        .any(|a| a.contains_addr(ip) || a.overlaps(net))
}

impl Engine {
    pub fn from_config(cfg: &AgentConfig) -> anyhow::Result<Self> {
        let jails = cfg
            .jail
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
            .collect::<anyhow::Result<Vec<_>>>()?;
        Ok(Self {
            jails,
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

    /// Effective settings per jail (heartbeats).
    pub fn jail_status(&self, now: DateTime<Utc>) -> Vec<JailStatus> {
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
            })
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

    /// Lifts active bans that overlap the controller's allowlist (a /64 ban
    /// containing an allowlisted address included). Offense history is kept.
    pub fn lift_allowlisted(&mut self, now: DateTime<Utc>) -> Vec<OffenderRecord> {
        let mut changed = Vec::new();
        for j in &mut self.jails {
            for (key, o) in j.offenders.iter_mut() {
                if o.banned_until > now && self.central.overlaps(&key.net()) {
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
}

//! Turns log lines into ban actions: jail routing → filter → allowlist →
//! tracker → escalated ban time.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, TimeDelta, Utc};
use df2b_core::{escalated_bantime, Allowlist, IpKey, PrefixPolicy};
use df2b_matcher::{Filter, FilterDef};
use df2b_sources::LogLine;
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
    #[allow(dead_code)] // reported to the controller (milestone 2)
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

#[derive(Debug)]
struct Jail {
    name: String,
    sources: Vec<String>,
    filter: Filter,
    tracker: Tracker,
    bantime: Duration,
    factor: f64,
    max_bantime: Option<Duration>,
    /// Keys this jail has banned: offense count and ban expiry. Failures of a
    /// key that is still banned are not counted, so one burst (e.g. catching
    /// up on a log file) cannot produce repeated bans and inflate the count.
    /// Entries are forgotten `offense_memory` after their ban expired.
    // TODO: clear / adjust on unban decisions (milestone 2).
    offenders: HashMap<IpKey, Offender>,
}

#[derive(Debug)]
pub struct Engine {
    jails: Vec<Jail>,
    allowlist: Allowlist,
    prefix: PrefixPolicy,
    offense_memory: TimeDelta,
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
            if !jail.sources.iter().any(|s| s.as_str() == &*line.source) {
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
            if self.allowlist.contains_addr(&m.ip) || self.allowlist.overlaps(&key.net()) {
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
                sample: line.line.clone(),
            });
        }
        actions
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
            sources: cfg.sources.clone(),
            filter,
            tracker: Tracker::new(cfg.maxretry, cfg.findtime, cfg.max_tracked),
            bantime: cfg.bantime,
            factor: cfg.bantime_factor,
            max_bantime: cfg.max_bantime,
            offenders: HashMap::new(),
        }
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
    fn ignores_other_sources_and_allowlist() {
        let mut e = engine();
        let now = Utc::now();
        for _ in 0..5 {
            assert!(e.process(&line("nginx", "203.0.113.7"), now).is_empty());
            assert!(e.process(&line("auth", "10.1.2.3"), now).is_empty());
        }
    }
}

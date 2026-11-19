//! Turns log lines into ban actions: jail routing → filter → allowlist →
//! tracker → escalated ban time.

use std::collections::HashMap;
use std::time::Duration;

use anyhow::Context;
use chrono::{DateTime, TimeDelta, Utc};
use df2b_core::{escalated_bantime, Allowlist, IpKey, PrefixPolicy};
use df2b_matcher::{Filter, FilterDef};
use df2b_sources::LogLine;
use tracing::debug;

use crate::config::{AgentConfig, JailConfig};
use crate::tracker::Tracker;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanAction {
    pub jail: String,
    pub key: IpKey,
    pub duration: Duration,
    /// 1 for the first ban of this key in this jail.
    pub offense: u32,
    #[allow(dead_code)] // reported to the controller (milestone 2)
    pub sample: String,
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
    /// Keys this jail has banned, with their expiry. Failures of a banned key
    /// are not counted, so one burst (e.g. catching up on a log file) cannot
    /// produce repeated bans and inflate the offense count.
    // TODO: fill from persisted state on startup; clear on unban decisions.
    banned: HashMap<IpKey, DateTime<Utc>>,
}

#[derive(Debug)]
pub struct Engine {
    jails: Vec<Jail>,
    allowlist: Allowlist,
    prefix: PrefixPolicy,
    // TODO: persist (redb) and expire old offense history
    offenses: HashMap<(usize, IpKey), u32>,
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
            offenses: HashMap::new(),
        })
    }

    pub fn jail_count(&self) -> usize {
        self.jails.len()
    }

    pub fn process(&mut self, line: &LogLine, now: DateTime<Utc>) -> Vec<BanAction> {
        let ts = line.ts.unwrap_or(now);
        let mut actions = Vec::new();
        for (idx, jail) in self.jails.iter_mut().enumerate() {
            if !jail.sources.iter().any(|s| s.as_str() == &*line.source) {
                continue;
            }
            let Some(m) = jail.filter.match_line(&line.line) else {
                continue;
            };
            let key = IpKey::from_addr(m.ip, self.prefix);
            if jail.banned.get(&key).is_some_and(|until| *until > now) {
                continue;
            }
            if self.allowlist.contains_addr(&m.ip) || self.allowlist.overlaps(&key.net()) {
                debug!(ip = %m.ip, jail = %jail.name, "allowlisted, ignoring");
                continue;
            }
            if !jail.tracker.record(key, ts, now) {
                continue;
            }
            let offense = self.offenses.entry((idx, key)).or_insert(0);
            *offense += 1;
            let duration = escalated_bantime(jail.bantime, jail.factor, jail.max_bantime, *offense);
            let until = TimeDelta::from_std(duration)
                .ok()
                .and_then(|d| now.checked_add_signed(d))
                .unwrap_or(DateTime::<Utc>::MAX_UTC);
            jail.banned.insert(key, until);
            actions.push(BanAction {
                jail: jail.name.clone(),
                key,
                duration,
                offense: *offense,
                sample: line.line.clone(),
            });
        }
        actions
    }

    pub fn prune(&mut self, now: DateTime<Utc>) {
        for j in &mut self.jails {
            j.tracker.prune(now);
            j.banned.retain(|_, until| *until > now);
        }
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
            banned: HashMap::new(),
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
        e.prune(now + TimeDelta::minutes(61));
        assert!(e.jails[0].banned.is_empty(), "expired bans are pruned");
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

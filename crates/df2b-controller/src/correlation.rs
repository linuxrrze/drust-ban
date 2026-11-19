//! Correlation policies (DESIGN.md §4.2): bans the controller decides from
//! what several agents observed.
//!
//! - `threshold`: at least `min_failures` failures from at least
//!   `min_agents` different agents within `window` (slow, distributed
//!   attacks: two failures on each of 15 hosts never trip a local jail).
//! - `quorum`: at least `min_agents` different agents banned the address
//!   locally within `window` (anti-poisoning: with ban propagation off, a
//!   single compromised agent cannot ban anything globally).
//!
//! A rule applies to one jail or all, and to all agents or one group (it
//! then only counts that group's agents and bans in that group). In monitor
//! mode it only records what it would have banned. Observations are kept
//! in memory for the longest window (at least an hour, for the address
//! page); a controller restart starts them afresh.

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

use crate::policy;

/// Observations kept at least this long (address page).
pub const MIN_KEEP: Duration = Duration::from_secs(3600);
pub const MAX_WINDOW: Duration = Duration::from_secs(24 * 3600);
/// Memory bound: addresses tracked at once.
const MAX_KEYS: usize = 200_000;
/// Observations accepted per agent and minute (§4.5 abuse safeguard).
pub const MAX_PER_AGENT_MINUTE: u32 = 20_000;
/// Monitor-mode hits kept for the UI.
const MAX_HITS: usize = 200;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RuleKind {
    Threshold,
    Quorum,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Rule {
    pub name: String,
    pub kind: RuleKind,
    /// None: all jails
    pub jail: Option<String>,
    /// None: all agents (bans globally); else only this group's agents
    /// count and the ban applies to the group
    pub group: Option<String>,
    pub min_agents: u32,
    /// threshold only
    #[serde(default)]
    pub min_failures: u32,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
    /// First ban; repeat offenders get bantime × factor^(offense-1)
    #[serde(with = "humantime_serde")]
    pub bantime: Duration,
    #[serde(default = "one")]
    pub bantime_factor: f64,
    /// upper bound for escalated bans (always at most 10 years)
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "humantime_serde"
    )]
    pub max_bantime: Option<Duration>,
    #[serde(default = "yes")]
    pub enabled: bool,
    /// only record what would be banned
    #[serde(default)]
    pub monitor: bool,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

fn yes() -> bool {
    true
}
fn one() -> f64 {
    1.0
}

impl Rule {
    pub fn validate(&self) -> Result<(), String> {
        if !policy::valid_jail(&self.name) {
            return Err("invalid rule name (letters, digits, - _ .)".into());
        }
        if self.jail.as_deref().is_some_and(|j| !policy::valid_jail(j)) {
            return Err("invalid jail name".into());
        }
        let min = match self.kind {
            RuleKind::Threshold => 1,
            // one agent alone is what propagation already does
            RuleKind::Quorum => 2,
        };
        if self.min_agents < min || self.min_agents > 1000 {
            return Err(format!("min_agents must be between {min} and 1000"));
        }
        if self.kind == RuleKind::Threshold
            && (self.min_failures == 0 || self.min_failures > 1_000_000)
        {
            return Err("min_failures must be between 1 and 1000000".into());
        }
        if self.window < Duration::from_secs(60) || self.window > MAX_WINDOW {
            return Err("window must be between 1 minute and 24 hours".into());
        }
        if self.bantime < policy::MIN_BANTIME || self.bantime > policy::MAX_BANTIME {
            return Err("bantime must be between 1 minute and 10 years".into());
        }
        if !(1.0..=policy::MAX_FACTOR).contains(&self.bantime_factor)
            || self.bantime_factor.is_nan()
        {
            return Err(format!(
                "bantime_factor must be between 1 and {}",
                policy::MAX_FACTOR
            ));
        }
        if let Some(m) = self.max_bantime {
            if m < self.bantime || m > policy::MAX_BANTIME {
                return Err("max_bantime must be between bantime and 10 years".into());
            }
        }
        Ok(())
    }

    /// Ban duration for the `offense`-th correlation ban of an address.
    pub fn bantime_for(&self, offense: u32) -> Duration {
        df2b_core::escalated_bantime(
            self.bantime,
            self.bantime_factor,
            Some(self.max_bantime.unwrap_or(policy::MAX_BANTIME)),
            offense,
        )
    }

    fn applies(&self, jail: &str, group: &str) -> bool {
        self.enabled
            && self.jail.as_deref().map_or(true, |j| j == jail)
            && self.group.as_deref().map_or(true, |g| g == group)
    }
}

/// One aggregated report from an agent.
#[derive(Debug, Clone, Serialize)]
pub struct Seen {
    pub agent: String,
    #[serde(skip)]
    pub group: String,
    pub at: DateTime<Utc>,
    pub failures: u32,
    /// a local ban (a quorum vote)
    pub banned: bool,
}

/// A rule that fired.
#[derive(Debug, Clone, Serialize)]
pub struct Trigger {
    pub rule: String,
    pub jail: String,
    pub target: IpNet,
    pub failures: u32,
    pub agents: Vec<String>,
    pub at: DateTime<Utc>,
    pub monitor: bool,
}

#[derive(Default)]
pub struct Correlator {
    seen: HashMap<(String, IpNet), VecDeque<Seen>>,
    /// (rule, jail, key) → not before (no repeated firing)
    fired: HashMap<(String, String, IpNet), DateTime<Utc>>,
    /// per agent: (minute, observations in it)
    rate: HashMap<String, (i64, u32)>,
    hits: VecDeque<Trigger>,
    dropped: u64,
}

impl Correlator {
    /// Rate limit per agent; false: drop this observation.
    pub fn admit(&mut self, agent: &str, now: DateTime<Utc>) -> bool {
        let minute = now.timestamp().div_euclid(60);
        let e = self.rate.entry(agent.to_owned()).or_insert((minute, 0));
        if e.0 != minute {
            *e = (minute, 0);
        }
        e.1 += 1;
        e.1 <= MAX_PER_AGENT_MINUTE
    }

    /// Records an observation; false if the memory bound was reached.
    pub fn record(&mut self, jail: &str, key: IpNet, s: Seen) -> bool {
        let k = (jail.to_owned(), key);
        if !self.seen.contains_key(&k) && self.seen.len() >= MAX_KEYS {
            self.dropped += 1;
            if self.dropped.is_power_of_two() {
                tracing::warn!(
                    dropped = self.dropped,
                    "correlation: too many addresses, dropping"
                );
            }
            return false;
        }
        self.seen.entry(k).or_default().push_back(s);
        true
    }

    /// Rules that fire for this key now.
    pub fn evaluate(
        &mut self,
        rules: &[Rule],
        jail: &str,
        key: IpNet,
        group: &str,
        now: DateTime<Utc>,
    ) -> Vec<Trigger> {
        let Some(entries) = self.seen.get(&(jail.to_owned(), key)) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for r in rules.iter().filter(|r| r.applies(jail, group)) {
            let fired_key = (r.name.clone(), jail.to_owned(), key);
            if self.fired.get(&fired_key).is_some_and(|t| *t > now) {
                continue;
            }
            let since = now - TimeDelta::from_std(r.window).unwrap_or(TimeDelta::MAX);
            let inside = entries
                .iter()
                .filter(|s| s.at >= since && r.group.as_deref().map_or(true, |g| s.group == g));
            let (agents, failures) = match r.kind {
                RuleKind::Threshold => {
                    let mut agents = HashSet::new();
                    let mut failures = 0u32;
                    for s in inside.filter(|s| !s.banned) {
                        agents.insert(s.agent.as_str());
                        failures = failures.saturating_add(s.failures);
                    }
                    if failures < r.min_failures {
                        continue;
                    }
                    (agents, failures)
                }
                RuleKind::Quorum => {
                    let agents: HashSet<&str> = inside
                        .filter(|s| s.banned)
                        .map(|s| s.agent.as_str())
                        .collect();
                    (agents, 0)
                }
            };
            if (agents.len() as u32) < r.min_agents {
                continue;
            }
            let mut agents: Vec<String> = agents.into_iter().map(str::to_owned).collect();
            agents.sort();
            // not again for this key until the ban (or, in monitor mode,
            // the window) is over
            let pause = if r.monitor { r.window } else { r.bantime };
            self.fired.insert(
                fired_key,
                now + TimeDelta::from_std(pause).unwrap_or(TimeDelta::MAX),
            );
            let t = Trigger {
                rule: r.name.clone(),
                jail: jail.to_owned(),
                target: key,
                failures,
                agents,
                at: now,
                monitor: r.monitor,
            };
            if r.monitor {
                self.hits.push_front(t.clone());
                self.hits.truncate(MAX_HITS);
            }
            out.push(t);
        }
        out
    }

    /// Forgets observations older than `keep` and expired firing pauses.
    pub fn prune(&mut self, now: DateTime<Utc>, keep: Duration) {
        let since = now - TimeDelta::from_std(keep).unwrap_or(TimeDelta::MAX);
        self.seen.retain(|_, q| {
            while q.front().is_some_and(|s| s.at < since) {
                q.pop_front();
            }
            !q.is_empty()
        });
        self.fired.retain(|_, t| *t > now);
        let minute = now.timestamp().div_euclid(60);
        self.rate.retain(|_, (m, _)| *m == minute);
    }

    /// Recent observations overlapping `net` (address page), newest first.
    pub fn recent(&self, net: &IpNet) -> Vec<(String, IpNet, Seen)> {
        let mut out: Vec<(String, IpNet, Seen)> = self
            .seen
            .iter()
            .filter(|((_, k), _)| k.contains(net) || net.contains(k))
            .flat_map(|((jail, k), q)| q.iter().map(move |s| (jail.clone(), *k, s.clone())))
            .collect();
        out.sort_by_key(|o| std::cmp::Reverse(o.2.at));
        out.truncate(500);
        out
    }

    pub fn hits(&self) -> Vec<Trigger> {
        self.hits.iter().cloned().collect()
    }

    pub fn tracked(&self) -> usize {
        self.seen.len()
    }
}

/// How long observations are kept for these rules.
pub fn keep_for(rules: &[Rule]) -> Duration {
    rules
        .iter()
        .map(|r| r.window)
        .max()
        .unwrap_or_default()
        .max(MIN_KEEP)
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn rule(kind: RuleKind, min_agents: u32, min_failures: u32) -> Rule {
        Rule {
            name: "r".into(),
            kind,
            jail: None,
            group: None,
            min_agents,
            min_failures,
            window: Duration::from_secs(600),
            bantime: Duration::from_secs(3600),
            bantime_factor: 1.0,
            max_bantime: None,
            enabled: true,
            monitor: false,
            updated_by: "ada".into(),
            updated_at: Utc::now(),
        }
    }

    fn seen(agent: &str, group: &str, at: DateTime<Utc>, failures: u32, banned: bool) -> Seen {
        Seen {
            agent: agent.into(),
            group: group.into(),
            at,
            failures,
            banned,
        }
    }

    #[test]
    fn threshold_across_agents() {
        let mut c = Correlator::default();
        let now = Utc::now();
        let key: IpNet = "203.0.113.7/32".parse().unwrap();
        let rules = [rule(RuleKind::Threshold, 3, 6)];
        // two failures on each of three agents
        for (i, a) in ["a1", "a2"].iter().enumerate() {
            c.record(
                "sshd",
                key,
                seen(a, "web", now - TimeDelta::seconds(i as i64), 2, false),
            );
        }
        assert!(
            c.evaluate(&rules, "sshd", key, "web", now).is_empty(),
            "2 agents, 4 failures"
        );
        // an old one outside the window does not count
        c.record(
            "sshd",
            key,
            seen("a3", "web", now - TimeDelta::minutes(30), 2, false),
        );
        assert!(c.evaluate(&rules, "sshd", key, "web", now).is_empty());
        c.record("sshd", key, seen("a3", "web", now, 2, false));
        let t = c.evaluate(&rules, "sshd", key, "web", now);
        assert_eq!((t.len(), t[0].failures), (1, 6));
        assert_eq!(t[0].agents, ["a1", "a2", "a3"]);
        // fires once per ban
        c.record("sshd", key, seen("a4", "web", now, 5, false));
        assert!(c.evaluate(&rules, "sshd", key, "web", now).is_empty());
        // local bans are not failures for threshold rules
        let k2: IpNet = "203.0.113.8/32".parse().unwrap();
        for a in ["a1", "a2", "a3"] {
            c.record("sshd", k2, seen(a, "web", now, 5, true));
        }
        assert!(c.evaluate(&rules, "sshd", k2, "web", now).is_empty());
    }

    #[test]
    fn quorum_scopes_and_monitor() {
        let mut c = Correlator::default();
        let now = Utc::now();
        let key: IpNet = "2001:db8::/64".parse().unwrap();
        let mut q = rule(RuleKind::Quorum, 2, 0);
        q.group = Some("web".into());
        q.jail = Some("sshd".into());
        let rules = [q];
        c.record("sshd", key, seen("w1", "web", now, 5, true));
        c.record("sshd", key, seen("d1", "db", now, 5, true));
        assert!(
            c.evaluate(&rules, "sshd", key, "web", now).is_empty(),
            "only web counts"
        );
        c.record("sshd", key, seen("w1", "web", now, 5, true));
        assert!(
            c.evaluate(&rules, "sshd", key, "web", now).is_empty(),
            "same agent twice is one vote"
        );
        c.record("nginx", key, seen("w2", "web", now, 5, true));
        assert!(
            c.evaluate(&rules, "nginx", key, "web", now).is_empty(),
            "other jail"
        );
        c.record("sshd", key, seen("w2", "web", now, 5, true));
        assert_eq!(c.evaluate(&rules, "sshd", key, "web", now).len(), 1);

        let mut m = rule(RuleKind::Threshold, 1, 3);
        m.monitor = true;
        let k: IpNet = "198.51.100.1/32".parse().unwrap();
        c.record("sshd", k, seen("w1", "web", now, 3, false));
        let t = c.evaluate(&[m], "sshd", k, "web", now);
        assert!(t[0].monitor);
        assert_eq!(c.hits().len(), 1);
    }

    #[test]
    fn pruning_rates_and_lookup() {
        let mut c = Correlator::default();
        let now = Utc::now();
        let key: IpNet = "192.0.2.9/32".parse().unwrap();
        c.record(
            "sshd",
            key,
            seen("a", "web", now - TimeDelta::hours(2), 1, false),
        );
        c.record("sshd", key, seen("a", "web", now, 1, false));
        assert_eq!(c.recent(&"192.0.2.0/24".parse().unwrap()).len(), 2);
        c.prune(now, MIN_KEEP);
        assert_eq!(c.recent(&key).len(), 1);
        assert_eq!(c.tracked(), 1);
        for _ in 0..MAX_PER_AGENT_MINUTE {
            assert!(c.admit("a", now));
        }
        assert!(!c.admit("a", now));
        assert!(c.admit("b", now));
        assert_eq!(keep_for(&[]), MIN_KEEP);
    }

    #[test]
    fn validation() {
        assert!(rule(RuleKind::Threshold, 3, 10).validate().is_ok());
        assert!(
            rule(RuleKind::Quorum, 1, 0).validate().is_err(),
            "quorum of one"
        );
        assert!(rule(RuleKind::Threshold, 2, 0).validate().is_err());
        let mut r = rule(RuleKind::Quorum, 2, 0);
        r.window = Duration::from_secs(2 * 86400);
        assert!(r.validate().is_err());
        r.window = Duration::from_secs(10);
        assert!(r.validate().is_err());
        let mut r = rule(RuleKind::Threshold, 2, 5);
        r.bantime_factor = 0.5;
        assert!(r.validate().is_err());
        r.bantime_factor = 2.0;
        r.max_bantime = Some(Duration::from_secs(60));
        assert!(r.validate().is_err(), "max below bantime");
        r.max_bantime = Some(Duration::from_secs(4 * 3600));
        assert!(r.validate().is_ok());
        let h = |n: u64| Duration::from_secs(n * 3600);
        assert_eq!(
            [1, 2, 3, 4].map(|o| r.bantime_for(o)),
            [h(1), h(2), h(4), h(4)]
        );
        r.max_bantime = None;
        r.bantime_factor = 10.0;
        assert_eq!(
            r.bantime_for(40),
            policy::MAX_BANTIME,
            "capped without a maximum"
        );
    }
}

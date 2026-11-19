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
//! page). They are also written to the database every few seconds and
//! replayed at startup, with the firing pauses and monitor hits, so a
//! controller restart loses at most the last few seconds.

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
/// Sample log lines kept per (jail, address), and in all (memory bound:
/// at most about 50 MB of lines).
const SAMPLES_PER_KEY: usize = 10;
const MAX_SAMPLES: usize = 100_000;

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
    /// the agent's sample log line (moved to the sample store on record)
    #[serde(skip)]
    pub sample: Option<String>,
}

/// A log line an agent sent with an observation (address page).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Sample {
    pub agent: String,
    pub at: DateTime<Utc>,
    pub line: String,
}

/// An observation as stored in the database.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Stored {
    pub jail: String,
    pub key: IpNet,
    pub agent: String,
    pub group: String,
    pub at: DateTime<Utc>,
    pub failures: u32,
    pub banned: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub sample: Option<String>,
}

/// Firing pauses and monitor hits, stored as one value.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Meta {
    /// (rule, jail, key, not before)
    pub fired: Vec<(String, String, IpNet, DateTime<Utc>)>,
    pub hits: Vec<Trigger>,
}

/// A rule that fired.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
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
    /// the latest sample lines per (jail, key), oldest first
    samples: HashMap<(String, IpNet), VecDeque<Sample>>,
    /// lines in `samples`
    sample_count: usize,
    /// (rule, jail, key) → not before (no repeated firing)
    fired: HashMap<(String, String, IpNet), DateTime<Utc>>,
    /// per agent: (minute, observations in it)
    rate: HashMap<String, (i64, u32)>,
    hits: VecDeque<Trigger>,
    dropped: u64,
    /// accepted since the last flush (written to the database)
    pending: Vec<Stored>,
    /// fired or hits changed since the last flush
    meta_dirty: bool,
}

impl Correlator {
    /// Milliseconds until `admit` accepts again after the agent hit its
    /// rate: the start of the next minute.
    pub fn retry_after_ms(now: DateTime<Utc>) -> u32 {
        60_000 - now.timestamp_millis().rem_euclid(60_000) as u32
    }

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
        let stored = Stored {
            jail: jail.to_owned(),
            key,
            agent: s.agent.clone(),
            group: s.group.clone(),
            at: s.at,
            failures: s.failures,
            banned: s.banned,
            sample: s.sample.clone(),
        };
        if !self.insert(jail, key, s) {
            return false;
        }
        self.pending.push(stored);
        true
    }

    fn insert(&mut self, jail: &str, key: IpNet, mut s: Seen) -> bool {
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
        if let Some(line) = s.sample.take() {
            self.add_sample(
                k.clone(),
                Sample {
                    agent: s.agent.clone(),
                    at: s.at,
                    line,
                },
            );
        }
        let q = self.seen.entry(k).or_default();
        // agents report in order, but several agents interleave: keep the
        // queue sorted so pruning from the front stays correct
        let pos = q.iter().rposition(|e| e.at <= s.at).map_or(0, |i| i + 1);
        q.insert(pos, s);
        true
    }

    fn add_sample(&mut self, k: (String, IpNet), sample: Sample) {
        let full = self.samples.get(&k).map_or(0, VecDeque::len) >= SAMPLES_PER_KEY;
        if !full && self.sample_count >= MAX_SAMPLES {
            return;
        }
        let q = self.samples.entry(k).or_default();
        if full {
            q.pop_front();
        } else {
            self.sample_count += 1;
        }
        q.push_back(sample);
    }

    /// Applies redaction rules to the kept sample lines (also those not
    /// yet written); returns how many changed.
    pub fn redact_samples(&mut self, r: &df2b_core::Redactor) -> usize {
        if r.is_empty() {
            return 0;
        }
        let redact = |line: &mut String| {
            let new = df2b_core::sample_line(&r.apply(line));
            let changed = new != *line;
            *line = new;
            changed
        };
        let mut n = 0;
        for q in self.samples.values_mut() {
            for s in q.iter_mut() {
                n += usize::from(redact(&mut s.line));
            }
        }
        for o in &mut self.pending {
            if let Some(l) = o.sample.as_mut() {
                redact(l);
            }
        }
        n
    }

    /// Replays stored observations and state (startup). Observations
    /// older than `keep` and expired pauses are skipped.
    pub fn restore(
        &mut self,
        observations: impl IntoIterator<Item = Stored>,
        meta: Option<Meta>,
        now: DateTime<Utc>,
        keep: Duration,
    ) -> usize {
        let since = now - TimeDelta::from_std(keep).unwrap_or(TimeDelta::MAX);
        let mut n = 0;
        for o in observations.into_iter().filter(|o| o.at >= since) {
            let seen = Seen {
                agent: o.agent,
                group: o.group,
                at: o.at,
                failures: o.failures,
                banned: o.banned,
                sample: o.sample,
            };
            if self.insert(&o.jail, o.key, seen) {
                n += 1;
            }
        }
        if let Some(m) = meta {
            self.fired.extend(
                m.fired
                    .into_iter()
                    .filter(|f| f.3 > now)
                    .map(|(r, j, k, t)| ((r, j, k), t)),
            );
            self.hits = m.hits.into_iter().take(MAX_HITS).collect();
        }
        n
    }

    /// What to write to the database since the last call: new
    /// observations, and the firing pauses and hits if they changed.
    pub fn take_unsaved(&mut self) -> (Vec<Stored>, Option<Meta>) {
        let meta = std::mem::take(&mut self.meta_dirty).then(|| Meta {
            fired: self
                .fired
                .iter()
                .map(|((r, j, k), t)| (r.clone(), j.clone(), *k, *t))
                .collect(),
            hits: self.hits.iter().cloned().collect(),
        });
        (std::mem::take(&mut self.pending), meta)
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
            self.meta_dirty = true;
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
        let mut count = 0;
        self.samples.retain(|_, q| {
            q.retain(|s| s.at >= since);
            count += q.len();
            !q.is_empty()
        });
        self.sample_count = count;
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

    /// Sample log lines for addresses overlapping `net`, newest first.
    pub fn samples(&self, net: &IpNet) -> Vec<(String, IpNet, Sample)> {
        let mut out: Vec<(String, IpNet, Sample)> = self
            .samples
            .iter()
            .filter(|((_, k), _)| k.contains(net) || net.contains(k))
            .flat_map(|((jail, k), q)| q.iter().map(move |s| (jail.clone(), *k, s.clone())))
            .collect();
        out.sort_by_key(|o| std::cmp::Reverse(o.2.at));
        out.truncate(50);
        out
    }

    pub fn hits(&self) -> Vec<Trigger> {
        self.hits.iter().cloned().collect()
    }

    pub fn tracked(&self) -> usize {
        self.seen.len()
    }

    #[cfg(test)]
    fn seen_for_test(&self) -> Vec<Stored> {
        self.seen
            .iter()
            .flat_map(|((jail, key), q)| {
                q.iter().map(move |s| Stored {
                    jail: jail.clone(),
                    key: *key,
                    agent: s.agent.clone(),
                    group: s.group.clone(),
                    at: s.at,
                    failures: s.failures,
                    banned: s.banned,
                    sample: None,
                })
            })
            .collect()
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
pub(crate) mod tests {
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
            sample: None,
        }
    }

    #[test]
    fn persistence_round_trip() {
        let now = Utc::now();
        let key: IpNet = "198.51.100.7/32".parse().unwrap();
        let mut c = Correlator::default();
        // out of order across agents: kept sorted
        let mut with_line = seen("a2", "web", now, 3, false);
        with_line.sample = Some("Failed password for root".into());
        c.record("sshd", key, with_line);
        c.record(
            "sshd",
            key,
            seen("a1", "web", now - TimeDelta::minutes(2), 2, false),
        );
        let mut monitor = rule(RuleKind::Threshold, 2, 5);
        monitor.monitor = true;
        assert_eq!(
            c.evaluate(&[monitor.clone()], "sshd", key, "web", now)
                .len(),
            1
        );
        let (obs, meta) = c.take_unsaved();
        assert_eq!(obs.len(), 2);
        let meta = meta.expect("fired changed");
        assert_eq!((meta.fired.len(), meta.hits.len()), (1, 1));
        assert_eq!(c.take_unsaved(), (vec![], None), "nothing new");

        // a fresh correlator from what was stored, plus one too old
        let mut old = obs[0].clone();
        old.at = now - TimeDelta::hours(3);
        let mut r = Correlator::default();
        let meta = serde_json::from_slice(&serde_json::to_vec(&meta).unwrap()).unwrap();
        let n = r.restore(obs.into_iter().chain([old]), Some(meta), now, MIN_KEEP);
        assert_eq!(n, 2, "the old one is skipped");
        assert_eq!(r.recent(&key).len(), 2);
        assert_eq!(r.samples(&key).len(), 1, "sample lines restored");
        assert_eq!(r.samples(&key)[0].2.line, "Failed password for root");
        assert_eq!(r.hits().len(), 1);
        assert!(
            r.evaluate(&[monitor.clone()], "sshd", key, "web", now)
                .is_empty(),
            "the pause survives"
        );
        assert_eq!(r.take_unsaved(), (vec![], None), "replayed, not new");
        // expired pauses are not restored
        let mut r = Correlator::default();
        let expired = Meta {
            fired: vec![("r".into(), "sshd".into(), key, now - TimeDelta::seconds(1))],
            hits: vec![],
        };
        r.restore(c.seen_for_test(), Some(expired), now, MIN_KEEP);
        assert_eq!(r.evaluate(&[monitor], "sshd", key, "web", now).len(), 1);
        // sorted: pruning keeps the newer one
        r.prune(now, Duration::from_secs(60));
        assert_eq!(r.recent(&key).len(), 1);
        assert_eq!(r.recent(&key)[0].2.agent, "a2");
    }

    #[test]
    fn samples_bounded_and_pruned() {
        let now = Utc::now();
        let key: IpNet = "198.51.100.8/32".parse().unwrap();
        let mut c = Correlator::default();
        for i in 0..15 {
            let mut s = seen("a1", "web", now - TimeDelta::minutes(20 - i), 1, false);
            s.sample = Some(format!("line {i}"));
            c.record("sshd", key, s);
        }
        c.record("sshd", key, seen("a2", "web", now, 1, false)); // no line
        let got = c.samples(&key);
        assert_eq!(got.len(), SAMPLES_PER_KEY, "only the latest per address");
        assert_eq!(got[0].2.line, "line 14", "newest first");
        assert_eq!(c.sample_count, SAMPLES_PER_KEY);
        // observations without a line keep no sample; the queue has them all
        assert_eq!(c.recent(&key).len(), 16);
        assert!(c.recent(&key).iter().all(|o| o.2.sample.is_none()));
        // pruned with the observations
        c.prune(now, Duration::from_secs(10 * 60));
        assert_eq!(c.samples(&key).len(), 5, "lines 10..14 are within 10 min");
        c.prune(now + TimeDelta::hours(1), Duration::from_secs(60));
        assert!(c.samples(&key).is_empty());
        assert_eq!(c.sample_count, 0);
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
        let next = now + TimeDelta::milliseconds(Correlator::retry_after_ms(now).into());
        assert_eq!(next.timestamp_millis() % 60_000, 0);
        assert!(next > now && c.admit("a", next));
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

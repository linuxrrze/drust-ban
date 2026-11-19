//! Sliding-window failure counter per key.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use df2b_core::IpKey;

#[derive(Debug)]
pub struct Tracker {
    maxretry: usize,
    findtime: TimeDelta,
    max_keys: usize,
    hits: HashMap<IpKey, VecDeque<DateTime<Utc>>>,
}

impl Tracker {
    pub fn new(maxretry: u32, findtime: Duration, max_keys: usize) -> Self {
        Self {
            maxretry: maxretry.max(1) as usize,
            findtime: TimeDelta::from_std(findtime).unwrap_or(TimeDelta::days(365)),
            max_keys: max_keys.max(1),
            hits: HashMap::new(),
        }
    }

    /// Records a failure at `ts`. Returns `true` when the threshold is
    /// reached; the key's counter is then reset.
    ///
    /// Events older than `findtime` relative to `now` are ignored (catch-up
    /// of old log content never triggers bans).
    pub fn record(&mut self, key: IpKey, ts: DateTime<Utc>, now: DateTime<Utc>) -> bool {
        let cutoff = now - self.findtime;
        if ts < cutoff {
            return false;
        }
        if self.hits.len() >= self.max_keys && !self.hits.contains_key(&key) {
            self.prune(now);
            if self.hits.len() >= self.max_keys {
                // TODO: count + expose as metric; consider evicting the
                // oldest key instead of dropping the new one.
                tracing::warn!(%key, "tracker full, dropping event");
                return false;
            }
        }
        let q = self.hits.entry(key).or_default();
        q.push_back(ts);
        while q.front().is_some_and(|t| *t < cutoff) {
            q.pop_front();
        }
        if q.len() >= self.maxretry {
            self.hits.remove(&key);
            true
        } else {
            false
        }
    }

    /// Drops expired timestamps and empty keys.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - self.findtime;
        self.hits.retain(|_, q| {
            q.retain(|t| *t >= cutoff);
            !q.is_empty()
        });
    }

    #[allow(dead_code)] // used by unban handling (milestone 2)
    pub fn reset(&mut self, key: &IpKey) {
        self.hits.remove(key);
    }

    #[allow(dead_code)]
    pub fn len(&self) -> usize {
        self.hits.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use df2b_core::PrefixPolicy;

    fn key(s: &str) -> IpKey {
        IpKey::from_addr(s.parse().unwrap(), PrefixPolicy::default())
    }

    #[test]
    fn triggers_within_window() {
        let mut t = Tracker::new(3, Duration::from_secs(60), 10);
        let now = Utc::now();
        let k = key("192.0.2.1");
        assert!(!t.record(k, now, now));
        assert!(!t.record(k, now, now));
        assert!(t.record(k, now, now));
        assert_eq!(t.len(), 0, "counter reset after trigger");
    }

    #[test]
    fn window_slides() {
        let mut t = Tracker::new(2, Duration::from_secs(60), 10);
        let start = Utc::now();
        let k = key("192.0.2.1");
        assert!(!t.record(k, start, start));
        let later = start + TimeDelta::seconds(120);
        assert!(!t.record(k, later, later), "first hit expired");
        assert!(t.record(k, later, later));
    }

    #[test]
    fn old_events_ignored() {
        let mut t = Tracker::new(1, Duration::from_secs(60), 10);
        let now = Utc::now();
        assert!(!t.record(key("192.0.2.1"), now - TimeDelta::hours(1), now));
    }

    #[test]
    fn bounded() {
        let mut t = Tracker::new(5, Duration::from_secs(60), 2);
        let now = Utc::now();
        t.record(key("192.0.2.1"), now, now);
        t.record(key("192.0.2.2"), now, now);
        t.record(key("192.0.2.3"), now, now);
        assert_eq!(t.len(), 2);
    }
}

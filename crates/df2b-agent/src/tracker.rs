//! Sliding-window failure counter per key.
//!
//! Bounded to `max_keys`. When full, expired entries are pruned (at most
//! once per second: pruning walks every key) and, if that does not make
//! room, the key tracked longest is evicted, so a flood of new addresses
//! is still counted instead of being ignored. Evictions are counted and
//! reported in heartbeats; they mean failures were forgotten and
//! `max_tracked` may be too small.

use std::collections::{HashMap, VecDeque};
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use df2b_core::IpKey;

#[derive(Debug)]
struct Entry {
    /// Matches this key's place in `order` (stale places are skipped).
    generation: u64,
    hits: VecDeque<DateTime<Utc>>,
}

#[derive(Debug)]
pub struct Tracker {
    maxretry: usize,
    findtime: TimeDelta,
    max_keys: usize,
    hits: HashMap<IpKey, Entry>,
    /// Keys in the order they started being tracked, for eviction.
    order: VecDeque<(IpKey, u64)>,
    next_generation: u64,
    last_full_prune: Option<DateTime<Utc>>,
    evicted: u64,
}

impl Tracker {
    pub fn new(maxretry: u32, findtime: Duration, max_keys: usize) -> Self {
        Self {
            maxretry: maxretry.max(1) as usize,
            findtime: TimeDelta::from_std(findtime).unwrap_or(TimeDelta::days(365)),
            max_keys: max_keys.max(1),
            hits: HashMap::new(),
            order: VecDeque::new(),
            next_generation: 0,
            last_full_prune: None,
            evicted: 0,
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
        if !self.hits.contains_key(&key) {
            self.make_room(now);
            let generation = self.next_generation;
            self.next_generation += 1;
            self.order.push_back((key, generation));
            self.hits.insert(
                key,
                Entry {
                    generation,
                    hits: VecDeque::new(),
                },
            );
        }
        let q = &mut self.hits.get_mut(&key).expect("inserted above").hits;
        q.push_back(ts);
        // events of several sources need not arrive in time order: drop
        // every expired one, not only those at the front
        q.retain(|t| *t >= cutoff);
        if q.len() >= self.maxretry {
            self.hits.remove(&key);
            true
        } else {
            false
        }
    }

    fn make_room(&mut self, now: DateTime<Utc>) {
        if self.hits.len() < self.max_keys {
            return;
        }
        if self
            .last_full_prune
            .map_or(true, |t| now - t >= TimeDelta::seconds(1))
        {
            self.last_full_prune = Some(now);
            self.prune(now);
        }
        while self.hits.len() >= self.max_keys {
            let Some((key, generation)) = self.order.pop_front() else {
                break;
            };
            if self
                .hits
                .get(&key)
                .is_some_and(|e| e.generation == generation)
            {
                self.hits.remove(&key);
                self.evicted += 1;
                if self.evicted.is_power_of_two() {
                    tracing::warn!(
                        evicted = self.evicted,
                        max_tracked = self.max_keys,
                        "failure tracker full, forgetting the oldest addresses"
                    );
                }
            }
        }
    }

    /// New threshold and window (central jail policy); counted failures are
    /// kept and judged by the new values from the next one on.
    pub fn set_limits(&mut self, maxretry: u32, findtime: Duration) {
        self.maxretry = maxretry.max(1) as usize;
        self.findtime = TimeDelta::from_std(findtime).unwrap_or(TimeDelta::days(365));
    }

    /// New key limit (configuration reload); a smaller one takes effect
    /// as new keys arrive.
    pub fn set_max_keys(&mut self, max_keys: usize) {
        self.max_keys = max_keys.max(1);
    }

    /// Drops expired timestamps and empty keys.
    pub fn prune(&mut self, now: DateTime<Utc>) {
        let cutoff = now - self.findtime;
        self.hits.retain(|_, e| {
            e.hits.retain(|t| *t >= cutoff);
            !e.hits.is_empty()
        });
        self.compact();
    }

    pub fn reset(&mut self, key: &IpKey) {
        self.hits.remove(key);
    }

    /// Keys currently tracked.
    pub fn len(&self) -> usize {
        self.hits.len()
    }

    /// Keys forgotten because the tracker was full (since start).
    pub fn evicted(&self) -> u64 {
        self.evicted
    }

    /// Drops places of keys no longer tracked once they dominate `order`.
    fn compact(&mut self) {
        if self.order.len() > 2 * self.hits.len() + 64 {
            let hits = &self.hits;
            self.order
                .retain(|(k, g)| hits.get(k).is_some_and(|e| e.generation == *g));
        }
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

    /// Regression: an expired event behind a newer one (out of order, two
    /// sources) still counted.
    #[test]
    fn out_of_order_events_expire() {
        let start = Utc::now();
        let k = key("192.0.2.1");
        let mut t = Tracker::new(3, Duration::from_secs(60), 10);
        let at50 = start + TimeDelta::seconds(50);
        assert!(!t.record(k, at50, at50));
        assert!(!t.record(k, start, at50), "older, still in the window");
        // at +100 s the event from `start` has expired although it sits
        // behind the one from +50 s
        let later = start + TimeDelta::seconds(100);
        assert!(!t.record(k, later, later), "only 2 of 3 in the window");
    }

    #[test]
    fn old_events_ignored() {
        let mut t = Tracker::new(1, Duration::from_secs(60), 10);
        let now = Utc::now();
        assert!(!t.record(key("192.0.2.1"), now - TimeDelta::hours(1), now));
    }

    #[test]
    fn bounded_evicts_the_oldest() {
        let mut t = Tracker::new(2, Duration::from_secs(60), 2);
        let now = Utc::now();
        t.record(key("192.0.2.1"), now, now);
        t.record(key("192.0.2.2"), now, now);
        t.record(key("192.0.2.3"), now, now);
        assert_eq!((t.len(), t.evicted()), (2, 1));
        // .1 was evicted: one more failure does not ban it; .3 is counted
        assert!(!t.record(key("192.0.2.1"), now, now));
        assert!(t.record(key("192.0.2.3"), now, now));
    }

    #[test]
    fn full_tracker_prunes_expired_before_evicting() {
        let mut t = Tracker::new(5, Duration::from_secs(60), 2);
        let start = Utc::now();
        t.record(key("192.0.2.1"), start, start);
        t.record(key("192.0.2.2"), start, start);
        let later = start + TimeDelta::seconds(120);
        t.record(key("192.0.2.3"), later, later);
        assert_eq!((t.len(), t.evicted()), (1, 0), "expired keys made room");
    }

    #[test]
    fn stale_order_entries_are_skipped_and_compacted() {
        let mut t = Tracker::new(1, Duration::from_secs(60), 2);
        let now = Utc::now();
        // maxretry 1: every key triggers and leaves at once
        for i in 0..1000u32 {
            assert!(t.record(key(&format!("10.0.{}.{}", i / 256, i % 256)), now, now));
        }
        assert_eq!(t.len(), 0);
        t.prune(now);
        assert!(t.order.len() <= 64, "compacted: {}", t.order.len());
        // a key removed and tracked again is not evicted by its old place
        let mut t = Tracker::new(5, Duration::from_secs(60), 2);
        t.record(key("192.0.2.1"), now, now);
        t.reset(&key("192.0.2.1"));
        t.record(key("192.0.2.2"), now, now);
        t.record(key("192.0.2.1"), now, now);
        t.record(key("192.0.2.3"), now, now);
        assert_eq!(t.evicted(), 1);
        assert!(
            t.hits.contains_key(&key("192.0.2.1")),
            "newer place kept it"
        );
        assert!(!t.hits.contains_key(&key("192.0.2.2")));
    }
}

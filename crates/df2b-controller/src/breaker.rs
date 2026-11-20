//! Circuit breaker for automatic bans (DESIGN.md §4.5).
//!
//! A runaway correlation rule, a broken filter on many agents or one agent
//! reporting garbage can turn into thousands of fleet-wide bans within
//! minutes. The breaker counts the automatic bans the controller
//! distributes (agent propagation and correlation rules, not bans a person
//! makes) and trips when more than `max` arrive within `window`. While
//! tripped, further automatic bans are held back (not recorded, so not
//! distributed; the agents still enforce their own local bans) until an
//! admin resets it. The tripped state is stored, so a restart does not
//! silently resume.

use std::collections::VecDeque;
use std::time::Duration;

use chrono::{DateTime, TimeDelta, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};

/// Held bans listed for the investigation (newest first).
pub const MAX_HELD_SAMPLES: usize = 20;

#[derive(Debug, Clone, Copy, PartialEq, Serialize)]
pub struct BreakerLimit {
    /// Automatic bans per window; 0 = no breaker.
    pub max: u32,
    #[serde(with = "humantime_serde")]
    pub window: Duration,
}

impl Default for BreakerLimit {
    fn default() -> Self {
        Self {
            max: 1000,
            window: Duration::from_secs(600),
        }
    }
}

/// A held-back ban (for the admin deciding whether to reset).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Held {
    pub target: IpNet,
    /// "agent:<id>" or "rule:<name>"
    pub origin: String,
    pub at: DateTime<Utc>,
}

/// Stored while tripped.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Tripped {
    pub at: DateTime<Utc>,
    /// Bans held back since.
    pub held: u64,
    pub samples: VecDeque<Held>,
}

#[derive(Debug, Default)]
pub struct Breaker {
    pub limit: BreakerLimit,
    /// When the automatic bans of the current window were made.
    recent: VecDeque<DateTime<Utc>>,
    pub tripped: Option<Tripped>,
}

#[derive(Debug, PartialEq)]
pub enum Admit {
    Pass,
    /// Held back; `true` if this one tripped the breaker.
    Held(bool),
}

impl Breaker {
    pub fn new(limit: BreakerLimit, tripped: Option<Tripped>) -> Self {
        Self {
            limit,
            recent: VecDeque::new(),
            tripped,
        }
    }

    /// One automatic ban about to be made.
    pub fn admit(&mut self, held: Held) -> Admit {
        let now = held.at;
        if let Some(t) = &mut self.tripped {
            t.held = t.held.saturating_add(1);
            t.samples.push_front(held);
            t.samples.truncate(MAX_HELD_SAMPLES);
            return Admit::Held(false);
        }
        if self.limit.max == 0 {
            return Admit::Pass;
        }
        let since = now - TimeDelta::from_std(self.limit.window).unwrap_or(TimeDelta::MAX);
        while self.recent.front().is_some_and(|t| *t <= since) {
            self.recent.pop_front();
        }
        if self.recent.len() >= self.limit.max as usize {
            self.recent.clear();
            self.tripped = Some(Tripped {
                at: now,
                held: 1,
                samples: VecDeque::from([held]),
            });
            return Admit::Held(true);
        }
        self.recent.push_back(now);
        Admit::Pass
    }

    /// Closes it again; returns what it held back.
    pub fn reset(&mut self) -> Option<Tripped> {
        self.recent.clear();
        self.tripped.take()
    }

    /// Automatic bans in the current window (`now`).
    pub fn recent(&self, now: DateTime<Utc>) -> usize {
        let since = now - TimeDelta::from_std(self.limit.window).unwrap_or(TimeDelta::MAX);
        self.recent.iter().filter(|t| **t > since).count()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn held(at: DateTime<Utc>, i: u32) -> Held {
        Held {
            target: IpNet::from(std::net::IpAddr::V4((0xc000_0200 + i).into())),
            origin: "rule:r".into(),
            at,
        }
    }

    #[test]
    fn trips_holds_and_resets() {
        let t0: DateTime<Utc> = "2026-11-20T10:00:00Z".parse().unwrap();
        let mut b = Breaker::new(
            BreakerLimit {
                max: 3,
                window: Duration::from_secs(60),
            },
            None,
        );
        for i in 0..3 {
            assert_eq!(b.admit(held(t0, i)), Admit::Pass);
        }
        assert_eq!(b.recent(t0), 3);
        // the window moves on: room again
        let t1 = t0 + TimeDelta::seconds(61);
        assert_eq!(b.admit(held(t1, 3)), Admit::Pass);
        assert_eq!(b.admit(held(t1, 4)), Admit::Pass);
        assert_eq!(b.admit(held(t1, 5)), Admit::Pass);
        // the fourth within a minute trips it
        assert_eq!(b.admit(held(t1, 6)), Admit::Held(true));
        // everything after is held, even much later
        let t2 = t1 + TimeDelta::days(1);
        for i in 7..40 {
            assert_eq!(b.admit(held(t2, i)), Admit::Held(false));
        }
        let t = b.tripped.as_ref().unwrap();
        assert_eq!((t.at, t.held), (t1, 34));
        assert_eq!(t.samples.len(), MAX_HELD_SAMPLES);
        assert_eq!(t.samples[0].target.to_string(), "192.0.2.39/32");
        // reset: closed, counting from zero
        assert_eq!(b.reset().unwrap().held, 34);
        assert!(b.tripped.is_none());
        for i in 0..3 {
            assert_eq!(b.admit(held(t2, i)), Admit::Pass);
        }
    }

    #[test]
    fn off() {
        let mut b = Breaker::new(
            BreakerLimit {
                max: 0,
                window: Duration::from_secs(60),
            },
            None,
        );
        let t0 = Utc::now();
        for i in 0..10_000 {
            assert_eq!(b.admit(held(t0, i)), Admit::Pass);
        }
        assert!(b.recent.is_empty(), "nothing kept when off");
    }
}

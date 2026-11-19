//! Reconcile loop: the firewall should hold exactly the bans the agent
//! knows about (jail bans, manual bans, controller bans). Someone flushing
//! the table, a host firewall reload or a failed `nft` call would otherwise
//! go unnoticed until the agent restarts.
//!
//! Every few minutes the main loop collects what it expects and a blocking
//! task lists the firewall's sets: missing prefixes are added again with
//! their remaining time, prefixes nobody claims are removed. If the sets
//! cannot be listed and the backend's check fails too (table gone), the
//! table is set up again and everything is re-added. Only presence is
//! compared, not remaining timeouts.
//!
//! Bans applied or lifted while a round runs can look missing or
//! unexpected for that round; re-adding an existing element and removing
//! a missing one are both harmless, and the next round sees them settled.

use std::collections::{HashMap, HashSet};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use df2b_firewall::{BanEntry, FirewallBackend};
use ipnet::IpNet;
use tracing::{info, warn};

pub const INTERVAL: Duration = Duration::from_secs(300);
/// Bans ending sooner are not re-added (they would be gone right away).
const MIN_REMAINING: chrono::TimeDelta = chrono::TimeDelta::seconds(10);

/// Prefix → expiry (`None` = permanent); the longest one wins.
#[derive(Debug, Default, Clone)]
pub struct Expected(HashMap<IpNet, Option<DateTime<Utc>>>);

impl Expected {
    pub fn add(&mut self, net: IpNet, until: Option<DateTime<Utc>>) {
        let e = self.0.entry(net).or_insert(until);
        *e = match (*e, until) {
            (None, _) | (_, None) => None,
            (Some(a), Some(b)) => Some(a.max(b)),
        };
    }
}

#[derive(Debug, Default, PartialEq)]
pub struct Plan {
    pub add: Vec<BanEntry>,
    pub remove: Vec<IpNet>,
}

pub fn plan(expected: &Expected, actual: &[IpNet], now: DateTime<Utc>) -> Plan {
    let have: HashSet<IpNet> = actual.iter().copied().collect();
    let mut add: Vec<BanEntry> = expected
        .0
        .iter()
        .filter(|(net, _)| !have.contains(net))
        .filter_map(|(net, until)| match until {
            None => Some(BanEntry {
                net: *net,
                timeout: None,
            }),
            Some(u) if *u - now > MIN_REMAINING => Some(BanEntry {
                net: *net,
                timeout: (*u - now).to_std().ok(),
            }),
            Some(_) => None,
        })
        .collect();
    let mut remove: Vec<IpNet> = have
        .into_iter()
        .filter(|n| !expected.0.contains_key(n))
        .collect();
    add.sort_by_key(|e| e.net);
    remove.sort();
    Plan { add, remove }
}

/// One round. Blocking (runs `nft`). `Ok(None)`: the backend cannot list.
pub fn run(
    backend: &Arc<dyn FirewallBackend>,
    expected: &Expected,
    now: DateTime<Utc>,
) -> anyhow::Result<Option<Plan>> {
    let actual = match backend.list() {
        Ok(None) => return Ok(None),
        Ok(Some(a)) => a,
        Err(e) => {
            // the table itself gone? then set it up again; else try later
            if backend.check().is_ok() {
                return Err(e.context("listing the firewall sets"));
            }
            warn!(error = %format!("{e:#}"), "firewall table missing, setting it up again");
            backend.ensure_setup()?;
            Vec::new()
        }
    };
    let p = plan(expected, &actual, now);
    if !p.remove.is_empty() {
        backend.unban(&p.remove)?;
    }
    if !p.add.is_empty() {
        backend.ban(&p.add)?;
    }
    if !p.add.is_empty() || !p.remove.is_empty() {
        info!(
            readded = p.add.len(),
            removed = p.remove.len(),
            "firewall reconciled with the agent's bans"
        );
    }
    Ok(Some(p))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    fn net(s: &str) -> IpNet {
        s.parse().unwrap()
    }

    #[test]
    fn plans_missing_and_unexpected() {
        let now = Utc::now();
        let mut e = Expected::default();
        e.add(net("192.0.2.1/32"), Some(now + chrono::TimeDelta::hours(1)));
        e.add(net("192.0.2.1/32"), Some(now + chrono::TimeDelta::hours(2)));
        e.add(
            net("192.0.2.2/32"),
            Some(now + chrono::TimeDelta::seconds(3)),
        );
        e.add(
            net("2001:db8::/64"),
            Some(now + chrono::TimeDelta::hours(1)),
        );
        e.add(net("2001:db8::/64"), None);
        e.add(net("198.51.100.0/24"), None);
        let actual = [net("198.51.100.0/24"), net("203.0.113.9/32")];
        let p = plan(&e, &actual, now);
        let added: Vec<_> = p
            .add
            .iter()
            .map(|b| (b.net.to_string(), b.timeout.map(|t| t.as_secs() / 60)))
            .collect();
        assert_eq!(
            added,
            [
                ("192.0.2.1/32".to_string(), Some(120)),
                ("2001:db8::/64".to_string(), None)
            ],
            "longest expiry wins, permanent beats any; ending soon is skipped"
        );
        assert_eq!(p.remove, [net("203.0.113.9/32")]);
        assert_eq!(
            plan(
                &e,
                &[
                    net("192.0.2.1/32"),
                    net("192.0.2.2/32"),
                    net("2001:db8::/64"),
                    net("198.51.100.0/24")
                ],
                now
            ),
            Plan::default()
        );
    }

    /// Lists what it holds; `lost` makes list and check fail once.
    #[derive(Default)]
    struct Fake {
        set: Mutex<HashSet<IpNet>>,
        lost: Mutex<bool>,
        setups: Mutex<u32>,
    }
    impl FirewallBackend for Fake {
        fn name(&self) -> &'static str {
            "fake"
        }
        fn ensure_setup(&self) -> anyhow::Result<()> {
            *self.lost.lock().unwrap() = false;
            *self.setups.lock().unwrap() += 1;
            self.set.lock().unwrap().clear();
            Ok(())
        }
        fn ban(&self, entries: &[BanEntry]) -> anyhow::Result<()> {
            self.set
                .lock()
                .unwrap()
                .extend(entries.iter().map(|e| e.net));
            Ok(())
        }
        fn unban(&self, nets: &[IpNet]) -> anyhow::Result<()> {
            let mut s = self.set.lock().unwrap();
            nets.iter().for_each(|n| {
                s.remove(n);
            });
            Ok(())
        }
        fn check(&self) -> anyhow::Result<()> {
            if *self.lost.lock().unwrap() {
                anyhow::bail!("no such table")
            }
            Ok(())
        }
        fn list(&self) -> anyhow::Result<Option<Vec<IpNet>>> {
            self.check()?;
            Ok(Some(self.set.lock().unwrap().iter().copied().collect()))
        }
    }

    #[test]
    fn rounds() {
        let now = Utc::now();
        let fake = Arc::new(Fake::default());
        let b: Arc<dyn FirewallBackend> = fake.clone();
        let mut e = Expected::default();
        e.add(net("192.0.2.1/32"), None);
        fake.set.lock().unwrap().insert(net("203.0.113.9/32"));
        let p = run(&b, &e, now).unwrap().unwrap();
        assert_eq!((p.add.len(), p.remove.len()), (1, 1));
        assert_eq!(
            *fake.set.lock().unwrap(),
            HashSet::from([net("192.0.2.1/32")])
        );
        // settled: nothing to do
        assert_eq!(run(&b, &e, now).unwrap().unwrap(), Plan::default());
        // table gone: set up again, everything re-added
        *fake.lost.lock().unwrap() = true;
        let p = run(&b, &e, now).unwrap().unwrap();
        assert_eq!((p.add.len(), *fake.setups.lock().unwrap()), (1, 1));
        assert!(fake.set.lock().unwrap().contains(&net("192.0.2.1/32")));
        // a backend that cannot list
        let dry: Arc<dyn FirewallBackend> = Arc::new(df2b_firewall::DryRun);
        assert!(run(&dry, &e, now).unwrap().is_none());
    }
}

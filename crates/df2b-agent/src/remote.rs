//! Bans received from the controller, and what applying them means for the
//! local firewall.
//!
//! Local and remote bans share the firewall sets. A remote ban that goes away
//! (snapshot without it) is only removed from the firewall if no other
//! remote decision and no local ban still covers the same prefix. An
//! explicit unban decision also ends local bans of that prefix.

use std::collections::HashMap;
use std::time::Duration;

use chrono::{DateTime, Utc};
use df2b_firewall::BanEntry;
use ipnet::IpNet;
use uuid::Uuid;

use crate::link::{FromController, RemoteDecision, RemoteKind};

#[derive(Debug, Clone)]
struct RemoteBan {
    target: IpNet,
    expires_at: Option<DateTime<Utc>>,
    /// From this agent's own report (also counted as a local ban).
    own: bool,
}

/// What the main loop has to do after applying controller events.
#[derive(Debug, Default, PartialEq, Eq)]
pub struct Changes {
    pub ban: Vec<BanEntry>,
    pub unban: Vec<IpNet>,
    /// Prefixes whose local bans must be lifted (unban decisions).
    pub lift: Vec<IpNet>,
}

#[cfg(test)]
impl Changes {
    pub fn is_empty(&self) -> bool {
        self.ban.is_empty() && self.unban.is_empty() && self.lift.is_empty()
    }
}

#[derive(Debug, Default)]
pub struct RemoteBans {
    bans: HashMap<Uuid, RemoteBan>,
}

fn timeout(expires_at: Option<DateTime<Utc>>, now: DateTime<Utc>) -> Option<Duration> {
    expires_at.map(|e| (e - now).to_std().unwrap_or(Duration::ZERO))
}

fn is_active(d: &RemoteDecision, now: DateTime<Utc>) -> bool {
    d.kind == RemoteKind::Ban && d.expires_at.map_or(true, |e| e > now)
}

impl RemoteBans {
    /// Remote bans that did not originate here (local ones are counted by
    /// the engine).
    pub fn len(&self) -> usize {
        self.bans.values().filter(|b| !b.own).count()
    }

    /// Whether a controller ban (including this agent's own, propagated
    /// ones) still covers exactly this prefix.
    pub fn covers(&self, net: &IpNet) -> bool {
        self.covered(net)
    }

    fn covered(&self, net: &IpNet) -> bool {
        self.bans.values().any(|b| b.target == *net)
    }

    /// `locally_banned` tells whether the local engine still bans a prefix.
    pub fn apply(
        &mut self,
        ev: FromController,
        now: DateTime<Utc>,
        locally_banned: impl Fn(&IpNet) -> bool,
    ) -> Changes {
        let mut c = Changes::default();
        match ev {
            FromController::Snapshot(list) => {
                let mut fresh = HashMap::new();
                for d in list.into_iter().filter(|d| is_active(d, now)) {
                    // own bans are already in the firewall; reconnects
                    // re-send what this agent already applied
                    if !d.own && !self.bans.contains_key(&d.id) {
                        c.ban.push(BanEntry {
                            net: d.target,
                            timeout: timeout(d.expires_at, now),
                        });
                    }
                    fresh.insert(
                        d.id,
                        RemoteBan {
                            target: d.target,
                            expires_at: d.expires_at,
                            own: d.own,
                        },
                    );
                }
                let old = std::mem::replace(&mut self.bans, fresh);
                for (id, b) in old {
                    if !self.bans.contains_key(&id)
                        && !self.covered(&b.target)
                        && !locally_banned(&b.target)
                        && !c.unban.contains(&b.target)
                    {
                        c.unban.push(b.target);
                    }
                }
            }
            FromController::Decision(d) => match d.kind {
                RemoteKind::Ban if is_active(&d, now) => {
                    if !d.own {
                        c.ban.push(BanEntry {
                            net: d.target,
                            timeout: timeout(d.expires_at, now),
                        });
                    }
                    self.bans.insert(
                        d.id,
                        RemoteBan {
                            target: d.target,
                            expires_at: d.expires_at,
                            own: d.own,
                        },
                    );
                }
                RemoteKind::Unban { revokes } => {
                    if let Some(b) = self.bans.remove(&revokes) {
                        c.lift.push(b.target);
                        if !self.covered(&b.target) {
                            c.unban.push(b.target);
                        }
                    }
                }
                // "allow for X" is a temporary entry of the central
                // allowlist (FromController::Allowlist); Allow decisions
                // are not produced by the controller
                RemoteKind::Ban | RemoteKind::Allow => {}
            },
            // handled by the main loop (engine + firewall)
            FromController::Allowlist(_) => {}
        }
        c
    }

    /// Forgets expired bans (the kernel already removed them).
    pub fn prune(&mut self, now: DateTime<Utc>) {
        self.bans
            .retain(|_, b| b.expires_at.map_or(true, |e| e > now));
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ban(n: u128, target: &str, own: bool) -> RemoteDecision {
        RemoteDecision {
            seq: n as u64,
            id: Uuid::from_u128(n),
            kind: RemoteKind::Ban,
            target: target.parse().unwrap(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            own,
        }
    }

    fn nets(v: &[BanEntry]) -> Vec<String> {
        v.iter().map(|e| e.net.to_string()).collect()
    }

    #[test]
    fn snapshot_replaces_state() {
        let mut r = RemoteBans::default();
        let now = Utc::now();
        let c = r.apply(
            FromController::Snapshot(vec![
                ban(1, "203.0.113.1/32", false),
                ban(2, "203.0.113.2/32", true),
                ban(3, "203.0.113.3/32", false),
            ]),
            now,
            |_| false,
        );
        assert_eq!(
            nets(&c.ban),
            ["203.0.113.1/32", "203.0.113.3/32"],
            "own bans skipped"
        );
        assert!(c.ban[0].timeout.unwrap() > Duration::from_secs(3500));

        // reconnect: 1 still there (not re-applied), 3 gone, 2 gone but
        // still banned locally, 4 new
        let c = r.apply(
            FromController::Snapshot(vec![
                ban(1, "203.0.113.1/32", false),
                ban(4, "203.0.113.4/32", false),
            ]),
            now,
            |n| n.to_string() == "203.0.113.2/32",
        );
        assert_eq!(nets(&c.ban), ["203.0.113.4/32"]);
        assert_eq!(c.unban, vec!["203.0.113.3/32".parse::<IpNet>().unwrap()]);
        assert_eq!(r.len(), 2);
    }

    #[test]
    fn unban_lifts_and_respects_overlaps() {
        let mut r = RemoteBans::default();
        let now = Utc::now();
        for d in [
            ban(1, "198.51.100.7/32", false),
            ban(2, "198.51.100.7/32", false),
        ] {
            r.apply(FromController::Decision(d), now, |_| false);
        }
        let unban = |revokes| RemoteDecision {
            kind: RemoteKind::Unban {
                revokes: Uuid::from_u128(revokes),
            },
            ..ban(9, "198.51.100.7/32", false)
        };
        // another active decision covers the same target: no firewall unban
        let c = r.apply(FromController::Decision(unban(1)), now, |_| false);
        assert!(c.unban.is_empty());
        assert_eq!(c.lift.len(), 1);
        let c = r.apply(FromController::Decision(unban(2)), now, |_| false);
        assert_eq!(c.unban.len(), 1);
        // unknown decision: nothing to do
        assert!(r
            .apply(FromController::Decision(unban(7)), now, |_| false)
            .is_empty());

        let mut expired = ban(5, "192.0.2.1/32", false);
        expired.expires_at = Some(now - chrono::Duration::seconds(1));
        assert!(r
            .apply(FromController::Decision(expired), now, |_| false)
            .is_empty());
    }
}

//! Firewall backends.
//!
//! Backends are synchronous; callers run them via `spawn_blocking`.

use std::time::Duration;

use ipnet::IpNet;

pub mod dry_run;
pub mod nftables;

pub use dry_run::DryRun;
pub use nftables::Nftables;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct BanEntry {
    pub net: IpNet,
    /// `None` = permanent.
    pub timeout: Option<Duration>,
}

/// Prepares a batch for interval sets, where an element overlapping
/// another fails the transaction: equal prefixes are merged (the longer
/// timeout wins, permanent beats any) and prefixes inside a wider one of
/// the batch are dropped. CIDR prefixes either nest or are disjoint. A
/// narrower ban that outlives the wider one is added again by the agent's
/// reconcile loop once the wider one expired.
pub fn normalize(entries: &[BanEntry]) -> Vec<BanEntry> {
    let longer = |a: Option<Duration>, b: Option<Duration>| match (a, b) {
        (None, _) | (_, None) => None,
        (Some(a), Some(b)) => Some(a.max(b)),
    };
    let mut v: Vec<BanEntry> = entries
        .iter()
        .map(|e| BanEntry {
            net: e.net.trunc(),
            timeout: e.timeout,
        })
        .collect();
    // wider first, so contained ones come after their container
    v.sort_by_key(|e| (matches!(e.net, IpNet::V6(_)), e.net.prefix_len(), e.net));
    let mut out: Vec<BanEntry> = Vec::with_capacity(v.len());
    for e in v {
        if let Some(same) = out.iter_mut().find(|o| o.net == e.net) {
            same.timeout = longer(same.timeout, e.timeout);
        } else if !out.iter().any(|o| o.net.contains(&e.net)) {
            out.push(e);
        }
    }
    out
}

/// Against the elements already in a set: entries an existing element
/// covers (equal or wider) are skipped, existing elements inside a new
/// wider entry are deleted first. Returns (delete, add).
pub fn resolve(existing: &[IpNet], entries: &[BanEntry]) -> (Vec<IpNet>, Vec<BanEntry>) {
    let mut delete = Vec::new();
    let mut add = Vec::new();
    for e in normalize(entries) {
        if existing.iter().any(|x| x.contains(&e.net)) {
            continue;
        }
        for x in existing.iter().filter(|x| e.net.contains(*x)) {
            if !delete.contains(x) {
                delete.push(*x);
            }
        }
        add.push(e);
    }
    (delete, add)
}

pub trait FirewallBackend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Creates tables/sets/chains. Called once at startup; may reset state,
    /// the caller re-applies active bans afterwards.
    fn ensure_setup(&self) -> anyhow::Result<()>;

    fn ban(&self, entries: &[BanEntry]) -> anyhow::Result<()>;

    fn unban(&self, nets: &[IpNet]) -> anyhow::Result<()>;

    /// Checks that the backend still works and its rules are in place (the
    /// table may have been flushed by someone else). Called periodically.
    fn check(&self) -> anyhow::Result<()> {
        Ok(())
    }

    /// The prefixes currently banned, for reconciling. `Ok(None)`: the
    /// backend cannot tell (then nothing is reconciled).
    fn list(&self) -> anyhow::Result<Option<Vec<IpNet>>> {
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn e(net: &str, secs: Option<u64>) -> BanEntry {
        BanEntry {
            net: net.parse().unwrap(),
            timeout: secs.map(Duration::from_secs),
        }
    }

    #[test]
    fn normalize_drops_contained_and_merges_equal() {
        let out = normalize(&[
            e("192.0.2.7/32", Some(60)),
            e("192.0.2.0/24", Some(30)),
            e("198.51.100.1/32", Some(10)),
            e("198.51.100.1/32", None),
            e("2001:db8::1/128", Some(5)),
            e("2001:db8::/64", Some(5)),
            e("2001:db8:1::/64", Some(5)),
            e("192.0.2.9/24", Some(90)), // not truncated: same as the /24
        ]);
        let got: Vec<_> = out
            .iter()
            .map(|b| (b.net.to_string(), b.timeout.map(|t| t.as_secs())))
            .collect();
        assert_eq!(
            got,
            [
                ("192.0.2.0/24".to_string(), Some(90)),
                ("198.51.100.1/32".to_string(), None),
                ("2001:db8::/64".to_string(), Some(5)),
                ("2001:db8:1::/64".to_string(), Some(5)),
            ]
        );
    }

    #[test]
    fn resolve_against_existing() {
        let existing: Vec<IpNet> = ["192.0.2.0/24", "198.51.100.5/32", "198.51.100.6/32"]
            .iter()
            .map(|s| s.parse().unwrap())
            .collect();
        let (delete, add) = resolve(
            &existing,
            &[
                e("192.0.2.7/32", Some(60)),    // covered: skipped
                e("198.51.100.0/24", Some(60)), // wider: replaces .5 and .6
                e("203.0.113.1/32", None),      // unrelated
            ],
        );
        assert_eq!(
            delete,
            vec![
                "198.51.100.5/32".parse::<IpNet>().unwrap(),
                "198.51.100.6/32".parse().unwrap()
            ]
        );
        let add: Vec<_> = add.iter().map(|b| b.net.to_string()).collect();
        assert_eq!(add, ["198.51.100.0/24", "203.0.113.1/32"]);
    }
}

//! Networks that must never be banned.

use std::net::IpAddr;

use ipnet::IpNet;

/// Set of never-ban networks.
///
/// TODO: replace the linear scan with a prefix trie once lists get large.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    nets: Vec<IpNet>,
}

impl Allowlist {
    pub fn new(nets: impl IntoIterator<Item = IpNet>) -> Self {
        Self {
            nets: nets.into_iter().map(|n| n.trunc()).collect(),
        }
    }

    pub fn contains_addr(&self, addr: &IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(addr))
    }

    /// True if banning `net` would affect any allowlisted address.
    pub fn overlaps(&self, net: &IpNet) -> bool {
        self.nets.iter().any(|n| n.contains(net) || net.contains(n))
    }

    pub fn iter(&self) -> impl Iterator<Item = &IpNet> {
        self.nets.iter()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contains_and_overlaps() {
        let a = Allowlist::new([
            "10.0.0.0/8".parse().unwrap(),
            "2001:db8::5/128".parse().unwrap(),
        ]);
        assert!(a.contains_addr(&"10.1.2.3".parse().unwrap()));
        assert!(!a.contains_addr(&"11.1.2.3".parse().unwrap()));
        // a /64 ban containing an allowlisted /128 must be refused
        assert!(a.overlaps(&"2001:db8::/64".parse().unwrap()));
        assert!(!a.overlaps(&"2001:db8:1::/64".parse().unwrap()));
    }
}

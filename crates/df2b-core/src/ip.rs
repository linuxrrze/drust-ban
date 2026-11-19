//! IP address normalization.
//!
//! Offenders are tracked and banned by *prefix*, not by single address:
//! IPv4 defaults to /32, IPv6 to /64 (attackers trivially rotate addresses
//! inside a /64).

use std::fmt;
use std::net::IpAddr;

use ipnet::{IpNet, Ipv4Net, Ipv6Net};
use serde::{Deserialize, Serialize};

/// Prefix lengths used to aggregate addresses into tracking keys.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PrefixPolicy {
    pub v4: u8,
    pub v6: u8,
}

impl Default for PrefixPolicy {
    fn default() -> Self {
        Self { v4: 32, v6: 64 }
    }
}

/// A normalized network prefix identifying an offender.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct IpKey(IpNet);

impl IpKey {
    /// Normalizes an address according to `policy`.
    ///
    /// IPv4-mapped IPv6 addresses (`::ffff:a.b.c.d`) are treated as IPv4.
    pub fn from_addr(addr: IpAddr, policy: PrefixPolicy) -> Self {
        let net = match addr {
            IpAddr::V4(a) => IpNet::V4(
                Ipv4Net::new(a, policy.v4.min(32))
                    .expect("prefix length clamped to 32")
                    .trunc(),
            ),
            IpAddr::V6(a) => {
                if let Some(v4) = a.to_ipv4_mapped() {
                    return Self::from_addr(IpAddr::V4(v4), policy);
                }
                IpNet::V6(
                    Ipv6Net::new(a, policy.v6.min(128))
                        .expect("prefix length clamped to 128")
                        .trunc(),
                )
            }
        };
        Self(net)
    }

    pub fn net(&self) -> IpNet {
        self.0
    }

    pub fn contains(&self, addr: &IpAddr) -> bool {
        self.0.contains(addr)
    }
}

impl From<IpNet> for IpKey {
    fn from(net: IpNet) -> Self {
        Self(net.trunc())
    }
}

impl fmt::Display for IpKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.fmt(f)
    }
}

/// Parses a ban target given by a user: either a prefix (`2001:db8::/48`)
/// or a single address (`203.0.113.7`, interpreted as /32 or /128).
pub fn parse_target(s: &str) -> Result<IpNet, String> {
    if let Ok(net) = s.parse::<IpNet>() {
        return Ok(net.trunc());
    }
    s.parse::<IpAddr>()
        .map(IpNet::from)
        .map_err(|_| format!("not an IP address or prefix: {s}"))
}

/// Networks no ban may touch: loopback, unspecified ("this network"),
/// link-local, multicast and the IPv4 broadcast address (banning them
/// breaks the host itself, never an attacker).
pub fn reserved(net: &IpNet) -> bool {
    const RESERVED: [&str; 10] = [
        "0.0.0.0/8",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "224.0.0.0/4",
        "255.255.255.255/32",
        "::/128",
        "::1/128",
        "fe80::/10",
        "ff00::/8",
        "::ffff:127.0.0.0/104",
    ];
    RESERVED.iter().any(|r| {
        let r: IpNet = r.parse().expect("valid");
        r.contains(net) || net.contains(&r)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(s: &str) -> IpKey {
        IpKey::from_addr(s.parse().unwrap(), PrefixPolicy::default())
    }

    #[test]
    fn ipv4_is_host_prefix() {
        assert_eq!(key("203.0.113.7").to_string(), "203.0.113.7/32");
    }

    #[test]
    fn ipv6_is_aggregated_to_64() {
        assert_eq!(key("2001:db8::1"), key("2001:db8::ffff:1"));
        assert_ne!(key("2001:db8::1"), key("2001:db8:0:1::1"));
        assert_eq!(key("2001:db8::1").to_string(), "2001:db8::/64");
    }

    #[test]
    fn mapped_ipv4_is_ipv4() {
        assert_eq!(key("::ffff:203.0.113.7"), key("203.0.113.7"));
    }

    #[test]
    fn custom_policy() {
        let p = PrefixPolicy { v4: 24, v6: 48 };
        let k = IpKey::from_addr("198.51.100.77".parse().unwrap(), p);
        assert_eq!(k.to_string(), "198.51.100.0/24");
        assert!(k.contains(&"198.51.100.1".parse().unwrap()));
    }

    #[test]
    fn parse_targets() {
        assert_eq!(
            parse_target("203.0.113.7").unwrap().to_string(),
            "203.0.113.7/32"
        );
        assert_eq!(
            parse_target("2001:db8::1/48").unwrap().to_string(),
            "2001:db8::/48"
        );
        assert!(parse_target("example.org").is_err());
    }

    #[test]
    fn reserved_ranges() {
        for n in [
            "127.0.0.1/32",
            "64.0.0.0/2",
            "0.0.0.0/0",
            "::1/128",
            "fe80::1/128",
            "ff02::1/128",
            "224.0.0.0/24",
            "::/0",
            "::ffff:127.0.0.1/128",
        ] {
            assert!(reserved(&n.parse().unwrap()), "{n}");
        }
        for n in ["192.0.2.1/32", "203.0.113.0/24", "2001:db8::/48"] {
            assert!(!reserved(&n.parse().unwrap()), "{n}");
        }
    }
}

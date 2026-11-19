//! Networks that must never be banned.

use std::net::IpAddr;

use ipnet::IpNet;

/// Set of never-ban networks: a binary prefix trie per address family, so
/// lookups cost at most 32 / 128 steps however long the list is.
#[derive(Debug, Clone, Default)]
pub struct Allowlist {
    nets: Vec<IpNet>,
    v4: Trie,
    v6: Trie,
}

/// Nodes in an arena; index 0 is the root, child index 0 = none.
#[derive(Debug, Clone)]
struct Trie {
    nodes: Vec<Node>,
}

#[derive(Debug, Clone, Copy, Default)]
struct Node {
    child: [u32; 2],
    /// An allowlisted prefix ends here.
    term: bool,
}

impl Default for Trie {
    fn default() -> Self {
        Self {
            nodes: vec![Node::default()],
        }
    }
}

impl Trie {
    /// `bits`: the address left-aligned in a u128; `len`: prefix length.
    fn insert(&mut self, bits: u128, len: u8) {
        let mut n = 0usize;
        for i in 0..len {
            let b = ((bits >> (127 - i)) & 1) as usize;
            if self.nodes[n].child[b] == 0 {
                self.nodes.push(Node::default());
                self.nodes[n].child[b] = (self.nodes.len() - 1) as u32;
            }
            n = self.nodes[n].child[b] as usize;
        }
        self.nodes[n].term = true;
    }

    /// Whether an allowlisted prefix contains the prefix, or lies inside it.
    fn overlaps(&self, bits: u128, len: u8) -> bool {
        let mut n = 0usize;
        for i in 0..len {
            if self.nodes[n].term {
                return true; // an allowlisted prefix contains it
            }
            let b = ((bits >> (127 - i)) & 1) as usize;
            match self.nodes[n].child[b] {
                0 => return false,
                c => n = c as usize,
            }
        }
        // at its end: allowlisted itself, or something below it is
        self.nodes[n].term || self.nodes[n].child != [0, 0]
    }
}

fn key(net: &IpNet) -> (bool, u128, u8) {
    match net {
        IpNet::V4(n) => (
            false,
            (u32::from(n.network()) as u128) << 96,
            n.prefix_len(),
        ),
        IpNet::V6(n) => (true, u128::from(n.network()), n.prefix_len()),
    }
}

impl Allowlist {
    pub fn new(nets: impl IntoIterator<Item = IpNet>) -> Self {
        let mut a = Self::default();
        for n in nets {
            let n = crate::ip::unmap(n);
            let (v6, bits, len) = key(&n);
            if v6 { &mut a.v6 } else { &mut a.v4 }.insert(bits, len);
            a.nets.push(n);
        }
        a
    }

    pub fn contains_addr(&self, addr: &IpAddr) -> bool {
        self.overlaps(&IpNet::from(*addr))
    }

    /// True if banning `net` would affect any allowlisted address.
    pub fn overlaps(&self, net: &IpNet) -> bool {
        let (v6, bits, len) = key(&crate::ip::unmap(*net));
        if v6 { &self.v6 } else { &self.v4 }.overlaps(bits, len)
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
        // families are separate; /0 contains everything of its family
        assert!(!a.overlaps(&"::a00:0/104".parse().unwrap()));
        assert!(Allowlist::new(["0.0.0.0/0".parse().unwrap()])
            .contains_addr(&"192.0.2.1".parse().unwrap()));
        assert!(!Allowlist::default().overlaps(&"0.0.0.0/0".parse().unwrap()));
        assert!(a.overlaps(&"0.0.0.0/0".parse().unwrap()));
    }

    /// Same answers as a linear scan, on random lists and queries.
    #[test]
    fn matches_linear_scan() {
        let mut seed = 0x2545_f491_4f6c_dd1du64;
        let mut rnd = move || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            seed
        };
        // few distinct high bits so prefixes actually collide
        let net = |rnd: &mut dyn FnMut() -> u64| -> IpNet {
            let r = rnd();
            if r % 3 == 0 {
                let a = (r as u128) << 64 | 0x2001_0db8 << 96;
                IpNet::new(
                    std::net::Ipv6Addr::from(a & !(0xffff << 80)).into(),
                    (rnd() % 129) as u8,
                )
                .unwrap()
                .trunc()
            } else {
                let a = ((r >> 8) as u32) & 0xc0a8_f0ff | 0x0a00_0000;
                IpNet::new(std::net::Ipv4Addr::from(a).into(), (rnd() % 33) as u8)
                    .unwrap()
                    .trunc()
            }
        };
        let mut seen = [0u32; 2];
        for _ in 0..50 {
            let nets: Vec<IpNet> = (0..(rnd() % 40)).map(|_| net(&mut rnd)).collect();
            let a = Allowlist::new(nets.clone());
            for _ in 0..200 {
                let q = net(&mut rnd);
                let linear = nets.iter().any(|n| n.contains(&q) || q.contains(n));
                assert_eq!(a.overlaps(&q), linear, "{q} vs {nets:?}");
                seen[linear as usize] += 1;
            }
        }
        assert!(
            seen[0] > 500 && seen[1] > 500,
            "both outcomes exercised: {seen:?}"
        );
    }
}

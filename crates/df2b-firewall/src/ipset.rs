//! ipset + iptables backend, for hosts without nftables.
//!
//! Two `hash:net` sets with timeouts (`df2b4`, `df2b6`) and one DROP rule
//! per family at the top of INPUT (`iptables`/`ip6tables -m set`). Changes
//! go through `ipset restore` (one batch per call); `hash:net` stores
//! nested prefixes side by side, so there are no overlap conflicts.
//!
//! ipset timeouts are at most 2147483 s (~24.8 days): longer bans are added
//! without a timeout, and the agent's reconcile loop removes them once
//! they expired.

use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{bail, Context};
use ipnet::IpNet;

use crate::{BanEntry, FirewallBackend};

/// Longest timeout ipset accepts.
pub const MAX_TIMEOUT_SECS: u64 = 2_147_483;

#[derive(Debug, Clone)]
pub struct Ipset {
    prefix: String,
    ipset: PathBuf,
    iptables: PathBuf,
    ip6tables: PathBuf,
}

impl Default for Ipset {
    fn default() -> Self {
        Self::new("df2b", "ipset", "iptables", "ip6tables")
    }
}

impl Ipset {
    pub fn new(
        prefix: impl Into<String>,
        ipset: impl Into<PathBuf>,
        iptables: impl Into<PathBuf>,
        ip6tables: impl Into<PathBuf>,
    ) -> Self {
        Self {
            prefix: prefix.into(),
            ipset: ipset.into(),
            iptables: iptables.into(),
            ip6tables: ip6tables.into(),
        }
    }

    fn set(&self, net: &IpNet) -> String {
        match net {
            IpNet::V4(_) => format!("{}4", self.prefix),
            IpNet::V6(_) => format!("{}6", self.prefix),
        }
    }

    pub fn ban_script(&self, entries: &[BanEntry]) -> String {
        let mut s = String::new();
        for e in entries {
            // 0 = no timeout
            let t = e
                .timeout
                .map(|t| t.as_secs().max(1))
                .filter(|t| *t <= MAX_TIMEOUT_SECS)
                .unwrap_or(0);
            s += &format!(
                "add {} {} timeout {t} -exist\n",
                self.set(&e.net),
                e.net.trunc()
            );
        }
        s
    }

    pub fn unban_script(&self, nets: &[IpNet]) -> String {
        nets.iter()
            .map(|n| format!("del {} {} -exist\n", self.set(n), n.trunc()))
            .collect()
    }

    fn run(bin: &PathBuf, args: &[&str], stdin: Option<&str>) -> anyhow::Result<String> {
        let mut child = Command::new(bin)
            .args(args)
            .stdin(if stdin.is_some() {
                Stdio::piped()
            } else {
                Stdio::null()
            })
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning {}", bin.display()))?;
        if let Some(input) = stdin {
            child
                .stdin
                .take()
                .expect("piped")
                .write_all(input.as_bytes())?;
        }
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "{} {} failed: {}",
                bin.display(),
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn restore(&self, script: &str) -> anyhow::Result<()> {
        if script.is_empty() {
            return Ok(());
        }
        Self::run(&self.ipset, &["restore"], Some(script)).map(|_| ())
    }

    /// The INPUT rule for one family: (binary, set name).
    fn rules(&self) -> [(&PathBuf, String); 2] {
        [
            (&self.iptables, format!("{}4", self.prefix)),
            (&self.ip6tables, format!("{}6", self.prefix)),
        ]
    }

    fn rule_args<'a>(op: &'a str, set: &'a str) -> Vec<&'a str> {
        let mut v = vec![op, "INPUT"];
        if op == "-I" {
            v.push("1");
        }
        v.extend(["-m", "set", "--match-set", set, "src", "-j", "DROP"]);
        v
    }
}

impl FirewallBackend for Ipset {
    fn name(&self) -> &'static str {
        "ipset"
    }

    /// Creates the sets (empty) and the DROP rules if missing.
    fn ensure_setup(&self) -> anyhow::Result<()> {
        let p = &self.prefix;
        self.restore(&format!(
            "create {p}4 hash:net family inet timeout 0 maxelem 1000000 -exist\n\
             create {p}6 hash:net family inet6 timeout 0 maxelem 1000000 -exist\n\
             flush {p}4\nflush {p}6\n"
        ))?;
        for (bin, set) in self.rules() {
            if Self::run(bin, &Self::rule_args("-C", &set), None).is_err() {
                Self::run(bin, &Self::rule_args("-I", &set), None)?;
            }
        }
        Ok(())
    }

    fn ban(&self, entries: &[BanEntry]) -> anyhow::Result<()> {
        self.restore(&self.ban_script(entries))
    }

    fn unban(&self, nets: &[IpNet]) -> anyhow::Result<()> {
        self.restore(&self.unban_script(nets))
    }

    fn check(&self) -> anyhow::Result<()> {
        for (bin, set) in self.rules() {
            Self::run(&self.ipset, &["list", "-n", &set], None)
                .with_context(|| format!("set {set}"))?;
            Self::run(bin, &Self::rule_args("-C", &set), None)
                .with_context(|| format!("the DROP rule for {set} is missing"))?;
        }
        Ok(())
    }

    fn list(&self) -> anyhow::Result<Option<Vec<IpNet>>> {
        let mut out = Vec::new();
        for (_, set) in self.rules() {
            let saved = Self::run(&self.ipset, &["save", &set], None)?;
            out.extend(parse_save(&saved, &set)?);
        }
        Ok(Some(out))
    }
}

/// The members of `set` in `ipset save` output ("add <set> <net> ...").
pub fn parse_save(text: &str, set: &str) -> anyhow::Result<Vec<IpNet>> {
    let mut out = Vec::new();
    for line in text.lines() {
        let mut w = line.split_whitespace();
        if w.next() != Some("add") || w.next() != Some(set) {
            continue;
        }
        let member = w.next().context("ipset save: add without member")?;
        let net = match member.parse::<IpNet>() {
            Ok(n) => n,
            Err(_) => IpNet::from(
                member
                    .parse::<std::net::IpAddr>()
                    .with_context(|| format!("ipset save: {member:?}"))?,
            ),
        };
        out.push(net.trunc());
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn scripts() {
        let b = Ipset::default();
        let s = b.ban_script(&[
            BanEntry {
                net: "203.0.113.7/32".parse().unwrap(),
                timeout: Some(Duration::from_secs(3600)),
            },
            BanEntry {
                net: "2001:db8::/64".parse().unwrap(),
                timeout: None,
            },
            BanEntry {
                net: "198.51.100.0/24".parse().unwrap(),
                timeout: Some(Duration::from_secs(MAX_TIMEOUT_SECS + 1)),
            },
        ]);
        assert_eq!(
            s,
            "add df2b4 203.0.113.7/32 timeout 3600 -exist\n\
             add df2b6 2001:db8::/64 timeout 0 -exist\n\
             add df2b4 198.51.100.0/24 timeout 0 -exist\n"
        );
        assert_eq!(
            b.unban_script(&["192.0.2.1/32".parse().unwrap()]),
            "del df2b4 192.0.2.1/32 -exist\n"
        );
    }

    #[test]
    fn save_parsing() {
        let text = "create df2b4 hash:net family inet hashsize 1024 maxelem 1000000 timeout 0\n\
                    add df2b4 203.0.113.7 timeout 3412\n\
                    add df2b4 198.51.100.0/24 timeout 0\n\
                    add other 192.0.2.1\n";
        let got: Vec<String> = parse_save(text, "df2b4")
            .unwrap()
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(got, ["203.0.113.7/32", "198.51.100.0/24"]);
        assert!(parse_save("add df2b4 nonsense\n", "df2b4").is_err());
    }

    /// Stand-ins for ipset/iptables that log their calls; iptables -C
    /// fails until -I was called.
    #[test]
    fn setup_ban_check_list_with_stand_ins() {
        let dir = std::env::temp_dir().join(format!("df2b-ipset-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let log = dir.join("log");
        let write = |name: &str, body: String| {
            let p = dir.join(name);
            crate::testutil::write_script(&p, &body);
            p
        };
        let ipset = write(
            "ipset",
            format!(
                "echo \"ipset $*\" >> {log}\n\
                 case \"$1\" in restore) cat >> {log};; save) echo \"add $2 192.0.2.7 timeout 5\";; esac",
                log = log.display()
            ),
        );
        let tables = |name: &str| {
            write(
                name,
                format!(
                    "echo \"{name} $*\" >> {log}\n\
                     if [ \"$1\" = -C ]; then [ -f {d}/{name}.rule ] || exit 1; fi\n\
                     if [ \"$1\" = -I ]; then touch {d}/{name}.rule; fi",
                    log = log.display(),
                    d = dir.display()
                ),
            )
        };
        let b = Ipset::new("df2b", ipset, tables("iptables"), tables("ip6tables"));
        assert!(b.check().is_err(), "no rules yet");
        b.ensure_setup().unwrap();
        b.ensure_setup().unwrap(); // rules not inserted twice
        b.check().unwrap();
        b.ban(&[BanEntry {
            net: "192.0.2.7/32".parse().unwrap(),
            timeout: Some(Duration::from_secs(60)),
        }])
        .unwrap();
        let listed = b.list().unwrap().unwrap();
        assert_eq!(listed.len(), 2, "one per set from the stand-in");
        let log = std::fs::read_to_string(&log).unwrap();
        assert_eq!(
            log.matches("iptables -I INPUT 1 -m set --match-set df2b4 src -j DROP")
                .count(),
            1
        );
        assert_eq!(
            log.matches("ip6tables -I INPUT 1 -m set --match-set df2b6 src -j DROP")
                .count(),
            1
        );
        assert!(log.contains("create df2b6 hash:net family inet6 timeout 0 maxelem 1000000 -exist"));
        assert!(log.contains("add df2b4 192.0.2.7/32 timeout 60 -exist"));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

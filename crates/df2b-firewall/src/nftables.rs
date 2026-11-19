//! nftables backend using `nft -f -` batches (one atomic transaction each).
//!
//! Bans are elements of `ban_v4` / `ban_v6` sets with kernel-side timeouts,
//! so they expire even if the agent is down.
//!
//! Set contents are listed with `nft -j list set` for the agent's
//! reconcile loop.
//!
//! The sets are interval sets, where overlapping elements fail a
//! transaction: batches are normalized first (prefixes inside wider ones
//! dropped), and if a batch still fails, the set is listed and the batch
//! resolved against it (covered entries skipped, narrower elements
//! replaced by a wider new one, in one transaction).
//!
//! TODO: talk netlink directly (rustables).

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::PathBuf;
use std::process::{Command, Stdio};

use anyhow::{bail, Context};
use ipnet::IpNet;
use tracing::{debug, warn};

use crate::{BanEntry, FirewallBackend};

#[derive(Debug, Clone)]
pub struct Nftables {
    table: String,
    nft: PathBuf,
}

impl Default for Nftables {
    fn default() -> Self {
        Self {
            table: "df2b".into(),
            nft: PathBuf::from("nft"),
        }
    }
}

/// Timeouts at or above this are applied as permanent bans.
const MAX_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10 * 365 * 24 * 3600);

fn set_name(net: &IpNet) -> &'static str {
    match net {
        IpNet::V4(_) => "ban_v4",
        IpNet::V6(_) => "ban_v6",
    }
}

impl Nftables {
    pub fn new(table: impl Into<String>, nft: impl Into<PathBuf>) -> Self {
        Self {
            table: table.into(),
            nft: nft.into(),
        }
    }

    /// Recreates the table from scratch (`add` + `delete` makes this
    /// idempotent whether or not the table exists).
    pub fn setup_script(&self) -> String {
        let t = &self.table;
        format!(
            "add table inet {t}\n\
             delete table inet {t}\n\
             table inet {t} {{\n\
             \tset ban_v4 {{ type ipv4_addr; flags interval, timeout; }}\n\
             \tset ban_v6 {{ type ipv6_addr; flags interval, timeout; }}\n\
             \tchain input {{\n\
             \t\ttype filter hook input priority -10; policy accept;\n\
             \t\tip saddr @ban_v4 drop\n\
             \t\tip6 saddr @ban_v6 drop\n\
             \t}}\n\
             }}\n"
        )
    }

    pub fn ban_script(&self, entries: &[BanEntry]) -> String {
        let mut s = String::new();
        for e in entries {
            let _ = write!(
                s,
                "add element inet {} {} {{ {}",
                self.table,
                set_name(&e.net),
                e.net
            );
            // very long (e.g. uncapped escalation) = permanent
            if let Some(t) = e.timeout.filter(|t| *t < MAX_TIMEOUT) {
                let _ = write!(s, " timeout {}s", t.as_secs().max(1));
            }
            s.push_str(" }\n");
        }
        s
    }

    pub fn unban_script(&self, nets: &[IpNet]) -> String {
        let mut s = String::new();
        for n in nets {
            let _ = writeln!(
                s,
                "delete element inet {} {} {{ {} }}",
                self.table,
                set_name(n),
                n
            );
        }
        s
    }

    /// Runs `nft <args>` and returns its standard output.
    fn query(&self, args: &[&str]) -> anyhow::Result<String> {
        let out = Command::new(&self.nft)
            .args(args)
            .stdin(Stdio::null())
            .output()
            .with_context(|| format!("spawning {}", self.nft.display()))?;
        if !out.status.success() {
            bail!(
                "nft {} failed: {}",
                args.join(" "),
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(String::from_utf8_lossy(&out.stdout).into_owned())
    }

    fn run(&self, script: &str) -> anyhow::Result<()> {
        debug!(script, "nft -f -");
        let mut child = Command::new(&self.nft)
            .args(["-f", "-"])
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .with_context(|| format!("spawning {}", self.nft.display()))?;
        child
            .stdin
            .take()
            .expect("stdin is piped")
            .write_all(script.as_bytes())?;
        let out = child.wait_with_output()?;
        if !out.status.success() {
            bail!(
                "nft failed: {}",
                String::from_utf8_lossy(&out.stderr).trim()
            );
        }
        Ok(())
    }
}

impl FirewallBackend for Nftables {
    fn name(&self) -> &'static str {
        "nftables"
    }

    fn ensure_setup(&self) -> anyhow::Result<()> {
        self.run(&self.setup_script())
    }

    fn ban(&self, entries: &[BanEntry]) -> anyhow::Result<()> {
        let entries = crate::normalize(entries);
        if entries.is_empty() {
            return Ok(());
        }
        let Err(first) = self.run(&self.ban_script(&entries)) else {
            return Ok(());
        };
        // probably overlapping elements already in the set
        let existing = match self.list() {
            Ok(Some(e)) => e,
            _ => return Err(first),
        };
        let (delete, add) = crate::resolve(&existing, &entries);
        if add.is_empty() {
            return Ok(());
        }
        debug!(
            replaced = delete.len(),
            add = add.len(),
            "ban batch resolved against the sets"
        );
        self.run(&(self.unban_script(&delete) + &self.ban_script(&add)))
            .with_context(|| format!("after the first attempt failed: {first:#}"))
    }

    fn list(&self) -> anyhow::Result<Option<Vec<IpNet>>> {
        let mut out = Vec::new();
        for set in ["ban_v4", "ban_v6"] {
            let json = self.query(&["-j", "list", "set", "inet", &self.table, set])?;
            out.extend(parse_set(&json).with_context(|| format!("reading set {set}"))?);
        }
        Ok(Some(out))
    }

    /// The input chain (with its table and sets) must still exist.
    fn check(&self) -> anyhow::Result<()> {
        let out = self.query(&["list", "chain", "inet", &self.table, "input"])?;
        if !out.contains("@ban_v4") || !out.contains("@ban_v6") {
            bail!(
                "nftables chain inet {} input lost its drop rules",
                self.table
            );
        }
        Ok(())
    }

    fn unban(&self, nets: &[IpNet]) -> anyhow::Result<()> {
        if nets.is_empty() {
            return Ok(());
        }
        // A batch fails atomically if any element is missing (e.g. already
        // expired); fall back to one transaction per element.
        if self.run(&self.unban_script(nets)).is_ok() {
            return Ok(());
        }
        for n in nets {
            if let Err(e) = self.run(&self.unban_script(std::slice::from_ref(n))) {
                warn!(net = %n, error = %e, "unban failed (probably already expired)");
            }
        }
        Ok(())
    }
}

/// The elements of a set in `nft -j list set` output: plain addresses,
/// prefixes and ranges, each possibly wrapped in `{"elem": {"val": …}}`
/// (elements with a timeout).
pub fn parse_set(json: &str) -> anyhow::Result<Vec<IpNet>> {
    use serde_json::Value;
    fn addr(v: &Value) -> anyhow::Result<std::net::IpAddr> {
        v.as_str()
            .and_then(|s| s.parse().ok())
            .with_context(|| format!("not an address: {v}"))
    }
    fn elem(v: &Value, out: &mut Vec<IpNet>) -> anyhow::Result<()> {
        if let Some(inner) = v.get("elem") {
            return elem(&inner["val"], out);
        }
        if let Some(p) = v.get("prefix") {
            let len = p["len"].as_u64().context("prefix without len")? as u8;
            out.push(IpNet::new(addr(&p["addr"])?, len)?.trunc());
            return Ok(());
        }
        if let Some(r) = v.get("range").and_then(Value::as_array) {
            let (Some(a), Some(b)) = (r.first(), r.get(1)) else {
                bail!("bad range: {v}");
            };
            match (addr(a)?, addr(b)?) {
                (std::net::IpAddr::V4(a), std::net::IpAddr::V4(b)) => {
                    out.extend(ipnet::Ipv4Subnets::new(a, b, 0).map(IpNet::V4))
                }
                (std::net::IpAddr::V6(a), std::net::IpAddr::V6(b)) => {
                    out.extend(ipnet::Ipv6Subnets::new(a, b, 0).map(IpNet::V6))
                }
                _ => bail!("mixed range: {v}"),
            }
            return Ok(());
        }
        out.push(IpNet::from(addr(v)?));
        Ok(())
    }
    let v: Value = serde_json::from_str(json).context("nft JSON")?;
    let mut out = Vec::new();
    for item in v["nftables"].as_array().into_iter().flatten() {
        let Some(set) = item.get("set") else { continue };
        for e in set["elem"].as_array().into_iter().flatten() {
            elem(e, &mut out)?;
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Duration;

    #[test]
    fn scripts() {
        let nft = Nftables::default();
        let s = nft.ban_script(&[
            BanEntry {
                net: "203.0.113.7/32".parse().unwrap(),
                timeout: Some(Duration::from_secs(3600)),
            },
            BanEntry {
                net: "2001:db8::/64".parse().unwrap(),
                timeout: None,
            },
        ]);
        assert_eq!(
            s,
            "add element inet df2b ban_v4 { 203.0.113.7/32 timeout 3600s }\n\
             add element inet df2b ban_v6 { 2001:db8::/64 }\n"
        );
        assert_eq!(
            nft.unban_script(&["203.0.113.7/32".parse().unwrap()]),
            "delete element inet df2b ban_v4 { 203.0.113.7/32 }\n"
        );
        assert!(nft.setup_script().contains("ip6 saddr @ban_v6 drop"));
    }

    /// A stand-in `nft` that prints `out` (exit 0) or fails.
    fn fake_nft(tag: &str, script: &str) -> PathBuf {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("df2b-nft-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("nft");
        std::fs::write(&p, format!("#!/bin/sh\n{script}\n")).unwrap();
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o755)).unwrap();
        p
    }

    #[test]
    fn check() {
        let ok = fake_nft(
            "ok",
            "echo 'table inet df2b { chain input { ip saddr @ban_v4 drop; ip6 saddr @ban_v6 drop } }'",
        );
        assert!(Nftables::new("df2b", &ok).check().is_ok());
        let flushed = fake_nft("flushed", "echo 'table inet df2b { chain input { } }'");
        assert!(Nftables::new("df2b", &flushed).check().is_err());
        let gone = fake_nft("gone", "echo 'No such file or directory' >&2; exit 1");
        let e = Nftables::new("df2b", &gone)
            .check()
            .unwrap_err()
            .to_string();
        assert!(e.contains("No such file"), "{e}");
        assert!(Nftables::new("df2b", "/nonexistent/nft").check().is_err());
    }

    #[test]
    fn set_listing() {
        let json = r#"{"nftables": [
          {"metainfo": {"version": "1.0.9", "json_schema_version": 1}},
          {"set": {"family": "inet", "name": "ban_v4", "table": "df2b",
            "type": "ipv4_addr", "handle": 2, "flags": ["interval", "timeout"],
            "elem": [
              {"elem": {"val": "203.0.113.7", "timeout": 3600, "expires": 3412}},
              {"elem": {"val": {"prefix": {"addr": "198.51.100.0", "len": 24}}, "timeout": 7200, "expires": 7000}},
              {"prefix": {"addr": "192.0.2.0", "len": 25}},
              "192.0.2.200",
              {"range": ["10.0.0.0", "10.0.0.3"]}
            ]}}]}"#;
        let got: Vec<String> = parse_set(json)
            .unwrap()
            .iter()
            .map(|n| n.to_string())
            .collect();
        assert_eq!(
            got,
            [
                "203.0.113.7/32",
                "198.51.100.0/24",
                "192.0.2.0/25",
                "192.0.2.200/32",
                "10.0.0.0/30"
            ]
        );
        let empty = r#"{"nftables": [{"metainfo": {}}, {"set": {"name": "ban_v6", "elem": []}}]}"#;
        assert!(parse_set(empty).unwrap().is_empty());
        let v6 = r#"{"nftables": [{"set": {"elem": [{"elem": {"val": {"prefix": {"addr": "2001:db8::", "len": 64}}}}]}}]}"#;
        assert_eq!(parse_set(v6).unwrap()[0].to_string(), "2001:db8::/64");
        assert!(parse_set("not json").is_err());
        assert!(parse_set(r#"{"nftables": [{"set": {"elem": ["nonsense"]}}]}"#).is_err());
    }

    #[test]
    fn ban_resolves_overlaps_after_a_failed_batch() {
        let dir = std::env::temp_dir().join(format!("df2b-nft-overlap-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let json = r#"{"nftables": [{"set": {"elem": [{"elem": {"val": "198.51.100.5", "timeout": 60}}, {"prefix": {"addr": "192.0.2.0", "len": 24}}]}}]}"#;
        let nft = fake_nft(
            "overlap",
            &format!(
                "d={d}\nif [ \"$1\" = -j ]; then echo '{json}'; exit 0; fi\n\
                 n=$(ls $d | grep -c call)\ncat > $d/call$n\n\
                 if [ $n = 0 ]; then echo 'Error: interval overlaps with an existing one' >&2; exit 1; fi",
                d = dir.display()
            ),
        );
        let b = Nftables::new("df2b", &nft);
        b.ban(&[
            BanEntry {
                net: "192.0.2.7/32".parse().unwrap(),
                timeout: Some(Duration::from_secs(60)),
            },
            BanEntry {
                net: "198.51.100.0/24".parse().unwrap(),
                timeout: Some(Duration::from_secs(600)),
            },
        ])
        .unwrap();
        let second = std::fs::read_to_string(dir.join("call1")).unwrap();
        assert_eq!(
            second,
            "delete element inet df2b ban_v4 { 198.51.100.5/32 }\n\
             add element inet df2b ban_v4 { 198.51.100.0/24 timeout 600s }\n"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

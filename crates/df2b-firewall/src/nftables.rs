//! nftables backend using `nft -f -` batches (one atomic transaction each).
//!
//! Bans are elements of `ban_v4` / `ban_v6` sets with kernel-side timeouts,
//! so they expire even if the agent is down.
//!
//! TODO: talk netlink directly (rustables), list set contents for the
//! reconcile loop, merge overlapping intervals before adding.

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
        if entries.is_empty() {
            return Ok(());
        }
        self.run(&self.ban_script(entries))
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
}

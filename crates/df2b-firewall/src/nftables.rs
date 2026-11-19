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
}

use ipnet::IpNet;
use tracing::info;

use crate::{BanEntry, FirewallBackend};

/// Logs instead of touching the firewall. Useful for rollout and testing.
#[derive(Debug, Default)]
pub struct DryRun;

impl FirewallBackend for DryRun {
    fn name(&self) -> &'static str {
        "dry-run"
    }

    fn ensure_setup(&self) -> anyhow::Result<()> {
        info!("dry-run firewall backend: no changes will be made");
        Ok(())
    }

    fn ban(&self, entries: &[BanEntry]) -> anyhow::Result<()> {
        for e in entries {
            info!(net = %e.net, timeout = ?e.timeout, "[dry-run] ban");
        }
        Ok(())
    }

    fn unban(&self, nets: &[IpNet]) -> anyhow::Result<()> {
        for n in nets {
            info!(net = %n, "[dry-run] unban");
        }
        Ok(())
    }
}

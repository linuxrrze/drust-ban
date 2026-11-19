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

pub trait FirewallBackend: Send + Sync {
    fn name(&self) -> &'static str;

    /// Creates tables/sets/chains. Called once at startup; may reset state,
    /// the caller re-applies active bans afterwards.
    fn ensure_setup(&self) -> anyhow::Result<()>;

    fn ban(&self, entries: &[BanEntry]) -> anyhow::Result<()>;

    fn unban(&self, nets: &[IpNet]) -> anyhow::Result<()>;
}

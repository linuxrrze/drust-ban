//! Agent configuration (`/etc/df2b/agent.toml`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use ipnet::IpNet;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub agent: AgentSection,
    #[serde(default)]
    pub source: Vec<SourceConfig>,
    #[serde(default)]
    pub jail: Vec<JailConfig>,
}

// controller/group/state_dir are used from milestone 2 on
#[allow(dead_code)]
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSection {
    /// Controller URL; `None` = standalone mode.
    #[serde(default)]
    pub controller: Option<String>,
    #[serde(default = "default_group")]
    pub group: String,
    #[serde(default = "default_v4_prefix")]
    pub ipv4_prefix: u8,
    #[serde(default = "default_v6_prefix")]
    pub ipv6_prefix: u8,
    #[serde(default = "default_filter_dir")]
    pub filter_dir: PathBuf,
    #[serde(default = "default_state_dir")]
    pub state_dir: PathBuf,
    #[serde(default)]
    pub firewall: FirewallKind,
    /// How long offense history is kept after a ban expired (drives ban-time
    /// escalation for repeat offenders).
    #[serde(default = "default_offense_memory", with = "humantime_serde")]
    pub offense_memory: Duration,
    /// Networks that are never banned (CIDR notation, e.g. "10.0.0.0/8").
    #[serde(default)]
    pub allowlist: Vec<IpNet>,
}

#[derive(Debug, Clone, Copy, Default, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "kebab-case")]
pub enum FirewallKind {
    #[default]
    Nftables,
    DryRun,
}

#[derive(Debug, Deserialize)]
pub struct SourceConfig {
    pub name: String,
    #[serde(flatten)]
    pub kind: SourceKind,
}

#[derive(Debug, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SourceKind {
    File {
        paths: Vec<PathBuf>,
        /// Skip existing content on first start (default: read from start).
        #[serde(default)]
        start_at_end: bool,
    },
    Journald {
        /// journalctl-style matches, e.g. "_SYSTEMD_UNIT=sshd.service";
        /// "+" starts a new OR group.
        #[serde(default)]
        matches: Vec<String>,
        /// Read journal files from this directory instead of the system journal.
        #[serde(default)]
        directory: Option<PathBuf>,
        /// Where to start without a saved cursor: "tail" (default), "head",
        /// or a duration such as "10m" (start that long ago).
        #[serde(default)]
        start: JournalStart,
    },
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(try_from = "String")]
pub enum JournalStart {
    #[default]
    Tail,
    Head,
    Since(Duration),
}

impl TryFrom<String> for JournalStart {
    type Error = String;

    fn try_from(s: String) -> Result<Self, Self::Error> {
        match s.as_str() {
            "tail" => Ok(Self::Tail),
            "head" => Ok(Self::Head),
            other => humantime::parse_duration(other)
                .map(Self::Since)
                .map_err(|_| {
                    format!("start must be \"tail\", \"head\" or a duration, got {other:?}")
                }),
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct JailConfig {
    pub name: String,
    pub sources: Vec<String>,
    pub filter: String,
    pub maxretry: u32,
    #[serde(with = "humantime_serde")]
    pub findtime: Duration,
    #[serde(with = "humantime_serde")]
    pub bantime: Duration,
    #[serde(default = "default_factor")]
    pub bantime_factor: f64,
    #[serde(default, with = "humantime_serde")]
    pub max_bantime: Option<Duration>,
    /// Upper bound on tracked keys for this jail (memory bound).
    #[serde(default = "default_max_tracked")]
    pub max_tracked: usize,
}

fn default_group() -> String {
    "default".into()
}
fn default_v4_prefix() -> u8 {
    32
}
fn default_v6_prefix() -> u8 {
    64
}
fn default_filter_dir() -> PathBuf {
    "/etc/df2b/filters".into()
}
fn default_state_dir() -> PathBuf {
    "/var/lib/df2b".into()
}
fn default_offense_memory() -> Duration {
    Duration::from_secs(30 * 24 * 3600)
}
fn default_factor() -> f64 {
    1.0
}
fn default_max_tracked() -> usize {
    100_000
}

impl AgentConfig {
    pub fn load(path: &Path) -> anyhow::Result<Self> {
        let text =
            std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
        let mut cfg: Self =
            toml::from_str(&text).with_context(|| format!("parsing {}", path.display()))?;
        // relative filter_dir is resolved against the config file location
        if cfg.agent.filter_dir.is_relative() {
            if let Some(dir) = path.parent() {
                cfg.agent.filter_dir = dir.join(&cfg.agent.filter_dir);
            }
        }
        cfg.validate()?;
        Ok(cfg)
    }

    pub fn validate(&self) -> anyhow::Result<()> {
        if self.agent.ipv4_prefix == 0 || self.agent.ipv4_prefix > 32 {
            bail!("ipv4_prefix must be 1..=32");
        }
        if self.agent.ipv6_prefix == 0 || self.agent.ipv6_prefix > 128 {
            bail!("ipv6_prefix must be 1..=128");
        }
        let mut names = HashSet::new();
        for s in &self.source {
            if !names.insert(s.name.as_str()) {
                bail!("duplicate source name '{}'", s.name);
            }
        }
        let mut jails = HashSet::new();
        for j in &self.jail {
            if !jails.insert(j.name.as_str()) {
                bail!("duplicate jail name '{}'", j.name);
            }
            if j.maxretry == 0 {
                bail!("jail '{}': maxretry must be >= 1", j.name);
            }
            for s in &j.sources {
                if !names.contains(s.as_str()) {
                    bail!("jail '{}' references unknown source '{s}'", j.name);
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn example_config_parses() {
        let text = include_str!("../../../config/agent.example.toml");
        let cfg: AgentConfig = toml::from_str(text).unwrap();
        cfg.validate().unwrap();
        assert_eq!(cfg.jail[0].findtime, Duration::from_secs(600));
        assert!(matches!(
            cfg.source[0].kind,
            SourceKind::Journald {
                start: JournalStart::Since(d),
                ..
            } if d == Duration::from_secs(600)
        ));
        assert!(matches!(cfg.source[1].kind, SourceKind::File { .. }));
    }

    #[test]
    fn unknown_source_rejected() {
        let cfg: AgentConfig = toml::from_str(
            r#"
            [agent]
            [[jail]]
            name = "x"
            sources = ["missing"]
            filter = "sshd"
            maxretry = 3
            findtime = "1m"
            bantime = "1m"
            "#,
        )
        .unwrap();
        assert!(cfg.validate().is_err());
    }
}

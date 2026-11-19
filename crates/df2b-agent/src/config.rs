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
    /// Applied to sample log lines before they leave this host (in order;
    /// the controller may redact further).
    #[serde(default)]
    pub redact: Vec<df2b_core::RedactRule>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AgentSection {
    /// Controller address, `https://host[:port]` (default port 7443);
    /// `None` = standalone mode. The agent's group is assigned by the
    /// enrollment token.
    #[serde(default)]
    pub controller: Option<String>,
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
    /// Accept jail definitions from the controller (with their filters and
    /// log sources). Local jails of the same name always win.
    #[serde(default = "yes")]
    pub central_jails: bool,
    /// Central file sources may only read below these directories.
    #[serde(default = "default_central_paths")]
    pub central_paths: Vec<PathBuf>,
    /// Central jails may read the systemd journal.
    #[serde(default = "yes")]
    pub central_journald: bool,
    /// Send the latest matching log line with the failure counts (shown on
    /// the controller's address page). Off: counts only, no log content
    /// leaves the host.
    #[serde(default = "yes")]
    pub send_samples: bool,
    /// Apply the controller's redaction rules to sample lines too (after
    /// the `[[redact]]` rules here), so the controller never receives what
    /// they hide.
    #[serde(default = "yes")]
    pub central_redaction: bool,
    /// Unix socket for `df2bctl --local` (default `<state_dir>/agent.sock`,
    /// mode 0600; "" turns it off).
    #[serde(default)]
    pub control_socket: Option<PathBuf>,
}

impl AgentSection {
    /// `None`: no control socket.
    pub fn control_socket_path(&self) -> Option<PathBuf> {
        match &self.control_socket {
            None => Some(self.state_dir.join("agent.sock")),
            Some(p) if p.as_os_str().is_empty() => None,
            Some(p) => Some(p.clone()),
        }
    }
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

fn yes() -> bool {
    true
}
fn default_central_paths() -> Vec<PathBuf> {
    vec!["/var/log".into()]
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
pub(crate) fn default_max_tracked() -> usize {
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
        if let Some(c) = &self.agent.controller {
            controller_addr(c)?;
        }
        df2b_core::Redactor::new(&self.redact).map_err(|e| anyhow::anyhow!("redact: {e}"))?;
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
            if s.name.starts_with("central:") {
                bail!(
                    "source name '{}': the prefix \"central:\" is reserved",
                    s.name
                );
            }
            if let SourceKind::File { paths, .. } = &s.kind {
                if paths.is_empty() {
                    bail!("source '{}': no paths", s.name);
                }
                for p in paths {
                    df2b_sources::file::check_path(p)
                        .map_err(|e| anyhow::anyhow!("source '{}': {e}", s.name))?;
                }
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
        for p in &self.agent.central_paths {
            if !p.is_absolute() {
                bail!("central_paths: {} is not absolute", p.display());
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
    fn redaction_rules() {
        let parse = |rules: &str| {
            let cfg: AgentConfig = toml::from_str(&format!("[agent]\n{rules}")).unwrap();
            cfg.validate().map(|()| cfg)
        };
        let cfg = parse(
            r#"
            [[redact]]
            pattern = '(for )\S+( from)'
            replace = "${1}[user]${2}"
            [[redact]]
            pattern = '[\w.]+@[\w.]+'
            "#,
        )
        .unwrap();
        assert_eq!(cfg.redact.len(), 2);
        assert_eq!(cfg.redact[1].replace, df2b_core::redact::DEFAULT_REPLACE);
        let err = parse("[[redact]]\npattern = '('").unwrap_err();
        assert!(format!("{err:#}").contains("redact"), "{err:#}");
        // the commented example in agent.example.toml works
        let example = include_str!("../../../config/agent.example.toml")
            .replace("# [[redact]]", "[[redact]]")
            .replace("# pattern = '", "pattern = '")
            .replace("# replace = '", "replace = '");
        let cfg: AgentConfig = toml::from_str(&example).unwrap();
        cfg.validate().unwrap();
        let r = df2b_core::Redactor::new(&cfg.redact).unwrap();
        assert_eq!(
            r.apply("Failed password for invalid user admin from 203.0.113.7 port 22"),
            "Failed password for [user] from 203.0.113.7 port 22"
        );
        // typos are errors, as elsewhere in agent.toml
        let typo: Result<AgentConfig, _> =
            toml::from_str("[agent]\n[[redact]]\npattern = 'x'\nreplacement = 'y'");
        assert!(typo.is_err());
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

    #[test]
    fn file_source_paths_checked() {
        let with = |paths: &str| {
            let cfg: AgentConfig = toml::from_str(&format!(
                "[agent]\n[[source]]\nname = \"f\"\ntype = \"file\"\npaths = {paths}"
            ))
            .unwrap();
            cfg.validate()
        };
        assert!(with(r#"["/var/log/nginx/*.access.log", "/var/log/auth.log"]"#).is_ok());
        assert!(with(r#"["/var/log/[nginx/*.log"]"#).is_err());
        assert!(with("[]").is_err());
    }
}

/// `https://host[:port]` (or `host[:port]`) → `host:port` for connecting.
pub fn controller_addr(url: &str) -> anyhow::Result<String> {
    let rest = match url.split_once("://") {
        Some(("https", rest)) => rest,
        Some((scheme, _)) => bail!("controller: unsupported scheme {scheme:?}, use https://"),
        None => url,
    };
    let hostport = rest.trim_end_matches('/');
    if hostport.is_empty() || hostport.contains('/') || hostport.contains('@') {
        bail!("controller: expected https://host[:port], got {url:?}");
    }
    // "[v6]" or "[v6]:port", "host" or "host:port"
    let has_port = match hostport.rfind(']') {
        Some(i) => hostport[i + 1..].starts_with(':'),
        None => hostport.contains(':'),
    };
    if hostport.contains(':') && !hostport.starts_with('[') && hostport.matches(':').count() > 1 {
        bail!("controller: put IPv6 addresses in brackets, e.g. https://[2001:db8::1]:7443");
    }
    Ok(if has_port {
        hostport.to_owned()
    } else {
        format!("{hostport}:7443")
    })
}

#[cfg(test)]
mod addr_tests {
    use super::controller_addr;

    #[test]
    fn controller_urls() {
        assert_eq!(
            controller_addr("https://ctl.example.org").unwrap(),
            "ctl.example.org:7443"
        );
        assert_eq!(controller_addr("https://ctl:9000/").unwrap(), "ctl:9000");
        assert_eq!(controller_addr("10.0.0.1").unwrap(), "10.0.0.1:7443");
        assert_eq!(
            controller_addr("https://[2001:db8::1]").unwrap(),
            "[2001:db8::1]:7443"
        );
        assert_eq!(controller_addr("https://[::1]:7443").unwrap(), "[::1]:7443");
        for bad in ["http://ctl", "https://", "https://ctl/path", "2001:db8::1"] {
            assert!(controller_addr(bad).is_err(), "{bad}");
        }
    }
}

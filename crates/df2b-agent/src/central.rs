//! Jails defined on the controller (DESIGN.md §9 "Central jails").
//!
//! The controller sends this agent's group's definitions with the central
//! filters they use. The agent decides what it accepts (agent.toml):
//! `central_jails` (off: none), `central_paths` (file sources only below
//! these directories, absolute paths without `..`), `central_journald`.
//! A local jail with the same name always wins. Rejected definitions are
//! reported in heartbeats with the reason.

use std::path::{Component, Path, PathBuf};
use std::time::Duration;

use df2b_proto::v1;
use serde::{Deserialize, Serialize};

use crate::config::{AgentSection, JournalStart, SourceConfig, SourceKind};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CentralJails {
    pub version: String,
    /// name → TOML
    pub filters: Vec<(String, String)>,
    pub jails: Vec<CentralJail>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CentralJail {
    pub name: String,
    pub filter: String,
    pub sources: Vec<CentralSource>,
    pub enabled: bool,
    pub maxretry: u32,
    #[serde(with = "humantime_serde")]
    pub findtime: Duration,
    #[serde(with = "humantime_serde")]
    pub bantime: Duration,
    pub factor: f64,
    #[serde(with = "humantime_serde")]
    pub max_bantime: Option<Duration>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CentralSource {
    File {
        paths: Vec<PathBuf>,
        start_at_end: bool,
    },
    Journald {
        matches: Vec<String>,
        start: String,
    },
}

impl CentralJail {
    /// Source names used by this jail ("central:<jail>:<n>").
    pub fn source_names(&self) -> Vec<String> {
        (0..self.sources.len())
            .map(|i| format!("central:{}:{i}", self.name))
            .collect()
    }

    /// Local source configurations for this jail's sources.
    pub fn source_configs(&self) -> anyhow::Result<Vec<SourceConfig>> {
        self.sources
            .iter()
            .zip(self.source_names())
            .map(|(s, name)| {
                let kind = match s {
                    CentralSource::File {
                        paths,
                        start_at_end,
                    } => SourceKind::File {
                        paths: paths.clone(),
                        start_at_end: *start_at_end,
                    },
                    CentralSource::Journald { matches, start } => SourceKind::Journald {
                        matches: matches.clone(),
                        directory: None,
                        start: if start.is_empty() {
                            JournalStart::default()
                        } else {
                            JournalStart::try_from(start.clone())
                                .map_err(|e| anyhow::anyhow!("journald start: {e}"))?
                        },
                    },
                };
                Ok(SourceConfig { name, kind })
            })
            .collect()
    }

    /// Whether this agent's configuration allows the jail's sources.
    pub fn check(&self, agent: &AgentSection) -> Result<(), String> {
        if !agent.central_jails {
            return Err("central jails are disabled in this agent's configuration".into());
        }
        for s in &self.sources {
            match s {
                CentralSource::File { paths, .. } => {
                    for p in paths {
                        if !path_allowed(p, &agent.central_paths) {
                            return Err(format!(
                                "{} is outside the allowed directories (central_paths)",
                                p.display()
                            ));
                        }
                    }
                }
                CentralSource::Journald { .. } => {
                    if !agent.central_journald {
                        return Err("journald sources are disabled (central_journald)".into());
                    }
                    if !cfg!(feature = "journald") {
                        return Err("this agent was built without journald support".into());
                    }
                }
            }
        }
        Ok(())
    }
}

/// Splits the definitions into those this agent accepts and those it
/// rejects, with the reason: (jail, filter, reason).
pub fn split(
    agent: &AgentSection,
    c: &CentralJails,
) -> (Vec<CentralJail>, Vec<(String, String, String)>) {
    let mut accepted = Vec::new();
    let mut rejected = Vec::new();
    for j in &c.jails {
        match j
            .check(agent)
            .and_then(|()| j.source_configs().map(|_| ()).map_err(|e| format!("{e:#}")))
        {
            Ok(()) => accepted.push(j.clone()),
            Err(reason) => rejected.push((j.name.clone(), j.filter.clone(), reason)),
        }
    }
    (accepted, rejected)
}

/// Absolute, no `..`, and below one of `allowed` (component-wise, so
/// "/var/logx" is not below "/var/log").
pub fn path_allowed(p: &Path, allowed: &[PathBuf]) -> bool {
    p.is_absolute()
        && p.components().all(|c| !matches!(c, Component::ParentDir))
        && allowed.iter().any(|a| p.starts_with(a) && p != a.as_path())
}

/// Converts the controller's message; implausible jails are dropped.
pub fn from_proto(c: v1::CentralJails) -> CentralJails {
    let dur = |ms: i64| (ms > 0).then(|| Duration::from_millis(ms as u64));
    let mut jails = Vec::new();
    for j in c.jails {
        let (Some(findtime), Some(bantime)) = (dur(j.findtime_ms), dur(j.bantime_ms)) else {
            tracing::warn!(jail = %j.name, "ignoring central jail without findtime/bantime");
            continue;
        };
        if j.maxretry == 0 || !j.bantime_factor.is_finite() || j.bantime_factor < 1.0 {
            tracing::warn!(jail = %j.name, "ignoring implausible central jail");
            continue;
        }
        let sources = j
            .sources
            .into_iter()
            .filter_map(|s| match s.kind? {
                v1::source_definition::Kind::File(f) => Some(CentralSource::File {
                    paths: f.paths.into_iter().map(PathBuf::from).collect(),
                    start_at_end: f.start_at_end,
                }),
                v1::source_definition::Kind::Journald(j) => Some(CentralSource::Journald {
                    matches: j.matches,
                    start: j.start,
                }),
            })
            .collect();
        jails.push(CentralJail {
            name: j.name,
            filter: j.filter,
            sources,
            enabled: j.enabled,
            maxretry: j.maxretry,
            findtime,
            bantime,
            factor: j.bantime_factor,
            max_bantime: dur(j.max_bantime_ms),
        });
    }
    CentralJails {
        version: c.version,
        filters: c.filters.into_iter().map(|f| (f.name, f.toml)).collect(),
        jails,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn paths() {
        let allowed = vec![PathBuf::from("/var/log"), PathBuf::from("/srv/app/logs")];
        for (p, ok) in [
            ("/var/log/auth.log", true),
            ("/var/log/nginx/error.log", true),
            ("/srv/app/logs/app.log", true),
            ("/var/log", false),
            ("/var/logx/auth.log", false),
            ("/var/log/../../etc/shadow", false),
            ("/etc/shadow", false),
            ("var/log/auth.log", false),
        ] {
            assert_eq!(path_allowed(Path::new(p), &allowed), ok, "{p}");
        }
    }

    fn agent(toml: &str) -> AgentSection {
        let cfg: crate::config::AgentConfig = toml::from_str(&format!("[agent]\n{toml}")).unwrap();
        cfg.agent
    }

    fn jail(sources: Vec<CentralSource>) -> CentralJail {
        CentralJail {
            name: "sshd".into(),
            filter: "sshd".into(),
            sources,
            enabled: true,
            maxretry: 3,
            findtime: Duration::from_secs(600),
            bantime: Duration::from_secs(3600),
            factor: 1.0,
            max_bantime: None,
        }
    }

    #[test]
    fn what_an_agent_accepts() {
        let file = |p: &str| CentralSource::File {
            paths: vec![p.into()],
            start_at_end: true,
        };
        let j = jail(vec![file("/var/log/auth.log")]);
        assert!(j.check(&agent("")).is_ok(), "defaults: on, /var/log");
        assert!(j
            .check(&agent("central_jails = false"))
            .unwrap_err()
            .contains("disabled"));
        assert!(jail(vec![file("/etc/passwd")])
            .check(&agent(""))
            .unwrap_err()
            .contains("outside"));
        assert!(j.check(&agent(r#"central_paths = ["/srv/logs"]"#)).is_err());
        let jd = jail(vec![CentralSource::Journald {
            matches: vec![],
            start: "10m".into(),
        }]);
        assert!(jd
            .check(&agent("central_journald = false"))
            .unwrap_err()
            .contains("journald"));
        assert_eq!(j.source_names(), ["central:sshd:0"]);
        assert!(j.source_configs().is_ok());
        assert!(jail(vec![CentralSource::Journald {
            matches: vec![],
            start: "whenever".into()
        }])
        .source_configs()
        .is_err());
    }

    #[test]
    fn conversion_drops_implausible_jails() {
        let ok = v1::JailDefinition {
            name: "sshd".into(),
            filter: "sshd".into(),
            sources: vec![v1::SourceDefinition {
                kind: Some(v1::source_definition::Kind::File(v1::FileSource {
                    paths: vec!["/var/log/auth.log".into()],
                    start_at_end: true,
                })),
            }],
            enabled: true,
            maxretry: 3,
            findtime_ms: 600_000,
            bantime_ms: 3_600_000,
            bantime_factor: 2.0,
            max_bantime_ms: 0,
        };
        let c = from_proto(v1::CentralJails {
            version: "v1".into(),
            filters: vec![v1::CentralFilter {
                name: "f".into(),
                toml: "x".into(),
            }],
            jails: vec![
                ok.clone(),
                v1::JailDefinition {
                    name: "zero".into(),
                    maxretry: 0,
                    ..ok.clone()
                },
                v1::JailDefinition {
                    name: "nan".into(),
                    bantime_factor: f64::NAN,
                    ..ok.clone()
                },
                v1::JailDefinition {
                    name: "noban".into(),
                    bantime_ms: 0,
                    ..ok
                },
            ],
        });
        assert_eq!(c.jails.len(), 1);
        assert_eq!(c.jails[0].max_bantime, None);
        assert_eq!(c.filters, [("f".to_string(), "x".to_string())]);
    }
}

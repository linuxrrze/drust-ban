//! Central jail definitions and filters (DESIGN.md §9 "Central jails").
//!
//! Admins define jails (filter, log sources, limits) for all agents or one
//! group, and filters in the agents' TOML format. Each agent receives its
//! group's definitions (a group definition replaces the one for all agents
//! with the same name) and the central filters they use. Agents decide
//! what they accept (paths, journald, local jails win; see the agent).

use std::time::Duration;

use chrono::{DateTime, Utc};
use df2b_proto::v1;
use serde::{Deserialize, Serialize};

use crate::policy::{self, JailSettings};

/// Largest filter definition (TOML) accepted.
pub const MAX_FILTER_BYTES: usize = 64 * 1024;
const MAX_FAILREGEX: usize = 100;
const MAX_SOURCES: usize = 8;
const MAX_PATHS: usize = 16;
const MAX_MATCHES: usize = 32;

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CentralFilter {
    pub name: String,
    pub toml: String,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum SourceDef {
    File {
        paths: Vec<String>,
        #[serde(default)]
        start_at_end: bool,
    },
    Journald {
        #[serde(default)]
        matches: Vec<String>,
        /// "tail" (default), "head" or a duration ("10m")
        #[serde(default)]
        start: Option<String>,
    },
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JailDef {
    pub name: String,
    /// None: all agents
    pub group: Option<String>,
    pub filter: String,
    pub sources: Vec<SourceDef>,
    #[serde(default = "yes")]
    pub enabled: bool,
    pub maxretry: u32,
    #[serde(with = "humantime_serde")]
    pub findtime: Duration,
    #[serde(with = "humantime_serde")]
    pub bantime: Duration,
    #[serde(default = "one")]
    pub bantime_factor: f64,
    #[serde(default, with = "humantime_serde")]
    pub max_bantime: Option<Duration>,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

fn yes() -> bool {
    true
}
fn one() -> f64 {
    1.0
}

impl JailDef {
    pub fn key(name: &str, group: Option<&str>) -> String {
        policy::JailOverride::key(name, group)
    }
}

/// Parses and compiles a filter, so errors show when it is saved.
pub fn validate_filter(name: &str, toml: &str) -> Result<(), String> {
    if !policy::valid_jail(name) {
        return Err("invalid filter name (letters, digits, - _ .)".into());
    }
    if toml.len() > MAX_FILTER_BYTES {
        return Err(format!("filter is larger than {MAX_FILTER_BYTES} bytes"));
    }
    let def = df2b_matcher::FilterDef::from_toml(toml).map_err(|e| format!("filter: {e}"))?;
    if def.failregex.len() > MAX_FAILREGEX {
        return Err(format!("at most {MAX_FAILREGEX} failregex patterns"));
    }
    df2b_matcher::Filter::compile(name, &def).map_err(|e| format!("filter: {e}"))?;
    Ok(())
}

/// A path the agents could open: absolute, no `..`, no control characters.
fn valid_path(p: &str) -> bool {
    let path = std::path::Path::new(p);
    p.len() <= 4096
        && path.is_absolute()
        && !p.chars().any(char::is_control)
        && path
            .components()
            .all(|c| !matches!(c, std::path::Component::ParentDir))
}

/// A path with `*`, `?` or `[` is a glob (agents expand it); it must parse.
fn valid_glob(p: &str) -> bool {
    !p.contains(['*', '?', '[']) || glob::Pattern::new(p).is_ok()
}

/// `FIELD=value` (journalctl syntax) or "+" (OR).
fn valid_match(m: &str) -> bool {
    m == "+"
        || m.split_once('=').is_some_and(|(f, _)| {
            !f.is_empty()
                && f.chars()
                    .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit() || c == '_')
        }) && m.len() <= 256
            && !m.chars().any(char::is_control)
}

fn valid_start(s: &str) -> bool {
    matches!(s, "tail" | "head") || humantime::parse_duration(s).is_ok()
}

pub fn validate_def(d: &JailDef) -> Result<(), String> {
    if !policy::valid_jail(&d.name) {
        return Err("invalid jail name (letters, digits, - _ .)".into());
    }
    if !policy::valid_jail(&d.filter) {
        return Err("invalid filter name".into());
    }
    if d.sources.is_empty() || d.sources.len() > MAX_SOURCES {
        return Err(format!("between 1 and {MAX_SOURCES} sources"));
    }
    for s in &d.sources {
        match s {
            SourceDef::File { paths, .. } => {
                if paths.is_empty() || paths.len() > MAX_PATHS {
                    return Err(format!("a file source needs 1 to {MAX_PATHS} paths"));
                }
                if let Some(p) = paths.iter().find(|p| !valid_path(p)) {
                    return Err(format!("invalid path {p:?} (absolute, without \"..\")"));
                }
                if let Some(p) = paths.iter().find(|p| !valid_glob(p)) {
                    return Err(format!("invalid glob pattern {p:?}"));
                }
            }
            SourceDef::Journald { matches, start } => {
                if matches.len() > MAX_MATCHES {
                    return Err(format!("at most {MAX_MATCHES} journald matches"));
                }
                if let Some(m) = matches.iter().find(|m| !valid_match(m)) {
                    return Err(format!("invalid journald match {m:?} (FIELD=value or +)"));
                }
                if start.as_deref().is_some_and(|s| !valid_start(s)) {
                    return Err("journald start must be tail, head or a duration".into());
                }
            }
        }
    }
    JailSettings {
        enabled: Some(d.enabled),
        maxretry: Some(d.maxretry),
        findtime: Some(d.findtime),
        bantime: Some(d.bantime),
        bantime_factor: Some(d.bantime_factor),
        max_bantime: d.max_bantime,
    }
    .validate()
}

/// Everything central: filters and jail definitions.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct CentralConfig {
    pub filters: Vec<CentralFilter>,
    pub defs: Vec<JailDef>,
}

impl CentralConfig {
    /// Definitions for a group: group ones replace all-agent ones by name.
    pub fn defs_for(&self, group: &str) -> Vec<&JailDef> {
        let mut by_name: std::collections::BTreeMap<&str, &JailDef> = Default::default();
        for d in self.defs.iter().filter(|d| d.group.is_none()) {
            by_name.insert(&d.name, d);
        }
        for d in self
            .defs
            .iter()
            .filter(|d| d.group.as_deref() == Some(group))
        {
            by_name.insert(&d.name, d);
        }
        by_name.into_values().collect()
    }

    /// Jail definitions using a filter (any scope).
    pub fn users_of(&self, filter: &str) -> Vec<String> {
        self.defs
            .iter()
            .filter(|d| d.filter == filter)
            .map(|d| match &d.group {
                Some(g) => format!("{} (group {g})", d.name),
                None => d.name.clone(),
            })
            .collect()
    }

    /// What the agents of `group` receive; the version is a content hash.
    pub fn for_group(&self, group: &str) -> v1::CentralJails {
        let ms = |d: Duration| i64::try_from(d.as_millis()).unwrap_or(i64::MAX);
        let defs = self.defs_for(group);
        let jails: Vec<v1::JailDefinition> = defs
            .iter()
            .map(|d| v1::JailDefinition {
                name: d.name.clone(),
                filter: d.filter.clone(),
                sources: d
                    .sources
                    .iter()
                    .map(|s| v1::SourceDefinition {
                        kind: Some(match s {
                            SourceDef::File {
                                paths,
                                start_at_end,
                            } => v1::source_definition::Kind::File(v1::FileSource {
                                paths: paths.clone(),
                                start_at_end: *start_at_end,
                            }),
                            SourceDef::Journald { matches, start } => {
                                v1::source_definition::Kind::Journald(v1::JournaldSource {
                                    matches: matches.clone(),
                                    start: start.clone().unwrap_or_default(),
                                })
                            }
                        }),
                    })
                    .collect(),
                enabled: d.enabled,
                maxretry: d.maxretry,
                findtime_ms: ms(d.findtime),
                bantime_ms: ms(d.bantime),
                bantime_factor: d.bantime_factor,
                max_bantime_ms: d.max_bantime.map_or(0, ms),
            })
            .collect();
        // only the filters these jails use
        let mut filters: Vec<v1::CentralFilter> = self
            .filters
            .iter()
            .filter(|f| defs.iter().any(|d| d.filter == f.name))
            .map(|f| v1::CentralFilter {
                name: f.name.clone(),
                toml: f.toml.clone(),
            })
            .collect();
        filters.sort_by(|a, b| a.name.cmp(&b.name));
        let text = format!("{jails:?}{filters:?}");
        v1::CentralJails {
            version: df2b_tls::hex(&df2b_tls::sha256(text.as_bytes())[..8]),
            filters,
            jails,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(crate) fn def(name: &str, group: Option<&str>, filter: &str) -> JailDef {
        JailDef {
            name: name.into(),
            group: group.map(Into::into),
            filter: filter.into(),
            sources: vec![SourceDef::File {
                paths: vec!["/var/log/auth.log".into()],
                start_at_end: true,
            }],
            enabled: true,
            maxretry: 5,
            findtime: Duration::from_secs(600),
            bantime: Duration::from_secs(3600),
            bantime_factor: 2.0,
            max_bantime: None,
            updated_by: "ada".into(),
            updated_at: Utc::now(),
        }
    }

    const SSHD: &str = r#"
literals = ["Failed password"]
failregex = ['Failed password for .* from <HOST>']
"#;

    #[test]
    fn filters_are_compiled() {
        assert!(validate_filter("sshd", SSHD).is_ok());
        assert!(validate_filter("bad name", SSHD).is_err());
        assert!(validate_filter("x", "failregex = ['no host tag']")
            .unwrap_err()
            .contains("HOST"));
        assert!(
            validate_filter("x", "failregex = ['(<HOST>']").is_err(),
            "regex error"
        );
        assert!(validate_filter("x", "nonsense = 1").is_err());
        assert!(validate_filter("x", &"#".repeat(MAX_FILTER_BYTES + 1)).is_err());
    }

    #[test]
    fn definitions_are_validated() {
        assert!(validate_def(&def("sshd", None, "sshd")).is_ok());
        let mut globbed = def("sshd", None, "sshd");
        globbed.sources = vec![SourceDef::File {
            paths: vec!["/var/log/nginx/*.access.log".into()],
            start_at_end: true,
        }];
        assert!(validate_def(&globbed).is_ok());
        let with = |f: fn(&mut JailDef)| {
            let mut d = def("sshd", None, "sshd");
            f(&mut d);
            validate_def(&d)
        };
        for (what, r) in [
            (
                "relative path",
                with(|d| {
                    d.sources = vec![SourceDef::File {
                        paths: vec!["auth.log".into()],
                        start_at_end: false,
                    }]
                }),
            ),
            (
                "bad glob",
                with(|d| {
                    d.sources = vec![SourceDef::File {
                        paths: vec!["/var/log/[nginx/*.log".into()],
                        start_at_end: false,
                    }]
                }),
            ),
            (
                "dotdot",
                with(|d| {
                    d.sources = vec![SourceDef::File {
                        paths: vec!["/var/log/../../etc/shadow".into()],
                        start_at_end: false,
                    }]
                }),
            ),
            ("no sources", with(|d| d.sources.clear())),
            (
                "bad match",
                with(|d| {
                    d.sources = vec![SourceDef::Journald {
                        matches: vec!["unit sshd".into()],
                        start: None,
                    }]
                }),
            ),
            (
                "bad start",
                with(|d| {
                    d.sources = vec![SourceDef::Journald {
                        matches: vec![],
                        start: Some("yesterday".into()),
                    }]
                }),
            ),
            ("maxretry", with(|d| d.maxretry = 0)),
            ("bantime", with(|d| d.bantime = Duration::from_secs(1))),
            ("name", with(|d| d.name = "a/b".into())),
        ] {
            assert!(r.is_err(), "{what}");
        }
        assert!(with(|d| d.sources = vec![SourceDef::Journald {
            matches: vec![
                "_SYSTEMD_UNIT=sshd.service".into(),
                "+".into(),
                "SYSLOG_IDENTIFIER=sshd".into()
            ],
            start: Some("10m".into()),
        }])
        .is_ok());
    }

    #[test]
    fn group_definitions_replace_and_filters_follow() {
        let f = |name: &str| CentralFilter {
            name: name.into(),
            toml: SSHD.into(),
            updated_by: "ada".into(),
            updated_at: Utc::now(),
        };
        let cfg = CentralConfig {
            filters: vec![f("sshd-strict"), f("unused")],
            defs: vec![
                def("sshd", None, "sshd"),
                def("sshd", Some("web"), "sshd-strict"),
                def("nginx", Some("db"), "nginx-auth"),
            ],
        };
        let web = cfg.for_group("web");
        assert_eq!(web.jails.len(), 1);
        assert_eq!(web.jails[0].filter, "sshd-strict", "group definition wins");
        assert_eq!(web.filters.len(), 1, "only filters in use are sent");
        let db = cfg.for_group("db");
        assert_eq!(
            db.jails.iter().map(|j| j.name.as_str()).collect::<Vec<_>>(),
            ["nginx", "sshd"]
        );
        assert!(db.filters.is_empty(), "agent-local filters are not shipped");
        assert_ne!(web.version, db.version);
        assert_eq!(cfg.for_group("web"), web, "stable");
        assert_eq!(cfg.users_of("sshd-strict"), ["sshd (group web)"]);
    }
}

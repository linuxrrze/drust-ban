//! Three-stage log line matcher:
//!
//! 1. Aho-Corasick literal prefilter (drops the vast majority of lines),
//! 2. `RegexSet` to find which patterns match,
//! 3. capture of `<HOST>` from the first matching pattern, validated by
//!    parsing into [`IpAddr`]. No DNS lookups.

use std::net::IpAddr;

use aho_corasick::AhoCorasick;
use regex::{Regex, RegexSet};
use serde::Deserialize;

/// Placeholder in filter patterns that is replaced by the host capture group.
pub const HOST_TAG: &str = "<HOST>";

/// Deliberately permissive; the capture is validated by parsing it as an IP.
const HOST_PATTERN: &str = r"(?P<host>[0-9A-Fa-f:.]{2,45})";

/// Filter definition as stored in `filters/<name>.toml`.
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FilterDef {
    /// A line must contain at least one of these literals to be considered.
    /// Leave empty to disable the prefilter.
    #[serde(default)]
    pub literals: Vec<String>,
    /// Patterns that identify a failure. Each must contain `<HOST>` once.
    pub failregex: Vec<String>,
    /// Lines matching any of these are ignored.
    #[serde(default)]
    pub ignoreregex: Vec<String>,
}

impl FilterDef {
    pub fn from_toml(s: &str) -> Result<Self, toml::de::Error> {
        toml::from_str(s)
    }
}

#[derive(Debug, thiserror::Error)]
pub enum FilterError {
    #[error("filter has no failregex")]
    Empty,
    #[error("failregex #{index} must contain <HOST> exactly once: {pattern}")]
    HostTag { index: usize, pattern: String },
    #[error(transparent)]
    Regex(#[from] regex::Error),
    #[error(transparent)]
    Literals(#[from] aho_corasick::BuildError),
}

/// Result of a successful match.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FilterMatch {
    pub ip: IpAddr,
    /// Index of the matching `failregex`.
    pub pattern: usize,
}

/// A compiled filter.
#[derive(Debug, Clone)]
pub struct Filter {
    name: String,
    prefilter: Option<AhoCorasick>,
    set: RegexSet,
    regexes: Vec<Regex>,
    ignore: Option<RegexSet>,
}

impl Filter {
    pub fn compile(name: impl Into<String>, def: &FilterDef) -> Result<Self, FilterError> {
        if def.failregex.is_empty() {
            return Err(FilterError::Empty);
        }
        let mut patterns = Vec::with_capacity(def.failregex.len());
        for (index, p) in def.failregex.iter().enumerate() {
            if p.matches(HOST_TAG).count() != 1 {
                return Err(FilterError::HostTag {
                    index,
                    pattern: p.clone(),
                });
            }
            patterns.push(p.replace(HOST_TAG, HOST_PATTERN));
        }
        let regexes = patterns
            .iter()
            .map(|p| Regex::new(p))
            .collect::<Result<Vec<_>, _>>()?;
        let set = RegexSet::new(&patterns)?;
        let prefilter = if def.literals.is_empty() {
            None
        } else {
            Some(AhoCorasick::new(&def.literals)?)
        };
        let ignore = if def.ignoreregex.is_empty() {
            None
        } else {
            Some(RegexSet::new(&def.ignoreregex)?)
        };
        Ok(Self {
            name: name.into(),
            prefilter,
            set,
            regexes,
            ignore,
        })
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn match_line(&self, line: &str) -> Option<FilterMatch> {
        if let Some(pf) = &self.prefilter {
            if !pf.is_match(line) {
                return None;
            }
        }
        let hits = self.set.matches(line);
        if !hits.matched_any() {
            return None;
        }
        if let Some(ig) = &self.ignore {
            if ig.is_match(line) {
                return None;
            }
        }
        for pattern in hits.iter() {
            let Some(caps) = self.regexes[pattern].captures(line) else {
                continue;
            };
            let Some(host) = caps.name("host") else {
                continue;
            };
            // the permissive host pattern may swallow a sentence-ending '.'
            if let Ok(ip) = host.as_str().trim_end_matches('.').parse::<IpAddr>() {
                return Some(FilterMatch { ip, pattern });
            }
        }
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const SSHD: &str = include_str!("../../../filters/sshd.toml");

    fn sshd() -> Filter {
        Filter::compile("sshd", &FilterDef::from_toml(SSHD).unwrap()).unwrap()
    }

    fn ip(f: &Filter, line: &str) -> Option<String> {
        f.match_line(line).map(|m| m.ip.to_string())
    }

    #[test]
    fn matches_journald_messages() {
        let f = sshd();
        assert_eq!(
            ip(
                &f,
                "Failed password for root from 203.0.113.7 port 52144 ssh2"
            )
            .as_deref(),
            Some("203.0.113.7")
        );
        assert_eq!(
            ip(&f, "Invalid user admin from 2001:db8::42 port 40022").as_deref(),
            Some("2001:db8::42")
        );
        assert_eq!(
            ip(
                &f,
                "Accepted publickey for alice from 198.51.100.1 port 1 ssh2"
            ),
            None
        );
    }

    #[test]
    fn matches_syslog_file_lines() {
        let f = sshd();
        let line = "Nov 19 05:52:01 host sshd[812]: Failed password for invalid user bob from 198.51.100.9 port 22 ssh2";
        assert_eq!(ip(&f, line).as_deref(), Some("198.51.100.9"));
    }

    #[test]
    fn username_injection_does_not_redirect_ban() {
        let f = sshd();
        let line = "Invalid user x from 10.0.0.1 port 1 from 203.0.113.5 port 22";
        assert_eq!(ip(&f, line).as_deref(), Some("203.0.113.5"));
    }

    #[test]
    fn rejects_patterns_without_host() {
        let def = FilterDef {
            literals: vec![],
            failregex: vec!["no host here".into()],
            ignoreregex: vec![],
        };
        assert!(matches!(
            Filter::compile("x", &def),
            Err(FilterError::HostTag { .. })
        ));
    }

    #[test]
    fn ignoreregex_wins() {
        let def = FilterDef {
            literals: vec!["fail".into()],
            failregex: vec![r"fail from <HOST>".into()],
            ignoreregex: vec!["test-run".into()],
        };
        let f = Filter::compile("x", &def).unwrap();
        assert!(f.match_line("fail from 192.0.2.1").is_some());
        assert!(f.match_line("test-run fail from 192.0.2.1").is_none());
    }
}

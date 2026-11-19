//! Central jail settings (DESIGN.md §9 "Policies").
//!
//! Jails are defined in each agent's configuration (sources and filters are
//! host-specific). Admins override their parameters centrally, for all
//! agents or for one group; a group's settings win field by field over the
//! ones for all agents. Unset fields keep the agent's own value. The merged
//! settings for a group are sent to its agents over the decision stream.

use std::time::Duration;

use chrono::{DateTime, Utc};
use df2b_proto::v1;
use serde::{Deserialize, Serialize};

/// Bounds for central settings (agents accept them as they come).
pub const MAX_MAXRETRY: u32 = 1000;
pub const MAX_FINDTIME: Duration = Duration::from_secs(7 * 86400);
pub const MIN_BANTIME: Duration = Duration::from_secs(60);
pub const MAX_BANTIME: Duration = Duration::from_secs(10 * 365 * 86400);
pub const MAX_FACTOR: f64 = 10.0;

/// The settings a policy can change; `None` keeps what is below it.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JailSettings {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub enabled: Option<bool>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub maxretry: Option<u32>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "humantime_serde"
    )]
    pub findtime: Option<Duration>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "humantime_serde"
    )]
    pub bantime: Option<Duration>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bantime_factor: Option<f64>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        with = "humantime_serde"
    )]
    pub max_bantime: Option<Duration>,
}

impl JailSettings {
    pub fn is_empty(&self) -> bool {
        *self == Self::default()
    }

    /// `other`'s fields win.
    fn overlay(&mut self, other: &Self) {
        macro_rules! take {
            ($($f:ident),*) => { $( if other.$f.is_some() { self.$f = other.$f; } )* };
        }
        take!(
            enabled,
            maxretry,
            findtime,
            bantime,
            bantime_factor,
            max_bantime
        );
    }

    pub fn validate(&self) -> Result<(), String> {
        if let Some(m) = self.maxretry {
            if m == 0 || m > MAX_MAXRETRY {
                return Err(format!("maxretry must be between 1 and {MAX_MAXRETRY}"));
            }
        }
        if let Some(f) = self.findtime {
            if f < Duration::from_secs(1) || f > MAX_FINDTIME {
                return Err("findtime must be between 1s and 7 days".into());
            }
        }
        for (name, v) in [("bantime", self.bantime), ("max_bantime", self.max_bantime)] {
            if let Some(b) = v {
                if b < MIN_BANTIME || b > MAX_BANTIME {
                    return Err(format!("{name} must be between 1 minute and 10 years"));
                }
            }
        }
        if let (Some(b), Some(m)) = (self.bantime, self.max_bantime) {
            if m < b {
                return Err("max_bantime must not be shorter than bantime".into());
            }
        }
        if let Some(f) = self.bantime_factor {
            if !(1.0..=MAX_FACTOR).contains(&f) || f.is_nan() {
                return Err(format!("bantime_factor must be between 1 and {MAX_FACTOR}"));
            }
        }
        Ok(())
    }
}

/// A stored override: one jail, all agents (`group: None`) or one group.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JailOverride {
    pub jail: String,
    pub group: Option<String>,
    #[serde(flatten)]
    pub settings: JailSettings,
    pub updated_by: String,
    pub updated_at: DateTime<Utc>,
}

impl JailOverride {
    pub fn key(jail: &str, group: Option<&str>) -> String {
        match group {
            Some(g) => format!("group:{g}|{jail}"),
            None => format!("*|{jail}"),
        }
    }
}

/// Jail names as in agent configurations.
pub fn valid_jail(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

/// Merged settings for the agents of `group`, by jail name.
pub fn merged(overrides: &[JailOverride], group: &str) -> Vec<(String, JailSettings)> {
    let mut out: std::collections::BTreeMap<String, JailSettings> = Default::default();
    // all agents first, then the group on top
    for o in overrides.iter().filter(|o| o.group.is_none()) {
        out.entry(o.jail.clone()).or_default().overlay(&o.settings);
    }
    for o in overrides
        .iter()
        .filter(|o| o.group.as_deref() == Some(group))
    {
        out.entry(o.jail.clone()).or_default().overlay(&o.settings);
    }
    out.into_iter().filter(|(_, s)| !s.is_empty()).collect()
}

fn ms(d: Option<Duration>) -> Option<i64> {
    d.map(|d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX))
}

/// What the agents of a group receive. The version is a content hash.
pub fn for_group(overrides: &[JailOverride], group: &str) -> v1::JailPolicies {
    let jails: Vec<v1::JailPolicy> = merged(overrides, group)
        .into_iter()
        .map(|(jail, s)| v1::JailPolicy {
            jail,
            enabled: s.enabled,
            maxretry: s.maxretry,
            findtime_ms: ms(s.findtime),
            bantime_ms: ms(s.bantime),
            bantime_factor: s.bantime_factor,
            max_bantime_ms: ms(s.max_bantime),
        })
        .collect();
    let text = format!("{jails:?}");
    v1::JailPolicies {
        version: df2b_tls::hex(&df2b_tls::sha256(text.as_bytes())[..8]),
        jails,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn o(jail: &str, group: Option<&str>, s: JailSettings) -> JailOverride {
        JailOverride {
            jail: jail.into(),
            group: group.map(Into::into),
            settings: s,
            updated_by: "ada".into(),
            updated_at: Utc::now(),
        }
    }

    #[test]
    fn group_wins_field_by_field() {
        let all = o(
            "sshd",
            None,
            JailSettings {
                maxretry: Some(5),
                bantime: Some(Duration::from_secs(3600)),
                ..Default::default()
            },
        );
        let web = o(
            "sshd",
            Some("web"),
            JailSettings {
                maxretry: Some(3),
                ..Default::default()
            },
        );
        let nginx = o(
            "nginx",
            Some("db"),
            JailSettings {
                enabled: Some(false),
                ..Default::default()
            },
        );
        let list = [all, web, nginx];
        let m = merged(&list, "web");
        assert_eq!(m.len(), 1);
        assert_eq!(m[0].1.maxretry, Some(3), "group wins");
        assert_eq!(
            m[0].1.bantime,
            Some(Duration::from_secs(3600)),
            "rest from all agents"
        );
        let m = merged(&list, "db");
        assert_eq!(m.len(), 2);
        assert_eq!(
            m.iter().find(|(j, _)| j == "nginx").unwrap().1.enabled,
            Some(false)
        );
        // versions differ per group and are stable
        assert_ne!(
            for_group(&list, "web").version,
            for_group(&list, "db").version
        );
        assert_eq!(for_group(&list, "web"), for_group(&list, "web"));
        assert!(for_group(&[], "web").jails.is_empty());
    }

    #[test]
    fn validation() {
        let ok = JailSettings {
            maxretry: Some(3),
            findtime: Some(Duration::from_secs(600)),
            bantime: Some(Duration::from_secs(3600)),
            bantime_factor: Some(2.0),
            max_bantime: Some(Duration::from_secs(86400)),
            enabled: Some(true),
        };
        assert!(ok.validate().is_ok());
        for bad in [
            JailSettings {
                maxretry: Some(0),
                ..Default::default()
            },
            JailSettings {
                maxretry: Some(5000),
                ..Default::default()
            },
            JailSettings {
                findtime: Some(Duration::from_secs(30 * 86400)),
                ..Default::default()
            },
            JailSettings {
                bantime: Some(Duration::from_secs(10)),
                ..Default::default()
            },
            JailSettings {
                bantime_factor: Some(0.5),
                ..Default::default()
            },
            JailSettings {
                bantime_factor: Some(f64::NAN),
                ..Default::default()
            },
            JailSettings {
                bantime: Some(Duration::from_secs(7200)),
                max_bantime: Some(Duration::from_secs(3600)),
                ..Default::default()
            },
        ] {
            assert!(bad.validate().is_err(), "{bad:?}");
        }
        assert!(valid_jail("sshd") && valid_jail("nginx-auth.v2"));
        assert!(!valid_jail("") && !valid_jail("a b") && !valid_jail("../x"));
    }
}

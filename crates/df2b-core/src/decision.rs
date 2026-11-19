//! The decision log model: every ban / unban / allow is an append-only
//! decision with a monotonic sequence number assigned by the controller.

use chrono::{DateTime, Utc};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Stable agent identity (the CN of the agent's client certificate).
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(transparent)]
pub struct AgentId(pub String);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DecisionKind {
    Ban,
    /// Revokes an earlier decision (by id).
    Unban {
        revokes: Uuid,
    },
    /// Temporary or permanent allow entry (e.g. "unban and allow for 1h").
    Allow,
}

/// Which agents a decision applies to.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Scope {
    Global,
    Group(String),
    Agents(Vec<AgentId>),
}

/// Who created a decision.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", content = "value", rename_all = "snake_case")]
pub enum Origin {
    Agent(AgentId),
    Correlation(String),
    User(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Decision {
    pub seq: u64,
    pub id: Uuid,
    pub kind: DecisionKind,
    pub target: IpNet,
    pub scope: Scope,
    pub jail: Option<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    pub origin: Origin,
    pub reason: String,
}

impl Decision {
    pub fn is_active(&self, now: DateTime<Utc>) -> bool {
        self.expires_at.map_or(true, |e| e > now)
    }

    pub fn applies_to(&self, agent: &AgentId, groups: &[String]) -> bool {
        match &self.scope {
            Scope::Global => true,
            Scope::Group(g) => groups.iter().any(|x| x == g),
            Scope::Agents(ids) => ids.contains(agent),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample() -> Decision {
        Decision {
            seq: 1,
            id: Uuid::new_v4(),
            kind: DecisionKind::Ban,
            target: "203.0.113.7/32".parse().unwrap(),
            scope: Scope::Group("web".into()),
            jail: Some("sshd".into()),
            created_at: Utc::now(),
            expires_at: Some(Utc::now() + chrono::Duration::hours(1)),
            origin: Origin::Agent(AgentId("web-01".into())),
            reason: "5 failures in 10m".into(),
        }
    }

    #[test]
    fn scope_and_expiry() {
        let d = sample();
        let a = AgentId("web-02".into());
        assert!(d.applies_to(&a, &["web".into()]));
        assert!(!d.applies_to(&a, &["db".into()]));
        assert!(d.is_active(Utc::now()));
        assert!(!d.is_active(Utc::now() + chrono::Duration::hours(2)));
    }

    #[test]
    fn json_roundtrip() {
        let d = sample();
        let s = serde_json::to_string(&d).unwrap();
        assert_eq!(serde_json::from_str::<Decision>(&s).unwrap(), d);
    }
}

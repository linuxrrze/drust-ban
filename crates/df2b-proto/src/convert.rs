//! Conversions between the protocol and `df2b-core` types.

use chrono::{DateTime, TimeZone, Utc};
use df2b_core::{Decision, DecisionKind, Origin};

use crate::v1;

pub fn to_unix_ms(t: DateTime<Utc>) -> i64 {
    t.timestamp_millis()
}

/// `0` (and out-of-range values) map to `None`.
pub fn from_unix_ms(ms: i64) -> Option<DateTime<Utc>> {
    if ms == 0 {
        return None;
    }
    Utc.timestamp_millis_opt(ms).single()
}

pub fn origin_string(o: &Origin) -> String {
    match o {
        Origin::Agent(id) => format!("agent:{}", id.0),
        Origin::Correlation(rule) => format!("correlation:{rule}"),
        Origin::User(name) => format!("user:{name}"),
    }
}

impl From<&Decision> for v1::Decision {
    fn from(d: &Decision) -> Self {
        let (kind, revokes) = match &d.kind {
            DecisionKind::Ban => (v1::DecisionKind::Ban, String::new()),
            DecisionKind::Unban { revokes } => (v1::DecisionKind::Unban, revokes.to_string()),
            DecisionKind::Allow => (v1::DecisionKind::Allow, String::new()),
        };
        Self {
            seq: d.seq,
            id: d.id.to_string(),
            kind: kind.into(),
            target: d.target.to_string(),
            jail: d.jail.clone().unwrap_or_default(),
            created_unix_ms: to_unix_ms(d.created_at),
            expires_unix_ms: d.expires_at.map_or(0, to_unix_ms),
            revokes,
            origin: origin_string(&d.origin),
            reason: d.reason.clone(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use df2b_core::{AgentId, Scope};

    #[test]
    fn decision_to_proto() {
        let now = Utc.timestamp_millis_opt(1_700_000_000_123).unwrap();
        let d = Decision {
            seq: 7,
            id: uuid::Uuid::nil(),
            kind: DecisionKind::Ban,
            target: "2001:db8::/64".parse().unwrap(),
            scope: Scope::Global,
            jail: Some("sshd".into()),
            created_at: now,
            expires_at: None,
            origin: Origin::Agent(AgentId("web-01".into())),
            reason: "r".into(),
        };
        let p = v1::Decision::from(&d);
        assert_eq!(p.kind(), v1::DecisionKind::Ban);
        assert_eq!(p.target, "2001:db8::/64");
        assert_eq!(p.expires_unix_ms, 0);
        assert_eq!(p.origin, "agent:web-01");
        assert_eq!(from_unix_ms(p.created_unix_ms), Some(now));
        assert_eq!(from_unix_ms(0), None);
    }
}

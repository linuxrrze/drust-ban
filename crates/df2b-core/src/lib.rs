//! Shared types for dist-f2b.

pub mod allowlist;
pub mod bantime;
pub mod decision;
pub mod ip;
pub mod redact;
pub mod sample;

pub use allowlist::Allowlist;
pub use bantime::escalated_bantime;
pub use decision::{AgentId, Decision, DecisionKind, Origin, Scope};
pub use ip::{parse_target, reserved, unmap, IpKey, PrefixPolicy};
pub use redact::{RedactRule, Redactor};
pub use sample::sample_line;

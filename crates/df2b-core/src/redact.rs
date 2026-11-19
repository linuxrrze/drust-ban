//! Redaction of sample log lines (DESIGN.md §9 "Sample log lines").
//!
//! A rule replaces every match of a regular expression; the replacement
//! may use capture groups (`$1`, `${name}`; `$$` is a literal `$`). Rules
//! apply in order. The `regex` crate matches in linear time, so an
//! administrator's pattern cannot stall the agent or the controller; the
//! compiled size is bounded as well.

use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};

/// Longest pattern accepted.
pub const MAX_PATTERN: usize = 500;
/// Most rules in one list.
pub const MAX_RULES: usize = 50;
/// Replacement when none is given.
pub const DEFAULT_REPLACE: &str = "[redacted]";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedactRule {
    /// Shown in the UI and audit log (optional in agent.toml).
    #[serde(default)]
    pub name: String,
    pub pattern: String,
    #[serde(default = "default_replace")]
    pub replace: String,
    #[serde(default = "yes")]
    pub enabled: bool,
}

fn default_replace() -> String {
    DEFAULT_REPLACE.to_owned()
}
fn yes() -> bool {
    true
}

/// Compiles one pattern with the limits above.
pub fn compile(pattern: &str) -> Result<Regex, String> {
    if pattern.trim().is_empty() {
        return Err("the pattern is empty".into());
    }
    if pattern.len() > MAX_PATTERN {
        return Err(format!(
            "the pattern is longer than {MAX_PATTERN} characters"
        ));
    }
    let re = RegexBuilder::new(pattern)
        .size_limit(1 << 20)
        .dfa_size_limit(1 << 20)
        .build()
        .map_err(|e| format!("invalid pattern: {e}"))?;
    if re.is_match("") {
        // would insert the replacement between every character
        return Err("the pattern matches the empty string".into());
    }
    Ok(re)
}

/// Compiled rules (the enabled ones).
#[derive(Debug, Clone, Default)]
pub struct Redactor {
    rules: Vec<(Regex, String)>,
}

impl Redactor {
    pub fn new(rules: &[RedactRule]) -> Result<Self, String> {
        if rules.len() > MAX_RULES {
            return Err(format!("at most {MAX_RULES} redaction rules"));
        }
        let mut out = Vec::new();
        for r in rules {
            let re = compile(&r.pattern).map_err(|e| {
                if r.name.is_empty() {
                    e
                } else {
                    format!("{}: {e}", r.name)
                }
            })?;
            if r.enabled {
                out.push((re, r.replace.clone()));
            }
        }
        Ok(Self { rules: out })
    }

    /// Like [`Redactor::new`], but rules that do not compile (or exceed
    /// the limits) are left out; returns their errors. For rules received
    /// from elsewhere, where one bad rule must not drop the others.
    pub fn lenient(rules: &[RedactRule]) -> (Self, Vec<String>) {
        let mut out = Vec::new();
        let mut errors = Vec::new();
        for (i, r) in rules.iter().enumerate() {
            if i >= MAX_RULES {
                errors.push(format!("at most {MAX_RULES} redaction rules"));
                break;
            }
            match Self::new(std::slice::from_ref(r)) {
                Ok(one) => out.extend(one.rules),
                Err(e) => errors.push(e),
            }
        }
        (Self { rules: out }, errors)
    }

    /// These rules, then `other`'s.
    pub fn then(&self, other: &Redactor) -> Redactor {
        Self {
            rules: self.rules.iter().chain(&other.rules).cloned().collect(),
        }
    }

    pub fn len(&self) -> usize {
        self.rules.len()
    }

    pub fn is_empty(&self) -> bool {
        self.rules.is_empty()
    }

    /// The line with every rule applied in order.
    pub fn apply(&self, line: &str) -> String {
        let mut s = line.to_owned();
        for (re, replace) in &self.rules {
            if let std::borrow::Cow::Owned(o) = re.replace_all(&s, replace.as_str()) {
                s = o;
            }
        }
        s
    }
}

/// Common rules offered in the UI: (name, description, pattern, replace),
/// in a working order (credentials before e-mail addresses: `user:pw@host`).
pub const PRESETS: &[(&str, &str, &str, &str)] = &[
    (
        "ssh-user",
        "user names in sshd lines (\"for root from\", \"Invalid user admin\")",
        r"(?i)((?:\bfor|\binvalid user|\billegal user|\buser)\s+)(?:invalid user\s+)?\S+(\s+from\b)",
        "${1}[user]${2}",
    ),
    (
        "auth-header",
        "credentials in Authorization headers and basic-auth URLs",
        r"(?i)(authorization:\s*\w+\s+)\S+|(://)[^/\s:@]+:[^/\s@]+@",
        "${1}${2}[credentials]",
    ),
    (
        "email",
        "e-mail addresses",
        r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}",
        "[email]",
    ),
    (
        "url-query",
        "query strings in URLs (tokens, session ids)",
        r#"\?[^\s"']*"#,
        "?[query]",
    ),
];

#[cfg(test)]
mod tests {
    use super::*;

    fn rule(pattern: &str, replace: &str) -> RedactRule {
        RedactRule {
            name: "t".into(),
            pattern: pattern.into(),
            replace: replace.into(),
            enabled: true,
        }
    }

    fn preset(name: &str) -> RedactRule {
        let p = PRESETS.iter().find(|p| p.0 == name).unwrap();
        rule(p.2, p.3)
    }

    #[test]
    fn rules_apply_in_order_with_groups() {
        let r = Redactor::new(&[
            rule(r"user (\w+)", "user <$1>"),
            rule(r"<root>", "[admin]"),
            RedactRule {
                enabled: false,
                ..rule("from", "FROM")
            },
        ])
        .unwrap();
        assert_eq!(r.apply("user root from x"), "user [admin] from x");
        assert_eq!(r.apply("no match"), "no match");
        assert!(Redactor::default().is_empty());
        // chained: the first redactor's rules run first
        let second = Redactor::new(&[rule(r"\[admin\]", "[x]")]).unwrap();
        assert_eq!(r.then(&second).apply("user root"), "user [x]");
        assert_eq!(second.then(&r).apply("user root"), "user [admin]");
    }

    #[test]
    fn lenient_skips_bad_rules() {
        let (r, errors) = Redactor::lenient(&[rule("(", ""), rule("b", "B"), rule("a*", "")]);
        assert_eq!(r.len(), 1);
        assert_eq!(r.apply("abc"), "aBc");
        assert_eq!(errors.len(), 2, "{errors:?}");
        let (r, errors) = Redactor::lenient(&vec![rule("x", "y"); MAX_RULES + 3]);
        assert_eq!((r.len(), errors.len()), (MAX_RULES, 1));
    }

    #[test]
    fn limits() {
        assert!(compile("(").unwrap_err().contains("invalid"));
        assert!(compile("").is_err());
        assert!(compile("a*").unwrap_err().contains("empty string"));
        assert!(compile(&"a".repeat(MAX_PATTERN + 1)).is_err());
        // huge compiled programs are refused
        assert!(compile(r"\w{1000}\w{1000}\w{1000}").is_err());
        let many = vec![rule("x", "y"); MAX_RULES + 1];
        assert!(Redactor::new(&many).is_err());
        let err = Redactor::new(&[rule("(", "")]).unwrap_err();
        assert!(err.starts_with("t: "), "{err}");
    }

    #[test]
    fn presets() {
        for p in PRESETS {
            compile(p.2).unwrap_or_else(|e| panic!("{}: {e}", p.0));
        }
        let ssh = Redactor::new(&[preset("ssh-user")]).unwrap();
        for (line, want) in [
            (
                "sshd[1]: Failed password for root from 203.0.113.5 port 22 ssh2",
                "sshd[1]: Failed password for [user] from 203.0.113.5 port 22 ssh2",
            ),
            (
                "sshd[1]: Failed password for invalid user admin from 203.0.113.5 port 22",
                "sshd[1]: Failed password for [user] from 203.0.113.5 port 22",
            ),
            (
                "sshd[1]: Invalid user oracle from 203.0.113.5 port 4711",
                "sshd[1]: Invalid user [user] from 203.0.113.5 port 4711",
            ),
            (
                "sshd[1]: Connection closed by authenticating user git 203.0.113.5 port 22",
                "sshd[1]: Connection closed by authenticating user git 203.0.113.5 port 22",
            ),
        ] {
            assert_eq!(ssh.apply(line), want);
        }
        let all =
            Redactor::new(&PRESETS.iter().map(|p| rule(p.2, p.3)).collect::<Vec<_>>()).unwrap();
        assert_eq!(
            all.apply(r#"GET /reset?token=abc123&u=ann@example.org HTTP/1.1" 401 "https://bob:hunter2@example.com/""#),
            r#"GET /reset?[query] HTTP/1.1" 401 "https://[credentials]example.com/""#
        );
        assert_eq!(
            all.apply("mail from ann.lee@mail.example.co.uk rejected"),
            "mail from [email] rejected"
        );
        assert_eq!(
            all.apply("Authorization: Bearer eyJhbGciOi.x.y bad"),
            "Authorization: Bearer [credentials] bad"
        );
    }
}

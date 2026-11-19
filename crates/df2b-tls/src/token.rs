//! Enrollment tokens: `df2b1.<secret>.<ca-fingerprint>` (both base64url).
//!
//! The secret authenticates the agent to the controller (the controller only
//! stores its SHA-256). The CA fingerprint authenticates the controller to the
//! agent: the agent pins it during the enrollment handshake, so there is no
//! trust on first use.

use std::fmt;
use std::str::FromStr;

use anyhow::{bail, Context};
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64;
use base64::Engine;

use crate::{hex, random_bytes, sha256};

const PREFIX: &str = "df2b1";

#[derive(Clone, PartialEq, Eq)]
pub struct EnrollToken {
    pub secret: [u8; 32],
    pub ca_fingerprint: [u8; 32],
}

impl EnrollToken {
    pub fn generate(ca_fingerprint: [u8; 32]) -> Self {
        Self {
            secret: random_bytes(),
            ca_fingerprint,
        }
    }

    /// What the controller stores and looks up (hex SHA-256 of the secret).
    pub fn secret_hash(&self) -> String {
        secret_hash(&self.secret)
    }
}

pub fn secret_hash(secret: &[u8]) -> String {
    hex(&sha256(secret))
}

impl fmt::Display for EnrollToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{PREFIX}.{}.{}",
            B64.encode(self.secret),
            B64.encode(self.ca_fingerprint)
        )
    }
}

// never print the secret
impl fmt::Debug for EnrollToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("EnrollToken")
            .field("ca_fingerprint", &hex(&self.ca_fingerprint))
            .finish_non_exhaustive()
    }
}

impl FromStr for EnrollToken {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let mut parts = s.trim().split('.');
        let (Some(PREFIX), Some(secret), Some(fp), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            bail!("malformed enrollment token (expected df2b1.<secret>.<fingerprint>)");
        };
        let decode = |p: &str, what: &str| -> anyhow::Result<[u8; 32]> {
            B64.decode(p)
                .ok()
                .and_then(|v| v.try_into().ok())
                .with_context(|| format!("malformed enrollment token ({what})"))
        };
        Ok(Self {
            secret: decode(secret, "secret")?,
            ca_fingerprint: decode(fp, "fingerprint")?,
        })
    }
}

/// REST API bearer token: `df2bapi1.<secret>` (base64url). The controller
/// stores only the SHA-256 of the secret.
#[derive(Clone, PartialEq, Eq)]
pub struct ApiToken {
    pub secret: [u8; 32],
}

const API_PREFIX: &str = "df2bapi1";

impl ApiToken {
    pub fn generate() -> Self {
        Self {
            secret: random_bytes(),
        }
    }

    pub fn secret_hash(&self) -> String {
        secret_hash(&self.secret)
    }
}

impl fmt::Display for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{API_PREFIX}.{}", B64.encode(self.secret))
    }
}

impl fmt::Debug for ApiToken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("ApiToken(..)")
    }
}

impl FromStr for ApiToken {
    type Err = anyhow::Error;

    fn from_str(s: &str) -> anyhow::Result<Self> {
        let secret = s
            .trim()
            .strip_prefix(API_PREFIX)
            .and_then(|r| r.strip_prefix('.'))
            .and_then(|r| B64.decode(r).ok())
            .and_then(|v| <[u8; 32]>::try_from(v).ok())
            .context("malformed API token (expected df2bapi1.<secret>)")?;
        Ok(Self { secret })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_token_roundtrip() {
        let t = ApiToken::generate();
        assert_eq!(t.to_string().parse::<ApiToken>().unwrap(), t);
        assert_eq!(format!("{t:?}"), "ApiToken(..)");
        for bad in ["", "df2bapi1.", "df2bapi1.abc", "df2b1.x.y"] {
            assert!(bad.parse::<ApiToken>().is_err(), "{bad}");
        }
    }

    #[test]
    fn roundtrip_and_rejects_garbage() {
        let t = EnrollToken::generate([7; 32]);
        let s = t.to_string();
        assert!(s.starts_with("df2b1."));
        assert_eq!(s.parse::<EnrollToken>().unwrap(), t);
        assert!(!format!("{t:?}").contains(&B64.encode(t.secret)));
        for bad in ["", "df2b1.a.b", "df2b2.x.y", &format!("{s}.extra")] {
            assert!(bad.parse::<EnrollToken>().is_err(), "{bad}");
        }
    }
}

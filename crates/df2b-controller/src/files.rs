//! Files in the controller state directory.
//!
//! ```text
//! <state_dir>/ca.pem, ca.key        internal CA (key 0600)
//! <state_dir>/enroll-tokens/<sha256(secret)>.json   pending one-time tokens
//! <state_dir>/revoked/<agent-id>    revoked agents
//! <state_dir>/controller.redb       agents + decision log (see store.rs)
//! ```
//!
//! Token creation and revocation work by writing files, so they also work
//! while the controller runs (redb allows a single process) and require
//! write access to the state directory, i.e. the administrator.
//! TODO: expose both through the authenticated REST API for `df2bctl`.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use df2b_tls::{Ca, EnrollToken};
use serde::{Deserialize, Serialize};

const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca.key";
const TOKENS: &str = "enroll-tokens";
const REVOKED: &str = "revoked";

/// Writes `data` atomically (temp file + rename) with `mode`.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension(format!("tmp{}", std::process::id()));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(mode)
        .open(&tmp)?;
    f.write_all(data)?;
    f.sync_all()?;
    fs::rename(&tmp, path)
}

/// Loads the CA, creating it on first start.
pub fn load_or_create_ca(dir: &Path) -> anyhow::Result<Ca> {
    if dir.join(CA_CERT).exists() {
        return load_ca(dir);
    }
    fs::create_dir_all(dir).with_context(|| format!("creating {}", dir.display()))?;
    fs::set_permissions(dir, fs::Permissions::from_mode(0o700))?;
    let ca = Ca::generate("dist-f2b controller CA")?;
    // key first: a certificate without key would look like a valid CA
    write_atomic(&dir.join(CA_KEY), ca.key_pem().as_bytes(), 0o600)?;
    write_atomic(&dir.join(CA_CERT), ca.cert_pem().as_bytes(), 0o644)?;
    tracing::info!(
        fingerprint = %df2b_tls::hex(&ca.fingerprint()),
        "created internal CA"
    );
    Ok(ca)
}

pub fn load_ca(dir: &Path) -> anyhow::Result<Ca> {
    let read = |name: &str| {
        let p = dir.join(name);
        fs::read_to_string(&p).with_context(|| format!("reading {}", p.display()))
    };
    let (cert, key) = (read(CA_CERT)?, read(CA_KEY)?);
    Ca::from_pem(&cert, &key).context("loading CA")
}

#[derive(Debug, Serialize, Deserialize)]
pub struct TokenFile {
    pub group: String,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
}

fn token_dir(dir: &Path) -> PathBuf {
    dir.join(TOKENS)
}

/// Creates a one-time enrollment token. Only the secret's hash is stored.
pub fn create_token(dir: &Path, group: &str, ttl: Duration) -> anyhow::Result<EnrollToken> {
    if group.is_empty()
        || !group
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
    {
        bail!("invalid group name {group:?} (allowed: letters, digits, - _ .)");
    }
    let ca =
        load_ca(dir).context("the controller must have been started once (it creates the CA)")?;
    let token = EnrollToken::generate(ca.fingerprint());
    let now = Utc::now();
    let file = TokenFile {
        group: group.to_owned(),
        created_at: now,
        expires_at: now + chrono::Duration::from_std(ttl)?,
    };
    let tdir = token_dir(dir);
    fs::create_dir_all(&tdir)?;
    // readable by the controller even when created by root
    write_atomic(
        &tdir.join(format!("{}.json", token.secret_hash())),
        &serde_json::to_vec_pretty(&file)?,
        0o644,
    )?;
    Ok(token)
}

/// Consumes a token: succeeds at most once per token (atomic rename).
/// Returns `None` for unknown, used or expired tokens.
pub fn redeem_token(dir: &Path, token: &EnrollToken) -> anyhow::Result<Option<TokenFile>> {
    let tdir = token_dir(dir);
    let path = tdir.join(format!("{}.json", token.secret_hash()));
    let claimed = tdir.join(format!(
        "{}.redeemed-{}",
        token.secret_hash(),
        df2b_tls::hex(&df2b_tls::random_bytes::<4>())
    ));
    match fs::rename(&path, &claimed) {
        Ok(()) => {}
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e.into()),
    }
    let data = fs::read(&claimed);
    let _ = fs::remove_file(&claimed);
    let file: TokenFile = serde_json::from_slice(&data?)?;
    Ok((file.expires_at > Utc::now()).then_some(file))
}

/// Deletes expired, never-used tokens.
pub fn prune_tokens(dir: &Path) {
    let Ok(entries) = fs::read_dir(token_dir(dir)) else {
        return;
    };
    for e in entries.flatten() {
        let p = e.path();
        let expired = fs::read(&p)
            .ok()
            .and_then(|d| serde_json::from_slice::<TokenFile>(&d).ok())
            .is_some_and(|t| t.expires_at <= Utc::now());
        if expired {
            let _ = fs::remove_file(&p);
        }
    }
}

fn valid_agent_id(id: &str) -> bool {
    !id.is_empty()
        && id.len() <= 64
        && id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '.')
        && !id.starts_with('.')
}

pub fn revoke(dir: &Path, agent_id: &str) -> anyhow::Result<()> {
    if !valid_agent_id(agent_id) {
        bail!("invalid agent id {agent_id:?}");
    }
    let rdir = dir.join(REVOKED);
    fs::create_dir_all(&rdir)?;
    write_atomic(
        &rdir.join(agent_id),
        Utc::now().to_rfc3339().as_bytes(),
        0o644,
    )?;
    Ok(())
}

pub fn is_revoked(dir: &Path, agent_id: &str) -> bool {
    !valid_agent_id(agent_id) || dir.join(REVOKED).join(agent_id).exists()
}

/// Agent id derived from the reported hostname plus a random suffix.
pub fn new_agent_id(hostname: &str) -> String {
    let mut host: String = hostname
        .chars()
        .map(|c| c.to_ascii_lowercase())
        .filter(|c| c.is_ascii_alphanumeric() || *c == '-' || *c == '.')
        .take(48)
        .collect();
    host = host.trim_matches(|c| c == '.' || c == '-').to_owned();
    if host.is_empty() {
        host = "agent".into();
    }
    format!("{host}-{}", df2b_tls::hex(&df2b_tls::random_bytes::<3>()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("df2b-ctl-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        d
    }

    #[test]
    fn tokens_are_one_time_and_expire() {
        let dir = tmp("tok");
        let ca = load_or_create_ca(&dir).unwrap();
        assert_eq!(
            load_ca(&dir).unwrap().fingerprint(),
            ca.fingerprint(),
            "CA must be stable across loads"
        );
        let t = create_token(&dir, "web", Duration::from_secs(3600)).unwrap();
        assert_eq!(t.ca_fingerprint, ca.fingerprint());
        assert_eq!(redeem_token(&dir, &t).unwrap().unwrap().group, "web");
        assert!(redeem_token(&dir, &t).unwrap().is_none(), "second use");

        let t = create_token(&dir, "web", Duration::from_secs(0)).unwrap();
        assert!(redeem_token(&dir, &t).unwrap().is_none(), "expired");
        assert!(create_token(&dir, "../x", Duration::from_secs(1)).is_err());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn agent_ids_and_revocation() {
        let dir = tmp("rev");
        let id = new_agent_id("Web-01.example.org");
        assert!(id.starts_with("web-01.example.org-"), "{id}");
        assert!(new_agent_id("../../etc").starts_with("etc-"));
        assert!(new_agent_id("").starts_with("agent-"));
        assert!(!is_revoked(&dir, &id));
        revoke(&dir, &id).unwrap();
        assert!(is_revoked(&dir, &id));
        assert!(revoke(&dir, "../x").is_err());
        assert!(is_revoked(&dir, "../x"), "invalid ids are never accepted");
        let _ = fs::remove_dir_all(&dir);
    }
}

//! Files in the controller state directory.
//!
//! ```text
//! <state_dir>/ca.pem, ca.key        internal CA (key 0600)
//! <state_dir>/enroll-tokens/<sha256(secret)>.json   pending one-time tokens
//! <state_dir>/revoked/<agent-id>    revoked agents
//! <state_dir>/api-tokens/<sha256(secret)>.json      REST API tokens
//! <state_dir>/users/<name>.json      web UI users (argon2id hash, 0600)
//! <state_dir>/controller.redb       agents + decision log (see store.rs)
//! ```
//!
//! Tokens and revocations are files, so the controller's subcommands work
//! while it runs (redb allows a single process); they require write access
//! to the state directory, i.e. the administrator. The REST API uses the same
//! functions. Only hashes of token secrets are stored.

use std::fs;
use std::io::{self, Write};
use std::os::unix::fs::{OpenOptionsExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{bail, Context};
use chrono::{DateTime, Utc};
use clap::ValueEnum;
use df2b_tls::{ApiToken, Ca, EnrollToken};
use serde::{Deserialize, Serialize};

const CA_CERT: &str = "ca.pem";
const CA_KEY: &str = "ca.key";
const TOKENS: &str = "enroll-tokens";
const REVOKED: &str = "revoked";
const API_TOKENS: &str = "api-tokens";
const USERS: &str = "users";

/// Shortest accepted password.
pub const MIN_PASSWORD_LEN: usize = 12;

/// Writes `data` atomically (temp file + rename) with `mode`.
/// The temporary file is new (random name, `O_EXCL`, no symlinks
/// followed): run by root on a directory the controller's user can write,
/// a planted symlink must not redirect the write.
pub fn write_atomic(path: &Path, data: &[u8], mode: u32) -> io::Result<()> {
    let tmp = path.with_extension(format!(
        "tmp-{}",
        df2b_tls::hex(&df2b_tls::random_bytes::<8>())
    ));
    let mut f = fs::OpenOptions::new()
        .write(true)
        .create_new(true)
        .custom_flags(libc::O_NOFOLLOW)
        .mode(mode)
        .open(&tmp)?;
    let written = f.write_all(data).and_then(|()| f.sync_all());
    if let Err(e) = written {
        let _ = fs::remove_file(&tmp);
        return Err(e);
    }
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
/// Group names: letters, digits, - _ . (at most 64).
pub fn valid_group(group: &str) -> bool {
    !group.is_empty()
        && group.len() <= 64
        && group
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.".contains(c))
}

pub fn create_token(dir: &Path, group: &str, ttl: Duration) -> anyhow::Result<EnrollToken> {
    if !valid_group(group) {
        bail!("invalid group name {group:?} (allowed: letters, digits, - _ .)");
    }
    let ca =
        load_ca(dir).context("the controller must have been started once (it creates the CA)")?;
    let token = EnrollToken::generate(ca.fingerprint());
    let now = Utc::now();
    let file = TokenFile {
        group: group.to_owned(),
        created_at: now,
        expires_at: chrono::Duration::from_std(ttl)
            .ok()
            .and_then(|d| now.checked_add_signed(d))
            .context("ttl out of range")?,
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
/// Whether an unused token file exists (cheap; checked before any work
/// for an enrollment - only redeeming it is authoritative).
pub fn token_exists(dir: &Path, token: &EnrollToken) -> bool {
    token_dir(dir)
        .join(format!("{}.json", token.secret_hash()))
        .is_file()
}

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

/// REST API roles (DESIGN.md §9), ordered by privilege.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// Read everything except the audit log.
    Viewer,
    /// Viewer + ban / unban.
    Operator,
    /// Everything: agents, enrollment tokens, audit log.
    Admin,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ApiTokenFile {
    pub name: String,
    pub role: Role,
    pub created_at: DateTime<Utc>,
    pub expires_at: Option<DateTime<Utc>>,
    /// User who created it in the web UI; none: on the controller host.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub created_by: Option<String>,
}

/// Audit actor for back-channel logouts; not available as a name.
pub const RESERVED_NAMES: &[&str] = &["oidc-provider"];

pub fn valid_name(name: &str) -> bool {
    !RESERVED_NAMES.contains(&name)
        && !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || "-_.@".contains(c))
}

pub fn list_api_tokens(dir: &Path) -> anyhow::Result<Vec<ApiTokenFile>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir.join(API_TOKENS)) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for e in entries.flatten() {
        if e.path().extension().is_some_and(|x| x == "json") {
            if let Ok(t) = serde_json::from_slice::<ApiTokenFile>(&fs::read(e.path())?) {
                out.push(t);
            }
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

pub fn create_api_token(
    dir: &Path,
    name: &str,
    role: Role,
    ttl: Option<Duration>,
) -> anyhow::Result<ApiToken> {
    create_api_token_by(dir, name, role, ttl, None)
}

pub fn create_api_token_by(
    dir: &Path,
    name: &str,
    role: Role,
    ttl: Option<Duration>,
    created_by: Option<&str>,
) -> anyhow::Result<ApiToken> {
    if !valid_name(name) {
        bail!("invalid token name {name:?} (allowed: letters, digits, - _ . @)");
    }
    if list_api_tokens(dir)?.iter().any(|t| t.name == name) {
        bail!("an API token named {name:?} exists already (revoke it first)");
    }
    if user_path(dir, name).exists() {
        bail!("{name:?} is a user name; API tokens and users share one namespace (audit log)");
    }
    let token = ApiToken::generate();
    let now = Utc::now();
    let file = ApiTokenFile {
        name: name.to_owned(),
        role,
        created_at: now,
        expires_at: ttl
            .map(|d| {
                chrono::Duration::from_std(d)
                    .ok()
                    .and_then(|d| now.checked_add_signed(d))
                    .context("ttl out of range")
            })
            .transpose()?,
        created_by: created_by.map(str::to_owned),
    };
    let tdir = dir.join(API_TOKENS);
    fs::create_dir_all(&tdir)?;
    write_atomic(
        &tdir.join(format!("{}.json", token.secret_hash())),
        &serde_json::to_vec_pretty(&file)?,
        0o644, // only a hash; readable by the controller when created by root
    )?;
    Ok(token)
}

/// Deletes the token named `name`; false if there is none.
pub fn revoke_api_token(dir: &Path, name: &str) -> anyhow::Result<bool> {
    let Ok(entries) = fs::read_dir(dir.join(API_TOKENS)) else {
        return Ok(false);
    };
    let mut found = false;
    for e in entries.flatten() {
        let matches = fs::read(e.path())
            .ok()
            .and_then(|d| serde_json::from_slice::<ApiTokenFile>(&d).ok())
            .is_some_and(|t| t.name == name);
        if matches {
            fs::remove_file(e.path())?;
            found = true;
        }
    }
    Ok(found)
}

/// The token's record if it exists and has not expired.
pub fn lookup_api_token(dir: &Path, token: &ApiToken) -> Option<ApiTokenFile> {
    let path = dir
        .join(API_TOKENS)
        .join(format!("{}.json", token.secret_hash()));
    let t: ApiTokenFile = serde_json::from_slice(&fs::read(path).ok()?).ok()?;
    t.expires_at.map_or(true, |e| e > Utc::now()).then_some(t)
}

// -------------------------------------------------------------------- users

/// A web UI user. Created, changed and deleted on the controller host
/// (`df2b-controller user ...`); read on every request, so deletion and role
/// or password changes take effect immediately.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UserFile {
    pub name: String,
    pub role: Role,
    /// argon2id, PHC string format
    pub password_hash: String,
    pub created_at: DateTime<Utc>,
    /// Sessions created before this are invalid.
    pub password_changed_at: DateTime<Utc>,
    /// Set by an admin (temporary password): the user must choose a new
    /// one before doing anything else.
    #[serde(default)]
    pub must_change_password: bool,
}

/// Longest accepted password (argon2 hashes anything, but bound the work).
pub const MAX_PASSWORD_LEN: usize = 1024;

/// Password rules (length; not the user name).
pub fn check_password(name: &str, password: &str) -> anyhow::Result<()> {
    let n = password.chars().count();
    if n < MIN_PASSWORD_LEN {
        bail!("password must have at least {MIN_PASSWORD_LEN} characters");
    }
    if password.len() > MAX_PASSWORD_LEN {
        bail!("password is too long");
    }
    if password.trim().eq_ignore_ascii_case(name) {
        bail!("password must not be the user name");
    }
    Ok(())
}

fn user_path(dir: &Path, name: &str) -> PathBuf {
    dir.join(USERS).join(format!("{name}.json"))
}

fn hash_password(password: &str) -> anyhow::Result<String> {
    use argon2::password_hash::{rand_core::OsRng, PasswordHasher, SaltString};
    if password.chars().count() < MIN_PASSWORD_LEN {
        bail!("password must have at least {MIN_PASSWORD_LEN} characters");
    }
    let salt = SaltString::generate(&mut OsRng);
    Ok(argon2::Argon2::default()
        .hash_password(password.as_bytes(), &salt)
        .map_err(|e| anyhow::anyhow!("hashing password: {e}"))?
        .to_string())
}

/// Constant work whether or not `hash` belongs to a real user.
pub fn verify_password(hash: Option<&str>, password: &str) -> bool {
    use argon2::password_hash::{PasswordHash, PasswordVerifier};
    static DUMMY: std::sync::OnceLock<String> = std::sync::OnceLock::new();
    let dummy = DUMMY.get_or_init(|| {
        hash_password(&df2b_tls::hex(&df2b_tls::random_bytes::<16>())).expect("hashing")
    });
    let (hash, real) = match hash {
        Some(h) => (h, true),
        None => (dummy.as_str(), false),
    };
    let Ok(parsed) = PasswordHash::new(hash) else {
        return false;
    };
    let ok = argon2::Argon2::default()
        .verify_password(password.as_bytes(), &parsed)
        .is_ok();
    ok && real
}

fn write_user(dir: &Path, u: &UserFile) -> anyhow::Result<()> {
    let udir = dir.join(USERS);
    fs::create_dir_all(&udir)?;
    fs::set_permissions(&udir, fs::Permissions::from_mode(0o700))?;
    // the hash allows offline guessing: readable by the controller only
    write_atomic(
        &user_path(dir, &u.name),
        &serde_json::to_vec_pretty(u)?,
        0o600,
    )?;
    Ok(())
}

pub fn create_user(dir: &Path, name: &str, role: Role, password: &str) -> anyhow::Result<()> {
    create_user_with(dir, name, role, password, false)
}

/// `temporary`: the user must change the password at the first login.
pub fn create_user_with(
    dir: &Path,
    name: &str,
    role: Role,
    password: &str,
    temporary: bool,
) -> anyhow::Result<()> {
    if !valid_name(name) {
        bail!("invalid user name {name:?} (allowed: letters, digits, - _ . @)");
    }
    if user_path(dir, name).exists() {
        bail!("user {name:?} exists already");
    }
    if list_api_tokens(dir)?.iter().any(|t| t.name == name) {
        bail!(
            "{name:?} is an API token name; API tokens and users share one namespace (audit log)"
        );
    }
    check_password(name, password)?;
    let now = Utc::now();
    write_user(
        dir,
        &UserFile {
            name: name.to_owned(),
            role,
            password_hash: hash_password(password)?,
            created_at: now,
            password_changed_at: now,
            must_change_password: temporary,
        },
    )
}

/// The user, if `name` is valid and exists.
pub fn load_user(dir: &Path, name: &str) -> anyhow::Result<Option<UserFile>> {
    if !valid_name(name) {
        return Ok(None);
    }
    match fs::read(user_path(dir, name)) {
        Ok(d) => Ok(Some(serde_json::from_slice(&d)?)),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e).with_context(|| format!("reading user {name:?}")),
    }
}

pub fn list_users(dir: &Path) -> anyhow::Result<Vec<UserFile>> {
    let mut out = Vec::new();
    let entries = match fs::read_dir(dir.join(USERS)) {
        Ok(e) => e,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(out),
        Err(e) => return Err(e.into()),
    };
    for e in entries.flatten() {
        if e.path().extension().is_some_and(|x| x == "json") {
            out.push(serde_json::from_slice::<UserFile>(&fs::read(e.path())?)?);
        }
    }
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Sets a new password and/or role; a new password ends all sessions.
pub fn update_user(
    dir: &Path,
    name: &str,
    role: Option<Role>,
    password: Option<&str>,
) -> anyhow::Result<()> {
    let mut u = load_user(dir, name)?.with_context(|| format!("no user {name:?}"))?;
    if let Some(r) = role {
        u.role = r;
    }
    if let Some(p) = password {
        check_password(name, p)?;
        u.password_hash = hash_password(p)?;
        u.password_changed_at = Utc::now();
        u.must_change_password = false;
    }
    write_user(dir, &u)
}

/// Sets a password; `temporary` (admin reset) forces a change at the next
/// login. Ends the user's sessions. Returns the new `password_changed_at`.
pub fn set_password(
    dir: &Path,
    name: &str,
    password: &str,
    temporary: bool,
) -> anyhow::Result<DateTime<Utc>> {
    let mut u = load_user(dir, name)?.with_context(|| format!("no user {name:?}"))?;
    check_password(name, password)?;
    u.password_hash = hash_password(password)?;
    // strictly later than before, so older sessions never match
    u.password_changed_at =
        Utc::now().max(u.password_changed_at + chrono::Duration::microseconds(1));
    u.must_change_password = temporary;
    write_user(dir, &u)?;
    Ok(u.password_changed_at)
}

/// False if there is no such user.
pub fn delete_user(dir: &Path, name: &str) -> anyhow::Result<bool> {
    if !valid_name(name) {
        return Ok(false);
    }
    match fs::remove_file(user_path(dir, name)) {
        Ok(()) => Ok(true),
        Err(e) if e.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(e) => Err(e.into()),
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
    fn api_tokens() {
        let dir = tmp("api");
        let t = create_api_token(&dir, "alice", Role::Operator, None).unwrap();
        assert!(
            create_api_token(&dir, "alice", Role::Admin, None).is_err(),
            "duplicate"
        );
        assert!(create_api_token(&dir, "a/b", Role::Admin, None).is_err());
        assert_eq!(lookup_api_token(&dir, &t).unwrap().role, Role::Operator);
        assert!(lookup_api_token(&dir, &ApiToken::generate()).is_none());
        let old = create_api_token(&dir, "old", Role::Admin, Some(Duration::ZERO)).unwrap();
        assert!(lookup_api_token(&dir, &old).is_none(), "expired");
        assert_eq!(list_api_tokens(&dir).unwrap().len(), 2);
        assert!(revoke_api_token(&dir, "alice").unwrap());
        assert!(!revoke_api_token(&dir, "alice").unwrap());
        assert!(lookup_api_token(&dir, &t).is_none());
        assert!(Role::Admin > Role::Operator && Role::Operator > Role::Viewer);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn users() {
        let dir = tmp("users");
        assert!(create_user(&dir, "alice", Role::Admin, "short").is_err());
        create_user(&dir, "alice", Role::Admin, "correct horse battery").unwrap();
        assert!(create_user(&dir, "alice", Role::Viewer, "another long password").is_err());
        assert!(create_user(&dir, "../x", Role::Viewer, "another long password").is_err());
        create_api_token(&dir, "ci", Role::Viewer, None).unwrap();
        assert!(create_user(&dir, "ci", Role::Viewer, "another long password").is_err());
        assert!(create_api_token(&dir, "alice", Role::Viewer, None).is_err());

        let u = load_user(&dir, "alice").unwrap().unwrap();
        assert!(u.password_hash.starts_with("$argon2id$"));
        let mode = fs::metadata(user_path(&dir, "alice"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
        assert!(verify_password(
            Some(&u.password_hash),
            "correct horse battery"
        ));
        assert!(!verify_password(
            Some(&u.password_hash),
            "wrong horse battery"
        ));
        assert!(!verify_password(None, "correct horse battery"));
        assert!(load_user(&dir, "../../etc/passwd").unwrap().is_none());

        update_user(
            &dir,
            "alice",
            Some(Role::Viewer),
            Some("a new long password"),
        )
        .unwrap();
        let v = load_user(&dir, "alice").unwrap().unwrap();
        assert_eq!(v.role, Role::Viewer);
        assert!(v.password_changed_at > u.password_changed_at);
        assert!(verify_password(
            Some(&v.password_hash),
            "a new long password"
        ));
        assert_eq!(list_users(&dir).unwrap().len(), 1);
        assert!(
            set_password(&dir, "alice", "alice", false).is_err(),
            "too short"
        );
        assert!(set_password(&dir, "alice", "Alice", false).is_err());
        create_user(&dir, "longername1234", Role::Viewer, "longername1234").unwrap_err();
        let t = set_password(&dir, "alice", "temporary password", true).unwrap();
        let w = load_user(&dir, "alice").unwrap().unwrap();
        assert!(w.must_change_password && w.password_changed_at == t && t > v.password_changed_at);
        update_user(&dir, "alice", None, Some("chosen by alice herself")).unwrap();
        assert!(
            !load_user(&dir, "alice")
                .unwrap()
                .unwrap()
                .must_change_password
        );
        // files from before the flag existed still load
        let old = r#"{"name":"old","role":"viewer","password_hash":"$argon2id$x","created_at":"2026-01-01T00:00:00Z","password_changed_at":"2026-01-01T00:00:00Z"}"#;
        assert!(
            !serde_json::from_str::<UserFile>(old)
                .unwrap()
                .must_change_password
        );
        assert!(delete_user(&dir, "alice").unwrap());
        assert!(!delete_user(&dir, "alice").unwrap());
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

    /// Regression (security review): a huge --ttl on the host CLI
    /// overflowed the date arithmetic (panic).
    #[test]
    fn huge_ttl_is_an_error() {
        let dir = std::env::temp_dir().join(format!("df2b-files-ttl-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        load_or_create_ca(&dir).unwrap();
        assert!(create_token(&dir, "web", Duration::MAX).is_err());
        assert!(create_api_token(&dir, "x", Role::Viewer, Some(Duration::MAX)).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn write_atomic_replaces_with_a_fresh_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("df2b-files-atomic-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("x.json");
        write_atomic(&p, b"one", 0o600).unwrap();
        write_atomic(&p, b"two", 0o600).unwrap();
        assert_eq!(std::fs::read(&p).unwrap(), b"two");
        assert_eq!(
            std::fs::metadata(&p).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert_eq!(
            std::fs::read_dir(&dir).unwrap().count(),
            1,
            "no temp files left"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

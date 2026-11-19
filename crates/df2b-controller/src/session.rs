//! Browser sessions for the web UI.
//!
//! Login with a local user (argon2id, see files.rs) sets a cookie
//! `__Host-df2b_session` (Secure, HttpOnly, SameSite=Strict, Path=/). The
//! controller keeps only the SHA-256 of the session secret, in memory: a
//! restart logs everybody out. Each session has a CSRF token that requests
//! other than GET/HEAD must echo in `X-CSRF-Token`.
//!
//! Sessions end after `IDLE` without requests, after their maximum age
//! (`MAX_AGE`, OIDC: `session_lifetime`), on logout, and for local users as
//! soon as the user is deleted or their password changes (the user file is
//! read on every request). OIDC sessions keep the role from the login.
//!
//! Failed logins are limited per client (IPv6: per /64) and per user name.

use std::collections::HashMap;
use std::net::IpAddr;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use base64::Engine;
use chrono::{DateTime, Utc};

use crate::files::Role;

pub const COOKIE: &str = "__Host-df2b_session";
pub const CSRF_HEADER: &str = "x-csrf-token";
pub const IDLE: Duration = Duration::from_secs(4 * 3600);
pub const MAX_AGE: Duration = Duration::from_secs(24 * 3600);

/// Failed logins allowed per window, per client network and per user name.
const MAX_FAILURES_PER_CLIENT: u32 = 10;
const MAX_FAILURES_PER_USER: u32 = 30;
const FAILURE_WINDOW: Duration = Duration::from_secs(15 * 60);

/// How the user logged in.
#[derive(Debug, Clone)]
pub enum Kind {
    /// Local user; the user's `password_changed_at` at login.
    Password { password_changed_at: DateTime<Utc> },
    /// OpenID Connect; role as mapped at login; subject and provider
    /// session id for back-channel logout.
    Oidc {
        role: Role,
        subject: String,
        sid: Option<String>,
    },
}

#[derive(Debug, Clone)]
pub struct Session {
    pub user: String,
    pub csrf: String,
    pub kind: Kind,
    max_age: Duration,
    created: Instant,
    last_used: Instant,
}

impl Session {
    fn expired(&self, now: Instant) -> bool {
        now.duration_since(self.created) > self.max_age || now.duration_since(self.last_used) > IDLE
    }
}

#[derive(Default)]
struct Failures {
    count: u32,
    since: Option<Instant>,
}

impl Failures {
    fn current(&mut self, now: Instant) -> u32 {
        if self
            .since
            .is_some_and(|s| now.duration_since(s) > FAILURE_WINDOW)
        {
            *self = Self::default();
        }
        self.count
    }

    fn add(&mut self, now: Instant) {
        self.current(now);
        self.since.get_or_insert(now);
        self.count += 1;
    }
}

#[derive(Default)]
pub struct Sessions {
    sessions: Mutex<HashMap<[u8; 32], Session>>,
    by_client: Mutex<HashMap<IpAddr, Failures>>,
    by_user: Mutex<HashMap<String, Failures>>,
}

fn key(secret: &str) -> [u8; 32] {
    df2b_tls::sha256(secret.as_bytes())
}

fn random_token() -> String {
    URL_SAFE_NO_PAD.encode(df2b_tls::random_bytes::<32>())
}

/// IPv6 clients usually control a whole /64.
fn client_key(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => match v6.to_ipv4_mapped() {
            Some(v4) => IpAddr::V4(v4),
            None => {
                let s = v6.segments();
                IpAddr::V6([s[0], s[1], s[2], s[3], 0, 0, 0, 0].into())
            }
        },
        v4 => v4,
    }
}

/// Compares in time independent of where the inputs differ.
pub fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    a.len() == b.len() && a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

impl Sessions {
    fn lock<T>(m: &Mutex<T>) -> std::sync::MutexGuard<'_, T> {
        m.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Whether another login attempt is allowed now.
    pub fn login_allowed(&self, client: Option<IpAddr>, user: &str) -> bool {
        let now = Instant::now();
        let client_ok = client.map_or(true, |ip| {
            Self::lock(&self.by_client)
                .entry(client_key(ip))
                .or_default()
                .current(now)
                < MAX_FAILURES_PER_CLIENT
        });
        let user_ok = Self::lock(&self.by_user)
            .get_mut(user)
            .map_or(true, |f| f.current(now) < MAX_FAILURES_PER_USER);
        client_ok && user_ok
    }

    pub fn login_failed(&self, client: Option<IpAddr>, user: &str) {
        let now = Instant::now();
        if let Some(ip) = client {
            Self::lock(&self.by_client)
                .entry(client_key(ip))
                .or_default()
                .add(now);
        }
        // only names that exist would be worth limiting, but checking that
        // here would reveal which do; bound the map instead
        let mut by_user = Self::lock(&self.by_user);
        if by_user.len() < 10_000 || by_user.contains_key(user) {
            by_user.entry(user.to_owned()).or_default().add(now);
        }
    }

    /// Creates a session; returns the cookie secret and the session.
    pub fn create(&self, user: &str, kind: Kind, max_age: Duration) -> (String, Session) {
        let secret = random_token();
        let now = Instant::now();
        let s = Session {
            user: user.to_owned(),
            csrf: random_token(),
            kind,
            max_age: max_age.min(MAX_AGE),
            created: now,
            last_used: now,
        };
        Self::lock(&self.sessions).insert(key(&secret), s.clone());
        (secret, s)
    }

    /// The live session for a cookie secret (and marks it used).
    pub fn get(&self, secret: &str) -> Option<Session> {
        let now = Instant::now();
        let mut map = Self::lock(&self.sessions);
        let k = key(secret);
        let s = map.get_mut(&k)?;
        if s.expired(now) {
            map.remove(&k);
            return None;
        }
        s.last_used = now;
        Some(s.clone())
    }

    pub fn remove(&self, secret: &str) {
        Self::lock(&self.sessions).remove(&key(secret));
    }

    /// Back-channel logout: ends the OIDC sessions with this provider
    /// session id (if given) or else all of this subject. Returns how many.
    pub fn end_oidc(&self, subject: Option<&str>, sid: Option<&str>) -> usize {
        let mut map = Self::lock(&self.sessions);
        let before = map.len();
        map.retain(|_, s| match &s.kind {
            Kind::Oidc {
                subject: sub,
                sid: ssid,
                ..
            } => {
                let hit = match (sid, subject) {
                    (Some(want), Some(who)) => ssid.as_deref() == Some(want) && sub == who,
                    (Some(want), None) => ssid.as_deref() == Some(want),
                    (None, Some(who)) => sub == who,
                    (None, None) => false,
                };
                !hit
            }
            Kind::Password { .. } => true,
        });
        before - map.len()
    }

    /// Drops expired sessions and old failure counters.
    pub fn prune(&self) {
        let now = Instant::now();
        Self::lock(&self.sessions).retain(|_, s| !s.expired(now));
        Self::lock(&self.by_client).retain(|_, f| f.current(now) > 0);
        Self::lock(&self.by_user).retain(|_, f| f.current(now) > 0);
    }

    pub fn count(&self) -> usize {
        Self::lock(&self.sessions).len()
    }
}

/// `Set-Cookie` value for a new session.
pub fn set_cookie(secret: &str) -> String {
    format!(
        "{COOKIE}={secret}; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age={}",
        MAX_AGE.as_secs()
    )
}

/// `Set-Cookie` value that deletes the session cookie.
pub fn clear_cookie() -> String {
    format!("{COOKIE}=; Path=/; Secure; HttpOnly; SameSite=Strict; Max-Age=0")
}

/// The session secret from a `Cookie` header.
pub fn from_cookie_header(header: &str) -> Option<&str> {
    header
        .split(';')
        .filter_map(|c| c.trim().split_once('='))
        .find(|(k, _)| *k == COOKIE)
        .map(|(_, v)| v)
        .filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pw() -> Kind {
        Kind::Password {
            password_changed_at: Utc::now(),
        }
    }

    #[test]
    fn sessions() {
        let s = Sessions::default();
        let (secret, sess) = s.create("alice", pw(), MAX_AGE);
        assert_eq!(s.get(&secret).unwrap().csrf, sess.csrf);
        assert!(s.get("nope").is_none());
        let (other, _) = s.create("bob", pw(), MAX_AGE);
        let (short, _) = s.create("carol", pw(), Duration::ZERO);
        std::thread::sleep(Duration::from_millis(5));
        assert!(s.get(&short).is_none(), "per-session maximum age");
        s.remove(&secret);
        assert!(s.get(&secret).is_none());
        assert!(s.get(&other).is_some());
        assert_eq!(s.count(), 1);
    }

    #[test]
    fn backchannel_matching() {
        let s = Sessions::default();
        let oidc = |sub: &str, sid: Option<&str>| Kind::Oidc {
            role: Role::Viewer,
            subject: sub.into(),
            sid: sid.map(Into::into),
        };
        let (a1, _) = s.create("alice", oidc("u-a", Some("s1")), MAX_AGE);
        let (a2, _) = s.create("alice", oidc("u-a", Some("s2")), MAX_AGE);
        let (a3, _) = s.create("alice", oidc("u-a", None), MAX_AGE);
        let (b, _) = s.create("bob", oidc("u-b", Some("s1")), MAX_AGE);
        let (local, _) = s.create("u-a", pw(), MAX_AGE);
        assert_eq!(s.end_oidc(Some("u-a"), Some("s1")), 1);
        assert!(
            s.get(&a1).is_none() && s.get(&b).is_some(),
            "sid of another subject"
        );
        assert_eq!(s.end_oidc(None, Some("s2")), 1);
        assert!(s.get(&a2).is_none());
        assert_eq!(s.end_oidc(Some("u-a"), None), 1);
        assert!(s.get(&a3).is_none());
        assert!(s.get(&local).is_some(), "local sessions are never touched");
        assert_eq!(s.end_oidc(None, None), 0);
    }

    #[test]
    fn cookies() {
        let (secret, _) = Sessions::default().create("a", pw(), MAX_AGE);
        let h = format!("theme=dark; {COOKIE}={secret}; x=y");
        assert_eq!(from_cookie_header(&h), Some(secret.as_str()));
        assert_eq!(from_cookie_header("theme=dark"), None);
        assert_eq!(from_cookie_header(&format!("{COOKIE}=")), None);
        assert!(set_cookie("abc").contains("HttpOnly"));
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
    }

    #[test]
    fn login_limits() {
        let s = Sessions::default();
        let a: IpAddr = "2001:db8::1".parse().unwrap();
        let b: IpAddr = "2001:db8::2".parse().unwrap(); // same /64
        let c: IpAddr = "192.0.2.1".parse().unwrap();
        for _ in 0..MAX_FAILURES_PER_CLIENT {
            assert!(s.login_allowed(Some(a), "x"));
            s.login_failed(Some(a), "x");
        }
        assert!(!s.login_allowed(Some(b), "y"), "same /64");
        assert!(s.login_allowed(Some(c), "y"));
        for _ in 0..MAX_FAILURES_PER_USER {
            s.login_failed(Some(c), "victim");
        }
        assert!(!s.login_allowed(Some("198.51.100.1".parse().unwrap()), "victim"));
        assert!(s.login_allowed(Some("198.51.100.1".parse().unwrap()), "other"));
    }
}

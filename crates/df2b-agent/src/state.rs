//! Persistent agent state in redb (`<state_dir>/agent.redb`).
//!
//! Stored:
//! - **source positions** (journal cursor, file dev/inode/offset), so a
//!   restart neither re-reads nor skips log lines;
//! - **offender records** (offense count + ban expiry per jail and key), so
//!   active bans are re-applied after a restart and escalation continues;
//! - the **central allowlist** last received from the controller, so it
//!   applies after a restart even while the controller is unreachable;
//! - **manual bans** made with `df2bctl --local ban` (re-applied after a
//!   restart; they are not reported to the controller);
//! - **unsent reports** for the controller (see `outbox.rs`), so bans and
//!   failure counts from an offline period survive a restart.
//!
//! Writes are buffered in [`Pending`] and committed in one transaction (one
//! fsync) per flush interval, not per batch: at high volume, per-batch commits
//! would mean thousands of fsyncs per second. After a crash, at most one
//! flush interval of log lines is read again.
//!
//! Values are JSON: tiny, written rarely, and easy to inspect.

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::Context;
use df2b_core::IpKey;
use df2b_sources::Position;
use redb::{Database, ReadableTable, TableDefinition};

use crate::engine::OffenderRecord;

const POSITIONS: TableDefinition<&str, &[u8]> = TableDefinition::new("positions");
const OFFENDERS: TableDefinition<&str, &[u8]> = TableDefinition::new("offenders");
const META: TableDefinition<&str, &[u8]> = TableDefinition::new("meta");
/// Queue id → protobuf-encoded `v1::Observation`.
const REPORTS: TableDefinition<u64, &[u8]> = TableDefinition::new("reports");
const CENTRAL_ALLOWLIST: &str = "central_allowlist";
const JAIL_POLICIES: &str = "jail_policies";
const CENTRAL_JAILS: &str = "central_jails";
const CENTRAL_REDACTION: &str = "central_redaction";
const MANUAL_BANS: &str = "manual_bans";

/// A ban made on this host with `df2bctl --local ban`.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct ManualBan {
    pub target: ipnet::IpNet,
    /// `None` = permanent.
    pub until: Option<chrono::DateTime<chrono::Utc>>,
    pub reason: String,
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Who made it: "uid 0".
    pub by: String,
}

/// The controller's redaction rules as last applied.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CentralRedaction {
    pub version: String,
    pub rules: Vec<df2b_core::RedactRule>,
}

/// The controller's jail settings as last applied.
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct JailPolicies {
    pub version: String,
    pub jails: Vec<crate::engine::JailOverride>,
}

/// The controller's allowlist as last applied.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CentralAllowlist {
    pub version: String,
    pub networks: Vec<ipnet::IpNet>,
    /// Expiry per network (same order); empty: all permanent.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub expires_at: Vec<Option<chrono::DateTime<chrono::Utc>>>,
}

impl CentralAllowlist {
    /// Networks still in force (temporary entries expire here too, also
    /// while the controller is unreachable).
    pub fn live(&self, now: chrono::DateTime<chrono::Utc>) -> Vec<ipnet::IpNet> {
        self.networks
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                self.expires_at
                    .get(*i)
                    .copied()
                    .flatten()
                    .map_or(true, |e| e > now)
            })
            .map(|(_, n)| *n)
            .collect()
    }
}

/// Key of a source position: one per journald source, one per file path.
pub fn position_key(source: &str, position: &Position) -> String {
    match position {
        Position::JournalCursor(_) => journald_position_key(source),
        Position::File { path, .. } => file_position_key(source, path),
    }
}

pub fn file_position_key(source: &str, path: &Path) -> String {
    format!("file:{source}:{}", path.display())
}

pub fn journald_position_key(source: &str) -> String {
    format!("journald:{source}")
}

/// A configured source, for [`stale_positions`].
pub enum KnownSource<'a> {
    Journald(&'a str),
    /// Name and configured paths (literal or glob).
    Files(&'a str, &'a [PathBuf]),
}

/// Saved positions nobody will resume from: of sources no longer
/// configured, and of files that are gone unless configured by their
/// literal path (a file rotated away while the agent was down is found
/// through that position). Glob matches that are gone are not followed
/// again; a new file at that path is read from its start anyway.
pub fn stale_positions(
    positions: &HashMap<String, Position>,
    sources: &[KnownSource<'_>],
) -> Vec<String> {
    positions
        .iter()
        .filter(|(key, pos)| match pos {
            Position::JournalCursor(_) => !sources.iter().any(
                |s| matches!(s, KnownSource::Journald(n) if journald_position_key(n) == **key),
            ),
            Position::File { path, .. } => {
                let Some(paths) = sources.iter().find_map(|s| match s {
                    KnownSource::Files(n, paths) if file_position_key(n, path) == **key => {
                        Some(*paths)
                    }
                    _ => None,
                }) else {
                    return true; // source gone
                };
                !paths.iter().any(|p| p == path) && !path.exists()
            }
        })
        .map(|(k, _)| k.clone())
        .collect()
}

fn offender_key(jail: &str, key: &IpKey) -> String {
    format!("{jail}|{key}")
}

/// Changes not yet committed.
#[derive(Debug, Default)]
pub struct Pending {
    /// `None` = delete
    positions: HashMap<String, Option<Position>>,
    /// `None` = delete
    offenders: HashMap<String, Option<OffenderRecord>>,
}

impl Pending {
    pub fn set_position(&mut self, source: &str, position: Position) {
        self.positions
            .insert(position_key(source, &position), Some(position));
    }

    /// Drops a saved position (by its key).
    pub fn forget_position(&mut self, key: String) {
        self.positions.insert(key, None);
    }

    pub fn set_offender(&mut self, record: OffenderRecord) {
        self.offenders
            .insert(offender_key(&record.jail, &record.key), Some(record));
    }

    pub fn forget_offender(&mut self, jail: &str, key: &IpKey) {
        self.offenders.insert(offender_key(jail, key), None);
    }

    pub fn is_empty(&self) -> bool {
        self.positions.is_empty() && self.offenders.is_empty()
    }
}

/// Everything loaded at startup.
#[derive(Debug, Default)]
pub struct Loaded {
    pub positions: HashMap<String, Position>,
    pub offenders: Vec<OffenderRecord>,
    pub central_allowlist: Option<CentralAllowlist>,
    pub jail_policies: Option<JailPolicies>,
    pub central_jails: Option<crate::central::CentralJails>,
    pub central_redaction: Option<CentralRedaction>,
    pub manual_bans: Vec<ManualBan>,
}

#[derive(Clone)]
pub struct State {
    db: Arc<Database>,
    path: PathBuf,
}

impl State {
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        std::fs::create_dir_all(dir)
            .with_context(|| format!("creating state directory {}", dir.display()))?;
        let path = dir.join("agent.redb");
        let db = Database::create(&path)
            .with_context(|| format!("opening state database {}", path.display()))?;
        // create tables so read transactions never hit "table does not exist"
        let tx = db.begin_write()?;
        tx.open_table(POSITIONS)?;
        tx.open_table(OFFENDERS)?;
        tx.open_table(META)?;
        tx.open_table(REPORTS)?;
        tx.commit()?;
        Ok(Self {
            db: Arc::new(db),
            path,
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn load(&self) -> anyhow::Result<Loaded> {
        let tx = self.db.begin_read()?;
        let mut loaded = Loaded::default();
        for item in tx.open_table(POSITIONS)?.iter()? {
            let (k, v) = item?;
            match serde_json::from_slice(v.value()) {
                Ok(p) => {
                    loaded.positions.insert(k.value().to_owned(), p);
                }
                Err(e) => {
                    tracing::warn!(key = k.value(), error = %e, "ignoring unreadable saved position")
                }
            }
        }
        for item in tx.open_table(OFFENDERS)?.iter()? {
            let (k, v) = item?;
            match serde_json::from_slice(v.value()) {
                Ok(r) => loaded.offenders.push(r),
                Err(e) => {
                    tracing::warn!(key = k.value(), error = %e, "ignoring unreadable offender record")
                }
            }
        }
        if let Some(v) = tx.open_table(META)?.get(CENTRAL_JAILS)? {
            match serde_json::from_slice(v.value()) {
                Ok(c) => loaded.central_jails = Some(c),
                Err(e) => tracing::warn!(error = %e, "ignoring unreadable saved central jails"),
            }
        }
        if let Some(v) = tx.open_table(META)?.get(JAIL_POLICIES)? {
            match serde_json::from_slice(v.value()) {
                Ok(p) => loaded.jail_policies = Some(p),
                Err(e) => tracing::warn!(error = %e, "ignoring unreadable saved jail policies"),
            }
        }
        if let Some(v) = tx.open_table(META)?.get(CENTRAL_REDACTION)? {
            match serde_json::from_slice(v.value()) {
                Ok(r) => loaded.central_redaction = Some(r),
                Err(e) => tracing::warn!(error = %e, "ignoring unreadable saved redaction rules"),
            }
        }
        if let Some(v) = tx.open_table(META)?.get(MANUAL_BANS)? {
            match serde_json::from_slice(v.value()) {
                Ok(m) => loaded.manual_bans = m,
                Err(e) => tracing::warn!(error = %e, "ignoring unreadable saved manual bans"),
            }
        }
        if let Some(v) = tx.open_table(META)?.get(CENTRAL_ALLOWLIST)? {
            match serde_json::from_slice(v.value()) {
                Ok(a) => loaded.central_allowlist = Some(a),
                Err(e) => tracing::warn!(error = %e, "ignoring unreadable saved central allowlist"),
            }
        }
        Ok(loaded)
    }

    /// Saves the central jail definitions (only when they change). Blocking.
    pub fn save_central_jails(&self, c: &crate::central::CentralJails) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(META)?
            .insert(CENTRAL_JAILS, serde_json::to_vec(c)?.as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// Saves the jail policies (only when they change). Blocking.
    pub fn save_jail_policies(&self, p: &JailPolicies) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(META)?
            .insert(JAIL_POLICIES, serde_json::to_vec(p)?.as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// Saves the controller's redaction rules (only when they change).
    /// Blocking.
    pub fn save_central_redaction(&self, r: &CentralRedaction) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(META)?
            .insert(CENTRAL_REDACTION, serde_json::to_vec(r)?.as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// Saves the central allowlist (rare: only when it changes). Blocking.
    pub fn save_central_allowlist(&self, a: &CentralAllowlist) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(META)?
            .insert(CENTRAL_ALLOWLIST, serde_json::to_vec(a)?.as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// Saves all manual bans (when they change). Blocking.
    pub fn save_manual_bans(&self, m: &[ManualBan]) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(META)?
            .insert(MANUAL_BANS, serde_json::to_vec(m)?.as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// Unsent reports in queue order. Blocking.
    pub fn load_reports(&self) -> anyhow::Result<Vec<(u64, Vec<u8>)>> {
        let tx = self.db.begin_read()?;
        let mut out = Vec::new();
        for item in tx.open_table(REPORTS)?.iter()? {
            let (k, v) = item?;
            out.push((k.value(), v.value().to_vec()));
        }
        Ok(out)
    }

    /// Adds and removes unsent reports in one transaction. Blocking.
    pub fn save_reports(&self, add: &[(u64, Vec<u8>)], remove: &[u64]) -> anyhow::Result<()> {
        if add.is_empty() && remove.is_empty() {
            return Ok(());
        }
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(REPORTS)?;
            for (id, bytes) in add {
                t.insert(*id, bytes.as_slice())?;
            }
            for id in remove {
                t.remove(*id)?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Commits `pending` in one transaction. Blocking (fsync): call it from
    /// `spawn_blocking` or [`State::flush_async`].
    pub fn flush(&self, pending: Pending) -> anyhow::Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let tx = self.db.begin_write()?;
        {
            let mut positions = tx.open_table(POSITIONS)?;
            for (k, p) in &pending.positions {
                match p {
                    Some(p) => {
                        positions.insert(k.as_str(), serde_json::to_vec(p)?.as_slice())?;
                    }
                    None => {
                        positions.remove(k.as_str())?;
                    }
                }
            }
            let mut offenders = tx.open_table(OFFENDERS)?;
            for (k, r) in &pending.offenders {
                match r {
                    Some(r) => {
                        offenders.insert(k.as_str(), serde_json::to_vec(r)?.as_slice())?;
                    }
                    None => {
                        offenders.remove(k.as_str())?;
                    }
                }
            }
        }
        tx.commit()?;
        Ok(())
    }

    pub async fn flush_async(&self, pending: Pending) -> anyhow::Result<()> {
        if pending.is_empty() {
            return Ok(());
        }
        let this = self.clone();
        tokio::task::spawn_blocking(move || this.flush(pending)).await?
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use df2b_core::PrefixPolicy;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("df2b-state-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    fn record(ip: &str, offenses: u32) -> OffenderRecord {
        OffenderRecord {
            jail: "sshd".into(),
            key: IpKey::from_addr(ip.parse().unwrap(), PrefixPolicy::default()),
            offenses,
            banned_until: Utc::now(),
        }
    }

    #[test]
    fn roundtrip_across_reopen() {
        let dir = tmp("rt");
        {
            let s = State::open(&dir).unwrap();
            let mut p = Pending::default();
            p.set_position("sshd", Position::JournalCursor("s=abc;i=1".into()));
            p.set_position(
                "auth",
                Position::File {
                    path: "/var/log/auth.log".into(),
                    dev: 1,
                    ino: 2,
                    offset: 3,
                },
            );
            p.set_offender(record("203.0.113.7", 2));
            p.set_offender(record("2001:db8::1", 1));
            s.flush(p).unwrap();

            // later: newer position overwrites, one offender forgotten
            let mut p = Pending::default();
            p.set_position("sshd", Position::JournalCursor("s=abc;i=2".into()));
            p.forget_offender("sshd", &record("2001:db8::1", 1).key);
            p.set_position("gone", Position::JournalCursor("x".into()));
            p.forget_position(journald_position_key("gone"));
            s.flush(p).unwrap();
        }
        let s = State::open(&dir).unwrap();
        let l = s.load().unwrap();
        assert_eq!(
            l.positions[&journald_position_key("sshd")],
            Position::JournalCursor("s=abc;i=2".into())
        );
        assert!(matches!(
            l.positions[&file_position_key("auth", Path::new("/var/log/auth.log"))],
            Position::File { offset: 3, .. }
        ));
        assert_eq!(l.offenders.len(), 1);
        assert_eq!(l.offenders[0].offenses, 2);
        assert_eq!(l.positions.len(), 2, "forgotten position not written");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn stale_positions_are_found() {
        let dir = tmp("stale");
        std::fs::create_dir_all(&dir).unwrap();
        let live = dir.join("app-1.log");
        std::fs::write(&live, "").unwrap();
        let file = |p: &Path| Position::File {
            path: p.to_owned(),
            dev: 1,
            ino: 2,
            offset: 3,
        };
        let literal = PathBuf::from("/var/log/auth.log"); // missing, but configured
        let gone = dir.join("app-0.log");
        let mut positions = HashMap::new();
        for (src, p) in [
            ("auth", &literal),
            ("apps", &live),
            ("apps", &gone),
            ("old", &live),
        ] {
            positions.insert(file_position_key(src, p), file(p));
        }
        positions.insert(
            journald_position_key("sshd"),
            Position::JournalCursor("c".into()),
        );
        positions.insert(
            journald_position_key("removed"),
            Position::JournalCursor("c".into()),
        );
        let auth = [literal.clone()];
        let apps = [dir.join("app-*.log")];
        let known = [
            KnownSource::Journald("sshd"),
            KnownSource::Files("auth", &auth),
            KnownSource::Files("apps", &apps),
        ];
        let mut stale = stale_positions(&positions, &known);
        stale.sort();
        let mut want = vec![
            file_position_key("apps", &gone),
            file_position_key("old", &live),
            journald_position_key("removed"),
        ];
        want.sort();
        assert_eq!(stale, want);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn empty_flush_is_noop() {
        let dir = tmp("empty");
        let s = State::open(&dir).unwrap();
        s.flush(Pending::default()).unwrap();
        assert!(s.load().unwrap().positions.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn central_allowlist_persists() {
        let dir = tmp("central");
        let a = CentralAllowlist {
            version: "abcd".into(),
            networks: vec![
                "192.0.2.0/24".parse().unwrap(),
                "198.51.100.7/32".parse().unwrap(),
            ],
            expires_at: vec![
                None,
                Some(chrono::Utc::now() - chrono::Duration::seconds(1)),
            ],
        };
        assert_eq!(a.live(chrono::Utc::now()).len(), 1, "expired entry dropped");
        {
            let st = State::open(&dir).unwrap();
            assert!(st.load().unwrap().central_allowlist.is_none());
            st.save_central_allowlist(&a).unwrap();
        }
        let st = State::open(&dir).unwrap();
        assert_eq!(st.load().unwrap().central_allowlist, Some(a));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn central_redaction_persists() {
        let dir = tmp("redaction");
        let r = CentralRedaction {
            version: "0123".into(),
            rules: vec![df2b_core::RedactRule {
                name: "user".into(),
                pattern: r"user \S+".into(),
                replace: "user [u]".into(),
                enabled: true,
            }],
        };
        {
            let st = State::open(&dir).unwrap();
            assert!(st.load().unwrap().central_redaction.is_none());
            st.save_central_redaction(&r).unwrap();
        }
        let st = State::open(&dir).unwrap();
        assert_eq!(st.load().unwrap().central_redaction, Some(r));
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn manual_bans_persist() {
        let dir = tmp("manual");
        let m = vec![ManualBan {
            target: "192.0.2.0/24".parse().unwrap(),
            until: None,
            reason: "abuse".into(),
            created_at: Utc::now(),
            by: "uid 0".into(),
        }];
        {
            let st = State::open(&dir).unwrap();
            assert!(st.load().unwrap().manual_bans.is_empty());
            st.save_manual_bans(&m).unwrap();
        }
        assert_eq!(State::open(&dir).unwrap().load().unwrap().manual_bans, m);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn reports_persist_in_order() {
        let dir = tmp("reports");
        {
            let st = State::open(&dir).unwrap();
            assert!(st.load_reports().unwrap().is_empty());
            st.save_reports(
                &[(2, b"b".to_vec()), (10, b"c".to_vec()), (1, b"a".to_vec())],
                &[],
            )
            .unwrap();
            st.save_reports(&[], &[2]).unwrap();
        }
        let st = State::open(&dir).unwrap();
        assert_eq!(
            st.load_reports().unwrap(),
            vec![(1, b"a".to_vec()), (10, b"c".to_vec())]
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn jail_policies_persist() {
        let dir = tmp("jailpol");
        let p = JailPolicies {
            version: "v9".into(),
            jails: vec![crate::engine::JailOverride {
                jail: "sshd".into(),
                maxretry: Some(3),
                bantime: Some(std::time::Duration::from_secs(7200)),
                ..Default::default()
            }],
        };
        {
            let st = State::open(&dir).unwrap();
            assert!(st.load().unwrap().jail_policies.is_none());
            st.save_jail_policies(&p).unwrap();
        }
        assert_eq!(
            State::open(&dir).unwrap().load().unwrap().jail_policies,
            Some(p)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

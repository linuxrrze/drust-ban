//! Persistent agent state in redb (`<state_dir>/agent.redb`).
//!
//! Stored:
//! - **source positions** (journal cursor, file dev/inode/offset), so a
//!   restart neither re-reads nor skips log lines;
//! - **offender records** (offense count + ban expiry per jail and key), so
//!   active bans are re-applied after a restart and escalation continues;
//! - the **central allowlist** last received from the controller, so it
//!   applies after a restart even while the controller is unreachable.
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
const CENTRAL_ALLOWLIST: &str = "central_allowlist";

/// The controller's allowlist as last applied.
#[derive(Debug, Clone, Default, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct CentralAllowlist {
    pub version: String,
    pub networks: Vec<ipnet::IpNet>,
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

fn offender_key(jail: &str, key: &IpKey) -> String {
    format!("{jail}|{key}")
}

/// Changes not yet committed.
#[derive(Debug, Default)]
pub struct Pending {
    positions: HashMap<String, Position>,
    /// `None` = delete
    offenders: HashMap<String, Option<OffenderRecord>>,
}

impl Pending {
    pub fn set_position(&mut self, source: &str, position: Position) {
        self.positions
            .insert(position_key(source, &position), position);
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
        if let Some(v) = tx.open_table(META)?.get(CENTRAL_ALLOWLIST)? {
            match serde_json::from_slice(v.value()) {
                Ok(a) => loaded.central_allowlist = Some(a),
                Err(e) => tracing::warn!(error = %e, "ignoring unreadable saved central allowlist"),
            }
        }
        Ok(loaded)
    }

    /// Saves the central allowlist (rare: only when it changes). Blocking.
    pub fn save_central_allowlist(&self, a: &CentralAllowlist) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(META)?
            .insert(CENTRAL_ALLOWLIST, serde_json::to_vec(a)?.as_slice())?;
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
                positions.insert(k.as_str(), serde_json::to_vec(p)?.as_slice())?;
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
            networks: vec!["192.0.2.0/24".parse().unwrap()],
        };
        {
            let st = State::open(&dir).unwrap();
            assert!(st.load().unwrap().central_allowlist.is_none());
            st.save_central_allowlist(&a).unwrap();
        }
        let st = State::open(&dir).unwrap();
        assert_eq!(st.load().unwrap().central_allowlist, Some(a));
        let _ = std::fs::remove_dir_all(&dir);
    }
}

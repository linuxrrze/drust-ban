//! Persistent controller state in redb (`<state_dir>/controller.redb`):
//! enrolled agents and the append-only decision log.
//!
//! Runtime status (last heartbeat, open streams) is kept in memory only: it
//! changes every few seconds per agent and is worthless after a restart.
//! TODO: SQLite/PostgreSQL via sqlx (DESIGN.md §6), log compaction.

use std::path::Path;
use std::sync::Arc;

use anyhow::Context;
use chrono::{DateTime, Utc};
use df2b_core::Decision;
use redb::{Database, ReadableTable, TableDefinition};
use serde::{Deserialize, Serialize};

const AGENTS: TableDefinition<&str, &[u8]> = TableDefinition::new("agents");
const DECISIONS: TableDefinition<u64, &[u8]> = TableDefinition::new("decisions");
const AUDIT: TableDefinition<u64, &[u8]> = TableDefinition::new("audit");

/// One administrative action (REST API or enrollment).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub seq: u64,
    pub time: DateTime<Utc>,
    /// API token name, or `agent:<id>` for enrollments.
    pub actor: String,
    pub remote_addr: Option<String>,
    pub action: String,
    pub details: serde_json::Value,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AgentRecord {
    pub id: String,
    pub hostname: String,
    pub group: String,
    pub enrolled_at: DateTime<Utc>,
    /// Accepted certificate serials (hex): the current one and, after a
    /// renewal, the previous one.
    pub serials: Vec<String>,
    pub cert_not_after: DateTime<Utc>,
}

#[derive(Clone)]
pub struct Store {
    db: Arc<Database>,
}

impl Store {
    pub fn open(dir: &Path) -> anyhow::Result<Self> {
        let path = dir.join("controller.redb");
        let db = Database::create(&path)
            .with_context(|| format!("opening controller database {}", path.display()))?;
        let tx = db.begin_write()?;
        tx.open_table(AGENTS)?;
        tx.open_table(DECISIONS)?;
        tx.open_table(AUDIT)?;
        tx.commit()?;
        Ok(Self { db: Arc::new(db) })
    }

    pub fn agents(&self) -> anyhow::Result<Vec<AgentRecord>> {
        let tx = self.db.begin_read()?;
        let mut out = Vec::new();
        for item in tx.open_table(AGENTS)?.iter()? {
            let (_, v) = item?;
            out.push(serde_json::from_slice(v.value())?);
        }
        Ok(out)
    }

    pub fn put_agent(&self, a: &AgentRecord) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        tx.open_table(AGENTS)?
            .insert(a.id.as_str(), serde_json::to_vec(a)?.as_slice())?;
        tx.commit()?;
        Ok(())
    }

    /// Appends decisions (already numbered) in one transaction.
    pub fn append(&self, decisions: &[Decision]) -> anyhow::Result<()> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(DECISIONS)?;
            for d in decisions {
                t.insert(d.seq, serde_json::to_vec(d)?.as_slice())?;
            }
        }
        tx.commit()?;
        Ok(())
    }

    /// Decisions with `from < seq <= to`, in order.
    pub fn range(&self, from: u64, to: u64) -> anyhow::Result<Vec<Decision>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(DECISIONS)?;
        let mut out = Vec::new();
        for item in t.range(from.saturating_add(1)..=to)? {
            let (_, v) = item?;
            out.push(serde_json::from_slice(v.value())?);
        }
        Ok(out)
    }

    /// Appends an audit entry; assigns its sequence number.
    pub fn audit(&self, mut e: AuditEntry) -> anyhow::Result<AuditEntry> {
        let tx = self.db.begin_write()?;
        {
            let mut t = tx.open_table(AUDIT)?;
            e.seq = t.last()?.map_or(1, |(k, _)| k.value() + 1);
            t.insert(e.seq, serde_json::to_vec(&e)?.as_slice())?;
        }
        tx.commit()?;
        Ok(e)
    }

    /// Newest first, at most `limit`, with `seq < before`.
    pub fn audit_log(&self, limit: usize, before: u64) -> anyhow::Result<Vec<AuditEntry>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(AUDIT)?;
        let mut out = Vec::new();
        for item in t.range(..before)?.rev().take(limit) {
            let (_, v) = item?;
            out.push(serde_json::from_slice(v.value())?);
        }
        Ok(out)
    }

    /// Newest first, at most `limit` decisions matching `filter`.
    pub fn history(
        &self,
        filter: impl Fn(&Decision) -> bool,
        limit: usize,
    ) -> anyhow::Result<Vec<Decision>> {
        let tx = self.db.begin_read()?;
        let t = tx.open_table(DECISIONS)?;
        let mut out = Vec::new();
        for item in t.iter()?.rev() {
            let (_, v) = item?;
            let d: Decision = serde_json::from_slice(v.value())?;
            if filter(&d) {
                out.push(d);
                if out.len() >= limit {
                    break;
                }
            }
        }
        Ok(out)
    }

    /// Calls `f` for every decision in order (startup replay).
    pub fn for_each(&self, mut f: impl FnMut(Decision)) -> anyhow::Result<()> {
        let tx = self.db.begin_read()?;
        for item in tx.open_table(DECISIONS)?.iter()? {
            let (_, v) = item?;
            f(serde_json::from_slice(v.value())?);
        }
        Ok(())
    }
}

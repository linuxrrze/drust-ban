//! journald source.
//!
//! TODO (milestone 1): implement on top of libsystemd's sd-journal API:
//! - `sd_journal_open` + `sd_journal_add_match` for each configured match,
//! - `sd_journal_get_fd` wrapped in `tokio::io::unix::AsyncFd` for wakeups,
//! - read `MESSAGE` and `__REALTIME_TIMESTAMP` (→ `LogLine::ts`),
//! - persist `sd_journal_get_cursor` and resume with `sd_journal_seek_cursor`.

use std::sync::Arc;

use tokio::sync::mpsc;

use crate::LogLine;

#[derive(Debug, Clone)]
pub struct JournaldSource {
    source: Arc<str>,
    matches: Vec<String>,
}

impl JournaldSource {
    pub fn new(source: Arc<str>, matches: Vec<String>) -> Self {
        Self { source, matches }
    }

    pub async fn run(self, _tx: mpsc::Sender<LogLine>) -> anyhow::Result<()> {
        anyhow::bail!(
            "journald source '{}' (matches: {:?}) is not implemented yet",
            self.source,
            self.matches
        )
    }
}

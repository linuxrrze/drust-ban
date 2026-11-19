//! Log sources.
//!
//! Sources push [`SourceBatch`]es (up to [`BATCH_MAX`] lines) into a bounded
//! channel. Batching amortizes channel synchronization at high volume; a full
//! channel applies back-pressure to the source.

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod file;
#[cfg(feature = "journald")]
pub mod journald;
pub mod watch;

pub use file::{Ended, FileSource, FileTailer};
#[cfg(feature = "journald")]
pub use journald::JournaldSource;

/// Maximum number of lines per batch.
pub const BATCH_MAX: usize = 1024;
/// Lines (messages) longer than this are truncated.
pub const MAX_LINE: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct LogLine {
    /// Name of the configured source this line came from.
    pub source: Arc<str>,
    /// Event time if the source knows it (journald); `None` means "now".
    pub ts: Option<DateTime<Utc>>,
    pub line: String,
}

/// Where a source stands after a batch; persist it to resume exactly.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Position {
    JournalCursor(String),
    File {
        path: PathBuf,
        dev: u64,
        ino: u64,
        offset: u64,
    },
}

#[derive(Debug)]
pub struct SourceBatch {
    /// Name of the configured source.
    pub source: Arc<str>,
    pub lines: Vec<LogLine>,
    /// Position after the last line of this batch.
    pub position: Option<Position>,
    /// Bytes not read yet after this batch (files: how far behind).
    pub backlog: Option<u64>,
    /// A file the source stopped following because it is gone (a glob
    /// match deleted or rotated away): its saved position can be dropped.
    /// Sent with no lines.
    pub gone: Option<PathBuf>,
}

/// The last error of each source that stopped reading (or one of whose
/// files did), for status reports; logged as well.
#[derive(Debug, Default)]
pub struct SourceErrors(Mutex<HashMap<String, String>>);

impl SourceErrors {
    pub fn set(&self, source: &str, error: String) {
        self.lock().insert(source.to_owned(), error);
    }

    pub fn clear(&self, source: &str) {
        self.lock().remove(source);
    }

    pub fn get(&self, source: &str) -> Option<String> {
        self.lock().get(source).cloned()
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<String, String>> {
        self.0.lock().unwrap_or_else(|e| e.into_inner())
    }
}

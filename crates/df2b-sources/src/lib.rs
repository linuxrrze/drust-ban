//! Log sources.
//!
//! Sources push [`SourceBatch`]es (up to [`BATCH_MAX`] lines) into a bounded
//! channel. Batching amortizes channel synchronization at high volume; a full
//! channel applies back-pressure to the source.

use std::path::PathBuf;
use std::sync::Arc;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

pub mod file;
#[cfg(feature = "journald")]
pub mod journald;

pub use file::FileTailer;
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
}

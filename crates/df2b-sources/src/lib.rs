//! Log sources. Every source pushes [`LogLine`]s into a bounded channel;
//! a full channel applies back-pressure to the source.

use std::sync::Arc;

use chrono::{DateTime, Utc};

pub mod file;
#[cfg(feature = "journald")]
pub mod journald;

pub use file::FileTailer;
#[cfg(feature = "journald")]
pub use journald::JournaldSource;

#[derive(Debug, Clone)]
pub struct LogLine {
    /// Name of the configured source this line came from.
    pub source: Arc<str>,
    /// Event time if the source knows it (journald); `None` means "now".
    pub ts: Option<DateTime<Utc>>,
    pub line: String,
}

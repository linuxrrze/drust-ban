//! Polling file tailer with rotation and truncation detection.
//!
//! TODO (milestone 1):
//! - inotify-driven wakeups instead of polling,
//! - glob paths,
//! - persisted offsets (redb) so restarts resume exactly,
//! - drain the remainder of a rotated-away file before switching inodes,
//! - per-source timestamp extraction.

use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::mpsc;
use tracing::{debug, info, warn};

use crate::LogLine;

/// Maximum bytes read per poll iteration (bounds memory per tailer).
const MAX_READ: u64 = 4 * 1024 * 1024;
/// Lines longer than this are truncated (protects against garbage input).
const MAX_LINE: usize = 16 * 1024;

#[derive(Debug, Clone)]
pub struct FileTailer {
    source: Arc<str>,
    path: PathBuf,
    start_at_end: bool,
    poll: Duration,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileTailer {
    pub fn new(source: Arc<str>, path: PathBuf, start_at_end: bool) -> Self {
        Self {
            source,
            path,
            start_at_end,
            poll: Duration::from_millis(250),
        }
    }

    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self
    }

    /// Runs until the receiver is dropped.
    pub async fn run(self, tx: mpsc::Sender<LogLine>) -> anyhow::Result<()> {
        info!(source = %self.source, path = %self.path.display(), "tailing file");
        let mut current: Option<(FileId, u64)> = None;
        let mut pending: Vec<u8> = Vec::with_capacity(64 * 1024);

        loop {
            let meta = match tokio::fs::metadata(&self.path).await {
                Ok(m) => m,
                Err(e) => {
                    debug!(path = %self.path.display(), error = %e, "file not available");
                    tokio::time::sleep(self.poll).await;
                    continue;
                }
            };
            let id = FileId {
                dev: meta.dev(),
                ino: meta.ino(),
            };
            let offset = match current {
                Some((cur, off)) if cur == id => {
                    if meta.len() < off {
                        info!(path = %self.path.display(), "file truncated, restarting at 0");
                        pending.clear();
                        0
                    } else {
                        off
                    }
                }
                Some(_) => {
                    info!(path = %self.path.display(), "file rotated, switching to new inode");
                    pending.clear();
                    0
                }
                None if self.start_at_end => meta.len(),
                None => 0,
            };

            if meta.len() == offset {
                current = Some((id, offset));
                tokio::time::sleep(self.poll).await;
                continue;
            }

            let mut file = match tokio::fs::File::open(&self.path).await {
                Ok(f) => f,
                Err(e) => {
                    warn!(path = %self.path.display(), error = %e, "cannot open file");
                    tokio::time::sleep(self.poll).await;
                    continue;
                }
            };
            file.seek(SeekFrom::Start(offset)).await?;
            let mut chunk = Vec::new();
            let n = file.take(MAX_READ).read_to_end(&mut chunk).await? as u64;
            current = Some((id, offset + n));

            pending.extend_from_slice(&chunk);
            let mut start = 0;
            for pos in memchr::memchr_iter(b'\n', &pending) {
                let raw = &pending[start..pos.min(start + MAX_LINE)];
                start = pos + 1;
                let line = LogLine {
                    source: self.source.clone(),
                    ts: None,
                    line: String::from_utf8_lossy(raw).into_owned(),
                };
                if tx.send(line).await.is_err() {
                    return Ok(()); // receiver gone: shutting down
                }
            }
            pending.drain(..start);
            if pending.len() > MAX_LINE {
                warn!(path = %self.path.display(), "discarding over-long partial line");
                pending.clear();
            }

            if n < MAX_READ {
                tokio::time::sleep(self.poll).await;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    #[tokio::test]
    async fn follows_appends_and_truncation() {
        let dir = std::env::temp_dir().join(format!("df2b-tail-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("test.log");
        std::fs::write(&path, "one\ntwo\npart").unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let tailer = FileTailer::new(Arc::from("t"), path.clone(), false)
            .with_poll_interval(Duration::from_millis(10));
        let handle = tokio::spawn(tailer.run(tx));

        async fn recv(rx: &mut mpsc::Receiver<LogLine>) -> String {
            tokio::time::timeout(Duration::from_secs(5), rx.recv())
                .await
                .expect("timeout")
                .expect("closed")
                .line
        }
        assert_eq!(recv(&mut rx).await, "one");
        assert_eq!(recv(&mut rx).await, "two");

        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"ial\n").unwrap();
        assert_eq!(recv(&mut rx).await, "partial");

        std::fs::write(&path, "fresh\n").unwrap(); // truncate + rewrite
        assert_eq!(recv(&mut rx).await, "fresh");

        drop(rx);
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

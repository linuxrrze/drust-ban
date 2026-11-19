//! Polling file tailer with rotation and truncation detection.
//!
//! TODO (milestone 1):
//! - inotify-driven wakeups instead of polling,
//! - glob paths,
//! - resume from a persisted [`Position`] (redb),
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

use crate::{LogLine, Position, SourceBatch, BATCH_MAX, MAX_LINE};

/// Maximum bytes read per poll iteration (bounds memory per tailer).
const MAX_READ: u64 = 4 * 1024 * 1024;

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

    /// Sends `batch` with the position `offset`; false if the receiver is gone.
    async fn send(
        &self,
        tx: &mpsc::Sender<SourceBatch>,
        batch: &mut Vec<LogLine>,
        id: FileId,
        offset: u64,
    ) -> bool {
        let lines = std::mem::take(batch);
        let position = Some(Position::File {
            path: self.path.clone(),
            dev: id.dev,
            ino: id.ino,
            offset,
        });
        tx.send(SourceBatch { lines, position }).await.is_ok()
    }

    /// Runs until the receiver is dropped.
    pub async fn run(self, tx: mpsc::Sender<SourceBatch>) -> anyhow::Result<()> {
        info!(source = %self.source, path = %self.path.display(), "tailing file");
        let mut current: Option<(FileId, u64)> = None;
        // Bytes of an incomplete last line; they precede `offset` in the file.
        let mut pending: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut batch: Vec<LogLine> = Vec::new();

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

            // file offset of pending[0]
            let base = offset - pending.len() as u64;
            pending.extend_from_slice(&chunk);
            let mut start = 0;
            for pos in memchr::memchr_iter(b'\n', &pending) {
                let raw = &pending[start..pos.min(start + MAX_LINE)];
                start = pos + 1;
                batch.push(LogLine {
                    source: self.source.clone(),
                    ts: None,
                    line: String::from_utf8_lossy(raw).into_owned(),
                });
                if batch.len() >= BATCH_MAX
                    && !self.send(&tx, &mut batch, id, base + start as u64).await
                {
                    return Ok(()); // receiver gone: shutting down
                }
            }
            if !batch.is_empty() && !self.send(&tx, &mut batch, id, base + start as u64).await {
                return Ok(());
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
    use std::collections::VecDeque;
    use std::io::Write;

    async fn recv_batch(rx: &mut mpsc::Receiver<SourceBatch>) -> SourceBatch {
        tokio::time::timeout(Duration::from_secs(5), rx.recv())
            .await
            .expect("timeout")
            .expect("closed")
    }

    async fn next_line(rx: &mut mpsc::Receiver<SourceBatch>, buf: &mut VecDeque<String>) -> String {
        while buf.is_empty() {
            buf.extend(recv_batch(rx).await.lines.into_iter().map(|l| l.line));
        }
        buf.pop_front().unwrap()
    }

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

        // first batch: both complete lines, position after "two\n"
        let b = recv_batch(&mut rx).await;
        let lines: Vec<_> = b.lines.iter().map(|l| l.line.as_str()).collect();
        assert_eq!(lines, ["one", "two"]);
        assert!(matches!(b.position, Some(Position::File { offset: 8, .. })));

        let mut buf = VecDeque::new();
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"ial\n").unwrap();
        assert_eq!(next_line(&mut rx, &mut buf).await, "partial");

        std::fs::write(&path, "fresh\n").unwrap(); // truncate + rewrite
        assert_eq!(next_line(&mut rx, &mut buf).await, "fresh");

        drop(rx);
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn large_files_are_batched() {
        let dir = std::env::temp_dir().join(format!("df2b-batch-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("big.log");
        let total = BATCH_MAX * 3 + 7;
        let content: String = (0..total).map(|i| format!("line {i}\n")).collect();
        std::fs::write(&path, &content).unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let handle = tokio::spawn(
            FileTailer::new(Arc::from("t"), path, false)
                .with_poll_interval(Duration::from_millis(10))
                .run(tx),
        );
        let mut seen = 0;
        let mut last_offset = 0;
        while seen < total {
            let b = recv_batch(&mut rx).await;
            assert!(b.lines.len() <= BATCH_MAX);
            assert_eq!(b.lines[0].line, format!("line {seen}"));
            seen += b.lines.len();
            if let Some(Position::File { offset, .. }) = b.position {
                assert!(offset > last_offset);
                last_offset = offset;
            }
        }
        assert_eq!(seen, total);
        assert_eq!(last_offset, content.len() as u64);

        drop(rx);
        handle.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

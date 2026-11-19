//! journald source.
//!
//! Each source runs on a dedicated OS thread that owns its `sd_journal`
//! handle (the handle is not thread-safe). The thread reads entries as fast
//! as the journal yields them, groups them into batches of up to
//! [`BATCH_MAX`] lines and blocks on `sd_journal_wait` once caught up.
//!
//! Per entry only `MESSAGE` and the realtime timestamp are read, with a data
//! threshold so oversized messages are not fully decompressed. The cursor is
//! fetched once per batch, not per entry.
//!
//! Matches follow `journalctl` semantics: `FIELD=value` terms on the same
//! field are ORed, on different fields ANDed, and a `"+"` term starts a new
//! group that is ORed with the previous one.

pub mod sys;

use std::path::PathBuf;
use std::sync::Arc;
use std::thread::JoinHandle;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{anyhow, Context};
use chrono::DateTime;
use tokio::sync::mpsc;
use tracing::{debug, error, info, warn};

use self::sys::Journal;
use crate::{LogLine, Position, SourceBatch, SourceErrors, BATCH_MAX, MAX_LINE};

/// How long `sd_journal_wait` blocks before checking for shutdown.
const WAIT_TIMEOUT: Duration = Duration::from_millis(500);

/// Where to start reading when there is no saved cursor.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Start {
    /// Only entries written after startup.
    #[default]
    Tail,
    /// Entries from this long ago onwards.
    Since(Duration),
    /// The whole journal.
    Head,
}

#[derive(Debug, Clone)]
pub struct JournaldSource {
    source: Arc<str>,
    matches: Vec<String>,
    directory: Option<PathBuf>,
    start: Start,
    cursor: Option<String>,
    errors: Option<Arc<SourceErrors>>,
}

impl JournaldSource {
    pub fn new(source: Arc<str>, matches: Vec<String>) -> Self {
        Self {
            source,
            matches,
            directory: None,
            start: Start::Tail,
            cursor: None,
            errors: None,
        }
    }

    /// Where an error that stops the source is recorded.
    pub fn with_errors(mut self, errors: Arc<SourceErrors>) -> Self {
        self.errors = Some(errors);
        self
    }

    /// Read journal files from `dir` instead of the system journal.
    pub fn with_directory(mut self, dir: Option<PathBuf>) -> Self {
        self.directory = dir;
        self
    }

    pub fn with_start(mut self, start: Start) -> Self {
        self.start = start;
        self
    }

    /// Resume after this cursor (takes precedence over [`Start`]).
    pub fn with_cursor(mut self, cursor: Option<String>) -> Self {
        self.cursor = cursor;
        self
    }

    /// Opens the journal on a dedicated thread and starts following it.
    ///
    /// Returns once the journal is open and positioned, so configuration
    /// errors (no libsystemd, bad match, unreadable directory) surface here.
    /// The thread ends when the receiver is dropped.
    pub fn spawn(self, tx: mpsc::Sender<SourceBatch>) -> anyhow::Result<JoinHandle<()>> {
        let (init_tx, init_rx) = std::sync::mpsc::sync_channel::<anyhow::Result<()>>(1);
        let name = self.source.clone();
        let handle = std::thread::Builder::new()
            .name(format!("journald-{}", self.source))
            .spawn(move || {
                let mut journal = match self.open() {
                    Ok(j) => {
                        let _ = init_tx.send(Ok(()));
                        j
                    }
                    Err(e) => {
                        let _ = init_tx.send(Err(e));
                        return;
                    }
                };
                info!(source = %self.source, "following journal");
                if let Err(e) = self.follow(&mut journal, &tx) {
                    error!(source = %self.source, error = %format!("{e:#}"), "journal source stopped");
                    if let Some(errors) = &self.errors {
                        errors.set(&self.source, format!("journal source stopped: {e:#}"));
                    }
                }
            })
            .context("spawning journald thread")?;
        init_rx
            .recv()
            .map_err(|_| anyhow!("journald thread for '{name}' died during startup"))??;
        Ok(handle)
    }

    fn open(&self) -> anyhow::Result<Journal> {
        let mut j = match &self.directory {
            Some(dir) => Journal::open_directory(dir)
                .with_context(|| format!("opening journal directory {}", dir.display()))?,
            None => Journal::open_system().context("opening system journal")?,
        };
        // "MESSAGE=" prefix + the longest message we keep
        j.set_data_threshold(MAX_LINE + 8)?;
        for m in &self.matches {
            if m == "+" {
                j.add_disjunction()?;
            } else {
                j.add_match(m).with_context(|| {
                    format!("invalid journal match '{m}' (expected FIELD=value)")
                })?;
            }
        }
        self.position(&mut j)?;
        Ok(j)
    }

    /// Positions the journal so that the next `next()` returns the first
    /// entry to process.
    fn position(&self, j: &mut Journal) -> anyhow::Result<()> {
        if let Some(c) = &self.cursor {
            j.seek_cursor(c).context("seeking to saved cursor")?;
            // `next()` lands on the saved entry if it still exists (already
            // processed: stay there) or on the following one (unprocessed:
            // step back so the main loop's `next()` returns it).
            if j.next_entry()? && !j.test_cursor(c)? {
                j.previous_entry()?;
            }
            return Ok(());
        }
        match self.start {
            Start::Head => j.seek_head()?,
            Start::Tail => {
                j.seek_tail()?;
                // without this, the first next() may return the last old entry
                j.previous_entry()?;
            }
            Start::Since(d) => {
                let since = SystemTime::now()
                    .checked_sub(d)
                    .unwrap_or(UNIX_EPOCH)
                    .duration_since(UNIX_EPOCH)
                    .unwrap_or_default();
                j.seek_realtime_usec(u64::try_from(since.as_micros()).unwrap_or(u64::MAX))?;
            }
        }
        Ok(())
    }

    fn follow(&self, j: &mut Journal, tx: &mpsc::Sender<SourceBatch>) -> anyhow::Result<()> {
        let mut batch: Vec<LogLine> = Vec::with_capacity(BATCH_MAX);
        loop {
            match j.next_entry() {
                Ok(true) => {
                    if let Some(line) = self.read_entry(j) {
                        batch.push(line);
                        if batch.len() >= BATCH_MAX && !self.flush(j, &mut batch, tx) {
                            return Ok(());
                        }
                    }
                    continue;
                }
                Ok(false) => {} // caught up
                Err(e) => warn!(source = %self.source, error = %e, "reading journal entry failed"),
            }
            if !batch.is_empty() && !self.flush(j, &mut batch, tx) {
                return Ok(());
            }
            if tx.is_closed() {
                return Ok(());
            }
            j.wait(WAIT_TIMEOUT)
                .context("waiting for journal changes")?;
        }
    }

    fn read_entry(&self, j: &mut Journal) -> Option<LogLine> {
        let ts = j
            .realtime_usec()
            .ok()
            .and_then(|us| DateTime::from_timestamp_micros(i64::try_from(us).ok()?));
        let data = match j.data(c"MESSAGE") {
            Ok(Some(d)) => d,
            Ok(None) => return None,
            Err(e) => {
                debug!(source = %self.source, error = %e, "skipping unreadable entry");
                return None;
            }
        };
        let msg = data.strip_prefix(b"MESSAGE=").unwrap_or(data);
        let msg = &msg[..msg.len().min(MAX_LINE)];
        Some(LogLine {
            source: self.source.clone(),
            ts,
            line: String::from_utf8_lossy(msg).into_owned(),
        })
    }

    /// Sends the batch, tagged with the current entry's cursor. Blocks while
    /// the channel is full (back-pressure). False if the receiver is gone.
    fn flush(
        &self,
        j: &mut Journal,
        batch: &mut Vec<LogLine>,
        tx: &mpsc::Sender<SourceBatch>,
    ) -> bool {
        let position = match j.cursor() {
            Ok(c) => Some(Position::JournalCursor(c)),
            Err(e) => {
                debug!(source = %self.source, error = %e, "no cursor for batch");
                None
            }
        };
        let lines = std::mem::replace(batch, Vec::with_capacity(BATCH_MAX));
        tx.blocking_send(SourceBatch {
            source: self.source.clone(),
            lines,
            position,
            backlog: None,
            gone: None,
        })
        .is_ok()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::Instant;

    fn empty_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("df2b-journal-{tag}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn libsystemd_or_skip() -> bool {
        if sys::available() {
            true
        } else {
            eprintln!("libsystemd.so.0 not available, skipping");
            false
        }
    }

    #[test]
    fn opens_with_match_groups_and_stops_on_receiver_drop() {
        if !libsystemd_or_skip() {
            return;
        }
        let dir = empty_dir("ok");
        let (tx, rx) = mpsc::channel(4);
        let handle = JournaldSource::new(
            Arc::from("sshd"),
            vec![
                "_SYSTEMD_UNIT=sshd.service".into(),
                "_SYSTEMD_UNIT=ssh.service".into(),
                "+".into(),
                "SYSLOG_IDENTIFIER=sshd".into(),
            ],
        )
        .with_directory(Some(dir.clone()))
        .spawn(tx)
        .expect("journal opens");

        drop(rx);
        let t = Instant::now();
        while !handle.is_finished() {
            assert!(t.elapsed() < Duration::from_secs(5), "thread did not stop");
            std::thread::sleep(Duration::from_millis(20));
        }
        handle.join().unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn all_start_positions_work_on_empty_journal() {
        if !libsystemd_or_skip() {
            return;
        }
        let dir = empty_dir("start");
        for start in [
            Start::Head,
            Start::Tail,
            Start::Since(Duration::from_secs(600)),
        ] {
            let (tx, rx) = mpsc::channel(4);
            let h = JournaldSource::new(Arc::from("s"), vec![])
                .with_directory(Some(dir.clone()))
                .with_start(start)
                .spawn(tx)
                .unwrap_or_else(|e| panic!("{start:?}: {e:#}"));
            drop(rx);
            h.join().unwrap();
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn invalid_match_fails_at_spawn() {
        if !libsystemd_or_skip() {
            return;
        }
        let dir = empty_dir("bad");
        let (tx, _rx) = mpsc::channel(4);
        let err = JournaldSource::new(Arc::from("s"), vec!["not a match".into()])
            .with_directory(Some(dir.clone()))
            .spawn(tx)
            .unwrap_err();
        assert!(
            format!("{err:#}").contains("invalid journal match"),
            "{err:#}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Needs a running journald and `systemd-cat`:
    /// `cargo test -p df2b-sources --features journald -- --ignored live_journal`
    #[test]
    #[ignore = "requires a running systemd-journald"]
    fn live_journal_roundtrip() {
        let ident = format!("df2b-test-{}", std::process::id());
        let (tx, mut rx) = mpsc::channel(16);
        let _h = JournaldSource::new(
            Arc::from("live"),
            vec![format!("SYSLOG_IDENTIFIER={ident}")],
        )
        .spawn(tx)
        .expect("system journal opens");

        let mut child = std::process::Command::new("systemd-cat")
            .args(["-t", &ident])
            .stdin(std::process::Stdio::piped())
            .spawn()
            .expect("systemd-cat available");
        use std::io::Write;
        let mut stdin = child.stdin.take().unwrap();
        for i in 0..3 {
            writeln!(
                stdin,
                "Failed password for root from 203.0.113.{i} port 22 ssh2"
            )
            .unwrap();
        }
        drop(stdin);
        child.wait().unwrap();

        let mut got = Vec::new();
        let deadline = Instant::now() + Duration::from_secs(10);
        while got.len() < 3 && Instant::now() < deadline {
            if let Ok(b) = rx.try_recv() {
                assert!(matches!(b.position, Some(Position::JournalCursor(_))));
                got.extend(b.lines);
            } else {
                std::thread::sleep(Duration::from_millis(50));
            }
        }
        assert_eq!(got.len(), 3, "entries received: {got:?}");
        assert!(got.iter().all(|l| l.ts.is_some()));
        assert_eq!(
            got[2].line,
            "Failed password for root from 203.0.113.2 port 22 ssh2"
        );
    }
}

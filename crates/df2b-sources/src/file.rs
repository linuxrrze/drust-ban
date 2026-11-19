//! File sources: a polling tailer per file, and glob paths on top.
//!
//! [`FileTailer`] follows one path. It keeps the file it reads open, so a
//! rotation by rename + create does not lose the lines written to the old
//! file after the last poll: it reads the old file to its end before
//! switching to the new one, and waits up to the rotation grace period while
//! the new file is still empty (the writer may not have reopened its log
//! yet). Truncation (copytruncate) restarts at 0. Resuming after a restart
//! finds a file rotated while the agent was down in the same directory (by
//! device and inode, whatever it is called now) and reads its remainder first.
//!
//! [`FileSource`] takes the configured paths; those with glob characters
//! (`*`, `?`, `[`) are expanded again periodically, and new matches get their
//! own tailer (from the start: they are new files). The tailer of a matched
//! file ends once the file is gone and read to its end.
//!
//! Tailers wake up on inotify events (see `watch.rs`) for their path's
//! directory entry and for the file they have open, and otherwise check
//! every [`IDLE_POLL`]; without inotify they poll every 250 ms.
//!
//! Lines get their event time from a timestamp at their start when they
//! have one (see `timestamp.rs`; [`FileTailer::with_timestamps`]).

use std::collections::{HashMap, HashSet};
use std::io::SeekFrom;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant};

use std::os::unix::io::AsRawFd;
use tokio::io::{AsyncReadExt, AsyncSeekExt};

use tokio::sync::{mpsc, Notify};
use tokio::task::JoinSet;
use tracing::{debug, error, info, warn};

use crate::watch::{Hub, Watch};
use crate::{LogLine, Position, SourceBatch, SourceErrors, BATCH_MAX, MAX_LINE};

/// Maximum bytes read per poll iteration (bounds memory per tailer).
const MAX_READ: u64 = 4 * 1024 * 1024;
/// How much older than the time it was read a line read live may claim
/// to be (buffered writers, e.g. nginx with `flush=`).
const LIVE_SLACK: chrono::TimeDelta = chrono::TimeDelta::minutes(5);

/// Check interval while inotify wakes the tailer (a safety net only).
pub const IDLE_POLL: Duration = Duration::from_secs(2);
/// How long a rotated-away file is kept open while its replacement is empty.
const ROTATION_GRACE: Duration = Duration::from_secs(30);
/// Files followed per source at most (glob matches beyond are ignored).
pub const MAX_FILES: usize = 1024;

/// True if `path` contains glob characters and is expanded by [`FileSource`].
pub fn is_glob(path: &Path) -> bool {
    path.to_string_lossy().contains(['*', '?', '['])
}

/// Checks a configured path: a glob must be a valid pattern.
pub fn check_path(path: &Path) -> anyhow::Result<()> {
    if is_glob(path) {
        glob::Pattern::new(&path.to_string_lossy())
            .map_err(|e| anyhow::anyhow!("{}: invalid glob: {e}", path.display()))?;
    }
    Ok(())
}

/// Why a tailer stopped.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Ended {
    /// The receiver is gone (shutting down).
    Closed,
    /// The file is gone and read to its end ([`FileTailer::exit_when_gone`]).
    Gone,
}

#[derive(Debug, Clone)]
pub struct FileTailer {
    source: Arc<str>,
    path: PathBuf,
    start_at_end: bool,
    poll: Duration,
    idle_poll: Duration,
    grace: Duration,
    exit_when_gone: bool,
    timestamps: bool,
    /// Canonical directories the opened file must really be in (sources
    /// the controller defined: symlinks and glob tricks must not lead
    /// elsewhere).
    roots: Option<Arc<Vec<PathBuf>>>,
    resume: Option<FileId>,
    resume_offset: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct FileId {
    dev: u64,
    ino: u64,
}

impl FileId {
    fn of(meta: &std::fs::Metadata) -> Self {
        Self {
            dev: meta.dev(),
            ino: meta.ino(),
        }
    }
}

/// The file being read, kept open across rotations.
struct Open {
    id: FileId,
    file: tokio::fs::File,
    /// Next byte to read; bytes of an incomplete last line precede it.
    offset: u64,
}

impl FileTailer {
    pub fn new(source: Arc<str>, path: PathBuf, start_at_end: bool) -> Self {
        Self {
            source,
            path,
            start_at_end,
            poll: Duration::from_millis(250),
            idle_poll: IDLE_POLL,
            grace: ROTATION_GRACE,
            exit_when_gone: false,
            timestamps: true,
            roots: None,
            resume: None,
            resume_offset: 0,
        }
    }

    /// Resume from a saved position (overrides `start_at_end`).
    ///
    /// If the file at `path` is still the same inode, reading continues at
    /// `offset` (or at 0 if it was truncated meanwhile). If it was replaced
    /// (rotated while the agent was down), the old file is looked up in the
    /// same directory and read from `offset` first; then the new file is
    /// read from 0.
    pub fn with_position(mut self, dev: u64, ino: u64, offset: u64) -> Self {
        self.resume = Some(FileId { dev, ino });
        self.resume_offset = offset;
        self
    }

    /// Check interval without inotify; also replaces [`IDLE_POLL`].
    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = poll;
        self.idle_poll = poll;
        self
    }

    /// Check interval while inotify works.
    pub fn with_idle_poll(mut self, poll: Duration) -> Self {
        self.idle_poll = poll;
        self
    }

    /// How long a rotated-away file stays open while the new one is empty.
    pub fn with_rotation_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// Take each line's event time from its timestamp (default); off: the
    /// time it is read.
    pub fn with_timestamps(mut self, on: bool) -> Self {
        self.timestamps = on;
        self
    }

    /// Only read files that really are below one of these (canonical)
    /// directories, wherever the path or its symlinks point.
    pub fn with_allowed_roots(mut self, roots: Arc<Vec<PathBuf>>) -> Self {
        self.roots = Some(roots);
        self
    }

    /// Opens a regular file without blocking (a FIFO would block until a
    /// writer comes) and checks where it really is.
    async fn open_checked(&self, path: &Path) -> Option<(tokio::fs::File, std::fs::Metadata)> {
        let file = tokio::fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NONBLOCK)
            .open(path)
            .await
            .map_err(|e| debug!(path = %path.display(), error = %e, "file not available"))
            .ok()?;
        let meta = file.metadata().await.ok()?;
        if !meta.is_file() {
            warn!(path = %path.display(), "not a regular file, not reading it");
            return None;
        }
        if let Some(roots) = &self.roots {
            let real = std::fs::read_link(format!("/proc/self/fd/{}", file.as_raw_fd())).ok()?;
            if !under_roots(&real, roots) {
                warn!(path = %path.display(), real = %real.display(), "file is outside the allowed directories, not reading it");
                return None;
            }
        }
        Some((file, meta))
    }

    /// End once the path is gone (after the grace period) and the last file
    /// is read to its end, instead of waiting for it to come back.
    pub fn exit_when_gone(mut self, exit: bool) -> Self {
        self.exit_when_gone = exit;
        self
    }

    /// Sends `batch` with the position `offset` and the bytes still to
    /// read; false if the receiver is gone.
    async fn send(
        &self,
        tx: &mpsc::Sender<SourceBatch>,
        batch: &mut Vec<LogLine>,
        id: FileId,
        offset: u64,
        backlog: u64,
    ) -> bool {
        let lines = std::mem::take(batch);
        let position = Some(Position::File {
            path: self.path.clone(),
            dev: id.dev,
            ino: id.ino,
            offset,
        });
        tx.send(SourceBatch {
            source: self.source.clone(),
            lines,
            position,
            backlog: Some(backlog),
            gone: None,
        })
        .await
        .is_ok()
    }

    /// `live`: read while following the file (not catching up on older
    /// content): it was written just now, so a timestamp claiming it is
    /// much older is not believed - part of a line can be attacker text
    /// (an access log's user field comes before its time stamp) and an old
    /// stamp would keep its failures from counting.
    fn line(&self, raw: &[u8], live: bool) -> LogLine {
        let raw = &raw[..raw.len().min(MAX_LINE)];
        // CRLF logs: the patterns end with $
        let raw = raw.strip_suffix(b"\r").unwrap_or(raw);
        let line = String::from_utf8_lossy(raw).into_owned();
        let now = chrono::Utc::now();
        let ts = if self.timestamps {
            crate::timestamp::parse(&line, now)
        } else {
            None
        };
        let ts = match ts {
            Some(t) if live => Some(t.max(now - LIVE_SLACK)),
            t => t,
        };
        LogLine {
            source: self.source.clone(),
            ts,
            line,
        }
    }

    /// Opens `path` if it is still the file `id`; the offset to read from.
    async fn open_if(&self, path: &Path, id: FileId, offset: u64) -> Option<Open> {
        let (file, meta) = self.open_checked(path).await?;
        (FileId::of(&meta) == id).then(|| Open {
            id,
            file,
            offset: if meta.len() < offset { 0 } else { offset },
        })
    }

    /// The file to read next: on the first call the saved position (also a
    /// file rotated away meanwhile), else the file now at `path`.
    async fn open_next(&self, first: bool) -> Option<Open> {
        if first {
            if let Some(id) = self.resume {
                if let Some(o) = self.open_if(&self.path, id, self.resume_offset).await {
                    return Some(o);
                }
                if let Some(old) = find_by_id(&self.path, id).await {
                    if let Some(o) = self.open_if(&old, id, self.resume_offset).await {
                        info!(
                            path = %self.path.display(), rotated = %old.display(),
                            offset = o.offset, "file rotated while stopped, reading the rest first"
                        );
                        return Some(o);
                    }
                }
            }
        }
        let (file, meta) = self.open_checked(&self.path).await?;
        let offset = if first && self.resume.is_none() && self.start_at_end {
            meta.len()
        } else {
            0
        };
        Some(Open {
            id: FileId::of(&meta),
            file,
            offset,
        })
    }

    /// Keeps the inotify watches current: the directory entry of `path`,
    /// and the open file (by inode, also after a rename).
    fn rewatch(&self, w: &mut Watches, open: Option<&Open>) {
        let Some(hub) = Hub::global() else { return };
        if w.entry.is_none() {
            let dir = match self.path.parent() {
                Some(d) if !d.as_os_str().is_empty() => d,
                _ => Path::new("."),
            };
            if let Some(name) = self.path.file_name() {
                match hub.watch_entry(dir, name, &w.notify) {
                    Ok(x) => w.entry = Some(x),
                    Err(e) => {
                        debug!(path = %self.path.display(), error = %e, "cannot watch directory")
                    }
                }
            }
        }
        match open {
            None => w.file = None,
            Some(o) if w.file.as_ref().map(|f| f.0) != Some(o.id) => {
                w.file = match hub.watch_fd(o.file.as_raw_fd(), &w.notify) {
                    Ok(x) => Some((o.id, x)),
                    Err(e) => {
                        debug!(path = %self.path.display(), error = %e, "cannot watch file");
                        None
                    }
                };
            }
            Some(_) => {}
        }
    }

    /// Waits for an inotify event or the poll interval; while a rotated
    /// file waits for its grace period, not longer than that.
    async fn idle(&self, w: &mut Watches, open: Option<&Open>, rotated_since: Option<Instant>) {
        self.rewatch(w, open);
        let mut d = if w.entry.is_some() {
            self.idle_poll
        } else {
            self.poll
        };
        if let Some(since) = rotated_since {
            d = d.min(self.grace.saturating_sub(since.elapsed()).max(self.poll));
        }
        tokio::select! {
            _ = w.notify.notified() => {}
            _ = tokio::time::sleep(d) => {}
        }
    }

    /// Runs until the receiver is dropped (or, with [`Self::exit_when_gone`],
    /// the file is gone).
    pub async fn run(self, tx: mpsc::Sender<SourceBatch>) -> anyhow::Result<Ended> {
        info!(source = %self.source, path = %self.path.display(), "tailing file");
        let mut open: Option<Open> = None;
        let mut first = true;
        // Bytes of an incomplete last line; they precede `offset` in the file.
        let mut pending: Vec<u8> = Vec::with_capacity(64 * 1024);
        let mut batch: Vec<LogLine> = Vec::new();
        // Since when `path` is no longer the open file.
        let mut rotated_since: Option<Instant> = None;
        // Read the open file to its end once more, then switch.
        let mut finishing = false;
        // inside an over-long line, skipping to its end
        let mut skipping = false;
        // caught up with the open file once (see `line`)
        let mut live = false;
        let mut watches = Watches {
            notify: Arc::new(Notify::new()),
            entry: None,
            file: None,
        };

        loop {
            if tx.is_closed() {
                return Ok(Ended::Closed);
            }
            let Some(cur) = open.as_mut() else {
                match self.open_next(first).await {
                    Some(o) => {
                        first = false;
                        open = Some(o);
                    }
                    None if self.exit_when_gone => return Ok(Ended::Gone),
                    None => self.idle(&mut watches, None, None).await,
                }
                continue;
            };

            let len = cur.file.metadata().await?.len();
            if len < cur.offset {
                info!(path = %self.path.display(), "file truncated, restarting at 0");
                pending.clear();
                cur.offset = 0;
                skipping = false;
            }
            let mut n = 0;
            if len > cur.offset {
                cur.file.seek(SeekFrom::Start(cur.offset)).await?;
                let mut chunk = Vec::new();
                n = (&mut cur.file)
                    .take(MAX_READ)
                    .read_to_end(&mut chunk)
                    .await? as u64;
                // file offset of pending[0]
                let mut base = cur.offset - pending.len() as u64;
                cur.offset += n;
                let unread = len.saturating_sub(cur.offset);
                if skipping {
                    // the rest of an over-long line: never a line of its own
                    match memchr::memchr(b'\n', &chunk) {
                        Some(i) => {
                            chunk.drain(..=i);
                            base += i as u64 + 1;
                            skipping = false;
                        }
                        None => {
                            base += chunk.len() as u64;
                            chunk.clear();
                        }
                    }
                }
                pending.extend_from_slice(&chunk);
                let mut start = 0;
                for pos in memchr::memchr_iter(b'\n', &pending) {
                    batch.push(self.line(&pending[start..pos], live));
                    start = pos + 1;
                    if batch.len() >= BATCH_MAX
                        && !self
                            .send(&tx, &mut batch, cur.id, base + start as u64, unread)
                            .await
                    {
                        return Ok(Ended::Closed); // receiver gone: shutting down
                    }
                }
                if !batch.is_empty()
                    && !self
                        .send(&tx, &mut batch, cur.id, base + start as u64, unread)
                        .await
                {
                    return Ok(Ended::Closed);
                }
                pending.drain(..start);
                if pending.len() > MAX_LINE {
                    // keep its start (like any over-long line), skip the
                    // rest up to its newline: the tail must not become a
                    // line of its own (it could be a forged log entry).
                    // The position stays at the line's start, so after a
                    // restart it is cut again rather than its tail read.
                    warn!(path = %self.path.display(), "over-long line, keeping its first {MAX_LINE} bytes");
                    let line_start = base + start as u64;
                    batch.push(self.line(&pending, live));
                    pending.clear();
                    skipping = true;
                    if !self.send(&tx, &mut batch, cur.id, line_start, unread).await {
                        return Ok(Ended::Closed);
                    }
                }
            }
            if n == MAX_READ {
                continue; // more to read right away
            }
            // at the end of what was written: from now on lines are new
            live = true;

            if finishing {
                // The rotated-away file is read to its end: nobody will
                // complete its last line any more.
                if !pending.is_empty() {
                    batch.push(self.line(&pending, live));
                    pending.clear();
                    if !self.send(&tx, &mut batch, cur.id, cur.offset, 0).await {
                        return Ok(Ended::Closed);
                    }
                }
                open = None;
                finishing = false;
                // the next file starts fresh
                live = false;
                skipping = false;
                rotated_since = None;
                continue;
            }

            // At the end of the open file: is `path` still this file?
            match tokio::fs::metadata(&self.path).await {
                Ok(m) if FileId::of(&m) == cur.id => rotated_since = None,
                now => {
                    let since = *rotated_since.get_or_insert_with(Instant::now);
                    let replaced = now.as_ref().ok();
                    let new_has_data = replaced.is_some_and(|m| m.len() > 0);
                    let waited = since.elapsed() >= self.grace;
                    if new_has_data || (waited && (replaced.is_some() || self.exit_when_gone)) {
                        if replaced.is_some() {
                            info!(path = %self.path.display(), "file rotated, switching to new inode");
                        } else {
                            info!(path = %self.path.display(), "file gone");
                        }
                        finishing = true;
                        continue;
                    }
                }
            }
            let cur = open.as_ref();
            self.idle(&mut watches, cur, rotated_since).await;
        }
    }
}

struct Watches {
    notify: Arc<Notify>,
    /// The directory entry of the path.
    entry: Option<Watch>,
    /// The open file.
    file: Option<(FileId, Watch)>,
}

/// A file in the directory of `path` that is the file `id` (a rotated-away
/// log under its new name).
async fn find_by_id(path: &Path, id: FileId) -> Option<PathBuf> {
    let dir = match path.parent() {
        Some(d) if !d.as_os_str().is_empty() => d.to_path_buf(),
        _ => PathBuf::from("."),
    };
    tokio::task::spawn_blocking(move || {
        for entry in std::fs::read_dir(&dir).ok()?.flatten() {
            let Ok(meta) = entry.metadata() else { continue };
            if meta.is_file() && FileId::of(&meta) == id {
                return Some(entry.path());
            }
        }
        None
    })
    .await
    .ok()
    .flatten()
}

/// The configured paths of one file source, glob paths expanded.
#[derive(Debug, Clone)]
pub struct FileSource {
    source: Arc<str>,
    paths: Vec<PathBuf>,
    start_at_end: bool,
    positions: HashMap<PathBuf, (u64, u64, u64)>,
    /// Overrides the tailers' poll intervals.
    poll: Option<Duration>,
    grace: Duration,
    rescan: Duration,
    errors: Option<Arc<SourceErrors>>,
    timestamps: bool,
    /// See [`FileTailer::with_allowed_roots`] (not yet canonical).
    roots: Option<Vec<PathBuf>>,
}

impl FileSource {
    pub fn new(source: Arc<str>, paths: Vec<PathBuf>, start_at_end: bool) -> Self {
        Self {
            source,
            paths,
            start_at_end,
            positions: HashMap::new(),
            poll: None,
            grace: ROTATION_GRACE,
            rescan: Duration::from_secs(10),
            errors: None,
            timestamps: true,
            roots: None,
        }
    }

    /// Only follow files really below these directories (sources the
    /// controller defined; see [`FileTailer::with_allowed_roots`]).
    pub fn with_allowed_roots(mut self, roots: Vec<PathBuf>) -> Self {
        self.roots = Some(roots);
        self
    }

    /// See [`FileTailer::with_timestamps`].
    pub fn with_timestamps(mut self, on: bool) -> Self {
        self.timestamps = on;
        self
    }

    /// Where errors of its files are recorded.
    pub fn with_errors(mut self, errors: Arc<SourceErrors>) -> Self {
        self.errors = Some(errors);
        self
    }

    /// The saved position of the file at `path` (a configured path or a
    /// glob match).
    pub fn with_position(mut self, path: PathBuf, dev: u64, ino: u64, offset: u64) -> Self {
        self.positions.insert(path, (dev, ino, offset));
        self
    }

    pub fn with_poll_interval(mut self, poll: Duration) -> Self {
        self.poll = Some(poll);
        self
    }

    pub fn with_rotation_grace(mut self, grace: Duration) -> Self {
        self.grace = grace;
        self
    }

    /// How often glob paths are expanded again.
    pub fn with_rescan_interval(mut self, rescan: Duration) -> Self {
        self.rescan = rescan;
        self
    }

    fn tailer(
        &self,
        path: &Path,
        start_at_end: bool,
        roots: &Option<Arc<Vec<PathBuf>>>,
    ) -> FileTailer {
        let mut t = FileTailer::new(self.source.clone(), path.to_path_buf(), start_at_end)
            .with_rotation_grace(self.grace)
            .with_timestamps(self.timestamps);
        if let Some(r) = roots {
            t = t.with_allowed_roots(r.clone());
        }
        if let Some(poll) = self.poll {
            t = t.with_poll_interval(poll);
        }
        if let Some(&(dev, ino, offset)) = self.positions.get(path) {
            info!(source = %self.source, path = %path.display(), offset, "resuming file");
            t = t.with_position(dev, ino, offset);
        }
        t
    }

    /// Runs until the receiver is dropped; ends the tailers when it ends.
    pub async fn run(self, tx: mpsc::Sender<SourceBatch>) -> anyhow::Result<()> {
        let (globs, literal): (Vec<_>, Vec<_>) = self.paths.iter().partition(|p| is_glob(p));
        let patterns = globs
            .iter()
            .map(|p| {
                check_path(p)?;
                Ok(p.to_string_lossy().into_owned())
            })
            .collect::<anyhow::Result<Vec<_>>>()?;
        // canonical, so symlinks in the allowed directories themselves are
        // fine; a missing one allows nothing
        let roots: Option<Arc<Vec<PathBuf>>> = self.roots.as_ref().map(|r| {
            Arc::new(
                r.iter()
                    .filter_map(|p| std::fs::canonicalize(p).ok())
                    .collect(),
            )
        });

        let mut tasks: JoinSet<PathBuf> = JoinSet::new();
        let mut active: HashSet<PathBuf> = HashSet::new();
        let spawn = |tasks: &mut JoinSet<PathBuf>, t: FileTailer| {
            let (path, source, tx) = (t.path.clone(), self.source.clone(), tx.clone());
            let errors = self.errors.clone();
            tasks.spawn(async move {
                match t.run(tx.clone()).await {
                    Ok(Ended::Gone) => {
                        // its saved position is of no use any more
                        let _ = tx
                            .send(SourceBatch {
                                source: source.clone(),
                                lines: Vec::new(),
                                position: None,
                                backlog: None,
                                gone: Some(path.clone()),
                            })
                            .await;
                    }
                    Ok(Ended::Closed) => {}
                    Err(e) => {
                        error!(%source, path = %path.display(), error = %e, "file source failed");
                        if let Some(errors) = errors {
                            errors.set(&source, format!("{}: {e:#}", path.display()));
                        }
                    }
                }
                path
            });
        };
        for p in literal {
            if active.insert(p.clone()) {
                spawn(&mut tasks, self.tailer(p, self.start_at_end, &roots));
            }
        }

        let mut first = true;
        let mut warned = false;
        loop {
            if !patterns.is_empty() {
                let found = tokio::task::spawn_blocking({
                    let (patterns, roots) = (patterns.clone(), roots.clone());
                    move || {
                        let mut found = expand(&patterns);
                        // matches that really are elsewhere are not followed
                        if let Some(roots) = roots {
                            found.retain(|p| {
                                std::fs::canonicalize(p)
                                    .is_ok_and(|real| under_roots(&real, &roots))
                            });
                        }
                        found
                    }
                })
                .await?;
                for path in found {
                    if active.contains(&path) {
                        continue;
                    }
                    if active.len() >= MAX_FILES {
                        if !warned {
                            warn!(source = %self.source, max = MAX_FILES, "too many files, ignoring further matches");
                            warned = true;
                        }
                        break;
                    }
                    if !first {
                        info!(source = %self.source, path = %path.display(), "new file");
                    }
                    // files present at start follow `start_at_end`; files
                    // appearing later are new and read from the start
                    let t = self
                        .tailer(&path, first && self.start_at_end, &roots)
                        .exit_when_gone(true);
                    active.insert(path);
                    spawn(&mut tasks, t);
                }
            } else if tasks.is_empty() {
                return Ok(());
            }
            first = false;

            let rescan = tokio::time::sleep(self.rescan);
            tokio::pin!(rescan);
            loop {
                tokio::select! {
                    Some(done) = tasks.join_next() => {
                        if let Ok(path) = done {
                            active.remove(&path);
                        }
                        if tx.is_closed() {
                            return Ok(());
                        }
                    }
                    _ = &mut rescan => break,
                    _ = tx.closed() => return Ok(()),
                }
            }
        }
    }
}

/// Below (not equal to) one of the canonical `roots`.
fn under_roots(real: &Path, roots: &[PathBuf]) -> bool {
    roots
        .iter()
        .any(|r| real.starts_with(r) && real != r.as_path())
}

/// Regular files matching any of `patterns`, sorted, without duplicates.
fn expand(patterns: &[String]) -> Vec<PathBuf> {
    let mut found = Vec::new();
    for p in patterns {
        let Ok(paths) = glob::glob(p) else { continue };
        found.extend(paths.flatten().filter(|p| p.is_file()));
    }
    found.sort();
    found.dedup();
    found
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Datelike;
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
    async fn resumes_from_saved_position() {
        let dir = std::env::temp_dir().join(format!("df2b-resume-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("r.log");
        std::fs::write(&path, "old1\nold2\nnew1\n").unwrap();
        let meta = std::fs::metadata(&path).unwrap();

        // same inode: continue after "old1\nold2\n"
        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileTailer::new(Arc::from("t"), path.clone(), false)
                .with_poll_interval(Duration::from_millis(10))
                .with_position(meta.dev(), meta.ino(), 10)
                .run(tx),
        );
        let lines: Vec<_> = recv_batch(&mut rx)
            .await
            .lines
            .into_iter()
            .map(|l| l.line)
            .collect();
        assert_eq!(lines, ["new1"]);
        drop(rx);
        h.abort();

        // different inode (rotated while down): read the new file from 0
        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileTailer::new(Arc::from("t"), path.clone(), true)
                .with_poll_interval(Duration::from_millis(10))
                .with_position(meta.dev(), meta.ino() + 1, 10)
                .run(tx),
        );
        assert_eq!(recv_batch(&mut rx).await.lines[0].line, "old1");
        drop(rx);
        h.abort();
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

    fn tmpdir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("df2b-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn append(path: &Path, s: &str) {
        std::fs::OpenOptions::new()
            .append(true)
            .create(true)
            .open(path)
            .unwrap()
            .write_all(s.as_bytes())
            .unwrap();
    }

    #[tokio::test]
    async fn rotation_reads_the_old_file_to_its_end() {
        let dir = tmpdir("rotate");
        let path = dir.join("app.log");
        std::fs::write(&path, "a\n").unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileTailer::new(Arc::from("t"), path.clone(), false)
                .with_poll_interval(Duration::from_millis(10))
                .run(tx),
        );
        let mut buf = VecDeque::new();
        assert_eq!(next_line(&mut rx, &mut buf).await, "a");

        // rename + create; the writer still writes to the old file, which
        // ends in an incomplete line
        let old = dir.join("app.log.1");
        std::fs::rename(&path, &old).unwrap();
        append(&old, "b\nc");
        std::fs::write(&path, "d\n").unwrap();
        assert_eq!(next_line(&mut rx, &mut buf).await, "b");
        assert_eq!(next_line(&mut rx, &mut buf).await, "c");
        assert_eq!(next_line(&mut rx, &mut buf).await, "d");

        drop(rx);
        h.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rotation_waits_while_the_new_file_is_empty() {
        let dir = tmpdir("grace");
        let path = dir.join("app.log");
        std::fs::write(&path, "a\n").unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileTailer::new(Arc::from("t"), path.clone(), false)
                .with_poll_interval(Duration::from_millis(10))
                .run(tx),
        );
        let mut buf = VecDeque::new();
        assert_eq!(next_line(&mut rx, &mut buf).await, "a");

        let old = dir.join("app.log.1");
        std::fs::rename(&path, &old).unwrap();
        std::fs::write(&path, "").unwrap();
        tokio::time::sleep(Duration::from_millis(50)).await;
        append(&old, "late\n"); // the writer has not reopened yet
        assert_eq!(next_line(&mut rx, &mut buf).await, "late");
        append(&path, "new\n");
        assert_eq!(next_line(&mut rx, &mut buf).await, "new");
        let b = recv_batch_or_none(&mut rx).await;
        assert!(b.is_none(), "nothing more expected");

        drop(rx);
        h.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    async fn recv_batch_or_none(rx: &mut mpsc::Receiver<SourceBatch>) -> Option<SourceBatch> {
        tokio::time::timeout(Duration::from_millis(100), rx.recv())
            .await
            .ok()
            .flatten()
    }

    #[tokio::test]
    async fn resume_reads_a_file_rotated_while_stopped() {
        let dir = tmpdir("resume-rotated");
        let path = dir.join("r.log");
        std::fs::write(&path, "old1\nold2\n").unwrap();
        let meta = std::fs::metadata(&path).unwrap();
        // stopped after "old1\n"; then rotated, more written to the old file
        let old = dir.join("r.log-20261119");
        std::fs::rename(&path, &old).unwrap();
        append(&old, "old3\n");
        std::fs::write(&path, "new1\n").unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileTailer::new(Arc::from("t"), path.clone(), true)
                .with_poll_interval(Duration::from_millis(10))
                .with_position(meta.dev(), meta.ino(), 5)
                .run(tx),
        );
        let b = recv_batch(&mut rx).await;
        let lines: Vec<_> = b.lines.iter().map(|l| l.line.as_str()).collect();
        assert_eq!(lines, ["old2", "old3"]);
        // the position names the configured path and the old inode
        assert_eq!(
            b.position,
            Some(Position::File {
                path: path.clone(),
                dev: meta.dev(),
                ino: meta.ino(),
                offset: 15
            })
        );
        let mut buf = VecDeque::new();
        assert_eq!(next_line(&mut rx, &mut buf).await, "new1");

        drop(rx);
        h.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn glob_paths_pick_up_new_files() {
        let dir = tmpdir("glob");
        let a = dir.join("a.log");
        std::fs::write(&a, "a-old\n").unwrap();
        std::fs::write(dir.join("ignored.txt"), "x\n").unwrap();

        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileSource::new(Arc::from("t"), vec![dir.join("*.log")], true)
                .with_poll_interval(Duration::from_millis(10))
                .with_rescan_interval(Duration::from_millis(20))
                .with_rotation_grace(Duration::from_millis(20))
                .run(tx),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        let mut buf = VecDeque::new();
        append(&a, "a1\n"); // existing file: from its end
        assert_eq!(next_line(&mut rx, &mut buf).await, "a1");

        let b = dir.join("b.log");
        std::fs::write(&b, "b1\n").unwrap(); // new file: from the start
        let batch = recv_batch(&mut rx).await;
        assert_eq!(batch.lines[0].line, "b1");
        assert!(matches!(&batch.position, Some(Position::File { path, .. }) if path == &b));

        // removed: its position is given up; created again: a new tailer
        // reads it
        std::fs::remove_file(&b).unwrap();
        let gone = recv_batch(&mut rx).await;
        assert!(gone.lines.is_empty() && gone.position.is_none());
        assert_eq!(gone.gone.as_deref(), Some(b.as_path()));
        tokio::time::sleep(Duration::from_millis(100)).await;
        std::fs::write(&b, "b2\n").unwrap();
        assert_eq!(next_line(&mut rx, &mut buf).await, "b2");

        drop(rx);
        tokio::time::timeout(Duration::from_secs(5), h)
            .await
            .expect("source ends with the receiver")
            .unwrap()
            .unwrap();
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn glob_detection_and_check() {
        assert!(is_glob(Path::new("/var/log/nginx/*.log")));
        assert!(is_glob(Path::new("/var/log/app?.log")));
        assert!(!is_glob(Path::new("/var/log/auth.log")));
        assert!(check_path(Path::new("/var/log/[a.log")).is_err());
        assert!(check_path(Path::new("/var/log/*/access.log")).is_ok());
    }

    async fn quick(rx: &mut mpsc::Receiver<SourceBatch>) -> Vec<String> {
        tokio::time::timeout(Duration::from_secs(2), rx.recv())
            .await
            .expect("no inotify wake-up")
            .unwrap()
            .lines
            .into_iter()
            .map(|l| l.line)
            .collect()
    }

    #[tokio::test]
    async fn inotify_wakes_without_polling() {
        let dir = std::env::temp_dir().join(format!("df2b-tail-inotify-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("app.log");
        let (tx, mut rx) = mpsc::channel(16);
        // polling far too slow for the deadlines below: events must do it
        let h = tokio::spawn(
            FileTailer::new(Arc::from("t"), path.clone(), false)
                .with_poll_interval(Duration::from_secs(60))
                .with_rotation_grace(Duration::from_secs(60))
                .run(tx),
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
        // the file appears
        std::fs::write(&path, "one\n").unwrap();
        assert_eq!(quick(&mut rx).await, ["one"]);
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        f.write_all(b"two\n").unwrap();
        assert_eq!(quick(&mut rx).await, ["two"]);
        // rotation: the writer still writes to the old file, then the
        // new one gets data
        std::fs::rename(&path, dir.join("app.log.1")).unwrap();
        f.write_all(b"three\n").unwrap();
        assert_eq!(quick(&mut rx).await, ["three"]);
        std::fs::write(&path, "four\n").unwrap();
        assert_eq!(quick(&mut rx).await, ["four"]);
        h.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: the tail of a discarded over-long partial line used to
    /// come out as a line of its own (a forged entry after 16 KiB of junk).
    #[tokio::test]
    async fn over_long_line_tail_is_not_a_line() {
        let dir = tmpdir("overlong");
        let path = dir.join("app.log");
        std::fs::write(&path, "").unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileTailer::new(Arc::from("t"), path.clone(), false)
                .with_poll_interval(Duration::from_millis(10))
                .run(tx),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        append(&path, &"A".repeat(MAX_LINE + 1000));
        let cut = recv_batch(&mut rx).await;
        assert_eq!(cut.lines.len(), 1);
        assert_eq!(cut.lines[0].line.len(), MAX_LINE, "kept, cut");
        append(&path, "Nov 19 05:52:01 host sshd[1]: Failed password for root from 192.0.2.77 port 22 ssh2\nreal\n");
        let mut buf = VecDeque::new();
        assert_eq!(
            next_line(&mut rx, &mut buf).await,
            "real",
            "the forged tail was skipped"
        );
        h.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: a time stamp in attacker-controlled text (an access
    /// log's user field) could make a live line look ancient, so its
    /// failure never counted. Catching up keeps the stamps.
    #[tokio::test]
    async fn live_lines_cannot_claim_to_be_old() {
        let dir = tmpdir("livets");
        let path = dir.join("access.log");
        let line = r#"203.0.113.7 - x [01/Jan/2000:00:00:00 +0000] "GET / HTTP/1.1" 401 0"#;
        std::fs::write(&path, format!("{line}\r\n")).unwrap();
        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileTailer::new(Arc::from("t"), path.clone(), false)
                .with_poll_interval(Duration::from_millis(10))
                .run(tx),
        );
        let old = recv_batch(&mut rx).await.lines.remove(0);
        assert_eq!(old.line, line, "CR stripped");
        assert_eq!(
            old.ts.unwrap().year(),
            2000,
            "catching up: the stamp counts"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        append(&path, &format!("{line}\n"));
        let live = recv_batch(&mut rx).await.lines.remove(0);
        let age = chrono::Utc::now() - live.ts.unwrap();
        assert!(
            age <= LIVE_SLACK + chrono::TimeDelta::seconds(5),
            "live: {age}"
        );
        h.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: files the controller defined could be reached through
    /// symlinks (and glob tricks) outside central_paths; a FIFO blocked the
    /// tailer on open.
    #[tokio::test]
    async fn allowed_roots_are_enforced() {
        let dir = tmpdir("roots");
        let logs = dir.join("logs");
        std::fs::create_dir_all(&logs).unwrap();
        let secret = dir.join("secret.txt");
        std::fs::write(
            &secret,
            "Failed password for root from 192.0.2.9 port 1 ssh2\n",
        )
        .unwrap();
        std::os::unix::fs::symlink(&secret, logs.join("evil.log")).unwrap();
        std::fs::write(logs.join("ok.log"), "fine\n").unwrap();
        let fifo = logs.join("fifo.log");
        assert!(std::process::Command::new("mkfifo")
            .arg(&fifo)
            .status()
            .unwrap()
            .success());

        let (tx, mut rx) = mpsc::channel(16);
        let h = tokio::spawn(
            FileSource::new(Arc::from("central:x"), vec![logs.join("*.log")], false)
                .with_allowed_roots(vec![logs.clone()])
                .with_poll_interval(Duration::from_millis(10))
                .with_rescan_interval(Duration::from_millis(50))
                .run(tx),
        );
        let b = recv_batch(&mut rx).await;
        assert_eq!(b.lines[0].line, "fine");
        // the literal path of the symlink is refused as well
        let (tx2, mut rx2) = mpsc::channel(16);
        let h2 = tokio::spawn(
            FileSource::new(
                Arc::from("central:y"),
                vec![logs.join("evil.log"), fifo.clone()],
                false,
            )
            .with_allowed_roots(vec![logs.clone()])
            .with_poll_interval(Duration::from_millis(10))
            .run(tx2),
        );
        tokio::time::sleep(Duration::from_millis(300)).await;
        assert!(
            rx.try_recv().is_err(),
            "nothing from outside or from the FIFO"
        );
        assert!(rx2.try_recv().is_err());
        // a FIFO is refused at once, not waited on
        let t = FileTailer::new(Arc::from("central:y"), fifo.clone(), false);
        let opened = tokio::time::timeout(Duration::from_secs(1), t.open_checked(&fifo))
            .await
            .expect("open of a FIFO must not block");
        assert!(opened.is_none());
        h.abort();
        h2.abort();
        let _ = std::fs::remove_dir_all(&dir);
    }
}

//! inotify wake-ups for the file tailers.
//!
//! One inotify instance per process (the default limit is 128 instances per
//! user, and a glob source alone may follow 1024 files), read by one thread
//! that wakes the subscribed tailers through [`Notify`]: it works with any
//! tokio runtime, and a wake-up arriving while the tailer is busy is kept
//! until it waits again. Tailers only use the events as a hint to look at
//! their file now; they still poll slowly, so a missed event (inotify
//! unavailable, out of watches, a network filesystem) only adds latency.

use std::collections::HashMap;
use std::ffi::{CString, OsStr, OsString};
use std::os::unix::ffi::OsStrExt;
use std::os::unix::io::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, OnceLock};

use tokio::sync::Notify;
use tracing::{debug, warn};

/// Changes to entries of a watched directory (filtered by name).
const DIR_MASK: u32 = libc::IN_CREATE
    | libc::IN_MOVED_TO
    | libc::IN_MOVED_FROM
    | libc::IN_DELETE
    | libc::IN_MODIFY
    | libc::IN_ATTRIB;
/// Changes to a watched file (by inode, whatever its name is now).
const FILE_MASK: u32 =
    libc::IN_MODIFY | libc::IN_ATTRIB | libc::IN_MOVE_SELF | libc::IN_DELETE_SELF;

struct Sub {
    id: u64,
    /// Directory watches: only events for this entry name.
    name: Option<OsString>,
    notify: Arc<Notify>,
}

pub struct Hub {
    fd: OwnedFd,
    subs: Mutex<HashMap<i32, Vec<Sub>>>,
    next_id: AtomicU64,
}

/// Removes its subscription when dropped (and the kernel watch with the
/// last one).
pub struct Watch {
    hub: &'static Hub,
    wd: i32,
    id: u64,
}

impl Drop for Watch {
    fn drop(&mut self) {
        let mut subs = self.hub.lock();
        if let Some(list) = subs.get_mut(&self.wd) {
            list.retain(|s| s.id != self.id);
            if list.is_empty() {
                subs.remove(&self.wd);
                // SAFETY: plain syscall on our own descriptor
                unsafe { libc::inotify_rm_watch(self.hub.fd.as_raw_fd(), self.wd) };
            }
        }
    }
}

impl Hub {
    /// The process-wide hub; `None` if inotify is not available (logged
    /// once; tailers then only poll).
    pub fn global() -> Option<&'static Hub> {
        static HUB: OnceLock<Option<&'static Hub>> = OnceLock::new();
        *HUB.get_or_init(|| match Hub::start() {
            Ok(h) => Some(h),
            Err(e) => {
                warn!(error = %e, "inotify not available, file sources poll only");
                None
            }
        })
    }

    fn start() -> std::io::Result<&'static Hub> {
        // SAFETY: plain syscall; the result is checked
        let fd = unsafe { libc::inotify_init1(libc::IN_CLOEXEC) };
        if fd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let hub: &'static Hub = Box::leak(Box::new(Hub {
            // SAFETY: a fresh descriptor we own
            fd: unsafe { OwnedFd::from_raw_fd(fd) },
            subs: Mutex::new(HashMap::new()),
            next_id: AtomicU64::new(1),
        }));
        std::thread::Builder::new()
            .name("df2b-inotify".into())
            .spawn(move || hub.read_loop())?;
        Ok(hub)
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<i32, Vec<Sub>>> {
        self.subs.lock().unwrap_or_else(|e| e.into_inner())
    }

    /// Wakes `notify` on changes to the entry `name` in directory `dir`.
    pub fn watch_entry(
        &'static self,
        dir: &Path,
        name: &OsStr,
        notify: &Arc<Notify>,
    ) -> std::io::Result<Watch> {
        self.add(dir, DIR_MASK, Some(name.to_owned()), notify)
    }

    /// Wakes `notify` on changes to the open file `fd` (also after it was
    /// renamed or deleted).
    pub fn watch_fd(&'static self, fd: RawFd, notify: &Arc<Notify>) -> std::io::Result<Watch> {
        // the link resolves to exactly the open inode, not to whatever is
        // at its path by now
        self.add(
            Path::new(&format!("/proc/self/fd/{fd}")),
            FILE_MASK,
            None,
            notify,
        )
    }

    fn add(
        &'static self,
        path: &Path,
        mask: u32,
        name: Option<OsString>,
        notify: &Arc<Notify>,
    ) -> std::io::Result<Watch> {
        let c = CString::new(path.as_os_str().as_bytes())
            .map_err(|_| std::io::Error::from(std::io::ErrorKind::InvalidInput))?;
        // under the lock: no concurrent rm_watch of the same wd
        let mut subs = self.lock();
        // SAFETY: valid C string, our descriptor; the result is checked
        let wd = unsafe { libc::inotify_add_watch(self.fd.as_raw_fd(), c.as_ptr(), mask) };
        if wd < 0 {
            return Err(std::io::Error::last_os_error());
        }
        let id = self.next_id.fetch_add(1, Ordering::Relaxed);
        subs.entry(wd).or_default().push(Sub {
            id,
            name,
            notify: notify.clone(),
        });
        Ok(Watch { hub: self, wd, id })
    }

    fn read_loop(&self) {
        let mut buf = vec![0u8; 64 * 1024];
        loop {
            // SAFETY: reads into our buffer of the given length
            let n = unsafe { libc::read(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len()) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                warn!(error = %e, "reading inotify events failed, file sources poll only");
                return;
            }
            self.dispatch(&buf[..n as usize]);
        }
    }

    fn dispatch(&self, mut events: &[u8]) {
        const HEADER: usize = std::mem::size_of::<libc::inotify_event>();
        let subs = self.lock();
        while events.len() >= HEADER {
            // SAFETY: the kernel writes whole events; read unaligned
            let ev: libc::inotify_event =
                unsafe { std::ptr::read_unaligned(events.as_ptr().cast()) };
            let end = (HEADER + ev.len as usize).min(events.len());
            let raw = &events[HEADER..end];
            let name = &raw[..raw.iter().position(|&b| b == 0).unwrap_or(raw.len())];
            events = &events[end..];
            if ev.mask & libc::IN_Q_OVERFLOW != 0 {
                debug!("inotify queue overflow, waking all file sources");
                subs.values().flatten().for_each(|s| s.notify.notify_one());
                continue;
            }
            let Some(list) = subs.get(&ev.wd) else {
                continue;
            };
            for s in list {
                if s.name.as_ref().map_or(true, |want| want.as_bytes() == name) {
                    s.notify.notify_one();
                }
            }
        }
        // a watch the kernel dropped (IN_IGNORED: directory or file
        // deleted) keeps its entry until its `Watch` is dropped; tailers
        // add new watches when they open the next file
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;
    use std::time::Duration;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!("df2b-watch-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    async fn woken(n: &Notify) -> bool {
        tokio::time::timeout(Duration::from_secs(2), n.notified())
            .await
            .is_ok()
    }

    #[tokio::test]
    async fn entry_and_fd_watches() {
        let hub = Hub::global().expect("inotify");
        let dir = tmp("basic");
        let path = dir.join("app.log");
        let n = Arc::new(Notify::new());
        let _w = hub.watch_entry(&dir, OsStr::new("app.log"), &n).unwrap();
        // another file in the directory: no wake-up
        std::fs::write(dir.join("other.log"), "x\n").unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), n.notified())
                .await
                .is_err()
        );
        std::fs::write(&path, "a\n").unwrap();
        assert!(woken(&n).await, "created");

        // the open file, renamed away: writes to it still wake
        let f = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        let m = Arc::new(Notify::new());
        let w = hub.watch_fd(f.as_raw_fd(), &m).unwrap();
        std::fs::rename(&path, dir.join("app.log.1")).unwrap();
        assert!(woken(&m).await, "moved");
        (&f).write_all(b"b\n").unwrap();
        assert!(woken(&m).await, "written after rotation");
        drop(w);
        (&f).write_all(b"c\n").unwrap();
        assert!(
            tokio::time::timeout(Duration::from_millis(200), m.notified())
                .await
                .is_err(),
            "no wake-ups after the watch is dropped"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

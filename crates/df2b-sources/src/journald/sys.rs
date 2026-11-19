//! Minimal safe wrapper around libsystemd's `sd-journal` API.
//!
//! libsystemd is loaded at runtime (`dlopen("libsystemd.so.0")`), so building
//! needs no systemd headers and the same binary runs on hosts without systemd;
//! there, opening a journal fails with a clear error.
//!
//! An `sd_journal` handle is not thread-safe and must be used on the thread
//! that opened it. [`Journal`] holds a raw pointer and is therefore `!Send`.

use std::ffi::{c_char, c_int, c_void, CStr, CString};
use std::io;
use std::os::unix::ffi::OsStrExt;
use std::path::Path;
use std::sync::OnceLock;
use std::time::Duration;

#[repr(C)]
pub struct SdJournal {
    _private: [u8; 0],
}

type JFn = unsafe extern "C" fn(*mut SdJournal) -> c_int;

struct Api {
    open: unsafe extern "C" fn(*mut *mut SdJournal, c_int) -> c_int,
    open_directory: unsafe extern "C" fn(*mut *mut SdJournal, *const c_char, c_int) -> c_int,
    close: unsafe extern "C" fn(*mut SdJournal),
    add_match: unsafe extern "C" fn(*mut SdJournal, *const c_void, usize) -> c_int,
    add_disjunction: JFn,
    seek_head: JFn,
    seek_tail: JFn,
    seek_realtime_usec: unsafe extern "C" fn(*mut SdJournal, u64) -> c_int,
    seek_cursor: unsafe extern "C" fn(*mut SdJournal, *const c_char) -> c_int,
    test_cursor: unsafe extern "C" fn(*mut SdJournal, *const c_char) -> c_int,
    next: JFn,
    previous: JFn,
    get_data: unsafe extern "C" fn(
        *mut SdJournal,
        *const c_char,
        *mut *const c_void,
        *mut usize,
    ) -> c_int,
    get_realtime_usec: unsafe extern "C" fn(*mut SdJournal, *mut u64) -> c_int,
    get_cursor: unsafe extern "C" fn(*mut SdJournal, *mut *mut c_char) -> c_int,
    set_data_threshold: unsafe extern "C" fn(*mut SdJournal, usize) -> c_int,
    wait: unsafe extern "C" fn(*mut SdJournal, u64) -> c_int,
    // Keeps the function pointers above valid; never unloaded.
    _lib: libloading::Library,
}

extern "C" {
    fn free(ptr: *mut c_void);
}

const SD_JOURNAL_LOCAL_ONLY: c_int = 1 << 0;
const SD_JOURNAL_SYSTEM: c_int = 1 << 2;
const ENOENT: c_int = 2;

impl Api {
    unsafe fn load() -> Result<Self, String> {
        let lib = libloading::Library::new("libsystemd.so.0")
            .map_err(|e| format!("cannot load libsystemd.so.0: {e}"))?;
        macro_rules! sym {
            ($name:literal) => {
                *lib.get(concat!($name, "\0").as_bytes())
                    .map_err(|e| format!("libsystemd lacks {}: {e}", $name))?
            };
        }
        Ok(Self {
            open: sym!("sd_journal_open"),
            open_directory: sym!("sd_journal_open_directory"),
            close: sym!("sd_journal_close"),
            add_match: sym!("sd_journal_add_match"),
            add_disjunction: sym!("sd_journal_add_disjunction"),
            seek_head: sym!("sd_journal_seek_head"),
            seek_tail: sym!("sd_journal_seek_tail"),
            seek_realtime_usec: sym!("sd_journal_seek_realtime_usec"),
            seek_cursor: sym!("sd_journal_seek_cursor"),
            test_cursor: sym!("sd_journal_test_cursor"),
            next: sym!("sd_journal_next"),
            previous: sym!("sd_journal_previous"),
            get_data: sym!("sd_journal_get_data"),
            get_realtime_usec: sym!("sd_journal_get_realtime_usec"),
            get_cursor: sym!("sd_journal_get_cursor"),
            set_data_threshold: sym!("sd_journal_set_data_threshold"),
            wait: sym!("sd_journal_wait"),
            _lib: lib,
        })
    }
}

fn api() -> io::Result<&'static Api> {
    static API: OnceLock<Result<Api, String>> = OnceLock::new();
    API.get_or_init(|| unsafe { Api::load() })
        .as_ref()
        .map_err(|e| io::Error::new(io::ErrorKind::NotFound, e.clone()))
}

/// True if libsystemd could be loaded.
pub fn available() -> bool {
    api().is_ok()
}

fn check(r: c_int) -> io::Result<c_int> {
    if r < 0 {
        Err(io::Error::from_raw_os_error(-r))
    } else {
        Ok(r)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Wakeup {
    /// Timeout, nothing changed.
    Nop,
    /// New entries were appended.
    Append,
    /// Journal files were added or removed (rotation, vacuum).
    Invalidate,
}

pub struct Journal {
    api: &'static Api,
    j: *mut SdJournal,
}

impl Journal {
    /// The local system journal (what `journalctl` shows without `--user`).
    pub fn open_system() -> io::Result<Self> {
        let api = api()?;
        let mut j = std::ptr::null_mut();
        check(unsafe { (api.open)(&mut j, SD_JOURNAL_LOCAL_ONLY | SD_JOURNAL_SYSTEM) })?;
        Ok(Self { api, j })
    }

    /// All journal files in `dir` (e.g. a container's or a copied journal).
    pub fn open_directory(dir: &Path) -> io::Result<Self> {
        let api = api()?;
        let path = CString::new(dir.as_os_str().as_bytes())
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in path"))?;
        let mut j = std::ptr::null_mut();
        check(unsafe { (api.open_directory)(&mut j, path.as_ptr(), 0) })?;
        Ok(Self { api, j })
    }

    /// Adds a `FIELD=value` match. Matches on the same field are ORed,
    /// different fields are ANDed.
    pub fn add_match(&mut self, m: &str) -> io::Result<()> {
        check(unsafe { (self.api.add_match)(self.j, m.as_ptr().cast(), m.len()) }).map(drop)
    }

    /// Starts a new group of matches, ORed with the previous group.
    pub fn add_disjunction(&mut self) -> io::Result<()> {
        check(unsafe { (self.api.add_disjunction)(self.j) }).map(drop)
    }

    pub fn seek_head(&mut self) -> io::Result<()> {
        check(unsafe { (self.api.seek_head)(self.j) }).map(drop)
    }

    pub fn seek_tail(&mut self) -> io::Result<()> {
        check(unsafe { (self.api.seek_tail)(self.j) }).map(drop)
    }

    pub fn seek_realtime_usec(&mut self, usec: u64) -> io::Result<()> {
        check(unsafe { (self.api.seek_realtime_usec)(self.j, usec) }).map(drop)
    }

    pub fn seek_cursor(&mut self, cursor: &str) -> io::Result<()> {
        let c = CString::new(cursor)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in cursor"))?;
        check(unsafe { (self.api.seek_cursor)(self.j, c.as_ptr()) }).map(drop)
    }

    /// True if the current entry has this cursor.
    pub fn test_cursor(&mut self, cursor: &str) -> io::Result<bool> {
        let c = CString::new(cursor)
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "NUL in cursor"))?;
        check(unsafe { (self.api.test_cursor)(self.j, c.as_ptr()) }).map(|r| r > 0)
    }

    /// Advances to the next entry; false at the end of the journal.
    pub fn next_entry(&mut self) -> io::Result<bool> {
        check(unsafe { (self.api.next)(self.j) }).map(|r| r > 0)
    }

    pub fn previous_entry(&mut self) -> io::Result<bool> {
        check(unsafe { (self.api.previous)(self.j) }).map(|r| r > 0)
    }

    /// Raw `FIELD=value` bytes of a field of the current entry, or `None` if
    /// the entry has no such field. Valid until the journal is moved.
    pub fn data(&mut self, field: &CStr) -> io::Result<Option<&[u8]>> {
        let mut ptr: *const c_void = std::ptr::null();
        let mut len = 0usize;
        let r = unsafe { (self.api.get_data)(self.j, field.as_ptr(), &mut ptr, &mut len) };
        if r == -ENOENT {
            return Ok(None);
        }
        check(r)?;
        Ok(Some(unsafe {
            std::slice::from_raw_parts(ptr.cast::<u8>(), len)
        }))
    }

    pub fn realtime_usec(&mut self) -> io::Result<u64> {
        let mut usec = 0u64;
        check(unsafe { (self.api.get_realtime_usec)(self.j, &mut usec) })?;
        Ok(usec)
    }

    /// Cursor of the current entry (allocates; call once per batch, not per entry).
    pub fn cursor(&mut self) -> io::Result<String> {
        let mut ptr: *mut c_char = std::ptr::null_mut();
        check(unsafe { (self.api.get_cursor)(self.j, &mut ptr) })?;
        let s = unsafe { CStr::from_ptr(ptr) }
            .to_string_lossy()
            .into_owned();
        unsafe { free(ptr.cast()) };
        Ok(s)
    }

    /// Limits how much of a field is returned (and decompressed).
    pub fn set_data_threshold(&mut self, bytes: usize) -> io::Result<()> {
        check(unsafe { (self.api.set_data_threshold)(self.j, bytes) }).map(drop)
    }

    /// Blocks until the journal changes or `timeout` passes.
    pub fn wait(&mut self, timeout: Duration) -> io::Result<Wakeup> {
        let usec = u64::try_from(timeout.as_micros()).unwrap_or(u64::MAX);
        match check(unsafe { (self.api.wait)(self.j, usec) })? {
            0 => Ok(Wakeup::Nop),
            1 => Ok(Wakeup::Append),
            _ => Ok(Wakeup::Invalidate),
        }
    }
}

impl Drop for Journal {
    fn drop(&mut self) {
        unsafe { (self.api.close)(self.j) }
    }
}

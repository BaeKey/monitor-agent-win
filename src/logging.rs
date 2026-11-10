//! Bounded, best-effort logging. This module deliberately has no filesystem or
//! stderr fallback: privileged path/ACL operations belong to the secure-fs layer.
//!
//! By default the worker uses `crate::log_path()` and `crate::secure_fs` on Windows.
//! Optionally call `init` before the first `log_line` to inject protected storage.
//! The factory runs on the detached worker, never on the calling thread.
//! On non-Windows platforms the default sink is disabled (useful for core tests).
//! Callers must redact secrets *before* calling this API; escaping is not redaction.

use std::io;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::{self, SyncSender, TrySendError};
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

pub const MAX_LINE_BYTES: usize = 4096;
pub const QUEUE_CAPACITY: usize = 128;
pub const MAX_LINES_PER_SECOND: u64 = 64;
pub const MAX_FILE_BYTES: u64 = 1024 * 1024;
pub const BACKUP_COUNT: usize = 3;

/// Security boundary implemented by the installer/secure-fs integration.
/// Slot 0 is the active log; slots 1..=BACKUP_COUNT are newest to oldest backups.
///
/// Implementations MUST:
/// - use only a validated, service-specific protected directory; provision it
///   once in the factory, not on each append;
/// - reject reparse points/symlinks, unsafe owners/ACLs, and path substitution
///   for *every* operation, including backups, creation, removal and renaming;
/// - open/create files with the protected ACL already in effect (no exposure
///   window), and enforce exclusive writer ownership for this entire session;
/// - close/reopen active handles as needed for Windows rename semantics;
/// - treat absent files as success for remove/rename, but not other failures;
/// - append exactly the supplied bytes, or return an error (never silently
///   ignore partial writes). Do not independently emit diagnostics to stderr.
///
/// The core performs rotation, but cannot enforce these properties for a faulty
/// implementation. It never constructs a path or opens a file itself.
pub trait LogStorage: Send {
    fn len(&mut self, slot: usize) -> io::Result<Option<u64>>;
    fn remove_if_exists(&mut self, slot: usize) -> io::Result<()>;
    fn rename_if_exists(&mut self, from: usize, to: usize) -> io::Result<()>;
    fn append_all(&mut self, bytes: &[u8]) -> io::Result<()>;
}

type Factory = Box<dyn FnOnce() -> io::Result<Box<dyn LogStorage>> + Send>;
static CONFIG: OnceLock<Mutex<Option<Factory>>> = OnceLock::new();
static LOGGER: OnceLock<Option<SyncSender<String>>> = OnceLock::new();
static START: OnceLock<Instant> = OnceLock::new();
static RATE: AtomicU64 = AtomicU64::new(0);
static DROPPED: AtomicU64 = AtomicU64::new(0);
static TRUNCATED: AtomicU64 = AtomicU64::new(0);
static STORAGE_ERRORS: AtomicU64 = AtomicU64::new(0);

// The default binary uses the built-in secure-fs factory. Keep the explicit
// injection API available for embedders without requiring a main.rs call site.
#[allow(dead_code)] // Error type belongs to the optional init API below.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AlreadyInitialized;

/// Installs a protected-storage factory. No I/O or worker creation occurs here.
/// Fails if initialization or the first log call has already claimed CONFIG.
/// Deliberately accepts no raw PathBuf: callers cannot bypass protected opens.
/// Normal Windows use needs no init: the built-in adapter uses secure_fs directly.
#[allow(dead_code)] // Optional protected-storage injection; normal startup is lazy.
pub fn init<F>(factory: F) -> Result<(), AlreadyInitialized>
where
    F: FnOnce() -> io::Result<Box<dyn LogStorage>> + Send + 'static,
{
    CONFIG.set(Mutex::new(Some(Box::new(factory)))).map_err(|_| AlreadyInitialized)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Counters {
    pub dropped: u64,
    pub truncated: u64,
    /// Factory/open/rotation/append failures. A failure disables the sink for
    /// the lifetime of this process, rather than repeatedly hammering the disk.
    pub storage_errors: u64,
}

pub fn counters() -> Counters {
    Counters {
        dropped: DROPPED.load(Ordering::Relaxed),
        truncated: TRUNCATED.load(Ordering::Relaxed),
        storage_errors: STORAGE_ERRORS.load(Ordering::Relaxed),
    }
}

fn increment(counter: &AtomicU64) {
    let _ = counter.try_update(Ordering::Relaxed, Ordering::Relaxed, |n| Some(n.saturating_add(1)));
}

/// Fixed one-second windows; at most 64 admitted records per window (up to 128
/// across a window boundary). Bounded CAS retries also bound caller contention.
fn admit(rate: &AtomicU64, seconds: u64) -> bool {
    // 32-bit second counter wraps only after ~136 years of process uptime.
    let window = (seconds & u64::from(u32::MAX)) << 32;
    let mut old = rate.load(Ordering::Relaxed);
    for _ in 0..16 {
        // A caller preempted at a window boundary must not reset a newer
        // window and admit another burst using its stale timestamp.
        if old & 0xffff_ffff_0000_0000 > window {
            return false;
        }
        let count = if old & 0xffff_ffff_0000_0000 == window { old & u64::from(u32::MAX) } else { 0 };
        if count >= MAX_LINES_PER_SECOND {
            return false;
        }
        match rate.compare_exchange_weak(old, window | (count + 1), Ordering::Relaxed, Ordering::Relaxed) {
            Ok(_) => return true,
            Err(current) => old = current,
        }
    }
    false
}

/// Sanitizes at most MAX_LINE_BYTES of output, never copies the entire input.
/// All Unicode control characters (including newline, CR, NUL, ESC and C1) are
/// escaped. Bidi formatting controls and Unicode line separators are escaped too.
fn sanitize(line: &str) -> (String, bool) {
    const MARKER: &str = " [truncated]";
    let budget = MAX_LINE_BYTES - MARKER.len() - 1;
    let mut out = String::with_capacity(MAX_LINE_BYTES);
    let mut truncated = false;
    for ch in line.chars() {
        let escape = ch.is_control()
            || matches!(ch, '\u{061c}' | '\u{200e}' | '\u{200f}' | '\u{2028}'..='\u{202e}' | '\u{2066}'..='\u{2069}');
        let mut buf = [0_u8; 4];
        if escape {
            // char::escape_default is bounded to ten ASCII bytes.
            let mut escaped = [0_u8; 10];
            let mut n = 0;
            for c in ch.escape_default() {
                escaped[n] = c as u8;
                n += 1;
            }
            if out.len() + n > budget {
                truncated = true;
                break;
            }
            // All bytes produced by escape_default are ASCII.
            for &byte in &escaped[..n] {
                out.push(char::from(byte));
            }
        } else {
            let text = ch.encode_utf8(&mut buf);
            if out.len() + text.len() > budget {
                truncated = true;
                break;
            }
            out.push_str(text);
        }
    }
    if truncated {
        out.push_str(MARKER);
    }
    out.push('\n');
    (out, truncated)
}

/// Best effort: bounded formatting, rate limiting and try_send only. No file,
/// stderr, sleep, waiting for queue capacity, or caller-side storage callbacks.
/// The first call lazily initializes OnceLocks and spawns one detached worker;
/// this one-time OS operation is not a hard real-time/nonblocking guarantee.
/// Thread creation failure silently disables logging, without panic/retry.
/// Pass an already-redacted &str; an upstream `format!` is outside this bound.
pub fn log_line(line: &str) {
    let start = START.get_or_init(Instant::now);
    let sender = LOGGER.get_or_init(|| {
        CONFIG.get_or_init(|| Mutex::new(default_factory()));
        let (tx, rx) = mpsc::sync_channel(QUEUE_CAPACITY);
        match std::thread::Builder::new()
            .name("monitor-log".into())
            .stack_size(256 * 1024)
            .spawn(move || worker(rx))
        {
            Ok(handle) => {
                drop(handle); // detach; service shutdown must not wait for I/O
                Some(tx)
            }
            Err(_) => None,
        }
    });
    if !admit(&RATE, start.elapsed().as_secs()) {
        increment(&DROPPED);
        return;
    }
    let Some(sender) = sender else {
        increment(&DROPPED);
        return;
    };
    let (message, truncated) = sanitize(line);
    if truncated {
        increment(&TRUNCATED);
    }
    match sender.try_send(message) {
        Ok(()) => {}
        Err(TrySendError::Full(_) | TrySendError::Disconnected(_)) => increment(&DROPPED),
    }
}

fn default_factory() -> Option<Factory> {
    #[cfg(windows)]
    {
        Some(Box::new(|| Ok(Box::new(ProtectedFiles::open(crate::log_path())?) as Box<dyn LogStorage>)))
    }
    #[cfg(not(windows))]
    {
        None
    }
}

/// All ordinary path operations below occur under a live DirectoryGuard, in a
/// directory writable only by SYSTEM/Administrators. Those principals are trusted;
/// check_destination alone is NOT safe in a directory writable by an attacker.
#[cfg(windows)]
struct ProtectedFiles {
    paths: [std::path::PathBuf; BACKUP_COUNT + 1],
    active: Option<std::fs::File>,
    _writer_lock: std::fs::File,
    _directory: crate::secure_fs::DirectoryGuard,
}

#[cfg(windows)]
impl ProtectedFiles {
    fn open(path: std::path::PathBuf) -> io::Result<Self> {
        let parent =
            path.parent().ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "missing log parent"))?;
        let directory = crate::secure_fs::ensure_private_dir(parent).map_err(io::Error::other)?;
        let paths = std::array::from_fn(|slot| {
            let mut name = path.as_os_str().to_os_string();
            if slot != 0 {
                name.push(format!(".{slot}"));
            }
            std::path::PathBuf::from(name)
        });
        let mut lock_name = path.as_os_str().to_os_string();
        lock_name.push(".writer.lock");
        // open_log denies write/delete sharing. Keep this zero-byte handle for
        // the entire session, including periods when rotation closes active.
        let writer_lock =
            crate::secure_fs::open_log(std::path::Path::new(&lock_name)).map_err(io::Error::other)?;
        Ok(Self { paths, active: None, _writer_lock: writer_lock, _directory: directory })
    }

    fn checked_path(&self, slot: usize) -> io::Result<&std::path::Path> {
        let path = self
            .paths
            .get(slot)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "invalid log slot"))?;
        crate::secure_fs::check_destination(path).map_err(io::Error::other)?;
        Ok(path)
    }
}

#[cfg(windows)]
impl LogStorage for ProtectedFiles {
    fn len(&mut self, slot: usize) -> io::Result<Option<u64>> {
        let path = self.checked_path(slot)?;
        match std::fs::symlink_metadata(path) {
            Ok(metadata) => {
                // The secure-fs check above rejects hardlinks/reparse points;
                // protect existing backups too, not only the current file.
                crate::secure_fs::harden(path).map_err(io::Error::other)?;
                Ok(Some(metadata.len()))
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }

    fn remove_if_exists(&mut self, slot: usize) -> io::Result<()> {
        if slot == 0 {
            self.active.take();
        }
        let path = self.checked_path(slot)?;
        match std::fs::remove_file(path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn rename_if_exists(&mut self, from: usize, to: usize) -> io::Result<()> {
        if from == 0 || to == 0 {
            self.active.take();
        }
        let source = self.checked_path(from)?;
        let target = self.checked_path(to)?;
        // No replace: a destination unexpectedly appearing is a fail-closed
        // error. On Windows std::fs::rename refuses an existing destination.
        match std::fs::rename(source, target) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(error) => Err(error),
        }
    }

    fn append_all(&mut self, bytes: &[u8]) -> io::Result<()> {
        use std::io::Write;
        if self.active.is_none() {
            self.active = Some(crate::secure_fs::open_log(&self.paths[0]).map_err(io::Error::other)?);
        }
        match self.active.as_mut() {
            Some(file) => file.write_all(bytes),
            None => Err(io::Error::other("protected log unavailable")),
        }
    }
}

struct Rotating {
    storage: Box<dyn LogStorage>,
    active_len: u64,
    limit: u64,
}

impl Rotating {
    fn new(mut storage: Box<dyn LogStorage>, limit: u64) -> io::Result<Self> {
        // Normalize old oversized logs before accepting any record. Only the
        // four designated slots are touched, never a directory scan.
        for slot in 0..=BACKUP_COUNT {
            if storage.len(slot)?.is_some_and(|size| size > limit) {
                storage.remove_if_exists(slot)?;
            }
        }
        let active_len = storage.len(0)?.unwrap_or(0);
        Ok(Self { storage, active_len, limit })
    }

    fn write(&mut self, bytes: &[u8]) -> io::Result<()> {
        let size = bytes.len() as u64;
        if size > self.limit {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "log record exceeds file limit"));
        }
        if size > self.limit - self.active_len {
            self.storage.remove_if_exists(BACKUP_COUNT)?;
            for from in (0..BACKUP_COUNT).rev() {
                self.storage.rename_if_exists(from, from + 1)?;
            }
            self.active_len = 0;
        }
        self.storage.append_all(bytes)?;
        self.active_len += size;
        Ok(())
    }
}

fn write_record(sink: &mut Option<Rotating>, bytes: &[u8]) {
    if let Some(writer) = sink {
        if writer.write(bytes).is_ok() {
            return;
        }
        increment(&STORAGE_ERRORS);
        // Fail closed after partial writes/rotation errors; do not write using
        // stale lengths or attempt an insecure fallback.
        *sink = None;
    }
    increment(&DROPPED);
}

fn worker(rx: mpsc::Receiver<String>) {
    // This is the only acquisition of this mutex; no log caller locks it.
    let factory = CONFIG.get().and_then(|config| config.lock().ok()?.take());
    let mut sink = factory.and_then(|factory| {
        match factory().and_then(|storage| Rotating::new(storage, MAX_FILE_BYTES)) {
            Ok(writer) => Some(writer),
            Err(_) => {
                increment(&STORAGE_ERRORS);
                None
            }
        }
    });
    let mut reported = Counters { dropped: 0, truncated: 0, storage_errors: 0 };
    let mut last_report = Instant::now();
    loop {
        match rx.recv_timeout(Duration::from_secs(1)) {
            Ok(message) => write_record(&mut sink, message.as_bytes()),
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => break,
        }
        if last_report.elapsed() >= Duration::from_secs(1) {
            last_report = Instant::now();
            let current = counters();
            if current != reported && sink.is_some() {
                // Only bounded integers are formatted, once per second maximum.
                let summary = format!(
                    "[logger] totals: dropped {}, truncated {}, storage_errors {}\n",
                    current.dropped, current.truncated, current.storage_errors
                );
                write_record(&mut sink, summary.as_bytes());
                reported = current;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use std::sync::Arc;

    #[derive(Default)]
    struct Memory {
        slots: BTreeMap<usize, Vec<u8>>,
        fail_append: bool,
        fail_rename: bool,
        appends: usize,
    }

    struct Fake(Arc<Mutex<Memory>>);

    impl LogStorage for Fake {
        fn len(&mut self, slot: usize) -> io::Result<Option<u64>> {
            Ok(self.0.lock().unwrap().slots.get(&slot).map(|b| b.len() as u64))
        }
        fn remove_if_exists(&mut self, slot: usize) -> io::Result<()> {
            self.0.lock().unwrap().slots.remove(&slot);
            Ok(())
        }
        fn rename_if_exists(&mut self, from: usize, to: usize) -> io::Result<()> {
            let mut m = self.0.lock().unwrap();
            if m.fail_rename {
                return Err(io::Error::other("injected rename failure"));
            }
            if let Some(bytes) = m.slots.remove(&from) {
                assert!(!m.slots.contains_key(&to));
                m.slots.insert(to, bytes);
            }
            Ok(())
        }
        fn append_all(&mut self, bytes: &[u8]) -> io::Result<()> {
            let mut m = self.0.lock().unwrap();
            m.appends += 1;
            if m.fail_append {
                return Err(io::Error::other("injected append failure"));
            }
            m.slots.entry(0).or_default().extend_from_slice(bytes);
            Ok(())
        }
    }

    fn memory_writer(limit: u64) -> (Rotating, Arc<Mutex<Memory>>) {
        let memory = Arc::new(Mutex::new(Memory::default()));
        let writer = Rotating::new(Box::new(Fake(memory.clone())), limit).unwrap();
        (writer, memory)
    }

    #[test]
    fn escapes_injection_and_unicode_controls() {
        let (out, truncated) = sanitize("a\r\nb\t\0\u{1b}\u{85}\u{202e}\u{2028}");
        assert!(!truncated);
        assert_eq!(out, "a\\r\\nb\\t\\u{0}\\u{1b}\\u{85}\\u{202e}\\u{2028}\n");
        assert_eq!(out.chars().filter(|c| c.is_control()).collect::<String>(), "\n");
    }

    #[test]
    fn bounded_utf8_and_huge_input() {
        for input in ["x".repeat(1_000_000), "🦀".repeat(4096), "\u{202e}".repeat(4096)] {
            let (out, truncated) = sanitize(&input);
            assert!(truncated);
            assert!(out.len() <= MAX_LINE_BYTES);
            assert!(out.ends_with(" [truncated]\n"));
        }
        assert_eq!(sanitize("").0, "\n");
    }

    #[test]
    fn fixed_window_rate_is_bounded_and_resets() {
        let rate = AtomicU64::new(0);
        for _ in 0..MAX_LINES_PER_SECOND {
            assert!(admit(&rate, 0));
        }
        assert!(!admit(&rate, 0));
        assert!(admit(&rate, 1));
    }

    #[test]
    fn stale_caller_cannot_reset_newer_rate_window() {
        let rate = AtomicU64::new(0);
        assert!(admit(&rate, 2));
        assert!(!admit(&rate, 1));
        for _ in 1..MAX_LINES_PER_SECOND {
            assert!(admit(&rate, 2));
        }
        assert!(!admit(&rate, 2));
    }

    #[test]
    fn concurrent_rate_limit_is_shared() {
        let rate = Arc::new(AtomicU64::new(0));
        let mut threads = Vec::new();
        for _ in 0..8 {
            let rate = rate.clone();
            threads.push(std::thread::spawn(move || (0..100).filter(|_| admit(&rate, 10)).count()));
        }
        let count: usize = threads.into_iter().map(|t| t.join().unwrap()).sum();
        assert!(count <= MAX_LINES_PER_SECOND as usize);
    }

    #[test]
    fn queue_full_does_not_wait_for_receiver() {
        let (tx, _rx) = mpsc::sync_channel(QUEUE_CAPACITY);
        for _ in 0..QUEUE_CAPACITY {
            tx.try_send(sanitize("record").0).unwrap();
        }
        assert!(matches!(tx.try_send(String::new()), Err(TrySendError::Full(_))));
    }

    #[test]
    fn exact_limit_and_rotation_keep_only_three_backups() {
        let (mut writer, memory) = memory_writer(16);
        writer.write(b"12345678").unwrap();
        writer.write(b"abcdefgh").unwrap();
        assert_eq!(memory.lock().unwrap().slots.len(), 1);
        for n in 0..100_u8 {
            writer.write(&[n; 16]).unwrap();
            let m = memory.lock().unwrap();
            assert!(m.slots.len() <= 4);
            assert!(m.slots.values().all(|b| b.len() <= 16));
            assert!(m.slots.values().map(Vec::len).sum::<usize>() <= 64);
        }
        let m = memory.lock().unwrap();
        for slot in 0..=3 {
            assert_eq!(m.slots[&slot], vec![99 - slot as u8; 16]);
        }
    }

    #[test]
    fn sparse_backups_rotate_without_overwrite() {
        let (mut writer, memory) = memory_writer(4);
        memory.lock().unwrap().slots.insert(2, b"old".to_vec());
        writer.write(b"full").unwrap();
        writer.write(b"new").unwrap();
        let m = memory.lock().unwrap();
        assert_eq!(m.slots[&0], b"new");
        assert_eq!(m.slots[&1], b"full");
        assert!(!m.slots.contains_key(&2));
        assert_eq!(m.slots[&3], b"old");
    }

    #[test]
    fn oversized_existing_files_removed_before_first_append() {
        let memory = Arc::new(Mutex::new(Memory::default()));
        for slot in 0..=3 {
            memory.lock().unwrap().slots.insert(slot, vec![0; 17]);
        }
        let mut writer = Rotating::new(Box::new(Fake(memory.clone())), 16).unwrap();
        assert!(memory.lock().unwrap().slots.is_empty());
        writer.write(b"ok\n").unwrap();
        assert_eq!(memory.lock().unwrap().slots[&0], b"ok\n");
    }

    #[test]
    fn oversized_record_rejected_without_writing() {
        let (mut writer, memory) = memory_writer(16);
        assert!(writer.write(&[0; 17]).is_err());
        assert_eq!(memory.lock().unwrap().appends, 0);
    }

    #[test]
    fn append_failure_disables_sink_without_retry() {
        let (writer, memory) = memory_writer(16);
        memory.lock().unwrap().fail_append = true;
        let mut sink = Some(writer);
        write_record(&mut sink, b"test");
        assert!(sink.is_none());
        write_record(&mut sink, b"test");
        assert_eq!(memory.lock().unwrap().appends, 1);
    }

    #[test]
    fn rename_failure_disables_sink_without_append() {
        let (mut writer, memory) = memory_writer(16);
        writer.write(&[0; 16]).unwrap();
        memory.lock().unwrap().fail_rename = true;
        let mut sink = Some(writer);
        write_record(&mut sink, b"next");
        assert!(sink.is_none());
        assert_eq!(memory.lock().unwrap().appends, 1);
    }
}

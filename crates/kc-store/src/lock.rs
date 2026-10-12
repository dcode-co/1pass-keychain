//! Cross-process locking with advisory file locks (fd-lock).
//!
//! - `<config_dir>/kc.lock` protects `index.json` (several namespaces can share one).
//! - A user-wide `dev.1pass.kc.lock` protects the keychain itself, also between processes
//!   that use different config directories or environments (say one with `KC_CONFIG_DIR` or
//!   `HOME` set differently). Its place therefore depends on nothing but the OS user:
//!   `/tmp/dev.1pass.kc-<uid>/` on Unix (created with mode 0700; kc refuses to run if it
//!   exists but isn't a private directory of the user), and `%LOCALAPPDATA%\dev.1pass.kc\`
//!   (found through the Known Folder API) on Windows. Lock files are touched on every use so
//!   that `/tmp` cleaners leave them alone.
//!
//! Mutations hold both locks exclusively across the keychain write and the index update. Reads
//! that combine several keychain entries hold them shared, so they never see a half-finished
//! write. Waiting is bounded ([`StoreError::Busy`]).
//!
//! A keychain call that timed out may still be running on its worker thread, and the keychain
//! service may still carry it out. Releasing the locks then would let another process
//! interleave with it, so when a mutation ends with such a call outstanding, exclusive locks
//! are kept by a background thread until the call has returned.
//!
//! The OS drops the locks when a process exits, killed or not, possibly with a change still on
//! its way to the keychain service. So every mutation first writes an `in-doubt` marker next
//! to the user-wide lock and removes it only once all its calls have come back; while it waits
//! on the keychain, the marker's time is refreshed every second. A process that gets the locks
//! and finds a marker knows its owner stopped mid-change, and refuses to change the keychain
//! ([`StoreError::Unavailable`]) until [`IN_DOUBT_GRACE`] has passed since the owner's last
//! sign of life, giving the service time to carry out or drop that change.

use std::fs::{File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};
use std::thread;
use std::time::{Duration, Instant};

use crate::error::{Result, StoreError};

const CONFIG_LOCK: &str = "kc.lock";
const USER_LOCK: &str = "dev.1pass.kc.lock";
const IN_DOUBT: &str = "in-doubt";
const POLL: Duration = Duration::from_millis(20);

/// How long other processes stay away from the keychain after a kc process stopped in the
/// middle of a change.
pub(crate) const IN_DOUBT_GRACE: Duration = Duration::from_secs(30);

/// How often a waiting mutation refreshes its marker.
pub(crate) const HEARTBEAT: Duration = Duration::from_secs(1);

thread_local! {
    /// The marker of the mutation running on this thread, refreshed by [`heartbeat`]. A
    /// mutation makes all its keychain calls from its own thread.
    static ACTIVE_MARKER: std::cell::RefCell<Option<PathBuf>> = const { std::cell::RefCell::new(None) };
}

/// Refreshes the marker of the mutation running on this thread, if any: the process is alive
/// and waiting on the keychain.
pub(crate) fn heartbeat() {
    ACTIVE_MARKER.with(|active| {
        if let Some(marker) = active.borrow().as_ref() {
            touch(marker);
        }
    });
}

fn touch(marker: &Path) {
    let _ = OpenOptions::new()
        .write(true)
        .open(marker)
        .and_then(|file| file.set_modified(std::time::SystemTime::now()));
}

fn set_active_marker(marker: Option<PathBuf>) {
    ACTIVE_MARKER.with(|active| *active.borrow_mut() = marker);
}

/// A locked file. Closing it (dropping this) releases the lock.
type Held = fd_lock::RwLock<File>;

pub(crate) struct Locks {
    /// Taken in this order: the user-wide lock first, then the config-directory lock.
    files: Vec<PathBuf>,
    /// The `in-doubt` marker, next to the user-wide lock.
    in_doubt: PathBuf,
}

impl Locks {
    /// The locks for a store whose config directory (already created) is `config_dir`.
    pub(crate) fn new(config_dir: &Path) -> Result<Self> {
        let dir = user_lock_dir()?;
        Ok(Locks {
            files: vec![dir.join(USER_LOCK), config_dir.join(CONFIG_LOCK)],
            in_doubt: dir.join(IN_DOUBT),
        })
    }

    /// Locks that live entirely in `config_dir`, for stores on the in-memory test backend: they
    /// must not touch the real user-wide lock.
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn local(config_dir: &Path) -> Self {
        Locks {
            files: vec![config_dir.join(USER_LOCK), config_dir.join(CONFIG_LOCK)],
            in_doubt: config_dir.join(IN_DOUBT),
        }
    }

    #[cfg(test)]
    pub(crate) fn with_files(files: Vec<PathBuf>) -> Self {
        let in_doubt = files[0].with_file_name(IN_DOUBT);
        Locks { files, in_doubt }
    }

    /// Runs `f` holding every lock exclusively.
    pub(crate) fn exclusive<R>(&self, wait: Duration, f: impl FnOnce() -> Result<R>) -> Result<R> {
        let start = Instant::now();
        let held = loop {
            let held = self.acquire(true, wait.saturating_sub(start.elapsed()))?;
            match in_doubt_age(&self.in_doubt) {
                Some(age) if age < IN_DOUBT_GRACE => {
                    drop(held);
                    if start.elapsed() >= wait {
                        return Err(StoreError::Unavailable {
                            reason: format!(
                                "a kc process stopped in the middle of changing the keychain {}s \
                                 ago, and the keychain may still carry that change out",
                                age.as_secs()
                            ),
                            hint: format!(
                                "Try again in {}s. If the keychain service is stuck, restart it",
                                (IN_DOUBT_GRACE - age).as_secs().max(1)
                            ),
                        });
                    }
                    thread::sleep(POLL * 5);
                }
                Some(_) => {
                    let _ = std::fs::remove_file(&self.in_doubt);
                    break held;
                }
                None => break held,
            }
        };
        // Armed before the first keychain change, cleared once every call has come back.
        std::fs::write(&self.in_doubt, std::process::id().to_string())
            .map_err(|err| StoreError::io(&self.in_doubt, err))?;
        set_active_marker(Some(self.in_doubt.clone()));
        let given_up_before = crate::backend::calls_given_up_while_running();
        let result = f();
        set_active_marker(None);
        // A change whose outcome is unknown may still land: keep the marker. That is the case
        // when a running keychain call was given up on, or a change wasn't confirmed.
        let doubt = crate::backend::calls_given_up_while_running() != given_up_before
            || matches!(&result, Err(err) if err.leaves_doubt());
        release_when_keychain_idle(held, &self.in_doubt, doubt);
        result
    }

    /// Runs `f` holding every lock shared.
    pub(crate) fn shared<R>(&self, wait: Duration, f: impl FnOnce() -> Result<R>) -> Result<R> {
        let held = self.acquire(false, wait)?;
        let result = f();
        drop(held);
        result
    }

    fn acquire(&self, exclusive: bool, wait: Duration) -> Result<Vec<Held>> {
        let start = Instant::now();
        let mut held = Vec::with_capacity(self.files.len());
        for path in &self.files {
            // On failure the locks already taken are dropped, i.e. released.
            held.push(lock_one(path, exclusive, start, wait)?);
        }
        Ok(held)
    }
}

/// Opens and locks one file. The guard is forgotten so the lock can outlive this stack frame;
/// the lock goes when the file is closed.
fn lock_one(path: &Path, exclusive: bool, start: Instant, wait: Duration) -> Result<Held> {
    let mut lock = fd_lock::RwLock::new(open(path)?);
    loop {
        let attempt = if exclusive {
            lock.try_write().map(std::mem::forget)
        } else {
            lock.try_read().map(std::mem::forget)
        };
        match attempt {
            Ok(()) => return Ok(lock),
            Err(err) if is_contended(&err) => {}
            Err(err) => return Err(StoreError::io(path, err)),
        }
        let waited = start.elapsed();
        if waited >= wait {
            return Err(StoreError::Busy {
                path: path.to_path_buf(),
                waited,
            });
        }
        thread::sleep(POLL);
    }
}

/// Clears the marker and releases `held` now, or once every keychain call of this process
/// that timed out has actually returned. Until then the marker keeps being refreshed: should
/// this process exit first, other processes wait for the keychain to settle.
///
/// With `doubt` (the mutation ended in an unknown outcome) the marker stays, freshly
/// timestamped, so other processes keep away for the grace period.
fn release_when_keychain_idle(held: Vec<Held>, in_doubt: &Path, doubt: bool) {
    let settle = move |marker: &Path| {
        if doubt {
            touch(marker);
        } else {
            let _ = std::fs::remove_file(marker);
        }
    };
    if crate::backend::no_abandoned_calls() {
        settle(in_doubt);
        return;
    }
    let marker = in_doubt.to_path_buf();
    let keep = move || {
        loop {
            touch(&marker);
            if crate::backend::wait_for_abandoned_calls_for(HEARTBEAT) {
                break;
            }
        }
        settle(&marker);
        drop(held);
    };
    let keeper = std::sync::Arc::new(std::sync::Mutex::new(Some(keep)));
    let in_thread = std::sync::Arc::clone(&keeper);
    let spawned = thread::Builder::new()
        .name("kc-lock-keeper".into())
        .spawn(move || {
            if let Some(keep) = in_thread.lock().ok().and_then(|mut keep| keep.take()) {
                keep();
            }
        });
    if spawned.is_err() {
        // No thread to wait in: wait here rather than release the locks early.
        if let Some(keep) = keeper.lock().ok().and_then(|mut keep| keep.take()) {
            keep();
        }
    }
}

/// How old the `in-doubt` marker is, if there is one.
fn in_doubt_age(marker: &Path) -> Option<Duration> {
    let modified = std::fs::metadata(marker).ok()?.modified().ok()?;
    // A marker from the future (clock change) counts as fresh.
    Some(modified.elapsed().unwrap_or(Duration::ZERO))
}

fn open(path: &Path) -> Result<File> {
    let mut options = OpenOptions::new();
    options.read(true).write(true).create(true).truncate(false);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let file = options
        .open(path)
        .map_err(|err| StoreError::io(path, err))?;
    // Fresh times keep periodic /tmp cleaners from deleting a lock file that is in use.
    let now = std::time::SystemTime::now();
    let _ = file.set_times(
        std::fs::FileTimes::new()
            .set_accessed(now)
            .set_modified(now),
    );
    Ok(file)
}

fn is_contended(err: &io::Error) -> bool {
    matches!(
        err.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::Interrupted
    )
}

/// `KC_LOCK_DIR`, in debug builds only: tests use it to stay away from the real lock.
fn lock_dir_override() -> Result<Option<PathBuf>> {
    if !cfg!(debug_assertions) {
        return Ok(None);
    }
    let Some(dir) = std::env::var_os(crate::config::ENV_LOCK_DIR).filter(|v| !v.is_empty()) else {
        return Ok(None);
    };
    let dir = PathBuf::from(dir);
    std::fs::create_dir_all(&dir).map_err(|err| StoreError::io(&dir, err))?;
    Ok(Some(dir))
}

/// The directory of the user-wide lock: derived from the OS user (effective uid) only.
#[cfg(unix)]
fn user_lock_dir() -> Result<PathBuf> {
    use std::os::unix::fs::DirBuilderExt;
    if let Some(dir) = lock_dir_override()? {
        return Ok(dir);
    }
    let uid = rustix::process::geteuid().as_raw();
    let dir = PathBuf::from(format!("/tmp/dev.1pass.kc-{uid}"));
    match std::fs::DirBuilder::new().mode(0o700).create(&dir) {
        Ok(()) => {}
        Err(err) if err.kind() == io::ErrorKind::AlreadyExists => {}
        Err(err) => return Err(StoreError::io(&dir, err)),
    }
    // Not following symlinks: the directory itself must be ours and closed to others.
    let meta = std::fs::symlink_metadata(&dir).map_err(|err| StoreError::io(&dir, err))?;
    if !is_private_dir(&meta, uid) {
        return Err(StoreError::Unavailable {
            reason: format!(
                "{} is not a private directory of this user, so kc can't lock safely",
                dir.display()
            ),
            hint: "Remove it (it must be a directory owned by you with mode 0700) and run kc again"
                .into(),
        });
    }
    Ok(dir)
}

#[cfg(unix)]
fn is_private_dir(meta: &std::fs::Metadata, uid: u32) -> bool {
    use std::os::unix::fs::MetadataExt;
    meta.is_dir() && meta.uid() == uid && meta.mode() & 0o077 == 0
}

/// The directory of the user-wide lock: `%LOCALAPPDATA%\dev.1pass.kc`, through the Known
/// Folder API rather than the environment.
#[cfg(windows)]
fn user_lock_dir() -> Result<PathBuf> {
    if let Some(dir) = lock_dir_override()? {
        return Ok(dir);
    }
    let base = directories::BaseDirs::new().ok_or_else(|| StoreError::Unavailable {
        reason: "the local application data folder can't be determined".into(),
        hint: "kc needs it to coordinate kc processes".into(),
    })?;
    let dir = base.data_local_dir().join("dev.1pass.kc");
    std::fs::create_dir_all(&dir).map_err(|err| StoreError::io(&dir, err))?;
    Ok(dir)
}

#[cfg(not(any(unix, windows)))]
fn user_lock_dir() -> Result<PathBuf> {
    Err(StoreError::Unavailable {
        reason: "kc can't place its lock file on this platform".into(),
        hint: String::new(),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn locks_in(dir: &Path) -> Locks {
        Locks::with_files(vec![dir.join("user.lock"), dir.join("kc.lock")])
    }

    #[test]
    fn exclusive_sections_never_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let inside = Arc::new(AtomicUsize::new(0));
        let path = dir.path().to_path_buf();
        let threads: Vec<_> = (0..8)
            .map(|_| {
                let inside = Arc::clone(&inside);
                let path = path.clone();
                thread::spawn(move || {
                    for _ in 0..20 {
                        // Fresh Locks per call: new file descriptions, like separate processes.
                        locks_in(&path)
                            .exclusive(Duration::from_secs(30), || {
                                assert_eq!(inside.fetch_add(1, Ordering::SeqCst), 0);
                                thread::sleep(Duration::from_micros(200));
                                inside.fetch_sub(1, Ordering::SeqCst);
                                Ok(())
                            })
                            .unwrap();
                    }
                })
            })
            .collect();
        for t in threads {
            t.join().unwrap();
        }
    }

    #[test]
    fn waiting_is_bounded_and_locks_are_released() {
        let dir = tempfile::tempdir().unwrap();
        let holder = locks_in(dir.path());
        let contender = locks_in(dir.path());
        holder
            .exclusive(Duration::from_secs(5), || {
                let start = Instant::now();
                let err = contender
                    .shared(Duration::from_millis(100), || Ok(()))
                    .unwrap_err();
                assert!(matches!(err, StoreError::Busy { .. }), "{err}");
                assert!(start.elapsed() < Duration::from_secs(5));
                Ok(())
            })
            .unwrap();
        // Released afterwards (possibly by the keeper, if another test's keychain call is
        // running in this process right now).
        contender
            .shared(Duration::from_secs(10), || Ok(()))
            .unwrap();
    }

    #[test]
    fn exclusive_locks_outlive_a_timed_out_keychain_call() {
        let _serial = crate::backend::TIMING_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let holder = locks_in(dir.path());
        let contender = locks_in(dir.path());
        holder
            .exclusive(Duration::from_secs(5), || {
                // A keychain call that times out but keeps running for a while.
                let err = crate::backend::bounded(Duration::from_millis(20), "test", "", || {
                    thread::sleep(Duration::from_millis(600));
                    Ok(())
                })
                .unwrap_err();
                assert!(matches!(err, StoreError::Timeout { .. }), "{err}");
                Ok(())
            })
            .unwrap();
        // The call is still running, so another kc process must stay locked out...
        let err = contender
            .shared(Duration::from_millis(100), || Ok(()))
            .unwrap_err();
        assert!(matches!(err, StoreError::Busy { .. }), "{err}");
        // ...until it has returned.
        contender
            .shared(Duration::from_secs(10), || Ok(()))
            .unwrap();
    }

    #[test]
    fn an_in_doubt_marker_blocks_changes_until_it_expires() {
        // Abandoned calls are tracked process-wide; keep other timing tests out.
        let _serial = crate::backend::TIMING_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::backend::wait_for_abandoned_calls();
        let dir = tempfile::tempdir().unwrap();
        let locks = locks_in(dir.path());
        let marker = dir.path().join(IN_DOUBT);
        std::fs::write(&marker, b"").unwrap();
        let err = locks
            .exclusive(Duration::from_millis(200), || Ok(()))
            .unwrap_err();
        assert!(matches!(err, StoreError::Unavailable { .. }), "{err}");
        assert_eq!(err.exit_code(), 4);
        // Reads aren't held up.
        locks.shared(Duration::from_secs(5), || Ok(())).unwrap();

        let old = std::time::SystemTime::now() - IN_DOUBT_GRACE - Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_modified(old)
            .unwrap();
        locks.exclusive(Duration::from_secs(5), || Ok(())).unwrap();
        assert!(!marker.exists());
    }

    #[test]
    fn a_timed_out_change_keeps_the_locks_and_then_the_marker() {
        let _serial = crate::backend::TIMING_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let dir = tempfile::tempdir().unwrap();
        let locks = locks_in(dir.path());
        let marker = dir.path().join(IN_DOUBT);
        let err = locks
            .exclusive(Duration::from_secs(5), || {
                crate::backend::bounded(Duration::from_millis(20), "test", "", || {
                    thread::sleep(Duration::from_millis(300));
                    Ok(())
                })
            })
            .unwrap_err();
        assert!(matches!(err, StoreError::Timeout { .. }), "{err}");
        assert!(marker.exists());
        // Once the call is back the locks are free, but its outcome is unknown, so changes
        // stay blocked for the grace period...
        crate::backend::wait_for_abandoned_calls();
        thread::sleep(Duration::from_millis(100));
        let err = locks
            .exclusive(Duration::from_millis(300), || Ok(()))
            .unwrap_err();
        assert!(matches!(err, StoreError::Unavailable { .. }), "{err}");
        // ...and allowed again after it.
        let old = std::time::SystemTime::now() - IN_DOUBT_GRACE - Duration::from_secs(1);
        std::fs::File::options()
            .write(true)
            .open(&marker)
            .unwrap()
            .set_modified(old)
            .unwrap();
        locks.exclusive(Duration::from_secs(5), || Ok(())).unwrap();
        assert!(!marker.exists());
    }

    #[test]
    fn a_change_arms_its_marker_until_it_is_done() {
        let _serial = crate::backend::TIMING_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::backend::wait_for_abandoned_calls();
        let dir = tempfile::tempdir().unwrap();
        let locks = locks_in(dir.path());
        let marker = dir.path().join(IN_DOUBT);
        locks
            .exclusive(Duration::from_secs(5), || {
                // Should the process die here, the next one would wait.
                assert!(marker.exists());
                let old = std::time::SystemTime::now() - Duration::from_secs(60);
                std::fs::File::options()
                    .write(true)
                    .open(&marker)
                    .unwrap()
                    .set_modified(old)
                    .unwrap();
                // Waiting on the keychain refreshes it.
                heartbeat();
                assert!(in_doubt_age(&marker).unwrap() < Duration::from_secs(5));
                Ok(())
            })
            .unwrap();
        assert!(!marker.exists());
    }

    #[test]
    fn an_unknown_outcome_keeps_the_marker() {
        let _serial = crate::backend::TIMING_TESTS
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        crate::backend::wait_for_abandoned_calls();
        let dir = tempfile::tempdir().unwrap();
        let locks = locks_in(dir.path());
        let marker = dir.path().join(IN_DOUBT);
        // An ordinary failure (say the keyring is locked) clears it...
        let err = locks
            .exclusive(Duration::from_secs(5), || -> Result<()> {
                Err(StoreError::Locked {
                    what: "test".into(),
                    hint: String::new(),
                })
            })
            .unwrap_err();
        assert!(matches!(err, StoreError::Locked { .. }));
        assert!(!marker.exists());
        // ...one that leaves a change in doubt doesn't.
        let err = locks
            .exclusive(Duration::from_secs(5), || -> Result<()> {
                Err(StoreError::OutcomeUnknown {
                    op: "write",
                    detail: "test".into(),
                    hint: String::new(),
                })
            })
            .unwrap_err();
        assert_eq!(err.exit_code(), 4);
        assert!(marker.exists());
        assert!(
            locks
                .exclusive(Duration::from_millis(100), || Ok(()))
                .is_err()
        );
    }

    #[test]
    fn shared_sections_overlap() {
        let dir = tempfile::tempdir().unwrap();
        let a = locks_in(dir.path());
        let b = locks_in(dir.path());
        a.shared(Duration::from_secs(5), || {
            b.shared(Duration::from_millis(500), || Ok(()))
        })
        .unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn the_user_lock_needs_a_private_directory() {
        use std::os::unix::fs::{MetadataExt, PermissionsExt};
        let dir = tempfile::tempdir().unwrap();
        let uid = std::fs::metadata(dir.path()).unwrap().uid();
        let check = |mode| {
            std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(mode)).unwrap();
            is_private_dir(&std::fs::symlink_metadata(dir.path()).unwrap(), uid)
        };
        assert!(check(0o700));
        assert!(!check(0o750));
        assert!(!check(0o777));
        std::fs::set_permissions(dir.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!is_private_dir(
            &std::fs::symlink_metadata(dir.path()).unwrap(),
            uid + 1
        ));
    }

    #[cfg(unix)]
    #[test]
    fn the_user_lock_lives_in_a_fixed_per_user_directory() {
        let config = tempfile::tempdir().unwrap();
        let uid = rustix::process::geteuid().as_raw();
        let locks = Locks::new(config.path()).unwrap();
        assert_eq!(
            locks.files[0],
            PathBuf::from(format!("/tmp/dev.1pass.kc-{uid}/{USER_LOCK}"))
        );
        assert_eq!(locks.files[1], config.path().join(CONFIG_LOCK));
        locks.exclusive(Duration::from_secs(10), || Ok(())).unwrap();
    }
}

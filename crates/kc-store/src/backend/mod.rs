//! The keychain backend seam: the real OS keychain or, in tests, the in-memory backend from
//! [`crate::testing`].
//!
//! - macOS, Windows: [`keyring::KeyringBackend`] (keyring-core plus the platform store crate).
//! - Linux, BSD: [`secret_service::SecretServiceBackend`] (prompt-free Secret Service client).
//! - anything else: [`connect`] fails with [`StoreError::Unavailable`]; there is no fallback.

use std::sync::mpsc::{self, RecvTimeoutError};
use std::sync::{Arc, Condvar, Mutex, PoisonError};
use std::thread;
use std::time::Duration;

use zeroize::Zeroizing;

use crate::config::StoreConfig;
use crate::error::{Result, StoreError};

#[cfg(any(test, target_os = "macos", target_os = "windows"))]
pub(crate) mod keyring;
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
pub(crate) mod secret_service;

/// Raw access to one namespace of a keychain. Accounts and blobs are opaque here; the
/// layout and format live in [`crate::name`] and [`crate::encoding`].
pub(crate) trait Backend: Send + Sync {
    /// Human-readable description, for `kc doctor`-style output.
    fn describe(&self) -> String;
    /// Reads one entry. `Ok(None)` if it doesn't exist.
    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>>;
    /// Creates or overwrites one entry.
    fn set(&self, account: &str, blob: &[u8]) -> Result<()>;
    /// Deletes one entry. `Ok(false)` if it didn't exist.
    fn delete(&self, account: &str) -> Result<bool>;
    /// Whether an entry exists, without reading its secret where the platform allows.
    fn exists(&self, account: &str) -> Result<bool>;
    /// Every account in the namespace. Fails rather than return an incomplete list (garbage
    /// collection relies on it). Used only by `reindex` and `verify`.
    ///
    /// On the Secret Service the account of each item is recovered from the stored blob
    /// (`GetSecret`, a method call), never from `org.freedesktop.DBus.Properties`: reading a
    /// property of a client that has disconnected crashes gnome-keyring. So this reads every
    /// secret in the namespace; `list`, `delete` and `purge` avoid it for that reason.
    fn accounts(&self) -> Result<Vec<String>>;
    /// Deletes every entry in the namespace and returns how many. For `purge`: it needs no
    /// account names, so on the Secret Service it reads no secrets (search by path, delete).
    fn purge(&self) -> Result<usize>;
    /// Reads an entry that some other program wrote (`kc adopt`).
    fn read_foreign(&self, service: &str, account: Option<&str>) -> Result<ForeignItem>;
    /// Whether creating an entry can be cut off half-way, leaving it empty (the Secret Service
    /// creates items empty and fills them in a second call). `reindex` then checks every
    /// current value, not only those with chunks or a previous value.
    fn may_leave_empty_entries(&self) -> bool {
        false
    }
}

/// A secret read from outside the kc namespace.
pub(crate) struct ForeignItem {
    /// The account (user name) of the entry, if the platform has one.
    pub account: Option<String>,
    pub value: Zeroizing<Vec<u8>>,
}

/// Opens the platform keychain for `cfg.namespace`.
#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) fn connect(cfg: &StoreConfig) -> Result<Arc<dyn Backend>> {
    Ok(Arc::new(keyring::KeyringBackend::connect(cfg)?))
}

/// Opens the platform keychain for `cfg.namespace`.
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
pub(crate) fn connect(cfg: &StoreConfig) -> Result<Arc<dyn Backend>> {
    Ok(Arc::new(secret_service::SecretServiceBackend::connect(
        cfg,
    )?))
}

/// No supported keychain on this platform. Fail loudly, never fall back to a mock.
#[cfg(not(any(
    target_os = "macos",
    target_os = "windows",
    all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    )
)))]
pub(crate) fn connect(_cfg: &StoreConfig) -> Result<Arc<dyn Backend>> {
    Err(StoreError::Unavailable {
        reason: "kc supports the OS keychains of macOS, Windows, Linux and the BSDs only".into(),
        hint: String::new(),
    })
}

pub(crate) fn not_found(service: &str, account: Option<&str>) -> StoreError {
    match account {
        Some(account) => StoreError::NotFound(format!(
            "no keychain entry with service {service:?} and account {account:?}"
        )),
        None => StoreError::NotFound(format!("no keychain entry with service {service:?}")),
    }
}

/// Serialises every OS keychain call in this process. Windows Credential Manager does not
/// order concurrent operations on one credential reliably, and macOS's "disable user
/// interaction" switch is process-wide, so one call at a time is the safe rule everywhere.
static KEYCHAIN_CALLS: Mutex<()> = Mutex::new(());

/// Tests that start slow keychain workers take this, so they don't hold up each other's
/// timing-sensitive calls on [`KEYCHAIN_CALLS`].
#[cfg(test)]
pub(crate) static TIMING_TESTS: Mutex<()> = Mutex::new(());

thread_local! {
    /// How many calls this thread gave up on while they were already running. A call given up
    /// on while still waiting for its turn never reaches the keychain and isn't counted.
    static GIVEN_UP_RUNNING: std::cell::Cell<u64> = const { std::cell::Cell::new(0) };
}

/// See [`GIVEN_UP_RUNNING`]. A mutation (which makes all its calls from its own thread)
/// compares this before and after: if it grew, a keychain call may still be carried out after
/// the mutation reported its error.
pub(crate) fn calls_given_up_while_running() -> u64 {
    GIVEN_UP_RUNNING.with(std::cell::Cell::get)
}

/// How many calls timed out but haven't finished yet (running, or still waiting for their
/// turn so they can be skipped).
static ABANDONED: Mutex<usize> = Mutex::new(0);
static ABANDONED_SETTLED: Condvar = Condvar::new();

/// Whether every call that timed out in this process has finished.
pub(crate) fn no_abandoned_calls() -> bool {
    *ABANDONED.lock().unwrap_or_else(PoisonError::into_inner) == 0
}

/// Blocks until every call that timed out in this process has finished.
#[cfg(test)]
pub(crate) fn wait_for_abandoned_calls() {
    let mut count = ABANDONED.lock().unwrap_or_else(PoisonError::into_inner);
    while *count > 0 {
        count = ABANDONED_SETTLED
            .wait(count)
            .unwrap_or_else(PoisonError::into_inner);
    }
}

/// Waits up to `limit` for every call that timed out to finish. True if none is left.
pub(crate) fn wait_for_abandoned_calls_for(limit: Duration) -> bool {
    let count = ABANDONED.lock().unwrap_or_else(PoisonError::into_inner);
    let (count, _) = ABANDONED_SETTLED
        .wait_timeout_while(count, limit, |count| *count > 0)
        .unwrap_or_else(PoisonError::into_inner);
    *count == 0
}

fn settle_abandoned_call() {
    let mut count = ABANDONED.lock().unwrap_or_else(PoisonError::into_inner);
    *count = count.saturating_sub(1);
    ABANDONED_SETTLED.notify_all();
}

/// Blocks until every call that timed out in this process has actually finished, refreshing the
/// in-doubt heartbeat between checks (see [`crate::lock`]). A backend runs this after a timeout so
/// the process can't exit, and close its connection to the keychain service, with a request still
/// in flight (which crashes gnome-keyring; see [`secret_service`]).
#[cfg(all(
    unix,
    not(any(target_os = "macos", target_os = "ios", target_os = "android"))
))]
pub(crate) fn drain_abandoned_calls() {
    drain_abandoned_calls_with(crate::lock::HEARTBEAT);
}

/// [`drain_abandoned_calls`] with an explicit poll interval, so tests can drive it quickly.
#[cfg(any(
    test,
    all(
        unix,
        not(any(target_os = "macos", target_os = "ios", target_os = "android"))
    )
))]
fn drain_abandoned_calls_with(interval: Duration) {
    while !wait_for_abandoned_calls_for(interval) {
        crate::lock::heartbeat();
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CallState {
    Waiting,
    Running,
    Done,
    Abandoned,
}

/// Marks a call done when the worker finishes, also by panicking, and settles it if the caller
/// had given up on it by then.
struct Settle(Arc<Mutex<CallState>>);

impl Drop for Settle {
    fn drop(&mut self) {
        let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
        let abandoned = *state == CallState::Abandoned;
        *state = CallState::Done;
        drop(state);
        if abandoned {
            settle_abandoned_call();
        }
    }
}

/// Runs `f` on a worker thread and gives up after `timeout`.
///
/// A keychain call that hangs (an unanswered prompt, a wedged D-Bus service) turns into
/// [`StoreError::Timeout`] instead of blocking the caller forever. A call still waiting for its
/// turn when the caller gives up never starts. A call already running is left to finish on
/// its own and counted until it does; [`crate::lock`] keeps the cross-process locks held
/// meanwhile (see [`no_abandoned_calls`]), so another kc process can't interleave with it.
/// Whatever the worker eventually produces is dropped, and zeroized, on the worker thread.
pub(crate) fn bounded<T, F>(timeout: Duration, op: &'static str, hint: &str, f: F) -> Result<T>
where
    T: Send + 'static,
    F: FnOnce() -> Result<T> + Send + 'static,
{
    let state = Arc::new(Mutex::new(CallState::Waiting));
    let worker_state = Arc::clone(&state);
    let (tx, rx) = mpsc::sync_channel(1);
    thread::Builder::new()
        .name(format!("kc-keychain-{op}"))
        .spawn(move || {
            let _one_at_a_time = KEYCHAIN_CALLS
                .lock()
                .unwrap_or_else(PoisonError::into_inner);
            {
                let mut state = worker_state.lock().unwrap_or_else(PoisonError::into_inner);
                if *state == CallState::Abandoned {
                    // The caller gave up while this call waited: don't start it.
                    *state = CallState::Done;
                    drop(state);
                    settle_abandoned_call();
                    return;
                }
                *state = CallState::Running;
            }
            let settle = Settle(worker_state);
            let result = f();
            let abandoned =
                *settle.0.lock().unwrap_or_else(PoisonError::into_inner) == CallState::Abandoned;
            if !abandoned {
                let _ = tx.send(result);
            }
            drop(settle);
        })
        .map_err(|err| StoreError::Backend {
            op,
            detail: format!("cannot start a keychain worker thread: {err}"),
        })?;
    // While waiting, keep telling other processes that this one is alive (see crate::lock).
    crate::lock::heartbeat();
    let deadline = std::time::Instant::now() + timeout;
    let outcome = loop {
        let left = deadline.saturating_duration_since(std::time::Instant::now());
        match rx.recv_timeout(left.min(crate::lock::HEARTBEAT)) {
            Err(RecvTimeoutError::Timeout) if !left.is_zero() => crate::lock::heartbeat(),
            other => break other,
        }
    };
    match outcome {
        Ok(result) => result,
        Err(RecvTimeoutError::Timeout) => {
            let mut call = state.lock().unwrap_or_else(PoisonError::into_inner);
            if *call == CallState::Done {
                // It finished right at the deadline.
                drop(call);
                return rx.recv().unwrap_or_else(|_| {
                    Err(StoreError::Backend {
                        op,
                        detail: "the keychain worker thread panicked".into(),
                    })
                });
            }
            if *call == CallState::Running {
                GIVEN_UP_RUNNING.with(|count| count.set(count.get() + 1));
            }
            *call = CallState::Abandoned;
            *ABANDONED.lock().unwrap_or_else(PoisonError::into_inner) += 1;
            Err(StoreError::Timeout {
                op,
                timeout,
                hint: hint.to_owned(),
            })
        }
        Err(RecvTimeoutError::Disconnected) => Err(StoreError::Backend {
            op,
            detail: "the keychain worker thread panicked".into(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
    use std::time::Instant;

    // These tests share the process-wide KEYCHAIN_CALLS with each other, so each one keeps
    // its workers short.

    #[test]
    fn bounded_returns_the_result() {
        let value = bounded(Duration::from_secs(5), "test", "", || Ok(41 + 1)).unwrap();
        assert_eq!(value, 42);
        let err = bounded::<(), _>(Duration::from_secs(5), "test", "", || {
            Err(StoreError::NotFound("nope".into()))
        })
        .unwrap_err();
        assert!(matches!(err, StoreError::NotFound(_)));
    }

    #[test]
    fn bounded_times_out_and_queued_calls_never_start() {
        let _serial = TIMING_TESTS.lock().unwrap_or_else(PoisonError::into_inner);
        let started = Arc::new(AtomicUsize::new(0));
        let start = Instant::now();
        let slow = Arc::clone(&started);
        let err = bounded(Duration::from_millis(50), "test", "a hint", move || {
            slow.fetch_add(1, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(400));
            Ok(())
        })
        .unwrap_err();
        assert!(start.elapsed() < Duration::from_millis(350));
        match err {
            StoreError::Timeout { op, hint, .. } => {
                assert_eq!(op, "test");
                assert_eq!(hint, "a hint");
            }
            other => panic!("unexpected {other}"),
        }
        assert!(!no_abandoned_calls());
        // Make sure the slow call is running (it may have waited for a quick call of another
        // test first).
        let deadline = Instant::now() + Duration::from_secs(5);
        while started.load(Ordering::SeqCst) == 0 && Instant::now() < deadline {
            thread::sleep(Duration::from_millis(5));
        }
        assert_eq!(started.load(Ordering::SeqCst), 1);
        // The slow call still holds the keychain; this one queues, times out, and must not
        // run once the slow call is done.
        let queued = Arc::clone(&started);
        let err = bounded(Duration::from_millis(20), "test", "", move || {
            queued.fetch_add(1, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, StoreError::Timeout { .. }));
        wait_for_abandoned_calls();
        assert_eq!(started.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn a_timed_out_call_that_panics_is_still_settled() {
        let _serial = TIMING_TESTS.lock().unwrap_or_else(PoisonError::into_inner);
        let err = bounded::<(), _>(Duration::from_millis(20), "test", "", || {
            thread::sleep(Duration::from_millis(100));
            panic!("boom")
        })
        .unwrap_err();
        assert!(matches!(err, StoreError::Timeout { .. }));
        wait_for_abandoned_calls();
    }

    #[test]
    fn bounded_reports_a_panicking_worker() {
        let err =
            bounded::<(), _>(Duration::from_secs(5), "test", "", || panic!("boom")).unwrap_err();
        assert!(matches!(err, StoreError::Backend { .. }), "{err}");
    }

    // The drain the Secret Service backend runs after a timeout ([`drain_abandoned_calls`]) must
    // block until the abandoned call has actually come back, so the process can't exit with a
    // request still in flight. This exercises that production helper (not a copy) and checks it
    // keeps looping past expired poll intervals: a single bounded wait would return early.
    //
    // The worker blocks on a release channel, so the call stays demonstrably outstanding until the
    // test releases it; the 200 ms bounded timeout is a generous margin for the worker to have
    // started (it holds TIMING_TESTS, so no slow call competes for KEYCHAIN_CALLS). A pre-start
    // abandonment would fail the assertions below rather than pass by accident.
    #[test]
    fn draining_waits_until_an_abandoned_call_finishes() {
        let _serial = TIMING_TESTS.lock().unwrap_or_else(PoisonError::into_inner);
        let (release_tx, release_rx) = std::sync::mpsc::channel::<()>();
        let finished = Arc::new(AtomicBool::new(false));
        let worker = Arc::clone(&finished);
        let err = bounded(Duration::from_millis(200), "test", "", move || {
            // Stay outstanding until the test releases us, then record completion.
            release_rx.recv().ok();
            worker.store(true, Ordering::SeqCst);
            Ok(())
        })
        .unwrap_err();
        assert!(matches!(err, StoreError::Timeout { .. }));
        assert!(
            !no_abandoned_calls(),
            "the call should still be outstanding"
        );
        assert!(!finished.load(Ordering::SeqCst));

        // Run the production drain on another thread with a short poll interval while the worker is
        // still blocked. It must keep going past several expired intervals.
        let drained = Arc::new(AtomicBool::new(false));
        let drained_flag = Arc::clone(&drained);
        let drainer = thread::spawn(move || {
            drain_abandoned_calls_with(Duration::from_millis(10));
            drained_flag.store(true, Ordering::SeqCst);
        });
        thread::sleep(Duration::from_millis(60));
        assert!(
            !drained.load(Ordering::SeqCst),
            "the drain returned while the call was still outstanding"
        );
        assert!(!finished.load(Ordering::SeqCst));

        // Release the worker; now the drain must finish, and only after the call actually did.
        release_tx.send(()).unwrap();
        drainer.join().unwrap();
        assert!(drained.load(Ordering::SeqCst));
        assert!(no_abandoned_calls());
        assert!(
            finished.load(Ordering::SeqCst),
            "the drain returned before the abandoned call finished"
        );
    }
}

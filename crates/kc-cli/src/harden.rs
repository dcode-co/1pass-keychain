//! Process hardening for the `kc` binary (Linux).
//!
//! At startup [`harden_process`] makes the process non-dumpable and turns core dumps off,
//! so neither a crash nor another process of the same user (ptrace, `/proc/<pid>/mem`) can
//! copy secrets out of kc's memory. `kc exec` calls [`restore_core_limit`] right before it
//! replaces kc with the user's command, so that command keeps the core-dump limit it would
//! have had; `execve` resets the dumpable flag by itself.
//!
//! This is the only `unsafe` in kc-cli: libc calls that take integers or a pointer to a
//! `rlimit` we own, or take nothing at all, and that can't violate memory safety.
#![allow(unsafe_code)]

#[cfg(target_os = "linux")]
static ORIGINAL_CORE_LIMIT: std::sync::OnceLock<libc::rlimit> = std::sync::OnceLock::new();

/// No core dumps and no same-user ptrace for this process. Best effort: failures are
/// ignored, since they can only leave the defaults in place.
pub fn harden_process() {
    #[cfg(target_os = "linux")]
    {
        // SAFETY: PR_SET_DUMPABLE takes only integer arguments and reads no memory.
        unsafe {
            libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0);
        }
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: `limit` is a valid, writable `rlimit` that outlives the call.
        if unsafe { libc::getrlimit(libc::RLIMIT_CORE, &mut limit) } == 0 {
            let _ = ORIGINAL_CORE_LIMIT.set(limit);
            // Only the soft limit: the hard limit stays, so `restore_core_limit` can undo this.
            let off = libc::rlimit {
                rlim_cur: 0,
                rlim_max: limit.rlim_max,
            };
            // SAFETY: `off` is a valid `rlimit` that outlives the call.
            unsafe {
                libc::setrlimit(libc::RLIMIT_CORE, &off);
            }
        }
    }
}

/// The effective user id, to find the per-user lock directory without trusting the
/// environment.
#[cfg(all(unix, not(target_os = "macos")))]
pub(crate) fn effective_uid() -> u32 {
    // SAFETY: geteuid takes no arguments, touches no memory and can't fail.
    unsafe { libc::geteuid() }
}

/// Puts back the core-dump limit [`harden_process`] found, for a command kc is about to
/// `exec`.
pub fn restore_core_limit() {
    #[cfg(target_os = "linux")]
    if let Some(limit) = ORIGINAL_CORE_LIMIT.get() {
        // SAFETY: `limit` points at a valid `rlimit` in a static.
        unsafe {
            libc::setrlimit(libc::RLIMIT_CORE, limit);
        }
    }
}

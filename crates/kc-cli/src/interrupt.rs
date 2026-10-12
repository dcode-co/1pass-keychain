//! Ctrl-C.
//!
//! A keychain write that is cut off midway leaves kc-store's in-doubt marker behind, and
//! that marker holds off every change for 30 seconds. So the `kc` binary installs a handler
//! ([`install`]) that, on Ctrl-C, waits for the keychain call in flight (if any) to return
//! and then exits with 130. Every keychain call holds [`keychain_call`] while it runs.
//!
//! At a prompt the terminal is in raw mode and Ctrl-C arrives as a key, which the prompt
//! reports as a cancellation; the handler isn't involved.

use std::io::Write as _;
use std::sync::{PoisonError, RwLock, RwLockReadGuard};

use crate::error::EXIT_CANCELLED;

static KEYCHAIN_CALLS: RwLock<()> = RwLock::new(());

/// Installs the Ctrl-C handler. For the `kc` binary; failing to install it only means
/// Ctrl-C keeps its default behaviour.
pub fn install() {
    let _ = ctrlc::set_handler(|| {
        let _ = writeln!(std::io::stderr(), "\nkc: interrupted");
        // The write side waits for the keychain call in flight and keeps new ones out.
        let _quiet = KEYCHAIN_CALLS
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        std::process::exit(EXIT_CANCELLED);
    });
}

/// Held around each keychain call, so Ctrl-C lets it finish.
pub(crate) fn keychain_call() -> RwLockReadGuard<'static, ()> {
    KEYCHAIN_CALLS
        .read()
        .unwrap_or_else(PoisonError::into_inner)
}

//! # kc-store
//!
//! Secrets in the OS keychain for `kc` (1pass keychain), plus a small metadata index.
//!
//! ```no_run
//! use kc_store::{ItemKind, Origin, Store, StoreConfig};
//!
//! # fn main() -> kc_store::Result<()> {
//! let store = Store::open(StoreConfig::from_env()?.with_interactive(false))?;
//! store.set("openai-api-key", b"sk-...", ItemKind::Text, Origin::Local)?;
//! let value = store.get("openai-api-key")?.expect("just stored");
//! assert_eq!(value.as_bytes(), b"sk-...");
//! # Ok(())
//! # }
//! ```
//!
//! ## Where secrets live
//!
//! One explicitly chosen backend per OS, never the `keyring` v1 wrapper and never a mock (a
//! store that doesn't persist is refused):
//!
//! - **macOS**: keyring-core + `apple-native-keyring-store`, the login keychain (generic
//!   passwords). macOS ties access to the binary that created an item, so an unsigned or
//!   rebuilt `kc` triggers an "allow access" prompt the first time it touches an existing item.
//!   Release builds are code-signed with the Dcode Developer ID so "Always Allow" sticks across
//!   updates. Non-interactive stores turn prompts off per call and fail fast with
//!   [`StoreError::InteractionRequired`] instead.
//! - **Windows**: keyring-core + `windows-native-keyring-store`, Credential Manager generic
//!   credentials `<account>@<namespace>` (upper case escaped, since target names are
//!   case-insensitive), persistence Local. Credential blobs are limited to 2560 bytes, so large
//!   values are chunked.
//! - **Linux / BSD**: the Secret Service (gnome-keyring, KeePassXC) over D-Bus, through the
//!   `secret-service` client directly. The keyring store crates for the Secret Service unlock
//!   locked items by themselves (a password prompt) and can't be told not to, so kc uses only
//!   calls that cannot prompt: a locked keyring is [`StoreError::Locked`], a missing bus or
//!   service is [`StoreError::Unavailable`], each with remediation. If
//!   `DBUS_SESSION_BUS_ADDRESS` is unset, `$XDG_RUNTIME_DIR/bus` is used (in-process; the
//!   environment is not modified), which makes SSH sessions work.
//!
//! The keychain service is the namespace ([`DEFAULT_NAMESPACE`]); accounts are `item:<name>`,
//! `item:<name>#prev`, `item:<name>#<gen>.<i>`, `sys:<key>` and, only while a restore runs,
//! `item:<name>#swap` (see [`Store`] for the operations). Every stored blob starts with a
//! one-byte format tag; values whose tagged form exceeds [`StoreConfig::max_blob_len`] (2048
//! bytes by default) are written as chunks of a fresh generation followed by a manifest
//! `{gen, n, len, sha256}`, and the sha256 is verified before a value is returned. Writes and
//! restores are ordered so that an interruption at any point loses neither the old nor the new
//! value; leftovers are cleaned up by later writes, `delete` and [`Store::reindex`].
//!
//! ## Index and locking
//!
//! The keychain is the source of truth; [`Store::list`] uses its search. `index.json` in the
//! config directory only caches metadata the keychain can't hold (kind, origin, timestamps) and
//! is rebuilt by [`Store::reindex`]. It never contains secrets. Every mutation holds
//! `<config_dir>/kc.lock` plus a user-wide lock (`/tmp/dev.1pass.kc-<uid>/` on Unix,
//! `%LOCALAPPDATA%\dev.1pass.kc\` on Windows) across the keychain write and the index
//! update, and the index is written atomically (temp file, fsync, rename) after the keychain
//! write succeeded.
//!
//! ## Timeouts
//!
//! Every keychain call runs on a worker thread with a timeout: 5 s for non-interactive
//! callers, 60 s for interactive ones ([`StoreConfig::interactive`]). One call runs at a time
//! per process. A call that times out but keeps running holds the cross-process locks until it
//! returns, so no other kc process can interleave with it. Every mutation also arms an
//! `in-doubt` marker next to the user-wide lock (refreshed while it waits on the keychain) and
//! clears it once all its calls came back with a known outcome; a process that finds a marker
//! from a kc process that stopped mid-change, or whose change wasn't confirmed
//! ([`StoreError::OutcomeUnknown`]), stays away from changes for 30 s. One limit remains: a
//! change that a wedged keychain service carries out later than that can still override a later
//! change of the same item.
//!
//! ## Errors and exit codes
//!
//! [`StoreError::kind`] classifies errors for the CLI: not found → 3, keychain
//! unavailable/locked → 4, interaction required → 5, invalid input → 2, anything else → 1.
//!
//! ## Environment
//!
//! - `KC_CONFIG_DIR`: config directory (default: the platform config directory).
//! - `KC_NAMESPACE`: keychain namespace, honoured in debug builds only (tests).
//! - `KC_LOCK_DIR`: directory of the user-wide lock, honoured in debug builds only (tests).

#![forbid(unsafe_code)]

mod backend;
mod config;
mod encoding;
mod error;
mod index;
mod lock;
mod name;
mod secret;
mod store;

#[cfg(any(test, feature = "test-util"))]
pub mod testing;

pub use config::{
    DEFAULT_MAX_BLOB_LEN, DEFAULT_NAMESPACE, ENV_CONFIG_DIR, ENV_LOCK_DIR, ENV_NAMESPACE,
    INTERACTIVE_TIMEOUT, MIN_MAX_BLOB_LEN, NON_INTERACTIVE_TIMEOUT, StoreConfig,
    WINDOWS_MAX_BLOB_LEN, default_config_dir,
};
pub use encoding::MAX_VALUE_LEN;
pub use error::{ErrorKind, Result, StoreError};
pub use index::{ItemInfo, ItemKind, Origin};
pub use name::{MAX_NAME_LEN, validate_name};
pub use secret::SecretValue;
pub use store::{Change, Drift, ReindexReport, SetOutcome, Store};

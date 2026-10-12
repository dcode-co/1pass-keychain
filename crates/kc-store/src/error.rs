//! Error type and the exit-code friendly [`ErrorKind`] classification.
//!
//! No variant ever carries secret bytes: keychain errors that embed raw data
//! (`keyring_core::Error::BadEncoding` and friends) are converted to plain messages.

use std::path::PathBuf;
use std::time::Duration;

/// Result alias used throughout kc-store.
pub type Result<T, E = StoreError> = std::result::Result<T, E>;

/// Broad error categories. Each maps to one `kc` exit code (see [`ErrorKind::exit_code`]).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ErrorKind {
    /// The requested thing doesn't exist. Exit code 3.
    NotFound,
    /// The OS keychain can't be used right now: locked, no session, no service, timed out,
    /// or access refused. Exit code 4.
    Unavailable,
    /// The keychain needs a prompt, but the caller is non-interactive. Exit code 5.
    InteractionRequired,
    /// Bad input: invalid name or configuration, empty or oversized value, ambiguous adopt.
    /// Exit code 2 (the same as a usage error).
    InvalidInput,
    /// Anything else: damaged data, index or I/O trouble, unexpected keychain errors. Exit code 1.
    Other,
}

impl ErrorKind {
    /// The `kc` process exit code for this kind of error.
    ///
    /// | kind | code |
    /// |---|---|
    /// | [`NotFound`](Self::NotFound) | 3 |
    /// | [`Unavailable`](Self::Unavailable) | 4 |
    /// | [`InteractionRequired`](Self::InteractionRequired) | 5 |
    /// | [`InvalidInput`](Self::InvalidInput) | 2 |
    /// | [`Other`](Self::Other) | 1 |
    pub const fn exit_code(self) -> i32 {
        match self {
            ErrorKind::NotFound => 3,
            ErrorKind::Unavailable => 4,
            ErrorKind::InteractionRequired => 5,
            ErrorKind::InvalidInput => 2,
            ErrorKind::Other => 1,
        }
    }
}

/// Everything that can go wrong in kc-store.
///
/// Messages are written for the person running `kc`: the keychain variants carry a `hint`
/// that says how to fix the problem.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum StoreError {
    /// A name, internal key or namespace doesn't follow the naming rule.
    #[error("invalid {what} {value:?}: {rule}")]
    InvalidName {
        what: &'static str,
        value: String,
        rule: &'static str,
    },

    /// The value can't be stored (empty or too large).
    #[error("invalid value: {0}")]
    InvalidValue(String),

    /// A [`StoreConfig`](crate::StoreConfig) field is out of range.
    #[error("invalid kc-store configuration: {0}")]
    InvalidConfig(String),

    /// The item (or the foreign item to adopt, or the previous value to restore) doesn't exist.
    #[error("{0}")]
    NotFound(String),

    /// `adopt` without an account matched several keychain items.
    #[error(
        "{} keychain items match service {service:?}; pass an account to pick one: {}",
        candidates.len(),
        candidates.join(", ")
    )]
    Ambiguous {
        service: String,
        candidates: Vec<String>,
    },

    /// The keychain (or the collection holding the item) is locked. kc never shows an unlock
    /// prompt; the hint says how to unlock it.
    #[error("the OS keychain is locked ({what}). {hint}")]
    Locked { what: String, hint: String },

    /// No usable keychain: no session bus, no Secret Service, no logon session, unsupported OS.
    #[error("the OS keychain is unavailable: {reason}. {hint}")]
    Unavailable { reason: String, hint: String },

    /// A keychain call didn't come back within the configured timeout.
    #[error(
        "the OS keychain did not answer within {:.1}s ({op}). {hint}",
        timeout.as_secs_f64()
    )]
    Timeout {
        op: &'static str,
        timeout: Duration,
        hint: String,
    },

    /// A change was sent to the keychain, but whether it was carried out is unknown (the
    /// connection broke or the bus gave up waiting). Other kc processes hold off changing the
    /// keychain for a while (see the crate docs on timeouts).
    #[error("the OS keychain may or may not have carried out a change ({op}): {detail}. {hint}")]
    OutcomeUnknown {
        op: &'static str,
        detail: String,
        hint: String,
    },

    /// The keychain wants to show a prompt but the store was opened non-interactively.
    #[error("the OS keychain needs user interaction ({op}) but kc runs non-interactively. {hint}")]
    InteractionRequired { op: &'static str, hint: String },

    /// The keychain refused access (for example "Deny" at a macOS prompt).
    #[error("the OS keychain refused access ({op}): {detail}. {hint}")]
    AccessDenied {
        op: &'static str,
        detail: String,
        hint: String,
    },

    /// Any other keychain error.
    #[error("OS keychain error ({op}): {detail}")]
    Backend { op: &'static str, detail: String },

    /// A stored value failed its format or sha256 check.
    #[error(
        "stored value {account:?} is damaged: {reason}. Overwrite it with `kc set` or delete it"
    )]
    Corrupt { account: String, reason: String },

    /// `index.json` can't be parsed. The keychain itself is unaffected.
    #[error("{}: {detail}. Run `kc reindex` to rebuild it from the keychain", path.display())]
    IndexCorrupt { path: PathBuf, detail: String },

    /// Another `kc` process held the lock for longer than we were willing to wait.
    #[error(
        "another kc process is using {} (waited {:.0}s); try again",
        path.display(),
        waited.as_secs_f64()
    )]
    Busy { path: PathBuf, waited: Duration },

    /// File system error on the index or the lock file.
    #[error("{}: {source}", path.display())]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },

    /// Neither `KC_CONFIG_DIR` nor a home directory is available.
    #[error(
        "cannot determine the kc config directory (no home directory?); set {}",
        crate::config::ENV_CONFIG_DIR
    )]
    NoConfigDir,
}

impl StoreError {
    /// The category of this error.
    pub fn kind(&self) -> ErrorKind {
        match self {
            StoreError::NotFound(_) => ErrorKind::NotFound,
            StoreError::Locked { .. }
            | StoreError::Unavailable { .. }
            | StoreError::Timeout { .. }
            | StoreError::OutcomeUnknown { .. }
            | StoreError::AccessDenied { .. } => ErrorKind::Unavailable,
            StoreError::InteractionRequired { .. } => ErrorKind::InteractionRequired,
            StoreError::InvalidName { .. }
            | StoreError::InvalidValue(_)
            | StoreError::InvalidConfig(_)
            | StoreError::Ambiguous { .. } => ErrorKind::InvalidInput,
            StoreError::Backend { .. }
            | StoreError::Corrupt { .. }
            | StoreError::IndexCorrupt { .. }
            | StoreError::Busy { .. }
            | StoreError::Io { .. }
            | StoreError::NoConfigDir => ErrorKind::Other,
        }
    }

    /// Whether a keychain change may still be carried out after this error was reported.
    /// (Timeouts are judged separately, by whether the call had started; see `crate::lock`.)
    pub(crate) fn leaves_doubt(&self) -> bool {
        matches!(self, StoreError::OutcomeUnknown { .. })
    }

    /// Shorthand for `self.kind().exit_code()`.
    pub fn exit_code(&self) -> i32 {
        self.kind().exit_code()
    }

    pub(crate) fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        StoreError::Io {
            path: path.into(),
            source,
        }
    }

    pub(crate) fn corrupt(account: &str, reason: impl Into<String>) -> Self {
        StoreError::Corrupt {
            account: account.to_owned(),
            reason: reason.into(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_match_the_cli_contract() {
        assert_eq!(StoreError::NotFound("x".into()).exit_code(), 3);
        let locked = StoreError::Locked {
            what: "w".into(),
            hint: "h".into(),
        };
        assert_eq!(locked.exit_code(), 4);
        let unavailable = StoreError::Unavailable {
            reason: "r".into(),
            hint: "h".into(),
        };
        assert_eq!(unavailable.exit_code(), 4);
        let timeout = StoreError::Timeout {
            op: "read",
            timeout: Duration::from_secs(5),
            hint: "h".into(),
        };
        assert_eq!(timeout.exit_code(), 4);
        let interaction = StoreError::InteractionRequired {
            op: "read",
            hint: "h".into(),
        };
        assert_eq!(interaction.exit_code(), 5);
        assert_eq!(StoreError::InvalidValue("v".into()).exit_code(), 2);
        assert_eq!(StoreError::corrupt("item:a", "bad").exit_code(), 1);
    }

    #[test]
    fn store_error_is_send_and_sync() {
        fn assert_send_sync<T: Send + Sync + 'static>() {}
        assert_send_sync::<StoreError>();
    }
}

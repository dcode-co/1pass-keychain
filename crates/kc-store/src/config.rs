//! [`StoreConfig`] and environment handling.

use std::path::PathBuf;
use std::time::Duration;

use crate::error::{Result, StoreError};
use crate::name::validate_namespace;

/// The keychain service name used for real items.
pub const DEFAULT_NAMESPACE: &str = "dev.1pass.kc";

/// Overrides the namespace. Honoured only in debug builds (tests and local development);
/// release builds always use [`DEFAULT_NAMESPACE`] unless the caller sets
/// [`StoreConfig::namespace`] itself.
pub const ENV_NAMESPACE: &str = "KC_NAMESPACE";

/// Overrides the config directory that holds `index.json` and `kc.lock`.
pub const ENV_CONFIG_DIR: &str = "KC_CONFIG_DIR";

/// Overrides the directory of the user-wide lock and its `in-doubt` marker. Honoured in debug
/// builds only, so that tests (which may kill kc mid-change) never touch the real one.
pub const ENV_LOCK_DIR: &str = "KC_LOCK_DIR";

/// Default largest stored blob (format tag included). Values that don't fit are chunked.
pub const DEFAULT_MAX_BLOB_LEN: usize = 2048;

/// Smallest accepted [`StoreConfig::max_blob_len`]: room for the largest manifest head, which
/// is the account frame (a name at the length limit plus `#prev`) plus the manifest JSON — about
/// 275 bytes — so that no stored blob ever exceeds the limit. Tests use it to force chunking.
pub const MIN_MAX_BLOB_LEN: usize = 288;

/// Windows Credential Manager refuses credential blobs larger than this (`CRED_MAX_CREDENTIAL_BLOB_SIZE`).
pub const WINDOWS_MAX_BLOB_LEN: usize = 2560;

/// Keychain call timeout for non-interactive callers (agents, scripts, SSH).
pub const NON_INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(5);

/// Keychain call timeout for interactive callers, long enough to answer a macOS prompt.
pub const INTERACTIVE_TIMEOUT: Duration = Duration::from_secs(60);

/// How a [`Store`](crate::Store) is opened.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StoreConfig {
    /// Keychain service name. Every entry kc writes uses it.
    pub namespace: String,
    /// Directory for `index.json` (metadata cache) and `kc.lock`.
    pub config_dir: PathBuf,
    /// Whether a person can answer keychain prompts.
    ///
    /// - `false` (default): 5 s timeout; on macOS keychain prompts are disabled, so a call that
    ///   would prompt fails fast with [`StoreError::InteractionRequired`].
    /// - `true`: 60 s timeout; macOS may show its "allow access" prompt.
    ///
    /// Linux never prompts in either mode: a locked keyring is reported as
    /// [`StoreError::Locked`].
    pub interactive: bool,
    /// Overrides the per-call timeout chosen by [`interactive`](Self::interactive).
    pub timeout: Option<Duration>,
    /// Largest blob written to one keychain entry, format tag included. Larger values are split
    /// into chunks. Must be at least [`MIN_MAX_BLOB_LEN`], and at most
    /// [`WINDOWS_MAX_BLOB_LEN`] on Windows.
    pub max_blob_len: usize,
}

impl StoreConfig {
    /// A non-interactive configuration with defaults for everything but the namespace and
    /// config directory.
    pub fn new(namespace: impl Into<String>, config_dir: impl Into<PathBuf>) -> Self {
        StoreConfig {
            namespace: namespace.into(),
            config_dir: config_dir.into(),
            interactive: false,
            timeout: None,
            max_blob_len: DEFAULT_MAX_BLOB_LEN,
        }
    }

    /// The configuration `kc` uses: `KC_CONFIG_DIR` (or the platform config directory) and,
    /// in debug builds only, `KC_NAMESPACE`. Non-interactive; call
    /// [`with_interactive`](Self::with_interactive) for a terminal session.
    pub fn from_env() -> Result<Self> {
        let config_dir = default_config_dir()?;
        let namespace = namespace_from_env().unwrap_or_else(|| DEFAULT_NAMESPACE.to_owned());
        Ok(StoreConfig::new(namespace, config_dir))
    }

    /// Sets [`interactive`](Self::interactive).
    pub fn with_interactive(mut self, interactive: bool) -> Self {
        self.interactive = interactive;
        self
    }

    /// Sets [`timeout`](Self::timeout).
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// Sets [`max_blob_len`](Self::max_blob_len).
    pub fn with_max_blob_len(mut self, max_blob_len: usize) -> Self {
        self.max_blob_len = max_blob_len;
        self
    }

    /// The timeout applied to each keychain call.
    pub fn effective_timeout(&self) -> Duration {
        self.timeout.unwrap_or(if self.interactive {
            INTERACTIVE_TIMEOUT
        } else {
            NON_INTERACTIVE_TIMEOUT
        })
    }

    /// How long to wait for another kc process to release `kc.lock`.
    pub(crate) fn lock_wait(&self) -> Duration {
        self.effective_timeout().saturating_mul(3)
    }

    pub(crate) fn validate(&self) -> Result<()> {
        validate_namespace(&self.namespace)?;
        if self.max_blob_len < MIN_MAX_BLOB_LEN {
            return Err(StoreError::InvalidConfig(format!(
                "max_blob_len {} is below the minimum of {MIN_MAX_BLOB_LEN}",
                self.max_blob_len
            )));
        }
        if cfg!(windows) && self.max_blob_len > WINDOWS_MAX_BLOB_LEN {
            return Err(StoreError::InvalidConfig(format!(
                "max_blob_len {} exceeds the Windows credential limit of {WINDOWS_MAX_BLOB_LEN}",
                self.max_blob_len
            )));
        }
        if self.effective_timeout().is_zero() {
            return Err(StoreError::InvalidConfig("timeout must be positive".into()));
        }
        Ok(())
    }
}

/// The config directory: `KC_CONFIG_DIR` if set, else the platform's config directory for
/// `dev.1pass.keychain` (`~/.config/keychain` on Linux,
/// `~/Library/Application Support/dev.1pass.keychain` on macOS,
/// `%APPDATA%\1pass\keychain\config` on Windows).
pub fn default_config_dir() -> Result<PathBuf> {
    if let Some(dir) = std::env::var_os(ENV_CONFIG_DIR).filter(|v| !v.is_empty()) {
        return Ok(PathBuf::from(dir));
    }
    directories::ProjectDirs::from("dev", "1pass", "keychain")
        .map(|dirs| dirs.config_dir().to_path_buf())
        .ok_or(StoreError::NoConfigDir)
}

/// `KC_NAMESPACE`, in debug builds only.
fn namespace_from_env() -> Option<String> {
    if !cfg!(debug_assertions) {
        return None;
    }
    std::env::var(ENV_NAMESPACE).ok().filter(|v| !v.is_empty())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn timeouts_follow_interactivity() {
        let cfg = StoreConfig::new(DEFAULT_NAMESPACE, "/tmp/x");
        assert_eq!(cfg.effective_timeout(), NON_INTERACTIVE_TIMEOUT);
        let cfg = cfg.with_interactive(true);
        assert_eq!(cfg.effective_timeout(), INTERACTIVE_TIMEOUT);
        let cfg = cfg.with_timeout(Duration::from_millis(250));
        assert_eq!(cfg.effective_timeout(), Duration::from_millis(250));
    }

    #[test]
    fn validation() {
        let ok = StoreConfig::new("dev.1pass.kc.test-1", "/tmp/x");
        assert!(ok.validate().is_ok());
        assert!(
            ok.clone()
                .with_max_blob_len(MIN_MAX_BLOB_LEN - 1)
                .validate()
                .is_err()
        );
        assert!(ok.clone().with_timeout(Duration::ZERO).validate().is_err());
        assert!(
            StoreConfig::new("bad/namespace", "/tmp/x")
                .validate()
                .is_err()
        );
        let big = ok.with_max_blob_len(WINDOWS_MAX_BLOB_LEN + 1).validate();
        assert_eq!(big.is_err(), cfg!(windows));
    }
}

//! macOS and Windows: keyring-core with one explicitly chosen store crate per OS.
//!
//! | OS | store crate | where secrets go |
//! |---|---|---|
//! | macOS | `apple-native-keyring-store` (`keychain`) | login keychain, generic passwords (service, account) |
//! | Windows | `windows-native-keyring-store` | Credential Manager generic credentials `<account>@<namespace>` (encoded, see below), persistence Local |
//!
//! The store is built directly, checked to be persistent (a mock or in-memory store is
//! refused with [`StoreError::Unavailable`]), registered with
//! `keyring_core::set_default_store`, and the registration is read back. Every call goes
//! through [`bounded`], which applies the configured timeout and runs one keychain call at a
//! time per process.

#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::collections::HashMap;
use std::sync::Arc;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use std::time::Duration;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use keyring_core::Entry;
use keyring_core::{CredentialPersistence, CredentialStore};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use zeroize::Zeroizing;

#[cfg(any(target_os = "macos", target_os = "windows"))]
use super::{Backend, ForeignItem, bounded};
#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::config::StoreConfig;
#[cfg(any(target_os = "macos", target_os = "windows"))]
use crate::error::Result;
use crate::error::StoreError;

#[cfg(any(target_os = "macos", target_os = "windows"))]
pub(crate) struct KeyringBackend {
    inner: Arc<Inner>,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
struct Inner {
    store: Arc<CredentialStore>,
    namespace: String,
    interactive: bool,
    timeout: Duration,
    description: String,
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl KeyringBackend {
    /// Opens the platform keychain. Fails with a typed error (never falls back to a mock).
    pub(crate) fn connect(cfg: &StoreConfig) -> Result<Self> {
        let timeout = cfg.effective_timeout();
        let namespace = cfg.namespace.clone();
        let interactive = cfg.interactive;
        let inner = bounded(timeout, "connect", sys::TIMEOUT_HINT, move || {
            let _prompts = sys::CallGuard::enter(interactive)?;
            let store = sys::connect()?;
            ensure_persistent(&store)?;
            keyring_core::set_default_store(Arc::clone(&store));
            ensure_default_store_is(&store)?;
            let description = format!("{} ({})", sys::NAME, store.vendor());
            Ok(Arc::new(Inner {
                store,
                namespace,
                interactive,
                timeout,
                description,
            }))
        })?;
        Ok(KeyringBackend { inner })
    }

    fn call<T, F>(&self, op: &'static str, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Inner) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        bounded(self.inner.timeout, op, sys::TIMEOUT_HINT, move || {
            let _prompts = sys::CallGuard::enter(inner.interactive)?;
            f(&inner)
        })
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl Inner {
    /// A fresh keyring-core entry for `account` in our namespace. Built per call, so every
    /// read really goes to the OS store instead of an object that remembers what it wrote.
    fn entry(&self, account: &str) -> Result<Entry> {
        let owned = sys::modifiers();
        let modifiers: HashMap<&str, &str> = owned.iter().map(|(k, v)| (*k, v.as_str())).collect();
        self.store
            .build(
                &sys::store_name(&self.namespace),
                &sys::store_name(account),
                Some(&modifiers),
            )
            .map_err(|err| sys::map_err(err, "open entry"))
    }
}

#[cfg(any(target_os = "macos", target_os = "windows"))]
impl Backend for KeyringBackend {
    fn describe(&self) -> String {
        self.inner.description.clone()
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let account = account.to_owned();
        self.call("read", move |inner| {
            match inner.entry(&account)?.get_secret() {
                Ok(secret) => Ok(Some(Zeroizing::new(secret))),
                Err(keyring_core::Error::NoEntry) => Ok(None),
                Err(err) => Err(sys::map_err(err, "read")),
            }
        })
    }

    fn set(&self, account: &str, blob: &[u8]) -> Result<()> {
        let account = account.to_owned();
        let blob = Zeroizing::new(blob.to_vec());
        self.call("write", move |inner| {
            inner
                .entry(&account)?
                .set_secret(&blob)
                .map_err(|err| sys::map_err(err, "write"))
        })
    }

    fn delete(&self, account: &str) -> Result<bool> {
        let account = account.to_owned();
        self.call("delete", move |inner| {
            match inner.entry(&account)?.delete_credential() {
                Ok(()) => Ok(true),
                Err(keyring_core::Error::NoEntry) => Ok(false),
                Err(err) => Err(sys::map_err(err, "delete")),
            }
        })
    }

    fn exists(&self, account: &str) -> Result<bool> {
        let account = account.to_owned();
        self.call("lookup", move |inner| sys::exists(inner, &account))
    }

    fn accounts(&self) -> Result<Vec<String>> {
        self.call("list", sys::accounts)
    }

    fn read_foreign(&self, service: &str, account: Option<&str>) -> Result<ForeignItem> {
        let service = service.to_owned();
        let account = account.map(str::to_owned);
        self.call("adopt", move |inner| {
            sys::read_foreign(inner, &service, account.as_deref())
        })
    }
}

/// Refuses stores that don't keep secrets on disk, such as keyring-core's mock store. This is
/// the guard against the old "keyring without platform features silently used a mock" trap.
fn ensure_persistent(store: &Arc<CredentialStore>) -> Result<(), StoreError> {
    if matches!(store.persistence(), CredentialPersistence::UntilDelete) {
        Ok(())
    } else {
        Err(StoreError::Unavailable {
            reason: format!("{} does not keep secrets on disk", store.vendor()),
            hint: "kc refuses to use an in-memory or mock credential store".into(),
        })
    }
}

/// The `store_status()` equivalent: the store we registered must be the default store now.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn ensure_default_store_is(store: &Arc<CredentialStore>) -> Result<()> {
    match keyring_core::get_default_store() {
        Some(default) if default.vendor() == store.vendor() && default.id() == store.id() => Ok(()),
        _ => Err(StoreError::Unavailable {
            reason: "the platform credential store could not be registered with keyring-core"
                .into(),
            hint: "this is a bug in kc; please report it".into(),
        }),
    }
}

/// Maps the platform-independent keyring-core errors. Never copies secret bytes
/// (`BadEncoding` and `BadDataFormat` carry them) into the result.
fn map_common(err: keyring_core::Error, op: &'static str) -> StoreError {
    use keyring_core::Error as E;
    let detail = match err {
        E::NoEntry => "no matching keychain entry".to_owned(),
        E::BadEncoding(_) | E::BadDataFormat(..) => "the keychain returned malformed data".into(),
        E::BadStoreFormat(reason) => format!("the keychain store is malformed: {reason}"),
        E::TooLong(attr, limit) => format!("{attr} is longer than the platform limit of {limit}"),
        E::Invalid(attr, reason) => format!("{attr} is invalid: {reason}"),
        E::Ambiguous(entries) => format!(
            "{} keychain entries share this service and account; remove the duplicates",
            entries.len()
        ),
        E::NoDefaultStore => {
            return StoreError::Unavailable {
                reason: "no credential store is configured".into(),
                hint: "this is a bug in kc; please report it".into(),
            };
        }
        E::NotSupportedByStore(what) => format!("not supported by this keychain: {what}"),
        E::PlatformFailure(inner) => inner.to_string(),
        E::NoStorageAccess(inner) => {
            return StoreError::Unavailable {
                reason: inner.to_string(),
                hint: String::new(),
            };
        }
        other => other.to_string(),
    };
    StoreError::Backend { op, detail }
}

/// The Win32 error code inside a `windows-native-keyring-store` platform error. Its
/// `PlatformError(u32)` type is private to that crate, so the code is read from its derived
/// `Debug` form, `PlatformError(<code>)`.
#[cfg(any(test, target_os = "windows"))]
fn windows_error_code(err: &(dyn std::error::Error + Send + Sync)) -> Option<u32> {
    format!("{err:?}")
        .strip_prefix("PlatformError(")?
        .strip_suffix(')')?
        .parse()
        .ok()
}

/// The account of a search result. Fails instead of skipping: an incomplete list would make
/// garbage collection delete live chunks.
#[cfg(any(target_os = "macos", target_os = "windows"))]
fn specifiers(entry: &Entry, op: &'static str) -> Result<(String, String)> {
    entry.get_specifiers().ok_or_else(|| StoreError::Backend {
        op,
        detail: "the keychain returned an entry without service and account".into(),
    })
}

// ---------------------------------------------------------------------------------------------
// macOS: the login keychain.
// ---------------------------------------------------------------------------------------------
#[cfg(target_os = "macos")]
mod sys {
    //! Items are generic passwords in the login keychain (service = namespace,
    //! account = `item:<name>` …).
    //!
    //! macOS ties keychain access to the binary that created the item. An unsigned or rebuilt
    //! `kc` counts as a new application, so macOS shows an "allow access" prompt the first time
    //! it touches an existing item. Release builds are code-signed with the Dcode Developer ID
    //! so "Always Allow" survives updates. Non-interactive stores disable keychain prompts for
    //! the duration of each call; a call that would prompt then fails at once with
    //! `errSecInteractionNotAllowed` (-25308), reported as
    //! [`StoreError::InteractionRequired`].

    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use apple_native_keyring_store::keychain::Store as KeychainStore;
    use keyring_core::CredentialStore;
    use security_framework::os::macos::keychain::{KeychainUserInteractionLock, SecKeychain};
    use zeroize::Zeroizing;

    use super::super::{ForeignItem, not_found};
    use super::{Inner, map_common, specifiers};
    use crate::error::{Result, StoreError};

    pub(super) const NAME: &str = "macOS login keychain";
    pub(super) const TIMEOUT_HINT: &str = "A keychain prompt may be waiting on screen: answer it \
        (choose \"Always Allow\") and run kc again";
    const INTERACTION_HINT: &str = "macOS wants to show a keychain prompt: the login keychain is \
        locked, or this kc binary isn't allowed to use the item yet (unsigned or rebuilt binaries \
        count as new apps). Run the same kc command once in a terminal and choose \
        \"Always Allow\", or unlock the keychain with \
        `security unlock-keychain ~/Library/Keychains/login.keychain-db`";
    const DENIED_HINT: &str = "Run kc again and choose \"Always Allow\" at the keychain prompt";
    const UNAVAILABLE_HINT: &str = "The login keychain isn't available in this session; log in to \
        the Mac's desktop once, or run `security unlock-keychain`";

    /// Disables keychain prompts for one call when the store is non-interactive; dropping it
    /// turns them back on.
    pub(super) struct CallGuard {
        _prompts_off: Option<KeychainUserInteractionLock>,
    }

    impl CallGuard {
        pub(super) fn enter(interactive: bool) -> Result<CallGuard> {
            if interactive {
                return Ok(CallGuard { _prompts_off: None });
            }
            SecKeychain::disable_user_interaction()
                .map(|lock| CallGuard {
                    _prompts_off: Some(lock),
                })
                .map_err(|err| StoreError::Backend {
                    op: "disable keychain prompts",
                    detail: err.to_string(),
                })
        }
    }

    pub(super) fn connect() -> Result<Arc<CredentialStore>> {
        // The default configuration is the User (login) keychain.
        KeychainStore::new()
            .map(|store| store as Arc<CredentialStore>)
            .map_err(|err| map_err(err, "connect"))
    }

    pub(super) fn modifiers() -> Vec<(&'static str, String)> {
        Vec::new()
    }

    /// Service and account names go to the keychain unchanged.
    pub(super) fn store_name(name: &str) -> Cow<'_, str> {
        Cow::Borrowed(name)
    }

    /// Attribute-only search: no secret is read, so no prompt.
    pub(super) fn exists(inner: &Inner, account: &str) -> Result<bool> {
        let spec = HashMap::from([("service", inner.namespace.as_str()), ("user", account)]);
        let found = inner
            .store
            .search(&spec)
            .map_err(|err| map_err(err, "lookup"))?;
        Ok(!found.is_empty())
    }

    pub(super) fn accounts(inner: &Inner) -> Result<Vec<String>> {
        let spec = HashMap::from([("service", inner.namespace.as_str())]);
        let found = inner
            .store
            .search(&spec)
            .map_err(|err| map_err(err, "list"))?;
        let mut accounts = Vec::with_capacity(found.len());
        for entry in &found {
            let (service, account) = specifiers(entry, "list")?;
            if service == inner.namespace {
                accounts.push(account);
            }
        }
        Ok(accounts)
    }

    /// A generic password with this service and account. Without an account, the single
    /// generic password with this service.
    pub(super) fn read_foreign(
        inner: &Inner,
        service: &str,
        account: Option<&str>,
    ) -> Result<ForeignItem> {
        let account = match account {
            Some(account) => account.to_owned(),
            None => {
                let spec = HashMap::from([("service", service)]);
                let found = inner
                    .store
                    .search(&spec)
                    .map_err(|err| map_err(err, "adopt"))?;
                let mut accounts = Vec::with_capacity(found.len());
                for entry in &found {
                    accounts.push(specifiers(entry, "adopt")?.1);
                }
                accounts.sort();
                accounts.dedup();
                match accounts.len() {
                    0 => return Err(not_found(service, None)),
                    1 => accounts.remove(0),
                    _ => {
                        return Err(StoreError::Ambiguous {
                            service: service.to_owned(),
                            candidates: accounts.iter().map(|a| format!("account={a}")).collect(),
                        });
                    }
                }
            }
        };
        let entry = inner
            .store
            .build(service, &account, None)
            .map_err(|err| map_err(err, "adopt"))?;
        match entry.get_secret() {
            Ok(secret) => Ok(ForeignItem {
                account: Some(account),
                value: Zeroizing::new(secret),
            }),
            Err(keyring_core::Error::NoEntry) => Err(not_found(service, Some(&account))),
            Err(err) => Err(map_err(err, "adopt")),
        }
    }

    pub(super) fn map_err(err: keyring_core::Error, op: &'static str) -> StoreError {
        use keyring_core::Error as E;
        match err {
            E::PlatformFailure(inner) | E::NoStorageAccess(inner) => {
                let code = inner
                    .downcast_ref::<security_framework::base::Error>()
                    .map(|err| err.code());
                let detail = inner.to_string();
                match code {
                    // errSecInteractionNotAllowed
                    Some(-25308) => StoreError::InteractionRequired {
                        op,
                        hint: INTERACTION_HINT.into(),
                    },
                    // userCanceled, errSecAuthFailed, write permission, invalid owner edit, read-only
                    Some(-128 | -25293 | -61 | -25244 | -25292) => StoreError::AccessDenied {
                        op,
                        detail,
                        hint: DENIED_HINT.into(),
                    },
                    // errSecNotAvailable, errSecNoSuchKeychain, errSecInvalidKeychain
                    Some(-25291 | -25294 | -25295) => StoreError::Unavailable {
                        reason: detail,
                        hint: UNAVAILABLE_HINT.into(),
                    },
                    _ => StoreError::Backend { op, detail },
                }
            }
            other => map_common(other, op),
        }
    }
}

// ---------------------------------------------------------------------------------------------
// Windows: Credential Manager.
// ---------------------------------------------------------------------------------------------
#[cfg(target_os = "windows")]
mod sys {
    //! Generic credentials named `<account>@<namespace>`, persistence Local so nothing roams
    //! with a domain profile. Credential blobs are limited to 2560 bytes, which is why values
    //! are chunked at 2048 bytes.
    //!
    //! Credential Manager compares target names case-insensitively while kc names are
    //! case-sensitive, so upper-case letters are written as `!` plus the lower-case letter
    //! (`apple-p8/ID` → `apple-p8/!i!d`). Names and namespaces never contain `!` or `@`, so
    //! the mapping is one-to-one and the target name splits unambiguously at `@`.

    use std::borrow::Cow;
    use std::collections::HashMap;
    use std::sync::Arc;

    use keyring_core::{CredentialStore, Entry};
    use windows_native_keyring_store::Store as WindowsStore;
    use zeroize::Zeroizing;

    use super::super::{ForeignItem, not_found};
    use super::{Inner, map_common, specifiers};
    use crate::error::{Result, StoreError};

    pub(super) const NAME: &str = "Windows Credential Manager";
    pub(super) const TIMEOUT_HINT: &str = "Windows Credential Manager did not answer; try again";
    const NO_SESSION_HINT: &str = "Credential Manager isn't available in this logon session \
        (ERROR_NO_SUCH_LOGON_SESSION, typical for OpenSSH key authentication). Run kc from an \
        interactive desktop session, or connect over SSH with password authentication";
    const ACCESS_DENIED_HINT: &str = "Windows refused access to the credential. Run kc as the \
        user who owns it, outside any sandbox or policy that restricts Credential Manager";
    /// ERROR_ACCESS_DENIED
    const ERROR_ACCESS_DENIED: u32 = 5;

    pub(super) struct CallGuard;

    impl CallGuard {
        pub(super) fn enter(_interactive: bool) -> Result<CallGuard> {
            Ok(CallGuard)
        }
    }

    pub(super) fn connect() -> Result<Arc<CredentialStore>> {
        let config = HashMap::from([("divider", "@"), ("service_no_divider", "true")]);
        WindowsStore::new_with_configuration(&config)
            .map(|store| store as Arc<CredentialStore>)
            .map_err(|err| map_err(err, "connect"))
    }

    pub(super) fn modifiers() -> Vec<(&'static str, String)> {
        vec![("persistence", "Local".to_owned())]
    }

    /// The case-preserving, case-insensitive-safe form of a service or account name.
    pub(super) fn store_name(name: &str) -> Cow<'_, str> {
        if !name.bytes().any(|b| b.is_ascii_uppercase()) {
            return Cow::Borrowed(name);
        }
        let mut encoded = String::with_capacity(name.len() * 2);
        for c in name.chars() {
            if c.is_ascii_uppercase() {
                encoded.push('!');
                encoded.push(c.to_ascii_lowercase());
            } else {
                encoded.push(c);
            }
        }
        Cow::Owned(encoded)
    }

    /// Reverses [`store_name`]. `None` for names kc didn't write.
    fn decode_name(stored: &str) -> Option<String> {
        let mut decoded = String::with_capacity(stored.len());
        let mut chars = stored.chars();
        while let Some(c) = chars.next() {
            match c {
                '!' => match chars.next() {
                    Some(next) if next.is_ascii_lowercase() => {
                        decoded.push(next.to_ascii_uppercase())
                    }
                    _ => return None,
                },
                c if c.is_ascii_uppercase() => return None,
                c => decoded.push(c),
            }
        }
        Some(decoded)
    }

    pub(super) fn exists(inner: &Inner, account: &str) -> Result<bool> {
        match inner.entry(account)?.get_credential() {
            Ok(_) => Ok(true),
            Err(keyring_core::Error::NoEntry) => Ok(false),
            Err(err) => Err(map_err(err, "lookup")),
        }
    }

    pub(super) fn accounts(inner: &Inner) -> Result<Vec<String>> {
        let service = store_name(&inner.namespace);
        let pattern = format!("^.+@{}$", regex::escape(&service));
        let spec = HashMap::from([("pattern", pattern.as_str())]);
        let found = inner
            .store
            .search(&spec)
            .map_err(|err| map_err(err, "list"))?;
        let mut accounts = Vec::with_capacity(found.len());
        for entry in &found {
            let (found_service, found_account) = specifiers(entry, "list")?;
            if found_service != *service {
                continue;
            }
            // Credentials matching our pattern that kc didn't write are skipped, not fatal.
            if let Some(account) = decode_name(&found_account) {
                accounts.push(account);
            }
        }
        Ok(accounts)
    }

    /// Supported credentials: target `<account>.<service>` (keyring-rs v1–v3 layout) or a
    /// generic credential whose target is the service itself (`cmdkey /generic:<service>`),
    /// whose user name must equal the account when one is given. Without an account, every
    /// `<anything>.<service>` target counts too, and more than one match is ambiguous.
    pub(super) fn read_foreign(
        inner: &Inner,
        service: &str,
        account: Option<&str>,
    ) -> Result<ForeignItem> {
        let mut found: Vec<(String, ForeignItem)> = Vec::new();
        match account {
            Some(account) => {
                let target = format!("{account}.{service}");
                if let Some(item) = read_target(inner, &target)? {
                    found.push((target, item));
                }
                if let Some(item) = read_target(inner, service)?
                    && item.account.as_deref() == Some(account)
                {
                    found.push((service.to_owned(), item));
                }
            }
            None => {
                if let Some(item) = read_target(inner, service)? {
                    found.push((service.to_owned(), item));
                }
                // Credential Manager compares target names case-insensitively; so does this.
                let pattern = format!("(?i)^.+\\.{}$", regex::escape(service));
                let spec = HashMap::from([("pattern", pattern.as_str())]);
                let entries = inner
                    .store
                    .search(&spec)
                    .map_err(|err| map_err(err, "adopt"))?;
                for entry in &entries {
                    let target = target_name(entry)?;
                    if found
                        .iter()
                        .any(|(seen, _)| seen.eq_ignore_ascii_case(&target))
                    {
                        continue;
                    }
                    if let Some(mut item) = read_target(inner, &target)? {
                        if item.account.is_none() {
                            item.account = account_prefix(&target, service);
                        }
                        found.push((target, item));
                    }
                }
            }
        }
        match found.len() {
            0 => Err(not_found(service, account)),
            1 => Ok(found.remove(0).1),
            _ => Err(StoreError::Ambiguous {
                service: service.to_owned(),
                candidates: found
                    .iter()
                    .map(|(target, _)| format!("target={target}"))
                    .collect(),
            }),
        }
    }

    /// `alice` from `alice.Service` for service `service`, comparing case-insensitively.
    fn account_prefix(target: &str, service: &str) -> Option<String> {
        let split = target.len().checked_sub(service.len() + 1)?;
        let (account, suffix) = (target.get(..split)?, target.get(split..)?);
        let matches = suffix.strip_prefix('.')?.eq_ignore_ascii_case(service);
        (matches && !account.is_empty()).then(|| account.to_owned())
    }

    fn target_name(entry: &Entry) -> Result<String> {
        let attributes = entry
            .get_attributes()
            .map_err(|err| map_err(err, "adopt"))?;
        attributes
            .get("target_name")
            .cloned()
            .ok_or_else(|| StoreError::Backend {
                op: "adopt",
                detail: "a credential without a target name".into(),
            })
    }

    fn read_target(inner: &Inner, target: &str) -> Result<Option<ForeignItem>> {
        let modifiers = HashMap::from([("target", target)]);
        // Service and user are ignored when an explicit target is given.
        let entry = inner
            .store
            .build("kc-adopt", "kc-adopt", Some(&modifiers))
            .map_err(|err| map_err(err, "adopt"))?;
        let value = match entry.get_secret() {
            Ok(secret) => Zeroizing::new(secret),
            Err(keyring_core::Error::NoEntry) => return Ok(None),
            Err(err) => return Err(map_err(err, "adopt")),
        };
        let attributes = entry
            .get_attributes()
            .map_err(|err| map_err(err, "adopt"))?;
        let account = attributes
            .get("username")
            .filter(|user| !user.is_empty())
            .cloned();
        Ok(Some(ForeignItem { account, value }))
    }

    pub(super) fn map_err(err: keyring_core::Error, op: &'static str) -> StoreError {
        match err {
            // The store reports ERROR_NO_SUCH_LOGON_SESSION (1312) as NoStorageAccess.
            keyring_core::Error::NoStorageAccess(inner) => StoreError::Unavailable {
                reason: format!("no Credential Manager logon session ({inner})"),
                hint: NO_SESSION_HINT.into(),
            },
            // The store reports ERROR_ACCESS_DENIED (5) as a plain platform failure.
            keyring_core::Error::PlatformFailure(inner)
                if super::windows_error_code(&*inner) == Some(ERROR_ACCESS_DENIED) =>
            {
                StoreError::AccessDenied {
                    op,
                    detail: inner.to_string(),
                    hint: ACCESS_DENIED_HINT.into(),
                }
            }
            other => map_common(other, op),
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        #[test]
        fn target_names_are_one_to_one_under_case_folding() {
            for name in ["item:apple-p8/ID", "item:foo", "item:Foo", "dev.1pass.kc"] {
                assert_eq!(decode_name(&store_name(name)).as_deref(), Some(name));
            }
            let a = store_name("item:Foo").to_ascii_lowercase();
            let b = store_name("item:foo").to_ascii_lowercase();
            assert_ne!(a, b);
            assert_eq!(decode_name("item:Foo"), None);
            assert_eq!(decode_name("item:!1"), None);
        }

        /// Stand-in with the same derived `Debug` form as the store's private error type.
        #[derive(Debug)]
        struct PlatformError(u32);

        impl std::fmt::Display for PlatformError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "Windows error code {}", self.0)
            }
        }

        impl std::error::Error for PlatformError {}

        #[test]
        fn access_denied_is_access_denied() {
            let err = map_err(
                keyring_core::Error::PlatformFailure(Box::new(PlatformError(ERROR_ACCESS_DENIED))),
                "write",
            );
            assert!(matches!(err, StoreError::AccessDenied { .. }), "{err}");
            assert_eq!(err.exit_code(), 4);
            let other = map_err(
                keyring_core::Error::PlatformFailure(Box::new(PlatformError(1783))),
                "write",
            );
            assert!(matches!(other, StoreError::Backend { .. }), "{other}");
        }

        #[test]
        fn account_prefix_ignores_case() {
            assert_eq!(
                account_prefix("alice.ExampleService", "exampleservice").as_deref(),
                Some("alice")
            );
            assert_eq!(account_prefix("exampleservice", "exampleservice"), None);
            assert_eq!(account_prefix(".svc", "svc"), None);
            assert_eq!(account_prefix("alice.other", "svc"), None);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mock_store_is_refused() {
        let mock: Arc<CredentialStore> = keyring_core::mock::Store::new().unwrap();
        let err = ensure_persistent(&mock).unwrap_err();
        assert!(matches!(err, StoreError::Unavailable { .. }), "{err}");
        assert_eq!(err.exit_code(), 4);
    }

    #[test]
    fn reads_windows_error_codes_from_the_debug_form() {
        #[derive(Debug)]
        struct PlatformError(u32);
        impl std::fmt::Display for PlatformError {
            fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                write!(f, "Windows error code {}", self.0)
            }
        }
        impl std::error::Error for PlatformError {}

        let boxed: Box<dyn std::error::Error + Send + Sync> = Box::new(PlatformError(5));
        assert_eq!(windows_error_code(&*boxed), Some(5));
        let other: Box<dyn std::error::Error + Send + Sync> = "PlatformError(x)".into();
        assert_eq!(windows_error_code(&*other), None);
    }

    #[test]
    fn keyring_errors_never_carry_secret_bytes() {
        let secret = b"fake-secret-bytes-for-test".to_vec();
        let err = map_common(keyring_core::Error::BadEncoding(secret), "read");
        let shown = format!("{err} {err:?}");
        assert!(!shown.contains("fake-secret"), "{shown}");
        assert!(!shown.contains("102, 97, 107, 101"), "{shown}");
    }
}

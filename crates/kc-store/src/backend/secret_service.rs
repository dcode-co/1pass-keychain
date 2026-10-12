//! Linux and the BSDs: the Secret Service (gnome-keyring, KeePassXC) over D-Bus.
//!
//! **Never prompts, by construction.** The keyring store crates for the Secret Service unlock
//! locked items and collections on their own, which shows a password dialog (or hangs
//! without a display), and they can't be configured not to. So this backend talks to the
//! service directly and only uses calls that cannot prompt:
//!
//! - `SearchItems`, `GetSecret`, `SetSecret` and property reads, through the `secret-service`
//!   crate over an encrypted (Diffie-Hellman) session. On a locked item they fail; they never
//!   unlock.
//! - `CreateItem` and `Item.Delete` as raw D-Bus calls. On a locked collection they answer with
//!   a prompt object; kc dismisses it without running it and reports [`StoreError::Locked`].
//!   `CreateItem` carries an empty placeholder (over a plain session, so nothing secret
//!   travels unencrypted); the real value follows with `SetSecret`.
//!
//! `Unlock` and `Prompt.Prompt` are never called.
//!
//! Calls carry no D-Bus-level timeout on purpose: a call that took too long may still be
//! carried out by the service, so the worker thread waits for the real answer. The caller is
//! released by the worker-thread timeout ([`bounded`]) and the cross-process locks stay held
//! until the worker is done (see [`crate::lock`]).
//!
//! The session bus comes from `DBUS_SESSION_BUS_ADDRESS`; when that is unset, zbus itself uses
//! `$XDG_RUNTIME_DIR/bus` (or `/run/user/<uid>/bus`) in-process, so SSH sessions work without
//! changing anybody's environment.
//!
//! Items carry the attributes `service` (the namespace) and `username` (the account), the
//! same layout keyring-rs uses, and the label `kc <account> (<namespace>)`.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use secret_service::EncryptionType;
use secret_service::blocking::SecretService;
use zbus::zvariant::{OwnedObjectPath, OwnedValue, Value};
use zeroize::Zeroizing;

use super::{Backend, ForeignItem, bounded, not_found};
use crate::config::StoreConfig;
use crate::error::{Result, StoreError};

const SERVICE_NAME: &str = "org.freedesktop.secrets";
const SERVICE_PATH: &str = "/org/freedesktop/secrets";
const SERVICE_IFACE: &str = "org.freedesktop.Secret.Service";
const COLLECTION_IFACE: &str = "org.freedesktop.Secret.Collection";
const ITEM_IFACE: &str = "org.freedesktop.Secret.Item";
const PROMPT_IFACE: &str = "org.freedesktop.Secret.Prompt";
const CONTENT_TYPE: &str = "application/octet-stream";

const TIMEOUT_HINT: &str = "The Secret Service (gnome-keyring or KeePassXC) is not responding; \
    restart it, e.g. `systemctl --user restart gnome-keyring-daemon`, and try again";
const LOCKED_HINT: &str = "kc never shows an unlock prompt. Unlock the keyring first: log in to \
    the desktop session, unlock it in Seahorse or KeePassXC, or run \
    `gnome-keyring-daemon --unlock` in this terminal, type the keyring password and press Ctrl-D";
const NO_BUS_HINT: &str = "kc needs your user's D-Bus session bus and a Secret Service. Over SSH \
    or in a headless session run `loginctl enable-linger $USER` so the user session and \
    $XDG_RUNTIME_DIR/bus stay up, then start gnome-keyring \
    (`systemctl --user start gnome-keyring-daemon`) or KeePassXC with Secret Service integration";
const NO_SERVICE_HINT: &str = "No Secret Service is running on the session bus. Start \
    gnome-keyring (`systemctl --user start gnome-keyring-daemon`) or enable KeePassXC's Secret \
    Service integration";
const OUTCOME_HINT: &str = "The Secret Service didn't confirm the change. Once it responds \
    again, check the value with `kc get`; kc holds off further changes for a short while";
const NO_DEFAULT_HINT: &str = "The Secret Service has no default collection. Create a keyring \
    and make it the default in Seahorse (\"Passwords and Keys\") or KeePassXC";

pub(crate) struct SecretServiceBackend {
    inner: Arc<Inner>,
}

struct Inner {
    /// One connection, shared by the client below and the raw calls.
    conn: zbus::blocking::Connection,
    /// Client with an encrypted session, for everything that carries a secret.
    ss: Mutex<SecretService<'static>>,
    /// A plain session, used only for the empty `CreateItem` placeholder.
    plain_session: OwnedObjectPath,
    namespace: String,
    timeout: Duration,
}

impl SecretServiceBackend {
    /// Connects and checks that the default collection exists.
    pub(crate) fn connect(cfg: &StoreConfig) -> Result<Self> {
        let timeout = cfg.effective_timeout();
        let namespace = cfg.namespace.clone();
        let inner = bounded(timeout, "connect", TIMEOUT_HINT, move || {
            check_bus_address()?;
            let conn = zbus::blocking::connection::Builder::session()
                .and_then(|builder| builder.build())
                .map_err(|err| bus_connect_error(&err, timeout))?;
            let ss = SecretService::connect_with_existing(EncryptionType::Dh, conn.clone())
                .map_err(|err| ss_error(err, "connect", timeout))?;
            let plain_session =
                open_plain_session(&conn).map_err(|err| zbus_error(&err, "connect", timeout))?;
            let inner = Inner {
                conn,
                ss: Mutex::new(ss),
                plain_session,
                namespace,
                timeout,
            };
            inner.default_collection("connect")?;
            Ok(Arc::new(inner))
        })?;
        Ok(SecretServiceBackend { inner })
    }

    fn call<T, F>(&self, op: &'static str, f: F) -> Result<T>
    where
        T: Send + 'static,
        F: FnOnce(&Inner) -> Result<T> + Send + 'static,
    {
        let inner = Arc::clone(&self.inner);
        let result = bounded(self.inner.timeout, op, TIMEOUT_HINT, move || f(&inner));
        if matches!(result, Err(StoreError::Timeout { .. })) {
            // A timed-out call keeps running on its worker thread (see [`super::bounded`]),
            // possibly mid `Properties.Get` or method call. Keep this process, and so its D-Bus
            // connection, alive until every such call has actually come back: a bounded wait is
            // not enough, because a request still in flight when the process exits closes the
            // connection under the daemon, and an orphaned property read crashes gnome-keyring
            // (see [`Inner::default_collection`]). This mirrors [`crate::lock`]'s keeper, which
            // already holds the cross-process locks until the same calls settle.
            super::drain_abandoned_calls();
        }
        result
    }
}

impl Backend for SecretServiceBackend {
    fn describe(&self) -> String {
        "Secret Service (org.freedesktop.secrets on the D-Bus session bus)".into()
    }

    /// `CreateItem` stores an empty placeholder and `SetSecret` fills it in.
    fn may_leave_empty_entries(&self) -> bool {
        true
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        let account = account.to_owned();
        self.call("read", move |inner| {
            match inner.own_item(&account, false, "read")? {
                Some(path) => inner.read_secret(&path, "read").map(Some),
                None => Ok(None),
            }
        })
    }

    fn set(&self, account: &str, blob: &[u8]) -> Result<()> {
        let account = account.to_owned();
        let blob = Zeroizing::new(blob.to_vec());
        self.call("write", move |inner| {
            match inner.own_item(&account, true, "write")? {
                Some(path) => inner.write_secret(&path, &blob, "write"),
                None => inner.create(&account, &blob),
            }
        })
    }

    fn delete(&self, account: &str) -> Result<bool> {
        let account = account.to_owned();
        self.call("delete", move |inner| {
            let paths = inner.search(&inner.attributes(&account), "delete")?;
            for path in &paths {
                inner.delete_path(path, "delete")?;
            }
            Ok(!paths.is_empty())
        })
    }

    fn exists(&self, account: &str) -> Result<bool> {
        let account = account.to_owned();
        self.call("lookup", move |inner| {
            Ok(!inner
                .search(&inner.attributes(&account), "lookup")?
                .is_empty())
        })
    }

    fn accounts(&self) -> Result<Vec<String>> {
        self.call("list", move |inner| {
            let spec = HashMap::from([("service", inner.namespace.as_str())]);
            let mut accounts = Vec::new();
            for path in inner.search(&spec, "list")? {
                // Errors propagate: an incomplete list would make garbage collection delete
                // live chunks.
                let attributes = inner.item_attributes(&path, "list")?;
                // An item in the namespace without a username wasn't written by kc.
                if let Some(account) = attributes.get("username") {
                    accounts.push(account.clone());
                }
            }
            Ok(accounts)
        })
    }

    /// Supported shapes: attributes `{service, account}` (what `secret-tool store` and most
    /// scripts write), `{service, username}` (keyring-rs, Python keyring), or, without an
    /// account, `{service}` alone when exactly one item has it.
    fn read_foreign(&self, service: &str, account: Option<&str>) -> Result<ForeignItem> {
        let service = service.to_owned();
        let account = account.map(str::to_owned);
        self.call("adopt", move |inner| {
            let specs: Vec<HashMap<&str, &str>> = match account.as_deref() {
                Some(account) => vec![
                    HashMap::from([("service", service.as_str()), ("account", account)]),
                    HashMap::from([("service", service.as_str()), ("username", account)]),
                ],
                None => vec![HashMap::from([("service", service.as_str())])],
            };
            let mut seen = HashSet::new();
            let mut found = Vec::new();
            for spec in &specs {
                for path in inner.search(spec, "adopt")? {
                    if seen.insert(path.clone()) {
                        found.push(path);
                    }
                }
            }
            match found.as_slice() {
                [] => Err(not_found(&service, account.as_deref())),
                [path] => {
                    let attributes = inner.item_attributes(path, "adopt")?;
                    let value = inner.read_secret(path, "adopt")?;
                    Ok(ForeignItem {
                        account: account_attribute(&attributes),
                        value,
                    })
                }
                many => {
                    let mut candidates = Vec::with_capacity(many.len());
                    for path in many {
                        let attributes = inner.item_attributes(path, "adopt")?;
                        candidates.push(account_attribute(&attributes).map_or_else(
                            || "(no account attribute)".to_owned(),
                            |account| format!("account={account}"),
                        ));
                    }
                    Err(StoreError::Ambiguous {
                        service: service.clone(),
                        candidates,
                    })
                }
            }
        })
    }
}

impl Inner {
    fn ss(&self) -> MutexGuard<'_, SecretService<'static>> {
        self.ss.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn attributes<'a>(&'a self, account: &'a str) -> HashMap<&'a str, &'a str> {
        HashMap::from([("service", self.namespace.as_str()), ("username", account)])
    }

    /// Unlocked items with exactly these attributes. A match in a locked collection is an
    /// error: reading or changing it would need an unlock, which kc never asks for.
    fn search(
        &self,
        attributes: &HashMap<&str, &str>,
        op: &'static str,
    ) -> Result<Vec<OwnedObjectPath>> {
        let ss = self.ss();
        let found = ss
            .search_items(attributes.clone())
            .map_err(|err| ss_error(err, op, self.timeout))?;
        if !found.locked.is_empty() {
            return Err(locked(format!(
                "{} matching item(s) are in a locked keyring",
                found.locked.len()
            )));
        }
        Ok(found
            .unlocked
            .iter()
            .map(|item| item.item_path.clone())
            .collect())
    }

    /// The item holding `account`, if any.
    ///
    /// Items are created with `replace = false`, so a creation that reached the service late
    /// (from a kc process that timed out and exited) adds an empty duplicate instead of
    /// blanking the real item. Empty duplicates are such leftovers: they are skipped, and
    /// deleted when `cleanup` is set (only by writers, which hold the exclusive lock).
    fn own_item(
        &self,
        account: &str,
        cleanup: bool,
        op: &'static str,
    ) -> Result<Option<OwnedObjectPath>> {
        let mut paths = self.search(&self.attributes(account), op)?;
        if paths.len() <= 1 {
            return Ok(paths.pop());
        }
        let mut filled = Vec::new();
        for path in paths {
            if !self.read_secret(&path, op)?.is_empty() {
                filled.push(path);
            } else if cleanup {
                self.delete_path(&path, op)?;
            }
        }
        match filled.len() {
            0 | 1 => Ok(filled.pop()),
            n => Err(StoreError::Backend {
                op,
                detail: format!(
                    "{n} keychain items share the account {account:?}; remove the duplicates \
                     (for example in Seahorse)"
                ),
            }),
        }
    }

    fn read_secret(&self, path: &OwnedObjectPath, op: &'static str) -> Result<Zeroizing<Vec<u8>>> {
        let ss = self.ss();
        let item = ss
            .get_item_by_path(path.clone())
            .map_err(|err| ss_error(err, op, self.timeout))?;
        item.get_secret()
            .map(Zeroizing::new)
            .map_err(|err| ss_error(err, op, self.timeout))
    }

    fn write_secret(&self, path: &OwnedObjectPath, secret: &[u8], op: &'static str) -> Result<()> {
        let ss = self.ss();
        let item = ss
            .get_item_by_path(path.clone())
            .map_err(|err| ss_error(err, op, self.timeout))?;
        item.set_secret(secret, CONTENT_TYPE)
            .map_err(|err| change_error(classify_ss(&err), err.to_string(), op, self.timeout))
    }

    fn item_attributes(
        &self,
        path: &OwnedObjectPath,
        op: &'static str,
    ) -> Result<HashMap<String, String>> {
        let ss = self.ss();
        let item = ss
            .get_item_by_path(path.clone())
            .map_err(|err| ss_error(err, op, self.timeout))?;
        item.get_attributes()
            .map_err(|err| ss_error(err, op, self.timeout))
    }

    /// The object path of the default collection, where new items go. Resolved with the
    /// `ReadAlias` method only: kc never reads the collection's `Locked` or `Label`
    /// properties.
    ///
    /// A `Properties.Get`/`GetAll` left in flight when its caller exits or times out crashes
    /// gnome-keyring 50: the daemon's idle property getter aborts (a GLib assertion) when the
    /// caller's record is already gone. So this backend issues method calls only, which the
    /// daemon answers with a plain D-Bus error in the same situation. A locked default
    /// collection is still reported without ever prompting or unlocking: reads find it in the
    /// `SearchItems` locked list (see [`Inner::search`]) and writes get a prompt object from
    /// `CreateItem` that kc dismisses (see [`Inner::create`]).
    fn default_collection(&self, op: &'static str) -> Result<OwnedObjectPath> {
        let reply = self
            .conn
            .call_method(
                Some(SERVICE_NAME),
                SERVICE_PATH,
                Some(SERVICE_IFACE),
                "ReadAlias",
                &"default",
            )
            .map_err(|err| zbus_error(&err, op, self.timeout))?;
        let path: OwnedObjectPath = reply
            .body()
            .deserialize()
            .map_err(|err| zbus_error(&err, op, self.timeout))?;
        if path.as_str() == "/" {
            return Err(StoreError::Unavailable {
                reason: "the Secret Service has no default collection".into(),
                hint: NO_DEFAULT_HINT.into(),
            });
        }
        Ok(path)
    }

    /// Creates the item for `account` in the default collection without ever prompting.
    fn create(&self, account: &str, secret: &[u8]) -> Result<()> {
        let collection = self.default_collection("write")?;
        let label = format!("kc {account} ({})", self.namespace);
        let mut properties: HashMap<&str, Value<'_>> = HashMap::new();
        properties.insert(
            "org.freedesktop.Secret.Item.Label",
            Value::from(label.as_str()),
        );
        properties.insert(
            "org.freedesktop.Secret.Item.Attributes",
            Value::from(self.attributes(account)),
        );
        // (session, parameters, value, content type) with an empty value.
        let placeholder = (
            &self.plain_session,
            Vec::<u8>::new(),
            Vec::<u8>::new(),
            CONTENT_TYPE,
        );
        let reply = self
            .conn
            .call_method(
                Some(SERVICE_NAME),
                collection.as_str(),
                Some(COLLECTION_IFACE),
                "CreateItem",
                // Never replace: see `own_item`.
                &(properties, placeholder, false),
            )
            .map_err(|err| {
                change_error(classify_zbus(&err), err.to_string(), "write", self.timeout)
            })?;
        let (item, prompt): (OwnedObjectPath, OwnedObjectPath) = reply
            .body()
            .deserialize()
            .map_err(|err| zbus_error(&err, "write", self.timeout))?;
        if item.as_str() == "/" {
            self.dismiss(&prompt);
            return Err(locked("the default keyring is locked".into()));
        }
        if let Err(err) = self.write_secret(&item, secret, "write") {
            // Don't leave the empty placeholder behind.
            let cleanup = self.delete_path(&item, "write");
            return Err(failed_creation(err, cleanup));
        }
        Ok(())
    }

    /// `Item.Delete`, without ever running the prompt it may return.
    fn delete_path(&self, path: &OwnedObjectPath, op: &'static str) -> Result<()> {
        let reply = self
            .conn
            .call_method(
                Some(SERVICE_NAME),
                path.as_str(),
                Some(ITEM_IFACE),
                "Delete",
                &(),
            )
            .map_err(|err| change_error(classify_zbus(&err), err.to_string(), op, self.timeout))?;
        let prompt: OwnedObjectPath = reply
            .body()
            .deserialize()
            .map_err(|err| zbus_error(&err, op, self.timeout))?;
        if prompt.as_str() != "/" {
            self.dismiss(&prompt);
            return Err(locked("the item is in a locked keyring".into()));
        }
        Ok(())
    }

    /// Withdraws a prompt object the service handed out. It was never shown.
    fn dismiss(&self, prompt: &OwnedObjectPath) {
        let _ = self.conn.call_method(
            Some(SERVICE_NAME),
            prompt.as_str(),
            Some(PROMPT_IFACE),
            "Dismiss",
            &(),
        );
    }
}

/// The error to report when filling a new item failed (`err`) and removing its placeholder
/// ended in `cleanup`. A cleanup whose outcome is unknown wins: a delete that may still land
/// must keep other processes away (see `crate::lock`), or it could remove their new value.
fn failed_creation(err: StoreError, cleanup: Result<()>) -> StoreError {
    match cleanup {
        Err(cleanup @ StoreError::OutcomeUnknown { .. }) => cleanup,
        _ => err,
    }
}

fn open_plain_session(conn: &zbus::blocking::Connection) -> zbus::Result<OwnedObjectPath> {
    let reply = conn.call_method(
        Some(SERVICE_NAME),
        SERVICE_PATH,
        Some(SERVICE_IFACE),
        "OpenSession",
        &("plain", Value::from("")),
    )?;
    let (_output, session): (OwnedValue, OwnedObjectPath) = reply.body().deserialize()?;
    Ok(session)
}

fn account_attribute(attributes: &HashMap<String, String>) -> Option<String> {
    ["account", "username", "user"]
        .iter()
        .find_map(|key| attributes.get(*key))
        .filter(|value| !value.is_empty())
        .cloned()
}

fn locked(what: String) -> StoreError {
    StoreError::Locked {
        what,
        hint: LOCKED_HINT.into(),
    }
}

/// Fails fast when there is clearly no session bus to talk to.
fn check_bus_address() -> Result<()> {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some() {
        return Ok(());
    }
    match std::env::var_os("XDG_RUNTIME_DIR") {
        Some(dir) if !dir.is_empty() => {
            let bus = Path::new(&dir).join("bus");
            if bus.exists() {
                Ok(())
            } else {
                Err(StoreError::Unavailable {
                    reason: format!(
                        "DBUS_SESSION_BUS_ADDRESS is unset and {} does not exist",
                        bus.display()
                    ),
                    hint: NO_BUS_HINT.into(),
                })
            }
        }
        // zbus falls back to /run/user/<uid>/bus; a failure there is reported by connect.
        _ => Ok(()),
    }
}

enum Class {
    Locked,
    NoBus,
    NoService,
    NoDefault,
    Timeout,
    Denied,
    Other,
}

fn classify_name(name: &str) -> Class {
    match name.rsplit('.').next().unwrap_or(name) {
        "ServiceUnknown" | "NameHasNoOwner" | "SpawnServiceNotFound" => Class::NoService,
        "NoReply" | "Timeout" | "TimedOut" => Class::Timeout,
        "NoServer" | "Disconnected" => Class::NoBus,
        "IsLocked" => Class::Locked,
        "AccessDenied" | "AuthFailed" => Class::Denied,
        _ => Class::Other,
    }
}

fn classify_zbus(err: &zbus::Error) -> Class {
    match err {
        zbus::Error::InputOutput(io) if io.kind() == std::io::ErrorKind::TimedOut => Class::Timeout,
        zbus::Error::InputOutput(_) | zbus::Error::Address(_) | zbus::Error::Handshake(_) => {
            Class::NoBus
        }
        zbus::Error::MethodError(name, _, _) => classify_name(name.as_str()),
        zbus::Error::FDO(fdo) => classify_fdo(fdo),
        _ => Class::Other,
    }
}

fn classify_fdo(err: &zbus::fdo::Error) -> Class {
    use zbus::fdo::Error as F;
    match err {
        F::ZBus(inner) => classify_zbus(inner),
        F::ServiceUnknown(_) | F::NameHasNoOwner(_) | F::SpawnServiceNotFound(_) => {
            Class::NoService
        }
        F::NoReply(_) | F::Timeout(_) | F::TimedOut(_) => Class::Timeout,
        F::NoServer(_) | F::Disconnected(_) | F::BadAddress(_) => Class::NoBus,
        F::AccessDenied(_) | F::AuthFailed(_) => Class::Denied,
        _ => Class::Other,
    }
}

fn classify_ss(err: &secret_service::Error) -> Class {
    use secret_service::Error as S;
    match err {
        S::Locked | S::Prompt => Class::Locked,
        S::Unavailable => Class::NoService,
        S::NoResult => Class::NoDefault,
        S::Zbus(inner) => classify_zbus(inner),
        S::ZbusFdo(inner) => classify_fdo(inner),
        _ => Class::Other,
    }
}

fn to_store_error(class: Class, detail: String, op: &'static str, timeout: Duration) -> StoreError {
    match class {
        Class::Locked => locked(detail),
        Class::NoBus => StoreError::Unavailable {
            reason: format!("cannot reach the D-Bus session bus ({detail})"),
            hint: NO_BUS_HINT.into(),
        },
        Class::NoService => StoreError::Unavailable {
            reason: format!("no Secret Service on the session bus ({detail})"),
            hint: NO_SERVICE_HINT.into(),
        },
        Class::NoDefault => StoreError::Unavailable {
            reason: format!("the Secret Service has no default collection ({detail})"),
            hint: NO_DEFAULT_HINT.into(),
        },
        Class::Timeout => StoreError::Timeout {
            op,
            timeout,
            hint: TIMEOUT_HINT.into(),
        },
        Class::Denied => StoreError::AccessDenied {
            op,
            detail,
            hint: LOCKED_HINT.into(),
        },
        Class::Other => StoreError::Backend { op, detail },
    }
}

/// For calls that change the keychain: no answer, or a connection that broke while waiting
/// for one, leaves the outcome unknown.
fn change_error(class: Class, detail: String, op: &'static str, timeout: Duration) -> StoreError {
    match class {
        Class::Timeout | Class::NoBus => StoreError::OutcomeUnknown {
            op,
            detail,
            hint: OUTCOME_HINT.into(),
        },
        class => to_store_error(class, detail, op, timeout),
    }
}

fn ss_error(err: secret_service::Error, op: &'static str, timeout: Duration) -> StoreError {
    to_store_error(classify_ss(&err), err.to_string(), op, timeout)
}

fn zbus_error(err: &zbus::Error, op: &'static str, timeout: Duration) -> StoreError {
    to_store_error(classify_zbus(err), err.to_string(), op, timeout)
}

/// Any failure to open the session bus connection (other than a timeout) means there is no
/// usable bus. zbus versions differ in how they report it, so don't match on the variant.
fn bus_connect_error(err: &zbus::Error, timeout: Duration) -> StoreError {
    let class = match classify_zbus(err) {
        Class::Timeout => Class::Timeout,
        _ => Class::NoBus,
    };
    to_store_error(class, err.to_string(), "connect", timeout)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unknown() -> StoreError {
        StoreError::OutcomeUnknown {
            op: "write",
            detail: "no reply".into(),
            hint: String::new(),
        }
    }

    #[test]
    fn an_unconfirmed_placeholder_cleanup_is_reported() {
        let refused = || StoreError::Backend {
            op: "write",
            detail: "refused".into(),
        };
        // Cleanup outcome unknown: that's what the caller must hear.
        assert!(failed_creation(refused(), Err(unknown())).leaves_doubt());
        // Otherwise the original failure stands, unknown or not.
        assert!(matches!(
            failed_creation(refused(), Ok(())),
            StoreError::Backend { .. }
        ));
        assert!(matches!(
            failed_creation(refused(), Err(refused())),
            StoreError::Backend { .. }
        ));
        assert!(failed_creation(unknown(), Ok(())).leaves_doubt());
    }

    #[test]
    fn changes_without_an_answer_have_an_unknown_outcome() {
        let timeout = Duration::from_secs(5);
        for class in [Class::Timeout, Class::NoBus] {
            assert!(change_error(class, "x".into(), "write", timeout).leaves_doubt());
        }
        assert!(matches!(
            change_error(Class::Locked, "x".into(), "write", timeout),
            StoreError::Locked { .. }
        ));
    }
}

//! [`Store`]: the public API over the keychain backend, the index and the lock.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::fs;
use std::path::Path;
use std::sync::{Arc, Mutex, PoisonError};

use zeroize::Zeroizing;

use crate::backend::Backend;
use crate::config::{DEFAULT_NAMESPACE, StoreConfig};
use crate::encoding::{self, Head, MAX_VALUE_LEN, Manifest, TAG_INLINE};
use crate::error::{Result, StoreError};
use crate::index::{self, Index, IndexFile, ItemInfo, ItemKind, Origin, PrevRecord, Record};
use crate::lock::Locks;
use crate::name::{Part, Slot, chunk_account, parse_account, validate_internal_key, validate_name};
use crate::secret::SecretValue;

/// Upper bound on chunk indices; every chunk holds at least one byte.
const MAX_CHUNKS: u32 = MAX_VALUE_LEN as u32;

/// What a write did.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Change {
    /// The item didn't exist.
    Created,
    /// The item had another value; that value is now the item's previous value.
    Updated,
    /// The item already held exactly this value. Nothing was written.
    Unchanged,
}

/// Result of [`Store::set`] and [`Store::adopt`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SetOutcome {
    pub change: Change,
    pub info: ItemInfo,
}

/// Differences between the keychain (the truth) and the index (the metadata cache).
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Drift {
    /// Index entries whose item no longer exists in the keychain.
    pub stale: Vec<ItemInfo>,
    /// Items in the keychain the index has no metadata for.
    pub unindexed: Vec<String>,
}

impl Drift {
    /// True when the index matches the keychain.
    pub fn is_clean(&self) -> bool {
        self.stale.is_empty() && self.unindexed.is_empty()
    }
}

/// What [`Store::reindex`] changed.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ReindexReport {
    /// Items that got index entries (with [`Origin::Unknown`]).
    pub added: Vec<String>,
    /// Index entries dropped because their item is gone.
    pub removed: Vec<String>,
    /// Leftover keychain entries deleted: chunks no value points at, `#prev` without a value.
    pub orphans_removed: usize,
    /// Whether an unreadable `index.json` was moved aside to `index.json.corrupt`.
    pub replaced_corrupt_index: bool,
}

/// Secrets in the OS keychain, plus a metadata index.
///
/// Opening a store doesn't touch the keychain; the first call that needs it connects (and
/// reports [`StoreError::Unavailable`] / [`StoreError::Locked`] if it can't). A store is
/// `Send + Sync`; calls from several threads are serialised.
///
/// Conflict policy is the caller's business: [`set`](Self::set) overwrites, keeping the
/// replaced value as the item's previous value (see [`restore`](Self::restore)).
pub struct Store {
    cfg: StoreConfig,
    index: Index,
    lock: Locks,
    backend: Mutex<Option<Arc<dyn Backend>>>,
}

impl fmt::Debug for Store {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Store")
            .field("namespace", &self.cfg.namespace)
            .field("config_dir", &self.cfg.config_dir)
            .field("interactive", &self.cfg.interactive)
            .finish_non_exhaustive()
    }
}

impl Store {
    /// Opens a store: validates `cfg` and creates the config directory (mode 0700 on Unix).
    pub fn open(cfg: StoreConfig) -> Result<Store> {
        cfg.validate()?;
        create_private_dir(&cfg.config_dir)?;
        Ok(Store {
            index: Index::new(&cfg.config_dir),
            lock: Locks::new(&cfg.config_dir)?,
            cfg,
            backend: Mutex::new(None),
        })
    }

    /// [`open`](Self::open) with [`StoreConfig::from_env`].
    pub fn open_default() -> Result<Store> {
        Store::open(StoreConfig::from_env()?)
    }

    /// A store on a test backend. Its locks live in the config directory, away from the real
    /// user-wide lock.
    #[cfg(any(test, feature = "test-util"))]
    pub(crate) fn with_backend(cfg: StoreConfig, backend: Arc<dyn Backend>) -> Result<Store> {
        cfg.validate()?;
        create_private_dir(&cfg.config_dir)?;
        Ok(Store {
            index: Index::new(&cfg.config_dir),
            lock: Locks::local(&cfg.config_dir),
            cfg,
            backend: Mutex::new(Some(backend)),
        })
    }

    /// The configuration this store was opened with.
    pub fn config(&self) -> &StoreConfig {
        &self.cfg
    }

    /// The keychain service name in use.
    pub fn namespace(&self) -> &str {
        &self.cfg.namespace
    }

    /// Connects to the keychain if needed and describes it, e.g.
    /// `Secret Service (org.freedesktop.secrets on the D-Bus session bus)`.
    pub fn backend_description(&self) -> Result<String> {
        Ok(self.backend()?.describe())
    }

    fn backend(&self) -> Result<Arc<dyn Backend>> {
        let mut slot = self.backend.lock().unwrap_or_else(PoisonError::into_inner);
        if let Some(backend) = slot.as_ref() {
            return Ok(Arc::clone(backend));
        }
        let backend = crate::backend::connect(&self.cfg)?;
        *slot = Some(Arc::clone(&backend));
        Ok(backend)
    }

    /// Stores `value` under `name`, replacing any current value.
    ///
    /// - The replaced value is kept as the previous value (one level; see [`restore`](Self::restore)).
    /// - Writing the value the item already holds changes nothing ([`Change::Unchanged`]).
    /// - The index is updated only after the keychain write succeeded.
    pub fn set(
        &self,
        name: &str,
        value: &[u8],
        kind: ItemKind,
        origin: Origin,
    ) -> Result<SetOutcome> {
        validate_name(name)?;
        validate_value(value)?;
        let backend = self.backend()?;
        self.lock.exclusive(self.cfg.lock_wait(), || {
            // Load first: a damaged index fails the write before the keychain is touched.
            let mut index = self.index.load()?;
            let change = write_slot(&*backend, Slot::Item(name), value, self.cfg.max_blob_len)?;
            let (info, dirty) =
                record_write(&mut index, &self.cfg.namespace, name, kind, origin, change);
            if dirty {
                self.index.save(&index)?;
            }
            Ok(SetOutcome { change, info })
        })
    }

    /// The current value of `name`, verified (format tag, length, sha256) before it's returned.
    pub fn get(&self, name: &str) -> Result<Option<SecretValue>> {
        validate_name(name)?;
        let backend = self.backend()?;
        let value = self.lock.shared(self.cfg.lock_wait(), || {
            read_slot(&*backend, &Slot::Item(name).account())
        })?;
        Ok(value.map(SecretValue::from))
    }

    /// Whether `name` exists in the keychain. Doesn't read the secret where the platform
    /// allows (macOS and Linux search by attributes).
    pub fn exists(&self, name: &str) -> Result<bool> {
        validate_name(name)?;
        self.backend()?.exists(&Slot::Item(name).account())
    }

    /// Index metadata for `name`. This is the cache: it can be stale or missing even when the
    /// item exists (see [`verify`](Self::verify)).
    pub fn info(&self, name: &str) -> Result<Option<ItemInfo>> {
        validate_name(name)?;
        let index = self
            .lock
            .shared(self.cfg.lock_wait(), || self.index.load())?;
        Ok(index
            .record(&self.cfg.namespace, name)
            .map(|record| record.info(name)))
    }

    /// Deletes `name`: its value, its previous value, every chunk, and its index entry.
    /// Returns whether anything existed.
    pub fn delete(&self, name: &str) -> Result<bool> {
        validate_name(name)?;
        let backend = self.backend()?;
        self.lock.exclusive(self.cfg.lock_wait(), || {
            let mut index = self.index.load()?;
            let existed = delete_slot(&*backend, Slot::Item(name))?;
            let had_record = index.remove(&self.cfg.namespace, name);
            if had_record {
                self.index.save(&index)?;
            }
            Ok(existed || had_record)
        })
    }

    /// Makes the previous value of `name` current again; the value it replaces becomes the
    /// previous value, so a second `restore` undoes the first. Fails with
    /// [`StoreError::NotFound`] when there is no previous value, and with
    /// [`StoreError::Corrupt`] (changing nothing) when the previous value doesn't verify.
    pub fn restore(&self, name: &str) -> Result<ItemInfo> {
        validate_name(name)?;
        let backend = self.backend()?;
        self.lock.exclusive(self.cfg.lock_wait(), || {
            let mut index = self.index.load()?;
            let had_current = restore_slot(&*backend, name)?;
            let info = record_restore(&mut index, &self.cfg.namespace, name, had_current);
            self.index.save(&index)?;
            Ok(info)
        })
    }

    /// Every item in the namespace, found with the keychain's own search and decorated with
    /// index metadata ([`Origin::Unknown`] where the index has none). Sorted by name.
    pub fn list(&self) -> Result<Vec<ItemInfo>> {
        let backend = self.backend()?;
        self.lock.shared(self.cfg.lock_wait(), || {
            let names = live_item_names(&backend.accounts()?);
            let index = self.index.load()?;
            Ok(names
                .iter()
                .map(|name| {
                    index
                        .record(&self.cfg.namespace, name)
                        .map_or_else(|| ItemInfo::unknown(name), |record| record.info(name))
                })
                .collect())
        })
    }

    /// Compares the index with the keychain. Read-only; [`reindex`](Self::reindex) fixes drift.
    pub fn verify(&self) -> Result<Drift> {
        let backend = self.backend()?;
        self.lock.shared(self.cfg.lock_wait(), || {
            let live = live_item_names(&backend.accounts()?);
            let index = self.index.load()?;
            let known = index.items(&self.cfg.namespace);
            let stale = known
                .into_iter()
                .flatten()
                .filter(|(name, _)| !live.contains(*name))
                .map(|(name, record)| record.info(name))
                .collect();
            let unindexed = live
                .iter()
                .filter(|name| known.is_none_or(|items| !items.contains_key(*name)))
                .cloned()
                .collect();
            Ok(Drift { stale, unindexed })
        })
    }

    /// Rebuilds the index from the keychain and removes leftover keychain entries (chunks of
    /// dropped generations, a `#prev` whose item is gone). Metadata of surviving items is kept;
    /// items without metadata get [`Origin::Unknown`]. A damaged `index.json` is moved aside to
    /// `index.json.corrupt` and rebuilt.
    pub fn reindex(&self) -> Result<ReindexReport> {
        let backend = self.backend()?;
        self.lock.exclusive(self.cfg.lock_wait(), || {
            let mut report = ReindexReport::default();
            let mut accounts = backend.accounts()?;
            report.orphans_removed = collect_garbage(&*backend, &accounts)?;
            if report.orphans_removed > 0 {
                // Garbage collection may have removed heads of unfinished creations.
                accounts = backend.accounts()?;
            }
            let live = live_item_names(&accounts);
            let mut index = match self.index.load() {
                Ok(index) => index,
                Err(StoreError::IndexCorrupt { .. }) => {
                    self.index.quarantine()?;
                    report.replaced_corrupt_index = true;
                    IndexFile::empty()
                }
                Err(err) => return Err(err),
            };
            let items = index.items_mut(&self.cfg.namespace);
            items.retain(|name, _| {
                let keep = live.contains(name);
                if !keep {
                    report.removed.push(name.clone());
                }
                keep
            });
            for name in &live {
                if !items.contains_key(name) {
                    items.insert(name.clone(), Record::unknown());
                    report.added.push(name.clone());
                }
            }
            index.prune();
            self.index.save(&index)?;
            Ok(report)
        })
    }

    /// Copies an entry some other program put in the OS keychain into this namespace as
    /// `as_name`, with [`Origin::Adopted`]. The original entry is left alone.
    ///
    /// - macOS: the generic password with this service and account.
    /// - Linux: an item with attributes `{service, account}` (`secret-tool store … service S
    ///   account A`) or `{service, username}` (keyring-rs, Python keyring).
    /// - Windows: target `<account>.<service>` (keyring-rs layout) or a generic credential
    ///   whose target is the service itself and whose user name is the account.
    ///
    /// Without an account, the single matching entry is used; several matches give
    /// [`StoreError::Ambiguous`] listing them, none gives [`StoreError::NotFound`]. On macOS,
    /// reading another program's item may need the "allow access" prompt, so non-interactive
    /// stores can get [`StoreError::InteractionRequired`]. The kind is [`ItemKind::Text`] for
    /// UTF-8 values and [`ItemKind::File`] otherwise.
    pub fn adopt(&self, service: &str, account: Option<&str>, as_name: &str) -> Result<SetOutcome> {
        validate_name(as_name)?;
        if service.is_empty() || account == Some("") {
            return Err(StoreError::InvalidName {
                what: "service or account to adopt",
                value: String::new(),
                rule: "must not be empty",
            });
        }
        let foreign = self.backend()?.read_foreign(service, account)?;
        let kind = if std::str::from_utf8(&foreign.value).is_ok() {
            ItemKind::Text
        } else {
            ItemKind::File
        };
        let origin = Origin::Adopted {
            service: service.to_owned(),
            account: foreign.account.clone(),
        };
        self.set(as_name, &foreign.value, kind, origin)
    }

    /// Stores an internal value (device private key, inbox read token) under `sys:<key>`.
    /// Internal values are never listed, have no previous value and no index entry.
    pub fn set_internal(&self, key: &str, value: &[u8]) -> Result<Change> {
        validate_internal_key(key)?;
        validate_value(value)?;
        let backend = self.backend()?;
        self.lock.exclusive(self.cfg.lock_wait(), || {
            write_slot(&*backend, Slot::Internal(key), value, self.cfg.max_blob_len)
        })
    }

    /// Reads an internal value.
    pub fn get_internal(&self, key: &str) -> Result<Option<SecretValue>> {
        validate_internal_key(key)?;
        let backend = self.backend()?;
        let value = self.lock.shared(self.cfg.lock_wait(), || {
            read_slot(&*backend, &Slot::Internal(key).account())
        })?;
        Ok(value.map(SecretValue::from))
    }

    /// Deletes an internal value. Returns whether it existed.
    pub fn delete_internal(&self, key: &str) -> Result<bool> {
        validate_internal_key(key)?;
        let backend = self.backend()?;
        self.lock.exclusive(self.cfg.lock_wait(), || {
            delete_slot(&*backend, Slot::Internal(key))
        })
    }

    /// Deletes every keychain entry in this store's namespace and drops its index section.
    /// For test namespaces: refuses [`DEFAULT_NAMESPACE`]. Returns the number of entries deleted.
    pub fn purge_namespace(&self) -> Result<usize> {
        if self.cfg.namespace == DEFAULT_NAMESPACE {
            return Err(StoreError::InvalidConfig(format!(
                "refusing to purge the default namespace {DEFAULT_NAMESPACE:?}"
            )));
        }
        let backend = self.backend()?;
        self.lock.exclusive(self.cfg.lock_wait(), || {
            let mut removed = 0;
            for account in backend.accounts()? {
                if backend.delete(&account)? {
                    removed += 1;
                }
            }
            match self.index.load() {
                Ok(mut index) => {
                    if index.namespaces.remove(&self.cfg.namespace).is_some() {
                        self.index.save(&index)?;
                    }
                }
                Err(StoreError::IndexCorrupt { .. }) => {}
                Err(err) => return Err(err),
            }
            Ok(removed)
        })
    }
}

fn validate_value(value: &[u8]) -> Result<()> {
    if value.is_empty() {
        return Err(StoreError::InvalidValue("the value is empty".into()));
    }
    if value.len() > MAX_VALUE_LEN {
        return Err(StoreError::InvalidValue(format!(
            "the value is {} bytes; the limit is {MAX_VALUE_LEN}",
            value.len()
        )));
    }
    Ok(())
}

fn create_private_dir(dir: &Path) -> Result<()> {
    let mut builder = fs::DirBuilder::new();
    builder.recursive(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::DirBuilderExt;
        builder.mode(0o700);
    }
    builder.create(dir).map_err(|err| StoreError::io(dir, err))
}

/// Names of the user items present in the keychain.
fn live_item_names(accounts: &[String]) -> BTreeSet<String> {
    accounts
        .iter()
        .filter_map(|account| parse_account(account))
        .filter(|parsed| !parsed.internal && parsed.part == Part::Current)
        .map(|parsed| parsed.name)
        .collect()
}

/// `(generation, chunk count)` of a manifest blob.
fn head_generation(blob: &[u8]) -> Option<(u64, u32)> {
    encoding::peek(blob).manifest().map(|m| (m.generation, m.n))
}

/// Writes `value` into `slot`:
///
/// 0. a restore that was interrupted is finished or rolled back first;
/// 1. chunks of a fresh, random generation, if the value doesn't fit inline; nothing points at
///    them yet;
/// 2. the replaced value is copied to `#prev` (user items only);
/// 3. the head (inline value or manifest) is written: from here on readers see the new value;
/// 4. generations neither head points at any more are deleted.
///
/// A failure before step 3 leaves the old value fully readable; a failure after it leaves
/// only garbage, which `delete` and `reindex` remove. Generations are random rather than
/// counted so that a write still pending at the keychain from an earlier, timed-out kc process
/// can never land on chunks of a newer value.
fn write_slot(
    backend: &dyn Backend,
    slot: Slot<'_>,
    value: &[u8],
    max_blob_len: usize,
) -> Result<Change> {
    recover_interrupted_restore(backend, slot)?;
    let base = slot.account();
    let current = fetch(backend, &base)?;
    if let Some(current) = &current
        && holds_value(backend, &base, current, value)?
    {
        return Ok(Change::Unchanged);
    }
    let prev_account = slot.prev_account();
    let prev = match &prev_account {
        Some(account) => fetch(backend, account)?,
        None => None,
    };
    let current_gen = current
        .as_deref()
        .map(Vec::as_slice)
        .and_then(head_generation);
    let prev_gen = prev.as_deref().map(Vec::as_slice).and_then(head_generation);
    let in_use: Vec<u64> = [current_gen, prev_gen]
        .into_iter()
        .flatten()
        .map(|(generation, _)| generation)
        .collect();
    let generation = fresh_generation(&in_use);

    let (head, chunks) = if encoding::needs_chunks(value.len(), max_blob_len) {
        let mut n: u32 = 0;
        for part in value.chunks(encoding::chunk_size(max_blob_len)) {
            backend.set(
                &chunk_account(&base, generation, n),
                &encoding::encode_chunk(part),
            )?;
            n += 1;
        }
        let manifest = Manifest::for_value(generation, n, value);
        (Zeroizing::new(encoding::encode_manifest(&manifest)), n)
    } else {
        (encoding::encode_inline(value), 0)
    };

    if let (Some(prev_account), Some(current)) = (&prev_account, &current) {
        backend.set(prev_account, current)?;
    }
    backend.set(&base, &head)?;

    // A #prev without a current value is left over from an interrupted delete.
    if let (Some(prev_account), None, Some(_)) = (&prev_account, &current, &prev) {
        backend.delete(prev_account)?;
    }

    // Generations the heads point at now: the new value's, and the old current value's if it
    // became #prev. Every other generation the old heads pointed at is garbage. (After an
    // interrupted write both old heads can point at the same generation; it must survive.)
    let new_prev_gen = match (&prev_account, &current) {
        (Some(_), Some(_)) => current_gen,
        _ => None,
    };
    let live = |candidate: u64| {
        (chunks > 0 && candidate == generation)
            || new_prev_gen.is_some_and(|(kept, _)| kept == candidate)
    };
    let mut dropped: Vec<(u64, u32)> = [current_gen, prev_gen].into_iter().flatten().collect();
    dropped.sort_unstable();
    dropped.dedup_by_key(|(dropped, _)| *dropped);
    for (old, n) in dropped {
        if !live(old) {
            delete_generation(backend, &base, old, n)?;
        }
    }
    Ok(if current.is_some() {
        Change::Updated
    } else {
        Change::Created
    })
}

/// Whether the head blob `head` (at `base`) already stores exactly `value`. Chunked values
/// are read back and compared, so a damaged copy is rewritten instead of reported unchanged.
fn holds_value(backend: &dyn Backend, base: &str, head: &[u8], value: &[u8]) -> Result<bool> {
    match encoding::peek(head) {
        Head::Inline(stored) => Ok(stored == value),
        Head::Manifest(manifest) if manifest.describes(value) => {
            match read_chunks(backend, base, base, &manifest) {
                Ok(stored) => Ok(stored.as_slice() == value),
                Err(StoreError::Corrupt { .. }) => Ok(false),
                Err(err) => Err(err),
            }
        }
        _ => Ok(false),
    }
}

/// A random generation number not in `in_use`. Random, not counted: see [`write_slot`].
fn fresh_generation(in_use: &[u64]) -> u64 {
    loop {
        let generation = rand::random_range(1..=u64::from(u32::MAX));
        if !in_use.contains(&generation) {
            return generation;
        }
    }
}

fn delete_generation(backend: &dyn Backend, base: &str, generation: u64, n: u32) -> Result<()> {
    for index in 0..n {
        backend.delete(&chunk_account(base, generation, index))?;
    }
    delete_chunks_from(backend, base, generation, n)
}

/// Deletes chunks `from`, `from + 1`, … of one generation until one is missing.
fn delete_chunks_from(backend: &dyn Backend, base: &str, generation: u64, from: u32) -> Result<()> {
    let mut index = from;
    while index <= MAX_CHUNKS && backend.delete(&chunk_account(base, generation, index))? {
        index += 1;
    }
    Ok(())
}

fn read_slot(backend: &dyn Backend, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    match fetch(backend, account)? {
        Some(blob) => decode_value(backend, account, account, blob).map(Some),
        None => Ok(None),
    }
}

/// Turns a head blob into its value. `chunk_base` is the account the chunks hang off:
/// `item:<name>` for both the current and the `#prev` value.
fn decode_value(
    backend: &dyn Backend,
    account: &str,
    chunk_base: &str,
    mut blob: Zeroizing<Vec<u8>>,
) -> Result<Zeroizing<Vec<u8>>> {
    if blob.first() == Some(&TAG_INLINE) {
        // In place: no second copy of the secret.
        blob.remove(0);
        return Ok(blob);
    }
    match encoding::peek(&blob) {
        Head::Manifest(manifest) => read_chunks(backend, account, chunk_base, &manifest),
        Head::Unreadable(reason) => Err(StoreError::corrupt(account, reason)),
        Head::Inline(_) => unreachable!("inline values are handled above"),
    }
}

/// Reassembles a chunked value and checks its length and sha256.
fn read_chunks(
    backend: &dyn Backend,
    account: &str,
    chunk_base: &str,
    manifest: &Manifest,
) -> Result<Zeroizing<Vec<u8>>> {
    // `len <= MAX_VALUE_LEN` was checked when the manifest was parsed.
    let len = manifest.len as usize;
    // Full capacity up front: growing the vector would leave unwiped copies behind.
    let mut value = Zeroizing::new(Vec::with_capacity(len));
    for index in 0..manifest.n {
        let chunk = chunk_account(chunk_base, manifest.generation, index);
        let blob = fetch(backend, &chunk)?.ok_or_else(|| {
            StoreError::corrupt(
                account,
                format!(
                    "chunk {index} of {} (generation {}) is missing",
                    manifest.n, manifest.generation
                ),
            )
        })?;
        let part = encoding::chunk_payload(&chunk, &blob)?;
        if value.len() + part.len() > len {
            return Err(StoreError::corrupt(
                account,
                "the chunks are longer than the manifest says",
            ));
        }
        value.extend_from_slice(part);
    }
    if value.len() != len {
        return Err(StoreError::corrupt(
            account,
            "the chunks are shorter than the manifest says",
        ));
    }
    if encoding::sha256_hex(&value) != manifest.sha256 {
        return Err(StoreError::corrupt(account, "sha256 mismatch"));
    }
    Ok(value)
}

/// Deletes a slot: the head first (from then on the value is gone), then `#prev`, then every
/// remaining `<account>#…` entry the keychain's search finds (all chunk generations and
/// leftovers of interrupted writes).
fn delete_slot(backend: &dyn Backend, slot: Slot<'_>) -> Result<bool> {
    let base = slot.account();
    let mut existed = backend.delete(&base)?;
    if let Some(prev) = slot.prev_account() {
        existed |= backend.delete(&prev)?;
    }
    let prefix = format!("{base}#");
    for account in backend.accounts()? {
        if account.starts_with(&prefix) {
            existed |= backend.delete(&account)?;
        }
    }
    Ok(existed)
}

/// Swaps the current and previous values of an item. Returns whether there was a current value.
///
/// Crash-safe: the value being displaced is copied to `#swap` before anything else changes,
/// so at every moment both values are stored somewhere. An interrupted restore is finished
/// (or rolled back) by the next write, restore or reindex of the item.
fn restore_slot(backend: &dyn Backend, name: &str) -> Result<bool> {
    let slot = Slot::Item(name);
    recover_interrupted_restore(backend, slot)?;
    let base = slot.account();
    let prev_account = slot
        .prev_account()
        .expect("user items keep a previous value");
    let swap_account = slot.swap_account().expect("user items have a swap slot");
    let Some(prev) = fetch(backend, &prev_account)? else {
        return Err(StoreError::NotFound(format!(
            "{name:?} has no previous value to restore"
        )));
    };
    // Don't make something unreadable current.
    decode_value(backend, &prev_account, &base, prev.clone())?;
    let current = fetch(backend, &base)?;
    match &current {
        Some(current) => {
            backend.set(&swap_account, current)?;
            backend.set(&base, &prev)?;
            backend.set(&prev_account, current)?;
            backend.delete(&swap_account)?;
        }
        None => {
            backend.set(&base, &prev)?;
            backend.delete(&prev_account)?;
        }
    }
    Ok(current.is_some())
}

/// Finishes or rolls back a restore that stopped half-way (see [`restore_slot`]).
fn recover_interrupted_restore(backend: &dyn Backend, slot: Slot<'_>) -> Result<()> {
    let (Some(swap_account), Some(prev_account)) = (slot.swap_account(), slot.prev_account())
    else {
        return Ok(());
    };
    // The common case, cheaply: no restore was interrupted.
    if !backend.exists(&swap_account)? {
        return Ok(());
    }
    // An empty #swap is one whose creation was cut off: the restore never got further.
    if let Some(swap) = fetch(backend, &swap_account)? {
        match fetch(backend, &slot.account())? {
            // The restore had already made the previous value current: the displaced value,
            // kept in #swap, becomes the previous value.
            Some(current) if current != swap => backend.set(&prev_account, &swap)?,
            // It stopped before that, or the item was being deleted: nothing to finish.
            _ => {}
        }
    }
    backend.delete(&swap_account)?;
    Ok(())
}

/// Reads one entry. An empty entry counts as absent: kc never stores an empty blob (every
/// blob has a format tag), but on the Secret Service an item is created empty and filled in
/// a second call, so an interrupted creation leaves one behind.
fn fetch(backend: &dyn Backend, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
    Ok(backend.get(account)?.filter(|blob| !blob.is_empty()))
}

/// Deletes keychain entries nothing points at. Returns how many were deleted.
fn collect_garbage(backend: &dyn Backend, accounts: &[String]) -> Result<usize> {
    #[derive(Default)]
    struct Owned {
        current: bool,
        prev: bool,
        swap: bool,
        chunks: Vec<(u64, u32, String)>,
    }
    let mut groups: BTreeMap<(bool, String), Owned> = BTreeMap::new();
    for account in accounts {
        let Some(parsed) = parse_account(account) else {
            continue;
        };
        let group = groups.entry((parsed.internal, parsed.name)).or_default();
        match parsed.part {
            Part::Current => group.current = true,
            Part::Prev => group.prev = true,
            Part::Swap => group.swap = true,
            Part::Chunk { generation, index } => {
                group.chunks.push((generation, index, account.clone()))
            }
        }
    }
    let mut removed = 0;
    for ((internal, name), group) in groups {
        let slot = if internal {
            Slot::Internal(&name)
        } else {
            Slot::Item(&name)
        };
        let mut has_value = group.current;
        let companions = group.prev || group.swap || !group.chunks.is_empty();
        if has_value && (companions || backend.may_leave_empty_entries()) {
            // An empty head is a creation that was cut off: the item never got a value.
            has_value = fetch(backend, &slot.account())?.is_some();
        }
        if !has_value {
            // No value: everything left is debris of an interrupted delete or creation.
            let leftovers = [
                group.current.then(|| slot.account()),
                slot.prev_account().filter(|_| group.prev),
                slot.swap_account().filter(|_| group.swap),
            ];
            let chunks = group.chunks.iter().map(|(_, _, account)| account.clone());
            for account in leftovers.into_iter().flatten().chain(chunks) {
                if backend.delete(&account)? {
                    removed += 1;
                }
            }
            continue;
        }
        if group.swap {
            recover_interrupted_restore(backend, slot)?;
            removed += 1;
        }
        if group.chunks.is_empty() {
            continue;
        }
        // Chunks the heads point at: indices below `n` of each manifest's generation.
        let heads = [Some(slot.account()), slot.prev_account()];
        let mut live: BTreeMap<u64, u32> = BTreeMap::new();
        let mut understood = true;
        for head in heads.iter().flatten() {
            if let Some(blob) = fetch(backend, head)? {
                match encoding::peek(&blob) {
                    Head::Manifest(manifest) => {
                        // Both heads can point at one generation (after an interrupted write):
                        // keep every chunk either of them needs.
                        let n = live.entry(manifest.generation).or_insert(0);
                        *n = (*n).max(manifest.n);
                    }
                    Head::Inline(_) => {}
                    // Written by a newer kc, or damaged: don't guess which chunks it needs.
                    Head::Unreadable(_) => understood = false,
                }
            }
        }
        if !understood {
            continue;
        }
        for (generation, index, account) in &group.chunks {
            let referenced = live.get(generation).is_some_and(|n| index < n);
            if !referenced && backend.delete(account)? {
                removed += 1;
            }
        }
    }
    Ok(removed)
}

/// Updates the index after a successful write. Returns the item's metadata and whether the
/// index changed.
fn record_write(
    index: &mut IndexFile,
    namespace: &str,
    name: &str,
    kind: ItemKind,
    origin: Origin,
    change: Change,
) -> (ItemInfo, bool) {
    let now = index::now();
    let items = index.items_mut(namespace);
    let record = match change {
        Change::Unchanged => {
            if let Some(record) = items.get(name) {
                return (record.info(name), false);
            }
            // The keychain already had this value but the index didn't know the item.
            Record {
                kind,
                origin,
                created_at: None,
                updated_at: None,
                prev: None,
            }
        }
        Change::Created => Record {
            kind,
            origin,
            created_at: Some(now),
            updated_at: Some(now),
            prev: None,
        },
        Change::Updated => {
            let old = items.remove(name);
            let prev = match &old {
                Some(old) => PrevRecord {
                    kind: old.kind,
                    origin: old.origin.clone(),
                    updated_at: old.updated_at,
                },
                None => PrevRecord {
                    kind: ItemKind::Text,
                    origin: Origin::Unknown,
                    updated_at: None,
                },
            };
            Record {
                kind,
                origin,
                created_at: old.and_then(|old| old.created_at),
                updated_at: Some(now),
                prev: Some(prev),
            }
        }
    };
    let info = record.info(name);
    items.insert(name.to_owned(), record);
    (info, true)
}

/// Swaps current and previous metadata after a successful restore.
fn record_restore(
    index: &mut IndexFile,
    namespace: &str,
    name: &str,
    had_current: bool,
) -> ItemInfo {
    let now = index::now();
    let items = index.items_mut(namespace);
    let old = items.remove(name);
    let (restored, created_at) = match &old {
        Some(old) => (old.prev.clone(), old.created_at),
        None => (None, None),
    };
    let restored = restored.unwrap_or(PrevRecord {
        kind: ItemKind::Text,
        origin: Origin::Unknown,
        updated_at: None,
    });
    let prev = match (had_current, &old) {
        (true, Some(old)) => Some(PrevRecord {
            kind: old.kind,
            origin: old.origin.clone(),
            updated_at: old.updated_at,
        }),
        (true, None) => Some(PrevRecord {
            kind: ItemKind::Text,
            origin: Origin::Unknown,
            updated_at: None,
        }),
        (false, _) => None,
    };
    let record = Record {
        kind: restored.kind,
        origin: restored.origin,
        created_at: created_at.or(Some(now)),
        updated_at: Some(now),
        prev,
    };
    let info = record.info(name);
    items.insert(name.to_owned(), record);
    info
}

#[cfg(test)]
mod tests;

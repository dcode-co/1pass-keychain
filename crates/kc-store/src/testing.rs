//! An in-memory keychain for tests (feature `test-util`; always on for this crate's own tests).
//!
//! Values live only in process memory and vanish with it. This exists so code that uses
//! kc-store can be tested without an OS keychain. It is never selected automatically: the
//! only way in is [`Store::open_with_memory_backend`].

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};

use zeroize::Zeroizing;

use crate::backend::{Backend, ForeignItem};
use crate::config::StoreConfig;
use crate::error::{Result, StoreError};
use crate::store::Store;

/// A shared in-memory keychain. Clones share contents, so two [`Store`]s opened on clones of
/// one `MemoryBackend` see each other's writes, like two processes on one OS keychain.
#[derive(Clone, Default)]
pub struct MemoryBackend {
    state: Arc<Mutex<State>>,
}

#[derive(Default)]
struct State {
    entries: BTreeMap<(String, String), Zeroizing<Vec<u8>>>,
    writes: usize,
    writes_left: Option<usize>,
}

impl MemoryBackend {
    /// An empty keychain.
    pub fn new() -> Self {
        Self::default()
    }

    /// Stores an entry directly, under any service (for example a "foreign" entry to adopt).
    pub fn insert(&self, service: &str, account: &str, blob: &[u8]) {
        self.lock().entries.insert(
            (service.to_owned(), account.to_owned()),
            Zeroizing::new(blob.to_vec()),
        );
    }

    /// The raw stored blob (format tag included).
    pub fn raw(&self, service: &str, account: &str) -> Option<Zeroizing<Vec<u8>>> {
        self.lock()
            .entries
            .get(&(service.to_owned(), account.to_owned()))
            .cloned()
    }

    /// Removes an entry directly. Returns whether it existed.
    pub fn remove(&self, service: &str, account: &str) -> bool {
        self.lock()
            .entries
            .remove(&(service.to_owned(), account.to_owned()))
            .is_some()
    }

    /// The accounts stored under `service`, sorted.
    pub fn accounts(&self, service: &str) -> Vec<String> {
        self.lock()
            .entries
            .keys()
            .filter(|(s, _)| s == service)
            .map(|(_, account)| account.clone())
            .collect()
    }

    /// How many writes have succeeded so far.
    pub fn writes(&self) -> usize {
        self.lock().writes
    }

    /// Lets the next `n` writes succeed, then fails every write until
    /// [`allow_writes`](Self::allow_writes).
    pub fn fail_writes_after(&self, n: usize) {
        self.lock().writes_left = Some(n);
    }

    /// Undoes [`fail_writes_after`](Self::fail_writes_after).
    pub fn allow_writes(&self) {
        self.lock().writes_left = None;
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.state.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

impl Store {
    /// Opens a store on `memory` instead of the OS keychain. For tests only.
    pub fn open_with_memory_backend(cfg: StoreConfig, memory: &MemoryBackend) -> Result<Store> {
        let backend = Arc::new(Namespaced {
            memory: memory.clone(),
            namespace: cfg.namespace.clone(),
        });
        Store::with_backend(cfg, backend)
    }
}

struct Namespaced {
    memory: MemoryBackend,
    namespace: String,
}

impl Namespaced {
    fn key(&self, account: &str) -> (String, String) {
        (self.namespace.clone(), account.to_owned())
    }
}

impl Backend for Namespaced {
    fn describe(&self) -> String {
        "in-memory test keychain".into()
    }

    /// Like the Secret Service, so tests cover the cleanup of half-made entries.
    fn may_leave_empty_entries(&self) -> bool {
        true
    }

    fn get(&self, account: &str) -> Result<Option<Zeroizing<Vec<u8>>>> {
        Ok(self.memory.lock().entries.get(&self.key(account)).cloned())
    }

    fn set(&self, account: &str, blob: &[u8]) -> Result<()> {
        let mut state = self.memory.lock();
        if let Some(left) = state.writes_left.as_mut() {
            if *left == 0 {
                return Err(StoreError::Backend {
                    op: "write",
                    detail: "injected write failure".into(),
                });
            }
            *left -= 1;
        }
        state.writes += 1;
        state
            .entries
            .insert(self.key(account), Zeroizing::new(blob.to_vec()));
        Ok(())
    }

    fn delete(&self, account: &str) -> Result<bool> {
        Ok(self
            .memory
            .lock()
            .entries
            .remove(&self.key(account))
            .is_some())
    }

    fn exists(&self, account: &str) -> Result<bool> {
        Ok(self.memory.lock().entries.contains_key(&self.key(account)))
    }

    fn accounts(&self) -> Result<Vec<String>> {
        Ok(self.memory.accounts(&self.namespace))
    }

    fn read_foreign(&self, service: &str, account: Option<&str>) -> Result<ForeignItem> {
        let state = self.memory.lock();
        let found: Vec<(&String, &Zeroizing<Vec<u8>>)> = state
            .entries
            .iter()
            .filter(|((s, a), _)| s == service && account.is_none_or(|want| a == want))
            .map(|((_, a), value)| (a, value))
            .collect();
        match found.as_slice() {
            [] => Err(StoreError::NotFound(format!(
                "no keychain entry with service {service:?}"
            ))),
            [(account, value)] => Ok(ForeignItem {
                account: Some((*account).clone()),
                value: (*value).clone(),
            }),
            many => Err(StoreError::Ambiguous {
                service: service.to_owned(),
                candidates: many.iter().map(|(a, _)| format!("account={a}")).collect(),
            }),
        }
    }
}

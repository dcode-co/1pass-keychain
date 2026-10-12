//! [`Keychain`]: the kc-store [`Store`] as the commands use it. Each call holds
//! [`interrupt::keychain_call`], so Ctrl-C waits for it instead of cutting a keychain write
//! short.

use kc_store::{
    Drift, ItemInfo, ItemKind, Origin, ReindexReport, Result, SecretValue, SetOutcome, Store,
};

use crate::interrupt::keychain_call;

pub struct Keychain {
    store: Store,
}

impl Keychain {
    pub fn new(store: Store) -> Keychain {
        Keychain { store }
    }

    pub fn namespace(&self) -> &str {
        self.store.namespace()
    }

    pub fn backend_description(&self) -> Result<String> {
        let _call = keychain_call();
        self.store.backend_description()
    }

    pub fn set(
        &self,
        name: &str,
        value: &[u8],
        kind: ItemKind,
        origin: Origin,
    ) -> Result<SetOutcome> {
        let _call = keychain_call();
        self.store.set(name, value, kind, origin)
    }

    pub fn get(&self, name: &str) -> Result<Option<SecretValue>> {
        let _call = keychain_call();
        self.store.get(name)
    }

    pub fn exists(&self, name: &str) -> Result<bool> {
        let _call = keychain_call();
        self.store.exists(name)
    }

    pub fn info(&self, name: &str) -> Result<Option<ItemInfo>> {
        let _call = keychain_call();
        self.store.info(name)
    }

    pub fn delete(&self, name: &str) -> Result<bool> {
        let _call = keychain_call();
        self.store.delete(name)
    }

    pub fn restore(&self, name: &str) -> Result<ItemInfo> {
        let _call = keychain_call();
        self.store.restore(name)
    }

    pub fn list(&self) -> Result<Vec<ItemInfo>> {
        let _call = keychain_call();
        self.store.list()
    }

    pub fn verify(&self) -> Result<Drift> {
        let _call = keychain_call();
        self.store.verify()
    }

    pub fn reindex(&self) -> Result<ReindexReport> {
        let _call = keychain_call();
        self.store.reindex()
    }

    pub fn adopt(&self, service: &str, account: Option<&str>, as_name: &str) -> Result<SetOutcome> {
        let _call = keychain_call();
        self.store.adopt(service, account, as_name)
    }

    pub fn set_internal(&self, key: &str, value: &[u8]) -> Result<kc_store::Change> {
        let _call = keychain_call();
        self.store.set_internal(key, value)
    }

    pub fn get_internal(&self, key: &str) -> Result<Option<SecretValue>> {
        let _call = keychain_call();
        self.store.get_internal(key)
    }

    pub fn delete_internal(&self, key: &str) -> Result<bool> {
        let _call = keychain_call();
        self.store.delete_internal(key)
    }
}

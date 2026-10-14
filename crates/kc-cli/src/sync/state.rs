//! Public metadata contains neither values nor HMAC fingerprints. Secret transaction
//! records live in immutable keychain slots, referenced by the durable journal pointer.
use crate::{commands::Ctx, error::Result, host::Host, state::StateDir};
use kc_proto::sync::{AckResult, ChangeId, ItemKind, Vid};
use kc_sync::{Generations, Limiter, Outbox, SlotKind};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Serialize, Deserialize)]
pub struct Item {
    pub head: Vid,
    pub lineage: Vec<Vid>,
    pub parents: Vec<Vid>,
    pub known: Vec<Vid>,
    pub scope: BTreeSet<String>,
    pub own: bool,
    pub conflict: bool,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Version {
    pub name: String,
    pub vid: Vid,
    pub parents: Vec<Vid>,
    pub lineage: Vec<Vid>,
    pub kind: ItemKind,
    pub slot: String,
}
#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    Proposal,
    Held,
    Conflict,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Candidate {
    pub peer: String,
    pub version: Version,
    pub generation: u64,
    pub category: CandidateKind,
    pub base_head: Option<Vid>,
    pub base_record: String,
    pub retire: bool,
    pub legacy: bool,
    #[serde(default)]
    pub invalid_binding: bool,
}
#[derive(Clone, Default, Serialize, Deserialize)]
pub struct Peer {
    pub hello_sent: bool,
    pub capable: bool,
    pub enabled: bool,
    pub last_digest: Option<i64>,
    pub reoffer: BTreeSet<String>,
    pub quarantine: BTreeSet<String>,
}
// These are intentionally NOT SyncMsg: that wire enum can contain secret values.
#[derive(Clone, Serialize, Deserialize)]
pub enum Control {
    Hello { reply: bool },
    Accept { name: String, generation: u64 },
    Leave { name: String, generation: u64 },
    Ack { id: ChangeId, result: AckResult },
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Offer {
    pub peer: String,
    pub name: String,
    pub vid: Vid,
}
#[derive(Clone, Serialize, Deserialize)]
pub struct Journal {
    pub record: String,
    pub name: String,
}
#[derive(Default, Serialize, Deserialize)]
pub struct State {
    pub frozen: bool,
    #[serde(default)]
    pub proposals_today: BTreeMap<String, Vec<i64>>,
    #[serde(default)]
    pub receipts: BTreeMap<String, (AckResult, i64)>,
    #[serde(default)]
    pub attempts: BTreeMap<String, i64>,
    #[serde(default)]
    pub deferred: BTreeSet<String>,
    #[serde(default)]
    pub rejected_offers: BTreeSet<String>,
    /// Expiry of each `rejected_offers` entry, kept apart so older versions still read it.
    #[serde(default)]
    pub rejected_until: BTreeMap<String, i64>,
    #[serde(default)]
    pub unbound: BTreeSet<String>,
    /// `name:vid` bindings that left known while something else still referred to them;
    /// deleted once nothing does. Bounded per item by its lineage (64), versions and
    /// candidates.
    #[serde(default)]
    pub(crate) unbind_watch: BTreeSet<String>,
    pub items: BTreeMap<String, Item>,
    pub peers: BTreeMap<String, Peer>,
    pub generations: Generations,
    pub outbox: Outbox,
    pub limiter: Limiter,
    pub versions: BTreeMap<String, Version>,
    #[serde(default)]
    pub latest_local: BTreeMap<String, Vid>,
    pub offers: Vec<Offer>,
    pub controls: Vec<(String, Control)>,
    pub candidates: BTreeMap<String, Candidate>,
    pub slots: BTreeMap<String, SlotKind>,
    pub journal: Option<Journal>,
    pub capacity_blocked: bool,
    pub reconnect: bool,
    /// The last delivery attempt failed; cleared by the next flush that reaches every peer.
    #[serde(default)]
    pub delivery_failed: bool,
    pub gc: BTreeSet<String>,
}
impl State {
    pub fn load(dir: &StateDir) -> Result<Self> {
        let path = dir.root().join("sync.json");
        match std::fs::read(path) {
            Ok(bytes) => serde_json::from_slice(&bytes).map_err(|_| super::state_error()),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Self::default()),
            Err(_) => Err(super::state_error()),
        }
    }
    pub fn save(&self, dir: &StateDir) -> Result<()> {
        crate::state::create_private_dir(dir.root())?;
        let bytes = serde_json::to_vec_pretty(self).map_err(|_| super::state_error())?;
        crate::state::write_private_atomic(&dir.root().join("sync.json"), &bytes)
            .map_err(|_| super::state_error())
    }
    pub fn cleanup<H: Host>(&mut self, ctx: &Ctx<'_, H>) -> Result<()> {
        super::prune(self, ctx.host.now());
        // Deletion gate: a binding queued for deletion may have become live again in the
        // same transaction (an accepted proposal evicted by its own checkpoint reservation,
        // or a rejected vid that an accepted lineage names). Known bindings are left to
        // trim_known; the others are watched until nothing refers to them.
        let known: BTreeSet<String> = self
            .items
            .iter()
            .flat_map(|(name, i)| i.known.iter().map(|vid| super::record_slot(name, *vid)))
            .collect();
        let referenced: BTreeMap<String, (String, Vid)> = self
            .items
            .iter()
            .flat_map(|(name, i)| {
                std::iter::once(i.head)
                    .chain(i.lineage.iter().copied())
                    .map(move |vid| (name.clone(), vid))
            })
            .chain(self.versions.values().map(|v| (v.name.clone(), v.vid)))
            .chain(
                self.candidates
                    .values()
                    .map(|c| (c.version.name.clone(), c.version.vid)),
            )
            .map(|(name, vid)| (super::record_slot(&name, vid), (name, vid)))
            .collect();
        for slot in std::mem::take(&mut self.gc) {
            if known.contains(&slot) {
                continue;
            }
            if let Some((name, vid)) = referenced.get(&slot) {
                self.unbind_watch.insert(super::binding_key(name, *vid));
                continue;
            }
            self.gc.insert(slot);
        }
        // Metadata is durable before deletion. A restart repeats only harmless deletes.
        self.save(&ctx.state)?;
        for slot in &self.gc {
            ctx.store.delete_internal(slot)?;
        }
        self.gc.clear();
        self.save(&ctx.state)
    }
}

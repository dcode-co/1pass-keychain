use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Deserializer, Serialize, Serializer};
use crate::{AckResult, PeerId, Vid};

/// Exact receiver-specific change identity; vids are random, not chronological (§12.3).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ChangeId {
    /// Item name (§12.3).
    pub name: String,
    /// Target receiver's accepted generation (§12.2).
    pub generation: u64,
    /// Immutable version being delivered (§12.3).
    pub new_vid: Vid,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Delivery { order: u64, final_ack: Option<AckResult> }

/// Per-peer queues and all-target snapshot retention; contains no values (§2.8, §12.3).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Outbox {
    #[serde(serialize_with = "serialize_deliveries", deserialize_with = "deserialize_deliveries")]
    deliveries: BTreeMap<PeerId, BTreeMap<ChangeId, Delivery>>,
    reoffer: BTreeMap<PeerId, BTreeSet<String>>,
    next_order: u64,
}

fn serialize_deliveries<S: Serializer>(deliveries: &BTreeMap<PeerId, BTreeMap<ChangeId, Delivery>>, s: S) -> Result<S::Ok, S::Error> {
    deliveries.iter().map(|(peer, queue)| (peer, queue.iter().collect::<Vec<_>>())).collect::<Vec<_>>().serialize(s)
}

fn deserialize_deliveries<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<PeerId, BTreeMap<ChangeId, Delivery>>, D::Error> {
    let peers = Vec::<(PeerId, Vec<(ChangeId, Delivery)>)>::deserialize(d)?;
    let mut result = BTreeMap::new();
    for (peer, entries) in peers {
        let count = entries.len();
        let queue: BTreeMap<_, _> = entries.into_iter().collect();
        if queue.len() != count || result.insert(peer, queue).is_some() {
            return Err(serde::de::Error::custom("duplicate outbox identity"));
        }
    }
    Ok(result)
}

impl Outbox {
    /// Adds an exact target delivery; repeated enqueue does not reset its ACK (§2.8, §12.3).
    pub fn enqueue(&mut self, peer: PeerId, change: ChangeId) {
        if self.deliveries.get(&peer).is_some_and(|q| q.contains_key(&change)) { return; }
        // Renumbering is unnecessary in practice, but exhaustion must never invert ordering.
        if self.next_order == u64::MAX {
            let mut orders: Vec<_> = self.deliveries.values().flat_map(|q| q.values().map(|d| d.order)).collect();
            orders.sort_unstable();
            orders.dedup();
            for queue in self.deliveries.values_mut() {
                for entry in queue.values_mut() { entry.order = orders.binary_search(&entry.order).unwrap() as u64; }
            }
            self.next_order = orders.len() as u64;
        }
        self.deliveries.entry(peer).or_default().insert(change, Delivery { order: self.next_order, final_ack: None });
        self.next_order += 1;
    }

    /// Applies a final exact ACK and supersedes only earlier entries for this peer/name (§12.3).
    pub fn ack(&mut self, peer: &PeerId, change: &ChangeId, result: AckResult) -> bool {
        if !result.is_final() { return false; }
        let Some(queue) = self.deliveries.get_mut(peer) else { return false; };
        let Some(delivery) = queue.get(change) else { return false; };
        if delivery.final_ack.is_some() { return false; }
        let order = delivery.order;
        for (id, delivery) in queue.iter_mut() {
            if id.name == change.name && delivery.order <= order && delivery.final_ack.is_none() {
                delivery.final_ack = Some(result);
            }
        }
        if result == AckResult::StaleGeneration {
            self.reoffer.entry(peer.clone()).or_default().insert(change.name.clone());
        }
        true
    }

    /// Iterates only pending exact entries for a peer; finalized metadata is retained until release (§12.3).
    pub fn pending<'a>(&'a self, peer: &PeerId) -> impl Iterator<Item = &'a ChangeId> {
        self.deliveries.get(peer).into_iter().flat_map(|q| q.iter())
            .filter(|(_, d)| d.final_ack.is_none()).map(|(id, _)| id)
    }

    /// True only for a known snapshot with a final ACK from every target peer/generation (§12.3).
    pub fn snapshot_releasable(&self, name: &str, vid: Vid) -> bool {
        let mut found = false;
        for queue in self.deliveries.values() {
            for (id, delivery) in queue {
                if id.name == name && id.new_vid == vid {
                    found = true;
                    if delivery.final_ack.is_none() { return false; }
                }
            }
        }
        found
    }

    /// Removes finalized bookkeeping only once the shared snapshot is releasable (§12.3).
    pub fn release_snapshot(&mut self, name: &str, vid: Vid) -> bool {
        if !self.snapshot_releasable(name, vid) { return false; }
        for queue in self.deliveries.values_mut() { queue.retain(|id, _| id.name != name || id.new_vid != vid); }
        self.deliveries.retain(|_, q| !q.is_empty());
        true
    }

    /// Exposes the stale-generation status for a peer/name (§12.2).
    pub fn needs_reoffer(&self, peer: &PeerId, name: &str) -> bool {
        self.reoffer.get(peer).is_some_and(|names| names.contains(name))
    }

    /// Clears the re-offer status after a new Accept (§12.2).
    pub fn accepted(&mut self, peer: &PeerId, name: &str) {
        if let Some(names) = self.reoffer.get_mut(peer) { names.remove(name); }
    }
}

use std::collections::BTreeMap;
use serde::{Deserialize, Serialize};
use crate::{AckResult, Decision, Fp, HoldReason};

/// Slot priority in increasing order; checkpoints are never evicted (§12.3).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum SlotKind {
    /// Lowest-priority unsolicited offer (§12.3).
    Proposal,
    /// Value waiting for human review (§12.3).
    Held,
    /// Unresolved candidate or outbound value snapshot (§2.6, §12.3).
    ConflictCandidate,
    /// Human-confirmed recovery baseline (§2.6).
    Checkpoint,
}

/// Reservation result; callers must durably remove evicted lower-priority slots (§12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Reservation {
    /// Reservation succeeded, possibly evicting a lower-priority slot (§12.3).
    Reserved {
        /// Evicted slot name, if any; never a checkpoint (§12.3).
        evicted: Option<String>,
    },
    /// No space, or the name already belongs to a different slot kind (§12.3).
    Refused,
}

/// Serializable slot ledger with deterministic lower-priority eviction (§12.3).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SlotBudget {
    capacity: usize,
    slots: BTreeMap<String, SlotKind>,
    pinned_snapshots: std::collections::BTreeSet<String>,
}

impl SlotBudget {
    /// Creates a budget of max(16, items × 4), saturating arithmetic (§12.3).
    pub fn new(items: usize) -> Self {
        Self { capacity: items.saturating_mul(4).max(16), slots: BTreeMap::new(), pinned_snapshots: Default::default() }
    }
    /// Returns the configured total capacity (§12.3).
    pub fn capacity(&self) -> usize { self.capacity }
    /// Returns the count of reserved slots (§12.3).
    pub fn used(&self) -> usize { self.slots.len() }
    /// Looks up a reservation without touching its value (§12.3).
    pub fn kind(&self, name: &str) -> Option<SlotKind> { self.slots.get(name).copied() }

    /// Reserves a slot; new Held and Proposal slots never evict at capacity (§12.3).
    pub fn reserve(&mut self, name: &str, kind: SlotKind) -> Reservation {
        if let Some(existing) = self.slots.get(name) {
            return if *existing == kind { Reservation::Reserved { evicted: None } } else { Reservation::Refused };
        }
        let mut evicted = None;
        if self.slots.len() >= self.capacity {
            if kind <= SlotKind::Held { return Reservation::Refused; }
            evicted = self.slots.iter()
                .filter(|(name, existing)| **existing < kind && !self.pinned_snapshots.contains(*name))
                .min_by_key(|(name, existing)| (**existing, *name))
                .map(|(name, _)| name.clone());
            let Some(victim) = &evicted else { return Reservation::Refused; };
            self.slots.remove(victim);
        }
        self.slots.insert(name.into(), kind);
        Reservation::Reserved { evicted }
    }

    /// Reserves an outbound snapshot pinned until all-target final ACK (§2.8, §12.3).
    pub fn reserve_snapshot(&mut self, name: &str) -> Reservation {
        let result = self.reserve(name, SlotKind::ConflictCandidate);
        if matches!(result, Reservation::Reserved { .. }) { self.pinned_snapshots.insert(name.into()); }
        result
    }

    /// Releases resolved/rejected slots or finally acknowledged snapshots, never checkpoints (§12.3).
    pub fn release(&mut self, name: &str) -> bool {
        if self.slots.get(name) == Some(&SlotKind::Checkpoint) { return false; }
        self.pinned_snapshots.remove(name);
        self.slots.remove(name).is_some()
    }

    /// Ensures a checkpoint before overwrite; fallback is held, then capacity deferral (§2.6, §12.3).
    pub fn prepare_overwrite(&mut self, checkpoint_slot: &str, held_slot: &str) -> OverwriteCapacity {
        match self.reserve(checkpoint_slot, SlotKind::Checkpoint) {
            Reservation::Reserved { evicted } => OverwriteCapacity::Ready { evicted },
            Reservation::Refused => match self.reserve(held_slot, SlotKind::Held) {
                Reservation::Reserved { .. } => OverwriteCapacity::Held(Decision::held(HoldReason::OverLimit)),
                Reservation::Refused => OverwriteCapacity::Deferred(Decision::unchanged(AckResult::DeferredCapacity)),
            },
        }
    }
}

/// First-overwrite capacity gate; only Ready permits a keychain write (§2.6, §12.3).
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum OverwriteCapacity {
    /// Checkpoint slot exists before the overwrite (§2.6).
    Ready {
        /// Lower-priority reservation displaced by the checkpoint (§12.3).
        evicted: Option<String>,
    },
    /// Retain incoming value for review (§12.3).
    Held(Decision),
    /// Retain nothing and ask sender to retry (§12.3).
    Deferred(Decision),
}

/// Recovery baseline whose fingerprint cannot be replaced by remote overwrites (§2.6).
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Checkpoint { fp: Option<Fp> }

impl Checkpoint {
    /// Captures the original value only on the first remote overwrite (§2.6).
    pub fn before_remote_overwrite(&mut self, current: Fp) -> Fp { *self.fp.get_or_insert(current) }
    /// Returns the retained fingerprint for caller-owned recovery storage (§2.6).
    pub fn fingerprint(&self) -> Option<Fp> { self.fp }
    /// Explicit human confirmation is the only way to replace a baseline (§2.6).
    pub fn human_confirm(&mut self, current: Fp) { self.fp = Some(current); }
}

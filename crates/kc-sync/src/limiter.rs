use crate::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Rolling non-interactive overwrite and peer breaker window in seconds (§4).
pub const WINDOW_SECS: i64 = 24 * 60 * 60;

/// Counted remote operation; retirement never deletes a value (§4, §2.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum RemoteOperation {
    /// Value overwrite (§4).
    Overwrite,
    /// Registration removal (§4).
    Retire,
}

/// Limiter outcome that the caller feeds into `decide` (§4, §12.5).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LimitResult {
    /// Within both item and peer limits (§4).
    Allowed,
    /// This item already had a non-interactive overwrite in the window (§4).
    ItemLimited,
    /// Peer is latched off until a human resets it; hold all its messages (§4).
    PeerTripped,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Event {
    at: i64,
    name: String,
    op: RemoteOperation,
}

/// Serializable deterministic limiter; caller supplies time and records only committed operations (§4).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Limiter {
    items: BTreeMap<String, i64>,
    events: BTreeMap<PeerId, Vec<Event>>,
    tripped: BTreeSet<PeerId>,
}

fn recent(at: i64, now: i64) -> bool {
    // Future timestamps remain active under clock rollback, including i64 extremes.
    (now as i128) - (at as i128) < WINDOW_SECS as i128
}

impl Limiter {
    /// Checks the proposed operation and latches a breaker before crossing a threshold (§4).
    pub fn check(
        &mut self,
        peer: &PeerId,
        name: &str,
        op: RemoteOperation,
        now: i64,
        sync_set_size: usize,
        interactive: bool,
    ) -> LimitResult {
        if self.tripped.contains(peer) {
            return LimitResult::PeerTripped;
        }
        self.prune(now);
        let events = self.events.get(peer).map(Vec::as_slice).unwrap_or_default();
        let overwrites = events
            .iter()
            .filter(|e| e.op == RemoteOperation::Overwrite)
            .count()
            + usize::from(op == RemoteOperation::Overwrite);
        let retires = events
            .iter()
            .filter(|e| e.op == RemoteOperation::Retire)
            .count()
            + usize::from(op == RemoteOperation::Retire);
        let affected: BTreeSet<&str> = events
            .iter()
            .map(|e| e.name.as_str())
            .chain([name])
            .collect();
        if overwrites > 5
            || retires > 3
            || (sync_set_size >= 8 && affected.len() > sync_set_size / 4)
        {
            self.tripped.insert(peer.clone());
            return LimitResult::PeerTripped;
        }
        if op == RemoteOperation::Overwrite
            && !interactive
            && self.items.get(name).is_some_and(|at| recent(*at, now))
        {
            return LimitResult::ItemLimited;
        }
        LimitResult::Allowed
    }

    /// Records an actually committed operation; interactive writes bypass only the item cap (§4).
    pub fn record(
        &mut self,
        peer: &PeerId,
        name: &str,
        op: RemoteOperation,
        now: i64,
        interactive: bool,
    ) {
        self.prune(now);
        if op == RemoteOperation::Overwrite && !interactive {
            self.items.insert(name.into(), now);
        }
        self.events.entry(peer.clone()).or_default().push(Event {
            at: now,
            name: name.into(),
            op,
        });
    }

    /// Tests the sticky peer breaker for any incoming message, including offers (§4).
    pub fn is_tripped(&self, peer: &PeerId) -> bool {
        self.tripped.contains(peer)
    }

    /// Human reset clears this peer's breaker history but preserves per-item overwrite limits (§4).
    pub fn human_reset(&mut self, peer: &PeerId) {
        self.tripped.remove(peer);
        self.events.remove(peer);
    }

    /// Drops expired counters without clearing sticky breakers (§4).
    pub fn prune(&mut self, now: i64) {
        self.items.retain(|_, at| recent(*at, now));
        self.events.retain(|_, events| {
            events.retain(|e| recent(e.at, now));
            !events.is_empty()
        });
    }
}

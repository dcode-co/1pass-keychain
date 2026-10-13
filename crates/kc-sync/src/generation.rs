use crate::PeerId;
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet};

/// Receiver-issued registration message, with explicit peer scoping (§12.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Registration {
    /// Name being accepted or left (§12.2).
    pub name: String,
    /// Receiver-owned generation (§12.2).
    pub generation: u64,
}

/// Exhaustion must not wrap a receiver's generation and revive stale changes (§12.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
#[error("registration generation exhausted")]
pub struct GenerationExhausted;

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
struct Owned {
    generation: u64,
    peers: BTreeSet<PeerId>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct Remote {
    generation: u64,
    accepted: bool,
}

/// Receiver generations and sender-side Accept/Leave bookkeeping, never automatic enrollment (§12.2).
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Generations {
    owned: BTreeMap<String, Owned>,
    remote: BTreeMap<PeerId, BTreeMap<String, Remote>>,
}

impl Generations {
    /// Returns the generation owned by this receiver, initially zero (§12.2).
    pub fn generation(&self, name: &str) -> u64 {
        self.owned.get(name).map_or(0, |o| o.generation)
    }

    /// Human review accepts an offer for exactly the specified peer (§2.1, §12.2).
    pub fn accept(&mut self, name: &str, peer: PeerId) -> Registration {
        let owned = self.owned.entry(name.into()).or_default();
        owned.generation = owned.generation.max(1);
        owned.peers.insert(peer);
        Registration {
            name: name.into(),
            generation: owned.generation,
        }
    }

    /// Checks local registration membership for a peer/name (§2.1, §12.2).
    pub fn includes(&self, name: &str, peer: &PeerId) -> bool {
        self.owned.get(name).is_some_and(|o| o.peers.contains(peer))
    }

    /// Removes one scope member without changing generation; send Leave only to this peer (§12.2).
    pub fn remove_peer(&mut self, name: &str, peer: &PeerId) -> Option<(Registration, PeerId)> {
        let owned = self.owned.get_mut(name)?;
        if !owned.peers.remove(peer) {
            return None;
        }
        Some((
            Registration {
                name: name.into(),
                generation: owned.generation,
            },
            peer.clone(),
        ))
    }

    /// Removes local membership and bumps its generation; send Leave to returned peers (§12.2).
    pub fn rm(
        &mut self,
        name: &str,
    ) -> Result<(Registration, BTreeSet<PeerId>), GenerationExhausted> {
        let owned = self.owned.entry(name.into()).or_default();
        let next = owned.generation.checked_add(1).ok_or(GenerationExhausted)?;
        owned.generation = next;
        let peers = std::mem::take(&mut owned.peers);
        Ok((
            Registration {
                name: name.into(),
                generation: next,
            },
            peers,
        ))
    }

    /// Records a peer's Accept, ignoring generations older than a previously observed Leave (§12.2).
    pub fn received_accept(&mut self, peer: PeerId, accept: Registration) -> bool {
        let names = self.remote.entry(peer).or_default();
        if names
            .get(&accept.name)
            .is_some_and(|r| r.generation > accept.generation)
        {
            return false;
        }
        names.insert(
            accept.name,
            Remote {
                generation: accept.generation,
                accepted: true,
            },
        );
        true
    }

    /// Records a peer's Leave without permitting reordered older messages to roll it back (§12.2).
    pub fn received_leave(&mut self, peer: PeerId, leave: Registration) -> bool {
        let names = self.remote.entry(peer).or_default();
        if names.get(&leave.name).is_some_and(|r| {
            r.generation > leave.generation || (r.generation == leave.generation && r.accepted)
        }) {
            return false;
        }
        names.insert(
            leave.name,
            Remote {
                generation: leave.generation,
                accepted: false,
            },
        );
        true
    }

    /// Last receiver generation learned from either Accept or Leave; zero means unknown.
    pub fn known_generation(&self, peer: &PeerId, name: &str) -> u64 {
        self.remote
            .get(peer)
            .and_then(|names| names.get(name))
            .map_or(0, |r| r.generation)
    }

    /// Returns the receiver-issued generation only after Accept and before Leave (§12.2).
    pub fn outgoing_generation(&self, peer: &PeerId, name: &str) -> Option<u64> {
        let remote = self.remote.get(peer)?.get(name)?;
        remote.accepted.then_some(remote.generation)
    }
}

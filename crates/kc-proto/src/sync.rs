//! Sync messages carried by inbox v2 (design §5 and §12.1).
//!
//! Field and variant order is the postcard wire contract. Values use the
//! same zeroize-on-drop storage as `payload::Item`.

use std::collections::HashSet;
use std::fmt;

use serde::{Deserialize, Deserializer, Serialize, Serializer};

use crate::inbox::{InboxError, MessageId};
use crate::names::ItemName;
use crate::rng;
use crate::secret::SecretBytes;

pub const MAX_LINEAGE: usize = 64;
pub const MAX_PARENTS: usize = 65;

/// A random version identifier: raw 16 bytes in postcard, hex in JSON.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Vid(pub [u8; 16]);

impl Vid {
    pub fn random() -> Self {
        Self(rng::array())
    }
}

impl fmt::Debug for Vid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Vid({})", MessageId(self.0).to_hex())
    }
}

impl Serialize for Vid {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        MessageId(self.0).serialize(serializer)
    }
}

impl<'de> Deserialize<'de> for Vid {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        MessageId::deserialize(deserializer).map(|id| Self(id.0))
    }
}

/// Value presentation, matching the store's Text/File meanings. v1 Item
/// has no kind field; sync carries it explicitly without changing v1.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ItemKind {
    Text,
    File,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ChangeId {
    pub name: ItemName,
    pub generation: u64,
    pub new_vid: Vid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Op {
    Put { kind: ItemKind, value: SecretBytes },
    Retire,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Change {
    pub name: ItemName,
    pub generation: u64,
    pub new_vid: Vid,
    #[serde(deserialize_with = "deserialize_parents")]
    pub parents: Vec<Vid>,
    #[serde(deserialize_with = "deserialize_lineage")]
    pub lineage: Vec<Vid>,
    pub op: Op,
    pub approval_ref: Option<[u8; 16]>,
}

impl Change {
    pub fn validate(&self) -> Result<(), InboxError> {
        if self.lineage.len() > MAX_LINEAGE || self.parents.len() > MAX_PARENTS {
            return Err(InboxError::Malformed);
        }
        Ok(())
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum AckResult {
    Applied,
    Held,
    Conflict,
    StaleGeneration,
    DeferredCapacity,
    Rejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DigestEntry {
    pub name: ItemName,
    pub generation: u64,
    pub head: Vid,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum SyncMsg {
    Hello {
        features: Vec<String>,
        is_reply: bool,
    },
    Offer {
        name: ItemName,
        /// The receiver's registration generation for `name` as the sender last learned it
        /// from an `Accept` or `Leave` (0 = never). The receiver ignores an offer whose
        /// value is below its current generation: it was sent before a `sync rm` (§2.1).
        known_generation: u64,
        vid: Vid,
        #[serde(deserialize_with = "deserialize_lineage")]
        lineage: Vec<Vid>,
        kind: ItemKind,
        value: SecretBytes,
    },
    Accept {
        name: ItemName,
        generation: u64,
    },
    Leave {
        name: ItemName,
        generation: u64,
    },
    Changes {
        changes: Vec<Change>,
    },
    Ack {
        #[serde(deserialize_with = "deserialize_ack_results")]
        results: Vec<(ChangeId, AckResult)>,
    },
    Digest {
        #[serde(deserialize_with = "deserialize_digest_entries")]
        entries: Vec<DigestEntry>,
    },
    Approvals {
        docs: Vec<Vec<u8>>,
    },
}

impl SyncMsg {
    /// Checks in-memory messages too, before sealing or after opening.
    pub fn validate(&self) -> Result<(), InboxError> {
        match self {
            Self::Offer { lineage, .. } if lineage.len() > MAX_LINEAGE => {
                return Err(InboxError::Malformed);
            }
            Self::Changes { changes } => {
                let mut names = HashSet::new();
                for change in changes {
                    change.validate()?;
                    if !names.insert(&change.name) {
                        return Err(InboxError::Malformed);
                    }
                }
            }
            Self::Digest { entries } => {
                let mut names = HashSet::new();
                if entries.iter().any(|entry| !names.insert(&entry.name)) {
                    return Err(InboxError::Malformed);
                }
            }
            Self::Ack { results } => {
                let mut ids = HashSet::new();
                if results.iter().any(|(id, _)| !ids.insert(id)) {
                    return Err(InboxError::Malformed);
                }
            }
            _ => {}
        }
        Ok(())
    }
}

fn deserialize_ack_results<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<(ChangeId, AckResult)>, D::Error> {
    let results = Vec::<(ChangeId, AckResult)>::deserialize(deserializer)?;
    let mut ids = HashSet::new();
    if results.iter().any(|(id, _)| !ids.insert(id)) {
        return Err(serde::de::Error::custom("duplicate ACK change_id"));
    }
    Ok(results)
}

fn deserialize_digest_entries<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Vec<DigestEntry>, D::Error> {
    let entries = Vec::<DigestEntry>::deserialize(deserializer)?;
    let mut names = HashSet::new();
    if entries.iter().any(|entry| !names.insert(&entry.name)) {
        return Err(serde::de::Error::custom("duplicate digest name"));
    }
    Ok(entries)
}

// Bound allocation as well as the decoded number of version identifiers.
fn deserialize_lineage<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Vid>, D::Error> {
    deserialize_vids::<D, MAX_LINEAGE>(deserializer)
}

fn deserialize_parents<'de, D: Deserializer<'de>>(deserializer: D) -> Result<Vec<Vid>, D::Error> {
    deserialize_vids::<D, MAX_PARENTS>(deserializer)
}

fn deserialize_vids<'de, D: Deserializer<'de>, const MAX: usize>(
    deserializer: D,
) -> Result<Vec<Vid>, D::Error> {
    struct Vids<const MAX: usize>;
    impl<'de, const MAX: usize> serde::de::Visitor<'de> for Vids<MAX> {
        type Value = Vec<Vid>;
        fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "at most {MAX} version identifiers")
        }
        fn visit_seq<A: serde::de::SeqAccess<'de>>(self, mut seq: A) -> Result<Vec<Vid>, A::Error> {
            if seq.size_hint().is_some_and(|n| n > MAX) {
                return Err(serde::de::Error::custom("too many version identifiers"));
            }
            let mut out = Vec::with_capacity(seq.size_hint().unwrap_or(0).min(MAX));
            while let Some(vid) = seq.next_element()? {
                if out.len() == MAX {
                    return Err(serde::de::Error::custom("too many version identifiers"));
                }
                out.push(vid);
            }
            Ok(out)
        }
    }
    deserializer.deserialize_seq(Vids::<MAX>)
}

use std::collections::{BTreeMap, BTreeSet};
use serde::{Deserialize, Deserializer, Serialize, Serializer};

// Structured keys are encoded as pairs so state remains usable in sync.json as well as binary serde.
pub(crate) fn serialize_map<S: Serializer, K: Serialize, V: Serialize>(map: &BTreeMap<K, V>, s: S) -> Result<S::Ok, S::Error> {
    map.iter().collect::<Vec<_>>().serialize(s)
}

pub(crate) fn deserialize_map<'de, D: Deserializer<'de>, K: Deserialize<'de> + Ord, V: Deserialize<'de>>(d: D) -> Result<BTreeMap<K, V>, D::Error> {
    let pairs = Vec::<(K, V)>::deserialize(d)?;
    let count = pairs.len();
    let map: BTreeMap<_, _> = pairs.into_iter().collect();
    if map.len() != count { return Err(serde::de::Error::custom("duplicate map key")); }
    Ok(map)
}

/// Opaque, caller-generated version identifier (§2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Vid(pub [u8; 16]);

/// Opaque, locally computed value fingerprint; never a wire value (§2.2).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Fp(pub [u8; 32]);

/// Opaque peer key, independent of transport or display labels (§12.2).
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PeerId(pub String);

/// Maximum retained lineage size (§2.4).
pub const MAX_LINEAGE: usize = 64;
/// Bounded immutable-VID cache; unresolved candidate records live separately (§2.2, §2.4).
pub const MAX_KNOWN: usize = 256;

/// Sorted, bounded set of version identifiers (§2.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[serde(transparent)]
pub struct Lineage(BTreeSet<Vid>);

impl<'de> Deserialize<'de> for Lineage {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        let values = BTreeSet::<Vid>::deserialize(d)?;
        if values.len() > MAX_LINEAGE {
            return Err(serde::de::Error::custom("lineage exceeds 64 vids"));
        }
        Ok(Self(values))
    }
}

impl Lineage {
    /// Retains the greatest 64 distinct vids, deterministically (§2.4).
    pub fn new(vids: impl IntoIterator<Item = Vid>) -> Self {
        let mut result = Self(vids.into_iter().collect());
        while result.0.len() > MAX_LINEAGE { result.0.pop_first(); }
        result
    }

    /// Unions two lineages, dropping smallest identifiers first (§2.4).
    pub fn merge(a: &Self, b: &Self) -> Self {
        Self::new(a.0.union(&b.0).copied())
    }

    /// Pins the resulting current head even when it is smaller than retained ancestors (§2.4).
    pub fn with_head(mut self, head: Vid) -> Self {
        self.0.insert(head);
        if self.0.len() > MAX_LINEAGE {
            let victim = self.0.iter().copied().find(|v| *v != head).unwrap();
            self.0.remove(&victim);
        }
        self
    }

    /// Tests ancestry membership without trusting remote ancestry for authorization (§2.2).
    pub fn contains(&self, vid: &Vid) -> bool { self.0.contains(vid) }
    /// Returns identifiers in deterministic ascending order (§2.4).
    pub fn iter(&self) -> impl Iterator<Item = &Vid> { self.0.iter() }
    /// Returns the retained identifier count (§2.4).
    pub fn len(&self) -> usize { self.0.len() }
    /// Reports an empty ancestry set (§2.4).
    pub fn is_empty(&self) -> bool { self.0.is_empty() }
}

/// Immutable value and direct-parent binding for a known version (§2.2, §2.4).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VidRecord {
    /// Locally computed value fingerprint (§2.2).
    pub fp: Fp,
    /// Exact ordered parent list bound to this vid (§2.4).
    pub parents: Vec<Vid>,
}

/// Preserved unresolved heads and their immutable bindings (§2.4).
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConflictSet {
    /// Candidate values must remain in caller-owned slots until resolve or rejection (§12.3).
    #[serde(serialize_with = "serialize_map", deserialize_with = "deserialize_map")]
    pub candidates: BTreeMap<Vid, VidRecord>,
}

/// Receiver-owned item state; construct/update its bounded cache with `remember` (§2.2, §12.2).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemState {
    /// Receiver's registration generation (§12.2).
    pub generation: u64,
    /// Current value's immutable version (§2.2).
    pub head: Vid,
    /// Bounded ancestry, with the head pinned by transitions (§2.4).
    pub lineage: Lineage,
    /// All unresolved candidate values, including the current head (§2.4).
    pub conflict: Option<ConflictSet>,
    /// Bounded recent bindings; candidate bindings are additionally kept in `conflict` (§2.4).
    #[serde(serialize_with = "serialize_map", deserialize_with = "deserialize_known")]
    pub known: BTreeMap<Vid, VidRecord>,
}

fn deserialize_known<'de, D: Deserializer<'de>>(d: D) -> Result<BTreeMap<Vid, VidRecord>, D::Error> {
    let known: BTreeMap<Vid, VidRecord> = deserialize_map(d)?;
    if known.len() > MAX_KNOWN { return Err(serde::de::Error::custom("known cache exceeds bound")); }
    Ok(known)
}

impl ItemState {
    /// Initializes a single local head using caller-supplied randomness (§2.2).
    pub fn new(generation: u64, head: Vid, fp: Fp, parents: Vec<Vid>) -> Self {
        Self { generation, head, lineage: Lineage::new([head]), conflict: None,
            known: BTreeMap::from([(head, VidRecord { fp, parents })]) }
    }

    /// Remembers a binding, rejects mutation, and deterministically bounds the cache (§2.2, §2.4).
    pub fn remember(&mut self, vid: Vid, record: VidRecord) -> bool {
        if self.record(&vid).is_some_and(|old| old != &record) { return false; }
        self.known.insert(vid, record);
        while self.known.len() > MAX_KNOWN {
            let victim = self.known.keys().copied().find(|v| *v != self.head).unwrap();
            self.known.remove(&victim);
        }
        true
    }

    pub(crate) fn record(&self, vid: &Vid) -> Option<&VidRecord> {
        self.known.get(vid).or_else(|| self.conflict.as_ref()?.candidates.get(vid))
    }
}

/// Authenticated envelope data plus locally computed fingerprint for decision-making (§12.5).
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Incoming {
    /// Generation previously supplied by this receiver (§12.2).
    pub generation: u64,
    /// Immutable proposed version (§2.2).
    pub new_vid: Vid,
    /// Claimed direct parents; approval verification must bind this exact list (§12.5).
    pub parents: Vec<Vid>,
    /// Claimed bounded ancestry, never sufficient to authorize overwrites (§2.2).
    pub lineage: Lineage,
    /// Local fingerprint of Put value; absent for Retire (§2.5).
    pub value_fp: Option<Fp>,
    /// Unregister only; this operation must never delete a value (§2.5).
    pub retire: bool,
}

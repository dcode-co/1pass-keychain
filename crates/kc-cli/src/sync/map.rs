//! The only conversions between the transport and pure sync contracts.
use kc_proto::sync as wire;
use kc_sync as core;

pub fn vid(v: wire::Vid) -> core::Vid { core::Vid(v.0) }
pub fn wire_vid(v: core::Vid) -> wire::Vid { wire::Vid(v.0) }
pub fn id(v: &wire::ChangeId) -> core::ChangeId {
    core::ChangeId { name: v.name.to_string(), generation: v.generation, new_vid: vid(v.new_vid) }
}
pub fn ack(v: wire::AckResult) -> core::AckResult {
    match v {
        wire::AckResult::Applied => core::AckResult::Applied,
        wire::AckResult::Held => core::AckResult::Held,
        wire::AckResult::Conflict => core::AckResult::Conflict,
        wire::AckResult::StaleGeneration => core::AckResult::StaleGeneration,
        wire::AckResult::DeferredCapacity => core::AckResult::DeferredCapacity,
        wire::AckResult::Rejected => core::AckResult::Rejected,
    }
}
pub fn wire_ack(v: core::AckResult) -> wire::AckResult {
    match v {
        core::AckResult::Applied => wire::AckResult::Applied,
        core::AckResult::Held => wire::AckResult::Held,
        core::AckResult::Conflict => wire::AckResult::Conflict,
        core::AckResult::StaleGeneration => wire::AckResult::StaleGeneration,
        core::AckResult::DeferredCapacity => wire::AckResult::DeferredCapacity,
        core::AckResult::Rejected => wire::AckResult::Rejected,
    }
}
pub fn kind(v: wire::ItemKind) -> kc_store::ItemKind {
    match v { wire::ItemKind::Text => kc_store::ItemKind::Text, wire::ItemKind::File => kc_store::ItemKind::File }
}
pub fn wire_kind(v: kc_store::ItemKind) -> wire::ItemKind {
    match v { kc_store::ItemKind::Text => wire::ItemKind::Text, kc_store::ItemKind::File => wire::ItemKind::File }
}

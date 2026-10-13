//! Phase 1 persistence adapter: all mutations require items -> state locks. The pure
//! crate owns decisions, lineage, delivery accounting, generations, limits and recovery.
mod map;
mod state;
mod transaction;
mod transport;
mod receive;
pub(crate) mod actions;
pub(crate) use state::{State, CandidateKind};
pub(crate) use transaction::{local_set, observed_write, scan, recover};
pub(crate) use transport::{flush, send_after_write};
pub(crate) use receive::{receive, legacy};

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use serde::{Serialize, de::DeserializeOwned};
use kc_proto::sync::{Vid, ItemKind};
use kc_sync::{Fp, PeerId, SlotBudget, SlotKind, Reservation, VidRecord, ItemState};
use zeroize::Zeroizing;
use crate::{commands::Ctx, error::{CliError, Result}, host::Host, i18n::tr, LocalAuthOutcome};
use state::{Item, Version};

pub(crate) fn state_error() -> CliError { CliError::failure(tr!("Sync state is unavailable or damaged; retry after checking the keychain and state directory.")) }
pub(crate) fn human<H: Host>(ctx: &mut Ctx<'_, H>, reason: &str) -> Result<()> {
    if !ctx.interactive() || ctx.host.local_confirm(reason) != LocalAuthOutcome::Confirmed {
        return Err(CliError::interaction(tr!("Sync needs local confirmation."))
            .with_hint(tr!("Run this command at a terminal and confirm in the operating system.")));
    }
    Ok(())
}
pub(crate) fn hex(bytes: &[u8]) -> String { bytes.iter().map(|b| format!("{b:02x}")).collect() }
fn tag(name: &str) -> String { hex(&Sha256::digest(name.as_bytes())) }
fn delivery_key(peer: &str, name: &str, generation: u64, vid: Vid) -> String {
    format!("{peer}/{name}/{generation}/{}", hex(&vid.0))
}
fn vid_key(vid: Vid) -> String { hex(&vid.0) }
fn record_slot(name: &str, vid: Vid) -> String { format!("sync/fp/{}/{}", tag(name), vid_key(vid)) }
fn snapshot_slot(vid: Vid) -> String { format!("sync/snapshot/{}", vid_key(vid)) }
fn checkpoint_slot(name: &str) -> String { format!("sync/kg/{}", tag(name)) }
fn candidate_slot(peer: &str, vid: Vid) -> String { format!("sync/candidate/{}/{}", tag(peer), vid_key(vid)) }
fn private_put<H: Host, T: Serialize>(ctx: &Ctx<'_, H>, slot: &str, value: &T) -> Result<()> {
    let bytes = Zeroizing::new(serde_json::to_vec(value).map_err(|_| state_error())?);
    ctx.store.set_internal(slot, &bytes)?;
    Ok(())
}
fn private_get<H: Host, T: DeserializeOwned>(ctx: &Ctx<'_, H>, slot: &str) -> Result<T> {
    let bytes = ctx.store.get_internal(slot)?.ok_or_else(state_error)?;
    serde_json::from_slice(bytes.as_bytes()).map_err(|_| state_error())
}
fn fingerprint<H: Host>(ctx: &Ctx<'_, H>, name: &str, kind: ItemKind, value: &[u8]) -> Result<Fp> {
    if ctx.store.get_internal("sync-key")?.is_none() {
        let mut key = Zeroizing::new(Vec::with_capacity(32));
        key.extend_from_slice(&Vid::random().0);
        key.extend_from_slice(&Vid::random().0);
        ctx.store.set_internal("sync-key", &key)?;
    }
    let key = ctx.store.get_internal("sync-key")?.ok_or_else(state_error)?;
    if key.as_bytes().len() != 32 { return Err(state_error()); }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| state_error())?;
    mac.update(&(name.len() as u64).to_be_bytes());
    mac.update(name.as_bytes());
    mac.update(&[match kind { ItemKind::Text => 0, ItemKind::File => 1 }]);
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
    Ok(Fp(mac.finalize().into_bytes().into()))
}
fn current<H: Host>(ctx: &Ctx<'_, H>, name: &str) -> Result<Option<(Zeroizing<Vec<u8>>, ItemKind, Fp)>> {
    let Some(value) = ctx.store.get(name)? else { return Ok(None) };
    let kind = map::wire_kind(ctx.store.info(name)?.ok_or_else(state_error)?.kind);
    let fp = fingerprint(ctx, name, kind, value.as_bytes())?;
    Ok(Some((value.into_zeroizing(), kind, fp)))
}
fn remember<H: Host>(ctx: &Ctx<'_, H>, name: &str, vid: Vid, fp: Fp, parents: &[Vid]) -> Result<bool> {
    let slot = record_slot(name, vid);
    let binding = VidRecord { fp, parents: parents.iter().copied().map(map::vid).collect() };
    if ctx.store.get_internal(&slot)?.is_some() {
        return Ok(private_get::<_, VidRecord>(ctx, &slot)? == binding);
    }
    private_put(ctx, &slot, &binding)?;
    Ok(true)
}
fn pure<H: Host>(ctx: &Ctx<'_, H>, s: &State, name: &str, item: &Item) -> Result<ItemState> {
    let rec: VidRecord = private_get(ctx, &record_slot(name, item.head))?;
    let mut result = ItemState::new(s.generations.generation(name), map::vid(item.head), rec.fp, rec.parents);
    result.lineage = kc_sync::Lineage::new(item.lineage.iter().copied().map(map::vid));
    for v in &item.known { result.remember(map::vid(*v), private_get(ctx, &record_slot(name, *v))?); }
    for c in s.candidates.values().filter(|c| c.version.name == name && !c.retire && !c.invalid_binding) {
        result.remember(map::vid(c.version.vid), private_get(ctx, &record_slot(name, c.version.vid))?);
    }
    if item.conflict {
        let mut set = kc_sync::ConflictSet::default();
        set.candidates.insert(result.head, private_get(ctx, &record_slot(name, item.head))?);
        for c in s.candidates.values().filter(|c| c.version.name == name && c.category == CandidateKind::Conflict) {
            set.candidates.insert(map::vid(c.version.vid), private_get(ctx, &record_slot(name, c.version.vid))?);
        }
        result.conflict = Some(set);
    }
    Ok(result)
}
fn reserve<H: Host>(ctx: &Ctx<'_, H>, s: &mut State, slot: &str, kind: SlotKind, snapshot: bool) -> Result<bool> {
    if let Some(existing) = s.slots.get_mut(slot) {
        if kind > *existing { *existing = kind; }
        return Ok(true)
    }
    let mut budget = SlotBudget::new(s.items.len());
    // Never evict existing data merely because rm reduced the capacity.
    if s.slots.len() > budget.capacity() { s.capacity_blocked = true; return Ok(false) }
    for (name, k) in &s.slots {
        let result = if s.versions.values().any(|v| &v.slot == name) {
            budget.reserve_snapshot(name)
        } else { budget.reserve(name, *k) };
        if !matches!(result, Reservation::Reserved { evicted: None }) { return Err(state_error()) }
    }
    let result = if snapshot { budget.reserve_snapshot(slot) } else { budget.reserve(slot, kind) };
    match result {
        Reservation::Refused => { s.capacity_blocked = true; Ok(false) }
        Reservation::Reserved { evicted } => {
            if let Some(victim) = evicted {
                s.candidates.retain(|_, c| c.version.slot != victim);
                s.slots.remove(&victim);
                s.gc.insert(victim);
            }
            s.slots.insert(slot.to_owned(), kind);
            s.capacity_blocked = false;
            // Persist reservations before writes, leaving failed slot creation retryable.
            s.save(&ctx.state)?;
            Ok(true)
        }
    }
}
fn release(s: &mut State, slot: &str) {
    if s.slots.get(slot) != Some(&SlotKind::Checkpoint) {
        s.slots.remove(slot);
        s.gc.insert(slot.to_owned());
        if s.slots.len() < SlotBudget::new(s.items.len()).capacity() { s.capacity_blocked = false; }
    }
}
fn size(value: &[u8]) -> Result<()> {
    if value.is_empty() || value.len() > 200 * 1024 {
        return Err(CliError::usage(tr!("Sync items must contain between 1 byte and 200 KiB.")))
    }
    Ok(())
}
fn capacity() -> CliError { CliError::new(8, tr!("Sync storage is full; review pending items before retrying.")) }
pub(crate) fn pending_code<H: Host>(ctx: &Ctx<'_, H>) -> Result<i32> {
    let s = State::load(&ctx.state)?;
    Ok(if pending(&s) { 8 } else { 0 })
}
fn pending(s: &State) -> bool {
    s.frozen || s.capacity_blocked || s.reconnect || !s.candidates.is_empty() || !s.offers.is_empty()
        || s.items.values().any(|i| i.conflict)
        || s.peers.iter().any(|(p, state)| !state.reoffer.is_empty() || !state.quarantine.is_empty()
            || s.limiter.is_tripped(&PeerId(p.clone())) || s.outbox.pending(&PeerId(p.clone())).next().is_some())
}
fn log<H: Host>(ctx: &mut Ctx<'_, H>, text: String) -> Result<()> {
    use std::io::Write;
    let path = ctx.state.root().join("sync.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() >= 1024 * 1024) {
        std::fs::rename(&path, ctx.state.root().join("sync.log.1")).map_err(|_| state_error())?;
    }
    if !path.exists() { crate::state::write_private_atomic(&path, b"").map_err(|_| state_error())?; }
    let mut file = std::fs::OpenOptions::new().append(true).open(&path).map_err(|_| state_error())?;
    writeln!(file, "{text}").map_err(|_| state_error())
}

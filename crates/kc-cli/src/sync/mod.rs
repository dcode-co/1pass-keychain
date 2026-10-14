//! Phase 1 persistence adapter: all mutations require items -> state locks. The pure
//! crate owns decisions, lineage, delivery accounting, generations, limits and recovery.
pub(crate) mod actions;
mod map;
mod receive;
mod state;
mod transaction;
mod transport;
pub(crate) use receive::{legacy, receive};
pub(crate) use state::{CandidateKind, State};
pub(crate) use transaction::{local_set, observed_write, recover, scan};
pub(crate) use transport::{flush, send_after_write};

use crate::{
    LocalAuthOutcome,
    commands::Ctx,
    error::{CliError, Result},
    host::Host,
    i18n::tr,
};
use hmac::{Hmac, Mac};
use kc_proto::sync::{ItemKind, Vid};
use kc_sync::{Fp, ItemState, PeerId, Reservation, SlotBudget, SlotKind, VidRecord};
use serde::{Serialize, de::DeserializeOwned};
use sha2::{Digest, Sha256};
use state::{Item, Version};
use zeroize::Zeroizing;

pub(crate) fn state_error() -> CliError {
    CliError::failure(tr!(
        "Sync state is unavailable or damaged; retry after checking the keychain and state directory."
    ))
}
pub(crate) fn human<H: Host>(ctx: &mut Ctx<'_, H>, reason: &str) -> Result<()> {
    let hint = if !ctx.interactive() {
        tr!("Run this command at a terminal and confirm in the operating system.")
    } else {
        match ctx.host.local_confirm(reason) {
            LocalAuthOutcome::Confirmed => return Ok(()),
            // Unavailable carries why (e.g. no polkit agent); say so instead of the generic hint.
            outcome => outcome.hint(),
        }
    };
    Err(CliError::interaction(tr!("Sync needs local confirmation.")).with_hint(hint))
}
pub(crate) fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn tag(name: &str) -> String {
    hex(&Sha256::digest(name.as_bytes()))
}
fn delivery_key(peer: &str, name: &str, generation: u64, vid: Vid) -> String {
    format!("{peer}/{name}/{generation}/{}", hex(&vid.0))
}
fn vid_key(vid: Vid) -> String {
    hex(&vid.0)
}
fn record_slot(name: &str, vid: Vid) -> String {
    format!("sync/fp/{}/{}", tag(name), vid_key(vid))
}
fn snapshot_slot(vid: Vid) -> String {
    format!("sync/snapshot/{}", vid_key(vid))
}
fn checkpoint_slot(name: &str) -> String {
    format!("sync/kg/{}", tag(name))
}
fn candidate_slot(peer: &str, vid: Vid) -> String {
    format!("sync/candidate/{}/{}", tag(peer), vid_key(vid))
}
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
    let key = ctx
        .store
        .get_internal("sync-key")?
        .ok_or_else(state_error)?;
    if key.as_bytes().len() != 32 {
        return Err(state_error());
    }
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes()).map_err(|_| state_error())?;
    mac.update(&(name.len() as u64).to_be_bytes());
    mac.update(name.as_bytes());
    mac.update(&[match kind {
        ItemKind::Text => 0,
        ItemKind::File => 1,
    }]);
    mac.update(&(value.len() as u64).to_be_bytes());
    mac.update(value);
    Ok(Fp(mac.finalize().into_bytes().into()))
}
/// An item's current value, kind and fingerprint.
type Current = (Zeroizing<Vec<u8>>, ItemKind, Fp);

fn current<H: Host>(ctx: &Ctx<'_, H>, name: &str) -> Result<Option<Current>> {
    let Some(value) = ctx.store.get(name)? else {
        return Ok(None);
    };
    let kind = map::wire_kind(ctx.store.info(name)?.ok_or_else(state_error)?.kind);
    let fp = fingerprint(ctx, name, kind, value.as_bytes())?;
    Ok(Some((value.into_zeroizing(), kind, fp)))
}
fn remember<H: Host>(
    ctx: &Ctx<'_, H>,
    name: &str,
    vid: Vid,
    fp: Fp,
    parents: &[Vid],
) -> Result<bool> {
    let slot = record_slot(name, vid);
    let binding = VidRecord {
        fp,
        parents: parents.iter().copied().map(map::vid).collect(),
    };
    if ctx.store.get_internal(&slot)?.is_some() {
        return Ok(private_get::<_, VidRecord>(ctx, &slot)? == binding);
    }
    private_put(ctx, &slot, &binding)?;
    Ok(true)
}
fn pure<H: Host>(ctx: &Ctx<'_, H>, s: &State, name: &str, item: &Item) -> Result<ItemState> {
    let rec: VidRecord = private_get(ctx, &record_slot(name, item.head))?;
    let mut result = ItemState::new(
        s.generations.generation(name),
        map::vid(item.head),
        rec.fp,
        rec.parents,
    );
    result.lineage = kc_sync::Lineage::new(item.lineage.iter().copied().map(map::vid));
    for v in &item.known {
        result.remember(map::vid(*v), private_get(ctx, &record_slot(name, *v))?);
    }
    for c in s
        .candidates
        .values()
        .filter(|c| c.version.name == name && !c.retire && !c.invalid_binding)
    {
        result.remember(
            map::vid(c.version.vid),
            private_get(ctx, &record_slot(name, c.version.vid))?,
        );
    }
    if item.conflict {
        let mut set = kc_sync::ConflictSet::default();
        set.candidates.insert(
            result.head,
            private_get(ctx, &record_slot(name, item.head))?,
        );
        for c in s
            .candidates
            .values()
            .filter(|c| c.version.name == name && c.category == CandidateKind::Conflict)
        {
            set.candidates.insert(
                map::vid(c.version.vid),
                private_get(ctx, &record_slot(name, c.version.vid))?,
            );
        }
        result.conflict = Some(set);
    }
    Ok(result)
}
fn reserve<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    slot: &str,
    kind: SlotKind,
    snapshot: bool,
) -> Result<bool> {
    reserve_keeping(ctx, s, slot, kind, snapshot, None)
}
/// Like `reserve`, but never evicts `keep`: the candidate whose acceptance needs the slot.
fn reserve_keeping<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    slot: &str,
    kind: SlotKind,
    snapshot: bool,
    keep: Option<&str>,
) -> Result<bool> {
    if let Some(existing) = s.slots.get_mut(slot) {
        if kind > *existing {
            *existing = kind;
        }
        return Ok(true);
    }
    let mut budget = SlotBudget::new(s.items.len());
    // Never evict existing data merely because rm reduced the capacity.
    if s.slots.len() > budget.capacity() {
        s.capacity_blocked = true;
        return Ok(false);
    }
    for (name, k) in &s.slots {
        let result = if s.versions.values().any(|v| &v.slot == name) {
            budget.reserve_snapshot(name)
        } else {
            budget.reserve(name, *k)
        };
        if !matches!(result, Reservation::Reserved { evicted: None }) {
            return Err(state_error());
        }
    }
    if let Some(keep) = keep {
        budget.pin(keep);
    }
    let result = if snapshot {
        budget.reserve_snapshot(slot)
    } else {
        budget.reserve(slot, kind)
    };
    match result {
        Reservation::Refused => {
            s.capacity_blocked = true;
            Ok(false)
        }
        Reservation::Reserved { evicted } => {
            if let Some(victim) = evicted {
                let evicted = s
                    .candidates
                    .values()
                    .filter(|c| c.version.slot == victim)
                    .cloned()
                    .collect::<Vec<_>>();
                s.candidates.retain(|_, c| c.version.slot != victim);
                for c in evicted {
                    s.gc.insert(c.base_record);
                    // Only a proposal's binding goes with it: held and conflict bindings stay
                    // for the immutable-vid check, as in retire_superseded. An invalid
                    // binding's record belongs to the legitimate vid.
                    if c.category == CandidateKind::Proposal && !c.invalid_binding {
                        forget_binding(s, &c.version.name, c.version.vid);
                    }
                }
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
/// Drops a dropped proposal's vid binding (`sync/fp/...` record, unbound entry, known vid)
/// unless the head, a version or another candidate still refers to it.
fn forget_binding(s: &mut State, name: &str, vid: Vid) {
    let referenced = s.items.get(name).is_some_and(|i| i.head == vid)
        || s.versions.values().any(|v| v.name == name && v.vid == vid)
        || s.candidates
            .values()
            .any(|other| other.version.name == name && other.version.vid == vid);
    if referenced {
        return;
    }
    s.unbound.remove(&format!("{}:{}", name, vid_key(vid)));
    if let Some(item) = s.items.get_mut(name) {
        item.known.retain(|known| *known != vid);
    }
    s.gc.insert(record_slot(name, vid));
}

/// A rejected offer stays blocked while its sender keeps retrying.
const REJECTED_OFFER_TTL: i64 = kc_wire::limits::INBOX_IDLE_DELETE_DAYS as i64 * 86400;
fn reject_offer(s: &mut State, delivery: String, now: i64) {
    s.rejected_until
        .insert(delivery.clone(), now.saturating_add(REJECTED_OFFER_TTL));
    s.rejected_offers.insert(delivery);
}
/// Whether an offer was rejected; a retry extends the block, so only silence expires it.
fn offer_rejected(s: &mut State, delivery: &str, now: i64) -> bool {
    if !s.rejected_offers.contains(delivery) {
        return false;
    }
    s.rejected_until
        .insert(delivery.into(), now.saturating_add(REJECTED_OFFER_TTL));
    true
}
/// Expires silent rejected offers and drops bindings of offers that no longer have a
/// candidate. State written before expiries existed gets a full TTL on first prune.
fn prune(s: &mut State, now: i64) {
    let rejected = std::mem::take(&mut s.rejected_offers);
    let until = std::mem::take(&mut s.rejected_until);
    for delivery in rejected {
        let expiry = until
            .get(&delivery)
            .copied()
            .unwrap_or_else(|| now.saturating_add(REJECTED_OFFER_TTL));
        if expiry >= now {
            s.rejected_until.insert(delivery.clone(), expiry);
            s.rejected_offers.insert(delivery);
        }
    }
    // An unfinished transaction may still own a candidate's binding.
    if s.journal.is_some() {
        return;
    }
    for entry in std::mem::take(&mut s.unbound) {
        let Some((name, vid)) = entry
            .rsplit_once(':')
            .and_then(|(name, hex)| Some((name.to_owned(), parse_vid(hex)?)))
        else {
            continue;
        };
        s.unbound.insert(entry);
        let candidate = s
            .candidates
            .values()
            .any(|c| c.version.name == name && c.version.vid == vid);
        // An accepted offer stays unbound until its sender's change arrives.
        let accepted = s
            .items
            .get(&name)
            .is_some_and(|i| i.head == vid || i.lineage.contains(&vid));
        if !candidate && !accepted {
            forget_binding(s, &name, vid);
        }
    }
}
fn parse_vid(hex: &str) -> Option<Vid> {
    let mut vid = [0; 16];
    if hex.len() != 32 || !hex.is_ascii() {
        return None;
    }
    for (byte, pair) in vid.iter_mut().zip(hex.as_bytes().chunks(2)) {
        *byte = u8::from_str_radix(std::str::from_utf8(pair).ok()?, 16).ok()?;
    }
    Some(Vid(vid))
}

fn release(s: &mut State, slot: &str) {
    if s.slots.get(slot) != Some(&SlotKind::Checkpoint) {
        s.slots.remove(slot);
        s.gc.insert(slot.to_owned());
        if s.slots.len() < SlotBudget::new(s.items.len()).capacity() {
            s.capacity_blocked = false;
        }
    }
}
fn size(value: &[u8]) -> Result<()> {
    if value.is_empty() || value.len() > 200 * 1024 {
        return Err(CliError::usage(tr!(
            "Sync items must contain between 1 byte and 200 KiB."
        )));
    }
    Ok(())
}
fn capacity() -> CliError {
    CliError::new(
        8,
        tr!("Sync storage is full; review pending items before retrying."),
    )
}
pub(crate) fn pending_code<H: Host>(ctx: &Ctx<'_, H>) -> Result<i32> {
    let s = State::load(&ctx.state)?;
    Ok(if pending(&s) { 8 } else { 0 })
}
fn pending(s: &State) -> bool {
    s.frozen
        || s.capacity_blocked
        || s.reconnect
        || s.delivery_failed
        || !s.candidates.is_empty()
        || !s.offers.is_empty()
        || s.items.values().any(|i| i.conflict)
        || s.peers.iter().any(|(p, state)| {
            !state.reoffer.is_empty()
                || !state.quarantine.is_empty()
                || s.limiter.is_tripped(&PeerId(p.clone()))
                || s.outbox.pending(&PeerId(p.clone())).next().is_some()
        })
}
fn log<H: Host>(ctx: &Ctx<'_, H>, text: String) -> Result<()> {
    use std::io::Write;
    let path = ctx.state.root().join("sync.log");
    if std::fs::metadata(&path).is_ok_and(|m| m.len() >= 1024 * 1024) {
        std::fs::rename(&path, ctx.state.root().join("sync.log.1")).map_err(|_| state_error())?;
    }
    if !path.exists() {
        crate::state::write_private_atomic(&path, b"").map_err(|_| state_error())?;
    }
    let mut file = std::fs::OpenOptions::new()
        .append(true)
        .open(&path)
        .map_err(|_| state_error())?;
    writeln!(file, "{text}").map_err(|_| state_error())
}

/// Keep local confirmation dialogs readable without hiding that more items are selected.
fn names_summary(names: &[String]) -> String {
    if names.len() <= 3 {
        names.join(", ")
    } else {
        tr!(
            "{names} and {n} more",
            names = names[..3].join(", "),
            n = names.len() - 3
        )
    }
}

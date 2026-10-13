use super::*;
use kc_store::{Origin, SetOutcome};
use kc_sync::{
    LocalJournalRecord, LocalRecovery, QueueTarget, RemoteJournalRecord, RemoteRecovery,
};
use serde::{Deserialize, Serialize};
use state::{Candidate, Control, Journal};

#[derive(Serialize, Deserialize)]
pub(super) struct Blob {
    pub kind: ItemKind,
    pub value: kc_proto::SecretBytes,
}
pub(super) fn put_blob<H: Host>(
    ctx: &Ctx<'_, H>,
    slot: &str,
    kind: ItemKind,
    value: &[u8],
) -> Result<()> {
    private_put(
        ctx,
        slot,
        &Blob {
            kind,
            value: kc_proto::SecretBytes::from_slice(value),
        },
    )
}
pub(super) fn blob<H: Host>(ctx: &Ctx<'_, H>, slot: &str) -> Result<Blob> {
    private_get(ctx, slot)
}
#[derive(Serialize, Deserialize)]
enum Intent {
    Local {
        record: LocalJournalRecord,
        version: Version,
        clear: bool,
    },
    Remote {
        record: RemoteJournalRecord,
        candidate: Candidate,
    },
    // Store's restore/adopt API does not expose the intended value before the mutation.
    // This durable pre-intent makes an interrupted operation recoverable by observation.
    Observe {
        name: String,
        previous: Fp,
        vid: Vid,
        parents: Vec<Vid>,
        snapshot: String,
    },
}
fn intent<H: Host>(ctx: &Ctx<'_, H>, s: &mut State, name: &str, record: &Intent) -> Result<()> {
    let slot = format!("sync/journal/{}", vid_key(Vid::random()));
    private_put(ctx, &slot, record)?;
    if let Some(old) = s.journal.replace(Journal {
        record: slot,
        name: name.into(),
    }) {
        s.gc.insert(old.record);
    }
    s.save(&ctx.state)
}
fn clear_intent<H: Host>(ctx: &Ctx<'_, H>, s: &mut State) -> Result<()> {
    if let Some(j) = s.journal.take() {
        s.gc.insert(j.record);
    }
    s.cleanup(ctx)
}
fn interrupted<H: Host>(ctx: &mut Ctx<'_, H>) -> Result<()> {
    if ctx.host.sync_interrupt_after_write() {
        return Err(state_error());
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
fn prepare_local<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    name: &str,
    previous: Fp,
    kind: ItemKind,
    value: &[u8],
    parents: Vec<Vid>,
    vid: Vid,
    clear: bool,
) -> Result<(LocalJournalRecord, Version)> {
    size(value)?;
    let slot = snapshot_slot(vid);
    if !reserve(ctx, s, &slot, SlotKind::ConflictCandidate, true)? {
        return Err(capacity());
    }
    let item = s.items.get(name).ok_or_else(state_error)?;
    let new_fp = fingerprint(ctx, name, kind, value)?;
    let record = LocalJournalRecord {
        name: name.into(),
        prev_fp: previous,
        new_fp,
        new_vid: map::vid(vid),
        parents: parents.iter().copied().map(map::vid).collect(),
        snapshot_slot: slot.clone(),
        targets: item
            .scope
            .iter()
            .filter_map(|p| {
                s.generations
                    .outgoing_generation(&PeerId(p.clone()), name)
                    .map(|generation| QueueTarget {
                        peer: PeerId(p.clone()),
                        generation,
                    })
            })
            .collect(),
    };
    let lineage = kc_sync::Lineage::new(item.lineage.iter().chain(&parents).copied().map(map::vid))
        .with_head(map::vid(vid))
        .iter()
        .copied()
        .map(map::wire_vid)
        .collect();
    let version = Version {
        name: name.into(),
        vid,
        parents,
        lineage,
        kind,
        slot,
    };
    intent(
        ctx,
        s,
        name,
        &Intent::Local {
            record: record.clone(),
            version: version.clone(),
            clear,
        },
    )?;
    Ok((record, version))
}
fn finish_local<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    r: &LocalJournalRecord,
    v: &Version,
    clear: bool,
) -> Result<()> {
    if !remember(ctx, &r.name, v.vid, r.new_fp, &v.parents)? {
        return Err(state_error());
    }
    let item = s.items.get_mut(&r.name).ok_or_else(state_error)?;
    item.head = v.vid;
    item.lineage = v.lineage.clone();
    item.parents = v.parents.clone();
    item.own = true;
    if !item.known.contains(&v.vid) {
        item.known.push(v.vid);
    }
    if item.known.len() > 256 {
        item.known.remove(0);
    }
    if clear {
        item.conflict = false;
    }
    s.versions.insert(vid_key(v.vid), v.clone());
    s.latest_local.insert(r.name.clone(), v.vid);
    for target in &r.targets {
        s.outbox.enqueue(
            target.peer.clone(),
            kc_sync::ChangeId {
                name: r.name.clone(),
                generation: target.generation,
                new_vid: r.new_vid,
            },
        );
    }
    for offer in &mut s.offers {
        if offer.name == r.name {
            offer.vid = v.vid;
        }
    }
    if clear {
        clear_candidates(s, &r.name);
    }
    s.save(&ctx.state)
}
pub(super) fn clear_candidates(s: &mut State, name: &str) {
    let keys: Vec<_> = s
        .candidates
        .iter()
        .filter(|(_, c)| c.version.name == name)
        .map(|(k, _)| k.clone())
        .collect();
    for key in keys {
        if let Some(c) = s.candidates.remove(&key) {
            release(s, &c.version.slot);
            s.gc.insert(c.base_record);
        }
    }
}
pub(crate) fn local_set<H: Host>(
    ctx: &mut Ctx<'_, H>,
    name: &str,
    value: &[u8],
    kind: kc_store::ItemKind,
    origin: Origin,
) -> Result<SetOutcome> {
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    recover(ctx, &mut s)?;
    if !s.items.contains_key(name) {
        return Ok(ctx.store.set(name, value, kind, origin)?);
    }
    scan_one(ctx, &mut s, name)?;
    let item = s.items[name].clone();
    if item.conflict {
        super::receive::preserve_mine(ctx, &mut s, name, &item)?;
    }
    let previous = current(ctx, name)?.map_or(Fp([0; 32]), |v| v.2);
    let k = map::wire_kind(kind);
    if fingerprint(ctx, name, k, value)? == previous {
        return Ok(ctx.store.set(name, value, kind, origin)?);
    }
    let parents = vec![s.items[name].head];
    let (r, v) = prepare_local(
        ctx,
        &mut s,
        name,
        previous,
        k,
        value,
        parents,
        Vid::random(),
        false,
    )?;
    let outcome = ctx.store.set(name, value, kind, origin)?;
    interrupted(ctx)?;
    put_blob(ctx, &v.slot, k, value)?;
    finish_local(ctx, &mut s, &r, &v, false)?;
    clear_intent(ctx, &mut s)?;
    Ok(outcome)
}
pub(crate) fn observed_write<H: Host, T>(
    ctx: &mut Ctx<'_, H>,
    name: &str,
    write: impl FnOnce(&crate::keychain::Keychain) -> std::result::Result<T, kc_store::StoreError>,
) -> Result<T> {
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    recover(ctx, &mut s)?;
    if !s.items.contains_key(name) {
        return Ok(write(&ctx.store)?);
    }
    scan_one(ctx, &mut s, name)?;
    let item = s.items[name].clone();
    if item.conflict {
        super::receive::preserve_mine(ctx, &mut s, name, &item)?;
    }
    let previous = current(ctx, name)?.map_or(Fp([0; 32]), |v| v.2);
    let vid = Vid::random();
    let snapshot = snapshot_slot(vid);
    if !reserve(ctx, &mut s, &snapshot, SlotKind::ConflictCandidate, true)? {
        return Err(capacity());
    }
    let parents = vec![s.items[name].head];
    intent(
        ctx,
        &mut s,
        name,
        &Intent::Observe {
            name: name.into(),
            previous,
            vid,
            parents,
            snapshot,
        },
    )?;
    let result = write(&ctx.store)?;
    interrupted(ctx)?;
    recover(ctx, &mut s)?;
    Ok(result)
}
pub(crate) fn scan<H: Host>(ctx: &mut Ctx<'_, H>, s: &mut State) -> Result<()> {
    recover(ctx, s)?;
    for name in s.items.keys().cloned().collect::<Vec<_>>() {
        scan_one(ctx, s, &name)?;
        let item = s.items[&name].clone();
        if item.conflict {
            super::receive::preserve_mine(ctx, s, &name, &item)?;
        }
    }
    s.cleanup(ctx)
}
fn scan_one<H: Host>(ctx: &mut Ctx<'_, H>, s: &mut State, name: &str) -> Result<()> {
    let Some((value, kind, fp)) = current(ctx, name)? else {
        s.items.get_mut(name).ok_or_else(state_error)?.conflict = true;
        return s.save(&ctx.state);
    };
    if size(&value).is_err() {
        s.items.get_mut(name).unwrap().conflict = true;
        return s.save(&ctx.state);
    }
    let item = &s.items[name];
    let binding: VidRecord = private_get(ctx, &record_slot(name, item.head))?;
    if fp == binding.fp {
        return Ok(());
    }
    let parents = vec![item.head];
    let prepared = prepare_local(
        ctx,
        s,
        name,
        binding.fp,
        kind,
        &value,
        parents,
        Vid::random(),
        false,
    );
    let (r, v) = match prepared {
        Ok(value) => value,
        Err(error) if error.code == 8 && s.capacity_blocked => {
            s.items.get_mut(name).unwrap().conflict = true;
            log(
                ctx,
                tr!("Sync storage is full; review pending items before retrying."),
            )?;
            return s.save(&ctx.state);
        }
        Err(error) => return Err(error),
    };
    put_blob(ctx, &v.slot, kind, &value)?;
    finish_local(ctx, s, &r, &v, false)?;
    clear_intent(ctx, s)
}
pub(super) fn publish_current<H: Host>(
    ctx: &mut Ctx<'_, H>,
    s: &mut State,
    name: &str,
) -> Result<()> {
    let (value, kind, fp) = current(ctx, name)?.ok_or_else(state_error)?;
    let parents = vec![s.items[name].head];
    let (r, v) = prepare_local(
        ctx,
        s,
        name,
        fp,
        kind,
        &value,
        parents,
        Vid::random(),
        false,
    )?;
    put_blob(ctx, &v.slot, kind, &value)?;
    finish_local(ctx, s, &r, &v, false)?;
    clear_intent(ctx, s)
}
pub(super) fn resolve_value<H: Host>(
    ctx: &mut Ctx<'_, H>,
    s: &mut State,
    name: &str,
    value: &[u8],
    kind: ItemKind,
) -> Result<()> {
    let item = &s.items[name];
    if !item.conflict
        && !s.candidates.values().any(|c| c.version.name == name)
        && current(ctx, name)?.is_some_and(|v| v.1 == kind && v.0.as_slice() == value)
    {
        return Ok(());
    }
    let mut parents = vec![item.head];
    parents.extend(
        s.candidates
            .values()
            .filter(|c| c.version.name == name)
            .map(|c| c.version.vid),
    );
    parents.sort();
    parents.dedup();
    let fp = current(ctx, name)?.map_or(Fp([0; 32]), |v| v.2);
    let (r, v) = match prepare_local(ctx, s, name, fp, kind, value, parents, Vid::random(), true) {
        Ok(prepared) => prepared,
        Err(error) if error.code == 8 && s.capacity_blocked => {
            log(
                ctx,
                tr!("Sync storage is full; review pending items before retrying."),
            )?;
            return s.save(&ctx.state);
        }
        Err(error) => return Err(error),
    };
    ctx.store.set(name, value, map::kind(kind), Origin::Local)?;
    interrupted(ctx)?;
    put_blob(ctx, &v.slot, kind, value)?;
    finish_local(ctx, s, &r, &v, true)?;
    clear_intent(ctx, s)
}
pub(super) fn accept<H: Host>(ctx: &mut Ctx<'_, H>, s: &mut State, c: &Candidate) -> Result<bool> {
    let name = &c.version.name;
    let now = current(ctx, name)?;
    let actual = now.as_ref().map_or(Fp([0; 32]), |v| v.2);
    let expected: Fp = private_get(ctx, &c.base_record)?;
    let head = s.items.get(name).map(|i| i.head);
    if actual != expected || head != c.base_head || c.invalid_binding {
        if c.invalid_binding
            && let Some(peer) = s.peers.get_mut(&c.peer)
        {
            peer.quarantine.insert(name.into());
        }
        let key = c.version.slot.clone();
        if let Some(c) = s.candidates.get_mut(&key) {
            c.category = CandidateKind::Conflict;
        }
        if let Some(item) = s.items.get_mut(name) {
            item.conflict = true;
        }
        s.save(&ctx.state)?;
        return Ok(false);
    }
    if c.retire {
        super::actions::remove(ctx, s, name)?;
        return Ok(true);
    }
    let value = blob(ctx, &c.version.slot)?;
    let fp = fingerprint(ctx, name, value.kind, value.value.expose())?;
    let checkpoint = if now.is_some() {
        Some(checkpoint_slot(name))
    } else {
        None
    };
    if let Some(slot) = &checkpoint
        && !reserve(ctx, s, slot, SlotKind::Checkpoint, false)?
    {
        return Ok(false);
    }
    let lineage =
        kc_sync::Lineage::new(c.version.lineage.iter().copied().chain(head).map(map::vid))
            .with_head(map::vid(c.version.vid));
    let r = RemoteJournalRecord {
        change_id: kc_sync::ChangeId {
            name: name.clone(),
            generation: c.generation,
            new_vid: map::vid(c.version.vid),
        },
        sender: PeerId(c.peer.clone()),
        prev_fp: actual,
        new_fp: fp,
        head: map::vid(c.version.vid),
        lineage,
        approval_key: None,
        ack: kc_sync::AckResult::Applied,
        checkpoint_slot: checkpoint.clone(),
        candidate_slot: c.version.slot.clone(),
    };
    intent(
        ctx,
        s,
        name,
        &Intent::Remote {
            record: r.clone(),
            candidate: c.clone(),
        },
    )?;
    if let (Some(slot), Some((old, old_kind, _))) = (&checkpoint, now)
        && ctx.store.get_internal(slot)?.is_none()
    {
        put_blob(ctx, slot, old_kind, &old)?;
    }
    ctx.store.set(
        name,
        value.value.expose(),
        map::kind(value.kind),
        Origin::Received {
            from_device: super::actions::label(ctx, &c.peer)?,
        },
    )?;
    interrupted(ctx)?;
    finish_remote(ctx, s, &r, c)?;
    clear_intent(ctx, s)?;
    Ok(true)
}
fn finish_remote<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    r: &RemoteJournalRecord,
    c: &Candidate,
) -> Result<()> {
    let name = &r.change_id.name;
    if !remember(ctx, name, c.version.vid, r.new_fp, &c.version.parents)? {
        return Err(state_error());
    }
    let proposal = c.category == CandidateKind::Proposal;
    let mut scope = s
        .items
        .get(name)
        .map(|i| i.scope.clone())
        .unwrap_or_default();
    if !c.legacy {
        scope.insert(c.peer.clone());
    }
    let mut known = s
        .items
        .get(name)
        .map(|i| i.known.clone())
        .unwrap_or_default();
    if !known.contains(&c.version.vid) {
        known.push(c.version.vid);
    }
    if known.len() > 256 {
        known.remove(0);
    }
    s.items.insert(
        name.clone(),
        Item {
            head: c.version.vid,
            lineage: r.lineage.iter().copied().map(map::wire_vid).collect(),
            parents: c.version.parents.clone(),
            known,
            scope,
            own: false,
            conflict: false,
        },
    );
    if proposal {
        let registration = s.generations.accept(name, PeerId(c.peer.clone()));
        queue(
            s,
            &c.peer,
            Control::Accept {
                name: name.clone(),
                generation: registration.generation,
            },
        );
        // Both peers grant their own generations. The reciprocal Accept is sent once.
    } else if !c.legacy {
        queue(
            s,
            &c.peer,
            Control::Ack {
                id: kc_proto::sync::ChangeId {
                    name: crate::values::item_name(name)?,
                    generation: c.generation,
                    new_vid: c.version.vid,
                },
                result: map::wire_ack(r.ack),
            },
        );
    }
    clear_candidates(s, name);
    s.save(&ctx.state)
}
pub(super) fn queue(s: &mut State, peer: &str, message: Control) {
    // Coalesce metadata-only controls; messages never contain values or fingerprints.
    let encoded = serde_json::to_vec(&message).unwrap_or_default();
    if !s
        .controls
        .iter()
        .any(|(p, c)| p == peer && serde_json::to_vec(c).unwrap_or_default() == encoded)
    {
        s.controls.push((peer.into(), message));
    }
}
pub(crate) fn recover<H: Host>(ctx: &mut Ctx<'_, H>, s: &mut State) -> Result<()> {
    let Some(journal) = s.journal.clone() else {
        return collect_orphan_snapshots(ctx, s);
    };
    let record: Intent = private_get(ctx, &journal.record)?;
    match record {
        Intent::Local {
            record: r,
            version: v,
            clear,
        } => {
            let cur = current(ctx, &r.name)?;
            let fp = cur.as_ref().map_or(Fp([0; 32]), |v| v.2);
            let committed = s
                .items
                .get(&r.name)
                .is_some_and(|i| map::vid(i.head) == r.new_vid);
            let exists = ctx.store.get_internal(&r.snapshot_slot)?.is_some();
            match kc_sync::recover_local(r.prev_fp, r.new_fp, fp, committed, exists) {
                LocalRecovery::RebuildSnapshotAndCommit => {
                    let (value, kind, _) = cur.ok_or_else(state_error)?;
                    put_blob(ctx, &r.snapshot_slot, kind, &value)?;
                    finish_local(ctx, s, &r, &v, clear)?;
                }
                LocalRecovery::Commit => finish_local(ctx, s, &r, &v, clear)?,
                LocalRecovery::CleanJournal | LocalRecovery::KeepSnapshotAndScan => {}
                LocalRecovery::DiscardSnapshot | LocalRecovery::DiscardSnapshotAndScan => {
                    release(s, &r.snapshot_slot)
                }
            }
        }
        Intent::Remote {
            record: r,
            candidate: c,
        } => {
            let fp = current(ctx, &r.change_id.name)?.map_or(Fp([0; 32]), |v| v.2);
            match kc_sync::recover_remote(&r, fp) {
                RemoteRecovery::FinishFromStep4 => finish_remote(ctx, s, &r, &c)?,
                RemoteRecovery::Retry => {}
                RemoteRecovery::Conflict => {
                    if let Some(item) = s.items.get_mut(&r.change_id.name) {
                        item.conflict = true;
                    }
                    if let Some(candidate) = s.candidates.get_mut(&c.version.slot) {
                        candidate.category = CandidateKind::Conflict;
                    }
                }
            }
        }
        Intent::Observe {
            name,
            previous,
            vid,
            parents,
            snapshot,
        } => {
            if let Some((value, kind, fp)) = current(ctx, &name)? {
                if size(&value).is_err() {
                    s.items.get_mut(&name).ok_or_else(state_error)?.conflict = true;
                    release(s, &snapshot);
                } else if fp != previous {
                    let (r, v) =
                        prepare_local(ctx, s, &name, previous, kind, &value, parents, vid, false)?;
                    put_blob(ctx, &v.slot, kind, &value)?;
                    finish_local(ctx, s, &r, &v, false)?;
                } else {
                    release(s, &snapshot);
                }
            } else {
                release(s, &snapshot);
            }
        }
    }
    clear_intent(ctx, s)?;
    collect_orphan_snapshots(ctx, s)
}

fn collect_orphan_snapshots<H: Host>(ctx: &Ctx<'_, H>, s: &mut State) -> Result<()> {
    // Called after journal recovery: its in-flight snapshot must survive until then.
    let orphaned = s
        .slots
        .keys()
        .filter(|slot| {
            slot.starts_with("sync/snapshot/")
                && !s.versions.values().any(|v| &v.slot == *slot)
                && !s.offers.iter().any(|o| snapshot_slot(o.vid) == **slot)
                && !s.peers.keys().any(|peer| {
                    s.outbox
                        .pending(&PeerId(peer.clone()))
                        .any(|id| snapshot_slot(map::wire_vid(id.new_vid)) == **slot)
                })
        })
        .cloned()
        .collect::<Vec<_>>();
    for slot in orphaned {
        release(s, &slot);
    }
    if !s.gc.is_empty() {
        s.cleanup(ctx)?;
    }
    Ok(())
}

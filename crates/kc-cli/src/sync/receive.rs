use super::*;
use kc_proto::sync::{AckResult, Change, ChangeId, Op, SyncMsg};
use kc_sync::{Incoming, LimitResult, RemoteOperation, Transition};
use state::{Candidate, CandidateKind, Control, Peer};
use transaction::{put_blob, queue};

pub(crate) fn receive<H: Host>(ctx: &mut Ctx<'_, H>, peer: &str, message: &SyncMsg) -> Result<()> {
    // The shared inbox owns both locks before entering this adapter.
    let mut s = State::load(&ctx.state)?;
    scan(ctx, &mut s)?;
    s.receipts.retain(|_, (_, until)| *until >= ctx.host.now());
    s.attempts.retain(|_, until| *until >= ctx.host.now());
    let p = s.peers.entry(peer.into()).or_insert_with(|| Peer {
        enabled: true,
        ..Peer::default()
    });
    match message {
        SyncMsg::Hello { is_reply, .. } => {
            p.capable = true;
            s.reconnect = false;
            if !is_reply {
                queue(&mut s, peer, Control::Hello { reply: true });
            }
        }
        SyncMsg::Offer {
            name,
            vid,
            lineage,
            kind,
            value,
            known_generation,
        } => {
            let name = name.as_str();
            if !p.enabled || s.limiter.is_tripped(&PeerId(peer.into())) {
                log(
                    ctx,
                    tr!(
                        "Ignored a sync offer from disabled or blocked peer {peer}.",
                        peer = super::actions::label(ctx, peer)?
                    ),
                )?;
            } else if *known_generation < s.generations.generation(name) {
                log(
                    ctx,
                    tr!("Ignored a stale sync offer for {name}.", name = name),
                )?;
            } else if offer_rejected(
                &mut s,
                &delivery_key(peer, name, *known_generation, *vid),
                ctx.host.now(),
            ) {
                // A rejected proposal is never resurrected by a transport retry.
            } else if lineage.len() <= 64
                && value.expose().len() <= 200 * 1024
                && !value.expose().is_empty()
            {
                let mut version = Version {
                    name: name.into(),
                    vid: *vid,
                    parents: vec![],
                    lineage: lineage.clone(),
                    kind: *kind,
                    slot: candidate_slot(peer, *vid),
                };
                let fp = fingerprint(ctx, name, *kind, value.expose())?;
                // Offers carry no parent assertion; never replace an existing binding.
                let existing = ctx.store.get_internal(&record_slot(name, *vid))?;
                if existing.is_some()
                    && private_get::<_, VidRecord>(ctx, &record_slot(name, *vid))?.fp != fp
                {
                    s.peers
                        .get_mut(peer)
                        .unwrap()
                        .quarantine
                        .insert(name.into());
                } else if s
                    .items
                    .get(name)
                    .is_some_and(|i| i.head == *vid && i.scope.contains(peer))
                {
                    let generation = s.generations.generation(name);
                    queue(
                        &mut s,
                        peer,
                        Control::Accept {
                            name: name.into(),
                            generation,
                        },
                    );
                } else if !s.candidates.contains_key(&version.slot) {
                    let category = if s.items.get(name).is_some_and(|i| {
                        i.conflict
                            && i.scope.contains(peer)
                            && *known_generation == s.generations.generation(name)
                    }) {
                        CandidateKind::Conflict
                    } else {
                        CandidateKind::Proposal
                    };
                    if existing.is_some() {
                        let record: VidRecord = private_get(ctx, &record_slot(name, *vid))?;
                        version.parents = record.parents.into_iter().map(map::wire_vid).collect();
                    }
                    let times = s.proposals_today.entry(peer.into()).or_default();
                    times.retain(|at| (ctx.host.now() as i128) - (*at as i128) < 86400);
                    let allowed = times.len() < ctx.settings.sync.max_proposals_per_day;
                    let stored = allowed
                        && store_candidate(
                            ctx,
                            &mut s,
                            peer,
                            version,
                            *known_generation,
                            category,
                            value.expose(),
                            false,
                            false,
                        )?;
                    if stored {
                        if existing.is_none() {
                            s.unbound.insert(format!("{}:{}", name, vid_key(*vid)));
                        }
                        s.proposals_today
                            .entry(peer.into())
                            .or_default()
                            .push(ctx.host.now());
                    }
                    if !stored {
                        s.capacity_blocked = true;
                        queue(
                            &mut s,
                            peer,
                            Control::Ack {
                                id: ChangeId {
                                    name: crate::values::item_name(name)?,
                                    generation: *known_generation,
                                    new_vid: *vid,
                                },
                                result: AckResult::DeferredCapacity,
                            },
                        );
                    }
                }
            }
        }
        SyncMsg::Accept { name, generation } => {
            let name = name.as_str();
            // A peer may grant a generation only for an item explicitly offered to it,
            // or the reciprocal half of a locally accepted proposal.
            let wanted = s.offers.iter().any(|o| o.peer == peer && o.name == name)
                || s.items.get(name).is_some_and(|i| i.scope.contains(peer));
            let previously_accepted = s
                .generations
                .outgoing_generation(&PeerId(peer.into()), name)
                .is_some();
            if wanted
                && *generation >= 1
                && s.generations.received_accept(
                    PeerId(peer.into()),
                    kc_sync::Registration {
                        name: name.into(),
                        generation: *generation,
                    },
                )
            {
                let own = s.generations.accept(name, PeerId(peer.into()));
                if let Some(item) = s.items.get_mut(name) {
                    item.scope.insert(peer.into());
                }
                s.offers.retain(|o| o.peer != peer || o.name != name);
                s.peers.get_mut(peer).unwrap().reoffer.remove(name);
                s.outbox.accepted(&PeerId(peer.into()), name);
                if !previously_accepted {
                    queue(
                        &mut s,
                        peer,
                        Control::Accept {
                            name: name.into(),
                            generation: own.generation,
                        },
                    );
                }
                if !previously_accepted && s.items.get(name).is_some_and(|i| i.own) {
                    super::transport::resend(ctx, &mut s, peer, name)?;
                }
            }
        }
        SyncMsg::Leave { name, generation } => {
            let name = name.as_str();
            let expected = s.items.get(name).is_some_and(|i| i.scope.contains(peer))
                || s.generations.known_generation(&PeerId(peer.into()), name) != 0;
            if expected
                && s.generations.received_leave(
                    PeerId(peer.into()),
                    kc_sync::Registration {
                        name: name.into(),
                        generation: *generation,
                    },
                )
            {
                s.peers.get_mut(peer).unwrap().reoffer.insert(name.into());
                let ids: Vec<_> = s
                    .outbox
                    .pending(&PeerId(peer.into()))
                    .filter(|id| id.name == name)
                    .cloned()
                    .collect();
                for id in ids {
                    s.outbox.ack(
                        &PeerId(peer.into()),
                        &id,
                        kc_sync::AckResult::StaleGeneration,
                    );
                }
                s.offers.retain(|o| o.peer != peer || o.name != name);
            }
        }
        SyncMsg::Changes { changes } => {
            for change in changes {
                change_received(ctx, &mut s, peer, change)?;
            }
        }
        SyncMsg::Ack { results } => {
            for (id, result) in results {
                let expected = s
                    .outbox
                    .pending(&PeerId(peer.into()))
                    .any(|pending| *pending == map::id(id))
                    || s.offers.iter().any(|o| {
                        o.peer == peer && o.name == id.name.as_str() && o.vid == id.new_vid
                    });
                if !expected {
                    continue;
                }
                let delivery = delivery_key(peer, id.name.as_str(), id.generation, id.new_vid);
                if *result == AckResult::DeferredCapacity {
                    s.deferred.insert(delivery);
                } else {
                    s.deferred.remove(&delivery);
                }
                s.outbox
                    .ack(&PeerId(peer.into()), &map::id(id), map::ack(*result));
                if *result == AckResult::StaleGeneration
                    && s.generations
                        .known_generation(&PeerId(peer.into()), id.name.as_str())
                        <= id.generation
                {
                    // The ACK carries the rejected (old) generation, not the receiver's
                    // new one. Invalidate only that still-current grant; a reordered ACK
                    // must not revoke a newer Accept. Re-offering learns the actual epoch.
                    if s.generations
                        .outgoing_generation(&PeerId(peer.into()), id.name.as_str())
                        == Some(id.generation)
                    {
                        invalidate_generation(&mut s, peer, id.name.as_str())?;
                    }
                    s.peers
                        .get_mut(peer)
                        .unwrap()
                        .reoffer
                        .insert(id.name.to_string());
                }
            }
        }
        SyncMsg::Digest { entries } => {
            for entry in entries {
                let name = entry.name.as_str();
                let generation = s.generations.generation(name);
                if entry.generation < generation {
                    queue(
                        &mut s,
                        peer,
                        Control::Leave {
                            name: name.into(),
                            generation,
                        },
                    );
                    continue;
                }
                if let Some(item) = s.items.get(name).cloned() {
                    if item.own
                        && item.head != entry.head
                        && item.lineage.contains(&entry.head)
                        && item.scope.contains(peer)
                    {
                        super::transport::resend(ctx, &mut s, peer, name)?;
                    } else if item.head != entry.head && item.scope.contains(peer) {
                        s.peers.get_mut(peer).unwrap().reoffer.insert(name.into());
                    }
                }
            }
        }
        SyncMsg::Approvals { .. } => log(
            ctx,
            tr!("Ignored signed approvals: Phase 1 requires local review."),
        )?,
    }
    super::transport::collect_snapshots(&mut s);
    s.cleanup(ctx)
}
// The Phase 1 core API cannot revoke an accepted grant at the same generation.
// Preserve the known receiver epoch while clearing its grant in the persisted adapter.
fn invalidate_generation(s: &mut State, peer: &str, name: &str) -> Result<()> {
    let mut generations = serde_json::to_value(&s.generations).map_err(|_| state_error())?;
    let accepted = generations
        .get_mut("remote")
        .and_then(|remote| remote.get_mut(peer))
        .and_then(|names| names.get_mut(name))
        .and_then(|grant| grant.get_mut("accepted"))
        .ok_or_else(state_error)?;
    *accepted = serde_json::Value::Bool(false);
    s.generations = serde_json::from_value(generations).map_err(|_| state_error())?;
    Ok(())
}
fn ack(s: &mut State, peer: &str, c: &Change, result: AckResult) {
    queue(
        s,
        peer,
        Control::Ack {
            id: ChangeId {
                name: c.name.clone(),
                generation: c.generation,
                new_vid: c.new_vid,
            },
            result,
        },
    );
}
fn change_received<H: Host>(
    ctx: &mut Ctx<'_, H>,
    s: &mut State,
    peer: &str,
    c: &Change,
) -> Result<()> {
    let name = c.name.as_str();
    let Some(item) = s.items.get(name).cloned() else {
        ack(s, peer, c, AckResult::StaleGeneration);
        return Ok(());
    };
    if !item.scope.contains(peer)
        || !s.generations.includes(name, &PeerId(peer.into()))
        || c.generation != s.generations.generation(name)
    {
        ack(s, peer, c, AckResult::StaleGeneration);
        return Ok(());
    }
    let (value, kind, retire) = match &c.op {
        Op::Put { kind, value } => (value.expose(), *kind, false),
        Op::Retire => (&[][..], ItemKind::Text, true),
    };
    if (!retire && size(value).is_err()) || c.parents.len() > 256 {
        ack(s, peer, c, AckResult::Rejected);
        return Ok(());
    }
    if s.peers[peer].quarantine.contains(name) {
        ack(s, peer, c, AckResult::Rejected);
        return Ok(());
    }
    let slot = candidate_slot(peer, c.new_vid);
    let fp = if retire {
        None
    } else {
        Some(fingerprint(ctx, name, kind, value)?)
    };
    let delivery = delivery_key(peer, name, c.generation, c.new_vid);
    if let Some((AckResult::Rejected, _)) = s.receipts.get(&delivery) {
        ack(s, peer, c, AckResult::Rejected);
        return Ok(());
    }
    let current_fp = current(ctx, name)?.map_or(Fp([0; 32]), |v| v.2);
    let mut state = pure(ctx, s, name, &item)?;
    // An accepted Offer has no parent field. Bind its first explicit parent assertion
    // only when the fingerprint still matches the immutable offered value.
    let unbound = format!("{}:{}", name, vid_key(c.new_vid));
    if s.unbound.contains(&unbound)
        && let Some(rec) = state.known.get_mut(&map::vid(c.new_vid))
        && Some(rec.fp) == fp
    {
        rec.parents = c.parents.iter().copied().map(map::vid).collect();
        private_put(ctx, &record_slot(name, c.new_vid), rec)?;
        s.unbound.remove(&unbound);
    }
    let incoming = Incoming {
        generation: c.generation,
        new_vid: map::vid(c.new_vid),
        parents: c.parents.iter().copied().map(map::vid).collect(),
        lineage: kc_sync::Lineage::new(c.lineage.iter().copied().map(map::vid)),
        value_fp: fp,
        retire,
    };
    let unseen = !s.attempts.contains_key(&delivery)
        && !s.candidates.contains_key(&slot)
        && !state.lineage.contains(&incoming.new_vid);
    let overwrite = retire || fp != Some(current_fp);
    let mut within = ctx.settings.sync.max_remote_overwrites != 0;
    if unseen && overwrite {
        let op = if retire {
            RemoteOperation::Retire
        } else {
            RemoteOperation::Overwrite
        };
        within &= s.limiter.check(
            &PeerId(peer.into()),
            name,
            op,
            ctx.host.now(),
            s.items.len(),
            false,
        ) == LimitResult::Allowed;
        // Phase 1 counts durably received overwrite attempts, although they are held.
        s.limiter
            .record(&PeerId(peer.into()), name, op, ctx.host.now(), false);
        s.attempts
            .insert(delivery.clone(), ctx.host.now().saturating_add(3 * 86400));
    }
    let frozen = s.frozen || !s.peers[peer].enabled || s.limiter.is_tripped(&PeerId(peer.into()));
    let decision = kc_sync::decide(&state, current_fp, &incoming, frozen, None, within);
    if decision.quarantine {
        s.peers
            .get_mut(peer)
            .unwrap()
            .quarantine
            .insert(name.into());
    }
    let mut result = map::wire_ack(decision.ack);
    match decision.transition {
        Transition::Hold { .. } | Transition::Conflict { .. } => {
            let category = if result == AckResult::Conflict {
                CandidateKind::Conflict
            } else {
                CandidateKind::Held
            };
            if category == CandidateKind::Conflict {
                preserve_mine(ctx, s, name, &item)?;
            }
            let version = Version {
                name: name.into(),
                vid: c.new_vid,
                parents: c.parents.clone(),
                lineage: c.lineage.clone(),
                kind,
                slot: slot.clone(),
            };
            if !store_candidate(
                ctx,
                s,
                peer,
                version,
                c.generation,
                category,
                value,
                retire,
                false,
            )? {
                result = AckResult::DeferredCapacity;
            } else {
                if category == CandidateKind::Conflict {
                    s.items.get_mut(name).unwrap().conflict = true;
                }
                // Only a stored successor may retire the held change it supersedes.
                transaction::retire_superseded(s, ctx.host.now());
            }
        }
        Transition::Advance {
            head,
            lineage,
            write_value: false,
            ..
        } => {
            if let Some(fp) = fp
                && !matches!(remember(ctx, name, c.new_vid, fp, &c.parents), Ok(true))
            {
                s.peers
                    .get_mut(peer)
                    .unwrap()
                    .quarantine
                    .insert(name.into());
                s.receipts.insert(
                    delivery,
                    (
                        AckResult::Rejected,
                        ctx.host.now().saturating_add(3 * 86400),
                    ),
                );
                ack(s, peer, c, AckResult::Rejected);
                log(
                    ctx,
                    tr!(
                        "Sync {name}: {result}.",
                        name = name,
                        result = tr!("declined")
                    ),
                )?;
                return s.save(&ctx.state);
            }
            let item = s.items.get_mut(name).unwrap();
            item.head = map::wire_vid(head);
            item.lineage = lineage.iter().copied().map(map::wire_vid).collect();
            if item.head == c.new_vid {
                item.parents = c.parents.clone();
                item.own = false;
            }
            if !item.known.contains(&c.new_vid) {
                item.known.push(c.new_vid);
            }
        }
        Transition::Unchanged => {}
        // No verified approval is ever constructed in Phase 1.
        _ => return Err(state_error()),
    }
    if result != AckResult::DeferredCapacity {
        s.receipts
            .insert(delivery, (result, ctx.host.now().saturating_add(3 * 86400)));
    }
    ack(s, peer, c, result);
    s.save(&ctx.state)?;
    let result_text = match result {
        AckResult::Applied => tr!("in sync"),
        AckResult::Held => tr!("held"),
        AckResult::Conflict => tr!("conflict"),
        AckResult::Rejected => tr!("declined"),
        AckResult::StaleGeneration => tr!("re-offer needed"),
        AckResult::DeferredCapacity => {
            tr!("Sync storage is full; review pending items before retrying.")
        }
    };
    log(
        ctx,
        tr!("Sync {name}: {result}.", name = name, result = result_text),
    )?;
    Ok(())
}
pub(super) fn preserve_mine<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    name: &str,
    item: &Item,
) -> Result<()> {
    let slot = candidate_slot("mine", item.head);
    if s.candidates.contains_key(&slot) {
        return Ok(());
    }
    if let Some((value, kind, _)) = current(ctx, name)? {
        if size(&value).is_err() {
            return Ok(());
        }
        let version = Version {
            name: name.into(),
            vid: item.head,
            parents: item.parents.clone(),
            lineage: item.lineage.clone(),
            kind,
            slot,
        };
        if !store_candidate(
            ctx,
            s,
            "mine",
            version,
            s.generations.generation(name),
            CandidateKind::Conflict,
            &value,
            false,
            false,
        )? {
            log(
                ctx,
                tr!("Sync storage is full; review pending items before retrying."),
            )?;
        }
    }
    Ok(())
}
#[allow(clippy::too_many_arguments)]
pub(super) fn store_candidate<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    peer: &str,
    mut v: Version,
    generation: u64,
    category: CandidateKind,
    value: &[u8],
    retire: bool,
    legacy: bool,
) -> Result<bool> {
    let mut invalid_binding = false;
    if !retire
        && category != CandidateKind::Proposal
        && ctx
            .store
            .get_internal(&record_slot(&v.name, v.vid))?
            .is_some()
    {
        let record: VidRecord = private_get(ctx, &record_slot(&v.name, v.vid))?;
        invalid_binding = record.fp != fingerprint(ctx, &v.name, v.kind, value)?
            || record.parents != v.parents.iter().copied().map(map::vid).collect::<Vec<_>>();
    }
    if invalid_binding {
        // Freeze precedes immutable-VID violations: retain the evidence without changing
        // the immutable binding. Review must turn it into a conflict, never apply that vid.
        for old in s.candidates.values().filter(|c| {
            c.peer == peer
                && c.version.vid == v.vid
                && c.invalid_binding
                && c.version.parents == v.parents
        }) {
            let stored = transaction::blob(ctx, &old.version.slot)?;
            if stored.kind == v.kind && stored.value.expose() == value {
                return Ok(true);
            }
        }
        v.slot.push_str(&format!("/{}", hex(&Vid::random().0[..4])));
    }
    if let Some(old) = s.candidates.get(&v.slot) {
        let promote = old.category == CandidateKind::Proposal
            && category != CandidateKind::Proposal
            && !invalid_binding;
        if (!promote && old.version.parents != v.parents) || old.retire != retire {
            return Ok(false);
        }
        if !retire {
            let old_value = transaction::blob(ctx, &v.slot)?;
            if old_value.value.expose() != value || old_value.kind != v.kind {
                return Ok(false);
            }
        }
        if promote || category == CandidateKind::Conflict {
            let old = s.candidates.get_mut(&v.slot).unwrap();
            old.category = category;
            old.version.parents = v.parents;
            old.version.lineage = v.lineage;
            old.generation = generation;
            s.slots.insert(
                v.slot.clone(),
                if category == CandidateKind::Conflict {
                    SlotKind::ConflictCandidate
                } else {
                    SlotKind::Held
                },
            );
        }
        return Ok(true);
    }
    let kind = match category {
        CandidateKind::Proposal => SlotKind::Proposal,
        CandidateKind::Held => SlotKind::Held,
        CandidateKind::Conflict => SlotKind::ConflictCandidate,
    };
    if !reserve(ctx, s, &v.slot, kind, false)? {
        return Ok(false);
    }
    let base = current(ctx, &v.name)?.map_or(Fp([0; 32]), |v| v.2);
    let base_record = format!("sync/base/{}", vid_key(Vid::random()));
    private_put(ctx, &base_record, &base)?;
    if !retire {
        put_blob(ctx, &v.slot, v.kind, value)?;
        let fp = fingerprint(ctx, &v.name, v.kind, value)?;
        if category == CandidateKind::Proposal {
            if ctx
                .store
                .get_internal(&record_slot(&v.name, v.vid))?
                .is_none()
            {
                remember(ctx, &v.name, v.vid, fp, &[])?;
                s.unbound.insert(format!("{}:{}", v.name, vid_key(v.vid)));
            }
        } else if !invalid_binding && !remember(ctx, &v.name, v.vid, fp, &v.parents)? {
            release(s, &v.slot);
            s.gc.insert(base_record);
            return Ok(false);
        }
    }
    if !retire
        && !invalid_binding
        && let Some(item) = s.items.get_mut(&v.name)
    {
        if !item.known.contains(&v.vid) {
            item.known.push(v.vid);
        }
        while item.known.len() > 256 {
            let index = item.known.iter().position(|vid| *vid != item.head).unwrap();
            item.known.remove(index);
        }
    }
    let key = v.slot.clone();
    s.candidates.insert(
        key,
        Candidate {
            peer: peer.into(),
            generation,
            category,
            base_head: s.items.get(&v.name).map(|i| i.head),
            version: v,
            base_record,
            retire,
            legacy,
            invalid_binding,
        },
    );
    Ok(true)
}
/// Existing v1/code imports enter the same review path. Caller already owns both locks.
/// A terminal may confirm the individual overwrite locally; noninteractive imports hold.
pub(crate) fn legacy<H: Host>(
    ctx: &mut Ctx<'_, H>,
    item: &kc_proto::payload::Item,
    from: &str,
    overwrite: bool,
) -> Result<Option<kc_proto::ItemStatus>> {
    let mut s = State::load(&ctx.state)?;
    if !s.items.contains_key(item.name.as_str()) {
        return Ok(None);
    }
    recover(ctx, &mut s)?;
    scan(ctx, &mut s)?;
    let name = item.name.as_str();
    let kind = if std::str::from_utf8(item.value.expose()).is_ok() {
        ItemKind::Text
    } else {
        ItemKind::File
    };
    if current(ctx, name)?.is_some_and(|v| v.0.as_slice() == item.value.expose()) {
        return Ok(Some(kc_proto::ItemStatus::Unchanged));
    }
    size(item.value.expose())?;
    let peer = ctx
        .state
        .load_peers()?
        .find(from)
        .map(|p| p.fingerprint.to_hex())
        .unwrap_or_else(|| "legacy".into());
    let vid = Vid::random();
    let v = Version {
        name: name.into(),
        vid,
        parents: vec![s.items[name].head],
        lineage: s.items[name].lineage.clone(),
        kind,
        slot: candidate_slot(&peer, vid),
    };
    let slot = v.slot.clone();
    let generation = s.generations.generation(name);
    if !store_candidate(
        ctx,
        &mut s,
        &peer,
        v,
        generation,
        CandidateKind::Held,
        item.value.expose(),
        false,
        true,
    )? {
        s.cleanup(ctx)?;
        crate::commands::say!(ctx, "{}", tr!("Sync item held; run `kc sync review`."));
        return Ok(Some(kc_proto::ItemStatus::SkippedConflict));
    }
    s.save(&ctx.state)?;
    if overwrite && ctx.interactive() && !s.frozen {
        if let Err(error) = human(
            ctx,
            &tr!(
                "Replace {name} with the value from {device}",
                name = name,
                device = from
            ),
        ) {
            s.cleanup(ctx)?;
            crate::commands::say!(ctx, "{}", tr!("Sync item held; run `kc sync review`."));
            return Err(error);
        }
        let c = s.candidates[&slot].clone();
        if transaction::accept(ctx, &mut s, &c)? {
            return Ok(Some(kc_proto::ItemStatus::Stored));
        }
    }
    s.cleanup(ctx)?;
    crate::commands::say!(ctx, "{}", tr!("Sync item held; run `kc sync review`."));
    Ok(Some(kc_proto::ItemStatus::SkippedConflict))
}

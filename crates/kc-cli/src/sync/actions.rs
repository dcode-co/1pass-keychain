use super::*;
use crate::cli::{SyncCommand, SyncPeerCommand};
use state::{CandidateKind, Control, Item, Offer, Peer};
use transaction::{Accepted, blob, put_blob, queue};

pub(crate) fn label<H: Host>(ctx: &Ctx<'_, H>, peer: &str) -> Result<String> {
    if peer == "mine" {
        return Ok(tr!("this device"));
    }
    Ok(ctx
        .state
        .load_peers()?
        .peers
        .iter()
        .find(|p| p.fingerprint.to_hex() == peer)
        .map(|p| p.label.to_string())
        .unwrap_or_else(|| peer.to_string()))
}
fn selected_peers<H: Host>(ctx: &Ctx<'_, H>, s: &State, labels: &[String]) -> Result<Vec<String>> {
    let peers = ctx.state.load_peers()?;
    if labels.is_empty() {
        return Ok(peers
            .peers
            .iter()
            .filter(|p| {
                s.peers
                    .get(&p.fingerprint.to_hex())
                    .is_none_or(|p| p.enabled)
            })
            .map(|p| p.fingerprint.to_hex())
            .collect());
    }
    labels
        .iter()
        .map(|label| {
            peers
                .find(label)
                .map(|p| p.fingerprint.to_hex())
                .ok_or_else(|| {
                    CliError::not_found(tr!("Unknown sync peer: {label}.", label = label))
                })
        })
        .collect()
}
fn offer<H: Host>(ctx: &mut Ctx<'_, H>, s: &mut State, name: &str, peers: &[String]) -> Result<()> {
    let (value, kind, fp) = current(ctx, name)?.ok_or_else(state_error)?;
    size(&value)?;
    let item = s.items[name].clone();
    // Re-offering a received value is a new local publication, never forwarding its vid.
    if item.conflict {
        return Err(CliError::new(8, tr!("Sync needs local confirmation.")));
    }
    if !item.own {
        transaction::publish_current(ctx, s, name)?;
    }
    let item = s.items[name].clone();
    let slot = snapshot_slot(item.head);
    if !reserve(ctx, s, &slot, SlotKind::ConflictCandidate, true)? {
        return Err(capacity());
    }
    put_blob(ctx, &slot, kind, &value)?;
    remember(ctx, name, item.head, fp, &item.parents)?;
    s.latest_local.insert(name.into(), item.head);
    s.versions.insert(
        vid_key(item.head),
        Version {
            name: name.into(),
            vid: item.head,
            parents: item.parents.clone(),
            lineage: item.lineage.clone(),
            kind,
            slot,
        },
    );
    for peer in peers {
        s.peers.entry(peer.clone()).or_insert_with(|| Peer {
            enabled: true,
            ..Peer::default()
        });
        s.items.get_mut(name).unwrap().scope.insert(peer.clone());
        s.generations.accept(name, PeerId(peer.clone()));
        s.offers.retain(|o| o.peer != *peer || o.name != name);
        s.offers.push(Offer {
            peer: peer.clone(),
            name: name.into(),
            vid: item.head,
        });
    }
    Ok(())
}
pub(crate) fn remove<H: Host>(ctx: &Ctx<'_, H>, s: &mut State, name: &str) -> Result<()> {
    let (registration, mut peers) = s.generations.rm(name).map_err(|_| state_error())?;
    // The known vids' sync/fp records stay: after `sync add` of the same name, a peer could
    // otherwise reuse an old vid with another value under the new generation unquarantined.
    if let Some(item) = s.items.remove(name) {
        peers.extend(item.scope.into_iter().map(PeerId));
    }
    for peer in peers {
        if peer.0 == "mine" {
            continue;
        }
        queue(
            s,
            &peer.0,
            Control::Leave {
                name: name.into(),
                generation: registration.generation,
            },
        );
    }
    let checkpoint = checkpoint_slot(name);
    s.slots.remove(&checkpoint);
    s.gc.insert(checkpoint);
    s.offers.retain(|o| o.name != name);
    transaction::clear_candidates(s, name);
    for peer in s.peers.keys().cloned().collect::<Vec<_>>() {
        let ids = s
            .outbox
            .pending(&PeerId(peer.clone()))
            .filter(|id| id.name == name)
            .cloned()
            .collect::<Vec<_>>();
        for id in ids {
            s.outbox
                .ack(&PeerId(peer.clone()), &id, kc_sync::AckResult::Rejected);
        }
    }
    super::transport::collect_snapshots(s);
    s.cleanup(ctx)
}
/// One `kc sync status` row for people: an item (`peers`) or a candidate (`peer`).
fn row_line(row: &serde_json::Value) -> String {
    let peers = match (&row["peer"], &row["peers"]) {
        (serde_json::Value::String(peer), _) => peer.clone(),
        (_, serde_json::Value::Array(peers)) if !peers.is_empty() => peers
            .iter()
            .filter_map(|p| p.as_str())
            .collect::<Vec<_>>()
            .join(", "),
        _ => "-".into(),
    };
    format!(
        "{}  {}  {}  {}",
        row["name"].as_str().unwrap_or(""),
        row["state"].as_str().unwrap_or(""),
        row["fingerprint"].as_str().unwrap_or("-"),
        peers
    )
}
/// One device line for people, naming only what needs attention.
fn peer_line(peer: &serde_json::Value) -> String {
    let count = |key: &str| peer[key].as_array().map_or(0, Vec::len);
    let mut flags = Vec::new();
    if peer["enabled"] == false {
        flags.push(tr!("removed from sync"));
    }
    if peer["v2"] == false {
        flags.push(tr!("hasn't answered the sync handshake yet"));
    }
    if peer["breaker"] == true {
        flags.push(tr!("paused after too many changes"));
    }
    if count("quarantine") > 0 {
        flags.push(tr!("quarantined: {n}", n = count("quarantine")));
    }
    if count("reoffer") > 0 {
        flags.push(tr!("re-offer needed: {n}", n = count("reoffer")));
    }
    let state = if flags.is_empty() {
        tr!("ok")
    } else {
        flags.join(", ")
    };
    tr!(
        "device {label}: {state}",
        label = peer["label"].as_str().unwrap_or(""),
        state = state
    )
}
/// What keeps sync at exit code 8, for people. Mirrors [`pending`].
pub(crate) fn pending_notes(s: &State) -> Vec<String> {
    let mut notes = Vec::new();
    if s.frozen {
        notes.push(tr!("sync is frozen (`kc sync unfreeze`)"));
    }
    if s.capacity_blocked {
        notes.push(tr!("sync storage is full"));
    }
    if !s.offers.is_empty() {
        notes.push(tr!("waiting for review on other devices"));
    }
    if !s.candidates.is_empty() {
        notes.push(tr!("changes to review here (`kc sync review`)"));
    }
    if s.items.values().any(|i| i.conflict) {
        notes.push(tr!("conflicts to resolve (`kc sync resolve`)"));
    }
    if s.reconnect
        || s.delivery_failed
        || s.peers
            .keys()
            .any(|p| s.outbox.pending(&PeerId(p.clone())).next().is_some())
    {
        notes.push(tr!("changes queued for delivery (`kc sync`)"));
    }
    if s.peers.iter().any(|(p, peer)| {
        !peer.reoffer.is_empty()
            || !peer.quarantine.is_empty()
            || s.limiter.is_tripped(&PeerId(p.clone()))
    }) {
        notes.push(tr!("a device needs attention (`kc sync status`)"));
    }
    notes
}
pub(crate) fn status<H: Host>(ctx: &mut Ctx<'_, H>, json: bool) -> Result<i32> {
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    recover(ctx, &mut s)?;
    let mut rows = Vec::new();
    for (name, item) in &s.items {
        let state = if s.frozen {
            tr!("frozen")
        } else if item.conflict {
            tr!("conflict")
        } else if item
            .scope
            .iter()
            .any(|p| s.peers.get(p).is_some_and(|p| p.reoffer.contains(name)))
        {
            tr!("re-offer needed")
        } else if s
            .candidates
            .values()
            .any(|c| c.version.name == *name && c.category == CandidateKind::Held)
        {
            tr!("held")
        } else if s.offers.iter().any(|o| o.name == *name)
            || item.scope.iter().any(|p| {
                s.outbox
                    .pending(&PeerId(p.clone()))
                    .any(|c| c.name == *name)
            })
        {
            tr!("awaiting review")
        } else {
            tr!("in sync")
        };
        let fingerprint = ctx
            .store
            .get(name)?
            .map(|v| crate::values::value_fingerprint(v.as_bytes()));
        let peers = item
            .scope
            .iter()
            .map(|p| label(ctx, p))
            .collect::<Result<Vec<_>>>()?;
        rows.push(serde_json::json!({"name": name, "state": state, "head": item.head, "fingerprint": fingerprint, "peers": peers}));
    }
    let mut candidates = Vec::new();
    for c in s.candidates.values() {
        let fp = if c.retire {
            None
        } else {
            {
                let value = blob(ctx, &c.version.slot)?;
                Some(crate::values::value_fingerprint(value.value.expose()))
            }
        };
        let state = match c.category {
            CandidateKind::Proposal => tr!("proposal"),
            CandidateKind::Held => tr!("held"),
            CandidateKind::Conflict => tr!("conflict"),
        };
        candidates.push(serde_json::json!({"name": c.version.name, "state": state, "peer": label(ctx, &c.peer)?, "vid": c.version.vid, "fingerprint": fp}));
    }
    let mut peers = Vec::new();
    for (id, peer) in &s.peers {
        peers.push(serde_json::json!({"label":label(ctx, id)?, "enabled":peer.enabled, "v2":peer.capable,
            "breaker":s.limiter.is_tripped(&PeerId(id.clone())), "quarantine":peer.quarantine, "last_digest":peer.last_digest, "reoffer":peer.reoffer}));
    }
    let output = serde_json::json!({"items": rows, "candidates": candidates, "peers": peers, "frozen":s.frozen,
        "capacity_blocked":s.capacity_blocked, "slots_used":s.slots.len(), "slot_capacity":SlotBudget::new(s.items.len()).capacity(),
        "reconnect":s.reconnect, "delivery_failed":s.delivery_failed, "notice":tr!("Only the device that created a change sends it; if it is lost, publish a new local change from a remaining copy.")});
    if json {
        ctx.emit(
            format!(
                "{}\n",
                serde_json::to_string_pretty(&output).map_err(|_| state_error())?
            )
            .as_bytes(),
        )?;
    } else {
        for row in rows.iter().chain(&candidates) {
            ctx.emit(format!("{}\n", row_line(row)).as_bytes())?;
        }
        for peer in &peers {
            ctx.emit(format!("{}\n", peer_line(peer)).as_bytes())?;
        }
        if s.capacity_blocked {
            crate::commands::say!(
                ctx,
                "{}",
                tr!("Sync storage is full; review pending items before retrying.")
            );
        }
        if s.reconnect || s.delivery_failed {
            crate::commands::say!(
                ctx,
                "{}",
                tr!("Sync delivery is queued; run `kc sync` to retry.")
            );
        }
        crate::commands::say!(
            ctx,
            "{}",
            tr!(
                "Only the device that created a change sends it; if it is lost, publish a new local change from a remaining copy."
            )
        );
    }
    Ok(if pending(&s) { 8 } else { 0 })
}
pub(crate) fn review<H: Host>(ctx: &mut Ctx<'_, H>) -> Result<i32> {
    if !ctx.interactive() {
        human(ctx, &tr!("Review sync changes."))?;
    }
    let candidates = {
        let _items = ctx.state.lock_items(ctx.store.namespace())?;
        let _state = ctx.state.lock()?;
        let s = State::load(&ctx.state)?;
        if s.frozen {
            return Ok(8);
        }
        s.candidates
            .values()
            .filter(|c| c.category != CandidateKind::Conflict)
            .filter(|c| !transaction::is_superseded(&s, c))
            .cloned()
            .collect::<Vec<_>>()
    };
    if candidates.is_empty() {
        crate::commands::say!(ctx, "{}", tr!("Nothing to review."));
    }
    let mut accepts = Vec::new();
    let mut rejects = Vec::new();
    let mut later = Vec::new();
    for c in candidates {
        let fingerprint = if c.retire {
            "-".into()
        } else {
            let value = blob(ctx, &c.version.slot)?;
            crate::values::value_fingerprint(value.value.expose())
        };
        let existing = ctx
            .store
            .get(&c.version.name)?
            .map(|v| crate::values::value_fingerprint(v.as_bytes()))
            .unwrap_or_else(|| "-".into());
        let question = tr!(
            "Review {name} from {peer}: current {current}, proposed {proposed}.",
            name = c.version.name,
            peer = label(ctx, &c.peer)?,
            current = existing,
            proposed = fingerprint
        );
        match ctx.select(
            &question,
            &[tr!("Accept"), tr!("Reject"), tr!("Leave for later")],
            2,
        )? {
            0 => accepts.push(c),
            1 => rejects.push(c),
            _ => later.push(c.version.name),
        }
    }
    if !accepts.is_empty() || !rejects.is_empty() {
        let names = names_summary(
            &accepts
                .iter()
                .map(|c| c.version.name.clone())
                .collect::<Vec<_>>(),
        );
        let devices = names_summary(
            &accepts
                .iter()
                .map(|c| label(ctx, &c.peer))
                .collect::<Result<Vec<_>>>()?,
        );
        let rejected = names_summary(
            &rejects
                .iter()
                .map(|c| c.version.name.clone())
                .collect::<Vec<_>>(),
        );
        // The OS dialog shows only the clauses that apply.
        let reason = match (accepts.is_empty(), rejects.is_empty()) {
            (false, false) => tr!(
                "Accept {names} from {devices}; reject {rejected}",
                names = names,
                devices = devices,
                rejected = rejected
            ),
            (false, true) => tr!(
                "Accept {names} from {devices}",
                names = names,
                devices = devices
            ),
            _ => tr!("Reject {rejected}", rejected = rejected),
        };
        human(ctx, &reason)?;
    }
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    scan(ctx, &mut s)?;
    let mut done = Vec::new();
    for c in rejects {
        if let Some(current) = s.candidates.remove(&c.version.slot) {
            done.push(tr!("Rejected {name}.", name = c.version.name));
            release(&mut s, &current.version.slot);
            s.gc.insert(current.base_record);
            let delivery = delivery_key(&c.peer, &c.version.name, c.generation, c.version.vid);
            if c.category == CandidateKind::Proposal {
                reject_offer(&mut s, delivery, ctx.host.now());
                forget_binding(&mut s, &c.version.name, c.version.vid);
            } else {
                drop_binding(&mut s, &c.version.name, c.version.vid);
                s.receipts.insert(
                    delivery,
                    (
                        kc_proto::sync::AckResult::Rejected,
                        ctx.host.now().saturating_add(3 * 86400),
                    ),
                );
            }
            if !c.legacy && c.category != CandidateKind::Proposal {
                queue(
                    &mut s,
                    &c.peer,
                    Control::Ack {
                        id: kc_proto::sync::ChangeId {
                            name: crate::values::item_name(&c.version.name)?,
                            generation: c.generation,
                            new_vid: c.version.vid,
                        },
                        result: kc_proto::sync::AckResult::Rejected,
                    },
                );
            }
        }
    }
    // Accepting one candidate clears the item's other candidates.
    let mut applied = std::collections::BTreeSet::new();
    for c in accepts {
        if s.frozen {
            break;
        }
        // The candidate may have changed since it was listed: retired as superseded by a
        // newer change from the same peer, or turned into a conflict.
        let Some(current) = s.candidates.get(&c.version.slot).cloned() else {
            if !applied.contains(&c.version.name) {
                done.push(tr!(
                    "{name} from {peer} was replaced by a newer change; run `kc sync review` again.",
                    name = c.version.name,
                    peer = label(ctx, &c.peer)?
                ));
            }
            continue;
        };
        if current.category == CandidateKind::Conflict {
            done.push(tr!(
                "{name} is in conflict; settle it with `kc sync resolve {name}` first.",
                name = c.version.name
            ));
        } else {
            match transaction::accept(ctx, &mut s, &current)? {
                Accepted::Applied => {
                    done.push(tr!(
                        "Accepted {name} from {peer}.",
                        name = c.version.name,
                        peer = label(ctx, &c.peer)?
                    ));
                    applied.insert(c.version.name.clone());
                }
                Accepted::Conflict => done.push(tr!(
                    "{name} changed on this device meanwhile and is now a conflict; settle it with `kc sync resolve {name}`.",
                    name = c.version.name
                )),
                // accept() already said which conflict must be settled first.
                Accepted::Unsettled => {}
                Accepted::Full => done.push(tr!(
                    "Sync storage is full; review pending items before retrying."
                )),
            }
        }
    }
    s.cleanup(ctx)?;
    for line in done {
        crate::commands::say!(ctx, "{line}");
    }
    for name in later {
        crate::commands::say!(ctx, "{}", tr!("Left {name} for later.", name = name));
    }
    Ok(if pending(&s) { 8 } else { 0 })
}
pub(crate) fn command<H: Host>(ctx: &mut Ctx<'_, H>, mut command: SyncCommand) -> Result<i32> {
    if let SyncCommand::Status {
        json,
        confirm_checkpoint: None,
    } = command
    {
        return status(ctx, json);
    }
    if matches!(command, SyncCommand::Review) {
        return review(ctx);
    }
    if let SyncCommand::Add { names, .. } = &mut command
        && names.is_empty()
    {
        let options = ctx
            .store
            .list()?
            .into_iter()
            .map(|i| i.name)
            .collect::<Vec<_>>();
        *names = ctx
            .multi_select(&tr!("Select sync items."), &options)?
            .into_iter()
            .map(|i| options[i].clone())
            .collect();
    }
    let reason = match &command {
        SyncCommand::Add { names, .. } => {
            Some(tr!("kc sync add {names}", names = names_summary(names)))
        }
        SyncCommand::Rm { names } => Some(tr!("kc sync rm {names}", names = names_summary(names))),
        SyncCommand::Peer {
            command: SyncPeerCommand::Add { label },
        } => Some(tr!("kc sync peer add {label}", label = label)),
        SyncCommand::Peer {
            command: SyncPeerCommand::Rm { label },
        } => Some(tr!("kc sync peer rm {label}", label = label)),
        SyncCommand::Resolve { name, keep } => Some(tr!(
            "Resolve {name}: keep {choice}",
            name = name,
            choice = keep
        )),
        SyncCommand::RestoreCheckpoint { name } => {
            Some(tr!("Restore {name} to its checkpoint", name = name))
        }
        SyncCommand::Unfreeze => Some(tr!("Unfreeze sync")),
        SyncCommand::Status {
            confirm_checkpoint: Some(name),
            ..
        } => Some(tr!(
            "Confirm the current value of {name} as its checkpoint",
            name = name
        )),
        _ => None,
    };
    if let Some(reason) = reason {
        human(ctx, &reason)?;
    }
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    recover(ctx, &mut s)?;
    let mut done = Vec::new();
    match command {
        SyncCommand::Add { names, peers } => {
            let peers = selected_peers(ctx, &s, &peers)?;
            let mut added = Vec::new();
            for name in &names {
                crate::values::item_name(name)?;
                let (v, _, _) = current(ctx, name)?.ok_or_else(state_error)?;
                size(&v)?;
            }
            for name in names {
                let (value, kind, fp) = current(ctx, &name)?.ok_or_else(state_error)?;
                if !s.items.contains_key(&name) {
                    let head = Vid::random();
                    remember(ctx, &name, head, fp, &[])?;
                    s.items.insert(
                        name.clone(),
                        Item {
                            head,
                            lineage: vec![head],
                            parents: vec![],
                            known: vec![head],
                            scope: Default::default(),
                            own: true,
                            conflict: false,
                        },
                    );
                    // Allocate receiver generation even when there are no peers yet.
                    s.generations.accept(&name, PeerId("mine".into()));
                }
                let _ = (value, kind);
                offer(ctx, &mut s, &name, &peers)?;
                added.push(name);
            }
            for name in added {
                done.push(match peers.len() {
                    0 => tr!(
                        "Added {name} to sync; there is no paired device to offer it to yet.",
                        name = name
                    ),
                    n => crate::commands::plural_tr(
                        n,
                        tr!(
                            "Added {name} to sync and offered it to {n} device; accept it there with `kc sync review`.",
                            name = name,
                            n = n
                        ),
                        tr!(
                            "Added {name} to sync and offered it to {n} devices; accept it on each with `kc sync review`.",
                            name = name,
                            n = n
                        ),
                    ),
                });
            }
        }
        SyncCommand::Offer { names, peers } => {
            let peers = selected_peers(ctx, &s, &peers)?;
            for name in names {
                if !s.items.contains_key(&name) {
                    return Err(state_error());
                }
                // An agent may propose only to the already locally approved scope.
                let allowed = peers
                    .iter()
                    .filter(|p| s.items[&name].scope.contains(*p))
                    .cloned()
                    .collect::<Vec<_>>();
                if allowed.len() != peers.len() {
                    return Err(CliError::interaction(tr!("Sync needs local confirmation.")));
                }
                // An explicit re-offer is a fresh proposal even if the previous vid
                // was rejected. Transport retries keep the old vid and stay rejected.
                if s.items[&name].conflict {
                    return Err(CliError::new(8, tr!("Sync needs local confirmation.")));
                }
                transaction::publish_current(ctx, &mut s, &name)?;
                offer(ctx, &mut s, &name, &allowed)?;
            }
        }
        SyncCommand::Rm { names } => {
            for name in names {
                crate::values::item_name(&name)?;
                remove(ctx, &mut s, &name)?;
            }
        }
        SyncCommand::Freeze => s.frozen = true,
        SyncCommand::Unfreeze => {
            s.frozen = false;
            for peer in s.peers.keys() {
                s.limiter.human_reset(&PeerId(peer.clone()));
            }
        }
        SyncCommand::Status {
            confirm_checkpoint: Some(name),
            ..
        } => {
            if !s.items.contains_key(&name) {
                return Err(state_error());
            }
            let (value, kind, _) = current(ctx, &name)?.ok_or_else(state_error)?;
            let slot = checkpoint_slot(&name);
            if !reserve(ctx, &mut s, &slot, SlotKind::Checkpoint, false)? {
                return Err(capacity());
            }
            put_blob(ctx, &slot, kind, &value)?;
        }
        SyncCommand::RestoreCheckpoint { name } => {
            scan(ctx, &mut s)?;
            if !s.items.contains_key(&name) {
                return Err(state_error());
            }
            let value = blob(ctx, &checkpoint_slot(&name))?;
            if !transaction::resolve_value(ctx, &mut s, &name, value.value.expose(), value.kind)? {
                done.push(tr!(
                    "Sync storage is full; review pending items before retrying."
                ));
            }
        }
        SyncCommand::Resolve { name, keep } => {
            scan(ctx, &mut s)?;
            let choice = if keep == "mine" {
                tr!("this device")
            } else {
                keep.clone()
            };
            let was_proposal = !s.items.contains_key(&name);
            if was_proposal {
                let scope = s
                    .candidates
                    .values()
                    .filter(|c| c.version.name == name && !c.legacy)
                    .map(|c| c.peer.clone())
                    .collect::<std::collections::BTreeSet<_>>();
                if scope.is_empty() {
                    return Err(state_error());
                }
                let (_, _, fp) = current(ctx, &name)?.ok_or_else(state_error)?;
                let head = Vid::random();
                remember(ctx, &name, head, fp, &[])?;
                s.items.insert(
                    name.clone(),
                    Item {
                        head,
                        lineage: vec![head],
                        parents: vec![],
                        known: vec![head],
                        scope: scope.clone(),
                        own: true,
                        conflict: true,
                    },
                );
                for peer in scope {
                    let registration = s.generations.accept(&name, PeerId(peer.clone()));
                    queue(
                        &mut s,
                        &peer,
                        Control::Accept {
                            name: name.clone(),
                            generation: registration.generation,
                        },
                    );
                }
            }
            let (value, kind) = if keep == "mine" {
                let (v, k, _) = current(ctx, &name)?.ok_or_else(state_error)?;
                (v, k)
            } else {
                let peer = selected_peers(ctx, &s, &[keep])?.remove(0);
                let options = s
                    .candidates
                    .values()
                    .filter(|c| c.version.name == name && c.peer == peer && !c.retire)
                    .cloned()
                    .collect::<Vec<_>>();
                let choice = if options.len() > 1 {
                    ctx.select(
                        &tr!("Select sync items."),
                        &options
                            .iter()
                            .map(|c| vid_key(c.version.vid))
                            .collect::<Vec<_>>(),
                        0,
                    )?
                } else {
                    0
                };
                let c = options.get(choice).ok_or_else(state_error)?;
                let value = blob(ctx, &c.version.slot)?;
                (Zeroizing::new(value.value.expose().to_vec()), value.kind)
            };
            done.push(if transaction::resolve_value(ctx, &mut s, &name, &value, kind)? {
                tr!(
                    "Resolved {name}, keeping {choice}; the other devices review it with `kc sync review`.",
                    name = name,
                    choice = choice
                )
            } else {
                tr!("Sync storage is full; review pending items before retrying.")
            });
        }
        SyncCommand::Peer { command } => match command {
            SyncPeerCommand::List => {
                for (p, peer) in &s.peers {
                    ctx.emit(format!("{}  {}\n", label(ctx, p)?, peer.enabled).as_bytes())?;
                }
            }
            SyncPeerCommand::Add { label } => {
                let id = selected_peers(ctx, &s, &[label])?.remove(0);
                let peer = s.peers.entry(id.clone()).or_default();
                peer.enabled = true;
                if !peer.capable {
                    peer.hello_sent = false;
                }
                for name in s.items.keys().cloned().collect::<Vec<_>>() {
                    offer(ctx, &mut s, &name, std::slice::from_ref(&id))?;
                }
            }
            SyncPeerCommand::Rm { label } => {
                let id = selected_peers(ctx, &s, &[label])?.remove(0);
                s.peers.entry(id.clone()).or_default().enabled = false;
                let names = s
                    .items
                    .iter()
                    .filter(|(_, i)| i.scope.contains(&id))
                    .map(|(n, _)| n.clone())
                    .collect::<Vec<_>>();
                for name in names {
                    let (registration, _) = s.generations.rm(&name).map_err(|_| state_error())?;
                    s.items.get_mut(&name).unwrap().scope.remove(&id);
                    queue(
                        &mut s,
                        &id,
                        Control::Leave {
                            name: name.clone(),
                            generation: registration.generation,
                        },
                    );
                    for p in s.items[&name].scope.clone() {
                        s.generations.accept(&name, PeerId(p.clone()));
                        queue(
                            &mut s,
                            &p,
                            Control::Accept {
                                name: name.clone(),
                                generation: registration.generation,
                            },
                        );
                    }
                }
                s.offers.retain(|o| o.peer != id);
                for change in s
                    .outbox
                    .pending(&PeerId(id.clone()))
                    .cloned()
                    .collect::<Vec<_>>()
                {
                    s.outbox
                        .ack(&PeerId(id.clone()), &change, kc_sync::AckResult::Rejected);
                }
                super::transport::collect_snapshots(&mut s);
            }
        },
        _ => {}
    }
    s.cleanup(ctx)?;
    for line in done {
        crate::commands::say!(ctx, "{line}");
    }
    Ok(if pending(&s) { 8 } else { 0 })
}

#[cfg(test)]
mod tests {
    use super::{peer_line, row_line};
    use serde_json::json;

    #[test]
    fn status_rows_list_peers_without_json_syntax() {
        let item = json!({"name": "KEY", "state": "in sync", "fingerprint": "ab12",
            "peers": ["omarchy", "host.local"]});
        assert_eq!(row_line(&item), "KEY  in sync  ab12  omarchy, host.local");
        let lonely = json!({"name": "KEY", "state": "in sync", "fingerprint": null, "peers": []});
        assert_eq!(row_line(&lonely), "KEY  in sync  -  -");
        let candidate = json!({"name": "KEY", "state": "proposal", "peer": "omarchy",
            "vid": [0], "fingerprint": "cd34"});
        assert_eq!(row_line(&candidate), "KEY  proposal  cd34  omarchy");
    }

    #[test]
    fn status_peer_lines_name_only_what_needs_attention() {
        let healthy = json!({"label": "omarchy", "enabled": true, "v2": true, "breaker": false,
            "quarantine": [], "last_digest": 1, "reoffer": []});
        assert_eq!(peer_line(&healthy), "device omarchy: ok");
        let troubled = json!({"label": "host.local", "enabled": false, "v2": false,
            "breaker": true, "quarantine": ["A", "B"], "last_digest": null, "reoffer": ["A"]});
        assert_eq!(
            peer_line(&troubled),
            "device host.local: removed from sync, hasn't answered the sync handshake yet, \
             paused after too many changes, quarantined: 2, re-offer needed: 1"
        );
    }
}

use super::*;
use crate::cli::{SyncCommand, SyncPeerCommand};
use state::{CandidateKind, Control, Item, Offer, Peer};
use transaction::{queue, blob, put_blob};

pub(crate) fn label<H: Host>(ctx: &Ctx<'_, H>, peer: &str) -> Result<String> {
    if peer == "mine" { return Ok(tr!("this device")) }
    Ok(ctx.state.load_peers()?.peers.iter().find(|p| p.fingerprint.to_hex() == peer)
        .map(|p| p.label.to_string()).unwrap_or_else(|| peer.to_string()))
}
fn selected_peers<H: Host>(ctx: &Ctx<'_, H>, s: &State, labels: &[String]) -> Result<Vec<String>> {
    let peers = ctx.state.load_peers()?;
    if labels.is_empty() {
        return Ok(peers.peers.iter().filter(|p| s.peers.get(&p.fingerprint.to_hex()).is_none_or(|p| p.enabled))
            .map(|p| p.fingerprint.to_hex()).collect())
    }
    labels.iter().map(|label| peers.find(label).map(|p| p.fingerprint.to_hex()).ok_or_else(|| CliError::not_found(tr!("Unknown sync peer: {label}.", label = label)))).collect()
}
fn offer<H: Host>(ctx: &mut Ctx<'_, H>, s: &mut State, name: &str, peers: &[String]) -> Result<()> {
    let (value, kind, fp) = current(ctx, name)?.ok_or_else(state_error)?;
    size(&value)?;
    let item = s.items[name].clone();
    // Re-offering a received value is a new local publication, never forwarding its vid.
    if item.conflict { return Err(CliError::new(8, tr!("Sync needs local confirmation."))) }
    if !item.own { transaction::publish_current(ctx, s, name)?; }
    let item = s.items[name].clone();
    let slot = snapshot_slot(item.head);
    if !reserve(ctx, s, &slot, SlotKind::ConflictCandidate, true)? { return Err(capacity()) }
    put_blob(ctx, &slot, kind, &value)?;
    remember(ctx, name, item.head, fp, &item.parents)?;
    s.latest_local.insert(name.into(), item.head);
    s.versions.insert(vid_key(item.head), Version { name: name.into(), vid: item.head, parents: item.parents.clone(), lineage: item.lineage.clone(), kind, slot });
    for peer in peers {
        s.peers.entry(peer.clone()).or_insert_with(|| Peer { enabled: true, ..Peer::default() });
        s.items.get_mut(name).unwrap().scope.insert(peer.clone());
        s.generations.accept(name, PeerId(peer.clone()));
        s.offers.retain(|o| o.peer != *peer || o.name != name);
        s.offers.push(Offer { peer: peer.clone(), name: name.into(), vid: item.head });
    }
    Ok(())
}
pub(crate) fn remove<H: Host>(ctx: &Ctx<'_, H>, s: &mut State, name: &str) -> Result<()> {
    let (registration, mut peers) = s.generations.rm(name).map_err(|_| state_error())?;
    if let Some(item) = s.items.remove(name) { peers.extend(item.scope.into_iter().map(PeerId)); }
    for peer in peers { if peer.0 == "mine" { continue } queue(s, &peer.0, Control::Leave { name: name.into(), generation: registration.generation }); }
    s.offers.retain(|o| o.name != name);
    transaction::clear_candidates(s, name);
    for peer in s.peers.keys().cloned().collect::<Vec<_>>() {
        let ids = s.outbox.pending(&PeerId(peer.clone())).filter(|id| id.name == name).cloned().collect::<Vec<_>>();
        for id in ids { s.outbox.ack(&PeerId(peer.clone()), &id, kc_sync::AckResult::Rejected); }
    }
    super::transport::collect_snapshots(s);
    s.cleanup(ctx)
}
pub(crate) fn status<H: Host>(ctx: &mut Ctx<'_, H>, json: bool) -> Result<i32> {
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    recover(ctx, &mut s)?;
    let mut rows = Vec::new();
    for (name, item) in &s.items {
        let state = if s.frozen { tr!("frozen") }
            else if item.conflict { tr!("conflict") }
            else if item.scope.iter().any(|p| s.peers.get(p).is_some_and(|p| p.reoffer.contains(name))) { tr!("re-offer needed") }
            else if s.candidates.values().any(|c| c.version.name == *name && c.category == CandidateKind::Held) { tr!("held") }
            else if s.offers.iter().any(|o| o.name == *name) || item.scope.iter().any(|p| s.outbox.pending(&PeerId(p.clone())).any(|c| c.name == *name)) { tr!("awaiting review") }
            else { tr!("in sync") };
        let fingerprint = current(ctx, name)?.map(|v| hex(&v.2.0[..6]));
        let peers = item.scope.iter().map(|p| label(ctx, p)).collect::<Result<Vec<_>>>()?;
        rows.push(serde_json::json!({"name": name, "state": state, "head": item.head, "fingerprint": fingerprint, "peers": peers}));
    }
    let mut candidates = Vec::new();
    for c in s.candidates.values() {
        let fp = if c.retire { None } else { { let value = blob(ctx, &c.version.slot)?; Some(fingerprint(ctx, &c.version.name, value.kind, value.value.expose())?) } };
        let state = match c.category { CandidateKind::Proposal => tr!("proposal"), CandidateKind::Held => tr!("held"), CandidateKind::Conflict => tr!("conflict") };
        candidates.push(serde_json::json!({"name": c.version.name, "state": state, "peer": label(ctx, &c.peer)?, "vid": c.version.vid, "fingerprint": fp.map(|f| hex(&f.0[..6]))}));
    }
    let mut peers = Vec::new();
    for (id, peer) in &s.peers {
        peers.push(serde_json::json!({"label":label(ctx, id)?, "enabled":peer.enabled, "v2":peer.capable,
            "breaker":s.limiter.is_tripped(&PeerId(id.clone())), "quarantine":peer.quarantine, "last_digest":peer.last_digest, "reoffer":peer.reoffer}));
    }
    let output = serde_json::json!({"items": rows, "candidates": candidates, "peers": peers, "frozen":s.frozen,
        "capacity_blocked":s.capacity_blocked, "slots_used":s.slots.len(), "slot_capacity":SlotBudget::new(s.items.len()).capacity(),
        "reconnect":s.reconnect, "notice":tr!("Only the device that created a change sends it; if it is lost, publish a new local change from a remaining copy.")});
    if json { ctx.emit(format!("{}\n", serde_json::to_string_pretty(&output).map_err(|_| state_error())?).as_bytes())?; }
    else {
        for row in rows.iter().chain(&candidates) { ctx.emit(format!("{}  {}  {}  {}\n", row["name"].as_str().unwrap_or(""), row["state"].as_str().unwrap_or(""),
            row["fingerprint"].as_str().unwrap_or("-"), row.get("peer").cloned().unwrap_or_else(|| row["peers"].clone())).as_bytes())?; }
        for peer in peers { ctx.emit(format!("{}\n", peer).as_bytes())?; }
        if s.capacity_blocked { crate::commands::say!(ctx, "{}", tr!("Sync storage is full; review pending items before retrying.")); }
        if s.reconnect { crate::commands::say!(ctx, "{}", tr!("Sync delivery is queued; run `kc sync` to retry.")); }
        crate::commands::say!(ctx, "{}", tr!("Only the device that created a change sends it; if it is lost, publish a new local change from a remaining copy."));
    }
    Ok(if pending(&s) { 8 } else { 0 })
}
pub(crate) fn review<H: Host>(ctx: &mut Ctx<'_, H>) -> Result<i32> {
    if !ctx.interactive() { human(ctx, &tr!("Review sync changes."))?; }
    let candidates = {
        let _items = ctx.state.lock_items(ctx.store.namespace())?;
        let _state = ctx.state.lock()?;
        let mut s = State::load(&ctx.state)?;
        scan(ctx, &mut s)?;
        if s.frozen { return Ok(8) }
        s.candidates.values().filter(|c| c.category != CandidateKind::Conflict).cloned().collect::<Vec<_>>()
    };
    let mut accepts = Vec::new(); let mut rejects = Vec::new();
    for c in candidates {
        let fingerprint = if c.retire { "-".into() } else {
            let value = blob(ctx, &c.version.slot)?;
            hex(&super::fingerprint(ctx, &c.version.name, value.kind, value.value.expose())?.0[..6])
        };
        let existing = current(ctx, &c.version.name)?.map(|v| hex(&v.2.0[..6])).unwrap_or_else(|| "-".into());
        let question = tr!("Review {name} from {peer}: current {current}, proposed {proposed}.", name = c.version.name, peer = label(ctx, &c.peer)?, current = existing, proposed = fingerprint);
        match ctx.select(&question, &[tr!("Accept"), tr!("Reject"), tr!("Leave for later")], 2)? {
            0 => accepts.push(c), 1 => rejects.push(c), _ => {},
        }
    }
    if !accepts.is_empty() {
        human(ctx, &tr!("Review sync: accept {accept}, reject {reject}.", accept = accepts.len(), reject = rejects.len()))?;
    }
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    scan(ctx, &mut s)?;
    for c in rejects {
        if let Some(current) = s.candidates.remove(&c.version.slot) {
            release(&mut s, &current.version.slot); s.gc.insert(current.base_record);
            let delivery = delivery_key(&c.peer, &c.version.name, c.generation, c.version.vid);
            if c.category == CandidateKind::Proposal { s.rejected_offers.insert(delivery); }
            else { s.receipts.insert(delivery, (kc_proto::sync::AckResult::Rejected, ctx.host.now().saturating_add(3 * 86400))); }
            if !c.legacy && c.category != CandidateKind::Proposal {
                queue(&mut s, &c.peer, Control::Ack { id: kc_proto::sync::ChangeId { name: crate::values::item_name(&c.version.name)?, generation: c.generation, new_vid: c.version.vid }, result: kc_proto::sync::AckResult::Rejected });
            }
        }
    }
    for c in accepts {
        if s.frozen { break }
        if let Some(current) = s.candidates.get(&c.version.slot).cloned() {
            if current.category != CandidateKind::Conflict { transaction::accept(ctx, &mut s, &current)?; }
        }
    }
    s.cleanup(ctx)?;
    Ok(if pending(&s) { 8 } else { 0 })
}
pub(crate) fn command<H: Host>(ctx: &mut Ctx<'_, H>, command: SyncCommand) -> Result<i32> {
    if let SyncCommand::Status { json, confirm_checkpoint: None } = command { return status(ctx, json) }
    if matches!(command, SyncCommand::Review) { return review(ctx) }
    let no_auth = matches!(command, SyncCommand::Freeze | SyncCommand::Offer { .. } | SyncCommand::Peer { command: SyncPeerCommand::List });
    if !no_auth { human(ctx, &tr!("Confirm the requested sync operation."))?; }
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    recover(ctx, &mut s)?;
    match command {
        SyncCommand::Add { mut names, peers } => {
            if names.is_empty() {
                let options = ctx.store.list()?.into_iter().map(|i| i.name).collect::<Vec<_>>();
                names = ctx.multi_select(&tr!("Select sync items."), &options)?.into_iter().map(|i| options[i].clone()).collect();
            }
            let peers = selected_peers(ctx, &s, &peers)?;
            for name in &names { crate::values::item_name(name)?; let (v, _, _) = current(ctx, name)?.ok_or_else(state_error)?; size(&v)?; }
            for name in names {
                let (value, kind, fp) = current(ctx, &name)?.ok_or_else(state_error)?;
                if !s.items.contains_key(&name) {
                    let head = Vid::random();
                    remember(ctx, &name, head, fp, &[])?;
                    s.items.insert(name.clone(), Item { head, lineage: vec![head], parents: vec![], known: vec![head], scope: Default::default(), own: true, conflict: false });
                    // Allocate receiver generation even when there are no peers yet.
                    s.generations.accept(&name, PeerId("mine".into()));
                }
                let _ = (value, kind);
                offer(ctx, &mut s, &name, &peers)?;
            }
        }
        SyncCommand::Offer { names, peers } => {
            let peers = selected_peers(ctx, &s, &peers)?;
            for name in names {
                if !s.items.contains_key(&name) { return Err(state_error()) }
                // An agent may propose only to the already locally approved scope.
                let allowed = peers.iter().filter(|p| s.items[&name].scope.contains(*p)).cloned().collect::<Vec<_>>();
                if allowed.len() != peers.len() { return Err(CliError::interaction(tr!("Sync needs local confirmation."))) }
                // An explicit re-offer is a fresh proposal even if the previous vid
                // was rejected. Transport retries keep the old vid and stay rejected.
                if s.items[&name].conflict { return Err(CliError::new(8, tr!("Sync needs local confirmation."))) }
                transaction::publish_current(ctx, &mut s, &name)?;
                offer(ctx, &mut s, &name, &allowed)?;
            }
        }
        SyncCommand::Rm { names } => { for name in names { crate::values::item_name(&name)?; remove(ctx, &mut s, &name)?; } }
        SyncCommand::Freeze => s.frozen = true,
        SyncCommand::Unfreeze => {
            s.frozen = false;
            for peer in s.peers.keys() { s.limiter.human_reset(&PeerId(peer.clone())); }
        }
        SyncCommand::Status { confirm_checkpoint: Some(name), .. } => {
            if !s.items.contains_key(&name) { return Err(state_error()) }
            let (value, kind, _) = current(ctx, &name)?.ok_or_else(state_error)?;
            let slot = checkpoint_slot(&name);
            if !reserve(ctx, &mut s, &slot, SlotKind::Checkpoint, false)? { return Err(capacity()) }
            put_blob(ctx, &slot, kind, &value)?;
        }
        SyncCommand::RestoreCheckpoint { name } => {
            scan(ctx, &mut s)?;
            if !s.items.contains_key(&name) { return Err(state_error()) }
            let value = blob(ctx, &checkpoint_slot(&name))?;
            transaction::resolve_value(ctx, &mut s, &name, value.value.expose(), value.kind)?;
        }
        SyncCommand::Resolve { name, keep } => {
            scan(ctx, &mut s)?;
            let was_proposal = !s.items.contains_key(&name);
            if was_proposal {
                let scope = s.candidates.values().filter(|c| c.version.name == name && !c.legacy)
                    .map(|c| c.peer.clone()).collect::<std::collections::BTreeSet<_>>();
                if scope.is_empty() { return Err(state_error()) }
                let (_, _, fp) = current(ctx, &name)?.ok_or_else(state_error)?;
                let head = Vid::random();
                remember(ctx, &name, head, fp, &[])?;
                s.items.insert(name.clone(), Item { head, lineage: vec![head], parents: vec![], known: vec![head], scope: scope.clone(), own: true, conflict: true });
                for peer in scope {
                    let registration = s.generations.accept(&name, PeerId(peer.clone()));
                    queue(&mut s, &peer, Control::Accept { name: name.clone(), generation: registration.generation });
                }
            }
            let (value, kind) = if keep == "mine" {
                let (v, k, _) = current(ctx, &name)?.ok_or_else(state_error)?; (v, k)
            } else {
                let peer = selected_peers(ctx, &s, &[keep])?.remove(0);
                let options = s.candidates.values().filter(|c| c.version.name == name && c.peer == peer && !c.retire).cloned().collect::<Vec<_>>();
                let choice = if options.len() > 1 { ctx.select(&tr!("Select sync items."), &options.iter().map(|c| vid_key(c.version.vid)).collect::<Vec<_>>(), 0)? } else { 0 };
                let c = options.get(choice).ok_or_else(state_error)?;
                let value = blob(ctx, &c.version.slot)?;
                (Zeroizing::new(value.value.expose().to_vec()), value.kind)
            };
            transaction::resolve_value(ctx, &mut s, &name, &value, kind)?;
        }
        SyncCommand::Peer { command } => match command {
            SyncPeerCommand::List => { for (p, peer) in &s.peers { ctx.emit(format!("{}  {}\n", label(ctx, p)?, peer.enabled).as_bytes())?; } }
            SyncPeerCommand::Add { label } => {
                let id = selected_peers(ctx, &s, &[label])?.remove(0);
                let peer = s.peers.entry(id.clone()).or_default();
                peer.enabled = true;
                if !peer.capable { peer.hello_sent = false; }
                for name in s.items.keys().cloned().collect::<Vec<_>>() { offer(ctx, &mut s, &name, std::slice::from_ref(&id))?; }
            }
            SyncPeerCommand::Rm { label } => {
                let id = selected_peers(ctx, &s, &[label])?.remove(0);
                s.peers.entry(id.clone()).or_default().enabled = false;
                let names = s.items.iter().filter(|(_, i)| i.scope.contains(&id)).map(|(n, _)| n.clone()).collect::<Vec<_>>();
                for name in names {
                    let (registration, _) = s.generations.rm(&name).map_err(|_| state_error())?;
                    s.items.get_mut(&name).unwrap().scope.remove(&id);
                    queue(&mut s, &id, Control::Leave { name: name.clone(), generation: registration.generation });
                    for p in s.items[&name].scope.clone() {
                        s.generations.accept(&name, PeerId(p.clone()));
                        queue(&mut s, &p, Control::Accept { name: name.clone(), generation: registration.generation });
                    }
                }
                s.offers.retain(|o| o.peer != id);
                for change in s.outbox.pending(&PeerId(id.clone())).cloned().collect::<Vec<_>>() {
                    s.outbox.ack(&PeerId(id.clone()), &change, kc_sync::AckResult::Rejected);
                }
                super::transport::collect_snapshots(&mut s);
            }
        },
        _ => {},
    }
    s.cleanup(ctx)?;
    Ok(if pending(&s) { 8 } else { 0 })
}

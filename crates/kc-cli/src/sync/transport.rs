use super::*;
use kc_proto::inbox::{self, Body};
use kc_proto::payload::WriterToken;
use kc_proto::relay::RelayApi;
use kc_proto::sync::{Change, DigestEntry, Op, SyncMsg};
use state::Control;
use std::time::Duration;

fn control(c: &Control) -> Result<SyncMsg> {
    Ok(match c {
        Control::Hello { reply } => SyncMsg::Hello {
            features: vec!["sync-phase1".into()],
            is_reply: *reply,
        },
        Control::Accept { name, generation } => SyncMsg::Accept {
            name: crate::values::item_name(name)?,
            generation: *generation,
        },
        Control::Leave { name, generation } => SyncMsg::Leave {
            name: crate::values::item_name(name)?,
            generation: *generation,
        },
        Control::Ack { id, result } => SyncMsg::Ack {
            results: vec![(id.clone(), *result)],
        },
    })
}
async fn post<H: Host>(
    ctx: &Ctx<'_, H>,
    peer: &crate::state::Peer,
    message: SyncMsg,
) -> Result<()> {
    let key = crate::commands::pairing::device_key(ctx)?.ok_or_else(state_error)?;
    let stored = ctx
        .store
        .get_internal(&peer.token_key())?
        .ok_or_else(state_error)?;
    let raw = Zeroizing::new(<[u8; 32]>::try_from(stored.as_bytes()).map_err(|_| state_error())?);
    let token = WriterToken::from_bytes(*raw);
    let body = Body::Sync(message);
    // seal_v2 checks the actual postcard plaintext/padded/envelope size against 256 KiB.
    let sealed = inbox::seal_v2(
        &key,
        &peer.device_pk,
        &body,
        Duration::from_secs(kc_wire::limits::INBOX_MESSAGE_TTL_SECS),
        ctx.host.now(),
    )?;
    ctx.connect()?
        .post_message(&peer.inbox_id.to_b64url(), &token.bearer(), &sealed.body)
        .await
        .map_err(|error| {
            let mut error = CliError::from(error);
            error.code = 6;
            error
        })?;
    Ok(())
}
async fn deliver<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    peer: &crate::state::Peer,
    message: SyncMsg,
) -> Result<()> {
    if let Err(error) = post(ctx, peer, message).await {
        s.delivery_failed = true;
        s.save(&ctx.state)?;
        return Err(error);
    }
    Ok(())
}
pub(crate) async fn flush<H: Host>(ctx: &mut Ctx<'_, H>, digest: bool) -> Result<usize> {
    if !ctx.state.root().join("sync.json").exists() {
        return Ok(0);
    }
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    let mut s = State::load(&ctx.state)?;
    recover(ctx, &mut s)?;
    let peers = ctx.state.load_peers()?;
    let mut sent = 0;
    for peer in &peers.peers {
        let id = peer.fingerprint.to_hex();
        let Some(p) = s.peers.get(&id) else { continue };
        if !p.capable {
            if !p.hello_sent {
                s.peers.get_mut(&id).unwrap().hello_sent = true;
                // Persist the attempt, but permit retry if delivery fails.
                s.save(&ctx.state)?;
                if let Err(error) = deliver(
                    ctx,
                    &mut s,
                    peer,
                    SyncMsg::Hello {
                        features: vec!["sync-phase1".into()],
                        is_reply: false,
                    },
                )
                .await
                {
                    s.peers.get_mut(&id).unwrap().hello_sent = false;
                    s.save(&ctx.state)?;
                    return Err(error);
                }
            }
            continue;
        }
        let controls = s
            .controls
            .iter()
            .filter(|(p, _)| p == &id)
            .cloned()
            .collect::<Vec<_>>();
        for entry in controls {
            deliver(ctx, &mut s, peer, control(&entry.1)?).await?;
            let bytes = serde_json::to_vec(&entry).map_err(|_| state_error())?;
            if let Some(i) = s
                .controls
                .iter()
                .position(|c| serde_json::to_vec(c).ok().as_ref() == Some(&bytes))
            {
                s.controls.remove(i);
            }
            s.save(&ctx.state)?;
        }
        if !s.peers[&id].enabled {
            continue;
        }
        let digest_due = digest
            && s.peers[&id]
                .last_digest
                .is_none_or(|last| (ctx.host.now() as i128) - (last as i128) >= 86400);
        let offers = s
            .offers
            .iter()
            .filter(|o| o.peer == id)
            .cloned()
            .collect::<Vec<_>>();
        for offer in offers {
            let generation = s
                .generations
                .known_generation(&PeerId(id.clone()), &offer.name);
            if s.deferred
                .contains(&delivery_key(&id, &offer.name, generation, offer.vid))
            {
                continue;
            }
            let Some(v) = s.versions.get(&vid_key(offer.vid)).cloned() else {
                return Err(state_error());
            };
            let value = transaction::blob(ctx, &v.slot)?;
            deliver(
                ctx,
                &mut s,
                peer,
                SyncMsg::Offer {
                    name: crate::values::item_name(&v.name)?,
                    vid: v.vid,
                    lineage: v.lineage.clone(),
                    kind: value.kind,
                    value: value.value,
                    known_generation: generation,
                },
            )
            .await?;
            sent += 1;
        }
        let ids: Vec<_> = s.outbox.pending(&PeerId(id.clone())).cloned().collect();
        for change in &ids {
            if let Some(latest) = s.latest_local.get(&change.name)
                && change.new_vid != map::vid(*latest)
                && ids
                    .iter()
                    .any(|id| id.name == change.name && id.new_vid == map::vid(*latest))
            {
                continue;
            }
            if s.deferred.contains(&delivery_key(
                &id,
                &change.name,
                change.generation,
                map::wire_vid(change.new_vid),
            )) {
                continue;
            }
            let v = s
                .versions
                .get(&vid_key(map::wire_vid(change.new_vid)))
                .cloned()
                .ok_or_else(state_error)?;
            let value = transaction::blob(ctx, &v.slot)?;
            deliver(
                ctx,
                &mut s,
                peer,
                SyncMsg::Changes {
                    changes: vec![Change {
                        name: crate::values::item_name(&v.name)?,
                        generation: change.generation,
                        new_vid: v.vid,
                        parents: v.parents.clone(),
                        lineage: v.lineage.clone(),
                        op: Op::Put {
                            kind: value.kind,
                            value: value.value,
                        },
                        approval_ref: None,
                    }],
                },
            )
            .await?;
            sent += 1;
        }
        if digest_due {
            let entries: Vec<_> = s
                .items
                .iter()
                .filter(|(_, i)| i.scope.contains(&id))
                .map(|(name, i)| {
                    Ok(DigestEntry {
                        name: crate::values::item_name(name)?,
                        head: i.head,
                        generation: s.generations.known_generation(&PeerId(id.clone()), name),
                    })
                })
                .collect::<Result<_>>()?;
            // A conservative count bound keeps each chunk small; sealing still enforces
            // the actual serialized size instead of assuming byte lengths from item values.
            for chunk in entries.chunks(256) {
                deliver(
                    ctx,
                    &mut s,
                    peer,
                    SyncMsg::Digest {
                        entries: chunk.to_vec(),
                    },
                )
                .await?;
            }
            s.peers.get_mut(&id).unwrap().last_digest = Some(ctx.host.now());
            s.deferred.retain(|key| !key.starts_with(&format!("{id}/")));
            s.save(&ctx.state)?;
        }
    }
    // Every peer was reached without an error, so nothing waits on a failed delivery.
    s.delivery_failed = false;
    collect_snapshots(&mut s);
    s.cleanup(ctx)?;
    Ok(sent)
}
pub(super) fn collect_snapshots(s: &mut State) {
    let versions = s.versions.values().cloned().collect::<Vec<_>>();
    for v in versions {
        let waiting = s.offers.iter().any(|o| o.vid == v.vid)
            || s.peers.keys().any(|p| {
                s.outbox
                    .pending(&PeerId(p.clone()))
                    .any(|c| c.new_vid == map::vid(v.vid) && c.name == v.name)
            });
        if !waiting {
            s.outbox.release_snapshot(&v.name, map::vid(v.vid));
            release(s, &v.slot);
            // Retain only the metadata for the latest locally authored head, for digest.
            if s.items
                .get(&v.name)
                .is_none_or(|i| i.head != v.vid || !i.own)
            {
                s.versions.remove(&vid_key(v.vid));
            }
        }
    }
}
pub(super) fn resend<H: Host>(
    ctx: &Ctx<'_, H>,
    s: &mut State,
    peer: &str,
    name: &str,
) -> Result<()> {
    let item = s.items[name].clone();
    if !item.own {
        return Ok(());
    }
    let Some(generation) = s
        .generations
        .outgoing_generation(&PeerId(peer.into()), name)
    else {
        return Ok(());
    };
    let v = s
        .versions
        .get(&vid_key(item.head))
        .cloned()
        .ok_or_else(state_error)?;
    if !s.slots.contains_key(&v.slot) {
        let Some((value, kind, fp)) = current(ctx, name)? else {
            return Ok(());
        };
        let record: VidRecord = private_get(ctx, &record_slot(name, item.head))?;
        if fp != record.fp {
            return Ok(());
        }
        if !reserve(ctx, s, &v.slot, SlotKind::ConflictCandidate, true)? {
            return Ok(());
        }
        transaction::put_blob(ctx, &v.slot, kind, &value)?;
    }
    s.outbox.enqueue(
        PeerId(peer.into()),
        kc_sync::ChangeId {
            name: name.into(),
            generation,
            new_vid: map::vid(v.vid),
        },
    );
    Ok(())
}
pub(crate) async fn send_after_write<H: Host>(ctx: &mut Ctx<'_, H>) {
    if flush(ctx, false).await.is_err() {
        crate::commands::say!(
            ctx,
            "{}",
            tr!("Sync delivery is queued; run `kc sync` to retry.")
        );
    }
}

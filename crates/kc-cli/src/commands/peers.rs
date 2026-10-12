//! `kc peers [list | rm LABEL]`.

use kc_proto::relay::RelayApi;
use kc_wire::{ErrorCode, exit};

use super::{Ctx, pairing, say};
use crate::cli::{PeersArgs, PeersCommand};
use crate::error::{CliError, Result};
use crate::host::Host;

pub(super) async fn peers<H: Host>(ctx: &mut Ctx<'_, H>, args: PeersArgs) -> Result<i32> {
    match args.command.unwrap_or(PeersCommand::List) {
        PeersCommand::List => list(ctx),
        PeersCommand::Rm { label } => remove(ctx, &label).await,
    }
}

fn list<H: Host>(ctx: &mut Ctx<'_, H>) -> Result<i32> {
    let peers = ctx.state.load_peers()?;
    if peers.peers.is_empty() {
        say!(ctx, "No paired devices. Pair one with `kc pair`.");
        return Ok(exit::OK);
    }
    let width = peers
        .peers
        .iter()
        .map(|p| p.label.as_str().len())
        .max()
        .unwrap_or(0)
        .max("LABEL".len());
    let mut out = format!("{:<width$}  {:<19}  PAIRED\n", "LABEL", "FINGERPRINT");
    for peer in &peers.peers {
        let paired = u64::try_from(peer.paired_at)
            .ok()
            .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
            .map_or_else(
                || "-".to_owned(),
                |t| humantime::format_rfc3339_seconds(t).to_string(),
            );
        out.push_str(&format!(
            "{:<width$}  {}  {paired}\n",
            peer.label.as_str(),
            peer.fingerprint.short()
        ));
    }
    ctx.emit(out.as_bytes())?;
    Ok(exit::OK)
}

/// Forgets the peer here and revokes the writer registration this device made for it, so
/// it can't post to this device's inbox any more.
async fn remove<H: Host>(ctx: &mut Ctx<'_, H>, label: &str) -> Result<i32> {
    let lock = ctx.state.lock()?;
    let mut peers = ctx.state.load_peers()?;
    let Some(index) = peers.position(label) else {
        return Err(CliError::not_found("no paired device has that label")
            .with_hint("`kc peers` lists them"));
    };
    let peer = peers.peers[index].clone();

    // Its current registration, and any it had before that a re-pairing retired.
    let mut writers: Vec<String> = peer.writer_id.iter().cloned().collect();
    writers.extend(
        peers
            .pending_writers
            .iter()
            .filter(|w| w.peer == Some(peer.fingerprint))
            .filter_map(|w| w.writer_id.clone()),
    );
    let mut unrevoked = Vec::new();
    let mut relay_error = None;
    if let Some((inbox_id, owner)) = pairing::own_inbox(ctx)?
        && !writers.is_empty()
    {
        match ctx.connect() {
            Ok(relay) => {
                for writer_id in &writers {
                    match relay.delete_writer(&inbox_id, &owner, writer_id).await {
                        // Already gone: the registration, or the whole inbox.
                        Ok(()) => {}
                        Err(e) if e.is(ErrorCode::NotFound) || e.is(ErrorCode::Unauthorized) => {}
                        Err(e) => {
                            unrevoked.push(writer_id.clone());
                            relay_error.get_or_insert(CliError::from(e));
                        }
                    }
                }
            }
            Err(e) => {
                unrevoked = writers.clone();
                relay_error = Some(e);
            }
        }
    }
    ctx.store.delete_internal(&peer.token_key())?;
    peers.peers.remove(index);
    peers
        .pending_writers
        .retain(|w| w.peer != Some(peer.fingerprint));
    for writer_id in &unrevoked {
        pairing::revoke_later(&mut peers, writer_id);
    }
    ctx.state.save_peers(&peers)?;
    drop(lock);

    say!(
        ctx,
        "Unpaired {} ({}).",
        peer.label,
        peer.fingerprint.short()
    );
    match relay_error {
        None => Ok(exit::OK),
        Some(e) => {
            say!(
                ctx,
                "Its permission to post to this device's inbox couldn't be revoked on the relay: {}",
                e.message
            );
            say!(
                ctx,
                "Its messages are refused here anyway, and the next pairing revokes it."
            );
            Ok(exit::RELAY_UNAVAILABLE)
        }
    }
}

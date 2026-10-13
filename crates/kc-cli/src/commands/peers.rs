//! `kc peers [list | rm LABEL]`.

use kc_proto::relay::RelayApi;
use kc_wire::{ErrorCode, exit};

use super::{Ctx, display_width, pad_to, pairing, say};
use crate::cli::{PeersArgs, PeersCommand};
use crate::error::{CliError, Result};
use crate::host::Host;
use crate::i18n::tr;

pub(super) async fn peers<H: Host>(ctx: &mut Ctx<'_, H>, args: PeersArgs) -> Result<i32> {
    match args.command.unwrap_or(PeersCommand::List) {
        PeersCommand::List => list(ctx),
        PeersCommand::Rm { label } => remove(ctx, &label).await,
    }
}

fn list<H: Host>(ctx: &mut Ctx<'_, H>) -> Result<i32> {
    let peers = ctx.state.load_peers()?;
    if peers.peers.is_empty() {
        say!(
            ctx,
            "{}",
            tr!("No paired devices. Pair one with `kc pair`.")
        );
        return Ok(exit::OK);
    }
    let (label, fingerprint, paired) = (tr!("LABEL"), tr!("FINGERPRINT"), tr!("PAIRED"));
    let width = peers
        .peers
        .iter()
        .map(|p| p.label.as_str().len())
        .max()
        .unwrap_or(0)
        .max(display_width(&label));
    let fp_width = display_width(&fingerprint).max(19);
    let mut out = format!(
        "{}  {}  {paired}\n",
        pad_to(&label, width),
        pad_to(&fingerprint, fp_width)
    );
    for peer in &peers.peers {
        let paired = u64::try_from(peer.paired_at)
            .ok()
            .map(|secs| std::time::UNIX_EPOCH + std::time::Duration::from_secs(secs))
            .map_or_else(
                || "-".to_owned(),
                |t| humantime::format_rfc3339_seconds(t).to_string(),
            );
        out.push_str(&format!(
            "{}  {}  {paired}\n",
            pad_to(peer.label.as_str(), width),
            pad_to(&peer.fingerprint.short(), fp_width)
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
        return Err(CliError::not_found(tr!("no paired device has that label"))
            .with_hint(tr!("`kc peers` lists them")));
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
        "{}",
        tr!(
            "Unpaired {label} ({fingerprint}).",
            label = peer.label,
            fingerprint = peer.fingerprint.short()
        )
    );
    match relay_error {
        None => Ok(exit::OK),
        Some(e) => {
            say!(
                ctx,
                "{}",
                tr!(
                    "Its permission to post to this device's inbox couldn't be revoked on the relay: {error}",
                    error = e.message
                )
            );
            say!(
                ctx,
                "{}",
                tr!("Its messages are refused here anyway, and the next pairing revokes it.")
            );
            Ok(exit::RELAY_UNAVAILABLE)
        }
    }
}

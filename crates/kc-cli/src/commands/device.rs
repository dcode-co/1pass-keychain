//! `kc device [show | rename LABEL | rotate]`.

use std::time::Duration;

use kc_proto::relay::RelayApi;
use kc_proto::{DeviceKeyPair, Label};
use kc_wire::{ErrorCode, exit};
use zeroize::Zeroizing;

use super::{Ctx, pairing, plural, say};
use crate::cli::{DeviceArgs, DeviceCommand};
use crate::error::{CliError, Result};
use crate::host::Host;
use crate::state::Peers;

pub(super) async fn device<H: Host>(ctx: &mut Ctx<'_, H>, args: DeviceArgs) -> Result<i32> {
    match args.command.unwrap_or(DeviceCommand::Show) {
        DeviceCommand::Show => show(ctx),
        DeviceCommand::Rename { label } => rename(ctx, &label),
        DeviceCommand::Rotate => rotate(ctx).await,
    }
}

fn show<H: Host>(ctx: &mut Ctx<'_, H>) -> Result<i32> {
    let label = ctx.label();
    let fingerprint = match pairing::device_key(ctx)? {
        Some(key) => key.fingerprint().short(),
        None => "none yet (made when this device first pairs)".to_owned(),
    };
    let inbox = match pairing::own_inbox(ctx)? {
        Some(_) => "yes",
        None => "none yet (made when this device first pairs)",
    };
    let relay = ctx
        .relay_url()
        .map_or_else(|e| format!("invalid: {}", e.message), |url| url.to_string());
    let peers = ctx.state.load_peers()?.peers.len();
    let text = format!(
        "label:            {label}\n\
         fingerprint:      {fingerprint}\n\
         inbox:            {inbox}\n\
         relay:            {relay}\n\
         paired devices:   {peers}\n\
         agent code sends: {}\n",
        if ctx.settings.agent_code_send {
            "allowed (agent_code_send = true)"
        } else {
            "refused"
        }
    );
    ctx.emit(text.as_bytes())?;
    Ok(exit::OK)
}

fn rename<H: Host>(ctx: &mut Ctx<'_, H>, label: &str) -> Result<i32> {
    let label = Label::new(label.trim())
        .map_err(|_| CliError::usage("a device label is 1-64 printable ASCII characters"))?;
    let lock = ctx.state.lock()?;
    pairing::update_settings(ctx, &lock, |s| s.label = Some(label.to_string()))?;
    say!(
        ctx,
        "This device now suggests the label {label} when it pairs."
    );
    say!(
        ctx,
        "Devices already paired keep the label they chose for it."
    );
    Ok(exit::OK)
}

/// The inbox, if it can be used. A damaged entry counts as none: rotation replaces it
/// (and can't delete the inbox it named).
fn usable_inbox<H: Host>(ctx: &Ctx<'_, H>) -> Result<Option<(String, Zeroizing<String>)>> {
    Ok(match pairing::inbox_slot(&ctx.store)? {
        pairing::InboxSlot::Present(id, owner) => Some((id, owner)),
        pairing::InboxSlot::Missing | pairing::InboxSlot::Damaged => None,
    })
}

/// A new device key and a new inbox. The old inbox is deleted, every pairing ends, and the
/// previous key keeps opening messages for 72 hours.
async fn rotate<H: Host>(ctx: &mut Ctx<'_, H>) -> Result<i32> {
    let relay = ctx.connect()?;
    let old_inbox = usable_inbox(ctx)?;
    let peers = ctx.state.load_peers()?;
    let labels: Vec<String> = peers.peers.iter().map(|p| p.label.to_string()).collect();
    let pending = match &old_inbox {
        Some((id, owner)) => relay
            .list_messages(id, owner, Duration::ZERO)
            .await
            .map(|l| l.messages.len())
            .unwrap_or(0),
        None => 0,
    };
    say!(
        ctx,
        "Rotating makes a new device key and inbox, deletes the old inbox and unpairs {}{}.",
        plural(labels.len(), "device"),
        if labels.is_empty() {
            String::new()
        } else {
            format!(" ({})", labels.join(", "))
        }
    );
    if pending > 0 {
        say!(
            ctx,
            "{} waiting in the inbox will be lost; run `kc inbox` first to keep them.",
            plural(pending, "message")
        );
    }
    if !ctx.confirm("Rotate this device's key?", false)? {
        say!(ctx, "Nothing changed.");
        return Ok(exit::PARTIAL);
    }

    // Order matters: after each step, the device has a usable identity even if the next
    // step fails or the process dies.
    //  1. the new inbox, on the relay (nothing local has changed yet);
    //  2. the pairings end: peers.json is emptied, then the peers' token slots go;
    //  3. the new inbox is installed (inbox id and owner token in one keychain write);
    //  4. the old key becomes the previous key (with its 72 h in config.toml), then the
    //     new key is stored;
    //  5. the old inbox is deleted on the relay.
    let lock = ctx.state.lock()?;
    ctx.settings = crate::settings::Settings::load(ctx.state.root())?;
    // Read again under the lock: another kc process may have changed them meanwhile.
    let peers = ctx.state.load_peers()?;
    let old_inbox = usable_inbox(ctx)?;
    let created = relay
        .create_inbox()
        .await
        .map_err(|e| CliError::from(e).context("making the new inbox; nothing changed"))?;
    let new_owner = Zeroizing::new(created.owner_token);
    let new_inbox = created.inbox_id;

    if let Err(e) = ctx.state.save_peers(&Peers::default()) {
        let _ = relay.delete_inbox(&new_inbox, &new_owner).await;
        return Err(e.context("nothing changed"));
    }
    let mut leftovers = 0;
    for peer in &peers.peers {
        if ctx.store.delete_internal(&peer.token_key()).is_err() {
            leftovers += 1;
        }
    }

    if let Err(e) = pairing::install_inbox(ctx, &lock, &new_inbox, &new_owner) {
        let installed =
            matches!(pairing::read_inbox(&ctx.store), Ok(Some((id, _))) if id == new_inbox);
        if !installed {
            let _ = relay.delete_inbox(&new_inbox, &new_owner).await;
            return Err(e
                .context("the pairings were removed, but the new inbox couldn't be stored")
                .with_hint("run `kc device rotate` again"));
        }
        // Installed in the keychain; config.toml's copy of the id is written again with
        // the key below, and rotation fails if that doesn't work either.
    }

    let new_key = DeviceKeyPair::generate();
    let now = ctx.host.now();
    // Only a usable old key is kept as the previous one; a damaged one is dropped.
    let old_key = ctx
        .store
        .get_internal(pairing::DEVICE_KEY)?
        .filter(|old| DeviceKeyPair::from_secret_bytes(old.as_bytes()).is_ok());
    let key_replaced = match old_key {
        Some(old) => ctx
            .store
            .set_internal(pairing::DEVICE_KEY_PREV, old.as_bytes())
            .map_err(CliError::from)
            .and_then(|_| {
                pairing::update_settings(ctx, &lock, |s| {
                    s.inbox_id = Some(new_inbox.clone());
                    s.device_key_prev_until = Some(now + pairing::PREV_KEY_SECS);
                })
            }),
        None => ctx
            .store
            .delete_internal(pairing::DEVICE_KEY_PREV)
            .map_err(CliError::from)
            .and_then(|_| {
                pairing::update_settings(ctx, &lock, |s| {
                    s.inbox_id = Some(new_inbox.clone());
                    s.device_key_prev_until = None;
                })
            }),
    }
    .and_then(|()| {
        ctx.store
            .set_internal(pairing::DEVICE_KEY, &*new_key.secret_bytes())
            .map(drop)
            .map_err(CliError::from)
    });
    drop(lock);

    let mut code = exit::OK;
    if let Some((id, owner)) = &old_inbox
        && let Err(e) = relay.delete_inbox(id, owner).await
        // Unauthorized: the relay already deleted it (unread for 30 days).
        && !e.is(ErrorCode::Unauthorized)
    {
        say!(
            ctx,
            "The old inbox couldn't be deleted ({e}); the relay drops it after 30 idle days."
        );
        code = exit::RELAY_UNAVAILABLE;
    }
    if let Err(e) = key_replaced {
        return Err(e
            .context("the new inbox is in place and the pairings are gone, but the rotation didn't finish")
            .with_hint("run `kc device rotate` again"));
    }
    say!(ctx, "New fingerprint: {}.", new_key.fingerprint().short());
    if !labels.is_empty() {
        say!(
            ctx,
            "On each device that was paired ({}), run `kc peers rm` with its label for this \
             device, then pair again with `kc pair` here and `kc pair --join` there.",
            labels.join(", ")
        );
    }
    if leftovers > 0 {
        return Err(CliError::failure(format!(
            "rotated, but {} of the old pairings' tokens couldn't be deleted from the keychain",
            leftovers
        ))
        .with_hint("they are no longer used, so leaving them does no harm"));
    }
    Ok(code)
}

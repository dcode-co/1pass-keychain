//! This device's identity and remembered devices (PROTOCOL §4).
//!
//! Keychain internal slots (kc-store `sys:<key>`):
//!
//! | key | holds |
//! |---|---|
//! | `device-key` | this device's X25519 secret key |
//! | `device-key-prev` | the key `kc device rotate` replaced, used for 72 h |
//! | `inbox-owner` | this device's inbox: `<inbox id>.<owner token>` |
//! | `writer/<fingerprint hex>/<tag>` | the token for posting to that peer's inbox |
//!
//! - The inbox id and its owner token share one slot, so they change in one write and no
//!   crash can leave one without the other. `inbox_id` in config.toml mirrors it for people.
//! - Writer slots are keyed by the peer's fingerprint (labels may hold characters keychain
//!   keys can't) plus a tag per pairing. peers.json names the slot in use, so a re-pairing
//!   writes the new token first and switches peers.json over in one write.
//!
//! Pairing, on each side: make sure our inbox exists, register a writer token for the peer
//! on it ([`prepare_offer`]), send our [`PairOffer`] inside the channel, and on the peer's
//! offer choose a local label and store the peer ([`remember_peer`]). Whatever fails after
//! [`prepare_offer`] revokes that registration again ([`discard_offer`]).

use kc_proto::payload::{InboxId, PairOffer, WriterToken};
use kc_proto::relay::RelayApi;
use kc_proto::{DeviceKeyPair, Fingerprint, Label};
use kc_store::SecretValue;
use kc_wire::ErrorCode;
use kc_wire::limits::INBOX_MESSAGE_TTL_SECS;
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use super::{Ctx, say};
use crate::error::{CliError, Result};
use crate::host::Host;
use crate::i18n::tr;
use crate::keychain::Keychain;
use crate::settings::Settings;
use crate::state::{Peer, PendingWriter, StateLock, WRITER_KEY_PREFIX};
use crate::values::shell_word;

pub(crate) const DEVICE_KEY: &str = "device-key";
pub(crate) const DEVICE_KEY_PREV: &str = "device-key-prev";
pub(crate) const INBOX_OWNER: &str = "inbox-owner";
/// How long `device-key-prev` keeps opening inbox messages.
pub(crate) const PREV_KEY_SECS: i64 = INBOX_MESSAGE_TTL_SECS as i64;

fn parse_key(value: &SecretValue) -> Result<DeviceKeyPair> {
    DeviceKeyPair::from_secret_bytes(value.as_bytes()).map_err(|_| {
        CliError::failure(tr!("this device's key in the keychain is damaged")).with_hint(tr!(
            "`kc device rotate` makes a new one (paired devices must pair again)"
        ))
    })
}

/// This device's key, if it has one.
pub(crate) fn device_key<H: Host>(ctx: &Ctx<'_, H>) -> Result<Option<DeviceKeyPair>> {
    match ctx.store.get_internal(DEVICE_KEY)? {
        Some(value) => parse_key(&value).map(Some),
        None => Ok(None),
    }
}

fn device_key_or_create<H: Host>(ctx: &Ctx<'_, H>) -> Result<DeviceKeyPair> {
    if let Some(key) = device_key(ctx)? {
        return Ok(key);
    }
    let key = DeviceKeyPair::generate();
    ctx.store.set_internal(DEVICE_KEY, &*key.secret_bytes())?;
    Ok(key)
}

/// The keys inbox messages may be addressed to: the current one, plus the previous one for
/// 72 h after a rotation.
pub(crate) fn own_keys<H: Host>(ctx: &Ctx<'_, H>) -> Result<Vec<DeviceKeyPair>> {
    let mut keys = Vec::with_capacity(2);
    if let Some(key) = device_key(ctx)? {
        keys.push(key);
    }
    if ctx
        .settings
        .device_key_prev_until
        .is_some_and(|until| ctx.host.now() <= until)
        && let Some(value) = ctx.store.get_internal(DEVICE_KEY_PREV)?
        // A damaged previous key opens nothing; it isn't worth failing the inbox over.
        && let Ok(prev) = parse_key(&value)
    {
        keys.push(prev);
    }
    Ok(keys)
}

/// Deletes the previous device key once its 72 hours are over. Housekeeping: it runs only
/// when `state.lock` is free and ignores failures, so it never holds up a command.
pub(crate) fn expire_prev_key<H: Host>(ctx: &mut Ctx<'_, H>) {
    let now = ctx.host.now();
    let expired = |s: &Settings| s.device_key_prev_until.is_some_and(|until| now > until);
    if !expired(&ctx.settings) {
        return;
    }
    let Some(lock) = ctx.state.try_lock() else {
        return;
    };
    // A rotation may have happened since config.toml was read: decide again under the lock.
    let Ok(settings) = Settings::load(ctx.state.root()) else {
        return;
    };
    ctx.settings = settings;
    if expired(&ctx.settings) && ctx.store.delete_internal(DEVICE_KEY_PREV).is_ok() {
        let _ = update_settings(ctx, &lock, |s| s.device_key_prev_until = None);
    }
}

/// This device's key and inbox.
pub(crate) struct Identity {
    pub key: DeviceKeyPair,
    pub inbox_id: String,
    pub owner: Zeroizing<String>,
}

fn damaged_inbox() -> CliError {
    CliError::failure(tr!("this device's inbox entry in the keychain is damaged")).with_hint(tr!(
        "`kc device rotate` makes a new inbox (paired devices must pair again)"
    ))
}

/// What the keychain's `inbox-owner` slot holds.
pub(crate) enum InboxSlot {
    Missing,
    /// Unreadable; making a new inbox replaces it.
    Damaged,
    Present(String, Zeroizing<String>),
}

/// The inbox id and owner token, if this device has an inbox.
pub(crate) fn own_inbox<H: Host>(ctx: &Ctx<'_, H>) -> Result<Option<(String, Zeroizing<String>)>> {
    read_inbox(&ctx.store)
}

/// [`own_inbox`], when this config directory is the one the inbox was set up with (its
/// config.toml names it). The keychain is shared by every config directory using the same
/// namespace, but the trust state that goes with the inbox (peers.json, seen.json) isn't:
/// another directory would read the inbox with an empty peer list and drop its messages as
/// coming from strangers.
pub(crate) fn owned_inbox<H: Host>(
    ctx: &Ctx<'_, H>,
) -> Result<Option<(String, Zeroizing<String>)>> {
    match own_inbox(ctx)? {
        Some((id, owner)) if ctx.settings.inbox_id.as_deref() == Some(id.as_str()) => {
            Ok(Some((id, owner)))
        }
        Some(_) => Err(foreign_inbox()),
        None => Ok(None),
    }
}

fn foreign_inbox() -> CliError {
    CliError::failure(tr!(
        "this device's inbox was set up with another kc config directory, which holds its \
         paired devices"
    ))
    .with_hint(tr!(
        "use that directory (KC_CONFIG_DIR), or run `kc device rotate` to start over with this one"
    ))
}

/// [`own_inbox`], from a store.
pub(crate) fn read_inbox(store: &Keychain) -> Result<Option<(String, Zeroizing<String>)>> {
    match inbox_slot(store)? {
        InboxSlot::Missing => Ok(None),
        InboxSlot::Damaged => Err(damaged_inbox()),
        InboxSlot::Present(id, owner) => Ok(Some((id, owner))),
    }
}

/// The `inbox-owner` slot. Keychain errors are errors; an unreadable slot is
/// [`InboxSlot::Damaged`], so the commands that make a new inbox can replace it.
pub(crate) fn inbox_slot(store: &Keychain) -> Result<InboxSlot> {
    let Some(value) = store.get_internal(INBOX_OWNER)? else {
        return Ok(InboxSlot::Missing);
    };
    let parsed = std::str::from_utf8(value.as_bytes())
        .ok()
        .and_then(|text| text.split_once('.'))
        .filter(|(id, owner)| valid_inbox(id, owner));
    Ok(match parsed {
        Some((id, owner)) => InboxSlot::Present(id.to_owned(), Zeroizing::new(owner.to_owned())),
        None => InboxSlot::Damaged,
    })
}

/// An inbox id is 16 bytes and an owner token 32 bytes, both base64url.
fn valid_inbox(id: &str, owner: &str) -> bool {
    InboxId::from_b64url(id).is_some() && WriterToken::from_bearer(owner).is_some()
}

/// Makes `inbox_id` this device's inbox. The keychain write is the commit point (id and
/// token together); config.toml's `inbox_id` then mirrors it. Needs `state.lock`.
pub(crate) fn install_inbox<H: Host>(
    ctx: &mut Ctx<'_, H>,
    held: &StateLock,
    inbox_id: &str,
    owner: &str,
) -> Result<()> {
    if !valid_inbox(inbox_id, owner) {
        return Err(CliError::new(
            kc_wire::exit::RELAY_UNAVAILABLE,
            tr!("the relay returned an invalid inbox; nothing was changed"),
        ));
    }
    let mut slot = Zeroizing::new(String::with_capacity(inbox_id.len() + 1 + owner.len()));
    slot.push_str(inbox_id);
    slot.push('.');
    slot.push_str(owner);
    ctx.store.set_internal(INBOX_OWNER, slot.as_bytes())?;
    update_settings(ctx, held, |s| s.inbox_id = Some(inbox_id.to_owned()))
}

/// Re-reads config.toml, changes it and writes it back. Needs `state.lock`.
pub(crate) fn update_settings<H: Host>(
    ctx: &mut Ctx<'_, H>,
    _held: &StateLock,
    change: impl FnOnce(&mut Settings),
) -> Result<()> {
    let mut settings = Settings::load(ctx.state.root())?;
    change(&mut settings);
    settings.save(ctx.state.root())?;
    ctx.settings = settings;
    Ok(())
}

/// The device key and inbox, created on first use.
pub(crate) async fn ensure_identity<H: Host>(
    ctx: &mut Ctx<'_, H>,
    relay: &H::Relay,
) -> Result<Identity> {
    let lock = ctx.state.lock()?;
    ctx.settings = Settings::load(ctx.state.root())?;
    let key = device_key_or_create(ctx)?;
    // Another kc process may have created the inbox meanwhile. A damaged entry is replaced.
    let (inbox_id, owner) = match inbox_slot(&ctx.store)? {
        InboxSlot::Present(id, _) if ctx.settings.inbox_id.as_deref() != Some(id.as_str()) => {
            return Err(foreign_inbox());
        }
        InboxSlot::Present(id, owner) => (id, owner),
        InboxSlot::Missing | InboxSlot::Damaged => new_inbox(ctx, relay, &lock).await?,
    };
    Ok(Identity {
        key,
        inbox_id,
        owner,
    })
}

/// Creates an inbox on the relay and installs it. If installing fails before the keychain
/// write, the new inbox is deleted again. Needs `state.lock`.
async fn new_inbox<H: Host>(
    ctx: &mut Ctx<'_, H>,
    relay: &H::Relay,
    held: &StateLock,
) -> Result<(String, Zeroizing<String>)> {
    let created = relay
        .create_inbox()
        .await
        .map_err(|e| CliError::from(e).context(tr!("making this device's inbox on the relay")))?;
    let owner = Zeroizing::new(created.owner_token);
    let inbox_id = created.inbox_id;
    if let Err(e) = install_inbox(ctx, held, &inbox_id, &owner) {
        let installed = matches!(own_inbox(ctx), Ok(Some((id, _))) if id == inbox_id);
        if !installed {
            let _ = relay.delete_inbox(&inbox_id, &owner).await;
        }
        return Err(e);
    }
    Ok((inbox_id, owner))
}

/// This device's inbox `lost` is gone from the relay (nobody read it for 30 days, so the
/// relay deleted it): makes a new one, unless another kc process already replaced or
/// rotated it meanwhile, in which case that one is used. Returns whether a new inbox was
/// made here. The writer registrations paired devices used went with the old inbox, so they
/// must pair again to reach this device; sending to them still works. Needs `state.lock`.
pub(crate) async fn replace_lost_inbox<H: Host>(
    ctx: &mut Ctx<'_, H>,
    relay: &H::Relay,
    held: &StateLock,
    lost: &str,
) -> Result<(Identity, bool)> {
    ctx.settings = Settings::load(ctx.state.root())?;
    let key = device_key_or_create(ctx)?;
    if let InboxSlot::Present(inbox_id, owner) = inbox_slot(&ctx.store)?
        && inbox_id != lost
    {
        let ident = Identity {
            key,
            inbox_id,
            owner,
        };
        return Ok((ident, false));
    }
    let (inbox_id, owner) = new_inbox(ctx, relay, held).await?;
    // Our registrations for the peers lived on the old inbox. Best effort: a stale id only
    // makes `kc peers rm` revoke something that's already gone.
    if let Ok(mut peers) = ctx.state.load_peers() {
        for peer in &mut peers.peers {
            peer.writer_id = None;
        }
        peers.pending_writers.clear();
        let _ = ctx.state.save_peers(&peers);
    }
    let ident = Identity {
        key,
        inbox_id,
        owner,
    };
    Ok((ident, true))
}

/// Tells the person what [`replace_lost_inbox`] means for them.
pub(crate) fn lost_inbox_notice<H: Host>(ctx: &mut Ctx<'_, H>) {
    say!(
        ctx,
        "{}",
        tr!(
            "This device's inbox was gone from the relay (the relay deletes inboxes nobody reads \
             for 30 days), so a new one was made. Messages sent to the old one are lost."
        )
    );
    say!(
        ctx,
        "{}",
        tr!(
            "Paired devices can't send here until they pair again (`kc pair` here, `kc pair \
             --join` there). Running `kc inbox` now and then keeps the inbox alive."
        )
    );
}

/// Our side of a pairing: a writer token for the peer, registered on our inbox.
pub(crate) struct Prepared {
    pub offer: PairOffer,
    pub writer_id: String,
}

/// Registers a writer token for the peer on our inbox and builds our offer. If the relay no
/// longer knows our inbox, a new one replaces it first (`ident` is updated).
///
/// The registration is written down as pending before the relay is asked, so one this run
/// never finishes (Ctrl-C, a crash, a lost answer) is revoked by a later pairing.
pub(crate) async fn prepare_offer<H: Host>(
    ctx: &mut Ctx<'_, H>,
    relay: &H::Relay,
    ident: &mut Identity,
) -> Result<Prepared> {
    revoke_stale_writers(ctx, relay, ident).await;
    let token = WriterToken::generate();
    let registration = token.registration();
    let registered = match register(ctx, relay, ident, &registration).await? {
        Err(e) if e.is(ErrorCode::Unauthorized) => {
            let lock = ctx.state.lock()?;
            let lost = ident.inbox_id.clone();
            let (replacement, replaced) = replace_lost_inbox(ctx, relay, &lock, &lost).await?;
            drop(lock);
            *ident = replacement;
            if replaced {
                lost_inbox_notice(ctx);
            }
            register(ctx, relay, ident, &registration).await?
        }
        other => other,
    };
    let writer_id = registered.map_err(|e| {
        let full = e.is(ErrorCode::InboxFull);
        let err = CliError::from(e).context(tr!("registering the other device on this inbox"));
        if full {
            err.with_hint(tr!(
                "this inbox already accepts 16 devices; unpair some with `kc peers rm`"
            ))
        } else {
            err
        }
    })?;
    let inbox_id = InboxId::from_b64url(&ident.inbox_id)
        .ok_or_else(|| CliError::failure(tr!("the relay returned an invalid inbox id")))?;
    Ok(Prepared {
        offer: PairOffer {
            suggested_label: ctx.label(),
            device_pk: *ident.key.public(),
            inbox_id,
            writer_token: token,
        },
        writer_id,
    })
}

/// Records the registration as pending, registers it, then records its id. The outer
/// error is local (writing peers.json), the inner one the relay's.
async fn register<H: Host>(
    ctx: &mut Ctx<'_, H>,
    relay: &H::Relay,
    ident: &Identity,
    registration: &kc_wire::WriterRegister,
) -> Result<Result<String, kc_proto::relay::RelayError>> {
    let hash = registration.writer_token_sha256.clone();
    edit_peers(ctx, |peers, now| {
        peers.pending_writers.push(PendingWriter {
            writer_id: None,
            token_sha256: Some(hash.clone()),
            since: now,
            revoking: false,
            peer: None,
        });
    })?;
    let registered = match relay
        .register_writer(&ident.inbox_id, &ident.owner, registration)
        .await
    {
        Ok(registered) => registered,
        Err(e) => return Ok(Err(e)),
    };
    let writer_id = registered.writer_id;
    // Best effort: without the id, cleanup finds the registration again by its hash.
    let _ = edit_peers(ctx, |peers, _| {
        for pending in &mut peers.pending_writers {
            if pending.token_sha256.as_deref() == Some(hash.as_str()) {
                pending.writer_id = Some(writer_id.clone());
            }
        }
    });
    Ok(Ok(writer_id))
}

/// Hands a registration that couldn't be revoked now to the pending list, for the next
/// pairing to revoke. Needs `state.lock` held by the caller around `peers`.
pub(crate) fn revoke_later(peers: &mut crate::state::Peers, writer_id: &str) {
    peers.pending_writers.push(PendingWriter {
        writer_id: Some(writer_id.to_owned()),
        token_sha256: None,
        since: 0,
        revoking: false,
        peer: None,
    });
}

/// Undoes [`prepare_offer`] when the pairing doesn't happen. Best effort: a registration
/// that can't be revoked now stays pending, and a later pairing revokes it.
pub(crate) async fn discard_offer<H: Host>(
    ctx: &mut Ctx<'_, H>,
    relay: &H::Relay,
    ident: &Identity,
    prepared: Prepared,
) {
    if revoke_writer(relay, ident, &prepared.writer_id).await {
        let _ = edit_peers(ctx, |peers, _| {
            peers
                .pending_writers
                .retain(|w| w.writer_id.as_deref() != Some(prepared.writer_id.as_str()));
        });
    }
}

/// Deletes a writer registration on our inbox. True if it's gone (already gone counts).
async fn revoke_writer<R: RelayApi>(relay: &R, ident: &Identity, writer_id: &str) -> bool {
    match relay
        .delete_writer(&ident.inbox_id, &ident.owner, writer_id)
        .await
    {
        Ok(()) => true,
        Err(e) => e.is(ErrorCode::NotFound) || e.is(ErrorCode::Unauthorized),
    }
}

/// How long a pairing can still be running: a channel lives 10 minutes. A pairing whose
/// confirmation takes longer finds its registration revoked and fails (see
/// [`commit_peer`]).
const PAIRING_MAX_SECS: i64 = kc_wire::limits::CHANNEL_TTL_SECS as i64 + 300;

/// Revokes the registrations interrupted pairings left pending, and replaced ones that
/// couldn't be revoked at the time. Best effort.
async fn revoke_stale_writers<H: Host>(ctx: &mut Ctx<'_, H>, relay: &H::Relay, ident: &Identity) {
    // First, under the lock, mark the stale entries as being revoked: from then on no
    // pairing can commit with them (see `commit_peer`), even if this run dies midway.
    let mut stale = Vec::new();
    let marked = edit_peers(ctx, |peers, now| {
        for pending in &mut peers.pending_writers {
            if now - pending.since > PAIRING_MAX_SECS {
                pending.revoking = true;
                stale.push(pending.clone());
            }
        }
    });
    if marked.is_err() {
        return;
    }
    let mut revoked = Vec::new();
    for pending in &stale {
        // Without an id, registering the same hash again gives it back (or makes a
        // registration that is revoked right away).
        let writer_id = match (&pending.writer_id, &pending.token_sha256) {
            (Some(id), _) => Some(id.clone()),
            (None, Some(hash)) => {
                let again = kc_wire::WriterRegister {
                    writer_token_sha256: hash.clone(),
                };
                relay
                    .register_writer(&ident.inbox_id, &ident.owner, &again)
                    .await
                    .ok()
                    .map(|r| r.writer_id)
            }
            (None, None) => None,
        };
        if let Some(writer_id) = writer_id
            && revoke_writer(relay, ident, &writer_id).await
        {
            revoked.push(pending.clone());
        }
    }
    if !revoked.is_empty() {
        let _ = edit_peers(ctx, |peers, _| {
            peers.pending_writers.retain(|w| {
                !revoked.iter().any(|r: &PendingWriter| {
                    r.writer_id == w.writer_id && r.token_sha256 == w.token_sha256
                })
            });
        });
    }
}

/// Changes peers.json under `state.lock`. `change` gets the current time too.
fn edit_peers<H: Host>(
    ctx: &mut Ctx<'_, H>,
    change: impl FnOnce(&mut crate::state::Peers, i64),
) -> Result<()> {
    let _lock = ctx.state.lock()?;
    let mut peers = ctx.state.load_peers()?;
    change(&mut peers, ctx.host.now());
    ctx.state.save_peers(&peers)
}

/// Stores the peer from `their` offer. The label is the peer's suggestion made valid and
/// unique here; a peer that is already known (same key) keeps its label. On any failure our
/// registration for the peer is revoked. Returns the label.
pub(crate) async fn remember_peer<H: Host>(
    ctx: &mut Ctx<'_, H>,
    relay: &H::Relay,
    ident: &Identity,
    their: &PairOffer,
    ours: Prepared,
) -> Result<Label> {
    match commit_peer(ctx, ident, their, &ours.writer_id) {
        Ok(label) => Ok(label),
        Err(e) => {
            discard_offer(ctx, relay, ident, ours).await;
            Err(e)
        }
    }
}

/// The local half of [`remember_peer`], under `state.lock`: checks that this device's
/// identity is still the one the pairing used and that its registration is still pending
/// (not revoked as stale meanwhile), writes the peer's token to a new slot, then switches
/// peers.json to it in one write. A registration this pairing replaces moves to the pending
/// list, due only once messages the peer queued with it have expired: revoking a writer
/// deletes its queued messages. Returns the label.
fn commit_peer<H: Host>(
    ctx: &mut Ctx<'_, H>,
    ident: &Identity,
    their: &PairOffer,
    writer_id: &str,
) -> Result<Label> {
    let fp = their.device_pk.fingerprint();
    if fp == ident.key.fingerprint() {
        return Err(CliError::new(
            kc_wire::exit::AUTH_FAILED,
            tr!("the other device has this device's own key; not pairing"),
        ));
    }
    let _lock = ctx.state.lock()?;
    // Another kc process may have rotated this device's key or inbox since the pairing
    // began; the offer we sent would then point at an identity this device no longer has.
    let key_now = device_key(ctx)?.map(|k| k.fingerprint());
    let inbox_now = own_inbox(ctx)?.map(|(id, _)| id);
    if key_now != Some(ident.key.fingerprint()) || inbox_now.as_deref() != Some(&ident.inbox_id) {
        return Err(CliError::failure(tr!(
            "this device's key or inbox changed while pairing (`kc device rotate`?); pair again"
        )));
    }
    let mut peers = ctx.state.load_peers()?;
    let ours = |w: &PendingWriter| w.writer_id.as_deref() == Some(writer_id);
    if !peers.pending_writers.iter().any(|w| ours(w) && !w.revoking) {
        return Err(CliError::failure(tr!(
            "the pairing took too long and its registration was revoked; pair again"
        )));
    }
    let token_key = format!(
        "{WRITER_KEY_PREFIX}{}/{}",
        fp.to_hex(),
        token_tag(&their.writer_token)
    );
    ctx.store
        .set_internal(&token_key, their.writer_token.expose())?;
    let now = ctx.host.now();
    let (label, replaced, old_key) = match peers.peers.iter_mut().find(|p| p.fingerprint == fp) {
        Some(known) => {
            let old_key = known.token_key();
            known.inbox_id = their.inbox_id;
            known.paired_at = now;
            known.token_key = Some(token_key.clone());
            let replaced = known.writer_id.replace(writer_id.to_owned());
            (known.label.clone(), replaced, Some(old_key))
        }
        None => {
            let label = Label::sanitize(their.suggested_label.as_str())
                .unique(|candidate| peers.label_taken(candidate));
            peers.peers.push(Peer {
                label: label.clone(),
                fingerprint: fp,
                device_pk: their.device_pk,
                inbox_id: their.inbox_id,
                writer_id: Some(writer_id.to_owned()),
                token_key: Some(token_key.clone()),
                paired_at: now,
            });
            (label, None, None)
        }
    };
    let replaced = replaced.filter(|old| old != writer_id);
    peers.pending_writers.retain(|w| !ours(w));
    if let Some(old) = &replaced {
        peers.pending_writers.push(PendingWriter {
            writer_id: Some(old.clone()),
            token_sha256: None,
            since: now + kc_wire::limits::INBOX_MESSAGE_TTL_SECS as i64,
            revoking: false,
            peer: Some(fp),
        });
    }
    if let Err(e) = ctx.state.save_peers(&peers) {
        let _ = ctx.store.delete_internal(&token_key);
        return Err(e);
    }
    if let Some(old) = old_key.filter(|old| *old != token_key) {
        let _ = ctx.store.delete_internal(&old);
    }
    Ok(label)
}

/// Names a token's slot: the first 8 bytes of SHA-256(token), in hex. It reveals nothing
/// usable about the token.
fn token_tag(token: &WriterToken) -> String {
    Sha256::digest(token.expose())[..8]
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect()
}

/// Tells the person how to use the new pairing.
pub(crate) fn announce_pairing<H: Host>(ctx: &mut Ctx<'_, H>, label: &Label, fp: &Fingerprint) {
    say!(
        ctx,
        "{}",
        tr!(
            "Paired with {label} (fingerprint {fingerprint}).",
            label = label,
            fingerprint = fp.short()
        )
    );
    say!(
        ctx,
        "{}",
        tr!(
            "Send to it without a code: kc send NAME --to {label}. It picks items up with `kc inbox`.",
            label = shell_word(label.as_str())
        )
    );
}

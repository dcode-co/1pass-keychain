//! `kc inbox`: stores what paired devices sent (PROTOCOL §4).
//!
//! For each message waiting in this device's inbox: open it (it must come from a remembered
//! peer, be addressed to one of our keys, be within its lifetime and not be in the seen-set),
//! show it (and at a terminal, confirm), store its items under the conflict policy, record
//! its id as seen, then delete it from the relay. Messages that can never be opened are
//! deleted too; one dated in the future (clock skew) or from a newer kc stays for later.
//!
//! The import is journaled in seen.json (`pending`, with each settled item) before the
//! first item is written. A crash or a keychain failure leaves the message on the relay and
//! the journal behind; the next run skips the settled items and finishes the rest, so no
//! item is ever applied twice.

use std::time::Duration;

use kc_proto::inbox::{self, InboxError, MessageId};
use kc_proto::relay::{RelayApi, RelayError, message_body};
use kc_proto::{DeviceKeyPair, ItemName, ItemResult};
use kc_wire::limits::LONG_POLL_MAX_SECS;
use kc_wire::{ErrorCode, exit};
use tokio::time::Instant;

use super::apply::{self, Conflicts};
use super::{Ctx, pairing, say};
use crate::cli::InboxArgs;
use crate::error::{CliError, Result};
use crate::host::Host;
use crate::i18n::tr;
use crate::state::{Seen, StateDir};

pub(super) async fn inbox<H: Host>(ctx: &mut Ctx<'_, H>, args: InboxArgs) -> Result<i32> {
    let Some((inbox_id, owner)) = pairing::owned_inbox(ctx)? else {
        say!(
            ctx,
            "{}",
            tr!("No inbox: this device hasn't been paired yet. Pair it with `kc pair`.")
        );
        return Ok(exit::OK);
    };
    let relay = ctx.connect()?;
    if let Some(seconds) = args.wait {
        // Waits without holding state.lock, so other kc commands aren't blocked meanwhile.
        match wait_for_messages(&relay, &inbox_id, &owner, Duration::from_secs(seconds)).await {
            Ok(true) => {}
            Ok(false) => {
                say!(ctx, "{}", tr!("No new messages."));
                return Ok(exit::OK);
            }
            Err(e) if e.is(ErrorCode::Unauthorized) => {
                return lost_inbox(ctx, &relay, &inbox_id).await;
            }
            Err(e) => return Err(CliError::from(e).context(tr!("reading this device's inbox"))),
        }
    }
    let _lock = ctx.state.lock()?;
    let listing = match relay.list_messages(&inbox_id, &owner, Duration::ZERO).await {
        Ok(listing) => listing,
        Err(e) if e.is(ErrorCode::Unauthorized) => {
            drop(_lock);
            return lost_inbox(ctx, &relay, &inbox_id).await;
        }
        Err(e) => return Err(CliError::from(e).context(tr!("reading this device's inbox"))),
    };
    if listing.messages.is_empty() {
        say!(ctx, "{}", tr!("No new messages."));
        return Ok(exit::OK);
    }
    let keys = pairing::own_keys(ctx)?;
    if keys.is_empty() {
        return Err(
            CliError::failure(tr!("this device has an inbox but no device key"))
                .with_hint(tr!("`kc device rotate` makes a new key and inbox")),
        );
    }
    let key_refs: Vec<&DeviceKeyPair> = keys.iter().collect();
    let peers = ctx.state.load_peers()?;
    let now = ctx.host.now();
    let mut seen = ctx.state.load_seen(now)?;
    // Inbox imports never overwrite without `--on-conflict overwrite` (PROTOCOL §4), so the
    // conflict question doesn't offer it.
    let conflicts = Conflicts::from_flag(args.on_conflict, ctx.interactive(), false);
    let mut outcome = Outcome::default();

    for message in &listing.messages {
        let opened = message_body(message)
            .map_err(|_| InboxError::Malformed)
            .and_then(|body| {
                inbox::open(
                    &body,
                    &key_refs,
                    |fp| peers.by_fingerprint(fp).map(|p| p.device_pk),
                    |id| seen.contains(id),
                    now,
                )
            });
        let opened = match opened {
            Ok(opened) => opened,
            Err(e) => {
                let keep = matches!(
                    e,
                    InboxError::NotYetValid
                        | InboxError::UnsupportedVersion(_)
                        | InboxError::UnsupportedSuite(_)
                );
                if keep {
                    say!(
                        ctx,
                        "{}",
                        tr!("A message was left in the inbox: {error}.", error = e)
                    );
                } else {
                    let text = if e == InboxError::Replay {
                        tr!(
                            "A message was dropped: {error} (or one this device stored before but couldn't delete).",
                            error = e
                        )
                    } else {
                        tr!("A message was dropped: {error}.", error = e)
                    };
                    say!(ctx, "{text}");
                    delete(ctx, &relay, &inbox_id, &owner, &message.msg_id).await;
                }
                outcome.failed(e.exit_code());
                continue;
            }
        };
        let label = peers
            .by_fingerprint(&opened.sender_fp)
            .map_or_else(|| opened.sender_fp.short(), |p| p.label.to_string());
        let names: Vec<&str> = opened.items.iter().map(|i| i.name.as_str()).collect();
        let (n, names) = (names.len(), names.join(", "));
        let text = if n == 1 {
            tr!(
                "From {label}: {n} item: {names}",
                label = label,
                n = n,
                names = names
            )
        } else {
            tr!(
                "From {label}: {n} items: {names}",
                label = label,
                n = n,
                names = names
            )
        };
        say!(ctx, "{text}");
        if ctx.interactive() && !ctx.confirm(&tr!("Store them?"), true)? {
            say!(
                ctx,
                "{}",
                tr!("Left in the inbox (it expires within 72 hours).")
            );
            outcome.partial();
            continue;
        }
        let until = opened.keep_seen_until();
        seen.pending(&opened.msg_id, until);
        ctx.state.save_seen(&seen)?;
        let applied = {
            let mut journal = MessageJournal {
                seen: &mut seen,
                id: opened.msg_id,
                until,
            };
            apply::apply_items(ctx, &opened.items, conflicts, &label, Some(&mut journal))?
        };
        apply::print_results(ctx, &applied.results, true);
        if applied.done_before > 0 {
            let n = applied.done_before;
            let text = if n == 1 {
                tr!(
                    "({n} item of these settled by an earlier run that was interrupted)",
                    n = n
                )
            } else {
                tr!(
                    "({n} items of these settled by an earlier run that was interrupted)",
                    n = n
                )
            };
            say!(ctx, "  {text}");
        }
        if applied.not_tried > 0 {
            let n = applied.not_tried;
            let text = if n == 1 {
                tr!(
                    "({n} item not tried yet: the import stops at a failed write)",
                    n = n
                )
            } else {
                tr!(
                    "({n} items not tried yet: the import stops at a failed write)",
                    n = n
                )
            };
            say!(ctx, "  {text}");
        }
        if let Some((e, _)) = &applied.keychain_error {
            // Not seen, not deleted: the next `kc inbox` finishes the rest.
            say!(ctx, "{}", tr!("Keychain error: {error}", error = e));
            say!(
                ctx,
                "{}",
                tr!(
                    "The message stays in the inbox; run `kc inbox` again once the keychain works."
                )
            );
            outcome.applied(applied.exit_code());
            continue;
        }
        seen.insert(&opened.msg_id, until);
        ctx.state.save_seen(&seen)?;
        delete(ctx, &relay, &inbox_id, &owner, &message.msg_id).await;
        outcome.applied(applied.exit_code());
    }
    Ok(outcome.exit_code())
}

/// [`apply::Journal`] for one inbox message, kept in seen.json.
struct MessageJournal<'a> {
    seen: &'a mut Seen,
    id: MessageId,
    until: i64,
}

impl apply::Journal for MessageJournal<'_> {
    fn progress(&self, name: &ItemName) -> apply::Progress {
        let Some(record) = self.seen.pending.get(&self.id.to_hex()) else {
            return apply::Progress::New;
        };
        if let Some(result) = record.done.iter().find(|d| d.name == *name) {
            apply::Progress::Done(result.clone())
        } else if record.writing.as_deref() == Some(name.as_str()) {
            apply::Progress::InDoubt
        } else {
            apply::Progress::New
        }
    }

    fn writing(&mut self, state: &StateDir, name: &ItemName) -> Result<()> {
        self.seen.pending(&self.id, self.until).writing = Some(name.to_string());
        state.save_seen(self.seen)
    }

    fn settled(&mut self, state: &StateDir, result: &ItemResult) -> Result<()> {
        let record = self.seen.pending(&self.id, self.until);
        record.done.push(result.clone());
        record.writing = None;
        state.save_seen(self.seen)
    }
}

/// The relay doesn't know the inbox `lost` any more: make a new one (unless another kc
/// process just did) and say what that means.
async fn lost_inbox<H: Host>(ctx: &mut Ctx<'_, H>, relay: &H::Relay, lost: &str) -> Result<i32> {
    let lock = ctx.state.lock()?;
    let (_, replaced) = pairing::replace_lost_inbox(ctx, relay, &lock, lost).await?;
    drop(lock);
    if replaced {
        pairing::lost_inbox_notice(ctx);
    } else {
        say!(
            ctx,
            "{}",
            tr!("This device's inbox changed while kc was reading it; run `kc inbox` again.")
        );
    }
    Ok(exit::EXPIRED)
}

/// Long-polls (25 s at a time, so at most 25 reads for the 600 s maximum) until a message
/// is waiting or `wait` is over. Inbox reads are rate-limited (120 an hour).
async fn wait_for_messages<R: RelayApi>(
    relay: &R,
    inbox_id: &str,
    owner: &str,
    wait: Duration,
) -> Result<bool, RelayError> {
    let deadline = Instant::now() + wait;
    loop {
        let started = Instant::now();
        let poll = deadline.saturating_duration_since(started).clamp(
            Duration::from_secs(1),
            Duration::from_secs(LONG_POLL_MAX_SECS),
        );
        if !relay
            .list_messages(inbox_id, owner, poll)
            .await?
            .messages
            .is_empty()
        {
            return Ok(true);
        }
        if Instant::now() >= deadline {
            return Ok(false);
        }
        // Don't spin if the relay answers early.
        tokio::time::sleep_until((started + Duration::from_secs(1)).min(deadline)).await;
    }
}

/// Deletes one message from the relay. A failure only means it is listed again next time,
/// where the seen-set (or its expiry) stops it.
async fn delete<H: Host>(
    ctx: &mut Ctx<'_, H>,
    relay: &H::Relay,
    inbox_id: &str,
    owner: &str,
    msg_id: &str,
) {
    if let Err(e) = relay.delete_message(inbox_id, owner, msg_id).await {
        say!(
            ctx,
            "{}",
            tr!(
                "Couldn't delete the message from the relay ({error}); it will be skipped next time.",
                error = e
            )
        );
    }
}

/// The worst thing that happened, in order: auth failure (7), expiry (9), a keychain
/// failure (its own code: 4, 5 or 1), partial (8).
#[derive(Debug, Default)]
struct Outcome {
    auth_failed: bool,
    expired: bool,
    keychain: Option<i32>,
    partial: bool,
}

impl Outcome {
    fn failed(&mut self, code: i32) {
        match code {
            exit::EXPIRED => self.expired = true,
            _ => self.auth_failed = true,
        }
    }

    fn applied(&mut self, code: i32) {
        match code {
            exit::OK => {}
            exit::PARTIAL => self.partial = true,
            other => {
                self.keychain.get_or_insert(other);
            }
        }
    }

    fn partial(&mut self) {
        self.partial = true;
    }

    fn exit_code(&self) -> i32 {
        if self.auth_failed {
            exit::AUTH_FAILED
        } else if self.expired {
            exit::EXPIRED
        } else if let Some(code) = self.keychain {
            code
        } else if self.partial {
            exit::PARTIAL
        } else {
            exit::OK
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn outcome_order() {
        let mut o = Outcome::default();
        assert_eq!(o.exit_code(), 0);
        o.partial();
        assert_eq!(o.exit_code(), exit::PARTIAL);
        o.applied(exit::INTERACTION_REQUIRED);
        o.applied(exit::KEYCHAIN_UNAVAILABLE);
        assert_eq!(o.exit_code(), exit::INTERACTION_REQUIRED);
        o.failed(InboxError::Expired.exit_code());
        assert_eq!(o.exit_code(), exit::EXPIRED);
        o.failed(InboxError::Replay.exit_code());
        assert_eq!(o.exit_code(), exit::AUTH_FAILED);
    }
}

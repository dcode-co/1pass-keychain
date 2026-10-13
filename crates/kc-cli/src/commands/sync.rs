use super::{Ctx, inbox, say};
use crate::{cli::{SyncArgs, InboxArgs}, error::Result, host::Host, i18n::tr, sync::{self, State}};

pub(super) async fn run<H: Host>(ctx: &mut Ctx<'_, H>, args: SyncArgs) -> Result<i32> {
    if let Some(command) = args.command {
        let quiet = matches!(command, crate::cli::SyncCommand::Status { .. } | crate::cli::SyncCommand::Freeze | crate::cli::SyncCommand::Peer { command: crate::cli::SyncPeerCommand::List });
        let code = sync::actions::command(ctx, command)?;
        if !quiet { sync::flush(ctx, false).await?; }
        return Ok(code);
    }
    let before = {
        let _items = ctx.state.lock_items(ctx.store.namespace())?;
        let _state = ctx.state.lock()?;
        let mut s = State::load(&ctx.state)?;
        sync::scan(ctx, &mut s)?;
        s.items.iter().map(|(n, i)| (n.clone(), i.head)).collect::<std::collections::BTreeMap<_, _>>()
    };
    let received = inbox::inbox(ctx, InboxArgs { on_conflict: None, wait: None }).await?;
    let sent = sync::flush(ctx, true).await?;
    let s = State::load(&ctx.state)?;
    let updated = s.items.iter().filter(|(n, i)| before.get(*n) != Some(&i.head)).count();
    let conflict = s.items.values().filter(|i| i.conflict).count();
    let held = s.candidates.values().filter(|c| c.category != sync::CandidateKind::Conflict).count();
    say!(ctx, "{}", tr!("{sent} sent, {updated} updated, {conflict} conflict, {held} held", sent = sent, updated = updated, conflict = conflict, held = held));
    Ok(if received != 0 && received != 8 { received } else { sync::pending_code(ctx)?.max(received) })
}

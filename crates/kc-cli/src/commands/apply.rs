//! Storing received items under a conflict policy, shared by `receive`, `pair` and `inbox`.
//!
//! - A new name is stored. The same value as here is `Unchanged`.
//! - A different value here is a conflict: `skip` keeps ours, `overwrite` replaces it (kc-store
//!   keeps the old value for `kc restore`), `rename` stores the new value as `NAME-2` (or the
//!   next free name). At a terminal without `--on-conflict`, each conflict is asked about.
//!
//! Item names were validated when the payload was decoded.

use kc_proto::payload::{Item, ItemResult, ItemStatus};
use kc_proto::{ItemName, SecretBytes};
use kc_store::{ErrorKind, ItemKind, MAX_NAME_LEN, MAX_VALUE_LEN, Origin, StoreError};
use kc_wire::exit;

use super::{Ctx, display_width, pad_to, say};
use crate::cli::ConflictPolicy;
use crate::error::{CliError, Result};
use crate::host::Host;
use crate::i18n::tr;
use crate::state::StateDir;

/// `Rejected(u16)` codes (PROTOCOL §3).
pub(crate) const REJECT_INVALID: u16 = 1;
pub(crate) const REJECT_POLICY: u16 = 2;
pub(crate) const REJECT_KEYCHAIN: u16 = 3;
pub(crate) const REJECT_TOO_LARGE: u16 = 4;

/// How conflicts are settled.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Conflicts {
    Policy(ConflictPolicy),
    /// Ask for each one (interactive runs without `--on-conflict`). `overwrite` offers
    /// replacing: inbox imports never overwrite without the flag (PROTOCOL §4).
    Ask {
        overwrite: bool,
    },
}

impl Conflicts {
    /// `--on-conflict` if given; otherwise ask at a terminal and skip elsewhere.
    pub fn from_flag(
        flag: Option<ConflictPolicy>,
        interactive: bool,
        may_offer_overwrite: bool,
    ) -> Conflicts {
        match flag {
            Some(policy) => Conflicts::Policy(policy),
            None if interactive => Conflicts::Ask {
                overwrite: may_offer_overwrite,
            },
            None => Conflicts::Policy(ConflictPolicy::Skip),
        }
    }
}

/// What applying a batch did.
#[derive(Debug, Default)]
pub(crate) struct Applied {
    pub results: Vec<ItemResult>,
    pub confirmation_denied: bool,
    /// The first keychain error, to show once, with its exit code: 4 when the keychain is
    /// unavailable, 5 when it wants a person to confirm, 1 otherwise.
    pub keychain_error: Option<(String, i32)>,
    /// Items an earlier, interrupted run already settled (see [`Journal`]). Their recorded
    /// results are part of `results`.
    pub done_before: usize,
    /// Items not tried because the import stopped at an unresolved write.
    pub not_tried: usize,
}

impl Applied {
    /// 0 if everything is here, the keychain error's code if the keychain failed, else 8.
    pub fn exit_code(&self) -> i32 {
        if self.confirmation_denied { return exit::INTERACTION_REQUIRED; }
        match &self.keychain_error {
            Some((_, code)) => *code,
            None => local_exit_code(&self.results),
        }
    }
}

/// Where an inbox import records its progress, so a retry after a crash or a keychain
/// failure never applies an item twice.
pub(crate) trait Journal {
    /// What an earlier run did with `name`.
    fn progress(&self, name: &ItemName) -> Progress;
    /// Records that `name` is about to be written. A failure stops the import.
    fn writing(&mut self, state: &StateDir, name: &ItemName) -> Result<()>;
    /// Records that `result` is settled. A failure stops the import.
    fn settled(&mut self, state: &StateDir, result: &ItemResult) -> Result<()>;
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Progress {
    New,
    /// Settled by an earlier run, with this result.
    Done(ItemResult),
    /// An earlier run stopped while writing it: it may or may not be stored.
    InDoubt,
}

/// Exit code for results applied on this device.
pub(crate) fn local_exit_code(results: &[ItemResult]) -> i32 {
    if results
        .iter()
        .any(|r| r.status == ItemStatus::Rejected(REJECT_KEYCHAIN))
    {
        exit::KEYCHAIN_UNAVAILABLE
    } else if results.iter().all(|r| succeeded(&r.status)) {
        exit::OK
    } else {
        exit::PARTIAL
    }
}

pub(crate) fn succeeded(status: &ItemStatus) -> bool {
    matches!(
        status,
        ItemStatus::Stored | ItemStatus::Unchanged | ItemStatus::Renamed(_)
    )
}

/// Every item declined (`Rejected(2)`).
pub(crate) fn declined(items: &[Item]) -> Vec<ItemResult> {
    items
        .iter()
        .map(|item| ItemResult {
            name: item.name.clone(),
            status: ItemStatus::Rejected(REJECT_POLICY),
        })
        .collect()
}

pub(crate) fn apply_items<H: Host>(
    ctx: &mut Ctx<'_, H>,
    items: &[Item],
    conflicts: Conflicts,
    from_device: &str,
    journal: Option<&mut dyn Journal>,
) -> Result<Applied> {
    let _items = ctx.state.lock_items(ctx.store.namespace())?;
    let _state = ctx.state.lock()?;
    apply_items_locked(ctx, items, conflicts, from_device, journal)
}

pub(crate) fn apply_items_locked<H: Host>(
    ctx: &mut Ctx<'_, H>,
    items: &[Item],
    conflicts: Conflicts,
    from_device: &str,
    mut journal: Option<&mut dyn Journal>,
) -> Result<Applied> {
    let mut applied = Applied::default();
    // Names in this batch: a rename never takes one of them.
    let batch: Vec<&str> = items.iter().map(|i| i.name.as_str()).collect();
    for (index, item) in items.iter().enumerate() {
        let progress = journal
            .as_ref()
            .map_or(Progress::New, |j| j.progress(&item.name));
        // An item an earlier run may or may not have written is settled the safe way: it
        // is stored if absent, and never replaces what is there now (which may be a local
        // change made since).
        let conflicts = match progress {
            Progress::Done(result) => {
                applied.done_before += 1;
                applied.results.push(result);
                continue;
            }
            Progress::InDoubt => Conflicts::Policy(ConflictPolicy::Skip),
            Progress::New => conflicts,
        };
        let mut mark = |state: &StateDir| match journal.as_mut() {
            Some(journal) => journal.writing(state, &item.name),
            None => Ok(()),
        };
        let outcome = apply_one(ctx, item, conflicts, from_device, &batch, &mut mark);
        let status = match outcome {
            Ok(status) => status,
            Err(Failure::Store(e)) => {
                let status = ItemStatus::Rejected(reject_code(&e));
                if applied.keychain_error.is_none()
                    && status == ItemStatus::Rejected(REJECT_KEYCHAIN)
                {
                    applied.keychain_error = Some((e.to_string(), e.exit_code()));
                }
                status
            }
            Err(Failure::SyncConfirmation(e)) => {
                applied.confirmation_denied = true;
                say!(ctx, "{e}");
                ItemStatus::SkippedConflict
            }
            Err(Failure::Cli(e)) => return Err(e),
        };
        let result = ItemResult {
            name: item.name.clone(),
            status,
        };
        let unresolved = result.status == ItemStatus::Rejected(REJECT_KEYCHAIN);
        if let Some(journal) = journal.as_mut() {
            if unresolved {
                // Whether that write landed is unknown, and the journal marks one item in
                // doubt at a time: stop here; the next run starts with this item.
                applied.results.push(result);
                applied.not_tried = items.len() - index - 1;
                return Ok(applied);
            }
            journal.settled(&ctx.state, &result)?;
        }
        applied.results.push(result);
    }
    Ok(applied)
}

enum Failure {
    SyncConfirmation(CliError),
    Store(StoreError),
    /// A prompt was cancelled, or a lock couldn't be taken.
    Cli(CliError),
}

impl From<StoreError> for Failure {
    fn from(e: StoreError) -> Failure {
        Failure::Store(e)
    }
}

impl From<CliError> for Failure {
    fn from(e: CliError) -> Failure {
        Failure::Cli(e)
    }
}

fn reject_code(e: &StoreError) -> u16 {
    match e {
        StoreError::InvalidValue(_) | StoreError::InvalidName { .. } => REJECT_INVALID,
        _ if e.kind() == ErrorKind::InvalidInput => REJECT_INVALID,
        _ => REJECT_KEYCHAIN,
    }
}

/// Records that a keychain write is about to happen (the journal's in-flight marker), so
/// only a write that may really have happened is ever treated as in doubt.
type MarkWrite<'a> = dyn FnMut(&StateDir) -> Result<()> + 'a;

/// What `items.lock` protects: the check of what's stored and the write it decides on.
fn apply_one<H: Host>(
    ctx: &mut Ctx<'_, H>,
    item: &Item,
    conflicts: Conflicts,
    from_device: &str,
    batch: &[&str],
    mark: &mut MarkWrite<'_>,
) -> std::result::Result<ItemStatus, Failure> {
    let value = item.value.expose();
    if value.is_empty() {
        return Ok(ItemStatus::Rejected(REJECT_INVALID));
    }
    if value.len() > MAX_VALUE_LEN {
        return Ok(ItemStatus::Rejected(REJECT_TOO_LARGE));
    }
    if let Some(status) = crate::sync::legacy(ctx, item, from_device, conflicts == Conflicts::Policy(ConflictPolicy::Overwrite))
            .map_err(|e| if e.code == exit::INTERACTION_REQUIRED { Failure::SyncConfirmation(e) } else { Failure::Cli(e) })?
    {
        return Ok(status);
    }
    let policy = match conflicts {
        Conflicts::Policy(policy) => policy,
        Conflicts::Ask { overwrite } => {
            {
                if let Some(status) = settle_without_conflict(ctx, item, from_device, mark)? {
                    return Ok(status);
                }
            }
            // Ask without holding the lock; what's stored is checked again below.
            ask(ctx, &item.name, overwrite)?
        }
    };
    if let Some(status) = settle_without_conflict(ctx, item, from_device, mark)? {
        return Ok(status);
    }
    match policy {
        ConflictPolicy::Skip => Ok(ItemStatus::SkippedConflict),
        ConflictPolicy::Overwrite if !ctx.interactive() => Ok(ItemStatus::SkippedConflict),
        ConflictPolicy::Overwrite => {
            mark(&ctx.state)?;
            store(ctx, item.name.as_str(), item, from_device)?;
            Ok(ItemStatus::Stored)
        }
        ConflictPolicy::Rename => rename(ctx, item, from_device, batch, mark),
    }
}

/// Stores a new name, or recognises the same value. `None` means a conflict. Needs
/// `items.lock`.
fn settle_without_conflict<H: Host>(
    ctx: &Ctx<'_, H>,
    item: &Item,
    from_device: &str,
    mark: &mut MarkWrite<'_>,
) -> std::result::Result<Option<ItemStatus>, Failure> {
    let name = item.name.as_str();
    Ok(match same_value(ctx, name, &item.value)? {
        None => {
            mark(&ctx.state)?;
            store(ctx, name, item, from_device)?;
            Some(ItemStatus::Stored)
        }
        Some(true) => Some(ItemStatus::Unchanged),
        Some(false) => None,
    })
}

/// `None` if `name` doesn't exist; otherwise whether it holds `value` (constant time).
fn same_value<H: Host>(
    ctx: &Ctx<'_, H>,
    name: &str,
    value: &SecretBytes,
) -> std::result::Result<Option<bool>, StoreError> {
    Ok(ctx
        .store
        .get(name)?
        .map(|existing| SecretBytes::from(existing.into_zeroizing()) == *value))
}

fn store<H: Host>(
    ctx: &Ctx<'_, H>,
    name: &str,
    item: &Item,
    from_device: &str,
) -> std::result::Result<(), StoreError> {
    let value = item.value.expose();
    let kind = if std::str::from_utf8(value).is_ok() {
        ItemKind::Text
    } else {
        ItemKind::File
    };
    let origin = Origin::Received {
        from_device: from_device.to_owned(),
    };
    ctx.store.set(name, value, kind, origin).map(|_| ())
}

/// `NAME-2`, `NAME-3`, …: the first name that is free (or already holds this value) and
/// isn't another item of the batch. Needs `items.lock`.
fn rename<H: Host>(
    ctx: &Ctx<'_, H>,
    item: &Item,
    from_device: &str,
    batch: &[&str],
    mark: &mut MarkWrite<'_>,
) -> std::result::Result<ItemStatus, Failure> {
    for n in 2..1000u32 {
        let Some(candidate) = numbered(&item.name, n) else {
            continue;
        };
        if batch.contains(&candidate.as_str()) {
            continue;
        }
        match same_value(ctx, candidate.as_str(), &item.value)? {
            None => {
                mark(&ctx.state)?;
                store(ctx, candidate.as_str(), item, from_device)?;
                return Ok(ItemStatus::Renamed(candidate));
            }
            Some(true) => return Ok(ItemStatus::Renamed(candidate)),
            Some(false) => {}
        }
    }
    Ok(ItemStatus::SkippedConflict)
}

/// `name-n`, shortened to fit 128 characters.
pub(crate) fn numbered(name: &ItemName, n: u32) -> Option<ItemName> {
    let suffix = format!("-{n}");
    let keep = MAX_NAME_LEN.checked_sub(suffix.len())?;
    let base = &name.as_str()[..name.as_str().len().min(keep)];
    ItemName::new(&format!("{base}{suffix}")).ok()
}

fn ask<H: Host>(ctx: &mut Ctx<'_, H>, name: &ItemName, overwrite: bool) -> Result<ConflictPolicy> {
    say!(
        ctx,
        "{}",
        tr!(
            "{name} already exists here with a different value.",
            name = name
        )
    );
    let mut options = vec![(ConflictPolicy::Skip, tr!("Keep this device's value (skip)"))];
    if overwrite {
        options.push((
            ConflictPolicy::Overwrite,
            tr!(
                "Replace it (`kc restore {name}` brings the old value back)",
                name = name
            ),
        ));
    }
    options.push((
        ConflictPolicy::Rename,
        tr!(
            "Store the new value under another name ({name}-2 or the next free one)",
            name = name
        ),
    ));
    let labels: Vec<String> = options.iter().map(|(_, label)| label.clone()).collect();
    let choice = ctx.select(
        &tr!("What should happen to {name}?", name = name),
        &labels,
        0,
    )?;
    Ok(options
        .get(choice)
        .map_or(ConflictPolicy::Skip, |(policy, _)| *policy))
}

/// One line per item, for the device that stored them (`local`) or the one that sent them.
pub(crate) fn describe(status: &ItemStatus, local: bool) -> String {
    match status {
        ItemStatus::Stored => tr!("stored"),
        ItemStatus::Unchanged => tr!("unchanged (same value)"),
        ItemStatus::SkippedConflict if local => {
            tr!("skipped: a different value is already here (use --on-conflict)")
        }
        ItemStatus::SkippedConflict => {
            tr!("skipped: the other device already has a different value")
        }
        ItemStatus::Renamed(name) => tr!("stored as {name}", name = name),
        ItemStatus::Rejected(REJECT_INVALID) => tr!("rejected: invalid item"),
        ItemStatus::Rejected(REJECT_POLICY) => tr!("declined"),
        ItemStatus::Rejected(REJECT_KEYCHAIN) => tr!("not stored: the keychain write failed"),
        ItemStatus::Rejected(REJECT_TOO_LARGE) => tr!("not stored: too large for the keychain"),
        ItemStatus::Rejected(code) => tr!("rejected (code {code})", code = code),
    }
}

pub(crate) fn print_results<H: Host>(ctx: &mut Ctx<'_, H>, results: &[ItemResult], local: bool) {
    let width = results
        .iter()
        .map(|r| display_width(r.name.as_str()))
        .max()
        .unwrap_or(0);
    for result in results {
        say!(
            ctx,
            "  {}  {}",
            pad_to(result.name.as_str(), width),
            describe(&result.status, local)
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn result(status: ItemStatus) -> ItemResult {
        ItemResult {
            name: ItemName::new("A").unwrap(),
            status,
        }
    }

    #[test]
    fn numbered_names_fit() {
        let name = ItemName::new("GITHUB_TOKEN").unwrap();
        assert_eq!(numbered(&name, 2).unwrap().as_str(), "GITHUB_TOKEN-2");
        let long = ItemName::new(&"x".repeat(128)).unwrap();
        let n = numbered(&long, 17).unwrap();
        assert_eq!(n.as_str().len(), 128);
        assert!(n.as_str().ends_with("x-17"));
    }

    #[test]
    fn exit_codes_from_results() {
        assert_eq!(local_exit_code(&[result(ItemStatus::Stored)]), 0);
        assert_eq!(
            local_exit_code(&[
                result(ItemStatus::Unchanged),
                result(ItemStatus::Renamed(ItemName::new("A-2").unwrap()))
            ]),
            0
        );
        assert_eq!(
            local_exit_code(&[
                result(ItemStatus::Stored),
                result(ItemStatus::SkippedConflict)
            ]),
            exit::PARTIAL
        );
        assert_eq!(
            local_exit_code(&[result(ItemStatus::Rejected(REJECT_KEYCHAIN))]),
            exit::KEYCHAIN_UNAVAILABLE
        );
        assert_eq!(local_exit_code(&[]), 0);
    }

    #[test]
    fn policy_defaults() {
        assert_eq!(
            Conflicts::from_flag(None, true, true),
            Conflicts::Ask { overwrite: true }
        );
        assert_eq!(
            Conflicts::from_flag(None, true, false),
            Conflicts::Ask { overwrite: false }
        );
        assert_eq!(
            Conflicts::from_flag(None, false, true),
            Conflicts::Policy(ConflictPolicy::Skip)
        );
        assert_eq!(
            Conflicts::from_flag(Some(ConflictPolicy::Rename), true, false),
            Conflicts::Policy(ConflictPolicy::Rename)
        );
    }
}

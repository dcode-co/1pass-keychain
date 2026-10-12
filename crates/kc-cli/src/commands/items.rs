//! Local items: `set`, `get`, `exec`, `list`, `rm`, `restore`, `adopt` (PROTOCOL §7).

use std::collections::HashSet;
use std::ffi::OsString;
use std::process::Command as Process;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use kc_proto::ItemName;
use kc_store::{Change, ItemInfo, ItemKind, MAX_VALUE_LEN, Origin};
use kc_wire::exit;
use zeroize::Zeroizing;

use super::{Ctx, plural, say};
use crate::cli::{AdoptArgs, ExecArgs, GetArgs, ListArgs, NameArgs, RmArgs, SetArgs};
use crate::console::Console as _;
use crate::error::{CliError, Result};
use crate::host::Host;
use crate::state::write_secret_file;
use crate::values::{
    is_env_var_name, item_name, printable, read_file, read_secret, strip_line_ending,
    value_fingerprint,
};

pub(super) fn set<H: Host>(ctx: &mut Ctx<'_, H>, args: SetArgs) -> Result<i32> {
    if !args.extra.is_empty() {
        return Err(CliError::usage(format!(
            "kc set takes only the item name; {} not shown. Values are never taken from \
             arguments (they'd stay in shell history and the process list)",
            plural(args.extra.len(), "extra argument")
        ))
        .with_hint("pipe the value: printf %s \"$VALUE\" | kc set NAME, or use --from-file PATH"));
    }
    let name = item_name(&args.name)?;
    let (value, kind) = match &args.from_file {
        Some(path) => (read_file(path, MAX_VALUE_LEN)?, ItemKind::File),
        // The policy already refused this for non-interactive runs.
        None if ctx.host.stdin_is_terminal() => {
            let typed = ctx.secret(&format!("Value for {name}:"))?;
            (Zeroizing::new(typed.as_bytes().to_vec()), ItemKind::Text)
        }
        None => {
            let mut value = read_secret(ctx.host.console().stdin(), MAX_VALUE_LEN + 2)
                .map_err(|e| CliError::usage(format!("can't read the value from stdin: {e}")))?;
            if !args.raw {
                strip_line_ending(&mut value);
            }
            (value, ItemKind::Text)
        }
    };
    if value.is_empty() {
        return Err(CliError::usage("the value is empty; nothing was stored"));
    }
    let outcome = {
        let _items = ctx.state.lock_items(ctx.store.namespace())?;
        ctx.store.set(name.as_str(), &value, kind, Origin::Local)?
    };
    match outcome.change {
        Change::Created => say!(ctx, "Stored {name} ({}).", plural(value.len(), "byte")),
        Change::Updated => say!(
            ctx,
            "Updated {name}. The previous value is kept: `kc restore {name}` brings it back."
        ),
        Change::Unchanged => say!(ctx, "{name} already has this value."),
    }
    Ok(exit::OK)
}

pub(super) fn get<H: Host>(ctx: &mut Ctx<'_, H>, args: GetArgs) -> Result<i32> {
    let name = item_name(&args.name)?;
    if args.check {
        return Ok(if ctx.store.exists(name.as_str())? {
            exit::OK
        } else {
            exit::NOT_FOUND
        });
    }
    let terminal = ctx.host.stdout_is_terminal();
    let printing = args.to_file.is_none() && !args.fingerprint;
    if printing && terminal && !args.reveal {
        return Err(CliError::interaction(
            "stdout is a terminal; kc get prints values there only with --reveal",
        )
        .with_hint(
            "pass it on without printing: kc exec --env VAR=NAME -- cmd, or VAR=\"$(kc get NAME)\" cmd",
        ));
    }
    let Some(value) = ctx.store.get(name.as_str())? else {
        return Err(not_found(&name));
    };
    if args.fingerprint {
        let line = format!("{}\n", value_fingerprint(value.as_bytes()));
        ctx.emit(line.as_bytes())?;
        return Ok(exit::OK);
    }
    if let Some(path) = &args.to_file {
        write_secret_file(path, value.as_bytes())
            .map_err(|e| CliError::failure(format!("can't write {}: {e}", path.display())))?;
        say!(
            ctx,
            "Wrote {name} to {} (readable only by you).",
            path.display()
        );
        return Ok(exit::OK);
    }
    if args.base64 {
        // The newline goes out separately: appending it could move (and so leave behind,
        // unwiped) the encoded secret.
        let encoded = Zeroizing::new(STANDARD.encode(value.as_bytes()));
        ctx.emit(encoded.as_bytes())?;
        ctx.emit(b"\n")?;
    } else {
        ctx.emit(value.as_bytes())?;
        if terminal && !value.as_bytes().ends_with(b"\n") {
            ctx.emit(b"\n")?;
        }
    }
    Ok(exit::OK)
}

pub(super) fn exec<H: Host>(ctx: &mut Ctx<'_, H>, args: ExecArgs) -> Result<i32> {
    let mut wanted: Vec<(String, ItemName)> = Vec::with_capacity(args.env.len());
    let mut vars = HashSet::new();
    for spec in &args.env {
        let (var, name) = spec.split_once('=').ok_or_else(|| {
            CliError::usage("--env takes VAR=NAME, the variable and the item name (not shown)")
        })?;
        if !is_env_var_name(var) {
            return Err(CliError::usage(
                "invalid variable name in --env VAR=NAME (not shown): use letters, digits and \
                 _, not starting with a digit",
            ));
        }
        let name = item_name(name).map_err(|e| e.context("--env VAR=NAME"))?;
        // Windows variable names ignore case: TOKEN and token are one variable there.
        let key = if cfg!(windows) {
            var.to_ascii_uppercase()
        } else {
            var.to_owned()
        };
        if !vars.insert(key) {
            return Err(CliError::usage(format!("--env sets {var} twice")));
        }
        wanted.push((var.to_owned(), name));
    }
    let (program, rest) = args
        .command
        .split_first()
        .ok_or_else(|| CliError::usage("missing the command to run after --"))?;
    let mut command = Process::new(program);
    command.args(rest);
    for (var, name) in &wanted {
        let Some(value) = ctx.store.get(name.as_str())? else {
            return Err(not_found(name));
        };
        if value.as_bytes().contains(&0) {
            return Err(CliError::usage(format!(
                "{name} contains a NUL byte, which an environment variable can't hold"
            )));
        }
        command.env(var, env_value(name, value.into_zeroizing())?);
    }
    ctx.host.run_command(command)
}

/// The value as an environment string. The copy inside `Command` can't be wiped; on Unix
/// the process image is replaced by the command right after.
#[cfg(unix)]
fn env_value(_name: &ItemName, value: Zeroizing<Vec<u8>>) -> Result<OsString> {
    use std::os::unix::ffi::OsStringExt as _;
    Ok(OsString::from_vec(value.to_vec()))
}

#[cfg(not(unix))]
fn env_value(name: &ItemName, value: Zeroizing<Vec<u8>>) -> Result<OsString> {
    match std::str::from_utf8(&value) {
        Ok(text) => Ok(OsString::from(text)),
        Err(_) => Err(CliError::usage(format!(
            "{name} isn't UTF-8 text, which Windows environment variables need"
        ))),
    }
}

pub(super) fn list<H: Host>(ctx: &mut Ctx<'_, H>, args: ListArgs) -> Result<i32> {
    let items = ctx.store.list()?;
    if args.json {
        let mut json = serde_json::to_vec_pretty(&items)
            .map_err(|e| CliError::failure(format!("can't encode the list: {e}")))?;
        json.push(b'\n');
        ctx.emit(&json)?;
    } else if items.is_empty() {
        say!(ctx, "No items. Add one with `kc set NAME`.");
    } else {
        let table = format_table(&items);
        ctx.emit(table.as_bytes())?;
    }
    if args.verify {
        let drift = ctx.store.verify()?;
        if drift.is_clean() {
            say!(ctx, "The metadata index matches the keychain.");
        } else {
            for info in &drift.stale {
                say!(ctx, "index entry without a keychain item: {}", info.name);
            }
            for name in &drift.unindexed {
                say!(ctx, "keychain item without index metadata: {name}");
            }
            say!(
                ctx,
                "`kc doctor --reindex` rebuilds the index from the keychain."
            );
        }
    }
    Ok(exit::OK)
}

fn origin_text(origin: &Origin) -> String {
    match origin {
        Origin::Local => "set here".into(),
        Origin::Adopted { service, account } => match account {
            Some(account) => format!(
                "adopted from {} / {}",
                printable(service),
                printable(account)
            ),
            None => format!("adopted from {}", printable(service)),
        },
        Origin::Received { from_device } => format!("from {}", printable(from_device)),
        Origin::Unknown => "-".into(),
    }
}

fn format_table(items: &[ItemInfo]) -> String {
    let rows: Vec<[String; 4]> = items
        .iter()
        .map(|info| {
            [
                info.name.clone(),
                match info.kind {
                    ItemKind::Text => "text".into(),
                    ItemKind::File => "file".into(),
                },
                origin_text(&info.origin),
                info.updated_at
                    .map(|t| humantime::format_rfc3339_seconds(t).to_string())
                    .unwrap_or_else(|| "-".into()),
            ]
        })
        .collect();
    let header = ["NAME", "KIND", "ORIGIN", "UPDATED"];
    let mut widths = header.map(str::len);
    for row in &rows {
        for (w, cell) in widths.iter_mut().zip(row) {
            *w = (*w).max(cell.chars().count());
        }
    }
    let mut out = String::new();
    for row in std::iter::once(header.map(String::from)).chain(rows) {
        let line = row
            .iter()
            .zip(widths)
            .map(|(cell, w)| format!("{cell:<w$}"))
            .collect::<Vec<_>>()
            .join("  ");
        out.push_str(line.trim_end());
        out.push('\n');
    }
    out
}

pub(super) fn rm<H: Host>(ctx: &mut Ctx<'_, H>, args: RmArgs) -> Result<i32> {
    let name = item_name(&args.name)?;
    if ctx.interactive() && !args.yes {
        if !ctx.store.exists(name.as_str())? {
            return Err(not_found(&name));
        }
        if !ctx.confirm(&format!("Delete {name} and its previous value?"), false)? {
            say!(ctx, "Nothing deleted.");
            return Ok(exit::PARTIAL);
        }
    }
    let deleted = {
        let _items = ctx.state.lock_items(ctx.store.namespace())?;
        ctx.store.delete(name.as_str())?
    };
    if deleted {
        say!(ctx, "Deleted {name}.");
        Ok(exit::OK)
    } else {
        Err(not_found(&name))
    }
}

pub(super) fn restore<H: Host>(ctx: &mut Ctx<'_, H>, args: NameArgs) -> Result<i32> {
    let name = item_name(&args.name)?;
    {
        let _items = ctx.state.lock_items(ctx.store.namespace())?;
        ctx.store.restore(name.as_str())?;
    }
    say!(
        ctx,
        "Restored the previous value of {name}. Run `kc restore {name}` again to undo."
    );
    Ok(exit::OK)
}

pub(super) fn adopt<H: Host>(ctx: &mut Ctx<'_, H>, args: AdoptArgs) -> Result<i32> {
    let name = match &args.as_name {
        Some(name) => item_name(name)?,
        None => ItemName::new(&args.service).map_err(|_| {
            CliError::usage("the service isn't a valid item name; choose one with --as NAME")
        })?,
    };
    let outcome = {
        let _items = ctx.state.lock_items(ctx.store.namespace())?;
        ctx.store
            .adopt(&args.service, args.account.as_deref(), name.as_str())?
    };
    match outcome.change {
        Change::Created => say!(
            ctx,
            "Adopted it as {name}. The original entry is unchanged."
        ),
        Change::Updated => say!(
            ctx,
            "Adopted it as {name}, replacing its value (`kc restore {name}` brings that back)."
        ),
        Change::Unchanged => say!(ctx, "{name} already has this value."),
    }
    Ok(exit::OK)
}

pub(super) fn not_found(name: &ItemName) -> CliError {
    CliError::not_found(format!("no item named {name}")).with_hint("`kc list` shows the items")
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, UNIX_EPOCH};

    use super::*;

    #[test]
    fn table_aligns_columns() {
        let items = vec![
            ItemInfo {
                name: "GITHUB_TOKEN".into(),
                kind: ItemKind::Text,
                origin: Origin::Local,
                created_at: None,
                updated_at: Some(UNIX_EPOCH + Duration::from_secs(1_760_000_000)),
            },
            ItemInfo {
                name: "app.env".into(),
                kind: ItemKind::File,
                origin: Origin::Received {
                    from_device: "mac\u{1b}".into(),
                },
                created_at: None,
                updated_at: None,
            },
        ];
        let table = format_table(&items);
        let lines: Vec<&str> = table.lines().collect();
        assert_eq!(lines.len(), 3);
        assert!(lines[0].starts_with("NAME          KIND  ORIGIN"));
        assert!(lines[1].contains("2025-10-09T08:53:20Z"));
        assert!(lines[2].contains("from mac?"));
    }
}

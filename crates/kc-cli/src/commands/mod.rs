//! The commands. [`run`] parses the arguments, applies the agent policy (see
//! [`crate::policy`]) before anything touches the keychain or the network, and dispatches.

mod apply;
mod device;
mod doctor;
mod inbox;
mod items;
pub(crate) mod pairing;
mod peers;
mod sync;
mod transfer;

use std::ffi::OsString;
use std::fmt;

use clap::error::{ContextKind, ErrorKind};
use clap::{CommandFactory as _, FromArgMatches as _};
use kc_proto::Label;
use kc_wire::exit;
use zeroize::Zeroizing;

use crate::cli::{Cli, Command};
use crate::console::{Console as _, PromptError};
use crate::error::{CliError, Result};
use crate::host::Host;
use crate::i18n::tr;
use crate::keychain::Keychain;
use crate::policy::{self, Interactivity, Policy};
use crate::settings::{self, ENV_RELAY, RelayUrl, Settings};
use crate::state::StateDir;

/// Prints a line to stderr (messages for people; stdout is for data).
macro_rules! say {
    ($ctx:expr, $($arg:tt)*) => {
        $ctx.say(format_args!($($arg)*))
    };
}
pub(crate) use say;

pub(crate) async fn run<H: Host>(host: &mut H, args: impl IntoIterator<Item = OsString>) -> i32 {
    let lang = crate::i18n::choose(host);
    crate::i18n::scope(lang, run_in_language(host, args)).await
}

async fn run_in_language<H: Host>(host: &mut H, args: impl IntoIterator<Item = OsString>) -> i32 {
    let parsed = crate::i18n::localize(Cli::command())
        .try_get_matches_from(args)
        .and_then(|m| Cli::from_arg_matches(&m));
    let cli = match parsed {
        Ok(cli) => cli,
        Err(e) => return report_parse_error(host, &e),
    };
    match execute(host, cli).await {
        Ok(code) => code,
        Err(e) => {
            let _ = writeln!(host.console().stderr(), "{e}");
            e.code
        }
    }
}

async fn execute<H: Host>(host: &mut H, cli: Cli) -> Result<i32> {
    let state = StateDir::new(host.config_dir()?);
    let interactivity = Interactivity {
        stdin_terminal: host.stdin_is_terminal(),
        stderr_terminal: host.stderr_is_terminal(),
        ci: host.env_var("CI").is_some(),
        claudecode: host.env_var("CLAUDECODE").is_some(),
        no_input: cli.no_input,
    };
    if let Command::Doctor(args) = &cli.command {
        let settings = Settings::load(state.root());
        return doctor::doctor(host, &state, settings, interactivity, &cli, args).await;
    }
    let settings = Settings::load(state.root())?;
    let policy = Policy::new(interactivity, settings.agent_code_send);
    let mut gates = policy::gates(&cli.command, interactivity.stdin_terminal);
    if !crate::sync::State::load(&state)?.items.is_empty() {
        gates.retain(|gate| *gate != policy::Gate::Overwrite);
    }
    policy.check(&gates)?;
    let store = Keychain::new(host.open_store(policy.interactive())?);
    let mut ctx = Ctx {
        host,
        store,
        state,
        settings,
        policy,
        relay_flag: cli.relay,
        allow_http_flag: cli.allow_http,
    };
    dispatch(&mut ctx, cli.command).await
}

async fn dispatch<H: Host>(ctx: &mut Ctx<'_, H>, command: Command) -> Result<i32> {
    pairing::expire_prev_key(ctx);
    match command {
        Command::Set(args) => {
            let code = items::set(ctx, args)?;
            crate::sync::send_after_write(ctx).await;
            Ok(code)
        }
        Command::Get(args) => items::get(ctx, args),
        Command::Exec(args) => items::exec(ctx, args),
        Command::List(args) => items::list(ctx, args),
        Command::Rm(args) => items::rm(ctx, args),
        Command::Restore(args) => {
            let code = items::restore(ctx, args)?;
            crate::sync::send_after_write(ctx).await;
            Ok(code)
        }
        Command::Adopt(args) => {
            let code = items::adopt(ctx, args)?;
            crate::sync::send_after_write(ctx).await;
            Ok(code)
        }
        Command::Send(args) => transfer::send(ctx, args).await,
        Command::Receive(args) => transfer::receive(ctx, args).await,
        Command::Pair(args) => transfer::pair(ctx, args).await,
        Command::Peers(args) => peers::peers(ctx, args).await,
        Command::Inbox(args) => {
            let code = inbox::inbox(ctx, args).await?;
            crate::sync::flush(ctx, false).await?;
            Ok(code.max(crate::sync::pending_code(ctx)?))
        }
        Command::Sync(args) => sync::run(ctx, args).await,
        Command::Device(args) => device::device(ctx, args).await,
        Command::Doctor(_) => unreachable!("handled before the store is opened"),
    }
}

/// Everything a command works with.
pub(crate) struct Ctx<'h, H: Host> {
    pub host: &'h mut H,
    pub store: Keychain,
    pub state: StateDir,
    pub settings: Settings,
    pub policy: Policy,
    pub relay_flag: Option<String>,
    pub allow_http_flag: bool,
}

impl<H: Host> Ctx<'_, H> {
    pub fn interactive(&self) -> bool {
        self.policy.interactive()
    }

    /// One line on stderr. Failing to write a message isn't worth failing the command for.
    pub fn say(&mut self, line: fmt::Arguments<'_>) {
        let err = self.host.console().stderr();
        let _ = err.write_fmt(line);
        let _ = err.write_all(b"\n");
        let _ = err.flush();
    }

    /// Writes data to stdout. A closed pipe (`kc list | head -1`) isn't an error.
    pub fn emit(&mut self, data: &[u8]) -> Result<()> {
        let out = self.host.console().stdout();
        match out.write_all(data).and_then(|()| out.flush()) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::BrokenPipe => Ok(()),
            Err(e) => Err(CliError::failure(tr!(
                "can't write to stdout: {error}",
                error = e
            ))),
        }
    }

    pub fn relay_url(&self) -> Result<RelayUrl> {
        settings::resolve_relay(
            self.relay_flag.as_deref(),
            self.host.env_var(ENV_RELAY).as_deref(),
            &self.settings,
            self.allow_http_flag,
        )
    }

    pub fn connect(&self) -> Result<H::Relay> {
        let url = self.relay_url()?;
        self.host.connect(&url)
    }

    /// The label this device suggests when pairing: `label` from config.toml, else the
    /// host name, made valid.
    pub fn label(&self) -> Label {
        match &self.settings.label {
            Some(label) => Label::new(label).unwrap_or_else(|_| Label::sanitize(label)),
            None => Label::sanitize(&self.host.hostname()),
        }
    }

    /// The last line of defence for PROTOCOL §6: no prompt ever opens in a non-interactive
    /// run, whatever path led to it. [`crate::policy`] normally refuses such runs earlier,
    /// naming the missing flags.
    fn may_prompt(&self) -> Result<()> {
        if self.interactive() {
            return Ok(());
        }
        let reasons = self.policy.interactivity.reasons().join(", ");
        Err(CliError::interaction(tr!(
            "this needs a person at a terminal, and kc never prompts without one"
        ))
        .with_hint(tr!(
            "kc runs non-interactively here ({reasons})",
            reasons = reasons
        )))
    }

    /// Asks yes/no. Esc counts as no; Ctrl-C cancels the command.
    pub fn confirm(&mut self, message: &str, default: bool) -> Result<bool> {
        self.may_prompt()?;
        match self.host.console().confirm(message, default) {
            Ok(answer) => Ok(answer),
            Err(PromptError::Cancelled) => Ok(false),
            Err(e) => Err(prompt_failed(e)),
        }
    }

    pub fn select(&mut self, message: &str, options: &[String], default: usize) -> Result<usize> {
        self.may_prompt()?;
        self.host
            .console()
            .select(message, options, default)
            .map_err(prompt_failed)
    }

    pub fn multi_select(&mut self, message: &str, options: &[String]) -> Result<Vec<usize>> {
        self.may_prompt()?;
        self.host
            .console()
            .multi_select(message, options)
            .map_err(prompt_failed)
    }

    /// Hidden input.
    pub fn secret(&mut self, message: &str) -> Result<Zeroizing<String>> {
        self.may_prompt()?;
        self.host.console().secret(message).map_err(prompt_failed)
    }

    /// Visible input (codes).
    pub fn text(&mut self, message: &str) -> Result<Zeroizing<String>> {
        self.may_prompt()?;
        self.host.console().text(message).map_err(prompt_failed)
    }
}

pub(crate) fn prompt_failed(e: PromptError) -> CliError {
    match e {
        PromptError::Cancelled | PromptError::Interrupted => CliError::cancelled(),
        PromptError::Failed(why) => CliError::interaction(tr!("can't prompt: {why}", why = why))
            .with_hint(tr!("pass --no-input")),
    }
}

/// One of two whole messages by count, each already translated:
/// `plural_tr(n, tr!("Sent {n} item.", n = n), tr!("Sent {n} items.", n = n))`.
/// Languages without plural forms translate both the same.
pub(crate) fn plural_tr(n: usize, one: String, other: String) -> String {
    if n == 1 { one } else { other }
}

/// Columns `s` takes in a terminal: 2 for wide (CJK, Hangul, full-width) characters, 0
/// for combining marks and zero-width characters, 1 for the rest.
pub(crate) fn display_width(s: &str) -> usize {
    s.chars()
        .map(|c| match u32::from(c) {
            0x0300..=0x036F | 0x200B..=0x200F | 0xFE00..=0xFE0F => 0,
            0x1100..=0x115F
            | 0x2E80..=0x303E
            | 0x3041..=0x33FF
            | 0x3400..=0x4DBF
            | 0x4E00..=0x9FFF
            | 0xA000..=0xA4CF
            | 0xAC00..=0xD7A3
            | 0xF900..=0xFAFF
            | 0xFE30..=0xFE4F
            | 0xFF00..=0xFF60
            | 0xFFE0..=0xFFE6
            | 0x20000..=0x3FFFD => 2,
            _ => 1,
        })
        .sum()
}

/// `s` padded with spaces to `width` columns (see [`display_width`]).
pub(crate) fn pad_to(s: &str, width: usize) -> String {
    format!("{s}{}", " ".repeat(width.saturating_sub(display_width(s))))
}

/// clap's own messages repeat what was typed, which could be a value pasted in the wrong
/// place. This rebuilds them from the parts that come from kc's own definitions and shows
/// typed text only when it looks like an option or command name.
fn report_parse_error<H: Host>(host: &mut H, err: &clap::Error) -> i32 {
    match err.kind() {
        ErrorKind::DisplayHelp | ErrorKind::DisplayVersion => {
            let _ = write!(host.console().stdout(), "{}", err.render());
            return exit::OK;
        }
        ErrorKind::DisplayHelpOnMissingArgumentOrSubcommand => {
            let _ = write!(host.console().stderr(), "{}", err.render());
            return exit::USAGE;
        }
        _ => {}
    }
    let mut text = format!("kc: {}", parse_error_message(err));
    if let Some(usage) = err.get(ContextKind::Usage) {
        // clap writes its own "Usage:" heading here; the help pages get theirs from i18n.
        let usage = usage
            .to_string()
            .replacen("Usage:", crate::i18n::lookup("Usage:"), 1);
        text.push_str(&format!("\n\n{usage}"));
    }
    text.push_str("\n\n");
    text.push_str(&tr!("For more information, try 'kc --help'."));
    let _ = writeln!(host.console().stderr(), "{text}");
    exit::USAGE
}

fn parse_error_message(err: &clap::Error) -> String {
    let ctx = |kind| err.get(kind).map(ToString::to_string);
    let ours = |kind| ctx(kind).unwrap_or_else(|| tr!("an argument"));
    let suggestion = ctx(ContextKind::SuggestedArg)
        .or_else(|| ctx(ContextKind::SuggestedSubcommand))
        .map(|s| tr!(" (did you mean '{suggested}'?)", suggested = s))
        .unwrap_or_default();
    match err.kind() {
        ErrorKind::UnknownArgument => match ctx(ContextKind::InvalidArg) {
            Some(arg) if looks_like_option(&arg) => tr!(
                "unknown option '{arg}'{suggestion}",
                arg = arg,
                suggestion = suggestion
            ),
            _ => tr!(
                "unexpected argument (not shown, in case it is a secret){suggestion}. Values \
                 are never taken from arguments",
                suggestion = suggestion
            ),
        },
        ErrorKind::InvalidSubcommand => match ctx(ContextKind::InvalidSubcommand) {
            Some(cmd) if looks_like_word(&cmd) => tr!(
                "unknown command '{command}'{suggestion}",
                command = cmd,
                suggestion = suggestion
            ),
            _ => tr!(
                "unknown command (not shown){suggestion}",
                suggestion = suggestion
            ),
        },
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let arg = ours(ContextKind::InvalidArg);
            match ctx(ContextKind::ValidValue) {
                Some(valid) => tr!(
                    "invalid value (not shown) for {arg}; possible values: {valid}",
                    arg = arg,
                    valid = valid
                ),
                None => tr!("invalid value (not shown) for {arg}", arg = arg),
            }
        }
        ErrorKind::MissingRequiredArgument => {
            tr!("missing {arg}", arg = ours(ContextKind::InvalidArg))
        }
        ErrorKind::ArgumentConflict => tr!(
            "{arg} can't be used with {other}",
            arg = ours(ContextKind::InvalidArg),
            other = ours(ContextKind::PriorArg)
        ),
        ErrorKind::MissingSubcommand => tr!("missing command"),
        ErrorKind::InvalidUtf8 => tr!("arguments must be valid UTF-8"),
        ErrorKind::NoEquals
        | ErrorKind::TooManyValues
        | ErrorKind::TooFewValues
        | ErrorKind::WrongNumberOfValues => tr!(
            "wrong number of values for {arg}",
            arg = ours(ContextKind::InvalidArg)
        ),
        _ => tr!("invalid arguments"),
    }
}

/// `-x` or `--word-word`, short: what a mistyped option looks like, not a secret.
fn looks_like_option(s: &str) -> bool {
    let body = s.strip_prefix("--").or_else(|| s.strip_prefix('-'));
    body.is_some_and(|b| {
        !b.is_empty()
            && b.len() <= 24
            && b.as_bytes()[0].is_ascii_alphabetic()
            && b.bytes().all(|c| c.is_ascii_alphanumeric() || c == b'-')
    })
}

fn looks_like_word(s: &str) -> bool {
    !s.is_empty() && s.len() <= 20 && s.bytes().all(|c| c.is_ascii_lowercase() || c == b'-')
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;

    fn message(args: &[&str]) -> String {
        let err = Cli::try_parse_from(std::iter::once("kc").chain(args.iter().copied()))
            .expect_err("should not parse");
        parse_error_message(&err)
    }

    #[test]
    fn parse_errors_never_repeat_typed_values() {
        // Long like a real credential. (Unknown options of up to 24 letters, digits and
        // dashes are shown, to help with typos.)
        let pasted = "not-a-real-value-0123456789abcdefghij";
        for args in [
            vec!["get", "NAME", pasted],
            vec!["get", "NAME", &format!("--{pasted}")],
            vec!["get", "NAME", "--colour=not-a-real-value"],
            vec!["inbox", "--on-conflict", pasted],
            vec![pasted],
            vec!["rm", "a", "b", pasted],
        ] {
            let msg = message(&args);
            assert!(!msg.contains("not-a-real"), "{args:?}: {msg}");
        }
    }

    #[test]
    fn parse_errors_still_help_with_typos() {
        let msg = message(&["get", "NAME", "--revael"]);
        assert!(msg.contains("--revael"), "{msg}");
        assert!(msg.contains("--reveal"), "{msg}");
        assert!(message(&["lsit"]).contains("'lsit'"));
        let msg = message(&["inbox", "--on-conflict", "clobber"]);
        assert!(msg.contains("skip"), "{msg}");
        assert!(message(&["get", "A", "--check", "--reveal"]).contains("can't be used with"));
    }
}

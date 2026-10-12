//! The commands. [`run`] parses the arguments, applies the agent policy (see
//! [`crate::policy`]) before anything touches the keychain or the network, and dispatches.

mod apply;
mod device;
mod doctor;
mod inbox;
mod items;
mod pairing;
mod peers;
mod transfer;

use std::ffi::OsString;
use std::fmt;

use clap::Parser as _;
use clap::error::{ContextKind, ErrorKind};
use kc_proto::Label;
use kc_wire::exit;
use zeroize::Zeroizing;

use crate::cli::{Cli, Command};
use crate::console::{Console as _, PromptError};
use crate::error::{CliError, Result};
use crate::host::Host;
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
    let cli = match Cli::try_parse_from(args) {
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
    policy.check(&policy::gates(&cli.command, interactivity.stdin_terminal))?;
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
        Command::Set(args) => items::set(ctx, args),
        Command::Get(args) => items::get(ctx, args),
        Command::Exec(args) => items::exec(ctx, args),
        Command::List(args) => items::list(ctx, args),
        Command::Rm(args) => items::rm(ctx, args),
        Command::Restore(args) => items::restore(ctx, args),
        Command::Adopt(args) => items::adopt(ctx, args),
        Command::Send(args) => transfer::send(ctx, args).await,
        Command::Receive(args) => transfer::receive(ctx, args).await,
        Command::Pair(args) => transfer::pair(ctx, args).await,
        Command::Peers(args) => peers::peers(ctx, args).await,
        Command::Inbox(args) => inbox::inbox(ctx, args).await,
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
            Err(e) => Err(CliError::failure(format!("can't write to stdout: {e}"))),
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
        Err(CliError::interaction(
            "this needs a person at a terminal, and kc never prompts without one",
        )
        .with_hint(format!("kc runs non-interactively here ({reasons})")))
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
        PromptError::Failed(why) => {
            CliError::interaction(format!("can't prompt: {why}")).with_hint("pass --no-input")
        }
    }
}

/// `"1 item"`, `"2 items"`.
pub(crate) fn plural(n: usize, one: &str) -> String {
    if n == 1 {
        format!("{n} {one}")
    } else {
        format!("{n} {one}s")
    }
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
        text.push_str(&format!("\n\n{usage}"));
    }
    text.push_str("\n\nFor more information, try 'kc --help'.");
    let _ = writeln!(host.console().stderr(), "{text}");
    exit::USAGE
}

fn parse_error_message(err: &clap::Error) -> String {
    let ctx = |kind| err.get(kind).map(ToString::to_string);
    let ours = |kind| ctx(kind).unwrap_or_else(|| "an argument".into());
    let suggestion = ctx(ContextKind::SuggestedArg)
        .or_else(|| ctx(ContextKind::SuggestedSubcommand))
        .map(|s| format!(" (did you mean '{s}'?)"))
        .unwrap_or_default();
    match err.kind() {
        ErrorKind::UnknownArgument => match ctx(ContextKind::InvalidArg) {
            Some(arg) if looks_like_option(&arg) => format!("unknown option '{arg}'{suggestion}"),
            _ => format!(
                "unexpected argument (not shown, in case it is a secret){suggestion}. Values \
                 are never taken from arguments"
            ),
        },
        ErrorKind::InvalidSubcommand => match ctx(ContextKind::InvalidSubcommand) {
            Some(cmd) if looks_like_word(&cmd) => format!("unknown command '{cmd}'{suggestion}"),
            _ => format!("unknown command (not shown){suggestion}"),
        },
        ErrorKind::InvalidValue | ErrorKind::ValueValidation => {
            let valid = ctx(ContextKind::ValidValue)
                .map(|v| format!("; possible values: {v}"))
                .unwrap_or_default();
            format!(
                "invalid value (not shown) for {}{valid}",
                ours(ContextKind::InvalidArg)
            )
        }
        ErrorKind::MissingRequiredArgument => {
            format!("missing {}", ours(ContextKind::InvalidArg))
        }
        ErrorKind::ArgumentConflict => format!(
            "{} can't be used with {}",
            ours(ContextKind::InvalidArg),
            ours(ContextKind::PriorArg)
        ),
        ErrorKind::MissingSubcommand => "missing command".into(),
        ErrorKind::InvalidUtf8 => "arguments must be valid UTF-8".into(),
        ErrorKind::NoEquals
        | ErrorKind::TooManyValues
        | ErrorKind::TooFewValues
        | ErrorKind::WrongNumberOfValues => {
            format!(
                "wrong number of values for {}",
                ours(ContextKind::InvalidArg)
            )
        }
        _ => "invalid arguments".into(),
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

//! [`Host`]: everything a command needs from the outside world, so the same code runs in
//! the `kc` binary ([`RealHost`]) and in-process in tests (a fake keychain, an in-memory
//! relay, a scripted terminal).

use std::ffi::OsString;
use std::future::Future;
use std::io::IsTerminal as _;
use std::path::PathBuf;
use std::process::Command;

use kc_proto::relay::{RelayApi, RelayError};
use kc_proto::session::SessionOptions;
use kc_store::{Store, StoreConfig};
use kc_wire::Limits;

use crate::console::{Console, TermConsole};
use crate::error::{CliError, Result};
use crate::http::HttpRelay;
use crate::i18n::tr;
use crate::settings::RelayUrl;

pub trait Host {
    type Relay: RelayApi;
    type Console: Console;

    fn console(&mut self) -> &mut Self::Console;
    /// A process environment variable (`CI`, `CLAUDECODE`, `KC_RELAY`).
    fn env_var(&self, key: &str) -> Option<OsString>;
    fn stdin_is_terminal(&self) -> bool;
    fn stdout_is_terminal(&self) -> bool;
    fn stderr_is_terminal(&self) -> bool;
    /// Where `config.toml`, `peers.json`, `seen.json` and kc-store's index live.
    fn config_dir(&self) -> Result<PathBuf>;
    /// The keychain store; `interactive` picks kc-store's timeouts and prompt behaviour.
    fn open_store(&self, interactive: bool) -> Result<Store>;
    fn connect(&self, relay: &RelayUrl) -> Result<Self::Relay>;
    /// `GET /v1/limits`, for `kc doctor`.
    fn relay_limits(&self, relay: &RelayUrl) -> impl Future<Output = Result<Limits, RelayError>>;
    /// The default device label.
    fn hostname(&self) -> String;
    /// The OS's preferred language (`ko-KR`), for messages when no locale variable is set.
    fn system_locale(&self) -> Option<String> {
        None
    }
    /// Runs `kc exec`'s command and returns its exit code. The real host replaces the kc
    /// process with it on Unix (so this only returns on failure).
    fn run_command(&mut self, command: Command) -> Result<i32>;

    /// Unix seconds.
    fn now(&self) -> i64 {
        kc_proto::inbox::unix_now()
    }

    fn session_options(&self) -> SessionOptions {
        SessionOptions::default()
    }
}

/// The real terminal, OS keychain and HTTPS relay.
pub struct RealHost {
    console: TermConsole,
}

impl RealHost {
    pub fn new() -> RealHost {
        RealHost {
            console: TermConsole::new(),
        }
    }
}

impl Default for RealHost {
    fn default() -> RealHost {
        RealHost::new()
    }
}

impl Host for RealHost {
    type Relay = HttpRelay;
    type Console = TermConsole;

    fn console(&mut self) -> &mut TermConsole {
        &mut self.console
    }

    fn env_var(&self, key: &str) -> Option<OsString> {
        std::env::var_os(key)
    }

    fn stdin_is_terminal(&self) -> bool {
        std::io::stdin().is_terminal()
    }

    fn stdout_is_terminal(&self) -> bool {
        std::io::stdout().is_terminal()
    }

    fn stderr_is_terminal(&self) -> bool {
        std::io::stderr().is_terminal()
    }

    fn config_dir(&self) -> Result<PathBuf> {
        Ok(kc_store::default_config_dir()?)
    }

    fn open_store(&self, interactive: bool) -> Result<Store> {
        let cfg = StoreConfig::from_env()?.with_interactive(interactive);
        Ok(Store::open(cfg)?)
    }

    fn connect(&self, relay: &RelayUrl) -> Result<HttpRelay> {
        HttpRelay::new(relay)
    }

    async fn relay_limits(&self, relay: &RelayUrl) -> Result<Limits, RelayError> {
        let client = HttpRelay::new(relay).map_err(|e| RelayError::Transport(e.message))?;
        client.limits().await
    }

    fn system_locale(&self) -> Option<String> {
        sys_locale::get_locale()
    }

    fn hostname(&self) -> String {
        gethostname::gethostname().to_string_lossy().into_owned()
    }

    fn run_command(&mut self, command: Command) -> Result<i32> {
        replace_process(command)
    }
}

/// Unix: becomes `command` (execvp), so signals and the exit code are the command's own and
/// kc's memory is gone. Returns only if the command can't be started.
#[cfg(unix)]
fn replace_process(mut command: Command) -> Result<i32> {
    use std::os::unix::process::CommandExt as _;
    crate::harden::restore_core_limit();
    let program = command.get_program().to_string_lossy().into_owned();
    let error = command.exec();
    Err(start_error(&program, &error))
}

#[cfg(not(unix))]
fn replace_process(command: Command) -> Result<i32> {
    spawn_and_wait(command)
}

/// Starts `command`, waits for it and returns its exit code (128 + signal number if a
/// signal ended it, like a shell).
pub fn spawn_and_wait(mut command: Command) -> Result<i32> {
    let program = command.get_program().to_string_lossy().into_owned();
    let status = command.status().map_err(|e| start_error(&program, &e))?;
    if let Some(code) = status.code() {
        return Ok(code);
    }
    #[cfg(unix)]
    {
        use std::os::unix::process::ExitStatusExt as _;
        if let Some(signal) = status.signal() {
            return Ok(128 + signal);
        }
    }
    Ok(crate::error::EXIT_FAILURE)
}

/// 127 (not found) or 126 (can't run), as shells report it.
fn start_error(program: &str, error: &std::io::Error) -> CliError {
    let code = if error.kind() == std::io::ErrorKind::NotFound {
        127
    } else {
        126
    };
    CliError::new(
        code,
        tr!(
            "can't run {program}: {e}",
            program = format!("{program:?}"),
            e = error
        ),
    )
}

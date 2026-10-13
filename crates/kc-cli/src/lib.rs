//! `kc` (1pass keychain) moves secrets between one person's devices' OS keychains through
//! a relay that never sees plaintext. See `docs/PROTOCOL.md` and `docs/SECURITY.md`.
//!
//! This crate is the command-line program as a library, so every flow runs in-process in
//! tests: [`run`] parses the arguments and runs one command against a [`Host`], which
//! supplies the terminal, the keychain store and the relay. `main.rs` only hardens the
//! process ([`harden`]) and calls [`run`] with a [`RealHost`].
//!
//! Where things live:
//! - [`policy`]: who may do what without a human (PROTOCOL §6). Checked once, before a
//!   command touches the keychain or the network.
//! - [`http`]: [`HttpRelay`], the relay over HTTPS (reqwest + rustls).
//! - [`settings`] and [`state`]: `config.toml`, `peers.json`, `seen.json`.
//! - [`cli`]: the command line. Values and codes are never accepted as arguments.
//! - Exit codes: [`kc_wire::exit`], carried by [`CliError`].

#![deny(unsafe_code)]

pub mod cli;
mod commands;
pub mod console;
pub mod error;
pub mod harden;
pub mod host;
pub mod http;
pub mod i18n;
pub mod interrupt;
mod keychain;
pub mod policy;
pub mod settings;
pub mod state;
mod values;

pub use console::{Console, PromptError, TermConsole};
pub use error::CliError;
pub use host::{Host, RealHost, spawn_and_wait};
pub use http::HttpRelay;
pub use settings::{RelayUrl, Settings};

use std::ffi::OsString;

/// Runs `kc` with `args` (the first one is the program name) and returns the exit code.
pub async fn run<H: Host>(host: &mut H, args: impl IntoIterator<Item = OsString>) -> i32 {
    commands::run(host, args).await
}

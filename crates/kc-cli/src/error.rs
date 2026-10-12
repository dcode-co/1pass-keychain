//! [`CliError`]: what a failed command prints, and its exit code.
//!
//! Exit codes come from [`kc_wire::exit`] (PROTOCOL §8). Two codes outside that table:
//! [`EXIT_FAILURE`] (1) for anything else, the same as kc-store's `ErrorKind::Other`, and
//! [`EXIT_CANCELLED`] (130) when a person cancels a prompt with Esc or Ctrl-C.
//!
//! Messages never contain secret values: the conversions below use the `Display` text of
//! kc-store and kc-proto errors, which carry no values, and the commands never format
//! values or codes into errors.

use std::fmt;

use kc_proto::inbox::InboxError;
use kc_proto::relay::RelayError;
use kc_proto::session::SessionError;
use kc_store::StoreError;
use kc_wire::exit;

/// Anything that doesn't fit a `kc_wire::exit` code.
pub const EXIT_FAILURE: i32 = 1;
/// A person cancelled a prompt (Esc or Ctrl-C), like a shell's 128 + SIGINT.
pub const EXIT_CANCELLED: i32 = 130;

pub type Result<T, E = CliError> = std::result::Result<T, E>;

/// A command failed: `message` (and an optional `hint`) go to stderr, `code` is the exit code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CliError {
    pub code: i32,
    pub message: String,
    pub hint: Option<String>,
}

impl CliError {
    pub fn new(code: i32, message: impl Into<String>) -> CliError {
        CliError {
            code,
            message: message.into(),
            hint: None,
        }
    }

    /// Exit 2: bad arguments or input.
    pub fn usage(message: impl Into<String>) -> CliError {
        CliError::new(exit::USAGE, message)
    }

    /// Exit 3.
    pub fn not_found(message: impl Into<String>) -> CliError {
        CliError::new(exit::NOT_FOUND, message)
    }

    /// Exit 5: the command needs a person at a terminal, or a missing flag.
    pub fn interaction(message: impl Into<String>) -> CliError {
        CliError::new(exit::INTERACTION_REQUIRED, message)
    }

    /// Exit 1.
    pub fn failure(message: impl Into<String>) -> CliError {
        CliError::new(EXIT_FAILURE, message)
    }

    pub fn cancelled() -> CliError {
        CliError::new(EXIT_CANCELLED, "cancelled")
    }

    pub fn with_hint(mut self, hint: impl Into<String>) -> CliError {
        self.hint = Some(hint.into());
        self
    }

    /// Prefixes the message, e.g. `"sending to mac: <message>"`.
    pub fn context(mut self, prefix: impl fmt::Display) -> CliError {
        self.message = format!("{prefix}: {}", self.message);
        self
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "kc: {}", self.message)?;
        if let Some(hint) = &self.hint {
            write!(f, "\n  hint: {hint}")?;
        }
        Ok(())
    }
}

impl std::error::Error for CliError {}

impl From<StoreError> for CliError {
    fn from(e: StoreError) -> CliError {
        CliError::new(e.exit_code(), e.to_string())
    }
}

impl From<SessionError> for CliError {
    fn from(e: SessionError) -> CliError {
        let code = e.exit_code();
        let err = CliError::new(code, e.to_string());
        match e {
            SessionError::UnknownChannel | SessionError::ChannelClosed | SessionError::TimedOut => {
                err.with_hint("codes work once and expire after 10 minutes; ask for a new one")
            }
            SessionError::PossibleInterception | SessionError::WrongCodeOrInterception => err
                .with_hint("the code is used up; start again with a new code and check each word"),
            _ => err,
        }
    }
}

impl From<RelayError> for CliError {
    fn from(e: RelayError) -> CliError {
        CliError::new(e.exit_code(), e.to_string())
    }
}

impl From<InboxError> for CliError {
    fn from(e: InboxError) -> CliError {
        CliError::new(e.exit_code(), e.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exit_codes_follow_the_contract() {
        assert_eq!(CliError::usage("x").code, 2);
        assert_eq!(CliError::not_found("x").code, 3);
        assert_eq!(CliError::interaction("x").code, 5);
        assert_eq!(
            CliError::from(StoreError::NotFound("gone".into())).code,
            exit::NOT_FOUND
        );
        assert_eq!(
            CliError::from(SessionError::WrongCodeOrInterception).code,
            exit::AUTH_FAILED
        );
        assert_eq!(CliError::from(SessionError::TimedOut).code, exit::EXPIRED);
        assert_eq!(
            CliError::from(RelayError::Transport("down".into())).code,
            exit::RELAY_UNAVAILABLE
        );
        assert_eq!(CliError::from(InboxError::Replay).code, exit::AUTH_FAILED);
    }

    #[test]
    fn display_has_prefix_and_hint() {
        let e = CliError::usage("bad").with_hint("try this").context("set");
        assert_eq!(e.to_string(), "kc: set: bad\n  hint: try this");
    }
}

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

use crate::i18n::tr;

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
        CliError::new(EXIT_CANCELLED, tr!("cancelled"))
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
            write!(f, "\n  {}", tr!("hint: {hint}", hint = hint))?;
        }
        Ok(())
    }
}

impl std::error::Error for CliError {}

impl From<StoreError> for CliError {
    fn from(e: StoreError) -> CliError {
        CliError::new(e.exit_code(), store_message(&e))
    }
}

impl From<SessionError> for CliError {
    fn from(e: SessionError) -> CliError {
        let code = e.exit_code();
        let err = CliError::new(code, session_message(&e));
        match e {
            SessionError::UnknownChannel | SessionError::ChannelClosed | SessionError::TimedOut => {
                err.with_hint(tr!(
                    "codes work once and expire after 10 minutes; ask for a new one"
                ))
            }
            SessionError::PossibleInterception | SessionError::WrongCodeOrInterception => err
                .with_hint(tr!(
                    "the code is used up; start again with a new code and check each word"
                )),
            _ => err,
        }
    }
}

impl From<RelayError> for CliError {
    fn from(e: RelayError) -> CliError {
        CliError::new(e.exit_code(), relay_message(&e))
    }
}

impl From<InboxError> for CliError {
    fn from(e: InboxError) -> CliError {
        CliError::new(e.exit_code(), inbox_message(&e))
    }
}

// The texts below repeat the `#[error]` texts of kc-store and kc-proto so they can be
// translated; in English they are the same as `e.to_string()` (see the tests). Variants
// whose text is only a nested error or a string from below keep `e.to_string()`.

fn store_message(e: &StoreError) -> String {
    match e {
        StoreError::InvalidName { what, value, rule } => tr!(
            "invalid {what} {value}: {rule}",
            what = what,
            value = format!("{value:?}"),
            rule = rule
        ),
        StoreError::InvalidValue(why) => tr!("invalid value: {why}", why = why),
        StoreError::InvalidConfig(why) => {
            tr!("invalid kc-store configuration: {why}", why = why)
        }
        StoreError::Ambiguous {
            service,
            candidates,
        } => tr!(
            "{count} keychain items match service {service}; pass an account to pick one: \
             {candidates}",
            count = candidates.len(),
            service = format!("{service:?}"),
            candidates = candidates.join(", ")
        ),
        StoreError::Locked { what, hint } => tr!(
            "the OS keychain is locked ({what}). {hint}",
            what = what,
            hint = hint
        ),
        StoreError::Unavailable { reason, hint } => tr!(
            "the OS keychain is unavailable: {reason}. {hint}",
            reason = reason,
            hint = hint
        ),
        StoreError::Timeout { op, timeout, hint } => tr!(
            "the OS keychain did not answer within {seconds}s ({op}). {hint}",
            seconds = format!("{:.1}", timeout.as_secs_f64()),
            op = op,
            hint = hint
        ),
        StoreError::OutcomeUnknown { op, detail, hint } => tr!(
            "the OS keychain may or may not have carried out a change ({op}): {detail}. {hint}",
            op = op,
            detail = detail,
            hint = hint
        ),
        StoreError::InteractionRequired { op, hint } => tr!(
            "the OS keychain needs user interaction ({op}) but kc runs non-interactively. \
             {hint}",
            op = op,
            hint = hint
        ),
        StoreError::AccessDenied { op, detail, hint } => tr!(
            "the OS keychain refused access ({op}): {detail}. {hint}",
            op = op,
            detail = detail,
            hint = hint
        ),
        StoreError::Backend { op, detail } => tr!(
            "OS keychain error ({op}): {detail}",
            op = op,
            detail = detail
        ),
        StoreError::Corrupt { account, reason } => tr!(
            "stored value {account} is damaged: {reason}. Overwrite it with `kc set` or delete it",
            account = format!("{account:?}"),
            reason = reason
        ),
        StoreError::IndexCorrupt { path, detail } => tr!(
            "{path}: {detail}. Run `kc reindex` to rebuild it from the keychain",
            path = path.display(),
            detail = detail
        ),
        StoreError::Busy { path, waited } => tr!(
            "another kc process is using {path} (waited {seconds}s); try again",
            path = path.display(),
            seconds = format!("{:.0}", waited.as_secs_f64())
        ),
        StoreError::NoConfigDir => tr!(
            "cannot determine the kc config directory (no home directory?); set {var}",
            var = kc_store::ENV_CONFIG_DIR
        ),
        _ => e.to_string(),
    }
}

fn session_message(e: &SessionError) -> String {
    match e {
        SessionError::PossibleInterception => {
            tr!("someone else used this code (possible interception); ask for a new code")
        }
        SessionError::WrongCodeOrInterception => {
            tr!("wrong code, or someone interfered with the exchange")
        }
        SessionError::BadPeerMessage => {
            tr!("the other side sent an invalid key-exchange message")
        }
        SessionError::Tampered => {
            tr!("a message from the other side failed authentication (tampered or corrupted)")
        }
        SessionError::Malformed(why) => {
            tr!("the other side sent a malformed message: {why}", why = why)
        }
        SessionError::UnknownChannel => {
            tr!("no channel with that number; the code is wrong or has expired")
        }
        SessionError::ChannelClosed => {
            tr!("the channel was closed by the other side or has expired")
        }
        SessionError::TimedOut => tr!("timed out waiting for the other side"),
        SessionError::TooLarge(what) => tr!("{what} is too large for the relay", what = what),
        SessionError::Relay(relay) => relay_message(relay),
        _ => e.to_string(),
    }
}

fn relay_message(e: &RelayError) -> String {
    match e {
        RelayError::Api { code, .. } => match serde_json::to_value(code) {
            Ok(serde_json::Value::String(name)) => {
                tr!("the relay refused the request ({code})", code = name)
            }
            _ => e.to_string(),
        },
        RelayError::Status(status) => tr!("the relay answered HTTP {status}", status = status),
        RelayError::Transport(why) => tr!("could not reach the relay: {why}", why = why),
        RelayError::BadResponse(why) => {
            tr!("the relay sent an invalid response: {why}", why = why)
        }
    }
}

fn inbox_message(e: &InboxError) -> String {
    match e {
        InboxError::Malformed => tr!("the message is malformed"),
        InboxError::UnsupportedVersion(v) => {
            tr!("unsupported message version {version}", version = v)
        }
        InboxError::UnsupportedSuite(s) => tr!("unsupported cipher suite {suite}", suite = s),
        InboxError::WrongRecipient => tr!("the message is addressed to a different device"),
        InboxError::UnknownSender => {
            tr!("the message is from a device that isn't paired with this one")
        }
        InboxError::DecryptFailed => {
            tr!("the message failed authentication (tampered, or not from that device)")
        }
        InboxError::FingerprintMismatch => {
            tr!("the message header and contents name different devices")
        }
        InboxError::BadLifetime => tr!("the message has an invalid lifetime"),
        InboxError::Expired => tr!("the message has expired"),
        InboxError::NotYetValid => {
            tr!("the message is dated in the future; check this device's clock")
        }
        InboxError::Replay => tr!("the message was already received (replay)"),
        InboxError::InvalidTtl => {
            tr!("a message lifetime must be between 1 second and 72 hours")
        }
        InboxError::TooLarge => tr!("the message is larger than the relay accepts"),
        InboxError::InvalidItems(why) => tr!("invalid items: {why}", why = why),
        InboxError::Seal => tr!("encryption failed"),
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
    fn english_texts_match_the_lower_crates() {
        use std::path::PathBuf;
        use std::time::Duration;

        use kc_proto::payload::PayloadError;
        use kc_wire::ErrorCode;

        let hint = || "unlock it first".to_string();
        let store = [
            StoreError::InvalidName {
                what: "item name",
                value: "a b".into(),
                rule: "no spaces",
            },
            StoreError::InvalidValue("empty".into()),
            StoreError::InvalidConfig("timeout is zero".into()),
            StoreError::Ambiguous {
                service: "svc".into(),
                candidates: vec!["a".into(), "b".into()],
            },
            StoreError::Locked {
                what: "login".into(),
                hint: hint(),
            },
            StoreError::Unavailable {
                reason: "no bus".into(),
                hint: hint(),
            },
            StoreError::Timeout {
                op: "read",
                timeout: Duration::from_millis(2550),
                hint: hint(),
            },
            StoreError::OutcomeUnknown {
                op: "write",
                detail: "bus gone".into(),
                hint: hint(),
            },
            StoreError::InteractionRequired {
                op: "read",
                hint: hint(),
            },
            StoreError::AccessDenied {
                op: "read",
                detail: "denied".into(),
                hint: hint(),
            },
            StoreError::Backend {
                op: "read",
                detail: "code -1".into(),
            },
            StoreError::Corrupt {
                account: "acct".into(),
                reason: "bad sha".into(),
            },
            StoreError::IndexCorrupt {
                path: PathBuf::from("/x/index.json"),
                detail: "eof".into(),
            },
            StoreError::Busy {
                path: PathBuf::from("/x/lock"),
                waited: Duration::from_millis(15400),
            },
            StoreError::NoConfigDir,
            StoreError::NotFound("gone".into()),
        ];
        for e in &store {
            assert_eq!(store_message(e), e.to_string());
        }

        let relay = || {
            [
                RelayError::Api {
                    code: ErrorCode::RateLimited,
                    retry_after_s: Some(3),
                },
                RelayError::Status(502),
                RelayError::Transport("reset".into()),
                RelayError::BadResponse("bad json".into()),
            ]
        };
        for e in &relay() {
            assert_eq!(relay_message(e), e.to_string());
        }

        let mut session = vec![
            SessionError::PossibleInterception,
            SessionError::WrongCodeOrInterception,
            SessionError::BadPeerMessage,
            SessionError::Tampered,
            SessionError::Malformed("short".into()),
            SessionError::UnknownChannel,
            SessionError::ChannelClosed,
            SessionError::TimedOut,
            SessionError::Invalid("not allowed"),
            SessionError::TooLarge("the payload"),
        ];
        session.extend(relay().map(SessionError::Relay));
        for e in &session {
            assert_eq!(session_message(e), e.to_string());
        }

        let inbox = [
            InboxError::Malformed,
            InboxError::UnsupportedVersion(9),
            InboxError::UnsupportedSuite(7),
            InboxError::WrongRecipient,
            InboxError::UnknownSender,
            InboxError::DecryptFailed,
            InboxError::FingerprintMismatch,
            InboxError::BadLifetime,
            InboxError::Expired,
            InboxError::NotYetValid,
            InboxError::Replay,
            InboxError::InvalidTtl,
            InboxError::TooLarge,
            InboxError::InvalidItems(PayloadError::DuplicateName("A".into())),
            InboxError::Seal,
        ];
        for e in &inbox {
            assert_eq!(inbox_message(e), e.to_string());
        }
    }

    #[test]
    fn display_has_prefix_and_hint() {
        let e = CliError::usage("bad").with_hint("try this").context("set");
        assert_eq!(e.to_string(), "kc: set: bad\n  hint: try this");
    }
}

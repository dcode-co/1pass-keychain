//! Frozen HTTP contract between `kc` and `kc-relay`, protocol v1.
//!
//! This crate holds only serde types, paths, limits and error codes. It has no
//! crypto and no I/O. The orchestrator owns it: lanes must not change it.
//! Every change here comes with a matching change to `docs/PROTOCOL.md`.
//!
//! Conventions:
//! - Every request carries the header `Kc-Proto: 1`. A wrong version gets 426.
//! - `Id16` is 16 random bytes and `Tok` is 32 random bytes, both base64url
//!   without padding.
//! - Control bodies are JSON. Phase bodies and inbox message bodies are raw
//!   `application/octet-stream`.
//! - Error bodies are [`ApiError`] and never echo input.

use serde::{Deserialize, Serialize};

pub const PROTO_VERSION: u32 = 1;
pub const PROTO_HEADER: &str = "kc-proto";
/// Set by the relay's Caddy block to the real client address. The relay
/// trusts it only when the TCP peer is inside the configured proxy CIDRs.
pub const CLIENT_IP_HEADER: &str = "x-kc-client-ip";
pub const USER_AGENT: &str = "kc/1";

pub mod limits {
    pub const CHANNEL_NUMBER_MAX: u16 = 9999;
    /// Channel lifetime from allocation.
    pub const CHANNEL_TTL_SECS: u64 = 600;
    /// After DELETE or expiry a channel answers 410 this long, then 404. A
    /// number isn't reused while it is a tombstone.
    pub const CHANNEL_TOMBSTONE_SECS: u64 = 600;
    pub const LONG_POLL_MAX_SECS: u64 = 25;
    pub const MAX_OPEN_CHANNELS: usize = 1000;
    pub const MAX_CHANNEL_RAM_BYTES: usize = 32 * 1024 * 1024;

    pub const MAX_PAKE_BYTES: usize = 64;
    pub const MAX_CONFIRM_BYTES: usize = 64;
    pub const MAX_PAYLOAD_BYTES: usize = 256 * 1024;
    pub const MAX_ACK_BYTES: usize = 16 * 1024;

    pub const INBOX_MESSAGE_TTL_SECS: u64 = 72 * 3600;
    pub const MAX_MESSAGE_BYTES: usize = 256 * 1024;
    pub const INBOX_MAX_MESSAGES: usize = 20;
    pub const INBOX_MAX_BYTES: usize = 4 * 1024 * 1024;
    pub const INBOX_MAX_WRITERS: usize = 16;
    /// Inboxes nobody has read for this long are deleted.
    pub const INBOX_IDLE_DELETE_DAYS: u64 = 30;
    pub const MAX_INBOXES: usize = 5000;

    /// Clients pad encrypted payloads to a multiple of this.
    pub const PAD_BUCKET_BYTES: usize = 4096;
}

/// Which participant a side token belongs to. The receiver allocates the
/// channel and shows the code; the sender joins with the code.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    Receiver,
    Sender,
}

impl Role {
    pub fn peer(self) -> Role {
        match self {
            Role::Receiver => Role::Sender,
            Role::Sender => Role::Receiver,
        }
    }
    /// One byte used by the crypto layer (AAD, MAC labels).
    pub fn byte(self) -> u8 {
        match self {
            Role::Receiver => b'r',
            Role::Sender => b's',
        }
    }
}

/// Phases of a channel. Each role writes a phase at most once.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Phase {
    /// SPAKE2 message, both roles.
    Pake,
    /// Key-confirmation MAC, both roles.
    Confirm,
    /// Encrypted items, sender only.
    Payload,
    /// Encrypted result, receiver only.
    Ack,
}

impl Phase {
    pub const ALL: [Phase; 4] = [Phase::Pake, Phase::Confirm, Phase::Payload, Phase::Ack];

    pub fn as_str(self) -> &'static str {
        match self {
            Phase::Pake => "pake",
            Phase::Confirm => "confirm",
            Phase::Payload => "payload",
            Phase::Ack => "ack",
        }
    }

    pub fn parse(s: &str) -> Option<Phase> {
        Phase::ALL.into_iter().find(|p| p.as_str() == s)
    }

    /// One byte used by the crypto layer (AAD).
    pub fn byte(self) -> u8 {
        match self {
            Phase::Pake => 1,
            Phase::Confirm => 2,
            Phase::Payload => 3,
            Phase::Ack => 4,
        }
    }

    pub fn max_bytes(self) -> usize {
        match self {
            Phase::Pake => limits::MAX_PAKE_BYTES,
            Phase::Confirm => limits::MAX_CONFIRM_BYTES,
            Phase::Payload => limits::MAX_PAYLOAD_BYTES,
            Phase::Ack => limits::MAX_ACK_BYTES,
        }
    }

    pub fn writable_by(self, role: Role) -> bool {
        match self {
            Phase::Pake | Phase::Confirm => true,
            Phase::Payload => role == Role::Sender,
            Phase::Ack => role == Role::Receiver,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeleteReason {
    Done,
    BadConfirm,
    Abort,
}

impl DeleteReason {
    pub fn as_str(self) -> &'static str {
        match self {
            DeleteReason::Done => "done",
            DeleteReason::BadConfirm => "bad_confirm",
            DeleteReason::Abort => "abort",
        }
    }
}

pub mod paths {
    use super::Phase;

    pub const HEALTHZ: &str = "/healthz";
    pub const LIMITS: &str = "/v1/limits";
    pub const CHANNELS: &str = "/v1/channels";
    pub const INBOXES: &str = "/v1/inboxes";

    pub fn channel(channel: u16) -> String {
        format!("/v1/channels/{channel}")
    }
    pub fn join(channel: u16) -> String {
        format!("/v1/channels/{channel}/join")
    }
    pub fn phase(channel: u16, phase: Phase) -> String {
        format!("/v1/channels/{channel}/{}", phase.as_str())
    }
    pub fn inbox(inbox_id: &str) -> String {
        format!("/v1/inboxes/{inbox_id}")
    }
    pub fn writers(inbox_id: &str) -> String {
        format!("/v1/inboxes/{inbox_id}/writers")
    }
    pub fn writer(inbox_id: &str, writer_id: &str) -> String {
        format!("/v1/inboxes/{inbox_id}/writers/{writer_id}")
    }
    pub fn messages(inbox_id: &str) -> String {
        format!("/v1/inboxes/{inbox_id}/messages")
    }
    pub fn message(inbox_id: &str, msg_id: &str) -> String {
        format!("/v1/inboxes/{inbox_id}/messages/{msg_id}")
    }
}

// ---- channels -----------------------------------------------------------------
// POST   /v1/channels                          -> 201 ChannelAllocated   (caller = receiver)
// POST   /v1/channels/{c}/join                 -> 200 ChannelJoined      (caller = sender; 3rd join -> 409 crowded)
// PUT    /v1/channels/{c}/{phase}   raw body   -> 204   Bearer side_token; 403 wrong_role, 409 already_written
// GET    /v1/channels/{c}/{phase}?wait=0..=25  -> 200 raw peer bytes | 204 not yet   Bearer side_token
// DELETE /v1/channels/{c}?reason=done|bad_confirm|abort -> 204          Bearer side_token
//
// ---- inboxes ------------------------------------------------------------------
// POST   /v1/inboxes                                -> 201 InboxCreated
// POST   /v1/inboxes/{id}/writers      WriterRegister   -> 201 WriterRegistered   Bearer owner_token
// DELETE /v1/inboxes/{id}/writers/{wid}             -> 204                       Bearer owner_token
// POST   /v1/inboxes/{id}/messages     raw body     -> 201 MessageAccepted    Bearer writer_token
// GET    /v1/inboxes/{id}/messages?wait=0..=25      -> 200 InboxMessages      Bearer owner_token
// DELETE /v1/inboxes/{id}/messages/{msg_id}         -> 204                       Bearer owner_token
// DELETE /v1/inboxes/{id}                           -> 204                       Bearer owner_token
// An unknown inbox and a wrong token both answer 401, so ids can't be probed.
//
// ---- misc ---------------------------------------------------------------------
// GET /healthz -> 200 "ok"     GET /v1/limits -> 200 Limits

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelAllocated {
    pub channel: u16,
    pub side_token: String,
    /// RFC 3339, UTC.
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChannelJoined {
    pub side_token: String,
    pub expires_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxCreated {
    pub inbox_id: String,
    pub owner_token: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriterRegister {
    /// base64url of SHA-256(writer_token). The writer token itself travels to
    /// the peer only inside an encrypted channel.
    pub writer_token_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriterRegistered {
    pub writer_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MessageAccepted {
    pub msg_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxMessage {
    pub msg_id: String,
    pub writer_id: String,
    pub received_at: String,
    /// base64url, no padding.
    pub body_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InboxMessages {
    pub messages: Vec<InboxMessage>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Limits {
    pub proto_version: u32,
    pub channel_ttl_secs: u64,
    pub long_poll_max_secs: u64,
    pub max_payload_bytes: usize,
    pub max_ack_bytes: usize,
    pub max_message_bytes: usize,
    pub inbox_max_messages: usize,
    pub inbox_max_bytes: usize,
    pub inbox_message_ttl_secs: u64,
}

impl Limits {
    pub fn current() -> Limits {
        Limits {
            proto_version: PROTO_VERSION,
            channel_ttl_secs: limits::CHANNEL_TTL_SECS,
            long_poll_max_secs: limits::LONG_POLL_MAX_SECS,
            max_payload_bytes: limits::MAX_PAYLOAD_BYTES,
            max_ack_bytes: limits::MAX_ACK_BYTES,
            max_message_bytes: limits::MAX_MESSAGE_BYTES,
            inbox_max_messages: limits::INBOX_MAX_MESSAGES,
            inbox_max_bytes: limits::INBOX_MAX_BYTES,
            inbox_message_ttl_secs: limits::INBOX_MESSAGE_TTL_SECS,
        }
    }
}

/// Body of every non-2xx response. It never echoes request input.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApiError {
    pub code: ErrorCode,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub retry_after_s: Option<u32>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    BadRequest,
    Unauthorized,
    WrongRole,
    NotFound,
    Crowded,
    AlreadyWritten,
    Gone,
    TooLarge,
    UnsupportedVersion,
    RateLimited,
    Capacity,
    InboxFull,
    Internal,
}

impl ErrorCode {
    pub fn http_status(self) -> u16 {
        match self {
            ErrorCode::BadRequest => 400,
            ErrorCode::Unauthorized => 401,
            ErrorCode::WrongRole => 403,
            ErrorCode::NotFound => 404,
            ErrorCode::Crowded | ErrorCode::AlreadyWritten => 409,
            ErrorCode::Gone => 410,
            ErrorCode::TooLarge => 413,
            ErrorCode::UnsupportedVersion => 426,
            ErrorCode::RateLimited => 429,
            ErrorCode::Capacity => 503,
            ErrorCode::InboxFull => 507,
            ErrorCode::Internal => 500,
        }
    }
}

/// `kc` process exit codes. Agents and the memory docs depend on these.
pub mod exit {
    pub const OK: i32 = 0;
    pub const USAGE: i32 = 2;
    pub const NOT_FOUND: i32 = 3;
    /// No session bus, locked keychain, Windows 1312, macOS -25308.
    pub const KEYCHAIN_UNAVAILABLE: i32 = 4;
    /// The command needs a human at a terminal (or a missing flag).
    pub const INTERACTION_REQUIRED: i32 = 5;
    pub const RELAY_UNAVAILABLE: i32 = 6;
    /// Wrong code, bad MAC, tampering or replay.
    pub const AUTH_FAILED: i32 = 7;
    /// Some items were skipped (conflicts).
    pub const PARTIAL: i32 = 8;
    pub const EXPIRED: i32 = 9;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn contract_is_stable() {
        assert_eq!(paths::phase(42, Phase::Payload), "/v1/channels/42/payload");
        assert_eq!(paths::join(7), "/v1/channels/7/join");
        assert_eq!(paths::messages("abc"), "/v1/inboxes/abc/messages");
        assert_eq!(
            serde_json::to_string(&ErrorCode::AlreadyWritten).unwrap(),
            "\"already_written\""
        );
        assert_eq!(
            serde_json::to_string(&Role::Receiver).unwrap(),
            "\"receiver\""
        );
        assert_eq!(Phase::parse("ack"), Some(Phase::Ack));
        assert!(!Phase::Payload.writable_by(Role::Receiver));
        assert!(!Phase::Ack.writable_by(Role::Sender));
        assert_eq!(ErrorCode::InboxFull.http_status(), 507);
        let e = ApiError {
            code: ErrorCode::RateLimited,
            retry_after_s: Some(30),
        };
        assert_eq!(
            serde_json::to_string(&e).unwrap(),
            r#"{"code":"rate_limited","retry_after_s":30}"#
        );
    }
}

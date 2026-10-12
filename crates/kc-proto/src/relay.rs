//! The relay as the protocol sees it. [`RelayApi`] mirrors the `kc-wire`
//! endpoints one to one; `kc-cli` implements it over HTTP and
//! `memory_relay::MemoryRelay` (feature `test-util`) implements it in memory.
//!
//! Tokens are passed as their wire form (base64url, no padding) and bodies as
//! raw bytes. Implementations map every non-2xx answer to [`RelayError`].

use std::future::Future;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kc_wire::{
    ApiError, ChannelAllocated, ChannelJoined, DeleteReason, ErrorCode, InboxCreated, InboxMessage,
    InboxMessages, MessageAccepted, Phase, WriterRegister, WriterRegistered,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// The relay answered with an [`ApiError`] body.
    #[error("the relay refused the request ({})", error_code_name(*code))]
    Api {
        code: ErrorCode,
        retry_after_s: Option<u32>,
    },
    /// A non-2xx answer without a usable `ApiError` body (for example a
    /// proxy's 502 page).
    #[error("the relay answered HTTP {0}")]
    Status(u16),
    /// The request didn't complete: DNS, connection, TLS or timeout.
    #[error("could not reach the relay: {0}")]
    Transport(String),
    /// A 2xx answer whose body didn't make sense.
    #[error("the relay sent an invalid response: {0}")]
    BadResponse(String),
}

fn error_code_name(code: ErrorCode) -> &'static str {
    match code {
        ErrorCode::BadRequest => "bad_request",
        ErrorCode::Unauthorized => "unauthorized",
        ErrorCode::WrongRole => "wrong_role",
        ErrorCode::NotFound => "not_found",
        ErrorCode::Crowded => "crowded",
        ErrorCode::AlreadyWritten => "already_written",
        ErrorCode::Gone => "gone",
        ErrorCode::TooLarge => "too_large",
        ErrorCode::UnsupportedVersion => "unsupported_version",
        ErrorCode::RateLimited => "rate_limited",
        ErrorCode::Capacity => "capacity",
        ErrorCode::InboxFull => "inbox_full",
        ErrorCode::Internal => "internal",
    }
}

impl From<ApiError> for RelayError {
    fn from(e: ApiError) -> RelayError {
        RelayError::Api {
            code: e.code,
            retry_after_s: e.retry_after_s,
        }
    }
}

impl RelayError {
    pub fn api(code: ErrorCode) -> RelayError {
        RelayError::Api {
            code,
            retry_after_s: None,
        }
    }

    pub fn code(&self) -> Option<ErrorCode> {
        match self {
            RelayError::Api { code, .. } => Some(*code),
            _ => None,
        }
    }

    pub fn is(&self, code: ErrorCode) -> bool {
        self.code() == Some(code)
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            RelayError::Api {
                retry_after_s: Some(s),
                ..
            } => Some(Duration::from_secs(u64::from(*s))),
            _ => None,
        }
    }

    /// Worth retrying the same request later: transport failures, rate
    /// limits, capacity and server errors.
    pub fn is_transient(&self) -> bool {
        match self {
            RelayError::Transport(_) => true,
            RelayError::Status(s) => *s >= 500 || *s == 429,
            RelayError::Api { code, .. } => {
                matches!(
                    code,
                    ErrorCode::RateLimited | ErrorCode::Capacity | ErrorCode::Internal
                )
            }
            RelayError::BadResponse(_) => false,
        }
    }

    /// The `kc` exit code for this error (`kc_wire::exit`).
    pub fn exit_code(&self) -> i32 {
        use kc_wire::exit;
        match self.code() {
            Some(ErrorCode::Gone) => exit::EXPIRED,
            Some(ErrorCode::NotFound) => exit::NOT_FOUND,
            Some(ErrorCode::Unauthorized) => exit::AUTH_FAILED,
            Some(ErrorCode::TooLarge | ErrorCode::BadRequest) => exit::USAGE,
            _ => exit::RELAY_UNAVAILABLE,
        }
    }
}

/// Every relay endpoint the client uses (see the table in `kc-wire`).
///
/// `wait` is the long-poll time; implementations send whole seconds, capped
/// at `kc_wire::limits::LONG_POLL_MAX_SECS`.
pub trait RelayApi: Send + Sync {
    /// `POST /v1/channels`. The caller becomes the receiver.
    fn allocate(&self) -> impl Future<Output = Result<ChannelAllocated, RelayError>> + Send;

    /// `POST /v1/channels/{c}/join`. The caller becomes the sender; a third
    /// participant gets `crowded`.
    fn join(&self, channel: u16) -> impl Future<Output = Result<ChannelJoined, RelayError>> + Send;

    /// `PUT /v1/channels/{c}/{phase}` with `Authorization: Bearer side_token`.
    fn put_phase(
        &self,
        channel: u16,
        side_token: &str,
        phase: Phase,
        body: &[u8],
    ) -> impl Future<Output = Result<(), RelayError>> + Send;

    /// `GET /v1/channels/{c}/{phase}?wait=`: the peer's bytes for that phase,
    /// or `None` if the relay answered 204 (not written yet).
    fn get_phase(
        &self,
        channel: u16,
        side_token: &str,
        phase: Phase,
        wait: Duration,
    ) -> impl Future<Output = Result<Option<Vec<u8>>, RelayError>> + Send;

    /// `DELETE /v1/channels/{c}?reason=`.
    fn delete_channel(
        &self,
        channel: u16,
        side_token: &str,
        reason: DeleteReason,
    ) -> impl Future<Output = Result<(), RelayError>> + Send;

    /// `POST /v1/inboxes`.
    fn create_inbox(&self) -> impl Future<Output = Result<InboxCreated, RelayError>> + Send;

    /// `POST /v1/inboxes/{id}/writers` with `Bearer owner_token`.
    fn register_writer(
        &self,
        inbox_id: &str,
        owner_token: &str,
        request: &WriterRegister,
    ) -> impl Future<Output = Result<WriterRegistered, RelayError>> + Send;

    /// `DELETE /v1/inboxes/{id}/writers/{writer_id}` with `Bearer owner_token`.
    fn delete_writer(
        &self,
        inbox_id: &str,
        owner_token: &str,
        writer_id: &str,
    ) -> impl Future<Output = Result<(), RelayError>> + Send;

    /// `POST /v1/inboxes/{id}/messages` with `Bearer writer_token`.
    fn post_message(
        &self,
        inbox_id: &str,
        writer_token: &str,
        body: &[u8],
    ) -> impl Future<Output = Result<MessageAccepted, RelayError>> + Send;

    /// `GET /v1/inboxes/{id}/messages?wait=` with `Bearer owner_token`.
    fn list_messages(
        &self,
        inbox_id: &str,
        owner_token: &str,
        wait: Duration,
    ) -> impl Future<Output = Result<InboxMessages, RelayError>> + Send;

    /// `DELETE /v1/inboxes/{id}/messages/{msg_id}` with `Bearer owner_token`.
    fn delete_message(
        &self,
        inbox_id: &str,
        owner_token: &str,
        msg_id: &str,
    ) -> impl Future<Output = Result<(), RelayError>> + Send;

    /// `DELETE /v1/inboxes/{id}` with `Bearer owner_token`.
    fn delete_inbox(
        &self,
        inbox_id: &str,
        owner_token: &str,
    ) -> impl Future<Output = Result<(), RelayError>> + Send;
}

/// Decodes [`InboxMessage::body_b64`].
pub fn message_body(message: &InboxMessage) -> Result<Vec<u8>, RelayError> {
    URL_SAFE_NO_PAD
        .decode(&message.body_b64)
        .map_err(|_| RelayError::BadResponse("message body is not base64url".into()))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn error_classification() {
        let rate = RelayError::from(ApiError {
            code: ErrorCode::RateLimited,
            retry_after_s: Some(30),
        });
        assert!(rate.is_transient());
        assert_eq!(rate.retry_after(), Some(Duration::from_secs(30)));
        assert_eq!(rate.exit_code(), kc_wire::exit::RELAY_UNAVAILABLE);
        assert!(!RelayError::api(ErrorCode::Crowded).is_transient());
        assert!(RelayError::Transport("reset".into()).is_transient());
        assert!(RelayError::Status(502).is_transient());
        assert!(!RelayError::Status(404).is_transient());
        assert_eq!(
            RelayError::api(ErrorCode::Gone).exit_code(),
            kc_wire::exit::EXPIRED
        );
        assert_eq!(
            RelayError::api(ErrorCode::Gone).to_string(),
            "the relay refused the request (gone)"
        );
    }
}

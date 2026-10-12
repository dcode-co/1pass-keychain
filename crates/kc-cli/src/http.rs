//! [`HttpRelay`]: [`RelayApi`] over HTTP(S) with reqwest and rustls (ring), as `kc-wire`
//! specifies.
//!
//! - Every request carries `kc-proto: 1` and `User-Agent: kc/1`.
//! - Redirects are never followed and reqwest's own retries are off: kc-proto's sessions
//!   decide what to retry.
//! - A read stalls out after 35 s (long-polls wait at most 25 s), a connect after 10 s.
//! - Response bodies are read up to a cap, so a misbehaving relay can't exhaust memory,
//!   into wiped buffers: allocate, join and inbox-create answers carry bearer tokens.
//! - Non-2xx answers become [`RelayError::Api`] from the `ApiError` body, with
//!   `Retry-After` taken from the body or the header; answers without a usable body become
//!   [`RelayError::Status`] (429 and 503 still keep their `Retry-After`).
//! - Bearer tokens are sent as sensitive header values; our copies are wiped.
//!
//! [`RelayUrl`] has already checked the scheme (https unless local or explicitly allowed).

use std::time::Duration;

use kc_proto::relay::{RelayApi, RelayError};
use kc_wire::limits::{INBOX_MAX_BYTES, LONG_POLL_MAX_SECS, MAX_ACK_BYTES, MAX_PAYLOAD_BYTES};
use kc_wire::{
    ApiError, ChannelAllocated, ChannelJoined, DeleteReason, ErrorCode, InboxCreated,
    InboxMessages, Limits, MessageAccepted, PROTO_HEADER, PROTO_VERSION, Phase, USER_AGENT,
    WriterRegister, WriterRegistered, paths,
};
use reqwest::header::{self, HeaderMap, HeaderName, HeaderValue};
use reqwest::{Method, StatusCode};
use serde::de::DeserializeOwned;
use zeroize::Zeroizing;

use crate::error::CliError;
use crate::settings::RelayUrl;
use crate::state::is_url_token;

const READ_TIMEOUT: Duration = Duration::from_secs(35);
/// The most one request may take, body included, on top of any long-poll wait: a relay
/// that trickles bytes can't stall kc for longer than this.
const REQUEST_TIMEOUT: Duration = Duration::from_secs(120);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
/// Error bodies are tiny `ApiError` JSON.
const MAX_ERROR_BODY: usize = 4 * 1024;
/// Control answers (allocate, join, ids).
const MAX_CONTROL_BODY: usize = 16 * 1024;
/// A full inbox listing: up to 4 MiB of messages, base64url-encoded, plus JSON framing.
const MAX_LISTING_BODY: usize = INBOX_MAX_BYTES / 3 * 4 + 256 * 1024;

pub struct HttpRelay {
    client: reqwest::Client,
    relay: RelayUrl,
}

impl std::fmt::Debug for HttpRelay {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("HttpRelay")
            .field("relay", &self.relay.as_str())
            .finish_non_exhaustive()
    }
}

/// rustls needs a process-wide crypto provider; reqwest is built without one so that
/// aws-lc (OpenSSL-licensed) stays out. An error only means one is installed already.
fn install_crypto_provider() {
    let _ = rustls::crypto::ring::default_provider().install_default();
}

impl HttpRelay {
    pub fn new(relay: &RelayUrl) -> Result<HttpRelay, CliError> {
        install_crypto_provider();
        let mut headers = HeaderMap::new();
        headers.insert(
            HeaderName::from_static(PROTO_HEADER),
            HeaderValue::from_str(&PROTO_VERSION.to_string()).expect("digits"),
        );
        let client = reqwest::Client::builder()
            .user_agent(USER_AGENT)
            .default_headers(headers)
            .redirect(reqwest::redirect::Policy::none())
            .retry(reqwest::retry::never())
            .read_timeout(READ_TIMEOUT)
            .connect_timeout(CONNECT_TIMEOUT)
            .https_only(!relay.is_plain_http())
            .http1_only()
            .build()
            .map_err(|e| CliError::failure(format!("can't set up the HTTP client: {e}")))?;
        Ok(HttpRelay {
            client,
            relay: relay.clone(),
        })
    }

    pub fn relay(&self) -> &RelayUrl {
        &self.relay
    }

    /// `GET /v1/limits`: the relay's protocol version and limits (for `kc doctor`).
    pub async fn limits(&self) -> Result<Limits, RelayError> {
        let body = self
            .call(
                Method::GET,
                paths::LIMITS,
                None,
                None,
                MAX_CONTROL_BODY,
                Duration::ZERO,
            )
            .await?
            .expect_status(&[StatusCode::OK])?;
        parse_json(&body)
    }

    async fn call(
        &self,
        method: Method,
        path: &str,
        bearer: Option<&str>,
        body: Option<Body>,
        max_body: usize,
        wait: Duration,
    ) -> Result<Answer, RelayError> {
        let mut request = self
            .client
            .request(method, self.relay.endpoint(path))
            .timeout(REQUEST_TIMEOUT + wait.min(Duration::from_secs(LONG_POLL_MAX_SECS)));
        if let Some(token) = bearer {
            let value = Zeroizing::new(format!("Bearer {token}"));
            let mut value = HeaderValue::from_str(&value)
                .map_err(|_| RelayError::BadResponse("invalid token".into()))?;
            value.set_sensitive(true);
            request = request.header(header::AUTHORIZATION, value);
        }
        match body {
            Some(Body::Octets(bytes)) => {
                request = request
                    .header(header::CONTENT_TYPE, "application/octet-stream")
                    .body(bytes);
            }
            Some(Body::Json(bytes)) => {
                request = request
                    .header(header::CONTENT_TYPE, "application/json")
                    .body(bytes);
            }
            None => {}
        }
        let mut response = request.send().await.map_err(transport)?;
        let status = response.status();
        if status.is_success() {
            let body = read_capped(&mut response, max_body).await?;
            return Ok(Answer { status, body });
        }
        let retry_after = retry_after_header(response.headers());
        let body = read_capped(&mut response, MAX_ERROR_BODY)
            .await
            .unwrap_or_else(|_| Zeroizing::new(Vec::new()));
        Err(error_from(status, &body, retry_after))
    }
}

enum Body {
    Octets(Vec<u8>),
    Json(Vec<u8>),
}

struct Answer {
    status: StatusCode,
    body: Zeroizing<Vec<u8>>,
}

impl Answer {
    fn expect_status(self, allowed: &[StatusCode]) -> Result<Zeroizing<Vec<u8>>, RelayError> {
        if allowed.contains(&self.status) {
            Ok(self.body)
        } else {
            Err(RelayError::BadResponse(format!(
                "unexpected status {}",
                self.status.as_u16()
            )))
        }
    }
}

fn transport(e: reqwest::Error) -> RelayError {
    let e = e.without_url();
    let what = if e.is_timeout() {
        "timed out".to_owned()
    } else if e.is_connect() {
        format!("connection failed ({})", root_cause(&e))
    } else {
        root_cause(&e)
    };
    RelayError::Transport(what)
}

/// The innermost error message (reqwest's own top-level message is generic).
fn root_cause(e: &(dyn std::error::Error + 'static)) -> String {
    let mut cause = e;
    while let Some(next) = cause.source() {
        cause = next;
    }
    cause.to_string()
}

/// Reads the body, at most `cap` bytes, into a wiped buffer. Growing copies into a new
/// wiped buffer, so no reallocation leaves a token behind.
async fn read_capped(
    response: &mut reqwest::Response,
    cap: usize,
) -> Result<Zeroizing<Vec<u8>>, RelayError> {
    let expected = response.content_length();
    if expected.is_some_and(|len| len > cap as u64) {
        return Err(RelayError::BadResponse("the answer is too large".into()));
    }
    let first = expected.map_or(1024, |len| len as usize).min(cap);
    let mut out = Zeroizing::new(Vec::with_capacity(first));
    while let Some(chunk) = response.chunk().await.map_err(transport)? {
        let needed = out.len() + chunk.len();
        if needed > cap {
            return Err(RelayError::BadResponse("the answer is too large".into()));
        }
        if needed > out.capacity() {
            let mut bigger = Zeroizing::new(Vec::with_capacity(
                (out.capacity() * 2).max(needed).min(cap),
            ));
            bigger.extend_from_slice(&out);
            out = bigger;
        }
        out.extend_from_slice(&chunk);
    }
    Ok(out)
}

fn retry_after_header(headers: &HeaderMap) -> Option<u32> {
    headers
        .get(header::RETRY_AFTER)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// Maps a non-2xx answer: the `ApiError` body if there is one, else the status.
fn error_from(status: StatusCode, body: &[u8], retry_after: Option<u32>) -> RelayError {
    if let Ok(api) = serde_json::from_slice::<ApiError>(body) {
        return RelayError::Api {
            code: api.code,
            retry_after_s: api.retry_after_s.or(retry_after),
        };
    }
    match status {
        StatusCode::TOO_MANY_REQUESTS => RelayError::Api {
            code: ErrorCode::RateLimited,
            retry_after_s: retry_after,
        },
        StatusCode::SERVICE_UNAVAILABLE if retry_after.is_some() => RelayError::Api {
            code: ErrorCode::Capacity,
            retry_after_s: retry_after,
        },
        _ => RelayError::Status(status.as_u16()),
    }
}

fn parse_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, RelayError> {
    serde_json::from_slice(body)
        .map_err(|_| RelayError::BadResponse("the answer isn't the expected JSON".into()))
}

fn wait_query(wait: Duration) -> String {
    format!("?wait={}", wait.as_secs().min(LONG_POLL_MAX_SECS))
}

/// Ids go into URL paths; anything but base64url is refused before a request is made.
fn check_id(id: &str, what: &str) -> Result<(), RelayError> {
    if is_url_token(id) {
        Ok(())
    } else {
        Err(RelayError::BadResponse(format!("invalid {what}")))
    }
}

impl RelayApi for HttpRelay {
    async fn allocate(&self) -> Result<ChannelAllocated, RelayError> {
        let body = self
            .call(
                Method::POST,
                paths::CHANNELS,
                None,
                None,
                MAX_CONTROL_BODY,
                Duration::ZERO,
            )
            .await?
            .expect_status(&[StatusCode::CREATED, StatusCode::OK])?;
        parse_json(&body)
    }

    async fn join(&self, channel: u16) -> Result<ChannelJoined, RelayError> {
        let body = self
            .call(
                Method::POST,
                &paths::join(channel),
                None,
                None,
                MAX_CONTROL_BODY,
                Duration::ZERO,
            )
            .await?
            .expect_status(&[StatusCode::OK, StatusCode::CREATED])?;
        parse_json(&body)
    }

    async fn put_phase(
        &self,
        channel: u16,
        side_token: &str,
        phase: Phase,
        body: &[u8],
    ) -> Result<(), RelayError> {
        self.call(
            Method::PUT,
            &paths::phase(channel, phase),
            Some(side_token),
            Some(Body::Octets(body.to_vec())),
            MAX_ERROR_BODY,
            Duration::ZERO,
        )
        .await?
        .expect_status(&[StatusCode::NO_CONTENT, StatusCode::OK])?;
        Ok(())
    }

    async fn get_phase(
        &self,
        channel: u16,
        side_token: &str,
        phase: Phase,
        wait: Duration,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        let cap = match phase {
            Phase::Payload => MAX_PAYLOAD_BYTES,
            Phase::Ack => MAX_ACK_BYTES,
            Phase::Pake | Phase::Confirm => MAX_ERROR_BODY,
        };
        let path = format!("{}{}", paths::phase(channel, phase), wait_query(wait));
        let answer = self
            .call(Method::GET, &path, Some(side_token), None, cap, wait)
            .await?;
        match answer.status {
            StatusCode::NO_CONTENT => Ok(None),
            // Ciphertext: no need to keep it in a wiped buffer.
            StatusCode::OK => Ok(Some(answer.body.to_vec())),
            other => Err(RelayError::BadResponse(format!(
                "unexpected status {}",
                other.as_u16()
            ))),
        }
    }

    async fn delete_channel(
        &self,
        channel: u16,
        side_token: &str,
        reason: DeleteReason,
    ) -> Result<(), RelayError> {
        let path = format!("{}?reason={}", paths::channel(channel), reason.as_str());
        self.call(
            Method::DELETE,
            &path,
            Some(side_token),
            None,
            MAX_ERROR_BODY,
            Duration::ZERO,
        )
        .await?
        .expect_status(&[StatusCode::NO_CONTENT, StatusCode::OK])?;
        Ok(())
    }

    async fn create_inbox(&self) -> Result<InboxCreated, RelayError> {
        let body = self
            .call(
                Method::POST,
                paths::INBOXES,
                None,
                None,
                MAX_CONTROL_BODY,
                Duration::ZERO,
            )
            .await?
            .expect_status(&[StatusCode::CREATED, StatusCode::OK])?;
        let created: InboxCreated = parse_json(&body)?;
        check_id(&created.inbox_id, "inbox id")?;
        Ok(created)
    }

    async fn register_writer(
        &self,
        inbox_id: &str,
        owner_token: &str,
        request: &WriterRegister,
    ) -> Result<WriterRegistered, RelayError> {
        check_id(inbox_id, "inbox id")?;
        let json = serde_json::to_vec(request)
            .map_err(|_| RelayError::BadResponse("can't encode the request".into()))?;
        let body = self
            .call(
                Method::POST,
                &paths::writers(inbox_id),
                Some(owner_token),
                Some(Body::Json(json)),
                MAX_CONTROL_BODY,
                Duration::ZERO,
            )
            .await?
            .expect_status(&[StatusCode::CREATED, StatusCode::OK])?;
        let registered: WriterRegistered = parse_json(&body)?;
        check_id(&registered.writer_id, "writer id")?;
        Ok(registered)
    }

    async fn delete_writer(
        &self,
        inbox_id: &str,
        owner_token: &str,
        writer_id: &str,
    ) -> Result<(), RelayError> {
        check_id(inbox_id, "inbox id")?;
        check_id(writer_id, "writer id")?;
        self.call(
            Method::DELETE,
            &paths::writer(inbox_id, writer_id),
            Some(owner_token),
            None,
            MAX_ERROR_BODY,
            Duration::ZERO,
        )
        .await?
        .expect_status(&[StatusCode::NO_CONTENT, StatusCode::OK])?;
        Ok(())
    }

    async fn post_message(
        &self,
        inbox_id: &str,
        writer_token: &str,
        body: &[u8],
    ) -> Result<MessageAccepted, RelayError> {
        check_id(inbox_id, "inbox id")?;
        let answer = self
            .call(
                Method::POST,
                &paths::messages(inbox_id),
                Some(writer_token),
                Some(Body::Octets(body.to_vec())),
                MAX_CONTROL_BODY,
                Duration::ZERO,
            )
            .await?
            .expect_status(&[StatusCode::CREATED, StatusCode::OK])?;
        parse_json(&answer)
    }

    async fn list_messages(
        &self,
        inbox_id: &str,
        owner_token: &str,
        wait: Duration,
    ) -> Result<InboxMessages, RelayError> {
        check_id(inbox_id, "inbox id")?;
        let path = format!("{}{}", paths::messages(inbox_id), wait_query(wait));
        let body = self
            .call(
                Method::GET,
                &path,
                Some(owner_token),
                None,
                MAX_LISTING_BODY,
                wait,
            )
            .await?
            .expect_status(&[StatusCode::OK])?;
        let listing: InboxMessages = parse_json(&body)?;
        for m in &listing.messages {
            check_id(&m.msg_id, "message id")?;
        }
        Ok(listing)
    }

    async fn delete_message(
        &self,
        inbox_id: &str,
        owner_token: &str,
        msg_id: &str,
    ) -> Result<(), RelayError> {
        check_id(inbox_id, "inbox id")?;
        check_id(msg_id, "message id")?;
        self.call(
            Method::DELETE,
            &paths::message(inbox_id, msg_id),
            Some(owner_token),
            None,
            MAX_ERROR_BODY,
            Duration::ZERO,
        )
        .await?
        .expect_status(&[StatusCode::NO_CONTENT, StatusCode::OK])?;
        Ok(())
    }

    async fn delete_inbox(&self, inbox_id: &str, owner_token: &str) -> Result<(), RelayError> {
        check_id(inbox_id, "inbox id")?;
        self.call(
            Method::DELETE,
            &paths::inbox(inbox_id),
            Some(owner_token),
            None,
            MAX_ERROR_BODY,
            Duration::ZERO,
        )
        .await?
        .expect_status(&[StatusCode::NO_CONTENT, StatusCode::OK])?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn api_errors_keep_retry_after() {
        let body = br#"{"code":"rate_limited","retry_after_s":30}"#;
        assert_eq!(
            error_from(StatusCode::TOO_MANY_REQUESTS, body, Some(5)),
            RelayError::Api {
                code: ErrorCode::RateLimited,
                retry_after_s: Some(30)
            }
        );
        let body = br#"{"code":"capacity"}"#;
        assert_eq!(
            error_from(StatusCode::SERVICE_UNAVAILABLE, body, Some(60)),
            RelayError::Api {
                code: ErrorCode::Capacity,
                retry_after_s: Some(60)
            }
        );
        // A proxy's HTML page.
        assert_eq!(
            error_from(StatusCode::TOO_MANY_REQUESTS, b"<html>", Some(7)),
            RelayError::Api {
                code: ErrorCode::RateLimited,
                retry_after_s: Some(7)
            }
        );
        assert_eq!(
            error_from(StatusCode::BAD_GATEWAY, b"<html>", None),
            RelayError::Status(502)
        );
        assert_eq!(
            error_from(StatusCode::GONE, br#"{"code":"gone"}"#, None),
            RelayError::api(ErrorCode::Gone)
        );
    }

    #[test]
    fn wait_is_whole_seconds_capped() {
        assert_eq!(wait_query(Duration::from_millis(2500)), "?wait=2");
        assert_eq!(wait_query(Duration::from_secs(600)), "?wait=25");
        assert_eq!(wait_query(Duration::ZERO), "?wait=0");
    }

    #[test]
    fn ids_must_be_url_safe() {
        assert!(check_id("AbC-_09", "x").is_ok());
        assert!(check_id("../../v1", "x").is_err());
        assert!(check_id("a/b", "x").is_err());
        assert!(check_id("", "x").is_err());
    }

    #[test]
    fn client_builds_for_https_and_local_http() {
        let https = RelayUrl::parse("https://relay.1pass.dev", false).unwrap();
        assert!(HttpRelay::new(&https).is_ok());
        let local = RelayUrl::parse("http://127.0.0.1:1", false).unwrap();
        assert!(HttpRelay::new(&local).is_ok());
    }
}

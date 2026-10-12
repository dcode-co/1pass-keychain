//! The channel flows of PROTOCOL §3 over any [`RelayApi`].
//!
//! Receiver (shows the code):
//! ```text
//! let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, SessionOptions::default()).await?;
//! show(rx.code());
//! let received = rx.exchange().await?;   // SPAKE2, both MACs checked, payload decrypted
//! // show item names (+ SAS and the sender's label when pairing), store what the user accepts
//! rx.ack(results, my_pair_offer).await?;
//! ```
//! Sender (types the code):
//! ```text
//! let code = Code::parse(&typed)?;        // checked locally, so a typo never burns the code
//! let mut tx = SenderSession::join(&relay, &code, SessionOptions::default()).await?;
//! show(tx.sas());                          // pairing only
//! let ack = tx.send(&payload).await?;
//! ```
//! Each side checks the peer's confirmation MAC before writing anything else.
//! On a bad MAC both sides fail with [`SessionError::WrongCodeOrInterception`]
//! and the receiver deletes the channel with `reason=bad_confirm`.

use std::time::Duration;

use kc_wire::limits::{CHANNEL_TTL_SECS, LONG_POLL_MAX_SECS, MAX_ACK_BYTES, MAX_PAYLOAD_BYTES};
use kc_wire::{DeleteReason, ErrorCode, Phase, Role};
use tokio::time::Instant;
use zeroize::Zeroizing;

use crate::code::{Code, CodeKind};
use crate::pake::{ChannelKeys, OpenError, PakeStart, Sas};
use crate::payload::{ChannelAck, ChannelPayload, ItemResult, PairOffer};
use crate::relay::{RelayApi, RelayError};
use crate::rng;

/// Consecutive transient failures tolerated for one relay call.
const MAX_RETRIES: u32 = 5;
/// Minimum gap between two long-polls of the same slot.
const MIN_POLL_GAP: Duration = Duration::from_secs(1);
/// Upper bound for a best-effort `DELETE`.
const CLOSE_TIMEOUT: Duration = Duration::from_secs(10);
/// Slowest poll while waiting for the peer to close the channel.
const MAX_LINGER_POLL: Duration = Duration::from_secs(2);

#[derive(Debug, Clone)]
pub struct SessionOptions {
    /// Total time to wait for the other side, counted from `open`/`join`.
    pub timeout: Duration,
    /// After writing the ack, how long the receiver waits for the sender to
    /// read it and close the channel. If the sender doesn't, the receiver
    /// leaves the channel to expire (the sender may still be retrying).
    pub ack_linger: Duration,
    /// After a bad confirmation MAC, how long the receiver keeps the channel
    /// so the sender can read the receiver's MAC and see the mismatch too.
    pub mismatch_linger: Duration,
    /// First poll interval while lingering; it doubles up to 2 s.
    pub poll_interval: Duration,
}

impl Default for SessionOptions {
    fn default() -> SessionOptions {
        SessionOptions {
            timeout: Duration::from_secs(CHANNEL_TTL_SECS),
            ack_linger: Duration::from_secs(15),
            mismatch_linger: Duration::from_secs(3),
            poll_interval: Duration::from_millis(250),
        }
    }
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    /// Someone else joined the channel first (`409 crowded`). Don't retry
    /// with the same code.
    #[error("someone else used this code (possible interception); ask for a new code")]
    PossibleInterception,
    /// The confirmation MACs didn't match. The sender also reports this when
    /// the receiver closes the channel during key confirmation.
    #[error("wrong code, or someone interfered with the exchange")]
    WrongCodeOrInterception,
    #[error("the other side sent an invalid key-exchange message")]
    BadPeerMessage,
    /// An encrypted phase failed authentication.
    #[error("a message from the other side failed authentication (tampered or corrupted)")]
    Tampered,
    #[error("the other side sent a malformed message: {0}")]
    Malformed(String),
    #[error("no channel with that number; the code is wrong or has expired")]
    UnknownChannel,
    #[error("the channel was closed by the other side or has expired")]
    ChannelClosed,
    #[error("timed out waiting for the other side")]
    TimedOut,
    /// The caller asked for something the protocol doesn't allow.
    #[error("{0}")]
    Invalid(&'static str),
    #[error("{0} is too large for the relay")]
    TooLarge(&'static str),
    #[error(transparent)]
    Relay(#[from] RelayError),
}

impl SessionError {
    /// The `kc` exit code for this error (`kc_wire::exit`).
    pub fn exit_code(&self) -> i32 {
        use kc_wire::exit;
        match self {
            SessionError::PossibleInterception
            | SessionError::WrongCodeOrInterception
            | SessionError::BadPeerMessage
            | SessionError::Tampered
            | SessionError::Malformed(_) => exit::AUTH_FAILED,
            SessionError::UnknownChannel | SessionError::ChannelClosed | SessionError::TimedOut => {
                exit::EXPIRED
            }
            SessionError::Invalid(_) | SessionError::TooLarge(_) => exit::USAGE,
            SessionError::Relay(e) => e.exit_code(),
        }
    }
}

/// What the receiver got from the sender.
#[derive(Debug)]
pub struct Received {
    /// Verified and decrypted. Item names and labels are already validated.
    pub payload: ChannelPayload,
    /// The 4 SAS words, for pairing codes only. Show them next to the
    /// sender's label; the sender's screen shows the same words.
    pub sas: Option<Sas>,
}

/// One side's view of a channel: the relay, its side token and a deadline.
struct Link<'r, R: RelayApi> {
    relay: &'r R,
    channel: u16,
    token: Zeroizing<String>,
    deadline: Instant,
    opts: SessionOptions,
}

impl<R: RelayApi> Link<'_, R> {
    async fn put(&self, phase: Phase, body: &[u8]) -> Result<(), SessionError> {
        self.put_inner(phase, body, false).await
    }

    /// `gone_after_retry_ok`: after an attempt that may have landed, treat
    /// `gone` as delivered. Only right for the ack, which the sender reads
    /// before it closes.
    async fn put_inner(
        &self,
        phase: Phase,
        body: &[u8],
        gone_after_retry_ok: bool,
    ) -> Result<(), SessionError> {
        let mut retries = 0;
        // Whether an earlier attempt failed in a way that may still have
        // written the slot (a lost answer, a server error), as opposed to a
        // definite refusal such as 429.
        let mut maybe_landed = false;
        loop {
            let call = self.relay.put_phase(self.channel, &self.token, phase, body);
            match tokio::time::timeout_at(self.deadline, call).await {
                Err(_) => return Err(SessionError::TimedOut),
                Ok(Ok(())) => return Ok(()),
                // Only our token can write our slot, so this means an earlier
                // attempt landed.
                Ok(Err(e)) if maybe_landed && e.is(ErrorCode::AlreadyWritten) => return Ok(()),
                Ok(Err(e)) if maybe_landed && gone_after_retry_ok && e.is(ErrorCode::Gone) => {
                    return Ok(());
                }
                Ok(Err(e)) if e.is_transient() && retries < MAX_RETRIES => {
                    maybe_landed |= may_have_landed(&e);
                    retries += 1;
                    self.back_off(retries, e).await?;
                }
                Ok(Err(e)) => return Err(channel_error(e)),
            }
        }
    }

    /// Long-polls the peer's message for `phase` until it arrives or the
    /// deadline passes.
    async fn wait(&self, phase: Phase) -> Result<Vec<u8>, SessionError> {
        let mut retries = 0;
        loop {
            let now = Instant::now();
            let remaining = self.deadline.saturating_duration_since(now);
            if remaining.is_zero() {
                return Err(SessionError::TimedOut);
            }
            let wait = Duration::from_secs(remaining.as_secs().min(LONG_POLL_MAX_SECS));
            let call = self.relay.get_phase(self.channel, &self.token, phase, wait);
            match tokio::time::timeout_at(self.deadline, call).await {
                Err(_) => return Err(SessionError::TimedOut),
                Ok(Ok(Some(body))) => return Ok(body),
                Ok(Ok(None)) => {
                    retries = 0;
                    // Don't spin when the relay answers early or `wait` is 0.
                    tokio::time::sleep_until((now + MIN_POLL_GAP).min(self.deadline)).await;
                }
                Ok(Err(e)) if e.is_transient() && retries < MAX_RETRIES => {
                    retries += 1;
                    self.back_off(retries, e).await?;
                }
                Ok(Err(e)) => return Err(channel_error(e)),
            }
        }
    }

    /// Sleeps before a retry: the relay's `Retry-After`, or exponential
    /// backoff, plus jitter. Gives up if that would pass the deadline.
    async fn back_off(&self, attempt: u32, error: RelayError) -> Result<(), SessionError> {
        let base = error
            .retry_after()
            .unwrap_or(Duration::from_secs(1 << attempt.min(5)));
        let jitter = Duration::from_millis(u64::from(rng::below(500)));
        let until = Instant::now() + base + jitter;
        if until >= self.deadline {
            return Err(SessionError::Relay(error));
        }
        tokio::time::sleep_until(until).await;
        Ok(())
    }

    /// Best-effort `DELETE`. Errors (already gone, unreachable) are ignored.
    async fn close(&self, reason: DeleteReason) {
        let call = self.relay.delete_channel(self.channel, &self.token, reason);
        let _ = tokio::time::timeout(CLOSE_TIMEOUT, call).await;
    }

    /// Waits up to `max` for the peer to delete the channel; true if it did.
    /// The peer's `pake` slot stays readable until then. Transient errors
    /// don't end the wait; anything else does.
    async fn wait_for_peer_close(&self, max: Duration) -> bool {
        let until = Instant::now() + max;
        let mut interval = self.opts.poll_interval;
        loop {
            let call = self
                .relay
                .get_phase(self.channel, &self.token, Phase::Pake, Duration::ZERO);
            let mut pause = interval;
            match tokio::time::timeout_at(until, call).await {
                Ok(Ok(_)) => {}
                Ok(Err(e)) if e.is_transient() => {
                    // Respect Retry-After, with jitter, like any other retry.
                    if let Some(after) = e.retry_after() {
                        pause = after + Duration::from_millis(u64::from(rng::below(500)));
                    }
                }
                Ok(Err(e)) => return e.is(ErrorCode::Gone) || e.is(ErrorCode::NotFound),
                Err(_) => return false,
            }
            let left = until.saturating_duration_since(Instant::now());
            if left.is_zero() || pause >= left {
                return false;
            }
            tokio::time::sleep(pause).await;
            interval = (interval * 2).min(MAX_LINGER_POLL);
        }
    }
}

/// Failures after which the request may have been applied anyway.
fn may_have_landed(e: &RelayError) -> bool {
    match e {
        RelayError::Transport(_) => true,
        RelayError::Status(s) => *s >= 500,
        RelayError::Api { code, .. } => *code == ErrorCode::Internal,
        RelayError::BadResponse(_) => true,
    }
}

fn channel_error(e: RelayError) -> SessionError {
    match e.code() {
        Some(ErrorCode::Gone | ErrorCode::NotFound) => SessionError::ChannelClosed,
        Some(ErrorCode::TooLarge) => SessionError::TooLarge("a message"),
        _ => SessionError::Relay(e),
    }
}

fn open_error(e: OpenError) -> SessionError {
    match e {
        OpenError::Tampered => SessionError::Tampered,
        OpenError::Malformed => SessionError::Malformed("undecodable contents".into()),
    }
}

/// Errors after which the channel is already closed or the receiver closes it.
fn needs_close(e: &SessionError) -> bool {
    !matches!(
        e,
        SessionError::WrongCodeOrInterception
            | SessionError::ChannelClosed
            | SessionError::UnknownChannel
    )
}

enum RxState {
    Waiting(Box<PakeStart>),
    Exchanged(Box<ChannelKeys>),
    Done,
}

/// The receiving side: allocates the channel and shows the code.
pub struct ReceiverSession<'r, R: RelayApi> {
    link: Link<'r, R>,
    code: Code,
    expires_at: String,
    state: RxState,
}

impl<'r, R: RelayApi> ReceiverSession<'r, R> {
    /// Allocates a channel, generates the code and writes our SPAKE2 message.
    /// `kind` is [`CodeKind::Pairing`] for `kc pair` and `--remember`.
    pub async fn open(
        relay: &'r R,
        kind: CodeKind,
        opts: SessionOptions,
    ) -> Result<Self, SessionError> {
        let deadline = Instant::now() + opts.timeout;
        let allocated = tokio::time::timeout_at(deadline, relay.allocate())
            .await
            .map_err(|_| SessionError::TimedOut)??;
        let link = Link {
            relay,
            channel: allocated.channel,
            token: Zeroizing::new(allocated.side_token),
            deadline,
            opts,
        };
        let Ok(code) = Code::generate(allocated.channel, kind) else {
            link.close(DeleteReason::Abort).await;
            return Err(RelayError::BadResponse(format!(
                "channel number {} is out of range",
                allocated.channel
            ))
            .into());
        };
        let pake = PakeStart::new(Role::Receiver, &code);
        if let Err(e) = link.put(Phase::Pake, pake.message()).await {
            if needs_close(&e) {
                link.close(DeleteReason::Abort).await;
            }
            return Err(e);
        }
        Ok(ReceiverSession {
            link,
            code,
            expires_at: allocated.expires_at,
            state: RxState::Waiting(Box::new(pake)),
        })
    }

    /// The code to show.
    pub fn code(&self) -> &Code {
        &self.code
    }

    pub fn channel(&self) -> u16 {
        self.link.channel
    }

    /// When the relay will expire the channel (RFC 3339, as the relay sent it).
    pub fn expires_at(&self) -> &str {
        &self.expires_at
    }

    /// Waits for the sender, runs SPAKE2 and key confirmation, then receives
    /// and verifies the payload. Fails on a timeout, a wrong code, tampering
    /// or a malformed payload, and closes the channel in each case.
    pub async fn exchange(&mut self) -> Result<Received, SessionError> {
        let pake = match std::mem::replace(&mut self.state, RxState::Done) {
            RxState::Waiting(pake) => pake,
            other => {
                self.state = other;
                return Err(SessionError::Invalid(
                    "exchange() can only run once, after open()",
                ));
            }
        };
        match self.run_exchange(*pake).await {
            Ok((keys, received)) => {
                self.state = RxState::Exchanged(Box::new(keys));
                Ok(received)
            }
            Err(e) => {
                if needs_close(&e) {
                    self.link.close(DeleteReason::Abort).await;
                }
                Err(e)
            }
        }
    }

    async fn run_exchange(&self, pake: PakeStart) -> Result<(ChannelKeys, Received), SessionError> {
        let peer = self.link.wait(Phase::Pake).await?;
        let keys = pake
            .finish(&peer)
            .map_err(|_| SessionError::BadPeerMessage)?;
        self.link.put(Phase::Confirm, &keys.confirm_mac()).await?;
        let peer_mac = self.link.wait(Phase::Confirm).await?;
        if !keys.verify_peer_confirm(&peer_mac) {
            // Our MAC is already written; give the sender a moment to read
            // it so it reports the mismatch too, then close the channel.
            self.link
                .wait_for_peer_close(self.link.opts.mismatch_linger)
                .await;
            self.link.close(DeleteReason::BadConfirm).await;
            return Err(SessionError::WrongCodeOrInterception);
        }
        let body = self.link.wait(Phase::Payload).await?;
        let payload: ChannelPayload = keys.open(Phase::Payload, &body).map_err(open_error)?;
        payload
            .validate()
            .map_err(|e| SessionError::Malformed(e.to_string()))?;
        if payload.pair.is_some() && self.code.kind() != CodeKind::Pairing {
            return Err(SessionError::Malformed(
                "a pairing offer needs a pairing code".into(),
            ));
        }
        let sas = keys.sas();
        Ok((keys, Received { payload, sas }))
    }

    /// Writes the encrypted ack and waits up to `ack_linger` for the sender to
    /// read it and close the channel. `pair` is our own offer when we remember
    /// the sender (pairing codes only).
    pub async fn ack(
        &mut self,
        results: Vec<ItemResult>,
        pair: Option<PairOffer>,
    ) -> Result<(), SessionError> {
        if pair.is_some() && self.code.kind() != CodeKind::Pairing {
            return Err(SessionError::Invalid(
                "a pairing offer needs a pairing code",
            ));
        }
        let RxState::Exchanged(keys) = &self.state else {
            return Err(SessionError::Invalid(
                "ack() needs a successful exchange() first, and runs once",
            ));
        };
        let body = keys
            .seal(Phase::Ack, &ChannelAck::new(results, pair))
            .map_err(|_| SessionError::Invalid("the ack could not be encoded"))?;
        if body.len() > MAX_ACK_BYTES {
            return Err(SessionError::TooLarge("the ack (too many item results)"));
        }
        self.state = RxState::Done;
        match self.link.put_inner(Phase::Ack, &body, true).await {
            Ok(()) => {
                // The sender closes the channel once it has read the ack. If it
                // hasn't within the linger, leave the channel to its TTL rather
                // than delete an ack the sender may still be retrying to read.
                self.link
                    .wait_for_peer_close(self.link.opts.ack_linger)
                    .await;
                Ok(())
            }
            // No DELETE here either: after a lost answer the ack may have
            // landed, and the sender may still read it. The TTL cleans up.
            Err(e) => Err(e),
        }
    }

    /// Gives up: deletes the channel with `reason=abort`.
    pub async fn abort(mut self) {
        self.state = RxState::Done;
        self.link.close(DeleteReason::Abort).await;
    }
}

impl<R: RelayApi> std::fmt::Debug for ReceiverSession<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let state = match self.state {
            RxState::Waiting(_) => "waiting",
            RxState::Exchanged(_) => "exchanged",
            RxState::Done => "done",
        };
        f.debug_struct("ReceiverSession")
            .field("code", &self.code)
            .field("expires_at", &self.expires_at)
            .field("state", &state)
            .finish_non_exhaustive()
    }
}

/// The sending side: joins with the code the receiver showed.
pub struct SenderSession<'r, R: RelayApi> {
    link: Link<'r, R>,
    kind: CodeKind,
    keys: Option<Box<ChannelKeys>>,
}

impl<'r, R: RelayApi> SenderSession<'r, R> {
    /// Joins the channel, runs SPAKE2 and checks the receiver's MAC.
    ///
    /// `crowded` (someone joined first) becomes
    /// [`SessionError::PossibleInterception`]; never retry it automatically.
    pub async fn join(
        relay: &'r R,
        code: &Code,
        opts: SessionOptions,
    ) -> Result<Self, SessionError> {
        let deadline = Instant::now() + opts.timeout;
        let joined = tokio::time::timeout_at(deadline, relay.join(code.channel()))
            .await
            .map_err(|_| SessionError::TimedOut)?
            .map_err(|e| match e.code() {
                Some(ErrorCode::Crowded) => SessionError::PossibleInterception,
                Some(ErrorCode::NotFound) => SessionError::UnknownChannel,
                Some(ErrorCode::Gone) => SessionError::ChannelClosed,
                _ => SessionError::Relay(e),
            })?;
        let link = Link {
            relay,
            channel: code.channel(),
            token: Zeroizing::new(joined.side_token),
            deadline,
            opts,
        };
        let mut session = SenderSession {
            link,
            kind: code.kind(),
            keys: None,
        };
        match session.handshake(PakeStart::new(Role::Sender, code)).await {
            Ok(keys) => {
                session.keys = Some(Box::new(keys));
                Ok(session)
            }
            Err(e) => {
                // On a bad MAC the receiver closes the channel.
                if needs_close(&e) {
                    session.link.close(DeleteReason::Abort).await;
                }
                Err(e)
            }
        }
    }

    async fn handshake(&self, pake: PakeStart) -> Result<ChannelKeys, SessionError> {
        self.link.put(Phase::Pake, pake.message()).await?;
        let peer = self.link.wait(Phase::Pake).await?;
        let keys = pake
            .finish(&peer)
            .map_err(|_| SessionError::BadPeerMessage)?;
        let peer_mac = match self.confirm(&keys).await {
            Ok(mac) => mac,
            // The receiver writes its MAC before reading ours and only closes
            // the channel during confirmation when ours doesn't match (or it
            // gave up). A slow or flaky link can make us see the close first.
            Err(SessionError::ChannelClosed) => return Err(SessionError::WrongCodeOrInterception),
            Err(e) => return Err(e),
        };
        if !keys.verify_peer_confirm(&peer_mac) {
            return Err(SessionError::WrongCodeOrInterception);
        }
        Ok(keys)
    }

    async fn confirm(&self, keys: &ChannelKeys) -> Result<Vec<u8>, SessionError> {
        self.link.put(Phase::Confirm, &keys.confirm_mac()).await?;
        self.link.wait(Phase::Confirm).await
    }

    /// The 4 SAS words, for pairing codes only.
    pub fn sas(&self) -> Option<Sas> {
        self.keys.as_ref().and_then(|k| k.sas())
    }

    pub fn channel(&self) -> u16 {
        self.link.channel
    }

    /// Sends the payload and waits for the receiver's ack. Closes the channel
    /// afterwards. Can be called once.
    pub async fn send(&mut self, payload: &ChannelPayload) -> Result<ChannelAck, SessionError> {
        payload.validate().map_err(|_| {
            SessionError::Invalid("the payload has a bad version or duplicate item names")
        })?;
        if payload.pair.is_some() && self.kind != CodeKind::Pairing {
            return Err(SessionError::Invalid(
                "a pairing offer needs a pairing code",
            ));
        }
        let Some(keys) = self.keys.as_ref() else {
            return Err(SessionError::Invalid(
                "send() can only run once, after a successful join()",
            ));
        };
        let body = keys
            .seal(Phase::Payload, payload)
            .map_err(|_| SessionError::Invalid("the payload could not be encoded"))?;
        if body.len() > MAX_PAYLOAD_BYTES {
            return Err(SessionError::TooLarge("the payload"));
        }
        let keys = self.keys.take().expect("checked above");
        let result = self.deliver(&keys, &body).await;
        match &result {
            Ok(_) => self.link.close(DeleteReason::Done).await,
            Err(e) if needs_close(e) => self.link.close(DeleteReason::Abort).await,
            Err(_) => {}
        }
        result
    }

    async fn deliver(&self, keys: &ChannelKeys, body: &[u8]) -> Result<ChannelAck, SessionError> {
        self.link.put(Phase::Payload, body).await?;
        let ack_body = self.link.wait(Phase::Ack).await?;
        let ack: ChannelAck = keys.open(Phase::Ack, &ack_body).map_err(open_error)?;
        ack.validate()
            .map_err(|e| SessionError::Malformed(e.to_string()))?;
        if ack.pair.is_some() && self.kind != CodeKind::Pairing {
            return Err(SessionError::Malformed(
                "a pairing offer needs a pairing code".into(),
            ));
        }
        Ok(ack)
    }

    /// Gives up: deletes the channel with `reason=abort`.
    pub async fn abort(mut self) {
        self.keys = None;
        self.link.close(DeleteReason::Abort).await;
    }
}

impl<R: RelayApi> std::fmt::Debug for SenderSession<'_, R> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SenderSession")
            .field("channel", &self.link.channel)
            .field("kind", &self.kind)
            .field("confirmed", &self.keys.is_some())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests;

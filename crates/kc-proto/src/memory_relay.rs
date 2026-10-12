//! [`MemoryRelay`]: an in-process relay with the channel and inbox rules of
//! PROTOCOL §5, for tests. Enable it with the `test-util` feature.
//!
//! What it enforces:
//! - channels: random numbers, 600 s TTL, side tokens, a third join gets
//!   `crowded`, each role writes each phase once (`already_written`),
//!   `payload` only by the sender and `ack` only by the receiver
//!   (`wrong_role`), per-phase size caps, long-poll, `gone` for 600 s after
//!   delete or expiry and then `not_found`, the open-channel and RAM caps;
//! - inboxes: owner and writer tokens stored as SHA-256 and compared in
//!   constant time, `unauthorized` for both unknown inboxes and wrong tokens,
//!   at most 16 writers, 20 messages and 4 MiB (`inbox_full`), 256 KiB per
//!   message, 72 h expiry.
//!
//! It skips rate limits, `Kc-Proto` header checks and the inbox idle sweep.
//! Time is `tokio::time`, so paused-clock tests can fast-forward through TTLs.

use std::collections::HashMap;
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use kc_wire::limits::{
    CHANNEL_NUMBER_MAX, CHANNEL_TOMBSTONE_SECS, CHANNEL_TTL_SECS, INBOX_MAX_BYTES,
    INBOX_MAX_MESSAGES, INBOX_MAX_WRITERS, INBOX_MESSAGE_TTL_SECS, LONG_POLL_MAX_SECS,
    MAX_CHANNEL_RAM_BYTES, MAX_INBOXES, MAX_MESSAGE_BYTES, MAX_OPEN_CHANNELS,
};
use kc_wire::{
    ChannelAllocated, ChannelJoined, DeleteReason, ErrorCode, InboxCreated, InboxMessage,
    InboxMessages, MessageAccepted, Phase, Role, WriterRegister, WriterRegistered,
};
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;
use tokio::sync::Notify;
use tokio::time::Instant;

use crate::relay::{RelayApi, RelayError};
use crate::rng;

/// What a channel number currently is, for test assertions.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ChannelStatus {
    Unknown,
    Open,
    /// Deleted (with the reason) or expired (`None`).
    Gone(Option<DeleteReason>),
}

/// An in-memory relay. Clones share state.
#[derive(Clone, Default)]
pub struct MemoryRelay {
    inner: Arc<Inner>,
}

#[derive(Default)]
struct Inner {
    state: Mutex<State>,
    changed: Notify,
}

#[derive(Default)]
struct State {
    channels: HashMap<u16, Channel>,
    inboxes: HashMap<String, Inbox>,
    corrupt_next: Vec<(Role, Phase)>,
}

enum Channel {
    Open(OpenChannel),
    Tombstone {
        until: Instant,
        reason: Option<DeleteReason>,
    },
}

struct OpenChannel {
    receiver: [u8; 32],
    sender: Option<[u8; 32]>,
    expires: Instant,
    expires_at: String,
    slots: HashMap<(Role, Phase), Vec<u8>>,
}

struct Inbox {
    owner: [u8; 32],
    writers: Vec<(String, [u8; 32])>,
    messages: Vec<Stored>,
}

struct Stored {
    msg_id: String,
    writer_id: String,
    received_at: String,
    expires: Instant,
    body: Vec<u8>,
}

fn err(code: ErrorCode) -> RelayError {
    RelayError::api(code)
}

fn new_token() -> (String, [u8; 32]) {
    let raw = rng::array::<32>();
    (URL_SAFE_NO_PAD.encode(raw), Sha256::digest(raw).into())
}

fn new_id() -> String {
    URL_SAFE_NO_PAD.encode(rng::array::<16>())
}

/// SHA-256 of a bearer token's raw bytes; `None` if it isn't 32 bytes of base64url.
fn token_hash(bearer: &str) -> Option<[u8; 32]> {
    let raw = URL_SAFE_NO_PAD.decode(bearer).ok()?;
    (raw.len() == 32).then(|| Sha256::digest(&raw).into())
}

fn matches(hash: Option<[u8; 32]>, stored: &[u8; 32]) -> bool {
    hash.is_some_and(|h| bool::from(h.ct_eq(stored)))
}

fn long_poll(wait: Duration) -> Duration {
    wait.min(Duration::from_secs(LONG_POLL_MAX_SECS))
}

impl OpenChannel {
    fn role(&self, bearer: &str) -> Result<Role, RelayError> {
        let hash = token_hash(bearer);
        if matches(hash, &self.receiver) {
            Ok(Role::Receiver)
        } else if self.sender.as_ref().is_some_and(|s| matches(hash, s)) {
            Ok(Role::Sender)
        } else {
            Err(err(ErrorCode::Unauthorized))
        }
    }
}

impl State {
    /// The open channel, after applying expiry and tombstone timeouts.
    fn open_channel(&mut self, channel: u16, now: Instant) -> Result<&mut OpenChannel, RelayError> {
        let expired_at = match self.channels.get(&channel) {
            None => return Err(err(ErrorCode::NotFound)),
            Some(Channel::Tombstone { until, .. }) if now >= *until => {
                self.channels.remove(&channel);
                return Err(err(ErrorCode::NotFound));
            }
            Some(Channel::Tombstone { .. }) => return Err(err(ErrorCode::Gone)),
            Some(Channel::Open(c)) => (now >= c.expires).then_some(c.expires),
        };
        if let Some(expired_at) = expired_at {
            // The tombstone period runs from the expiry itself, not from
            // whenever the channel is next looked at.
            let until = expired_at + Duration::from_secs(CHANNEL_TOMBSTONE_SECS);
            if now >= until {
                self.channels.remove(&channel);
                return Err(err(ErrorCode::NotFound));
            }
            self.channels.insert(
                channel,
                Channel::Tombstone {
                    until,
                    reason: None,
                },
            );
            return Err(err(ErrorCode::Gone));
        }
        match self.channels.get_mut(&channel) {
            Some(Channel::Open(c)) => Ok(c),
            _ => Err(err(ErrorCode::NotFound)),
        }
    }

    fn sweep_channels(&mut self, now: Instant) {
        let numbers: Vec<u16> = self.channels.keys().copied().collect();
        for n in numbers {
            let _ = self.open_channel(n, now);
        }
    }

    fn open_channels(&self) -> usize {
        self.channels
            .values()
            .filter(|c| matches!(c, Channel::Open(_)))
            .count()
    }

    fn channel_bytes(&self) -> usize {
        self.channels
            .values()
            .map(|c| match c {
                Channel::Open(c) => c.slots.values().map(Vec::len).sum(),
                Channel::Tombstone { .. } => 0,
            })
            .sum()
    }

    fn inbox(&mut self, inbox_id: &str, owner_token: &str) -> Result<&mut Inbox, RelayError> {
        let hash = token_hash(owner_token);
        match self.inboxes.get_mut(inbox_id) {
            Some(inbox) if matches(hash, &inbox.owner) => {
                let now = Instant::now();
                inbox.messages.retain(|m| m.expires > now);
                Ok(inbox)
            }
            _ => Err(err(ErrorCode::Unauthorized)),
        }
    }
}

impl MemoryRelay {
    pub fn new() -> MemoryRelay {
        MemoryRelay::default()
    }

    fn lock(&self) -> MutexGuard<'_, State> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    /// Flips one bit in the next body written to `(role, phase)`, as a
    /// tampering relay would.
    pub fn corrupt_next_put(&self, role: Role, phase: Phase) {
        self.lock().corrupt_next.push((role, phase));
    }

    /// Makes a channel expire now.
    pub fn expire_channel(&self, channel: u16) {
        if let Some(Channel::Open(c)) = self.lock().channels.get_mut(&channel) {
            c.expires = Instant::now();
        }
        self.inner.changed.notify_waiters();
    }

    pub fn channel_status(&self, channel: u16) -> ChannelStatus {
        let mut st = self.lock();
        match st.open_channel(channel, Instant::now()) {
            Ok(_) => ChannelStatus::Open,
            Err(e) if e.is(ErrorCode::Gone) => match st.channels.get(&channel) {
                Some(Channel::Tombstone { reason, .. }) => ChannelStatus::Gone(*reason),
                _ => ChannelStatus::Gone(None),
            },
            Err(_) => ChannelStatus::Unknown,
        }
    }

    /// Number of messages waiting in an inbox (expired ones excluded).
    pub fn pending_messages(&self, inbox_id: &str) -> usize {
        let now = Instant::now();
        self.lock()
            .inboxes
            .get(inbox_id)
            .map_or(0, |i| i.messages.iter().filter(|m| m.expires > now).count())
    }

    /// Waits until `check` returns something or `wait` runs out. `check` sees
    /// the locked state; registering for wake-ups first avoids lost wake-ups.
    async fn wait_for<T>(
        &self,
        wait: Duration,
        mut check: impl FnMut(&mut State, Instant) -> Result<Option<T>, RelayError>,
    ) -> Result<Option<T>, RelayError> {
        let deadline = Instant::now() + long_poll(wait);
        loop {
            let notified = self.inner.changed.notified();
            tokio::pin!(notified);
            notified.as_mut().enable();
            if let Some(v) = check(&mut self.lock(), Instant::now())? {
                return Ok(Some(v));
            }
            let wake = {
                // Also wake when a channel expires, to answer 410 promptly.
                let st = self.lock();
                st.channels
                    .values()
                    .filter_map(|c| match c {
                        Channel::Open(c) => Some(c.expires),
                        Channel::Tombstone { .. } => None,
                    })
                    .filter(|e| *e > Instant::now())
                    .min()
                    .map_or(deadline, |e| e.min(deadline))
            };
            if tokio::time::timeout_at(wake, notified).await.is_err() && Instant::now() >= deadline
            {
                // One last look, so a channel or inbox that went away while
                // we waited answers with its error rather than "nothing yet".
                return check(&mut self.lock(), Instant::now());
            }
        }
    }
}

impl RelayApi for MemoryRelay {
    async fn allocate(&self) -> Result<ChannelAllocated, RelayError> {
        let now = Instant::now();
        let mut st = self.lock();
        st.sweep_channels(now);
        if st.open_channels() >= MAX_OPEN_CHANNELS
            || st.channels.len() >= usize::from(CHANNEL_NUMBER_MAX)
        {
            return Err(RelayError::Api {
                code: ErrorCode::Capacity,
                retry_after_s: Some(30),
            });
        }
        let channel = loop {
            let n =
                u16::try_from(rng::below(u32::from(CHANNEL_NUMBER_MAX)) + 1).expect("fits in u16");
            if !st.channels.contains_key(&n) {
                break n;
            }
        };
        let (side_token, receiver) = new_token();
        let expires_at = rfc3339(SystemTime::now() + Duration::from_secs(CHANNEL_TTL_SECS));
        st.channels.insert(
            channel,
            Channel::Open(OpenChannel {
                receiver,
                sender: None,
                expires: now + Duration::from_secs(CHANNEL_TTL_SECS),
                expires_at: expires_at.clone(),
                slots: HashMap::new(),
            }),
        );
        Ok(ChannelAllocated {
            channel,
            side_token,
            expires_at,
        })
    }

    async fn join(&self, channel: u16) -> Result<ChannelJoined, RelayError> {
        let mut st = self.lock();
        let c = st.open_channel(channel, Instant::now())?;
        if c.sender.is_some() {
            return Err(err(ErrorCode::Crowded));
        }
        let (side_token, sender) = new_token();
        c.sender = Some(sender);
        Ok(ChannelJoined {
            side_token,
            expires_at: c.expires_at.clone(),
        })
    }

    async fn put_phase(
        &self,
        channel: u16,
        side_token: &str,
        phase: Phase,
        body: &[u8],
    ) -> Result<(), RelayError> {
        {
            let mut st = self.lock();
            let now = Instant::now();
            // Expired channels no longer count against the RAM cap.
            st.sweep_channels(now);
            let total = st.channel_bytes();
            let role = {
                let c = st.open_channel(channel, now)?;
                let role = c.role(side_token)?;
                if !phase.writable_by(role) {
                    return Err(err(ErrorCode::WrongRole));
                }
                if body.len() > phase.max_bytes() {
                    return Err(err(ErrorCode::TooLarge));
                }
                if c.slots.contains_key(&(role, phase)) {
                    return Err(err(ErrorCode::AlreadyWritten));
                }
                role
            };
            if total + body.len() > MAX_CHANNEL_RAM_BYTES {
                return Err(RelayError::Api {
                    code: ErrorCode::Capacity,
                    retry_after_s: Some(30),
                });
            }
            let mut stored = body.to_vec();
            if let Some(i) = st.corrupt_next.iter().position(|f| *f == (role, phase)) {
                st.corrupt_next.remove(i);
                if let Some(last) = stored.last_mut() {
                    *last ^= 0x01;
                }
            }
            st.open_channel(channel, now)?
                .slots
                .insert((role, phase), stored);
        }
        self.inner.changed.notify_waiters();
        Ok(())
    }

    async fn get_phase(
        &self,
        channel: u16,
        side_token: &str,
        phase: Phase,
        wait: Duration,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        self.wait_for(wait, |st, now| {
            let c = st.open_channel(channel, now)?;
            let role = c.role(side_token)?;
            Ok(c.slots.get(&(role.peer(), phase)).cloned())
        })
        .await
    }

    async fn delete_channel(
        &self,
        channel: u16,
        side_token: &str,
        reason: DeleteReason,
    ) -> Result<(), RelayError> {
        {
            let mut st = self.lock();
            let now = Instant::now();
            st.open_channel(channel, now)?.role(side_token)?;
            let until = now + Duration::from_secs(CHANNEL_TOMBSTONE_SECS);
            st.channels.insert(
                channel,
                Channel::Tombstone {
                    until,
                    reason: Some(reason),
                },
            );
        }
        self.inner.changed.notify_waiters();
        Ok(())
    }

    async fn create_inbox(&self) -> Result<InboxCreated, RelayError> {
        let mut st = self.lock();
        if st.inboxes.len() >= MAX_INBOXES {
            return Err(RelayError::Api {
                code: ErrorCode::Capacity,
                retry_after_s: Some(3600),
            });
        }
        let inbox_id = new_id();
        let (owner_token, owner) = new_token();
        st.inboxes.insert(
            inbox_id.clone(),
            Inbox {
                owner,
                writers: Vec::new(),
                messages: Vec::new(),
            },
        );
        Ok(InboxCreated {
            inbox_id,
            owner_token,
        })
    }

    async fn register_writer(
        &self,
        inbox_id: &str,
        owner_token: &str,
        request: &WriterRegister,
    ) -> Result<WriterRegistered, RelayError> {
        let mut st = self.lock();
        let inbox = st.inbox(inbox_id, owner_token)?;
        let hash: [u8; 32] = URL_SAFE_NO_PAD
            .decode(&request.writer_token_sha256)
            .ok()
            .and_then(|h| h.try_into().ok())
            .ok_or_else(|| err(ErrorCode::BadRequest))?;
        if inbox.writers.len() >= INBOX_MAX_WRITERS {
            return Err(err(ErrorCode::InboxFull));
        }
        let writer_id = new_id();
        inbox.writers.push((writer_id.clone(), hash));
        Ok(WriterRegistered { writer_id })
    }

    async fn delete_writer(
        &self,
        inbox_id: &str,
        owner_token: &str,
        writer_id: &str,
    ) -> Result<(), RelayError> {
        let mut st = self.lock();
        let inbox = st.inbox(inbox_id, owner_token)?;
        let before = inbox.writers.len();
        inbox.writers.retain(|(id, _)| id != writer_id);
        if inbox.writers.len() == before {
            Err(err(ErrorCode::NotFound))
        } else {
            Ok(())
        }
    }

    async fn post_message(
        &self,
        inbox_id: &str,
        writer_token: &str,
        body: &[u8],
    ) -> Result<MessageAccepted, RelayError> {
        let msg_id = {
            let mut st = self.lock();
            let hash = token_hash(writer_token);
            let now = Instant::now();
            let inbox = st
                .inboxes
                .get_mut(inbox_id)
                .ok_or_else(|| err(ErrorCode::Unauthorized))?;
            let writer_id = inbox
                .writers
                .iter()
                .find(|(_, h)| matches(hash, h))
                .map(|(id, _)| id.clone())
                .ok_or_else(|| err(ErrorCode::Unauthorized))?;
            if body.len() > MAX_MESSAGE_BYTES {
                return Err(err(ErrorCode::TooLarge));
            }
            inbox.messages.retain(|m| m.expires > now);
            let bytes: usize = inbox.messages.iter().map(|m| m.body.len()).sum();
            if inbox.messages.len() >= INBOX_MAX_MESSAGES || bytes + body.len() > INBOX_MAX_BYTES {
                return Err(err(ErrorCode::InboxFull));
            }
            let msg_id = new_id();
            inbox.messages.push(Stored {
                msg_id: msg_id.clone(),
                writer_id,
                received_at: rfc3339(SystemTime::now()),
                expires: now + Duration::from_secs(INBOX_MESSAGE_TTL_SECS),
                body: body.to_vec(),
            });
            msg_id
        };
        self.inner.changed.notify_waiters();
        Ok(MessageAccepted { msg_id })
    }

    async fn list_messages(
        &self,
        inbox_id: &str,
        owner_token: &str,
        wait: Duration,
    ) -> Result<InboxMessages, RelayError> {
        let listed = self
            .wait_for(wait, |st, _| {
                let inbox = st.inbox(inbox_id, owner_token)?;
                Ok((!inbox.messages.is_empty()).then(|| {
                    inbox
                        .messages
                        .iter()
                        .map(|m| InboxMessage {
                            msg_id: m.msg_id.clone(),
                            writer_id: m.writer_id.clone(),
                            received_at: m.received_at.clone(),
                            body_b64: URL_SAFE_NO_PAD.encode(&m.body),
                        })
                        .collect()
                }))
            })
            .await?;
        Ok(InboxMessages {
            messages: listed.unwrap_or_default(),
        })
    }

    async fn delete_message(
        &self,
        inbox_id: &str,
        owner_token: &str,
        msg_id: &str,
    ) -> Result<(), RelayError> {
        let mut st = self.lock();
        let inbox = st.inbox(inbox_id, owner_token)?;
        let before = inbox.messages.len();
        inbox.messages.retain(|m| m.msg_id != msg_id);
        if inbox.messages.len() == before {
            Err(err(ErrorCode::NotFound))
        } else {
            Ok(())
        }
    }

    async fn delete_inbox(&self, inbox_id: &str, owner_token: &str) -> Result<(), RelayError> {
        {
            let mut st = self.lock();
            st.inbox(inbox_id, owner_token)?;
            st.inboxes.remove(inbox_id);
        }
        // Waiting readers recheck and get 401 for the unknown inbox.
        self.inner.changed.notify_waiters();
        Ok(())
    }
}

/// RFC 3339 UTC with second precision, e.g. `2025-10-09T08:53:20Z`.
fn rfc3339(t: SystemTime) -> String {
    let secs = t.duration_since(UNIX_EPOCH).map_or(0, |d| d.as_secs());
    let secs = i64::try_from(secs).unwrap_or(i64::MAX);
    let (days, sod) = (secs.div_euclid(86_400), secs.rem_euclid(86_400));
    // Howard Hinnant's civil_from_days.
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z.rem_euclid(146_097);
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02}T{:02}:{:02}:{:02}Z",
        sod / 3600,
        sod % 3600 / 60,
        sod % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::WriterToken;

    const W0: Duration = Duration::ZERO;

    #[test]
    fn rfc3339_formatting() {
        let at = |s: u64| rfc3339(UNIX_EPOCH + Duration::from_secs(s));
        assert_eq!(at(0), "1970-01-01T00:00:00Z");
        assert_eq!(at(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(at(1_760_000_000), "2025-10-09T08:53:20Z");
        assert_eq!(at(4_102_444_799), "2099-12-31T23:59:59Z");
    }

    #[tokio::test]
    async fn channel_rules() {
        let relay = MemoryRelay::new();
        let alloc = relay.allocate().await.unwrap();
        let c = alloc.channel;
        assert!((1..=CHANNEL_NUMBER_MAX).contains(&c));
        let r = alloc.side_token;
        let s = relay.join(c).await.unwrap().side_token;
        assert!(relay.join(c).await.unwrap_err().is(ErrorCode::Crowded));

        relay
            .put_phase(c, &r, Phase::Pake, b"from r")
            .await
            .unwrap();
        assert!(
            relay
                .put_phase(c, &r, Phase::Pake, b"again")
                .await
                .unwrap_err()
                .is(ErrorCode::AlreadyWritten)
        );
        assert!(
            relay
                .put_phase(c, &r, Phase::Payload, b"x")
                .await
                .unwrap_err()
                .is(ErrorCode::WrongRole)
        );
        assert!(
            relay
                .put_phase(c, &s, Phase::Ack, b"x")
                .await
                .unwrap_err()
                .is(ErrorCode::WrongRole)
        );
        let big = vec![0u8; Phase::Pake.max_bytes() + 1];
        assert!(
            relay
                .put_phase(c, &s, Phase::Pake, &big)
                .await
                .unwrap_err()
                .is(ErrorCode::TooLarge)
        );
        let (stranger, _) = new_token();
        assert!(
            relay
                .put_phase(c, &stranger, Phase::Pake, b"x")
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );
        assert!(
            relay
                .put_phase(c, "not base64!", Phase::Pake, b"x")
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );

        // Each side reads the peer's slot.
        assert_eq!(
            relay
                .get_phase(c, &s, Phase::Pake, W0)
                .await
                .unwrap()
                .as_deref(),
            Some(&b"from r"[..])
        );
        assert_eq!(relay.get_phase(c, &r, Phase::Pake, W0).await.unwrap(), None);

        relay
            .delete_channel(c, &s, DeleteReason::Done)
            .await
            .unwrap();
        assert_eq!(
            relay.channel_status(c),
            ChannelStatus::Gone(Some(DeleteReason::Done))
        );
        assert!(
            relay
                .get_phase(c, &r, Phase::Pake, W0)
                .await
                .unwrap_err()
                .is(ErrorCode::Gone)
        );
        assert!(relay.join(c).await.unwrap_err().is(ErrorCode::Gone));
        assert!(relay.join(c.wrapping_add(1).max(1)).await.is_err());
    }

    #[tokio::test(start_paused = true)]
    async fn long_poll_expiry_and_tombstones() {
        let relay = MemoryRelay::new();
        let alloc = relay.allocate().await.unwrap();
        let (c, r) = (alloc.channel, alloc.side_token);
        let s = relay.join(c).await.unwrap().side_token;

        // A waiting reader is woken by the write.
        let writer = {
            let relay = relay.clone();
            let s = s.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(3)).await;
                relay
                    .put_phase(c, &s, Phase::Confirm, b"mac")
                    .await
                    .unwrap();
            })
        };
        let started = Instant::now();
        let got = relay
            .get_phase(c, &r, Phase::Confirm, Duration::from_secs(25))
            .await
            .unwrap();
        assert_eq!(got.as_deref(), Some(&b"mac"[..]));
        assert_eq!(started.elapsed().as_secs(), 3);
        writer.await.unwrap();

        // An empty slot answers None after the wait, capped at 25 s.
        let started = Instant::now();
        assert_eq!(
            relay
                .get_phase(c, &r, Phase::Payload, Duration::from_secs(60))
                .await
                .unwrap(),
            None
        );
        assert_eq!(started.elapsed().as_secs(), LONG_POLL_MAX_SECS);

        // Expiry: 410 for the tombstone period, then 404.
        tokio::time::advance(Duration::from_secs(CHANNEL_TTL_SECS)).await;
        assert!(
            relay
                .get_phase(c, &r, Phase::Pake, W0)
                .await
                .unwrap_err()
                .is(ErrorCode::Gone)
        );
        assert_eq!(relay.channel_status(c), ChannelStatus::Gone(None));
        tokio::time::advance(Duration::from_secs(CHANNEL_TOMBSTONE_SECS)).await;
        assert!(
            relay
                .get_phase(c, &r, Phase::Pake, W0)
                .await
                .unwrap_err()
                .is(ErrorCode::NotFound)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn tombstones_run_from_the_expiry_time() {
        let relay = MemoryRelay::new();
        let alloc = relay.allocate().await.unwrap();
        // Nobody touches the channel until both periods are over.
        tokio::time::advance(Duration::from_secs(
            CHANNEL_TTL_SECS + CHANNEL_TOMBSTONE_SECS + 1,
        ))
        .await;
        assert_eq!(relay.channel_status(alloc.channel), ChannelStatus::Unknown);
        assert!(
            relay
                .join(alloc.channel)
                .await
                .unwrap_err()
                .is(ErrorCode::NotFound)
        );
    }

    #[tokio::test(start_paused = true)]
    async fn expired_channels_free_the_ram_budget() {
        let relay = MemoryRelay::new();
        let big = vec![0u8; Phase::Payload.max_bytes()];
        let per_channel = big.len();
        let mut filled = 0;
        while filled + per_channel <= MAX_CHANNEL_RAM_BYTES {
            let alloc = relay.allocate().await.unwrap();
            let s = relay.join(alloc.channel).await.unwrap().side_token;
            relay
                .put_phase(alloc.channel, &s, Phase::Payload, &big)
                .await
                .unwrap();
            filled += per_channel;
        }
        let alloc = relay.allocate().await.unwrap();
        let s = relay.join(alloc.channel).await.unwrap().side_token;
        let full = relay
            .put_phase(alloc.channel, &s, Phase::Payload, &big)
            .await
            .unwrap_err();
        assert!(full.is(ErrorCode::Capacity));

        tokio::time::advance(Duration::from_secs(CHANNEL_TTL_SECS - 1)).await;
        let fresh = relay.allocate().await.unwrap();
        tokio::time::advance(Duration::from_secs(1)).await; // the old ones expire
        let s = relay.join(fresh.channel).await.unwrap().side_token;
        relay
            .put_phase(fresh.channel, &s, Phase::Payload, &big)
            .await
            .unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn delete_wakes_waiters_with_gone() {
        let relay = MemoryRelay::new();
        let alloc = relay.allocate().await.unwrap();
        let (c, r) = (alloc.channel, alloc.side_token);
        let s = relay.join(c).await.unwrap().side_token;
        let deleter = {
            let relay = relay.clone();
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                relay
                    .delete_channel(c, &s, DeleteReason::Abort)
                    .await
                    .unwrap();
            })
        };
        let err = relay
            .get_phase(c, &r, Phase::Payload, Duration::from_secs(25))
            .await
            .unwrap_err();
        assert!(err.is(ErrorCode::Gone));
        deleter.await.unwrap();
    }

    #[tokio::test]
    async fn inbox_rules() {
        let relay = MemoryRelay::new();
        let inbox = relay.create_inbox().await.unwrap();
        let (id, owner) = (inbox.inbox_id, inbox.owner_token);
        let token = WriterToken::generate();
        let writer = relay
            .register_writer(&id, &owner, &token.registration())
            .await
            .unwrap();

        let (wrong, _) = new_token();
        assert!(
            relay
                .register_writer(&id, &wrong, &token.registration())
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );
        assert!(
            relay
                .list_messages("nope", &owner, W0)
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );
        assert!(
            relay
                .post_message(&id, &wrong, b"x")
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );
        assert!(
            relay
                .post_message("nope", &token.bearer(), b"x")
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );
        // The owner token isn't a writer token.
        assert!(
            relay
                .post_message(&id, &owner, b"x")
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );

        let accepted = relay
            .post_message(&id, &token.bearer(), b"hello")
            .await
            .unwrap();
        let listed = relay.list_messages(&id, &owner, W0).await.unwrap();
        assert_eq!(listed.messages.len(), 1);
        assert_eq!(listed.messages[0].writer_id, writer.writer_id);
        assert_eq!(
            crate::relay::message_body(&listed.messages[0]).unwrap(),
            b"hello"
        );
        relay
            .delete_message(&id, &owner, &accepted.msg_id)
            .await
            .unwrap();
        assert!(
            relay
                .delete_message(&id, &owner, &accepted.msg_id)
                .await
                .unwrap_err()
                .is(ErrorCode::NotFound)
        );

        let too_big = vec![0u8; MAX_MESSAGE_BYTES + 1];
        assert!(
            relay
                .post_message(&id, &token.bearer(), &too_big)
                .await
                .unwrap_err()
                .is(ErrorCode::TooLarge)
        );
        for _ in 0..INBOX_MAX_MESSAGES {
            relay
                .post_message(&id, &token.bearer(), b"m")
                .await
                .unwrap();
        }
        assert!(
            relay
                .post_message(&id, &token.bearer(), b"m")
                .await
                .unwrap_err()
                .is(ErrorCode::InboxFull)
        );

        relay
            .delete_writer(&id, &owner, &writer.writer_id)
            .await
            .unwrap();
        assert!(
            relay
                .post_message(&id, &token.bearer(), b"m")
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );
        for _ in 0..INBOX_MAX_WRITERS {
            relay
                .register_writer(&id, &owner, &WriterToken::generate().registration())
                .await
                .unwrap();
        }
        let extra = relay
            .register_writer(&id, &owner, &WriterToken::generate().registration())
            .await;
        assert!(extra.unwrap_err().is(ErrorCode::InboxFull));
        let bad = WriterRegister {
            writer_token_sha256: "short".into(),
        };
        assert!(
            relay
                .register_writer(&id, &owner, &bad)
                .await
                .unwrap_err()
                .is(ErrorCode::BadRequest)
        );

        relay.delete_inbox(&id, &owner).await.unwrap();
        assert!(
            relay
                .list_messages(&id, &owner, W0)
                .await
                .unwrap_err()
                .is(ErrorCode::Unauthorized)
        );
    }

    #[tokio::test]
    async fn inbox_byte_cap() {
        let relay = MemoryRelay::new();
        let inbox = relay.create_inbox().await.unwrap();
        let token = WriterToken::generate();
        relay
            .register_writer(&inbox.inbox_id, &inbox.owner_token, &token.registration())
            .await
            .unwrap();
        let body = vec![0u8; MAX_MESSAGE_BYTES];
        for _ in 0..(INBOX_MAX_BYTES / MAX_MESSAGE_BYTES) {
            relay
                .post_message(&inbox.inbox_id, &token.bearer(), &body)
                .await
                .unwrap();
        }
        let full = relay
            .post_message(&inbox.inbox_id, &token.bearer(), b"x")
            .await;
        assert!(full.unwrap_err().is(ErrorCode::InboxFull));
    }

    #[tokio::test(start_paused = true)]
    async fn deleting_an_inbox_ends_pending_reads_with_401() {
        let relay = MemoryRelay::new();
        let inbox = relay.create_inbox().await.unwrap();
        let deleter = {
            let (relay, id, owner) = (
                relay.clone(),
                inbox.inbox_id.clone(),
                inbox.owner_token.clone(),
            );
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(1)).await;
                relay.delete_inbox(&id, &owner).await.unwrap();
            })
        };
        let started = Instant::now();
        let read = relay
            .list_messages(&inbox.inbox_id, &inbox.owner_token, Duration::from_secs(25))
            .await;
        assert!(read.unwrap_err().is(ErrorCode::Unauthorized));
        assert_eq!(started.elapsed().as_secs(), 1);
        deleter.await.unwrap();
    }

    #[tokio::test(start_paused = true)]
    async fn inbox_long_poll_and_expiry() {
        let relay = MemoryRelay::new();
        let inbox = relay.create_inbox().await.unwrap();
        let token = WriterToken::generate();
        relay
            .register_writer(&inbox.inbox_id, &inbox.owner_token, &token.registration())
            .await
            .unwrap();
        let poster = {
            let (relay, id, bearer) = (
                relay.clone(),
                inbox.inbox_id.clone(),
                token.bearer().to_string(),
            );
            tokio::spawn(async move {
                tokio::time::sleep(Duration::from_secs(2)).await;
                relay.post_message(&id, &bearer, b"late").await.unwrap();
            })
        };
        let listed = relay
            .list_messages(&inbox.inbox_id, &inbox.owner_token, Duration::from_secs(25))
            .await
            .unwrap();
        assert_eq!(listed.messages.len(), 1);
        poster.await.unwrap();
        tokio::time::advance(Duration::from_secs(INBOX_MESSAGE_TTL_SECS)).await;
        assert_eq!(relay.pending_messages(&inbox.inbox_id), 0);
        let listed = relay
            .list_messages(&inbox.inbox_id, &inbox.owner_token, W0)
            .await
            .unwrap();
        assert!(listed.messages.is_empty());
    }

    #[tokio::test]
    async fn corrupt_next_put_flips_a_bit_once() {
        let relay = MemoryRelay::new();
        let alloc = relay.allocate().await.unwrap();
        let (c, r) = (alloc.channel, alloc.side_token);
        let s = relay.join(c).await.unwrap().side_token;
        relay.corrupt_next_put(Role::Sender, Phase::Pake);
        relay.put_phase(c, &s, Phase::Pake, &[0, 0]).await.unwrap();
        assert_eq!(
            relay.get_phase(c, &r, Phase::Pake, W0).await.unwrap(),
            Some(vec![0, 1])
        );
        relay
            .put_phase(c, &s, Phase::Confirm, &[0, 0])
            .await
            .unwrap();
        assert_eq!(
            relay.get_phase(c, &r, Phase::Confirm, W0).await.unwrap(),
            Some(vec![0, 0])
        );
    }
}

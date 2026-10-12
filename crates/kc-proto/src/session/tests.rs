//! End-to-end channel sessions over `MemoryRelay`. The clock is paused, so
//! timeouts and lingering run instantly.

use std::sync::atomic::{AtomicU32, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};

use kc_wire::exit;
use kc_wire::{
    ChannelAllocated, ChannelJoined, InboxCreated, InboxMessages, MessageAccepted, WriterRegister,
    WriterRegistered,
};

use super::*;
use crate::device::DeviceKeyPair;
use crate::memory_relay::{ChannelStatus, MemoryRelay};
use crate::names::{ItemName, Label};
use crate::payload::{InboxId, Item, ItemStatus, WriterToken};
use crate::secret::SecretBytes;

fn item(name: &str, value: &[u8]) -> Item {
    Item {
        name: ItemName::new(name).unwrap(),
        value: SecretBytes::from_slice(value),
        updated_at: 1_760_000_000,
    }
}

fn offer(label: &str) -> PairOffer {
    PairOffer {
        suggested_label: Label::new(label).unwrap(),
        device_pk: *DeviceKeyPair::generate().public(),
        inbox_id: InboxId([4; 16]),
        writer_token: WriterToken::generate(),
    }
}

fn opts() -> SessionOptions {
    SessionOptions::default()
}

fn stored(payload: &ChannelPayload) -> Vec<ItemResult> {
    payload
        .items
        .iter()
        .map(|i| ItemResult {
            name: i.name.clone(),
            status: ItemStatus::Stored,
        })
        .collect()
}

/// What a person would type after reading the receiver's screen.
fn typed(rx: &ReceiverSession<'_, impl RelayApi>) -> Code {
    Code::parse(&rx.code().to_string().to_uppercase().replace('-', " ")).unwrap()
}

/// A code for the same channel with a different first word.
fn wrong_code(rx: &ReceiverSession<'_, impl RelayApi>) -> Code {
    let words = rx.code().words();
    let first = if words[0] == "aardvark" {
        "absurd"
    } else {
        "aardvark"
    };
    let rest = words[1..].join("-");
    Code::parse(&format!("{}-{first}-{rest}", rx.channel())).unwrap()
}

async fn receive_and_ack<R: RelayApi>(
    rx: &mut ReceiverSession<'_, R>,
    pair: Option<PairOffer>,
) -> Result<Received, SessionError> {
    let received = rx.exchange().await?;
    rx.ack(stored(&received.payload), pair).await?;
    Ok(received)
}

async fn join_and_send<R: RelayApi>(
    relay: &R,
    code: &Code,
    payload: &ChannelPayload,
) -> Result<ChannelAck, SessionError> {
    let mut tx = SenderSession::join(relay, code, opts()).await?;
    tx.send(payload).await
}

#[tokio::test(start_paused = true)]
async fn transfer_succeeds_and_closes_the_channel() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    assert_eq!((code.kind(), code.words().len()), (CodeKind::Transfer, 2));
    let channel = rx.channel();
    let payload = ChannelPayload::new(
        vec![
            item("GITHUB_TOKEN", b"ghp_123"),
            item("app.env", b"A=1\nB=2\n"),
        ],
        None,
    );

    let (received, ack) = tokio::join!(
        receive_and_ack(&mut rx, None),
        join_and_send(&relay, &code, &payload)
    );
    let (received, ack) = (received.unwrap(), ack.unwrap());
    assert_eq!(received.payload, payload);
    assert!(received.sas.is_none());
    assert_eq!(ack.results, stored(&payload));
    assert!(ack.pair.is_none());
    assert_eq!(
        relay.channel_status(channel),
        ChannelStatus::Gone(Some(DeleteReason::Done))
    );
}

#[tokio::test(start_paused = true)]
async fn pairing_shows_the_same_sas_and_swaps_offers() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Pairing, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    assert_eq!(code.words().len(), 3);
    let (r_offer, s_offer) = (offer("work-mac"), offer("omarchy"));

    let receiver = async {
        let received = rx.exchange().await?;
        rx.ack(vec![], Some(r_offer.clone())).await?;
        Ok::<_, SessionError>(received)
    };
    let sender = async {
        let mut tx = SenderSession::join(&relay, &code, opts()).await?;
        let sas = tx.sas().expect("pairing codes have a SAS");
        let ack = tx
            .send(&ChannelPayload::new(vec![], Some(s_offer.clone())))
            .await?;
        Ok::<_, SessionError>((ack, sas))
    };
    let (received, sent) = tokio::join!(receiver, sender);
    let (received, (ack, s_sas)) = (received.unwrap(), sent.unwrap());
    assert_eq!(received.sas, Some(s_sas));
    assert_eq!(received.payload.pair, Some(s_offer));
    assert_eq!(ack.pair, Some(r_offer));
}

#[tokio::test(start_paused = true)]
async fn wrong_code_fails_on_both_sides_and_the_receiver_closes() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let (channel, wrong) = (rx.channel(), wrong_code(&rx));
    let (r, s) = tokio::join!(rx.exchange(), SenderSession::join(&relay, &wrong, opts()));
    let (r, s) = (r.unwrap_err(), s.unwrap_err());
    assert!(matches!(r, SessionError::WrongCodeOrInterception), "{r:?}");
    assert!(matches!(s, SessionError::WrongCodeOrInterception), "{s:?}");
    assert_eq!(
        (r.exit_code(), s.exit_code()),
        (exit::AUTH_FAILED, exit::AUTH_FAILED)
    );
    assert_eq!(
        relay.channel_status(channel),
        ChannelStatus::Gone(Some(DeleteReason::BadConfirm))
    );
}

#[tokio::test(start_paused = true)]
async fn a_guess_burns_the_code() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let (real, guess) = (typed(&rx), wrong_code(&rx));
    let (r, attacker) = tokio::join!(rx.exchange(), SenderSession::join(&relay, &guess, opts()));
    assert!(matches!(
        r.unwrap_err(),
        SessionError::WrongCodeOrInterception
    ));
    assert!(matches!(
        attacker.unwrap_err(),
        SessionError::WrongCodeOrInterception
    ));
    // The real sender comes too late: the channel is closed.
    let late = SenderSession::join(&relay, &real, opts())
        .await
        .unwrap_err();
    assert!(matches!(late, SessionError::ChannelClosed), "{late:?}");
}

#[tokio::test(start_paused = true)]
async fn crowded_join_is_possible_interception() {
    let relay = MemoryRelay::new();
    let rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    relay.join(code.channel()).await.unwrap(); // someone else got there first
    let err = SenderSession::join(&relay, &code, opts())
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::PossibleInterception), "{err:?}");
    assert_eq!(err.exit_code(), exit::AUTH_FAILED);
}

#[tokio::test(start_paused = true)]
async fn tampered_payload_is_rejected() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let (code, channel) = (typed(&rx), rx.channel());
    relay.corrupt_next_put(Role::Sender, Phase::Payload);
    let payload = ChannelPayload::new(vec![item("K", b"v")], None);
    let (r, s) = tokio::join!(rx.exchange(), join_and_send(&relay, &code, &payload));
    let r = r.unwrap_err();
    assert!(matches!(r, SessionError::Tampered), "{r:?}");
    assert_eq!(r.exit_code(), exit::AUTH_FAILED);
    assert!(matches!(s.unwrap_err(), SessionError::ChannelClosed));
    assert_eq!(
        relay.channel_status(channel),
        ChannelStatus::Gone(Some(DeleteReason::Abort))
    );
}

#[tokio::test(start_paused = true)]
async fn tampered_ack_is_rejected() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    relay.corrupt_next_put(Role::Receiver, Phase::Ack);
    let payload = ChannelPayload::new(vec![item("K", b"v")], None);
    let (r, s) = tokio::join!(
        receive_and_ack(&mut rx, None),
        join_and_send(&relay, &code, &payload)
    );
    assert!(r.is_ok(), "the receiver can't tell: {r:?}");
    assert!(matches!(s.unwrap_err(), SessionError::Tampered));
}

#[tokio::test(start_paused = true)]
async fn tampered_confirm_or_pake_never_reaches_the_payload() {
    for phase in [Phase::Confirm, Phase::Pake] {
        let relay = MemoryRelay::new();
        let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
            .await
            .unwrap();
        let code = typed(&rx);
        relay.corrupt_next_put(Role::Sender, phase);
        let payload = ChannelPayload::new(vec![item("K", b"v")], None);
        let (r, s) = tokio::join!(rx.exchange(), join_and_send(&relay, &code, &payload));
        let r = r.unwrap_err();
        assert!(
            matches!(
                r,
                SessionError::WrongCodeOrInterception | SessionError::BadPeerMessage
            ),
            "{phase:?}: {r:?}"
        );
        assert!(s.is_err(), "{phase:?}");
    }
}

#[tokio::test(start_paused = true)]
async fn receiver_times_out_when_nobody_joins() {
    let relay = MemoryRelay::new();
    let short = SessionOptions {
        timeout: Duration::from_secs(30),
        ..opts()
    };
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, short)
        .await
        .unwrap();
    let started = Instant::now();
    let err = rx.exchange().await.unwrap_err();
    assert!(matches!(err, SessionError::TimedOut), "{err:?}");
    assert_eq!(err.exit_code(), exit::EXPIRED);
    assert!(started.elapsed() <= Duration::from_secs(31));
    assert_eq!(
        relay.channel_status(rx.channel()),
        ChannelStatus::Gone(Some(DeleteReason::Abort))
    );
}

#[tokio::test(start_paused = true)]
async fn sender_times_out_without_an_ack() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    let short = SessionOptions {
        timeout: Duration::from_secs(60),
        ..opts()
    };
    let sender = async {
        let mut tx = SenderSession::join(&relay, &code, short).await?;
        tx.send(&ChannelPayload::new(vec![item("K", b"v")], None))
            .await
    };
    // The receiver gets the payload but never acks (a person who walked away).
    let (r, s) = tokio::join!(rx.exchange(), sender);
    assert!(r.is_ok());
    assert!(matches!(s.unwrap_err(), SessionError::TimedOut));
}

#[tokio::test(start_paused = true)]
async fn expired_and_unknown_channels() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    relay.expire_channel(rx.channel());
    let err = SenderSession::join(&relay, &code, opts())
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::ChannelClosed), "{err:?}");
    assert!(matches!(
        rx.exchange().await.unwrap_err(),
        SessionError::ChannelClosed
    ));

    let nobody = Code::parse(&format!(
        "{}-absurd-amulet",
        if code.channel() == 1 { 2 } else { 1 }
    ))
    .unwrap();
    let err = SenderSession::join(&relay, &nobody, opts())
        .await
        .unwrap_err();
    assert!(matches!(err, SessionError::UnknownChannel), "{err:?}");
    assert_eq!(err.exit_code(), exit::EXPIRED);
}

#[tokio::test(start_paused = true)]
async fn pairing_offers_need_a_pairing_code() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    let sender = async {
        let mut tx = SenderSession::join(&relay, &code, opts()).await?;
        // The sender API refuses, and the session stays usable.
        let refused = tx
            .send(&ChannelPayload::new(vec![], Some(offer("pc"))))
            .await
            .unwrap_err();
        assert!(matches!(refused, SessionError::Invalid(_)), "{refused:?}");
        tx.send(&ChannelPayload::new(vec![item("K", b"v")], None))
            .await
    };
    let receiver = async {
        rx.exchange().await?;
        let refused = rx.ack(vec![], Some(offer("mac"))).await.unwrap_err();
        assert!(matches!(refused, SessionError::Invalid(_)), "{refused:?}");
        rx.ack(vec![], None).await
    };
    let (r, s) = tokio::join!(receiver, sender);
    r.unwrap();
    s.unwrap();
}

/// A sender that follows the protocol by hand, to send what `SenderSession` won't.
async fn raw_sender(
    relay: &MemoryRelay,
    code: &Code,
    payload: &ChannelPayload,
) -> (ChannelKeys, String) {
    let token = relay.join(code.channel()).await.unwrap().side_token;
    let pake = PakeStart::new(Role::Sender, code);
    relay
        .put_phase(code.channel(), &token, Phase::Pake, pake.message())
        .await
        .unwrap();
    let wait = Duration::from_secs(25);
    let peer = relay
        .get_phase(code.channel(), &token, Phase::Pake, wait)
        .await
        .unwrap()
        .unwrap();
    let keys = pake.finish(&peer).unwrap();
    relay
        .put_phase(code.channel(), &token, Phase::Confirm, &keys.confirm_mac())
        .await
        .unwrap();
    let body = keys.seal(Phase::Payload, payload).unwrap();
    relay
        .put_phase(code.channel(), &token, Phase::Payload, &body)
        .await
        .unwrap();
    (keys, token)
}

#[tokio::test(start_paused = true)]
async fn receiver_rejects_a_pairing_offer_over_a_transfer_code() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    let channel = rx.channel();
    let payload = ChannelPayload::new(vec![], Some(offer("sneaky")));
    let (r, _) = tokio::join!(rx.exchange(), raw_sender(&relay, &code, &payload));
    assert!(matches!(r.unwrap_err(), SessionError::Malformed(_)));
    assert_eq!(
        relay.channel_status(channel),
        ChannelStatus::Gone(Some(DeleteReason::Abort))
    );
}

#[tokio::test(start_paused = true)]
async fn receiver_rejects_duplicate_item_names() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    let payload = ChannelPayload::new(vec![item("K", b"1"), item("K", b"2")], None);
    let (r, _) = tokio::join!(rx.exchange(), raw_sender(&relay, &code, &payload));
    assert!(matches!(r.unwrap_err(), SessionError::Malformed(_)));
}

#[tokio::test(start_paused = true)]
async fn malformed_pake_is_rejected() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let channel = rx.channel();
    let token = relay.join(channel).await.unwrap().side_token;
    relay
        .put_phase(channel, &token, Phase::Pake, b"not a spake2 message")
        .await
        .unwrap();
    let err = rx.exchange().await.unwrap_err();
    assert!(matches!(err, SessionError::BadPeerMessage), "{err:?}");
    assert_eq!(
        relay.channel_status(channel),
        ChannelStatus::Gone(Some(DeleteReason::Abort))
    );
}

#[tokio::test(start_paused = true)]
async fn oversized_payload_is_refused_before_sending() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    let sender = async {
        let mut tx = SenderSession::join(&relay, &code, opts()).await?;
        let big = ChannelPayload::new(vec![item("big", &vec![7u8; MAX_PAYLOAD_BYTES])], None);
        let err = tx.send(&big).await.unwrap_err();
        assert!(matches!(err, SessionError::TooLarge(_)), "{err:?}");
        assert_eq!(err.exit_code(), exit::USAGE);
        tx.abort().await;
        Ok::<_, SessionError>(())
    };
    let (r, s) = tokio::join!(rx.exchange(), sender);
    s.unwrap();
    assert!(matches!(r.unwrap_err(), SessionError::ChannelClosed));
}

#[tokio::test(start_paused = true)]
async fn calls_out_of_order_are_refused() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    assert!(matches!(
        rx.ack(vec![], None).await.unwrap_err(),
        SessionError::Invalid(_)
    ));
    let code = typed(&rx);
    let payload = ChannelPayload::new(vec![item("K", b"v")], None);
    let sender = async {
        let mut tx = SenderSession::join(&relay, &code, opts()).await.unwrap();
        let ack = tx.send(&payload).await;
        assert!(matches!(
            tx.send(&payload).await.unwrap_err(),
            SessionError::Invalid(_)
        ));
        ack
    };
    let (r, s) = tokio::join!(receive_and_ack(&mut rx, None), sender);
    r.unwrap();
    s.unwrap();
    assert!(matches!(
        rx.exchange().await.unwrap_err(),
        SessionError::Invalid(_)
    ));
    assert!(matches!(
        rx.ack(vec![], None).await.unwrap_err(),
        SessionError::Invalid(_)
    ));
}

#[tokio::test(start_paused = true)]
async fn debug_output_hides_the_code_and_tokens() {
    let relay = MemoryRelay::new();
    let rx = ReceiverSession::open(&relay, CodeKind::Pairing, opts())
        .await
        .unwrap();
    let debug = format!("{rx:?}");
    for word in rx.code().words() {
        assert!(!debug.contains(word), "{debug}");
    }
    assert!(!debug.contains(rx.link.token.as_str()), "{debug}");
}

/// Delegates to `MemoryRelay` but loses answers, as a flaky network would.
#[derive(Clone, Default)]
struct Flaky {
    /// How many upcoming PUTs answer 429 without being applied.
    rate_limit_puts: Arc<AtomicUsize>,
    /// Retry-After for the injected 429s (0 means 3 s).
    retry_after_s: Arc<AtomicU32>,
    inner: MemoryRelay,
    /// Phases whose next PUT is applied but answered with a transport error.
    lose_put_answer: Arc<Mutex<Vec<Phase>>>,
    /// How many upcoming GETs fail before reaching the relay.
    fail_gets: Arc<AtomicUsize>,
    /// How many upcoming GETs answer 429 with Retry-After.
    rate_limit_gets: Arc<AtomicUsize>,
}

impl Flaky {
    fn rate_limited(&self) -> RelayError {
        let after = match self.retry_after_s.load(Ordering::SeqCst) {
            0 => 3,
            s => s,
        };
        RelayError::Api {
            code: ErrorCode::RateLimited,
            retry_after_s: Some(after),
        }
    }
}

fn take_one(counter: &AtomicUsize) -> bool {
    let mut n = counter.load(Ordering::SeqCst);
    while n > 0 {
        match counter.compare_exchange(n, n - 1, Ordering::SeqCst, Ordering::SeqCst) {
            Ok(_) => return true,
            Err(actual) => n = actual,
        }
    }
    false
}

impl RelayApi for Flaky {
    async fn allocate(&self) -> Result<ChannelAllocated, RelayError> {
        self.inner.allocate().await
    }
    async fn join(&self, channel: u16) -> Result<ChannelJoined, RelayError> {
        self.inner.join(channel).await
    }
    async fn put_phase(
        &self,
        channel: u16,
        token: &str,
        phase: Phase,
        body: &[u8],
    ) -> Result<(), RelayError> {
        let lose_pending = self.lose_put_answer.lock().unwrap().contains(&phase);
        if !lose_pending && take_one(&self.rate_limit_puts) {
            return Err(self.rate_limited());
        }
        let result = self.inner.put_phase(channel, token, phase, body).await;
        let lose = {
            let mut lose = self.lose_put_answer.lock().unwrap();
            lose.iter()
                .position(|p| *p == phase)
                .map(|i| lose.remove(i))
                .is_some()
        };
        if lose {
            Err(RelayError::Transport("connection reset".into()))
        } else {
            result
        }
    }
    async fn get_phase(
        &self,
        channel: u16,
        token: &str,
        phase: Phase,
        wait: Duration,
    ) -> Result<Option<Vec<u8>>, RelayError> {
        if take_one(&self.fail_gets) {
            return Err(RelayError::Transport("timed out".into()));
        }
        if take_one(&self.rate_limit_gets) {
            return Err(self.rate_limited());
        }
        self.inner.get_phase(channel, token, phase, wait).await
    }
    async fn delete_channel(
        &self,
        channel: u16,
        token: &str,
        reason: DeleteReason,
    ) -> Result<(), RelayError> {
        self.inner.delete_channel(channel, token, reason).await
    }
    async fn create_inbox(&self) -> Result<InboxCreated, RelayError> {
        self.inner.create_inbox().await
    }
    async fn register_writer(
        &self,
        id: &str,
        owner: &str,
        req: &WriterRegister,
    ) -> Result<WriterRegistered, RelayError> {
        self.inner.register_writer(id, owner, req).await
    }
    async fn delete_writer(
        &self,
        id: &str,
        owner: &str,
        writer_id: &str,
    ) -> Result<(), RelayError> {
        self.inner.delete_writer(id, owner, writer_id).await
    }
    async fn post_message(
        &self,
        id: &str,
        writer: &str,
        body: &[u8],
    ) -> Result<MessageAccepted, RelayError> {
        self.inner.post_message(id, writer, body).await
    }
    async fn list_messages(
        &self,
        id: &str,
        owner: &str,
        wait: Duration,
    ) -> Result<InboxMessages, RelayError> {
        self.inner.list_messages(id, owner, wait).await
    }
    async fn delete_message(&self, id: &str, owner: &str, msg_id: &str) -> Result<(), RelayError> {
        self.inner.delete_message(id, owner, msg_id).await
    }
    async fn delete_inbox(&self, id: &str, owner: &str) -> Result<(), RelayError> {
        self.inner.delete_inbox(id, owner).await
    }
}

#[tokio::test(start_paused = true)]
async fn transient_failures_are_retried() {
    let relay = Flaky::default();
    relay
        .lose_put_answer
        .lock()
        .unwrap()
        .extend([Phase::Payload, Phase::Ack, Phase::Confirm]);
    relay.fail_gets.store(3, Ordering::SeqCst);
    relay.rate_limit_gets.store(2, Ordering::SeqCst);
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let code = typed(&rx);
    let payload = ChannelPayload::new(vec![item("K", b"v")], None);
    let (r, s) = tokio::join!(
        receive_and_ack(&mut rx, None),
        join_and_send(&relay, &code, &payload)
    );
    assert_eq!(r.unwrap().payload, payload);
    assert_eq!(s.unwrap().results, stored(&payload));
}

#[tokio::test(start_paused = true)]
async fn persistent_failures_give_up() {
    let relay = Flaky::default();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    relay.fail_gets.store(usize::MAX, Ordering::SeqCst);
    let err = rx.exchange().await.unwrap_err();
    assert!(
        matches!(err, SessionError::Relay(RelayError::Transport(_))),
        "{err:?}"
    );
    assert_eq!(err.exit_code(), exit::RELAY_UNAVAILABLE);
}

#[tokio::test(start_paused = true)]
async fn sender_reports_wrong_code_when_the_receiver_closes_during_confirmation() {
    // A receiver that rejects the sender's MAC and closes the channel before
    // the sender gets to read the receiver's MAC.
    let relay = MemoryRelay::new();
    let allocated = relay.allocate().await.unwrap();
    let (channel, r_token) = (allocated.channel, allocated.side_token);
    let real = Code::generate(channel, CodeKind::Transfer).unwrap();
    let pake = PakeStart::new(Role::Receiver, &real);
    relay
        .put_phase(channel, &r_token, Phase::Pake, pake.message())
        .await
        .unwrap();
    let receiver = async {
        let wait = Duration::from_secs(25);
        while relay
            .get_phase(channel, &r_token, Phase::Confirm, wait)
            .await
            .unwrap()
            .is_none()
        {}
        relay
            .delete_channel(channel, &r_token, DeleteReason::BadConfirm)
            .await
            .unwrap();
    };
    let (_, s) = tokio::join!(receiver, SenderSession::join(&relay, &real, opts()));
    let err = s.unwrap_err();
    assert!(
        matches!(err, SessionError::WrongCodeOrInterception),
        "{err:?}"
    );
}

#[tokio::test(start_paused = true)]
async fn receiver_leaves_the_ack_readable_if_the_sender_does_not_close() {
    let relay = MemoryRelay::new();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let (code, channel) = (typed(&rx), rx.channel());
    let payload = ChannelPayload::new(vec![item("K", b"v")], None);
    // A sender that is slow to come back for the ack (e.g. backing off after a 429).
    let sender = async {
        let sent = raw_sender(&relay, &code, &payload).await;
        tokio::time::sleep(opts().ack_linger * 2).await;
        sent
    };
    let (r, (keys, token)) = tokio::join!(receive_and_ack(&mut rx, None), sender);
    r.unwrap();
    assert_eq!(relay.channel_status(channel), ChannelStatus::Open);
    // Long after the receiver finished, the sender can still read the ack.
    let body = relay
        .get_phase(channel, &token, Phase::Ack, Duration::ZERO)
        .await
        .unwrap()
        .expect("the ack is still there");
    let ack: ChannelAck = keys.open(Phase::Ack, &body).unwrap();
    assert_eq!(ack.results, stored(&payload));
}

/// Runs the exchange against a hand-driven sender that never closes the
/// channel; returns the sender's keys and side token.
async fn exchanged_with_raw_sender(
    relay: &Flaky,
    rx: &mut ReceiverSession<'_, Flaky>,
    payload: &ChannelPayload,
) -> (ChannelKeys, String) {
    let code = typed(rx);
    let (received, sent) = tokio::join!(rx.exchange(), raw_sender(&relay.inner, &code, payload));
    assert_eq!(&received.unwrap().payload, payload);
    sent
}

#[tokio::test(start_paused = true)]
async fn an_ack_that_may_have_landed_is_never_deleted() {
    let relay = Flaky::default();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let channel = rx.channel();
    let payload = ChannelPayload::new(vec![item("K", b"v")], None);
    let (keys, token) = exchanged_with_raw_sender(&relay, &mut rx, &payload).await;

    // The ack lands but its answer is lost; the retry is rate-limited past the deadline.
    relay.lose_put_answer.lock().unwrap().push(Phase::Ack);
    relay.retry_after_s.store(3600, Ordering::SeqCst);
    relay.rate_limit_puts.store(1, Ordering::SeqCst);
    let err = rx.ack(stored(&payload), None).await.unwrap_err();
    assert!(
        matches!(&err, SessionError::Relay(e) if e.is(ErrorCode::RateLimited)),
        "{err:?}"
    );

    assert_eq!(relay.inner.channel_status(channel), ChannelStatus::Open);
    let body = relay
        .inner
        .get_phase(channel, &token, Phase::Ack, Duration::ZERO)
        .await
        .unwrap()
        .unwrap();
    let ack: ChannelAck = keys.open(Phase::Ack, &body).unwrap();
    assert_eq!(ack.results, stored(&payload));
}

#[tokio::test(start_paused = true)]
async fn lingering_respects_retry_after() {
    let relay = Flaky::default();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let payload = ChannelPayload::new(vec![item("K", b"v")], None);
    exchanged_with_raw_sender(&relay, &mut rx, &payload).await;

    relay.retry_after_s.store(30, Ordering::SeqCst); // longer than the 15 s linger
    relay.rate_limit_gets.store(100, Ordering::SeqCst);
    let started = Instant::now();
    rx.ack(stored(&payload), None).await.unwrap();
    assert_eq!(
        100 - relay.rate_limit_gets.load(Ordering::SeqCst),
        1,
        "one poll, then it stops"
    );
    assert!(started.elapsed() < Duration::from_secs(1));
}

#[tokio::test(start_paused = true)]
async fn a_refused_ack_is_not_reported_as_delivered() {
    let relay = Flaky::default();
    let mut rx = ReceiverSession::open(&relay, CodeKind::Transfer, opts())
        .await
        .unwrap();
    let channel = rx.channel();
    let payload = ChannelPayload::new(vec![item("K", b"v")], None);
    let (_, token) = exchanged_with_raw_sender(&relay, &mut rx, &payload).await;

    // The first ack PUT is refused outright (429, nothing stored); the sender
    // gives up and closes the channel before the retry.
    relay.rate_limit_puts.store(1, Ordering::SeqCst);
    let sender_gives_up = async {
        tokio::time::sleep(Duration::from_secs(1)).await;
        relay
            .inner
            .delete_channel(channel, &token, DeleteReason::Abort)
            .await
            .unwrap();
    };
    let (acked, ()) = tokio::join!(rx.ack(stored(&payload), None), sender_gives_up);
    let err = acked.unwrap_err();
    assert!(matches!(err, SessionError::ChannelClosed), "{err:?}");
}

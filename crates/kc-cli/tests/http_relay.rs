//! The same flows over HTTP: [`kc_cli::HttpRelay`] against a real `kc-relay` on a loopback
//! port (`spawn_test_relay`), with in-memory keychains. Plus the client's own HTTP rules
//! (headers, no redirects, Retry-After), checked against a raw socket.

mod common;

use std::time::Duration;

use common::{Answer, Device, Http, Run, transfer, wrong_code};
use kc_cli::{HttpRelay, RelayUrl};
use kc_proto::relay::{RelayApi, RelayError};
use kc_relay::{Config, TestRelay, spawn_test_relay};
use kc_wire::{ErrorCode, exit};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

async fn setup() -> (TestRelay, Device<Http>, Device<Http>) {
    let relay = spawn_test_relay(Config::for_tests()).await.unwrap();
    let mut a = Device::new("alpha", Http);
    let mut b = Device::new("bravo", Http);
    for d in [&mut a, &mut b] {
        d.env.push(("KC_RELAY".into(), relay.url()));
    }
    (relay, a, b)
}

fn typed_code(code: String) -> Run {
    Run::human(vec![Answer::Text(code), Answer::Yes])
}

#[tokio::test]
async fn code_transfer_and_wrong_code_over_http() {
    let (_relay, a, b) = setup().await;
    a.set("GITHUB_TOKEN", b"fake-http-1").await;
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "GITHUB_TOKEN"],
        typed_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert_eq!(b.value("GITHUB_TOKEN").unwrap(), b"fake-http-1");

    a.set("OTHER", b"fake-http-2").await;
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "OTHER"],
        |code| Run::human(vec![Answer::Text(wrong_code(&code))]),
    )
    .await;
    rx.expect(exit::AUTH_FAILED);
    tx.expect(exit::AUTH_FAILED);
    assert_eq!(b.value("OTHER"), None);
}

#[tokio::test]
async fn pairing_send_to_inbox_and_replay_over_http() {
    let (relay, a, b) = setup().await;
    let (shown, joined) = transfer(
        &b,
        &["pair"],
        Run::human(vec![Answer::Yes]),
        &a,
        &["pair", "--join"],
        typed_code,
    )
    .await;
    shown.expect(0);
    joined.expect(0);
    assert_eq!(shown.sas(), joined.sas());

    a.set("K1", b"fake-k1").await;
    a.run(&["send", "--to", "bravo", "--names", "K1"], Run::agent())
        .await
        .expect(0);

    // Keep a copy of the message to replay it later.
    let client = HttpRelay::new(&RelayUrl::parse(&relay.url(), false).unwrap()).unwrap();
    let (inbox_id, owner) = b.inbox_credentials();
    let listing = client
        .list_messages(&inbox_id, &owner, Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(listing.messages.len(), 1);
    let body = kc_proto::relay::message_body(&listing.messages[0]).unwrap();

    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(b.value("K1").unwrap(), b"fake-k1");

    client
        .post_message(&inbox_id, &a.writer_bearer("bravo"), &body)
        .await
        .unwrap();
    let replayed = b.run(&["inbox"], Run::agent()).await;
    replayed.expect(exit::AUTH_FAILED);
    assert!(replayed.stderr.contains("replay"), "{}", replayed.stderr);

    // The relay holds at most 10 pending messages per sender.
    for _ in 0..10 {
        a.run(&["send", "--to", "bravo", "--names", "K1"], Run::agent())
            .await
            .expect(0);
    }
    let full = a
        .run(&["send", "--to", "bravo", "--names", "K1"], Run::agent())
        .await;
    full.expect(exit::RELAY_UNAVAILABLE);
    assert!(full.stderr.contains("inbox is full"), "{}", full.stderr);
    b.run(&["inbox", "--wait", "1"], Run::agent())
        .await
        .expect(0);

    // Unpairing revokes A's permission on B's inbox, on the relay.
    b.run(&["peers", "rm", "alpha"], Run::agent())
        .await
        .expect(0);
    a.run(&["send", "--to", "bravo", "--names", "K1"], Run::agent())
        .await
        .expect(exit::AUTH_FAILED);

    let doctor = a.run(&["doctor"], Run::agent()).await;
    doctor.expect(0);
    assert!(doctor.stdout_text().contains("(protocol 1)"));
}

#[tokio::test]
async fn a_third_participant_is_told_about_interception() {
    let (relay, _, _) = setup().await;
    let client = HttpRelay::new(&RelayUrl::parse(&relay.url(), false).unwrap()).unwrap();
    let channel = client.allocate().await.unwrap().channel;
    client.join(channel).await.unwrap();
    let third = client.join(channel).await.unwrap_err();
    assert!(third.is(ErrorCode::Crowded), "{third:?}");
    let missing = client
        .join(if channel == 1 { 2 } else { 1 })
        .await
        .unwrap_err();
    assert!(missing.is(ErrorCode::NotFound), "{missing:?}");
    let bad = client
        .delete_inbox("AAAAAAAAAAAAAAAAAAAAAA", "AAAA")
        .await
        .unwrap_err();
    assert!(bad.is(ErrorCode::Unauthorized), "{bad:?}");
}

/// Serves one canned answer on a loopback socket and returns the request head it read.
async fn one_shot(answer: &'static str) -> (String, tokio::task::JoinHandle<String>) {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let url = format!("http://{}", listener.local_addr().unwrap());
    let task = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.unwrap();
        let mut head = Vec::new();
        let mut buf = [0u8; 1024];
        while !head.windows(4).any(|w| w == b"\r\n\r\n") {
            let n = socket.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            head.extend_from_slice(&buf[..n]);
        }
        socket.write_all(answer.as_bytes()).await.unwrap();
        socket.shutdown().await.unwrap();
        String::from_utf8_lossy(&head).to_lowercase()
    });
    (url, task)
}

#[tokio::test]
async fn requests_carry_the_protocol_headers_and_never_follow_redirects() {
    let (url, request) = one_shot(
        "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:1/v1/limits\r\nContent-Length: 0\r\n\r\n",
    )
    .await;
    let client = HttpRelay::new(&RelayUrl::parse(&url, false).unwrap()).unwrap();
    let err = client.limits().await.unwrap_err();
    assert_eq!(err, RelayError::Status(302));
    let head = request.await.unwrap();
    assert!(head.starts_with("get /v1/limits http/1.1"), "{head}");
    assert!(head.contains("\r\nkc-proto: 1\r\n"), "{head}");
    assert!(head.contains("\r\nuser-agent: kc/1\r\n"), "{head}");
}

#[tokio::test]
async fn retry_after_comes_from_the_header_when_the_body_has_none() {
    let (url, request) =
        one_shot("HTTP/1.1 429 Too Many Requests\r\nRetry-After: 17\r\nContent-Length: 0\r\n\r\n")
            .await;
    let client = HttpRelay::new(&RelayUrl::parse(&url, false).unwrap()).unwrap();
    let err = client.create_inbox().await.unwrap_err();
    assert_eq!(
        err,
        RelayError::Api {
            code: ErrorCode::RateLimited,
            retry_after_s: Some(17)
        }
    );
    assert!(err.is_transient());
    let head = request.await.unwrap();
    assert!(head.starts_with("post /v1/inboxes http/1.1"), "{head}");
}

#[tokio::test]
async fn bearer_tokens_go_in_the_authorization_header() {
    let (url, request) = one_shot(
        "HTTP/1.1 401 Unauthorized\r\nContent-Type: application/json\r\nContent-Length: 23\r\n\r\n{\"code\":\"unauthorized\"}",
    )
    .await;
    let client = HttpRelay::new(&RelayUrl::parse(&url, false).unwrap()).unwrap();
    let err = client
        .list_messages("AAAAAAAAAAAAAAAAAAAAAA", "dG9rZW4", Duration::from_secs(99))
        .await
        .unwrap_err();
    assert!(err.is(ErrorCode::Unauthorized));
    let head = request.await.unwrap();
    assert!(
        head.starts_with("get /v1/inboxes/aaaaaaaaaaaaaaaaaaaaaa/messages?wait=25 http/1.1"),
        "{head}"
    );
    assert!(
        head.contains("\r\nauthorization: bearer dg9rzw4\r\n"),
        "{head}"
    );
}

async fn pair_http(a: &Device<Http>, b: &Device<Http>) -> (common::Output, common::Output) {
    transfer(
        b,
        &["pair"],
        Run::human(vec![Answer::Yes]),
        a,
        &["pair", "--join"],
        typed_code,
    )
    .await
}

#[tokio::test]
async fn a_registration_whose_answer_was_lost_is_found_and_revoked() {
    let (relay, a, b) = setup().await;
    let (shown, joined) = pair_http(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    // An interrupted pairing registered this token on A's inbox, but only the hash it sent
    // was written down: the relay's answer (the writer id) never arrived.
    let client = HttpRelay::new(&RelayUrl::parse(&relay.url(), false).unwrap()).unwrap();
    let (inbox_id, owner) = a.inbox_credentials();
    let token = kc_proto::payload::WriterToken::generate();
    client
        .register_writer(&inbox_id, &owner, &token.registration())
        .await
        .unwrap();
    let state = kc_cli::state::StateDir::new(a.dir.path());
    let mut peers = state.load_peers().unwrap();
    peers.pending_writers.push(kc_cli::state::PendingWriter {
        writer_id: None,
        token_sha256: Some(token.sha256_b64url()),
        since: 1,
        revoking: false,
        peer: None,
    });
    state.save_peers(&peers).unwrap();
    let (shown, joined) = pair_http(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    // (The registration this re-pairing replaced stays pending, revoked after 72 hours.)
    let hash = token.sha256_b64url();
    assert!(
        a.peers()
            .pending_writers
            .iter()
            .all(|w| w.token_sha256.as_deref() != Some(hash.as_str()))
    );
    let refused = client
        .post_message(&inbox_id, &token.bearer(), b"not-a-message")
        .await
        .unwrap_err();
    assert!(refused.is(ErrorCode::Unauthorized), "{refused:?}");
}

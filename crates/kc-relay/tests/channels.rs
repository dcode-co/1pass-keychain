//! Channel routes through the real router and middleware.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{Relay, random_token};
use kc_relay::Config;
use kc_relay::config::ChannelConfig;
use kc_wire::{ErrorCode, Limits, limits};
use tokio::time::Instant;

fn relay() -> Relay {
    Relay::new(Config::for_tests())
}

fn relay_with(channels: ChannelConfig) -> Relay {
    Relay::new(Config {
        channels,
        ..Config::for_tests()
    })
}

#[tokio::test]
async fn healthz_limits_and_version_gate() {
    let r = relay();
    let h = r.get("/healthz").without_proto().send().await;
    assert_eq!(h.status, StatusCode::OK);
    assert_eq!(h.text(), "ok");
    assert_eq!(h.header("cache-control"), Some("no-store"));

    let l = r.get("/v1/limits").send().await;
    assert_eq!(l.status, StatusCode::OK);
    assert_eq!(l.json::<Limits>(), Limits::current());
    assert_eq!(l.header("cache-control"), Some("no-store"));

    let missing = r.get("/v1/limits").without_proto().send().await;
    assert_eq!(missing.code(), ErrorCode::UnsupportedVersion);
    assert_eq!(missing.header("cache-control"), Some("no-store"));
    let wrong = r
        .get("/v1/limits")
        .without_proto()
        .header("kc-proto", "2")
        .send()
        .await;
    assert_eq!(wrong.code(), ErrorCode::UnsupportedVersion);
    // Even a valid-looking request is refused without the header.
    assert_eq!(
        r.post("/v1/channels").without_proto().send().await.code(),
        ErrorCode::UnsupportedVersion
    );

    assert_eq!(r.get("/v1/nope").send().await.code(), ErrorCode::NotFound);
    assert_eq!(
        r.get("/v1/channels").send().await.code(),
        ErrorCode::BadRequest,
        "wrong method"
    );
    let bad = r
        .get("/v1/channels/abc/pake")
        .bearer(&random_token())
        .send()
        .await;
    assert_eq!(bad.code(), ErrorCode::BadRequest);
    assert_eq!(
        bad.text(),
        r#"{"code":"bad_request"}"#,
        "errors never echo input"
    );
    let bad_phase = r
        .get("/v1/channels/12/secret-word")
        .bearer(&random_token())
        .send()
        .await;
    assert_eq!(bad_phase.text(), r#"{"code":"bad_request"}"#);
}

#[tokio::test]
async fn full_channel_lifecycle() {
    let r = relay();
    let a = r.allocate().await;
    assert!((1..=limits::CHANNEL_NUMBER_MAX).contains(&a.channel));
    assert_eq!(a.side_token.len(), 43);
    assert!(a.expires_at.ends_with('Z'));
    let j = r.join(a.channel).await;
    assert_eq!(j.expires_at, a.expires_at);
    let (c, rt, st) = (a.channel, a.side_token, j.side_token);

    assert_eq!(
        r.put_phase(c, "pake", &rt, &[0xAA; 33]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.put_phase(c, "pake", &st, &[0xBB; 33]).await.status,
        StatusCode::NO_CONTENT
    );
    let got = r.get_phase(c, "pake", &rt, 0).await;
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(got.header("content-type"), Some("application/octet-stream"));
    assert_eq!(
        &got.body[..],
        &[0xBB; 33],
        "the receiver reads the sender's message"
    );
    assert_eq!(&r.get_phase(c, "pake", &st, 0).await.body[..], &[0xAA; 33]);

    assert_eq!(
        r.put_phase(c, "confirm", &rt, &[1; 32]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.put_phase(c, "confirm", &st, &[2; 32]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(&r.get_phase(c, "confirm", &st, 0).await.body[..], &[1; 32]);
    assert_eq!(&r.get_phase(c, "confirm", &rt, 0).await.body[..], &[2; 32]);

    assert_eq!(
        r.get_phase(c, "payload", &rt, 0).await.status,
        StatusCode::NO_CONTENT,
        "not written yet"
    );
    let payload = vec![7u8; 8192];
    assert_eq!(
        r.put_phase(c, "payload", &st, &payload).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        &r.get_phase(c, "payload", &rt, 0).await.body[..],
        &payload[..]
    );
    assert_eq!(
        r.put_phase(c, "ack", &rt, &[3; 100]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(&r.get_phase(c, "ack", &st, 0).await.body[..], &[3; 100]);

    let d1 = r
        .delete(&format!("/v1/channels/{c}?reason=done"))
        .bearer(&rt)
        .send()
        .await;
    assert_eq!(d1.status, StatusCode::NO_CONTENT);
    let d2 = r
        .delete(&format!("/v1/channels/{c}?reason=done"))
        .bearer(&st)
        .send()
        .await;
    assert_eq!(
        d2.status,
        StatusCode::NO_CONTENT,
        "the second side's DELETE is idempotent"
    );
    assert_eq!(r.get_phase(c, "ack", &st, 0).await.code(), ErrorCode::Gone);
    assert_eq!(
        r.put_phase(c, "pake", &rt, &[1]).await.code(),
        ErrorCode::Gone
    );
    assert_eq!(r.state.channels.stats().ram, 0, "data is dropped at once");
}

#[tokio::test]
async fn write_once_roles_tokens_and_sizes() {
    let r = relay();
    let (c, rt, st) = r.pair().await;
    assert_eq!(
        r.put_phase(c, "pake", &rt, &[1; 33]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.put_phase(c, "pake", &rt, &[2; 33]).await.code(),
        ErrorCode::AlreadyWritten
    );
    assert_eq!(
        &r.get_phase(c, "pake", &st, 0).await.body[..],
        &[1; 33],
        "first write wins"
    );

    assert_eq!(
        r.put_phase(c, "payload", &rt, &[1]).await.code(),
        ErrorCode::WrongRole
    );
    assert_eq!(
        r.put_phase(c, "ack", &st, &[1]).await.code(),
        ErrorCode::WrongRole
    );
    assert_eq!(
        r.get_phase(c, "ack", &rt, 0).await.code(),
        ErrorCode::WrongRole
    );
    assert_eq!(
        r.get_phase(c, "payload", &st, 0).await.code(),
        ErrorCode::WrongRole
    );

    let path = format!("/v1/channels/{c}/confirm");
    assert_eq!(
        r.put(&path).body(vec![1]).send().await.code(),
        ErrorCode::Unauthorized
    );
    assert_eq!(
        r.put_phase(c, "confirm", &random_token(), &[1])
            .await
            .code(),
        ErrorCode::Unauthorized
    );
    let short = common::b64(&[5u8; 31]);
    assert_eq!(
        r.put_phase(c, "confirm", &short, &[1]).await.code(),
        ErrorCode::Unauthorized
    );
    let basic = r
        .put(&path)
        .header("authorization", &format!("Basic {rt}"))
        .body(vec![1])
        .send()
        .await;
    assert_eq!(basic.code(), ErrorCode::Unauthorized);

    assert_eq!(
        r.put_phase(c, "confirm", &rt, &[]).await.code(),
        ErrorCode::BadRequest,
        "empty body"
    );
    assert_eq!(
        r.put_phase(c, "confirm", &rt, &[0; 65]).await.code(),
        ErrorCode::TooLarge
    );
    assert_eq!(
        r.put_phase(c, "confirm", &rt, &[0; 64]).await.status,
        StatusCode::NO_CONTENT
    );
    let declared = r
        .put(&format!("/v1/channels/{c}/payload"))
        .bearer(&st)
        .header("content-length", "300000")
        .send()
        .await;
    assert_eq!(
        declared.code(),
        ErrorCode::TooLarge,
        "declared length is checked before reading"
    );
    let too_big = vec![0u8; limits::MAX_PAYLOAD_BYTES + 1];
    assert_eq!(
        r.put_phase(c, "payload", &st, &too_big).await.code(),
        ErrorCode::TooLarge
    );
    let max = vec![0u8; limits::MAX_PAYLOAD_BYTES];
    assert_eq!(
        r.put_phase(c, "payload", &st, &max).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.put_phase(c, "ack", &rt, &vec![0u8; limits::MAX_ACK_BYTES + 1])
            .await
            .code(),
        ErrorCode::TooLarge
    );
}

#[tokio::test]
async fn third_join_is_crowded_and_channel_stays_open() {
    let r = relay();
    let (c, rt, st) = r.pair().await;
    let third = r.post(&format!("/v1/channels/{c}/join")).send().await;
    assert_eq!(third.code(), ErrorCode::Crowded);
    assert_eq!(
        r.put_phase(c, "pake", &rt, &[1; 33]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.put_phase(c, "pake", &st, &[2; 33]).await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.post("/v1/channels/9999/join").send().await.code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn long_poll_waits_then_returns_peer_bytes() {
    let r = relay_with(ChannelConfig {
        long_poll_max: Duration::from_secs(2),
        ..ChannelConfig::default()
    });
    let (c, rt, st) = r.pair().await;

    let t0 = std::time::Instant::now();
    let empty = r.get_phase(c, "pake", &rt, 1).await;
    assert_eq!(empty.status, StatusCode::NO_CONTENT);
    assert!(
        t0.elapsed() >= Duration::from_millis(900),
        "waited {:?}",
        t0.elapsed()
    );

    let t1 = std::time::Instant::now();
    let clamped = r.get_phase(c, "pake", &rt, 99).await;
    assert_eq!(clamped.status, StatusCode::NO_CONTENT);
    assert!(
        t1.elapsed() < Duration::from_secs(10),
        "wait is clamped to the maximum"
    );

    let waiting = tokio::spawn({
        let req = r.get(&format!("/v1/channels/{c}/pake?wait=2")).bearer(&rt);
        async move { (std::time::Instant::now(), req.send().await) }
    });
    tokio::time::sleep(Duration::from_millis(200)).await;
    assert_eq!(
        r.put_phase(c, "pake", &st, &[9; 33]).await.status,
        StatusCode::NO_CONTENT
    );
    let (started, got) = waiting.await.unwrap();
    assert_eq!(got.status, StatusCode::OK);
    assert_eq!(&got.body[..], &[9; 33]);
    assert!(
        started.elapsed() < Duration::from_millis(1500),
        "woken by the write, not the timeout"
    );

    // A DELETE ends the peer's wait with 410.
    let waiting = tokio::spawn(
        r.get(&format!("/v1/channels/{c}/confirm?wait=2"))
            .bearer(&st)
            .send(),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let d = r
        .delete(&format!("/v1/channels/{c}?reason=bad_confirm"))
        .bearer(&rt)
        .send()
        .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    assert_eq!(waiting.await.unwrap().code(), ErrorCode::Gone);
}

#[tokio::test(start_paused = true)]
async fn expiry_answers_410_then_404() {
    let r = relay_with(ChannelConfig {
        ttl: Duration::from_secs(600),
        tombstone: Duration::from_secs(600),
        ..ChannelConfig::default()
    });
    let (c, rt, st) = r.pair().await;
    assert_eq!(
        r.put_phase(c, "pake", &rt, &[1; 33]).await.status,
        StatusCode::NO_CONTENT
    );

    // A long-poll that outlives the channel ends with 410 at expiry.
    tokio::time::advance(Duration::from_secs(590)).await;
    let t0 = Instant::now();
    let w = r.get_phase(c, "confirm", &st, 25).await;
    assert_eq!(w.code(), ErrorCode::Gone);
    assert!(Instant::now() - t0 <= Duration::from_secs(11));

    assert_eq!(r.get_phase(c, "pake", &st, 0).await.code(), ErrorCode::Gone);
    assert_eq!(
        r.post(&format!("/v1/channels/{c}/join"))
            .send()
            .await
            .code(),
        ErrorCode::Gone
    );
    assert_eq!(r.state.channels.stats().ram, 0);
    tokio::time::advance(Duration::from_secs(600)).await;
    assert_eq!(
        r.get_phase(c, "pake", &st, 0).await.code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        r.delete(&format!("/v1/channels/{c}"))
            .bearer(&rt)
            .send()
            .await
            .code(),
        ErrorCode::NotFound
    );
}

#[tokio::test(start_paused = true)]
async fn delete_needs_a_side_token_and_is_idempotent() {
    let r = relay();
    let (c, rt, st) = r.pair().await;
    let path = format!("/v1/channels/{c}?reason=abort");
    assert_eq!(r.delete(&path).send().await.code(), ErrorCode::Unauthorized);
    assert_eq!(
        r.delete(&path).bearer(&random_token()).send().await.code(),
        ErrorCode::Unauthorized
    );
    assert_eq!(
        r.delete(&format!("/v1/channels/{c}?reason=bogus"))
            .bearer(&rt)
            .send()
            .await
            .code(),
        ErrorCode::BadRequest
    );
    assert_eq!(
        r.delete(&path).bearer(&st).send().await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.delete(&path).bearer(&rt).send().await.status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.delete(&path).send().await.status,
        StatusCode::NO_CONTENT,
        "a tombstone holds nothing to protect"
    );
    assert_eq!(
        r.delete(&format!("/v1/channels/{c}"))
            .bearer(&rt)
            .send()
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    tokio::time::advance(Duration::from_secs(601)).await;
    assert_eq!(
        r.delete(&path).bearer(&rt).send().await.code(),
        ErrorCode::NotFound
    );
}

#[tokio::test]
async fn capacity_limits_answer_503_with_retry_after() {
    let r = relay_with(ChannelConfig {
        max_open: 2,
        max_ram_bytes: 100,
        ..ChannelConfig::default()
    });
    let (c, rt, _) = r.pair().await;
    r.allocate().await;
    let full = r.post("/v1/channels").send().await;
    assert_eq!(full.code(), ErrorCode::Capacity);
    full.assert_retry_after();

    assert_eq!(
        r.put_phase(c, "pake", &rt, &[0; 64]).await.status,
        StatusCode::NO_CONTENT
    );
    let ram = r.put_phase(c, "confirm", &rt, &[0; 64]).await;
    assert_eq!(ram.code(), ErrorCode::Capacity);
    ram.assert_retry_after();

    // Tombstoned numbers are not handed out again.
    let r = relay_with(ChannelConfig {
        number_max: 2,
        ..ChannelConfig::default()
    });
    let a = r.allocate().await;
    r.allocate().await;
    let d = r
        .delete(&format!("/v1/channels/{}", a.channel))
        .bearer(&a.side_token)
        .send()
        .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    assert_eq!(
        r.post("/v1/channels").send().await.code(),
        ErrorCode::Capacity
    );
}

#[tokio::test]
async fn bodies_are_refused_where_no_body_belongs() {
    let r = relay();
    let (c, rt, _) = r.pair().await;
    // A long-poll carrying a body would park that body in socket buffers.
    let poll = r
        .get(&format!("/v1/channels/{c}/pake?wait=25"))
        .bearer(&rt)
        .body(vec![0u8; 1024])
        .header("content-length", "1024")
        .send()
        .await;
    assert_eq!(poll.code(), ErrorCode::BadRequest);
    assert_eq!(poll.header("connection"), Some("close"));
    let chunked = r
        .post("/v1/channels")
        .header("transfer-encoding", "chunked")
        .body(vec![1u8; 10])
        .send()
        .await;
    assert_eq!(chunked.code(), ErrorCode::BadRequest);
    let delete = r
        .delete(&format!("/v1/channels/{c}"))
        .bearer(&rt)
        .header("content-length", "3")
        .body(b"abc".to_vec())
        .send()
        .await;
    assert_eq!(delete.code(), ErrorCode::BadRequest);
    // An empty body is fine, and the routes that take one still do.
    let empty = r
        .post("/v1/channels")
        .header("content-length", "0")
        .send()
        .await;
    assert_eq!(empty.status, StatusCode::CREATED);
    assert_eq!(
        r.put_phase(c, "pake", &rt, &[1; 33]).await.status,
        StatusCode::NO_CONTENT
    );
    // An error on a route that takes a body closes rather than drains.
    let refused = r
        .put(&format!("/v1/channels/{c}/pake"))
        .bearer(&random_token())
        .header("content-length", "5")
        .body(b"hello".to_vec())
        .send()
        .await;
    assert_eq!(refused.code(), ErrorCode::Unauthorized);
    assert_eq!(refused.header("connection"), Some("close"));
}

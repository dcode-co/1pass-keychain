//! Rate limits, concurrency caps and the trusted-proxy client address.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{Relay, random_token};
use kc_relay::Config;
use kc_relay::config::{ChannelConfig, HttpConfig, RateConfig};
use kc_relay::ip::parse_cidr_list;
use kc_relay::limiter::Quota;
use kc_wire::ErrorCode;

fn relay_with(rate: RateConfig) -> Relay {
    Relay::new(Config {
        rate,
        ..Config::for_tests()
    })
}

fn loose() -> RateConfig {
    Config::for_tests().rate
}

#[tokio::test]
async fn allocate_and_join_are_limited_per_address() {
    let r = relay_with(RateConfig {
        allocate: Quota::per_hour(2),
        join: Quota::per_hour(1),
        ..loose()
    });
    let a = r.allocate().await;
    r.allocate().await;
    let limited = r.post("/v1/channels").send().await;
    assert_eq!(limited.code(), ErrorCode::RateLimited);
    limited.assert_retry_after();
    let other = r.post("/v1/channels").peer("198.51.100.2:1").send().await;
    assert_eq!(
        other.status,
        StatusCode::CREATED,
        "another address has its own bucket"
    );

    r.join(a.channel).await;
    let second = r.post("/v1/channels/1234/join").send().await;
    assert_eq!(
        second.code(),
        ErrorCode::RateLimited,
        "probing numbers spends the join budget"
    );
    second.assert_retry_after();
}

#[tokio::test]
async fn inbox_create_read_and_writer_quotas() {
    let r = relay_with(RateConfig {
        inbox_create: Quota::per_day(1),
        inbox_read: Quota::per_hour(2),
        writer_write: Quota::per_hour(2),
        ..loose()
    });
    let inbox = r.create_inbox().await;
    let again = r.post("/v1/inboxes").send().await;
    assert_eq!(again.code(), ErrorCode::RateLimited);
    let retry: u32 = again.header("retry-after").unwrap().parse().unwrap();
    assert!(retry > 3600, "5/day style quotas refill slowly: {retry}");

    let (w1, _) = r.add_writer(&inbox).await;
    let (w2, _) = r.add_writer(&inbox).await;
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w1, b"1").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w1, b"2").await.status,
        StatusCode::CREATED
    );
    let w1_limited = r.post_message(&inbox.inbox_id, &w1, b"3").await;
    assert_eq!(w1_limited.code(), ErrorCode::RateLimited);
    w1_limited.assert_retry_after();
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w2, b"4").await.status,
        StatusCode::CREATED,
        "quota is per writer"
    );

    assert_eq!(r.list(&inbox, 0).await.status, StatusCode::OK);
    assert_eq!(r.list(&inbox, 0).await.status, StatusCode::OK);
    let read_limited = r.list(&inbox, 0).await;
    assert_eq!(read_limited.code(), ErrorCode::RateLimited);
    read_limited.assert_retry_after();
}

#[tokio::test]
async fn every_request_counts_against_the_per_address_safety_net() {
    let r = relay_with(RateConfig {
        per_ip: Quota::per_minute(3),
        ..loose()
    });
    for _ in 0..3 {
        assert_eq!(r.get("/v1/limits").send().await.status, StatusCode::OK);
    }
    let limited = r.get("/v1/limits").send().await;
    assert_eq!(limited.code(), ErrorCode::RateLimited);
    limited.assert_retry_after();
    assert_eq!(limited.header("cache-control"), Some("no-store"));
    // The container healthcheck is never limited.
    assert_eq!(
        r.get("/healthz").without_proto().send().await.status,
        StatusCode::OK
    );
}

#[tokio::test]
async fn concurrent_long_polls_are_capped_per_address() {
    let r = Relay::new(Config {
        rate: RateConfig {
            long_polls_per_ip: 2,
            ..loose()
        },
        channels: ChannelConfig {
            long_poll_max: Duration::from_secs(3),
            ..ChannelConfig::default()
        },
        ..Config::for_tests()
    });
    let (c, rt, st) = r.pair().await;
    let mut waiting = Vec::new();
    for (phase, token) in [("pake", &rt), ("confirm", &st)] {
        waiting.push(tokio::spawn(
            r.get(&format!("/v1/channels/{c}/{phase}?wait=3"))
                .bearer(token)
                .send(),
        ));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let third = r
        .get(&format!("/v1/channels/{c}/payload?wait=3"))
        .bearer(&rt)
        .send()
        .await;
    assert_eq!(third.code(), ErrorCode::RateLimited);
    third.assert_retry_after();
    // An immediate check (wait=0) never holds a slot, so it still works.
    assert_eq!(
        r.get_phase(c, "payload", &rt, 0).await.status,
        StatusCode::NO_CONTENT
    );
    // A different address isn't affected.
    let elsewhere = r
        .get(&format!("/v1/channels/{c}/payload?wait=1"))
        .bearer(&rt)
        .peer("198.51.100.9:1")
        .send()
        .await;
    assert_eq!(elsewhere.status, StatusCode::NO_CONTENT);
    for w in waiting {
        assert_eq!(w.await.unwrap().status, StatusCode::NO_CONTENT);
    }
    assert_eq!(
        r.state.limits.long_polls_per_ip.tracked(),
        0,
        "slots are released"
    );
}

#[tokio::test]
async fn client_ip_header_is_honoured_only_from_the_proxy_network() {
    let r = Relay::new(Config {
        trusted_proxies: parse_cidr_list("10.9.0.0/24").unwrap(),
        rate: RateConfig {
            allocate: Quota::per_hour(1),
            ..loose()
        },
        ..Config::for_tests()
    });
    let proxy = "10.9.0.2:45000";
    let alloc = |peer: &str, ip: &str| r.post("/v1/channels").peer(peer).client_ip(ip).send();

    // Through the proxy, each forwarded client has its own bucket.
    assert_eq!(
        alloc(proxy, "203.0.113.1").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        alloc(proxy, "203.0.113.1").await.code(),
        ErrorCode::RateLimited
    );
    assert_eq!(
        alloc(proxy, "203.0.113.2").await.status,
        StatusCode::CREATED
    );

    // From anywhere else the header is ignored: rotating it doesn't help.
    let outsider = "198.51.100.7:1";
    assert_eq!(
        alloc(outsider, "203.0.113.3").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        alloc(outsider, "203.0.113.4").await.code(),
        ErrorCode::RateLimited
    );
    // Nor can an outsider borrow a fresh forwarded identity's budget.
    assert_eq!(
        alloc(outsider, "203.0.113.50").await.code(),
        ErrorCode::RateLimited
    );

    // IPv6 clients are grouped per /64.
    assert_eq!(
        alloc(proxy, "2001:db8:1:2::1").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        alloc(proxy, "2001:db8:1:2:ffff::9").await.code(),
        ErrorCode::RateLimited
    );
    assert_eq!(
        alloc(proxy, "2001:db8:1:3::1").await.status,
        StatusCode::CREATED
    );

    // A malformed header from the proxy falls back to the proxy's own address.
    assert_eq!(
        alloc(proxy, "1.2.3.4, 5.6.7.8").await.status,
        StatusCode::CREATED
    );
    assert_eq!(alloc(proxy, "garbage").await.code(), ErrorCode::RateLimited);
}

#[tokio::test]
async fn large_responses_hold_outbound_budget_until_handed_off() {
    let r = Relay::new(Config {
        http: HttpConfig {
            outbound_budget_bytes: 300 * 1024,
            outbound_per_ip: 1,
            ..HttpConfig::default()
        },
        ..Config::for_tests()
    });
    let full = r.state.outbound_available_kib();
    assert_eq!(full, 300);
    let (c, rt, st) = r.pair().await;
    let payload = vec![5u8; 200 * 1024];
    assert_eq!(
        r.put_phase(c, "payload", &st, &payload).await.status,
        StatusCode::NO_CONTENT
    );

    // An unread response keeps its share of the budget and the client's slot.
    let held = r
        .get(&format!("/v1/channels/{c}/payload"))
        .bearer(&rt)
        .send_raw()
        .await;
    assert_eq!(held.status(), StatusCode::OK);
    assert_eq!(r.state.outbound_available_kib(), full - 200);
    let same_client = r.get_phase(c, "payload", &rt, 0).await;
    assert_eq!(same_client.code(), ErrorCode::RateLimited);
    same_client.assert_retry_after();
    let other_client = r
        .get(&format!("/v1/channels/{c}/payload"))
        .bearer(&rt)
        .peer("198.51.100.20:1")
        .send()
        .await;
    assert_eq!(other_client.code(), ErrorCode::Capacity, "budget exhausted");
    other_client.assert_retry_after();
    // Small responses never touch the budget.
    assert_eq!(
        r.get_phase(c, "pake", &rt, 0).await.status,
        StatusCode::NO_CONTENT
    );

    drop(held);
    assert_eq!(
        r.state.outbound_available_kib(),
        full,
        "dropping the response releases it"
    );

    // Reading the body to the end releases it too, and the bytes arrive intact.
    let read = r.get_phase(c, "payload", &rt, 0).await;
    assert_eq!(read.status, StatusCode::OK);
    assert_eq!(
        read.header("content-type"),
        Some("application/octet-stream")
    );
    assert_eq!(&read.body[..], &payload[..]);
    // The collected body is the same allocation; the budget comes back with it.
    assert!(r.state.outbound_available_kib() < full);
    drop(read);
    assert_eq!(r.state.outbound_available_kib(), full);
    assert_eq!(r.state.limits.outbound_per_ip.tracked(), 0);
}

#[tokio::test]
async fn requests_in_progress_are_capped_per_address() {
    let r = Relay::new(Config {
        rate: RateConfig {
            inflight_per_ip: 2,
            ..loose()
        },
        channels: ChannelConfig {
            long_poll_max: Duration::from_secs(2),
            ..ChannelConfig::default()
        },
        ..Config::for_tests()
    });
    let (c, rt, st) = r.pair().await;
    let mut waiting = Vec::new();
    for (phase, token) in [("pake", &rt), ("confirm", &st)] {
        waiting.push(tokio::spawn(
            r.get(&format!("/v1/channels/{c}/{phase}?wait=2"))
                .bearer(token)
                .send(),
        ));
    }
    tokio::time::sleep(Duration::from_millis(300)).await;
    let third = r.get("/v1/limits").send().await;
    assert_eq!(third.code(), ErrorCode::RateLimited);
    third.assert_retry_after();
    let elsewhere = r.get("/v1/limits").peer("198.51.100.30:1").send().await;
    assert_eq!(elsewhere.status, StatusCode::OK);
    for w in waiting {
        assert_eq!(w.await.unwrap().status, StatusCode::NO_CONTENT);
    }
    assert_eq!(r.get("/v1/limits").send().await.status, StatusCode::OK);
    assert_eq!(r.state.limits.inflight_per_ip.tracked(), 0);
}

#[tokio::test]
async fn channel_probes_spend_the_join_budget_but_participants_never_do() {
    let r = relay_with(RateConfig {
        join: Quota::per_hour(3),
        ..loose()
    });
    let (c, rt, st) = r.pair().await;
    let other = r.allocate().await.channel;

    // A stranger learns something from each of these, so each costs a join.
    let stranger = "198.51.100.40:1";
    let open = r
        .delete(&format!("/v1/channels/{c}"))
        .peer(stranger)
        .send()
        .await;
    assert_eq!(open.code(), ErrorCode::Unauthorized);
    let absent = r
        .get(&format!(
            "/v1/channels/{}/pake",
            if other == 1 { 2 } else { 1 }
        ))
        .bearer(&random_token())
        .peer(stranger)
        .send()
        .await;
    assert!(matches!(
        absent.code(),
        ErrorCode::NotFound | ErrorCode::Unauthorized
    ));
    let wrong_token = r
        .put(&format!("/v1/channels/{other}/pake"))
        .bearer(&random_token())
        .body(vec![1])
        .peer(stranger)
        .send()
        .await;
    assert_eq!(wrong_token.code(), ErrorCode::Unauthorized);
    let fourth = r
        .get(&format!("/v1/channels/{c}/pake"))
        .bearer(&random_token())
        .peer(stranger)
        .send()
        .await;
    assert_eq!(fourth.code(), ErrorCode::RateLimited);
    fourth.assert_retry_after();

    // Participants with their side tokens are never charged, even for 410s.
    let d = r
        .delete(&format!("/v1/channels/{c}?reason=done"))
        .bearer(&rt)
        .send()
        .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);
    for _ in 0..5 {
        assert_eq!(r.get_phase(c, "ack", &st, 0).await.code(), ErrorCode::Gone);
        let again = r
            .delete(&format!("/v1/channels/{c}?reason=done"))
            .bearer(&st)
            .send()
            .await;
        assert_eq!(again.status, StatusCode::NO_CONTENT);
    }
    // The stranger's tombstone probe is charged (and now refused).
    let tomb = r
        .delete(&format!("/v1/channels/{c}"))
        .peer(stranger)
        .send()
        .await;
    assert_eq!(tomb.code(), ErrorCode::RateLimited);
}

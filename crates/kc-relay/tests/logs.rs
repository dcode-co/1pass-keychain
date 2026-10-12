//! The access log: route templates, statuses and coarse sizes only. This
//! lives in its own test binary because `tracing` caches callsite interest
//! process-wide; a thread-local subscriber can miss events while other tests
//! run in parallel threads of the same binary.

mod common;

use std::sync::{Arc, Mutex};

use axum::http::StatusCode;
use common::{Relay, b64, unb64};
use kc_relay::Config;
use kc_wire::{ChannelAllocated, InboxMessages};

#[derive(Clone, Default)]
struct Capture(Arc<Mutex<Vec<u8>>>);

impl std::io::Write for Capture {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.lock().unwrap().extend_from_slice(buf);
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

impl<'a> tracing_subscriber::fmt::MakeWriter<'a> for Capture {
    type Writer = Capture;
    fn make_writer(&'a self) -> Capture {
        self.clone()
    }
}

#[tokio::test]
async fn logs_hold_route_templates_but_no_ids_tokens_ips_or_bodies() {
    let capture = Capture::default();
    let subscriber = tracing_subscriber::fmt()
        .with_writer(capture.clone())
        .with_ansi(false)
        .with_max_level(tracing::Level::TRACE)
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);

    let cfg = Config {
        trusted_proxies: kc_relay::ip::parse_cidr_list("10.9.0.0/24").unwrap(),
        ..Config::for_tests()
    };
    let r = Relay::new(cfg);
    let peer = "10.9.0.2:4000";
    let client = "203.0.113.77";
    let secret = b"SECRET-PAYLOAD-MARKER";

    let a = r
        .post("/v1/channels")
        .peer(peer)
        .client_ip(client)
        .send()
        .await
        .json::<ChannelAllocated>();
    let j = r.join(a.channel).await;
    let put = r.put_phase(a.channel, "pake", &a.side_token, secret).await;
    assert_eq!(put.status, StatusCode::NO_CONTENT);
    assert_eq!(
        &r.get_phase(a.channel, "pake", &j.side_token, 0).await.body[..],
        secret
    );
    let d = r
        .delete(&format!("/v1/channels/{}?reason=bad_confirm", a.channel))
        .bearer(&j.side_token)
        .send()
        .await;
    assert_eq!(d.status, StatusCode::NO_CONTENT);

    let inbox = r.create_inbox().await;
    let (writer_token, writer_id) = r.add_writer(&inbox).await;
    let msg = r.post_message(&inbox.inbox_id, &writer_token, secret).await;
    assert_eq!(msg.status, StatusCode::CREATED);
    let listed = r.list(&inbox, 0).await.json::<InboxMessages>();
    assert_eq!(unb64(&listed.messages[0].body_b64), secret);
    let msg_id = listed.messages[0].msg_id.clone();
    // Unauthenticated noise with an id in the path.
    r.get(&format!("/v1/inboxes/{}/messages", inbox.inbox_id))
        .send()
        .await;

    let logs = String::from_utf8(capture.0.lock().unwrap().clone()).unwrap();
    assert!(logs.contains("/v1/channels/{channel}/{phase}"), "{logs}");
    assert!(logs.contains("/v1/inboxes/{inbox}/messages"));
    assert!(logs.contains("bad_confirm"));
    assert!(logs.contains("status=201"));
    let forbidden = [
        a.side_token.clone(),
        j.side_token.clone(),
        inbox.inbox_id.clone(),
        inbox.owner_token.clone(),
        writer_token.clone(),
        writer_id.clone(),
        msg_id.clone(),
        b64(secret),
        String::from_utf8_lossy(secret).into_owned(),
        format!("/v1/channels/{}", a.channel),
        client.to_string(),
        "10.9.0.2".to_string(),
        "198.51.100.1".to_string(),
        "user-agent".to_string(),
    ];
    for needle in &forbidden {
        assert!(
            !logs.contains(needle.as_str()),
            "log leaked {needle:?}:\n{logs}"
        );
    }
}

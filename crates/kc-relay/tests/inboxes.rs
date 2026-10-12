//! Inbox routes through the real router and middleware.

mod common;

use std::time::Duration;

use axum::http::StatusCode;
use common::{Relay, TempDir, b64, random_token, sha256, unb64};
use kc_relay::config::InboxConfig;
use kc_relay::{Config, DbLocation};
use kc_wire::{ErrorCode, InboxMessages, MessageAccepted, WriterRegister, limits};

fn relay_with(inbox: InboxConfig) -> Relay {
    Relay::new(Config {
        inbox,
        ..Config::for_tests()
    })
}

#[tokio::test]
async fn inbox_create_write_read_delete() {
    let r = relay_with(InboxConfig::default());
    let inbox = r.create_inbox().await;
    assert_eq!(unb64(&inbox.inbox_id).len(), 16);
    assert_eq!(unb64(&inbox.owner_token).len(), 32);
    let (writer_token, writer_id) = r.add_writer(&inbox).await;

    let sent = r
        .post_message(&inbox.inbox_id, &writer_token, b"hpke ciphertext")
        .await;
    assert_eq!(sent.status, StatusCode::CREATED);
    let msg_id = sent.json::<MessageAccepted>().msg_id;
    assert_eq!(unb64(&msg_id).len(), 16);

    let listed = r.list(&inbox, 0).await;
    assert_eq!(listed.status, StatusCode::OK);
    assert_eq!(listed.header("cache-control"), Some("no-store"));
    let msgs = listed.json::<InboxMessages>().messages;
    assert_eq!(msgs.len(), 1);
    assert_eq!(msgs[0].msg_id, msg_id);
    assert_eq!(msgs[0].writer_id, writer_id);
    assert!(msgs[0].received_at.ends_with('Z'));
    assert_eq!(unb64(&msgs[0].body_b64), b"hpke ciphertext");

    let del_path = format!("/v1/inboxes/{}/messages/{msg_id}", inbox.inbox_id);
    assert_eq!(
        r.delete(&del_path)
            .bearer(&inbox.owner_token)
            .send()
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.delete(&del_path)
            .bearer(&inbox.owner_token)
            .send()
            .await
            .code(),
        ErrorCode::NotFound
    );
    assert!(
        r.list(&inbox, 0)
            .await
            .json::<InboxMessages>()
            .messages
            .is_empty()
    );

    let writer_path = format!("/v1/inboxes/{}/writers/{writer_id}", inbox.inbox_id);
    assert_eq!(
        r.delete(&writer_path)
            .bearer(&inbox.owner_token)
            .send()
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(
        r.delete(&writer_path)
            .bearer(&inbox.owner_token)
            .send()
            .await
            .code(),
        ErrorCode::NotFound
    );
    assert_eq!(
        r.post_message(&inbox.inbox_id, &writer_token, b"x")
            .await
            .code(),
        ErrorCode::Unauthorized
    );

    let inbox_path = format!("/v1/inboxes/{}", inbox.inbox_id);
    assert_eq!(
        r.delete(&inbox_path)
            .bearer(&inbox.owner_token)
            .send()
            .await
            .status,
        StatusCode::NO_CONTENT
    );
    assert_eq!(r.list(&inbox, 0).await.code(), ErrorCode::Unauthorized);
    assert_eq!(
        r.delete(&inbox_path)
            .bearer(&inbox.owner_token)
            .send()
            .await
            .code(),
        ErrorCode::Unauthorized
    );
}

#[tokio::test]
async fn unknown_inbox_and_bad_tokens_all_answer_the_same_401() {
    let r = relay_with(InboxConfig::default());
    let inbox = r.create_inbox().await;
    let (writer_token, _) = r.add_writer(&inbox).await;
    let unknown = b64(&[0u8; 16]);
    let messages = |id: &str| format!("/v1/inboxes/{id}/messages");

    let cases = [
        r.get(&messages(&unknown))
            .bearer(&inbox.owner_token)
            .send()
            .await,
        r.get(&messages("not-an-id"))
            .bearer(&inbox.owner_token)
            .send()
            .await,
        r.get(&messages(&inbox.inbox_id))
            .bearer(&random_token())
            .send()
            .await,
        r.get(&messages(&inbox.inbox_id))
            .bearer(&writer_token)
            .send()
            .await,
        r.get(&messages(&inbox.inbox_id)).send().await,
        r.post_message(&inbox.inbox_id, &inbox.owner_token, b"x")
            .await,
        r.post_message(&unknown, &writer_token, b"x").await,
        r.post_message(&inbox.inbox_id, &b64(&[1u8; 33]), b"x")
            .await,
        r.delete(&format!("/v1/inboxes/{unknown}"))
            .bearer(&inbox.owner_token)
            .send()
            .await,
    ];
    for resp in &cases {
        assert_eq!(resp.code(), ErrorCode::Unauthorized);
        assert_eq!(resp.text(), r#"{"code":"unauthorized"}"#);
    }

    let writers = format!("/v1/inboxes/{}/writers", inbox.inbox_id);
    let short = WriterRegister {
        writer_token_sha256: b64(&[1u8; 31]),
    };
    let r1 = r
        .post(&writers)
        .bearer(&inbox.owner_token)
        .json(&short)
        .send()
        .await;
    assert_eq!(r1.code(), ErrorCode::BadRequest);
    let r2 = r
        .post(&writers)
        .bearer(&inbox.owner_token)
        .body(b"{not json".to_vec())
        .send()
        .await;
    assert_eq!(r2.code(), ErrorCode::BadRequest);
    let long = r
        .post(&writers)
        .bearer(&inbox.owner_token)
        .body(vec![b' '; 4096])
        .send()
        .await;
    assert_eq!(long.code(), ErrorCode::TooLarge);
}

#[tokio::test]
async fn store_keeps_only_hashes() {
    let r = relay_with(InboxConfig::default());
    let inbox = r.create_inbox().await;
    let (writer_token, writer_id) = r.add_writer(&inbox).await;
    let id = unb64(&inbox.inbox_id);
    let owner = unb64(&inbox.owner_token);
    let writer = unb64(&writer_token);
    r.state.inbox.db().with_conn(|c| {
        let (id_hash, owner_hash): (Vec<u8>, Vec<u8>) =
            c.query_row("SELECT id_hash, owner_hash FROM inboxes", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(id_hash, sha256(&id));
        assert_eq!(owner_hash, sha256(&owner));
        let (wid, token_hash): (Vec<u8>, Vec<u8>) =
            c.query_row("SELECT writer_id, token_hash FROM writers", [], |row| Ok((row.get(0)?, row.get(1)?))).unwrap();
        assert_eq!(wid, unb64(&writer_id));
        assert_eq!(token_hash, sha256(&writer));
        for raw in [&id, &owner, &writer] {
            let hits: i64 = c
                .query_row(
                    "SELECT (SELECT COUNT(*) FROM inboxes WHERE instr(id_hash, ?1) OR instr(owner_hash, ?1))
                          + (SELECT COUNT(*) FROM writers WHERE instr(writer_id, ?1) OR instr(token_hash, ?1))",
                    [raw.as_slice()],
                    |row| row.get(0),
                )
                .unwrap();
            assert_eq!(hits, 0, "raw ids and tokens never reach the database");
        }
        let secure_delete: i64 = c.query_row("PRAGMA secure_delete", [], |row| row.get(0)).unwrap();
        assert_eq!(secure_delete, 1);
    });
}

#[tokio::test]
async fn quotas_answer_507_and_413() {
    let r = relay_with(InboxConfig {
        max_messages: 2,
        ..InboxConfig::default()
    });
    let inbox = r.create_inbox().await;
    let (w, _) = r.add_writer(&inbox).await;
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w, b"1").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w, b"2").await.status,
        StatusCode::CREATED
    );
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w, b"3").await.code(),
        ErrorCode::InboxFull
    );
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w, b"").await.code(),
        ErrorCode::BadRequest
    );

    // Message size: 256 KiB is accepted, one byte more is not.
    let r = relay_with(InboxConfig::default());
    let inbox = r.create_inbox().await;
    let (w, _) = r.add_writer(&inbox).await;
    let max = vec![1u8; limits::MAX_MESSAGE_BYTES];
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w, &max).await.status,
        StatusCode::CREATED
    );
    let over = vec![1u8; limits::MAX_MESSAGE_BYTES + 1];
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w, &over).await.code(),
        ErrorCode::TooLarge
    );

    // Sixteen writers fit; the seventeenth doesn't.
    for _ in 1..limits::INBOX_MAX_WRITERS {
        r.add_writer(&inbox).await;
    }
    let seventeenth = WriterRegister {
        writer_token_sha256: b64(&sha256(b"17")),
    };
    let resp = r
        .post(&format!("/v1/inboxes/{}/writers", inbox.inbox_id))
        .bearer(&inbox.owner_token)
        .json(&seventeenth)
        .send()
        .await;
    assert_eq!(resp.code(), ErrorCode::InboxFull);
}

#[tokio::test]
async fn inbox_count_and_database_caps_answer_503() {
    let r = relay_with(InboxConfig {
        max_inboxes: 1,
        ..InboxConfig::default()
    });
    r.create_inbox().await;
    let full = r.post("/v1/inboxes").send().await;
    assert_eq!(full.code(), ErrorCode::Capacity);
    full.assert_retry_after();

    // A file database with a tiny page cap fills up and refuses with 503,
    // while the owner can still read.
    let dir = TempDir::new();
    let cfg = Config {
        db: DbLocation::File(dir.0.join("relay.db")),
        inbox: InboxConfig {
            max_db_bytes: 512 * 1024,
            ..InboxConfig::default()
        },
        ..Config::for_tests()
    };
    let r = Relay::new(cfg);
    r.state.inbox.db().with_conn(|c| {
        let mode: String = c
            .query_row("PRAGMA journal_mode", [], |row| row.get(0))
            .unwrap();
        assert_eq!(mode, "wal");
        let auto_vacuum: i64 = c
            .query_row("PRAGMA auto_vacuum", [], |row| row.get(0))
            .unwrap();
        assert_eq!(auto_vacuum, 2, "incremental");
    });
    let inbox = r.create_inbox().await;
    let (w, _) = r.add_writer(&inbox).await;
    let mut hit_cap = false;
    for _ in 0..4 {
        let resp = r
            .post_message(&inbox.inbox_id, &w, &vec![9u8; 200 * 1024])
            .await;
        if resp.status != StatusCode::CREATED {
            assert_eq!(resp.code(), ErrorCode::Capacity);
            resp.assert_retry_after();
            hit_cap = true;
            break;
        }
    }
    assert!(hit_cap, "the page cap must stop the database growing");
    assert_eq!(r.list(&inbox, 0).await.status, StatusCode::OK);
}

#[tokio::test]
async fn long_poll_on_inbox_wakes_on_new_message() {
    let r = relay_with(InboxConfig::default());
    let inbox = r.create_inbox().await;
    let (w, _) = r.add_writer(&inbox).await;

    let t0 = std::time::Instant::now();
    let empty = r.list(&inbox, 1).await;
    assert_eq!(empty.status, StatusCode::OK);
    assert!(empty.json::<InboxMessages>().messages.is_empty());
    assert!(t0.elapsed() >= Duration::from_millis(900));

    let waiting = tokio::spawn(
        r.get(&format!("/v1/inboxes/{}/messages?wait=10", inbox.inbox_id))
            .bearer(&inbox.owner_token)
            .send(),
    );
    tokio::time::sleep(Duration::from_millis(200)).await;
    let t1 = std::time::Instant::now();
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w, b"wake").await.status,
        StatusCode::CREATED
    );
    let got = waiting.await.unwrap();
    assert!(t1.elapsed() < Duration::from_secs(5));
    let msgs = got.json::<InboxMessages>().messages;
    assert_eq!(msgs.len(), 1);
    assert_eq!(unb64(&msgs[0].body_b64), b"wake");
    assert_eq!(
        r.state.inbox.waiting_inboxes(),
        0,
        "waiter entries are cleaned up"
    );
}

#[tokio::test]
async fn purge_job_removes_expired_messages_and_idle_inboxes() {
    let r = relay_with(InboxConfig {
        message_ttl: Duration::from_millis(300),
        purge_interval: Duration::from_millis(100),
        ..InboxConfig::default()
    });
    let background = r.state.spawn_background();
    let inbox = r.create_inbox().await;
    let (w, _) = r.add_writer(&inbox).await;
    assert_eq!(
        r.post_message(&inbox.inbox_id, &w, b"short-lived")
            .await
            .status,
        StatusCode::CREATED
    );
    let rows = |r: &Relay| -> i64 {
        r.state.inbox.db().with_conn(|c| {
            c.query_row("SELECT COUNT(*) FROM messages", [], |row| row.get(0))
                .unwrap()
        })
    };
    assert_eq!(rows(&r), 1);
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    while rows(&r) > 0 {
        assert!(std::time::Instant::now() < deadline, "purge job never ran");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    r.state.begin_shutdown();
    for task in background {
        task.await.unwrap();
    }

    // Idle deletion: an inbox nobody read for `idle_delete` goes away with its writers.
    let stats = r
        .state
        .inbox
        .purge(
            kc_relay::util::now_ms() + 31 * 86_400_000,
            &std::sync::atomic::AtomicBool::new(false),
        )
        .await
        .unwrap();
    assert_eq!(stats.idle_inboxes, 1);
    assert_eq!(r.list(&inbox, 0).await.code(), ErrorCode::Unauthorized);
}

#[tokio::test]
async fn writer_registration_reads_no_body_before_the_owner_is_known() {
    let r = relay_with(InboxConfig::default());
    let inbox = r.create_inbox().await;
    let path = format!("/v1/inboxes/{}/writers", inbox.inbox_id);
    // A stranger announcing a huge body is turned away on the token alone.
    let stranger = r
        .post(&path)
        .bearer(&random_token())
        .header("content-length", "10000000")
        .send()
        .await;
    assert_eq!(stranger.code(), ErrorCode::Unauthorized);
    let owner = r
        .post(&path)
        .bearer(&inbox.owner_token)
        .header("content-length", "10000000")
        .send()
        .await;
    assert_eq!(owner.code(), ErrorCode::TooLarge);
}

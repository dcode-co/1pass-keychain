//! Real CLI flows through two isolated memory keychains and the authenticated relay.
mod common;
use common::{Answer, Device, Run, transfer};
use kc_cli::LocalAuthOutcome;
use kc_proto::memory_relay::MemoryRelay;
use kc_proto::relay::RelayApi;
use kc_proto::sync::{Change, Op, SyncMsg, Vid};
use kc_proto::{ItemName, SecretBytes};
use serde_json::Value;

fn human(answers: Vec<Answer>) -> Run {
    let mut run = Run::human(answers);
    run.local_auth.push_back(LocalAuthOutcome::Confirmed);
    run
}
fn state<N: common::Net>(d: &Device<N>) -> Value {
    serde_json::from_slice(&std::fs::read(d.dir.path().join("sync.json")).unwrap()).unwrap()
}
fn head(d: &Device<MemoryRelay>) -> Vid {
    serde_json::from_value(state(d)["items"]["KEY"]["head"].clone()).unwrap()
}
async fn pair(a: &Device<MemoryRelay>, b: &Device<MemoryRelay>) {
    let (rx, tx) = transfer(
        b,
        &["pair"],
        Run::human(vec![Answer::Yes]),
        a,
        &["pair", "--join"],
        |code| Run::human(vec![Answer::Text(code), Answer::Yes]),
    )
    .await;
    rx.expect(0);
    tx.expect(0);
}
async fn devices() -> (Device<MemoryRelay>, Device<MemoryRelay>, MemoryRelay) {
    let relay = MemoryRelay::new();
    let mut a = Device::new("alpha", relay.clone());
    let mut b = Device::new("bravo", relay.clone());
    for device in [&mut a, &mut b] {
        device.env.push((
            "TEST_NAMESPACE".into(),
            format!("dev.1pass.kc.sync-{}", u128::from_be_bytes(Vid::random().0)),
        ));
    }
    pair(&a, &b).await;
    (a, b, relay)
}
async fn pump(a: &Device<MemoryRelay>, b: &Device<MemoryRelay>) {
    for _ in 0..3 {
        for d in [a, b] {
            let out = d.run(&["sync"], Run::agent()).await;
            assert!([0, 8].contains(&out.code), "{}", out.stderr);
        }
    }
}
async fn enroll(a: &Device<MemoryRelay>, b: &Device<MemoryRelay>) {
    a.set("KEY", b"fake-initial-secret").await;
    let out = a
        .run(&["sync", "add", "KEY", "--peers", "bravo"], human(vec![]))
        .await;
    out.expect(8);
    assert!(
        out.stderr
            .contains("Added KEY to sync and offered it to 1 device;"),
        "{}",
        out.stderr
    );
    assert!(
        out.stderr
            .contains("Still pending: waiting for review on other devices"),
        "{}",
        out.stderr
    );
    pump(a, b).await;
    assert!(b.value("KEY").is_none());
    assert_eq!(state(b)["candidates"].as_object().unwrap().len(), 1);
    let out = b
        .run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await;
    assert!([0, 8].contains(&out.code), "{}", out.stderr);
    assert!(
        out.stderr.contains("Accepted KEY from alpha."),
        "{}",
        out.stderr
    );
    assert_eq!(
        out.prompts
            .iter()
            .filter(|p| p.starts_with("local confirmation:"))
            .count(),
        1
    );
    pump(a, b).await;
    assert_eq!(head(a), head(b));
}
async fn post(a: &Device<MemoryRelay>, b: &Device<MemoryRelay>, relay: &MemoryRelay, msg: SyncMsg) {
    let key = a.store().get_internal("device-key").unwrap().unwrap();
    let key = kc_proto::DeviceKeyPair::from_secret_bytes(key.as_bytes()).unwrap();
    let peer = a.peers().find("bravo").unwrap().clone();
    let sealed = kc_proto::inbox::seal_v2(
        &key,
        &peer.device_pk,
        &kc_proto::inbox::Body::Sync(msg),
        std::time::Duration::from_secs(86400),
        kc_proto::inbox::unix_now(),
    )
    .unwrap();
    relay
        .post_message(
            &b.inbox_credentials().0,
            &a.writer_bearer("bravo"),
            &sealed.body,
        )
        .await
        .unwrap();
}
#[tokio::test]
async fn add_offer_review_local_confirmation_and_accept_on_both_sides() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    assert_eq!(a.value("KEY"), b.value("KEY"));
    let out = a.run(&["sync", "status"], Run::agent()).await;
    out.expect(0);
    let text = out.stdout_text();
    assert!(text.contains("KEY  in sync  "), "{text}");
    assert!(text.contains("  bravo\n"), "{text}");
    assert!(text.contains("device bravo: ok\n"), "{text}");
    assert!(!text.contains('{') && !text.contains('['), "{text}");
    a.run(&["sync", "status", "--json"], Run::agent())
        .await
        .expect(0);
    b.run(&["sync", "status", "--json"], Run::agent())
        .await
        .expect(0);
    assert!(
        state(&a)["slots"]
            .as_object()
            .unwrap()
            .keys()
            .all(|k| !k.contains("snapshot"))
    );
}
#[tokio::test]
async fn local_change_is_held_review_converges_and_ack_releases_snapshot() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-second-secret").await;
    pump(&a, &b).await;
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    assert!(
        state(&b)["candidates"]
            .as_object()
            .unwrap()
            .values()
            .any(|v| v["category"] == "held")
    );
    assert!(
        state(&a)["slots"]
            .as_object()
            .unwrap()
            .keys()
            .all(|k| !k.contains("snapshot"))
    );
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(0);
    pump(&a, &b).await;
    assert_eq!(head(&a), head(&b));
    assert_eq!(a.value("KEY"), b.value("KEY"));
    b.run(&["sync", "restore-checkpoint", "KEY"], human(vec![]))
        .await
        .expect(8);
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
}
#[tokio::test]
async fn concurrent_changes_conflict_resolve_is_held_then_converges() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-alpha-change").await;
    b.set("KEY", b"fake-bravo-change").await;
    pump(&a, &b).await;
    assert_eq!(state(&a)["items"]["KEY"]["conflict"], true);
    assert_eq!(state(&b)["items"]["KEY"]["conflict"], true);
    let out = a
        .run(&["sync", "resolve", "KEY", "--keep", "mine"], human(vec![]))
        .await;
    out.expect(8);
    assert!(
        out.stderr.contains("Resolved KEY, keeping this device;"),
        "{}",
        out.stderr
    );
    pump(&a, &b).await;
    assert_eq!(b.value("KEY").unwrap(), b"fake-bravo-change");
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(0);
    pump(&a, &b).await;
    assert_eq!(head(&a), head(&b));
    assert_eq!(a.value("KEY"), b.value("KEY"));
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
}
#[tokio::test]
async fn remove_bumps_generation_late_change_is_stale_and_requires_reoffer() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let old = head(&a);
    b.run(&["sync", "rm", "KEY"], human(vec![])).await.expect(0);
    post(
        &a,
        &b,
        &relay,
        SyncMsg::Changes {
            changes: vec![Change {
                name: ItemName::new("KEY").unwrap(),
                generation: 1,
                new_vid: Vid::random(),
                parents: vec![old],
                lineage: vec![old],
                op: Op::Put {
                    kind: kc_proto::sync::ItemKind::Text,
                    value: SecretBytes::from_slice(b"late-fake"),
                },
                approval_ref: None,
            }],
        },
    )
    .await;
    pump(&a, &b).await;
    assert!(state(&b)["items"].as_object().unwrap().is_empty());
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    assert!(
        a.run(&["sync", "status", "--json"], Run::agent())
            .await
            .stdout_text()
            .contains("re-offer needed")
    );
    a.run(&["sync", "offer", "KEY", "--peers", "bravo"], Run::agent())
        .await
        .expect(8);
    pump(&a, &b).await;
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(0);
    pump(&a, &b).await;
    assert_eq!(head(&a), head(&b));
}
#[tokio::test]
async fn v1_imports_normal_items_but_holds_sync_overwrites_and_rm_refuses() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.store()
        .set(
            "KEY",
            b"fake-v1-overwrite",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    a.set("OTHER", b"fake-normal").await;
    a.run(&["send", "KEY", "OTHER", "--to", "bravo"], Run::agent())
        .await
        .expect(0);
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert_eq!(b.value("OTHER").unwrap(), b"fake-normal");
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    b.run(&["rm", "KEY", "--yes"], Run::agent()).await.expect(5);
}
#[tokio::test]
async fn noninteractive_add_review_and_denied_local_confirmation_exit_five() {
    let relay = MemoryRelay::new();
    let a = Device::new("alpha", relay);
    a.set("KEY", b"fake").await;
    for args in [
        vec!["sync", "add", "KEY"],
        vec!["sync", "review"],
        vec!["sync", "unfreeze"],
        vec!["sync", "resolve", "KEY", "--keep", "mine"],
        vec!["sync", "restore-checkpoint", "KEY"],
        vec!["sync", "rm", "KEY"],
    ] {
        let before = std::fs::read(a.dir.path().join("sync.json")).ok();
        a.run(&args, Run::agent()).await.expect(5);
        assert_eq!(std::fs::read(a.dir.path().join("sync.json")).ok(), before);
        assert_eq!(a.value("KEY").unwrap(), b"fake");
    }
    let mut denied = Run::human(vec![]);
    denied.local_auth.push_back(LocalAuthOutcome::Denied);
    a.run(&["sync", "add", "KEY"], denied).await.expect(5);
    assert!(!a.dir.path().join("sync.json").exists());
    a.run(&["sync", "add", "KEY"], Run::human(vec![]))
        .await
        .expect(5);
}
#[tokio::test]
async fn crash_after_local_and_remote_keychain_writes_recovers_journal() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    let mut crash = Run::agent().stdin(b"fake-crash-local".to_vec());
    crash.env.push(("TEST_SYNC_CRASH".into(), "1".into()));
    a.run(&["set", "KEY"], crash).await.expect(1);
    assert!(!state(&a)["journal"].is_null());
    pump(&a, &b).await;
    assert!(state(&a)["journal"].is_null());
    let mut crash = human(vec![Answer::Select(0)]);
    crash.env.push(("TEST_SYNC_CRASH".into(), "1".into()));
    b.run(&["sync", "review"], crash).await.expect(1);
    assert!(!state(&b)["journal"].is_null());
    assert_eq!(b.value("KEY").unwrap(), b"fake-crash-local");
    pump(&a, &b).await;
    assert!(state(&b)["journal"].is_null());
    assert_eq!(head(&a), head(&b));
}
#[tokio::test]
async fn unknown_peer_gets_exactly_one_hello_and_no_offer_until_reply() {
    let (a, b, relay) = devices().await;
    a.set("KEY", b"fake").await;
    a.run(&["sync", "add", "KEY", "--peers", "bravo"], human(vec![]))
        .await
        .expect(8);
    for _ in 0..3 {
        a.run(&["sync"], Run::agent()).await.expect(8);
    }
    let (id, owner) = b.inbox_credentials();
    let listing = relay
        .list_messages(&id, &owner, std::time::Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(listing.messages.len(), 1);
    let key = b.store().get_internal("device-key").unwrap().unwrap();
    let key = kc_proto::DeviceKeyPair::from_secret_bytes(key.as_bytes()).unwrap();
    let sender = b.peers().find("alpha").unwrap().device_pk;
    let bytes = kc_proto::relay::message_body(&listing.messages[0]).unwrap();
    let opened = kc_proto::inbox::open_any(
        &bytes,
        &[&key],
        |_| Some(sender),
        |_| false,
        kc_proto::inbox::unix_now(),
    )
    .unwrap();
    assert!(matches!(
        opened.body,
        kc_proto::inbox::Body::Sync(SyncMsg::Hello {
            is_reply: false,
            ..
        })
    ));
}
#[tokio::test]
async fn freeze_holds_changes_and_status_and_state_never_contain_values() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    b.run(&["sync", "freeze"], Run::agent()).await.expect(8);
    a.set("KEY", b"fake-freeze-secret").await;
    pump(&a, &b).await;
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    let status = b.run(&["sync", "status", "--json"], Run::agent()).await;
    status.expect(8);
    assert!(status.stdout_text().contains("frozen"));
    for text in [
        status.stdout_text(),
        std::fs::read_to_string(b.dir.path().join("sync.json")).unwrap(),
    ] {
        assert!(!text.contains("fake-"));
    }
    b.run(&["sync", "unfreeze"], human(vec![])).await.expect(8);
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(0);
    pump(&a, &b).await;
    assert_eq!(head(&a), head(&b));
}

#[tokio::test]
async fn stale_unseen_offer_is_ignored_and_digest_recovers_a_lost_leave() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    b.run(&["sync", "rm", "KEY"], human(vec![])).await.expect(0);
    // Lose every Leave already posted to A.
    let (id, owner) = a.inbox_credentials();
    for msg in relay
        .list_messages(&id, &owner, std::time::Duration::ZERO)
        .await
        .unwrap()
        .messages
    {
        relay
            .delete_message(&id, &owner, &msg.msg_id)
            .await
            .unwrap();
    }
    post(
        &a,
        &b,
        &relay,
        SyncMsg::Offer {
            name: ItemName::new("KEY").unwrap(),
            vid: Vid::random(),
            lineage: vec![],
            kind: kc_proto::sync::ItemKind::Text,
            value: SecretBytes::from_slice(b"fake-stale-offer"),
            known_generation: 1,
        },
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
    post(
        &a,
        &b,
        &relay,
        SyncMsg::Digest {
            entries: vec![kc_proto::sync::DigestEntry {
                name: ItemName::new("KEY").unwrap(),
                generation: 1,
                head: head(&a),
            }],
        },
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(0);
    a.run(&["inbox"], Run::agent()).await.expect(8);
    assert!(
        a.run(&["sync", "status", "--json"], Run::agent())
            .await
            .stdout_text()
            .contains("re-offer needed")
    );
}
#[tokio::test]
async fn overwrite_attempts_trip_breaker_and_immutable_vid_is_quarantined() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let parent = head(&b);
    let first = Vid::random();
    for n in 0..6 {
        post(
            &a,
            &b,
            &relay,
            SyncMsg::Changes {
                changes: vec![Change {
                    name: ItemName::new("KEY").unwrap(),
                    generation: 1,
                    new_vid: if n == 0 { first } else { Vid::random() },
                    parents: vec![parent],
                    lineage: vec![parent],
                    op: Op::Put {
                        kind: kc_proto::sync::ItemKind::Text,
                        value: SecretBytes::from_slice(format!("fake-{n}").as_bytes()),
                    },
                    approval_ref: None,
                }],
            },
        )
        .await;
    }
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let status = b.run(&["sync", "status", "--json"], Run::agent()).await;
    let json: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(json["peers"][0]["breaker"], true);
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    b.run(&["sync", "unfreeze"], human(vec![])).await.expect(8);
    post(
        &a,
        &b,
        &relay,
        SyncMsg::Changes {
            changes: vec![Change {
                name: ItemName::new("KEY").unwrap(),
                generation: 1,
                new_vid: first,
                parents: vec![parent],
                lineage: vec![parent],
                op: Op::Put {
                    kind: kc_proto::sync::ItemKind::Text,
                    value: SecretBytes::from_slice(b"fake-mutated-vid"),
                },
                approval_ref: None,
            }],
        },
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert!(state(&b)["peers"].as_object().unwrap().values().any(|p| {
        p["quarantine"]
            .as_array()
            .unwrap()
            .contains(&Value::String("KEY".into()))
    }));
}
#[tokio::test]
async fn capacity_defers_seventeenth_proposal_without_storing_its_value() {
    let (a, b, relay) = devices().await;
    for n in 0..17 {
        post(
            &a,
            &b,
            &relay,
            SyncMsg::Offer {
                name: ItemName::new(&format!("KEY{n}")).unwrap(),
                vid: Vid::random(),
                lineage: vec![],
                known_generation: 0,
                kind: kc_proto::sync::ItemKind::Text,
                value: SecretBytes::from_slice(b"fake-capacity"),
            },
        )
        .await;
    }
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let s = state(&b);
    assert_eq!(s["candidates"].as_object().unwrap().len(), 16);
    assert_eq!(s["slots"].as_object().unwrap().len(), 16);
    assert_eq!(s["capacity_blocked"], true);
    assert!(b.value("KEY16").is_none());
}
#[tokio::test]
async fn recovery_never_overwrites_a_third_value_written_after_crash() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-remote-intent").await;
    pump(&a, &b).await;
    let mut crash = human(vec![Answer::Select(0)]);
    crash.env.push(("TEST_SYNC_CRASH".into(), "1".into()));
    b.run(&["sync", "review"], crash).await.expect(1);
    b.store()
        .set(
            "KEY",
            b"fake-third-value",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    b.run(&["sync"], Run::agent()).await.expect(8);
    assert_eq!(b.value("KEY").unwrap(), b"fake-third-value");
    assert_eq!(state(&b)["items"]["KEY"]["conflict"], true);
    assert!(state(&b)["journal"].is_null());
}
#[tokio::test]
async fn restore_and_adopt_publish_local_versions_and_checkpoint_confirmation_is_gated() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-next").await;
    let before = head(&a);
    a.run(&["restore", "KEY"], Run::agent()).await.expect(0);
    assert_ne!(before, head(&a));
    assert_eq!(a.value("KEY").unwrap(), b"fake-initial-secret");
    a.memory()
        .insert("foreign-service", "account", b"fake-adopted");
    let before = head(&a);
    a.run(
        &[
            "adopt",
            "--service",
            "foreign-service",
            "--account",
            "account",
            "--as",
            "KEY",
        ],
        Run::agent(),
    )
    .await
    .expect(0);
    assert_ne!(before, head(&a));
    assert_eq!(a.value("KEY").unwrap(), b"fake-adopted");
    a.run(
        &["sync", "status", "--confirm-checkpoint", "KEY"],
        Run::agent(),
    )
    .await
    .expect(5);
    a.run(
        &["sync", "status", "--confirm-checkpoint", "KEY"],
        human(vec![]),
    )
    .await
    .expect(8);
    a.set("KEY", b"fake-later").await;
    a.run(&["sync", "restore-checkpoint", "KEY"], human(vec![]))
        .await
        .expect(8);
    assert_eq!(a.value("KEY").unwrap(), b"fake-adopted");
}
#[tokio::test]
async fn rejected_held_change_is_not_recreated_by_retransmission() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let parent = head(&b);
    let vid = Vid::random();
    let message = SyncMsg::Changes {
        changes: vec![Change {
            name: ItemName::new("KEY").unwrap(),
            generation: 1,
            new_vid: vid,
            parents: vec![parent],
            lineage: vec![parent],
            op: Op::Put {
                kind: kc_proto::sync::ItemKind::Text,
                value: SecretBytes::from_slice(b"fake-rejected"),
            },
            approval_ref: None,
        }],
    };
    post(&a, &b, &relay, message.clone()).await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    b.run(&["sync", "review"], human(vec![Answer::Select(1)]))
        .await
        .expect(0);
    post(&a, &b, &relay, message).await;
    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
}

#[tokio::test]
async fn legacy_overwrite_flag_and_code_receive_cannot_bypass_local_confirmation() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.store()
        .set(
            "KEY",
            b"fake-legacy-terminal",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    a.run(&["send", "KEY", "--to", "bravo"], Run::agent())
        .await
        .expect(0);
    let before = std::fs::read(b.dir.path().join("sync.json")).unwrap();
    b.run(&["inbox", "--on-conflict", "overwrite"], Run::agent())
        .await
        .expect(5);
    assert_eq!(
        std::fs::read(b.dir.path().join("sync.json")).unwrap(),
        before
    );
    b.run(&["receive", "--on-conflict", "overwrite"], Run::agent())
        .await
        .expect(5);
    assert_eq!(
        std::fs::read(b.dir.path().join("sync.json")).unwrap(),
        before
    );
    b.run(
        &["inbox", "--on-conflict", "overwrite"],
        Run::human(vec![Answer::Yes]),
    )
    .await
    .expect(5);
    assert_eq!(state(&b)["candidates"].as_object().unwrap().len(), 1);
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    // The accepted v1 value is this device's own change, queued for the sync scope.
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(8);
    assert_eq!(b.value("KEY").unwrap(), b"fake-legacy-terminal");
    assert!(outbox_has(&b, head(&b)));
    a.store()
        .set(
            "KEY",
            b"fake-code-overwrite",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    let (rx, tx) = transfer(
        &b,
        &["receive", "--on-conflict", "overwrite"],
        Run::human(vec![Answer::Yes]),
        &a,
        &["send", "KEY"],
        |code| Run::human(vec![Answer::Text(code), Answer::Yes]),
    )
    .await;
    rx.expect(5);
    tx.expect(8);
    assert_eq!(b.value("KEY").unwrap(), b"fake-legacy-terminal");
}
#[tokio::test]
async fn local_change_between_receive_and_review_becomes_conflict() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-incoming").await;
    pump(&a, &b).await;
    b.set("KEY", b"fake-intervening-local").await;
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(8);
    assert_eq!(b.value("KEY").unwrap(), b"fake-intervening-local");
    assert_eq!(state(&b)["items"]["KEY"]["conflict"], true);
}
#[tokio::test]
async fn sync_peer_removal_is_locally_confirmed_and_stops_outgoing_updates() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.run(&["sync", "peer", "rm", "bravo"], Run::agent())
        .await
        .expect(5);
    a.run(&["sync", "peer", "rm", "bravo"], human(vec![]))
        .await
        .expect(0);
    a.set("KEY", b"fake-out-of-scope").await;
    pump(&a, &b).await;
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    assert!(
        state(&a)["items"]["KEY"]["scope"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

#[tokio::test]
async fn freeze_retains_immutable_vid_violation_but_review_cannot_apply_it() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let vid = head(&b);
    b.run(&["sync", "freeze"], Run::agent()).await.expect(8);
    post(
        &a,
        &b,
        &relay,
        SyncMsg::Changes {
            changes: vec![Change {
                name: ItemName::new("KEY").unwrap(),
                generation: 1,
                new_vid: vid,
                parents: vec![],
                lineage: vec![vid],
                op: Op::Put {
                    kind: kc_proto::sync::ItemKind::Text,
                    value: SecretBytes::from_slice(b"fake-mutation-while-frozen"),
                },
                approval_ref: None,
            }],
        },
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert!(
        state(&b)["candidates"]
            .as_object()
            .unwrap()
            .values()
            .any(|c| c["invalid_binding"] == true && c["category"] == "held")
    );
    b.run(&["sync", "unfreeze"], human(vec![])).await.expect(8);
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(8);
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    assert_eq!(state(&b)["items"]["KEY"]["conflict"], true);
}

#[tokio::test]
async fn rejecting_a_proposal_blocks_retries_but_an_explicit_reoffer_is_fresh() {
    let (a, b, _) = devices().await;
    a.set("KEY", b"fake-proposal").await;
    a.run(&["sync", "add", "KEY", "--peers", "bravo"], human(vec![]))
        .await
        .expect(8);
    pump(&a, &b).await;
    b.run(&["sync", "review"], human(vec![Answer::Select(1)]))
        .await
        .expect(0);
    pump(&a, &b).await;
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
    let old = head(&a);
    a.run(&["sync", "offer", "KEY", "--peers", "bravo"], Run::agent())
        .await
        .expect(8);
    assert_ne!(old, head(&a));
    pump(&a, &b).await;
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(0);
    pump(&a, &b).await;
    assert_eq!(head(&a), head(&b));
}

fn save_state(d: &Device<MemoryRelay>, s: &Value) {
    std::fs::write(
        d.dir.path().join("sync.json"),
        serde_json::to_vec_pretty(s).unwrap(),
    )
    .unwrap();
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}
fn fp_slot(name: &str, vid: Vid) -> String {
    use sha2::{Digest, Sha256};
    format!(
        "sync/fp/{}/{}",
        hex(&Sha256::digest(name.as_bytes())),
        hex(&vid.0)
    )
}
fn offer_message(name: &str, vid: Vid, value: &[u8], generation: u64) -> SyncMsg {
    SyncMsg::Offer {
        name: ItemName::new(name).unwrap(),
        vid,
        lineage: vec![],
        kind: kc_proto::sync::ItemKind::Text,
        value: SecretBytes::from_slice(value),
        known_generation: generation,
    }
}
fn change_message(name: &str, vid: Vid, parent: Vid, value: &[u8]) -> SyncMsg {
    SyncMsg::Changes {
        changes: vec![Change {
            name: ItemName::new(name).unwrap(),
            generation: 1,
            new_vid: vid,
            parents: vec![parent],
            lineage: vec![parent],
            op: Op::Put {
                kind: kc_proto::sync::ItemKind::Text,
                value: SecretBytes::from_slice(value),
            },
            approval_ref: None,
        }],
    }
}
fn confirmations(out: &common::Output) -> Vec<&str> {
    out.prompts
        .iter()
        .filter_map(|p| p.strip_prefix("local confirmation: "))
        .collect()
}

#[tokio::test]
async fn failed_hello_delivery_is_retried_on_next_sync() {
    let (a, b, relay) = devices().await;
    let fault = common::fault_relay::FaultRelay::new(relay.clone());
    let a = Device {
        name: a.name,
        dir: a.dir,
        keychain: a.keychain,
        net: fault.clone(),
        env: a.env,
    };
    a.set("KEY", b"fake-hello").await;
    fault
        .fail_post
        .store(true, std::sync::atomic::Ordering::SeqCst);
    a.run(&["sync", "add", "KEY", "--peers", "bravo"], human(vec![]))
        .await
        .expect(6);
    let peer = b.peers().find("alpha").unwrap().fingerprint.to_hex();
    let remote = a.peers().find("bravo").unwrap().fingerprint.to_hex();
    assert_eq!(state(&a)["peers"][&remote]["hello_sent"], false);
    let (id, owner) = b.inbox_credentials();
    assert!(
        relay
            .list_messages(&id, &owner, std::time::Duration::ZERO)
            .await
            .unwrap()
            .messages
            .is_empty()
    );
    a.run(&["sync"], Run::agent()).await.expect(8);
    assert_eq!(state(&a)["peers"][&remote]["hello_sent"], true);
    assert_eq!(
        relay
            .list_messages(&id, &owner, std::time::Duration::ZERO)
            .await
            .unwrap()
            .messages
            .len(),
        1
    );
    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(state(&b)["peers"][peer]["capable"], true);
}

#[tokio::test]
async fn corrupt_sync_state_does_not_break_get_or_exec() {
    let a = Device::new("alpha", MemoryRelay::new());
    a.set("KEY", b"fake-independent").await;
    std::fs::write(a.dir.path().join("sync.json"), b"broken json").unwrap();
    a.run(&["get", "KEY", "--fingerprint"], Run::agent())
        .await
        .expect(0);
    a.run(&["exec", "--env", "KEY=KEY", "--", "true"], Run::agent())
        .await
        .expect(0);
    assert_eq!(
        std::fs::read(a.dir.path().join("sync.json")).unwrap(),
        b"broken json"
    );
}

#[tokio::test]
async fn confirmation_reasons_name_actions_and_follow_selection() {
    let a = Device::new("alpha", MemoryRelay::new());
    for name in ["a", "b", "c", "d", "e", "f", "g"] {
        a.set(name, b"fake").await;
    }
    let mut denied = Run::human(vec![Answer::Multi(vec![0, 1, 2, 3, 4, 5, 6])]);
    denied.local_auth.push_back(LocalAuthOutcome::Denied);
    let out = a.run(&["sync", "add"], denied).await;
    out.expect(5);
    assert!(out.prompts[0].contains("Select sync items"));
    assert_eq!(confirmations(&out), vec!["kc sync add a, b, c and 4 more"]);
    assert!(!a.dir.path().join("sync.json").exists());
    let cases = [
        (vec!["sync", "rm", "a", "b"], "kc sync rm a, b"),
        (
            vec!["sync", "peer", "add", "bravo"],
            "kc sync peer add bravo",
        ),
        (vec!["sync", "peer", "rm", "bravo"], "kc sync peer rm bravo"),
        (
            vec!["sync", "resolve", "a", "--keep", "mine"],
            "Resolve a: keep mine",
        ),
        (
            vec!["sync", "restore-checkpoint", "a"],
            "Restore a to its checkpoint",
        ),
        (vec!["sync", "unfreeze"], "Unfreeze sync"),
        (
            vec!["sync", "status", "--confirm-checkpoint", "a"],
            "Confirm the current value of a as its checkpoint",
        ),
    ];
    for (args, expected) in cases {
        let out = a.run(&args, Run::human(vec![])).await;
        out.expect(5);
        assert_eq!(confirmations(&out), vec![expected]);
        assert!(!a.dir.path().join("sync.json").exists());
    }
}

#[tokio::test]
async fn review_accept_and_reject_share_one_confirmation_and_denial_changes_nothing() {
    let (a, b, relay) = devices().await;
    for name in ["A", "B"] {
        post(
            &a,
            &b,
            &relay,
            offer_message(name, Vid::random(), b"fake-review", 0),
        )
        .await;
    }
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let before = std::fs::read(b.dir.path().join("sync.json")).unwrap();
    let mut denied = Run::human(vec![Answer::Select(0), Answer::Select(1)]);
    denied.local_auth.push_back(LocalAuthOutcome::Denied);
    let out = b.run(&["sync", "review"], denied).await;
    out.expect(5);
    assert_eq!(confirmations(&out).len(), 1);
    assert!(confirmations(&out)[0].contains("from alpha; reject"));
    assert_eq!(
        std::fs::read(b.dir.path().join("sync.json")).unwrap(),
        before
    );
    assert!(b.value("A").is_none() && b.value("B").is_none());
    assert!(state(&b)["items"].as_object().unwrap().is_empty());
    let out = b
        .run(
            &["sync", "review"],
            human(vec![Answer::Select(0), Answer::Select(1)]),
        )
        .await;
    out.expect(0);
    assert_eq!(confirmations(&out).len(), 1);
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
    assert_eq!(state(&b)["items"].as_object().unwrap().len(), 1);
}

#[tokio::test]
async fn held_review_denied_and_agent_mutations_preserve_existing_state() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-denied").await;
    pump(&a, &b).await;
    let before = std::fs::read(b.dir.path().join("sync.json")).unwrap();
    let mut denied = Run::human(vec![Answer::Select(0)]);
    denied.local_auth.push_back(LocalAuthOutcome::Denied);
    b.run(&["sync", "review"], denied).await.expect(5);
    assert_eq!(
        std::fs::read(b.dir.path().join("sync.json")).unwrap(),
        before
    );
    for args in [
        vec!["sync", "resolve", "KEY", "--keep", "mine"],
        vec!["sync", "restore-checkpoint", "KEY"],
        vec!["sync", "rm", "KEY"],
    ] {
        b.run(&args, Run::agent()).await.expect(5);
        assert_eq!(
            std::fs::read(b.dir.path().join("sync.json")).unwrap(),
            before
        );
    }
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    assert_eq!(state(&b)["candidates"].as_object().unwrap().len(), 1);
}

#[tokio::test]
async fn legacy_policies_hold_and_denial_continues_batch_then_one_l_replaces() {
    for policy in [None, Some("skip"), Some("rename"), Some("overwrite")] {
        let (a, b, _) = devices().await;
        enroll(&a, &b).await;
        a.store()
            .set(
                "KEY",
                b"fake-legacy-batch",
                kc_store::ItemKind::Text,
                kc_store::Origin::Local,
            )
            .unwrap();
        a.set("OTHER", b"fake-other").await;
        a.run(&["send", "KEY", "OTHER", "--to", "bravo"], Run::agent())
            .await
            .expect(0);
        let mut args = vec!["inbox"];
        if let Some(p) = policy {
            args.extend(["--on-conflict", p]);
        }
        let mut run = Run::human(vec![Answer::Yes]);
        if policy == Some("overwrite") {
            run.local_auth.push_back(LocalAuthOutcome::Denied);
        }
        let out = b.run(&args, run).await;
        out.expect(if policy == Some("overwrite") { 5 } else { 8 });
        assert_eq!(b.value("OTHER").unwrap(), b"fake-other");
        assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
        assert_eq!(
            confirmations(&out).len(),
            usize::from(policy == Some("overwrite"))
        );
        assert!(b.value("KEY-2").is_none());
        assert_eq!(state(&b)["candidates"].as_object().unwrap().len(), 1);
        assert!(out.stderr.contains("run `kc sync review`"));
    }
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.store()
        .set(
            "KEY",
            b"fake-inline",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    a.run(&["send", "KEY", "--to", "bravo"], Run::agent())
        .await
        .expect(0);
    let out = b
        .run(
            &["inbox", "--on-conflict", "overwrite"],
            human(vec![Answer::Yes]),
        )
        .await;
    // Pending only because the accepted v1 value is queued for the sync scope.
    out.expect(8);
    assert!(outbox_has(&b, head(&b)));
    assert_eq!(
        confirmations(&out),
        vec!["Replace KEY with the value from alpha"]
    );
    assert_eq!(b.value("KEY").unwrap(), b"fake-inline");
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
}

#[tokio::test]
async fn status_and_review_fingerprints_match_get_across_devices() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    let fp = a
        .run(&["get", "KEY", "--fingerprint"], Run::agent())
        .await
        .stdout_text();
    for d in [&a, &b] {
        let out = d.run(&["sync", "status", "--json"], Run::agent()).await;
        let json: Value = serde_json::from_slice(&out.stdout).unwrap();
        assert_eq!(json["items"][0]["fingerprint"], fp.trim());
    }
    a.set("KEY", b"fake-fingerprint-new").await;
    pump(&a, &b).await;
    let proposed = a
        .run(&["get", "KEY", "--fingerprint"], Run::agent())
        .await
        .stdout_text();
    let out = b.run(&["sync", "status", "--json"], Run::agent()).await;
    let json: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(json["candidates"][0]["fingerprint"], proposed.trim());
    let out = b
        .run(&["sync", "review"], Run::human(vec![Answer::Select(2)]))
        .await;
    assert!(out.prompts[0].contains(fp.trim()));
    assert!(out.prompts[0].contains(proposed.trim()));
}

#[tokio::test]
async fn offers_from_disabled_or_tripped_peers_are_logged_only() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    b.run(&["sync", "peer", "rm", "alpha"], human(vec![]))
        .await
        .expect(0);
    post(
        &a,
        &b,
        &relay,
        offer_message("DISABLED", Vid::random(), b"fake-disabled", 0),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
    b.run(&["sync", "peer", "add", "alpha"], human(vec![]))
        .await
        .expect(8);
    // Peer rm removed KEY's scope. Restore it through the explicit add operation.
    b.run(&["sync", "add", "KEY", "--peers", "alpha"], human(vec![]))
        .await
        .expect(8);
    let parent = head(&b);
    for _ in 0..6 {
        let mut message = change_message("KEY", Vid::random(), parent, b"fake-trip");
        if let SyncMsg::Changes { changes } = &mut message {
            changes[0].generation = 2;
        }
        post(&a, &b, &relay, message).await;
    }
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let out = b.run(&["sync", "status", "--json"], Run::agent()).await;
    let status: Value = serde_json::from_slice(&out.stdout).unwrap();
    assert_eq!(status["peers"][0]["breaker"], true);
    let before = state(&b)["candidates"].clone();
    post(
        &a,
        &b,
        &relay,
        offer_message("BLOCKED", Vid::random(), b"fake-blocked", 0),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert_eq!(state(&b)["candidates"], before);
    assert!(
        std::fs::read_to_string(b.dir.path().join("sync.log"))
            .unwrap()
            .contains("Ignored a sync offer")
    );
}

#[tokio::test]
async fn offer_during_conflict_is_a_candidate_and_review_cannot_discard_it() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-conflict-a").await;
    b.set("KEY", b"fake-conflict-b").await;
    pump(&a, &b).await;
    let before = state(&b)["candidates"].as_object().unwrap().len();
    let offered = Vid::random();
    post(
        &a,
        &b,
        &relay,
        offer_message("KEY", offered, b"fake-conflict-offer", 1),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let s = state(&b);
    assert_eq!(s["candidates"].as_object().unwrap().len(), before + 1);
    assert!(
        s["candidates"]
            .as_object()
            .unwrap()
            .values()
            .any(
                |c| c["version"]["vid"] == serde_json::to_value(offered).unwrap()
                    && c["category"] == "conflict"
            )
    );
    b.run(&["sync", "review"], Run::human(vec![]))
        .await
        .expect(8);
    assert_eq!(state(&b)["candidates"], s["candidates"]);
    assert_eq!(b.value("KEY").unwrap(), b"fake-conflict-b");
}

#[tokio::test]
async fn offer_during_conflict_at_another_generation_stays_a_proposal() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-conflict-a").await;
    b.set("KEY", b"fake-conflict-b").await;
    pump(&a, &b).await;
    let offered = Vid::random();
    // Not stale (above the current generation) but not the registration in conflict either.
    post(
        &a,
        &b,
        &relay,
        offer_message("KEY", offered, b"fake-conflict-offer", 2),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let s = state(&b);
    let offer = s["candidates"]
        .as_object()
        .unwrap()
        .values()
        .find(|c| c["version"]["vid"] == serde_json::to_value(offered).unwrap())
        .expect("the offer is kept");
    assert_eq!(offer["category"], "proposal");
    // Accepting it would end the conflict and drop the other candidates; resolve must.
    let candidates = s["candidates"].clone();
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(8);
    let after = state(&b);
    assert_eq!(after["candidates"], candidates);
    assert_eq!(after["items"]["KEY"]["conflict"], true);
    assert_eq!(b.value("KEY").unwrap(), b"fake-conflict-b");
}

#[tokio::test]
async fn sync_envelope_replay_is_skipped_by_seen_set() {
    let (a, b, relay) = devices().await;
    post(
        &a,
        &b,
        &relay,
        SyncMsg::Hello {
            features: vec!["sync-phase1".into()],
            is_reply: false,
        },
    )
    .await;
    let (id, owner) = b.inbox_credentials();
    let listed = relay
        .list_messages(&id, &owner, std::time::Duration::ZERO)
        .await
        .unwrap();
    let body = kc_proto::relay::message_body(&listed.messages[0]).unwrap();
    b.run(&["inbox"], Run::agent()).await.expect(0);
    let (aid, aowner) = a.inbox_credentials();
    let replies = relay
        .list_messages(&aid, &aowner, std::time::Duration::ZERO)
        .await
        .unwrap()
        .messages
        .len();
    relay
        .post_message(&id, &a.writer_bearer("bravo"), &body)
        .await
        .unwrap();
    b.run(&["inbox"], Run::agent()).await.expect(7);
    assert_eq!(
        relay
            .list_messages(&aid, &aowner, std::time::Duration::ZERO)
            .await
            .unwrap()
            .messages
            .len(),
        replies
    );
}

#[tokio::test]
async fn convergence_binding_failure_quarantines_only_that_flow_and_rejects_ack() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let vid = Vid::random();
    // A valid stored record outside the bounded known list, with an incompatible fp.
    b.store()
        .set_internal(
            &fp_slot("KEY", vid),
            &serde_json::to_vec(&kc_sync::VidRecord {
                fp: kc_sync::Fp([7; 32]),
                parents: vec![],
            })
            .unwrap(),
        )
        .unwrap();
    let old_head = head(&b);
    post(
        &a,
        &b,
        &relay,
        change_message("KEY", vid, old_head, b"fake-initial-secret"),
    )
    .await;
    post(
        &a,
        &b,
        &relay,
        offer_message("OTHER", Vid::random(), b"fake-next-message", 0),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert_eq!(head(&b), old_head);
    assert!(state(&b)["peers"].as_object().unwrap().values().any(|p| {
        p["quarantine"]
            .as_array()
            .unwrap()
            .contains(&Value::String("KEY".into()))
    }));
    assert!(
        state(&b)["candidates"]
            .as_object()
            .unwrap()
            .values()
            .any(|c| c["version"]["name"] == "OTHER")
    );
    assert!(
        state(&b)["receipts"]
            .as_object()
            .unwrap()
            .values()
            .any(|r| r[0] == "Rejected")
    );
    let (id, owner) = a.inbox_credentials();
    let key = a.store().get_internal("device-key").unwrap().unwrap();
    let key = kc_proto::DeviceKeyPair::from_secret_bytes(key.as_bytes()).unwrap();
    let sender = a.peers().find("bravo").unwrap().device_pk;
    let mut rejected = false;
    for envelope in relay
        .list_messages(&id, &owner, std::time::Duration::ZERO)
        .await
        .unwrap()
        .messages
    {
        let bytes = kc_proto::relay::message_body(&envelope).unwrap();
        let opened = kc_proto::inbox::open_any(
            &bytes,
            &[&key],
            |_| Some(sender),
            |_| false,
            kc_proto::inbox::unix_now(),
        )
        .unwrap();
        if let kc_proto::inbox::Body::Sync(SyncMsg::Ack { results }) = opened.body {
            rejected |= results.iter().any(|(id, result)| {
                id.new_vid == vid && *result == kc_proto::sync::AckResult::Rejected
            });
        }
    }
    assert!(rejected);
}

#[tokio::test]
async fn offer_then_change_binds_parents_and_promotes_proposal_to_held() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let vid = Vid::random();
    post(
        &a,
        &b,
        &relay,
        offer_message("KEY", vid, b"fake-promoted", 1),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let parent = head(&b);
    post(
        &a,
        &b,
        &relay,
        change_message("KEY", vid, parent, b"fake-promoted"),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let s = state(&b);
    assert_eq!(s["candidates"].as_object().unwrap().len(), 1);
    let c = s["candidates"]
        .as_object()
        .unwrap()
        .values()
        .next()
        .unwrap();
    assert_eq!(c["category"], "held");
    assert_eq!(
        c["version"]["parents"],
        serde_json::to_value(vec![parent]).unwrap()
    );
    assert_eq!(c["invalid_binding"], false);
    assert!(s["unbound"].as_array().unwrap().is_empty());
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(0);
    assert_eq!(b.value("KEY").unwrap(), b"fake-promoted");
}

#[tokio::test]
async fn stale_ack_revokes_grant_without_inventing_generation_or_revoking_newer_accept() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-stale-ack").await;
    let vid = head(&a);
    let stale = SyncMsg::Ack {
        results: vec![(
            kc_proto::sync::ChangeId {
                name: ItemName::new("KEY").unwrap(),
                generation: 1,
                new_vid: vid,
            },
            kc_proto::sync::AckResult::StaleGeneration,
        )],
    };
    // post helper sends A -> B, so construct the reverse envelope here.
    let key = b.store().get_internal("device-key").unwrap().unwrap();
    let key = kc_proto::DeviceKeyPair::from_secret_bytes(key.as_bytes()).unwrap();
    let peer = b.peers().find("alpha").unwrap().clone();
    let sealed = kc_proto::inbox::seal_v2(
        &key,
        &peer.device_pk,
        &kc_proto::inbox::Body::Sync(stale.clone()),
        std::time::Duration::from_secs(86400),
        kc_proto::inbox::unix_now(),
    )
    .unwrap();
    relay
        .post_message(
            &a.inbox_credentials().0,
            &b.writer_bearer("alpha"),
            &sealed.body,
        )
        .await
        .unwrap();
    a.run(&["inbox"], Run::agent()).await.expect(8);
    let peer_id = a.peers().find("bravo").unwrap().fingerprint.to_hex();
    assert_eq!(
        state(&a)["generations"]["remote"][&peer_id]["KEY"]["accepted"],
        false
    );
    assert_eq!(
        state(&a)["generations"]["remote"][&peer_id]["KEY"]["generation"],
        1
    );
    a.set("KEY", b"fake-no-stale-send").await;
    let s = state(&a);
    let outbox: kc_sync::Outbox = serde_json::from_value(s["outbox"].clone()).unwrap();
    assert!(
        outbox
            .pending(&kc_sync::PeerId(peer_id.clone()))
            .next()
            .is_none()
    );

    // Recreate a pending old delivery with a newer accepted epoch to prove reordering safety.
    let mut s = state(&a);
    let mut outbox: kc_sync::Outbox = serde_json::from_value(s["outbox"].clone()).unwrap();
    outbox.enqueue(
        kc_sync::PeerId(peer_id.clone()),
        kc_sync::ChangeId {
            name: "KEY".into(),
            generation: 1,
            new_vid: kc_sync::Vid(vid.0),
        },
    );
    s["outbox"] = serde_json::to_value(outbox).unwrap();
    s["generations"]["remote"][&peer_id]["KEY"]["accepted"] = true.into();
    s["generations"]["remote"][&peer_id]["KEY"]["generation"] = 2.into();
    save_state(&a, &s);
    let sealed = kc_proto::inbox::seal_v2(
        &key,
        &peer.device_pk,
        &kc_proto::inbox::Body::Sync(stale),
        std::time::Duration::from_secs(86400),
        kc_proto::inbox::unix_now(),
    )
    .unwrap();
    relay
        .post_message(
            &a.inbox_credentials().0,
            &b.writer_bearer("alpha"),
            &sealed.body,
        )
        .await
        .unwrap();
    a.run(&["inbox"], Run::agent()).await.expect(8);
    assert_eq!(
        state(&a)["generations"]["remote"][&peer_id]["KEY"]["accepted"],
        true
    );
}

#[tokio::test]
async fn candidate_eviction_collects_base_and_startup_collects_only_orphan_snapshots() {
    let (a, b, relay) = devices().await;
    for n in 0..16 {
        post(
            &a,
            &b,
            &relay,
            offer_message(&format!("P{n}"), Vid::random(), b"fake-eviction", 0),
        )
        .await;
    }
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let before = state(&b);
    let base_slots = before["candidates"]
        .as_object()
        .unwrap()
        .iter()
        .map(|(slot, c)| (slot.clone(), c["base_record"].as_str().unwrap().to_owned()))
        .collect::<Vec<_>>();
    b.set("LOCAL", b"fake-local").await;
    b.run(&["sync", "add", "LOCAL", "--peers", "alpha"], human(vec![]))
        .await
        .expect(8);
    let after = state(&b);
    let evicted = base_slots
        .iter()
        .filter(|(slot, _)| after["candidates"].get(slot).is_none())
        .collect::<Vec<_>>();
    assert_eq!(evicted.len(), 1);
    for (slot, base) in evicted {
        assert!(b.store().get_internal(slot).unwrap().is_none());
        assert!(b.store().get_internal(base).unwrap().is_none());
    }
    let retained = after["slots"]
        .as_object()
        .unwrap()
        .keys()
        .find(|s| s.starts_with("sync/snapshot/"))
        .unwrap()
        .clone();
    let orphan = format!("sync/snapshot/{}", hex(&Vid::random().0));
    b.store().set_internal(&orphan, b"fake-orphan").unwrap();
    let mut injected = after;
    injected["slots"][&orphan] = "ConflictCandidate".into();
    let queued_vid = Vid::random();
    let queued_slot = format!("sync/snapshot/{}", hex(&queued_vid.0));
    b.store()
        .set_internal(&queued_slot, b"fake-queued")
        .unwrap();
    injected["slots"][&queued_slot] = "ConflictCandidate".into();
    let mut outbox: kc_sync::Outbox = serde_json::from_value(injected["outbox"].clone()).unwrap();
    outbox.enqueue(
        kc_sync::PeerId(b.peers().find("alpha").unwrap().fingerprint.to_hex()),
        kc_sync::ChangeId {
            name: "QUEUED".into(),
            generation: 1,
            new_vid: kc_sync::Vid(queued_vid.0),
        },
    );
    injected["outbox"] = serde_json::to_value(outbox).unwrap();
    save_state(&b, &injected);
    b.run(&["sync", "status", "--json"], Run::agent())
        .await
        .expect(8);
    assert!(b.store().get_internal(&orphan).unwrap().is_none());
    assert!(state(&b)["slots"].get(&orphan).is_none());
    assert!(b.store().get_internal(&retained).unwrap().is_some());
    assert!(state(&b)["slots"].get(&retained).is_some());
    assert!(b.store().get_internal(&queued_slot).unwrap().is_some());
    assert!(state(&b)["slots"].get(&queued_slot).is_some());
}

#[tokio::test]
async fn rejecting_proposal_deletes_binding_and_unbound_and_rm_releases_checkpoint() {
    let (a, b, relay) = devices().await;
    let vid = Vid::random();
    post(
        &a,
        &b,
        &relay,
        offer_message("PROPOSAL", vid, b"fake-proposal-gc", 0),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert!(
        b.store()
            .get_internal(&fp_slot("PROPOSAL", vid))
            .unwrap()
            .is_some()
    );
    assert_eq!(state(&b)["unbound"].as_array().unwrap().len(), 1);
    let before = std::fs::read(b.dir.path().join("sync.json")).unwrap();
    let out = b
        .run(&["sync", "review"], Run::human(vec![Answer::Select(1)]))
        .await;
    out.expect(5);
    assert_eq!(confirmations(&out).len(), 1);
    assert_eq!(
        std::fs::read(b.dir.path().join("sync.json")).unwrap(),
        before
    );
    let out = b
        .run(&["sync", "review"], human(vec![Answer::Select(1)]))
        .await;
    out.expect(0);
    assert_eq!(confirmations(&out).len(), 1);
    assert!(
        b.store()
            .get_internal(&fp_slot("PROPOSAL", vid))
            .unwrap()
            .is_none()
    );
    assert!(state(&b)["unbound"].as_array().unwrap().is_empty());
    enroll(&a, &b).await;
    b.run(
        &["sync", "status", "--confirm-checkpoint", "KEY"],
        human(vec![]),
    )
    .await
    .expect(0);
    let checkpoint = state(&b)["slots"]
        .as_object()
        .unwrap()
        .keys()
        .find(|s| s.starts_with("sync/kg/"))
        .unwrap()
        .clone();
    assert!(b.store().get_internal(&checkpoint).unwrap().is_some());
    b.run(&["sync", "rm", "KEY"], human(vec![])).await.expect(0);
    assert!(b.store().get_internal(&checkpoint).unwrap().is_none());
    assert!(state(&b)["slots"].get(&checkpoint).is_none());
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
}

fn holds_candidate(s: &Value, vid: Vid) -> bool {
    s["candidates"]
        .as_object()
        .unwrap()
        .keys()
        .any(|k| k.ends_with(&hex(&vid.0)))
}

#[tokio::test]
async fn evicted_proposal_forgets_its_binding_and_unbound_entry() {
    let (a, b, relay) = devices().await;
    let mut offers = Vec::new();
    for n in 0..16 {
        let name = format!("P{n}");
        let vid = Vid::random();
        post(
            &a,
            &b,
            &relay,
            offer_message(&name, vid, b"fake-eviction", 0),
        )
        .await;
        offers.push((name, vid));
    }
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert_eq!(state(&b)["unbound"].as_array().unwrap().len(), 16);
    b.set("LOCAL", b"fake-local").await;
    b.run(&["sync", "add", "LOCAL", "--peers", "alpha"], human(vec![]))
        .await
        .expect(8);
    let after = state(&b);
    let (evicted, kept): (Vec<_>, Vec<_>) = offers
        .iter()
        .partition(|(_, vid)| !holds_candidate(&after, *vid));
    assert_eq!(evicted.len(), 1);
    let (name, vid) = evicted[0];
    assert!(
        b.store()
            .get_internal(&fp_slot(name, *vid))
            .unwrap()
            .is_none()
    );
    let unbound = after["unbound"].as_array().unwrap();
    assert_eq!(unbound.len(), 15);
    assert!(!unbound.contains(&Value::from(format!("{name}:{}", hex(&vid.0)))));
    for (name, vid) in kept {
        assert!(
            b.store()
                .get_internal(&fp_slot(name, *vid))
                .unwrap()
                .is_some()
        );
    }
}

#[tokio::test]
async fn accepting_a_proposal_at_capacity_does_not_evict_itself() {
    let (a, b, relay) = devices().await;
    // Not a sync item, so accepting the offer reserves a checkpoint for the local value.
    b.set("TARGET", b"fake-target-local").await;
    // The smallest slot name: the checkpoint reservation's first eviction choice.
    let target = Vid([0; 16]);
    post(
        &a,
        &b,
        &relay,
        offer_message("TARGET", target, b"fake-target-offer", 0),
    )
    .await;
    let mut others = Vec::new();
    for n in 1..16 {
        let name = format!("P{n}");
        let vid = Vid::random();
        post(
            &a,
            &b,
            &relay,
            offer_message(&name, vid, b"fake-capacity", 0),
        )
        .await;
        others.push((name, vid));
    }
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert_eq!(state(&b)["candidates"].as_object().unwrap().len(), 16);
    let mut answers = vec![Answer::Select(0)];
    answers.extend(std::iter::repeat_with(|| Answer::Select(2)).take(15));
    let out = b.run(&["sync", "review"], human(answers)).await;
    out.expect(8);
    assert!(
        out.stderr.contains("Accepted TARGET from alpha."),
        "{}",
        out.stderr
    );
    assert_eq!(b.value("TARGET").unwrap(), b"fake-target-offer");
    let s = state(&b);
    let head: Vid = serde_json::from_value(s["items"]["TARGET"]["head"].clone()).unwrap();
    assert_eq!(head, target);
    assert!(
        b.store()
            .get_internal(&fp_slot("TARGET", target))
            .unwrap()
            .is_some()
    );
    assert_eq!(s["candidates"].as_object().unwrap().len(), 14);
    let evicted = others
        .iter()
        .filter(|(_, vid)| !holds_candidate(&s, *vid))
        .collect::<Vec<_>>();
    assert_eq!(evicted.len(), 1);
    let (name, vid) = evicted[0];
    assert!(
        b.store()
            .get_internal(&fp_slot(name, *vid))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn rejected_offer_tombstone_slides_on_retry_and_expires_after_silence() {
    let (a, b, relay) = devices().await;
    let vid = Vid::random();
    let offer = || offer_message("PROPOSAL", vid, b"fake-tombstone", 0);
    post(&a, &b, &relay, offer()).await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    b.run(&["sync", "review"], human(vec![Answer::Select(1)]))
        .await
        .expect(0);
    let s = state(&b);
    let key = s["rejected_offers"][0].as_str().unwrap().to_owned();
    let now = kc_proto::inbox::unix_now();
    assert!(s["rejected_until"][&key].as_i64().unwrap() > now);
    let mut s = s;
    s["rejected_until"][&key] = (now + 60).into();
    save_state(&b, &s);
    post(&a, &b, &relay, offer()).await;
    b.run(&["inbox"], Run::agent()).await.expect(0);
    let s = state(&b);
    assert!(s["candidates"].as_object().unwrap().is_empty());
    assert!(s["rejected_until"][&key].as_i64().unwrap() > now + 86400);
    let mut s = s;
    s["rejected_until"][&key] = 1.into();
    save_state(&b, &s);
    b.run(&["sync"], Run::agent()).await.expect(0);
    let s = state(&b);
    assert!(s["rejected_offers"].as_array().unwrap().is_empty());
    assert!(s["rejected_until"].as_object().unwrap().is_empty());
    post(&a, &b, &relay, offer()).await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert!(holds_candidate(&state(&b), vid));
}

#[tokio::test]
async fn legacy_rejected_offer_array_state_still_loads() {
    let (a, b, relay) = devices().await;
    let vid = Vid::random();
    let offer = || offer_message("PROPOSAL", vid, b"fake-legacy-tombstone", 0);
    post(&a, &b, &relay, offer()).await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    b.run(&["sync", "review"], human(vec![Answer::Select(1)]))
        .await
        .expect(0);
    // State written before expiries existed: only the tombstone array.
    let mut s = state(&b);
    let key = s["rejected_offers"][0].as_str().unwrap().to_owned();
    s.as_object_mut().unwrap().remove("rejected_until");
    save_state(&b, &s);
    b.run(&["sync"], Run::agent()).await.expect(0);
    let s = state(&b);
    // Older versions still read the array; the expiry lives beside it.
    assert_eq!(s["rejected_offers"], Value::from(vec![key.clone()]));
    assert!(s["rejected_until"][&key].as_i64().unwrap() > kc_proto::inbox::unix_now());
    post(&a, &b, &relay, offer()).await;
    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
}

#[tokio::test]
async fn unbound_entry_without_candidate_is_swept() {
    let (a, b, relay) = devices().await;
    let vid = Vid::random();
    post(
        &a,
        &b,
        &relay,
        offer_message("PROPOSAL", vid, b"fake-unbound", 0),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert!(
        b.store()
            .get_internal(&fp_slot("PROPOSAL", vid))
            .unwrap()
            .is_some()
    );
    // A candidate dropped without its binding, as eviction did before.
    let mut s = state(&b);
    s["candidates"] = serde_json::json!({});
    save_state(&b, &s);
    b.run(&["sync"], Run::agent()).await;
    assert!(state(&b)["unbound"].as_array().unwrap().is_empty());
    assert!(
        b.store()
            .get_internal(&fp_slot("PROPOSAL", vid))
            .unwrap()
            .is_none()
    );
}

#[tokio::test]
async fn full_capacity_scan_and_preserve_mine_leave_inbox_review_and_resolve_operational() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    // Pinned slots cannot be evicted. This isolates scan/preserve capacity failure
    // from the lower-priority eviction path exercised above.
    let mut s = state(&b);
    for n in 0..16 {
        let slot = format!("sync/kg/test-{n}");
        b.store().set_internal(&slot, b"fake-pinned").unwrap();
        s["slots"][slot] = "Checkpoint".into();
    }
    save_state(&b, &s);
    b.store()
        .set(
            "KEY",
            b"fake-out-of-band",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    post(
        &a,
        &b,
        &relay,
        SyncMsg::Hello {
            features: vec![],
            is_reply: true,
        },
    )
    .await;
    let out = b.run(&["inbox"], Run::agent()).await;
    out.expect(8);
    assert!(!out.stderr.contains("Sync storage is full"));
    let out = b.run(&["sync", "review"], Run::human(vec![])).await;
    out.expect(8);
    assert!(!out.stderr.contains("Sync storage is full"));
    let status = b.run(&["sync", "status", "--json"], Run::agent()).await;
    let status: Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(status["capacity_blocked"], true);
    assert!(
        std::fs::read_to_string(b.dir.path().join("sync.log"))
            .unwrap()
            .contains("Sync storage is full")
    );
    assert_eq!(b.value("KEY").unwrap(), b"fake-out-of-band");
    let out = b
        .run(&["sync", "resolve", "KEY", "--keep", "mine"], human(vec![]))
        .await;
    out.expect(8);
    // Resolve says why nothing was resolved instead of claiming success.
    assert!(
        out.stderr.contains("Sync storage is full"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("Resolved KEY"), "{}", out.stderr);
    assert_eq!(b.value("KEY").unwrap(), b"fake-out-of-band");
    // After capacity is freed, the same review/resolve path can recover normally.
    let mut s = state(&b);
    s["slots"]
        .as_object_mut()
        .unwrap()
        .retain(|slot, _| !slot.starts_with("sync/kg/test-"));
    save_state(&b, &s);
    b.run(&["sync", "resolve", "KEY", "--keep", "mine"], human(vec![]))
        .await
        .expect(8);
    assert_eq!(state(&b)["items"]["KEY"]["conflict"], false);
}

fn outbox_has(d: &Device<MemoryRelay>, vid: Vid) -> bool {
    let wanted = serde_json::to_value(vid.0).unwrap();
    state(d)["outbox"]["deliveries"]
        .as_array()
        .unwrap()
        .iter()
        .flat_map(|peer| peer[1].as_array().unwrap().iter())
        .any(|entry| entry[0]["name"] == "KEY" && entry[0]["new_vid"] == wanted)
}
#[tokio::test]
async fn legacy_accept_is_published_to_sync_scope() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.store()
        .set(
            "KEY",
            b"fake-legacy-published",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    a.run(&["send", "KEY", "--to", "bravo"], Run::agent())
        .await
        .expect(0);
    let out = b
        .run(
            &["inbox", "--on-conflict", "overwrite"],
            human(vec![Answer::Yes]),
        )
        .await;
    assert!([0, 8].contains(&out.code), "{}", out.stderr);
    assert_eq!(b.value("KEY").unwrap(), b"fake-legacy-published");
    let s = state(&b);
    assert_eq!(s["items"]["KEY"]["own"], true);
    let legacy_head = head(&b);
    assert!(outbox_has(&b, legacy_head));
    assert!(
        s["slots"]
            .get(format!("sync/snapshot/{}", hex(&legacy_head.0)))
            .is_some()
    );
    pump(&a, &b).await;
    assert_eq!(head(&a), head(&b));
    assert_eq!(a.value("KEY"), b.value("KEY"));
    assert!(state(&a)["candidates"].as_object().unwrap().is_empty());
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
}
/// Alpha's held change X, then bravo's local change: alpha resolves the conflict, keeping
/// bravo's value, with a change naming X as a parent. Returns X's candidate key and record.
async fn superseded_setup(a: &Device<MemoryRelay>, b: &Device<MemoryRelay>) -> (String, Value) {
    enroll(a, b).await;
    a.set("KEY", b"fake-alpha-superseded").await;
    pump(a, b).await;
    let s = state(b);
    let (key, held) = s["candidates"]
        .as_object()
        .unwrap()
        .iter()
        .next()
        .map(|(k, v)| (k.clone(), v.clone()))
        .unwrap();
    assert_eq!(held["category"], "held");
    b.set("KEY", b"fake-bravo-kept").await;
    pump(a, b).await;
    assert_eq!(state(a)["items"]["KEY"]["conflict"], true);
    (key, held)
}
#[tokio::test]
async fn review_skips_held_change_superseded_by_same_peer_resolve() {
    let (a, b, _) = devices().await;
    let (key, held) = superseded_setup(&a, &b).await;
    a.run(
        &["sync", "resolve", "KEY", "--keep", "bravo"],
        human(vec![]),
    )
    .await
    .expect(8);
    pump(&a, &b).await;
    let s = state(&b);
    let candidates = s["candidates"].as_object().unwrap();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert!(!candidates.contains_key(&key));
    assert!(s["slots"].get(&key).is_none());
    assert!(b.store().get_internal(&key).unwrap().is_none());
    let base = held["base_record"].as_str().unwrap();
    assert!(b.store().get_internal(base).unwrap().is_none());
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(0);
    pump(&a, &b).await;
    assert_eq!(head(&a), head(&b));
    assert_eq!(a.value("KEY"), b.value("KEY"));
    assert_eq!(b.value("KEY").unwrap(), b"fake-bravo-kept");
}
#[tokio::test]
async fn superseded_held_survives_when_new_candidate_is_capacity_deferred() {
    let (a, b, _) = devices().await;
    let (key, _) = superseded_setup(&a, &b).await;
    let mut s = state(&b);
    for n in 0..16 {
        let slot = format!("sync/kg/test-{n}");
        b.store().set_internal(&slot, b"fake-pinned").unwrap();
        s["slots"][slot] = "Checkpoint".into();
    }
    save_state(&b, &s);
    a.run(
        &["sync", "resolve", "KEY", "--keep", "bravo"],
        human(vec![]),
    )
    .await
    .expect(8);
    pump(&a, &b).await;
    let s = state(&b);
    let candidates = s["candidates"].as_object().unwrap();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert!(candidates.contains_key(&key));
    assert!(b.store().get_internal(&key).unwrap().is_some());
}
#[tokio::test]
async fn retired_superseded_vid_is_not_resurrected_by_duplicate_delivery() {
    let (a, b, relay) = devices().await;
    let (key, held) = superseded_setup(&a, &b).await;
    a.run(
        &["sync", "resolve", "KEY", "--keep", "bravo"],
        human(vec![]),
    )
    .await
    .expect(8);
    pump(&a, &b).await;
    assert!(
        !state(&b)["candidates"]
            .as_object()
            .unwrap()
            .contains_key(&key)
    );
    let version = &held["version"];
    post(
        &a,
        &b,
        &relay,
        SyncMsg::Changes {
            changes: vec![Change {
                name: ItemName::new("KEY").unwrap(),
                generation: held["generation"].as_u64().unwrap(),
                new_vid: serde_json::from_value(version["vid"].clone()).unwrap(),
                parents: serde_json::from_value(version["parents"].clone()).unwrap(),
                lineage: serde_json::from_value(version["lineage"].clone()).unwrap(),
                op: Op::Put {
                    kind: kc_proto::sync::ItemKind::Text,
                    value: SecretBytes::from_slice(b"fake-alpha-superseded"),
                },
                approval_ref: None,
            }],
        },
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let s = state(&b);
    let candidates = s["candidates"].as_object().unwrap();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert!(!candidates.contains_key(&key));
}
#[tokio::test]
async fn reordered_superseded_held_change_stays_retired_after_successor_is_rejected() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let base = head(&b);
    let (x, z) = (Vid::random(), Vid::random());
    let change = |vid: Vid, parents: Vec<Vid>, value: &[u8]| SyncMsg::Changes {
        changes: vec![Change {
            name: ItemName::new("KEY").unwrap(),
            generation: 1,
            new_vid: vid,
            lineage: parents.iter().copied().chain([vid]).collect(),
            parents,
            op: Op::Put {
                kind: kc_proto::sync::ItemKind::Text,
                value: SecretBytes::from_slice(value),
            },
            approval_ref: None,
        }],
    };
    let superseded = change(x, vec![base], b"fake-reordered-x");
    // The successor Z, naming X as a parent, arrives first.
    post(
        &a,
        &b,
        &relay,
        change(z, vec![base, x], b"fake-reordered-z"),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    post(&a, &b, &relay, superseded.clone()).await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    let s = state(&b);
    let candidates = s["candidates"].as_object().unwrap();
    assert_eq!(candidates.len(), 1, "{candidates:?}");
    assert!(candidates.keys().all(|k| k.ends_with(&hex(&z.0))));
    b.run(&["sync", "review"], human(vec![Answer::Select(1)]))
        .await
        .expect(0);
    post(&a, &b, &relay, superseded).await;
    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert!(state(&b)["candidates"].as_object().unwrap().is_empty());
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
}
#[tokio::test]
async fn review_accept_after_local_edit_reports_conflict_instead_of_accepted() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-incoming").await;
    pump(&a, &b).await;
    b.set("KEY", b"fake-intervening-local").await;
    let out = b
        .run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await;
    out.expect(8);
    assert!(!out.stderr.contains("Accepted KEY"), "{}", out.stderr);
    assert!(
        out.stderr
            .contains("KEY changed on this device meanwhile and is now a conflict"),
        "{}",
        out.stderr
    );
    assert_eq!(b.value("KEY").unwrap(), b"fake-intervening-local");
}
#[tokio::test]
async fn resolve_at_full_capacity_reports_storage_full_instead_of_resolved() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    let mut s = state(&b);
    for n in 0..16 {
        let slot = format!("sync/kg/test-{n}");
        b.store().set_internal(&slot, b"fake-pinned").unwrap();
        s["slots"][slot] = "Checkpoint".into();
    }
    save_state(&b, &s);
    b.store()
        .set(
            "KEY",
            b"fake-out-of-band",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    let out = b
        .run(&["sync", "resolve", "KEY", "--keep", "mine"], human(vec![]))
        .await;
    out.expect(8);
    assert!(!out.stderr.contains("Resolved KEY"), "{}", out.stderr);
    assert!(
        out.stderr
            .contains("Sync storage is full; review pending items before retrying."),
        "{}",
        out.stderr
    );
    assert_eq!(state(&b)["items"]["KEY"]["conflict"], true);
}
#[tokio::test]
async fn legacy_accept_turned_conflict_reports_the_conflict_not_held() {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.store()
        .set(
            "KEY",
            b"fake-legacy-terminal",
            kc_store::ItemKind::Text,
            kc_store::Origin::Local,
        )
        .unwrap();
    a.run(&["send", "KEY", "--to", "bravo"], Run::agent())
        .await
        .expect(0);
    // A local edit lands while the overwrite waits for local confirmation.
    let run = human(vec![Answer::Yes]).on_local_confirm(|store, _| {
        store
            .set(
                "KEY",
                b"fake-intervening-local",
                kc_store::ItemKind::Text,
                kc_store::Origin::Local,
            )
            .unwrap();
    });
    let out = b.run(&["inbox", "--on-conflict", "overwrite"], run).await;
    assert!(
        out.stderr
            .contains("KEY changed on this device meanwhile and is now a conflict"),
        "{}",
        out.stderr
    );
    assert!(!out.stderr.contains("Sync item held"), "{}", out.stderr);
    assert_eq!(b.value("KEY").unwrap(), b"fake-intervening-local");
    assert_eq!(state(&b)["items"]["KEY"]["conflict"], true);
}
#[tokio::test]
async fn evicted_held_candidate_keeps_its_binding() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let held = Vid::random();
    post(
        &a,
        &b,
        &relay,
        change_message("KEY", held, head(&b), b"fake-held"),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert!(holds_candidate(&state(&b), held));
    // Fill the budget with checkpoints so the next snapshot can only evict the held slot.
    let mut s = state(&b);
    let used = s["slots"].as_object().unwrap().len();
    for n in used..16 {
        let slot = format!("sync/kg/test-{n}");
        b.store().set_internal(&slot, b"fake-pinned").unwrap();
        s["slots"][slot] = "Checkpoint".into();
    }
    save_state(&b, &s);
    b.set("LOCAL", b"fake-local").await;
    b.run(&["sync", "add", "LOCAL", "--peers", "alpha"], human(vec![]))
        .await
        .expect(8);
    assert!(!holds_candidate(&state(&b), held));
    assert!(
        b.store()
            .get_internal(&fp_slot("KEY", held))
            .unwrap()
            .is_some()
    );
}
async fn review_with_candidate_changed_meanwhile(
    change: impl FnOnce(&mut Value) + Send + 'static,
) -> common::Output {
    let (a, b, _) = devices().await;
    enroll(&a, &b).await;
    a.set("KEY", b"fake-incoming").await;
    pump(&a, &b).await;
    assert_eq!(state(&b)["candidates"].as_object().unwrap().len(), 1);
    // Another process changes the candidate while review waits for local confirmation.
    let run = human(vec![Answer::Select(0)]).on_local_confirm(move |_, dir| {
        let path = dir.join("sync.json");
        let mut s: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
        change(&mut s);
        std::fs::write(&path, serde_json::to_vec_pretty(&s).unwrap()).unwrap();
    });
    let out = b.run(&["sync", "review"], run).await;
    assert!(!out.stderr.contains("Accepted KEY"), "{}", out.stderr);
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    out
}
#[tokio::test]
async fn review_reports_accepted_candidate_retired_meanwhile() {
    let out = review_with_candidate_changed_meanwhile(|s| {
        let slot = s["candidates"]
            .as_object()
            .unwrap()
            .keys()
            .next()
            .unwrap()
            .clone();
        s["candidates"].as_object_mut().unwrap().remove(&slot);
        s["slots"].as_object_mut().unwrap().remove(&slot);
    })
    .await;
    assert!(
        out.stderr
            .contains("KEY from alpha was replaced by a newer change; run `kc sync review` again."),
        "{}",
        out.stderr
    );
}
#[tokio::test]
async fn review_reports_accepted_candidate_turned_conflict_meanwhile() {
    let out = review_with_candidate_changed_meanwhile(|s| {
        let slots = s["candidates"]
            .as_object()
            .unwrap()
            .keys()
            .cloned()
            .collect::<Vec<_>>();
        for slot in slots {
            s["candidates"][&slot]["category"] = "conflict".into();
            s["slots"][&slot] = "ConflictCandidate".into();
        }
        s["items"]["KEY"]["conflict"] = true.into();
    })
    .await;
    assert_eq!(
        out.stderr
            .matches("KEY is in conflict; settle it with `kc sync resolve KEY` first.")
            .count(),
        1,
        "{}",
        out.stderr
    );
}
#[tokio::test]
async fn known_cap_drops_unreferenced_bindings_and_evicted_held_after_it_left_known() {
    let (a, b, relay) = devices().await;
    enroll(&a, &b).await;
    let held = Vid::random();
    post(
        &a,
        &b,
        &relay,
        change_message("KEY", held, head(&b), b"fake-held"),
    )
    .await;
    b.run(&["inbox"], Run::agent()).await.expect(8);
    assert!(holds_candidate(&state(&b), held));
    // Preload known past the cap: a lineage vid and the held vid sit first, then fillers.
    let mut s = state(&b);
    let head = head(&b);
    let record = b
        .store()
        .get_internal(&fp_slot("KEY", head))
        .unwrap()
        .unwrap();
    let in_lineage = Vid::random();
    let fillers = (0..256).map(|_| Vid::random()).collect::<Vec<_>>();
    for vid in std::iter::once(&in_lineage).chain(&fillers) {
        b.store()
            .set_internal(&fp_slot("KEY", *vid), record.as_bytes())
            .unwrap();
    }
    let mut known = vec![in_lineage, held];
    known.extend(&fillers);
    known.push(head);
    s["items"]["KEY"]["known"] = serde_json::to_value(&known).unwrap();
    s["items"]["KEY"]["lineage"]
        .as_array_mut()
        .unwrap()
        .insert(0, serde_json::to_value(in_lineage).unwrap());
    save_state(&b, &s);
    // A local change adds one more vid, so four fall out of known.
    b.set("KEY", b"fake-local-change").await;
    let s = state(&b);
    let lineage: Vec<Vid> = serde_json::from_value(s["items"]["KEY"]["lineage"].clone()).unwrap();
    assert!(lineage.contains(&in_lineage));
    let has = |vid: Vid| {
        b.store()
            .get_internal(&fp_slot("KEY", vid))
            .unwrap()
            .is_some()
    };
    assert!(!has(fillers[0]) && !has(fillers[1]));
    assert!(has(in_lineage) && has(held) && has(fillers[2]) && has(head));
    let known: Vec<Vid> = serde_json::from_value(s["items"]["KEY"]["known"].clone()).unwrap();
    assert_eq!(known.len(), 256);
    for vid in [in_lineage, held, fillers[0], fillers[1]] {
        assert!(!known.contains(&vid));
    }
    assert!(holds_candidate(&s, held));
    // Evicting the held candidate now that its vid left known deletes its binding.
    let mut s = state(&b);
    let used = s["slots"].as_object().unwrap().len();
    for n in used..16 {
        let slot = format!("sync/kg/test-{n}");
        b.store().set_internal(&slot, b"fake-pinned").unwrap();
        s["slots"][slot] = "Checkpoint".into();
    }
    save_state(&b, &s);
    b.set("LOCAL", b"fake-local").await;
    b.run(&["sync", "add", "LOCAL", "--peers", "alpha"], human(vec![]))
        .await
        .expect(8);
    assert!(!holds_candidate(&state(&b), held));
    assert!(!has(held));
}

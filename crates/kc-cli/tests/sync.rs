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
fn state(d: &Device<MemoryRelay>) -> Value {
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
    a.run(&["sync", "add", "KEY", "--peers", "bravo"], human(vec![]))
        .await
        .expect(8);
    pump(a, b).await;
    assert!(b.value("KEY").is_none());
    assert_eq!(state(b)["candidates"].as_object().unwrap().len(), 1);
    let out = b
        .run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await;
    assert!([0, 8].contains(&out.code), "{}", out.stderr);
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
    a.run(&["sync", "resolve", "KEY", "--keep", "mine"], human(vec![]))
        .await
        .expect(8);
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
    ] {
        a.run(&args, Run::agent()).await.expect(5);
    }
    let mut denied = Run::human(vec![]);
    denied.local_auth.push_back(LocalAuthOutcome::Denied);
    a.run(&["sync", "add", "KEY"], denied).await.expect(5);
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
    b.run(&["sync", "review"], Run::human(vec![Answer::Select(1)]))
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
    b.run(&["inbox", "--on-conflict", "overwrite"], Run::agent())
        .await
        .expect(8);
    assert_eq!(b.value("KEY").unwrap(), b"fake-initial-secret");
    b.run(&["sync", "review"], human(vec![Answer::Select(0)]))
        .await
        .expect(0);
    assert_eq!(b.value("KEY").unwrap(), b"fake-legacy-terminal");
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
        Run::agent(),
        &a,
        &["send", "KEY"],
        |code| Run::human(vec![Answer::Text(code), Answer::Yes]),
    )
    .await;
    rx.expect(8);
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
    b.run(&["sync", "review"], Run::human(vec![Answer::Select(1)]))
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

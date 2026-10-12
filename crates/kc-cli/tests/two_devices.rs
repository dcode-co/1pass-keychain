//! Two in-process devices (separate config directories and in-memory keychains) talking
//! through `MemoryRelay`: code transfers, pairing, `send --to` + `inbox`, replays, conflicts
//! and the agent policy.

mod common;

use common::{Answer, Device, Run, transfer, wrong_code};
use kc_proto::memory_relay::MemoryRelay;
use kc_proto::relay::RelayApi;
use kc_wire::exit;

fn devices() -> (Device<MemoryRelay>, Device<MemoryRelay>, MemoryRelay) {
    let relay = MemoryRelay::new();
    (
        Device::new("alpha", relay.clone()),
        Device::new("bravo", relay.clone()),
        relay,
    )
}

/// A human typing the code at the prompt and confirming.
fn typed_code(code: String) -> Run {
    Run::human(vec![Answer::Text(code), Answer::Yes])
}

/// An agent piping the code (needs `agent_code_send = true`).
fn piped_code(code: String) -> Run {
    Run::agent().stdin(format!("{code}\n"))
}

/// Pairs `a` (joins) with `b` (shows the code); returns both outputs.
async fn pair(
    a: &Device<MemoryRelay>,
    b: &Device<MemoryRelay>,
) -> (common::Output, common::Output) {
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
async fn code_transfer_from_a_person_to_an_agent() {
    let (a, b, _) = devices();
    a.set("GITHUB_TOKEN", b"fake-token-1").await;
    a.set("RENDER_API_KEY", b"fake-render-2").await;
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "GITHUB_TOKEN", "RENDER_API_KEY"],
        typed_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert!(rx.stderr.contains("Code: "));
    assert!(tx.stderr.contains("Sent 2 items"), "{}", tx.stderr);
    assert_eq!(b.value("GITHUB_TOKEN").unwrap(), b"fake-token-1");
    assert_eq!(b.value("RENDER_API_KEY").unwrap(), b"fake-render-2");
    // The receiver ran as an agent: never prompted. The sender confirmed once, with the names.
    assert!(rx.prompts.is_empty());
    assert_eq!(tx.prompts.len(), 2);
    assert!(tx.stderr.contains("GITHUB_TOKEN, RENDER_API_KEY"));
    // `kc get` hands the value to a pipe unchanged.
    let got = b.run(&["get", "GITHUB_TOKEN"], Run::agent()).await;
    got.expect(0);
    assert_eq!(got.stdout, b"fake-token-1");
    // Metadata records where it came from.
    let list = b.run(&["list", "--json"], Run::agent()).await;
    list.expect(0);
    assert!(
        list.stdout_text()
            .contains("\"from_device\": \"a one-time code\"")
    );
}

#[tokio::test]
async fn a_wrong_code_fails_on_both_sides_and_stores_nothing() {
    let (a, b, _) = devices();
    a.set("SECRET_A", b"fake-a").await;
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "SECRET_A"],
        |code| Run::human(vec![Answer::Text(wrong_code(&code))]),
    )
    .await;
    rx.expect(exit::AUTH_FAILED);
    tx.expect(exit::AUTH_FAILED);
    assert!(tx.stderr.contains("wrong code"), "{}", tx.stderr);
    assert_eq!(b.value("SECRET_A"), None);
    b.run(&["get", "SECRET_A", "--check"], Run::agent())
        .await
        .expect(exit::NOT_FOUND);
}

#[tokio::test]
async fn a_typo_in_the_code_is_caught_before_the_network() {
    let (a, b, relay) = devices();
    a.set("SECRET_A", b"fake-a").await;
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "SECRET_A"],
        |code| {
            let typo = code.replacen('-', "-x", 1);
            Run::human(vec![Answer::Text(typo), Answer::Text(code), Answer::Yes])
        },
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert!(tx.stderr.contains("is not a code word"), "{}", tx.stderr);
    assert_eq!(b.value("SECRET_A").unwrap(), b"fake-a");
    drop(relay);
}

#[tokio::test]
async fn pairing_shows_matching_sas_and_remembers_both_sides() {
    let (a, b, _) = devices();
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    let sas = shown.sas().expect("the code side shows SAS words");
    assert_eq!(sas.split_whitespace().count(), 4);
    assert_eq!(joined.sas().as_deref(), Some(sas.as_str()));
    assert!(
        shown.stderr.contains("calls itself alpha"),
        "{}",
        shown.stderr
    );

    let a_peers = a.peers();
    let b_peers = b.peers();
    assert_eq!(a_peers.peers.len(), 1);
    assert_eq!(b_peers.peers.len(), 1);
    assert_eq!(a_peers.peers[0].label.as_str(), "bravo");
    assert_eq!(b_peers.peers[0].label.as_str(), "alpha");
    // Each knows the other's key, and holds a token for the other's inbox.
    assert_eq!(a.writer_bearer("bravo").len(), 43);
    assert_eq!(b.writer_bearer("alpha").len(), 43);
    // The inbox lives in one keychain slot; config.toml mirrors its id.
    assert_eq!(a.config().inbox_id.unwrap(), a.inbox_credentials().0);
    assert_eq!(b.config().inbox_id.unwrap(), b.inbox_credentials().0);

    let listed = a.run(&["peers"], Run::agent()).await;
    listed.expect(0);
    assert!(listed.stdout_text().contains("bravo"));
}

#[tokio::test]
async fn declining_the_sas_on_the_code_side_pairs_nobody() {
    let (a, b, _) = devices();
    let (shown, joined) = transfer(
        &b,
        &["pair"],
        Run::human(vec![Answer::No]),
        &a,
        &["pair", "--join"],
        // The joining side asks only after the receipt, which carries no offer here.
        |code| Run::human(vec![Answer::Text(code)]),
    )
    .await;
    shown.expect(exit::AUTH_FAILED);
    joined.expect(exit::PARTIAL);
    assert!(a.peers().peers.is_empty());
    assert!(b.peers().peers.is_empty());
}

#[tokio::test]
async fn the_joining_side_compares_words_after_both_screens_show_them() {
    let (a, b, _) = devices();
    let (shown, joined) = transfer(
        &b,
        &["pair"],
        Run::human(vec![Answer::Yes]),
        &a,
        &["pair", "--join"],
        |code| Run::human(vec![Answer::Text(code), Answer::No]),
    )
    .await;
    shown.expect(0);
    joined.expect(exit::AUTH_FAILED);
    // The joining side's only question came after the receipt, and named the other device.
    assert_eq!(joined.prompts.len(), 2);
    assert!(
        joined.prompts[1].contains("Pair with bravo"),
        "{:?}",
        joined.prompts
    );
    assert!(a.peers().peers.is_empty());
    // B paired, but A revoked the token it gave B, so B can't post to A.
    assert_eq!(b.peers().peers.len(), 1);
    b.set("X", b"fake").await;
    b.run(&["send", "X", "--to", "alpha"], Run::agent())
        .await
        .expect(exit::AUTH_FAILED);
}

#[tokio::test]
async fn blank_names_never_open_the_checklist_without_a_terminal() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    a.set("X", b"fake").await;
    for run in [
        Run::agent(),
        Run {
            env: vec![("CLAUDECODE".into(), "1".into())],
            ..Run::human(vec![])
        },
    ] {
        let out = a.run(&["send", "--to", "bravo", "--names", " "], run).await;
        out.expect(exit::INTERACTION_REQUIRED);
        assert!(out.prompts.is_empty());
    }
    a.run(
        &["send", "--to", "bravo", "--names", " ", "--no-input"],
        Run::human(vec![]),
    )
    .await
    .expect(exit::INTERACTION_REQUIRED);
}

#[tokio::test]
async fn a_keychain_failure_leaves_the_message_for_the_next_inbox_run() {
    let (a, b, relay) = devices();
    pair(&a, &b).await.0.expect(0);
    a.set("K1", b"fake-k1").await;
    a.set("K2", b"fake-k2").await;
    a.run(&["send", "--to", "bravo", "--names", "K1,K2"], Run::agent())
        .await
        .expect(0);
    let inbox_id = b.config().inbox_id.unwrap();
    // The first item's write works, then the keychain fails (a generic keychain error,
    // which kc-store reports as exit 1; a locked keychain would be 4).
    b.memory().fail_writes_after(1);
    let failed = b.run(&["inbox"], Run::agent()).await;
    failed.expect(1);
    assert!(
        failed.stderr.contains("stays in the inbox"),
        "{}",
        failed.stderr
    );
    assert_eq!(relay.pending_messages(&inbox_id), 1);
    b.memory().allow_writes();
    // A local change after the interrupted import isn't undone by the retry.
    b.set("K1", b"fake-local").await;
    let retried = b
        .run(&["inbox", "--on-conflict", "rename"], Run::agent())
        .await;
    retried.expect(0);
    assert_eq!(b.value("K1").unwrap(), b"fake-local");
    assert_eq!(b.value("K1-2"), None);
    // The journal skipped K1, which the first run had stored.
    assert!(
        retried
            .stderr
            .contains("1 item of these settled by an earlier run"),
        "{}",
        retried.stderr
    );
    assert_eq!(b.value("K2").unwrap(), b"fake-k2");
    assert_eq!(relay.pending_messages(&inbox_id), 0);
    assert!(
        b.run(&["inbox"], Run::agent())
            .await
            .stderr
            .contains("No new messages")
    );
}

#[tokio::test]
async fn code_typos_are_described_without_the_typed_text() {
    let (a, _, _) = devices();
    a.write_config("agent_code_send = true\n");
    a.set("X", b"fake").await;
    let out = a
        .run(
            &["send", "X", "--code", "-"],
            Run::agent().stdin("4721-absrd-amulet\n"),
        )
        .await;
    out.expect(exit::USAGE);
    assert!(out.stderr.contains("word 1"), "{}", out.stderr);
    assert!(
        !out.stderr.contains("absrd") && !out.stderr.contains("absurd"),
        "{}",
        out.stderr
    );
}

#[tokio::test]
async fn the_previous_key_expires_on_any_command() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    a.run(&["device", "rotate"], Run::human(vec![Answer::Yes]))
        .await
        .expect(0);
    assert!(a.store().get_internal("device-key-prev").unwrap().is_some());
    let mut config = a.config();
    config.device_key_prev_until = Some(1);
    config.save(a.dir.path()).unwrap();
    a.run(&["list"], Run::agent()).await.expect(0);
    assert!(a.store().get_internal("device-key-prev").unwrap().is_none());
    assert_eq!(a.config().device_key_prev_until, None);
}

#[cfg(unix)]
#[tokio::test]
async fn a_rotation_that_cannot_save_its_config_changes_nothing() {
    use std::os::unix::fs::PermissionsExt as _;
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    let before = a.config();
    let owner = a
        .store()
        .get_internal("inbox-owner")
        .unwrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    let key = a
        .store()
        .get_internal("device-key")
        .unwrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    let dir = a.dir.path();
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o500)).unwrap();
    let out = a
        .run(&["device", "rotate"], Run::human(vec![Answer::Yes]))
        .await;
    std::fs::set_permissions(dir, std::fs::Permissions::from_mode(0o700)).unwrap();
    out.expect(1);
    assert!(out.stderr.contains("nothing changed"), "{}", out.stderr);
    assert_eq!(a.config(), before);
    let owner_after = a
        .store()
        .get_internal("inbox-owner")
        .unwrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    let key_after = a
        .store()
        .get_internal("device-key")
        .unwrap()
        .unwrap()
        .as_bytes()
        .to_vec();
    assert!(owner_after == owner && key_after == key);
    assert_eq!(a.peers().peers.len(), 1);
}

#[tokio::test]
async fn send_to_a_paired_device_then_inbox() {
    let (a, b, _) = devices();
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);

    a.set("K1", b"fake-k1").await;
    a.set("K2", b"fake-k2").await;
    let sent = a
        .run(&["send", "--to", "bravo", "--names", "K1,K2"], Run::agent())
        .await;
    sent.expect(0);
    assert!(
        sent.stderr.contains("Sent 2 items to bravo"),
        "{}",
        sent.stderr
    );
    assert_eq!(b.value("K1"), None, "nothing is stored before `kc inbox`");

    let got = b.run(&["inbox"], Run::agent()).await;
    got.expect(0);
    assert!(got.stderr.contains("From alpha: 2 items"), "{}", got.stderr);
    assert_eq!(b.value("K1").unwrap(), b"fake-k1");
    assert_eq!(b.value("K2").unwrap(), b"fake-k2");
    let list = b.run(&["list"], Run::agent()).await;
    assert!(list.stdout_text().contains("from alpha"));

    // The inbox is empty now.
    let again = b.run(&["inbox"], Run::agent()).await;
    again.expect(0);
    assert!(again.stderr.contains("No new messages"));

    // And the other direction works too, with positional names.
    b.set("FROM_B", b"fake-b").await;
    b.run(&["send", "FROM_B", "--to", "ALPHA"], Run::agent())
        .await
        .expect(0);
    a.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(a.value("FROM_B").unwrap(), b"fake-b");
}

#[tokio::test]
async fn a_replayed_inbox_message_is_rejected() {
    let (a, b, relay) = devices();
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    a.set("K1", b"fake-original").await;
    a.run(&["send", "--to", "bravo", "--names", "K1"], Run::agent())
        .await
        .expect(0);

    // Keep a copy of the message as the relay holds it.
    let (inbox_id, owner) = b.inbox_credentials();
    let listing = relay
        .list_messages(&inbox_id, &owner, std::time::Duration::ZERO)
        .await
        .unwrap();
    assert_eq!(listing.messages.len(), 1);
    let body = kc_proto::relay::message_body(&listing.messages[0]).unwrap();

    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(b.value("K1").unwrap(), b"fake-original");
    b.set("K1", b"fake-changed-locally").await;

    // Post the same bytes again with A's writer token, as a malicious relay or eavesdropper could.
    relay
        .post_message(&inbox_id, &a.writer_bearer("bravo"), &body)
        .await
        .unwrap();

    let replayed = b
        .run(&["inbox", "--on-conflict", "rename"], Run::agent())
        .await;
    replayed.expect(exit::AUTH_FAILED);
    assert!(replayed.stderr.contains("replay"), "{}", replayed.stderr);
    assert_eq!(b.value("K1").unwrap(), b"fake-changed-locally");
    assert_eq!(b.value("K1-2"), None);
    assert_eq!(
        relay.pending_messages(&inbox_id),
        0,
        "the replay is deleted"
    );
}

#[tokio::test]
async fn conflicts_skip_rename_and_overwrite_with_restore() {
    let (a, b, _) = devices();
    a.write_config("agent_code_send = true\n");
    a.set("X", b"fake-new").await;
    b.set("X", b"fake-old").await;

    // skip (the default for agents): ours is kept, both sides report partial.
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "X", "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(exit::PARTIAL);
    tx.expect(exit::PARTIAL);
    assert!(
        tx.stderr.contains("already has a different value"),
        "{}",
        tx.stderr
    );
    assert_eq!(b.value("X").unwrap(), b"fake-old");

    // rename: stored next to ours.
    let (rx, tx) = transfer(
        &b,
        &["receive", "--on-conflict", "rename"],
        Run::agent(),
        &a,
        &["send", "X", "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert!(tx.stderr.contains("stored as X-2"), "{}", tx.stderr);
    assert_eq!(b.value("X").unwrap(), b"fake-old");
    assert_eq!(b.value("X-2").unwrap(), b"fake-new");

    // overwrite needs a person; then `kc restore` brings the old value back, and back again.
    let (rx, tx) = transfer(
        &b,
        &["receive", "--on-conflict", "overwrite"],
        Run::human(vec![Answer::Yes]),
        &a,
        &["send", "X", "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert_eq!(b.value("X").unwrap(), b"fake-new");
    b.run(&["restore", "X"], Run::agent()).await.expect(0);
    assert_eq!(b.value("X").unwrap(), b"fake-old");
    b.run(&["restore", "X"], Run::agent()).await.expect(0);
    assert_eq!(b.value("X").unwrap(), b"fake-new");

    // At a terminal without --on-conflict, each conflict is asked about.
    b.set("X", b"fake-third").await;
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::human(vec![Answer::Yes, Answer::Select(1)]),
        &a,
        &["send", "X", "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert_eq!(b.value("X").unwrap(), b"fake-new");
}

#[tokio::test]
async fn the_same_value_is_unchanged_not_a_conflict() {
    let (a, b, _) = devices();
    a.write_config("agent_code_send = true\n");
    a.set("SAME", b"fake-same").await;
    b.set("SAME", b"fake-same").await;
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "SAME", "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert!(tx.stderr.contains("unchanged"), "{}", tx.stderr);
}

#[tokio::test]
async fn agent_code_send_allows_a_non_interactive_code_send() {
    let (a, b, _) = devices();
    a.set("TOKEN", b"fake-agent").await;
    // Refused by default...
    let refused = a
        .run(
            &["send", "TOKEN", "--code", "-"],
            Run::agent().stdin("1-aardvark-adroitness\n"),
        )
        .await;
    refused.expect(exit::INTERACTION_REQUIRED);
    assert!(
        refused.stderr.contains("agent_code_send"),
        "{}",
        refused.stderr
    );
    // ...allowed with the setting.
    a.write_config("agent_code_send = true\n");
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "TOKEN", "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert_eq!(b.value("TOKEN").unwrap(), b"fake-agent");
    // A code on the command line is refused without being echoed.
    let argv = a
        .run(
            &["send", "TOKEN", "--code", "4721-absurd-amulet"],
            Run::agent(),
        )
        .await;
    argv.expect(exit::USAGE);
    assert!(!argv.stderr.contains("absurd"), "{}", argv.stderr);
}

#[tokio::test]
async fn non_interactive_runs_refuse_with_exit_5_and_never_prompt() {
    let (a, b, relay) = devices();
    a.set("X", b"fake-x").await;
    for args in [
        &["send", "X", "--code", "-"][..],
        &["send", "X"],
        &["send"],
        &["send", "--all", "--code", "-"],
        &["send", "--to", "bravo"],
        &["send", "X", "--remember", "--code", "-"],
        &["pair"],
        &["pair", "--join"],
        &["receive", "--remember"],
        &["receive", "--on-conflict", "overwrite"],
        &["inbox", "--on-conflict", "overwrite"],
        &["device", "rotate"],
    ] {
        let out = a.run(args, Run::agent()).await;
        out.expect(exit::INTERACTION_REQUIRED);
        assert!(
            out.stderr.contains("needs a person") || out.stderr.contains("pass"),
            "{args:?}: {}",
            out.stderr
        );
        assert!(out.prompts.is_empty());
    }
    // The other markers count too: CI, --no-input, and a pipe on stdin or stderr.
    let ci = Run {
        env: vec![("CI".into(), "true".into())],
        ..Run::human(vec![])
    };
    a.run(&["pair"], ci)
        .await
        .expect(exit::INTERACTION_REQUIRED);
    a.run(&["pair", "--no-input"], Run::human(vec![]))
        .await
        .expect(exit::INTERACTION_REQUIRED);
    // `set` with stdin on a terminal would prompt.
    let set = Run {
        terminal: true,
        ..Run::agent()
    };
    a.run(&["set", "Y"], set)
        .await
        .expect(exit::INTERACTION_REQUIRED);
    // Nothing reached the relay: no channel was ever allocated.
    for channel in 1..=9999u16 {
        assert_eq!(
            relay.channel_status(channel),
            kc_proto::memory_relay::ChannelStatus::Unknown
        );
    }
    drop(b);
}

#[tokio::test]
async fn get_guards_terminals_and_offers_check_fingerprint_and_files() {
    let (a, b, _) = devices();
    a.set("API", b"fake-api-value").await;
    // Not to a terminal without --reveal.
    let tty = a.run(&["get", "API"], Run::agent().stdout_terminal()).await;
    tty.expect(exit::INTERACTION_REQUIRED);
    assert!(tty.stdout.is_empty());
    assert!(tty.stderr.contains("--reveal"));
    let revealed = a
        .run(&["get", "API", "--reveal"], Run::agent().stdout_terminal())
        .await;
    revealed.expect(0);
    assert_eq!(revealed.stdout, b"fake-api-value\n");
    // --check prints nothing.
    let check = a
        .run(&["get", "API", "--check"], Run::agent().stdout_terminal())
        .await;
    check.expect(0);
    assert!(check.stdout.is_empty() && check.stderr.is_empty());
    a.run(&["get", "NOPE", "--check"], Run::agent())
        .await
        .expect(exit::NOT_FOUND);
    a.run(&["get", "NOPE"], Run::agent())
        .await
        .expect(exit::NOT_FOUND);
    // --base64.
    let b64 = a.run(&["get", "API", "--base64"], Run::agent()).await;
    b64.expect(0);
    assert_eq!(b64.stdout_text(), "ZmFrZS1hcGktdmFsdWU=\n");
    // --fingerprint is the same on two devices with the same value, and differs otherwise.
    b.set("API", b"fake-api-value").await;
    let fa = a
        .run(
            &["get", "API", "--fingerprint"],
            Run::agent().stdout_terminal(),
        )
        .await;
    let fb = b.run(&["get", "API", "--fingerprint"], Run::agent()).await;
    fa.expect(0);
    assert_eq!(fa.stdout, fb.stdout);
    assert!(!fa.stdout_text().contains("fake"));
    b.set("API", b"fake-api-other").await;
    let fb = b.run(&["get", "API", "--fingerprint"], Run::agent()).await;
    assert_ne!(fa.stdout, fb.stdout);
    // An invalid name isn't echoed.
    let bad = a.run(&["get", "NAME=not-a-real-value"], Run::agent()).await;
    bad.expect(exit::USAGE);
    assert!(!bad.stderr.contains("not-a-real"), "{}", bad.stderr);
}

#[tokio::test]
async fn set_reads_stdin_strips_one_newline_and_refuses_argv_values() {
    let (a, _, _) = devices();
    a.run(&["set", "A"], Run::agent().stdin("fake-line\n\n"))
        .await
        .expect(0);
    assert_eq!(a.value("A").unwrap(), b"fake-line\n");
    a.run(&["set", "B"], Run::agent().stdin("fake-crlf\r\n"))
        .await
        .expect(0);
    assert_eq!(a.value("B").unwrap(), b"fake-crlf");
    a.run(&["set", "C", "--raw"], Run::agent().stdin("fake-raw\n"))
        .await
        .expect(0);
    assert_eq!(a.value("C").unwrap(), b"fake-raw\n");
    // A value as an argument is refused and not echoed.
    let argv = a
        .run(
            &["set", "D", "not-a-real-value-in-argv"],
            Run::agent().stdin("x"),
        )
        .await;
    argv.expect(exit::USAGE);
    assert!(!argv.stderr.contains("not-a-real"), "{}", argv.stderr);
    assert_eq!(a.value("D"), None);
    // Empty input stores nothing.
    a.run(&["set", "E"], Run::agent().stdin("\n"))
        .await
        .expect(exit::USAGE);
    // The hidden prompt, for a person.
    a.run(
        &["set", "F"],
        Run::human(vec![Answer::Secret("fake-typed".into())]),
    )
    .await
    .expect(0);
    assert_eq!(a.value("F").unwrap(), b"fake-typed");
    // Overwriting keeps the previous value for restore.
    a.run(&["set", "F"], Run::agent().stdin("fake-second"))
        .await
        .expect(0);
    a.run(&["restore", "F"], Run::agent()).await.expect(0);
    assert_eq!(a.value("F").unwrap(), b"fake-typed");
    a.run(&["rm", "F"], Run::agent()).await.expect(0);
    assert_eq!(a.value("F"), None);
    a.run(&["rm", "F"], Run::agent())
        .await
        .expect(exit::NOT_FOUND);
    a.run(&["restore", "F"], Run::agent())
        .await
        .expect(exit::NOT_FOUND);
}

#[tokio::test]
async fn file_items_travel_byte_for_byte() {
    let (a, b, _) = devices();
    a.write_config("agent_code_send = true\n");
    let mut contents = b"FAKE_A=1\nFAKE_B=two words\n".to_vec();
    contents.extend_from_slice(&[0, 159, 146, 150, b'\n']);
    let src = a.dir.path().join("app.env");
    std::fs::write(&src, &contents).unwrap();
    a.run(
        &["set", "app.env", "--from-file", src.to_str().unwrap()],
        Run::agent(),
    )
    .await
    .expect(0);
    assert_eq!(
        a.value("app.env").unwrap(),
        contents,
        "files keep their trailing newline"
    );
    let list = a.run(&["list", "--json"], Run::agent()).await;
    assert!(list.stdout_text().contains("\"kind\": \"file\""));

    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "app.env", "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    let out = b.dir.path().join("restored.env");
    b.run(
        &["get", "app.env", "--to-file", out.to_str().unwrap()],
        Run::agent().stdout_terminal(),
    )
    .await
    .expect(0);
    assert_eq!(std::fs::read(&out).unwrap(), contents);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        let mode = std::fs::metadata(&out).unwrap().permissions().mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

#[tokio::test]
async fn bundles_and_the_checklist_pick_items() {
    let (a, b, _) = devices();
    a.write_config("agent_code_send = true\n");
    for name in ["ONE", "TWO", "THREE"] {
        a.set(name, format!("fake-{name}").as_bytes()).await;
    }
    let bundle = a.dir.path().join("new-machine.toml");
    std::fs::write(&bundle, "items = [\"ONE\", \"THREE\"]\n").unwrap();
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::agent(),
        &a,
        &["send", "--bundle", bundle.to_str().unwrap(), "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(0);
    tx.expect(0);
    assert!(b.value("ONE").is_some() && b.value("THREE").is_some() && b.value("TWO").is_none());

    // The checklist (sorted: ONE, THREE, TWO): pick TWO. It doesn't ask again afterwards.
    let (rx, tx) = transfer(&b, &["receive"], Run::agent(), &a, &["send"], |code| {
        Run::human(vec![Answer::Multi(vec![2]), Answer::Text(code)])
    })
    .await;
    rx.expect(0);
    tx.expect(0);
    assert_eq!(b.value("TWO").unwrap(), b"fake-TWO");
}

#[tokio::test]
async fn unpairing_revokes_the_peer() {
    let (a, b, _) = devices();
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    a.run(&["peers", "rm", "bravo"], Run::agent())
        .await
        .expect(0);
    assert!(a.peers().peers.is_empty());
    a.set("X", b"fake").await;
    a.run(&["send", "X", "--to", "bravo"], Run::agent())
        .await
        .expect(exit::NOT_FOUND);
    // B still has A, but A's inbox no longer accepts B's messages.
    b.set("Y", b"fake").await;
    let refused = b.run(&["send", "Y", "--to", "alpha"], Run::agent()).await;
    refused.expect(exit::AUTH_FAILED);
    assert!(
        refused.stderr.contains("no longer accepts"),
        "{}",
        refused.stderr
    );
}

#[tokio::test]
async fn rotation_makes_a_new_identity_and_ends_pairings() {
    let (a, b, _) = devices();
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    let old_fp = b.peers().peers[0].fingerprint;
    let old_inbox = a.config().inbox_id.unwrap();

    let rotated = a
        .run(&["device", "rotate"], Run::human(vec![Answer::Yes]))
        .await;
    rotated.expect(0);
    assert!(rotated.stderr.contains("New fingerprint"));
    assert!(a.peers().peers.is_empty());
    let config = a.config();
    assert_ne!(config.inbox_id.unwrap(), old_inbox);
    assert!(config.device_key_prev_until.is_some());
    assert!(a.store().get_internal("device-key-prev").unwrap().is_some());
    let shown = a.run(&["device"], Run::agent()).await;
    assert!(!shown.stdout_text().contains(&old_fp.short()));

    // B's pairing is dead: the old inbox is gone.
    b.set("Y", b"fake").await;
    b.run(&["send", "Y", "--to", "alpha"], Run::agent())
        .await
        .expect(exit::AUTH_FAILED);
    // Declining changes nothing.
    let declined = a
        .run(&["device", "rotate"], Run::human(vec![Answer::No]))
        .await;
    declined.expect(exit::PARTIAL);
}

#[tokio::test]
async fn re_pairing_keeps_the_label_and_rebinds_nothing() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    let first_slot = a.peers().peers[0].token_key();
    pair(&a, &b).await.0.expect(0);
    assert_eq!(a.peers().peers.len(), 1);
    assert_eq!(b.peers().peers.len(), 1);
    // The token moved to a new slot together with the peer entry; the old one is gone.
    let second_slot = a.peers().peers[0].token_key();
    assert_ne!(first_slot, second_slot);
    assert!(a.store().get_internal(&first_slot).unwrap().is_none());
    b.set("AGAIN", b"fake-again").await;
    b.run(&["send", "AGAIN", "--to", "alpha"], Run::agent())
        .await
        .expect(0);
    a.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(a.value("AGAIN").unwrap(), b"fake-again");
    // A different device that also calls itself "bravo" gets its own label.
    let relay = a.net.clone();
    let c = Device::new("bravo", relay);
    let (shown, joined) = pair(&a, &c).await;
    shown.expect(0);
    joined.expect(0);
    let labels: Vec<String> = a
        .peers()
        .peers
        .iter()
        .map(|p| p.label.to_string())
        .collect();
    assert_eq!(labels, ["bravo", "bravo-2"]);
}

#[tokio::test]
async fn doctor_and_device_show_report_state() {
    let (a, b, _) = devices();
    let doctor = a.run(&["doctor"], Run::agent()).await;
    doctor.expect(0);
    let text = doctor.stdout_text();
    assert!(text.contains("in-memory test keychain"), "{text}");
    assert!(text.contains("relay              ok"), "{text}");
    assert!(text.contains("CLAUDECODE is set"), "{text}");
    pair(&a, &b).await.0.expect(0);
    let shown = a.run(&["device"], Run::agent()).await;
    shown.expect(0);
    assert!(shown.stdout_text().contains("label:            alpha"));
    a.write_config("label = \"alpha\"\nagent_code_sned = true\n");
    let doctor = a.run(&["doctor"], Run::agent()).await;
    assert!(
        doctor
            .stdout_text()
            .contains("unknown keys: agent_code_sned")
    );
    a.run(&["device", "rename", "work laptop"], Run::agent())
        .await
        .expect(0);
    assert_eq!(a.config().label.as_deref(), Some("work laptop"));
    a.write_config("relay = \"http://relay.example\"\n");
    let doctor = a.run(&["doctor"], Run::agent()).await;
    doctor.expect(exit::USAGE);
    assert!(doctor.stdout_text().contains("plain-http"));
}

#[cfg(unix)]
#[tokio::test]
async fn exec_passes_values_in_the_environment_only() {
    let (a, _, _) = devices();
    a.set("EXEC_ITEM", b"fake-exec-value").await;
    a.run(
        &[
            "exec",
            "--env",
            "FOO=EXEC_ITEM",
            "--",
            "sh",
            "-c",
            "test \"$FOO\" = fake-exec-value",
        ],
        Run::agent(),
    )
    .await
    .expect(0);
    a.run(
        &[
            "exec",
            "--env",
            "FOO=EXEC_ITEM",
            "--",
            "sh",
            "-c",
            "test \"$FOO\" = other",
        ],
        Run::agent(),
    )
    .await
    .expect(1);
    a.run(
        &[
            "exec",
            "--env",
            "FOO=EXEC_ITEM",
            "--",
            "sh",
            "-c",
            "exit 42",
        ],
        Run::agent(),
    )
    .await
    .expect(42);
    let missing = a
        .run(
            &["exec", "--env", "FOO=MISSING", "--", "true"],
            Run::agent(),
        )
        .await;
    missing.expect(exit::NOT_FOUND);
    a.run(
        &["exec", "--env", "1FOO=EXEC_ITEM", "--", "true"],
        Run::agent(),
    )
    .await
    .expect(exit::USAGE);
    let bad = a
        .run(
            &["exec", "--env", "not-a-real-value", "--", "true"],
            Run::agent(),
        )
        .await;
    bad.expect(exit::USAGE);
    assert!(!bad.stderr.contains("not-a-real"), "{}", bad.stderr);
    a.run(
        &[
            "exec",
            "--env",
            "FOO=EXEC_ITEM",
            "--",
            "/nonexistent/kc-test",
        ],
        Run::agent(),
    )
    .await
    .expect(127);
    // Nothing was printed.
    let out = a
        .run(
            &["exec", "--env", "FOO=EXEC_ITEM", "--", "true"],
            Run::agent(),
        )
        .await;
    assert!(out.stdout.is_empty() && !out.stderr.contains("fake-exec"));
}

#[tokio::test]
async fn a_lost_inbox_is_replaced_and_pairing_works_again() {
    let (a, b, relay) = devices();
    pair(&a, &b).await.0.expect(0);
    // The relay forgets B's inbox (30 days unread).
    let (old_inbox, owner) = b.inbox_credentials();
    relay.delete_inbox(&old_inbox, &owner).await.unwrap();

    let read = b.run(&["inbox"], Run::agent()).await;
    read.expect(exit::EXPIRED);
    assert!(read.stderr.contains("pair again"), "{}", read.stderr);
    let new_inbox = b.config().inbox_id.unwrap();
    assert_ne!(new_inbox, old_inbox);
    // The new inbox works; A can't reach it until it pairs again...
    b.run(&["inbox"], Run::agent()).await.expect(0);
    a.set("K", b"fake-k").await;
    a.run(&["send", "K", "--to", "bravo"], Run::agent())
        .await
        .expect(exit::AUTH_FAILED);
    // ...and after pairing again it can.
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    a.run(&["send", "K", "--to", "bravo"], Run::agent())
        .await
        .expect(0);
    b.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(b.value("K").unwrap(), b"fake-k");
}

#[tokio::test]
async fn pairing_replaces_a_lost_inbox_on_the_fly() {
    let (a, b, relay) = devices();
    pair(&a, &b).await.0.expect(0);
    let (old_inbox, owner) = a.inbox_credentials();
    relay.delete_inbox(&old_inbox, &owner).await.unwrap();
    // A joins the next pairing: registering B on the lost inbox fails, so A makes a new one.
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    assert!(
        joined.stderr.contains("inbox was gone"),
        "{}",
        joined.stderr
    );
    assert_ne!(a.config().inbox_id.unwrap(), old_inbox);
    b.set("K", b"fake-k").await;
    b.run(&["send", "K", "--to", "alpha"], Run::agent())
        .await
        .expect(0);
    a.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(a.value("K").unwrap(), b"fake-k");
}

#[tokio::test]
async fn inbox_wait_picks_up_a_message_that_arrives_later() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    a.set("LATE", b"fake-late").await;
    let waiting = b.run(&["inbox", "--wait", "20"], Run::agent());
    let sending = async {
        tokio::time::sleep(std::time::Duration::from_millis(300)).await;
        a.run(&["send", "LATE", "--to", "bravo"], Run::agent())
            .await
    };
    let (got, sent) = tokio::join!(waiting, sending);
    sent.expect(0);
    got.expect(0);
    assert_eq!(b.value("LATE").unwrap(), b"fake-late");
    // --wait is bounded.
    b.run(&["inbox", "--wait", "601"], Run::agent())
        .await
        .expect(exit::USAGE);
}

#[tokio::test]
async fn transfers_too_big_to_confirm_are_refused_before_any_code() {
    let (a, _, relay) = devices();
    a.write_config("agent_code_send = true\n");
    let mut names = Vec::new();
    for i in 0..47 {
        let name = format!("{i:0>128}");
        a.set(&name, b"v").await;
        names.push(name);
    }
    let list = names.join(",");
    let out = a
        .run(
            &["send", "--names", &list, "--code", "-"],
            Run::agent().stdin("1-aardvark-adroitness\n"),
        )
        .await;
    out.expect(exit::USAGE);
    assert!(
        out.stderr.contains("groups of at most 46"),
        "{}",
        out.stderr
    );
    assert_eq!(
        relay.channel_status(1),
        kc_proto::memory_relay::ChannelStatus::Unknown
    );
}

#[tokio::test]
async fn a_full_inbox_is_reported() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    a.set("K", b"fake").await;
    // MemoryRelay holds at most 20 messages per inbox.
    for _ in 0..20 {
        a.run(&["send", "K", "--to", "bravo"], Run::agent())
            .await
            .expect(0);
    }
    let full = a.run(&["send", "K", "--to", "bravo"], Run::agent()).await;
    full.expect(exit::RELAY_UNAVAILABLE);
    assert!(full.stderr.contains("inbox is full"), "{}", full.stderr);
    assert!(full.stderr.contains("kc inbox"), "{}", full.stderr);
    // Reading the inbox stores the item once; the 19 copies are unchanged.
    let read = b.run(&["inbox"], Run::agent()).await;
    read.expect(0);
    assert_eq!(read.stderr.matches("From alpha").count(), 20);
}

#[tokio::test]
async fn an_interrupted_pairing_revokes_what_it_handed_out() {
    let (a, b, _) = devices();
    let (shown, joined) = transfer(
        &b,
        &["pair"],
        Run::human(vec![Answer::Yes]),
        &a,
        &["pair", "--join"],
        |code| Run::human(vec![Answer::Text(code), Answer::Interrupt]),
    )
    .await;
    shown.expect(0);
    joined.expect(130);
    assert!(a.peers().peers.is_empty());
    // B stored A before sending its receipt, but A revoked the token it had given B.
    b.set("X", b"fake").await;
    b.run(&["send", "X", "--to", "alpha"], Run::agent())
        .await
        .expect(exit::AUTH_FAILED);
}

#[tokio::test]
async fn the_inbox_never_offers_to_overwrite_without_the_flag() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    a.set("X", b"fake-new").await;
    b.set("X", b"fake-old").await;
    a.run(&["send", "X", "--to", "bravo"], Run::agent())
        .await
        .expect(0);
    // The conflict menu is [skip, rename]: the second choice renames, it doesn't replace.
    let got = b
        .run(&["inbox"], Run::human(vec![Answer::Yes, Answer::Select(1)]))
        .await;
    got.expect(0);
    assert_eq!(b.value("X").unwrap(), b"fake-old");
    assert_eq!(b.value("X-2").unwrap(), b"fake-new");
}

#[tokio::test]
async fn an_item_whose_write_is_in_doubt_never_replaces_a_local_change() {
    let (a, b, relay) = devices();
    pair(&a, &b).await.0.expect(0);
    a.set("K", b"fake-sent").await;
    a.run(&["send", "K", "--to", "bravo"], Run::agent())
        .await
        .expect(0);
    let (inbox_id, _) = b.inbox_credentials();
    // The write fails: whether it landed is unknown, so the journal marks it in doubt.
    b.memory().fail_writes_after(0);
    b.run(&["inbox"], Run::agent()).await.expect(1);
    b.memory().allow_writes();
    // Meanwhile K changes here; the retry must not override it, whatever the flag says.
    b.set("K", b"fake-local").await;
    let retried = b
        .run(&["inbox", "--on-conflict", "rename"], Run::agent())
        .await;
    retried.expect(exit::PARTIAL);
    assert_eq!(b.value("K").unwrap(), b"fake-local");
    assert_eq!(b.value("K-2"), None);
    assert_eq!(relay.pending_messages(&inbox_id), 0);
}

#[tokio::test]
async fn a_resumed_import_still_reports_what_the_first_run_skipped() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    a.set("K1", b"fake-sent-1").await;
    a.set("K2", b"fake-sent-2").await;
    b.set("K1", b"fake-local-1").await;
    a.run(&["send", "--to", "bravo", "--names", "K1,K2"], Run::agent())
        .await
        .expect(0);
    // K1 is skipped (a conflict); K2's write fails and stops the import there.
    b.memory().fail_writes_after(0);
    let first = b.run(&["inbox"], Run::agent()).await;
    first.expect(1);
    b.memory().allow_writes();
    let retried = b.run(&["inbox"], Run::agent()).await;
    // K2 is stored now, but K1's skip from the first run still counts.
    retried.expect(exit::PARTIAL);
    assert!(retried.stderr.contains("K1  skipped"), "{}", retried.stderr);
    assert_eq!(b.value("K1").unwrap(), b"fake-local-1");
    assert_eq!(b.value("K2").unwrap(), b"fake-sent-2");
}

#[tokio::test]
async fn registrations_an_interrupted_pairing_left_are_revoked_later() {
    let (a, b, relay) = devices();
    pair(&a, &b).await.0.expect(0);
    assert!(a.peers().pending_writers.is_empty());
    // A pairing that died midway (a crash, or Ctrl-C while waiting) left this behind.
    let (inbox_id, owner) = a.inbox_credentials();
    let token = kc_proto::payload::WriterToken::generate();
    let left = relay
        .register_writer(&inbox_id, &owner, &token.registration())
        .await
        .unwrap();
    let state = kc_cli::state::StateDir::new(a.dir.path());
    let mut peers = state.load_peers().unwrap();
    peers.pending_writers.push(kc_cli::state::PendingWriter {
        writer_id: Some(left.writer_id.clone()),
        token_sha256: None,
        since: 1,
        revoking: false,
        peer: None,
    });
    state.save_peers(&peers).unwrap();
    // The next pairing revokes it: its token no longer posts to A's inbox. (The
    // registration this re-pairing replaced stays pending, revoked after 72 hours.)
    pair(&a, &b).await.0.expect(0);
    assert!(
        a.peers()
            .pending_writers
            .iter()
            .all(|w| w.writer_id.as_deref() != Some(left.writer_id.as_str()))
    );
    let refused = relay
        .post_message(&inbox_id, &token.bearer(), b"not-a-message")
        .await
        .unwrap_err();
    assert!(refused.is(kc_wire::ErrorCode::Unauthorized), "{refused:?}");
}

#[tokio::test]
async fn rotation_replaces_a_damaged_inbox_entry() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    a.store()
        .set_internal("inbox-owner", b"not-an-inbox")
        .unwrap();
    let broken = a.run(&["inbox"], Run::agent()).await;
    broken.expect(1);
    assert!(
        broken.stderr.contains("kc device rotate"),
        "{}",
        broken.stderr
    );
    a.run(&["device", "rotate"], Run::human(vec![Answer::Yes]))
        .await
        .expect(0);
    let (inbox_id, _) = a.inbox_credentials();
    assert_eq!(a.config().inbox_id.unwrap(), inbox_id);
    a.run(&["inbox"], Run::agent()).await.expect(0);
}

#[tokio::test]
async fn rotation_drops_a_damaged_device_key_instead_of_keeping_it() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    a.store().set_internal("device-key", b"damaged").unwrap();
    a.run(&["device", "rotate"], Run::human(vec![Answer::Yes]))
        .await
        .expect(0);
    assert!(a.store().get_internal("device-key-prev").unwrap().is_none());
    assert_eq!(a.config().device_key_prev_until, None);
    // B forgets the old identity, as the rotation message says; paired again, the inbox
    // works.
    b.run(&["peers", "rm", "alpha"], Run::agent())
        .await
        .expect(0);
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    b.set("AFTER", b"fake-after").await;
    b.run(&["send", "AFTER", "--to", "alpha"], Run::agent())
        .await
        .expect(0);
    a.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(a.value("AFTER").unwrap(), b"fake-after");
}

#[tokio::test]
async fn pairing_again_keeps_messages_already_queued() {
    let (a, b, _) = devices();
    pair(&a, &b).await.0.expect(0);
    b.set("QUEUED", b"fake-queued").await;
    b.run(&["send", "QUEUED", "--to", "alpha"], Run::agent())
        .await
        .expect(0);
    // The same two devices pair again before A reads its inbox.
    let (shown, joined) = pair(&a, &b).await;
    shown.expect(0);
    joined.expect(0);
    a.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(a.value("QUEUED").unwrap(), b"fake-queued");
    // The replaced registration is revoked later, once such messages would have expired.
    assert_eq!(a.peers().pending_writers.len(), 1);
}

#[tokio::test]
async fn only_one_pairing_runs_at_a_time_on_a_device() {
    let (a, _, _) = devices();
    let held = kc_cli::state::StateDir::new(a.dir.path())
        .try_lock_pairing()
        .unwrap();
    let out = a.run(&["pair"], Run::human(vec![])).await;
    out.expect(1);
    assert!(out.stderr.contains("another pairing"), "{}", out.stderr);
    drop(held);
}

#[tokio::test]
async fn unpairing_also_revokes_registrations_a_re_pairing_retired() {
    let (a, b, relay) = devices();
    pair(&a, &b).await.0.expect(0);
    let old_token = b.writer_bearer("alpha");
    pair(&a, &b).await.0.expect(0);
    // The registration behind B's old token is retired but kept (queued messages).
    assert_eq!(a.peers().pending_writers.len(), 1);
    a.run(&["peers", "rm", "bravo"], Run::agent())
        .await
        .expect(0);
    assert!(a.peers().pending_writers.is_empty());
    let (inbox_id, _) = a.inbox_credentials();
    let refused = relay
        .post_message(&inbox_id, &old_token, b"not-a-message")
        .await
        .unwrap_err();
    assert!(refused.is(kc_wire::ErrorCode::Unauthorized), "{refused:?}");
}

#[tokio::test]
async fn an_interrupted_receiver_closes_the_channel_at_once() {
    let (a, b, _) = devices();
    a.write_config("agent_code_send = true\n");
    a.set("X", b"fake").await;
    let started = std::time::Instant::now();
    let (rx, tx) = transfer(
        &b,
        &["receive"],
        Run::human(vec![Answer::Interrupt]),
        &a,
        &["send", "X", "--code", "-"],
        piped_code,
    )
    .await;
    rx.expect(130);
    // The sender hears about it now, not at its 60 s session timeout.
    tx.expect(exit::EXPIRED);
    assert!(started.elapsed() < std::time::Duration::from_secs(20));
    assert_eq!(b.value("X"), None);
}

#[tokio::test]
async fn another_config_directory_leaves_the_inbox_alone() {
    let (a, b, relay) = devices();
    pair(&a, &b).await.0.expect(0);
    b.set("X", b"fake").await;
    b.run(&["send", "X", "--to", "alpha"], Run::agent())
        .await
        .expect(0);
    // The same keychain, another config directory: no peer list, no seen-set.
    let elsewhere = tempfile::tempdir().unwrap();
    let other = Device {
        name: "alpha".into(),
        dir: elsewhere,
        keychain: common::Keychain::Memory(a.memory().clone()),
        net: relay.clone(),
        env: Vec::new(),
    };
    let refused = other.run(&["inbox"], Run::agent()).await;
    refused.expect(1);
    assert!(
        refused.stderr.contains("another kc config directory"),
        "{}",
        refused.stderr
    );
    other.run(&["pair"], Run::human(vec![])).await.expect(1);
    // The message is still there for the right directory.
    a.run(&["inbox"], Run::agent()).await.expect(0);
    assert_eq!(a.value("X").unwrap(), b"fake");
}

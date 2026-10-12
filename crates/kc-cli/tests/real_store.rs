//! End to end with the real `kc` binary, a real `kc-relay` (`spawn_test_relay`, loopback)
//! and the real OS keychain (the Secret Service on Linux).
//!
//! **On Linux this never touches your login keyring by default.** [`isolated_e2e`] re-runs this
//! test binary inside a `dbus-run-session` with a throwaway gnome-keyring (its own `HOME`/`XDG_*`,
//! control directory and `KC_LOCK_DIR`), and the E2E runs there against that disposable keyring;
//! it then requires the keyring daemon to still be alive. A stock `cargo test` drives it. Set
//! `KC_TEST_USER_KEYRING=1` to run against your own login keyring instead.
//!
//! On macOS and Windows it is opt-in (it writes to the user's keychain):
//!
//! ```text
//! KC_TEST_REAL_STORE=1 cargo test -p kc-cli --test real_store
//! ```
//!
//! Each device has its own config directory and a unique `KC_NAMESPACE` (debug builds
//! honour it), purged at the end even when the test fails. Values are fake and are
//! compared, never printed.

mod common;

use std::io::{BufRead as _, BufReader, Write as _};
use std::path::Path;
use std::process::{Child, Command, Output, Stdio};
use std::time::{SystemTime, UNIX_EPOCH};

use common::{Answer, Device, Http, Run, transfer};
use kc_relay::{Config, spawn_test_relay};
use kc_store::{Store, StoreConfig};

#[cfg(not(target_os = "linux"))]
fn enabled() -> bool {
    std::env::var_os("KC_TEST_REAL_STORE").is_some_and(|v| v == "1")
}

/// Whether this process is the inner run of [`isolated_e2e`]: a private session bus with a
/// throwaway gnome-keyring.
#[cfg(target_os = "linux")]
fn in_isolated_suite() -> bool {
    // Exactly "1": a stray KC_TEST_ISOLATED=0 or empty value must not open the door to the real
    // keyring.
    std::env::var("KC_TEST_ISOLATED").as_deref() == Ok("1")
}

/// Whether the user opted in to running the E2E against their own login keyring.
#[cfg(target_os = "linux")]
fn user_keyring_opt_in() -> bool {
    std::env::var("KC_TEST_USER_KEYRING").as_deref() == Ok("1")
}

#[cfg(target_os = "linux")]
fn have(tool: &str) -> bool {
    Command::new("sh")
        .arg("-c")
        .arg(format!("command -v {tool}"))
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}

/// Deletes everything in the test namespaces when dropped.
struct Purge(Vec<(String, std::path::PathBuf)>);

impl Drop for Purge {
    fn drop(&mut self) {
        for (namespace, dir) in &self.0 {
            match Store::open(StoreConfig::new(namespace.as_str(), dir.as_path()))
                .and_then(|store| store.purge_namespace())
            {
                Ok(_) => {}
                Err(e) => eprintln!("cleanup of {namespace} failed: {e}"),
            }
        }
    }
}

fn unique_namespace(device: &str) -> String {
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos();
    format!(
        "dev.1pass.kc.test-e2e-{}-{nanos}-{device}",
        std::process::id()
    )
}

/// The real binary, for one device, as a script would run it (no terminal, `CI` set).
fn kc(dir: &Path, namespace: &str, relay: &str) -> Command {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_kc"));
    cmd.env("KC_CONFIG_DIR", dir)
        .env("KC_NAMESPACE", namespace)
        .env("KC_RELAY", relay)
        .env("CI", "1")
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped());
    cmd
}

fn run_with_stdin(mut cmd: Command, args: &[&str], stdin: &[u8]) -> Output {
    let mut child = cmd.args(args).spawn().expect("kc runs");
    child.stdin.take().unwrap().write_all(stdin).unwrap();
    child.wait_with_output().unwrap()
}

#[track_caller]
fn expect(output: &Output, code: i32) {
    assert_eq!(
        output.status.code(),
        Some(code),
        "stderr:\n{}",
        String::from_utf8_lossy(&output.stderr)
    );
}

/// Starts `kc receive` and returns it with the code it shows on stderr.
fn start_receiver(cmd: Command) -> (Child, String, std::thread::JoinHandle<String>) {
    let mut cmd = cmd;
    let mut child = cmd.arg("receive").spawn().expect("kc runs");
    drop(child.stdin.take());
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    let mut seen = String::new();
    let code = loop {
        let line = lines
            .next()
            .unwrap_or_else(|| panic!("kc receive ended without a code:\n{seen}"))
            .unwrap();
        seen.push_str(&line);
        seen.push('\n');
        if let Some(code) = line.strip_prefix("Code: ") {
            break code.trim().to_owned();
        }
    };
    let rest = std::thread::spawn(move || {
        let mut text = seen;
        for line in lines.map_while(Result::ok) {
            text.push_str(&line);
            text.push('\n');
        }
        text
    });
    (child, code, rest)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn real_binary_real_keychain_real_relay() {
    // The explicit off switch wins everywhere, even under KC_TEST_USER_KEYRING=1.
    if std::env::var("KC_TEST_REAL_STORE").as_deref() == Ok("0") {
        eprintln!("skipped: KC_TEST_REAL_STORE=0");
        return;
    }
    // On Linux, run against the throwaway keyring the isolated wrapper sets up, or the user's own
    // keyring only when they opt in; never the user's keyring by default. Elsewhere, opt in with
    // KC_TEST_REAL_STORE=1.
    #[cfg(target_os = "linux")]
    if !in_isolated_suite() && !user_keyring_opt_in() {
        eprintln!(
            "skipped: the isolated E2E (`isolated_e2e`, run automatically by `cargo test`) covers \
             this; set KC_TEST_USER_KEYRING=1 to run against your own login keyring"
        );
        return;
    }
    #[cfg(not(target_os = "linux"))]
    if !enabled() {
        eprintln!("skipped: set KC_TEST_REAL_STORE=1 to run against the OS keychain");
        return;
    }
    // Release builds ignore KC_NAMESPACE and would work on the real kc namespace.
    if !cfg!(debug_assertions) {
        eprintln!("skipped: KC_NAMESPACE only works in debug builds; run without --release");
        return;
    }
    let relay = spawn_test_relay(Config::for_tests()).await.unwrap();
    let url = relay.url();
    let (ns_a, ns_b) = (unique_namespace("a"), unique_namespace("b"));
    let mut a = Device::on_os_keychain("alpha", Http, &ns_a);
    let mut b = Device::on_os_keychain("bravo", Http, &ns_b);
    for d in [&mut a, &mut b] {
        d.env.push(("KC_RELAY".into(), url.clone()));
    }
    let _purge = Purge(vec![
        (ns_a.clone(), a.dir.path().to_path_buf()),
        (ns_b.clone(), b.dir.path().to_path_buf()),
    ]);
    let kc_a = || kc(a.dir.path(), &ns_a, &url);
    let kc_b = || kc(b.dir.path(), &ns_b, &url);
    // Before anything is written: both binaries really use the test namespaces.
    for (cmd, ns) in [(kc_a(), &ns_a), (kc_b(), &ns_b)] {
        let doctor = run_with_stdin(cmd, &["doctor"], b"");
        let report = String::from_utf8_lossy(&doctor.stdout);
        assert!(
            report.contains(&format!("namespace {ns}")),
            "kc doesn't use the test namespace; refusing to touch the keychain:\n{report}"
        );
    }

    // 1. Code transfer, binary to binary, the code piped with `--code -`.
    expect(
        &run_with_stdin(kc_a(), &["set", "E2E_TOKEN"], b"fake-e2e-value\n"),
        0,
    );
    std::fs::write(a.dir.path().join("config.toml"), "agent_code_send = true\n").unwrap();
    let (mut receiver, code, receiver_log) = start_receiver(kc_b());

    #[cfg(target_os = "linux")]
    {
        // The waiting receiver is hardened: no core dumps, and other processes of the same
        // user can't read its memory or environment.
        let pid = receiver.id();
        let environ = std::fs::read(format!("/proc/{pid}/environ"));
        assert!(environ.is_err(), "kc's /proc/<pid>/environ is readable");
        let limits = std::fs::read_to_string(format!("/proc/{pid}/limits")).unwrap();
        let core = limits
            .lines()
            .find(|l| l.starts_with("Max core file size"))
            .unwrap();
        assert_eq!(core.split_whitespace().nth(4), Some("0"), "{core}");
    }

    let sent = run_with_stdin(
        kc_a(),
        &["send", "E2E_TOKEN", "--code", "-"],
        format!("{code}\n").as_bytes(),
    );
    expect(&sent, 0);
    let status = receiver.wait().unwrap();
    let log = receiver_log.join().unwrap();
    assert_eq!(status.code(), Some(0), "kc receive:\n{log}");

    let got = run_with_stdin(kc_b(), &["get", "E2E_TOKEN"], b"");
    expect(&got, 0);
    assert!(
        got.stdout == b"fake-e2e-value",
        "kc get returned a different value"
    );
    let list = run_with_stdin(kc_b(), &["list", "--json"], b"");
    expect(&list, 0);
    assert!(String::from_utf8_lossy(&list.stdout).contains("E2E_TOKEN"));
    let check = run_with_stdin(kc_b(), &["get", "MISSING", "--check"], b"");
    expect(&check, 3);

    // 2. Pair in-process (the scripted prompts stand in for the people; same keychains),
    //    then the binaries send to the paired device and read the inbox.
    let (shown, joined) = transfer(
        &b,
        &["pair"],
        Run::human(vec![Answer::Yes]),
        &a,
        &["pair", "--join"],
        |code| Run::human(vec![Answer::Text(code), Answer::Yes]),
    )
    .await;
    shown.expect(0);
    joined.expect(0);
    expect(
        &run_with_stdin(kc_a(), &["set", "E2E_FILE", "--raw"], b"FAKE=1\nOTHER=2\n"),
        0,
    );
    expect(
        &run_with_stdin(
            kc_a(),
            &["send", "--to", "bravo", "--names", "E2E_FILE"],
            b"",
        ),
        0,
    );
    expect(&run_with_stdin(kc_b(), &["inbox"], b""), 0);
    let out = b.dir.path().join("restored.env");
    expect(
        &run_with_stdin(
            kc_b(),
            &["get", "E2E_FILE", "--to-file", out.to_str().unwrap()],
            b"",
        ),
        0,
    );
    assert!(std::fs::read(&out).unwrap() == b"FAKE=1\nOTHER=2\n");

    // 3. exec hands a value to a child through its environment only.
    #[cfg(unix)]
    expect(
        &run_with_stdin(
            kc_b(),
            &[
                "exec",
                "--env",
                "TOKEN=E2E_TOKEN",
                "--",
                "sh",
                "-c",
                "test \"$TOKEN\" = fake-e2e-value",
            ],
            b"",
        ),
        0,
    );

    let doctor = run_with_stdin(kc_b(), &["doctor"], b"");
    expect(&doctor, 0);
    relay.shutdown().await.unwrap();
}

/// Runs the end-to-end test against a throwaway gnome-keyring so it never touches the user's
/// login keyring, and fails if that keyring daemon crashes.
///
/// A stock `cargo test` reaches this wrapper. It starts a private `dbus-run-session` with its own
/// gnome-keyring (own `HOME`/`XDG_*`, control directory and `KC_LOCK_DIR`), then re-runs this test
/// binary inside it with `KC_TEST_ISOLATED=1` so [`real_binary_real_keychain_real_relay`] runs
/// there. Afterwards the keyring daemon must still be alive. Set `KC_TEST_USER_KEYRING=1` to skip
/// the wrapper and use your own keyring directly.
#[cfg(target_os = "linux")]
#[test]
fn isolated_e2e() {
    if std::env::var("KC_TEST_REAL_STORE").as_deref() == Ok("0")
        || in_isolated_suite()
        || user_keyring_opt_in()
    {
        return;
    }
    if !cfg!(debug_assertions) {
        eprintln!("skipped: KC_NAMESPACE only works in debug builds; run without --release");
        return;
    }
    let tools = ["dbus-run-session", "gnome-keyring-daemon", "pgrep", "pkill"];
    if let Some(missing) = tools.iter().find(|tool| !have(tool)) {
        eprintln!("skipping isolated e2e: {missing} is not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    for sub in ["home", "data", "config", "run", "ctl", "lock"] {
        std::fs::create_dir(root.path().join(sub)).unwrap();
    }
    #[cfg(unix)]
    for sub in ["run", "ctl", "lock"] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.path().join(sub),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let script = r#"
set -u
case "$DBUS_SESSION_BUS_ADDRESS" in
  *"/run/user/"*|"") echo "refusing: not a private bus: $DBUS_SESSION_BUS_ADDRESS" >&2; exit 90;;
esac
SOCK=$(printf '%s' "$DBUS_SESSION_BUS_ADDRESS" | sed -n 's/.*unix:path=\([^,;]*\).*/\1/p')
[ -n "$SOCK" ] && ln -sf "$SOCK" "$XDG_RUNTIME_DIR/bus"
printf 'fake-test-password' \
  | gnome-keyring-daemon --unlock --components=pkcs11,secrets --control-directory="$ROOT/ctl" >/dev/null \
  || exit 91
sleep 0.3
GK=$(pgrep -f "control-directory=$ROOT/ctl" | head -1)
[ -n "$GK" ] || { echo "no private keyring daemon" >&2; exit 92; }
echo "isolated e2e: private bus $DBUS_SESSION_BUS_ADDRESS, keyring daemon pid $GK"
"$EXE" --nocapture --test-threads=1 --exact real_binary_real_keychain_real_relay
STATUS=$?
if ! kill -0 "$GK" 2>/dev/null; then
  echo "THE KEYRING DAEMON DIED during the isolated e2e" >&2
  STATUS=97
fi
pkill -f "control-directory=$ROOT/ctl" 2>/dev/null
exit $STATUS
"#;
    let output = Command::new("timeout")
        .args(["300", "dbus-run-session", "--", "bash", "-c", script])
        .env("ROOT", root.path())
        .env("EXE", std::env::current_exe().unwrap())
        .env("HOME", root.path().join("home"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_RUNTIME_DIR", root.path().join("run"))
        .env("KC_LOCK_DIR", root.path().join("lock"))
        .env("KC_TEST_ISOLATED", "1")
        .env("KC_TEST_REAL_STORE", "1")
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY")
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env_remove("GNOME_KEYRING_CONTROL")
        .env_remove("SSH_AUTH_SOCK")
        .output()
        .expect("dbus-run-session runs");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.status.success(), "isolated e2e failed:\n{text}");
}

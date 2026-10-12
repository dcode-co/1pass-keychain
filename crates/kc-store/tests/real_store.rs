//! Tests against the real OS keychain: the Secret Service on Linux, the login keychain on
//! macOS, Credential Manager on Windows.
//!
//! **On Linux these tests never touch your login keyring by default.** [`isolated_real_store_suite`]
//! re-runs this test binary inside a `dbus-run-session` with a throwaway gnome-keyring (its own
//! `HOME`/`XDG_*`, control directory and [`kc_store::ENV_LOCK_DIR`]), and all the real-store
//! tests run there against that disposable keyring. It also requires the keyring daemon to still
//! be alive afterwards, so a kc change that could crash gnome-keyring fails the suite. A stock
//! `cargo test` drives the whole thing automatically.
//!
//! - `KC_TEST_USER_KEYRING=1`: opt in to running these directly against your own login keyring
//!   (not used by CI). Without it, and outside the isolated suite, they skip.
//! - `KC_TEST_REAL_STORE=1`: a missing or unusable keychain fails the run instead of skipping
//!   (on macOS and Windows, and inside the isolated suite, which sets it).
//! - `KC_TEST_REAL_STORE=0`: skipped.
//!
//! Every test works in its own random namespace `dev.1pass.kc.test-<random>` (never the real
//! one) and deletes everything in it when it ends, also when it fails. Every value is fake.
//! Where possible, a separate process (`secret-tool`, `security`, `cmdkey`) confirms that the
//! entries really are in the OS keychain, which a mock store could never fake.

use std::path::PathBuf;
use std::process::Command;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use kc_store::{
    Change, DEFAULT_NAMESPACE, ItemKind, MIN_MAX_BLOB_LEN, Origin, Store, StoreConfig, StoreError,
};

const TEST_PREFIX: &str = "dev.1pass.kc.test-";

fn required() -> bool {
    std::env::var("KC_TEST_REAL_STORE").as_deref() == Ok("1")
}

fn disabled() -> bool {
    std::env::var("KC_TEST_REAL_STORE").as_deref() == Ok("0")
}

/// Whether this process is the inner run of [`isolated_real_store_suite`]: a private session bus
/// with a throwaway gnome-keyring, set up by the wrapper.
#[cfg(target_os = "linux")]
fn in_isolated_suite() -> bool {
    // Exactly "1": a stray KC_TEST_ISOLATED=0 or empty value must not open the door to the real
    // keyring (it would skip the wrapper and let TestNs::new use the inherited session bus).
    std::env::var("KC_TEST_ISOLATED").as_deref() == Ok("1")
}

/// Whether the user opted in to running the real-store tests against their own login keyring.
#[cfg(target_os = "linux")]
fn user_keyring_opt_in() -> bool {
    std::env::var("KC_TEST_USER_KEYRING").as_deref() == Ok("1")
}

/// A missing or unusable keychain is a hard failure (rather than a skip) when the keychain is
/// required: `KC_TEST_REAL_STORE=1`, or inside the isolated suite, which provides one.
fn keychain_required() -> bool {
    #[cfg(target_os = "linux")]
    if in_isolated_suite() {
        return true;
    }
    required()
}

fn random_suffix() -> String {
    static COUNTER: AtomicU32 = AtomicU32::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.subsec_nanos())
        .unwrap_or(0);
    format!(
        "{:x}{:08x}{:x}",
        std::process::id(),
        nanos,
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

/// A throwaway namespace and config directory, purged on drop.
struct TestNs {
    namespace: String,
    dir: tempfile::TempDir,
}

impl TestNs {
    /// `None` means "skip this test" (the reason has been printed).
    fn new(test: &str) -> Option<TestNs> {
        if disabled() {
            eprintln!("skipping {test}: KC_TEST_REAL_STORE=0");
            return None;
        }
        // On Linux, never touch the user's login keyring unless they explicitly opt in: the
        // isolated suite runs these against a throwaway keyring instead.
        #[cfg(target_os = "linux")]
        if !in_isolated_suite() && !user_keyring_opt_in() {
            eprintln!(
                "skipping {test}: real-store tests run in the isolated suite \
                 (`cargo test` runs it automatically); set KC_TEST_USER_KEYRING=1 to run them \
                 against your own login keyring"
            );
            return None;
        }
        let namespace = format!("{TEST_PREFIX}{}", random_suffix());
        assert_ne!(
            namespace, DEFAULT_NAMESPACE,
            "tests never use the real namespace"
        );
        let ns = TestNs {
            namespace,
            dir: tempfile::tempdir().unwrap(),
        };
        match ns.store().backend_description() {
            Ok(description) => {
                eprintln!("{test}: {description}, namespace {}", ns.namespace);
                Some(ns)
            }
            Err(err) if keychain_required() => {
                panic!("a keychain is required but the OS keychain is not usable: {err}")
            }
            Err(err) => {
                eprintln!(
                    "skipping {test}: no usable OS keychain ({err}). Set KC_TEST_REAL_STORE=1 to require one"
                );
                None
            }
        }
    }

    fn config(&self) -> StoreConfig {
        assert!(self.namespace.starts_with(TEST_PREFIX));
        // The tests run in parallel and keychain calls take turns within a process, so a call
        // can wait a while for its turn; the default 5 s is meant for one command at a time.
        StoreConfig::new(&self.namespace, self.dir.path()).with_timeout(Duration::from_secs(30))
    }

    /// A fresh store: new backend, new keychain connections, nothing cached.
    fn store(&self) -> Store {
        Store::open(self.config()).unwrap()
    }

    /// A fresh store with the smallest blob limit, so small values get chunked.
    fn chunky_store(&self) -> Store {
        Store::open(self.config().with_max_blob_len(MIN_MAX_BLOB_LEN)).unwrap()
    }
}

impl Drop for TestNs {
    fn drop(&mut self) {
        match Store::open(self.config()).map(|store| store.purge_namespace()) {
            Ok(Ok(_)) => {}
            Ok(Err(err)) | Err(err) => eprintln!("cleanup of {} failed: {err}", self.namespace),
        }
        #[cfg(target_os = "linux")]
        if have("secret-tool") {
            let _ = Command::new("secret-tool")
                .args(["clear", "service", &self.namespace])
                .status();
        }
    }
}

fn fake(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
        .collect()
}

fn get(store: &Store, name: &str) -> Option<Vec<u8>> {
    store.get(name).unwrap().map(|v| v.as_bytes().to_vec())
}

#[cfg(target_os = "linux")]
fn have(tool: &str) -> bool {
    Command::new("sh")
        .args(["-c", &format!("command -v {tool} >/dev/null 2>&1")])
        .status()
        .is_ok_and(|s| s.success())
}

// ---------------------------------------------------------------------------------------------
// A second process looks into the OS keychain.
// ---------------------------------------------------------------------------------------------

/// Whether another process sees `account` under `namespace` in the OS keychain. `None` when the
/// platform tool isn't installed (then the check is skipped, unless the real store is required).
#[cfg(target_os = "linux")]
fn external_finds(namespace: &str, account: &str) -> Option<bool> {
    let accounts = external_accounts(namespace)?;
    Some(accounts.iter().any(|a| a == account))
}

/// Every account another process (`secret-tool search --all`) sees under `namespace`.
#[cfg(target_os = "linux")]
fn external_accounts(namespace: &str) -> Option<Vec<String>> {
    if !have("secret-tool") {
        assert!(
            !required(),
            "KC_TEST_REAL_STORE=1 needs secret-tool (libsecret)"
        );
        eprintln!("secret-tool is not installed; skipping the separate-process check");
        return None;
    }
    let output = Command::new("secret-tool")
        .args(["search", "--all", "service", namespace])
        .output()
        .unwrap();
    // The output contains the (fake) secrets; it is parsed, never printed. secret-tool writes
    // the `attribute.* = …` lines to stderr and the rest to stdout.
    assert!(output.status.success(), "secret-tool search failed");
    let text = format!(
        "{}\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    let mut accounts: Vec<String> = text
        .lines()
        .filter_map(|line| line.strip_prefix("attribute.username = "))
        .map(str::to_owned)
        .collect();
    accounts.sort();
    Some(accounts)
}

/// `(generation, index)` of every chunk account of `base`, sorted.
#[cfg(target_os = "linux")]
fn chunk_generations(accounts: &[String], base: &str) -> Vec<(u64, u32)> {
    let prefix = format!("{base}#");
    let mut chunks: Vec<(u64, u32)> = accounts
        .iter()
        .filter_map(|account| account.strip_prefix(&prefix))
        .filter_map(|suffix| {
            let (generation, index) = suffix.split_once('.')?;
            Some((generation.parse().ok()?, index.parse().ok()?))
        })
        .collect();
    chunks.sort_unstable();
    chunks
}

#[cfg(target_os = "macos")]
fn external_finds(namespace: &str, account: &str) -> Option<bool> {
    // Without -g or -w, `security` reads attributes only: no secret, no prompt.
    let status = Command::new("security")
        .args(["find-generic-password", "-s", namespace, "-a", account])
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .unwrap();
    Some(status.success())
}

#[cfg(target_os = "windows")]
fn external_finds(namespace: &str, account: &str) -> Option<bool> {
    let target = format!("{account}@{namespace}");
    let output = Command::new("cmdkey")
        .arg(format!("/list:{target}"))
        .output()
        .unwrap();
    Some(String::from_utf8_lossy(&output.stdout).contains(&target))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn external_finds(_namespace: &str, _account: &str) -> Option<bool> {
    None
}

fn assert_external(namespace: &str, account: &str, expected: bool) {
    if let Some(found) = external_finds(namespace, account) {
        assert_eq!(
            found,
            expected,
            "a separate process {} {account:?} in the OS keychain",
            if expected {
                "should see"
            } else {
                "should not see"
            }
        );
    }
}

// ---------------------------------------------------------------------------------------------
// Every platform.
// ---------------------------------------------------------------------------------------------

#[test]
fn roundtrip_through_separate_instances_and_a_separate_process() {
    let Some(ns) = TestNs::new("roundtrip") else {
        return;
    };
    let writer = ns.store();
    let outcome = writer
        .set(
            "dev-env/api-key",
            b"fake-api-key-123",
            ItemKind::Text,
            Origin::Local,
        )
        .unwrap();
    assert_eq!(outcome.change, Change::Created);
    drop(writer);

    // A new store has its own backend and keychain connection: if writes had gone to an
    // in-memory store, this read would come back empty.
    let reader = ns.store();
    assert_eq!(
        get(&reader, "dev-env/api-key").as_deref(),
        Some(&b"fake-api-key-123"[..])
    );
    assert!(reader.exists("dev-env/api-key").unwrap());
    assert!(!reader.exists("missing").unwrap());
    assert_eq!(get(&reader, "missing"), None);
    assert_external(&ns.namespace, "item:dev-env/api-key", true);
    assert_external(&ns.namespace, "item:missing", false);

    if cfg!(target_os = "linux") {
        assert!(
            reader
                .backend_description()
                .unwrap()
                .contains("Secret Service")
        );
    }
}

#[test]
fn chunked_values_use_generations_and_overwrites_clean_up() {
    let Some(ns) = TestNs::new("chunked") else {
        return;
    };
    let (v1, v2, v3) = (fake(1000, 1), fake(350, 2), fake(10, 3));
    let store = ns.chunky_store();
    assert_eq!(
        store
            .set("big", &v1, ItemKind::File, Origin::Local)
            .unwrap()
            .change,
        Change::Created
    );
    assert_eq!(get(&ns.chunky_store(), "big"), Some(v1.clone()));
    assert_external(&ns.namespace, "item:big", true);
    // Seen from another process: 7 chunks of one generation.
    #[cfg(target_os = "linux")]
    let g1 = external_accounts(&ns.namespace).map(|accounts| {
        let chunks = chunk_generations(&accounts, "item:big");
        assert_eq!(chunks.len(), 7, "{accounts:?}");
        chunks[0].0
    });

    // Shrink: 7 chunks of one generation → 3 chunks of another; v1 stays as #prev.
    assert_eq!(
        store
            .set("big", &v2, ItemKind::File, Origin::Local)
            .unwrap()
            .change,
        Change::Updated
    );
    // Shrink again to an inline value: v1's generation goes, v2's is now #prev.
    assert_eq!(
        store
            .set("big", &v3, ItemKind::File, Origin::Local)
            .unwrap()
            .change,
        Change::Updated
    );
    let fresh = ns.chunky_store();
    assert_eq!(get(&fresh, "big"), Some(v3.clone()));
    assert_external(&ns.namespace, "item:big#prev", true);

    #[cfg(target_os = "linux")]
    if let (Some(accounts), Some(g1)) = (external_accounts(&ns.namespace), g1) {
        let chunks = chunk_generations(&accounts, "item:big");
        assert_eq!(chunks.len(), 3, "{accounts:?}");
        assert!(chunks.iter().all(|(generation, _)| *generation != g1));
        assert!(accounts.contains(&"item:big".to_owned()));
        assert!(accounts.contains(&"item:big#prev".to_owned()));
        assert_eq!(accounts.len(), 5, "{accounts:?}");
    }

    // The previous value comes back, verified, and a second restore undoes the first.
    fresh.restore("big").unwrap();
    assert_eq!(get(&ns.chunky_store(), "big"), Some(v2));
    fresh.restore("big").unwrap();
    assert_eq!(get(&ns.chunky_store(), "big"), Some(v3));
}

#[test]
fn identical_writes_are_no_ops() {
    let Some(ns) = TestNs::new("unchanged") else {
        return;
    };
    let store = ns.chunky_store();
    for value in [fake(20, 1), fake(400, 2)] {
        let name = format!("same-{}", value.len());
        let first = store
            .set(&name, &value, ItemKind::Text, Origin::Local)
            .unwrap();
        assert_eq!(first.change, Change::Created);
        let again = store
            .set(&name, &value, ItemKind::Text, Origin::Local)
            .unwrap();
        assert_eq!(again.change, Change::Unchanged);
        assert_external(&ns.namespace, &format!("item:{name}#prev"), false);
    }
}

#[test]
fn delete_removes_every_entry_of_an_item() {
    let Some(ns) = TestNs::new("delete") else {
        return;
    };
    let store = ns.chunky_store();
    store
        .set("gone", &fake(500, 1), ItemKind::Text, Origin::Local)
        .unwrap();
    store
        .set("gone", &fake(400, 2), ItemKind::Text, Origin::Local)
        .unwrap();
    store
        .set("kept", b"fake-kept", ItemKind::Text, Origin::Local)
        .unwrap();

    assert!(ns.store().delete("gone").unwrap());
    assert_eq!(get(&ns.store(), "gone"), None);
    assert!(!ns.store().delete("gone").unwrap());
    assert_external(&ns.namespace, "item:gone", false);
    assert_external(&ns.namespace, "item:gone#prev", false);
    assert_external(&ns.namespace, "item:kept", true);

    #[cfg(target_os = "linux")]
    if let Some(accounts) = external_accounts(&ns.namespace) {
        assert_eq!(accounts, ["item:kept"]);
    }
}

#[test]
fn internal_slots_roundtrip_and_stay_unlisted() {
    let Some(ns) = TestNs::new("internal") else {
        return;
    };
    let key = fake(32, 9);
    assert_eq!(
        ns.store().set_internal("device-key", &key).unwrap(),
        Change::Created
    );
    assert_eq!(
        ns.store()
            .get_internal("device-key")
            .unwrap()
            .unwrap()
            .as_bytes(),
        key
    );
    assert!(ns.store().list().unwrap().is_empty());
    assert_external(&ns.namespace, "sys:device-key", true);
    assert!(ns.store().delete_internal("device-key").unwrap());
    assert!(ns.store().get_internal("device-key").unwrap().is_none());
    assert_external(&ns.namespace, "sys:device-key", false);
}

#[test]
fn list_verify_and_reindex_use_the_keychain() {
    let Some(ns) = TestNs::new("list") else {
        return;
    };
    let store = ns.store();
    for name in ["a", "b/c"] {
        store
            .set(name, b"fake-listed", ItemKind::Text, Origin::Local)
            .unwrap();
    }
    let listed: Vec<String> = store.list().unwrap().into_iter().map(|i| i.name).collect();
    assert_eq!(listed, ["a", "b/c"]);

    // Lose the metadata cache: the keychain still lists the items.
    std::fs::remove_file(ns.dir.path().join("index.json")).unwrap();
    let store = ns.store();
    let listed = store.list().unwrap();
    assert_eq!(listed.len(), 2);
    assert!(listed.iter().all(|item| item.origin == Origin::Unknown));
    assert_eq!(store.verify().unwrap().unindexed, ["a", "b/c"]);
    let report = store.reindex().unwrap();
    assert_eq!(report.added, ["a", "b/c"]);
    assert!(store.verify().unwrap().is_clean());
}

// ---------------------------------------------------------------------------------------------
// Linux only: secret-tool interop, D-Bus environment handling, locked keyrings.
// ---------------------------------------------------------------------------------------------

#[cfg(target_os = "linux")]
fn secret_tool_store(attributes: &[&str], secret: &[u8]) {
    use std::io::Write;
    use std::process::Stdio;
    let mut args = vec!["store", "--label=kc-store test item"];
    args.extend_from_slice(attributes);
    let mut child = Command::new("secret-tool")
        .args(&args)
        .stdin(Stdio::piped())
        .spawn()
        .unwrap();
    child.stdin.take().unwrap().write_all(secret).unwrap();
    assert!(child.wait().unwrap().success(), "secret-tool store failed");
}

/// Clears a throwaway service on drop.
#[cfg(target_os = "linux")]
struct ClearService(String);

#[cfg(target_os = "linux")]
impl Drop for ClearService {
    fn drop(&mut self) {
        let _ = Command::new("secret-tool")
            .args(["clear", "service", &self.0])
            .status();
    }
}

#[cfg(target_os = "linux")]
#[test]
fn reads_entries_written_by_another_program() {
    let Some(ns) = TestNs::new("reverse") else {
        return;
    };
    if !have("secret-tool") {
        eprintln!("skipping reverse: secret-tool is not installed");
        return;
    }
    // kc's own format (tag 0x01 + value), written by a different program.
    secret_tool_store(
        &[
            "service",
            &ns.namespace,
            "username",
            "item:from-secret-tool",
        ],
        b"\x01fake-written-elsewhere",
    );
    assert_eq!(
        get(&ns.store(), "from-secret-tool").as_deref(),
        Some(&b"fake-written-elsewhere"[..])
    );
    let listed: Vec<String> = ns
        .store()
        .list()
        .unwrap()
        .into_iter()
        .map(|i| i.name)
        .collect();
    assert_eq!(listed, ["from-secret-tool"]);
}

#[cfg(target_os = "linux")]
#[test]
fn adopt_reads_secret_tool_and_keyring_style_items() {
    let Some(ns) = TestNs::new("adopt") else {
        return;
    };
    if !have("secret-tool") {
        eprintln!("skipping adopt: secret-tool is not installed");
        return;
    }
    let svc_a = format!("kc-test-adopt-a-{}", random_suffix());
    let svc_b = format!("kc-test-adopt-b-{}", random_suffix());
    let _clear_a = ClearService(svc_a.clone());
    let _clear_b = ClearService(svc_b.clone());
    // secret-tool style: {service, account}.
    secret_tool_store(&["service", &svc_a, "account", "me"], b"fake-adopt-me");
    // keyring-rs / Python keyring style: {service, username}.
    secret_tool_store(&["service", &svc_b, "username", "you"], b"fake-adopt-you");

    let store = ns.store();
    let outcome = store.adopt(&svc_a, Some("me"), "adopted/a").unwrap();
    assert_eq!(outcome.change, Change::Created);
    assert_eq!(
        outcome.info.origin,
        Origin::Adopted {
            service: svc_a.clone(),
            account: Some("me".into()),
        }
    );
    assert_eq!(
        get(&ns.store(), "adopted/a").as_deref(),
        Some(&b"fake-adopt-me"[..])
    );
    store.adopt(&svc_b, Some("you"), "adopted/b").unwrap();
    assert_eq!(
        get(&ns.store(), "adopted/b").as_deref(),
        Some(&b"fake-adopt-you"[..])
    );
    // Without an account: the single item.
    let outcome = store.adopt(&svc_a, None, "adopted/c").unwrap();
    assert_eq!(
        outcome.info.origin,
        Origin::Adopted {
            service: svc_a.clone(),
            account: Some("me".into()),
        }
    );
    // The originals are untouched.
    let output = Command::new("secret-tool")
        .args(["lookup", "service", &svc_a, "account", "me"])
        .output()
        .unwrap();
    assert_eq!(output.stdout, b"fake-adopt-me");

    secret_tool_store(
        &["service", &svc_a, "account", "other"],
        b"fake-adopt-other",
    );
    let err = store.adopt(&svc_a, None, "adopted/d").unwrap_err();
    assert!(matches!(err, StoreError::Ambiguous { .. }), "{err}");
    assert_eq!(err.exit_code(), 2);
    let message = err.to_string();
    assert!(
        message.contains("account=me") && message.contains("account=other"),
        "{message}"
    );
    let err = store
        .adopt(&format!("kc-test-missing-{}", random_suffix()), None, "x")
        .unwrap_err();
    assert!(matches!(err, StoreError::NotFound(_)), "{err}");
    assert_eq!(err.exit_code(), 3);
}

/// Runs one [`child_scenario`] in a new process of this test binary.
#[cfg(target_os = "linux")]
fn child(scenario: &str, namespace: &str, dir: &std::path::Path) -> Command {
    let mut command = Command::new(std::env::current_exe().unwrap());
    command
        .args([
            "--exact",
            "child_scenario",
            "--nocapture",
            "--test-threads=1",
        ])
        .env("KC_TEST_CHILD", scenario)
        .env("KC_TEST_CHILD_NS", namespace)
        .env("KC_TEST_CHILD_DIR", dir);
    command
}

#[cfg(target_os = "linux")]
fn run(mut command: Command) -> (bool, String) {
    let output = command.output().unwrap();
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    (output.status.success(), text)
}

/// Every operation on a locked keyring fails with `Locked` (exit code 4) and the unlock hint.
fn assert_every_operation_is_locked(store: &Store) {
    let results = [
        ("get", store.get("child-item").map(|_| ())),
        ("get chunked", store.get("child-big").map(|_| ())),
        (
            "overwrite",
            store
                .set("child-item", b"fake-new", ItemKind::Text, Origin::Local)
                .map(|_| ()),
        ),
        (
            "create",
            store
                .set("child-new", b"fake-new", ItemKind::Text, Origin::Local)
                .map(|_| ()),
        ),
        ("restore", store.restore("child-big").map(|_| ())),
        ("delete", store.delete("child-item").map(|_| ())),
        ("list", store.list().map(|_| ())),
        ("exists", store.exists("child-item").map(|_| ())),
        ("internal", store.get_internal("device-key").map(|_| ())),
    ];
    for (op, result) in results {
        let err = result.expect_err(op);
        assert!(matches!(err, StoreError::Locked { .. }), "{op}: {err}");
        assert_eq!(err.exit_code(), 4, "{op}");
        assert!(
            err.to_string().contains("gnome-keyring-daemon --unlock"),
            "{op}: {err}"
        );
    }
}

/// Not a test on its own: the scenarios above run it in child processes, with a different
/// environment. In a normal test run it returns at once.
#[test]
fn child_scenario() {
    let Ok(scenario) = std::env::var("KC_TEST_CHILD") else {
        return;
    };
    let namespace = std::env::var("KC_TEST_CHILD_NS").unwrap();
    assert!(namespace.starts_with(TEST_PREFIX));
    let dir = PathBuf::from(std::env::var("KC_TEST_CHILD_DIR").unwrap());
    let mut config = StoreConfig::new(&namespace, &dir);
    // Stress children may force a tiny timeout so their keychain calls are abandoned, to
    // exercise the drain that keeps an abandoned request from being left in flight on exit.
    if let Some(ms) = std::env::var("KC_TEST_CHILD_TIMEOUT_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        config = config.with_timeout(Duration::from_millis(ms));
    }
    let store = Store::open(config).unwrap();
    let start = Instant::now();
    match scenario.as_str() {
        // Short-lived stress workers: do a little work, then exit at once without graceful
        // teardown, like a quick `kc` command. See `stress_short_lived_processes_...`.
        "stress-hot" => {
            // Reads only (shared lock, no in-doubt marker), so a kill mid-flight is safe to
            // repeat. After the fix these make no Secret Service property reads.
            let _ = store.get("seed0");
            let _ = store.exists("seed1");
            let _ = store.get(&format!("missing-{}", std::process::id()));
            std::process::exit(0);
        }
        "stress-ops" => {
            // The full set/get/list/delete/adopt range, not killed, so require success: this
            // proves the workers actually exercise the keychain (including the `Item.Attributes`
            // property-read paths in `list` and `adopt`) rather than silently connect-failing,
            // and that it keeps working under churn.
            let account = format!("ops-{}", std::process::id());
            store
                .set(&account, b"fake-ops", ItemKind::Text, Origin::Local)
                .expect("stress set");
            assert_eq!(
                get(&store, &account).as_deref(),
                Some(&b"fake-ops"[..]),
                "stress get"
            );
            store.list().expect("stress list");
            if let Ok(foreign) = std::env::var("KC_TEST_STRESS_FOREIGN") {
                store
                    .adopt(&foreign, Some("me"), &format!("adopted-{account}"))
                    .expect("stress adopt");
            }
            assert!(
                store.delete(&account).expect("stress delete"),
                "nothing deleted"
            );
            std::process::exit(0);
        }
        "roundtrip" => {
            store
                .set(
                    "child-item",
                    b"fake-child-value",
                    ItemKind::Text,
                    Origin::Local,
                )
                .unwrap();
            assert_eq!(
                get(&store, "child-item").as_deref(),
                Some(&b"fake-child-value"[..])
            );
        }
        "connected-then-locked" => {
            // Connect and write while the keyring is open (a chunked value too)...
            store
                .set(
                    "child-item",
                    b"fake-child-value",
                    ItemKind::Text,
                    Origin::Local,
                )
                .unwrap();
            store
                .set("child-big", &fake(5000, 7), ItemKind::File, Origin::Local)
                .unwrap();
            store
                .set("child-big", &fake(4000, 8), ItemKind::File, Origin::Local)
                .unwrap();
            store.set_internal("device-key", &fake(32, 9)).unwrap();
            // ...then the keyring gets locked under the already connected store.
            let status = Command::new("gdbus")
                .args([
                    "call",
                    "--session",
                    "--dest",
                    "org.freedesktop.secrets",
                    "--object-path",
                    "/org/freedesktop/secrets",
                    "--method",
                    "org.freedesktop.Secret.Service.Lock",
                    "[objectpath '/org/freedesktop/secrets/collection/login']",
                ])
                .stdout(std::process::Stdio::null())
                .status()
                .unwrap();
            assert!(status.success(), "gdbus Lock failed");
            assert_every_operation_is_locked(&store);
        }
        "expect-locked" => assert_every_operation_is_locked(&store),
        "expect-unavailable" => {
            let err = store.get("child-item").unwrap_err();
            assert!(matches!(err, StoreError::Unavailable { .. }), "{err}");
            assert_eq!(err.exit_code(), 4);
            println!("unavailable: {err}");
        }
        other => panic!("unknown child scenario {other}"),
    }
    // A prompt or a hang would cost at least the 5 s timeout per operation; this allows for
    // waiting on the user-wide lock while the parent's other tests run.
    assert!(
        start.elapsed() < Duration::from_secs(15),
        "{scenario} took {:?}",
        start.elapsed()
    );
    println!("child-ok-{scenario}");
}

#[cfg(target_os = "linux")]
#[test]
fn works_without_dbus_session_bus_address() {
    let Some(ns) = TestNs::new("no-dbus-env") else {
        return;
    };
    let runtime = std::env::var_os("XDG_RUNTIME_DIR").map(PathBuf::from);
    if !runtime.is_some_and(|dir| dir.join("bus").exists()) {
        eprintln!("skipping no-dbus-env: $XDG_RUNTIME_DIR/bus doesn't exist here");
        return;
    }
    let mut command = child("roundtrip", &ns.namespace, ns.dir.path());
    command.env_remove("DBUS_SESSION_BUS_ADDRESS");
    let (ok, output) = run(command);
    assert!(ok && output.contains("child-ok-roundtrip"), "{output}");
    // The parent, with the normal environment, sees what the child wrote.
    assert_eq!(
        get(&ns.store(), "child-item").as_deref(),
        Some(&b"fake-child-value"[..])
    );
}

#[cfg(target_os = "linux")]
#[test]
fn no_session_bus_is_unavailable_at_once() {
    // Self-isolating (its own empty/dead bus, never the real keyring); run it once, in the outer
    // run, not again inside the isolated suite.
    if disabled() || in_isolated_suite() {
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    let namespace = format!("{TEST_PREFIX}{}", random_suffix());

    let mut command = child("expect-unavailable", &namespace, dir.path());
    command
        .env_remove("DBUS_SESSION_BUS_ADDRESS")
        .env("XDG_RUNTIME_DIR", dir.path().join("no-such-runtime-dir"));
    let (ok, output) = run(command);
    assert!(
        ok && output.contains("child-ok-expect-unavailable"),
        "{output}"
    );
    assert!(output.contains("loginctl enable-linger"), "{output}");

    let mut command = child("expect-unavailable", &namespace, dir.path());
    command.env(
        "DBUS_SESSION_BUS_ADDRESS",
        format!("unix:path={}", dir.path().join("dead-bus").display()),
    );
    let (ok, output) = run(command);
    assert!(
        ok && output.contains("child-ok-expect-unavailable"),
        "{output}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn a_bus_without_a_secret_service_is_unavailable() {
    // Self-isolating (its own service-less bus); run it once, in the outer run.
    if disabled() || in_isolated_suite() {
        return;
    }
    if !have("dbus-run-session") {
        eprintln!("skipping no-secret-service: dbus-run-session is not installed");
        return;
    }
    let dir = tempfile::tempdir().unwrap();
    // A session bus with no service directories, so nothing can be activated.
    let config = dir.path().join("bus.conf");
    std::fs::write(
        &config,
        r#"<!DOCTYPE busconfig PUBLIC "-//freedesktop//DTD D-Bus Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <type>session</type>
  <listen>unix:tmpdir=/tmp</listen>
  <auth>EXTERNAL</auth>
  <policy context="default">
    <allow send_destination="*" eavesdrop="true"/>
    <allow eavesdrop="true"/>
    <allow own="*"/>
  </policy>
</busconfig>
"#,
    )
    .unwrap();
    let namespace = format!("{TEST_PREFIX}{}", random_suffix());
    let inner = child("expect-unavailable", &namespace, dir.path());
    let mut command = Command::new("timeout");
    command
        .arg("60")
        .arg("dbus-run-session")
        .arg(format!("--config-file={}", config.display()))
        .arg("--")
        .arg(inner.get_program())
        .args(inner.get_args())
        .envs(
            inner
                .get_envs()
                .filter_map(|(key, value)| value.map(|value| (key, value))),
        );
    let (ok, output) = run(command);
    assert!(
        ok && output.contains("child-ok-expect-unavailable"),
        "{output}"
    );
    assert!(output.contains("no Secret Service"), "{output}");
}

/// A locked keyring must give `Locked`, never an `Unlock` call or a prompt: both for a store
/// that connects to an already locked keyring and for one that was connected (and wrote
/// values) before the keyring got locked under it. This runs a throwaway gnome-keyring on a
/// private session bus, so the real keyring is never touched or locked, and records the bus
/// traffic.
#[cfg(target_os = "linux")]
#[test]
fn a_locked_keyring_is_reported_without_unlocking_or_prompting() {
    // Self-isolating (its own throwaway gnome-keyring on a private bus); run it once, in the
    // outer run.
    if disabled() || in_isolated_suite() {
        return;
    }
    let tools = [
        "dbus-run-session",
        "gnome-keyring-daemon",
        "gdbus",
        "dbus-monitor",
        "pkill",
    ];
    if let Some(missing) = tools.iter().find(|tool| !have(tool)) {
        eprintln!("skipping locked-keyring: {missing} is not installed");
        return;
    }
    let root = tempfile::tempdir().unwrap();
    for sub in ["home", "data", "config", "run", "ctl", "kc"] {
        std::fs::create_dir(root.path().join(sub)).unwrap();
    }
    #[cfg(unix)]
    for sub in ["run", "ctl"] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            root.path().join(sub),
            std::fs::Permissions::from_mode(0o700),
        )
        .unwrap();
    }
    let namespace = format!("{TEST_PREFIX}{}", random_suffix());
    let script = r#"
set -u
cleanup() { kill "$MON" 2>/dev/null; pkill -f "control-directory=$ROOT/ctl"; }
printf 'fake-test-password' \
  | gnome-keyring-daemon --unlock --components=secrets --control-directory="$ROOT/ctl" >/dev/null \
  || exit 90
dbus-monitor --session "type=method_call,interface=org.freedesktop.Secret.Service" \
  "type=method_call,interface=org.freedesktop.Secret.Prompt" >"$ROOT/monitor.log" 2>/dev/null &
MON=$!
trap cleanup EXIT
sleep 0.5
KC_TEST_CHILD=connected-then-locked "$EXE" --exact child_scenario --nocapture --test-threads=1 \
  || exit 91
KC_TEST_CHILD=expect-locked "$EXE" --exact child_scenario --nocapture --test-threads=1
STATUS=$?
sleep 0.5
exit $STATUS
"#;
    let mut command = Command::new("timeout");
    command
        .args(["120", "dbus-run-session", "--", "bash", "-c", script])
        .env("ROOT", root.path())
        .env("EXE", std::env::current_exe().unwrap())
        .env("HOME", root.path().join("home"))
        .env("XDG_DATA_HOME", root.path().join("data"))
        .env("XDG_CONFIG_HOME", root.path().join("config"))
        .env("XDG_RUNTIME_DIR", root.path().join("run"))
        .env("KC_TEST_CHILD_NS", &namespace)
        .env("KC_TEST_CHILD_DIR", root.path().join("kc"))
        // No display: even if something asked for a prompt, nothing could appear on screen.
        .env_remove("DISPLAY")
        .env_remove("WAYLAND_DISPLAY");
    let (ok, output) = run(command);
    assert!(ok, "{output}");
    assert!(
        output.contains("child-ok-connected-then-locked"),
        "{output}"
    );
    assert!(output.contains("child-ok-expect-locked"), "{output}");

    let log = std::fs::read_to_string(root.path().join("monitor.log")).unwrap();
    // The monitor did see the traffic (our own Lock call and kc's searches)...
    assert!(log.contains("member=Lock"), "monitor saw nothing:\n{log}");
    assert!(log.contains("member=SearchItems"), "{log}");
    // ...and kc never tried to unlock anything or show a prompt.
    assert!(!log.contains("member=Unlock"), "kc called Unlock:\n{log}");
    assert!(
        !log.contains("member=Prompt"),
        "kc started a prompt:\n{log}"
    );
}

/// Owns a wave of stress children and reaps any still around when it is dropped, so an early
/// unwind (spawn failure or a failed assertion) never leaks them as zombies into later tests.
/// The normal path drains it first, so drop is then a no-op; only not-yet-reaped children (whose
/// pids can't have been recycled) are killed and waited here.
#[cfg(target_os = "linux")]
struct Wave(Vec<(std::process::Child, bool, usize)>);

#[cfg(target_os = "linux")]
impl Wave {
    fn new() -> Self {
        Wave(Vec::new())
    }
}

#[cfg(target_os = "linux")]
impl Drop for Wave {
    fn drop(&mut self) {
        for (kid, _, _) in &mut self.0 {
            let _ = kid.kill();
            let _ = kid.wait();
        }
    }
}

/// True if process `pid` (a decimal string) is still running.
#[cfg(target_os = "linux")]
fn keyring_alive(pid: &str) -> bool {
    Command::new("kill")
        .args(["-0", pid])
        .status()
        .map(|status| status.success())
        .unwrap_or(false)
}

/// Runs the whole real-store suite against a throwaway gnome-keyring so it never touches the
/// user's login keyring, and fails if that keyring daemon crashes.
///
/// A stock `cargo test` reaches this wrapper. It starts a private `dbus-run-session` with its
/// own gnome-keyring (own `HOME`/`XDG_*`, control directory and [`kc_store::ENV_LOCK_DIR`]), then
/// re-runs this very test binary inside it with `KC_TEST_ISOLATED=1`; that inner run is where the
/// real-store tests actually exercise the keychain (see [`TestNs::new`]). Afterwards the keyring
/// daemon must still be alive: a kc change that leaves a Secret Service request in flight can
/// crash gnome-keyring 50, and this turns that into a test failure instead of a wrecked login
/// session. Set `KC_TEST_USER_KEYRING=1` to skip the wrapper and use your own keyring directly.
#[cfg(target_os = "linux")]
#[test]
fn isolated_real_store_suite() {
    if disabled() || in_isolated_suite() || user_keyring_opt_in() {
        return;
    }
    // secret-tool is in the list because the inner run sets KC_TEST_REAL_STORE=1, under which the
    // external-program checks treat a missing secret-tool as a hard failure rather than a skip.
    let tools = [
        "dbus-run-session",
        "gnome-keyring-daemon",
        "secret-tool",
        "pgrep",
        "pkill",
    ];
    if let Some(missing) = tools.iter().find(|tool| !have(tool)) {
        if required() {
            panic!("KC_TEST_REAL_STORE=1 but {missing} is not installed");
        }
        eprintln!("skipping isolated real-store suite: {missing} is not installed");
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
    // Refuse the real bus; publish the private one; make $XDG_RUNTIME_DIR/bus point at it so the
    // "no DBUS_SESSION_BUS_ADDRESS" fallback test reaches the throwaway keyring too. Then run a
    // throwaway gnome-keyring, re-run this test binary against it, and require it to survive.
    let script = r#"
set -u
case "$DBUS_SESSION_BUS_ADDRESS" in
  *"/run/user/"*|"") echo "refusing: not a private bus: $DBUS_SESSION_BUS_ADDRESS" >&2; exit 90;;
esac
export KC_TEST_PRIVATE_BUS="$DBUS_SESSION_BUS_ADDRESS"
SOCK=$(printf '%s' "$DBUS_SESSION_BUS_ADDRESS" | sed -n 's/.*unix:path=\([^,;]*\).*/\1/p')
[ -n "$SOCK" ] && ln -sf "$SOCK" "$XDG_RUNTIME_DIR/bus"
printf 'fake-test-password' \
  | gnome-keyring-daemon --unlock --components=pkcs11,secrets --control-directory="$ROOT/ctl" >/dev/null \
  || exit 91
sleep 0.3
GK=$(pgrep -f "control-directory=$ROOT/ctl" | head -1)
[ -n "$GK" ] || { echo "no private keyring daemon" >&2; exit 92; }
echo "isolated suite: private bus $DBUS_SESSION_BUS_ADDRESS, keyring daemon pid $GK"
KC_TEST_KEYRING_PID="$GK" "$EXE" --nocapture --test-threads=4 --skip isolated_real_store_suite
STATUS=$?
if ! kill -0 "$GK" 2>/dev/null; then
  echo "THE KEYRING DAEMON DIED during the isolated real-store suite" >&2
  STATUS=97
fi
pkill -f "control-directory=$ROOT/ctl" 2>/dev/null
exit $STATUS
"#;
    let mut command = Command::new("timeout");
    command
        .args(["900", "dbus-run-session", "--", "bash", "-c", script])
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
        .env_remove("SSH_AUTH_SOCK");
    let (ok, output) = run(command);
    assert!(ok, "isolated real-store suite failed:\n{output}");
}

/// Hammers the throwaway keyring with hundreds of short-lived kc processes, some killed or timed
/// out mid-operation, and fails if the keyring daemon dies. This is the regression guard for the
/// gnome-keyring crash: a kc process that leaks a Secret Service `Properties.Get`/`GetAll` on
/// exit crashes the daemon, so churning fast-exiting processes must leave it standing.
///
/// Runs only inside [`isolated_real_store_suite`], where kc owns the keyring daemon and knows its
/// pid; it must never pound the user's real keyring.
#[cfg(target_os = "linux")]
#[test]
fn stress_short_lived_processes_keep_the_keyring_daemon_alive() {
    let Ok(daemon_pid) = std::env::var("KC_TEST_KEYRING_PID") else {
        eprintln!("skipping stress: only runs inside the isolated real-store suite");
        return;
    };
    let Some(ns) = TestNs::new("stress") else {
        return;
    };
    assert!(
        keyring_alive(&daemon_pid),
        "the private keyring daemon isn't running at the start"
    );
    // Seed a couple of items so reads and `list` have something to work on.
    let store = ns.store();
    for i in 0..3 {
        store
            .set(
                &format!("seed{i}"),
                &fake(64, i),
                ItemKind::Text,
                Origin::Local,
            )
            .unwrap();
    }
    drop(store);
    // A foreign item (written like another program) for the `stress-ops` workers to adopt, which
    // exercises the other `Item.Attributes` read path (`read_foreign`). Cleaned up at the end.
    let foreign = format!("kc-test-stress-foreign-{}", random_suffix());
    let foreign_seeded = have("secret-tool") && {
        secret_tool_store(&["service", &foreign, "account", "me"], b"fake-foreign");
        true
    };

    let waves = 20;
    let hot_per_wave = 24;
    let ops_per_wave = 4;
    let mut spawned = 0usize;
    for wave in 0..waves {
        // A guard so that an early unwind (a spawn failure, or the status assertion below) still
        // reaps every child of this wave instead of leaking zombies into later tests.
        let mut kids = Wave::new();
        for i in 0..hot_per_wave {
            let mut command = child("stress-hot", &ns.namespace, ns.dir.path());
            // One in four forces a tiny timeout, so its calls are abandoned and the backend has
            // to drain them before the process exits.
            if i % 4 == 0 {
                command.env("KC_TEST_CHILD_TIMEOUT_MS", "1");
            }
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // Kill about a third of them mid-flight. The hot path makes no property reads, so an
            // abrupt exit can't orphan one.
            let kill = i % 3 == 0;
            kids.0.push((command.spawn().unwrap(), kill, i));
            spawned += 1;
        }
        for _ in 0..ops_per_wave {
            let mut command = child("stress-ops", &ns.namespace, ns.dir.path());
            if foreign_seeded {
                command.env("KC_TEST_STRESS_FOREIGN", &foreign);
            }
            command
                .stdout(std::process::Stdio::null())
                .stderr(std::process::Stdio::null());
            // Not killed: a kill inside the attribute-read window is a gnome-keyring bug kc can't
            // prevent, so the guard doesn't depend on hitting it; these instead require their
            // operations to succeed.
            kids.0.push((command.spawn().unwrap(), false, 0));
            spawned += 1;
        }
        // Signal the marked workers promptly, while they are still mid-operation, before reaping
        // any of them: reaping first would let a slow sibling delay the signal until its target
        // had already exited, so the kill would land on nothing.
        for (kid, kill, i) in &kids.0 {
            if *kill {
                std::thread::sleep(Duration::from_millis(1 + (*i as u64 % 8)));
                let signal = if i % 2 == 0 { "-KILL" } else { "-INT" };
                let _ = Command::new("kill")
                    .args([signal, &kid.id().to_string()])
                    .status();
            }
        }
        // Reap the whole wave first (draining the guard), then judge: never leave children
        // unreaped behind a failed assertion.
        let mut failure = None;
        for (mut kid, kill, _) in kids.0.drain(..) {
            let status = kid.wait();
            // A worker that wasn't signalled must exit cleanly (it calls `process::exit(0)` after
            // its work): a non-zero exit there means a real failure, such as a panicking
            // `Store::open`, not the expected churn. Signalled workers exit via the signal.
            if !kill && !status.as_ref().map(|s| s.success()).unwrap_or(false) {
                failure.get_or_insert_with(|| format!("{status:?}"));
            }
        }
        assert!(
            failure.is_none(),
            "a stress worker that wasn't signalled failed: {failure:?}"
        );
        assert!(
            keyring_alive(&daemon_pid),
            "the keyring daemon died after wave {wave} (~{spawned} short-lived processes)"
        );
    }

    // It still works afterwards.
    let store = ns.store();
    store
        .set("after", b"fake-after", ItemKind::Text, Origin::Local)
        .unwrap();
    assert_eq!(get(&store, "after").as_deref(), Some(&b"fake-after"[..]));
    assert!(
        keyring_alive(&daemon_pid),
        "the keyring daemon died by the end of the stress run"
    );
    if foreign_seeded {
        let _ = Command::new("secret-tool")
            .args(["clear", "service", &foreign])
            .status();
    }
    eprintln!("stress: {spawned} short-lived processes, keyring daemon still alive");
}

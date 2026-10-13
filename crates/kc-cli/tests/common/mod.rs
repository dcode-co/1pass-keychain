//! In-process devices for kc-cli tests: each [`Device`] has its own config directory and
//! in-memory keychain, and they share a relay (in memory, or a real `kc-relay` over HTTP).
//! A [`TestConsole`] scripts the prompts and panics on any prompt it wasn't told about, so
//! a test also proves that non-interactive runs never prompt.
//!
//! Test values are fake and are compared, never printed.

#![allow(dead_code)]

use std::collections::VecDeque;
use std::ffi::OsString;
use std::io::{self, Read, Write};
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use kc_cli::{CliError, Console, Host, HttpRelay, LocalAuthOutcome, PromptError, RelayUrl};
use kc_proto::memory_relay::MemoryRelay;
use kc_proto::relay::{RelayApi, RelayError};
use kc_proto::session::SessionOptions;
use kc_store::testing::MemoryBackend;
use kc_store::{Store, StoreConfig};
use kc_wire::Limits;
use tempfile::TempDir;
use tokio::sync::oneshot;
use zeroize::Zeroizing;

pub const NAMESPACE: &str = "dev.1pass.kc.test-cli";

/// A scripted answer to the next prompt.
#[derive(Debug, Clone)]
pub enum Answer {
    Yes,
    No,
    Select(usize),
    Multi(Vec<usize>),
    Text(String),
    Secret(String),
    /// Ctrl-C at the prompt.
    Interrupt,
}

pub struct TestConsole {
    stdin: io::Cursor<Vec<u8>>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
    answers: VecDeque<Answer>,
    pub prompts: Vec<String>,
    code_tx: Option<oneshot::Sender<String>>,
}

impl TestConsole {
    fn next(&mut self, kind: &str, message: &str) -> Answer {
        self.prompts.push(message.to_owned());
        self.answers
            .pop_front()
            .unwrap_or_else(|| panic!("unscripted {kind} prompt: {message:?}"))
    }
}

impl Console for TestConsole {
    fn stdout(&mut self) -> &mut dyn Write {
        &mut self.stdout
    }

    fn stderr(&mut self) -> &mut dyn Write {
        &mut self.stderr
    }

    fn stdin(&mut self) -> &mut dyn Read {
        &mut self.stdin
    }

    fn confirm(&mut self, message: &str, _default: bool) -> Result<bool, PromptError> {
        match self.next("confirm", message) {
            Answer::Yes => Ok(true),
            Answer::No => Ok(false),
            Answer::Interrupt => Err(PromptError::Interrupted),
            other => panic!("confirm {message:?} got {other:?}"),
        }
    }

    fn select(
        &mut self,
        message: &str,
        options: &[String],
        _default: usize,
    ) -> Result<usize, PromptError> {
        match self.next("select", message) {
            Answer::Select(i) if i < options.len() => Ok(i),
            other => panic!("select {message:?} got {other:?}"),
        }
    }

    fn multi_select(
        &mut self,
        message: &str,
        options: &[String],
    ) -> Result<Vec<usize>, PromptError> {
        match self.next("multi-select", message) {
            Answer::Multi(chosen) if chosen.iter().all(|i| *i < options.len()) => Ok(chosen),
            other => panic!("multi-select {message:?} got {other:?}"),
        }
    }

    fn secret(&mut self, message: &str) -> Result<Zeroizing<String>, PromptError> {
        match self.next("secret", message) {
            Answer::Secret(s) => Ok(Zeroizing::new(s)),
            other => panic!("secret {message:?} got {other:?}"),
        }
    }

    fn text(&mut self, message: &str) -> Result<Zeroizing<String>, PromptError> {
        match self.next("text", message) {
            Answer::Text(s) => Ok(Zeroizing::new(s)),
            other => panic!("text {message:?} got {other:?}"),
        }
    }

    fn code_shown(&mut self, code: &str) {
        if let Some(tx) = self.code_tx.take() {
            let _ = tx.send(code.to_owned());
        }
    }
}

/// How a device reaches the relay.
pub trait Net {
    type Relay: RelayApi;
    fn connect(&self, url: &RelayUrl) -> Result<Self::Relay, CliError>;
    fn limits(&self, url: &RelayUrl) -> impl Future<Output = Result<Limits, RelayError>>;
}

impl Net for MemoryRelay {
    type Relay = MemoryRelay;

    fn connect(&self, _url: &RelayUrl) -> Result<MemoryRelay, CliError> {
        Ok(self.clone())
    }

    async fn limits(&self, _url: &RelayUrl) -> Result<Limits, RelayError> {
        Ok(Limits::current())
    }
}

/// The real HTTP client, against whatever `KC_RELAY` points at.
pub struct Http;

impl Net for Http {
    type Relay = HttpRelay;

    fn connect(&self, url: &RelayUrl) -> Result<HttpRelay, CliError> {
        HttpRelay::new(url)
    }

    async fn limits(&self, url: &RelayUrl) -> Result<Limits, RelayError> {
        HttpRelay::new(url)
            .map_err(|e| RelayError::Transport(e.message))?
            .limits()
            .await
    }
}

/// Where a device keeps its items.
pub enum Keychain {
    Memory(MemoryBackend),
    /// The real OS keychain, under a test namespace (honoured by debug builds).
    Os {
        namespace: String,
    },
}

pub struct Device<N: Net> {
    pub name: String,
    pub dir: TempDir,
    pub keychain: Keychain,
    pub net: N,
    /// Extra environment for every run (e.g. `KC_RELAY`).
    pub env: Vec<(String, String)>,
}

/// How to run one command.
pub struct Run {
    pub stdin: Vec<u8>,
    /// stdin and stderr are terminals.
    pub terminal: bool,
    pub stdout_terminal: bool,
    pub answers: Vec<Answer>,
    pub local_auth: VecDeque<LocalAuthOutcome>,
    pub env: Vec<(String, String)>,
    pub code_tx: Option<oneshot::Sender<String>>,
}

impl Run {
    /// An agent: piped stdin and `CLAUDECODE=1`.
    pub fn agent() -> Run {
        Run {
            stdin: Vec::new(),
            terminal: false,
            stdout_terminal: false,
            answers: Vec::new(),
            local_auth: VecDeque::new(),
            env: vec![("CLAUDECODE".into(), "1".into())],
            code_tx: None,
        }
    }

    /// A person at a terminal (stdout piped unless set).
    pub fn human(answers: Vec<Answer>) -> Run {
        Run {
            stdin: Vec::new(),
            terminal: true,
            stdout_terminal: false,
            answers,
            local_auth: VecDeque::new(),
            env: Vec::new(),
            code_tx: None,
        }
    }

    pub fn stdin(mut self, bytes: impl Into<Vec<u8>>) -> Run {
        self.stdin = bytes.into();
        self
    }

    pub fn stdout_terminal(mut self) -> Run {
        self.stdout_terminal = true;
        self
    }

    pub fn code_to(mut self, tx: oneshot::Sender<String>) -> Run {
        self.code_tx = Some(tx);
        self
    }
}

#[derive(Debug)]
pub struct Output {
    pub code: i32,
    pub stdout: Vec<u8>,
    pub stderr: String,
    pub prompts: Vec<String>,
}

impl Output {
    pub fn stdout_text(&self) -> String {
        String::from_utf8_lossy(&self.stdout).into_owned()
    }

    /// The words after "show the same words:".
    pub fn sas(&self) -> Option<String> {
        self.stderr
            .lines()
            .find_map(|l| l.split_once("the same words:"))
            .map(|(_, words)| words.trim().to_owned())
    }

    /// Asserts the exit code, showing stderr (never values) on failure.
    #[track_caller]
    pub fn expect(&self, code: i32) -> &Output {
        assert_eq!(self.code, code, "exit code; stderr:\n{}", self.stderr);
        self
    }
}

struct TestHost<'d, N: Net> {
    device: &'d Device<N>,
    console: TestConsole,
    terminal: bool,
    stdout_terminal: bool,
    env: Vec<(String, String)>,
    local_auth: VecDeque<LocalAuthOutcome>,
}

impl<N: Net> Host for TestHost<'_, N> {
    type Relay = N::Relay;
    type Console = TestConsole;

    fn console(&mut self) -> &mut TestConsole {
        &mut self.console
    }

    fn local_confirm(&mut self, _reason: &str) -> LocalAuthOutcome {
        self.local_auth.pop_front().unwrap_or_else(|| {
            LocalAuthOutcome::Unavailable("no scripted local confirmation".into())
        })
    }

    fn env_var(&self, key: &str) -> Option<OsString> {
        self.env
            .iter()
            .rev()
            .find(|(k, _)| k == key)
            .map(|(_, v)| OsString::from(v))
    }

    fn stdin_is_terminal(&self) -> bool {
        self.terminal
    }

    fn stdout_is_terminal(&self) -> bool {
        self.stdout_terminal
    }

    fn stderr_is_terminal(&self) -> bool {
        self.terminal
    }

    fn config_dir(&self) -> Result<PathBuf, CliError> {
        Ok(self.device.dir.path().to_path_buf())
    }

    fn open_store(&self, interactive: bool) -> Result<Store, CliError> {
        Ok(self.device.store_with(interactive)?)
    }

    fn connect(&self, url: &RelayUrl) -> Result<N::Relay, CliError> {
        self.device.net.connect(url)
    }

    async fn relay_limits(&self, url: &RelayUrl) -> Result<Limits, RelayError> {
        self.device.net.limits(url).await
    }

    fn hostname(&self) -> String {
        self.device.name.clone()
    }

    fn run_command(&mut self, command: Command) -> Result<i32, CliError> {
        kc_cli::spawn_and_wait(command)
    }

    fn session_options(&self) -> SessionOptions {
        SessionOptions {
            timeout: Duration::from_secs(60),
            ack_linger: Duration::from_secs(5),
            mismatch_linger: Duration::from_millis(500),
            poll_interval: Duration::from_millis(20),
        }
    }
}

impl<N: Net> Device<N> {
    pub fn new(name: &str, net: N) -> Device<N> {
        Device {
            name: name.to_owned(),
            dir: tempfile::tempdir().unwrap(),
            keychain: Keychain::Memory(MemoryBackend::new()),
            net,
            env: Vec::new(),
        }
    }

    /// A device on the real OS keychain, in `namespace`.
    pub fn on_os_keychain(name: &str, net: N, namespace: &str) -> Device<N> {
        Device {
            keychain: Keychain::Os {
                namespace: namespace.to_owned(),
            },
            ..Device::new(name, net)
        }
    }

    /// The in-memory keychain (for injecting failures).
    pub fn memory(&self) -> &MemoryBackend {
        match &self.keychain {
            Keychain::Memory(mem) => mem,
            Keychain::Os { .. } => panic!("not an in-memory device"),
        }
    }

    /// This device's store, as the commands see it.
    pub fn store(&self) -> Store {
        self.store_with(false).unwrap()
    }

    fn store_with(&self, interactive: bool) -> kc_store::Result<Store> {
        match &self.keychain {
            Keychain::Memory(mem) => {
                let cfg =
                    StoreConfig::new(NAMESPACE, self.dir.path()).with_interactive(interactive);
                Store::open_with_memory_backend(cfg, mem)
            }
            Keychain::Os { namespace } => Store::open(
                StoreConfig::new(namespace.as_str(), self.dir.path()).with_interactive(interactive),
            ),
        }
    }

    pub async fn run(&self, args: &[&str], run: Run) -> Output {
        let mut env = self.env.clone();
        env.extend(run.env);
        let mut host = TestHost {
            device: self,
            console: TestConsole {
                stdin: io::Cursor::new(run.stdin),
                stdout: Vec::new(),
                stderr: Vec::new(),
                answers: run.answers.into(),
                prompts: Vec::new(),
                code_tx: run.code_tx,
            },
            terminal: run.terminal,
            stdout_terminal: run.stdout_terminal,
            env,
            local_auth: run.local_auth,
        };
        let argv = std::iter::once("kc")
            .chain(args.iter().copied())
            .map(OsString::from);
        let code = kc_cli::run(&mut host, argv).await;
        let console = host.console;
        assert!(
            console.answers.is_empty(),
            "unused scripted answers {:?} for {args:?}; stderr:\n{}",
            console.answers,
            String::from_utf8_lossy(&console.stderr)
        );
        Output {
            code,
            stdout: console.stdout,
            stderr: String::from_utf8_lossy(&console.stderr).into_owned(),
            prompts: console.prompts,
        }
    }

    /// `kc set NAME` with `value` on stdin, as an agent.
    pub async fn set(&self, name: &str, value: &[u8]) {
        self.run(&["set", name, "--raw"], Run::agent().stdin(value))
            .await
            .expect(0);
    }

    /// The stored value (straight from the store, so nothing is printed).
    pub fn value(&self, name: &str) -> Option<Vec<u8>> {
        self.store()
            .get(name)
            .unwrap()
            .map(|v| v.as_bytes().to_vec())
    }

    /// This device's inbox id and owner token (from the keychain's `inbox-owner` slot).
    pub fn inbox_credentials(&self) -> (String, String) {
        let slot = self.store().get_internal("inbox-owner").unwrap().unwrap();
        let text = std::str::from_utf8(slot.as_bytes()).unwrap();
        let (id, owner) = text.split_once('.').unwrap();
        (id.to_owned(), owner.to_owned())
    }

    /// The bearer token this device holds for posting to the paired device `label`.
    pub fn writer_bearer(&self, label: &str) -> zeroize::Zeroizing<String> {
        let peers = self.peers();
        let peer = peers.find(label).unwrap();
        let raw = self
            .store()
            .get_internal(&peer.token_key())
            .unwrap()
            .unwrap();
        kc_proto::payload::WriterToken::from_bytes(raw.as_bytes().try_into().unwrap()).bearer()
    }

    pub fn write_config(&self, text: &str) {
        std::fs::write(self.dir.path().join("config.toml"), text).unwrap();
    }

    pub fn config(&self) -> kc_cli::Settings {
        kc_cli::Settings::load(self.dir.path()).unwrap()
    }

    pub fn peers(&self) -> kc_cli::state::Peers {
        kc_cli::state::StateDir::new(self.dir.path())
            .load_peers()
            .unwrap()
    }
}

/// Runs `receiver_args` on `rx` and, once it shows its code, `sender_args` on `tx`, with
/// the code supplied by `code_input` (stdin line or prompt answer).
pub async fn transfer<A: Net, B: Net>(
    rx: &Device<A>,
    receiver_args: &[&str],
    receiver_run: Run,
    tx: &Device<B>,
    sender_args: &[&str],
    sender_run: impl FnOnce(String) -> Run,
) -> (Output, Output) {
    let (code_tx, code_rx) = oneshot::channel();
    let receiving = rx.run(receiver_args, receiver_run.code_to(code_tx));
    let sending = async {
        let code = code_rx.await.expect("the receiver showed no code");
        tx.run(sender_args, sender_run(code)).await
    };
    tokio::join!(receiving, sending)
}

/// The same channel with a different first word.
pub fn wrong_code(code: &str) -> String {
    let parts: Vec<&str> = code.split('-').collect();
    let first = if parts[1] == "aardvark" {
        "absurd"
    } else {
        "aardvark"
    };
    let mut out = vec![parts[0], first];
    out.extend(&parts[2..]);
    out.join("-")
}

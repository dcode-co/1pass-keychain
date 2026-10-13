//! Who may do what without a human (PROTOCOL §6), enforced in one place.
//!
//! A run is **interactive** only if stdin and stderr are both terminals and none of `CI`,
//! `CLAUDECODE` or `--no-input` is set. Before a command touches the keychain or the
//! network, [`gates`] lists what it is about to do and [`Policy::check`] refuses (exit 5,
//! naming what's missing) anything a non-interactive run may not do:
//!
//! | Gate | Non-interactive |
//! |---|---|
//! | [`Gate::CodeSend`]: `send` with a one-time code | refused unless `agent_code_send = true` |
//! | [`Gate::Pair`], [`Gate::Remember`], [`Gate::All`] | refused |
//! | [`Gate::Overwrite`]: `--on-conflict overwrite` on `receive`/`inbox` | refused |
//! | [`Gate::Checklist`], [`Gate::CodePrompt`], [`Gate::ValuePrompt`]: a prompt would be needed | refused, naming the flag to pass |
//! | [`Gate::Rotate`]: `device rotate` ends every pairing | refused |
//!
//! Everything else (`get`, `exec`, `list`, `set` from stdin, `send --to … --names …`,
//! `inbox`, `receive`) is allowed; `inbox` and `receive` then skip conflicts. Commands
//! never prompt in a non-interactive run.

use crate::cli::{Command, ConflictPolicy, DeviceCommand};
use crate::error::CliError;
use crate::i18n::tr;

/// What decides interactivity.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Interactivity {
    pub stdin_terminal: bool,
    pub stderr_terminal: bool,
    /// `CI` is set (to anything).
    pub ci: bool,
    /// `CLAUDECODE` is set (to anything).
    pub claudecode: bool,
    /// `--no-input`.
    pub no_input: bool,
}

impl Interactivity {
    pub fn is_interactive(&self) -> bool {
        self.stdin_terminal
            && self.stderr_terminal
            && !self.ci
            && !self.claudecode
            && !self.no_input
    }

    /// Why the run isn't interactive.
    pub fn reasons(&self) -> Vec<String> {
        let mut reasons = Vec::new();
        if !self.stdin_terminal {
            reasons.push(tr!("stdin is not a terminal"));
        }
        if !self.stderr_terminal {
            reasons.push(tr!("stderr is not a terminal"));
        }
        if self.ci {
            reasons.push(tr!("CI is set"));
        }
        if self.claudecode {
            reasons.push(tr!("CLAUDECODE is set"));
        }
        if self.no_input {
            reasons.push(tr!("--no-input was given"));
        }
        reasons
    }
}

/// Something a command is about to do that may need a person.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Gate {
    /// `send` with a one-time code (not `--to`).
    CodeSend,
    /// The code would be asked for (no `--code -`).
    CodePrompt,
    /// `pair` or `pair --join`.
    Pair,
    /// `--remember` on `send` or `receive`.
    Remember,
    /// `send --all`.
    All,
    /// `--on-conflict overwrite` on `receive` or `inbox`.
    Overwrite,
    /// `send` without item names: the checklist would open.
    Checklist,
    /// `set` with stdin on a terminal: the hidden prompt would open.
    ValuePrompt,
    /// `device rotate`.
    Rotate,
}

impl Gate {
    /// What a non-interactive run needs instead.
    fn explain(self) -> String {
        match self {
            Gate::CodeSend => tr!(
                "sending with a one-time code needs a person at a terminal. Agents and scripts \
                 send to a paired device with `kc send --to LABEL --names A,B`; to allow code \
                 sends without a terminal, set `agent_code_send = true` in config.toml and \
                 pass the code with `--code -`"
            ),
            Gate::CodePrompt => tr!("pass `--code -` and pipe the code on stdin"),
            Gate::Pair => tr!("pairing needs a person at a terminal on both devices"),
            Gate::Remember => {
                tr!("`--remember` pairs the devices and needs a person at a terminal")
            }
            Gate::All => {
                tr!("`--all` needs a person at a terminal; name the items with `--names A,B`")
            }
            Gate::Overwrite => tr!(
                "`--on-conflict overwrite` needs a person at a terminal; use `skip` or `rename`"
            ),
            Gate::Checklist => tr!(
                "name the items to send: `kc send NAME…`, `--names A,B` or `--bundle FILE` \
                 (the checklist needs a terminal)"
            ),
            Gate::ValuePrompt => tr!(
                "pipe the value on stdin or pass `--from-file PATH` (the hidden prompt needs a \
                 terminal)"
            ),
            Gate::Rotate => {
                tr!("`kc device rotate` ends every pairing and needs a person at a terminal")
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Policy {
    pub interactivity: Interactivity,
    /// `agent_code_send` from config.toml.
    pub agent_code_send: bool,
}

impl Policy {
    pub fn new(interactivity: Interactivity, agent_code_send: bool) -> Policy {
        Policy {
            interactivity,
            agent_code_send,
        }
    }

    pub fn interactive(&self) -> bool {
        self.interactivity.is_interactive()
    }

    /// The gates a non-interactive run refuses.
    pub fn refused(&self, gates: &[Gate]) -> Vec<Gate> {
        if self.interactive() {
            return Vec::new();
        }
        gates
            .iter()
            .copied()
            .filter(|g| !(*g == Gate::CodeSend && self.agent_code_send))
            .collect()
    }

    /// `Ok` if the run may go ahead; otherwise exit 5 with what's missing.
    pub fn check(&self, gates: &[Gate]) -> Result<(), CliError> {
        let refused = self.refused(gates);
        if refused.is_empty() {
            return Ok(());
        }
        let mut message = tr!("this needs a person at a terminal:");
        for gate in &refused {
            message.push_str("\n  - ");
            message.push_str(&gate.explain());
        }
        let reasons = self.interactivity.reasons().join(", ");
        Err(CliError::interaction(message).with_hint(tr!(
            "kc runs non-interactively here ({reasons}) and never prompts then",
            reasons = reasons
        )))
    }
}

/// What `command` is about to do, as far as the policy is concerned. `stdin_terminal`
/// matters for `set`, which prompts only when nothing is piped in.
pub fn gates(command: &Command, stdin_terminal: bool) -> Vec<Gate> {
    let mut gates = Vec::new();
    match command {
        Command::Set(args) if args.from_file.is_none() && stdin_terminal => {
            gates.push(Gate::ValuePrompt);
        }
        Command::Send(args) => {
            if args.to.is_none() {
                gates.push(Gate::CodeSend);
                if args.code.is_none() {
                    gates.push(Gate::CodePrompt);
                }
            }
            if args.remember {
                gates.push(Gate::Remember);
            }
            // Blank names (`--names ' '`) are dropped later, so they don't count.
            let named = args
                .names
                .iter()
                .chain(&args.names_list)
                .any(|n| !n.trim().is_empty());
            if args.all {
                gates.push(Gate::All);
            } else if !named && args.bundle.is_none() {
                gates.push(Gate::Checklist);
            }
        }
        Command::Receive(args) => {
            if args.remember {
                gates.push(Gate::Remember);
            }
            if args.on_conflict == Some(ConflictPolicy::Overwrite) {
                gates.push(Gate::Overwrite);
            }
        }
        Command::Pair(_) => gates.push(Gate::Pair),
        Command::Inbox(args) => {
            if args.on_conflict == Some(ConflictPolicy::Overwrite) {
                gates.push(Gate::Overwrite);
            }
        }
        Command::Device(args) if matches!(args.command, Some(DeviceCommand::Rotate)) => {
            gates.push(Gate::Rotate);
        }
        _ => {}
    }
    gates
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    use super::*;
    use crate::cli::Cli;

    const TERMINAL: Interactivity = Interactivity {
        stdin_terminal: true,
        stderr_terminal: true,
        ci: false,
        claudecode: false,
        no_input: false,
    };

    fn agent() -> Interactivity {
        Interactivity {
            claudecode: true,
            ..TERMINAL
        }
    }

    fn gates_of(args: &str, stdin_terminal: bool) -> Vec<Gate> {
        let argv = std::iter::once("kc").chain(args.split_whitespace());
        gates(&Cli::try_parse_from(argv).unwrap().command, stdin_terminal)
    }

    /// Exit code of `args` under `policy` (0 = allowed).
    fn decide(policy: Policy, args: &str) -> i32 {
        match policy.check(&gates_of(args, false)) {
            Ok(()) => 0,
            Err(e) => e.code,
        }
    }

    #[test]
    fn interactivity_needs_two_terminals_and_no_markers() {
        assert!(TERMINAL.is_interactive());
        for not in [
            Interactivity {
                stdin_terminal: false,
                ..TERMINAL
            },
            Interactivity {
                stderr_terminal: false,
                ..TERMINAL
            },
            Interactivity {
                ci: true,
                ..TERMINAL
            },
            Interactivity {
                claudecode: true,
                ..TERMINAL
            },
            Interactivity {
                no_input: true,
                ..TERMINAL
            },
        ] {
            assert!(!not.is_interactive(), "{not:?}");
            assert_eq!(not.reasons().len(), 1, "{not:?}");
        }
    }

    #[test]
    fn non_interactive_matrix() {
        let agent = Policy::new(agent(), false);
        let allowed = [
            "get NAME",
            "get NAME --reveal",
            "exec --env A=NAME -- true",
            "list",
            "list --verify --json",
            "set NAME",
            "rm NAME",
            "restore NAME",
            "adopt --service s",
            "send --to mac --names A,B",
            "send --to mac A B",
            "send --to mac --bundle b.toml",
            "inbox",
            "inbox --on-conflict skip",
            "inbox --on-conflict rename",
            "receive",
            "receive --on-conflict rename",
            "peers",
            "peers rm mac",
            "device",
            "device rename x",
            "doctor",
        ];
        for args in allowed {
            assert_eq!(decide(agent, args), 0, "{args}");
        }
        let refused = [
            "send --to mac --names ,",
            "send A --code -",
            "send A",
            "send --names A",
            "send",
            "send --to mac",
            "send --to mac --all",
            "send --all --code -",
            "send A --remember --code -",
            "pair",
            "pair --join",
            "receive --remember",
            "receive --on-conflict overwrite",
            "inbox --on-conflict overwrite",
            "device rotate",
        ];
        for args in refused {
            assert_eq!(decide(agent, args), 5, "{args}");
        }
    }

    #[test]
    fn agent_code_send_only_unlocks_code_sends() {
        let allowed = Policy::new(agent(), true);
        assert_eq!(decide(allowed, "send A --code -"), 0);
        assert_eq!(decide(allowed, "send --names A,B --code -"), 0);
        // The code still can't be prompted for, and the rest stays refused.
        assert_eq!(decide(allowed, "send A"), 5);
        assert_eq!(decide(allowed, "send A --remember --code -"), 5);
        assert_eq!(decide(allowed, "send --all --code -"), 5);
        assert_eq!(decide(allowed, "pair"), 5);
        assert_eq!(decide(allowed, "receive --on-conflict overwrite"), 5);
    }

    #[test]
    fn everything_is_allowed_at_a_terminal() {
        let human = Policy::new(TERMINAL, false);
        for args in [
            "send A",
            "send",
            "send --all",
            "pair",
            "pair --join",
            "receive --remember --on-conflict overwrite",
            "inbox --on-conflict overwrite",
            "device rotate",
        ] {
            assert_eq!(decide(human, args), 0, "{args}");
        }
    }

    #[test]
    fn set_prompts_only_without_piped_input() {
        assert_eq!(gates_of("set NAME", true), vec![Gate::ValuePrompt]);
        assert!(gates_of("set NAME", false).is_empty());
        assert!(gates_of("set NAME --from-file f", true).is_empty());
    }

    #[test]
    fn refusal_names_what_is_missing() {
        let err = Policy::new(agent(), false)
            .check(&gates_of("send A", false))
            .unwrap_err();
        assert_eq!(err.code, kc_wire::exit::INTERACTION_REQUIRED);
        assert!(err.message.contains("agent_code_send"), "{}", err.message);
        assert!(err.message.contains("--code -"), "{}", err.message);
        assert!(err.hint.unwrap().contains("CLAUDECODE is set"));
    }
}

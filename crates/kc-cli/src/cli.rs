//! The command line (clap). Values and codes are never accepted as arguments: they would
//! end up in shell history and in `/proc/<pid>/cmdline`, which other users can read.

use std::ffi::OsString;
use std::path::PathBuf;

use clap::{Args, Parser, Subcommand, ValueEnum};

/// Move secrets between your own devices' OS keychains.
///
/// Values never pass through arguments or environment variables: `kc set` reads stdin, a
/// hidden prompt or a file, and codes are typed at a prompt or piped with `--code -`.
#[derive(Debug, Parser)]
#[command(name = "kc", version, about, max_term_width = 100)]
pub struct Cli {
    /// Relay URL [default: $KC_RELAY, then `relay` in config.toml, then
    /// https://relay.1pass.dev]
    #[arg(long, global = true, value_name = "URL")]
    pub relay: Option<String>,

    /// Allow a plain-http relay that isn't on this machine (for testing)
    #[arg(long, global = true)]
    pub allow_http: bool,

    /// Never prompt: behave as kc does for agents and scripts
    #[arg(long, global = true)]
    pub no_input: bool,

    #[command(subcommand)]
    pub command: Command,
}

#[derive(Debug, Subcommand)]
pub enum Command {
    /// Store a value read from stdin, a hidden prompt, or a file
    Set(SetArgs),
    /// Print a value (not to a terminal unless --reveal)
    Get(GetArgs),
    /// Run a command with values in its environment, without a shell
    Exec(ExecArgs),
    /// List items
    List(ListArgs),
    /// Delete an item and its previous value
    Rm(RmArgs),
    /// Swap an item with its previous value (undoes the last overwrite)
    Restore(NameArgs),
    /// Copy an existing OS keychain entry into kc
    Adopt(AdoptArgs),
    /// Send items with a one-time code, or to a paired device with --to
    Send(SendArgs),
    /// Show a one-time code and receive items
    Receive(ReceiveArgs),
    /// Pair with another device: shows a code (or enters one with --join)
    Pair(PairArgs),
    /// List or remove paired devices
    Peers(PeersArgs),
    /// Store items that paired devices sent to this one
    Inbox(InboxArgs),
    /// Show, rename or rotate this device's identity
    Device(DeviceArgs),
    /// Check the keychain, the relay and the configuration
    Doctor(DoctorArgs),
    /// Synchronize selected items with paired devices
    Sync(SyncArgs),
}

#[derive(Debug, Args)]
pub struct SetArgs {
    /// Item name: 1-128 characters of A-Z a-z 0-9 . _ / -
    pub name: String,

    /// Store the whole file, byte for byte
    #[arg(long, value_name = "PATH")]
    pub from_file: Option<PathBuf>,

    /// Keep the trailing newline of stdin input (one is stripped by default)
    #[arg(long)]
    pub raw: bool,

    /// Catches a value typed as an argument, so it can be refused without being echoed.
    #[arg(hide = true, trailing_var_arg = true, allow_hyphen_values = true)]
    pub extra: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct GetArgs {
    /// Item name
    pub name: String,

    /// Print the value even when stdout is a terminal
    #[arg(long)]
    pub reveal: bool,

    /// Write the value to PATH (mode 600) instead of stdout
    #[arg(long, value_name = "PATH", conflicts_with_all = ["reveal", "check", "fingerprint", "base64"])]
    pub to_file: Option<PathBuf>,

    /// Print nothing; exit 0 if the item exists, 3 if not
    #[arg(long, conflicts_with_all = ["reveal", "fingerprint", "base64"])]
    pub check: bool,

    /// Print a short hash of the value, to compare devices without revealing it
    #[arg(long, conflicts_with_all = ["reveal", "base64"])]
    pub fingerprint: bool,

    /// Print the value base64-encoded
    #[arg(long)]
    pub base64: bool,
}

#[derive(Debug, Args)]
pub struct ExecArgs {
    /// Set environment variable VAR to the value of item NAME (repeatable)
    #[arg(long = "env", value_name = "VAR=NAME", required = true)]
    pub env: Vec<String>,

    /// The command and its arguments, after `--`
    #[arg(last = true, required = true, value_name = "COMMAND")]
    pub command: Vec<OsString>,
}

#[derive(Debug, Args)]
pub struct ListArgs {
    /// Also compare the metadata index with the keychain
    #[arg(long)]
    pub verify: bool,

    /// Print JSON
    #[arg(long)]
    pub json: bool,
}

#[derive(Debug, Args)]
pub struct RmArgs {
    /// Item name
    pub name: String,

    /// Don't ask for confirmation
    #[arg(short = 'y', long)]
    pub yes: bool,
}

#[derive(Debug, Args)]
pub struct NameArgs {
    /// Item name
    pub name: String,
}

#[derive(Debug, Args)]
pub struct AdoptArgs {
    /// The entry's service (macOS: service, Linux: the `service` attribute, Windows: target)
    #[arg(long)]
    pub service: String,

    /// The entry's account, when several share the service
    #[arg(long)]
    pub account: Option<String>,

    /// The kc item name [default: the service]
    #[arg(long = "as", value_name = "NAME")]
    pub as_name: Option<String>,
}

#[derive(Debug, Args)]
pub struct SendArgs {
    /// Items to send. With no names, --names, --bundle or --all, a checklist opens
    pub names: Vec<String>,

    /// Comma-separated item names (the same as NAMES)
    #[arg(long = "names", value_name = "A,B", value_delimiter = ',')]
    pub names_list: Vec<String>,

    /// A TOML file that lists item names: items = ["A", "B"]
    #[arg(long, value_name = "FILE")]
    pub bundle: Option<PathBuf>,

    /// Send every item
    #[arg(long, conflicts_with_all = ["names", "names_list", "bundle"])]
    pub all: bool,

    /// Send to a paired device (no code needed)
    #[arg(long, value_name = "LABEL", conflicts_with_all = ["code", "remember"])]
    pub to: Option<String>,

    /// `--code -` reads the code from stdin. Codes are never taken from arguments
    #[arg(long, value_name = "-", allow_hyphen_values = true)]
    pub code: Option<String>,

    /// Also pair with the receiving device (it must run `kc receive --remember`)
    #[arg(long)]
    pub remember: bool,
}

/// What to do when an item already exists here with a different value.
#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum)]
pub enum ConflictPolicy {
    /// Keep this device's value
    Skip,
    /// Replace it; the old value stays available to `kc restore`
    Overwrite,
    /// Store the new value as NAME-2 (or the next free name)
    Rename,
}

#[derive(Debug, Args)]
pub struct ReceiveArgs {
    /// Also pair with the sending device (it must run `kc send --remember`)
    #[arg(long)]
    pub remember: bool,

    /// When an item exists with a different value [default: ask at a terminal, else skip]
    #[arg(long, value_enum, value_name = "POLICY")]
    pub on_conflict: Option<ConflictPolicy>,
}

#[derive(Debug, Args)]
pub struct PairArgs {
    /// Enter the code another device shows (`kc pair` there)
    #[arg(long)]
    pub join: bool,
}

#[derive(Debug, Args)]
pub struct PeersArgs {
    #[command(subcommand)]
    pub command: Option<PeersCommand>,
}

#[derive(Debug, Subcommand)]
pub enum PeersCommand {
    /// List paired devices (the default)
    List,
    /// Unpair a device: forget it and revoke its permission to post to this device
    Rm {
        /// The device's label here (see `kc peers`)
        label: String,
    },
}

#[derive(Debug, Args)]
pub struct InboxArgs {
    /// When an item exists with a different value [default: ask at a terminal, else skip]
    #[arg(long, value_enum, value_name = "POLICY")]
    pub on_conflict: Option<ConflictPolicy>,

    /// If nothing is waiting, wait up to SECONDS (at most 600) for a message to arrive
    #[arg(long, value_name = "SECONDS", value_parser = clap::value_parser!(u64).range(1..=600))]
    pub wait: Option<u64>,
}

#[derive(Debug, Args)]
pub struct DeviceArgs {
    #[command(subcommand)]
    pub command: Option<DeviceCommand>,
}

#[derive(Debug, Subcommand)]
pub enum DeviceCommand {
    /// Show this device's label, fingerprint and inbox (the default)
    Show,
    /// Change the label this device suggests when pairing
    Rename {
        /// 1-64 printable ASCII characters
        label: String,
    },
    /// New device key and inbox; every paired device must pair again
    Rotate,
}

#[derive(Debug, Args)]
pub struct DoctorArgs {
    /// Rebuild the metadata index from the keychain and remove leftover entries
    #[arg(long)]
    pub reindex: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse(args: &[&str]) -> Result<Cli, clap::Error> {
        Cli::try_parse_from(std::iter::once("kc").chain(args.iter().copied()))
    }

    #[test]
    fn the_definition_is_consistent() {
        use clap::CommandFactory as _;
        Cli::command().debug_assert();
    }

    #[test]
    fn set_catches_extra_arguments() {
        let Command::Set(set) = parse(&["set", "NAME", "not-a-real-value"]).unwrap().command else {
            panic!("not set")
        };
        assert_eq!(set.name, "NAME");
        assert_eq!(set.extra.len(), 1);
        let Command::Set(set) = parse(&["set", "NAME", "--raw"]).unwrap().command else {
            panic!("not set")
        };
        assert!(set.raw && set.extra.is_empty());
        let Command::Set(set) = parse(&["set", "NAME", "--", "--looks-like-a-flag"])
            .unwrap()
            .command
        else {
            panic!("not set")
        };
        assert_eq!(set.extra.len(), 1);
    }

    #[test]
    fn send_names_merge_and_conflicts() {
        let Command::Send(send) = parse(&["send", "A", "--names", "B,C", "--to", "mac"])
            .unwrap()
            .command
        else {
            panic!("not send")
        };
        assert_eq!(send.names, ["A"]);
        assert_eq!(send.names_list, ["B", "C"]);
        assert_eq!(send.to.as_deref(), Some("mac"));
        assert!(parse(&["send", "--to", "mac", "--code", "-"]).is_err());
        assert!(parse(&["send", "--to", "mac", "--remember"]).is_err());
        assert!(parse(&["send", "--all", "A"]).is_err());
        let Command::Send(send) = parse(&["send", "A", "--code", "-"]).unwrap().command else {
            panic!("not send")
        };
        assert_eq!(send.code.as_deref(), Some("-"));
    }

    #[test]
    fn get_flag_conflicts() {
        assert!(parse(&["get", "A", "--check", "--reveal"]).is_err());
        assert!(parse(&["get", "A", "--to-file", "x", "--base64"]).is_err());
        assert!(parse(&["get", "A", "--fingerprint", "--reveal"]).is_err());
        assert!(parse(&["get", "A", "--reveal", "--base64"]).is_ok());
    }

    #[test]
    fn exec_needs_env_and_command() {
        let Command::Exec(exec) = parse(&["exec", "--env", "A=x", "--", "env", "-0"])
            .unwrap()
            .command
        else {
            panic!("not exec")
        };
        assert_eq!(exec.env, ["A=x"]);
        assert_eq!(exec.command, ["env", "-0"]);
        assert!(parse(&["exec", "--", "env"]).is_err());
        assert!(parse(&["exec", "--env", "A=x"]).is_err());
    }

    #[test]
    fn conflict_policies_and_global_flags() {
        let cli = parse(&["inbox", "--on-conflict", "rename", "--no-input"]).unwrap();
        assert!(cli.no_input);
        let Command::Inbox(inbox) = cli.command else {
            panic!("not inbox")
        };
        assert_eq!(inbox.on_conflict, Some(ConflictPolicy::Rename));
        assert!(parse(&["receive", "--on-conflict", "clobber"]).is_err());
        let cli = parse(&["--relay", "http://127.0.0.1:1", "--allow-http", "doctor"]).unwrap();
        assert_eq!(cli.relay.as_deref(), Some("http://127.0.0.1:1"));
        assert!(cli.allow_http);
    }
}

#[derive(Debug, Args)]
pub struct SyncArgs {
    #[command(subcommand)]
    pub command: Option<SyncCommand>,
}

#[derive(Debug, Subcommand)]
pub enum SyncCommand {
    /// Show synchronization state without values
    Status {
        /// Print JSON
        #[arg(long)]
        json: bool,
        /// Confirm the current value as the recovery checkpoint
        #[arg(long, value_name = "NAME")]
        confirm_checkpoint: Option<String>,
    },
    /// Add items and offer them to paired devices
    Add {
        names: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,
    },
    /// Offer selected sync items again
    Offer {
        names: Vec<String>,
        #[arg(long, value_delimiter = ',')]
        peers: Vec<String>,
    },
    /// Remove items from this device's sync set, keeping their values
    Rm {
        #[arg(required = true)]
        names: Vec<String>,
    },
    /// Manage the paired devices used for sync
    Peer {
        #[command(subcommand)]
        command: SyncPeerCommand,
    },
    /// Review proposals and held changes
    Review,
    /// Resolve a conflict with a new version
    Resolve {
        name: String,
        #[arg(long)]
        keep: String,
    },
    /// Restore the recovery checkpoint
    RestoreCheckpoint { name: String },
    /// Hold all incoming sync changes
    Freeze,
    /// Resume sync after local confirmation
    Unfreeze,
}

#[derive(Debug, Subcommand)]
pub enum SyncPeerCommand {
    Add { label: String },
    Rm { label: String },
    List,
}

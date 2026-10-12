//! `kc doctor [--reindex]`: the keychain, the configuration and the relay, each checked on
//! its own so one failure doesn't hide the others. Exits with the code of the first failure.

use std::fmt::Display;

use crate::keychain::Keychain;
use kc_wire::{PROTO_VERSION, exit};

use super::pairing::{DEVICE_KEY, read_inbox};
use crate::cli::{Cli, DoctorArgs};
use crate::console::Console as _;
use crate::error::Result;
use crate::host::Host;
use crate::policy::Interactivity;
use crate::settings::{self, ENV_RELAY, Settings};
use crate::state::StateDir;

#[derive(Default)]
struct Report {
    text: String,
    code: Option<i32>,
}

impl Report {
    fn line(&mut self, what: &str, detail: impl Display) {
        self.text.push_str(&format!("{what:<18} {detail}\n"));
    }

    fn fail(&mut self, what: &str, detail: impl Display, code: i32) {
        self.line(what, format!("FAIL: {detail}"));
        self.code.get_or_insert(code);
    }

    fn warn(&mut self, what: &str, detail: impl Display) {
        self.line(what, format!("warning: {detail}"));
    }
}

pub(super) async fn doctor<H: Host>(
    host: &mut H,
    state: &StateDir,
    settings: Result<Settings>,
    interactivity: Interactivity,
    cli: &Cli,
    args: &DoctorArgs,
) -> Result<i32> {
    let mut r = Report::default();
    r.line("kc", env!("CARGO_PKG_VERSION"));
    r.line("config dir", state.root().display());

    let settings = match settings {
        Ok(settings) => {
            let unknown = Settings::unknown_keys(state.root());
            if unknown.is_empty() {
                r.line("config.toml", "ok");
            } else {
                r.warn(
                    "config.toml",
                    format!("unknown keys: {}", unknown.join(", ")),
                );
            }
            settings
        }
        Err(e) => {
            r.fail("config.toml", &e.message, e.code);
            Settings::default()
        }
    };
    if let Some(label) = &settings.label
        && kc_proto::Label::new(label).is_err()
    {
        r.warn(
            "label",
            "not 1-64 printable ASCII characters; kc uses a cleaned-up copy",
        );
    }

    let peers = match state.load_peers() {
        Ok(peers) => {
            r.line("paired devices", peers.peers.len());
            Some(peers)
        }
        Err(e) => {
            r.fail("peers.json", &e.message, e.code);
            None
        }
    };
    if let Err(e) = state.load_seen(host.now()) {
        r.fail("seen.json", &e.message, e.code);
    }

    match host.open_store(interactivity.is_interactive()) {
        Err(e) => r.fail("keychain", &e.message, e.code),
        Ok(store) => check_store(
            &mut r,
            &Keychain::new(store),
            &settings,
            peers.as_ref(),
            args,
        ),
    }

    let env_relay = host.env_var(ENV_RELAY);
    match settings::resolve_relay(
        cli.relay.as_deref(),
        env_relay.as_deref(),
        &settings,
        cli.allow_http,
    ) {
        Err(e) => r.fail("relay", &e.message, e.code),
        Ok(url) => {
            if url.is_plain_http() {
                r.warn("relay", format!("{url} is plain http (TLS off)"));
            }
            match host.relay_limits(&url).await {
                Ok(limits) if limits.proto_version == PROTO_VERSION => {
                    r.line(
                        "relay",
                        format!("ok: {url} (protocol {})", limits.proto_version),
                    );
                }
                Ok(limits) => r.fail(
                    "relay",
                    format!(
                        "{url} speaks protocol {}, this kc speaks {PROTO_VERSION}",
                        limits.proto_version
                    ),
                    exit::RELAY_UNAVAILABLE,
                ),
                Err(e) => r.fail("relay", format!("{url}: {e}"), exit::RELAY_UNAVAILABLE),
            }
        }
    }

    if interactivity.is_interactive() {
        r.line("session", "interactive");
    } else {
        r.line(
            "session",
            format!("non-interactive ({})", interactivity.reasons().join(", ")),
        );
    }
    r.line(
        "agent code sends",
        if settings.agent_code_send {
            "allowed (agent_code_send = true)"
        } else {
            "refused"
        },
    );

    let _ = host.console().stdout().write_all(r.text.as_bytes());
    let _ = host.console().stdout().flush();
    Ok(r.code.unwrap_or(exit::OK))
}

fn check_store(
    r: &mut Report,
    store: &Keychain,
    settings: &Settings,
    peers: Option<&crate::state::Peers>,
    args: &DoctorArgs,
) {
    match store.backend_description() {
        Ok(desc) => r.line(
            "keychain",
            format!("ok: {desc}, namespace {}", store.namespace()),
        ),
        Err(e) => {
            r.fail("keychain", e.to_string(), e.exit_code());
            return;
        }
    }
    if args.reindex {
        match store.reindex() {
            Ok(report) => r.line(
                "reindex",
                format!(
                    "done: {} added, {} removed, {} leftover entries deleted{}",
                    report.added.len(),
                    report.removed.len(),
                    report.orphans_removed,
                    if report.replaced_corrupt_index {
                        "; the damaged index was moved to index.json.corrupt"
                    } else {
                        ""
                    }
                ),
            ),
            Err(e) => r.fail("reindex", e.to_string(), e.exit_code()),
        }
    }
    match (store.list(), store.verify()) {
        (Ok(items), Ok(drift)) if drift.is_clean() => {
            r.line(
                "items",
                format!("{}; the index matches the keychain", items.len()),
            );
        }
        (Ok(items), Ok(drift)) => r.warn(
            "items",
            format!(
                "{}; the index is out of date ({} stale, {} missing): run `kc doctor --reindex`",
                items.len(),
                drift.stale.len(),
                drift.unindexed.len()
            ),
        ),
        (Err(e), _) | (_, Err(e)) => r.fail("items", e.to_string(), e.exit_code()),
    }
    let has = |key: &str| store.get_internal(key).map(|v| v.is_some());
    match (has(DEVICE_KEY), read_inbox(store)) {
        (Ok(false), Ok(None)) => r.line("device", "not paired yet (no device key or inbox)"),
        (Ok(true), Ok(None)) => r.line("device", "device key ok, no inbox yet"),
        (Ok(true), Ok(Some((id, _)))) if settings.inbox_id.as_deref() == Some(id.as_str()) => {
            r.line("device", "device key and inbox ok")
        }
        (Ok(true), Ok(Some(_))) => r.warn(
            "device",
            "config.toml's inbox_id doesn't match the keychain (the keychain is used; the next \
             pairing rewrites config.toml)",
        ),
        (Ok(false), Ok(Some(_))) => r.warn(
            "device",
            "an inbox but no device key; `kc device rotate` starts over",
        ),
        (Err(e), _) => r.fail("device", e.to_string(), e.exit_code()),
        (_, Err(e)) => r.fail("device", &e.message, e.code),
    }
    if let Some(peers) = peers {
        let missing: Vec<String> = peers
            .peers
            .iter()
            .filter(|p| matches!(has(&p.token_key()), Ok(false)))
            .map(|p| p.label.to_string())
            .collect();
        if !missing.is_empty() {
            r.warn(
                "paired devices",
                format!(
                    "no sending token for {}; pair with them again",
                    missing.join(", ")
                ),
            );
        }
    }
}

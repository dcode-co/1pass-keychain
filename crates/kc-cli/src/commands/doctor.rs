//! `kc doctor [--reindex]`: the keychain, the configuration and the relay, each checked on
//! its own so one failure doesn't hide the others. Exits with the code of the first failure.

use std::fmt::Display;

use crate::keychain::Keychain;
use kc_wire::{PROTO_VERSION, exit};

use super::pairing::{DEVICE_KEY, read_inbox};
use super::{display_width, pad_to};
use crate::cli::{Cli, DoctorArgs};
use crate::console::Console as _;
use crate::error::Result;
use crate::host::Host;
use crate::i18n::tr;
use crate::policy::Interactivity;
use crate::settings::{self, ENV_RELAY, Settings};
use crate::state::StateDir;

/// Rows of what was checked and how it went. The labels are translated, so the column is
/// as wide as the widest label in terminal columns plus two, at least 18.
#[derive(Default)]
struct Report {
    rows: Vec<(String, String)>,
    code: Option<i32>,
}

impl Report {
    fn line(&mut self, what: impl Into<String>, detail: impl Display) {
        self.rows.push((what.into(), detail.to_string()));
    }

    fn fail(&mut self, what: impl Into<String>, detail: impl Display, code: i32) {
        self.line(what, tr!("FAIL: {detail}", detail = detail));
        self.code.get_or_insert(code);
    }

    fn warn(&mut self, what: impl Into<String>, detail: impl Display) {
        self.line(what, tr!("warning: {detail}", detail = detail));
    }

    fn text(&self) -> String {
        let width = self
            .rows
            .iter()
            .map(|(what, _)| display_width(what) + 2)
            .fold(18, usize::max);
        self.rows
            .iter()
            .map(|(what, detail)| format!("{} {detail}\n", pad_to(what, width)))
            .collect()
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
    r.line(tr!("config dir"), state.root().display());

    let settings = match settings {
        Ok(settings) => {
            let unknown = Settings::unknown_keys(state.root());
            if unknown.is_empty() {
                r.line("config.toml", tr!("ok"));
            } else {
                r.warn(
                    "config.toml",
                    tr!("unknown keys: {keys}", keys = unknown.join(", ")),
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
            tr!("label"),
            tr!("not 1-64 printable ASCII characters; kc uses a cleaned-up copy"),
        );
    }

    let peers = match state.load_peers() {
        Ok(peers) => {
            r.line(tr!("paired devices"), peers.peers.len());
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
        Err(e) => r.fail(tr!("keychain"), &e.message, e.code),
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
        Err(e) => r.fail(tr!("relay"), &e.message, e.code),
        Ok(url) => {
            if url.is_plain_http() {
                r.warn(
                    tr!("relay"),
                    tr!("{url} is plain http (TLS off)", url = url),
                );
            }
            match host.relay_limits(&url).await {
                Ok(limits) if limits.proto_version == PROTO_VERSION => {
                    r.line(
                        tr!("relay"),
                        tr!(
                            "ok: {url} (protocol {version})",
                            url = url,
                            version = limits.proto_version
                        ),
                    );
                }
                Ok(limits) => r.fail(
                    tr!("relay"),
                    tr!(
                        "{url} speaks protocol {theirs}, this kc speaks {ours}",
                        url = url,
                        theirs = limits.proto_version,
                        ours = PROTO_VERSION
                    ),
                    exit::RELAY_UNAVAILABLE,
                ),
                Err(e) => r.fail(tr!("relay"), format!("{url}: {e}"), exit::RELAY_UNAVAILABLE),
            }
        }
    }

    if interactivity.is_interactive() {
        r.line(tr!("session"), tr!("interactive"));
    } else {
        r.line(
            tr!("session"),
            tr!(
                "non-interactive ({reasons})",
                reasons = interactivity.reasons().join(", ")
            ),
        );
    }
    r.line(
        tr!("agent code sends"),
        if settings.agent_code_send {
            tr!("allowed (agent_code_send = true)")
        } else {
            tr!("refused")
        },
    );

    let _ = host.console().stdout().write_all(r.text().as_bytes());
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
            tr!("keychain"),
            tr!(
                "ok: {backend}, namespace {namespace}",
                backend = desc,
                namespace = store.namespace()
            ),
        ),
        Err(e) => {
            r.fail(tr!("keychain"), e.to_string(), e.exit_code());
            return;
        }
    }
    if args.reindex {
        match store.reindex() {
            Ok(report) => {
                let (added, removed, leftover) = (
                    report.added.len(),
                    report.removed.len(),
                    report.orphans_removed,
                );
                r.line(
                    tr!("reindex"),
                    if report.replaced_corrupt_index {
                        tr!(
                            "done: {added} added, {removed} removed, {leftover} leftover entries \
                             deleted; the damaged index was moved to index.json.corrupt",
                            added = added,
                            removed = removed,
                            leftover = leftover
                        )
                    } else {
                        tr!(
                            "done: {added} added, {removed} removed, {leftover} leftover entries \
                             deleted",
                            added = added,
                            removed = removed,
                            leftover = leftover
                        )
                    },
                );
            }
            Err(e) => r.fail(tr!("reindex"), e.to_string(), e.exit_code()),
        }
    }
    match (store.list(), store.verify()) {
        (Ok(items), Ok(drift)) if drift.is_clean() => {
            r.line(
                tr!("items"),
                tr!("{n}; the index matches the keychain", n = items.len()),
            );
        }
        (Ok(items), Ok(drift)) => r.warn(
            tr!("items"),
            tr!(
                "{n}; the index is out of date ({stale} stale, {missing} missing): run `kc \
                 doctor --reindex`",
                n = items.len(),
                stale = drift.stale.len(),
                missing = drift.unindexed.len()
            ),
        ),
        (Err(e), _) | (_, Err(e)) => r.fail(tr!("items"), e.to_string(), e.exit_code()),
    }
    let has = |key: &str| store.get_internal(key).map(|v| v.is_some());
    match (has(DEVICE_KEY), read_inbox(store)) {
        (Ok(false), Ok(None)) => r.line(
            tr!("device"),
            tr!("not paired yet (no device key or inbox)"),
        ),
        (Ok(true), Ok(None)) => r.line(tr!("device"), tr!("device key ok, no inbox yet")),
        (Ok(true), Ok(Some((id, _)))) if settings.inbox_id.as_deref() == Some(id.as_str()) => {
            r.line(tr!("device"), tr!("device key and inbox ok"))
        }
        (Ok(true), Ok(Some(_))) => r.warn(
            tr!("device"),
            tr!(
                "config.toml's inbox_id doesn't match the keychain (the keychain is used; the \
                 next pairing rewrites config.toml)"
            ),
        ),
        (Ok(false), Ok(Some(_))) => r.warn(
            tr!("device"),
            tr!("an inbox but no device key; `kc device rotate` starts over"),
        ),
        (Err(e), _) => r.fail(tr!("device"), e.to_string(), e.exit_code()),
        (_, Err(e)) => r.fail(tr!("device"), &e.message, e.code),
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
                tr!("paired devices"),
                tr!(
                    "no sending token for {devices}; pair with them again",
                    devices = missing.join(", ")
                ),
            );
        }
    }
}

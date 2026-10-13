//! `config.toml` and the relay URL.
//!
//! `config.toml` lives in the config directory kc-store uses (`KC_CONFIG_DIR` overrides it)
//! and holds no secrets:
//!
//! ```toml
//! label = "laptop"                   # the name this device suggests to devices it pairs with
//! relay = "https://relay.1pass.dev"  # optional
//! agent_code_send = false            # let agents and scripts send with a one-time code
//! allow_http = false                 # allow a plain-http relay off this machine
//! inbox_id = "…"                     # this device's inbox, created when it first pairs
//! ```
//!
//! The relay URL is the `--relay` flag, then `KC_RELAY`, then `relay` here, then
//! [`DEFAULT_RELAY`]. It must be `https://` unless it points at this machine
//! (`localhost`, a loopback address) or `--allow-http` / `allow_http = true` is set.

use std::ffi::OsStr;
use std::fmt;
use std::net::IpAddr;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::error::{CliError, Result};
use crate::i18n::tr;
use crate::state::write_private_atomic;

pub const CONFIG_FILE: &str = "config.toml";
pub const DEFAULT_RELAY: &str = "https://relay.1pass.dev";
pub const ENV_RELAY: &str = "KC_RELAY";

const HEADER: &str = "# kc device settings (no secrets here). `kc doctor` checks this file.\n";

/// The fields kc knows; `kc doctor` reports any others.
const KNOWN_KEYS: [&str; 6] = [
    "label",
    "relay",
    "agent_code_send",
    "allow_http",
    "inbox_id",
    "device_key_prev_until",
];

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Settings {
    /// The label this device suggests when pairing. Default: the host name.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    /// Lets non-interactive sessions (agents, scripts) send with a one-time code.
    #[serde(default)]
    pub agent_code_send: bool,
    /// Allows a plain-http relay that isn't on this machine.
    #[serde(default)]
    pub allow_http: bool,
    /// This device's inbox (base64url), created the first time it pairs.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub inbox_id: Option<String>,
    /// Until when (Unix seconds) the device key replaced by `kc device rotate` still opens
    /// inbox messages.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub device_key_prev_until: Option<i64>,
}

impl Settings {
    /// Reads `config.toml` from `dir`; a missing file gives the defaults.
    pub fn load(dir: &Path) -> Result<Settings> {
        let path = dir.join(CONFIG_FILE);
        let text = match std::fs::read_to_string(&path) {
            Ok(text) => text,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Settings::default()),
            Err(e) => {
                return Err(CliError::failure(tr!(
                    "can't read {path}: {e}",
                    path = path.display(),
                    e = e
                )));
            }
        };
        toml::from_str(&text).map_err(|e| {
            let shown = path.display();
            let why = e.message();
            CliError::failure(match line_number(&text, e.span()) {
                Some(line) => tr!(
                    "{path} is invalid (line {line}): {why}",
                    path = shown,
                    line = line,
                    why = why
                ),
                None => tr!("{path} is invalid: {why}", path = shown, why = why),
            })
        })
    }

    pub fn save(&self, dir: &Path) -> Result<()> {
        let body = toml::to_string(self).map_err(|e| {
            CliError::failure(tr!("can't encode {path}: {e}", path = CONFIG_FILE, e = e))
        })?;
        let path = dir.join(CONFIG_FILE);
        write_private_atomic(&path, format!("{HEADER}{body}").as_bytes()).map_err(|e| {
            CliError::failure(tr!("can't write {path}: {e}", path = path.display(), e = e))
        })
    }

    /// Top-level keys in `config.toml` that kc doesn't know (typos, for `kc doctor`).
    pub fn unknown_keys(dir: &Path) -> Vec<String> {
        let Ok(text) = std::fs::read_to_string(dir.join(CONFIG_FILE)) else {
            return Vec::new();
        };
        let Ok(table) = text.parse::<toml::Table>() else {
            return Vec::new();
        };
        table
            .keys()
            .filter(|k| !KNOWN_KEYS.contains(&k.as_str()))
            .cloned()
            .collect()
    }
}

/// The 1-based line a parse error span starts on.
pub(crate) fn line_number(text: &str, span: Option<std::ops::Range<usize>>) -> Option<usize> {
    let span = span?;
    Some(
        text.get(..span.start)
            .map_or(0, |before| before.matches('\n').count())
            + 1,
    )
}

/// A checked relay base URL: `scheme://host[:port][/prefix]`, without a trailing slash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayUrl {
    base: String,
    plain_http: bool,
}

impl RelayUrl {
    /// Checks `input`. Plain `http://` is accepted for this machine, or with `allow_http`.
    /// Errors never repeat the input: a rejected URL may carry a password or a token.
    pub fn parse(input: &str, allow_http: bool) -> Result<RelayUrl> {
        let bad = |why: &str| {
            CliError::usage(tr!("invalid relay URL: {why}", why = why))
                .with_hint(tr!("for example {url}", url = DEFAULT_RELAY))
        };
        let url = reqwest::Url::parse(input.trim()).map_err(|e| bad(&e.to_string()))?;
        let plain_http = match url.scheme() {
            "https" => false,
            "http" => true,
            _ => return Err(bad(&tr!("use https://"))),
        };
        if !url.username().is_empty() || url.password().is_some() {
            return Err(bad(&tr!("it must not contain a user name or password")));
        }
        if url.query().is_some() || url.fragment().is_some() {
            return Err(bad(&tr!("it must not have a query or a fragment")));
        }
        let Some(host) = url.host_str() else {
            return Err(bad(&tr!("it has no host")));
        };
        if plain_http && !allow_http && !is_this_machine(host) {
            // Scheme, host and port only: nothing else of the input is shown.
            let shown = match url.port() {
                Some(port) => format!("http://{host}:{port}"),
                None => format!("http://{host}"),
            };
            return Err(CliError::usage(tr!(
                "refusing the plain-http relay {url}: only https:// relays are used, except \
                 on this machine",
                url = shown
            ))
            .with_hint(tr!(
                "pass --allow-http or set allow_http = true in config.toml for a test relay"
            )));
        }
        let base = url.as_str().trim_end_matches('/').to_owned();
        Ok(RelayUrl { base, plain_http })
    }

    pub fn as_str(&self) -> &str {
        &self.base
    }

    /// `base + path`, where `path` starts with `/` (a `kc_wire::paths` value).
    pub fn endpoint(&self, path: &str) -> String {
        format!("{}{path}", self.base)
    }

    pub fn is_plain_http(&self) -> bool {
        self.plain_http
    }
}

impl fmt::Display for RelayUrl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.base)
    }
}

fn is_this_machine(host: &str) -> bool {
    if host.eq_ignore_ascii_case("localhost") {
        return true;
    }
    let bare = host
        .strip_prefix('[')
        .and_then(|h| h.strip_suffix(']'))
        .unwrap_or(host);
    bare.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}

/// The relay to use: `--relay`, then `KC_RELAY`, then `config.toml`, then the default.
pub fn resolve_relay(
    flag: Option<&str>,
    env: Option<&OsStr>,
    settings: &Settings,
    allow_http_flag: bool,
) -> Result<RelayUrl> {
    let allow_http = allow_http_flag || settings.allow_http;
    if let Some(url) = flag {
        return RelayUrl::parse(url, allow_http).map_err(|e| e.context("--relay"));
    }
    if let Some(url) = env.filter(|v| !v.is_empty()) {
        let url = url
            .to_str()
            .ok_or_else(|| CliError::usage(tr!("{var} is not valid UTF-8", var = ENV_RELAY)))?;
        return RelayUrl::parse(url, allow_http).map_err(|e| e.context(ENV_RELAY));
    }
    if let Some(url) = settings.relay.as_deref() {
        return RelayUrl::parse(url, allow_http).map_err(|e| e.context(CONFIG_FILE));
    }
    RelayUrl::parse(DEFAULT_RELAY, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn settings() -> Settings {
        Settings::default()
    }

    #[test]
    fn https_is_required_off_this_machine() {
        assert!(RelayUrl::parse("https://relay.1pass.dev", false).is_ok());
        let e = RelayUrl::parse("http://relay.1pass.dev", false).unwrap_err();
        assert_eq!(e.code, kc_wire::exit::USAGE);
        let cgnat = RelayUrl::parse("http://100.64.0.1:8080", true).unwrap();
        assert!(cgnat.is_plain_http());
        assert_eq!(cgnat.as_str(), "http://100.64.0.1:8080");
        for local in [
            "http://localhost:8080",
            "http://127.0.0.1:9",
            "http://127.3.2.1",
            "http://[::1]:8080/",
            "http://LOCALHOST",
        ] {
            assert!(RelayUrl::parse(local, false).is_ok(), "{local}");
        }
        for secret in [
            "https://someone:zzmarker@relay.example",
            "https://relay.example/?q=zzmarker",
            "http://someone:zzmarker@relay.example",
            "not a url zzmarker",
        ] {
            let e = RelayUrl::parse(secret, false).unwrap_err();
            assert!(!e.to_string().contains("zzmarker"), "{e}");
        }
        for bad in [
            "ftp://relay.1pass.dev",
            "https://user:pw@relay.1pass.dev",
            "https://relay.1pass.dev/?x=1",
            "https://relay.1pass.dev/#f",
            "relay.1pass.dev",
            "http://localhost.evil.example",
        ] {
            assert!(RelayUrl::parse(bad, false).is_err(), "{bad}");
        }
    }

    #[test]
    fn base_has_no_trailing_slash_and_keeps_a_prefix() {
        let url = RelayUrl::parse("https://example.com/kc/", false).unwrap();
        assert_eq!(url.as_str(), "https://example.com/kc");
        assert_eq!(
            url.endpoint("/v1/limits"),
            "https://example.com/kc/v1/limits"
        );
        let url = RelayUrl::parse("https://relay.1pass.dev", false).unwrap();
        assert_eq!(
            url.endpoint("/v1/channels"),
            "https://relay.1pass.dev/v1/channels"
        );
    }

    #[test]
    fn resolution_order() {
        let mut s = settings();
        s.relay = Some("https://config.example".into());
        let env = OsStr::new("https://env.example");
        let flag = resolve_relay(Some("https://flag.example"), Some(env), &s, false).unwrap();
        assert_eq!(flag.as_str(), "https://flag.example");
        assert_eq!(
            resolve_relay(None, Some(env), &s, false).unwrap().as_str(),
            "https://env.example"
        );
        assert_eq!(
            resolve_relay(None, Some(OsStr::new("")), &s, false)
                .unwrap()
                .as_str(),
            "https://config.example"
        );
        assert_eq!(
            resolve_relay(None, None, &settings(), false)
                .unwrap()
                .as_str(),
            DEFAULT_RELAY
        );
        // allow_http comes from the flag or the config.
        s.relay = Some("http://100.64.0.1:8080".into());
        assert!(resolve_relay(None, None, &s, false).is_err());
        assert!(resolve_relay(None, None, &s, true).is_ok());
        s.allow_http = true;
        assert!(resolve_relay(None, None, &s, false).is_ok());
    }

    #[test]
    fn settings_round_trip() {
        let dir = tempfile::tempdir().unwrap();
        assert_eq!(Settings::load(dir.path()).unwrap(), Settings::default());
        let s = Settings {
            label: Some("laptop".into()),
            relay: Some("http://100.64.0.1:8080".into()),
            agent_code_send: true,
            allow_http: true,
            inbox_id: Some("AAAAAAAAAAAAAAAAAAAAAA".into()),
            device_key_prev_until: Some(1_760_000_000),
        };
        s.save(dir.path()).unwrap();
        assert_eq!(Settings::load(dir.path()).unwrap(), s);
        let text = std::fs::read_to_string(dir.path().join(CONFIG_FILE)).unwrap();
        assert!(text.starts_with('#'));
        assert!(Settings::unknown_keys(dir.path()).is_empty());

        std::fs::write(
            dir.path().join(CONFIG_FILE),
            "label = \"x\"\nagent_code_sned = true\n",
        )
        .unwrap();
        assert_eq!(
            Settings::unknown_keys(dir.path()),
            vec!["agent_code_sned".to_string()]
        );
        std::fs::write(
            dir.path().join(CONFIG_FILE),
            "label = \"x\"\nallow_http = 3\n",
        )
        .unwrap();
        let err = Settings::load(dir.path()).unwrap_err();
        assert!(err.message.contains("line 2"), "{}", err.message);
    }
}

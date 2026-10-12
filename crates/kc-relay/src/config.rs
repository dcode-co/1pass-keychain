//! Relay configuration. Production values come from `kc_wire::limits`; tests
//! shrink TTLs and caps through the same struct.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::time::Duration;

use ipnet::IpNet;
use kc_wire::limits;

use crate::ip;
use crate::limiter::Quota;

#[derive(Debug, Clone)]
pub struct Config {
    pub bind: SocketAddr,
    pub db: DbLocation,
    /// TCP peers inside these networks may set `x-kc-client-ip`.
    pub trusted_proxies: Vec<IpNet>,
    pub channels: ChannelConfig,
    pub inbox: InboxConfig,
    pub rate: RateConfig,
    pub http: HttpConfig,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DbLocation {
    File(PathBuf),
    /// No file, no WAL. For tests and `spawn_test_relay`.
    Memory,
}

#[derive(Debug, Clone)]
pub struct ChannelConfig {
    pub ttl: Duration,
    /// How long a closed or expired channel answers 410 before it answers 404
    /// and its number can be reused.
    pub tombstone: Duration,
    pub long_poll_max: Duration,
    pub max_open: usize,
    /// Payload bytes held by all open channels together.
    pub max_ram_bytes: usize,
    pub number_max: u16,
    pub sweep_interval: Duration,
    pub capacity_retry_after: Duration,
}

#[derive(Debug, Clone)]
pub struct InboxConfig {
    pub message_ttl: Duration,
    pub max_messages: usize,
    pub max_bytes: usize,
    pub max_writers: usize,
    /// One writer may fill at most this share of an inbox, so a single peer
    /// can't lock the others out until the owner reads.
    pub writer_max_messages: usize,
    pub writer_max_bytes: usize,
    pub idle_delete: Duration,
    pub max_inboxes: usize,
    /// SQLite `max_page_count` is derived from this.
    pub max_db_bytes: u64,
    pub purge_interval: Duration,
    pub capacity_retry_after: Duration,
    /// Database jobs queued or running at once.
    pub db_jobs: usize,
}

#[derive(Debug, Clone)]
pub struct RateConfig {
    /// Safety net over every request from one client address.
    pub per_ip: Quota,
    pub allocate: Quota,
    pub join: Quota,
    pub inbox_create: Quota,
    pub inbox_read: Quota,
    /// Per writer id, not per address.
    pub writer_write: Quota,
    pub long_polls_per_ip: usize,
    /// Requests one client address may have in progress at once.
    pub inflight_per_ip: usize,
    /// Bound on tracked keys per limiter (memory).
    pub max_keys: usize,
    pub cleanup_interval: Duration,
}

#[derive(Debug, Clone)]
pub struct HttpConfig {
    pub max_long_polls: usize,
    pub max_uploads: usize,
    pub uploads_per_ip: usize,
    /// Inbox listings being built at once (each can be several MiB of JSON).
    pub max_inbox_reads: usize,
    pub body_timeout: Duration,
    pub json_body_max: usize,
    /// Responses larger than this hold a share of `outbound_budget_bytes`
    /// (and one of `outbound_per_ip` slots) until they are fully handed to
    /// the connection or dropped.
    pub large_response_bytes: usize,
    pub outbound_budget_bytes: usize,
    pub outbound_per_ip: usize,
    pub header_read_timeout: Duration,
    /// A connection whose peer reads nothing for this long is dropped.
    pub write_stall_timeout: Duration,
    /// Total time one response may spend waiting for the peer to read
    /// (stops trickle readers that keep resetting the stall clock).
    pub write_budget: Duration,
    /// Open connections; beyond this the relay stops accepting until one
    /// closes.
    pub max_connections: usize,
    /// After shutdown starts, open connections get this long to finish.
    pub drain_timeout: Duration,
}

impl Default for ChannelConfig {
    fn default() -> Self {
        ChannelConfig {
            ttl: Duration::from_secs(limits::CHANNEL_TTL_SECS),
            tombstone: Duration::from_secs(limits::CHANNEL_TOMBSTONE_SECS),
            long_poll_max: Duration::from_secs(limits::LONG_POLL_MAX_SECS),
            max_open: limits::MAX_OPEN_CHANNELS,
            max_ram_bytes: limits::MAX_CHANNEL_RAM_BYTES,
            number_max: limits::CHANNEL_NUMBER_MAX,
            sweep_interval: Duration::from_secs(5),
            capacity_retry_after: Duration::from_secs(30),
        }
    }
}

impl Default for InboxConfig {
    fn default() -> Self {
        InboxConfig {
            message_ttl: Duration::from_secs(limits::INBOX_MESSAGE_TTL_SECS),
            max_messages: limits::INBOX_MAX_MESSAGES,
            max_bytes: limits::INBOX_MAX_BYTES,
            max_writers: limits::INBOX_MAX_WRITERS,
            writer_max_messages: limits::INBOX_MAX_MESSAGES.div_ceil(2),
            writer_max_bytes: limits::INBOX_MAX_BYTES / 2,
            idle_delete: Duration::from_secs(limits::INBOX_IDLE_DELETE_DAYS * 86_400),
            max_inboxes: limits::MAX_INBOXES,
            max_db_bytes: 256 * 1024 * 1024,
            purge_interval: Duration::from_secs(3600),
            capacity_retry_after: Duration::from_secs(600),
            db_jobs: crate::inbox::DB_JOBS,
        }
    }
}

impl Default for RateConfig {
    fn default() -> Self {
        RateConfig {
            per_ip: Quota::per_minute(300),
            allocate: Quota::per_hour(20),
            join: Quota::per_hour(20),
            inbox_create: Quota::per_day(5),
            inbox_read: Quota::per_hour(120),
            writer_write: Quota::per_hour(60),
            long_polls_per_ip: 8,
            inflight_per_ip: 24,
            max_keys: 50_000,
            cleanup_interval: Duration::from_secs(60),
        }
    }
}

impl Default for HttpConfig {
    fn default() -> Self {
        HttpConfig {
            max_long_polls: 2048,
            max_uploads: 32,
            uploads_per_ip: 4,
            max_inbox_reads: 4,
            body_timeout: Duration::from_secs(15),
            json_body_max: 1024,
            large_response_bytes: 64 * 1024,
            outbound_budget_bytes: 32 * 1024 * 1024,
            outbound_per_ip: 2,
            header_read_timeout: Duration::from_secs(30),
            write_stall_timeout: Duration::from_secs(60),
            write_budget: Duration::from_secs(240),
            max_connections: 2560,
            drain_timeout: Duration::from_secs(20),
        }
    }
}

pub const DEFAULT_BIND: &str = "0.0.0.0:8080";
pub const DEFAULT_DB: &str = "/data/relay.db";

impl Default for Config {
    /// Production limits, default bind address and database path.
    fn default() -> Self {
        Config {
            bind: DEFAULT_BIND.parse().expect("static address"),
            db: DbLocation::File(PathBuf::from(DEFAULT_DB)),
            trusted_proxies: ip::default_trusted_proxies(),
            channels: ChannelConfig::default(),
            inbox: InboxConfig::default(),
            rate: RateConfig::default(),
            http: HttpConfig::default(),
        }
    }
}

impl Config {
    /// Production config, overridden by `KC_RELAY_BIND`, `KC_RELAY_DB`
    /// (`:memory:` for no file) and `KC_RELAY_TRUSTED_PROXIES` (comma-separated
    /// CIDRs; empty trusts nobody).
    pub fn from_env() -> Result<Config, String> {
        Config::from_lookup(|k| std::env::var(k).ok())
    }

    pub fn from_lookup(get: impl Fn(&str) -> Option<String>) -> Result<Config, String> {
        let mut cfg = Config::default();
        if let Some(v) = get("KC_RELAY_BIND") {
            cfg.bind = v
                .trim()
                .parse()
                .map_err(|_| format!("KC_RELAY_BIND is not host:port: {v:?}"))?;
        }
        if let Some(v) = get("KC_RELAY_DB") {
            let v = v.trim();
            cfg.db = match v {
                "" => return Err("KC_RELAY_DB is empty".into()),
                ":memory:" => DbLocation::Memory,
                path => DbLocation::File(PathBuf::from(path)),
            };
        }
        if let Some(v) = get("KC_RELAY_TRUSTED_PROXIES") {
            cfg.trusted_proxies =
                ip::parse_cidr_list(&v).map_err(|e| format!("KC_RELAY_TRUSTED_PROXIES: {e}"))?;
        }
        Ok(cfg)
    }

    /// For tests and `spawn_test_relay`: loopback on a free port, in-memory
    /// database, only loopback trusted, production TTLs and caps, and rate
    /// limits loose enough that an end-to-end suite never trips them.
    pub fn for_tests() -> Config {
        let loose = Quota::per_hour(1_000_000);
        Config {
            bind: "127.0.0.1:0".parse().expect("static address"),
            db: DbLocation::Memory,
            trusted_proxies: ip::parse_cidr_list("127.0.0.1/32,::1/128").expect("static CIDRs"),
            rate: RateConfig {
                per_ip: loose,
                allocate: loose,
                join: loose,
                inbox_create: loose,
                inbox_read: loose,
                writer_write: loose,
                long_polls_per_ip: 64,
                inflight_per_ip: 256,
                ..RateConfig::default()
            },
            ..Config::default()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn env_overrides() {
        let env = |k: &str| match k {
            "KC_RELAY_BIND" => Some("127.0.0.1:9000".to_string()),
            "KC_RELAY_DB" => Some(":memory:".to_string()),
            "KC_RELAY_TRUSTED_PROXIES" => Some("172.30.0.0/24".to_string()),
            _ => None,
        };
        let cfg = Config::from_lookup(env).unwrap();
        assert_eq!(cfg.bind, "127.0.0.1:9000".parse().unwrap());
        assert_eq!(cfg.db, DbLocation::Memory);
        assert_eq!(cfg.trusted_proxies.len(), 1);
    }

    #[test]
    fn defaults_follow_the_contract() {
        let cfg = Config::from_lookup(|_| None).unwrap();
        assert_eq!(cfg.bind, DEFAULT_BIND.parse().unwrap());
        assert_eq!(cfg.db, DbLocation::File(DEFAULT_DB.into()));
        assert_eq!(cfg.channels.max_open, 1000);
        assert_eq!(cfg.channels.max_ram_bytes, 32 * 1024 * 1024);
        assert_eq!(cfg.inbox.max_writers, 16);
        assert_eq!(cfg.rate.allocate, Quota::per_hour(20));
        assert_eq!(cfg.rate.inbox_create, Quota::per_day(5));
        assert_eq!(cfg.rate.long_polls_per_ip, 8);
    }

    #[test]
    fn bad_env_is_rejected() {
        assert!(
            Config::from_lookup(|k| (k == "KC_RELAY_BIND").then(|| "nope".to_string())).is_err()
        );
        assert!(Config::from_lookup(|k| (k == "KC_RELAY_DB").then(String::new)).is_err());
        assert!(
            Config::from_lookup(
                |k| (k == "KC_RELAY_TRUSTED_PROXIES").then(|| "1.2.3.4/99".to_string())
            )
            .is_err()
        );
        let open =
            Config::from_lookup(|k| (k == "KC_RELAY_TRUSTED_PROXIES").then(String::new)).unwrap();
        assert!(open.trusted_proxies.is_empty());
    }
}

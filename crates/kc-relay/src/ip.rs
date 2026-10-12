//! Which address a request is accounted to.
//!
//! The relay sits behind one reverse proxy. That proxy overwrites a single
//! client-IP header with the TCP peer it saw. The header is believed only when
//! our own TCP peer is inside a trusted CIDR (the proxy's network). Anyone else
//! is accounted to their TCP peer address, whatever headers they send.

use std::net::{IpAddr, Ipv6Addr};

use ipnet::IpNet;

/// The address a request is accounted to, and the key rate limits use.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ClientIp {
    pub ip: IpAddr,
    pub key: RateKey,
}

impl ClientIp {
    pub fn new(ip: IpAddr) -> Self {
        let ip = ip.to_canonical();
        ClientIp {
            ip,
            key: RateKey::from_ip(ip),
        }
    }
}

/// Rate-limit bucket key. IPv4 addresses count individually. IPv6 counts per
/// /64, because one subscriber usually owns a whole /64 and can rotate through
/// it freely.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum RateKey {
    V4([u8; 4]),
    V6Net64([u8; 8]),
}

impl RateKey {
    pub fn from_ip(ip: IpAddr) -> Self {
        match ip.to_canonical() {
            IpAddr::V4(v4) => RateKey::V4(v4.octets()),
            IpAddr::V6(v6) => {
                let o = v6.octets();
                let mut net = [0u8; 8];
                net.copy_from_slice(&o[..8]);
                RateKey::V6Net64(net)
            }
        }
    }

    /// Stable byte form, used as HMAC input for log tags.
    pub fn to_bytes(self) -> Vec<u8> {
        match self {
            RateKey::V4(o) => [&[4u8][..], &o[..]].concat(),
            RateKey::V6Net64(n) => [&[6u8][..], &n[..]].concat(),
        }
    }
}

/// True when `peer` is inside one of `trusted`.
pub fn is_trusted(peer: IpAddr, trusted: &[IpNet]) -> bool {
    let peer = peer.to_canonical();
    trusted.iter().any(|net| net.contains(&peer))
}

/// Resolve the client address.
///
/// `forwarded` is the raw value of the proxy's client-IP header, if present.
/// It must hold exactly one IP address (the proxy overwrites it, so a list
/// would mean something upstream is wrong). It is used only when `peer` is
/// trusted. A malformed header from a trusted peer falls back to the peer, so a
/// broken proxy config fails towards one shared bucket, never towards a
/// client-chosen one.
pub fn resolve(peer: IpAddr, forwarded: Option<&[u8]>, trusted: &[IpNet]) -> ClientIp {
    let from_proxy = if is_trusted(peer, trusted) {
        forwarded.and_then(parse_single_ip)
    } else {
        None
    };
    ClientIp::new(from_proxy.unwrap_or(peer))
}

fn parse_single_ip(raw: &[u8]) -> Option<IpAddr> {
    let s = std::str::from_utf8(raw).ok()?.trim();
    if s.is_empty() || s.len() > 64 {
        return None;
    }
    // Tolerate a bracketed IPv6 literal; reject lists and ports.
    let s = s
        .strip_prefix('[')
        .and_then(|v| v.strip_suffix(']'))
        .unwrap_or(s);
    s.parse::<IpAddr>().ok()
}

/// Loopback plus the private ranges Docker hands out to bridge networks by
/// default. Production should narrow this to the proxy network's subnet.
pub fn default_trusted_proxies() -> Vec<IpNet> {
    ["127.0.0.0/8", "::1/128", "172.16.0.0/12", "192.168.0.0/16"]
        .iter()
        .map(|s| s.parse().expect("static CIDR"))
        .collect()
}

/// Parse a comma-separated CIDR list. Bare addresses become host routes.
/// An empty string means "trust nobody".
pub fn parse_cidr_list(s: &str) -> Result<Vec<IpNet>, String> {
    let mut out = Vec::new();
    for part in s.split(',').map(str::trim).filter(|p| !p.is_empty()) {
        let net = match part.parse::<IpNet>() {
            Ok(net) => net,
            Err(_) => match part.parse::<IpAddr>() {
                Ok(ip) => IpNet::from(ip),
                Err(_) => return Err(format!("not a CIDR or IP address: {part:?}")),
            },
        };
        out.push(net.trunc());
    }
    Ok(out)
}

/// The address used to reach a server bound to `bind` from inside the same
/// host (the container healthcheck).
pub fn local_target(bind: std::net::SocketAddr) -> std::net::SocketAddr {
    let ip = match bind.ip() {
        IpAddr::V4(v4) if v4.is_unspecified() => IpAddr::V4(std::net::Ipv4Addr::LOCALHOST),
        IpAddr::V6(v6) if v6.is_unspecified() => IpAddr::V6(Ipv6Addr::LOCALHOST),
        other => other,
    };
    std::net::SocketAddr::new(ip, bind.port())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn header_is_used_only_from_trusted_peers() {
        let trusted = parse_cidr_list("172.30.0.0/24").unwrap();
        let from_proxy = resolve(ip("172.30.0.5"), Some(b"203.0.113.9"), &trusted);
        assert_eq!(from_proxy.ip, ip("203.0.113.9"));

        let spoofed = resolve(ip("198.51.100.7"), Some(b"203.0.113.9"), &trusted);
        assert_eq!(spoofed.ip, ip("198.51.100.7"));

        let no_header = resolve(ip("172.30.0.5"), None, &trusted);
        assert_eq!(no_header.ip, ip("172.30.0.5"));
    }

    #[test]
    fn malformed_or_list_header_falls_back_to_peer() {
        let trusted = parse_cidr_list("127.0.0.1").unwrap();
        for bad in [
            &b"1.2.3.4, 5.6.7.8"[..],
            b"not-an-ip",
            b"",
            b"1.2.3.4:80",
            b"\xff\xfe",
        ] {
            assert_eq!(
                resolve(ip("127.0.0.1"), Some(bad), &trusted).ip,
                ip("127.0.0.1")
            );
        }
        assert_eq!(
            resolve(ip("127.0.0.1"), Some(b"[2001:db8::1]"), &trusted).ip,
            ip("2001:db8::1")
        );
    }

    #[test]
    fn mapped_ipv4_peer_matches_ipv4_cidr() {
        let trusted = parse_cidr_list("10.9.0.0/16").unwrap();
        let peer = ip("::ffff:10.9.1.2");
        assert!(is_trusted(peer, &trusted));
        assert_eq!(resolve(peer, None, &trusted).ip, ip("10.9.1.2"));
    }

    #[test]
    fn ipv6_is_keyed_per_slash_64() {
        let a = ClientIp::new(ip("2001:db8:1:2::1")).key;
        let b = ClientIp::new(ip("2001:db8:1:2:ffff::9")).key;
        let c = ClientIp::new(ip("2001:db8:1:3::1")).key;
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_ne!(
            ClientIp::new(ip("192.0.2.1")).key,
            ClientIp::new(ip("192.0.2.2")).key
        );
    }

    #[test]
    fn cidr_list_parsing() {
        assert!(parse_cidr_list("").unwrap().is_empty());
        let v = parse_cidr_list(" 10.0.0.0/8 , ::1 ,192.168.1.7").unwrap();
        assert_eq!(v.len(), 3);
        assert!(v[1].contains(&ip("::1")));
        assert!(v[2].contains(&ip("192.168.1.7")));
        assert!(!v[2].contains(&ip("192.168.1.8")));
        assert!(parse_cidr_list("10.0.0.0/33").is_err());
        assert!(parse_cidr_list("bogus").is_err());
        assert!(
            default_trusted_proxies()
                .iter()
                .any(|n| n.contains(&ip("172.18.0.3")))
        );
    }

    #[test]
    fn local_target_maps_unspecified_to_loopback() {
        assert_eq!(
            local_target("0.0.0.0:8080".parse().unwrap()),
            "127.0.0.1:8080".parse().unwrap()
        );
        assert_eq!(
            local_target("[::]:9".parse().unwrap()),
            "[::1]:9".parse().unwrap()
        );
        assert_eq!(
            local_target("10.1.2.3:7".parse().unwrap()),
            "10.1.2.3:7".parse().unwrap()
        );
    }
}

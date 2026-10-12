//! Over real sockets: `spawn_test_relay`, graceful shutdown, the binary's
//! healthcheck and SIGTERM handling, and what reaches the logs.

mod common;

use std::net::SocketAddr;
use std::process::Command;
use std::time::Duration;

use common::b64;
use kc_relay::{Config, spawn_test_relay};
use kc_wire::{ChannelAllocated, ChannelJoined, InboxCreated, WriterRegister};
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

/// One HTTP/1.1 exchange with `Connection: close`; returns (status, body).
async fn http_bytes(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
    body: &[u8],
) -> (u16, Vec<u8>) {
    let mut stream = tokio::net::TcpStream::connect(addr).await.expect("connect");
    let mut req = format!(
        "{method} {path} HTTP/1.1\r\nHost: test\r\nConnection: close\r\nContent-Length: {}\r\n",
        body.len()
    );
    for (k, v) in headers {
        req.push_str(&format!("{k}: {v}\r\n"));
    }
    req.push_str("\r\n");
    stream.write_all(req.as_bytes()).await.unwrap();
    stream.write_all(body).await.unwrap();
    let mut raw = Vec::new();
    stream.read_to_end(&mut raw).await.unwrap();
    let status = std::str::from_utf8(raw.get(9..12).unwrap_or_default())
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let split = raw
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .map_or(raw.len(), |i| i + 4);
    (status, raw[split..].to_vec())
}

async fn http(
    addr: SocketAddr,
    method: &str,
    path: &str,
    headers: &[(&str, &str)],
) -> (u16, String) {
    let (status, body) = http_bytes(addr, method, path, headers, &[]).await;
    (status, String::from_utf8_lossy(&body).into_owned())
}

#[tokio::test]
async fn spawn_test_relay_serves_and_shuts_down_promptly() {
    let relay = spawn_test_relay(Config::for_tests()).await.unwrap();
    assert!(relay.url().starts_with("http://127.0.0.1:"));
    let addr = relay.addr;
    assert_eq!(
        http(addr, "GET", "/healthz", &[]).await,
        (200, "ok".to_string())
    );
    let (status, body) = http(addr, "GET", "/v1/limits", &[("kc-proto", "1")]).await;
    assert_eq!(status, 200);
    assert!(body.contains("\"proto_version\":1"));

    let (status, body) = http(addr, "POST", "/v1/channels", &[("kc-proto", "1")]).await;
    assert_eq!(status, 201);
    let alloc: ChannelAllocated = serde_json::from_str(&body).unwrap();

    // A long-poll in progress must not hold up shutdown.
    let auth = format!("Bearer {}", alloc.side_token);
    let path = format!("/v1/channels/{}/pake?wait=25", alloc.channel);
    let poll = tokio::spawn(async move {
        http(
            addr,
            "GET",
            &path,
            &[("kc-proto", "1"), ("authorization", &auth)],
        )
        .await
    });
    tokio::time::sleep(Duration::from_millis(300)).await;
    let t0 = std::time::Instant::now();
    tokio::time::timeout(Duration::from_secs(10), relay.shutdown())
        .await
        .expect("shutdown hung")
        .unwrap();
    assert!(
        t0.elapsed() < Duration::from_secs(5),
        "shutdown took {:?}",
        t0.elapsed()
    );
    assert_eq!(poll.await.unwrap().0, 204);
    assert!(
        tokio::net::TcpStream::connect(addr).await.is_err(),
        "listener is closed"
    );
}

/// Run `kc-relay --healthcheck` against `addr` off the runtime thread (the
/// relay under test is served by this same runtime).
async fn probe(addr: SocketAddr) -> bool {
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_kc-relay"))
            .arg("--healthcheck")
            .env("KC_RELAY_BIND", addr.to_string())
            .output()
            .unwrap()
            .status
            .success()
    })
    .await
    .unwrap()
}

#[tokio::test]
async fn binary_healthcheck_probe() {
    let relay = spawn_test_relay(Config::for_tests()).await.unwrap();
    let addr = relay.addr;
    assert!(probe(addr).await);
    relay.shutdown().await.unwrap();
    assert!(!probe(addr).await);
}

#[cfg(unix)]
#[tokio::test]
async fn binary_serves_and_exits_cleanly_on_sigterm() {
    let dir = common::TempDir::new();
    let port = std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port();
    let bind = format!("127.0.0.1:{port}");
    let db = dir.0.join("sub").join("relay.db");
    let mut child = Command::new(env!("CARGO_BIN_EXE_kc-relay"))
        .env("KC_RELAY_BIND", &bind)
        .env("KC_RELAY_DB", &db)
        .env("RUST_LOG", "warn")
        .spawn()
        .unwrap();
    let addr: SocketAddr = bind.parse().unwrap();
    let deadline = std::time::Instant::now() + Duration::from_secs(20);
    loop {
        if tokio::net::TcpStream::connect(addr).await.is_ok() {
            break;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "binary never started listening"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
    let (status, body) = http(addr, "POST", "/v1/inboxes", &[("kc-proto", "1")]).await;
    assert_eq!(status, 201, "{body}");
    assert!(db.exists(), "database created, parent directory included");

    let kill = Command::new("kill")
        .arg("-TERM")
        .arg(child.id().to_string())
        .status()
        .unwrap();
    assert!(kill.success());
    let deadline = std::time::Instant::now() + Duration::from_secs(10);
    let exit = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        assert!(
            std::time::Instant::now() < deadline,
            "no exit after SIGTERM"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    };
    assert!(exit.success(), "graceful exit: {exit:?}");
}

#[tokio::test]
async fn large_payload_streams_over_a_real_connection() {
    let relay = spawn_test_relay(Config::for_tests()).await.unwrap();
    let addr = relay.addr;
    let proto = ("kc-proto", "1");
    let (status, body) = http(addr, "POST", "/v1/channels", &[proto]).await;
    assert_eq!(status, 201);
    let a: ChannelAllocated = serde_json::from_str(&body).unwrap();
    let (status, body) = http(
        addr,
        "POST",
        &format!("/v1/channels/{}/join", a.channel),
        &[proto],
    )
    .await;
    assert_eq!(status, 200);
    let j: ChannelJoined = serde_json::from_str(&body).unwrap();

    let payload: Vec<u8> = (0..kc_wire::limits::MAX_PAYLOAD_BYTES)
        .map(|i| (i % 251) as u8)
        .collect();
    let path = format!("/v1/channels/{}/payload", a.channel);
    let sender = format!("Bearer {}", j.side_token);
    let receiver = format!("Bearer {}", a.side_token);
    let (status, _) = http_bytes(
        addr,
        "PUT",
        &path,
        &[proto, ("authorization", &sender)],
        &payload,
    )
    .await;
    assert_eq!(status, 204);
    let (status, got) = http_bytes(
        addr,
        "GET",
        &path,
        &[proto, ("authorization", &receiver)],
        &[],
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(got, payload);
    assert_eq!(relay.state.outbound_available_kib(), 32 * 1024);
    relay.shutdown().await.unwrap();
}

/// Poll `cond` every 20 ms for up to `limit`.
async fn eventually(limit: Duration, mut cond: impl FnMut() -> bool) -> bool {
    let deadline = std::time::Instant::now() + limit;
    while std::time::Instant::now() < deadline {
        if cond() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    cond()
}

// Needs a response bigger than the kernel's socket buffers; Linux defaults
// (4 MiB) make that deterministic with a full inbox (~5.6 MiB of JSON).
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_client_that_never_reads_is_cut_off_and_releases_the_budget() {
    let mut cfg = Config::for_tests();
    cfg.http.write_stall_timeout = Duration::from_millis(300);
    cfg.inbox.writer_max_bytes = cfg.inbox.max_bytes;
    cfg.inbox.writer_max_messages = cfg.inbox.max_messages;
    let relay = spawn_test_relay(cfg).await.unwrap();
    let addr = relay.addr;
    let proto = ("kc-proto", "1");

    let (status, body) = http(addr, "POST", "/v1/inboxes", &[proto]).await;
    assert_eq!(status, 201);
    let inbox: InboxCreated = serde_json::from_str(&body).unwrap();
    let owner = format!("Bearer {}", inbox.owner_token);
    let writer_raw: [u8; 32] = rand::random();
    let register = serde_json::to_vec(&WriterRegister {
        writer_token_sha256: b64(&common::sha256(&writer_raw)),
    })
    .unwrap();
    let writers = format!("/v1/inboxes/{}/writers", inbox.inbox_id);
    let (status, _) = http_bytes(
        addr,
        "POST",
        &writers,
        &[proto, ("authorization", &owner)],
        &register,
    )
    .await;
    assert_eq!(status, 201);
    let writer = format!("Bearer {}", b64(&writer_raw));
    let messages = format!("/v1/inboxes/{}/messages", inbox.inbox_id);
    let chunk = vec![7u8; kc_wire::limits::MAX_MESSAGE_BYTES];
    for _ in 0..(kc_wire::limits::INBOX_MAX_BYTES / kc_wire::limits::MAX_MESSAGE_BYTES) {
        let (status, _) = http_bytes(
            addr,
            "POST",
            &messages,
            &[proto, ("authorization", &writer)],
            &chunk,
        )
        .await;
        assert_eq!(status, 201);
    }

    let full = relay.state.outbound_available_kib();
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.set_recv_buffer_size(4096).unwrap();
    let mut stream = socket.connect(addr).await.unwrap();
    let req = format!(
        "GET {messages} HTTP/1.1\r\nHost: t\r\nkc-proto: 1\r\nAuthorization: {owner}\r\n\r\n"
    );
    stream.write_all(req.as_bytes()).await.unwrap();
    // The stalled response holds its share of the budget...
    assert!(
        eventually(Duration::from_secs(5), || relay
            .state
            .outbound_available_kib()
            < full)
        .await
    );
    // ...until the write-stall timeout drops the connection.
    assert!(
        eventually(Duration::from_secs(10), || relay
            .state
            .outbound_available_kib()
            == full)
        .await,
        "budget never came back"
    );
    drop(stream);
    relay.shutdown().await.unwrap();
}

#[tokio::test]
async fn connections_beyond_the_cap_wait_for_a_free_slot() {
    let mut cfg = Config::for_tests();
    cfg.http.max_connections = 1;
    let relay = spawn_test_relay(cfg).await.unwrap();
    let addr = relay.addr;
    // An idle connection takes the only slot.
    let idle = tokio::net::TcpStream::connect(addr).await.unwrap();
    tokio::time::sleep(Duration::from_millis(100)).await;
    let waiting = tokio::spawn(async move { http(addr, "GET", "/healthz", &[]).await });
    tokio::time::sleep(Duration::from_millis(300)).await;
    assert!(!waiting.is_finished(), "served past the connection cap");
    drop(idle);
    let (status, body) = tokio::time::timeout(Duration::from_secs(5), waiting)
        .await
        .expect("served once the slot was free")
        .unwrap();
    assert_eq!((status, body.as_str()), (200, "ok"));
    relay.shutdown().await.unwrap();
}

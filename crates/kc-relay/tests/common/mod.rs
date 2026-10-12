//! Test client for the relay router: requests go through the real router and
//! middleware with `oneshot`, from a chosen TCP peer address.

#![allow(dead_code)]

use std::net::SocketAddr;
use std::path::PathBuf;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use bytes::Bytes;
use http_body_util::BodyExt as _;
use kc_relay::{AppState, Config, router};
use kc_wire::{
    ApiError, ChannelAllocated, ChannelJoined, ErrorCode, InboxCreated, WriterRegister,
    WriterRegistered,
};
use serde::Serialize;
use serde::de::DeserializeOwned;
use sha2::{Digest, Sha256};
use tower::ServiceExt as _;

pub const PEER: &str = "198.51.100.1:40000";

pub struct Relay {
    pub state: AppState,
    pub app: Router,
}

impl Relay {
    pub fn new(cfg: Config) -> Relay {
        let state = AppState::new(cfg).expect("state");
        Relay {
            app: router(state.clone()),
            state,
        }
    }

    pub fn req(&self, method: Method, path: &str) -> Req {
        Req {
            app: self.app.clone(),
            method,
            path: path.to_string(),
            peer: PEER.parse().unwrap(),
            headers: vec![("kc-proto".into(), "1".into())],
            body: Vec::new(),
        }
    }

    pub fn get(&self, path: &str) -> Req {
        self.req(Method::GET, path)
    }
    pub fn post(&self, path: &str) -> Req {
        self.req(Method::POST, path)
    }
    pub fn put(&self, path: &str) -> Req {
        self.req(Method::PUT, path)
    }
    pub fn delete(&self, path: &str) -> Req {
        self.req(Method::DELETE, path)
    }

    // ---- channel helpers ----

    pub async fn allocate(&self) -> ChannelAllocated {
        let r = self.post("/v1/channels").send().await;
        assert_eq!(r.status, StatusCode::CREATED, "allocate: {:?}", r.text());
        r.json()
    }

    pub async fn join(&self, channel: u16) -> ChannelJoined {
        let r = self
            .post(&format!("/v1/channels/{channel}/join"))
            .send()
            .await;
        assert_eq!(r.status, StatusCode::OK, "join: {:?}", r.text());
        r.json()
    }

    /// Allocate and join: `(channel, receiver token, sender token)`.
    pub async fn pair(&self) -> (u16, String, String) {
        let a = self.allocate().await;
        let j = self.join(a.channel).await;
        (a.channel, a.side_token, j.side_token)
    }

    pub async fn put_phase(&self, channel: u16, phase: &str, token: &str, body: &[u8]) -> Resp {
        self.put(&format!("/v1/channels/{channel}/{phase}"))
            .bearer(token)
            .body(body.to_vec())
            .send()
            .await
    }

    pub async fn get_phase(&self, channel: u16, phase: &str, token: &str, wait: u64) -> Resp {
        self.get(&format!("/v1/channels/{channel}/{phase}?wait={wait}"))
            .bearer(token)
            .send()
            .await
    }

    // ---- inbox helpers ----

    pub async fn create_inbox(&self) -> InboxCreated {
        let r = self.post("/v1/inboxes").send().await;
        assert_eq!(
            r.status,
            StatusCode::CREATED,
            "create inbox: {:?}",
            r.text()
        );
        r.json()
    }

    /// Register a fresh writer token; returns `(writer_token, writer_id)`.
    pub async fn add_writer(&self, inbox: &InboxCreated) -> (String, String) {
        let raw: [u8; 32] = rand::random();
        let r = self
            .post(&format!("/v1/inboxes/{}/writers", inbox.inbox_id))
            .bearer(&inbox.owner_token)
            .json(&WriterRegister {
                writer_token_sha256: b64(&Sha256::digest(raw)),
            })
            .send()
            .await;
        assert_eq!(r.status, StatusCode::CREATED, "add writer: {:?}", r.text());
        (b64(&raw), r.json::<WriterRegistered>().writer_id)
    }

    pub async fn post_message(&self, inbox_id: &str, writer_token: &str, body: &[u8]) -> Resp {
        self.post(&format!("/v1/inboxes/{inbox_id}/messages"))
            .bearer(writer_token)
            .body(body.to_vec())
            .send()
            .await
    }

    pub async fn list(&self, inbox: &InboxCreated, wait: u64) -> Resp {
        self.get(&format!(
            "/v1/inboxes/{}/messages?wait={wait}",
            inbox.inbox_id
        ))
        .bearer(&inbox.owner_token)
        .send()
        .await
    }
}

pub struct Req {
    app: Router,
    method: Method,
    path: String,
    peer: SocketAddr,
    headers: Vec<(String, String)>,
    body: Vec<u8>,
}

impl Req {
    pub fn peer(mut self, peer: &str) -> Self {
        self.peer = peer.parse().expect("peer address");
        self
    }
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_string(), value.to_string()));
        self
    }
    pub fn client_ip(self, ip: &str) -> Self {
        self.header("x-kc-client-ip", ip)
    }
    pub fn bearer(self, token: &str) -> Self {
        self.header("authorization", &format!("Bearer {token}"))
    }
    pub fn without_proto(mut self) -> Self {
        self.headers.retain(|(k, _)| k != "kc-proto");
        self
    }
    pub fn body(mut self, body: impl Into<Vec<u8>>) -> Self {
        self.body = body.into();
        self
    }
    pub fn json<T: Serialize>(self, value: &T) -> Self {
        let body = serde_json::to_vec(value).unwrap();
        self.header("content-type", "application/json").body(body)
    }

    /// The response with its body not yet read.
    pub async fn send_raw(self) -> axum::response::Response {
        let mut builder = Request::builder().method(self.method).uri(&self.path);
        for (k, v) in &self.headers {
            builder = builder.header(k.as_str(), v.as_str());
        }
        let mut req = builder.body(Body::from(self.body)).expect("request");
        req.extensions_mut().insert(ConnectInfo(self.peer));
        self.app.oneshot(req).await.expect("infallible")
    }

    pub async fn send(self) -> Resp {
        let resp = self.send_raw().await;
        let status = resp.status();
        let headers = resp.headers().clone();
        let body = resp.into_body().collect().await.expect("body").to_bytes();
        Resp {
            status,
            headers,
            body,
        }
    }
}

#[derive(Debug)]
pub struct Resp {
    pub status: StatusCode,
    pub headers: HeaderMap,
    pub body: Bytes,
}

impl Resp {
    pub fn json<T: DeserializeOwned>(&self) -> T {
        serde_json::from_slice(&self.body)
            .unwrap_or_else(|e| panic!("bad JSON ({e}): {:?}", self.text()))
    }

    pub fn text(&self) -> String {
        String::from_utf8_lossy(&self.body).into_owned()
    }

    /// The `ApiError` body, checked against the status and the no-echo rule.
    pub fn api_error(&self) -> ApiError {
        let e: ApiError = self.json();
        assert_eq!(
            self.status.as_u16(),
            e.code.http_status(),
            "status must match the error code"
        );
        let v: serde_json::Value = self.json();
        let keys: Vec<&String> = v.as_object().expect("object").keys().collect();
        assert!(
            keys.iter().all(|k| *k == "code" || *k == "retry_after_s"),
            "error body has extra fields: {keys:?}"
        );
        e
    }

    pub fn code(&self) -> ErrorCode {
        self.api_error().code
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers.get(name).and_then(|v| v.to_str().ok())
    }

    /// 429 and 503 must say when to come back, in the header and the body.
    pub fn assert_retry_after(&self) {
        let header: u32 = self
            .header("retry-after")
            .expect("Retry-After header")
            .parse()
            .unwrap();
        assert!(header >= 1);
        assert_eq!(self.api_error().retry_after_s, Some(header));
    }
}

pub fn b64(data: &[u8]) -> String {
    URL_SAFE_NO_PAD.encode(data)
}

pub fn unb64(s: &str) -> Vec<u8> {
    URL_SAFE_NO_PAD.decode(s).expect("base64url")
}

pub fn random_token() -> String {
    b64(&rand::random::<[u8; 32]>())
}

pub fn sha256(data: &[u8]) -> [u8; 32] {
    Sha256::digest(data).into()
}

/// A scratch directory removed on drop.
pub struct TempDir(pub PathBuf);

impl TempDir {
    pub fn new() -> TempDir {
        let dir = std::env::temp_dir().join(format!(
            "kc-relay-test-{}-{:016x}",
            std::process::id(),
            rand::random::<u64>()
        ));
        std::fs::create_dir_all(&dir).unwrap();
        TempDir(dir)
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

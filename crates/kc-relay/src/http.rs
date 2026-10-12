//! Routes, the front middleware and the handlers.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::{Body, HttpBody as _};
use axum::extract::{ConnectInfo, FromRequestParts, MatchedPath, Path, RawQuery, Request, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, header};
use axum::middleware::{self, Next};
use axum::response::{IntoResponse, Response};
use axum::routing::{delete, get, post, put};
use kc_wire::{
    CLIENT_IP_HEADER, ChannelAllocated, ChannelJoined, DeleteReason, ErrorCode, InboxCreated,
    InboxMessage, InboxMessages, Limits, MessageAccepted, PROTO_HEADER, PROTO_VERSION, Phase,
    WriterRegister, WriterRegistered, limits, paths,
};
use serde::de::DeserializeOwned;
use tokio::sync::{Semaphore, watch};
use tokio::time::Instant;

use bytes::Bytes;

use crate::body::{read_limited, with_guard};
use crate::channels::{ChannelError, ChannelStore, Closed, Poll};
use crate::config::Config;
use crate::error::{ApiErr, json};

const OCTETS: &str = "application/octet-stream";
const JSON: &str = "application/json";
use crate::inbox::{Db, InboxError, InboxStore};
use crate::ip::{self, ClientIp, RateKey};
use crate::limiter::{Denied, Inflight, RateLimiter};
use crate::logging::{LogTagger, size_bucket};
use crate::util::{Hash, Id, b64, b64_exact, bearer_hash, now_ms, rfc3339, rfc3339_ms, sha256};

pub struct Limiters {
    pub per_ip: RateLimiter<RateKey>,
    pub allocate: RateLimiter<RateKey>,
    pub join: RateLimiter<RateKey>,
    pub inbox_create: RateLimiter<RateKey>,
    pub inbox_read: RateLimiter<RateKey>,
    pub writer_write: RateLimiter<Id>,
    pub long_polls_per_ip: Arc<Inflight<RateKey>>,
    pub uploads_per_ip: Arc<Inflight<RateKey>>,
    pub outbound_per_ip: Arc<Inflight<RateKey>>,
    pub inflight_per_ip: Arc<Inflight<RateKey>>,
}

impl Limiters {
    fn cleanup(&self, now: Instant) {
        for lim in [
            &self.per_ip,
            &self.allocate,
            &self.join,
            &self.inbox_create,
            &self.inbox_read,
        ] {
            lim.cleanup(now);
        }
        self.writer_write.cleanup(now);
    }
}

pub struct Shared {
    pub cfg: Config,
    pub channels: ChannelStore,
    pub inbox: InboxStore,
    pub limits: Limiters,
    pub tagger: LogTagger,
    long_polls: Arc<Semaphore>,
    uploads: Arc<Semaphore>,
    inbox_reads: Semaphore,
    /// Bytes (in KiB) of large responses not yet handed to the connection.
    outbound: Arc<Semaphore>,
    shutdown: watch::Sender<bool>,
    /// The same signal for code running on blocking threads.
    stopping: AtomicBool,
}

/// Everything a request needs. Cheap to clone.
#[derive(Clone)]
pub struct AppState(pub Arc<Shared>);

impl std::ops::Deref for AppState {
    type Target = Shared;
    fn deref(&self) -> &Shared {
        &self.0
    }
}

impl AppState {
    /// Opens (or creates) the database. Does not start background tasks.
    pub fn new(cfg: Config) -> anyhow::Result<AppState> {
        let db = Db::open(&cfg.db, cfg.inbox.max_db_bytes, cfg.inbox.db_jobs)?;
        let r = &cfg.rate;
        let limits = Limiters {
            per_ip: RateLimiter::new(r.per_ip, r.max_keys),
            allocate: RateLimiter::new(r.allocate, r.max_keys),
            join: RateLimiter::new(r.join, r.max_keys),
            inbox_create: RateLimiter::new(r.inbox_create, r.max_keys),
            inbox_read: RateLimiter::new(r.inbox_read, r.max_keys),
            writer_write: RateLimiter::new(r.writer_write, r.max_keys),
            long_polls_per_ip: Inflight::new(r.long_polls_per_ip),
            uploads_per_ip: Inflight::new(cfg.http.uploads_per_ip),
            outbound_per_ip: Inflight::new(cfg.http.outbound_per_ip),
            inflight_per_ip: Inflight::new(r.inflight_per_ip),
        };
        Ok(AppState(Arc::new(Shared {
            channels: ChannelStore::new(cfg.channels.clone()),
            inbox: InboxStore::new(db, cfg.inbox.clone()),
            limits,
            tagger: LogTagger::default(),
            long_polls: Arc::new(Semaphore::new(cfg.http.max_long_polls)),
            uploads: Arc::new(Semaphore::new(cfg.http.max_uploads)),
            inbox_reads: Semaphore::new(cfg.http.max_inbox_reads.max(1)),
            outbound: Arc::new(Semaphore::new(cfg.http.outbound_budget_bytes / 1024)),
            shutdown: watch::channel(false).0,
            stopping: AtomicBool::new(false),
            cfg,
        })))
    }

    /// Unreserved outbound budget, in KiB.
    pub fn outbound_available_kib(&self) -> usize {
        self.outbound.available_permits()
    }

    /// Wake every long-poll so graceful shutdown doesn't wait 25 s on them.
    pub fn begin_shutdown(&self) {
        self.stopping.store(true, Ordering::Relaxed);
        self.shutdown.send_replace(true);
    }

    fn is_shutting_down(&self) -> bool {
        *self.shutdown.borrow()
    }

    async fn shutdown_signal(&self) {
        let mut rx = self.shutdown.subscribe();
        let _ = rx.wait_for(|down| *down).await;
    }

    /// Channel sweeper, limiter cleanup and the inbox purge. They stop when
    /// `begin_shutdown` is called.
    pub fn spawn_background(&self) -> Vec<tokio::task::JoinHandle<()>> {
        let sweeper = {
            let app = self.clone();
            tokio::spawn(async move {
                let mut channels = tokio::time::interval(app.cfg.channels.sweep_interval);
                let mut limiters = tokio::time::interval(app.cfg.rate.cleanup_interval);
                loop {
                    tokio::select! {
                        _ = channels.tick() => { app.channels.sweep(Instant::now()); }
                        _ = limiters.tick() => app.limits.cleanup(Instant::now()),
                        _ = app.shutdown_signal() => break,
                    }
                }
            })
        };
        let purger = {
            let app = self.clone();
            tokio::spawn(async move {
                let mut every = tokio::time::interval(app.cfg.inbox.purge_interval);
                loop {
                    tokio::select! {
                        _ = every.tick() => match app.inbox.purge(now_ms(), &app.stopping).await {
                            Ok(s) if s.expired_messages + s.idle_inboxes > 0 => tracing::info!(
                                expired_messages = s.expired_messages,
                                idle_inboxes = s.idle_inboxes,
                                "inbox purge"
                            ),
                            Ok(_) => {}
                            Err(e) => tracing::error!(error = ?e, "inbox purge failed"),
                        },
                        _ = app.shutdown_signal() => break,
                    }
                }
            })
        };
        vec![sweeper, purger]
    }
}

pub fn router(state: AppState) -> Router {
    Router::new()
        .route(paths::LIMITS, get(get_limits))
        .route(paths::CHANNELS, post(allocate))
        .route("/v1/channels/{channel}", delete(close_channel))
        .route("/v1/channels/{channel}/join", post(join))
        .route(
            "/v1/channels/{channel}/{phase}",
            put(write_phase).get(read_phase),
        )
        .route(paths::INBOXES, post(create_inbox))
        .route("/v1/inboxes/{inbox}", delete(delete_inbox))
        .route("/v1/inboxes/{inbox}/writers", post(add_writer))
        .route(
            "/v1/inboxes/{inbox}/writers/{writer}",
            delete(remove_writer),
        )
        .route(
            "/v1/inboxes/{inbox}/messages",
            post(post_message).get(list_messages),
        )
        .route("/v1/inboxes/{inbox}/messages/{msg}", delete(delete_message))
        .fallback(not_found)
        .method_not_allowed_fallback(method_not_allowed)
        .layer(middleware::from_fn_with_state(state.clone(), front))
        // Outside the front layer: no version header, no rate limit, no log
        // line every few seconds from the container healthcheck.
        .route(paths::HEALTHZ, get(healthz).fallback(method_not_allowed))
        .with_state(state)
}

// ---- front middleware -----------------------------------------------------------

fn version_ok(headers: &HeaderMap) -> bool {
    let mut values = headers.get_all(PROTO_HEADER).iter();
    match (values.next(), values.next()) {
        (Some(v), None) => {
            v.to_str().ok().and_then(|s| s.trim().parse::<u32>().ok()) == Some(PROTO_VERSION)
        }
        _ => false,
    }
}

fn content_length(headers: &HeaderMap) -> Option<u64> {
    headers
        .get(header::CONTENT_LENGTH)?
        .to_str()
        .ok()?
        .trim()
        .parse()
        .ok()
}

/// The request announces a non-empty body.
fn has_body(headers: &HeaderMap) -> bool {
    headers.contains_key(header::TRANSFER_ENCODING)
        || content_length(headers).is_some_and(|n| n > 0)
}

/// Only these routes read a request body. Anywhere else a body would sit
/// unread in socket buffers (for up to 25 s on a long-poll), so it is refused
/// before the handler runs.
fn takes_body(method: &Method, route: Option<&str>) -> bool {
    matches!(
        (method, route),
        (&Method::PUT, Some("/v1/channels/{channel}/{phase}"))
            | (
                &Method::POST,
                Some("/v1/inboxes/{inbox}/writers" | "/v1/inboxes/{inbox}/messages")
            )
    )
}

/// Close the connection after this response instead of draining an unread
/// request body.
fn close_after(resp: &mut Response) {
    resp.headers_mut()
        .insert(header::CONNECTION, HeaderValue::from_static("close"));
}

fn harden(headers: &mut HeaderMap) {
    headers.insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    headers.insert(
        header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
}

async fn front(State(app): State<AppState>, mut req: Request, next: Next) -> Response {
    let started = Instant::now();
    let peer = req
        .extensions()
        .get::<ConnectInfo<SocketAddr>>()
        .map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |ci| ci.0.ip());
    let client = ip::resolve(
        peer,
        req.headers()
            .get(CLIENT_IP_HEADER)
            .map(HeaderValue::as_bytes),
        &app.cfg.trusted_proxies,
    );
    let route = req.extensions().get::<MatchedPath>().cloned();
    let method = req.method().clone();
    let request_size = content_length(req.headers());
    let body = has_body(req.headers());
    let body_expected = takes_body(&method, route.as_ref().map(MatchedPath::as_str));

    let mut resp = match app.limits.per_ip.check(client.key, started) {
        Err(denied) => rate_err(denied).into_response(),
        Ok(()) if !version_ok(req.headers()) => {
            ApiErr::new(ErrorCode::UnsupportedVersion).into_response()
        }
        Ok(()) if body && !body_expected => ApiErr::BAD_REQUEST.into_response(),
        Ok(()) => match app.limits.inflight_per_ip.try_acquire(client.key) {
            None => busy().into_response(),
            Some(_in_progress) => {
                req.extensions_mut().insert(client);
                next.run(req).await
            }
        },
    };
    harden(resp.headers_mut());
    if body && !resp.status().is_success() {
        close_after(&mut resp);
    }

    let status = resp.status().as_u16();
    let size = match method {
        Method::PUT | Method::POST => request_size,
        _ => resp.body().size_hint().exact(),
    };
    let ms = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
    let route = route.as_ref().map_or("-", MatchedPath::as_str);
    let client = app.tagger.tag(client.key, SystemTime::now());
    let size = size_bucket(size);
    if status >= 500 {
        tracing::warn!(target: "kc_relay::access", %method, route, status, ms, size, client, "request");
    } else {
        tracing::info!(target: "kc_relay::access", %method, route, status, ms, size, client, "request");
    }
    resp
}

// ---- extractors -------------------------------------------------------------------

impl<S: Send + Sync> FromRequestParts<S> for ClientIp {
    type Rejection = ApiErr;
    async fn from_request_parts(parts: &mut Parts, _: &S) -> Result<Self, ApiErr> {
        parts
            .extensions
            .get::<ClientIp>()
            .copied()
            .ok_or(ApiErr::INTERNAL)
    }
}

/// `Path` whose rejection is a plain 400 that doesn't echo the path.
struct P<T>(T);

impl<S: Send + Sync, T: DeserializeOwned + Send> FromRequestParts<S> for P<T> {
    type Rejection = ApiErr;
    async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, ApiErr> {
        match Path::<T>::from_request_parts(parts, state).await {
            Ok(Path(v)) => Ok(P(v)),
            Err(_) => Err(ApiErr::BAD_REQUEST),
        }
    }
}

// ---- parsing helpers ----------------------------------------------------------------

fn channel_number(s: &str, max: u16) -> Result<u16, ApiErr> {
    if s.is_empty() || s.len() > 5 || !s.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ApiErr::BAD_REQUEST);
    }
    match s.parse::<u16>() {
        Ok(n) if (1..=max).contains(&n) => Ok(n),
        _ => Err(ApiErr::NOT_FOUND),
    }
}

fn phase(s: &str) -> Result<Phase, ApiErr> {
    Phase::parse(s).ok_or(ApiErr::BAD_REQUEST)
}

fn query_param<'q>(query: Option<&'q str>, key: &str) -> Result<Option<&'q str>, ApiErr> {
    let mut found = None;
    for pair in query.unwrap_or("").split('&').filter(|p| !p.is_empty()) {
        let (k, v) = pair.split_once('=').unwrap_or((pair, ""));
        if k == key {
            if found.is_some() {
                return Err(ApiErr::BAD_REQUEST);
            }
            found = Some(v);
        }
    }
    Ok(found)
}

/// `?wait=SECS`, missing means 0. Values above the maximum are clamped.
fn wait_param(query: Option<&str>, max: Duration) -> Result<Duration, ApiErr> {
    match query_param(query, "wait")? {
        None => Ok(Duration::ZERO),
        Some(v) if !v.is_empty() && v.len() <= 6 && v.bytes().all(|b| b.is_ascii_digit()) => {
            Ok(Duration::from_secs(v.parse().map_err(|_| ApiErr::BAD_REQUEST)?).min(max))
        }
        Some(_) => Err(ApiErr::BAD_REQUEST),
    }
}

fn reason_param(query: Option<&str>) -> Result<DeleteReason, ApiErr> {
    match query_param(query, "reason")? {
        None | Some("abort") => Ok(DeleteReason::Abort),
        Some("done") => Ok(DeleteReason::Done),
        Some("bad_confirm") => Ok(DeleteReason::BadConfirm),
        Some(_) => Err(ApiErr::BAD_REQUEST),
    }
}

/// `SHA-256(inbox_id)`. A malformed id can't name an inbox, so it gets the
/// same 401 as an unknown one.
fn inbox_key(s: &str) -> Result<Hash, ApiErr> {
    b64_exact::<16>(s)
        .map(|id| sha256(&id))
        .ok_or(ApiErr::UNAUTHORIZED)
}

fn token_hash(headers: &HeaderMap) -> Result<Hash, ApiErr> {
    bearer_hash(headers).ok_or(ApiErr::UNAUTHORIZED)
}

// ---- error mapping ------------------------------------------------------------------

fn rate_err(denied: Denied) -> ApiErr {
    match denied {
        Denied::RetryAfter(wait) => ApiErr::retry(ErrorCode::RateLimited, wait),
        Denied::Saturated => ApiErr::retry(ErrorCode::Capacity, Duration::from_secs(60)),
    }
}

fn busy() -> ApiErr {
    ApiErr::retry(ErrorCode::RateLimited, Duration::from_secs(5))
}

fn full(app: &AppState) -> ApiErr {
    ApiErr::retry(ErrorCode::Capacity, app.cfg.channels.capacity_retry_after)
}

/// A 200 response. Bodies over `large_response_bytes` reserve their size from
/// the outbound budget and take one of the client's outbound slots. Both stay
/// held until the last byte has left (or the connection died), however long
/// hyper keeps the data queued; slow readers are cut off by the connection's
/// write limits in `serve`.
fn send_bytes(
    app: &AppState,
    client: ClientIp,
    data: Bytes,
    content_type: &'static str,
) -> Result<Response, ApiErr> {
    let mut resp = if data.len() <= app.cfg.http.large_response_bytes {
        (StatusCode::OK, data).into_response()
    } else {
        let slot = app
            .limits
            .outbound_per_ip
            .try_acquire(client.key)
            .ok_or_else(busy)?;
        let kib = u32::try_from(data.len().div_ceil(1024)).unwrap_or(u32::MAX);
        let permit = Arc::clone(&app.outbound)
            .try_acquire_many_owned(kib)
            .map_err(|_| ApiErr::retry(ErrorCode::Capacity, Duration::from_secs(5)))?;
        (StatusCode::OK, with_guard(data, (permit, slot))).into_response()
    };
    resp.headers_mut()
        .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
    Ok(resp)
}

impl AppState {
    fn channel_err(&self, e: ChannelError) -> ApiErr {
        match e {
            ChannelError::NotFound => ApiErr::NOT_FOUND,
            ChannelError::Gone { .. } => ApiErr::new(ErrorCode::Gone),
            ChannelError::Unauthorized => ApiErr::UNAUTHORIZED,
            ChannelError::WrongRole => ApiErr::new(ErrorCode::WrongRole),
            ChannelError::Crowded => ApiErr::new(ErrorCode::Crowded),
            ChannelError::AlreadyWritten => ApiErr::new(ErrorCode::AlreadyWritten),
            ChannelError::Capacity => full(self),
        }
    }

    /// `channel_err` for requests that name a channel with a side token.
    /// When the caller isn't one of the channel's participants, the answer
    /// (absent, open, closed) still reveals whether the number is in use, so
    /// it costs a join attempt: probing numbers is no cheaper than joining.
    fn channel_failure(&self, client: ClientIp, e: ChannelError) -> ApiErr {
        let probe = matches!(
            e,
            ChannelError::NotFound
                | ChannelError::Unauthorized
                | ChannelError::Gone { participant: false }
        );
        if probe && let Err(denied) = self.limits.join.check(client.key, Instant::now()) {
            return rate_err(denied);
        }
        self.channel_err(e)
    }

    fn inbox_err(&self, e: InboxError) -> ApiErr {
        match e {
            InboxError::Unauthorized => ApiErr::UNAUTHORIZED,
            InboxError::NotFound => ApiErr::NOT_FOUND,
            InboxError::Full => ApiErr::new(ErrorCode::InboxFull),
            InboxError::Capacity => {
                ApiErr::retry(ErrorCode::Capacity, self.cfg.inbox.capacity_retry_after)
            }
            InboxError::Internal(msg) => {
                tracing::error!(error = %msg, "inbox store failed");
                ApiErr::INTERNAL
            }
        }
    }
}

// ---- misc -----------------------------------------------------------------------------

async fn healthz() -> Response {
    let mut resp = (
        StatusCode::OK,
        [(header::CONTENT_TYPE, "text/plain; charset=utf-8")],
        "ok",
    )
        .into_response();
    harden(resp.headers_mut());
    resp
}

async fn get_limits() -> Response {
    json(StatusCode::OK, &Limits::current())
}

async fn not_found() -> ApiErr {
    ApiErr::NOT_FOUND
}

/// The contract has no 405 code; a wrong method is a malformed request.
async fn method_not_allowed() -> Response {
    let mut resp = ApiErr::BAD_REQUEST.into_response();
    harden(resp.headers_mut());
    resp
}

// ---- channels -------------------------------------------------------------------------

async fn allocate(State(app): State<AppState>, client: ClientIp) -> Result<Response, ApiErr> {
    app.limits
        .allocate
        .check(client.key, Instant::now())
        .map_err(rate_err)?;
    let a = app
        .channels
        .allocate(Instant::now(), SystemTime::now())
        .map_err(|e| app.channel_err(e))?;
    Ok(json(
        StatusCode::CREATED,
        &ChannelAllocated {
            channel: a.channel,
            side_token: b64(&a.token),
            expires_at: rfc3339(a.expires_at),
        },
    ))
}

async fn join(
    State(app): State<AppState>,
    client: ClientIp,
    P(channel): P<String>,
) -> Result<Response, ApiErr> {
    let c = channel_number(&channel, app.cfg.channels.number_max)?;
    // Charged before the lookup, so probing numbers costs the same as joining.
    app.limits
        .join
        .check(client.key, Instant::now())
        .map_err(rate_err)?;
    let j = app
        .channels
        .join(c, Instant::now())
        .map_err(|e| app.channel_err(e))?;
    Ok(json(
        StatusCode::OK,
        &ChannelJoined {
            side_token: b64(&j.token),
            expires_at: rfc3339(j.expires_at),
        },
    ))
}

async fn write_phase(
    State(app): State<AppState>,
    client: ClientIp,
    P((channel, phase_name)): P<(String, String)>,
    headers: HeaderMap,
    body: Body,
) -> Result<StatusCode, ApiErr> {
    let c = channel_number(&channel, app.cfg.channels.number_max)?;
    let phase = phase(&phase_name)?;
    let token = token_hash(&headers)?;
    app.channels
        .check_write(c, &token, phase, Instant::now())
        .map_err(|e| app.channel_failure(client, e))?;
    let _ip_slot = app
        .limits
        .uploads_per_ip
        .try_acquire(client.key)
        .ok_or_else(busy)?;
    let _permit = Arc::clone(&app.uploads)
        .try_acquire_owned()
        .map_err(|_| full(&app))?;
    let bytes = read_limited(body, &headers, phase.max_bytes(), app.cfg.http.body_timeout).await?;
    if bytes.is_empty() {
        return Err(ApiErr::BAD_REQUEST);
    }
    app.channels
        .write(c, &token, phase, bytes, Instant::now())
        .map_err(|e| app.channel_failure(client, e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn read_phase(
    State(app): State<AppState>,
    client: ClientIp,
    P((channel, phase_name)): P<(String, String)>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Result<Response, ApiErr> {
    let c = channel_number(&channel, app.cfg.channels.number_max)?;
    let phase = phase(&phase_name)?;
    let wait = wait_param(query.as_deref(), app.cfg.channels.long_poll_max)?;
    let token = token_hash(&headers)?;
    let poll = |now| {
        app.channels
            .poll(c, &token, phase, now)
            .map_err(|e| app.channel_failure(client, e))
    };

    match poll(Instant::now())? {
        Poll::Ready(bytes) => return send_bytes(&app, client, bytes, OCTETS),
        Poll::Pending { .. } if wait.is_zero() || app.is_shutting_down() => {
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        Poll::Pending { .. } => {}
    }
    let _ip_slot = app
        .limits
        .long_polls_per_ip
        .try_acquire(client.key)
        .ok_or_else(busy)?;
    let _permit = Arc::clone(&app.long_polls)
        .try_acquire_owned()
        .map_err(|_| full(&app))?;
    let deadline = Instant::now() + wait;
    loop {
        let (notified, expires) = match poll(Instant::now())? {
            Poll::Ready(bytes) => return send_bytes(&app, client, bytes, OCTETS),
            Poll::Pending { notified, expires } => (notified, expires),
        };
        if Instant::now() >= deadline {
            return Ok(StatusCode::NO_CONTENT.into_response());
        }
        // Wake at expiry at the latest; the next poll then answers 410.
        let until = deadline.min(expires);
        tokio::select! {
            _ = notified => {}
            _ = tokio::time::sleep_until(until) => {}
            _ = app.shutdown_signal() => return Ok(StatusCode::NO_CONTENT.into_response()),
        }
    }
}

async fn close_channel(
    State(app): State<AppState>,
    client: ClientIp,
    P(channel): P<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Result<StatusCode, ApiErr> {
    let c = channel_number(&channel, app.cfg.channels.number_max)?;
    let reason = reason_param(query.as_deref())?;
    let token = bearer_hash(&headers);
    match app.channels.delete(c, token.as_ref(), Instant::now()) {
        Ok(Closed::Now) => {
            // A fixed label, not an id: bad_confirm spikes are worth seeing.
            tracing::info!(target: "kc_relay::access", reason = reason.as_str(), "channel closed");
            Ok(StatusCode::NO_CONTENT)
        }
        Ok(Closed::Already { participant: true }) => Ok(StatusCode::NO_CONTENT),
        Ok(Closed::Already { participant: false }) => {
            // Idempotent for anyone, but a stranger learned the number is in use.
            app.limits
                .join
                .check(client.key, Instant::now())
                .map_err(rate_err)?;
            Ok(StatusCode::NO_CONTENT)
        }
        Err(e) => Err(app.channel_failure(client, e)),
    }
}

// ---- inboxes ----------------------------------------------------------------------------

async fn create_inbox(State(app): State<AppState>, client: ClientIp) -> Result<Response, ApiErr> {
    app.limits
        .inbox_create
        .check(client.key, Instant::now())
        .map_err(rate_err)?;
    let (id, token) = app
        .inbox
        .create(now_ms())
        .await
        .map_err(|e| app.inbox_err(e))?;
    Ok(json(
        StatusCode::CREATED,
        &InboxCreated {
            inbox_id: b64(&id),
            owner_token: b64(&token),
        },
    ))
}

async fn add_writer(
    State(app): State<AppState>,
    client: ClientIp,
    P(inbox): P<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiErr> {
    let id_hash = inbox_key(&inbox)?;
    let owner = token_hash(&headers)?;
    // Only the owner gets to send a body; check before reading one.
    app.inbox
        .authorize_owner(id_hash, owner)
        .await
        .map_err(|e| app.inbox_err(e))?;
    let _ip_slot = app
        .limits
        .uploads_per_ip
        .try_acquire(client.key)
        .ok_or_else(busy)?;
    let _permit = Arc::clone(&app.uploads)
        .try_acquire_owned()
        .map_err(|_| full(&app))?;
    let raw = read_limited(
        body,
        &headers,
        app.cfg.http.json_body_max,
        app.cfg.http.body_timeout,
    )
    .await?;
    let req: WriterRegister = serde_json::from_slice(&raw).map_err(|_| ApiErr::BAD_REQUEST)?;
    let writer_hash = b64_exact::<32>(&req.writer_token_sha256).ok_or(ApiErr::BAD_REQUEST)?;
    let writer_id = app
        .inbox
        .add_writer(id_hash, owner, writer_hash, now_ms())
        .await
        .map_err(|e| app.inbox_err(e))?;
    Ok(json(
        StatusCode::CREATED,
        &WriterRegistered {
            writer_id: b64(&writer_id),
        },
    ))
}

async fn remove_writer(
    State(app): State<AppState>,
    P((inbox, writer)): P<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiErr> {
    let id_hash = inbox_key(&inbox)?;
    let owner = token_hash(&headers)?;
    app.inbox
        .remove_writer(id_hash, owner, b64_exact::<16>(&writer))
        .await
        .map_err(|e| app.inbox_err(e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn post_message(
    State(app): State<AppState>,
    client: ClientIp,
    P(inbox): P<String>,
    headers: HeaderMap,
    body: Body,
) -> Result<Response, ApiErr> {
    let id_hash = inbox_key(&inbox)?;
    let writer_token = token_hash(&headers)?;
    let writer_id = app
        .inbox
        .writer_for(id_hash, writer_token)
        .await
        .map_err(|e| app.inbox_err(e))?;
    app.limits
        .writer_write
        .check(writer_id, Instant::now())
        .map_err(rate_err)?;
    let _ip_slot = app
        .limits
        .uploads_per_ip
        .try_acquire(client.key)
        .ok_or_else(busy)?;
    let _permit = Arc::clone(&app.uploads)
        .try_acquire_owned()
        .map_err(|_| full(&app))?;
    let bytes = read_limited(
        body,
        &headers,
        limits::MAX_MESSAGE_BYTES,
        app.cfg.http.body_timeout,
    )
    .await?;
    if bytes.is_empty() {
        return Err(ApiErr::BAD_REQUEST);
    }
    let msg_id = app
        .inbox
        .post(id_hash, writer_token, bytes, now_ms())
        .await
        .map_err(|e| app.inbox_err(e))?;
    Ok(json(
        StatusCode::CREATED,
        &MessageAccepted {
            msg_id: b64(&msg_id),
        },
    ))
}

async fn list_messages(
    State(app): State<AppState>,
    client: ClientIp,
    P(inbox): P<String>,
    RawQuery(query): RawQuery,
    headers: HeaderMap,
) -> Result<Response, ApiErr> {
    let id_hash = inbox_key(&inbox)?;
    let owner = token_hash(&headers)?;
    let wait = wait_param(query.as_deref(), app.cfg.channels.long_poll_max)?;
    app.limits
        .inbox_read
        .check(client.key, Instant::now())
        .map_err(rate_err)?;

    let mut guards = None;
    let mut waiter = None;
    if !wait.is_zero() && !app.is_shutting_down() {
        let ip_slot = app
            .limits
            .long_polls_per_ip
            .try_acquire(client.key)
            .ok_or_else(busy)?;
        let permit = Arc::clone(&app.long_polls)
            .try_acquire_owned()
            .map_err(|_| full(&app))?;
        guards = Some((ip_slot, permit));
        // Register before reading so a message posted in between still wakes us.
        waiter = Some(app.inbox.waiter(id_hash));
    }
    let notified = waiter.as_ref().map(|w| w.notified());

    let mut listing = list_once(&app, id_hash, owner).await?;
    match notified {
        Some(notified) if listing.empty => {
            tokio::select! {
                _ = notified => {}
                _ = tokio::time::sleep(wait) => {}
                _ = app.shutdown_signal() => {}
            }
            listing = list_once(&app, id_hash, owner).await?;
        }
        _ => {}
    }
    drop(guards);
    send_bytes(&app, client, listing.json, JSON)
}

struct Listing {
    empty: bool,
    json: Bytes,
}

/// Read and serialize an inbox. Listings can be several MiB, so only
/// `max_inbox_reads` are built at once; `send_bytes` then bounds how many
/// wait on slow clients.
async fn list_once(app: &AppState, id_hash: Hash, owner: Hash) -> Result<Listing, ApiErr> {
    let _permit = app
        .inbox_reads
        .acquire()
        .await
        .map_err(|_| ApiErr::INTERNAL)?;
    let rows = app
        .inbox
        .list(id_hash, owner, now_ms())
        .await
        .map_err(|e| app.inbox_err(e))?;
    let empty = rows.is_empty();
    let messages = rows
        .into_iter()
        .map(|m| InboxMessage {
            msg_id: b64(&m.msg_id),
            writer_id: b64(&m.writer_id),
            received_at: rfc3339_ms(m.received_at_ms),
            body_b64: b64(&m.body),
        })
        .collect();
    let json = serde_json::to_vec(&InboxMessages { messages }).map_err(|_| ApiErr::INTERNAL)?;
    Ok(Listing {
        empty,
        json: Bytes::from(json),
    })
}

async fn delete_message(
    State(app): State<AppState>,
    P((inbox, msg)): P<(String, String)>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiErr> {
    let id_hash = inbox_key(&inbox)?;
    let owner = token_hash(&headers)?;
    app.inbox
        .delete_message(id_hash, owner, b64_exact::<16>(&msg))
        .await
        .map_err(|e| app.inbox_err(e))?;
    Ok(StatusCode::NO_CONTENT)
}

async fn delete_inbox(
    State(app): State<AppState>,
    P(inbox): P<String>,
    headers: HeaderMap,
) -> Result<StatusCode, ApiErr> {
    let id_hash = inbox_key(&inbox)?;
    let owner = token_hash(&headers)?;
    app.inbox
        .delete_inbox(id_hash, owner)
        .await
        .map_err(|e| app.inbox_err(e))?;
    Ok(StatusCode::NO_CONTENT)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn channel_numbers() {
        assert_eq!(channel_number("42", 9999), Ok(42));
        assert_eq!(channel_number("0042", 9999), Ok(42));
        assert_eq!(channel_number("0", 9999), Err(ApiErr::NOT_FOUND));
        assert_eq!(channel_number("10000", 9999), Err(ApiErr::NOT_FOUND));
        assert_eq!(channel_number("99999", 9999), Err(ApiErr::NOT_FOUND));
        assert_eq!(channel_number("4x", 9999), Err(ApiErr::BAD_REQUEST));
        assert_eq!(channel_number("", 9999), Err(ApiErr::BAD_REQUEST));
        assert_eq!(channel_number("-1", 9999), Err(ApiErr::BAD_REQUEST));
    }

    #[test]
    fn query_params() {
        let max = Duration::from_secs(25);
        assert_eq!(wait_param(None, max), Ok(Duration::ZERO));
        assert_eq!(wait_param(Some("wait=7"), max), Ok(Duration::from_secs(7)));
        assert_eq!(wait_param(Some("x=1&wait=99"), max), Ok(max));
        assert_eq!(wait_param(Some("wait=-1"), max), Err(ApiErr::BAD_REQUEST));
        assert_eq!(wait_param(Some("wait="), max), Err(ApiErr::BAD_REQUEST));
        assert_eq!(
            wait_param(Some("wait=1&wait=2"), max),
            Err(ApiErr::BAD_REQUEST)
        );
        assert_eq!(reason_param(None), Ok(DeleteReason::Abort));
        assert_eq!(
            reason_param(Some("reason=bad_confirm")),
            Ok(DeleteReason::BadConfirm)
        );
        assert_eq!(reason_param(Some("reason=done")), Ok(DeleteReason::Done));
        assert_eq!(reason_param(Some("reason=other")), Err(ApiErr::BAD_REQUEST));
    }

    #[test]
    fn version_header() {
        let mut h = HeaderMap::new();
        assert!(!version_ok(&h));
        h.insert(PROTO_HEADER, HeaderValue::from_static("1"));
        assert!(version_ok(&h));
        h.insert(PROTO_HEADER, HeaderValue::from_static("2"));
        assert!(!version_ok(&h));
        h.insert(PROTO_HEADER, HeaderValue::from_static("1"));
        h.append(PROTO_HEADER, HeaderValue::from_static("1"));
        assert!(!version_ok(&h));
    }
}

//! The accept loop. It does what `axum::serve` does, plus limits that axum
//! doesn't offer:
//!
//! - request headers must arrive within `header_read_timeout`;
//! - a connection whose peer reads nothing for `write_stall_timeout`, or whose
//!   current response has waited on the peer for `write_budget` in total, is
//!   dropped, so slow readers can't pin response memory;
//! - at most `max_connections` are open; beyond that the relay stops
//!   accepting until one closes;
//! - after shutdown starts, connections get `drain_timeout` to finish and are
//!   then aborted.
//!
//! HTTP/1.1 only: the relay sits behind a reverse proxy.

use std::future::Future;
use std::io;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use hyper::body::Incoming;
use hyper::server::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::server::graceful::GracefulShutdown;
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{Instant, Sleep};
use tower::ServiceExt as _;

use crate::config::HttpConfig;

/// Fails writes when the peer stops reading: after `stall_timeout` without
/// any progress, or once the writes of the current response have waited
/// `write_budget` in total. Request bytes arriving mean a new request, which
/// starts a fresh budget.
pub struct StallGuard<T> {
    io: T,
    stall_timeout: Duration,
    write_budget: Duration,
    waited: Duration,
    waiting_since: Option<Instant>,
    timer: Option<Pin<Box<Sleep>>>,
}

impl<T> StallGuard<T> {
    pub fn new(io: T, stall_timeout: Duration, write_budget: Duration) -> Self {
        StallGuard {
            io,
            stall_timeout,
            write_budget,
            waited: Duration::ZERO,
            waiting_since: None,
            timer: None,
        }
    }

    /// The inner writer isn't ready: start the clock, or fail once it ran out.
    fn blocked(&mut self, cx: &mut Context<'_>) -> Poll<io::Error> {
        let since = *self.waiting_since.get_or_insert_with(Instant::now);
        let left = self.write_budget.saturating_sub(self.waited);
        let deadline = since + self.stall_timeout.min(left);
        let timer = self
            .timer
            .get_or_insert_with(|| Box::pin(tokio::time::sleep_until(deadline)));
        match timer.as_mut().poll(cx) {
            Poll::Ready(()) => Poll::Ready(io::Error::new(
                io::ErrorKind::TimedOut,
                "peer stopped reading",
            )),
            Poll::Pending => Poll::Pending,
        }
    }

    fn progressed<R>(&mut self, result: R) -> Poll<R> {
        if let Some(since) = self.waiting_since.take() {
            self.waited += since.elapsed();
        }
        self.timer = None;
        Poll::Ready(result)
    }
}

impl<T: AsyncRead + Unpin> AsyncRead for StallGuard<T> {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        let before = buf.filled().len();
        let result = Pin::new(&mut this.io).poll_read(cx, buf);
        if matches!(result, Poll::Ready(Ok(()))) && buf.filled().len() > before {
            this.waited = Duration::ZERO;
        }
        result
    }
}

impl<T: AsyncWrite + Unpin> AsyncWrite for StallGuard<T> {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_write(cx, buf) {
            Poll::Ready(r) => this.progressed(r),
            Poll::Pending => this.blocked(cx).map(Err),
        }
    }

    fn poll_write_vectored(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bufs: &[io::IoSlice<'_>],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_write_vectored(cx, bufs) {
            Poll::Ready(r) => this.progressed(r),
            Poll::Pending => this.blocked(cx).map(Err),
        }
    }

    fn is_write_vectored(&self) -> bool {
        self.io.is_write_vectored()
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        match Pin::new(&mut this.io).poll_flush(cx) {
            Poll::Ready(r) => this.progressed(r),
            Poll::Pending => this.blocked(cx).map(Err),
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().io).poll_shutdown(cx)
    }
}

/// Serve `app` until `shutdown` resolves.
pub async fn run(
    listener: TcpListener,
    app: Router,
    http: &HttpConfig,
    shutdown: impl Future<Output = ()>,
) -> io::Result<()> {
    let graceful = GracefulShutdown::new();
    let slots = Arc::new(Semaphore::new(http.max_connections.max(1)));
    let mut connections = JoinSet::new();
    let mut shutdown = std::pin::pin!(shutdown);
    let mut builder = http1::Builder::new();
    builder
        .timer(TokioTimer::new())
        .header_read_timeout(http.header_read_timeout);
    loop {
        while connections.try_join_next().is_some() {}
        let slot = tokio::select! {
            slot = Arc::clone(&slots).acquire_owned() => slot.expect("the semaphore is never closed"),
            () = &mut shutdown => break,
        };
        let (stream, peer) = tokio::select! {
            accepted = listener.accept() => match accepted {
                Ok(conn) => conn,
                Err(e) => {
                    // Out of file descriptors and the like: don't spin.
                    tracing::warn!(error = %e, "accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
            () = &mut shutdown => break,
        };
        let _ = stream.set_nodelay(true);
        let io = TokioIo::new(StallGuard::new(
            stream,
            http.write_stall_timeout,
            http.write_budget,
        ));
        let app = app.clone();
        let service = hyper::service::service_fn(move |mut req: hyper::Request<Incoming>| {
            req.extensions_mut().insert(ConnectInfo(peer));
            app.clone().oneshot(req.map(Body::new))
        });
        let conn = graceful.watch(builder.serve_connection(io, service));
        connections.spawn(async move {
            let _ = conn.await;
            drop(slot);
        });
    }
    drop(listener);
    if tokio::time::timeout(http.drain_timeout, graceful.shutdown())
        .await
        .is_err()
    {
        tracing::warn!(
            open = connections.len(),
            "drain timed out, closing remaining connections"
        );
        connections.abort_all();
    }
    while connections.join_next().await.is_some() {}
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};

    const MIN: Duration = Duration::from_secs(60);

    #[tokio::test(start_paused = true)]
    async fn a_reader_that_stops_reading_times_out_the_writer() {
        let (near, mut far) = tokio::io::duplex(64);
        let mut guarded = StallGuard::new(near, MIN, 4 * MIN);
        guarded.write_all(&[1u8; 64]).await.unwrap();
        let mut first = [0u8; 64];
        far.read_exact(&mut first).await.unwrap();
        let t0 = Instant::now();
        let err = guarded.write_all(&[2u8; 4096]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        assert!(Instant::now() - t0 >= MIN);
    }

    #[tokio::test(start_paused = true)]
    async fn a_slow_but_steady_reader_is_fine() {
        let (near, mut far) = tokio::io::duplex(64);
        let mut guarded = StallGuard::new(near, MIN, 4 * MIN);
        let reader = tokio::spawn(async move {
            let mut total = 0;
            let mut buf = [0u8; 64];
            while total < 512 {
                tokio::time::sleep(Duration::from_secs(20)).await;
                total += far.read(&mut buf).await.unwrap();
            }
            total
        });
        guarded.write_all(&[3u8; 512]).await.unwrap();
        assert_eq!(reader.await.unwrap(), 512);
    }

    #[tokio::test(start_paused = true)]
    async fn a_trickle_reader_runs_out_of_write_budget() {
        let (near, mut far) = tokio::io::duplex(64);
        let mut guarded = StallGuard::new(near, MIN, 4 * MIN);
        // Reads a little every 50 s: never a full minute without progress.
        tokio::spawn(async move {
            let mut buf = [0u8; 8];
            loop {
                tokio::time::sleep(Duration::from_secs(50)).await;
                if far.read(&mut buf).await.unwrap_or(0) == 0 {
                    break;
                }
            }
        });
        let t0 = Instant::now();
        let err = guarded.write_all(&[4u8; 1 << 20]).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::TimedOut);
        let took = Instant::now() - t0;
        assert!(took >= 4 * MIN && took < 5 * MIN, "{took:?}");
    }

    #[tokio::test(start_paused = true)]
    async fn request_bytes_start_a_fresh_budget() {
        let (near, mut far) = tokio::io::duplex(64);
        let mut guarded = StallGuard::new(near, MIN, 2 * MIN);
        // First response: waits 90 s in total before the peer drains it.
        guarded.write_all(&[5u8; 64]).await.unwrap();
        let drain = tokio::spawn(async move {
            let mut buf = [0u8; 64];
            tokio::time::sleep(Duration::from_secs(45)).await;
            far.read_exact(&mut buf).await.unwrap();
            tokio::time::sleep(Duration::from_secs(45)).await;
            far.read_exact(&mut buf).await.unwrap();
            // The next request arrives.
            far.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
            tokio::time::sleep(Duration::from_secs(45)).await;
            far.read_exact(&mut buf).await.unwrap();
            far
        });
        guarded.write_all(&[6u8; 64]).await.unwrap();
        guarded.write_all(&[7u8; 64]).await.unwrap();
        let mut req = [0u8; 18];
        guarded.read_exact(&mut req).await.unwrap();
        // 90 s already waited would leave 30 s, and this write waits 45 s;
        // it only succeeds because the new request reset the budget.
        guarded.write_all(&[8u8; 64]).await.unwrap();
        drop(drain);
    }
}

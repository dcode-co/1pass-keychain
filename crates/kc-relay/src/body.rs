//! Request bodies, read with a size cap and a deadline.

use std::time::Duration;

use axum::body::Body;
use axum::http::{HeaderMap, header};
use bytes::{Bytes, BytesMut};
use http_body_util::BodyExt as _;

use crate::error::ApiErr;

/// Bytes that carry `guard` (budget permits, a per-client slot) until the
/// last reference to them is dropped. A response body made from these keeps
/// the guard while hyper still holds any part of the data, including frames
/// queued in its write buffer for a slow client; only then is the memory
/// really free and the budget returned.
pub fn with_guard<G: Send + 'static>(data: Bytes, guard: G) -> Bytes {
    Bytes::from_owner(Guarded {
        data,
        _guard: guard,
    })
}

struct Guarded<G> {
    data: Bytes,
    _guard: G,
}

impl<G> AsRef<[u8]> for Guarded<G> {
    fn as_ref(&self) -> &[u8] {
        &self.data
    }
}

/// Read at most `limit` bytes within `timeout`. A declared `Content-Length`
/// over the limit is refused before anything is read; a body that grows past
/// it while streaming is refused as soon as it does. Over the limit → 413;
/// malformed, aborted or too slow → 400.
pub async fn read_limited(
    body: Body,
    headers: &HeaderMap,
    limit: usize,
    timeout: Duration,
) -> Result<Bytes, ApiErr> {
    let declared = match headers.get(header::CONTENT_LENGTH) {
        None => None,
        Some(v) => Some(
            v.to_str()
                .ok()
                .and_then(|s| s.trim().parse::<u64>().ok())
                .ok_or(ApiErr::BAD_REQUEST)?,
        ),
    };
    if declared.is_some_and(|n| n > limit as u64) {
        return Err(ApiErr::TOO_LARGE);
    }
    let capacity = declared.map_or(0, |n| usize::try_from(n).unwrap_or(limit).min(limit));
    let collect = async move {
        let mut body = body;
        let mut buf = BytesMut::with_capacity(capacity);
        while let Some(frame) = body.frame().await {
            let frame = frame.map_err(|_| ApiErr::BAD_REQUEST)?;
            if let Ok(data) = frame.into_data() {
                if buf.len() + data.len() > limit {
                    return Err(ApiErr::TOO_LARGE);
                }
                buf.extend_from_slice(&data);
            }
        }
        Ok(buf.freeze())
    };
    tokio::time::timeout(timeout, collect)
        .await
        .map_err(|_| ApiErr::BAD_REQUEST)?
}

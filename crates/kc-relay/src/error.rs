//! Error responses. Every non-2xx answer is a `kc_wire::ApiError` whose HTTP
//! status is `code.http_status()`. Bodies carry only the code (and a retry
//! hint), never anything taken from the request.

use std::time::Duration;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use kc_wire::{ApiError, ErrorCode};
use serde::Serialize;

use crate::util::retry_secs;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiErr {
    pub code: ErrorCode,
    pub retry_after: Option<u32>,
}

impl ApiErr {
    pub const fn new(code: ErrorCode) -> Self {
        ApiErr {
            code,
            retry_after: None,
        }
    }

    pub fn retry(code: ErrorCode, after: Duration) -> Self {
        ApiErr {
            code,
            retry_after: Some(retry_secs(after)),
        }
    }

    pub const BAD_REQUEST: ApiErr = ApiErr::new(ErrorCode::BadRequest);
    pub const UNAUTHORIZED: ApiErr = ApiErr::new(ErrorCode::Unauthorized);
    pub const NOT_FOUND: ApiErr = ApiErr::new(ErrorCode::NotFound);
    pub const TOO_LARGE: ApiErr = ApiErr::new(ErrorCode::TooLarge);
    pub const INTERNAL: ApiErr = ApiErr::new(ErrorCode::Internal);
}

impl From<ErrorCode> for ApiErr {
    fn from(code: ErrorCode) -> Self {
        ApiErr::new(code)
    }
}

impl IntoResponse for ApiErr {
    fn into_response(self) -> Response {
        let status = StatusCode::from_u16(self.code.http_status())
            .unwrap_or(StatusCode::INTERNAL_SERVER_ERROR);
        let body = ApiError {
            code: self.code,
            retry_after_s: self.retry_after,
        };
        let mut resp = json(status, &body);
        if let Some(secs) = self.retry_after {
            resp.headers_mut()
                .insert(header::RETRY_AFTER, HeaderValue::from(secs));
        }
        resp
    }
}

/// A JSON response. Serialization of our own types can't fail in practice; if
/// it does, the client gets a bare 500.
pub fn json<T: Serialize>(status: StatusCode, value: &T) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => (
            status,
            [(
                header::CONTENT_TYPE,
                HeaderValue::from_static("application/json"),
            )],
            body,
        )
            .into_response(),
        Err(_) => StatusCode::INTERNAL_SERVER_ERROR.into_response(),
    }
}

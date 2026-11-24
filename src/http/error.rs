//! 统一错误体与状态码映射。
//!
//! 契约见 `specs/api.md`「公共约定」「状态码约定」：错误体恒为
//! `{"message":"...","request_id":"..."}`，`Content-Type` 为
//! `application/vnd.git-lfs+json`；401 额外带
//! `LFS-Authenticate: Basic realm="netdisk-lfs"`。request id 与响应头保持同值，
//! 便于客户端报障时直接对日志。

use axum::body::Body;
use axum::http::header;
use axum::http::{HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use thiserror::Error;

use super::{LFS_MEDIA_TYPE, REQUEST_ID_HEADER, RequestId};
use crate::store::StoreError;

/// 401 的认证挑战头；头名与取值由 `specs/api.md` 固定。
const AUTHENTICATE_HEADER: &str = "lfs-authenticate";
const AUTHENTICATE_CHALLENGE: &str = "Basic realm=\"netdisk-lfs\"";

/// LFS 错误体。
#[derive(Debug, Serialize)]
struct ErrorBody<'a> {
    message: &'a str,
    request_id: &'a str,
}

/// 协议层错误；每个变体对应 `specs/api.md`「状态码约定」里的一个状态码。
///
/// 只在 HTTP 边界使用：handler 里 `?` 上来后由本模块统一成 JSON 错误体，
/// 不把 `StoreError` 的 Display 直接当响应（那样会漏掉 `Content-Type` 与 request id）。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum ApiError {
    /// 400：请求体非法、oid 格式错、批次超出上限。
    #[error("{0}")]
    BadRequest(String),
    /// 401：未认证或凭据无效。
    #[error("{0}")]
    Unauthorized(String),
    /// 403：角色不足（只读账号尝试上传）。
    #[error("{0}")]
    Forbidden(String),
    /// 404：对象不存在。
    #[error("{0}")]
    NotFound(String),
    /// 422：超出单对象上限，或哈希/大小不符。
    #[error("{0}")]
    Unprocessable(String),
    /// 502：`bdpan` 调用失败。
    #[error("{0}")]
    BadGateway(String),
    /// 503：网盘不可用或 token 失效。
    #[error("{0}")]
    Unavailable(String),
    /// 500：服务端内部错误（本地 IO 等）。
    #[error("{0}")]
    Internal(String),
}

impl ApiError {
    /// 对应的 HTTP 状态码。
    pub(crate) fn status(&self) -> StatusCode {
        match self {
            Self::BadRequest(_) => StatusCode::BAD_REQUEST,
            Self::Unauthorized(_) => StatusCode::UNAUTHORIZED,
            Self::Forbidden(_) => StatusCode::FORBIDDEN,
            Self::NotFound(_) => StatusCode::NOT_FOUND,
            Self::Unprocessable(_) => StatusCode::UNPROCESSABLE_ENTITY,
            Self::BadGateway(_) => StatusCode::BAD_GATEWAY,
            Self::Unavailable(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Internal(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }

    /// 面向客户端的失败原因，同时用作日志里的错误摘要。
    pub(crate) fn message(&self) -> &str {
        match self {
            Self::BadRequest(message)
            | Self::Unauthorized(message)
            | Self::Forbidden(message)
            | Self::NotFound(message)
            | Self::Unprocessable(message)
            | Self::BadGateway(message)
            | Self::Unavailable(message)
            | Self::Internal(message) => message,
        }
    }

    /// 用请求级 id 构造错误响应；响应头与响应体里的 id 保持一致。
    ///
    /// 同时设置 `x-request-id` 响应头：外层中间件看到头已存在就保留（`or_insert`），
    /// 因此错误响应在脱离中间件的单测里也是自洽的。
    pub(crate) fn into_response_with(self, request_id: &RequestId) -> Response {
        let status = self.status();
        let body = match serde_json::to_vec(&ErrorBody {
            message: self.message(),
            request_id: request_id.as_str(),
        }) {
            Ok(body) => body,
            // 两个 `&str` 字段的序列化不会失败；真失败时退化成固定文案，
            // 但 request id 必须保留，否则客户端无从对账。
            Err(error) => {
                tracing::error!(error = %error, "序列化错误响应失败");
                format!(r#"{{"message":"internal error","request_id":"{}"}}"#, request_id.as_str())
                    .into_bytes()
            },
        };

        let mut response = Response::new(Body::from(body));
        let headers = response.headers_mut();
        headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(LFS_MEDIA_TYPE));
        if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
            headers.insert(REQUEST_ID_HEADER, value);
        }
        if matches!(self, Self::Unauthorized(_)) {
            headers.insert(AUTHENTICATE_HEADER, HeaderValue::from_static(AUTHENTICATE_CHALLENGE));
        }
        *response.status_mut() = status;
        response
    }
}

impl IntoResponse for ApiError {
    /// 兜底路径：没有请求上下文时自造一个 id，保证错误体结构永远完整。
    fn into_response(self) -> Response {
        self.into_response_with(&RequestId::generate())
    }
}

/// 存储层错误到 HTTP 状态码的映射（api.md「状态码约定」）。
///
/// 同 crate 内 `StoreError` 变体已知，match 不收 `_` 分支：将来新增变体会在此处
/// 编译失败，逼着补映射，避免新错误被悄悄归到 500。
impl From<StoreError> for ApiError {
    fn from(source: StoreError) -> Self {
        let message = source.to_string();
        match source {
            StoreError::NotFound { .. } => Self::NotFound(message),
            StoreError::HashMismatch { .. } => Self::Unprocessable(message),
            StoreError::Backend { .. } => Self::BadGateway(message),
            StoreError::Io { .. } => Self::Internal(message),
            StoreError::Unimplemented { .. } => Self::Unavailable(message),
        }
    }
}

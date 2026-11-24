//! HTTP 路由：健康检查与请求级 tracing span。
//!
//! 本阶段只有 `GET /healthz`，batch / upload / download 由后续分支加入。对象相关端点
//! 会在 span 中补充 `oid`、`bytes` 字段；这里的 span 已包含 `duration_ms` 与 `request_id`。

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::extract::Request;
use axum::http::HeaderValue;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::get;
use axum::{Json, Router};
use serde::Serialize;
use tracing::{Instrument, field, info_span};

/// 进程内请求序号，与毫秒时间戳拼成可排序的 request id。
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);
/// 回写给客户端与反向代理的请求 id 头。
const REQUEST_ID_HEADER: &str = "x-request-id";

/// 构造路由表。
pub(crate) fn router() -> Router {
    Router::new().route("/healthz", get(healthz)).layer(middleware::from_fn(request_span))
}

/// `/healthz` 响应体：`{"status":"ok"}`。
#[derive(Debug, Serialize)]
struct HealthStatus {
    status: &'static str,
}

/// 存活探针；bdpan 登录态探测留给后续分支。
async fn healthz() -> Json<HealthStatus> {
    Json(HealthStatus { status: "ok" })
}

/// 为每个请求建 span，记录状态码与耗时，并回写 `x-request-id`。
async fn request_span(request: Request, next: Next) -> Response {
    let request_id = next_request_id();
    let method = request.method().clone();
    let path = request.uri().path().to_owned();
    let span = info_span!(
        "http.request",
        request_id = %request_id,
        method = %method,
        path = %path,
        duration_ms = field::Empty,
    );

    let started = Instant::now();
    let mut response = next.run(request).instrument(span.clone()).await;
    let duration_ms = started.elapsed().as_secs_f64() * 1_000.0;
    span.record("duration_ms", duration_ms);

    if let Ok(value) = HeaderValue::from_str(&request_id) {
        response.headers_mut().insert(REQUEST_ID_HEADER, value);
    }
    span.in_scope(|| tracing::info!(status = response.status().as_u16(), "请求处理完成"));
    response
}

/// 形如 `0000018f2c3a4b5-00000042`：毫秒与序号都是定长十六进制，
/// 同进程内字符串排序与生成顺序一致，可作日志关联键。
fn next_request_id() -> String {
    let seq = REQUEST_SEQ.fetch_add(1, Ordering::Relaxed);
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis())
        .unwrap_or(0);
    format!("{millis:012x}-{seq:08x}")
}

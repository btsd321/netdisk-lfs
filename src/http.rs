//! HTTP 协议层：路由装配、请求级 span、请求 id 与共享状态。
//!
//! 端点与流程见 `specs/api.md`：既有 `GET /healthz` 保持无认证；`/lfs` 子路由统一
//! 挂 Basic 认证，`POST /lfs/objects/batch` 与后续分支的 PUT/GET/verify 都长在这条
//! 子路由下，新增端点自动继承认证。
//!
//! 分工：`auth` 负责认证与角色，`error` 负责统一错误体与状态码映射，`batch` 负责
//! 批量协商。本文件只做装配与请求级横切（span、request id）。

use std::fmt;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Instant, SystemTime, UNIX_EPOCH};

use axum::Router;
use axum::body::Body;
use axum::extract::Request;
use axum::http::HeaderValue;
use axum::http::header;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post};
use serde::Serialize;
use tracing::{Instrument, field, info_span};

use crate::config::Config;
use crate::store::ObjectStore;

mod auth;
mod batch;
mod error;

pub use error::ApiError;

/// LFS 协议媒体类型；请求与响应都用它（客户端可能附加 `; charset=utf-8`）。
pub(crate) const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";

/// 回写给客户端与反向代理的请求 id 头。
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";

/// 进程内请求序号，与毫秒时间戳拼成可排序的 request id。
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

/// 请求处理共享状态：存储后端与已校验的配置。
///
/// 两者都放在 `Arc` 里，handler 只持有轻量句柄；配置在启动后不可变，因此
/// 认证与 batch 读的是同一份快照。
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn ObjectStore>,
    config: Arc<Config>,
}

impl AppState {
    /// 用存储后端与已校验的配置构造；构造期不触发任何 IO（不会调用 `bdpan`）。
    pub fn new(store: Arc<dyn ObjectStore>, config: Arc<Config>) -> Self {
        Self { store, config }
    }

    /// 对象存储后端句柄。
    ///
    /// 返回 `Arc` 克隆而非借用：batch 需要对多个 oid 并发探测，探测任务必须
    /// 拥有自己的句柄才能 move 进 `JoinSet`。
    pub fn store(&self) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.store)
    }

    /// 运行期配置。
    pub fn config(&self) -> &Config {
        &self.config
    }
}

/// 构造路由表。
///
/// 装配顺序即请求经过顺序：请求级 span（含 request id）在最外层，之后才是
/// `/lfs` 子路由上的认证。`/healthz` 不经过认证，供探活与负载均衡使用。
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(healthz))
        .merge(lfs_router(state.clone()))
        .layer(middleware::from_fn(request_span))
        .with_state(state)
}

/// `/lfs` 子路由：认证统一挂这里，后续分支新增的 PUT/GET/verify 自动继承。
fn lfs_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/lfs/objects/batch", post(batch::handle))
        .route_layer(middleware::from_fn_with_state(state, auth::require))
}

/// `/healthz` 响应体：`{"status":"ok"}`。
#[derive(Debug, serde::Serialize)]
struct HealthStatus {
    status: &'static str,
}

/// 存活探针；`bdpan whoami` 探测留给部署分支。
async fn healthz() -> axum::Json<HealthStatus> {
    axum::Json(HealthStatus { status: "ok" })
}

/// 本次请求的服务端 id：中间件生成后放进请求扩展，handler 与错误体共用。
///
/// 错误响应会把同一个 id 同时写进响应头与响应体，方便客户端与日志对账；
/// 中间件未命中（例如直接调用 handler 的测试）时由 `generate` 兜底。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct RequestId(String);

impl RequestId {
    /// 生成一个新的服务端 id。
    pub(crate) fn generate() -> Self {
        Self(next_request_id())
    }

    /// 取字符串形式；`RequestId` 只含十六进制与连字符，可安全放进响应头。
    pub(crate) fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for RequestId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// 序列化成 LFS JSON 响应。
///
/// 不用 `axum::Json` 直接返回：后者的 `Content-Type` 是 `application/json`，
/// 而 api.md 要求 `application/vnd.git-lfs+json`。序列化失败说明响应模型不可
/// 序列化，属服务端缺陷，按 500 处理并保留同一个 request id。
pub(crate) fn json_response<T: Serialize>(value: &T, request_id: &RequestId) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = Response::new(Body::from(body));
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(LFS_MEDIA_TYPE));
            response
        },
        Err(error) => {
            tracing::error!(request_id = %request_id, error = %error, "序列化 LFS 响应失败");
            ApiError::Internal("序列化响应失败".to_owned()).into_response_with(request_id)
        },
    }
}

/// 为每个请求建 span，记录状态码与耗时，并回写 `x-request-id`。
///
/// id 一律由服务端新生成并写进请求扩展：客户端或反向代理传来的 `x-request-id`
/// **不可信**（任何人都能伪造一个与本服务日志毫无关系的 id，制造假的关联关系），
/// 这里既不读取也不回显。handler 若已显式设置响应头（例如流式响应需要先定 id），
/// 保留 handler 的值（`or_insert` 语义），否则回写服务端 id。
async fn request_span(mut request: Request, next: Next) -> Response {
    let request_id = RequestId::generate();
    request.extensions_mut().insert(request_id.clone());

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

    if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
        response.headers_mut().entry(REQUEST_ID_HEADER).or_insert(value);
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

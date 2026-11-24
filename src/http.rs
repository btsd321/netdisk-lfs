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
use axum::extract::{DefaultBodyLimit, Request};
use axum::http::HeaderValue;
use axum::http::StatusCode;
use axum::http::header;
use axum::middleware::{self, Next};
use axum::response::Response;
use axum::routing::{get, post, put};
use serde::Serialize;
use tracing::{Instrument, Span, field, info_span};

use crate::cache::Cache;
use crate::config::Config;
use crate::store::{ObjectStore, Oid};

mod auth;
mod batch;
mod error;
mod transfer;

pub use error::ApiError;
// 上传缓冲目录由 `transfer` 唯一实现（含 `data_dir` 缺省时的回退）；`main` 的启动
// 清理要清同一批目录，所以从这里导出，避免两处各推导一遍导致清理漏目录。
pub use transfer::upload_dir;

/// LFS 协议媒体类型；请求与响应都用它（客户端可能附加 `; charset=utf-8`）。
pub(crate) const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";

/// 回写给客户端与反向代理的请求 id 头。
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";

/// 进程内请求序号，与毫秒时间戳拼成可排序的 request id。
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

/// 请求处理共享状态：存储后端、已校验的配置与本地读缓存。
///
/// 三者都是轻量句柄（`Arc` / 内部 `Arc` 的 `Cache`），handler 随便 clone；配置与
/// 后端在启动后不可变，认证、batch 与传输读的都是同一份快照。
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn ObjectStore>,
    config: Arc<Config>,
    cache: Cache,
}

impl AppState {
    /// 用存储后端与已校验的配置构造，并按 `[cache]` 建一个索引为空的缓存。
    ///
    /// 只给测试与嵌入用法（不扫描目录、不做启动清理）。生产启动走
    /// [`Self::with_cache`]：`main` 先 [`Cache::open`] 重建索引、[`Cache::sweep`]
    /// 清理残留，再把同一个缓存交给路由，否则磁盘上已有的缓存对象既不知道大小、
    /// 也进不了 LRU。
    pub fn new(store: Arc<dyn ObjectStore>, config: Arc<Config>) -> Self {
        let cache = Cache::empty(&config.cache);
        Self::with_cache(store, config, cache)
    }

    /// 注入已扫描、已清理的缓存；`main` 的启动路径用这个。
    pub fn with_cache(store: Arc<dyn ObjectStore>, config: Arc<Config>, cache: Cache) -> Self {
        Self { store, config, cache }
    }

    /// 对象存储后端句柄。
    ///
    /// 返回 `Arc` 克隆而非借用：batch 需要对多个 oid 并发探测，传输端点要把句柄
    /// move 进单飞下载的 future，两者都必须拥有自己的句柄。
    pub fn store(&self) -> Arc<dyn ObjectStore> {
        Arc::clone(&self.store)
    }

    /// 运行期配置。
    pub fn config(&self) -> &Config {
        &self.config
    }

    /// 本地读缓存。
    pub fn cache(&self) -> &Cache {
        &self.cache
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
    // 对象内容端点按配置放开请求体上限；axum 默认 2 MiB，不放开会让 4 GiB 对象
    // 在框架层就被截断。batch 单独一条路由，继续受默认 2 MiB 保护（它的 body 只是
    // 一次 JSON 协商，不该有 MB 级体积）。
    //
    // 该层只对走提取器（`Bytes`/`Json` 等）的 handler 生效；`transfer::put` 直接消费
    // `Body` 流，真正的逐块上限由它按同一个 `max_object_bytes` 计数并返回 422，
    // 两层上限取同一份配置，不会出现「框架放行、业务拒绝」口径不一。
    let body_limit =
        DefaultBodyLimit::max(body_limit_bytes(state.config().storage.max_object_bytes));
    Router::new()
        .route("/lfs/objects/batch", post(batch::handle))
        .route("/lfs/objects/{oid}", put(transfer::put).get(transfer::get).layer(body_limit))
        .route("/lfs/objects/{oid}/verify", post(transfer::verify))
        .route_layer(middleware::from_fn_with_state(state, auth::require))
}

/// 把 `max_object_bytes` 换成 axum 请求体上限的 `usize`。
///
/// 服务器是 64 位，4 GiB 的默认上限可以精确表示；32 位平台装不下时退化为
/// `usize::MAX`，此时业务层按 `u64` 计数仍会先于框架拒绝。
fn body_limit_bytes(max_object_bytes: u64) -> usize {
    usize::try_from(max_object_bytes).unwrap_or(usize::MAX)
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

/// 传输 span 的 `outcome`：请求成功完成。
pub(crate) const OUTCOME_OK: &str = "ok";
/// 4xx：客户端可纠正（oid 非法、哈希不符、超限、未找到、角色不足）。
pub(crate) const OUTCOME_REJECTED: &str = "rejected";
/// 5xx：服务端或存储后端失败。
pub(crate) const OUTCOME_FAILED: &str = "failed";
/// 客户端中途断开或 future 被取消，没走完正常返回路径。
pub(crate) const OUTCOME_ABORTED: &str = "aborted";

/// 按 HTTP 状态码归类 `outcome`，避免每个 handler 各写一份 match。
pub(crate) fn outcome_for_status(status: StatusCode) -> &'static str {
    if status.is_success() {
        OUTCOME_OK
    } else if status.is_client_error() {
        OUTCOME_REJECTED
    } else {
        OUTCOME_FAILED
    }
}

/// 传输 handler 的耗时/结果守卫：Drop 时记录 `duration_ms` 与 `outcome`，并补发完成事件。
///
/// 为什么用 Drop 而不是在返回路径上直接 record：客户端中途断开时 axum 会丢弃
/// handler future，返回路径上的代码不会执行；只有 Drop 能兜底，把这次请求记为
/// `aborted` 并留下已传输字节数，否则日志里会出现「请求开始但永不结束」的黑洞。
///
/// 正常结束必须调用 [`Self::finish`]：初始 outcome 是 `aborted`，不覆盖就会被
/// 误记成中断。
pub(crate) struct DurationGuard {
    span: Span,
    started: Instant,
    outcome: &'static str,
}

impl DurationGuard {
    /// 绑定一个已建好的 span；初始 outcome 为 `aborted`。
    pub(crate) fn new(span: Span) -> Self {
        Self { span, started: Instant::now(), outcome: OUTCOME_ABORTED }
    }

    /// span 句柄，供 handler 补记 `oid` 等本层才知道的字段。
    pub(crate) fn span(&self) -> &Span {
        &self.span
    }

    /// 记录当前已处理的字节数；可重复调用，span 里保留最新值。
    ///
    /// 边收边记而不是结束时一次性记：future 被丢弃时也要留下已传输的量，
    /// 否则大对象传到一半断连只会看到 `bytes` 缺失。
    pub(crate) fn record_bytes(&self, bytes: u64) {
        self.span.record("bytes", bytes);
    }

    /// 正常结束：设置 outcome，随后由 Drop 统一落耗时与完成事件。
    pub(crate) fn finish(mut self, outcome: &'static str) {
        self.outcome = outcome;
    }
}

impl Drop for DurationGuard {
    fn drop(&mut self) {
        let duration_ms = self.started.elapsed().as_secs_f64() * 1_000.0;
        self.span.record("duration_ms", duration_ms);
        self.span.record("outcome", self.outcome);
        // fmt layer 只在事件发生时渲染 span 字段：record 之后必须再发一条事件，
        // 否则 duration_ms/outcome 不会落盘（B4 已踩过这个坑）。
        self.span.in_scope(|| tracing::info!(outcome = self.outcome, "传输处理结束"));
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

/// 对象内容端点（PUT 上传 / GET 下载）的相对路径。
///
/// batch 下发的 `href` 与 transfer 注册的路由必须同源，否则客户端会拿着一个
/// 本服务没有的地址去传输。两个助手集中在本模块，路由装配与 batch 协商都从这里取。
pub(crate) fn object_href(oid: &Oid) -> String {
    format!("/lfs/objects/{oid}")
}

/// 上传后校验端点的相对路径。
pub(crate) fn verify_href(oid: &Oid) -> String {
    format!("/lfs/objects/{oid}/verify")
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

#[cfg(test)]
mod tests {
    use axum::http::StatusCode;

    use super::{
        OUTCOME_FAILED, OUTCOME_OK, OUTCOME_REJECTED, object_href, outcome_for_status, verify_href,
    };
    use crate::store::Oid;

    fn oid() -> Oid {
        Oid::parse(&"0123456789abcdef".repeat(4)).expect("合法 oid")
    }

    #[test]
    fn given_status_code_when_outcome_for_status_then_classified_by_class() {
        assert_eq!(outcome_for_status(StatusCode::OK), OUTCOME_OK);
        assert_eq!(outcome_for_status(StatusCode::NOT_FOUND), OUTCOME_REJECTED);
        assert_eq!(outcome_for_status(StatusCode::UNPROCESSABLE_ENTITY), OUTCOME_REJECTED);
        assert_eq!(outcome_for_status(StatusCode::BAD_GATEWAY), OUTCOME_FAILED);
    }

    #[test]
    fn given_oid_when_hrefs_then_relative_paths() {
        let oid = oid();

        assert_eq!(object_href(&oid), format!("/lfs/objects/{oid}"));
        assert_eq!(verify_href(&oid), format!("/lfs/objects/{oid}/verify"));
        assert!(object_href(&oid).starts_with('/'), "href 必须是相对路径");
    }

    #[test]
    fn given_uppercase_oid_when_href_then_normalized_lowercase() {
        let raw = "ABCDEF01".repeat(8);
        let oid = Oid::parse(&raw).expect("合法 oid");

        assert_eq!(object_href(&oid), format!("/lfs/objects/{}", raw.to_lowercase()));
        assert!(verify_href(&oid).ends_with("/verify"));
    }
}

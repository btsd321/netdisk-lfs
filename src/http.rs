//! HTTP 协议层：路由装配、请求级 span、请求 id 与共享状态。
//!
//! 端点与流程见 `specs/api.md`：`GET /healthz` 与 `GET /metrics` 保持无认证（前者给
//! 探针，后者只在本机被抓取）；`/lfs` 子路由统一挂 Basic 认证，batch 与 PUT/GET/verify
//! 都长在这条子路由下，新增端点自动继承认证。
//!
//! 分工：`auth` 负责认证与角色，`admin` 负责管理员账户管理（JSON API + HTML 页），
//! `html` 负责极简页面的外壳/转义/表单解析，`error` 负责统一错误体与状态码映射，
//! `batch` 负责批量协商，`health` 负责 `bdpan` 探活与降级判定，`metrics` 负责
//! Prometheus 文本。本文件只做装配与请求级横切（span、request id）。

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
use axum::routing::{delete, get, patch, post, put};
use serde::Serialize;
use tracing::{Instrument, Span, field, info_span};

use crate::accounts::UserStore;
use crate::cache::Cache;
use crate::config::{Config, Role};
use crate::store::{ObjectStore, Oid};

mod account;
mod admin;
mod auth;
mod batch;
mod error;
mod health;
mod html;
mod limits;
mod metrics;
mod passwords;
mod register;
mod transfer;

use limits::{LOGIN_WINDOW, REGISTRATION_WINDOW, SlidingWindowLimiter};

pub use error::ApiError;
pub use health::{BdpanProbe, BdpanState, PROBE_TIMEOUT, PROBE_TTL};
// 上传缓冲目录由 `transfer` 唯一实现（含 `data_dir` 缺省时的回退）；`main` 的启动
// 清理要清同一批目录，所以从这里导出，避免两处各推导一遍导致清理漏目录。
pub use transfer::upload_dir;

/// LFS 协议媒体类型；请求与响应都用它（客户端可能附加 `; charset=utf-8`）。
pub(crate) const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";

/// 账户库未接入（`accounts: None`）时 `/account/*` 的 503 文案。
pub(crate) const ACCOUNTS_NOT_CONFIGURED_MESSAGE: &str =
    "账户库未启用：本实例没有接入 [accounts]，注册与账户管理端点不可用";

/// `[auth.users]` 里与 `name` 同名的条目（大小写不敏感），返回配置里的写法。
///
/// 账户库优先之后，config 里的同名条目就是「同一个人的另一个入口」：自助注册要拒
/// 它（否则能把引导管理员顶掉），管理端删除要先移走它（否则删库行会让旧口令复活）。
pub(crate) fn config_username<'a>(config: &'a Config, name: &str) -> Option<&'a str> {
    config
        .auth
        .users
        .keys()
        .find(|candidate| candidate.eq_ignore_ascii_case(name))
        .map(String::as_str)
}

/// 配置文件里**除 `name` 本人之外**的 active 管理员数量。
///
/// `[auth.users]` 在启动后不可变，这个数字可以在事务外算好再传给账户库：账户库的
/// 「最后一个管理员」判定把它当作数据库之外的兜底管理员，避免把「config 里还有别的
/// 管理员」的合法降级/删除也拒掉。同名条目不算（那是同一个人）。
pub(crate) fn config_admin_fallback(config: &Config, name: &str) -> u64 {
    let count = config
        .auth
        .users
        .iter()
        .filter(|(candidate, user)| {
            user.role == Role::Admin && !candidate.eq_ignore_ascii_case(name)
        })
        .count();
    u64::try_from(count).unwrap_or(u64::MAX)
}

/// 账户库已接入但读写失败（磁盘、锁、库损坏）时的 503 文案。
///
/// 与 [`ACCOUNTS_NOT_CONFIGURED_MESSAGE`] 分开：一个说「这个实例没配账户库」，
/// 一个说「配了但暂时用不了」，运维看到后该查的方向完全不同。
pub(crate) const ACCOUNTS_UNAVAILABLE_MESSAGE: &str = "账户库暂时不可用，请稍后重试";

/// 回写给客户端与反向代理的请求 id 头。
pub(crate) const REQUEST_ID_HEADER: &str = "x-request-id";

/// 进程内请求序号，与毫秒时间戳拼成可排序的 request id。
static REQUEST_SEQ: AtomicU64 = AtomicU64::new(0);

/// 请求处理共享状态：存储后端、已校验的配置、本地读缓存与 `bdpan` 探活器。
///
/// 都是轻量句柄（`Arc` / 内部 `Arc` 的 `Cache`），handler 随便 clone；配置与后端在
/// 启动后不可变，认证、batch、传输与探活读的都是同一份快照。
#[derive(Clone)]
pub struct AppState {
    store: Arc<dyn ObjectStore>,
    config: Arc<Config>,
    cache: Cache,
    /// `/healthz` 的 `bdpan` 探活器；`None` 表示未注入（嵌入用法/测试），此时
    /// `/healthz` 按不可用报降级，不谎报健康。
    probe: Option<Arc<BdpanProbe>>,
    /// SQLite 账户库；`None` 表示未接入（嵌入用法/既有测试），此时认证只查
    /// `[auth.users]`，`/account/*` 一律 503。
    accounts: Option<Arc<UserStore>>,
    /// 登录失败限速（按小写用户名）与注册限速（按来源地址）；进程内状态，重启清零。
    login_limits: Arc<SlidingWindowLimiter>,
    register_limits: Arc<SlidingWindowLimiter>,
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
        Self {
            store,
            config,
            cache,
            probe: None,
            accounts: None,
            login_limits: Arc::new(SlidingWindowLimiter::new(LOGIN_WINDOW)),
            register_limits: Arc::new(SlidingWindowLimiter::new(REGISTRATION_WINDOW)),
        }
    }

    /// 在已装配的 state 上注入账户库；`main` 的启动路径用这个。
    ///
    /// 与 [`Self::with_bdpan_probe`] 一样是可选注入：不注入时认证退回「只认
    /// `[auth.users]`」的旧行为，既有测试与嵌入用法不需要改。
    pub fn with_account_store(mut self, users: Arc<UserStore>) -> Self {
        self.accounts = Some(users);
        self
    }

    /// 构造一个接入了账户库的 state（空缓存、无探活）；测试与嵌入用法用这个。
    pub fn with_accounts(
        store: Arc<dyn ObjectStore>,
        config: Arc<Config>,
        users: Arc<UserStore>,
    ) -> Self {
        Self::new(store, config).with_account_store(users)
    }

    /// 注入 `bdpan` 探活器；`main` 在启动时接上它，`/healthz` 才会真的探测登录态。
    ///
    /// 不放进构造函数：探活要真起 `bdpan` 子进程，只有真正对外服务的进程（`main`）
    /// 才应该有这个副作用；测试与嵌入用法默认不探测。
    pub fn with_bdpan_probe(mut self, probe: Arc<BdpanProbe>) -> Self {
        self.probe = Some(probe);
        self
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

    /// `bdpan` 探活器；未注入时为 `None`。
    pub fn bdpan_probe(&self) -> Option<&BdpanProbe> {
        self.probe.as_deref()
    }

    /// 账户库；未接入时为 `None`（此时 `/account/*` 返回 503，认证只查配置）。
    pub fn accounts(&self) -> Option<&UserStore> {
        self.accounts.as_deref()
    }

    /// 登录失败限速器；认证中间件用它按用户名计数。
    pub(crate) fn login_limits(&self) -> &SlidingWindowLimiter {
        &self.login_limits
    }

    /// 注册限速器；注册端点用它按来源地址计数。
    pub(crate) fn register_limits(&self) -> &SlidingWindowLimiter {
        &self.register_limits
    }
}

/// 构造路由表。
///
/// 装配顺序即请求经过顺序：请求级 span（含 request id）在最外层，之后才是
/// `/lfs` 子路由上的认证。`/healthz` 与 `/metrics` 不经过认证：前者给探针用，
/// 后者只在本机被 Prometheus 抓取（对外暴露必须在反代上加 ACL，见 `metrics` 模块）。
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/healthz", get(health::healthz))
        .route("/metrics", get(metrics::metrics))
        .merge(register_router())
        .merge(account_router(state.clone()))
        .merge(admin_router(state.clone()))
        .merge(lfs_router(state.clone()))
        .layer(middleware::from_fn(request_span))
        .with_state(state)
}

/// 公开的注册路由：注册页与注册提交都不需要认证（否则没人能注册）。
fn register_router() -> Router<AppState> {
    Router::new().route("/account/register", get(register::page).post(register::submit))
}

/// 登录后的自身账户路由：单独一条受保护子路由，不并进 `/lfs`，避免 LFS 端点
/// 将来加路径级例外时误伤账户端点。
fn account_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/account/me", get(account::me))
        .route("/account/password", post(account::change_password))
        .route("/account", delete(account::delete_self))
        .route_layer(middleware::from_fn_with_state(state, auth::require))
}

/// 管理员路由：JSON API 与 HTML 管理页共用一条受保护子路由。
///
/// 两层层按「后注册的在外层」包裹：先 `auth::require` 认人，再
/// `admin::require_admin` 判角色——判角色只读扩展，不重复解析凭据。
fn admin_router(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/admin", get(admin::page))
        .route("/admin/users", get(admin::list).post(admin::create))
        .route("/admin/users/{name}", patch(admin::patch).delete(admin::delete))
        .route("/admin/users/{name}/password", post(admin::reset_password))
        // 以下为 HTML 管理页的便捷端点：只解析表单、复用上面同一套逻辑，成功后 303。
        .route("/admin/users/{name}/approve", post(admin::approve))
        .route("/admin/users/{name}/disable", post(admin::disable))
        .route("/admin/users/{name}/enable", post(admin::enable))
        .route("/admin/users/{name}/role", post(admin::role_form))
        .route("/admin/users/{name}/password-form", post(admin::password_form))
        .route("/admin/users/{name}/delete", post(admin::delete_form))
        .route_layer(middleware::from_fn(admin::require_admin))
        .route_layer(middleware::from_fn_with_state(state, auth::require))
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
    let max_object_bytes = state.config().storage.max_object_bytes;
    // `0` = 不限制：彻底关掉框架层限制（业务层也不再计数拒绝）。
    let body_limit = if max_object_bytes == 0 {
        DefaultBodyLimit::disable()
    } else {
        DefaultBodyLimit::max(body_limit_bytes(max_object_bytes))
    };
    Router::new()
        .route("/lfs/objects/batch", post(batch::handle))
        .route("/lfs/objects/{oid}", put(transfer::put).get(transfer::get).layer(body_limit))
        .route("/lfs/objects/{oid}/verify", post(transfer::verify))
        .route_layer(middleware::from_fn_with_state(state, auth::require))
}

/// 把 `max_object_bytes` 换成 axum 请求体上限的 `usize`。
///
/// 调用方已把 `0`（不限制）路由到 [`DefaultBodyLimit::disable`]；64 位平台可精确
/// 表示到 `u64::MAX` 的一半，32 位平台装不下时退化为 `usize::MAX`，业务层按 `u64`
/// 计数仍会先于框架拒绝。
fn body_limit_bytes(max_object_bytes: u64) -> usize {
    usize::try_from(max_object_bytes).unwrap_or(usize::MAX)
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
    json_body(StatusCode::OK, LFS_MEDIA_TYPE, value, request_id)
}

/// 账户类端点的 JSON 响应：`application/json`（不是 LFS 媒体类型），带请求 id。
pub(crate) fn json_with_status<T: Serialize>(
    status: StatusCode,
    value: &T,
    request_id: &RequestId,
) -> Response {
    json_body(status, "application/json", value, request_id)
}

/// 统一的 JSON 序列化出口：状态码与媒体类型由调用方给，错误路径共用同一套处理。
fn json_body<T: Serialize>(
    status: StatusCode,
    content_type: &'static str,
    value: &T,
    request_id: &RequestId,
) -> Response {
    match serde_json::to_vec(value) {
        Ok(body) => {
            let mut response = Response::new(Body::from(body));
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(content_type));
            if let Ok(value) = HeaderValue::from_str(request_id.as_str()) {
                response.headers_mut().insert(REQUEST_ID_HEADER, value);
            }
            *response.status_mut() = status;
            response
        },
        Err(error) => {
            tracing::error!(request_id = %request_id, error = %error, "序列化 JSON 响应失败");
            ApiError::Internal("序列化响应失败".to_owned()).into_response_with(request_id)
        },
    }
}

/// action URL 的基地址：优先配置的 `public_base`，否则按请求头推导。
///
/// **git-lfs 3.4.1 实测拒绝相对 href**（报 `missing protocol: "/lfs/objects/..."`），
/// 所以 batch 必须下发绝对 URL。反代场景要求代理透传 `Host` 与
/// `X-Forwarded-Proto`（Caddy 的 reverse_proxy 默认会传）；`public_base` 非空时
/// 直接用它，适合反代改写了主机名或端口的情形。
pub(crate) fn action_base(config: &Config, headers: &axum::http::HeaderMap) -> String {
    let configured = config.server.public_base.trim_end_matches('/');
    if !configured.is_empty() {
        return configured.to_owned();
    }
    // scheme 大小写不敏感（RFC 3986 §3.1），代理可能发 "HTTPS"/"Https"；
    // 逗号列表取第一个（多级代理会追加）。
    let proto = headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .map(|value| value.split(',').next().unwrap_or(value).trim())
        .filter(|value| value.eq_ignore_ascii_case("http") || value.eq_ignore_ascii_case("https"))
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "http".to_owned());
    let host = headers
        .get(header::HOST)
        .and_then(|value| value.to_str().ok())
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .unwrap_or_else(|| fallback_authority(config));
    format!("{proto}://{host}")
}

/// 没有 Host 头时的兜底 authority：取监听地址，至少要带端口。
///
/// 监听在通配地址（0.0.0.0 / [::]）时换成本机回环——`0.0.0.0:9001` 作为 URL 主机
/// 不可连接，而回环在直连场景下至少可达。
fn fallback_authority(config: &Config) -> String {
    let listen = config.server.listen;
    if listen.ip().is_unspecified() {
        format!("127.0.0.1:{}", listen.port())
    } else {
        listen.to_string()
    }
}

/// 对象内容端点（PUT 上传 / GET 下载）的绝对 URL。
///
/// batch 下发的 `href` 与 transfer 注册的路由必须同源，否则客户端会拿着一个
/// 本服务没有的地址去传输。两个助手集中在本模块，路由装配与 batch 协商都从这里取。
pub(crate) fn object_href(base: &str, oid: &Oid) -> String {
    format!("{base}/lfs/objects/{oid}")
}

/// 上传后校验端点的绝对 URL。
pub(crate) fn verify_href(base: &str, oid: &Oid) -> String {
    format!("{base}/lfs/objects/{oid}/verify")
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
        OUTCOME_FAILED, OUTCOME_OK, OUTCOME_REJECTED, action_base, object_href, outcome_for_status,
        verify_href,
    };
    use crate::config::{
        AccountsConfig, AuthConfig, CacheConfig, Config, RuntimeEnv, ServerConfig, StorageConfig,
    };
    use crate::store::Oid;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    fn test_config(public_base: &str, listen: &str) -> Config {
        Config {
            server: ServerConfig {
                listen: listen.parse().expect("合法监听地址"),
                public_base: public_base.to_owned(),
            },
            storage: StorageConfig {
                objects_root: "/apps/bdpan/lfs".to_owned(),
                tmp_root: "/apps/bdpan/lfs/tmp".to_owned(),
                bdpan_bin: "/bin/true".into(),
                max_object_bytes: 1024,
                max_bdpan_procs: 1,
                bdpan_timeout_secs: 300,
                bdpan_min_throughput_bytes_per_sec: 102_400,
            },
            cache: CacheConfig { dir: std::env::temp_dir(), max_bytes: 0 },
            accounts: AccountsConfig {
                db: std::env::temp_dir().join("netdisk-lfs-http-tests-accounts.db"),
                ..AccountsConfig::default()
            },
            auth: AuthConfig::default(),
            runtime_env: RuntimeEnv::Dev,
            data_dir: None,
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("头名合法"),
                HeaderValue::from_str(value).expect("头值合法"),
            );
        }
        map
    }

    fn oid() -> Oid {
        Oid::parse(&"0123456789abcdef".repeat(4)).expect("合法 oid")
    }

    #[test]
    fn given_headers_when_action_base_then_derivation_edges_covered() {
        // public_base 优先，并去掉尾斜杠。
        assert_eq!(
            action_base(
                &test_config("https://lfs.example.com/", "127.0.0.1:9001"),
                &HeaderMap::new()
            ),
            "https://lfs.example.com"
        );
        // 只有 Host：默认 http。
        assert_eq!(
            action_base(&test_config("", "127.0.0.1:9001"), &headers(&[("host", "lfs.test")])),
            "http://lfs.test"
        );
        // scheme 大小写不敏感（RFC 3986），代理可能发 HTTPS/Https。
        assert_eq!(
            action_base(
                &test_config("", "127.0.0.1:9001"),
                &headers(&[("host", "lfs.test"), ("x-forwarded-proto", "HTTPS")])
            ),
            "https://lfs.test"
        );
        // 多级代理的逗号列表取第一个有效值。
        assert_eq!(
            action_base(
                &test_config("", "127.0.0.1:9001"),
                &headers(&[("host", "lfs.test"), ("x-forwarded-proto", "https, http")])
            ),
            "https://lfs.test"
        );
        // 不认识的 scheme 回退 http，不把错误值塞进 URL。
        assert_eq!(
            action_base(
                &test_config("", "127.0.0.1:9001"),
                &headers(&[("host", "lfs.test"), ("x-forwarded-proto", "h2")])
            ),
            "http://lfs.test"
        );
        // 没有 Host：用监听地址兜底，且必须带端口（直接本机访问可达）。
        assert_eq!(
            action_base(&test_config("", "127.0.0.1:9001"), &HeaderMap::new()),
            "http://127.0.0.1:9001"
        );
        // 监听通配地址时换环回，0.0.0.0 作为 URL 主机不可连接。
        assert_eq!(
            action_base(&test_config("", "0.0.0.0:9001"), &HeaderMap::new()),
            "http://127.0.0.1:9001"
        );
    }

    #[test]
    fn given_status_code_when_outcome_for_status_then_classified_by_class() {
        assert_eq!(outcome_for_status(StatusCode::OK), OUTCOME_OK);
        assert_eq!(outcome_for_status(StatusCode::NOT_FOUND), OUTCOME_REJECTED);
        assert_eq!(outcome_for_status(StatusCode::UNPROCESSABLE_ENTITY), OUTCOME_REJECTED);
        assert_eq!(outcome_for_status(StatusCode::BAD_GATEWAY), OUTCOME_FAILED);
    }

    #[test]
    fn given_base_when_hrefs_then_absolute_urls() {
        let oid = oid();
        let base = "http://127.0.0.1:9001";

        assert_eq!(object_href(base, &oid), format!("{base}/lfs/objects/{oid}"));
        assert_eq!(verify_href(base, &oid), format!("{base}/lfs/objects/{oid}/verify"));
        // git-lfs 3.4.1 拒绝相对 href（missing protocol），必须带 scheme。
        assert!(object_href(base, &oid).starts_with("http://"));
    }

    #[test]
    fn given_uppercase_oid_when_href_then_normalized_lowercase() {
        let raw = "ABCDEF01".repeat(8);
        let oid = Oid::parse(&raw).expect("合法 oid");
        let base = "https://lfs.example.com";

        assert_eq!(object_href(base, &oid), format!("{base}/lfs/objects/{}", raw.to_lowercase()));
        assert!(verify_href(base, &oid).ends_with("/verify"));
    }
}

//! `/healthz`：进程存活、`bdpan` 登录态与缓存可用性。
//!
//! 契约见 `specs/api.md`「端点」与 `specs/architecture.md`「失败模式」：token 失效或
//! 网盘不可用必须能被探针发现，所以**`bdpan` 一降级就回 503**，探针（systemd、
//! Caddy、Uptime Kuma）不必解析响应体也能触发告警。`status=ok` 才回 200。
//!
//! `cache_enabled=false`（缓存目录不可用、已降级为直通）只上报、**不**触发 503：
//! 缓存只是加速层，关掉后每个请求都回源，响应依然正确。把性能降级算成 503 会让
//! 负载均衡/编排系统把还能干活的节点摘掉，反而放大故障。
//!
//! 三条设计要点：
//!
//! - **探活结果按 TTL 缓存**：健康探针可能每几秒打一次，每次 `bdpan whoami` 都起一个
//!   子进程既浪费也会占用并发许可。结果（含失败结论）缓存 [`PROBE_TTL`]，期间直接
//!   复用；失败也必须缓存，否则故障期间每个探针都会起一个注定失败的子进程。
//! - **降级 ≠ 不可用**：token 失效只影响**回源**（batch 探测、PUT、缓存未命中的 GET），
//!   本地缓存命中的 GET 仍然正常返回。所以 `/healthz` 的 503 是「需要人处理」的告警，
//!   不是「服务已死」——缓存仍可读这条性质由缓存层保证，本模块不改变它。
//! - **不挂认证**：探针与反向代理没有 LFS 账号，本端点必须留在 `/lfs` 认证层之外。

use std::time::{Duration, Instant};

use axum::Json;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use tokio::sync::Mutex;
use tracing::warn;

use crate::bdpan::{BdpanClient, BdpanClientConfig, BdpanError, RetryPolicy};
use crate::config::StorageConfig;
use crate::http::AppState;

/// 探活结论的复用时长。
///
/// 30s 是「故障发现延迟」与「子进程开销」的折中：探针通常 10~30s 一次，30s 的 TTL
/// 让正常时段平均每分钟最多 2 次 `whoami`，异常时也能在半分钟内暴露。
pub const PROBE_TTL: Duration = Duration::from_secs(30);

/// 单次探活的超时。
///
/// 独立于业务命令的 600s 默认超时：`/healthz` 必须在几秒内给出结论，探针不能陪大上传
/// 一起等。配合 [`RetryPolicy::none`]，最坏耗时就是这一个超时。
pub const PROBE_TIMEOUT: Duration = Duration::from_secs(15);

/// `bdpan` 侧的登录态结论。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum BdpanState {
    /// `bdpan whoami` 成功：token 有效、CLI 可执行。
    Ok,
    /// 登录态失效（token 过期/被吊销）：需要人工重新 `bdpan login`。
    AuthFailed,
    /// 其余失败：CLI 缺失/无执行权限、网盘不可达、输出无法解析等。
    Unavailable,
}

impl BdpanState {
    /// 响应体与日志里用的固定字面量（`specs/api.md` 只认这三个值）。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Ok => "ok",
            Self::AuthFailed => "auth_failed",
            Self::Unavailable => "unavailable",
        }
    }

    /// 是否健康（只有 `ok` 算健康）。
    pub fn is_healthy(self) -> bool {
        matches!(self, Self::Ok)
    }
}

/// `bdpan` 探活器：`whoami` + TTL 缓存。
///
/// 内部用独立的 [`BdpanClient`]（自带信号量），不排在业务上传/下载后面——否则 4 个
/// 在途大对象就能让 `/healthz` 一直等到 600s 超时。代价是极端情况下比
/// `max_bdpan_procs` 多一个子进程，由互斥锁保证同一时刻最多一个。
pub struct BdpanProbe {
    client: BdpanClient,
    ttl: Duration,
    /// 上一次探活的结论与发生时刻；`None` 表示本次进程还没探过。
    ///
    /// 用 `tokio::sync::Mutex` 而不是 `std::sync::Mutex`：这里要跨 `whoami().await`
    /// 持锁，把并发的探针合并成一次子进程调用（`docs/rust-style.md` 第 8 节）。
    cached: Mutex<Option<(Instant, BdpanState)>>,
}

impl BdpanProbe {
    /// 按 `[storage]` 配置构造：沿用 `bdpan_bin` 与并发上限，换成探活专用超时与不重试。
    pub fn from_storage(storage: &StorageConfig) -> Self {
        let client = BdpanClient::new(
            BdpanClientConfig::from_storage(storage)
                .with_timeout(PROBE_TIMEOUT)
                // 探针不重试：1s/4s/16s 的退避会把一次「不可用」拖到 21 秒，探针要的是快。
                .with_retry(RetryPolicy::none()),
        );
        Self::new(client, PROBE_TTL)
    }

    /// 用给定客户端与 TTL 构造（测试注入桩 `bdpan` 时用）。
    pub fn new(client: BdpanClient, ttl: Duration) -> Self {
        Self { client, ttl, cached: Mutex::new(None) }
    }

    /// 结论复用时长。
    pub fn ttl(&self) -> Duration {
        self.ttl
    }

    /// 取当前结论：缓存还新鲜就直接返回，否则真的跑一次 `bdpan whoami`。
    ///
    /// 失败只记 warn 并归类成 [`BdpanState`]，绝不向上抛错：探活失败是**被观测到**
    /// 的事实，不是 `/healthz` 自身的错误。
    pub async fn check(&self) -> BdpanState {
        // 持锁做探活：并发探针在锁上排队，拿到锁后看到新鲜结论直接返回，
        // 不会出现「一次故障被 N 个探针各起一个子进程」的放大。
        let mut cached = self.cached.lock().await;
        if let Some((at, state)) = *cached
            && at.elapsed() < self.ttl
        {
            return state;
        }

        let state = match self.client.whoami().await {
            Ok(()) => BdpanState::Ok,
            Err(error) if error.is_auth() => {
                // 只记分类，不回显 CLI 输出：`whoami` 的数据可能带账号凭据
                // （`BdpanClient::whoami` 的契约）。
                warn!(
                    state = BdpanState::AuthFailed.as_str(),
                    "bdpan 探活失败：登录态失效，需重新登录"
                );
                BdpanState::AuthFailed
            },
            Err(error) => {
                warn!(state = BdpanState::Unavailable.as_str(), error = %describe(&error), "bdpan 探活失败");
                BdpanState::Unavailable
            },
        };
        *cached = Some((Instant::now(), state));
        state
    }
}

/// 日志里的失败描述：去掉可能含凭据的原始文案，只留命令名与分类。
fn describe(error: &BdpanError) -> String {
    match error {
        BdpanError::Timeout { command, timeout } => {
            format!("{command} 超过 {}s 未结束", timeout.as_secs())
        },
        BdpanError::Spawn { command, .. } => format!("{command} 无法启动（检查 bdpan_bin 与权限）"),
        BdpanError::Decode { command, .. } | BdpanError::Exit { command, .. } => {
            format!("{command} 输出无法解析")
        },
        other => other.to_string(),
    }
}

/// `/healthz` 响应体；字段名即契约（`specs/api.md`）。
#[derive(Debug, Serialize)]
struct HealthBody {
    /// `ok` 或 `degraded`。
    status: &'static str,
    /// `ok` / `auth_failed` / `unavailable`。
    bdpan: &'static str,
    /// 缓存是否可用；`false` 表示启动扫描失败、已降级为直通。
    ///
    /// 只上报不判定：缓存不可用只影响性能（每个请求回源），不影响正确性，
    /// 因此不参与 `status` 与状态码（理由见模块文档）。
    cache_enabled: bool,
}

/// 健康检查：进程活着就一定能回包，但**后端不可用时回 503**。
pub(crate) async fn healthz(State(state): State<AppState>) -> Response {
    let bdpan = match state.bdpan_probe() {
        Some(probe) => probe.check().await,
        // 没有注入探针（嵌入用法/测试）：宁可误报降级，也不谎报健康。
        None => BdpanState::Unavailable,
    };
    let healthy = bdpan.is_healthy();
    let body = HealthBody {
        status: if healthy { "ok" } else { "degraded" },
        bdpan: bdpan.as_str(),
        cache_enabled: state.cache().is_enabled(),
    };
    let status = if healthy { StatusCode::OK } else { StatusCode::SERVICE_UNAVAILABLE };
    (status, Json(body)).into_response()
}

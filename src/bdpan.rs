//! `bdpan` CLI 子进程封装，以及基于它的网盘 [`ObjectStore`](crate::store::ObjectStore)。
//!
//! 存储通道唯一：对象只能经由 `bdpan` 子进程读写（见 `AGENTS.md`）。本模块把「起进程、
//! 超时、并发限流、指数退避重试、stdout JSON 容错解析、业务错误分类」收在一处，
//! handler 与缓存层都不必再直接碰 [`tokio::process::Command`]。
//!
//! 分工：
//!
//! - [`process`]：子进程执行、超时、信号量、重试与 [`BdpanError`]；
//! - `parse`：剥离进度条/ANSI 噪音后的 JSON 解析，以及按错误文案给失败分类。

mod parse;
mod process;

use std::time::Instant;

use tracing::Span;

pub use parse::LsEntry;
pub use process::{BdpanClient, BdpanClientConfig, BdpanError, RetryPolicy};

/// 在 span 上记录 `duration_ms` 的守卫。
///
/// 正常返回、`?` 提前返回、future 被取消（Drop）三条路径都会走到 `Drop`，因此
/// 不必在每个返回点手写一次耗时记录——少一处遗漏，日志里的 `duration_ms` 就少一处空洞。
struct DurationTimer {
    span: Span,
    started: Instant,
}

impl DurationTimer {
    /// 开始计时；`span` 必须有 `duration_ms` 字段（声明为
    /// `tracing::field::Empty`），否则记录会被静默丢弃。
    fn new(span: Span) -> Self {
        Self { span, started: Instant::now() }
    }
}

impl Drop for DurationTimer {
    fn drop(&mut self) {
        let millis = u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX);
        self.span.record("duration_ms", millis);
    }
}

//! tracing 初始化：dev 输出人类可读日志，prod 输出 JSON；两者都带时间戳与 span 字段。

use std::io::IsTerminal;

use tracing_subscriber::layer::SubscriberExt;
use tracing_subscriber::util::SubscriberInitExt;
use tracing_subscriber::{EnvFilter, fmt};

use crate::config::RuntimeEnv;

/// 按运行环境安装全局 subscriber；重复初始化会返回错误（测试里各自建 subscriber）。
pub(crate) fn init(runtime_env: RuntimeEnv) -> Result<(), tracing_subscriber::util::TryInitError> {
    // 允许用 RUST_LOG 临时调级；未设置时按环境给默认值。
    let default_filter = match runtime_env {
        RuntimeEnv::Dev => "netdisk_lfs=debug,info",
        RuntimeEnv::Prod => "netdisk_lfs=info,warn",
    };
    let filter = match EnvFilter::try_from_default_env() {
        Ok(filter) => filter,
        Err(err) => {
            // RUST_LOG 确有设置但解析失败（如 netdisk_lfs=deubg）时提醒运维：
            // 此处日志尚未安装，静默回退会让调级失效无从察觉。
            if std::env::var_os("RUST_LOG").is_some() {
                eprintln!("RUST_LOG 解析失败（{err}），回退默认级别 {default_filter}");
            }
            EnvFilter::new(default_filter)
        },
    };
    let registry = tracing_subscriber::registry().with(filter);

    match runtime_env {
        RuntimeEnv::Dev => {
            let layer = fmt::layer().with_target(true).with_ansi(std::io::stdout().is_terminal());
            registry.with(layer).try_init()
        },
        RuntimeEnv::Prod => {
            // JSON 一行一条，便于服务器侧采集；span 字段（含 request_id）随事件输出。
            let layer = fmt::layer().json().with_current_span(true).with_span_list(false);
            registry.with(layer).try_init()
        },
    }
}

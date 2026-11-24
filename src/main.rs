//! netdisk-lfs 二进制入口：加载环境与配置、初始化日志，再启动 HTTP 服务。
//!
//! 启动期的文件读取（`.env`、TOML）与日志初始化都在 tokio runtime 之前完成，
//! 避免在 async 上下文里做阻塞 IO（见 docs/rust-style.md 第 8 节）。

mod cli;
mod config;
mod http;
mod logging;

#[cfg(test)]
mod test_support;

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;

use clap::Parser;
use tokio::net::TcpListener;
use tracing::info;

use crate::cli::Cli;
use crate::config::{Config, ConfigError, EnvSource};

/// `.env` 只放机器相关值；缺失时由真实环境变量提供。
const DOTENV_FILE: &str = ".env";

fn main() -> ExitCode {
    match bootstrap().and_then(serve) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // 日志可能尚未初始化，直接写 stderr，保证启动失败一定有输出。
            eprintln!("启动失败：{err}");
            ExitCode::FAILURE
        },
    }
}

/// 同步启动阶段：读 `.env`、解析参数与配置、初始化日志。
fn bootstrap() -> Result<Config, StartupError> {
    let cli = Cli::parse();
    let env = EnvSource::load(Path::new(DOTENV_FILE))?;
    let config_path = cli.config_path(&env);
    let config = Config::load_with(&config_path, &env)?;
    logging::init(config.runtime_env)?;

    let data_dir = config
        .data_dir
        .as_deref()
        .map_or_else(|| "(unset)".to_owned(), |dir| dir.display().to_string());
    info!(
        config = %config_path.display(),
        listen = %config.server.listen,
        public_base = %config.server.public_base,
        runtime_env = %config.runtime_env,
        objects_root = %config.storage.objects_root,
        tmp_root = %config.storage.tmp_root,
        bdpan_bin = %config.storage.bdpan_bin.display(),
        max_object_bytes = config.storage.max_object_bytes,
        max_bdpan_procs = config.storage.max_bdpan_procs,
        cache_dir = %config.cache.dir.display(),
        cache_max_bytes = config.cache.max_bytes,
        data_dir = %data_dir,
        auth_users = config.auth.users.len(),
        "配置加载完成"
    );
    // 逐个打印用户与角色，便于核对权限配置；口令哈希不入日志。
    for (name, user) in &config.auth.users {
        tracing::debug!(user = %name, role = %user.role, "加载 LFS 用户凭据");
    }
    Ok(config)
}

/// 建立 tokio 多线程 runtime 并运行服务。
fn serve(config: Config) -> Result<(), StartupError> {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .thread_name("netdisk-lfs")
        .enable_all()
        .build()
        .map_err(StartupError::Runtime)?;
    runtime.block_on(run(config))
}

async fn run(config: Config) -> Result<(), StartupError> {
    let addr = config.server.listen;
    let listener =
        TcpListener::bind(addr).await.map_err(|source| StartupError::Bind { addr, source })?;
    let bound = listener.local_addr().unwrap_or(addr);
    info!(address = %bound, "开始监听");

    axum::serve(listener, http::router())
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(StartupError::Serve)?;
    info!("HTTP 服务已退出");
    Ok(())
}

/// Ctrl+C 与 SIGTERM 都触发优雅退出：停止接收新请求，等在途请求结束。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => log_ctrl_c(result),
                    _ = sigterm.recv() => info!("收到 SIGTERM，开始优雅退出"),
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "监听 SIGTERM 失败，仅响应 Ctrl+C");
                log_ctrl_c(tokio::signal::ctrl_c().await);
            },
        }
    }
    #[cfg(not(unix))]
    log_ctrl_c(tokio::signal::ctrl_c().await);
}

/// 记录 Ctrl+C 的等待结果；信号注册失败不阻止进程继续服务。
fn log_ctrl_c(result: std::io::Result<()>) {
    match result {
        Ok(()) => info!("收到 Ctrl+C，开始优雅退出"),
        Err(err) => tracing::warn!(error = %err, "监听 Ctrl+C 失败"),
    }
}

/// 启动期错误；`main` 统一打印并返回非零退出码。
#[derive(Debug, thiserror::Error)]
enum StartupError {
    #[error(transparent)]
    Config(#[from] ConfigError),
    #[error("初始化 tracing 日志失败")]
    Logging(#[from] tracing_subscriber::util::TryInitError),
    #[error("构建 tokio 运行时失败")]
    Runtime(#[source] std::io::Error),
    #[error("绑定监听地址 {addr} 失败")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: std::io::Error,
    },
    #[error("HTTP 服务运行失败")]
    Serve(#[source] std::io::Error),
}

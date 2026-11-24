//! netdisk-lfs 二进制入口：加载环境与配置、初始化日志，再启动 HTTP 服务。
//!
//! 启动期的文件读取（`.env`、TOML）与日志初始化都在 tokio runtime 之前完成，
//! 避免在 async 上下文里做阻塞 IO（见 docs/rust-style.md 第 8 节）。配置、路由与
//! 存储层实现都在 `netdisk_lfs` 库里，本文件只做启动编排。

mod cli;

use std::net::SocketAddr;
use std::path::Path;
use std::process::ExitCode;
use std::sync::Arc;

use clap::Parser;
use netdisk_lfs::http::upload_dir;
use netdisk_lfs::{
    AppState, BdpanProbe, BdpanStore, Cache, Config, ConfigError, EnvSource, ObjectStore,
    init_logging, router, transient_dir,
};
use tokio::net::TcpListener;
use tracing::info;

use crate::cli::Cli;

/// `.env` 只放机器相关值；缺失时由真实环境变量提供。
const DOTENV_FILE: &str = ".env";

fn main() -> ExitCode {
    match bootstrap().and_then(serve) {
        Ok(()) => ExitCode::SUCCESS,
        Err(err) => {
            // 日志可能尚未初始化，直接写 stderr，保证启动失败一定有输出。
            // thiserror 的 Display 只含最外层信息，逐层展开 source 链才能
            // 区分 EADDRINUSE / EACCES 这类根因。
            eprintln!("启动失败：{err}");
            let mut source = std::error::Error::source(&err);
            while let Some(cause) = source {
                eprintln!("  原因：{cause}");
                source = cause.source();
            }
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
    init_logging(config.runtime_env)?;

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

    // 构造后端不触发任何子进程：`bdpan` 只在第一次真实读写时才被调用，
    // 所以配置错误（如路径不可执行）不会在这里暴露，而是留给首个请求与
    // 部署分支的 `whoami` 探活。
    let store: Arc<dyn ObjectStore> = Arc::new(BdpanStore::from_storage(&config.storage));

    // 缓存启动清理：删除超龄 `.part` 残留、扫描目录重建索引、按预算收敛。
    // 三步都不返回错误（失败只降级为直通并记 warn）：缓存可随时清空、清空不影响
    // 正确性，所以缓存侧的问题绝不能阻止服务启动。
    // 降级直通模式的中转文件落在一个专用临时子目录里，同样纳入清理——
    // 不能把整个系统临时目录传进来（会误删其它进程的文件）。
    let cache = Cache::open(&config.cache).await;
    let sweep = cache.sweep(&[upload_dir(&config), transient_dir()]).await;
    info!(
        cache_dir = %cache.root().display(),
        cache_max_bytes = cache.max_bytes(),
        cache_objects = cache.len(),
        cache_used_bytes = cache.used_bytes(),
        cache_enabled = cache.is_enabled(),
        stale_parts = sweep.stale_parts,
        stale_bytes = sweep.stale_bytes,
        evicted_objects = sweep.evicted_objects,
        "缓存启动扫描完成"
    );

    // `bdpan` 探活器：自己的子进程与超时，给 `/healthz` 用。构造它不起子进程，
    // 第一次探测发生在首个 `/healthz` 请求（或探针轮询）时。
    let probe = BdpanProbe::from_storage(&config.storage);
    info!(
        probe_ttl_secs = probe.ttl().as_secs(),
        "bdpan 探活已启用：/healthz 会按 TTL 复用 whoami 结论"
    );

    let state =
        AppState::with_cache(store, Arc::new(config), cache).with_bdpan_probe(Arc::new(probe));

    let listener =
        TcpListener::bind(addr).await.map_err(|source| StartupError::Bind { addr, source })?;
    let bound = listener.local_addr().unwrap_or(addr);
    info!(address = %bound, "开始监听");

    axum::serve(listener, router(state))
        .with_graceful_shutdown(shutdown_signal())
        .await
        .map_err(StartupError::Serve)?;
    info!("HTTP 服务已退出");
    Ok(())
}

/// Ctrl+C 与 SIGTERM 都触发优雅退出：停止接收新请求，等在途请求结束。
///
/// 信号源注册失败只降级为忽略该源，绝不让本 future 提前结束——
/// `with_graceful_shutdown` 把返回视作停机指令，提前 resolve 等于误停机。
async fn shutdown_signal() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};

        match signal(SignalKind::terminate()) {
            Ok(mut sigterm) => {
                tokio::select! {
                    () = wait_ctrl_c() => {},
                    _ = sigterm.recv() => info!("收到 SIGTERM，开始优雅退出"),
                }
            },
            Err(err) => {
                tracing::warn!(error = %err, "监听 SIGTERM 失败，仅响应 Ctrl+C");
                wait_ctrl_c().await;
            },
        }
    }
    #[cfg(not(unix))]
    wait_ctrl_c().await;
}

/// 等待 Ctrl+C；注册失败时保持 pending（忽略该信号源），避免误触发停机。
async fn wait_ctrl_c() {
    match tokio::signal::ctrl_c().await {
        Ok(()) => info!("收到 Ctrl+C，开始优雅退出"),
        Err(err) => {
            tracing::warn!(error = %err, "监听 Ctrl+C 失败，忽略该信号源");
            std::future::pending::<()>().await;
        },
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

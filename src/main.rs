//! netdisk-lfs 二进制入口：加载环境与配置、初始化日志，再启动 HTTP 服务。
//!
//! 启动期的文件读取（`.env`、TOML）与日志初始化都在 tokio runtime 之前完成，
//! 避免在 async 上下文里做阻塞 IO（见 docs/rust-style.md 第 8 节）。配置、路由与
//! 存储层实现都在 `netdisk_lfs` 库里，本文件只做启动编排。

mod cli;

use std::fs::{File, OpenOptions, TryLockError};
use std::io;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};
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
    // 锁守卫必须活到进程退出：`_lock` 随 `serve` 返回才被丢弃，
    // 期间任何第二个实例都会在启动阶段被拒绝。
    match bootstrap().and_then(|(config, _lock)| serve(config)) {
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

/// 同步启动阶段：读 `.env`、解析参数与配置、初始化日志、抢单实例锁。
fn bootstrap() -> Result<(Config, Vec<SingletonLock>), StartupError> {
    let cli = Cli::parse();
    let env = EnvSource::load(Path::new(DOTENV_FILE))?;
    let config_path = cli.config_path(&env);
    let config = Config::load_with(&config_path, &env)?;
    init_logging(config.runtime_env)?;

    // 单实例：缓存目录与网盘中转都假定只有一个进程，第二个实例必须在绑定端口前退出。
    let lock = acquire_singleton(&config)?;

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
    Ok((config, lock))
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

/// 单实例锁文件名（放在本地数据根下）。
const LOCK_FILE: &str = "netdisk-lfs.lock";
/// 主机级锁文件名：降级直通的中转目录是 `temp_dir()` 下的固定路径，与 data_dir 无关，
/// 所以除了数据根锁，还需要一把与数据根无关的锁，覆盖「两个实例用不同 data_dir」的场景。
const HOST_LOCK_FILE: &str = "netdisk-lfs-transient.lock";

/// 单实例锁：`File` 持有期间 flock 生效，进程退出（含崩溃）由内核自动释放。
///
/// 没有它时两个实例可以同时跑：缓存索引各记各的、上传中转共用 `tmp/<oid>`、
/// 同一个 oid 的 put 会互相覆盖。systemd 只能保证同名 unit 不重复，
/// 手工再起一个二进制仍会冲突，所以锁必须在进程内做。
#[derive(Debug)]
struct SingletonLock {
    /// 锁文件句柄；字段只靠 Drop 释放锁，不读取。
    _file: File,
}

/// 取单实例锁：数据根、缓存目录、主机级临时目录各一把。
///
/// 三者都是跨进程共享的状态：数据根放锁与上传缓冲，`cache.dir` 是 LRU 索引与
/// 驱逐的目标（两个实例共用会互相驱逐、索引各记各的），临时目录是降级直通中转
/// 的固定路径。只有全部拿到才算启动成功。
fn acquire_singleton(config: &Config) -> Result<Vec<SingletonLock>, StartupError> {
    acquire_locks(config.data_dir.as_deref(), &config.cache.dir, &std::env::temp_dir())
}

/// `acquire_singleton` 的可注入版本：测试用独立路径，避免并行用例互抢真实 /tmp 锁。
fn acquire_locks(
    data_dir: Option<&Path>,
    cache_dir: &Path,
    temp_root: &Path,
) -> Result<Vec<SingletonLock>, StartupError> {
    let mut dirs: Vec<(&Path, &str)> = Vec::with_capacity(3);
    if let Some(dir) = data_dir {
        dirs.push((dir, LOCK_FILE));
    }
    dirs.push((cache_dir, LOCK_FILE));
    dirs.push((temp_root, HOST_LOCK_FILE));

    let mut locks = Vec::with_capacity(dirs.len());
    let mut seen: Vec<&Path> = Vec::with_capacity(dirs.len());
    for (dir, name) in dirs {
        // 同一个目录只锁一次：同进程对同一路径两次 try_lock 会自锁。
        if seen.contains(&dir) {
            continue;
        }
        seen.push(dir);
        locks.push(acquire_lock(dir, name)?);
    }
    Ok(locks)
}

fn acquire_lock(dir: &Path, name: &str) -> Result<SingletonLock, StartupError> {
    std::fs::create_dir_all(dir)
        .map_err(|source| StartupError::LockIo { path: dir.to_path_buf(), source })?;
    let path = dir.join(name);
    // 拒绝符号链接：/tmp 是可写目录，预置的链接会让锁写到别处（甚至覆盖文件）。
    if let Ok(meta) = std::fs::symlink_metadata(&path)
        && meta.file_type().is_symlink()
    {
        return Err(StartupError::LockIo {
            path,
            source: io::Error::other("锁路径是符号链接，拒绝使用"),
        });
    }
    let mut options = OpenOptions::new();
    options.create(true).truncate(false).read(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        // 新建时 0600：/tmp 下的锁不该让其他用户能打开（避免跨用户误锁与误写）。
        options.mode(0o600);
    }
    let file = options
        .open(&path)
        .map_err(|source| StartupError::LockIo { path: path.clone(), source })?;
    match file.try_lock() {
        Ok(()) => Ok(SingletonLock { _file: file }),
        Err(TryLockError::WouldBlock) => Err(StartupError::AlreadyRunning { path }),
        Err(TryLockError::Error(source)) => Err(StartupError::LockIo { path, source }),
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
    Runtime(#[source] io::Error),
    #[error("绑定监听地址 {addr} 失败")]
    Bind {
        addr: SocketAddr,
        #[source]
        source: io::Error,
    },
    #[error("HTTP 服务运行失败")]
    Serve(#[source] io::Error),
    #[error("已有 netdisk-lfs 实例在运行（锁文件 {path}）")]
    AlreadyRunning {
        /// 锁文件路径，便于定位是哪个数据根。
        path: PathBuf,
    },
    #[error("单实例锁 {} 不可用（若该文件属于其他用户，请用同一用户运行或设置 NETDISK_LFS_DATA_DIR）", path.display())]
    LockIo {
        /// 出错的锁文件或数据目录。
        path: PathBuf,
        /// 底层 IO 错误。
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::{StartupError, acquire_locks};
    use std::path::PathBuf;
    use std::sync::atomic::{AtomicU32, Ordering};

    static SEQ: AtomicU32 = AtomicU32::new(0);

    fn temp_root() -> PathBuf {
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let dir =
            std::env::temp_dir().join(format!("netdisk-lfs-lock-{}-{seq}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("建临时目录");
        dir
    }

    #[test]
    fn given_same_data_dir_when_second_instance_starts_then_rejected() {
        let root = temp_root();
        let data = root.join("data");
        let cache = root.join("cache");
        let temp = root.join("tmp");
        std::fs::create_dir_all(&temp).expect("建临时根");
        let first = acquire_locks(Some(&data), &cache, &temp).expect("首个实例应拿到锁");

        let err = acquire_locks(Some(&data), &cache, &temp).expect_err("第二个实例必须被拒绝");

        assert!(matches!(err, StartupError::AlreadyRunning { .. }), "实际错误：{err}");
        drop(first);
        acquire_locks(Some(&data), &cache, &temp).expect("释放后应能重新获取");
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn given_different_data_dir_but_shared_cache_when_second_starts_then_rejected() {
        // 两个实例共用一个 cache.dir 会互相驱逐、索引各记各的：必须互斥。
        let root = temp_root();
        let cache = root.join("cache");
        let temp = root.join("tmp");
        std::fs::create_dir_all(&temp).expect("建临时根");
        let first = acquire_locks(Some(&root.join("data-a")), &cache, &temp).expect("首个实例");

        let err = acquire_locks(Some(&root.join("data-b")), &cache, &temp)
            .expect_err("共用缓存目录也必须互斥");

        assert!(matches!(err, StartupError::AlreadyRunning { .. }), "实际错误：{err}");
        drop(first);
        let _ = std::fs::remove_dir_all(&root);
    }

    #[test]
    fn given_different_data_and_cache_but_shared_temp_when_second_starts_then_rejected() {
        // 降级中转目录是 temp 下的固定路径，与 data_dir/cache 无关。
        let root = temp_root();
        let temp = root.join("tmp");
        std::fs::create_dir_all(&temp).expect("建临时根");
        let first = acquire_locks(Some(&root.join("data-a")), &root.join("cache-a"), &temp)
            .expect("首个实例");

        let err = acquire_locks(Some(&root.join("data-b")), &root.join("cache-b"), &temp)
            .expect_err("共享临时中转目录也必须互斥");

        assert!(matches!(err, StartupError::AlreadyRunning { .. }), "实际错误：{err}");
        drop(first);
        let _ = std::fs::remove_dir_all(&root);
    }
}

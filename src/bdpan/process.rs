//! `bdpan` 子进程执行：超时、并发限流、指数退避重试，以及把 stdout 归类成错误。
//!
//! 每次调用都按「信号量许可 → 起进程 → 超时 → 解析 JSON → 分类」走一遍，重试包在
//! 分类之后：只有超时与网络类失败会退避重试，业务错误（不存在、已存在、登录失效）
//! 重试也不会变好，只会让调用方多等 21 秒。
//!
//! 子进程一律 `kill_on_drop(true)`：`tokio::time::timeout` 到期只是丢弃 future，
//! 不杀进程的话 4 GiB 上传的 `bdpan` 会在后台继续跑，而信号量许可已经释放——
//! `max_bdpan_procs` 就形同虚设了。

use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Arc;
use std::time::{Duration, Instant};

use tokio::process::Command;
use tokio::sync::Semaphore;
use tracing::{Instrument, warn};

use crate::bdpan::DurationTimer;
use crate::bdpan::parse::{self, LsEntry, ShapeError, Status};
use crate::config::StorageConfig;
use crate::store::Quota;

/// `bdpan` 调用失败的原因。
///
/// 分类不是为了好看：可重试（[`Timeout`](Self::Timeout)、[`Unavailable`](Self::Unavailable)）、
/// 需要上层换状态码（[`Auth`](Self::Auth) → 503）、可当幂等成功（[`DestinationExists`](Self::DestinationExists)、
/// [`NotFound`](Self::NotFound)）这三档语义完全不同，混成一个「后端错误」就只能靠文案猜。
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum BdpanError {
    /// 子进程在超时时间内没有结束；进程已被杀掉。
    #[error("bdpan {command} 超过 {}s 仍未结束", timeout.as_secs())]
    Timeout {
        /// 子命令名，如 `upload`。
        command: &'static str,
        /// 生效的超时。
        timeout: Duration,
    },
    /// 子进程起不来（可执行文件不存在、无执行权限等）。
    #[error("无法启动 bdpan（{command}，程序 {}）", bin.display())]
    Spawn {
        /// 配置里的可执行文件路径。
        bin: PathBuf,
        /// 子命令名。
        command: &'static str,
        /// 底层 IO 错误。
        #[source]
        source: io::Error,
    },
    /// 本地文件不可用（上传源不存在等）；不会浪费一次网盘往返。
    #[error("本地文件 {} 不可用", path.display())]
    LocalIo {
        /// 出错的本地路径。
        path: PathBuf,
        /// 底层 IO 错误。
        #[source]
        source: io::Error,
    },
    /// 退出码非 0 且 stdout 里没有任何 JSON；通常是 CLI 自身崩了或参数不被接受。
    #[error("bdpan {command} 退出码 {code} 且没有输出 JSON")]
    Exit {
        /// 子命令名。
        command: &'static str,
        /// 进程退出码。
        code: i32,
        /// 输出片段，已压平控制字符。
        detail: String,
    },
    /// stdout 里找不到可解析的结果 JSON。
    #[error("bdpan {command} 的输出无法解析成 JSON")]
    Decode {
        /// 子命令名。
        command: &'static str,
        /// 输出片段，已压平控制字符。
        detail: String,
    },
    /// 业务失败（`code` 非 0），且不属于下面任何可识别类别。
    #[error("bdpan {command} 失败：{message}")]
    Command {
        /// 子命令名。
        command: &'static str,
        /// CLI 给出的数字码。
        code: Option<i64>,
        /// CLI 给出的原因原文。
        message: String,
    },
    /// 登录态失效（token 过期/被吊销）；由 HTTP 层映射成 503。
    #[error("bdpan 登录态失效（{command}）：{message}")]
    Auth {
        /// 子命令名。
        command: &'static str,
        /// CLI 给出的原因原文。
        message: String,
    },
    /// 远端目标不存在；`ls`/`rm` 用它做幂等判定。
    #[error("bdpan {command} 报告目标不存在：{message}")]
    NotFound {
        /// 子命令名。
        command: &'static str,
        /// CLI 给出的原因原文。
        message: String,
    },
    /// 目标已存在（`mv` 不覆盖同名文件）；是上传幂等的冲突屏障。
    #[error("bdpan {command} 目标已存在：{message}")]
    DestinationExists {
        /// 子命令名。
        command: &'static str,
        /// CLI 给出的原因原文。
        message: String,
    },
    /// `upload` 被 CLI 同名自动重命名（CLI 不覆盖同名文件）。
    ///
    /// `actual` 是 CLI 报告的实际落盘名；调用方必须把它与请求名一起清理，
    /// 否则改名副本会永久留在中转目录（本进程没有 tmp GC）。
    #[error(
        "bdpan upload 被自动重命名（期望 {expected}，实际 {}），需清理后重试",
        actual.as_deref().unwrap_or("(未报告)")
    )]
    UploadRenamed {
        /// 请求的中转文件名（即 oid）。
        expected: String,
        /// CLI 报告的实际落盘名；未报告时为 `None`。
        actual: Option<String>,
    },
    /// 网络/服务端暂时不可用；可退避重试。
    #[error("bdpan {command} 暂时不可用：{message}")]
    Unavailable {
        /// 子命令名。
        command: &'static str,
        /// CLI 给出的原因原文。
        message: String,
    },
    /// 输出形状与命令契约不符，或语义上不该出现的结果（如上传被自动重命名）。
    #[error("bdpan {command} 的输出不符合预期：{detail}")]
    Unexpected {
        /// 子命令名。
        command: &'static str,
        /// 具体哪里不符合预期。
        detail: String,
    },
}

impl BdpanError {
    /// 是否登录态失效；HTTP 层据此映射 503（见 `specs/architecture.md` 失败模式表）。
    ///
    /// 单独提供判定而不是让调用方匹配变体：枚举是 `#[non_exhaustive]`，按字符串或按变体
    /// 猜都会在 CLI 换文案时悄悄失效，把「50x 该有的重试语义」变成「所有对象都 404」。
    pub fn is_auth(&self) -> bool {
        matches!(self, Self::Auth { .. })
    }

    /// 这次失败是否值得退避重试。
    ///
    /// 只放超时与网络类：登录失效、路径越界、目标已存在都不是「再试一次会变好」的
    /// 故障，重试只会把 502 延迟到 21 秒之后。
    fn is_retryable(&self) -> bool {
        matches!(self, Self::Timeout { .. } | Self::Unavailable { .. })
    }
}

/// 重试策略：默认 3 次、退避 1s/4s/16s（见 `specs/architecture.md` 失败模式表）。
#[derive(Debug, Clone, Copy)]
#[non_exhaustive]
pub struct RetryPolicy {
    /// 首次失败后最多再试几次；`0` 表示不重试。
    pub max_retries: u32,
    /// 第一次退避时长。
    pub initial_delay: Duration,
    /// 每次退避的倍数；默认 4，于是 1s → 4s → 16s。
    pub multiplier: u32,
}

impl RetryPolicy {
    /// 自定义策略；测试常用极短的退避，生产用 [`Default`] 的 1s/4s/16s。
    pub const fn new(max_retries: u32, initial_delay: Duration, multiplier: u32) -> Self {
        Self { max_retries, initial_delay, multiplier }
    }

    /// 不重试；测试与「失败要立刻暴露」的场景用。
    pub const fn none() -> Self {
        Self { max_retries: 0, initial_delay: Duration::from_secs(1), multiplier: 4 }
    }

    /// 第 `retry` 次重试（从 0 开始）前的退避时长。
    pub fn delay(&self, retry: u32) -> Duration {
        let factor = self.multiplier.saturating_pow(retry);
        self.initial_delay.saturating_mul(factor)
    }
}

impl Default for RetryPolicy {
    fn default() -> Self {
        Self { max_retries: 3, initial_delay: Duration::from_secs(1), multiplier: 4 }
    }
}

/// [`BdpanClient`] 的构造参数。
///
/// 字段全部可写，但推荐用 [`Self::new`] / [`Self::from_storage`] 加链式 `with_*`：
/// 默认值（600s 超时、3 次重试、4 个并发）是长期压测前的保守选择，改它们应当是一次
/// 显式决定而不是漏填。
#[derive(Debug, Clone)]
#[non_exhaustive]
pub struct BdpanClientConfig {
    /// `bdpan` 可执行文件路径。
    pub bin: PathBuf,
    /// 单次命令超时；`None` 表示不设超时（大对象上传可能数小时）。
    pub timeout: Option<Duration>,
    /// 重试策略。
    pub retry: RetryPolicy,
    /// 同时存在的 `bdpan` 子进程上限（信号量许可数）。
    pub max_procs: usize,
    /// 追加给子进程的环境变量；父进程环境仍然继承。
    ///
    /// 生产上用于补 `PATH` 之类；测试用它把桩脚本的开关（`FAKE_BDPAN_*`）注入进去，
    /// 避免改进程级环境变量（多线程测试里那是不安全的全局状态）。
    pub env: Vec<(OsString, OsString)>,
}

impl BdpanClientConfig {
    /// 单次命令的默认超时：600s。
    ///
    /// 这是「卡死保护」的保守缺省；生产由 `[storage] bdpan_timeout_secs` 覆盖
    /// （缺省 6 小时，`0` 表示不设超时），大对象上传按上行带宽可能需要数小时。
    pub const DEFAULT_TIMEOUT: Duration = Duration::from_secs(600);

    /// 用默认超时、默认重试与 4 个并发许可构造。
    pub fn new(bin: impl Into<PathBuf>) -> Self {
        Self {
            bin: bin.into(),
            timeout: Some(Self::DEFAULT_TIMEOUT),
            retry: RetryPolicy::default(),
            max_procs: 4,
            env: Vec::new(),
        }
    }

    /// 从 `[storage]` 配置构造：可执行路径、并发许可数与命令超时都取配置值。
    ///
    /// `bdpan_timeout_secs = 0` 映射为「不设超时」；重试策略仍用默认值
    /// （需要调整时用 [`BdpanClientConfig::with_retry`] 覆盖）。
    pub fn from_storage(storage: &StorageConfig) -> Self {
        let timeout = match storage.bdpan_timeout_secs {
            0 => None,
            secs => Some(Duration::from_secs(secs)),
        };
        Self { max_procs: storage.max_bdpan_procs, timeout, ..Self::new(storage.bdpan_bin.clone()) }
    }

    /// 覆盖单次命令超时。
    pub fn with_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = Some(timeout);
        self
    }

    /// 覆盖重试策略。
    pub fn with_retry(mut self, retry: RetryPolicy) -> Self {
        self.retry = retry;
        self
    }

    /// 覆盖并发许可数；`0` 会在建 [`BdpanClient`] 时被抬到 1（否则每个调用永久阻塞）。
    pub fn with_max_procs(mut self, max_procs: usize) -> Self {
        self.max_procs = max_procs;
        self
    }

    /// 追加一个传给子进程的环境变量。
    pub fn with_env(mut self, key: impl Into<OsString>, value: impl Into<OsString>) -> Self {
        self.env.push((key.into(), value.into()));
        self
    }
}

/// 一次调用的 `span` 上下文：远端路径、本地路径与已知字节数。
#[derive(Debug, Default, Clone, Copy)]
struct CallSite<'a> {
    /// 命令操作的远端路径。
    remote: Option<&'a str>,
    /// 命令涉及的本地路径（上传源或下载目标）。
    local: Option<&'a Path>,
    /// 已知的字节数；未知时为 `None`。
    bytes: Option<u64>,
}

/// 一次子进程执行的原样输出。
#[derive(Debug)]
struct ProcessOutput {
    /// 退出码；被信号杀死时为 `None`。
    code: Option<i32>,
    /// stdout（已做有损 UTF-8 解码）。
    stdout: String,
    /// stderr（已做有损 UTF-8 解码）。
    stderr: String,
}

/// `bdpan` CLI 的统一封装。
///
/// 本类型是仓库里唯一允许出现 `Command::new` 的地方（`AGENTS.md` 硬约束）。所有方法
/// 都带超时、并发限流与可重试失败的指数退避，并在 `span` 里记录命令名、路径、字节数
/// 与耗时。
#[derive(Debug)]
pub struct BdpanClient {
    bin: PathBuf,
    timeout: Option<Duration>,
    retry: RetryPolicy,
    env: Vec<(OsString, OsString)>,
    permits: Arc<Semaphore>,
}

impl BdpanClient {
    /// 按配置构造；并发许可数下限为 1。
    pub fn new(config: BdpanClientConfig) -> Self {
        Self {
            bin: config.bin,
            timeout: config.timeout,
            retry: config.retry,
            env: config.env,
            // 0 个许可会让第一个调用永久挂起，比「少限流」严重得多，这里静默抬到 1；
            // 配置加载阶段已经拒绝过 `max_bdpan_procs = 0`，走到这里说明是别的调用方。
            permits: Arc::new(Semaphore::new(config.max_procs.max(1))),
        }
    }

    /// 从 `[storage]` 配置构造。
    pub fn from_storage(storage: &StorageConfig) -> Self {
        Self::new(BdpanClientConfig::from_storage(storage))
    }

    /// 列目录；目录不存在时返回 `Ok(None)`。
    ///
    /// 实测 `ls` 用 `code:1` 表示「目录不存在」，没有单独的「空目录」区分——空目录返回
    /// `[]`。只有「文案已识别为不存在」（[`BdpanError::NotFound`]）或 `code:1` 才折成
    /// `None`；`code` 非 1 的未知失败必须原样上抛——把后端新错误吞成「不存在」会让
    /// `exists` 谎报缺失、`put` 白白重传整份对象。
    pub async fn ls(&self, dir: &str) -> Result<Option<Vec<LsEntry>>, BdpanError> {
        let args = vec![dir.to_owned()];
        let site = CallSite { remote: Some(dir), ..CallSite::default() };
        match self.invoke("ls", &args, site).await {
            Ok(value) => {
                let entries = parse::ls_entries(&value).map_err(|err| unexpected("ls", &err))?;
                Ok(Some(entries))
            },
            Err(
                err @ (BdpanError::NotFound { .. } | BdpanError::Command { code: Some(1), .. }),
            ) => {
                tracing::debug!(dir, error = %err, "ls 判定远端目录不存在");
                Ok(None)
            },
            Err(err) => Err(err),
        }
    }

    /// 建目录；已存在也算成功（`mkdir -p` 语义，可一次建多级）。
    pub async fn mkdir(&self, dir: &str) -> Result<(), BdpanError> {
        let args = vec![dir.to_owned()];
        self.invoke("mkdir", &args, CallSite { remote: Some(dir), ..CallSite::default() })
            .await
            .map(|_| ())
    }

    /// 上传本地文件到指定远端路径。
    ///
    /// 只做「CLI 是否接受」的判定：CLI 自身只校验 metadata，内容校验由调用方用 sha256
    /// 负责。若 CLI 因同名而自动重命名，返回 [`BdpanError::UploadRenamed`] 并携带实际
    /// 落盘名，供调用方连改名副本一起清理。
    pub async fn upload(&self, local: &Path, remote: &str) -> Result<(), BdpanError> {
        let meta = tokio::fs::metadata(local)
            .await
            .map_err(|source| BdpanError::LocalIo { path: local.to_path_buf(), source })?;
        if !meta.is_file() {
            return Err(BdpanError::LocalIo {
                path: local.to_path_buf(),
                source: io::Error::other("不是普通文件"),
            });
        }
        let local_arg = utf8_path("upload", local)?;
        let args = vec![local_arg.to_owned(), remote.to_owned()];
        let site = CallSite { remote: Some(remote), local: Some(local), bytes: Some(meta.len()) };
        let value = self.invoke("upload", &args, site).await?;
        match parse::upload_conflict(&value, remote) {
            Some(conflict) => Err(BdpanError::UploadRenamed {
                expected: conflict.expected,
                actual: conflict.actual,
            }),
            None => Ok(()),
        }
    }

    /// 移动文件到目标目录；文件名保持不变，目标已有同名文件时报
    /// [`BdpanError::DestinationExists`]。
    pub async fn mv(&self, src_file: &str, dest_dir: &str) -> Result<(), BdpanError> {
        let args = vec![src_file.to_owned(), dest_dir.to_owned()];
        self.invoke("mv", &args, CallSite { remote: Some(src_file), ..CallSite::default() })
            .await
            .map(|_| ())
    }

    /// 删除远端文件；返回是否真的删掉了（`false` 表示本来就不存在）。
    ///
    /// 只有「文案已识别为不存在」或 `code:1` 才折成 `Ok(false)`；其余未知失败上抛——
    /// `rm` 是清理中转文件用的，幂等很重要，但「删没删成功」不能靠猜：
    /// 把真实删除失败报成成功，残留文件就再也没人清理了。
    pub async fn rm(&self, remote: &str) -> Result<bool, BdpanError> {
        let args = vec![remote.to_owned()];
        let site = CallSite { remote: Some(remote), ..CallSite::default() };
        match self.invoke("rm", &args, site).await {
            Ok(_) => Ok(true),
            Err(
                err @ (BdpanError::NotFound { .. } | BdpanError::Command { code: Some(1), .. }),
            ) => {
                tracing::debug!(remote, error = %err, "rm 判定远端文件本来就不存在");
                Ok(false)
            },
            Err(err) => Err(err),
        }
    }

    /// 下载远端文件到本地路径。
    ///
    /// CLI 的进度条与 JSON 结果混流，且出现过「报成功但内容截断」的静默失败，所以
    /// 返回值只代表「CLI 认为成功」；内容是否完整必须由调用方用 sha256 校验。
    pub async fn download(&self, remote: &str, local: &Path) -> Result<(), BdpanError> {
        let local_arg = utf8_path("download", local)?;
        let args = vec![remote.to_owned(), local_arg.to_owned()];
        self.invoke(
            "download",
            &args,
            CallSite { remote: Some(remote), local: Some(local), bytes: None },
        )
        .await
        .map(|_| ())
    }

    /// 查询网盘配额。
    pub async fn quota(&self) -> Result<Quota, BdpanError> {
        let value = self.invoke("quota", &[], CallSite::default()).await?;
        parse::quota(&value).map_err(|err| unexpected("quota", &err))
    }

    /// 探测登录态（供 `/healthz` 用）。
    ///
    /// 真实 CLI 的输出是扁平对象（无 `code`/`data` 信封）：
    /// `{"authenticated":true,"has_valid_token":true,...}`；token 失效时字段转 `false`。
    /// 这里按字段判定，缺字段时以 CLI 的成功退出为准（不臆造失败）。
    ///
    /// 只判定成功与否，**不回显 CLI 输出**：`whoami --json` 可能带账号凭据，按
    /// `docs/git-workflow.md` 不得进日志或入库。
    pub async fn whoami(&self) -> Result<(), BdpanError> {
        let value = self.invoke("whoami", &[], CallSite::default()).await?;
        let authenticated = whoami_flag(&value, "authenticated")?;
        let valid_token = whoami_flag(&value, "has_valid_token")?;
        match (authenticated, valid_token) {
            (Some(false), _) | (_, Some(false)) => Err(BdpanError::Auth {
                command: "whoami",
                message: "CLI 报告登录态无效".to_owned(),
            }),
            _ => Ok(()),
        }
    }

    /// 带重试地执行一次命令，返回解析后的结果 JSON。
    async fn invoke(
        &self,
        command: &'static str,
        args: &[String],
        site: CallSite<'_>,
    ) -> Result<serde_json::Value, BdpanError> {
        let span = tracing::info_span!(
            "bdpan",
            cmd = command,
            remote = tracing::field::Empty,
            local = tracing::field::Empty,
            bytes = tracing::field::Empty,
            attempt = tracing::field::Empty,
            duration_ms = tracing::field::Empty,
        );
        // 缺的字段宁可不出现：`quota` 没有路径、`download` 事前不知道字节数，
        // 填成 0 或空串只会让日志看起来像「零字节对象」。
        if let Some(remote) = site.remote {
            span.record("remote", remote);
        }
        if let Some(local) = site.local {
            span.record("local", tracing::field::display(local.display()));
        }
        if let Some(bytes) = site.bytes {
            span.record("bytes", bytes);
        }
        // 计时器放在 instrument 之外：它要覆盖整段（含退避），Drop 时写回 duration_ms。
        let _timer = DurationTimer::new(span.clone());
        let span_for_record = span.clone();
        async move {
            let mut attempt: u32 = 0;
            loop {
                span_for_record.record("attempt", u64::from(attempt + 1));
                let started = Instant::now();
                let outcome = self.call_once(command, args).await;
                let elapsed = u64::try_from(started.elapsed().as_millis()).unwrap_or(u64::MAX);
                tracing::debug!(
                    cmd = command,
                    attempt = attempt + 1,
                    elapsed_ms = elapsed,
                    "bdpan 调用结束"
                );
                match outcome {
                    Ok(value) => return Ok(value),
                    Err(err) if attempt < self.retry.max_retries && err.is_retryable() => {
                        let delay = self.retry.delay(attempt);
                        warn!(
                            cmd = command,
                            attempt = attempt + 1,
                            delay_ms = u64::try_from(delay.as_millis()).unwrap_or(u64::MAX),
                            error = %err,
                            "bdpan 调用失败，退避后重试"
                        );
                        tokio::time::sleep(delay).await;
                        attempt += 1;
                    },
                    Err(err) => return Err(err),
                }
            }
        }
        .instrument(span)
        .await
    }

    /// 单次尝试：拿许可、起进程、解析 JSON、分类。
    async fn call_once(
        &self,
        command: &'static str,
        args: &[String],
    ) -> Result<serde_json::Value, BdpanError> {
        let permit = self.permits.acquire().await.map_err(|_| BdpanError::Unexpected {
            command,
            detail: "并发信号量已关闭".to_owned(),
        })?;
        let output = self.spawn(command, args).await;
        // 进程已结束（或已被杀），先还许可再解析，别让纯 CPU 的 JSON 解析占着许可。
        drop(permit);
        interpret(command, &output?)
    }

    /// 起子进程并等它结束；超时则杀进程并报 [`BdpanError::Timeout`]。
    async fn spawn(
        &self,
        command: &'static str,
        args: &[String],
    ) -> Result<ProcessOutput, BdpanError> {
        let mut child = Command::new(&self.bin);
        child
            .arg(command)
            .args(args)
            .arg("--json")
            .arg("--no-check-update")
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            // 超时/取消时子进程必须一起死，否则后台的 bdpan 会绕过 max_bdpan_procs。
            .kill_on_drop(true);
        for (key, value) in &self.env {
            child.env(key, value);
        }
        let output = match self.timeout {
            Some(limit) => match tokio::time::timeout(limit, child.output()).await {
                Ok(Ok(output)) => output,
                Ok(Err(source)) => {
                    return Err(BdpanError::Spawn { bin: self.bin.clone(), command, source });
                },
                Err(_elapsed) => {
                    return Err(BdpanError::Timeout { command, timeout: limit });
                },
            },
            // 不设超时：大对象上传期间只受 Ctrl+C / 进程被杀影响，
            // `kill_on_drop` 仍保证 future 被取消时子进程一起结束。
            None => match child.output().await {
                Ok(output) => output,
                Err(source) => {
                    return Err(BdpanError::Spawn { bin: self.bin.clone(), command, source });
                },
            },
        };
        Ok(ProcessOutput {
            code: output.status.code(),
            stdout: String::from_utf8_lossy(&output.stdout).into_owned(),
            stderr: String::from_utf8_lossy(&output.stderr).into_owned(),
        })
    }
}

/// 把子进程输出解释成「结果 JSON」或一个分类好的失败。
fn interpret(
    command: &'static str,
    output: &ProcessOutput,
) -> Result<serde_json::Value, BdpanError> {
    let Some(value) = parse::first_json(&output.stdout) else {
        let detail = format!(
            "stdout: {}；stderr: {}",
            parse::preview(&output.stdout, 200),
            parse::preview(&output.stderr, 200)
        );
        return Err(match output.code {
            Some(code) if code != 0 => BdpanError::Exit { command, code, detail },
            _ => BdpanError::Decode { command, detail },
        });
    };
    // 退出码不参与判定：实测业务错误的退出码同样是 0，只有 JSON 说得清发生了什么。
    match parse::status(&value) {
        Status::Success => Ok(value),
        Status::Failure { code, message } => Err(classify(command, code, message)),
    }
}

/// 按 CLI 的错误文案给失败归类；判定顺序见各谓词的文档。
fn classify(command: &'static str, code: Option<i64>, message: String) -> BdpanError {
    if parse::is_auth_failure(&message) {
        BdpanError::Auth { command, message }
    } else if parse::is_conflict_failure(&message) {
        BdpanError::DestinationExists { command, message }
    } else if parse::is_not_found_failure(&message) {
        BdpanError::NotFound { command, message }
    } else if parse::is_scope_failure(&message) {
        BdpanError::Unexpected { command, detail: format!("远端路径越界：{message}") }
    } else if parse::is_transient_failure(&message) {
        BdpanError::Unavailable { command, message }
    } else {
        BdpanError::Command { command, code, message }
    }
}

/// 形状不对的统一出口。
fn unexpected(command: &'static str, err: &ShapeError) -> BdpanError {
    BdpanError::Unexpected { command, detail: err.to_string() }
}

/// 读取 `whoami` 的布尔标志：缺键 → `None`（CLI 没报告该字段，以成功退出为准）；
/// 非布尔 → 形状漂移，按 [`BdpanError::Unexpected`] 失败（healthz 映射 503）。
///
/// 不能只用 `as_bool()` 然后 `unwrap_or(false)` 式的宽容：`1`/`"true"`/`null`
/// 这类近似编码会让 `as_bool()` 返回 `None`，从而在登录态不可读时谎报健康。
fn whoami_flag(value: &serde_json::Value, key: &str) -> Result<Option<bool>, BdpanError> {
    match value.get(key) {
        None => Ok(None),
        Some(serde_json::Value::Bool(flag)) => Ok(Some(*flag)),
        Some(_) => Err(BdpanError::Unexpected {
            command: "whoami",
            detail: format!("字段 {key} 不是布尔值"),
        }),
    }
}

/// 子进程参数只接受 UTF-8 路径；非 UTF-8 在本地就已经错了，不必下传到网盘。
fn utf8_path<'a>(command: &'static str, path: &'a Path) -> Result<&'a str, BdpanError> {
    path.to_str().ok_or_else(|| BdpanError::Unexpected {
        command,
        detail: format!("本地路径不是合法 UTF-8：{}", path.display()),
    })
}

#[cfg(test)]
mod tests {
    use super::{BdpanError, ProcessOutput, RetryPolicy, classify, interpret, whoami_flag};

    use std::path::PathBuf;
    use std::time::Duration;

    #[test]
    fn given_whoami_flag_when_missing_or_non_boolean_then_fail_safe() {
        // 缺键：CLI 没报告该字段，以成功退出为准。
        assert_eq!(whoami_flag(&serde_json::json!({}), "authenticated").expect("缺键"), None);
        assert_eq!(
            whoami_flag(&serde_json::json!({"authenticated": false}), "authenticated")
                .expect("布尔"),
            Some(false)
        );
        // 非布尔（1/"true"/null）：形状漂移，必须失败而不是谎报健康。
        for broken in [
            serde_json::json!({"authenticated": 1}),
            serde_json::json!({"authenticated": "true"}),
            serde_json::json!({"authenticated": null}),
        ] {
            let err = whoami_flag(&broken, "authenticated").expect_err("非布尔应报形状错误");
            assert!(matches!(err, BdpanError::Unexpected { .. }), "实际错误：{err}");
        }
    }

    #[test]
    fn given_default_policy_when_delay_then_one_four_sixteen_seconds() {
        let policy = RetryPolicy::default();

        let delays: Vec<u64> = (0..3).map(|retry| policy.delay(retry).as_secs()).collect();

        assert_eq!(policy.max_retries, 3);
        assert_eq!(delays, vec![1, 4, 16]);
    }

    #[test]
    fn given_none_policy_when_delay_then_still_computable_but_unused() {
        let policy = RetryPolicy::none();

        assert_eq!(policy.max_retries, 0);
        assert_eq!(policy.delay(0), Duration::from_secs(1));
    }

    #[test]
    fn given_timeouts_and_network_errors_when_retryable_then_true_others_false() {
        let timeout = BdpanError::Timeout { command: "upload", timeout: Duration::from_secs(600) };
        let unavailable =
            BdpanError::Unavailable { command: "download", message: "网络异常".to_owned() };
        let auth = BdpanError::Auth { command: "ls", message: "token 已过期".to_owned() };
        let conflict = BdpanError::DestinationExists {
            command: "mv",
            message: "file already exists".to_owned(),
        };
        let spawn = BdpanError::Spawn {
            bin: PathBuf::from("/usr/local/bin/bdpan"),
            command: "ls",
            source: std::io::Error::from(std::io::ErrorKind::NotFound),
        };

        assert!(timeout.is_retryable());
        assert!(unavailable.is_retryable());
        assert!(!auth.is_retryable());
        assert!(!conflict.is_retryable());
        assert!(!spawn.is_retryable());
    }

    #[test]
    fn given_auth_error_when_is_auth_then_true_and_others_false() {
        let auth = BdpanError::Auth { command: "ls", message: "token 已过期".to_owned() };
        let timeout = BdpanError::Timeout { command: "ls", timeout: Duration::from_secs(600) };

        assert!(auth.is_auth());
        assert!(!timeout.is_auth());
    }

    #[test]
    fn given_failure_messages_when_classify_then_each_bucket_is_distinct() {
        assert!(matches!(
            classify("ls", Some(1), "token 过期，请重新登录".to_owned()),
            BdpanError::Auth { .. }
        ));
        assert!(matches!(
            classify("mv", Some(1), "file already exists".to_owned()),
            BdpanError::DestinationExists { .. }
        ));
        assert!(matches!(
            classify("ls", Some(1), "目录不存在".to_owned()),
            BdpanError::NotFound { .. }
        ));
        assert!(matches!(
            classify("upload", Some(1), "网络异常：连接被重置".to_owned()),
            BdpanError::Unavailable { .. }
        ));
        assert!(matches!(
            classify("ls", Some(1), "路径超出授权目录范围: /lfs".to_owned()),
            BdpanError::Unexpected { .. }
        ));
        assert!(matches!(
            classify("upload", Some(2), "空间不足".to_owned()),
            BdpanError::Command { .. }
        ));
    }

    #[test]
    fn given_exit_code_without_json_when_interpret_then_exit_error() {
        let output = ProcessOutput {
            code: Some(3),
            stdout: "boom\n".to_owned(),
            stderr: "fake crash\n".to_owned(),
        };

        let err = interpret("quota", &output).expect_err("无 JSON 应报错");

        assert!(matches!(err, BdpanError::Exit { code: 3, .. }), "实际错误：{err}");
    }

    #[test]
    fn given_zero_exit_without_json_when_interpret_then_decode_error() {
        let output = ProcessOutput {
            code: Some(0),
            stdout: "no json here\n".to_owned(),
            stderr: String::new(),
        };

        let err = interpret("ls", &output).expect_err("无 JSON 应报错");

        assert!(matches!(err, BdpanError::Decode { .. }), "实际错误：{err}");
    }

    #[test]
    fn given_error_json_when_interpret_then_classified_failure() {
        let output = ProcessOutput {
            code: Some(0),
            stdout: "{\"code\":1,\"data\":null,\"error\":\"目录不存在\"}\n".to_owned(),
            stderr: String::new(),
        };

        let err = interpret("ls", &output).expect_err("业务失败应报错");

        assert!(matches!(err, BdpanError::NotFound { .. }), "实际错误：{err}");
    }
}

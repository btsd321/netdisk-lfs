//! 对象传输端点：上传、下载与上传后校验。
//!
//! 契约见 `specs/api.md` 与 `specs/storage.md`。三条容易踩的规则：
//!
//! - **内容寻址不可妥协**：PUT 先边收边算 sha256，与路径 oid 不符直接 422，
//!   只有校验通过的文件才会交给 `store.put`，绝不允许「先落最终路径再校验」；
//! - **全程流式**：4 GiB 级对象不整块进内存，PUT 用 64 KiB 缓冲边读 body 边写
//!   本地缓冲，GET 用 `ReaderStream` 边读文件边写响应体；
//! - **临时文件必须回收**：本地缓冲由 [`TempPath`] 守卫，正常返回、失败、
//!   future 被丢弃（客户端断连）三条路径都会删除。
//!
//! 本分支的 GET 取数走本地缓存：命中直接读缓存文件，未命中由缓存层的单飞锁触发
//! 一次 `store.fetch`（同 oid 并发只下载一次），Range 只读取区间对应的字节。

use std::future::poll_fn;
use std::io;
use std::io::SeekFrom;
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, HttpBody};
use axum::extract::{Extension, Path, State};
use axum::http::header;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncSeekExt, AsyncWriteExt, ReadBuf};
use tokio_util::io::ReaderStream;
use tracing::Instrument;

use super::error::ApiError;
use super::{
    AppState, DurationGuard, OUTCOME_ABORTED, OUTCOME_FAILED, OUTCOME_OK, OUTCOME_REJECTED,
    RequestId, outcome_for_status,
};
use crate::cache::CachedFile;
use crate::config::{Config, Role};
use crate::store::{HASH_BUFFER_BYTES, Oid, Sha256Writer, StoreError};

/// 上传缓冲子目录名，位于本地数据根下。
const UPLOAD_DIR: &str = "upload";

/// 未配置本地数据根时的上传缓冲目录名（落在系统临时目录）。
const UPLOAD_DIR_FALLBACK: &str = "netdisk-lfs-upload";

/// 下载响应的媒体类型；对象是无结构的二进制，LFS 客户端不解析内容。
const OCTET_STREAM: &str = "application/octet-stream";

/// verify 请求体上限：只有 `oid` 与 `size` 两个字段，给 8 KiB 已非常宽裕。
///
/// 单独设上限并返回 400 而不是让框架回 413，是为了让错误体仍是 LFS JSON
/// （客户端只认这一种错误格式）。
const MAX_VERIFY_BODY_BYTES: usize = 8 * 1024;

/// 上传缓冲目录。
///
/// 优先 `data_dir/upload`：与 `specs/storage.md` 的本地布局一致，也能和缓存目录
/// 分开清理。未配置 `NETDISK_LFS_DATA_DIR` 时退回系统临时目录，让 `cargo run`
/// 与一次性实验不必先建目录；代价是临时目录可能被重启清空、容量也偏小，
/// 因此只适合开发与测试，生产部署必须配置本地数据根。
///
/// 对外导出（`http::upload_dir`）是给启动清理用的：`main` 要清的是同一批目录，
/// 路径推导只能有一份实现，否则清理会漏掉某个回退分支。
pub fn upload_dir(config: &Config) -> PathBuf {
    config.data_dir.as_ref().map_or_else(
        || std::env::temp_dir().join(UPLOAD_DIR_FALLBACK),
        |root| root.join(UPLOAD_DIR),
    )
}

/// 本地文件操作失败统一映射成 500，并带上路径。
///
/// 直接构造 `ApiError::Internal` 会把路径丢掉；借道 `StoreError::io` 复用已有的
/// 「本地文件 xxx 操作失败」文案，日志里能直接定位是哪个缓冲文件。
fn local_io(path: &FsPath, error: io::Error) -> ApiError {
    ApiError::from(StoreError::io(path, error))
}

/// `PUT /lfs/objects/{oid}`：流式接收对象，校验 sha256 后交给存储层。
///
/// 只允许读写角色；只读账号即使带着合法 oid 也返回 403。
pub(crate) async fn put(
    State(state): State<AppState>,
    Extension(role): Extension<Role>,
    Extension(request_id): Extension<RequestId>,
    Path(raw_oid): Path<String>,
    body: Body,
) -> Response {
    let span = tracing::info_span!(
        "lfs.put",
        oid = tracing::field::Empty,
        bytes = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let guard = DurationGuard::new(span.clone());
    let outcome = receive(&state, role, &request_id, &raw_oid, body, &guard).instrument(span).await;
    match outcome {
        Ok(()) => {
            guard.finish(OUTCOME_OK);
            Response::new(Body::empty())
        },
        Err(error) => {
            guard.finish(outcome_for_status(error.status()));
            error.into_response_with(&request_id)
        },
    }
}

/// 收完 body、写本地缓冲、校验哈希并交给 `store.put`。
///
/// 成功返回时临时文件仍由 `TempPath` 在作用域结束时删除；任何提前返回都会
/// 先把 `file` 关掉再删文件（局部变量按声明逆序 Drop）。
async fn receive(
    state: &AppState,
    role: Role,
    request_id: &RequestId,
    raw_oid: &str,
    body: Body,
    guard: &DurationGuard,
) -> Result<(), ApiError> {
    let oid =
        Oid::parse(raw_oid).map_err(|error| ApiError::BadRequest(format!("oid 非法：{error}")))?;
    guard.span().record("oid", oid.as_str());

    // 角色检查放在读取 body 之前：只读账号的请求不该先落几个 GiB 的缓冲再被拒绝。
    if role != Role::Readwrite {
        return Err(ApiError::Forbidden("只读账号不允许上传对象".to_owned()));
    }

    let max_object_bytes = state.config().storage.max_object_bytes;
    let dir = upload_dir(state.config());
    fs::create_dir_all(&dir).await.map_err(|error| local_io(&dir, error))?;
    // 文件名带请求 id：同一 oid 的并发 PUT（客户端重试、两个分支同时推）不能共用
    // 一个缓冲文件，否则双方会互相截断/删除对方在途的内容。spec 的 `<uuid>.part`
    // 也是这个意思，这里用服务端 request id 代替随机 uuid。
    let temp = TempPath::new(dir.join(format!("{oid}-{request_id}.part")));
    let mut file =
        fs::File::create(temp.path()).await.map_err(|error| local_io(temp.path(), error))?;

    // 逐帧消费 body：`Body` 是异步 chunk 流，任何一步都不把整对象读进内存。
    // 用 `poll_frame` 而不是先收集成 `Bytes`，是为了让 4 GiB 上传的内存占用
    // 恒等于一个数据块。
    let mut body = body;
    let mut hasher = Sha256Writer::new();
    let mut received: u64 = 0;
    loop {
        let Some(frame) = poll_fn(|cx| Pin::new(&mut body).poll_frame(cx)).await else {
            break;
        };
        let frame =
            frame.map_err(|error| ApiError::BadRequest(format!("读取上传内容失败：{error}")))?;
        // trailer 等非数据帧本服务不消费，跳过即可。
        let Ok(chunk) = frame.into_data() else {
            continue;
        };
        received = received.saturating_add(chunk.len() as u64);
        // 超限即中止：不继续落盘，也不把这次请求当作完整对象。临时文件由守卫删除。
        // `max_object_bytes = 0` 表示不限制，只受磁盘与网盘约束。
        if max_object_bytes > 0 && received > max_object_bytes {
            return Err(ApiError::Unprocessable(format!(
                "对象超过单文件上限 {max_object_bytes} 字节"
            )));
        }
        hasher.update(&chunk);
        file.write_all(&chunk).await.map_err(|error| local_io(temp.path(), error))?;
        guard.record_bytes(received);
    }

    let digest = hasher.finish();
    if digest != oid.as_str() {
        // 期望值恒为 oid，复用存储层的错误构造，文案与其它哈希失败路径一致。
        return Err(ApiError::from(StoreError::hash_mismatch(&oid, &digest)));
    }

    // 关闭文件句柄再交给存储层读取，避免 Windows 上「文件被占用无法打开」。
    drop(file);
    state.store().put(&oid, temp.path()).await.map_err(ApiError::from)?;
    Ok(())
}

/// 临时文件守卫：离开作用域删除文件。
///
/// 用同步 `remove_file` 而不是 `async fn cleanup`：Drop 不能 await，而这里只是一次
/// unlink，耗时与一次内存分配同量级，不会卡住 runtime（与 B2 `StagingGuard` 同一取舍）。
struct TempPath(PathBuf);

impl TempPath {
    /// 绑定一个待清理路径；文件可以还不存在（删除时 NotFound 静默）。
    fn new(path: PathBuf) -> Self {
        Self(path)
    }

    /// 临时文件路径。
    fn path(&self) -> &FsPath {
        &self.0
    }
}

impl Drop for TempPath {
    fn drop(&mut self) {
        // 客户端断连时文件可能已由别的路径删掉，NotFound 属预期。
        match std::fs::remove_file(&self.0) {
            Ok(()) => {},
            Err(error) if error.kind() == io::ErrorKind::NotFound => {},
            Err(error) => {
                // abort 路径上 `tokio::fs::File` 的关闭可能被推迟到 blocking pool
                // （Drop 里不能同步关句柄），立删在 Windows 会撞共享冲突而不是
                // NotFound。这里不在 Drop 里阻塞等待，交给后台 blocking 任务重试；
                // 仍失败则留着给启动扫描（>1h 残留清理）兜底。
                if let Ok(handle) = tokio::runtime::Handle::try_current() {
                    let path = self.0.clone();
                    handle.spawn_blocking(move || remove_with_retry(&path));
                } else {
                    tracing::warn!(
                        path = %self.0.display(),
                        error = %error,
                        "清理传输临时文件失败"
                    );
                }
            },
        }
    }
}

/// 后台重试删除：只用于「句柄刚被延迟关闭」的竞态，最多等约 300 ms。
fn remove_with_retry(path: &FsPath) {
    for attempt in 1..=5_u64 {
        match std::fs::remove_file(path) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            Err(_) if attempt < 5 => {
                std::thread::sleep(std::time::Duration::from_millis(20 * attempt));
            },
            Err(error) => {
                tracing::warn!(
                    path = %path.display(),
                    error = %error,
                    "重试清理传输临时文件仍失败，留给启动扫描兜底"
                );
                return;
            },
        }
    }
}

/// `GET /lfs/objects/{oid}`：把对象流式返回，缓存命中时不触发后端下载。
///
/// `Range` 只支持单区间：`bytes=a-b`、`bytes=a-`、`bytes=-n` 回 `206` +
/// `Content-Range`；多区间与语法非法按 `specs/api.md`「多区间不支持，回 200 全量」
/// 忽略（不报 400）；语法合法但起点越界按 HTTP 语义回 416，见
/// [`ApiError::RangeNotSatisfiable`]。
///
/// 两种角色都允许下载。
pub(crate) async fn get(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(raw_oid): Path<String>,
    headers: HeaderMap,
) -> Response {
    let span = tracing::info_span!(
        "lfs.get",
        oid = tracing::field::Empty,
        bytes = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
        outcome = tracing::field::Empty,
        cache_hit = tracing::field::Empty,
        range = tracing::field::Empty,
    );
    let guard = DurationGuard::new(span.clone());
    // 取数阶段也要在 `lfs.get` 里：否则缓存与 `store(op=fetch)` 的子 span 会挂到
    // 外层 http.request 上，GET 与 PUT/verify 的 trace 结构不一致。
    let prepared = prepare_get(&state, &raw_oid, &span).instrument(span.clone()).await;
    let prepared = match prepared {
        Ok(prepared) => prepared,
        Err(error) => {
            guard.finish(outcome_for_status(error.status()));
            return error.into_response_with(&request_id);
        },
    };

    let total = prepared.size;
    let spec = parse_range(headers.get(header::RANGE), total);
    guard.span().record("range", range_label(spec, total));
    let (start, length, status) = match spec {
        RangeSpec::Full => (0, total, StatusCode::OK),
        RangeSpec::Partial { start, end } => (start, end - start + 1, StatusCode::PARTIAL_CONTENT),
        RangeSpec::Unsatisfiable => {
            // 已经下载/打开的文件要还回去：先关句柄再删中转文件（`Prepared` 的字段序）。
            guard.finish(OUTCOME_REJECTED);
            prepared.abandon();
            return ApiError::RangeNotSatisfiable { total }.into_response_with(&request_id);
        },
    };

    let Prepared { mut file, temp, path, .. } = prepared;
    // 只 seek 到区间起点，再用 `take` 限定长度：ReaderStream 照旧按 64 KiB 块读，
    // 4 GiB 对象的区间请求不会把区间整块读进内存。
    if start > 0
        && let Err(error) = file.seek(SeekFrom::Start(start)).await
    {
        guard.finish(OUTCOME_FAILED);
        drop(file);
        drop(temp);
        return local_io(&path, error).into_response_with(&request_id);
    }

    // 遥测交给响应体读取器：直到流真正结束（或客户端断开）才落 duration_ms，
    // 这样慢客户端的大对象下载也能看到真实传输耗时；`bytes` 记实际发送的字节数，
    // Range 时就是区间长度。
    let reader = BodyReader::new(file.take(length), temp, guard, length);
    let stream = ReaderStream::with_capacity(reader, HASH_BUFFER_BYTES);
    let mut response = Response::new(Body::from_stream(stream));
    let response_headers = response.headers_mut();
    response_headers.insert(header::CONTENT_TYPE, HeaderValue::from_static(OCTET_STREAM));
    // `Content-Length` 必填（api.md）；u64 的十进制形式是合法头值，转换不会失败。
    response_headers.insert(header::CONTENT_LENGTH, HeaderValue::from(length));
    // 声明支持区间，客户端才会在续传时直接带 Range 试一次。
    response_headers.insert(header::ACCEPT_RANGES, HeaderValue::from_static("bytes"));
    if let RangeSpec::Partial { .. } = spec {
        match HeaderValue::from_str(&content_range(start, start + length - 1, total)) {
            Ok(value) => {
                response_headers.insert(header::CONTENT_RANGE, value);
            },
            // 头值只含数字与分隔符，实际不会失败；真失败也只是少一个头，body 仍正确。
            Err(error) => tracing::error!(error = %error, "构造 Content-Range 响应头失败"),
        }
    }
    *response.status_mut() = status;
    response
}

/// 一次 GET 的本地文件：已打开、大小已知，清理责任一并带出来。
///
/// 字段顺序是有意的：`file` 在 `temp` 之前，整体 Drop 时先关句柄再删中转文件
/// （先删后关在 Windows 上会撞共享冲突，B5 已踩过）。
struct Prepared {
    /// 待发送的文件句柄。
    file: fs::File,
    /// 中转文件守卫；缓存命中为 `None`——缓存对象不能随响应删除。
    temp: Option<TempPath>,
    /// 文件真实大小；`Content-Length` 与 Range 的总量都用它。
    size: u64,
    /// 本地路径，仅用于错误信息与日志。
    path: PathBuf,
}

impl Prepared {
    /// 放弃这次响应：先关句柄，再让临时文件守卫删文件（顺序与 [`BodyReader`] 一致）。
    fn abandon(self) {
        let Self { file, temp, .. } = self;
        drop(file);
        drop(temp);
    }
}

/// 定位到本地文件：缓存命中只打开文件，未命中则单飞下载、入缓存后打开。
///
/// 404 只来自后端，且**不入缓存**（不缓存负面结果）：先 404、之后上传成功的对象，
/// 下一次 GET 能正常命中。
async fn prepare_get(
    state: &AppState,
    raw_oid: &str,
    span: &tracing::Span,
) -> Result<Prepared, ApiError> {
    let oid =
        Oid::parse(raw_oid).map_err(|error| ApiError::BadRequest(format!("oid 非法：{error}")))?;
    span.record("oid", oid.as_str());
    let cache = state.cache();

    // 命中路径：不触发 `store.fetch`，也不写缓存文件（spec「只读命中不写盘」）。
    if let Some(path) = cache.get(&oid).await {
        match open_local(&path).await {
            Ok((file, size)) => {
                span.record("cache_hit", true);
                return Ok(Prepared { file, temp: None, size, path });
            },
            Err(error) => {
                // `get` 刚校验过大小，这里失败只可能是「命中后被并发驱逐或删除」：
                // 丢掉索引项后按未命中重新下载，不把这次请求当 500。
                tracing::debug!(
                    oid = %oid,
                    error = error.message(),
                    "缓存命中后打开失败，驱逐索引项后重新下载"
                );
                cache.forget(&oid);
            },
        }
    }
    span.record("cache_hit", false);

    let store = state.store();
    let fetch_oid = oid.clone();
    let fetched = cache
        .fetch_once(&oid, move |part: PathBuf| async move { store.fetch(&fetch_oid, &part).await })
        .await
        .map_err(ApiError::from)?;
    // `Transient` 是超过预算（或缓存已降级）的直通文件：响应结束必须删；
    // `Cached` 是缓存对象，跟着响应删就等于把缓存清空。
    let path = fetched.path().to_path_buf();
    let temp = match fetched {
        CachedFile::Cached(_) => None,
        CachedFile::Transient(_) => Some(TempPath::new(path.clone())),
    };
    let (file, size) = open_local(&path).await?;
    Ok(Prepared { file, temp, size, path })
}

/// 打开本地文件并取真实大小（`Content-Length` 与 Range 的总量都用它）。
async fn open_local(path: &FsPath) -> Result<(fs::File, u64), ApiError> {
    let file = fs::File::open(path).await.map_err(|error| local_io(path, error))?;
    let size = file.metadata().await.map_err(|error| local_io(path, error))?.len();
    Ok((file, size))
}

/// `Range` 请求头的解析结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum RangeSpec {
    /// 忽略 `Range`，回 200 全量。
    Full,
    /// 单区间（闭区间），回 206。
    Partial {
        /// 区间起点。
        start: u64,
        /// 区间终点（含）。
        end: u64,
    },
    /// 语法正确但起点越界，回 416。
    Unsatisfiable,
}

/// 解析 `Range` 头；语义以 `specs/api.md`「GET /lfs/objects/{oid}」为准。
///
/// 取舍：
///
/// - 只支持 `bytes` 单位与**单区间**。多区间（含逗号）与语法非法一律回
///   [`RangeSpec::Full`]：客户端拿全量还能用，回 400 只会让 `git-lfs` 直接失败；
/// - 语法合法但 `start >= total`（含空对象上请求区间、`bytes=-0`）→
///   [`RangeSpec::Unsatisfiable`]，按 RFC 9110 回 416 而不是假装满足；
/// - `end` 越过对象末尾时截到最后一个字节（RFC 要求），不算越界。
fn parse_range(raw: Option<&HeaderValue>, total: u64) -> RangeSpec {
    let Some(raw) = raw else {
        return RangeSpec::Full;
    };
    let Ok(text) = raw.to_str() else {
        tracing::debug!("Range 头不是可见 ASCII，按全量处理");
        return RangeSpec::Full;
    };
    let Some(spec) = text.strip_prefix("bytes=") else {
        tracing::debug!(range = text, "不支持的 Range 单位，按全量处理");
        return RangeSpec::Full;
    };
    if spec.contains(',') {
        tracing::debug!(range = text, "多区间 Range 不支持，按 api.md 回 200 全量");
        return RangeSpec::Full;
    }
    let spec = spec.trim();
    let Some((first, last)) = spec.split_once('-') else {
        tracing::debug!(range = text, "Range 缺少 '-'，按全量处理");
        return RangeSpec::Full;
    };
    let (first, last) = (first.trim(), last.trim());

    if first.is_empty() {
        // 后缀区间 `bytes=-n`：最后 n 个字节。
        let Ok(suffix) = last.parse::<u64>() else {
            tracing::debug!(range = text, "后缀区间长度非法，按全量处理");
            return RangeSpec::Full;
        };
        if suffix == 0 || total == 0 {
            return RangeSpec::Unsatisfiable;
        }
        return RangeSpec::Partial { start: total.saturating_sub(suffix), end: total - 1 };
    }

    let Ok(start) = first.parse::<u64>() else {
        tracing::debug!(range = text, "区间起点非法，按全量处理");
        return RangeSpec::Full;
    };
    if start >= total {
        return RangeSpec::Unsatisfiable;
    }
    if last.is_empty() {
        return RangeSpec::Partial { start, end: total - 1 };
    }
    let Ok(end) = last.parse::<u64>() else {
        tracing::debug!(range = text, "区间终点非法，按全量处理");
        return RangeSpec::Full;
    };
    if end < start {
        tracing::debug!(range = text, "区间终点小于起点，按全量处理");
        return RangeSpec::Full;
    }
    RangeSpec::Partial { start, end: end.min(total - 1) }
}

/// `Content-Range` 的头值：`bytes {start}-{end}/{total}`。
fn content_range(start: u64, end: u64, total: u64) -> String {
    format!("bytes {start}-{end}/{total}")
}

/// `lfs.get` span 里记录 Range 的处置结果，便于排查「为什么回 200 而不是 206」。
fn range_label(spec: RangeSpec, total: u64) -> String {
    match spec {
        RangeSpec::Full => "full".to_owned(),
        RangeSpec::Unsatisfiable => format!("unsatisfiable/{total}"),
        RangeSpec::Partial { start, end } => content_range(start, end, total),
    }
}

/// `POST /lfs/objects/{oid}/verify`：回查对象存在且大小与声明一致。
///
/// 按 `specs/api.md`：存在且大小一致 → 200，否则 422（缺失也算校验失败，不是 404）。
/// 只读账号允许调用：它只读取存在性，不改变任何状态。
pub(crate) async fn verify(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(raw_oid): Path<String>,
    body: Body,
) -> Response {
    let span = tracing::info_span!(
        "lfs.verify",
        oid = tracing::field::Empty,
        bytes = tracing::field::Empty,
        declared_bytes = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let guard = DurationGuard::new(span.clone());
    let outcome = check(&state, &raw_oid, body, &guard).instrument(span).await;
    match outcome {
        Ok(()) => {
            guard.finish(OUTCOME_OK);
            Response::new(Body::empty())
        },
        Err(error) => {
            guard.finish(outcome_for_status(error.status()));
            error.into_response_with(&request_id)
        },
    }
}

/// verify 请求体；未知字段忽略，兼容客户端附加字段。
#[derive(Debug, serde::Deserialize)]
struct VerifyRequest {
    /// 客户端声明的 oid；必须与路径一致。
    oid: String,
    /// 客户端声明的字节数；与存储层权威大小比较。
    size: u64,
}

/// 读取并校验 verify 请求体。
async fn check(
    state: &AppState,
    raw_oid: &str,
    body: Body,
    guard: &DurationGuard,
) -> Result<(), ApiError> {
    let oid =
        Oid::parse(raw_oid).map_err(|error| ApiError::BadRequest(format!("oid 非法：{error}")))?;
    guard.span().record("oid", oid.as_str());

    let bytes = axum::body::to_bytes(body, MAX_VERIFY_BODY_BYTES)
        .await
        .map_err(|error| ApiError::BadRequest(format!("读取 verify 请求体失败：{error}")))?;
    // `bytes` 字段语义是「本请求实际处理的字节数」，与 put/get 一致；
    // 客户端声明的大小只作为观测值放 `declared_bytes`，不能拿去冒充流量。
    guard.record_bytes(bytes.len() as u64);
    let request: VerifyRequest = serde_json::from_slice(&bytes)
        .map_err(|error| ApiError::BadRequest(format!("verify 请求体不是合法 JSON：{error}")))?;
    guard.span().record("declared_bytes", request.size);

    let body_oid = Oid::parse(&request.oid)
        .map_err(|error| ApiError::BadRequest(format!("请求体 oid 非法：{error}")))?;
    if body_oid != oid {
        return Err(ApiError::BadRequest(format!("请求体 oid {body_oid} 与路径 oid {oid} 不一致")));
    }

    match state.store().exists(&oid).await.map_err(ApiError::from)? {
        Some(meta) if meta.size == request.size => Ok(()),
        Some(meta) => Err(ApiError::Unprocessable(format!(
            "对象 {oid} 大小不符：请求体声明 {} 字节，实际 {} 字节",
            request.size, meta.size
        ))),
        None => Err(ApiError::Unprocessable(format!("对象 {oid} 不存在，无法通过校验"))),
    }
}

/// 响应体读取器：边读文件边累计已发送字节，读尽/断开时落遥测并清理临时文件。
///
/// 直接实现 [`AsyncRead`] 而不是自己写 `Stream`：`ReaderStream` 负责把
/// `AsyncRead` 适配成 `Stream`，这里只需关心计数与收尾，避免 `pin-project`/
/// `unsafe`（本仓库 `unsafe_code = "forbid"`）。
///
/// 读取端是泛型：全量响应是 `fs::File`，Range 响应是 seek 过的 `Take<fs::File>`，
/// 两种形态都能直接套 `ReaderStream`，不需要为 Range 单独写一条发送路径。
struct BodyReader<R> {
    /// 待发送的读取端；声明在 `_temp` 之前，Drop 时先关闭句柄再删文件。
    reader: R,
    /// 中转文件守卫；缓存命中时为 `None`（缓存对象要留着给下一个请求）。
    ///
    /// 下划线前缀是刻意的：字段只靠 Drop 生效、从不被读，直接叫 `temp` 会触发
    /// `dead_code`，而这里又不能加 `#[allow]`（本仓库 lint 集中在 Cargo.toml）。
    _temp: Option<TempPath>,
    /// 遥测守卫：读到 EOF 后取出并 `finish`，否则由 Drop 按已发字节数收尾。
    telemetry: Option<DurationGuard>,
    /// 已读出的字节数。
    bytes: u64,
    /// 期望发送的总字节数（Content-Length）：Drop 时据此区分「发完」与「断连」。
    expected: u64,
}

impl<R> BodyReader<R> {
    /// 绑定读取端、清理守卫、遥测守卫与期望发送长度。
    fn new(reader: R, temp: Option<TempPath>, guard: DurationGuard, expected: u64) -> Self {
        Self { reader, _temp: temp, telemetry: Some(guard), bytes: 0, expected }
    }

    /// 结束遥测；重复调用无副作用（`telemetry` 取出后即为 `None`）。
    fn settle(&mut self, outcome: &'static str) {
        if let Some(guard) = self.telemetry.take() {
            guard.record_bytes(self.bytes);
            guard.finish(outcome);
        }
    }
}

impl<R: AsyncRead + Unpin> AsyncRead for BodyReader<R> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `R: Unpin` 且其余字段都 `Unpin`，可以从 Pin 里安全取出可变引用。
        let this = self.as_mut().get_mut();
        let filled_before = buf.filled().len();
        match Pin::new(&mut this.reader).poll_read(cx, buf) {
            Poll::Pending => Poll::Pending,
            Poll::Ready(Ok(())) => {
                let read = buf.filled().len() - filled_before;
                this.bytes = this.bytes.saturating_add(read as u64);
                // 读 0 字节即 EOF：此时告诉遥测「正常完成」，后续 Drop 不再改写 outcome。
                if read == 0 {
                    this.settle(OUTCOME_OK);
                }
                Poll::Ready(Ok(()))
            },
            Poll::Ready(Err(error)) => {
                // 本地读失败：响应已经发了一半，只能记 failed 并让连接断开。
                this.settle(OUTCOME_FAILED);
                Poll::Ready(Err(error))
            },
        }
    }
}

/// Drop 时的收尾结论：已读出字节达到期望长度记 ok，否则 aborted。
///
/// 近似说明：`bytes` 是**从本地文件读出**的字节数（交给 ReaderStream 的缓冲），
/// 不是已写入 socket 的字节数。客户端在最后一块读完之后、刷出之前断开时，这里
/// 仍会记 ok——窗口很小（≤64 KiB），只影响遥测口径，不影响数据正确性。
fn dropped_outcome(bytes: u64, expected: u64) -> &'static str {
    if bytes >= expected { OUTCOME_OK } else { OUTCOME_ABORTED }
}

impl<R> Drop for BodyReader<R> {
    fn drop(&mut self) {
        // 走到这里还没 settle 的原因有两种：客户端断连，或 hyper 在 Content-Length
        // 满足后直接丢弃 body（不再 poll 到 EOF，小对象尤其常见）。按已读出字节数
        // 与期望长度比较，避免把成功记成 aborted（口径近似见 `dropped_outcome`）。
        let outcome = dropped_outcome(self.bytes, self.expected);
        self.settle(outcome);
        // `reader`、`_temp` 随后按声明顺序 Drop：先关文件，再删中转文件。
    }
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;

    use super::{RangeSpec, content_range, dropped_outcome, parse_range};
    use crate::http::{OUTCOME_ABORTED, OUTCOME_OK};

    /// 造一个 `Range` 头值。
    fn range(value: &str) -> HeaderValue {
        HeaderValue::from_str(value).expect("测试用 Range 头值合法")
    }

    #[test]
    fn given_bytes_and_expected_when_dropped_outcome_then_completion_classified() {
        // 发满（含 0 字节空对象）→ ok；没发完 → aborted。
        assert_eq!(dropped_outcome(43, 43), OUTCOME_OK);
        assert_eq!(dropped_outcome(0, 0), OUTCOME_OK, "空对象不发字节也算完成");
        assert_eq!(dropped_outcome(42, 43), OUTCOME_ABORTED);
    }

    #[test]
    fn given_no_range_header_when_parse_then_full() {
        assert_eq!(parse_range(None, 10), RangeSpec::Full);
    }

    #[test]
    fn given_closed_range_when_parse_then_partial() {
        assert_eq!(
            parse_range(Some(&range("bytes=0-3")), 10),
            RangeSpec::Partial { start: 0, end: 3 }
        );
        assert_eq!(
            parse_range(Some(&range("bytes=4-4")), 10),
            RangeSpec::Partial { start: 4, end: 4 }
        );
    }

    #[test]
    fn given_open_ended_range_when_parse_then_partial_to_last_byte() {
        assert_eq!(
            parse_range(Some(&range("bytes=5-")), 10),
            RangeSpec::Partial { start: 5, end: 9 }
        );
    }

    #[test]
    fn given_suffix_range_when_parse_then_last_n_bytes() {
        assert_eq!(
            parse_range(Some(&range("bytes=-2")), 10),
            RangeSpec::Partial { start: 8, end: 9 }
        );
        // 后缀长度超过对象大小时从头开始，不是越界。
        assert_eq!(
            parse_range(Some(&range("bytes=-99")), 10),
            RangeSpec::Partial { start: 0, end: 9 }
        );
    }

    #[test]
    fn given_end_beyond_object_when_parse_then_clamped_to_last_byte() {
        assert_eq!(
            parse_range(Some(&range("bytes=0-99")), 4),
            RangeSpec::Partial { start: 0, end: 3 }
        );
    }

    #[test]
    fn given_start_beyond_object_when_parse_then_unsatisfiable() {
        assert_eq!(parse_range(Some(&range("bytes=999-")), 4), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range(Some(&range("bytes=4-5")), 4), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range(Some(&range("bytes=0-")), 0), RangeSpec::Unsatisfiable);
        assert_eq!(parse_range(Some(&range("bytes=-0")), 4), RangeSpec::Unsatisfiable);
    }

    #[test]
    fn given_multiple_ranges_when_parse_then_full() {
        assert_eq!(parse_range(Some(&range("bytes=0-1,3-4")), 10), RangeSpec::Full);
    }

    #[test]
    fn given_malformed_range_when_parse_then_full() {
        for value in [
            "bytes=abc-def",
            "bytes=",
            "bytes=3",
            "bytes=5-1",
            "bytes=-abc",
            "items=0-3",
            "bytes=--1",
        ] {
            assert_eq!(
                parse_range(Some(&range(value)), 10),
                RangeSpec::Full,
                "{value} 应按全量处理"
            );
        }
    }

    #[test]
    fn given_partial_range_when_content_range_then_http_format() {
        assert_eq!(content_range(0, 3, 10), "bytes 0-3/10");
        assert_eq!(content_range(8, 9, 10), "bytes 8-9/10");
    }
}

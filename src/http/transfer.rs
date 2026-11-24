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
//! 本分支的 GET 每次经 `store.fetch` 落一个临时文件再流式返回；缓存与 Range 归
//! 缓存分支，届时替换 `prepare_get` 的取数来源即可，路由与响应形态不变。

use std::future::poll_fn;
use std::io;
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;
use std::task::{Context, Poll};

use axum::body::{Body, HttpBody};
use axum::extract::{Extension, Path, State};
use axum::http::HeaderValue;
use axum::http::header;
use axum::response::Response;
use tokio::fs;
use tokio::io::{AsyncRead, AsyncWriteExt, ReadBuf};
use tokio_util::io::ReaderStream;
use tracing::Instrument;

use super::error::ApiError;
use super::{
    AppState, DurationGuard, OUTCOME_ABORTED, OUTCOME_FAILED, OUTCOME_OK, RequestId,
    outcome_for_status,
};
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
fn upload_dir(config: &Config) -> PathBuf {
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
        if received > max_object_bytes {
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
        if let Err(error) = std::fs::remove_file(&self.0)
            && error.kind() != io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.0.display(), error = %error, "清理传输临时文件失败");
        }
    }
}

/// `GET /lfs/objects/{oid}`：把对象整份流式返回。
///
/// 本分支不做 Range 与缓存：`Range` 请求头按「忽略并回全量 200」处理（与
/// `specs/api.md`「多区间不支持，回 200 全量」一致），缓存命中/单飞下载留给
/// 缓存分支，届时只需替换 [`prepare_get`] 的取数来源。
///
/// 两种角色都允许下载。
pub(crate) async fn get(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    Path(raw_oid): Path<String>,
) -> Response {
    let span = tracing::info_span!(
        "lfs.get",
        oid = tracing::field::Empty,
        bytes = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
        outcome = tracing::field::Empty,
    );
    let guard = DurationGuard::new(span.clone());
    match prepare_get(&state, &request_id, &raw_oid, &span).await {
        Ok((file, temp, size)) => {
            // 遥测交给响应体读取器：直到流真正结束（或客户端断开）才落 duration_ms，
            // 这样慢客户端的大对象下载也能看到真实传输耗时。
            let reader = BodyReader::new(file, temp, guard);
            let stream = ReaderStream::with_capacity(reader, HASH_BUFFER_BYTES);
            let mut response = Response::new(Body::from_stream(stream));
            response
                .headers_mut()
                .insert(header::CONTENT_TYPE, HeaderValue::from_static(OCTET_STREAM));
            // `Content-Length` 必填（api.md）；u64 的十进制形式是合法头值，转换不会失败。
            response.headers_mut().insert(header::CONTENT_LENGTH, HeaderValue::from(size));
            response
        },
        Err(error) => {
            guard.finish(outcome_for_status(error.status()));
            error.into_response_with(&request_id)
        },
    }
}

/// 解析 oid、下载到本地中转文件并打开待发送的文件句柄。
///
/// 返回的 [`TempPath`] 由调用方转交给 [`BodyReader`]：响应体没读完之前不能删文件，
/// 所以清理责任不能留在本函数里。
async fn prepare_get(
    state: &AppState,
    request_id: &RequestId,
    raw_oid: &str,
    span: &tracing::Span,
) -> Result<(fs::File, TempPath, u64), ApiError> {
    let oid =
        Oid::parse(raw_oid).map_err(|error| ApiError::BadRequest(format!("oid 非法：{error}")))?;
    span.record("oid", oid.as_str());

    let dir = download_dir(state.config());
    fs::create_dir_all(&dir).await.map_err(|error| local_io(&dir, error))?;
    // 与上传缓冲同理：同一 oid 的并发 GET 各用一个文件，互不覆盖。
    let temp = TempPath::new(dir.join(format!("{oid}-{request_id}.part")));
    // NotFound 由 From<StoreError> 映射成 404；其它失败按后端错误处理。
    state.store().fetch(&oid, temp.path()).await.map_err(ApiError::from)?;
    // Content-Length 用落盘后的真实大小：fetch 已校验过 sha256，这个值即对象大小。
    let size = fs::metadata(temp.path()).await.map_err(|error| local_io(temp.path(), error))?.len();
    let file = fs::File::open(temp.path()).await.map_err(|error| local_io(temp.path(), error))?;
    Ok((file, temp, size))
}

/// 下载中转目录：沿用 `[cache] dir`，与 `specs/storage.md` 的 `cache/<oid>.part` 一致。
///
/// 缓存分支会在同一个目录里做 LRU 与单飞；本分支每请求用独立文件名、响应结束即删，
/// 不会与将来的缓存对象混淆（缓存对象不带 `.part` 后缀）。
fn download_dir(config: &Config) -> PathBuf {
    config.cache.dir.clone()
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
    let request: VerifyRequest = serde_json::from_slice(&bytes)
        .map_err(|error| ApiError::BadRequest(format!("verify 请求体不是合法 JSON：{error}")))?;
    guard.record_bytes(request.size);

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

/// 响应体读取器：边读文件边累计已发送字节，读尽/断开时落遥测并删临时文件。
///
/// 直接实现 [`AsyncRead`] 而不是自己写 `Stream`：`ReaderStream` 负责把
/// `AsyncRead` 适配成 `Stream`，这里只需关心计数与收尾，避免 `pin-project`/
/// `unsafe`（本仓库 `unsafe_code = "forbid"`）。
struct BodyReader {
    /// 待发送的本地文件；声明在 `_temp` 之前，Drop 时先关闭句柄再删文件。
    file: fs::File,
    /// 临时文件守卫，随读取器一起被丢弃。
    ///
    /// 下划线前缀是刻意的：字段只靠 Drop 生效、从不被读，直接叫 `temp` 会触发
    /// `dead_code`，而这里又不能加 `#[allow]`（本仓库 lint 集中在 Cargo.toml）。
    _temp: TempPath,
    /// 遥测守卫：读到 EOF 后取出并 `finish`，否则（客户端断连）由 Drop 记 aborted。
    telemetry: Option<DurationGuard>,
    /// 已读出的字节数。
    bytes: u64,
}

impl BodyReader {
    /// 绑定文件、清理守卫与遥测守卫。
    fn new(file: fs::File, temp: TempPath, guard: DurationGuard) -> Self {
        Self { file, _temp: temp, telemetry: Some(guard), bytes: 0 }
    }

    /// 结束遥测；重复调用无副作用（`telemetry` 取出后即为 `None`）。
    fn settle(&mut self, outcome: &'static str) {
        if let Some(guard) = self.telemetry.take() {
            guard.record_bytes(self.bytes);
            guard.finish(outcome);
        }
    }
}

impl AsyncRead for BodyReader {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        // `BodyReader` 的字段都是 `Unpin`，可以从 Pin 里安全取出可变引用。
        let this = self.as_mut().get_mut();
        let filled_before = buf.filled().len();
        match Pin::new(&mut this.file).poll_read(cx, buf) {
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

impl Drop for BodyReader {
    fn drop(&mut self) {
        // 走到这里还没 settle，说明响应体没读完就被丢弃：客户端断连或响应被取消。
        self.settle(OUTCOME_ABORTED);
        // `file`、`_temp` 随后按声明顺序 Drop：先关文件，再删临时文件。
    }
}

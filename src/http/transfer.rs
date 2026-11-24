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
use std::path::{Path as FsPath, PathBuf};
use std::pin::Pin;

use axum::body::{Body, HttpBody};
use axum::extract::{Extension, Path, State};
use axum::response::Response;
use tokio::fs;
use tokio::io::AsyncWriteExt;
use tracing::Instrument;

use super::error::ApiError;
use super::{AppState, DurationGuard, OUTCOME_OK, RequestId, outcome_for_status};
use crate::config::{Config, Role};
use crate::store::{Oid, Sha256Writer, StoreError};

/// 上传缓冲子目录名，位于本地数据根下。
const UPLOAD_DIR: &str = "upload";

/// 未配置本地数据根时的上传缓冲目录名（落在系统临时目录）。
const UPLOAD_DIR_FALLBACK: &str = "netdisk-lfs-upload";

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
fn local_io(path: &FsPath, error: std::io::Error) -> ApiError {
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
            && error.kind() != std::io::ErrorKind::NotFound
        {
            tracing::warn!(path = %self.0.display(), error = %error, "清理传输临时文件失败");
        }
    }
}

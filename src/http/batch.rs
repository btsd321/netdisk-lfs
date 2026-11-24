//! `POST /lfs/objects/batch`：批量协商上传/下载。
//!
//! 契约见 `specs/api.md`。两条容易踩的规则：
//!
//! - 单个对象的错误写进 `objects[].error`，HTTP 仍是 200；只有整体失败
//!   （请求体非法、批次超限、`bdpan` 失败）才用 4xx/5xx；
//! - `href` 一律返回**相对路径**，由客户端按请求 URL 解析，避免反代后主机名错乱。
//!
//! 上传协商只在对象不存在时给 `upload` action；已存在则不给（客户端据此跳过传输），
//! 但附带 `verify` 让客户端补一次校验。

use std::collections::BTreeMap;
use std::sync::Arc;
use std::time::Instant;

use axum::body::Bytes;
use axum::extract::{Extension, State};
use axum::response::Response;
use serde::{Deserialize, Serialize};
use tokio::task::JoinSet;
use tracing::Instrument;

use super::error::ApiError;
use super::{AppState, RequestId, action_base, json_response, object_href, verify_href};
use crate::config::Role;
use crate::store::{ObjectMeta, Oid, StoreError};

/// batch 单次最多对象数，见 `specs/storage.md`「并发与限流」。
const MAX_BATCH_OBJECTS: usize = 100;

/// 唯一实现的 transfer 名；响应固定回它。
const TRANSFER_BASIC: &str = "basic";

/// 支持的哈希算法；缺省也按 sha256 处理。
const HASH_ALGO_SHA256: &str = "sha256";

/// batch 请求体。
///
/// 未知字段一律忽略（serde 默认行为）：客户端版本差异不应让请求整体失败。
/// `transfers` 与 `ref` 只用于日志，不影响协商结果——本服务只实现 basic。
#[derive(Debug, Deserialize)]
struct BatchRequest {
    /// `upload` 或 `download`；非法值在 handler 里映射成 400。
    operation: String,
    /// 客户端支持的 transfer 列表；缺省视为不限制。
    #[serde(default)]
    transfers: Vec<String>,
    /// 客户端 git ref，只用于日志定位（如 `refs/heads/main`）。
    #[serde(default, rename = "ref")]
    reference: Option<BatchRef>,
    /// 待协商对象。
    objects: Vec<ObjectSpec>,
    /// `sha256`；缺省接受。
    #[serde(default)]
    hash_algo: Option<String>,
}

/// 请求里的 `ref` 字段。
#[derive(Debug, Deserialize)]
struct BatchRef {
    /// 完整 ref 名，如 `refs/heads/main`。
    name: String,
}

/// 请求里的单个对象声明。
#[derive(Debug, Deserialize)]
struct ObjectSpec {
    /// 客户端声明的 oid（64 位十六进制）。
    oid: String,
    /// 客户端声明的字节数。
    size: u64,
}

/// 协商操作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Operation {
    /// 上传。
    Upload,
    /// 下载。
    Download,
}

impl Operation {
    /// 从请求字段解析；只接受 `upload` / `download`。
    fn parse(raw: &str) -> Result<Self, ApiError> {
        match raw {
            "upload" => Ok(Self::Upload),
            "download" => Ok(Self::Download),
            other => Err(ApiError::BadRequest(format!(
                "不支持的 operation：{other}，只接受 upload 或 download"
            ))),
        }
    }
}

/// batch 端点：整体失败返回 4xx/5xx，单对象失败写进 `objects[].error`。
pub(crate) async fn handle(
    State(state): State<AppState>,
    Extension(role): Extension<Role>,
    Extension(request_id): Extension<RequestId>,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let started = Instant::now();
    let span = tracing::info_span!(
        "lfs.batch",
        operation = tracing::field::Empty,
        objects = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
    );
    // git-lfs 要求 action href 是绝对 URL（相对路径会被拒），基地址优先取
    // `server.public_base`，否则按 Host / X-Forwarded-Proto 推导。
    let base = action_base(state.config(), &headers);
    let outcome = negotiate(&state, role, &request_id, &base, &body).instrument(span.clone()).await;
    span.record("duration_ms", started.elapsed().as_secs_f64() * 1_000.0);
    let response = match outcome {
        Ok(response) => json_response(&response, &request_id),
        Err(error) => error.into_response_with(&request_id),
    };
    // 完成事件必须在 span 内发出：fmt layer 只在事件发生时渲染 span 字段，
    // 若 record 之后再无事件，`duration_ms` 就永远不会落盘（与 request_span 一致）。
    span.in_scope(|| tracing::info!(status = response.status().as_u16(), "batch 处理完成"));
    response
}

/// 解析并协商整批对象；返回体只表达成功路径，整体失败用 [`ApiError`]。
async fn negotiate(
    state: &AppState,
    role: Role,
    request_id: &RequestId,
    base: &str,
    body: &[u8],
) -> Result<BatchResponse, ApiError> {
    let request: BatchRequest = serde_json::from_slice(body)
        .map_err(|error| ApiError::BadRequest(format!("请求体不是合法 JSON：{error}")))?;

    let operation = Operation::parse(&request.operation)?;
    // 角色检查放在对象校验之前：只读账号的 upload 请求不必再消耗网盘探测。
    if operation == Operation::Upload && role == Role::Readonly {
        return Err(ApiError::Forbidden("只读账号不允许 upload 操作".to_owned()));
    }

    if let Some(hash_algo) = request.hash_algo.as_deref()
        && !hash_algo.eq_ignore_ascii_case(HASH_ALGO_SHA256)
    {
        return Err(ApiError::BadRequest(format!(
            "不支持的 hash_algo：{hash_algo}，只接受 sha256"
        )));
    }

    if request.objects.len() > MAX_BATCH_OBJECTS {
        return Err(ApiError::BadRequest(format!(
            "batch 单次最多 {MAX_BATCH_OBJECTS} 个对象，实际 {}",
            request.objects.len()
        )));
    }

    // 批次级字段记到 span 上：外层 http.request 只有路径与总耗时，
    // 这里补 operation / objects，便于按操作类型聚合慢批次。
    let span = tracing::Span::current();
    span.record("operation", request.operation.as_str());
    span.record("objects", request.objects.len());

    tracing::debug!(
        request_id = %request_id,
        operation = %request.operation,
        transfers = ?request.transfers,
        reference = request.reference.as_ref().map(|reference| reference.name.as_str()),
        objects = request.objects.len(),
        "batch 请求"
    );

    // 先校验全部 oid，再碰存储：避免「前半批已查过网盘、后半批才发现格式错」。
    let mut parsed = Vec::with_capacity(request.objects.len());
    for object in &request.objects {
        let oid = Oid::parse(&object.oid)
            .map_err(|error| ApiError::BadRequest(format!("请求含非法 oid：{error}")))?;
        parsed.push((oid, object.size));
    }

    let max_object_bytes = state.config().storage.max_object_bytes;

    // 并发探测：每个 exists 在 BdpanStore 上是一次 bdpan 子进程 + 网络往返，
    // 100 个对象串行会让 push/pull 的首字节延迟叠加到分钟级。并发度由 BdpanClient
    // 内部的信号量（max_bdpan_procs）兜底，这里不再另造限流器；结果按索引回填，
    // 保证响应顺序与请求一致。超限对象不探测，直接给对象级 422。
    let store = state.store();
    let mut probes = JoinSet::new();
    for (index, (oid, size)) in parsed.iter().enumerate() {
        if *size > max_object_bytes {
            continue;
        }
        let store = Arc::clone(&store);
        let oid = oid.clone();
        probes.spawn(async move { (index, store.exists(&oid).await) });
    }
    let mut probed: Vec<Option<Result<Option<ObjectMeta>, StoreError>>> =
        parsed.iter().map(|_| None).collect();
    while let Some(joined) = probes.join_next().await {
        let (index, result) =
            joined.map_err(|error| ApiError::Internal(format!("探测任务异常：{error}")))?;
        probed[index] = Some(result);
    }

    let mut objects = Vec::with_capacity(parsed.len());
    for (index, (oid, size)) in parsed.iter().enumerate() {
        // 超限是单对象问题，不影响同批次其它对象：按 api.md 放 objects[].error(422)。
        if *size > max_object_bytes {
            objects.push(ObjectResponse::with_error(
                oid,
                *size,
                422,
                format!("对象 {oid} 大小 {size} 字节超过单文件上限 {max_object_bytes} 字节"),
            ));
            continue;
        }

        let existing = match probed[index].take() {
            Some(result) => result.map_err(ApiError::from)?,
            // 每个非超限对象都排进了探测任务，缺结果说明内部状态与探测计划不一致。
            None => return Err(ApiError::Internal("探测结果缺失".to_owned())),
        };
        // 存储层返回的对象大小是服务端权威值：客户端声明的 size 可能来自过期的
        // pointer 文件，不能原样回显——客户端用它当下载预期大小。
        let response = match (operation, existing) {
            (Operation::Download, Some(meta)) => ObjectResponse::for_download(base, oid, meta.size),
            (Operation::Download, None) => {
                ObjectResponse::with_error(oid, *size, 404, "object not found".to_owned())
            },
            (Operation::Upload, Some(meta)) => {
                ObjectResponse::for_existing_upload(base, oid, meta.size)
            },
            (Operation::Upload, None) => ObjectResponse::for_upload(base, oid, *size),
        };
        objects.push(response);
    }

    Ok(BatchResponse { transfer: TRANSFER_BASIC, objects })
}

/// batch 成功响应。
#[derive(Debug, Serialize)]
struct BatchResponse {
    /// 实际使用的 transfer 协议，固定 `basic`。
    transfer: &'static str,
    /// 与请求顺序一致的对象结果。
    objects: Vec<ObjectResponse>,
}

/// 单个对象的协商结果。
#[derive(Debug, Serialize)]
struct ObjectResponse {
    /// 对象 id。
    oid: String,
    /// 客户端声明的字节数。
    size: u64,
    /// 可用动作；对象不存在或超限时缺省。
    #[serde(skip_serializing_if = "Option::is_none")]
    actions: Option<Actions>,
    /// 单对象错误；HTTP 仍是 200。
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<ObjectError>,
}

impl ObjectResponse {
    /// 只带 oid 与 size 的空壳，供各构造器用结构体更新语法补齐。
    fn new(oid: &Oid, size: u64) -> Self {
        Self { oid: oid.as_str().to_owned(), size, actions: None, error: None }
    }

    /// 单对象错误。
    fn with_error(oid: &Oid, size: u64, code: u16, message: String) -> Self {
        Self { error: Some(ObjectError { code, message }), ..Self::new(oid, size) }
    }

    /// 可下载：给 `download` action，`header` 按 api.md 显式回空对象。
    fn for_download(base: &str, oid: &Oid, size: u64) -> Self {
        Self {
            actions: Some(Actions {
                download: Some(Action::new(object_href(base, oid), Some(BTreeMap::new()))),
                ..Actions::default()
            }),
            ..Self::new(oid, size)
        }
    }

    /// 需要上传：给 `upload` 与 `verify`，前者声明 `Content-Type`。
    fn for_upload(base: &str, oid: &Oid, size: u64) -> Self {
        let mut header = BTreeMap::new();
        header.insert("Content-Type".to_owned(), "application/octet-stream".to_owned());
        Self {
            actions: Some(Actions {
                upload: Some(Action::new(object_href(base, oid), Some(header))),
                verify: Some(Action::new(verify_href(base, oid), None)),
                ..Actions::default()
            }),
            ..Self::new(oid, size)
        }
    }

    /// 已存在：不给 `upload`（客户端据此跳过传输），只给 `verify` 供补校验。
    fn for_existing_upload(base: &str, oid: &Oid, size: u64) -> Self {
        Self {
            actions: Some(Actions {
                verify: Some(Action::new(verify_href(base, oid), None)),
                ..Actions::default()
            }),
            ..Self::new(oid, size)
        }
    }
}

/// 对象可用的动作集合；只序列化实际存在的动作。
#[derive(Debug, Default, Serialize)]
struct Actions {
    /// 上传地址。
    #[serde(skip_serializing_if = "Option::is_none")]
    upload: Option<Action>,
    /// 下载地址。
    #[serde(skip_serializing_if = "Option::is_none")]
    download: Option<Action>,
    /// 上传后校验地址。
    #[serde(skip_serializing_if = "Option::is_none")]
    verify: Option<Action>,
}

/// 一个 action 的目标与附加请求头。
#[derive(Debug, Serialize)]
struct Action {
    /// 相对路径，由客户端按请求 URL 解析。
    href: String,
    /// 客户端调用该 action 时要带的头；`None` 时整个字段省略（verify 即如此）。
    #[serde(skip_serializing_if = "Option::is_none")]
    header: Option<BTreeMap<String, String>>,
}

impl Action {
    /// 构造 action。
    fn new(href: String, header: Option<BTreeMap<String, String>>) -> Self {
        Self { href, header }
    }
}

/// 单对象错误。
#[derive(Debug, Serialize)]
struct ObjectError {
    /// HTTP 语义的状态码（如 404、422），不是 transport 错误。
    code: u16,
    /// 人类可读原因。
    message: String,
}

#[cfg(test)]
mod tests {
    use super::Operation;

    #[test]
    fn given_known_operations_when_parse_then_ok() {
        assert_eq!(Operation::parse("upload").expect("upload 应接受"), Operation::Upload);
        assert_eq!(Operation::parse("download").expect("download 应接受"), Operation::Download);
    }

    #[test]
    fn given_unknown_operation_when_parse_then_bad_request() {
        let error = Operation::parse("verify").expect_err("verify 不是 batch 操作");

        assert!(error.to_string().contains("verify"), "实际错误：{error}");
    }
}

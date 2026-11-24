//! `bdpan` 输出的解析与失败分类。
//!
//! 2026-11-24 实测（bdpan 3.8.9）的两条硬事实决定了这里的写法：
//!
//! 1. **业务错误的退出码同样是 0**，失败只体现在 stdout JSON（`code`/`error` 字段），
//!    所以判定一律解析 JSON，不看退出码；
//! 2. `download` 之类的命令把**进度条混在输出流里**，JSON 结果在最后，且带 ANSI
//!    控制序列与 `\r` 覆盖，解析前必须先剥噪音。
//!
//! 错误文案是唯一能把失败分类的线索（CLI 不给我们错误码枚举），所以
//! [`is_auth_failure`](fn@is_auth_failure) 一族谓词集中在这里，避免判定散落到调用点。

use serde_json::Value;

use crate::store::Quota;

/// `ls` 返回的一个目录条目。
///
/// 只保留封装层真正要用的字段：`md5` 字段实测出现过非法字符（如 `r`），不可作为
/// 校验依据，干脆不解析；大小以 `size` 为准，内容以本地 sha256 为准。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LsEntry {
    /// 条目名（不含目录部分）。
    pub name: String,
    /// 是否为目录。
    pub is_dir: bool,
    /// 文件字节数；目录为 0。
    pub size: u64,
}

/// JSON 形状与命令契约不符；由 [`super::process`] 转成 [`BdpanError::Unexpected`]。
///
/// [`BdpanError::Unexpected`]: super::BdpanError::Unexpected
#[derive(Debug, thiserror::Error)]
#[error("{0}")]
pub(super) struct ShapeError(String);

impl ShapeError {
    /// 记录一条人可读的形状问题。
    fn new(detail: impl Into<String>) -> Self {
        Self(detail.into())
    }
}

/// 一条 CLI 输出 JSON 的业务结论。
///
/// 成功时不带 `data`：调用方手里已经有整个 [`Value`]，再借出一份只会多一个生命周期参数。
#[derive(Debug)]
pub(super) enum Status {
    /// 成功。
    Success,
    /// 业务失败（`code` 非 0 或 `error` 非空）。
    Failure {
        /// CLI 给出的数字码；只在确实带 `code` 时有值。
        code: Option<i64>,
        /// 失败原因原文。
        message: String,
    },
}

/// 剥掉 ANSI 控制序列。
///
/// 只实现 CSI（`ESC [` … 终止字节）与单字符 ESC 序列两类——CLI 的进度条/着色用的是
/// 它们。颜色码留在 JSON 里会让 `serde_json` 直接解析失败，所以必须在切行之前剥掉。
pub(super) fn strip_ansi(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut chars = input.chars().peekable();
    while let Some(ch) = chars.next() {
        if ch != '\u{1b}' {
            out.push(ch);
            continue;
        }
        match chars.peek() {
            // CSI：ESC [ 参数位 终止字节（0x40..=0x7e）。
            Some('[') => {
                chars.next();
                for next in chars.by_ref() {
                    if ('\u{40}'..='\u{7e}').contains(&next) {
                        break;
                    }
                }
            },
            // 其余 ESC 序列（含光标定位的简写形式）只丢掉 ESC 与紧随的一个字符。
            Some(_) => {
                chars.next();
            },
            None => {},
        }
    }
    out
}

/// 从混杂的 stdout 里找出结果 JSON。
///
/// 先剥 ANSI，再按 `\n`/`\r` 切行，从**后往前**尝试从每个「看起来像 JSON 起点」的行
/// 解析出完整值：CLI 把结果打印在进度条之后，倒序能优先拿到最终结果；进度条
/// `[=====>] 50%` 虽然以 `[` 开头，但过不了 `serde_json`，会被自然跳过。再要求解析出的
/// 值带 `code`/`data`/`error`/`status` 之一（或本身是数组），避免把结果里的嵌套对象
/// 误当成整段结果。
///
/// 尾部残留的非 JSON 行不影响解析：`Deserializer::into_iter` 在第一个完整值处停下。
pub(super) fn first_json(stdout: &str) -> Option<Value> {
    let cleaned = strip_ansi(stdout);
    for start in candidate_starts(&cleaned).into_iter().rev() {
        let Some(rest) = cleaned.get(start..) else { continue };
        let mut values = serde_json::Deserializer::from_str(rest).into_iter::<Value>();
        if let Some(Ok(value)) = values.next()
            && looks_like_result(&value)
        {
            return Some(value);
        }
    }
    None
}

/// 候选 JSON 起点：每行去掉缩进后以 `{` 或 `[` 开头的字节偏移。
fn candidate_starts(text: &str) -> Vec<usize> {
    let mut starts = Vec::new();
    let mut offset = 0;
    for line in text.split_inclusive(['\n', '\r']) {
        let trimmed = line.trim_start();
        if trimmed.starts_with('{') || trimmed.starts_with('[') {
            starts.push(offset + (line.len() - trimmed.len()));
        }
        offset += line.len();
    }
    starts
}

/// 只把「像命令结果」的值当结果：数组、带 `code`/`data`/`error`/`status` 的信封对象，
/// 或 `whoami` 的扁平对象（实测真实 CLI 的 `whoami --json` 没有信封键，
/// 只有 `authenticated`/`has_valid_token` 等字段——没有这两个键就会把登录态
/// 探活误判成「输出无法解析」）。
fn looks_like_result(value: &Value) -> bool {
    match value {
        Value::Array(_) => true,
        Value::Object(map) => {
            ["code", "data", "error", "status", "authenticated", "has_valid_token"]
                .iter()
                .any(|key| map.contains_key(*key))
        },
        Value::Null | Value::Bool(_) | Value::Number(_) | Value::String(_) => false,
    }
}

/// 归纳一条 JSON 的业务结论。
///
/// 判定顺序有意义：
/// - `error` 非空**一律按失败**——实测出现过「code 为 0 但带 error」的混合输出，
///   宁可当失败处理，也不要放过一次静默的坏对象；
/// - `message` 只在 `code` 非 0 时才当失败原因：code 成功时它只是附言
///   （如「下载成功，[点击查看]」），不能反推出失败。
pub(super) fn status(value: &Value) -> Status {
    let Value::Object(map) = value else {
        // 数组（ls）与其它形态都交给具体命令的解析器，这里不算失败。
        return Status::Success;
    };
    let code = map.get("code").and_then(Value::as_i64);
    let error = map
        .get("error")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .map(str::to_owned);
    if let Some(message) = error {
        return Status::Failure { code, message };
    }
    let message = map
        .get("message")
        .and_then(Value::as_str)
        .filter(|text| !text.trim().is_empty())
        .map(str::to_owned);
    match (code, message) {
        (Some(0) | None, _) => Status::Success,
        (Some(other), message) => Status::Failure {
            code: Some(other),
            message: message.unwrap_or_else(|| format!("bdpan 返回 code {other} 但未说明原因")),
        },
    }
}

/// 判断失败文案是否属于登录态失效。
///
/// 刻意不匹配裸的 `auth`（会命中 `authorized directory`），也不匹配 `授权`——真实的
/// 「路径超出授权目录范围」是作用域配置问题，把它当登录失效会让 B4 误报 503。
pub(super) fn is_auth_failure(message: &str) -> bool {
    contains_any(
        message,
        &[
            "token",
            "登录",
            "未登录",
            "过期",
            "expired",
            "credential",
            "凭证",
            "unauthenticated",
            "unauthorized",
            "access denied",
            "重新授权",
        ],
    )
}

/// 判断失败文案是否表示「远端目标不存在」。
pub(super) fn is_not_found_failure(message: &str) -> bool {
    contains_any(
        message,
        &["不存在", "未找到", "找不到", "not found", "no such", "not exist", "does not exist"],
    )
}

/// 判断失败文案是否为「目标已存在」冲突（`mv` 的同名屏障）。
pub(super) fn is_conflict_failure(message: &str) -> bool {
    contains_any(message, &["already exists", "file already exists", "同名", "已存在"])
}

/// 判断失败文案是否为路径越界（配置里的网盘根写错，或拼出了 `/apps/bdpan/` 之外的路径）。
pub(super) fn is_scope_failure(message: &str) -> bool {
    contains_any(message, &["授权目录", "超出授权", "out of authorized", "authorized directory"])
}

/// 判断失败文案是否为网络/超时类可重试故障。
pub(super) fn is_transient_failure(message: &str) -> bool {
    contains_any(
        message,
        &[
            "timeout",
            "timed out",
            "超时",
            "network",
            "网络",
            "connection",
            "连接",
            "reset",
            "refused",
            "unavailable",
            "busy",
            "繁忙",
            "稍后",
            "try again",
            "econn",
            "503",
            "502",
            "504",
            "429",
        ],
    )
}

/// 大小写不敏感的多关键词匹配。
fn contains_any(message: &str, needles: &[&str]) -> bool {
    let lower = message.to_ascii_lowercase();
    needles.iter().any(|needle| lower.contains(needle))
}

/// 解析 `ls` 的结果。
///
/// 目录存在时顶层是条目数组；条目字段缺失或类型不对只跳过该条目并告警——一条脏条目
/// 不该让整棵对象树探测失败（实测 `md5` 就出现过非法字符）。
pub(super) fn ls_entries(value: &Value) -> Result<Vec<LsEntry>, ShapeError> {
    let Value::Array(items) = value else {
        return Err(ShapeError::new(format!("ls 应返回条目数组，实际为 {}", json_kind(value))));
    };
    let mut entries = Vec::with_capacity(items.len());
    for item in items {
        let Value::Object(map) = item else {
            tracing::debug!(kind = json_kind(item), "跳过非对象的 ls 条目");
            continue;
        };
        let Some(name) = map.get("server_filename").and_then(Value::as_str) else {
            tracing::debug!("跳过缺少 server_filename 的 ls 条目");
            continue;
        };
        let is_dir = map.get("isdir").and_then(as_boolish).unwrap_or(false);
        let size = map.get("size").and_then(as_u64ish).unwrap_or(0);
        entries.push(LsEntry { name: name.to_owned(), is_dir, size });
    }
    Ok(entries)
}

/// 解析 `quota` 的 `data.total_bytes` / `data.used_bytes`。
pub(super) fn quota(value: &Value) -> Result<Quota, ShapeError> {
    let data = value.get("data").ok_or_else(|| ShapeError::new("quota 输出缺少 data 字段"))?;
    let total = data
        .get("total_bytes")
        .and_then(as_u64ish)
        .ok_or_else(|| ShapeError::new("quota.data 缺少 total_bytes"))?;
    let used = data
        .get("used_bytes")
        .and_then(as_u64ish)
        .ok_or_else(|| ShapeError::new("quota.data 缺少 used_bytes"))?;
    Ok(Quota::new(total, used))
}

/// 检查 `upload` 是否真的落在了请求的远端路径上。
///
/// 同名文件存在时 CLI 会**自动重命名**（`<name>.1`…）而不是覆盖。中转文件以 oid 命名，
/// 一旦被改名，随后 `mv tmp/<oid>` 就会搬走旧文件——这是「上传了脏内容却报告成功」的
/// 入口，所以封装层宁可报错也不接受改名结果。
/// upload 的同名冲突结论。
pub(super) struct UploadConflict {
    /// 请求的落盘名（从 remote 路径取末段）。
    pub(super) expected: String,
    /// CLI 报告的实际落盘名；`conflict_detected` 但未报告名字时为 `None`。
    pub(super) actual: Option<String>,
}

/// 识别 upload 的同名自动重命名：CLI 不覆盖同名文件，会另起名字落盘。
///
/// 返回期望名与实际落盘名，供调用方构造类型化错误并清理改名副本——
/// 只给一段文案会把实际落盘名埋进字符串，残留清理无从下手。
pub(super) fn upload_conflict(value: &Value, remote: &str) -> Option<UploadConflict> {
    let data = value.get("data");
    let conflict =
        data.and_then(|data| data.get("conflict_detected")).and_then(as_boolish).unwrap_or(false);
    let expected = remote.rsplit('/').next().unwrap_or(remote);
    let landed = data.and_then(|data| data.get("server_filename")).and_then(Value::as_str);
    let renamed = landed.is_some_and(|name| name != expected);
    if conflict || renamed {
        return Some(UploadConflict {
            expected: expected.to_owned(),
            actual: landed.map(str::to_owned),
        });
    }
    None
}

/// 截取一段可放进错误信息的输出片段：压平控制字符、限长，避免日志注入与刷屏。
pub(super) fn preview(text: &str, max_chars: usize) -> String {
    let flattened: String = text.chars().map(|ch| if ch.is_control() { ' ' } else { ch }).collect();
    let mut out: String = flattened.chars().take(max_chars).collect();
    if flattened.chars().count() > max_chars {
        out.push('…');
    }
    out.trim().to_owned()
}

/// JSON 值的类型名，用于错误信息。
fn json_kind(value: &Value) -> &'static str {
    match value {
        Value::Null => "null",
        Value::Bool(_) => "布尔值",
        Value::Number(_) => "数字",
        Value::String(_) => "字符串",
        Value::Array(_) => "数组",
        Value::Object(_) => "对象",
    }
}

/// 宽容地取布尔：接受 `true`/`false`、`0`/`1`、`"true"`/`"0"`。
///
/// CLI 在不同子命令里对同一语义用过布尔与数字两种编码，硬要求一种会在真机上炸。
fn as_boolish(value: &Value) -> Option<bool> {
    match value {
        Value::Bool(flag) => Some(*flag),
        Value::Number(number) => number.as_i64().map(|raw| raw != 0),
        Value::String(text) => match text.trim().to_ascii_lowercase().as_str() {
            "true" | "1" | "yes" => Some(true),
            "false" | "0" | "no" => Some(false),
            _ => None,
        },
        Value::Null | Value::Array(_) | Value::Object(_) => None,
    }
}

/// 宽容地取无符号整数：接受数字与十进制字符串。
fn as_u64ish(value: &Value) -> Option<u64> {
    match value {
        Value::Number(number) => number.as_u64(),
        Value::String(text) => text.trim().parse().ok(),
        Value::Null | Value::Bool(_) | Value::Array(_) | Value::Object(_) => None,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        first_json, is_auth_failure, is_conflict_failure, is_not_found_failure, is_scope_failure,
        is_transient_failure, ls_entries, preview, quota, status, strip_ansi, upload_conflict,
    };

    use serde_json::json;

    #[test]
    fn given_ansi_progress_line_when_strip_then_keeps_text() {
        let raw = "\u{1b}[2K下载中  10%\r\u{1b}[2K下载中 100%\r\n";

        let cleaned = strip_ansi(raw);

        assert!(!cleaned.contains('\u{1b}'), "实际：{cleaned:?}");
        assert!(cleaned.contains("下载中"), "实际：{cleaned:?}");
    }

    #[test]
    fn given_noise_before_json_when_first_json_then_returns_result() {
        let stdout = concat!(
            "\u{1b}[2K下载中  10%\r\n",
            "\u{1b}[2K下载中 100%\r\n",
            "{\"code\":0,\"data\":{\"status\":\"ok\"}}\n",
        );

        let value = first_json(stdout).expect("应解析出结果 JSON");

        assert_eq!(value["code"], json!(0));
    }

    #[test]
    fn given_progress_bar_that_starts_with_bracket_when_first_json_then_skips_it() {
        let stdout = "[=====>     ] 50%\n{\"code\":1,\"data\":null,\"error\":\"目录不存在\"}\n";

        let value = first_json(stdout).expect("应跳过进度条并解析结果");

        assert_eq!(value["code"], json!(1));
    }

    #[test]
    fn given_pretty_printed_envelope_when_first_json_then_returns_whole_envelope() {
        let stdout = "{\n  \"code\": 0,\n  \"data\": {\n    \"status\": \"ok\"\n  }\n}\n";

        let value = first_json(stdout).expect("美化输出也应解析");

        assert_eq!(value["data"]["status"], json!("ok"));
    }

    #[test]
    fn given_trailing_noise_when_first_json_then_ignored() {
        let stdout = "{\"code\":0,\"data\":{\"action\":\"created\"}}\nsome trailing log\n";

        let value = first_json(stdout).expect("尾部噪音不应影响解析");

        assert_eq!(value["data"]["action"], json!("created"));
    }

    #[test]
    fn given_flat_whoami_object_when_first_json_then_parsed() {
        // 真实 `bdpan whoami --json` 没有 code/data 信封，只有扁平字段。
        let stdout = "{\n  \"authenticated\": true,\n  \"has_valid_token\": true\n}\n";

        let value = first_json(stdout).expect("whoami 扁平对象应被识别");

        assert_eq!(value["authenticated"], json!(true));
    }

    #[test]
    fn given_plain_text_when_first_json_then_none() {
        assert!(first_json("bdpan: command not found\n").is_none());
    }

    #[test]
    fn given_json_with_error_field_and_zero_code_when_status_then_failure() {
        let value = json!({"code": 0, "data": null, "error": "网络异常"});

        let super::Status::Failure { message, .. } = status(&value) else {
            panic!("带 error 字段应判为失败");
        };
        assert_eq!(message, "网络异常");
    }

    #[test]
    fn given_code_zero_when_status_then_success() {
        let value = json!({"code": 0, "data": {"status": "ok"}});

        assert!(matches!(status(&value), super::Status::Success), "code 0 应为成功");
    }

    #[test]
    fn given_array_ls_output_when_ls_entries_then_parsed_and_md5_ignored() {
        let value = json!([
            {"server_filename": "obj", "isdir": false, "size": 12, "md5": "r"},
            {"server_filename": "sub", "isdir": true, "size": 0, "fsid": 7},
        ]);

        let entries = ls_entries(&value).expect("数组应可解析");

        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "obj");
        assert!(!entries[0].is_dir);
        assert_eq!(entries[0].size, 12);
        assert!(entries[1].is_dir);
    }

    #[test]
    fn given_object_when_ls_entries_then_shape_error() {
        let err = ls_entries(&json!({"code": 1, "error": "目录不存在"})).expect_err("应报形状错误");

        assert!(err.to_string().contains("数组"), "实际错误：{err}");
    }

    #[test]
    fn given_quota_data_when_quota_then_numbers_parsed() {
        let value =
            json!({"code": 0, "data": {"total_bytes": 100, "used_bytes": 40, "free_bytes": 60}});

        let quota = quota(&value).expect("应解析配额");

        assert_eq!(quota.total, 100);
        assert_eq!(quota.used, 40);
        assert_eq!(quota.free(), 60);
    }

    #[test]
    fn given_missing_total_when_quota_then_shape_error() {
        let err =
            quota(&json!({"code": 0, "data": {"used_bytes": 1}})).expect_err("缺少字段应报错");

        assert!(err.to_string().contains("total_bytes"), "实际错误：{err}");
    }

    #[test]
    fn given_renamed_upload_when_conflict_then_structured_names() {
        let value =
            json!({"code": 0, "data": {"conflict_detected": true, "server_filename": "abc.1"}});

        let conflict = upload_conflict(&value, "/apps/bdpan/lfs/tmp/abc").expect("应识别冲突");

        assert_eq!(conflict.expected, "abc");
        assert_eq!(conflict.actual.as_deref(), Some("abc.1"));
    }

    #[test]
    fn given_upload_on_requested_name_when_conflict_then_none() {
        let value =
            json!({"code": 0, "data": {"conflict_detected": false, "server_filename": "abc"}});

        assert!(upload_conflict(&value, "/apps/bdpan/lfs/tmp/abc").is_none());
    }

    #[test]
    fn given_failure_texts_when_classified_then_each_bucket_matches() {
        assert!(is_auth_failure("token 已过期，请重新登录"));
        assert!(is_not_found_failure("目录不存在: /apps/bdpan/lfs/objects/aa"));
        assert!(is_conflict_failure("file already exists: x"));
        assert!(is_transient_failure("网络异常: 上传连接被重置"));
        assert!(is_transient_failure("request timed out"));
        assert!(is_scope_failure("路径超出授权目录范围: /lfs"));
        // 作用域错误不能被当成登录失效，否则 B4 会把配置错误映射成 503。
        assert!(!is_auth_failure("路径超出授权目录范围: /lfs"));
        // 冲突与「不存在」不能互相误判。
        assert!(!is_not_found_failure("file already exists"));
        assert!(!is_conflict_failure("no such file"));
    }

    #[test]
    fn given_control_chars_when_preview_then_flattened_and_truncated() {
        let raw = format!("line1\nline2\t{}", "x".repeat(50));

        let preview = preview(&raw, 10);

        assert!(!preview.contains('\n'), "实际：{preview:?}");
        assert!(preview.chars().count() <= 11, "实际：{preview:?}");
    }
}

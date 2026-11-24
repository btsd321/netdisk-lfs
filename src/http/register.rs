//! 自助注册端点：`GET /account/register`（极简 HTML 表单）与 `POST /account/register`。
//!
//! 行为由 `[accounts] registration` 决定：
//!
//! - `open`：创建 `Active` 账户，201；
//! - `approval`（默认）：创建 `Pending` 账户，202，需管理员在 C3 的 `/admin/users`
//!   里改为 `Active` 后才能登录；
//! - `closed`：403，账户只能由管理员创建。
//!
//! `POST` 同时接受 JSON 与 `application/x-www-form-urlencoded`：按 `Content-Type`
//! 分流，JSON 请求回 JSON（错误体沿用 `{message, request_id}`），表单请求回 HTML
//! 结果页（状态码一致）。表单来自注册页，所以带 `confirm_password` 时要求两次一致。
//!
//! **不引入模板引擎**：只有两个页面，字符串拼接 + [`escape_html`] 足够；任何动态
//! 文本（用户名、错误消息、request id）都必须经过转义后才能进 HTML。
//!
//! 限速按来源地址统计（小时窗口），只有**创建成功**才计数；被 429 拒掉的请求不再
//! 计数，否则攻击者持续打就能把窗口无限延长，把正常用户挡在外面。

use std::collections::HashMap;

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::{ACCOUNTS_NOT_CONFIGURED_MESSAGE, AppState, RequestId, json_with_status, passwords};
use crate::accounts::{UserStatus, validate_password, validate_username};
use crate::config::RegistrationPolicy;

/// 注册请求体上限：表单只有三个短字段，16 KiB 足够，超出直接 400。
const MAX_BODY_BYTES: usize = 16 * 1024;

/// 注册页的样式：只做可读性，不引外部资源（离线可用、无追踪）。
const PAGE_STYLE: &str = r#"
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 2.5rem auto;
       max-width: 32rem; padding: 0 1rem; line-height: 1.6; color: #1f2328; }
h1 { font-size: 1.4rem; margin-bottom: .5rem; }
p { margin: .5rem 0; }
form { display: grid; gap: .85rem; margin-top: 1.5rem; }
label { display: grid; gap: .3rem; font-size: .95rem; }
input { padding: .5rem; border: 1px solid #d0d7de; border-radius: .375rem; font-size: 1rem; }
button { padding: .55rem 1rem; border: 0; border-radius: .375rem; background: #1f6feb;
         color: #fff; font-size: 1rem; cursor: pointer; }
.hint { color: #59636e; font-size: .9rem; }
.error { color: #b42318; }
"#;

/// `GET /account/register`：极简注册页（无 JavaScript）。
pub(crate) async fn page(State(state): State<AppState>) -> Response {
    let policy = state.config().accounts.registration;
    if state.accounts().is_none() {
        return html_response(
            StatusCode::SERVICE_UNAVAILABLE,
            page_shell(
                "注册不可用",
                &format!(
                    r#"<h1>注册不可用</h1><p class="error">{ACCOUNTS_NOT_CONFIGURED_MESSAGE}</p>"#
                ),
            ),
        );
    }
    let min_len = state.config().accounts.min_password_len;
    html_response(StatusCode::OK, page_shell("注册账户", &render_form(policy, min_len)))
}

/// `POST /account/register`：按 `Content-Type` 分流 JSON 与表单。
pub(crate) async fn submit(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let request_id =
        parts.extensions.get::<RequestId>().cloned().unwrap_or_else(RequestId::generate);
    let mode = BodyMode::of(&parts.headers);
    let client = client_key(&state, &parts);

    match read_payload(body, mode).await {
        Ok(payload) => match register(&state, &client, payload).await {
            Ok(registered) => success_response(mode, &registered, &request_id),
            Err(error) => error_response(mode, error, &request_id),
        },
        Err(error) => error_response(mode, error, &request_id),
    }
}

/// 请求体的编码方式；只有 JSON 与表单两种，其余一律按表单解析。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum BodyMode {
    /// `application/json`（含 `+json`）。
    Json,
    /// `application/x-www-form-urlencoded`（含浏览器表单默认的 `text/html` 之类）。
    Form,
}

impl BodyMode {
    /// 按 `Content-Type` 判断：带 `json` 的走 JSON，其余走表单。
    ///
    /// 没有 `Content-Type` 时按 JSON 处理：API 客户端漏设头时得到的是结构化错误，
    /// 而不是「表单字段缺失」这种误导信息；浏览器表单一定会带 urlencoded 头。
    fn of(headers: &HeaderMap) -> Self {
        let Some(raw) = headers.get(CONTENT_TYPE).and_then(|value| value.to_str().ok()) else {
            return Self::Json;
        };
        if raw.to_ascii_lowercase().contains("json") { Self::Json } else { Self::Form }
    }
}

/// 注册接口的请求体；`confirm_password` 只在表单/显式提供时校验一致。
#[derive(Debug, Deserialize)]
struct RegisterPayload {
    /// 用户名（3–32 个 `[A-Za-z0-9._-]`）。
    username: String,
    /// 明文口令，只在本次请求内存在。
    password: String,
    /// 确认口令；表单必填，JSON 可选。
    #[serde(default)]
    confirm_password: Option<String>,
}

/// 注册成功后的对外视图；不回显口令或哈希。
#[derive(Debug, Serialize)]
struct Registered {
    /// 规范化的用户名（与请求一致，账户库按原样保存）。
    username: String,
    /// 新账户角色。
    role: crate::config::Role,
    /// 新账户状态（`active` 或 `pending`）。
    status: UserStatus,
}

/// 读取并解析请求体；body 大小超限与字段缺失都归 400。
async fn read_payload(body: Body, mode: BodyMode) -> Result<RegisterPayload, ApiError> {
    let bytes = axum::body::to_bytes(body, MAX_BODY_BYTES)
        .await
        .map_err(|_| ApiError::BadRequest(format!("请求体超过 {MAX_BODY_BYTES} 字节")))?;
    match mode {
        BodyMode::Json => {
            let mut payload: RegisterPayload = serde_json::from_slice(&bytes)
                .map_err(|error| ApiError::BadRequest(format!("请求体不是合法 JSON：{error}")))?;
            check_confirmation(&payload)?;
            payload.confirm_password = None;
            Ok(payload)
        },
        BodyMode::Form => form_payload(&bytes),
    }
}

/// 表单路径：解析 urlencoded，并要求 `confirm_password` 与 `password` 一致。
fn form_payload(body: &[u8]) -> Result<RegisterPayload, ApiError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ApiError::BadRequest("表单不是合法的 UTF-8".to_owned()))?;
    let fields = parse_form(text)?;
    let required = |name: &str| {
        fields
            .get(name)
            .cloned()
            .filter(|value| !value.is_empty())
            .ok_or_else(|| ApiError::BadRequest(format!("缺少表单字段 {name}")))
    };
    let payload = RegisterPayload {
        username: required("username")?,
        password: required("password")?,
        confirm_password: required("confirm_password")?.into(),
    };
    check_confirmation(&payload)?;
    Ok(payload)
}

/// 两次口令不一致 → 400。
fn check_confirmation(payload: &RegisterPayload) -> Result<(), ApiError> {
    match payload.confirm_password.as_deref() {
        Some(confirmation) if confirmation != payload.password => {
            Err(ApiError::BadRequest("两次输入的口令不一致".to_owned()))
        },
        _ => Ok(()),
    }
}

/// 解析 `application/x-www-form-urlencoded`：`&` 分隔、`=` 切分、`+` 与 `%XX` 解码。
///
/// 同名键取第一次出现的值（浏览器不会重复提交同一个控件），避免后出现的值覆盖
/// 前面的校验结果。
fn parse_form(body: &str) -> Result<HashMap<String, String>, ApiError> {
    let mut fields = HashMap::new();
    for pair in body.split('&').filter(|pair| !pair.is_empty()) {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(raw_key)?;
        let value = percent_decode(raw_value)?;
        fields.entry(key).or_insert(value);
    }
    Ok(fields)
}

/// 百分号与 `+` 解码；非法转义或非 UTF-8 都报 400。
fn percent_decode(raw: &str) -> Result<String, ApiError> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            },
            b'%' => {
                let pair = bytes
                    .get(index + 1..index + 3)
                    .ok_or_else(|| ApiError::BadRequest("表单转义不完整".to_owned()))?;
                let pair = std::str::from_utf8(pair)
                    .map_err(|_| ApiError::BadRequest("表单转义不是十六进制".to_owned()))?;
                let byte = u8::from_str_radix(pair, 16)
                    .map_err(|_| ApiError::BadRequest("表单转义不是十六进制".to_owned()))?;
                decoded.push(byte);
                index += 3;
            },
            byte => {
                decoded.push(byte);
                index += 1;
            },
        }
    }
    String::from_utf8(decoded).map_err(|_| ApiError::BadRequest("表单不是合法的 UTF-8".to_owned()))
}

/// 校验、限速并按策略创建账户。
async fn register(
    state: &AppState,
    client: &str,
    payload: RegisterPayload,
) -> Result<Registered, ApiError> {
    let Some(users) = state.accounts() else {
        return Err(ApiError::Unavailable(ACCOUNTS_NOT_CONFIGURED_MESSAGE.to_owned()));
    };
    let accounts = &state.config().accounts;

    // 限速放在最前面：否则「非法输入 → 400」这类便宜请求不计数，攻击者可以先用
    // 400/409 探路绕过每小时上限。
    if let Some(retry_after) =
        state.register_limits().blocked_for(client, accounts.registration_per_hour)
    {
        tracing::warn!(
            client = %client,
            retry_after_secs = retry_after.as_secs(),
            "注册请求超过每小时上限"
        );
        return Err(ApiError::TooManyRequests {
            message: format!("注册过于频繁，请 {} 秒后重试", retry_after.as_secs().max(1)),
            retry_after_secs: retry_after.as_secs().max(1),
        });
    }

    if let Err(error) = validate_username(&payload.username) {
        tracing::warn!(reason = "invalid_username", "注册被拒：用户名不合法");
        return Err(ApiError::BadRequest(error.to_string()));
    }
    if let Err(error) =
        validate_password(&payload.username, &payload.password, accounts.min_password_len)
    {
        tracing::warn!(username = %payload.username, reason = "invalid_password", "注册被拒：口令不符合策略");
        return Err(ApiError::BadRequest(error.to_string()));
    }

    let (status, policy) = match accounts.registration {
        RegistrationPolicy::Open => (UserStatus::Active, "open"),
        RegistrationPolicy::Approval => (UserStatus::Pending, "approval"),
        RegistrationPolicy::Closed => {
            tracing::warn!(username = %payload.username, policy = "closed", "注册被拒：已关闭自助注册");
            return Err(ApiError::Forbidden("已关闭自助注册，请联系管理员开通账户".to_owned()));
        },
    };

    // 先查重再哈希：Argon2 不便宜，没必要为一次必然失败的注册付 19 MiB 的开销。
    match users.get(&payload.username).await {
        Ok(Some(_)) => return Err(duplicate_username(&payload.username)),
        Ok(None) => {},
        Err(error) => {
            tracing::error!(username = %payload.username, error = %error, "注册时查询账户库失败");
            return Err(ApiError::Unavailable(ACCOUNTS_NOT_CONFIGURED_MESSAGE.to_owned()));
        },
    }

    let hash = passwords::hash(payload.password).await.map_err(|error| {
        tracing::error!(error = %error, "注册口令哈希失败");
        ApiError::Internal("生成口令哈希失败".to_owned())
    })?;

    match users.create(&payload.username, &hash, accounts.default_role, status).await {
        Ok(user) => {
            // 只有创建成功才计数：429 的请求不再延长窗口。
            state.register_limits().record(client);
            tracing::info!(
                username = %user.username,
                role = %user.role,
                status = user.status.as_str(),
                policy = policy,
                "注册成功"
            );
            Ok(Registered { username: user.username, role: user.role, status: user.status })
        },
        // 预检查与插入之间可能有并发注册抢到同一个用户名。
        Err(crate::accounts::AccountError::DuplicateUsername { .. }) => {
            Err(duplicate_username(&payload.username))
        },
        Err(error) => {
            tracing::error!(username = %payload.username, error = %error, "写入新账户失败");
            Err(ApiError::Internal("创建账户失败".to_owned()))
        },
    }
}

/// 409：用户名已被占用。
fn duplicate_username(username: &str) -> ApiError {
    tracing::warn!(username = %username, reason = "duplicate_username", "注册被拒：用户名已存在");
    ApiError::Conflict("用户名已被占用".to_owned())
}

/// 成功响应：JSON 返回 `{username, role, status}`，表单返回结果页。
fn success_response(mode: BodyMode, registered: &Registered, request_id: &RequestId) -> Response {
    let status = match registered.status {
        UserStatus::Active => StatusCode::CREATED,
        // Pending 用 202：请求已被接受，但真正生效要等管理员审批。
        _ => StatusCode::ACCEPTED,
    };
    match mode {
        BodyMode::Json => json_with_status(status, registered, request_id),
        BodyMode::Form => {
            let message = match registered.status {
                UserStatus::Active => format!(
                    "账户 <strong>{}</strong> 已创建（角色 {}），现在就可以用它在 Git 客户端上登录。",
                    escape_html(&registered.username),
                    registered.role
                ),
                _ => format!(
                    "账户 <strong>{}</strong> 已提交，等待管理员审批后即可登录。",
                    escape_html(&registered.username)
                ),
            };
            let title =
                if status == StatusCode::CREATED { "注册成功" } else { "注册已提交" };
            html_response(
                status,
                page_shell(
                    title,
                    &format!(
                        r#"<h1>{title}</h1><p>{message}</p><p class="hint"><a href="/account/register">返回注册页</a></p>"#
                    ),
                ),
            )
        },
    }
}

/// 失败响应：JSON 用统一错误体，表单用 HTML 错误页（状态码一致）。
fn error_response(mode: BodyMode, error: ApiError, request_id: &RequestId) -> Response {
    match mode {
        BodyMode::Json => error.into_response_with(request_id),
        BodyMode::Form => {
            let status = error.status();
            html_response(
                status,
                page_shell(
                    "注册失败",
                    &format!(
                        r#"<h1>注册失败</h1><p class="error">{}</p><p class="hint">请求 id：{}</p><p class="hint"><a href="/account/register">返回注册页</a></p>"#,
                        escape_html(error.message()),
                        escape_html(request_id.as_str())
                    ),
                ),
            )
        },
    }
}

/// 注册页/结果页的公共外壳：内联样式，不引外部资源，不含任何脚本。
fn page_shell(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · netdisk-lfs</title>
<style>{PAGE_STYLE}</style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>
"#,
        title = escape_html(title),
        body = body,
    )
}

/// 按策略渲染表单与提示；`min_password_len` 来自配置，写进输入框的 `minlength`。
fn render_form(policy: RegistrationPolicy, min_password_len: usize) -> String {
    let hint = match policy {
        RegistrationPolicy::Open => "注册后账户立即可用。",
        RegistrationPolicy::Approval => "注册后需要管理员审批，审批通过前无法登录。",
        RegistrationPolicy::Closed => {
            return r#"<h1>注册已关闭</h1><p class="hint">当前不接受自助注册，请联系管理员开通账户。</p>"#
                .to_owned();
        },
    };
    format!(
        r#"<h1>注册账户</h1>
<p class="hint">{hint}</p>
<form method="post" action="/account/register">
<label>用户名
<input name="username" autocomplete="username" required minlength="3" maxlength="32">
</label>
<label>口令
<input type="password" name="password" autocomplete="new-password" required minlength="{min_password_len}">
</label>
<label>确认口令
<input type="password" name="confirm_password" autocomplete="new-password" required minlength="{min_password_len}">
</label>
<button type="submit">注册</button>
</form>
<p class="hint">用户名 3–32 个字符，可用字母、数字、点、下划线与连字符；口令至少 {min_password_len} 个字符，且不能与用户名相同。</p>"#,
        hint = escape_html(hint),
    )
}

/// HTML 转义：`&` 最先替换，避免把后续生成的实体二次转义。
fn escape_html(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// 构造 HTML 响应（`text/html; charset=utf-8`）。
fn html_response(status: StatusCode, body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    *response.status_mut() = status;
    response
}

/// 注册限速的来源键：信任反代时取 `X-Forwarded-For` 第一段，否则用远端 IP。
///
/// 没有远端地址（嵌入用法、直接调用 router 的测试）时所有请求共用一个桶：
/// 仍然是「有限速」而不是「不限」，不会把这类用法变成无保护。
pub(crate) fn client_key(state: &AppState, parts: &axum::http::request::Parts) -> String {
    if state.config().accounts.trust_proxy
        && let Some(last) = parts
            .headers
            .get("x-forwarded-for")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.split(',').next_back())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    {
        // 取**最后**一段：代理是「追加」语义（`client-supplied, observed-peer`），
        // 最后一段才是代理观测到的对端；取第一段会被客户端伪造绕过限速。
        // 头值长度由客户端决定（最长可到 8 KiB），截断后再当键，避免键池被
        // 单个请求撑大；IPv6 最长 45 个字符，64 足够容纳真实地址。
        return format!("xff:{}", last.chars().take(64).collect::<String>());
    }
    // 只取 IP 不取端口：源端口每次连接都变，用它做键等于不限速。
    if let Some(axum::extract::ConnectInfo(addr)) =
        parts.extensions.get::<axum::extract::ConnectInfo<std::net::SocketAddr>>()
    {
        return format!("remote:{}", addr.ip());
    }
    "fallback".to_owned()
}

#[cfg(test)]
mod tests {
    use super::{BodyMode, escape_html, parse_form, percent_decode};
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    #[test]
    fn given_html_special_chars_when_escape_then_entities() {
        assert_eq!(
            escape_html("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape_html("a & b \"c\" 'd'"), "a &amp; b &quot;c&quot; &#39;d&#39;");
        // & 必须先替换，否则会二次转义成 &amp;lt;
        assert_eq!(escape_html("&lt;"), "&amp;lt;");
    }

    #[test]
    fn given_urlencoded_body_when_parse_then_fields_decoded() {
        let fields = parse_form("username=Alice_01&password=a%2Bb+c&confirm_password=a%2Bb+c")
            .expect("合法表单");

        assert_eq!(fields["username"], "Alice_01");
        assert_eq!(fields["password"], "a+b c");
        assert_eq!(fields["confirm_password"], "a+b c");
    }

    #[test]
    fn given_duplicate_key_when_parse_then_first_wins() {
        let fields = parse_form("username=alice&username=bob").expect("合法表单");

        assert_eq!(fields["username"], "alice");
    }

    #[test]
    fn given_broken_percent_escape_when_decode_then_bad_request() {
        assert!(percent_decode("%2").is_err(), "不完整的转义应被拒");
        assert!(percent_decode("%zz").is_err(), "非十六进制应被拒");
        assert!(percent_decode("%ff").is_err(), "非 UTF-8 字节应被拒");
        assert_eq!(percent_decode("a%20b").expect("合法转义"), "a b");
    }

    #[test]
    fn given_content_type_when_body_mode_then_json_or_form() {
        let mut headers = HeaderMap::new();
        assert_eq!(BodyMode::of(&headers), BodyMode::Json, "缺 Content-Type 按 JSON");

        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/x-www-form-urlencoded"),
        );
        assert_eq!(BodyMode::of(&headers), BodyMode::Form);

        headers.insert(
            HeaderName::from_static("content-type"),
            HeaderValue::from_static("application/vnd.git-lfs+json; charset=utf-8"),
        );
        assert_eq!(BodyMode::of(&headers), BodyMode::Json);
    }
}

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

use axum::body::Body;
use axum::extract::{Request, State};
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderMap, StatusCode};
use axum::response::Response;
use serde::{Deserialize, Serialize};

use super::error::ApiError;
use super::html::{escape_html, html_response, parse_form};
use super::layout;
use super::{
    ACCOUNTS_NOT_CONFIGURED_MESSAGE, ACCOUNTS_UNAVAILABLE_MESSAGE, AppState, RequestId,
    config_username, json_with_status, passwords,
};
use crate::accounts::{UserStatus, validate_password, validate_username};
use crate::config::RegistrationPolicy;

/// 注册请求体上限：表单只有三个短字段，16 KiB 足够，超出直接 400。
const MAX_BODY_BYTES: usize = 16 * 1024;

/// 注册页左侧的一句话定位（与登录页同一套说明）。
const SUBTITLE: &str = "创建一个账户，用于浏览器登录与 Git 客户端的 HTTP Basic 凭据。";

/// `GET /account/register`：注册页（无 JavaScript）。
pub(crate) async fn page(State(state): State<AppState>) -> Response {
    let policy = state.config().accounts.registration;
    if state.accounts().is_none() {
        return html_response(
            StatusCode::SERVICE_UNAVAILABLE,
            layout::public_page(
                "注册不可用",
                SUBTITLE,
                &format!(
                    r#"<p class="alert" role="alert">{ACCOUNTS_NOT_CONFIGURED_MESSAGE}</p>{BACK_TO_LOGIN}"#
                ),
            ),
        );
    }
    let min_len = state.config().accounts.min_password_len;
    match policy {
        RegistrationPolicy::Closed => html_response(
            StatusCode::OK,
            layout::public_page(
                "注册已关闭",
                SUBTITLE,
                &format!(
                    r#"<p class="note">当前不接受自助注册，请联系管理员开通账户。</p>{BACK_TO_LOGIN}"#
                ),
            ),
        ),
        _ => html_response(
            StatusCode::OK,
            layout::public_page("注册账户", SUBTITLE, &render_form(policy, min_len)),
        ),
    }
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

/// 校验、限速并按策略创建账户。
///
/// 顺序有意如此：先看策略、再碰用户名。`closed` 时连「这个名字是否已存在 / 是否被
/// `[auth.users]` 保留」都不能被区分出来，否则一个 409 就能探测出引导管理员的用户名。
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
    //
    // 注意这里只对**创建成功**计数（见下方 `record`）：重名/保留名的探测不计数。
    // 这是有意的取舍——两者的对外响应已经完全一致（统一 409），不再泄漏额外信息；
    // 若把失败也计数，攻击者只要用几个错用户名就能把同一出口 IP 后面的正常用户
    // 锁在 429 外面，代价比收益大。
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

    // 策略先于一切用户名/口令检查：closed 一律 403，不能因为「用户名字符集不对」而
    // 返回 400，把「这个实例关闭了注册」变成可以按输入区分的行为。
    let (status, policy) = match accounts.registration {
        RegistrationPolicy::Open => (UserStatus::Active, "open"),
        RegistrationPolicy::Approval => (UserStatus::Pending, "approval"),
        RegistrationPolicy::Closed => {
            tracing::warn!(policy = "closed", "注册被拒：已关闭自助注册");
            return Err(ApiError::Forbidden("已关闭自助注册，请联系管理员开通账户".to_owned()));
        },
    };

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

    // 自助注册不能占用 `[auth.users]` 里的用户名：DB 优先，一旦写入同名的
    // Pending/Active 记录，原 config 账户（常见是引导管理员）就再也登不上，
    // 变成可被利用的锁定路径。管理员在 `/admin/users` 创建同名账户不受此限
    // （那是显式的迁移动作）。
    //
    // 对外与「重名」共用同一条 409 文案：两者返回不同 message 的话，任何人都能
    // 用一轮探测把引导管理员的名字问出来。
    if config_username(state.config(), &payload.username).is_some() {
        tracing::warn!(
            username = %payload.username,
            reason = "reserved_username",
            "注册被拒：用户名被 [auth.users] 保留"
        );
        return Err(username_taken());
    }

    // 先查重再哈希：Argon2 不便宜，没必要为一次必然失败的注册付 19 MiB 的开销。
    match users.get(&payload.username).await {
        Ok(Some(_)) => {
            tracing::warn!(
                username = %payload.username,
                reason = "duplicate_username",
                "注册被拒：用户名已存在"
            );
            return Err(username_taken());
        },
        Ok(None) => {},
        Err(error) => {
            tracing::error!(username = %payload.username, error = %error, "注册时查询账户库失败");
            return Err(ApiError::Unavailable(ACCOUNTS_UNAVAILABLE_MESSAGE.to_owned()));
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
            tracing::warn!(
                username = %payload.username,
                reason = "duplicate_username",
                "注册被拒：用户名已存在（并发插入）"
            );
            Err(username_taken())
        },
        Err(error) => {
            tracing::error!(username = %payload.username, error = %error, "写入新账户失败");
            Err(ApiError::Unavailable(ACCOUNTS_UNAVAILABLE_MESSAGE.to_owned()))
        },
    }
}

/// 对外统一的「用户名不可用」文案：重名与 `[auth.users]` 保留名共用。
///
/// 两者返回不同 message 时，任何人都能用一轮注册探测把引导管理员的名字问出来
/// （`reserved_username` 的差异只允许出现在日志里）。
const USERNAME_TAKEN_MESSAGE: &str = "用户名已被占用";

/// 409：用户名已被占用（重名与保留名共用同一条文案）。
///
/// 只构造错误、不写日志：调用方才知道自己是「自助注册」还是「管理员创建」，
/// 审计语义与 `reason` 字段由各调用点决定。
pub(crate) fn username_taken() -> ApiError {
    ApiError::Conflict(USERNAME_TAKEN_MESSAGE.to_owned())
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
                layout::public_page(
                    title,
                    SUBTITLE,
                    &format!(
                        r#"<p>{message}</p><p class="note"><a href="/account/register">返回注册页</a></p>"#
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
                layout::public_page(
                    "注册失败",
                    SUBTITLE,
                    &format!(
                        r#"<p class="alert" role="alert">{}</p><p class="note">请求 id：{}</p><p class="note"><a href="/account/register">返回注册页</a></p>"#,
                        escape_html(error.message()),
                        escape_html(request_id.as_str())
                    ),
                ),
            )
        },
    }
}

/// 按策略渲染表单与提示；`min_password_len` 来自配置，写进输入框的 `minlength`。
///
/// 只返回票根里的正文：标题由 [`layout::public_page`] 渲染；`closed` 策略在
/// [`page`] 里单独处理（标题不同）。
fn render_form(policy: RegistrationPolicy, min_password_len: usize) -> String {
    let hint = match policy {
        RegistrationPolicy::Open => "注册后账户立即可用。",
        RegistrationPolicy::Approval => "注册后需要管理员审批，审批通过前无法登录。",
        // closed 不会走到这里（[`page`] 直接给「注册已关闭」页），保留一句兜底文案。
        RegistrationPolicy::Closed => "当前不接受自助注册，请联系管理员开通账户。",
    };
    format!(
        r#"<p class="note">{hint}</p>
<form method="post" action="/account/register" class="form">
<label class="field"><span>用户名</span>
<input name="username" autocomplete="username" required minlength="3" maxlength="32">
</label>
<label class="field"><span>口令</span>
<input type="password" name="password" autocomplete="new-password" required minlength="{min_password_len}">
</label>
<label class="field"><span>确认口令</span>
<input type="password" name="confirm_password" autocomplete="new-password" required minlength="{min_password_len}">
</label>
<button type="submit" class="btn btn-wide">注册</button>
</form>
<p class="note">用户名 3–32 个字符，可用字母、数字、点、下划线与连字符；口令至少 {min_password_len} 个字符，且不能与用户名相同。</p>{BACK_TO_LOGIN}"#,
        hint = escape_html(hint),
    )
}

/// 注册页底部的「返回登录」链接：注册与登录必须能互相走回去，否则用户只能靠改地址栏。
const BACK_TO_LOGIN: &str = r#"<p class="note"><a href="/">返回登录</a></p>"#;

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
    use super::BodyMode;
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

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

//! 浏览器登录与退出：`GET /`（登录页）、`POST /login`（表单登录）、`POST /logout`。
//!
//! 这三个端点都在认证层**之外**：登录本来就是拿凭据的入口，退出又必须对「Cookie
//! 已经失效」的请求幂等。页面无脚本、无外部资源，登录成功后才由会话 Cookie 代表
//! 身份；Git 客户端不走这里，继续用 HTTP Basic。
//!
//! 四个必须自己处理、不能指望框架的点：
//!
//! 1. **登录 CSRF**：此刻还没有会话 Cookie，`csrf::guard` 的判定条件不成立，所以
//!    `POST /login` 自己无条件调 [`csrf::cross_site_reason`]——否则恶意页面能把
//!    受害者的浏览器悄悄登进攻击者的账户（login CSRF），此后受害者的操作都记在
//!    攻击者名下；
//! 2. **`next` 只能是站内路径**：`//evil.example`、`/\evil.example`、带控制字符的
//!    值都会变成开放重定向，一律拒绝并回落到角色落地页；
//! 3. **Cookie 的 `Secure` 与签发时同源**：统一用 [`session::request_is_https`]
//!    判定，HTTPS 站点上清除时不带 `Secure` 是清不掉的；
//! 4. **凭据判定只有一份**：一律调到 [`auth::verify_credentials`]，与 Basic 中间件
//!    同一条「DB 优先 → config 回落 → 懒升级」路径，不允许登录端点多放行身份。

use axum::extract::{Request, State};
use axum::http::header::{HeaderValue, RETRY_AFTER, SET_COOKIE};
use axum::http::{StatusCode, request::Parts};
use axum::response::Response;

use super::auth::{self, LoginFailure};
use super::csrf;
use super::html::{escape_html, html_response, parse_form, see_other};
use super::layout;
use super::session::{self, SessionCookieState};
use super::{AppState, RequestId};
use crate::config::{RegistrationPolicy, Role};

/// 登录表单的请求体上限：三个短字段，16 KiB 足够，超出按 400 处理。
const MAX_BODY_BYTES: usize = 16 * 1024;

/// `next` 的长度上限：超长的值既不该进表单隐藏字段，也不该进 `Location` 头。
const MAX_NEXT_LEN: usize = 2048;

/// 口令错误与「账户未激活」共用这一条文案：区分两者等于告诉任何人「这个用户名
/// 存在，只是还没审批」。
const LOGIN_FAILED_MESSAGE: &str = "用户名或口令错误，或账户未激活";

/// 表单缺字段时的 400 文案。
const MISSING_FIELDS_MESSAGE: &str = "请输入用户名与口令";

/// 跨站提交登录表单时的 403 文案。
const CROSS_SITE_MESSAGE: &str = "拒绝跨站登录请求：请从本站登录页提交";

/// 账户库故障时的 503 文案（与认证端点同样的口径）。
const LOGIN_UNAVAILABLE_MESSAGE: &str = "登录暂时不可用，请稍后重试";

/// 建会话失败（系统随机源不可用）时的 500 文案。
const SESSION_CREATE_MESSAGE: &str = "无法建立会话，请稍后重试";

/// 表单本身解析不出来时的 400 文案。
const MALFORMED_FORM_MESSAGE: &str = "表单格式不正确，请从登录页重新提交";

/// 登录页左侧的一句话定位（公开页共用同一套说明）。
const SUBTITLE: &str = "自建的 Git LFS 服务端：大对象写进百度网盘，仓库里只留指针。";

/// `GET /`：已登录按角色落地（尊重站内 `next`），未登录显示登录页。
pub(crate) async fn page(State(state): State<AppState>, request: Request) -> Response {
    let (parts, _body) = request.into_parts();
    let request_id = request_id_of(&parts);
    let cookie = session::parse_session_cookie(&parts.headers);
    // 清除 Cookie 的 `Secure` 必须与签发时同一口径，否则 HTTPS 站点上清不掉。
    let secure = session::request_is_https(&parts.headers, state.config());
    let next = next_from_query(parts.uri.query());

    match auth::session_identity(&state, &cookie).await {
        Ok(user) => {
            let target = next.as_deref().unwrap_or_else(|| landing(user.role));
            tracing::debug!(
                request_id = %request_id,
                username = %user.username,
                target = %target,
                "已登录，跳转落地页"
            );
            see_other(target)
        },
        Err(failure) => {
            // 畸形/失效/被撤销的 Cookie 顺手清掉：浏览器会一直重发同一个值，不清就
            // 永远没有出口。「没带 Cookie」与「账户库故障」不清（后者要等恢复）。
            let clear = failure.clears_cookie();
            tracing::debug!(request_id = %request_id, failure = ?failure, "未登录，显示登录页");
            let page = html_response(
                StatusCode::OK,
                layout::public_page("登录", SUBTITLE, &render_form(&state, next.as_deref(), None)),
            );
            if clear { auth::with_clear_cookie(page, secure) } else { page }
        },
    }
}

/// `POST /login`：先同站校验，再解析表单，凭据交给 [`auth::verify_credentials`]。
pub(crate) async fn submit(State(state): State<AppState>, request: Request) -> Response {
    let (parts, body) = request.into_parts();
    let request_id = request_id_of(&parts);
    let secure = session::request_is_https(&parts.headers, state.config());

    // 登录 CSRF：这时还没有会话 Cookie，全局守卫不会拦这段请求，必须自己判一次。
    if let Some(reason) = csrf::cross_site_reason(&parts.headers) {
        tracing::warn!(request_id = %request_id, reason, "拒绝跨站登录请求");
        return csrf::forbidden(&request_id, true, CROSS_SITE_MESSAGE);
    }

    let bytes = match axum::body::to_bytes(body, MAX_BODY_BYTES).await {
        Ok(bytes) => bytes,
        Err(error) => {
            tracing::warn!(request_id = %request_id, error = %error, "读取登录表单失败");
            return message_page(&state, StatusCode::BAD_REQUEST, MALFORMED_FORM_MESSAGE, None);
        },
    };
    let Ok(text) = std::str::from_utf8(&bytes) else {
        return message_page(&state, StatusCode::BAD_REQUEST, MALFORMED_FORM_MESSAGE, None);
    };
    let fields = match parse_form(text) {
        Ok(fields) => fields,
        Err(error) => {
            tracing::warn!(request_id = %request_id, error = %error, "解析登录表单失败");
            return message_page(&state, StatusCode::BAD_REQUEST, MALFORMED_FORM_MESSAGE, None);
        },
    };

    // `next` 来自隐藏字段，同样是用户输入：每次都要重新校验，不能只信登录页那次。
    let next = fields.get("next").and_then(|raw| in_site_path(raw)).map(str::to_owned);
    let username = fields.get("username").map(String::as_str).unwrap_or("");
    let password = fields.get("password").map(String::as_str).unwrap_or("");
    if username.is_empty() || password.is_empty() {
        tracing::warn!(request_id = %request_id, reason = "missing_fields", "登录被拒：表单缺字段");
        return message_page(
            &state,
            StatusCode::BAD_REQUEST,
            MISSING_FIELDS_MESSAGE,
            next.as_deref(),
        );
    }

    match auth::verify_credentials(&state, username, password.as_bytes()).await {
        Ok(user) => {
            let Some(id) = state.sessions().create(&user.username, user.role) else {
                // 随机源不可用：宁可这次登不上（500），也不能发一个可预测的会话 id。
                tracing::error!(request_id = %request_id, "建立会话失败：系统随机源不可用");
                return message_page(
                    &state,
                    StatusCode::INTERNAL_SERVER_ERROR,
                    SESSION_CREATE_MESSAGE,
                    next.as_deref(),
                );
            };
            let target = next.unwrap_or_else(|| landing(user.role).to_owned());
            tracing::info!(
                request_id = %request_id,
                username = %user.username,
                role = %user.role,
                target = %target,
                "浏览器登录成功"
            );
            let mut response = see_other(&target);
            if let Ok(value) = HeaderValue::from_str(&session::secure_cookie(&id, secure)) {
                response.headers_mut().append(SET_COOKIE, value);
            }
            response
        },
        Err(failure) => failure_page(&state, failure, next.as_deref(), &request_id),
    }
}

/// `POST /logout`：撤销会话、清 Cookie、回登录页；没有 Cookie 也 303（幂等）。
pub(crate) async fn logout(State(state): State<AppState>, request: Request) -> Response {
    let (parts, _body) = request.into_parts();
    let request_id = request_id_of(&parts);
    let secure = session::request_is_https(&parts.headers, state.config());
    let cookie = session::parse_session_cookie(&parts.headers);

    // 撤销钩子（改密/禁用/删除）不覆盖显式退出：这里必须自己 revoke，否则这条
    // 会话会一直活到空闲过期，用户以为「退出了」其实还能用。
    match &cookie {
        SessionCookieState::Present(id) => {
            state.sessions().revoke(id);
            tracing::info!(request_id = %request_id, "退出登录：已撤销会话");
        },
        SessionCookieState::Malformed => {
            tracing::debug!(request_id = %request_id, "退出登录：Cookie 畸形，顺手清掉");
        },
        SessionCookieState::Missing => {
            tracing::debug!(request_id = %request_id, "退出登录：没有会话 Cookie（幂等）");
        },
    }

    // 有没有会话都清一次 Cookie 并 303：退出必须幂等，刷新、重放、退回历史页都不出错。
    auth::with_clear_cookie(see_other("/"), secure)
}

/// 登录后的默认落地页：管理员进管理页，其他角色进账户页。
fn landing(role: Role) -> &'static str {
    match role {
        Role::Admin => "/admin",
        _ => "/account",
    }
}

/// 校验 `next` 是否是本站内的绝对路径；不合法返回 `None`（调用方回落到角色落地页）。
///
/// 规则（任一条不满足即拒，防开放重定向）：
///
/// - 只接受**单个** `/` 开头：`//evil.example` 是协议相对 URL，浏览器会跳到外站；
/// - 不含反斜杠：浏览器把 `\` 规范成 `/`，`/\evil.example` 与 `//evil.example` 等价；
/// - 不含控制字符：`\r`/`\n` 能撕开 `Location` 头（响应头注入），NUL 会让下游工具
///   与日志行为异常；
/// - 长度不超过 [`MAX_NEXT_LEN`]。
///
/// 只做「是不是站内路径」的判断，不判断目标角色：`next=/admin` 交给普通用户也只会
/// 得到 `/admin` 自己的 403，不在登录端点上做第二套权限规则。
fn in_site_path(raw: &str) -> Option<&str> {
    if raw.len() > MAX_NEXT_LEN || !raw.starts_with('/') || raw.starts_with("//") {
        return None;
    }
    if raw.contains('\\') || raw.chars().any(char::is_control) {
        return None;
    }
    Some(raw)
}

/// 从查询串里取 `next`；缺省、解析失败或非法值都返回 `None`。
fn next_from_query(query: Option<&str>) -> Option<String> {
    let fields = parse_form(query?).ok()?;
    in_site_path(fields.get("next")?).map(str::to_owned)
}

/// 渲染登录表单；`next` 原样回填（转义后），错误文案只作为提示。
///
/// 只返回票根里的正文：`<h1>` 由 [`layout::public_page`] 渲染，避免标题出现两次。
fn render_form(state: &AppState, next: Option<&str>, error: Option<&str>) -> String {
    let mut body = String::from(
        r#"<p class="note">用账户用户名与口令登录；Git 客户端继续用 HTTP Basic，不需要在这里登录。</p>"#,
    );
    if let Some(error) = error {
        // `role="alert"`：读屏器会把登录失败当场播报，不必再去找错误在哪。
        body.push_str(&format!(r#"<p class="alert" role="alert">{}</p>"#, escape_html(error)));
    }
    body.push_str(r#"<form method="post" action="/login" class="form">"#);
    if let Some(next) = next {
        // 属性值必须转义：`next` 直接来自 `?next=`（用户可控）。
        body.push_str(&format!(
            r#"<input type="hidden" name="next" value="{}">"#,
            escape_html(next)
        ));
    }
    body.push_str(
        r#"<label class="field"><span>用户名</span>
<input name="username" autocomplete="username" required autofocus>
</label>
<label class="field"><span>口令</span>
<input type="password" name="password" autocomplete="current-password" required>
</label>
<button type="submit" class="btn btn-wide">登录</button>
</form>"#,
    );
    if matches!(state.config().accounts.registration, RegistrationPolicy::Approval) {
        body.push_str(r#"<p class="note">注册后需要管理员审批，审批通过前无法登录。</p>"#);
    }
    body.push_str(r#"<p class="note"><a href="/account/register">注册账号</a></p>"#);
    body
}

/// 以登录页形态回一个错误状态码（缺字段 400、建会话失败 500、账户库 503）。
fn message_page(
    state: &AppState,
    status: StatusCode,
    message: &str,
    next: Option<&str>,
) -> Response {
    html_response(
        status,
        layout::public_page("登录", SUBTITLE, &render_form(state, next, Some(message))),
    )
}

/// 凭据判定失败的响应：401 / 429（带 `Retry-After`）/ 503，页面形态保持一致。
fn failure_page(
    state: &AppState,
    failure: LoginFailure,
    next: Option<&str>,
    request_id: &RequestId,
) -> Response {
    let (status, message, retry_after) = match failure {
        // 「凭据不对」与「账户未激活」对外完全一致，状态码都是 401。
        LoginFailure::BadCredentials { .. } | LoginFailure::Inactive => {
            (StatusCode::UNAUTHORIZED, LOGIN_FAILED_MESSAGE.to_owned(), None)
        },
        LoginFailure::RateLimited { retry_after } => {
            let seconds = retry_after.as_secs().max(1);
            (
                StatusCode::TOO_MANY_REQUESTS,
                format!("登录失败次数过多，请 {seconds} 秒后重试"),
                Some(seconds),
            )
        },
        LoginFailure::Unavailable => {
            (StatusCode::SERVICE_UNAVAILABLE, LOGIN_UNAVAILABLE_MESSAGE.to_owned(), None)
        },
    };
    tracing::warn!(
        request_id = %request_id,
        reason = failure.reason(),
        status = status.as_u16(),
        "登录失败"
    );
    let mut response = html_response(
        status,
        layout::public_page("登录", SUBTITLE, &render_form(state, next, Some(&message))),
    );
    if let Some(seconds) = retry_after
        && let Ok(value) = HeaderValue::from_str(&seconds.to_string())
    {
        response.headers_mut().insert(RETRY_AFTER, value);
    }
    response
}

/// 请求级 id；中间件未命中（直接调用 handler 的测试）时自造一个，错误页也能对账。
fn request_id_of(parts: &Parts) -> RequestId {
    parts.extensions.get::<RequestId>().cloned().unwrap_or_else(RequestId::generate)
}

#[cfg(test)]
mod tests {
    use super::{in_site_path, landing, next_from_query};
    use crate::config::Role;

    #[test]
    fn given_role_when_landing_then_admin_goes_to_admin_page() {
        assert_eq!(landing(Role::Admin), "/admin");
        assert_eq!(landing(Role::Readwrite), "/account");
        assert_eq!(landing(Role::Readonly), "/account");
    }

    #[test]
    fn given_in_site_path_when_in_site_path_then_accepted() {
        for path in ["/", "/account", "/admin?status=pending", "/a/b-c_d.e?x=1&y=2", "/a%20b"] {
            assert_eq!(in_site_path(path), Some(path), "{path} 是站内路径");
        }
        // 上限之内的长路径仍然接受。
        let long = format!("/{}", "a".repeat(2047));
        assert!(in_site_path(&long).is_some());
    }

    #[test]
    fn given_offsite_or_control_chars_when_in_site_path_then_rejected() {
        // 协议相对 URL、绝对 URL、相对路径都不是站内绝对路径。
        for raw in
            ["", "//evil.example", "///evil.example", "https://evil.example", "evil", "./x", "../x"]
        {
            assert_eq!(in_site_path(raw), None, "{raw:?} 必须被拒");
        }
        // 反斜杠会被浏览器规范成 `/`，`/\evil.example` 等价于 `//evil.example`。
        assert_eq!(in_site_path("/\\evil.example"), None);
        // 控制字符能撕开响应头或干扰日志。
        for raw in ["/a\nb", "/a\rb", "/a\tb", "/a\0b", "/a\u{7f}b"] {
            assert_eq!(in_site_path(raw), None, "{raw:?} 必须被拒");
        }
        // 超长值。
        let long = format!("/{}", "a".repeat(2048));
        assert_eq!(in_site_path(&long), None);
    }

    #[test]
    fn given_query_when_next_from_query_then_decoded_and_validated() {
        assert_eq!(next_from_query(Some("next=%2Faccount")), Some("/account".to_owned()));
        assert_eq!(
            next_from_query(Some("next=%2Fadmin%3Fstatus%3Dpending")),
            Some("/admin?status=pending".to_owned())
        );
        // 没有 next、next 为空、next 非法、查询串本身解析失败都回 None。
        assert_eq!(next_from_query(None), None);
        assert_eq!(next_from_query(Some("")), None);
        assert_eq!(next_from_query(Some("next=")), None);
        assert_eq!(next_from_query(Some("next=%2F%2Fevil.example")), None);
        assert_eq!(next_from_query(Some("next=%zz")), None);
    }
}

//! 自身账户端点：`GET /account`（HTML 落地页）、`GET /account/me`、
//! `POST /account/password`、`DELETE /account`。
//!
//! 四个端点都挂认证（会话 Cookie 或 HTTP Basic，任意角色），只能操作**自己**——用户名
//! 取自认证中间件写进请求扩展的 [`AuthUser`]，没有「按用户名指定目标」的入口，因此
//! 不存在越权修改他人账户的可能；管理员管理他人账户是 C3 的 `/admin/*`。
//!
//! `GET /account` 是浏览器登录后的落地页：左「身份」、右「LFS 接入」，退出在页头。
//! 不提供改密/注销按钮（那两个是 API，走 `POST /account/password` 与
//! `DELETE /account`，需要重新确认口令）。账户库未接入时它照样能渲染：config-only
//! 用户本来就该有落地页，只是创建/最后登录时间显示 `—`；`GET /account/me` 与两个
//! 写端点仍保持「没有库就 503」（没有库就没有可改的账户，config 用户改口令请直接改
//! `config.toml` 后重启）。
//!
//! 页面会按「这次是怎么认证的」给出不同提示：Basic 是浏览器缓存的凭据，页面上的退出
//! 按钮只清会话 Cookie，对 Basic 用户无效，所以那种情况下不渲染退出表单（页头只给
//! 说明）并在身份面板里写清「当前为 HTTP Basic 认证」，避免给出一个按了也不生效的
//! 按钮。

use axum::Extension;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::auth::AuthUser;
use super::error::ApiError;
use super::html::{escape_html, format_unix_seconds, html_response};
use super::layout::{self, CredentialChannel, Nav, role_label, status_dot, status_label};
use super::{
    ACCOUNTS_NOT_CONFIGURED_MESSAGE, ACCOUNTS_UNAVAILABLE_MESSAGE, AppState, RequestId,
    action_base, config_admin_fallback, config_username, json_with_status, passwords,
};
use crate::accounts::{AccountError, User, UserStatus, validate_password};
use crate::config::Role;

/// 账户库未接入（`accounts: None`）时的 503。
fn accounts_disabled() -> ApiError {
    ApiError::Unavailable(ACCOUNTS_NOT_CONFIGURED_MESSAGE.to_owned())
}

/// 账户库已接入但读写失败时的 503：与「没配账户库」区分开，排障方向不同。
fn accounts_unavailable() -> ApiError {
    ApiError::Unavailable(ACCOUNTS_UNAVAILABLE_MESSAGE.to_owned())
}

/// `GET /account/me` 的响应体。
#[derive(Debug, Serialize)]
struct AccountView {
    /// 用户名。
    username: String,
    /// 角色。
    role: Role,
    /// 状态。
    status: UserStatus,
    /// 创建时间（unix 秒）；来自配置文件的旧账户没有这个信息，为 `null`。
    created_at: Option<i64>,
    /// 最后一次成功登录时间（unix 秒）；从未登录为 `null`。
    last_login_at: Option<i64>,
}

impl AccountView {
    /// 账户库里的账户视图。
    fn from_user(user: &User) -> Self {
        Self {
            username: user.username.clone(),
            role: user.role,
            status: user.status,
            created_at: Some(user.created_at),
            last_login_at: user.last_login_at,
        }
    }

    /// 只在 `[auth.users]` 里的旧账户视图（尚未懒升级成功时兜底）。
    fn from_config(username: &str, role: Role) -> Self {
        Self {
            username: username.to_owned(),
            role,
            status: UserStatus::Active,
            created_at: None,
            last_login_at: None,
        }
    }
}

/// `GET /account`：登录后的落地页（无脚本；退出走表单 POST `/logout`）。
///
/// 与 [`me`] 共用 [`AccountView`]，但**不**因为账户库未接入就 503：config-only 用户
/// 也有权看到自己的身份与 LFS 端点，只是创建/最后登录时间显示 `—`。
pub(crate) async fn page(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    headers: HeaderMap,
) -> Response {
    let view = match state.accounts() {
        Some(users) => match users.get(&auth.username).await {
            Ok(Some(user)) => AccountView::from_user(&user),
            // 库里没有这一行：config-only 用户（尚未懒升级，或用户名不符合库规则）。
            // 认证中间件刚刚放行过，这里按配置视图展示，不再 503。
            Ok(None) | Err(AccountError::InvalidUsername { .. }) => {
                AccountView::from_config(&auth.username, auth.role)
            },
            Err(error) => {
                tracing::error!(username = %auth.username, error = %error, "账户页读取自身账户失败");
                return problem_page(ACCOUNTS_UNAVAILABLE_MESSAGE);
            },
        },
        None => AccountView::from_config(&auth.username, auth.role),
    };
    // 与 batch 下发的 href 同一份推导：`public_base` 优先，否则按请求头算。
    let base = action_base(state.config(), &headers);
    // 同一路径两条通道都通：有 `Authorization` 就是 Basic（它的优先级高于 Cookie），
    // 页面必须据此给出「退出按钮能不能真的退出」的准确提示。
    let channel = CredentialChannel::of(&headers);
    tracing::debug!(
        request_id = %request_id,
        username = %view.username,
        channel = channel.as_str(),
        "渲染账户页"
    );
    html_response(
        StatusCode::OK,
        layout::authed_page(
            "我的账户",
            &auth,
            view.status,
            channel,
            Nav::Account,
            &render_page(&view, &base, channel),
        ),
    )
}

/// 账户页读库失败时的 503 页。
fn problem_page(message: &str) -> Response {
    let body = format!(r#"<p class="alert" role="alert">{}</p>"#, escape_html(message));
    html_response(
        StatusCode::SERVICE_UNAVAILABLE,
        layout::public_page("我的账户暂时不可用", "账户库读写失败，请稍后重试。", &body),
    )
}

/// 账户页正文：左「身份」面板 + 右「LFS 接入」面板。
///
/// 所有动态文本都过 [`escape_html`]：`base` 在没有 `public_base` 时来自 `Host` 头，
/// 用户名来自账户库，两者都必须按不可信输入处理。
fn render_page(view: &AccountView, base: &str, channel: CredentialChannel) -> String {
    let time = |seconds: Option<i64>| match seconds {
        Some(seconds) => format_unix_seconds(seconds),
        // 只有 config-only 用户会走到这里（库里有行就一定有 created_at）。
        None => "—".to_owned(),
    };
    // 首字母方块：用户名可能以非拉丁字符开头（甚至为空），取不到就退回中性符号，
    // 不让布局塌掉。
    let initial = view
        .username
        .chars()
        .next()
        .map(|first| first.to_uppercase().collect::<String>())
        .unwrap_or_else(|| "·".to_owned());
    // 两条通道的退出方式不同：会话可以由服务端撤销，Basic 只能由浏览器清除。
    let channel_note = match channel {
        CredentialChannel::Session => {
            "当前以会话 Cookie 登录，页头右侧可以退出；Git 客户端请用同一账户的 HTTP Basic 凭据。"
        },
        CredentialChannel::Basic => {
            "当前为 HTTP Basic 认证：凭据由浏览器缓存，本页无法代为清除；退出请关闭浏览器，或清除浏览器为本站点保存的凭据。"
        },
    };
    let admin_link = if view.role == Role::Admin {
        r#"<p class="panel-note"><a href="/admin">管理账户</a></p>"#
    } else {
        ""
    };

    let mut body = String::from(
        r#"<div class="lede"><h1>我的账户</h1><p>身份与 LFS 接入方式；角色与状态以账户库为准。</p></div>
<div class="split">"#,
    );
    body.push_str(&format!(
        r#"<section class="panel" aria-labelledby="identity-title">
<p class="panel-k" id="identity-title">身份</p>
<div class="id-head">
<span class="initial" aria-hidden="true">{initial}</span>
<div>
<div class="id-name">{name}</div>
<div class="id-sub"><span class="badge" title="{role_key}">{role}</span><span class="state"><span class="dot {dot}" aria-hidden="true"></span>{status}</span></div>
</div>
</div>
<dl class="meta">
<dt>创建时间</dt><dd>{created}</dd>
<dt>最后登录</dt><dd>{last_login}</dd>
</dl>
<p class="panel-note">{channel_note}</p>
{admin_link}
</section>"#,
        initial = escape_html(&initial),
        name = escape_html(&view.username),
        role_key = view.role.as_str(),
        role = escape_html(role_label(view.role)),
        dot = status_dot(view.status),
        status = escape_html(status_label(view.status)),
        created = time(view.created_at),
        last_login = time(view.last_login_at),
        channel_note = channel_note,
    ));
    // git-lfs 会把 `objects/batch` 拼在 `lfs.url` 后面，所以这里必须给到 `/lfs/`；
    // 只给站点根地址的话，用户照抄示例会在 `/objects/batch` 上拿到 404。
    body.push_str(&format!(
        r#"<section class="panel" aria-labelledby="lfs-title">
<p class="panel-k" id="lfs-title">LFS 接入</p>
<p>Endpoint <code>{base}/lfs/</code></p>
<p class="note">在仓库根目录提交 <code>.lfsconfig</code>，git-lfs 会把 <code>objects/batch</code> 拼在这个地址后面：</p>
<pre><code>[lfs]
	url = {base}/lfs/</code></pre>
<ol class="steps">
<li><code>git lfs install</code>：为当前用户启用 LFS 钩子。</li>
<li><code>git lfs track "*.bin"</code>：把大文件后缀登记进 <code>.gitattributes</code>。</li>
<li><code>git push origin main</code>：提交后对象经网关写入网盘，指针留在 Git 历史里。</li>
</ol>
<p class="note">凭据仍走 HTTP Basic：首次 push 时输入账户用户名与口令。</p>
</section>"#,
        base = escape_html(base),
    ));
    body.push_str("</div>");
    body
}

/// `GET /account/me`：返回当前登录账户的资料。
pub(crate) async fn me(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
) -> Response {
    let Some(users) = state.accounts() else {
        return accounts_disabled().into_response_with(&request_id);
    };
    match users.get(&auth.username).await {
        Ok(Some(user)) => {
            json_with_status(StatusCode::OK, &AccountView::from_user(&user), &request_id)
        },
        // 理论上认证中间件已经懒升级；账户库写失败时仍按 config 视图返回，
        // 让用户至少能看到自己是谁、什么角色，而不是一个 500。
        Ok(None) | Err(AccountError::InvalidUsername { .. }) => json_with_status(
            StatusCode::OK,
            &AccountView::from_config(&auth.username, auth.role),
            &request_id,
        ),
        Err(error) => {
            tracing::error!(username = %auth.username, error = %error, "读取自身账户失败");
            accounts_unavailable().into_response_with(&request_id)
        },
    }
}

/// `POST /account/password` 的请求体。
#[derive(Debug, Deserialize)]
struct PasswordChange {
    /// 当前口令，用于确认操作者是本人。
    old_password: String,
    /// 新口令，按 `[accounts] min_password_len` 校验。
    new_password: String,
}

/// `POST /account/password`：校验旧口令后替换为新口令，成功 204。
pub(crate) async fn change_password(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    body: axum::body::Bytes,
) -> Response {
    let response = change_password_inner(&state, &auth, &body).await;
    match response {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response_with(&request_id),
    }
}

/// 改密的实际流程；拆出来是为了让 handler 只做响应映射。
async fn change_password_inner(
    state: &AppState,
    auth: &AuthUser,
    body: &[u8],
) -> Result<(), ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_disabled());
    };
    let change: PasswordChange = serde_json::from_slice(body)
        .map_err(|error| ApiError::BadRequest(format!("请求体不是合法 JSON：{error}")))?;

    let user = match users.get(&auth.username).await {
        Ok(Some(user)) => user,
        Ok(None) | Err(AccountError::InvalidUsername { .. }) => {
            // config 用户没升级成功（例如账户库写失败）时无法用库里的哈希确认旧口令。
            return Err(accounts_unavailable());
        },
        Err(error) => {
            tracing::error!(username = %auth.username, error = %error, "改密时读取账户失败");
            return Err(accounts_unavailable());
        },
    };

    let hash = match users.password_hash(&user.username).await {
        Ok(Some(hash)) => hash,
        Ok(None) => return Err(accounts_unavailable()),
        Err(error) => {
            tracing::error!(username = %user.username, error = %error, "改密时读取口令哈希失败");
            return Err(accounts_unavailable());
        },
    };
    if !passwords::verify(hash, change.old_password.into_bytes()).await {
        tracing::warn!(username = %user.username, reason = "wrong_old_password", "改密被拒");
        return Err(ApiError::Unauthorized("旧口令不正确".to_owned()));
    }

    let min_len = state.config().accounts.min_password_len;
    validate_password(&user.username, &change.new_password, min_len)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let new_hash = passwords::hash(change.new_password).await.map_err(|error| {
        tracing::error!(username = %user.username, error = %error, "新口令哈希失败");
        ApiError::Internal("生成口令哈希失败".to_owned())
    })?;
    users.update_password_hash(&user.username, &new_hash).await.map_err(|error| {
        tracing::error!(username = %user.username, error = %error, "写入口令哈希失败");
        accounts_unavailable()
    })?;
    tracing::info!(username = %user.username, "账户自助修改口令成功");
    // 改口令 = 换凭据：包括当前浏览器在内的全部会话都失效，所有设备都要用新口令
    // 重新登录（这里不做「保留当前会话」的例外，少一份特例少一处漏判）。
    state.sessions().revoke_user(&user.username);
    Ok(())
}

/// `DELETE /account` 的请求体。
#[derive(Debug, Deserialize)]
struct DeleteAccount {
    /// 当前口令，用于确认操作者是本人。
    password: String,
}

/// `DELETE /account`：校验口令后删除自己的账户，成功 204。
///
/// 只删 `users` 行，**不删除任何 LFS 对象**：对象全局共享、内容寻址，其他仓库
/// 可能引用同一 oid。
pub(crate) async fn delete_self(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    body: axum::body::Bytes,
) -> Response {
    match delete_self_inner(&state, &auth, &body).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response_with(&request_id),
    }
}

async fn delete_self_inner(state: &AppState, auth: &AuthUser, body: &[u8]) -> Result<(), ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_disabled());
    };
    let request: DeleteAccount = serde_json::from_slice(body)
        .map_err(|error| ApiError::BadRequest(format!("请求体不是合法 JSON：{error}")))?;

    let user = match users.get(&auth.username).await {
        Ok(Some(user)) => user,
        Ok(None) | Err(AccountError::InvalidUsername { .. }) => {
            // 账户只在配置文件里：删除它需要改 config.toml 并重启，不能由 HTTP 完成。
            return Err(ApiError::Conflict(
                "该账户来自配置文件，无法自助注销；请让管理员从 [auth.users] 中移除".to_owned(),
            ));
        },
        Err(error) => {
            tracing::error!(username = %auth.username, error = %error, "注销时读取账户失败");
            return Err(accounts_unavailable());
        },
    };

    let hash = match users.password_hash(&user.username).await {
        Ok(Some(hash)) => hash,
        Ok(None) => return Err(accounts_unavailable()),
        Err(error) => {
            tracing::error!(username = %user.username, error = %error, "注销时读取口令哈希失败");
            return Err(accounts_unavailable());
        },
    };
    if !passwords::verify(hash, request.password.into_bytes()).await {
        tracing::warn!(username = %user.username, reason = "wrong_password", "注销被拒");
        return Err(ApiError::Unauthorized("口令不正确".to_owned()));
    }

    // 配置里还有同名用户时，删掉库里的行会让那份旧 sha256 口令重新生效——这里
    // 只告警不阻止（管理员可能正准备迁移），但必须让运维在日志里看得见。
    if config_username(state.config(), &user.username).is_some() {
        tracing::warn!(
            username = %user.username,
            "[auth.users] 中存在同名条目：删除账户后该配置口令会重新可用，请同步移除"
        );
    }

    // 「最后一个管理员」的判定与删除在账户库的同一个事务里完成：分成 count + delete
    // 两步时，两个管理员并发注销都能通过检查，事后一个管理员都不剩。
    let config_admins = config_admin_fallback(state.config(), &user.username);
    match users.delete_guarded(&user.username, config_admins).await {
        Ok(()) => {},
        Err(AccountError::LastAdmin { .. }) => {
            tracing::warn!(username = %user.username, reason = "last_admin", "注销被拒：最后一个管理员");
            return Err(ApiError::Conflict(
                "不能注销最后一个管理员账户：请先由其他管理员或配置文件接管".to_owned(),
            ));
        },
        Err(AccountError::NotFound { .. }) => {
            return Err(ApiError::NotFound("账户不存在".to_owned()));
        },
        Err(error) => {
            tracing::error!(username = %user.username, error = %error, "删除账户失败");
            return Err(ApiError::Internal("删除账户失败".to_owned()));
        },
    }
    // 审计：这里不删 LFS 对象（内容寻址、全局共享），只失效凭据。
    tracing::info!(
        username = %user.username,
        role = %user.role,
        "账户自助注销成功（LFS 对象不随账户删除）"
    );
    // 账户行已删，会话也必须跟着消失。
    state.sessions().revoke_user(&user.username);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::AccountView;
    use crate::accounts::UserStatus;
    use crate::config::Role;

    #[test]
    fn given_config_only_user_when_view_then_timestamps_are_null() {
        let view = AccountView::from_config("legacy", Role::Readonly);

        assert_eq!(view.username, "legacy");
        assert_eq!(view.role, Role::Readonly);
        assert_eq!(view.status, UserStatus::Active);
        assert_eq!(view.created_at, None);
        assert_eq!(view.last_login_at, None);
    }
}

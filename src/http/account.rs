//! 自身账户端点：`GET /account/me`、`POST /account/password`、`DELETE /account`。
//!
//! 三个端点都挂 Basic 认证（任意角色），只能操作**自己**——用户名取自认证中间件
//! 写进请求扩展的 [`AuthUser`]，没有「按用户名指定目标」的入口，因此不存在越权
//! 修改他人账户的可能；管理员管理他人账户是 C3 的 `/admin/*`。
//!
//! 账户库未接入时统一 503：没有库就没有可改的账户（config 用户改口令请直接改
//! `config.toml` 后重启）。

use axum::Extension;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};

use super::auth::AuthUser;
use super::error::ApiError;
use super::{ACCOUNTS_UNAVAILABLE_MESSAGE, AppState, RequestId, json_with_status, passwords};
use crate::accounts::{AccountError, User, UserStatus, validate_password};
use crate::config::Role;

/// 账户库未接入时的 503。
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

/// `GET /account/me`：返回当前登录账户的资料。
pub(crate) async fn me(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
) -> Response {
    let Some(users) = state.accounts() else {
        return accounts_unavailable().into_response_with(&request_id);
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
        return Err(accounts_unavailable());
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
        ApiError::Internal("更新口令失败".to_owned())
    })?;
    tracing::info!(username = %user.username, "账户自助修改口令成功");
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
        return Err(accounts_unavailable());
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

    if would_remove_last_admin(state, &user).await? {
        tracing::warn!(username = %user.username, reason = "last_admin", "注销被拒：最后一个管理员");
        return Err(ApiError::Conflict(
            "不能注销最后一个管理员账户：请先由其他管理员或配置文件接管".to_owned(),
        ));
    }

    // 配置里还有同名用户时，删掉库里的行会让那份旧 sha256 口令重新生效——这里
    // 只告警不阻止（管理员可能正准备迁移），但必须让运维在日志里看得见。
    if state.config().auth.users.keys().any(|name| name.eq_ignore_ascii_case(&user.username)) {
        tracing::warn!(
            username = %user.username,
            "[auth.users] 中存在同名条目：删除账户后该配置口令会重新可用，请同步移除"
        );
    }

    users.delete(&user.username).await.map_err(|error| {
        tracing::error!(username = %user.username, error = %error, "删除账户失败");
        ApiError::Internal("删除账户失败".to_owned())
    })?;
    // 审计：这里不删 LFS 对象（内容寻址、全局共享），只失效凭据。
    tracing::info!(
        username = %user.username,
        role = %user.role,
        "账户自助注销成功（LFS 对象不随账户删除）"
    );
    Ok(())
}

/// 删除 `user` 之后，系统是否会失去**最后一个** active 管理员。
///
/// 只有 `user` 本身是 active admin 时才需要保护；管理员来源有两处：账户库与
/// `[auth.users]`。配置文件里的同名条目不算「另一个管理员」——删掉库里的行之后
/// 它是**同一个人**重新获得 config 权限，不是冗余的第二个管理员。
///
/// C3 的 `DELETE /admin/users/{name}` 与「降级/禁用最后一个管理员」复用本函数。
pub(crate) async fn would_remove_last_admin(
    state: &AppState,
    user: &User,
) -> Result<bool, ApiError> {
    if user.role != Role::Admin || user.status != UserStatus::Active {
        return Ok(false);
    }
    let Some(users) = state.accounts() else {
        return Ok(false);
    };
    let db_admins = users.count_active_admins().await.map_err(|error| {
        tracing::error!(error = %error, "统计管理员数量失败");
        accounts_unavailable()
    })?;
    let config_admins = state
        .config()
        .auth
        .users
        .iter()
        .filter(|(name, config_user)| {
            config_user.role == Role::Admin && !name.eq_ignore_ascii_case(&user.username)
        })
        .count();
    // db_admins 包含 user 自己：只剩 1 个且配置里没有其他管理员时，删掉就没人能
    // 再进 /admin/*，只能改配置文件重启。
    Ok(db_admins <= 1 && config_admins == 0)
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

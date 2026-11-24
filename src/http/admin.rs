//! 管理员账户管理：JSON API（`/admin/users`）与极简 HTML 管理页（`/admin`）。
//!
//! 全部端点都过两道闸：先 Basic 认证（`auth::require`，判定「你是谁」），再过
//! [`require_admin`]（判定「能不能进」）。非管理员一律 403：脚本客户端拿到统一
//! JSON 错误体，浏览器（`Accept: text/html`）拿到 403 页。
//!
//! 两条入口、一套逻辑：
//!
//! - JSON API 是规范入口，供脚本与将来的 UI 使用；
//! - HTML 管理页的操作按钮走表单 POST（`.../approve`、`.../disable`、`.../delete`
//!   等），只做「解析表单 → 调同一套函数 → 303 回 `/admin`」，不复制任何判定逻辑。
//!   成功后 303（See Other）而不是 200：浏览器刷新时重新 GET 管理页，不会重复提交。
//!
//! 保护规则（顺序即优先级，见各函数）：
//!
//! 1. 目标不存在 → 404；账户库未接入 → 503；
//! 2. 会让系统失去最后一个 active 管理员 → 409（[`would_remove_last_admin`]）；
//! 3. 改/删自己 → 409（自助改口令与注销走 `/account/*`）；
//! 4. 删除时 `[auth.users]` 里还有同名条目 → 409：删掉库里的行会让那份旧 sha256
//!    口令重新可用，必须先由运维从配置里移除。
//!
//! 审计：**每个写操作**都打一条 `tracing::info!`，字段 `actor`、`action`、`target`、
//! `request_id`；口令只在请求体里存活，绝不进日志、不进响应。

use std::collections::HashMap;

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, Request, State};
use axum::http::header::LOCATION;
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::account::would_remove_last_admin;
use super::auth::AuthUser;
use super::error::ApiError;
use super::html::{
    escape_html, format_unix_seconds, html_response, page_shell, parse_form, table, wants_html,
};
use super::register::duplicate_username;
use super::{ACCOUNTS_NOT_CONFIGURED_MESSAGE, AppState, RequestId, json_with_status, passwords};
use crate::accounts::{AccountError, User, UserStatus, validate_password, validate_username};
use crate::config::Role;

/// `GET /admin/users` 未带 `limit` 时的页大小（与账户库的默认值一致）。
const DEFAULT_LIMIT: u32 = 50;

/// 单页上限，同时也是管理页一次展示的上限（账户库会把更大的 `limit` 截到这里）。
const MAX_LIMIT: u32 = 100;

/// 写操作请求体上限：字段都很短，16 KiB 足够，超出直接 400。
const MAX_BODY_BYTES: usize = 16 * 1024;

/// 账户库未接入时的 503。
fn accounts_unavailable() -> ApiError {
    ApiError::Unavailable(ACCOUNTS_NOT_CONFIGURED_MESSAGE.to_owned())
}

/// 管理员判定：请求扩展里的角色不是 [`Role::Admin`] 就 403。
///
/// 必须挂在 [`super::auth::require`] **之内**（先认证、后判角色），装配顺序见
/// `http::admin_router`。这里只读扩展不重新解析凭据：认证只做一次。
pub(crate) async fn require_admin(request: Request, next: Next) -> Response {
    let allowed = request.extensions().get::<Role>().is_some_and(|role| *role == Role::Admin);
    if allowed {
        return next.run(request).await;
    }
    let request_id =
        request.extensions().get::<RequestId>().cloned().unwrap_or_else(RequestId::generate);
    tracing::warn!(request_id = %request_id, "非管理员访问管理端点");
    if wants_html(request.headers()) {
        let body = format!(
            r#"<h1>禁止访问</h1><p class="error">管理页只对管理员开放：当前账户不是管理员。</p><p class="hint">请求 id：{}</p><p class="hint"><a href="/admin">返回管理页</a></p>"#,
            escape_html(request_id.as_str())
        );
        html_response(StatusCode::FORBIDDEN, page_shell("禁止访问", &body))
    } else {
        ApiError::Forbidden("需要管理员权限：当前账户不是管理员".to_owned())
            .into_response_with(&request_id)
    }
}

/// 对外暴露的账户视图；字段与 `/account/me` 保持一致，额外包含管理需要的 `status`。
#[derive(Debug, Serialize)]
struct AdminUserView {
    /// 用户名（账户库里的规范写法）。
    username: String,
    /// 角色。
    role: Role,
    /// 状态。
    status: UserStatus,
    /// 创建时间（unix 秒）；账户库里的账户一定有。
    created_at: i64,
    /// 最后一次成功登录时间（unix 秒）；从未登录为 `null`。
    last_login_at: Option<i64>,
}

impl AdminUserView {
    /// 账户库里的账户视图。
    fn from_user(user: &User) -> Self {
        Self {
            username: user.username.clone(),
            role: user.role,
            status: user.status,
            created_at: user.created_at,
            last_login_at: user.last_login_at,
        }
    }
}

/// `GET /admin/users` 的响应体：当页账户与过滤后的总数。
#[derive(Debug, Serialize)]
struct UserList {
    /// 当页账户，按创建顺序（账户库 `id`）排列。
    users: Vec<AdminUserView>,
    /// 满足 `status` 过滤条件的总数，与分页无关。
    total: u64,
}

/// `GET /admin/users?status=&limit=&offset=`。
pub(crate) async fn list(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    query: RawQuery,
) -> Response {
    match list_inner(&state, &query).await {
        Ok(page) => json_with_status(StatusCode::OK, &page, &request_id),
        Err(error) => error.into_response_with(&request_id),
    }
}

async fn list_inner(state: &AppState, query: &RawQuery) -> Result<UserList, ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_unavailable());
    };
    let (status, limit, offset) = parse_list_query(query.0.as_deref())?;
    let (page, total) = users.list(status, limit, offset).await.map_err(|error| {
        tracing::error!(error = %error, "列出账户失败");
        accounts_unavailable()
    })?;
    Ok(UserList { users: page.iter().map(AdminUserView::from_user).collect(), total })
}

/// 解析 `status` / `limit` / `offset`；非法取值一律 400（而不是静默忽略）。
fn parse_list_query(raw: Option<&str>) -> Result<(Option<UserStatus>, u32, u32), ApiError> {
    let Some(raw) = raw else {
        return Ok((None, DEFAULT_LIMIT, 0));
    };
    let fields = parse_form(raw)?;
    let status = match fields.get("status").map(String::as_str) {
        None | Some("") => None,
        Some(value) => Some(UserStatus::parse(value).ok_or_else(|| {
            ApiError::BadRequest(format!(
                "status 只能是 active、pending 或 disabled，实际为 {value}"
            ))
        })?),
    };
    let limit = parse_u32(&fields, "limit", DEFAULT_LIMIT)?;
    let offset = parse_u32(&fields, "offset", 0)?;
    Ok((status, limit, offset))
}

/// 从查询参数里读一个非负整数；缺省或空串用 `default`。
fn parse_u32(fields: &HashMap<String, String>, name: &str, default: u32) -> Result<u32, ApiError> {
    match fields.get(name).map(String::as_str) {
        None | Some("") => Ok(default),
        Some(raw) => raw
            .parse::<u32>()
            .map_err(|_| ApiError::BadRequest(format!("{name} 必须是非负整数，实际为 {raw}"))),
    }
}

/// `POST /admin/users` 的请求体。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct CreatePayload {
    /// 用户名（3–32 个 `[A-Za-z0-9._-]`）。
    username: String,
    /// 明文口令；按 `[accounts] min_password_len` 校验后立即哈希丢弃。
    password: String,
    /// 角色；管理员可以创建管理员。
    role: Role,
    /// 状态；缺省 `active`。
    #[serde(default)]
    status: Option<UserStatus>,
}

/// `PATCH /admin/users/{name}` 的请求体；至少要有 `role` 或 `status` 之一。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PatchPayload {
    /// 新角色。
    #[serde(default)]
    role: Option<Role>,
    /// 新状态。
    #[serde(default)]
    status: Option<UserStatus>,
}

/// `POST /admin/users/{name}/password` 的请求体。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordPayload {
    /// 新口令；管理员重置时不需要旧口令。
    password: String,
}

/// `POST /admin/users`：创建账户，成功 201。
pub(crate) async fn create(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    body: Bytes,
) -> Response {
    let payload: CreatePayload = match read_json(&body) {
        Ok(payload) => payload,
        Err(error) => return error.into_response_with(&request_id),
    };
    match create_account(&state, &request_id, &auth, payload).await {
        Ok(user) => {
            json_with_status(StatusCode::CREATED, &AdminUserView::from_user(&user), &request_id)
        },
        Err(error) => error.into_response_with(&request_id),
    }
}

/// `PATCH /admin/users/{name}`：改角色/状态，成功 200 并返回更新后的视图。
pub(crate) async fn patch(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    let changes: PatchPayload = match read_json(&body) {
        Ok(changes) => changes,
        Err(error) => return error.into_response_with(&request_id),
    };
    match patch_account(&state, &request_id, &auth, &name, changes).await {
        Ok(user) => json_with_status(StatusCode::OK, &AdminUserView::from_user(&user), &request_id),
        Err(error) => error.into_response_with(&request_id),
    }
}

/// `DELETE /admin/users/{name}`：删除账户，成功 204。
pub(crate) async fn delete(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
) -> Response {
    match delete_account(&state, &request_id, &auth, &name).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response_with(&request_id),
    }
}

/// `POST /admin/users/{name}/password`：管理员重置口令（含自己），成功 204。
pub(crate) async fn reset_password(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    let payload: PasswordPayload = match read_json(&body) {
        Ok(payload) => payload,
        Err(error) => return error.into_response_with(&request_id),
    };
    match reset_password_for(&state, &request_id, &auth, &name, payload.password).await {
        Ok(()) => StatusCode::NO_CONTENT.into_response(),
        Err(error) => error.into_response_with(&request_id),
    }
}

/// 管理员创建账户：绕过 `[accounts] registration` 策略，允许 `role = admin`。
///
/// 先查重再哈希，与自助注册同一套顺序：Argon2 不便宜，没必要为必然失败的请求付
/// 19 MiB 的开销。`status` 缺省 `active`——管理员创建账户通常就是为了立刻能用。
async fn create_account(
    state: &AppState,
    request_id: &RequestId,
    actor: &AuthUser,
    payload: CreatePayload,
) -> Result<User, ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_unavailable());
    };
    let min_len = state.config().accounts.min_password_len;

    validate_username(&payload.username)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    validate_password(&payload.username, &payload.password, min_len)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let status = payload.status.unwrap_or(UserStatus::Active);

    match users.get(&payload.username).await {
        Ok(Some(_)) => return Err(duplicate_username(&payload.username)),
        // 用户名刚校验通过，理论上不会走到这里；真走到就交给 `create` 的唯一约束兜底。
        Ok(None) | Err(AccountError::InvalidUsername { .. }) => {},
        Err(error) => {
            tracing::error!(error = %error, "创建账户前查重失败");
            return Err(accounts_unavailable());
        },
    }

    let hash = passwords::hash(payload.password).await.map_err(|error| {
        tracing::error!(error = %error, "管理员创建账户时生成口令哈希失败");
        ApiError::Internal("生成口令哈希失败".to_owned())
    })?;

    let user = match users.create(&payload.username, &hash, payload.role, status).await {
        Ok(user) => user,
        // 预检查与插入之间可能有并发创建抢到同一个用户名。
        Err(AccountError::DuplicateUsername { .. }) => {
            return Err(duplicate_username(&payload.username));
        },
        Err(AccountError::InvalidUsername { reason, .. }) => {
            return Err(ApiError::BadRequest(format!("用户名不合法：{reason}")));
        },
        Err(AccountError::InvalidPassword { reason }) => {
            return Err(ApiError::BadRequest(format!("口令不合法：{reason}")));
        },
        Err(error) => {
            tracing::error!(error = %error, "管理员创建账户失败");
            return Err(ApiError::Internal("创建账户失败".to_owned()));
        },
    };
    tracing::info!(
        actor = %actor.username,
        action = "user.create",
        target = %user.username,
        role = %user.role,
        status = user.status.as_str(),
        request_id = %request_id,
        "管理员创建账户"
    );
    Ok(user)
}

/// 管理员改角色/状态：审批（pending→active）、禁用、启用、升降级都走这一条。
///
/// 判定顺序见模块文档；`would_remove_last_admin` 抛错（账户库故障）时按 503 上报，
/// 不把「查不到管理员数量」当成「不是最后一个」放行。
async fn patch_account(
    state: &AppState,
    request_id: &RequestId,
    actor: &AuthUser,
    name: &str,
    changes: PatchPayload,
) -> Result<User, ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_unavailable());
    };
    if changes.role.is_none() && changes.status.is_none() {
        return Err(ApiError::BadRequest("至少要提供 role 或 status 之一".to_owned()));
    }
    let target = load_user(state, name).await?;
    let new_role = changes.role.unwrap_or(target.role);
    let new_status = changes.status.unwrap_or(target.status);
    let changed = new_role != target.role || new_status != target.status;

    // 先判「最后一个管理员」再判「自己」：只有一个管理员时，前者的解释更贴近真实
    // 原因（不是「你不许改自己」，而是「改了就没人能再进管理页」）。
    if changed && would_remove_last_admin(state, &target).await? {
        tracing::warn!(
            actor = %actor.username,
            target = %target.username,
            "拒绝降级或禁用最后一个管理员"
        );
        return Err(ApiError::Conflict(
            "不能降级或禁用最后一个 active 管理员：请先指定另一个管理员".to_owned(),
        ));
    }
    if target.username.eq_ignore_ascii_case(&actor.username) {
        return Err(ApiError::Conflict("不能修改自己的角色或状态：请由其他管理员操作".to_owned()));
    }
    // 无变化的 PATCH 不写库、不打审计：`updated_at` 是「资料变更时间」，不该被空操作刷新。
    if !changed {
        return Ok(target);
    }

    if new_role != target.role {
        users.update_role(&target.username, new_role).await.map_err(|error| {
            tracing::error!(target = %target.username, error = %error, "修改账户角色失败");
            ApiError::Internal("修改角色失败".to_owned())
        })?;
    }
    if new_status != target.status {
        users.update_status(&target.username, new_status).await.map_err(|error| {
            tracing::error!(target = %target.username, error = %error, "修改账户状态失败");
            ApiError::Internal("修改状态失败".to_owned())
        })?;
    }
    // 回读一次：响应里给的是账户库的真实状态，而不是我们以为写进去的值。
    let updated = load_user(state, &target.username).await?;
    tracing::info!(
        actor = %actor.username,
        action = "user.update",
        target = %updated.username,
        role = %updated.role,
        status = updated.status.as_str(),
        previous_role = %target.role,
        previous_status = target.status.as_str(),
        request_id = %request_id,
        "管理员修改账户"
    );
    Ok(updated)
}

/// 管理员删除账户：只删 `users` 行，**不删除任何 LFS 对象**（对象全局共享、内容寻址）。
async fn delete_account(
    state: &AppState,
    request_id: &RequestId,
    actor: &AuthUser,
    name: &str,
) -> Result<(), ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_unavailable());
    };
    let target = load_user(state, name).await?;

    if would_remove_last_admin(state, &target).await? {
        tracing::warn!(
            actor = %actor.username,
            target = %target.username,
            "拒绝删除最后一个管理员"
        );
        return Err(ApiError::Conflict(
            "不能删除最后一个 active 管理员：请先指定另一个管理员".to_owned(),
        ));
    }
    if target.username.eq_ignore_ascii_case(&actor.username) {
        return Err(ApiError::Conflict(
            "不能删除自己的账户：如需注销请用 DELETE /account 自助完成".to_owned(),
        ));
    }
    // 删掉库里的行之后，`[auth.users]` 里的同名条目会让那份旧 sha256 口令重新生效。
    // 这不是「可能重名」而是「同一个人换个入口原地复活」，必须硬拒。
    if let Some(config_name) = config_same_name(state, &target.username) {
        tracing::warn!(
            actor = %actor.username,
            target = %target.username,
            config_entry = %config_name,
            "拒绝删除：[auth.users] 中存在同名条目"
        );
        return Err(ApiError::Conflict(format!(
            "[auth.users] 中存在同名条目 {config_name}：请先移除该配置项，否则删除后旧口令会重新生效"
        )));
    }

    users.delete(&target.username).await.map_err(|error| {
        tracing::error!(target = %target.username, error = %error, "删除账户失败");
        ApiError::Internal("删除账户失败".to_owned())
    })?;
    tracing::info!(
        actor = %actor.username,
        action = "user.delete",
        target = %target.username,
        role = %target.role,
        status = target.status.as_str(),
        request_id = %request_id,
        "管理员删除账户（LFS 对象不随账户删除）"
    );
    Ok(())
}

/// 管理员重置口令：不需要旧口令，按同一套口令策略校验后覆盖哈希。
///
/// 允许重置自己的口令（忘记口令时的唯一自助补救），但仍然要求管理员身份。
async fn reset_password_for(
    state: &AppState,
    request_id: &RequestId,
    actor: &AuthUser,
    name: &str,
    password: String,
) -> Result<(), ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_unavailable());
    };
    let target = load_user(state, name).await?;
    let min_len = state.config().accounts.min_password_len;
    validate_password(&target.username, &password, min_len)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;

    let hash = passwords::hash(password).await.map_err(|error| {
        tracing::error!(target = %target.username, error = %error, "重置口令时生成哈希失败");
        ApiError::Internal("生成口令哈希失败".to_owned())
    })?;
    users.update_password_hash(&target.username, &hash).await.map_err(|error| {
        tracing::error!(target = %target.username, error = %error, "写入口令哈希失败");
        ApiError::Internal("更新口令失败".to_owned())
    })?;
    // 审计只记「谁给谁重置了」，不记口令本身。
    tracing::info!(
        actor = %actor.username,
        action = "user.reset_password",
        target = %target.username,
        request_id = %request_id,
        "管理员重置账户口令"
    );
    Ok(())
}

/// 按用户名取账户；不存在（含只存在于 `[auth.users]`、或用户名不符合库规则）报 404。
async fn load_user(state: &AppState, name: &str) -> Result<User, ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_unavailable());
    };
    match users.get(name).await {
        Ok(Some(user)) => Ok(user),
        Ok(None) | Err(AccountError::InvalidUsername { .. }) => {
            Err(ApiError::NotFound(missing_user_message(state, name)))
        },
        Err(error) => {
            tracing::error!(username = %name, error = %error, "查询账户失败");
            Err(accounts_unavailable())
        },
    }
}

/// 404 的文案：配置用户单独解释，避免运维以为「账户凭空消失」。
fn missing_user_message(state: &AppState, name: &str) -> String {
    match config_same_name(state, name) {
        Some(config_name) => format!(
            "账户库里没有 {config_name}：它只存在于 [auth.users]，首次登录升级为账户库账户后才可由管理端点管理"
        ),
        None => format!("用户 {name} 不存在"),
    }
}

/// `[auth.users]` 里与 `name` 同名的条目（大小写不敏感）；用于删除前的硬拒与 404 提示。
fn config_same_name(state: &AppState, name: &str) -> Option<String> {
    state.config().auth.users.keys().find(|candidate| candidate.eq_ignore_ascii_case(name)).cloned()
}

/// 解析 JSON 请求体；失败统一 400。
fn read_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ApiError::BadRequest(format!("请求体超过 {MAX_BODY_BYTES} 字节")));
    }
    serde_json::from_slice(body)
        .map_err(|error| ApiError::BadRequest(format!("请求体不是合法 JSON：{error}")))
}

/// 管理页的过滤条件：合法的 `?status=`，外加（若有）无法识别的原始输入。
#[derive(Debug)]
struct Filter {
    /// 生效的状态过滤；`None` 表示显示全部。
    status: Option<UserStatus>,
    /// 无法识别的 `?status=` 原文：页面提示「已忽略」并**转义**后回显。
    unknown: Option<String>,
}

/// `GET /admin`：只读的用户表格，所有改动都是页面上的表单 POST。
pub(crate) async fn page(
    State(state): State<AppState>,
    Extension(request_id): Extension<RequestId>,
    query: RawQuery,
) -> Response {
    let Some(users) = state.accounts() else {
        return accounts_unavailable_page();
    };
    let filter = match parse_filter(query.0.as_deref()) {
        Ok(filter) => filter,
        Err(error) => return error_page(&error, &request_id),
    };
    let (list, total) = match users.list(filter.status, MAX_LIMIT, 0).await {
        Ok(page) => page,
        Err(error) => {
            tracing::error!(error = %error, "管理页列出账户失败");
            return accounts_unavailable_page();
        },
    };
    let min_password_len = state.config().accounts.min_password_len;
    let body = render_page(&list, total, &filter, min_password_len);
    html_response(StatusCode::OK, page_shell("账户管理", &body))
}

/// 没有账户库时的管理页：503 页而不是空表格（空表格会被误读成「一个账户都没有」）。
fn accounts_unavailable_page() -> Response {
    let body = format!(
        r#"<h1>管理页不可用</h1><p class="error">{}</p>"#,
        escape_html(ACCOUNTS_NOT_CONFIGURED_MESSAGE)
    );
    html_response(StatusCode::SERVICE_UNAVAILABLE, page_shell("管理页不可用", &body))
}

/// 解析管理页的 `?status=`。
fn parse_filter(raw: Option<&str>) -> Result<Filter, ApiError> {
    let Some(raw) = raw else {
        return Ok(Filter { status: None, unknown: None });
    };
    let fields = parse_form(raw)?;
    let Some(value) = fields.get("status").filter(|value| !value.is_empty()) else {
        return Ok(Filter { status: None, unknown: None });
    };
    match UserStatus::parse(value) {
        Some(status) => Ok(Filter { status: Some(status), unknown: None }),
        None => Ok(Filter { status: None, unknown: Some(value.clone()) }),
    }
}

/// 渲染整页：过滤链接、提示、表格。
fn render_page(list: &[User], total: u64, filter: &Filter, min_password_len: usize) -> String {
    let mut body = String::from("<h1>账户管理</h1>");
    body.push_str(&format!(
        r#"<p class="hint">共 {total} 个账户，本页显示 {} 个（每页最多 {MAX_LIMIT} 个）。删除账户不会删除任何 LFS 对象：对象全局共享、内容寻址。</p>"#,
        list.len()
    ));
    body.push_str(&render_filters(filter));
    if let Some(unknown) = &filter.unknown {
        body.push_str(&format!(
            r#"<p class="error">无法识别的状态过滤 “{}”，已显示全部账户；可选 active、pending、disabled。</p>"#,
            escape_html(unknown)
        ));
    }
    let rows = list
        .iter()
        .map(|user| render_row(user, filter.status, min_password_len))
        .collect::<Vec<_>>();
    body.push_str(&table(&["用户名", "角色", "状态", "创建时间", "最后登录", "操作"], &rows));
    body.push_str(
        r#"<p class="hint">账户来自账户库；<code>[auth.users]</code> 里的配置用户在首次登录后才会出现在这里。</p>"#,
    );
    body
}

/// 状态过滤链接；每个链接都带 `?status=`，当前生效的那条加「(当前)」。
fn render_filters(filter: &Filter) -> String {
    let mut html = String::from(r#"<nav class="filters">"#);
    for (label, status) in [
        ("全部", None),
        ("正常", Some(UserStatus::Active)),
        ("待审批", Some(UserStatus::Pending)),
        ("已禁用", Some(UserStatus::Disabled)),
    ] {
        let href = match status {
            Some(status) => format!("/admin?status={}", status.as_str()),
            None => "/admin".to_owned(),
        };
        let current = if filter.status == status { " <strong>(当前)</strong>" } else { "" };
        html.push_str(&format!(r#"<a href="{href}">{label}{current}</a>"#));
    }
    html.push_str("</nav>");
    html
}

/// 一行表格：纯文本单元格全部转义，最后一格是操作表单。
fn render_row(user: &User, filter: Option<UserStatus>, min_password_len: usize) -> Vec<String> {
    vec![
        escape_html(&user.username),
        format!(r#"<span title="{}">{}</span>"#, user.role.as_str(), role_label(user.role)),
        format!(r#"<span title="{}">{}</span>"#, user.status.as_str(), status_label(user.status)),
        format_unix_seconds(user.created_at),
        match user.last_login_at {
            Some(seconds) => format_unix_seconds(seconds),
            None => "从未登录".to_owned(),
        },
        render_actions(user, filter, min_password_len),
    ]
}

/// 操作格：按状态给「批准 / 禁用 / 启用」，外加角色切换、重置口令与删除。
///
/// 每个按钮各自一个 `<form>`（HTML 不允许嵌套表单）；当前过滤条件作为隐藏字段
/// 随表单提交，操作完再跳回同一个过滤视图。
fn render_actions(user: &User, filter: Option<UserStatus>, min_password_len: usize) -> String {
    // 用户名虽然按规则只允许 ASCII 字母数字与 `.` `_` `-`，这里仍然转义：页面渲染要对
    // 「有人手工改库、或将来放宽用户名规则」保持安全，属性值也不例外。
    let name = escape_html(&user.username);
    let hidden = filter
        .map(|status| format!(r#"<input type="hidden" name="status" value="{}">"#, status.as_str()))
        .unwrap_or_default();

    let mut html = String::from(r#"<div class="actions">"#);
    let (action, label) = match user.status {
        UserStatus::Pending => ("approve", "批准"),
        UserStatus::Active => ("disable", "禁用"),
        UserStatus::Disabled => ("enable", "启用"),
    };
    html.push_str(&format!(
        r#"<form method="post" action="/admin/users/{name}/{action}">{hidden}<button type="submit">{label}</button></form>"#
    ));

    let mut options = String::new();
    for role in [Role::Readonly, Role::Readwrite, Role::Admin] {
        let selected = if role == user.role { " selected" } else { "" };
        options.push_str(&format!(
            r#"<option value="{}"{selected}>{}</option>"#,
            role.as_str(),
            role_label(role)
        ));
    }
    html.push_str(&format!(
        r#"<form method="post" action="/admin/users/{name}/role">{hidden}<select name="role">{options}</select><button type="submit">保存角色</button></form>"#
    ));

    html.push_str(&format!(
        r#"<form method="post" action="/admin/users/{name}/password-form">{hidden}<input type="password" name="password" placeholder="新口令" autocomplete="new-password" required minlength="{min_password_len}"><button type="submit">重置口令</button></form>"#
    ));

    // 删除是不可逆的：浏览器侧 `required` 勾选框 + 服务端再查一次 `confirm` 字段。
    html.push_str(&format!(
        r#"<form method="post" action="/admin/users/{name}/delete">{hidden}<label class="inline"><input type="checkbox" name="confirm" value="yes" required>确认删除</label><button type="submit" class="danger">删除</button></form>"#
    ));
    html.push_str("</div>");
    html
}

/// 角色在页面上的中文标签。
fn role_label(role: Role) -> &'static str {
    match role {
        Role::Readonly => "只读",
        Role::Readwrite => "读写",
        Role::Admin => "管理员",
    }
}

/// 状态在页面上的中文标签。
fn status_label(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "正常",
        UserStatus::Pending => "待审批",
        UserStatus::Disabled => "已禁用",
    }
}

/// `POST /admin/users/{name}/approve`：待审批 → 正常（303）。
pub(crate) async fn approve(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    set_status(state, auth, request_id, name, body, UserStatus::Active).await
}

/// `POST /admin/users/{name}/disable`：正常 → 已禁用（303）。
pub(crate) async fn disable(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    set_status(state, auth, request_id, name, body, UserStatus::Disabled).await
}

/// `POST /admin/users/{name}/enable`：已禁用 → 正常（303）。
pub(crate) async fn enable(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    set_status(state, auth, request_id, name, body, UserStatus::Active).await
}

/// 三个状态按钮的公共实现：解析隐藏的过滤条件 → 调 [`patch_account`] → 303 回管理页。
async fn set_status(
    state: AppState,
    auth: AuthUser,
    request_id: RequestId,
    name: String,
    body: Bytes,
    status: UserStatus,
) -> Response {
    let fields = match form_fields(&body) {
        Ok(fields) => fields,
        Err(error) => return error_page(&error, &request_id),
    };
    let filter = fields.get("status").and_then(|value| UserStatus::parse(value));
    let changes = PatchPayload { role: None, status: Some(status) };
    match patch_account(&state, &request_id, &auth, &name, changes).await {
        Ok(_) => redirect_to_admin(filter),
        Err(error) => error_page(&error, &request_id),
    }
}

/// `POST /admin/users/{name}/role`：切换角色（303）。
pub(crate) async fn role_form(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    let fields = match form_fields(&body) {
        Ok(fields) => fields,
        Err(error) => return error_page(&error, &request_id),
    };
    let filter = fields.get("status").and_then(|value| UserStatus::parse(value));
    let role = match fields.get("role").map(String::as_str) {
        Some(raw) => match Role::parse(raw) {
            Some(role) => role,
            None => {
                let error = ApiError::BadRequest(format!(
                    "未知的角色 {raw}：只能是 readonly、readwrite 或 admin"
                ));
                return error_page(&error, &request_id);
            },
        },
        None => {
            let error = ApiError::BadRequest("缺少表单字段 role".to_owned());
            return error_page(&error, &request_id);
        },
    };
    let changes = PatchPayload { role: Some(role), status: None };
    match patch_account(&state, &request_id, &auth, &name, changes).await {
        Ok(_) => redirect_to_admin(filter),
        Err(error) => error_page(&error, &request_id),
    }
}

/// `POST /admin/users/{name}/password-form`：管理页的重置口令表单（303）。
pub(crate) async fn password_form(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    let fields = match form_fields(&body) {
        Ok(fields) => fields,
        Err(error) => return error_page(&error, &request_id),
    };
    let filter = fields.get("status").and_then(|value| UserStatus::parse(value));
    let Some(password) = fields.get("password").filter(|value| !value.is_empty()).cloned() else {
        let error = ApiError::BadRequest("缺少表单字段 password".to_owned());
        return error_page(&error, &request_id);
    };
    match reset_password_for(&state, &request_id, &auth, &name, password).await {
        Ok(()) => redirect_to_admin(filter),
        Err(error) => error_page(&error, &request_id),
    }
}

/// `POST /admin/users/{name}/delete`：管理页的删除表单（303）。
///
/// 页面上的勾选框只是浏览器侧的护栏，服务端同样要求 `confirm` 字段：不能指望
/// 每个客户端都执行 HTML 校验。
pub(crate) async fn delete_form(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    body: Bytes,
) -> Response {
    let fields = match form_fields(&body) {
        Ok(fields) => fields,
        Err(error) => return error_page(&error, &request_id),
    };
    let filter = fields.get("status").and_then(|value| UserStatus::parse(value));
    if !fields.get("confirm").is_some_and(|value| !value.is_empty()) {
        let error = ApiError::BadRequest("删除需要先勾选确认框".to_owned());
        return error_page(&error, &request_id);
    }
    match delete_account(&state, &request_id, &auth, &name).await {
        Ok(()) => redirect_to_admin(filter),
        Err(error) => error_page(&error, &request_id),
    }
}

/// 解析表单请求体（`application/x-www-form-urlencoded`）。
fn form_fields(body: &[u8]) -> Result<HashMap<String, String>, ApiError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ApiError::BadRequest("表单不是合法的 UTF-8".to_owned()))?;
    parse_form(text)
}

/// 表单操作成功后的回跳地址：保留当前 `?status=` 过滤，避免审批完丢掉上下文。
fn redirect_to_admin(filter: Option<UserStatus>) -> Response {
    let location = match filter {
        Some(status) => format!("/admin?status={}", status.as_str()),
        None => "/admin".to_owned(),
    };
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    if let Ok(value) = HeaderValue::from_str(&location) {
        response.headers_mut().insert(LOCATION, value);
    }
    response
}

/// 表单操作的失败页：状态码沿用 [`ApiError`]，消息与 request id 都转义后回显。
fn error_page(error: &ApiError, request_id: &RequestId) -> Response {
    let status = error.status();
    let body = format!(
        r#"<h1>操作失败</h1><p class="error">{}</p><p class="hint">请求 id：{}</p><p class="hint"><a href="/admin">返回管理页</a></p>"#,
        escape_html(error.message()),
        escape_html(request_id.as_str())
    );
    html_response(status, page_shell("操作失败", &body))
}

#[cfg(test)]
mod tests {
    use super::{
        Filter, MAX_LIMIT, parse_filter, parse_list_query, render_actions, role_label, status_label,
    };
    use crate::accounts::{User, UserStatus};
    use crate::config::Role;

    #[test]
    fn given_hostile_username_when_render_actions_then_escaped_in_attributes() {
        let user = User {
            username: "<script>alert(1)</script>".to_owned(),
            role: Role::Admin,
            status: UserStatus::Active,
            created_at: 0,
            last_login_at: None,
        };

        let html = render_actions(&user, None, 12);

        assert!(!html.contains("<script"), "属性值也必须转义：{html}");
        assert!(html.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "实际：{html}");
        // 状态按钮、角色下拉、口令输入与删除确认都在同一格里。
        assert!(html.contains("/disable"), "active 账户应给「禁用」");
        assert!(html.contains(r#"<select name="role">"#));
        assert!(html.contains(r#"name="confirm" value="yes" required"#));
    }

    #[test]
    fn given_query_when_parse_list_then_defaults_and_filters() {
        assert_eq!(parse_list_query(None).expect("默认值合法"), (None, 50, 0));
        assert_eq!(
            parse_list_query(Some("status=pending&limit=7&offset=3")).expect("合法查询"),
            (Some(UserStatus::Pending), 7, 3)
        );
        assert_eq!(
            parse_list_query(Some("status=&limit=&offset=")).expect("空值按缺省"),
            (None, 50, 0)
        );
        // 上限由账户库截断，解析层只负责接受大值（不报错）。
        assert_eq!(
            parse_list_query(Some(&format!("limit={}", MAX_LIMIT + 900))).expect("大值可接受").1,
            MAX_LIMIT + 900
        );
    }

    #[test]
    fn given_bad_query_when_parse_list_then_bad_request() {
        assert!(parse_list_query(Some("status=unknown")).is_err(), "未知状态应 400");
        assert!(parse_list_query(Some("limit=abc")).is_err(), "非整数 limit 应 400");
        assert!(parse_list_query(Some("limit=-1")).is_err(), "负数 limit 应 400");
        assert!(parse_list_query(Some("offset=%zz")).is_err(), "非法转义应 400");
    }

    #[test]
    fn given_status_query_when_parse_filter_then_known_and_unknown() {
        assert_eq!(parse_filter(None).expect("缺省").status, None);
        assert_eq!(
            parse_filter(Some("status=active")).expect("合法").status,
            Some(UserStatus::Active)
        );

        let unknown: Filter = parse_filter(Some("status=bogus")).expect("未知值不报错");
        assert_eq!(unknown.status, None);
        assert_eq!(unknown.unknown.as_deref(), Some("bogus"), "原文留给页面提示（转义后回显）");
    }

    #[test]
    fn given_roles_and_statuses_when_label_then_chinese() {
        assert_eq!(role_label(Role::Admin), "管理员");
        assert_eq!(role_label(Role::Readwrite), "读写");
        assert_eq!(role_label(Role::Readonly), "只读");
        assert_eq!(status_label(UserStatus::Active), "正常");
        assert_eq!(status_label(UserStatus::Pending), "待审批");
        assert_eq!(status_label(UserStatus::Disabled), "已禁用");
    }
}

//! 管理员账户管理：JSON API（`/admin/users`）与极简 HTML 管理页（`/admin`）。
//!
//! 全部端点都过两道闸：先 Basic 认证（`auth::require`，判定「你是谁」），再过
//! [`require_admin`]（判定「能不能进」）。非管理员一律 403：脚本客户端拿到统一
//! JSON 错误体，浏览器（`Accept: text/html`）拿到 403 页。
//!
//! 写请求还有两道与「谁」无关的关卡：`require_admin` 里的同站校验（`Sec-Fetch-Site`
//! / `Origin`，挡浏览器 CSRF），以及各 handler 的 `Content-Type` 校验（JSON 端点
//! 只收 `application/json`、表单端点只收 `application/x-www-form-urlencoded`，
//! 否则 415——`text/plain` 请求体不触发 CORS 预检，是另一条绕过路径）。
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
//! 2. 改/删自己 → 409（自助改口令与注销走 `/account/*`）；
//! 3. 删除时 `[auth.users]` 里还有同名条目 → 409：删掉库里的行会让那份旧 sha256
//!    口令重新可用，必须先由运维从配置里移除；
//! 4. 「失去最后一个 active 管理员」→ 409，但这一条由账户库在**事务内**判定
//!    （`update_profile_guarded` / `delete_guarded`）：先 count 再 update 会留下
//!    并发窗口，两个管理员互降可以同时成功。`[auth.users]` 里不同名的管理员作为
//!    数据库之外的兜底一并计入，同名条目不算。
//!
//! 审计：**每个写操作**都打一条 `tracing::info!`，字段 `actor`、`action`、`target`、
//! `request_id`；口令只在请求体里存活，绝不进日志、不进响应。

use std::collections::HashMap;

use axum::Extension;
use axum::body::{Body, Bytes};
use axum::extract::{Path, RawQuery, Request, State};
use axum::http::HeaderMap;
use axum::http::header::{CONTENT_TYPE, LOCATION};
use axum::http::{HeaderValue, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use serde::de::DeserializeOwned;
use serde::{Deserialize, Serialize};

use super::auth::AuthUser;
use super::csrf;
use super::error::ApiError;
use super::html::{
    escape_html, format_unix_seconds, html_response, page_shell, parse_form, table, wants_html,
};
use super::register::username_taken;
use super::{
    ACCOUNTS_NOT_CONFIGURED_MESSAGE, ACCOUNTS_UNAVAILABLE_MESSAGE, AppState, RequestId,
    config_admin_fallback, config_username, json_with_status, passwords,
};
use crate::accounts::{AccountError, User, UserStatus, validate_password, validate_username};
use crate::config::Role;

/// `GET /admin/users` 未带 `limit` 时的页大小（与账户库的默认值一致）。
const DEFAULT_LIMIT: u32 = 50;

/// 单页上限，同时也是管理页一次展示的上限（账户库会把更大的 `limit` 截到这里）。
const MAX_LIMIT: u32 = 100;

/// 写操作请求体上限：字段都很短，16 KiB 足够，超出直接 400。
const MAX_BODY_BYTES: usize = 16 * 1024;

/// 账户库未接入（`accounts: None`）时的 503。
fn accounts_disabled() -> ApiError {
    ApiError::Unavailable(ACCOUNTS_NOT_CONFIGURED_MESSAGE.to_owned())
}

/// 账户库已接入但读写失败时的 503：与「没配账户库」区分开，排障方向不同。
fn accounts_unavailable() -> ApiError {
    ApiError::Unavailable(ACCOUNTS_UNAVAILABLE_MESSAGE.to_owned())
}

/// 管理员判定 + 写操作的同站校验。
///
/// 挂在 [`super::auth::require`] **之内**（先认证、后判角色），装配顺序见
/// `http::admin_router`。这里只读扩展、不重新解析凭据：认证只做一次。
///
/// 除了角色，这里还要挡 CSRF。Basic 凭据是浏览器的「环境凭据」：表单 POST 属于
/// CORS simple request，恶意页面不需要读到响应，就能让浏览器带着已缓存的凭据
/// 删账户、重置口令。判定顺序（读请求一律放行，跨站读没有 CORS 头也读不到内容）：
///
/// 1. `Sec-Fetch-Site` 存在时只认 `same-origin` / `same-site` / `none`，其余 403；
/// 2. 否则看 `Origin`：与请求 `Host` 的主机名比对（忽略 scheme 与端口），不一致 403；
/// 3. 两者都没有（curl / CLI / 老客户端）放行——这类客户端不会自动附带凭据，
///    不存在 CSRF 面。
pub(crate) async fn require_admin(request: Request, next: Next) -> Response {
    let actor = request
        .extensions()
        .get::<AuthUser>()
        .map(|auth| auth.username.clone())
        .unwrap_or_default();
    let request_id =
        request.extensions().get::<RequestId>().cloned().unwrap_or_else(RequestId::generate);
    let html_page = wants_html(request.headers());

    if request.extensions().get::<Role>().copied() != Some(Role::Admin) {
        tracing::warn!(request_id = %request_id, actor = %actor, "非管理员访问管理端点");
        return forbidden(&request_id, html_page, "需要管理员权限：当前账户不是管理员");
    }

    if csrf::is_write_method(request.method())
        && let Some(reason) = csrf::cross_site_reason(request.headers())
    {
        tracing::warn!(
            request_id = %request_id,
            actor = %actor,
            reason = reason,
            "拒绝跨站写请求"
        );
        return forbidden(
            &request_id,
            html_page,
            "拒绝跨站写请求：请从管理页操作，或使用 API 客户端",
        );
    }
    next.run(request).await
}

/// 403：浏览器给页面，脚本客户端给统一 JSON 错误体。
fn forbidden(request_id: &RequestId, html_page: bool, message: &str) -> Response {
    if html_page {
        let body = format!(
            r#"<h1>禁止访问</h1><p class="error">{}</p><p class="hint">请求 id：{}</p><p class="hint"><a href="/admin">返回管理页</a></p>"#,
            escape_html(message),
            escape_html(request_id.as_str())
        );
        html_response(StatusCode::FORBIDDEN, page_shell("禁止访问", &body))
    } else {
        ApiError::Forbidden(message.to_owned()).into_response_with(request_id)
    }
}

/// JSON 写端点要求 `application/json`（含 `+json`），否则 415。
///
/// 只靠同站校验不够：`text/plain` 的请求体不触发 CORS 预检，是「no-cors 就能打
/// 进来」的经典入口，媒体类型上必须再关一道。
fn require_json(headers: &HeaderMap) -> Result<(), ApiError> {
    match media_type(headers).as_deref() {
        Some(media) if media == "application/json" || media.ends_with("+json") => Ok(()),
        _ => Err(ApiError::UnsupportedMediaType(
            "管理 API 只接受 Content-Type: application/json".to_owned(),
        )),
    }
}

/// 表单端点要求 `application/x-www-form-urlencoded`，否则 415。
fn require_form(headers: &HeaderMap) -> Result<(), ApiError> {
    match media_type(headers).as_deref() {
        Some("application/x-www-form-urlencoded") => Ok(()),
        _ => Err(ApiError::UnsupportedMediaType(
            "管理页表单只接受 Content-Type: application/x-www-form-urlencoded".to_owned(),
        )),
    }
}

/// `Content-Type` 的媒体类型部分：小写、去掉 `; charset=...` 之类的参数。
fn media_type(headers: &HeaderMap) -> Option<String> {
    let raw = headers.get(CONTENT_TYPE)?.to_str().ok()?;
    Some(raw.split(';').next()?.trim().to_ascii_lowercase())
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
        return Err(accounts_disabled());
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
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_json(&headers) {
        return error.into_response_with(&request_id);
    }
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
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_json(&headers) {
        return error.into_response_with(&request_id);
    }
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
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_json(&headers) {
        return error.into_response_with(&request_id);
    }
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
        return Err(accounts_disabled());
    };
    let min_len = state.config().accounts.min_password_len;

    validate_username(&payload.username)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    validate_password(&payload.username, &payload.password, min_len)
        .map_err(|error| ApiError::BadRequest(error.to_string()))?;
    let status = payload.status.unwrap_or(UserStatus::Active);

    match users.get(&payload.username).await {
        Ok(Some(_)) => {
            tracing::warn!(
                actor = %actor.username,
                target = %payload.username,
                reason = "duplicate_username",
                "管理员创建账户被拒：用户名已存在"
            );
            return Err(username_taken());
        },
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
            tracing::warn!(
                actor = %actor.username,
                target = %payload.username,
                reason = "duplicate_username",
                "管理员创建账户被拒：用户名已存在（并发插入）"
            );
            return Err(username_taken());
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
/// 判定顺序见模块文档；「最后一个管理员」由账户库在事务内判定
/// （`update_profile_guarded`），抛出 [`AccountError::LastAdmin`] 时映射成 409；
/// 账户库故障（查不到管理员数量）按 503 上报，不把它当成「不是最后一个」放行。
async fn patch_account(
    state: &AppState,
    request_id: &RequestId,
    actor: &AuthUser,
    name: &str,
    changes: PatchPayload,
) -> Result<User, ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_disabled());
    };
    if changes.role.is_none() && changes.status.is_none() {
        return Err(ApiError::BadRequest("至少要提供 role 或 status 之一".to_owned()));
    }
    let target = load_user(state, name).await?;
    // 改自己：不允许（自助改口令/注销有专门端点，那里会校验旧口令）。
    if target.username.eq_ignore_ascii_case(&actor.username) {
        return Err(ApiError::Conflict("不能修改自己的角色或状态：请由其他管理员操作".to_owned()));
    }
    let new_role = changes.role.unwrap_or(target.role);
    let new_status = changes.status.unwrap_or(target.status);
    // 无变化的 PATCH 不写库、不打审计：`updated_at` 是「资料变更时间」，不该被空操作刷新。
    if new_role == target.role && new_status == target.status {
        return Ok(target);
    }

    // 判定与写入在账户库的同一个事务里完成：拆成 count + update 两步会让两个管理员
    // 并发互降同时通过「还有 2 个管理员」的检查，事后一个管理员都不剩。
    let config_admins = config_admin_fallback(state.config(), &target.username);
    let updated = match users
        .update_profile_guarded(&target.username, Some(new_role), Some(new_status), config_admins)
        .await
    {
        Ok(updated) => updated,
        Err(AccountError::LastAdmin { .. }) => {
            tracing::warn!(
                actor = %actor.username,
                target = %target.username,
                "拒绝降级或禁用最后一个管理员"
            );
            return Err(ApiError::Conflict(
                "不能降级或禁用最后一个 active 管理员：请先指定另一个管理员".to_owned(),
            ));
        },
        Err(AccountError::NotFound { .. }) => {
            return Err(ApiError::NotFound(missing_user_message(state, &target.username)));
        },
        Err(error) => {
            tracing::error!(target = %target.username, error = %error, "修改账户失败");
            return Err(accounts_unavailable());
        },
    };
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
    // 角色变了、或状态不再是 active（禁用、退回待审批），手里的会话都不能再代表这个人。
    // 认证中间件每次请求也会复核库里的角色与状态，这里只是让失效**立即**发生并顺手
    // 释放内存；漏掉 pending 的话，被退回待审批的会话能靠不断请求续到绝对过期。
    if updated.role != target.role || updated.status != UserStatus::Active {
        state.sessions().revoke_user(&updated.username);
    }
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
        return Err(accounts_disabled());
    };
    let target = load_user(state, name).await?;

    if target.username.eq_ignore_ascii_case(&actor.username) {
        return Err(ApiError::Conflict(
            "不能删除自己的账户：如需注销请用 DELETE /account 自助完成".to_owned(),
        ));
    }
    // 删掉库里的行之后，`[auth.users]` 里的同名条目会让那份旧 sha256 口令重新生效。
    // 这不是「可能重名」而是「同一个人换个入口原地复活」，必须硬拒。
    if let Some(config_name) = config_username(state.config(), &target.username) {
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

    // 「最后一个管理员」由账户库在同一个事务里判定并删除，避免并发删掉最后两个管理员。
    let config_admins = config_admin_fallback(state.config(), &target.username);
    match users.delete_guarded(&target.username, config_admins).await {
        Ok(()) => {},
        Err(AccountError::LastAdmin { .. }) => {
            tracing::warn!(
                actor = %actor.username,
                target = %target.username,
                "拒绝删除最后一个管理员"
            );
            return Err(ApiError::Conflict(
                "不能删除最后一个 active 管理员：请先指定另一个管理员".to_owned(),
            ));
        },
        Err(AccountError::NotFound { .. }) => {
            return Err(ApiError::NotFound(missing_user_message(state, &target.username)));
        },
        Err(error) => {
            tracing::error!(target = %target.username, error = %error, "删除账户失败");
            return Err(accounts_unavailable());
        },
    }
    tracing::info!(
        actor = %actor.username,
        action = "user.delete",
        target = %target.username,
        role = %target.role,
        status = target.status.as_str(),
        request_id = %request_id,
        "管理员删除账户（LFS 对象不随账户删除）"
    );
    // 账户没了，它的会话也必须立刻消失。
    state.sessions().revoke_user(&target.username);
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
        return Err(accounts_disabled());
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
        accounts_unavailable()
    })?;
    // 审计只记「谁给谁重置了」，不记口令本身。
    tracing::info!(
        actor = %actor.username,
        action = "user.reset_password",
        target = %target.username,
        request_id = %request_id,
        "管理员重置账户口令"
    );
    // 口令是凭据：换掉之后旧会话不能再代表这个人（管理员重置自己也一样）。
    state.sessions().revoke_user(&target.username);
    Ok(())
}

/// 按用户名取账户；不存在（含只存在于 `[auth.users]`、或用户名不符合库规则）报 404。
async fn load_user(state: &AppState, name: &str) -> Result<User, ApiError> {
    let Some(users) = state.accounts() else {
        return Err(accounts_disabled());
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
    match config_username(state.config(), name) {
        Some(config_name) => format!(
            "账户库里没有 {config_name}：它只存在于 [auth.users]，首次登录升级为账户库账户后才可由管理端点管理"
        ),
        None => format!("用户 {name} 不存在"),
    }
}

/// 解析 JSON 请求体；失败统一 400。
fn read_json<T: DeserializeOwned>(body: &[u8]) -> Result<T, ApiError> {
    if body.len() > MAX_BODY_BYTES {
        return Err(ApiError::BadRequest(format!("请求体超过 {MAX_BODY_BYTES} 字节")));
    }
    serde_json::from_slice(body)
        .map_err(|error| ApiError::BadRequest(format!("请求体不是合法 JSON：{error}")))
}

/// 管理页的位置：状态过滤 + 偏移，链接与表单隐藏字段共用同一份。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
struct PageQuery {
    /// 生效的状态过滤；`None` 表示显示全部。
    status: Option<UserStatus>,
    /// 跳过的行数；管理页按 `MAX_LIMIT` 分页。
    offset: u32,
}

/// 管理页的解析结果：合法的状态与偏移，外加（若有）无法识别的原始输入。
#[derive(Debug, Default)]
struct Filter {
    /// 生效的位置。
    page: PageQuery,
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
        return accounts_disabled_page();
    };
    let filter = match parse_filter(query.0.as_deref()) {
        Ok(filter) => filter,
        Err(error) => return error_page(&error, &request_id),
    };
    let (list, total) = match users.list(filter.page.status, MAX_LIMIT, filter.page.offset).await {
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
fn accounts_disabled_page() -> Response {
    accounts_problem_page(ACCOUNTS_NOT_CONFIGURED_MESSAGE)
}

/// 账户库暂时不可用时的管理页。
fn accounts_unavailable_page() -> Response {
    accounts_problem_page(ACCOUNTS_UNAVAILABLE_MESSAGE)
}

/// 503 页的公共外壳：原因文本必须转义后进页面。
fn accounts_problem_page(message: &str) -> Response {
    let body = format!(r#"<h1>管理页不可用</h1><p class="error">{}</p>"#, escape_html(message));
    html_response(StatusCode::SERVICE_UNAVAILABLE, page_shell("管理页不可用", &body))
}

/// 解析管理页的 `?status=` 与 `?offset=`。
///
/// 未知的状态值不算错误（页面提示「已忽略」并显示全部），非法的 offset 则 400：
/// 后者是翻页链接自己生成的，出现非法值说明请求被手工改过。
fn parse_filter(raw: Option<&str>) -> Result<Filter, ApiError> {
    let Some(raw) = raw else {
        return Ok(Filter::default());
    };
    let fields = parse_form(raw)?;
    let (status, unknown) =
        match fields.get("status").map(String::as_str).filter(|value| !value.is_empty()) {
            None => (None, None),
            Some(value) => match UserStatus::parse(value) {
                Some(status) => (Some(status), None),
                None => (None, Some(value.to_owned())),
            },
        };
    let offset = match fields.get("offset").map(String::as_str) {
        None | Some("") => 0,
        Some(value) => value
            .parse::<u32>()
            .map_err(|_| ApiError::BadRequest(format!("offset 必须是非负整数，实际为 {value}")))?,
    };
    Ok(Filter { page: PageQuery { status, offset }, unknown })
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
    let rows =
        list.iter().map(|user| render_row(user, filter.page, min_password_len)).collect::<Vec<_>>();
    body.push_str(&table(&["用户名", "角色", "状态", "创建时间", "最后登录", "操作"], &rows));
    body.push_str(&render_pager(filter, total));
    body.push_str(
        r#"<p class="hint">账户来自账户库；<code>[auth.users]</code> 里的配置用户在首次登录后才会出现在这里。</p>"#,
    );
    body
}

/// 构造 `/admin` 的地址：只带非默认参数，链接可读、测试也好断言。
fn page_location(page: PageQuery) -> String {
    let mut params = Vec::new();
    if let Some(status) = page.status {
        params.push(format!("status={}", status.as_str()));
    }
    if page.offset > 0 {
        params.push(format!("offset={}", page.offset));
    }
    if params.is_empty() { "/admin".to_owned() } else { format!("/admin?{}", params.join("&")) }
}

/// 翻页导航：按 `MAX_LIMIT` 与总数算上一页/下一页，并保留状态过滤。
fn render_pager(filter: &Filter, total: u64) -> String {
    let page_size = u64::from(MAX_LIMIT);
    let offset = u64::from(filter.page.offset);
    let mut links = String::new();
    if offset > 0 {
        let prev = offset.saturating_sub(page_size);
        let prev = u32::try_from(prev).unwrap_or(0);
        links.push_str(&format!(
            r#"<a href="{}">← 上一页</a>"#,
            page_location(PageQuery { offset: prev, ..filter.page })
        ));
    }
    if offset.saturating_add(page_size) < total {
        let next = u32::try_from(offset.saturating_add(page_size)).unwrap_or(u32::MAX);
        links.push_str(&format!(
            r#"<a href="{}">下一页 →</a>"#,
            page_location(PageQuery { offset: next, ..filter.page })
        ));
    }
    if links.is_empty() {
        return String::new();
    }
    format!(r#"<nav class="pager">{links}</nav>"#)
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
        let href = page_location(PageQuery { status, offset: 0 });
        let current = if filter.page.status == status { " <strong>(当前)</strong>" } else { "" };
        html.push_str(&format!(r#"<a href="{href}">{label}{current}</a>"#));
    }
    html.push_str("</nav>");
    html
}

/// 一行表格：纯文本单元格全部转义，最后一格是操作表单。
fn render_row(user: &User, page: PageQuery, min_password_len: usize) -> Vec<String> {
    vec![
        escape_html(&user.username),
        format!(r#"<span title="{}">{}</span>"#, user.role.as_str(), role_label(user.role)),
        format!(r#"<span title="{}">{}</span>"#, user.status.as_str(), status_label(user.status)),
        format_unix_seconds(user.created_at),
        match user.last_login_at {
            Some(seconds) => format_unix_seconds(seconds),
            None => "从未登录".to_owned(),
        },
        render_actions(user, page, min_password_len),
    ]
}

/// 操作格：按状态给「批准 / 禁用 / 启用」，外加角色切换、重置口令与删除。
///
/// 每个按钮各自一个 `<form>`（HTML 不允许嵌套表单）；当前过滤条件与页码作为隐藏
/// 字段随表单提交，操作完再跳回同一页。
fn render_actions(user: &User, page: PageQuery, min_password_len: usize) -> String {
    // 用户名虽然按规则只允许 ASCII 字母数字与 `.` `_` `-`，这里仍然转义：页面渲染要对
    // 「有人手工改库、或将来放宽用户名规则」保持安全，属性值也不例外。
    let name = escape_html(&user.username);
    let hidden = hidden_page_fields(page);

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

/// 表单里回传的页面位置：过滤条件与偏移，保证操作完回到同一页。
fn hidden_page_fields(page: PageQuery) -> String {
    let mut hidden = String::new();
    if let Some(status) = page.status {
        hidden.push_str(&format!(
            r#"<input type="hidden" name="status" value="{}">"#,
            status.as_str()
        ));
    }
    if page.offset > 0 {
        hidden.push_str(&format!(r#"<input type="hidden" name="offset" value="{}">"#, page.offset));
    }
    hidden
}

/// 角色在页面上的中文标签。
pub(crate) fn role_label(role: Role) -> &'static str {
    match role {
        Role::Readonly => "只读",
        Role::Readwrite => "读写",
        Role::Admin => "管理员",
    }
}

/// 状态在页面上的中文标签。
pub(crate) fn status_label(status: UserStatus) -> &'static str {
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
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_form(&headers) {
        return error_page(&error, &request_id);
    }
    set_status(state, auth, request_id, name, body, UserStatus::Active).await
}

/// `POST /admin/users/{name}/disable`：正常 → 已禁用（303）。
pub(crate) async fn disable(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_form(&headers) {
        return error_page(&error, &request_id);
    }
    set_status(state, auth, request_id, name, body, UserStatus::Disabled).await
}

/// `POST /admin/users/{name}/enable`：已禁用 → 正常（303）。
pub(crate) async fn enable(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_form(&headers) {
        return error_page(&error, &request_id);
    }
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
    let page = page_query_from_fields(&fields);
    let changes = PatchPayload { role: None, status: Some(status) };
    match patch_account(&state, &request_id, &auth, &name, changes).await {
        Ok(_) => redirect_to_admin(page),
        Err(error) => error_page(&error, &request_id),
    }
}

/// `POST /admin/users/{name}/role`：切换角色（303）。
pub(crate) async fn role_form(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_form(&headers) {
        return error_page(&error, &request_id);
    }
    let fields = match form_fields(&body) {
        Ok(fields) => fields,
        Err(error) => return error_page(&error, &request_id),
    };
    let page = page_query_from_fields(&fields);
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
        Ok(_) => redirect_to_admin(page),
        Err(error) => error_page(&error, &request_id),
    }
}

/// `POST /admin/users/{name}/password-form`：管理页的重置口令表单（303）。
pub(crate) async fn password_form(
    State(state): State<AppState>,
    Extension(auth): Extension<AuthUser>,
    Extension(request_id): Extension<RequestId>,
    Path(name): Path<String>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_form(&headers) {
        return error_page(&error, &request_id);
    }
    let fields = match form_fields(&body) {
        Ok(fields) => fields,
        Err(error) => return error_page(&error, &request_id),
    };
    let page = page_query_from_fields(&fields);
    let Some(password) = fields.get("password").filter(|value| !value.is_empty()).cloned() else {
        let error = ApiError::BadRequest("缺少表单字段 password".to_owned());
        return error_page(&error, &request_id);
    };
    match reset_password_for(&state, &request_id, &auth, &name, password).await {
        Ok(()) => redirect_to_admin(page),
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
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if let Err(error) = require_form(&headers) {
        return error_page(&error, &request_id);
    }
    let fields = match form_fields(&body) {
        Ok(fields) => fields,
        Err(error) => return error_page(&error, &request_id),
    };
    let page = page_query_from_fields(&fields);
    if !fields.get("confirm").is_some_and(|value| !value.is_empty()) {
        let error = ApiError::BadRequest("删除需要先勾选确认框".to_owned());
        return error_page(&error, &request_id);
    }
    match delete_account(&state, &request_id, &auth, &name).await {
        Ok(()) => redirect_to_admin(page),
        Err(error) => error_page(&error, &request_id),
    }
}

/// 解析表单请求体（`application/x-www-form-urlencoded`）。
fn form_fields(body: &[u8]) -> Result<HashMap<String, String>, ApiError> {
    let text = std::str::from_utf8(body)
        .map_err(|_| ApiError::BadRequest("表单不是合法的 UTF-8".to_owned()))?;
    parse_form(text)
}

/// 从表单隐藏字段里取页面位置（过滤 + 偏移）；缺省或非法值按第一页处理。
fn page_query_from_fields(fields: &HashMap<String, String>) -> PageQuery {
    PageQuery {
        status: fields.get("status").and_then(|value| UserStatus::parse(value)),
        offset: fields.get("offset").and_then(|value| value.parse::<u32>().ok()).unwrap_or(0),
    }
}

/// 表单操作成功后的回跳地址：保留当前过滤与页码，避免操作完丢掉上下文。
fn redirect_to_admin(page: PageQuery) -> Response {
    let location = page_location(page);
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
        Filter, MAX_LIMIT, PageQuery, parse_filter, parse_list_query, render_actions, role_label,
        status_label,
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

        let html = render_actions(&user, PageQuery::default(), 12);

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
        assert_eq!(parse_filter(None).expect("缺省").page.status, None);
        assert_eq!(
            parse_filter(Some("status=active")).expect("合法").page.status,
            Some(UserStatus::Active)
        );

        let unknown: Filter = parse_filter(Some("status=bogus")).expect("未知值不报错");
        assert_eq!(unknown.page.status, None);
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

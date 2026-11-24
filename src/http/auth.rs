//! 认证与角色提取：HTTP Basic 与会话 Cookie 双通道。
//!
//! **优先级**：请求带 `Authorization` 头时只认 Basic，失败即 401，不回退 Cookie；
//! 否则才看会话 Cookie。git 客户端只会用 Basic，浏览器登录后用 Cookie。
//!
//! **会话通道**每次都重新确认账户：账户库优先（角色也以库为准，改角色/禁用/删除
//! 立即生效），未接入账户库时回落 `[auth.users]`；确认不过就撤销该会话。
//!
//! Basic 的安全约定见 `specs/api.md`「公共约定」：
//!
//! - 未带认证头、格式错、用户名不存在、口令不符**一律 401**，响应体完全相同，
//!   不泄漏「用户名是否存在」；
//! - 账户库接入后**DB 优先**：库里有该用户就只用库里的 Argon2id 哈希校验，
//!   `[auth.users]` 的同名条目完全不再参与（改过口令后旧 config 口令不能复活）；
//! - 库里没有该用户（或用户名不符合账户库规则，例如 2 个字符的旧 config 用户名）
//!   时回落到 config 的 sha256 校验，成功即**懒升级**：把明文口令换成 Argon2id
//!   写进账户库，下次登录就走 DB 路径；
//! - `Pending` / `Disabled` 账户即使口令正确也 401，具体状态只进日志；
//! - 认证在 handler 之前完成，通过后把 [`Role`] 与 [`AuthUser`] 写进请求扩展，
//!   由 batch/transfer 按 operation 决定是否拒绝，`/account/*` 用用户名定位自己。
//!
//! 认证失败的具体原因只进日志（`reason` 字段），不进响应体。登录失败按小写用户名
//! 在 5 分钟窗口内计数，超过 `[accounts] login_failures_per_5min` 后一律 429——
//! 这条限制对「口令正确」的请求同样生效，否则限速对爆破毫无意义。
//!
//! **凭据判定只有一份**：[`verify_credentials`] 把「限速 → DB 优先（active/角色）→
//! config 回落（sha256）→ 懒升级」连同「成功清零失败计数」收成一个函数，Basic 中间件
//! 与表单登录（`login`）都调它。两边各写一份的话，最先坏掉的会是「config-only 用户
//! 登录成功、下一个请求 401」——判定口径一旦分叉，登录端点多放行的身份认证端点就会
//! 拒掉。
//!
use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::{AUTHORIZATION, SET_COOKIE};
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::error::{self, ApiError};
use super::passwords;
use super::session::{self, SessionCookieState, SessionId};
use super::{ACCOUNTS_UNAVAILABLE_MESSAGE, AppState, RequestId};
use crate::accounts::{AccountError, UserStatus, UserStore};
use crate::config::{Config, Role, UserConfig};

/// 所有 401 共用的文案：不区分「没带凭据」「用户不存在」「口令错误」。
const AUTH_FAILURE_MESSAGE: &str = "需要 HTTP Basic 认证";

/// 通过认证的身份：用户名（账户库里的规范大小写）与角色。
///
/// 单独放进请求扩展，是因为 `/account/*` 需要知道「我是谁」，而 [`Role`] 只够
/// 做权限判定。两个都插入，既有 handler 继续用 `Extension<Role>`。
#[derive(Debug, Clone)]
pub(crate) struct AuthUser {
    /// 用户名；DB 用户取库里的写法，config 用户取请求里的写法。
    pub(crate) username: String,
    /// 权限档位。
    pub(crate) role: Role,
}

/// `Authorization` 头解析失败的原因；只写日志，不写响应。
///
/// 只管「头本身读不出用户名与口令」，与「凭据对不对」分开：这类失败一律 401，
/// 且和凭据错误共用同一条文案（不泄漏「头格式错」还是「口令错」）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum AuthFailure {
    /// 没有 `Authorization` 头。
    MissingHeader,
    /// 不是 `Basic <payload>` 形式（含 scheme 不是 Basic）。
    MalformedHeader,
    /// payload 不是合法 base64。
    InvalidBase64,
    /// 解出的明文里没有 `:` 分隔用户名与口令。
    MissingSeparator,
    /// 用户名不是合法 UTF-8。
    NonUtf8Username,
}

impl AuthFailure {
    /// 日志字段值；固定小写英文，避免把用户输入带进日志。
    fn as_str(self) -> &'static str {
        match self {
            Self::MissingHeader => "missing_header",
            Self::MalformedHeader => "malformed_header",
            Self::InvalidBase64 => "invalid_base64",
            Self::MissingSeparator => "missing_separator",
            Self::NonUtf8Username => "non_utf8_username",
        }
    }
}

/// 凭据判定的失败分类：Basic 中间件与表单登录共用同一套结论。
///
/// 对外只有三种响应形态（401 / 429 / 503），具体原因只进日志。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum LoginFailure {
    /// 用户名不存在或口令不符。
    ///
    /// `reason` 只进日志，用来区分「没这个人」与「口令错」——两者对外必须是同一条
    /// 文案，否则一次登录就能把用户名枚举出来（CWE-204）。
    BadCredentials {
        /// 精确原因（`unknown_user` / `wrong_password`），只进日志。
        reason: &'static str,
    },
    /// 账户存在且口令正确，但状态不是 `active`（待审批 / 已禁用）。
    Inactive,
    /// 登录失败次数超过窗口上限。
    RateLimited {
        /// 建议的重试间隔。
        retry_after: Duration,
    },
    /// 账户库故障：无法判定凭据，按 503 让客户端稍后重试。
    Unavailable,
}

impl LoginFailure {
    /// 日志字段值；固定小写英文，避免把用户输入带进日志。
    pub(crate) fn reason(self) -> &'static str {
        match self {
            Self::BadCredentials { reason } => reason,
            Self::Inactive => "inactive_account",
            Self::RateLimited { .. } => "too_many_requests",
            Self::Unavailable => "accounts_unavailable",
        }
    }

    /// 是否计入登录失败次数。
    ///
    /// 429 是限速本身的结论，503 是基础设施故障——两者都不该继续延长封锁窗口，
    /// 否则攻击者只要持续打就能把真实用户永久锁在外面。
    fn counts_as_login_failure(self) -> bool {
        !matches!(self, Self::RateLimited { .. } | Self::Unavailable)
    }
}

/// Basic 通道的失败：头解析失败与凭据判定失败对外都是 401，但日志原因不同。
#[derive(Debug, Clone, Copy)]
enum BasicFailure {
    /// `Authorization` 头本身读不出来。
    Malformed(AuthFailure),
    /// 头合法，但凭据不通过。
    Credentials(LoginFailure),
}

impl BasicFailure {
    /// 日志字段值。
    fn reason(&self) -> &'static str {
        match self {
            Self::Malformed(failure) => failure.as_str(),
            Self::Credentials(failure) => failure.reason(),
        }
    }
}

/// 认证中间件：校验通过后把 [`Role`] 与 [`AuthUser`] 写进请求扩展，再交给下游 handler。
///
/// 双通道：
///
/// 1. 请求带 `Authorization` 头 → 走 Basic（git 客户端与脚本的既有路径），失败就
///    401，**不**回退到 Cookie——两套凭据同时出现时以 Basic 为准，避免「Basic 写错
///    却被 Cookie 放行」这种身份混淆；
/// 2. 否则看会话 Cookie：有效则以**账户库当前的角色**认人（管理员改角色立即生效），
///    失效/被撤销/账户不可用时删会话、401 并让浏览器清掉那条 Cookie。
///
/// 返回 `Response` 而不是 `Result`，是因为失败时要复用本次请求的 request id
/// 构造错误体——`ApiError` 的 `IntoResponse` 拿不到请求，只能另外生成一个，
/// 那样响应体与响应头的 id 会对不上。
pub(crate) async fn require(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // 先取出认证相关的头再进入异步：`Request<Body>` 不是 `Sync`，把 `&request`
    // 带过 `.await` 会让整个中间件 future 不是 `Send`（axum 的 `FromFn` 要求它）。
    let authorization = request.headers().get(AUTHORIZATION).cloned();
    let cookie = session::parse_session_cookie(request.headers());
    // 清 Cookie 时要与服务端签发时同样带不带 Secure，否则 HTTPS 站点上清不掉。
    let secure = session::request_is_https(request.headers(), state.config());

    let outcome = match authorization {
        Some(header) => authenticate(&state, Some(header)).await.map_err(Rejection::Basic),
        None => authenticate_session(&state, &cookie).await.map_err(Rejection::Session),
    };

    match outcome {
        Ok(user) => {
            request.extensions_mut().insert(user.role);
            request.extensions_mut().insert(user);
            next.run(request).await
        },
        Err(rejection) => {
            let request_id = request
                .extensions()
                .get::<RequestId>()
                .cloned()
                .unwrap_or_else(RequestId::generate);
            tracing::warn!(
                request_id = %request_id,
                channel = rejection.channel(),
                reason = rejection.reason(),
                "认证失败"
            );
            rejection.into_response(&request_id, secure)
        },
    }
}

/// 认证失败的通道归属：两条通道的失败语义不同（Basic 有 429、Cookie 要清 Cookie）。
enum Rejection {
    /// Basic 通道失败。
    Basic(BasicFailure),
    /// 会话 Cookie 通道失败。
    Session(SessionFailure),
}

impl Rejection {
    /// 日志字段值：哪条通道失败（`accounts_unavailable` 这类原因两条通道都会出现，
    /// 只靠 reason 分不清该去查账户库还是查会话）。
    fn channel(&self) -> &'static str {
        match self {
            Self::Basic(_) => "basic",
            Self::Session(_) => "session",
        }
    }

    /// 日志字段值：为什么失败（Basic 与 Session 的取值集合不同）。
    fn reason(&self) -> &'static str {
        match self {
            Self::Basic(failure) => failure.reason(),
            Self::Session(failure) => failure.as_str(),
        }
    }

    /// 映射成响应；`secure` 决定清除 Cookie 时是否带 `Secure`。
    fn into_response(self, request_id: &RequestId, secure: bool) -> Response {
        match self {
            Self::Basic(failure) => basic_failure_response(failure, request_id),
            Self::Session(failure) => session_failure_response(failure, request_id, secure),
        }
    }
}

/// 会话认证失败的原因；只写日志，不写响应。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum SessionFailure {
    /// 既没有 `Authorization` 头也没有会话 Cookie。
    Missing,
    /// 带了会话 Cookie，但值不是合法的会话 id：清掉它，别让浏览器无限重发。
    Malformed,
    /// Cookie 里的会话 id 不在表里（伪造、空闲/绝对过期或已被撤销）。
    Expired,
    /// 会话对应的账户已不可用：被删除、待审批或已禁用。
    Revoked,
    /// 账户库故障：无法确认账户状态，按 503 让客户端稍后重试。
    AccountsUnavailable,
}

impl SessionFailure {
    /// 日志字段值；固定小写英文，避免把用户输入带进日志。
    fn as_str(self) -> &'static str {
        match self {
            Self::Missing => "missing_session",
            Self::Malformed => "malformed_session",
            Self::Expired => "session_expired",
            Self::Revoked => "session_revoked",
            Self::AccountsUnavailable => "accounts_unavailable",
        }
    }

    /// 是否该顺手清掉浏览器里那条 Cookie。
    ///
    /// 畸形、失效、被撤销三种情况都要清：浏览器会一直重发同一个值，不清就永远没有
    /// 出口。「没带 Cookie」本来没有可清的，「账户库故障」则要保留它等恢复。
    pub(crate) fn clears_cookie(self) -> bool {
        matches!(self, Self::Malformed | Self::Expired | Self::Revoked)
    }
}

/// 会话通道的失败响应：401 统一文案、503 带认证挑战头；失效/被撤销时清除 Cookie。
fn session_failure_response(
    failure: SessionFailure,
    request_id: &RequestId,
    secure: bool,
) -> Response {
    let unauthorized =
        || ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.to_owned()).into_response_with(request_id);
    match failure {
        SessionFailure::AccountsUnavailable => error::with_auth_challenge(
            ApiError::Unavailable(ACCOUNTS_UNAVAILABLE_MESSAGE.to_owned())
                .into_response_with(request_id),
        ),
        // 没带 Cookie：本来就没有可清的东西，别凭空塞一条 Set-Cookie。
        SessionFailure::Missing => unauthorized(),
        // 畸形、失效或被撤销：让浏览器把那条 Cookie 扔掉，否则每个请求都会带着它回来，
        // 永远 401 且没有出口。
        SessionFailure::Malformed | SessionFailure::Expired | SessionFailure::Revoked => {
            with_clear_cookie(unauthorized(), secure)
        },
    }
}

/// 给响应附加一条清除会话 Cookie 的 `Set-Cookie`。
///
/// `pub(crate)`：登录页（畸形/失效 Cookie）与退出端点都要用，`secure` 的取值口径
/// 必须与签发时一致，否则 HTTPS 站点上清不掉。
pub(crate) fn with_clear_cookie(mut response: Response, secure: bool) -> Response {
    if let Ok(value) = HeaderValue::from_str(&session::secure_clear_cookie(secure)) {
        response.headers_mut().append(SET_COOKIE, value);
    }
    response
}

/// 按会话 Cookie 确认当前身份（账户库优先、config 回落）。
///
/// 与 [`require`] 的会话通道是同一个函数：登录页判断「你已经登录了」、退出端点判断
/// 「这条会话还属于谁」时不能另写一份判定，否则会出现「登录页认为已登录、下一个
/// 请求 401」。失败语义见 [`SessionFailure::clears_cookie`]。
pub(crate) async fn session_identity(
    state: &AppState,
    cookie: &SessionCookieState,
) -> Result<AuthUser, SessionFailure> {
    authenticate_session(state, cookie).await
}

/// 会话 Cookie 通道：查会话、再按「账户库优先、config 回落」确认账户仍可用。
///
/// 两件事必须每次都做，不能只信任登录时的快照：
///
/// - 账户状态：被删除/禁用/待审批的账户，其已有会话立即失效；
/// - 角色：以账户库里的**当前**角色为准，管理员降级某个账号后，那个账号手里的会话
///   不能还按旧角色操作。
async fn authenticate_session(
    state: &AppState,
    cookie: &SessionCookieState,
) -> Result<AuthUser, SessionFailure> {
    let id = match cookie {
        SessionCookieState::Missing => return Err(SessionFailure::Missing),
        // 值本身不合法：连查表都不用查，直接让浏览器清掉。
        SessionCookieState::Malformed => return Err(SessionFailure::Malformed),
        SessionCookieState::Present(id) => id,
    };
    // `get` 顺带滑动空闲计时：浏览器每访问一次，12 小时的空闲窗口就重新开始。
    let Some(session) = state.sessions().get(id) else {
        return Err(SessionFailure::Expired);
    };

    match state.accounts() {
        Some(users) => match users.get(&session.username).await {
            Ok(Some(user)) if user.status == UserStatus::Active => {
                Ok(AuthUser { username: user.username, role: user.role })
            },
            Ok(Some(user)) => {
                tracing::warn!(
                    username = %user.username,
                    status = user.status.as_str(),
                    "会话对应的账户已不可用，撤销会话"
                );
                state.sessions().revoke(id);
                Err(SessionFailure::Revoked)
            },
            // 库里没有这个账户：与 Basic 通道一致回落 `[auth.users]`。config-only 用户
            // （还没懒升级、或升级时写库失败）本来就是合法存在的身份。
            //
            // 被管理员删除的账户不会因此复活：管理端删除会先 revoke_user，而且删除时
            // `[auth.users]` 里有同名条目会直接 409，所以「库里没有 + config 也没有」
            // 就是这条会话的终点。用户名不合法（例如 2 个字符的旧 config 用户名）同理。
            Ok(None) | Err(AccountError::InvalidUsername { .. }) => {
                session_config_user(state, id, &session.username)
            },
            Err(error) => {
                tracing::error!(
                    username = %session.username,
                    error = %error,
                    "确认会话账户状态失败"
                );
                Err(SessionFailure::AccountsUnavailable)
            },
        },
        None => session_config_user(state, id, &session.username),
    }
}

/// 账户只能来自 `[auth.users]` 时（未接入账户库，或库里查不到这一行）用配置判角色。
///
/// 库里查不到这一行**不等于**账户没了：config-only 用户、懒升级写库失败的用户都还
/// 属于这里。配置里也找不到这个用户名时才是真的没了——会话不能凭空延续，这里不做
/// 「建立时有效就一直有效」的豁免，撤销后 401。
fn session_config_user(
    state: &AppState,
    id: &SessionId,
    username: &str,
) -> Result<AuthUser, SessionFailure> {
    match state.config().auth.users.get(username) {
        Some(user) => Ok(AuthUser { username: username.to_owned(), role: user.role }),
        None => {
            tracing::warn!(
                username = %username,
                "会话对应的用户不在 [auth.users] 里，撤销会话"
            );
            state.sessions().revoke(id);
            Err(SessionFailure::Revoked)
        },
    }
}

/// Basic 通道的失败响应：头解析失败只可能是 401；凭据判定按 [`LoginFailure`] 分流。
fn basic_failure_response(failure: BasicFailure, request_id: &RequestId) -> Response {
    match failure {
        BasicFailure::Malformed(_) => {
            ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.to_owned()).into_response_with(request_id)
        },
        BasicFailure::Credentials(failure) => login_failure_response(failure, request_id),
    }
}

/// 把凭据判定的失败映射成响应：401 统一文案、429 带 `Retry-After`、503 带认证挑战头。
fn login_failure_response(failure: LoginFailure, request_id: &RequestId) -> Response {
    match failure {
        LoginFailure::RateLimited { retry_after } => ApiError::TooManyRequests {
            message: format!("登录失败次数过多，请 {} 秒后重试", retry_after.as_secs().max(1)),
            retry_after_secs: retry_after.as_secs().max(1),
        }
        .into_response_with(request_id),
        LoginFailure::Unavailable => error::with_auth_challenge(
            ApiError::Unavailable(ACCOUNTS_UNAVAILABLE_MESSAGE.to_owned())
                .into_response_with(request_id),
        ),
        // 凭据不对与「账户未激活」必须是同一条文案、同一个状态码：区分两者等于把
        // 「这个用户名存在且待审批」告诉任何人。
        LoginFailure::BadCredentials { .. } | LoginFailure::Inactive => {
            ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.to_owned()).into_response_with(request_id)
        },
    }
}

/// Basic 通道：解析 `Authorization` 头，再交给 [`verify_credentials`] 判定凭据。
async fn authenticate(
    state: &AppState,
    authorization: Option<HeaderValue>,
) -> Result<AuthUser, BasicFailure> {
    let (username, password) =
        parse_basic(authorization.as_ref()).map_err(BasicFailure::Malformed)?;
    verify_credentials(state, &username, &password).await.map_err(BasicFailure::Credentials)
}

/// 校验用户名与口令：限速 → DB 优先（active/角色）→ config 回落（sha256）→ 懒升级。
///
/// Basic 中间件与 `POST /login` 共用这一个入口，因此两边对「谁能登录」的判断不可能
/// 分叉：config-only 用户、被禁用账户、限速、账户库故障的表现完全一致。
///
/// 口令按**字节**接收而不是 `&str`：`Authorization` 头允许非 UTF-8 口令字节，而
/// config 回落的 sha256 是按字节算的——收窄成 `&str` 会让这类历史口令登不上，属于
/// 行为变更。表单口令本来就是 UTF-8，调用方传 `as_bytes()` 即可。
///
/// 成功时照旧做三件事：清零该用户名的失败计数、更新/懒升级库记录、`touch_last_login`。
pub(crate) async fn verify_credentials(
    state: &AppState,
    username: &str,
    password: &[u8],
) -> Result<AuthUser, LoginFailure> {
    // 用户名大小写不敏感：库里的 UNIQUE COLLATE NOCASE 与 config 的键名都按字面量，
    // 但限速必须把 Alice/alice 算成同一个人，否则改个大小写就能绕开限速。
    let throttle_key = username.to_ascii_lowercase();
    let limit = state.config().accounts.login_failures_per_5min;
    if let Some(retry_after) = state.login_limits().blocked_for(&throttle_key, limit) {
        return Err(LoginFailure::RateLimited { retry_after });
    }

    let outcome = match state.accounts() {
        Some(users) => authenticate_with_store(state.config(), users, username, password).await,
        None => authenticate_config(state.config(), username, password),
    };
    match outcome {
        Ok(user) => {
            // 成功登录清零该用户名的失败计数：上一次失败不应影响后续正常登录。
            state.login_limits().reset(&throttle_key);
            tracing::debug!(username = %user.username, role = %user.role, "认证通过");
            Ok(user)
        },
        Err(failure) => {
            if failure.counts_as_login_failure() {
                state.login_limits().record(&throttle_key);
            }
            // 精确原因（unknown_user / wrong_password）只在日志里出现，响应体里两者
            // 完全一致；这里统一打一条，Basic 与表单登录都不会漏掉。
            tracing::debug!(reason = failure.reason(), "凭据判定失败");
            Err(failure)
        },
    }
}

/// 纯 config 认证（未接入账户库时的旧行为）。
fn authenticate_config(
    config: &Config,
    username: &str,
    password: &[u8],
) -> Result<AuthUser, LoginFailure> {
    let user = config.auth.users.get(username);
    // 未知用户名也付一次摘要+比较的开销，避免计时差泄漏用户名是否存在。
    let expected = user.map_or(DUMMY_DIGEST, |user| user.password_sha256.as_str());
    let matched = password_matches(password, expected);
    match user {
        Some(user) if matched => Ok(AuthUser { username: username.to_owned(), role: user.role }),
        Some(_) => Err(LoginFailure::BadCredentials { reason: "wrong_password" }),
        None => Err(LoginFailure::BadCredentials { reason: "unknown_user" }),
    }
}

/// 接入账户库后的认证：DB 优先，查不到再回落 config 并懒升级。
async fn authenticate_with_store(
    config: &Config,
    users: &UserStore,
    username: &str,
    password: &[u8],
) -> Result<AuthUser, LoginFailure> {
    let stored = match users.get(username).await {
        Ok(user) => user,
        // 旧 config 用户名可能只有 2 个字符，达不到账户库 3–32 的规则：对它来说
        // 「库里有这条记录」永远不可能，直接当「DB 里没有」回落 config。
        Err(AccountError::InvalidUsername { .. }) => None,
        Err(error) => {
            tracing::error!(username = %username, error = %error, "查询账户库失败");
            return Err(LoginFailure::Unavailable);
        },
    };

    match stored {
        Some(user) => authenticate_existing(users, user, password).await,
        None => authenticate_legacy(config, users, username, password).await,
    }
}

/// DB 里已有的账户：**只**用库里的 Argon2id 哈希校验，config 同名条目不再参与。
async fn authenticate_existing(
    users: &UserStore,
    user: crate::accounts::User,
    password: &[u8],
) -> Result<AuthUser, LoginFailure> {
    let hash = match users.password_hash(&user.username).await {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            // 刚按用户名查到、又读不到哈希：库被并发删除或损坏，按不可用处理。
            tracing::error!(username = %user.username, "账户库中缺少口令哈希");
            return Err(LoginFailure::Unavailable);
        },
        Err(error) => {
            tracing::error!(username = %user.username, error = %error, "读取口令哈希失败");
            return Err(LoginFailure::Unavailable);
        },
    };

    // Argon2 是同步的 CPU/内存密集操作（19 MiB），必须在阻塞线程池里跑：
    // 直接在 handler 线程上算会卡住整个 tokio worker。
    if !passwords::verify(hash, password.to_vec()).await {
        return Err(LoginFailure::BadCredentials { reason: "wrong_password" });
    }
    // 口令正确但状态不是 active（待审批 / 已禁用）同样拒绝；具体状态只进日志。
    if user.status != UserStatus::Active {
        tracing::warn!(
            username = %user.username,
            status = user.status.as_str(),
            "账户状态不允许登录"
        );
        return Err(LoginFailure::Inactive);
    }
    if let Err(error) = users.touch_last_login(&user.username).await {
        // 登录时间只是统计信息，写失败不该把已通过认证的请求拒掉。
        tracing::warn!(username = %user.username, error = %error, "记录登录时间失败");
    }
    Ok(AuthUser { username: user.username, role: user.role })
}

/// 库里没有该账户时的 config 回落与懒升级。
async fn authenticate_legacy(
    config: &Config,
    users: &UserStore,
    username: &str,
    password: &[u8],
) -> Result<AuthUser, LoginFailure> {
    let Some(config_user) = config.auth.users.get(username) else {
        // 两边都没有这个用户：付一次与真实校验等价的 Argon2 开销再拒绝，
        // 否则响应时间会泄漏「这个用户名在不在账户库里」。
        passwords::dummy_verify(password.to_vec()).await;
        return Err(LoginFailure::BadCredentials { reason: "unknown_user" });
    };
    if !password_matches(password, &config_user.password_sha256) {
        return Err(LoginFailure::BadCredentials { reason: "wrong_password" });
    }

    upgrade_legacy_user(users, username, password, config_user).await;
    Ok(AuthUser { username: username.to_owned(), role: config_user.role })
}

/// 首次成功登录时把 config 用户的明文口令换成 Argon2id 写进账户库。
///
/// 写失败只记 warn、不阻断登录：`[auth.users]` 是引导/应急入口，账户库损坏时
/// （比如磁盘满、文件被误删）运维仍要能用 config 里的管理员口令进去修。
///
/// 并发首登：两个请求可能同时走到这里，`create` 会有一方拿到
/// [`AccountError::DuplicateUsername`]，那一方改走 `update_password_hash`——
/// 两边哈希的是同一个明文口令，谁后写都一样。
async fn upgrade_legacy_user(
    users: &UserStore,
    username: &str,
    password: &[u8],
    config_user: &UserConfig,
) {
    // 明文口令只在这个函数里存活：哈希后立即丢弃，不进日志、不回响应。
    let Ok(plaintext) = std::str::from_utf8(password) else {
        // 非 UTF-8 口令能匹配 sha256 摘要（摘要按字节算），但 Argon2 只接受字符串：
        // 这类历史口令保持 config 路径，不做升级。
        tracing::warn!(username = %username, "config 口令不是 UTF-8，跳过哈希升级");
        return;
    };
    let Ok(hash) = passwords::hash(plaintext.to_owned()).await else {
        tracing::error!(username = %username, "生成 Argon2id 哈希失败，暂不升级");
        return;
    };

    match users.create(username, &hash, config_user.role, UserStatus::Active).await {
        Ok(_) => {
            tracing::info!(
                username = %username,
                role = %config_user.role,
                "config 用户首次登录，已升级为 Argon2id 账户"
            );
        },
        Err(AccountError::DuplicateUsername { .. }) => {
            if let Err(error) = users.update_password_hash(username, &hash).await {
                tracing::warn!(username = %username, error = %error, "并发升级时改写口令哈希失败");
                return;
            }
            tracing::info!(username = %username, "并发首登，已对齐账户库中的口令哈希");
        },
        Err(error) => {
            tracing::warn!(username = %username, error = %error, "账户库写入失败，本次仍按 config 登录");
            return;
        },
    }
    if let Err(error) = users.touch_last_login(username).await {
        tracing::warn!(username = %username, error = %error, "记录登录时间失败");
    }
}

/// 纯 config 认证的占位摘要（64 个 0）：未知用户名也付一次常量时间比较的开销，
/// 避免计时差泄漏用户名是否存在（CWE-208）。真实配置里不会出现全 0 摘要的可用口令。
const DUMMY_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 解析 `Basic <base64>`：只切第一个 `:`，口令本身允许含冒号。
fn parse_basic(header: Option<&HeaderValue>) -> Result<(String, Vec<u8>), AuthFailure> {
    let raw = header.ok_or(AuthFailure::MissingHeader)?;
    let text = raw.to_str().map_err(|_| AuthFailure::MalformedHeader)?;
    let (scheme, encoded) = text.split_once(' ').ok_or(AuthFailure::MalformedHeader)?;
    if !scheme.eq_ignore_ascii_case("basic") {
        return Err(AuthFailure::MalformedHeader);
    }
    // 某些代理会在头值尾部补空格；去掉后解码，但不接受中间的空白。
    let decoded = STANDARD.decode(encoded.trim()).map_err(|_| AuthFailure::InvalidBase64)?;
    let separator =
        decoded.iter().position(|byte| *byte == b':').ok_or(AuthFailure::MissingSeparator)?;
    let username = std::str::from_utf8(&decoded[..separator])
        .map_err(|_| AuthFailure::NonUtf8Username)?
        .to_owned();
    Ok((username, decoded[separator + 1..].to_vec()))
}

/// 对明文口令做 sha256，与期望的十六进制摘要做常量时间比较。
///
/// 允许配置里的摘要是大写十六进制（统一转小写后再比），也允许摘要长度不合法——
/// 那种情况比较必然失败，等价于该用户不可登录，不会误放行。
fn password_matches(password: &[u8], expected_hex: &str) -> bool {
    let actual = hex::encode(Sha256::digest(password));
    constant_time_eq(actual.as_bytes(), expected_hex.to_ascii_lowercase().as_bytes())
}

/// 常量时间字节比较：逐字节异或累加，不在第一个不同字节处提前返回。
///
/// 长度不同才提前返回——摘要长度是公开信息（恒为 64 个十六进制字符），
/// 不构成侧信道。没有用 `==`：`slice::eq` 可能因编译器优化提前退出。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0_u8;
    for (left_byte, right_byte) in left.iter().zip(right) {
        diff |= left_byte ^ right_byte;
    }
    diff == 0
}

#[cfg(test)]
mod tests {
    use axum::http::HeaderValue;
    use base64::Engine;
    use base64::engine::general_purpose::STANDARD;

    use super::{AuthFailure, constant_time_eq, parse_basic, password_matches};
    use crate::store::Sha256Writer;

    fn digest(password: &str) -> String {
        let mut writer = Sha256Writer::new();
        writer.update(password.as_bytes());
        writer.finish()
    }

    fn header(payload: &str) -> HeaderValue {
        HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(payload))).expect("合法头值")
    }

    #[test]
    fn given_equal_bytes_when_constant_time_eq_then_true() {
        assert!(constant_time_eq(b"same", b"same"));
        assert!(constant_time_eq(b"", b""));
    }

    #[test]
    fn given_same_length_different_bytes_when_constant_time_eq_then_false() {
        assert!(!constant_time_eq(b"same", b"samf"));
        // 只有最后一个字节不同，验证实现没有「读一半就返回 true」。
        assert!(!constant_time_eq(b"aaaa", b"aaab"));
    }

    #[test]
    fn given_different_length_when_constant_time_eq_then_false() {
        assert!(!constant_time_eq(b"short", b"longer"));
    }

    #[test]
    fn given_matching_password_when_password_matches_then_true() {
        assert!(password_matches(b"s3cret", &digest("s3cret")));
    }

    #[test]
    fn given_wrong_password_when_password_matches_then_false() {
        assert!(!password_matches(b"wrong", &digest("s3cret")));
    }

    #[test]
    fn given_uppercase_configured_digest_when_password_matches_then_accepts() {
        assert!(password_matches(b"s3cret", &digest("s3cret").to_uppercase()));
    }

    #[test]
    fn given_broken_configured_digest_when_password_matches_then_rejects() {
        // 长度不对 / 含非十六进制字符都必须失败（fail closed），不能 panic。
        assert!(!password_matches(b"s3cret", "abc"));
        assert!(!password_matches(b"s3cret", &"z".repeat(64)));
    }

    #[test]
    fn given_basic_header_when_parse_then_splits_user_and_password() {
        let (username, password) = parse_basic(Some(&header("alice:s3cret"))).expect("应解析成功");

        assert_eq!(username, "alice");
        assert_eq!(password, b"s3cret");
    }

    #[test]
    fn given_password_with_colon_when_parse_then_keeps_rest() {
        let (username, password) = parse_basic(Some(&header("alice:pa:ss"))).expect("应解析成功");

        assert_eq!(username, "alice");
        assert_eq!(password, b"pa:ss");
    }

    #[test]
    fn given_missing_header_when_parse_then_missing_header() {
        assert_eq!(parse_basic(None).expect_err("缺头应失败"), AuthFailure::MissingHeader);
    }

    #[test]
    fn given_non_basic_scheme_when_parse_then_malformed() {
        let raw = HeaderValue::from_static("Bearer token");

        assert_eq!(
            parse_basic(Some(&raw)).expect_err("scheme 不对应失败"),
            AuthFailure::MalformedHeader
        );
    }

    #[test]
    fn given_invalid_base64_when_parse_then_invalid_base64() {
        let raw = HeaderValue::from_static("Basic !!!not-base64!!!");

        assert_eq!(
            parse_basic(Some(&raw)).expect_err("非法 base64 应失败"),
            AuthFailure::InvalidBase64
        );
    }

    #[test]
    fn given_payload_without_colon_when_parse_then_missing_separator() {
        let raw = header("alice");

        assert_eq!(
            parse_basic(Some(&raw)).expect_err("缺分隔符应失败"),
            AuthFailure::MissingSeparator
        );
    }

    #[test]
    fn given_non_utf8_username_when_parse_then_non_utf8_username() {
        let mut payload = vec![0xff_u8];
        payload.push(b':');
        payload.extend_from_slice(b"s3cret");
        let raw = HeaderValue::from_str(&format!("Basic {}", STANDARD.encode(&payload)))
            .expect("合法头值");

        assert_eq!(
            parse_basic(Some(&raw)).expect_err("非法 UTF-8 用户名应失败"),
            AuthFailure::NonUtf8Username
        );
    }
}

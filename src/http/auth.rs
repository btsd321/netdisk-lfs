//! HTTP Basic 认证与角色提取。
//!
//! 安全约定见 `specs/api.md`「公共约定」：
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

use std::time::Duration;

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::error::{self, ApiError};
use super::{AppState, RequestId};
use crate::accounts::{AccountError, UserStatus, UserStore, hash_password, verify_password};
use crate::config::{Config, Role, UserConfig};

/// 所有 401 共用的文案：不区分「没带凭据」「用户不存在」「口令错误」。
const AUTH_FAILURE_MESSAGE: &str = "需要 HTTP Basic 认证";

/// 账户库故障时的 503 文案：不暴露 SQL 细节，只说明可以重试。
const ACCOUNTS_UNAVAILABLE_MESSAGE: &str = "账户库暂时不可用，请稍后重试";

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

/// 认证失败的原因；只写日志，不写响应。
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
    /// 用户名不在账户库与 `[auth.users]` 里。
    UnknownUser,
    /// 口令不匹配。
    WrongPassword,
    /// 账户存在且口令正确，但状态不是 `active`（待审批 / 已禁用）。
    InactiveAccount,
    /// 登录失败次数超过窗口上限。
    TooManyRequests {
        /// 建议的重试间隔。
        retry_after: Duration,
    },
    /// 账户库故障：无法判定凭据，按 503 让客户端稍后重试。
    AccountsUnavailable,
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
            Self::UnknownUser => "unknown_user",
            Self::WrongPassword => "wrong_password",
            Self::InactiveAccount => "inactive_account",
            Self::TooManyRequests { .. } => "too_many_requests",
            Self::AccountsUnavailable => "accounts_unavailable",
        }
    }

    /// 是否计入登录失败次数。
    ///
    /// 429 是限速本身的结论，503 是基础设施故障——两者都不该继续延长封锁窗口，
    /// 否则攻击者只要持续打就能把真实用户永久锁在外面。
    fn counts_as_login_failure(self) -> bool {
        !matches!(self, Self::TooManyRequests { .. } | Self::AccountsUnavailable)
    }
}

/// 认证中间件：校验通过后把 [`Role`] 与 [`AuthUser`] 写进请求扩展，再交给下游 handler。
///
/// 返回 `Response` 而不是 `Result`，是因为失败时要复用本次请求的 request id
/// 构造错误体——`ApiError` 的 `IntoResponse` 拿不到请求，只能另外生成一个，
/// 那样响应体与响应头的 id 会对不上。
pub(crate) async fn require(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    // 先取出 Authorization 头再进入异步：`Request<Body>` 不是 `Sync`，把 `&request`
    // 带过 `.await` 会让整个中间件 future 不是 `Send`（axum 的 `FromFn` 要求它）。
    let authorization = request.headers().get(AUTHORIZATION).cloned();
    match authenticate(&state, authorization).await {
        Ok(user) => {
            request.extensions_mut().insert(user.role);
            request.extensions_mut().insert(user);
            next.run(request).await
        },
        Err(failure) => {
            let request_id = request
                .extensions()
                .get::<RequestId>()
                .cloned()
                .unwrap_or_else(RequestId::generate);
            tracing::warn!(
                request_id = %request_id,
                reason = failure.as_str(),
                "LFS 认证失败"
            );
            failure_response(failure, &request_id)
        },
    }
}

/// 把失败原因映射成响应：401 统一文案、429 带 `Retry-After`、503 带认证挑战头。
fn failure_response(failure: AuthFailure, request_id: &RequestId) -> Response {
    match failure {
        AuthFailure::TooManyRequests { retry_after } => ApiError::TooManyRequests {
            message: format!("登录失败次数过多，请 {} 秒后重试", retry_after.as_secs().max(1)),
            retry_after_secs: retry_after.as_secs().max(1),
        }
        .into_response_with(request_id),
        AuthFailure::AccountsUnavailable => error::with_auth_challenge(
            ApiError::Unavailable(ACCOUNTS_UNAVAILABLE_MESSAGE.to_owned())
                .into_response_with(request_id),
        ),
        _ => ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.to_owned()).into_response_with(request_id),
    }
}

/// 解析凭据并完成认证；先过登录失败限速，再按「DB 优先、config 回落」判定。
async fn authenticate(
    state: &AppState,
    authorization: Option<HeaderValue>,
) -> Result<AuthUser, AuthFailure> {
    let (username, password) = parse_basic(authorization.as_ref())?;
    // 用户名大小写不敏感：库里的 UNIQUE COLLATE NOCASE 与 config 的键名都按字面量，
    // 但限速必须把 Alice/alice 算成同一个人，否则改个大小写就能绕开限速。
    let throttle_key = username.to_ascii_lowercase();
    let limit = state.config().accounts.login_failures_per_5min;
    if let Some(retry_after) = state.login_limits().blocked_for(&throttle_key, limit) {
        return Err(AuthFailure::TooManyRequests { retry_after });
    }

    let outcome = match state.accounts() {
        Some(users) => authenticate_with_store(state.config(), users, &username, &password).await,
        None => authenticate_config(state.config(), &username, &password),
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
            Err(failure)
        },
    }
}

/// 纯 config 认证（未接入账户库时的旧行为）。
fn authenticate_config(
    config: &Config,
    username: &str,
    password: &[u8],
) -> Result<AuthUser, AuthFailure> {
    let user = config.auth.users.get(username);
    // 未知用户名也付一次摘要+比较的开销，避免计时差泄漏用户名是否存在。
    let expected = user.map_or(DUMMY_DIGEST, |user| user.password_sha256.as_str());
    let matched = password_matches(password, expected);
    match user {
        Some(user) if matched => Ok(AuthUser { username: username.to_owned(), role: user.role }),
        Some(_) => Err(AuthFailure::WrongPassword),
        None => Err(AuthFailure::UnknownUser),
    }
}

/// 接入账户库后的认证：DB 优先，查不到再回落 config 并懒升级。
async fn authenticate_with_store(
    config: &Config,
    users: &UserStore,
    username: &str,
    password: &[u8],
) -> Result<AuthUser, AuthFailure> {
    let stored = match users.get(username).await {
        Ok(user) => user,
        // 旧 config 用户名可能只有 2 个字符，达不到账户库 3–32 的规则：对它来说
        // 「库里有这条记录」永远不可能，直接当「DB 里没有」回落 config。
        Err(AccountError::InvalidUsername { .. }) => None,
        Err(error) => {
            tracing::error!(username = %username, error = %error, "查询账户库失败");
            return Err(AuthFailure::AccountsUnavailable);
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
) -> Result<AuthUser, AuthFailure> {
    let hash = match users.password_hash(&user.username).await {
        Ok(Some(hash)) => hash,
        Ok(None) => {
            // 刚按用户名查到、又读不到哈希：库被并发删除或损坏，按不可用处理。
            tracing::error!(username = %user.username, "账户库中缺少口令哈希");
            return Err(AuthFailure::AccountsUnavailable);
        },
        Err(error) => {
            tracing::error!(username = %user.username, error = %error, "读取口令哈希失败");
            return Err(AuthFailure::AccountsUnavailable);
        },
    };

    // Argon2 是同步的 CPU/内存密集操作（19 MiB），必须在阻塞线程池里跑：
    // 直接在 handler 线程上算会卡住整个 tokio worker。
    if !verify_password_blocking(hash, password.to_vec()).await {
        return Err(AuthFailure::WrongPassword);
    }
    // 口令正确但状态不是 active（待审批 / 已禁用）同样拒绝；具体状态只进日志。
    if user.status != UserStatus::Active {
        tracing::warn!(
            username = %user.username,
            status = user.status.as_str(),
            "账户状态不允许登录"
        );
        return Err(AuthFailure::InactiveAccount);
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
) -> Result<AuthUser, AuthFailure> {
    let Some(config_user) = config.auth.users.get(username) else {
        // 两边都没有这个用户：付一次与真实校验等价的 Argon2 开销再拒绝，
        // 否则响应时间会泄漏「这个用户名在不在账户库里」。
        dummy_verify(password.to_vec()).await;
        return Err(AuthFailure::UnknownUser);
    };
    if !password_matches(password, &config_user.password_sha256) {
        return Err(AuthFailure::WrongPassword);
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
    let Ok(hash) = hash_password_blocking(plaintext.to_owned()).await else {
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

/// 在阻塞线程池里做 Argon2 校验；任务 panic 或运行时关闭时按「不匹配」处理。
async fn verify_password_blocking(hash: String, password: Vec<u8>) -> bool {
    let Ok(password) = String::from_utf8(password) else {
        return false;
    };
    match tokio::task::spawn_blocking(move || verify_password(&hash, &password)).await {
        Ok(matched) => matched,
        Err(error) => {
            tracing::error!(error = %error, "口令校验任务失败");
            false
        },
    }
}

/// 在阻塞线程池里生成 Argon2id 哈希。
async fn hash_password_blocking(password: String) -> Result<String, AccountError> {
    tokio::task::spawn_blocking(move || hash_password(&password)).await?
}

/// 不存在用户名的占位校验：耗时与真实 Argon2 校验一致，结果必然为 false。
async fn dummy_verify(password: Vec<u8>) {
    let Ok(password) = String::from_utf8(password) else {
        return;
    };
    // 占位哈希来自一个随机口令，代码里没有它的明文，因此永远不会校验通过。
    match tokio::task::spawn_blocking(move || verify_password(DUMMY_ARGON2_HASH, &password)).await {
        Ok(_) => {},
        Err(error) => tracing::debug!(error = %error, "占位口令校验任务失败"),
    }
}

/// 纯 config 认证的占位摘要（64 个 0）：未知用户名也付一次常量时间比较的开销，
/// 避免计时差泄漏用户名是否存在（CWE-208）。真实配置里不会出现全 0 摘要的可用口令。
const DUMMY_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 接入账户库后未知用户名的占位哈希。
///
/// 用一个随机口令的 Argon2id PHC 串：明文不在代码里，永远校验不通过，但校验过程
/// 会消耗与真实账户相同的 CPU/内存，让「用户名在不在库里」无法从响应时间分辨。
const DUMMY_ARGON2_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$KgEc2p7IRGjkwslYirgWXA$yZi4JDtWmw4Dl0E0q5t+OngJasOO5zhJLgcBLLmATks";

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

//! HTTP Basic 认证与角色提取。
//!
//! 安全约定见 `specs/api.md`「公共约定」：
//!
//! - 未带认证头、格式错、用户名不存在、口令不符**一律 401**，响应体完全相同，
//!   不泄漏「用户名是否存在」；
//! - 配置只存口令的 sha256 十六进制摘要，比较走常量时间实现（不因提前退出泄漏
//!   已匹配的前缀长度）；
//! - 认证在 handler 之前完成，通过后把 [`Role`] 写进请求扩展，由 batch handler
//!   按 operation 决定是否拒绝（只读账号只允许 download）。
//!
//! 认证失败的具体原因只进日志（`reason` 字段），不进响应体。

use axum::extract::{Request, State};
use axum::http::HeaderValue;
use axum::http::header::AUTHORIZATION;
use axum::middleware::Next;
use axum::response::Response;
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use sha2::{Digest, Sha256};

use super::error::ApiError;
use super::{AppState, RequestId};
use crate::config::Role;

/// 所有 401 共用的文案：不区分「没带凭据」「用户不存在」「口令错误」。
const AUTH_FAILURE_MESSAGE: &str = "需要 HTTP Basic 认证";

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
    /// 用户名不在 `[auth.users]` 里。
    UnknownUser,
    /// 口令摘要不匹配。
    WrongPassword,
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
        }
    }
}

/// 认证中间件：校验通过后把 [`Role`] 写进请求扩展，再交给下游 handler。
///
/// 返回 `Response` 而不是 `Result`，是因为失败时要复用本次请求的 request id
/// 构造错误体——`ApiError` 的 `IntoResponse` 拿不到请求，只能另外生成一个，
/// 那样响应体与响应头的 id 会对不上。
pub(crate) async fn require(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Response {
    match authenticate(&state, request.headers().get(AUTHORIZATION)) {
        Ok(role) => {
            request.extensions_mut().insert(role);
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
            ApiError::Unauthorized(AUTH_FAILURE_MESSAGE.to_owned()).into_response_with(&request_id)
        },
    }
}

/// 未知用户也照常走一遍摘要与常量时间比较用的占位摘要（64 个 0）。
///
/// 若未知用户提前返回，攻击者可凭响应时间差枚举用户名是否存在（CWE-208）；
/// 用占位摘要让两条路径成本一致。真实配置里不会出现全 0 摘要的可用口令。
const DUMMY_DIGEST: &str = "0000000000000000000000000000000000000000000000000000000000000000";

/// 校验 `Authorization` 头，返回调用方角色。
fn authenticate(state: &AppState, header: Option<&HeaderValue>) -> Result<Role, AuthFailure> {
    let (username, password) = parse_basic(header)?;
    let user = state.config().auth.users.get(&username);
    // 未知用户名也付一次摘要+比较的开销，避免计时差泄漏用户名是否存在。
    let expected = user.map_or(DUMMY_DIGEST, |user| user.password_sha256.as_str());
    let matched = password_matches(&password, expected);
    match user {
        Some(user) if matched => Ok(user.role),
        Some(_) => Err(AuthFailure::WrongPassword),
        None => Err(AuthFailure::UnknownUser),
    }
}

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

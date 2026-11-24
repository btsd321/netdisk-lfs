//! 口令哈希与口令策略。
//!
//! 新账户用 Argon2id（`Argon2::default()`：v19、m=19 MiB、t=2、p=1）生成 PHC
//! 字符串；盐、参数与版本都编码在哈希串里，校验时直接读串内参数，日后调参不需要
//! 迁移旧哈希。config 里的 sha256 摘要继续由 `http::auth` 处理，本模块不参与。

use argon2::{Argon2, PasswordHasher, PasswordVerifier};

use super::AccountError;

/// 口令最大字符数（业务策略）；Argon2 本身只限制字节数。
pub const MAX_PASSWORD_CHARS: usize = 128;

/// 生成 Argon2id 哈希，返回 PHC 字符串（形如 `$argon2id$v=19$m=19456,t=2,p=1$...`）。
///
/// # Errors
///
/// 系统随机数不可用，或参数/长度不满足 Argon2 约束时返回 [`AccountError::Hash`]。
pub fn hash_password(password: &str) -> Result<String, AccountError> {
    Argon2::default()
        .hash_password(password.as_bytes())
        .map(|hash| hash.to_string())
        .map_err(|error| AccountError::Hash { reason: error.to_string() })
}

/// 校验明文口令与 PHC 哈希是否匹配。
///
/// 哈希串损坏、算法不认识或口令不符一律返回 `false`，不 panic——调用方把它当作
/// 「认证失败」处理，不能因为库里的脏数据把请求打成 500。
pub fn verify_password(hash: &str, password: &str) -> bool {
    Argon2::default().verify_password(password.as_bytes(), hash).is_ok()
}

/// 校验口令策略：长度 `min_len..=128`、不等于用户名（大小写不敏感）、不能全空白。
///
/// # Errors
///
/// 违反上述任一规则时返回 [`AccountError::InvalidPassword`]，`reason` 说明具体规则。
pub fn validate_password(
    username: &str,
    password: &str,
    min_len: usize,
) -> Result<(), AccountError> {
    let length = password.chars().count();
    if length < min_len {
        return Err(AccountError::InvalidPassword {
            reason: format!("长度至少为 {min_len} 个字符，实际 {length} 个"),
        });
    }
    if length > MAX_PASSWORD_CHARS {
        return Err(AccountError::InvalidPassword {
            reason: format!("长度不能超过 {MAX_PASSWORD_CHARS} 个字符，实际 {length} 个"),
        });
    }
    // 用户名只允许 ASCII，口令按 ASCII 大小写折叠即可；不必引 Unicode 大小写表。
    if password.eq_ignore_ascii_case(username) {
        return Err(AccountError::InvalidPassword {
            reason: "不能与用户名相同（不区分大小写）".to_owned(),
        });
    }
    if password.trim().is_empty() {
        return Err(AccountError::InvalidPassword {
            reason: "不能全为空白字符".to_owned()
        });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{MAX_PASSWORD_CHARS, hash_password, validate_password, verify_password};

    #[test]
    fn given_password_when_hash_then_argon2id_phc_string_and_verifies() {
        let hash = hash_password("s3cret-passphrase").expect("哈希应成功");

        assert!(hash.starts_with("$argon2id$"), "实际哈希：{hash}");
        assert!(verify_password(&hash, "s3cret-passphrase"));
        assert!(!verify_password(&hash, "wrong-passphrase"));
    }

    #[test]
    fn given_corrupted_hash_when_verify_then_false_without_panic() {
        assert!(!verify_password("not-a-phc-string", "s3cret"));
        assert!(!verify_password("", "s3cret"));
        assert!(!verify_password("$argon2id$v=19$m=1,t=1,p=1$broken", "s3cret"));
    }

    #[test]
    fn given_too_short_password_when_validate_then_rejected() {
        let error = validate_password("alice", "short", 12).expect_err("应拒绝过短口令");

        assert!(error.to_string().contains("至少"), "实际错误：{error}");
    }

    #[test]
    fn given_password_equal_to_username_when_validate_then_rejected() {
        // 12 个字符，满足最小长度；大小写不同也应被拒。
        let error = validate_password("Alice", "aLiCeAlice12", 12);

        assert!(error.is_ok(), "仅大小写前缀相同不算相同口令");

        let error = validate_password("Alice", "alice", 5).expect_err("应拒绝与用户名相同的口令");
        assert!(error.to_string().contains("用户名"), "实际错误：{error}");
    }

    #[test]
    fn given_valid_password_when_validate_then_ok() {
        assert!(validate_password("alice", "correct horse battery", 12).is_ok());
        assert!(validate_password("alice", "abcdefghijkl", 12).is_ok());
        // 上限边界：128 个字符通过，129 个拒绝。
        assert!(validate_password("alice", &"x".repeat(MAX_PASSWORD_CHARS), 12).is_ok());
        assert!(
            validate_password("alice", &"x".repeat(MAX_PASSWORD_CHARS + 1), 12).is_err(),
            "超过上限应拒绝"
        );
    }

    #[test]
    fn given_whitespace_only_password_when_validate_then_rejected() {
        let error = validate_password("alice", "            ", 12).expect_err("应拒绝全空白口令");

        assert!(error.to_string().contains("空白"), "实际错误：{error}");
    }
}

//! 口令哈希与校验的异步包装。
//!
//! Argon2 是同步的 CPU/内存密集操作（默认 19 MiB、t=2），直接在 tokio worker 上
//! 执行会卡住同线程的其它请求，所以统一走 [`tokio::task::spawn_blocking`]。
//! 认证中间件、注册、改密都从这里取，避免三处各写一份阻塞包装。

use crate::accounts::{AccountError, hash_password, verify_password};

/// 接入账户库后未知用户名的占位哈希。
///
/// 用一个随机口令的 Argon2id PHC 串：明文不在代码里，永远校验不通过，但校验过程
/// 会消耗与真实账户相同的 CPU/内存，让「用户名在不在库里」无法从响应时间分辨。
const DUMMY_ARGON2_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$KgEc2p7IRGjkwslYirgWXA$yZi4JDtWmw4Dl0E0q5t+OngJasOO5zhJLgcBLLmATks";

/// 在阻塞线程池里生成 Argon2id 哈希。
///
/// # Errors
///
/// 阻塞任务加入失败（运行时已关闭）或 Argon2 本身失败时返回 [`AccountError`]。
pub(crate) async fn hash(password: String) -> Result<String, AccountError> {
    tokio::task::spawn_blocking(move || hash_password(&password)).await?
}

/// 在阻塞线程池里校验明文口令；任务 panic 或运行时关闭时按「不匹配」处理（fail closed）。
pub(crate) async fn verify(hash: String, password: Vec<u8>) -> bool {
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

/// 不存在用户名的占位校验：耗时与真实 Argon2 校验一致，结果必然为 false。
///
/// 只在「账户库里没有这个用户名」时调用；纯 config 模式保持原有零成本路径。
pub(crate) async fn dummy_verify(password: Vec<u8>) {
    let Ok(password) = String::from_utf8(password) else {
        return;
    };
    match tokio::task::spawn_blocking(move || verify_password(DUMMY_ARGON2_HASH, &password)).await {
        Ok(_) => {},
        Err(error) => tracing::debug!(error = %error, "占位口令校验任务失败"),
    }
}

#[cfg(test)]
mod tests {
    use super::{dummy_verify, hash, verify};

    #[tokio::test]
    async fn given_password_when_hash_and_verify_then_roundtrip() {
        let hash = hash("correct horse battery".to_owned()).await.expect("哈希应成功");

        assert!(hash.starts_with("$argon2id$"));
        assert!(verify(hash.clone(), b"correct horse battery".to_vec()).await);
        assert!(!verify(hash, b"wrong password".to_vec()).await);
    }

    #[tokio::test]
    async fn given_broken_hash_or_non_utf8_when_verify_then_false() {
        assert!(!verify("not-a-phc".to_owned(), b"s3cret".to_vec()).await);
        assert!(!verify("$argon2id$v=19$m=1,t=1,p=1$broken".to_owned(), vec![0xff, 0xfe]).await);
    }

    #[tokio::test]
    async fn given_any_password_when_dummy_verify_then_no_panic() {
        // 占位哈希的明文不在代码里：结果必然为 false，但不能 panic。
        dummy_verify(b"correct horse battery".to_vec()).await;
        dummy_verify(vec![0xff, 0xfe]).await;
    }
}

//! 存储层的域内错误。

use std::path::PathBuf;

use thiserror::Error;

use crate::store::Oid;

/// 存储层失败的原因。
///
/// 错误信息只描述「什么失败了、关键参数是什么」；oid 与本地路径一律带上，
/// 日志里能直接定位到具体对象。
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum StoreError {
    /// 对象在存储后端中不存在。
    #[error("对象 {oid} 不存在")]
    NotFound {
        /// 缺失的对象。
        oid: Oid,
    },
    /// 内容与 oid 不符：要么待上传的本地文件是脏的，要么后端给了坏对象。
    ///
    /// 期望值恒等于 oid 本身，因此不设 `expected` 字段——变体字段是公开的，
    /// 若单独携带 `expected` 就可能被构造成与 oid 不一致的误导信息；直接渲染
    /// `{oid}` 让张冠李戴在结构上不可能。
    #[error("对象 {oid} 哈希不符：实际 {actual}")]
    HashMismatch {
        /// 目标对象。
        oid: Oid,
        /// 实际算出的摘要，供日志留证。
        actual: String,
    },
    /// 存储后端（`bdpan` 或其它驱动）报错。
    #[error("存储后端失败：{message}")]
    Backend {
        /// 后端给出的、已解析成人类可读形式的失败原因。
        message: String,
        /// 原始错误，保留 source 链供排查。
        #[source]
        source: Option<Box<dyn std::error::Error + Send + Sync>>,
    },
    /// 本地文件系统操作失败。
    #[error("本地文件 {path} 操作失败")]
    Io {
        /// 出错的本地路径。
        path: PathBuf,
        /// 底层 IO 错误。
        #[source]
        source: std::io::Error,
    },
    /// 后端不具备该操作的能力（如没有配额查询）。
    #[error("存储后端不支持：{operation}")]
    Unimplemented {
        /// 操作名，如 `quota`。
        operation: &'static str,
    },
}

impl StoreError {
    /// 包装带路径上下文的本地 IO 失败。
    ///
    /// 不用 `#[from]` 是为了强制调用方补上路径：只报「No such file」的日志无法定位对象。
    pub fn io(path: impl Into<PathBuf>, source: std::io::Error) -> Self {
        Self::Io { path: path.into(), source }
    }

    /// 构造「内容与 oid 不符」错误；`actual` 是实际算出的十六进制摘要。
    ///
    /// 期望值恒为 oid 本身，集中在这里构造，后端实现不会传错。
    pub fn hash_mismatch(oid: &Oid, actual: &str) -> Self {
        Self::HashMismatch { oid: oid.clone(), actual: actual.to_owned() }
    }
}

#[cfg(test)]
mod tests {
    use super::StoreError;
    use crate::store::Oid;

    fn oid() -> Oid {
        Oid::parse(&"0".repeat(64)).expect("合法 oid")
    }

    #[test]
    fn given_mismatch_when_display_then_shows_oid_and_actual() {
        let err = StoreError::hash_mismatch(&oid(), "ff");

        let message = err.to_string();
        // 断言带标签的具体值：oid（64 个 0）与 actual（ff）都在，且顺序正确。
        let oid_pos = message.find(&"0".repeat(64)).expect("oid 应出现在错误信息中");
        let actual_pos = message.find("ff").expect("actual 应出现在错误信息中");
        assert!(oid_pos < actual_pos, "实际错误：{message}");
        assert!(message.contains("哈希不符"), "实际错误：{message}");
    }

    #[test]
    fn given_io_failure_when_display_then_names_path() {
        let err = StoreError::io("/tmp/x", std::io::Error::from(std::io::ErrorKind::NotFound));

        assert!(err.to_string().contains("/tmp/x"), "实际错误：{err}");
    }

    #[test]
    fn given_backend_error_when_source_then_keeps_original_kind() {
        let err = StoreError::Backend {
            message: "bdpan 超时".to_owned(),
            source: Some(Box::new(std::io::Error::from(std::io::ErrorKind::TimedOut))),
        };

        // downcast 验证 source 链确实保留了原始错误（而非只是「有 source」）。
        let source = std::error::Error::source(&err)
            .and_then(|source| source.downcast_ref::<std::io::Error>().map(std::io::Error::kind));
        assert_eq!(source, Some(std::io::ErrorKind::TimedOut));
        assert!(!err.to_string().ends_with('。'));
    }
}

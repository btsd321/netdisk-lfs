//! 配置层的域内错误。

use std::path::PathBuf;

/// 配置加载或启动期校验失败的原因。
///
/// 错误信息只描述「什么失败了、关键参数是什么」；路径一律带上，便于运维定位。
#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    /// `.env` 文件存在但无法解析。
    #[error("读取 .env 文件 {path} 失败：{message}")]
    Dotenv {
        /// `.env` 路径。
        path: PathBuf,
        /// 解析器给出的原因。
        message: String,
    },
    /// 配置文件读不出来（不存在、无权限等）。
    #[error("读取配置文件 {path} 失败")]
    Read {
        /// 配置文件路径。
        path: PathBuf,
        /// 底层 IO 错误。
        #[source]
        source: std::io::Error,
    },
    /// 配置文件存在但不是合法的 TOML 或不符合 schema。
    #[error("解析配置文件 {path} 失败：{source}")]
    Parse {
        /// 配置文件路径。
        path: PathBuf,
        /// TOML 反序列化错误（含字段名与行号）。
        #[source]
        source: toml::de::Error,
    },
    /// 解析成功但语义校验不通过。
    #[error("配置校验失败：{0}")]
    Invalid(String),
}

impl ConfigError {
    /// 构造一条校验失败错误；`message` 需说明哪个字段不合法。
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

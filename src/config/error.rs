//! 配置层的域内错误。

use std::path::PathBuf;

/// 配置加载或启动期校验失败的原因。
///
/// 错误信息只描述「什么失败了、关键参数是什么」；路径一律带上，便于运维定位。
#[derive(Debug, thiserror::Error)]
pub(crate) enum ConfigError {
    #[error("读取 .env 文件 {path} 失败：{message}")]
    Dotenv { path: PathBuf, message: String },
    #[error("读取配置文件 {path} 失败")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("解析配置文件 {path} 失败：{source}")]
    Parse {
        path: PathBuf,
        #[source]
        source: toml::de::Error,
    },
    #[error("配置校验失败：{0}")]
    Invalid(String),
}

impl ConfigError {
    /// 构造一条校验失败错误；`message` 需说明哪个字段不合法。
    pub(crate) fn invalid(message: impl Into<String>) -> Self {
        Self::Invalid(message.into())
    }
}

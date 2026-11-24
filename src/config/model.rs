//! 配置模型：与 `specs/storage.md`「配置样例」一一对应，字段可先定义、部分暂不消费。

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// 规范化后的完整配置。
#[derive(Debug, Clone)]
pub(crate) struct Config {
    /// `[server]`：监听地址与对外 URL。
    pub(crate) server: ServerConfig,
    /// `[storage]`：网盘路径与 bdpan 参数。
    pub(crate) storage: StorageConfig,
    /// `[cache]`：本地读缓存。
    pub(crate) cache: CacheConfig,
    /// `[auth.users]`：LFS 客户端凭据（B4 才消费）。
    pub(crate) auth: AuthConfig,
    /// `NETDISK_LFS_ENV`，决定日志格式与默认级别。
    pub(crate) runtime_env: RuntimeEnv,
    /// `NETDISK_LFS_DATA_DIR`，本地数据根；`cache.dir` 的缺省来源，后续分支还用它推导 upload 目录。
    pub(crate) data_dir: Option<PathBuf>,
}

/// `[server]` 段。
#[derive(Debug, Clone)]
pub(crate) struct ServerConfig {
    /// 监听地址，如 `127.0.0.1:9001`。
    pub(crate) listen: SocketAddr,
    /// 对外基地址；空串表示经反向代理、href 用相对路径。
    pub(crate) public_base: String,
}

/// `[storage]` 段。
#[derive(Debug, Clone)]
pub(crate) struct StorageConfig {
    /// 网盘对象根，必须位于 `/apps/bdpan/` 授权目录内。
    pub(crate) objects_root: String,
    /// 上传中转目录，必须是 `objects_root` 的子目录。
    pub(crate) tmp_root: String,
    /// `bdpan` CLI 绝对路径。
    pub(crate) bdpan_bin: PathBuf,
    /// 单对象上限（字节），超限直接拒绝。
    pub(crate) max_object_bytes: u64,
    /// 同时存在的 `bdpan` 子进程上限。
    pub(crate) max_bdpan_procs: usize,
}

/// `[cache]` 段。
#[derive(Debug, Clone)]
pub(crate) struct CacheConfig {
    /// 读缓存目录。
    pub(crate) dir: PathBuf,
    /// 缓存预算（字节）。
    pub(crate) max_bytes: u64,
}

/// `[auth]` 段。
#[derive(Debug, Default, Clone)]
pub(crate) struct AuthConfig {
    /// 用户名 → 凭据；用户名即 Basic Auth 的用户名。
    pub(crate) users: BTreeMap<String, UserConfig>,
}

/// `[auth.users.<name>]` 的凭据与角色。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct UserConfig {
    /// 口令的 sha256 十六进制摘要（不存明文）。
    pub(crate) password_sha256: String,
    /// 读写权限（B4 起生效）。
    pub(crate) role: Role,
}

/// LFS 客户端的权限档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub(crate) enum Role {
    /// 只读：仅允许下载。
    Readonly,
    /// 读写：允许上传与下载。
    Readwrite,
}

/// 运行环境标识，来自 `NETDISK_LFS_ENV`，缺省 `dev`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum RuntimeEnv {
    /// 本地开发：人类可读日志，默认 debug 级别。
    #[default]
    Dev,
    /// 服务器：JSON 日志，默认 info 级别。
    Prod,
}

impl RuntimeEnv {
    /// 解析 `dev` / `prod`，其它取值直接报错。
    pub(crate) fn parse(raw: &str) -> Result<Self, crate::config::error::ConfigError> {
        match raw {
            "dev" => Ok(Self::Dev),
            "prod" => Ok(Self::Prod),
            other => Err(crate::config::error::ConfigError::invalid(format!(
                "NETDISK_LFS_ENV 只能是 dev 或 prod，实际为 {other}"
            ))),
        }
    }
}

impl fmt::Display for Role {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Readonly => "readonly",
            Self::Readwrite => "readwrite",
        })
    }
}

impl fmt::Display for RuntimeEnv {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Dev => "dev",
            Self::Prod => "prod",
        })
    }
}

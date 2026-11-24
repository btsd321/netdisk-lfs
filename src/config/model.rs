//! 配置模型：与 `specs/storage.md`「配置样例」一一对应，字段可先定义、部分暂不消费。

use std::collections::BTreeMap;
use std::fmt;
use std::net::SocketAddr;
use std::path::PathBuf;

use serde::Deserialize;

/// 规范化后的完整配置。
#[derive(Debug, Clone)]
pub struct Config {
    /// `[server]`：监听地址与对外 URL。
    pub server: ServerConfig,
    /// `[storage]`：网盘路径与 bdpan 参数。
    pub storage: StorageConfig,
    /// `[cache]`：本地读缓存。
    pub cache: CacheConfig,
    /// `[accounts]`：SQLite 账户库路径与口令策略。
    pub accounts: AccountsConfig,
    /// `[auth.users]`：LFS 客户端凭据（B4 才消费）。
    pub auth: AuthConfig,
    /// `NETDISK_LFS_ENV`，决定日志格式与默认级别。
    pub runtime_env: RuntimeEnv,
    /// `NETDISK_LFS_DATA_DIR`，本地数据根；`cache.dir` 的缺省来源，后续分支还用它推导 upload 目录。
    pub data_dir: Option<PathBuf>,
}

/// `[server]` 段。
#[derive(Debug, Clone)]
pub struct ServerConfig {
    /// 监听地址，如 `127.0.0.1:9001`。
    pub listen: SocketAddr,
    /// 对外基地址；空串表示经反向代理、href 用相对路径。
    pub public_base: String,
}

/// `[storage]` 段。
#[derive(Debug, Clone)]
pub struct StorageConfig {
    /// 网盘对象根，必须位于 `/apps/bdpan/` 授权目录内。
    pub objects_root: String,
    /// 上传中转目录，必须是 `objects_root` 的子目录。
    pub tmp_root: String,
    /// `bdpan` CLI 绝对路径。
    pub bdpan_bin: PathBuf,
    /// 单对象上限（字节）；`0` 表示不限制（推荐——实际大小只受网盘与本地磁盘约束）。
    ///
    /// 非 0 时超限在 batch 与 PUT 两处都直接拒绝（422），不做分片。
    pub max_object_bytes: u64,
    /// 同时存在的 `bdpan` 子进程上限。
    pub max_bdpan_procs: usize,
    /// 非传输命令的固定超时，同时也是传输命令的启动宽限（秒）；`0` = 不设超时。
    ///
    /// 传输类命令（upload/download）的最终超时 = 本值 + `文件大小 / 最低吞吐`，
    /// 见 [`bdpan_min_throughput_bytes_per_sec`](Self::bdpan_min_throughput_bytes_per_sec)。
    pub bdpan_timeout_secs: u64,
    /// 传输类命令的最低吞吐（字节/秒），用于按文件大小推导超时；`0` = 不按吞吐计算。
    ///
    /// 默认 102400（100 KiB/s）：4.5 GiB 对象的超时约 13 小时，只有平均速度低于
    /// 100 KiB/s 才会被判卡死——正常上传/下载远快于此，不会误杀。
    pub bdpan_min_throughput_bytes_per_sec: u64,
}

/// `[cache]` 段。
#[derive(Debug, Clone)]
pub struct CacheConfig {
    /// 读缓存目录。
    pub dir: PathBuf,
    /// 缓存预算（字节）。
    pub max_bytes: u64,
}

/// `[accounts]` 段。
#[derive(Debug, Clone)]
pub struct AccountsConfig {
    /// 账户库（SQLite）路径；总是绝对路径，由 `accounts.db` 或数据根推导而来。
    pub db: PathBuf,
    /// 口令最小长度（字符数）；上限固定 128，由口令校验负责。
    pub min_password_len: usize,
}

/// `[auth]` 段。
#[derive(Debug, Default, Clone)]
pub struct AuthConfig {
    /// 用户名 → 凭据；用户名即 Basic Auth 的用户名。
    pub users: BTreeMap<String, UserConfig>,
}

/// `[auth.users.<name>]` 的凭据与角色。
#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UserConfig {
    /// 口令的 sha256 十六进制摘要（不存明文）。
    pub password_sha256: String,
    /// 读写权限（B4 起生效）。
    pub role: Role,
}

/// LFS 客户端的权限档位。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Role {
    /// 只读：仅允许下载。
    Readonly,
    /// 读写：允许上传与下载。
    Readwrite,
    /// 管理员：除读写权限外，还可在后续分支使用 `/admin/*` 管理账户。
    Admin,
}

impl Role {
    /// 是否允许上传（`readwrite` 与 `admin`）。
    ///
    /// 权限判定统一走这里：新增角色时只需改这一处，不会出现 batch 放行、
    /// PUT 拒绝之类的分叉。
    pub fn can_write(self) -> bool {
        matches!(self, Self::Readwrite | Self::Admin)
    }

    /// 稳定字符串表示，与 serde 的 lowercase 输出、账户库 `role` 列一致。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Readonly => "readonly",
            Self::Readwrite => "readwrite",
            Self::Admin => "admin",
        }
    }

    /// 从字符串解析角色；未知值返回 `None`，由调用方决定报错方式。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "readonly" => Some(Self::Readonly),
            "readwrite" => Some(Self::Readwrite),
            "admin" => Some(Self::Admin),
            _ => None,
        }
    }
}

/// 运行环境标识，来自 `NETDISK_LFS_ENV`，缺省 `dev`。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum RuntimeEnv {
    /// 本地开发：人类可读日志，默认 debug 级别。
    #[default]
    Dev,
    /// 服务器：JSON 日志，默认 info 级别。
    Prod,
}

impl RuntimeEnv {
    /// 解析 `dev` / `prod`，其它取值直接报错。
    pub fn parse(raw: &str) -> Result<Self, crate::config::error::ConfigError> {
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
        f.write_str(self.as_str())
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

#[cfg(test)]
mod tests {
    use super::Role;

    #[test]
    fn given_admin_role_when_can_write_then_true_and_readonly_denied() {
        assert!(Role::Admin.can_write(), "admin 必须拥有 readwrite 的 LFS 写权限");
        assert!(Role::Readwrite.can_write());
        assert!(!Role::Readonly.can_write());
    }

    #[test]
    fn given_each_role_when_display_and_parse_then_roundtrip() {
        for role in [Role::Readonly, Role::Readwrite, Role::Admin] {
            assert_eq!(role.to_string(), role.as_str());
            assert_eq!(Role::parse(role.as_str()), Some(role));
            assert_eq!(
                serde_json::from_str::<Role>(&format!("\"{}\"", role.as_str())).expect("合法角色"),
                role,
                "serde 的 lowercase 表示必须与 as_str 一致"
            );
        }
        assert_eq!(Role::parse("owner"), None);
    }
}

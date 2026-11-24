//! 配置加载：TOML 解析、环境变量覆盖与启动期校验。
//!
//! 优先级：进程环境 > `.env` 文件 > TOML 中的值；业务参数（账号口令哈希、各项上限）
//! 只来自 TOML。配置结构对应 `specs/storage.md`「配置样例」，其中 `[auth.users]`
//! 要到 B4 认证分支才被消费，本阶段只做解析与校验。

mod env;
mod error;
mod load;
mod model;

pub use env::{EnvSource, NETDISK_LFS_CONFIG};
pub use error::ConfigError;
pub use model::{
    AccountsConfig, AuthConfig, CacheConfig, Config, Role, RuntimeEnv, ServerConfig, StorageConfig,
    UserConfig,
};

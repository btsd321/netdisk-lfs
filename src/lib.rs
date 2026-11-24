//! netdisk-lfs 库：配置解析、HTTP 路由与存储层契约。
//!
//! 二进制入口 `main.rs` 只保留启动编排（读 `.env`、建 runtime、装日志、跑服务），
//! 其余能力都在本库里。拆出 lib target 是为了让 `tests/` 下的集成测试能直接使用
//! `Oid`、`ObjectStore`、`FakeStore` 这些类型——二进制 crate 无法被外部测试引入。
//!
//! 对外契约从 crate 根导出，模块路径不作为对外 API 的一部分。

pub mod accounts;
pub mod bdpan;
pub mod cache;
pub mod config;
pub mod http;
pub mod logging;
pub mod store;

#[cfg(test)]
mod test_support;

pub use accounts::{
    AccountError, MAX_PASSWORD_CHARS, User, UserStatus, UserStore, hash_password,
    validate_password, validate_username, verify_password,
};
pub use bdpan::{BdpanClient, BdpanClientConfig, BdpanError, BdpanStore, LsEntry, RetryPolicy};
pub use cache::{Cache, CachedFile, SweepReport, transient_dir};
pub use config::{
    AccountsConfig, AuthConfig, CacheConfig, Config, ConfigError, EnvSource, NETDISK_LFS_CONFIG,
    Role, RuntimeEnv, ServerConfig, StorageConfig, UserConfig,
};
pub use http::{ApiError, AppState, BdpanProbe, BdpanState, PROBE_TIMEOUT, PROBE_TTL, router};
pub use logging::init as init_logging;
pub use store::{
    FakeStore, ObjectMeta, ObjectStore, Oid, OidError, Quota, Sha256Writer, StoreError, hash_file,
    object_path,
};

//! netdisk-lfs 库：配置解析与 HTTP 路由。
//!
//! 二进制入口 `main.rs` 只保留启动编排（读 `.env`、建 runtime、装日志、跑服务），
//! 其余能力都在本库里。拆出 lib target 是为了让 `tests/` 下的集成测试能直接使用
//! crate 内的类型——二进制 crate 无法被外部测试引入。
//!
//! 对外契约从 crate 根导出，模块路径不作为对外 API 的一部分。

pub mod config;
pub mod http;
pub mod logging;
pub mod store;

#[cfg(test)]
mod test_support;

pub use config::{Config, ConfigError, EnvSource, NETDISK_LFS_CONFIG, RuntimeEnv};
pub use http::router;
pub use logging::init as init_logging;
pub use store::{Oid, OidError, Sha256Writer, hash_file};

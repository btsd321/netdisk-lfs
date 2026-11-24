//! 分级账户存储层：SQLite 账户库、Argon2id 口令与账户对象。
//!
//! 本模块只做存储与口令原语，不含 HTTP 端点：
//!
//! - [`UserStore`]：打开/迁移账户库，提供创建、查询、分页、改角色/状态/口令、
//!   记录登录与删除；所有 DB 操作都在阻塞线程池里执行；
//! - [`hash_password`] / [`verify_password`] / [`validate_password`]：Argon2id
//!   哈希与口令策略；
//! - [`User`] / [`UserStatus`] / [`StatusCounts`]：对外账户视图、状态与分组计数。
//!
//! 现有 `[auth.users]` 的 sha256 校验仍由 `http::auth` 处理，本模块不改变它的
//! 行为；C2 再做「DB 优先、config 回落、登录成功时懒升级哈希」。

mod error;
mod password;
mod store;

pub use error::AccountError;
pub use password::{MAX_PASSWORD_CHARS, hash_password, validate_password, verify_password};
pub use store::{StatusCounts, User, UserStatus, UserStore, validate_username};

//! 存储层契约：oid、流式哈希、`ObjectStore` 抽象与测试用实现。
//!
//! 协议层只依赖 [`ObjectStore`]，不关心对象落在百度网盘还是本地假目录；后端由配置在
//! 启动时选择（B3 起为 `bdpan` 驱动，测试用 [`FakeStore`]）。

mod hash;
mod oid;

pub use hash::{HASH_BUFFER_BYTES, Sha256Writer, hash_file};
pub use oid::{Oid, OidError};

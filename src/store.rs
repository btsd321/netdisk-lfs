//! 存储层契约：oid、流式哈希、`ObjectStore` 抽象与测试用实现。
//!
//! 协议层只依赖 [`ObjectStore`]，不关心对象落在百度网盘还是本地假目录；后端由配置在
//! 启动时选择（B3 起为 `bdpan` 驱动，测试用 [`FakeStore`]）。

use std::future::Future;
use std::path::Path;
use std::pin::Pin;

mod error;
mod fake;
mod hash;
mod oid;

pub use error::StoreError;
pub use fake::FakeStore;
pub use hash::{HASH_BUFFER_BYTES, Sha256Writer, hash_file};
pub use oid::{Oid, OidError};

/// 对象在存储后端中的目录名。
pub const OBJECTS_DIR: &str = "objects";

/// 由 oid 推导对象相对路径：`objects/<aa>/<bb>/<oid>`。
///
/// 这是本仓库唯一的分片路径实现——`BdpanStore`（远端）与 [`FakeStore`]（本地目录）
/// 都必须调用它，避免两处各写一份后布局漂移。返回值一律用 `/` 分隔，可以直接拼在
/// 后端的对象根（如 `/apps/bdpan/lfs`）后面。
pub fn object_path(oid: &Oid) -> String {
    let (first, second) = oid.shards();
    format!("{OBJECTS_DIR}/{first}/{second}/{oid}")
}

/// 存储操作返回的 future。
///
/// 这里用装箱 future 而非原生 `async fn in trait`：后者让 trait 失去 dyn 兼容性，
/// 协议层就无法把具体后端放进 `Arc<dyn ObjectStore>`——按配置选后端、集成测试换
/// [`FakeStore`] 都依赖这一点。代价是每次调用一次堆分配，相对网盘子进程与网络 IO
/// 可以忽略。
///
/// 生命周期统一写成 `'a`（`&'a self` 与参数同一生命周期），因为返回的 future 会借用
/// 参数；若按省略规则只绑 `&self`，实现里的异步块就没法捕获 `oid`。
pub type StoreFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, StoreError>> + Send + 'a>>;

/// 对象元信息；当前只有大小，按后端能力再扩。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub struct ObjectMeta {
    /// 对象字节数。
    pub size: u64,
}

impl ObjectMeta {
    /// 由字节数构造。
    pub fn new(size: u64) -> Self {
        Self { size }
    }
}

/// 存储后端的配额（字节），供监控使用。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Quota {
    /// 总容量。
    pub total: u64,
    /// 已用容量。
    pub used: u64,
}

impl Quota {
    /// 由总量与已用量构造。
    pub fn new(total: u64, used: u64) -> Self {
        Self { total, used }
    }

    /// 剩余容量；`used` 超过 `total` 时按 0 处理，不返回负数。
    pub fn free(&self) -> u64 {
        self.total.saturating_sub(self.used)
    }
}

/// 对象存储抽象。
///
/// 所有实现都必须守住同一份内容寻址契约：
///
/// - [`put`](Self::put)：先校验本地文件的 sha256 等于 oid，**校验通过才写最终路径**；
///   禁止「先落最终路径再校验」。oid 已存在时幂等成功，不重复上传。
/// - [`fetch`](Self::fetch)：完成后 `dest` 的 sha256 必须等于 oid，否则返回
///   [`StoreError::HashMismatch`]，且不留下坏文件。
/// - [`delete`](Self::delete)：oid 不存在时幂等成功。只用于清理上传中转与测试，
///   业务上不删除已发布对象。
/// - [`exists`](Self::exists)：`None` 表示不存在，不是错误。
/// - [`quota`](Self::quota)：后端没有配额概念时返回 [`StoreError::Unimplemented`]，
///   而不是伪装成成功。
pub trait ObjectStore: Send + Sync {
    /// 探测对象是否存在；存在时返回其元信息。
    fn exists<'a>(&'a self, oid: &'a Oid) -> StoreFuture<'a, Option<ObjectMeta>>;

    /// 把本地文件写入后端；实现方必须先校验哈希再落最终路径。
    fn put<'a>(&'a self, oid: &'a Oid, local_source: &'a Path) -> StoreFuture<'a, ()>;

    /// 把对象下载到本地 `dest`；完成后 `dest` 的哈希必须等于 oid。
    fn fetch<'a>(&'a self, oid: &'a Oid, dest: &'a Path) -> StoreFuture<'a, ()>;

    /// 删除对象；不存在时幂等成功。
    fn delete<'a>(&'a self, oid: &'a Oid) -> StoreFuture<'a, ()>;

    /// 查询后端配额。
    fn quota(&self) -> StoreFuture<'_, Quota>;
}

#[cfg(test)]
mod tests {
    use super::{OBJECTS_DIR, object_path};
    use crate::store::Oid;

    #[test]
    fn given_oid_when_object_path_then_two_level_fanout_and_plain_name() {
        let raw = format!("{}{}", "aabbccdd", "0".repeat(56));
        let oid = Oid::parse(&raw).expect("合法 oid");

        assert_eq!(object_path(&oid), format!("{OBJECTS_DIR}/aa/bb/{raw}"));
    }

    #[test]
    fn given_same_oid_when_object_path_twice_then_stable() {
        let oid = Oid::parse(&"0".repeat(64)).expect("合法 oid");

        assert_eq!(object_path(&oid), object_path(&oid));
        assert_eq!(object_path(&oid), format!("{OBJECTS_DIR}/00/00/{oid}"));
    }
}

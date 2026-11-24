//! 本地磁盘读缓存：目录布局、LRU 索引与启动清理。
//!
//! 契约见 `specs/storage.md`「缓存策略」「下载状态机」与 `specs/architecture.md`
//! 「失败模式」。三条不可妥协的规则：
//!
//! - **缓存可随时清空，正确性不变**：缓存只是加速层，删光目录后下一次 GET 会重新从
//!   后端拉取。因此缓存侧的失败一律降级（记 warn）而不是让请求失败；
//! - **只读命中不写盘**：访问序记在内存（[`lru::LruIndex`]），不依赖 `atime`；
//!   命中路径只有一次 `metadata`（按索引里的大小校验实际文件），不修改缓存文件。
//!
//! 分工：`lru` 是纯内存索引，`store` 是 [`Cache`] 本体（命中校验与预算驱逐），
//! `sweep` 是启动扫描与陈旧中转文件清理。

mod lru;
mod store;
mod sweep;

pub use store::Cache;
pub use sweep::SweepReport;

use std::path::{Path, PathBuf};

use crate::store::Oid;

/// 下载中转文件后缀；缓存对象本身**不带**这个后缀。
pub(crate) const PART_EXTENSION: &str = "part";

/// 启动清理的年龄阈值：`specs/storage.md`「进程崩溃恢复」定为 1 小时。
///
/// 只删「超龄」的残留下载中转文件，避免误删另一个请求正在写的文件——在途文件的
/// mtime 一直在更新，不会超龄。
pub(crate) const STALE_PART_AGE: std::time::Duration = std::time::Duration::from_secs(3600);

/// 缓存对象的本地路径：`<root>/<aa>/<bb>/<oid>`。
///
/// 分片与 `store::object_path` 同一规则（都只从 [`Oid::shards`] 取），但本地缓存
/// 没有 `objects/` 这一段——`specs/storage.md` 的本地布局是
/// `cache/<aa>/<bb>/<oid>`。布局只在这一个函数里实现，扫描与读写都调用它，避免
/// 「扫描认为在 A、读的时候去 B」这种索引与磁盘对不上的问题。
pub(crate) fn object_file(root: &Path, oid: &Oid) -> PathBuf {
    let (first, second) = oid.shards();
    root.join(first).join(second).join(oid.as_str())
}

//! 启动扫描与陈旧中转文件清理。
//!
//! 两件事分开做，因为它们的失败代价不同：
//!
//! - [`scan`] 重建索引，失败说明缓存目录本身不可用（权限、被当成文件），此时由
//!   [`Cache::open`](crate::cache::Cache::open) 把缓存降级为直通，服务照常启动；
//! - [`remove_stale_parts`] 删超龄的 `*.part` 残留，是纯清理动作，删不掉的只记
//!   warn——残留文件只占磁盘，不影响正确性。

use std::io;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use tokio::fs;

use super::{PART_EXTENSION, object_file};
use crate::store::Oid;

/// 启动清理的结果，供启动日志记录。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct SweepReport {
    /// 删除的超龄 `.part` 文件数。
    pub stale_parts: u64,
    /// 超龄 `.part` 释放的字节数。
    pub stale_bytes: u64,
    /// 为把用量收敛回预算而驱逐的对象数。
    pub evicted_objects: u64,
}

/// 过期 `.part` 清理的统计。
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub(crate) struct PartSweep {
    /// 删除的文件数。
    pub(crate) removed: u64,
    /// 释放的字节数。
    pub(crate) bytes: u64,
}

/// 扫描缓存目录，按对象最后修改时间升序返回 `(oid, size)`。
///
/// 只认「路径正好是 `<root>/<aa>/<bb>/<oid>`」的文件：
///
/// - 名字像 oid 但放在别处的文件不进索引——[`Cache::get`](crate::cache::Cache::get)
///   按 oid 推导路径，索引里放一个推导不出来的路径等于永远命不中，还会让
///   `used_bytes` 与磁盘对不上；
/// - `.part` 是未提交的中转文件，一律跳过（`used_bytes` 不把它算成缓存对象）。
///
/// 排序用 mtime：缓存命中不写盘，所以 mtime 近似「写入缓存的时刻」，比目录遍历
/// 顺序更接近真实的 LRU 次序。索引序号按这个顺序分配，最旧的先被淘汰。
pub(crate) async fn scan(root: &Path) -> io::Result<Vec<(Oid, u64)>> {
    let mut found: Vec<(SystemTime, Oid, u64)> = Vec::new();
    let mut pending: Vec<PathBuf> = vec![root.to_path_buf()];
    while let Some(dir) = pending.pop() {
        let mut entries = match fs::read_dir(&dir).await {
            Ok(entries) => entries,
            // 扫描期间目录被清空（缓存可随时清空）属于预期，不是错误。
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => return Err(error),
        };
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            if file_type.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !file_type.is_file() {
                // 符号链接等一律不索引：跟着链接读可能读到目录外的内容。
                continue;
            }
            let path = entry.path();
            let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
                continue;
            };
            let Ok(oid) = Oid::parse(name) else {
                tracing::debug!(path = %path.display(), "缓存目录里跳过非对象文件");
                continue;
            };
            if path != object_file(root, &oid) {
                tracing::warn!(
                    path = %path.display(),
                    expected = %object_file(root, &oid).display(),
                    "缓存目录里的对象不在既定分片路径上，跳过不索引"
                );
                continue;
            }
            let meta = entry.metadata().await?;
            // 拿不到 mtime 时按最旧处理：宁可先淘汰它，也不要让它永远占着预算。
            let modified = meta.modified().unwrap_or(SystemTime::UNIX_EPOCH);
            found.push((modified, oid, meta.len()));
        }
    }

    found.sort_by_key(|(modified, _, _)| *modified);
    Ok(found.into_iter().map(|(_, oid, size)| (oid, size)).collect())
}

/// 删除目录（递归）内最后修改时间早于 `max_age` 的 `*.part` 文件。
///
/// `max_age` 之外的文件是**在途**下载，绝不删：在途文件的 mtime 一直在更新。
/// 拿不到 mtime 的文件也留着，宁可多占一点磁盘，也不误删正在写的缓冲。
pub(crate) async fn remove_stale_parts(dir: &Path, max_age: Duration) -> PartSweep {
    let mut stats = PartSweep::default();
    let cutoff = SystemTime::now().checked_sub(max_age);
    let mut pending: Vec<PathBuf> = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let mut entries = match fs::read_dir(&current).await {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => continue,
            Err(error) => {
                tracing::warn!(dir = %current.display(), error = %error, "扫描残留中转文件失败");
                continue;
            },
        };
        loop {
            let entry = match entries.next_entry().await {
                Ok(Some(entry)) => entry,
                Ok(None) => break,
                Err(error) => {
                    tracing::warn!(dir = %current.display(), error = %error, "遍历残留中转文件失败");
                    break;
                },
            };
            let file_type = match entry.file_type().await {
                Ok(file_type) => file_type,
                Err(error) => {
                    tracing::debug!(path = %entry.path().display(), error = %error, "跳过无法判型的目录项");
                    continue;
                },
            };
            if file_type.is_dir() {
                pending.push(entry.path());
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let path = entry.path();
            if path.extension().is_none_or(|ext| ext != PART_EXTENSION) {
                continue;
            }
            let meta = entry.metadata().await.ok();
            let stale = match (cutoff, meta.as_ref().and_then(|meta| meta.modified().ok())) {
                (Some(cutoff), Some(modified)) => modified < cutoff,
                // 系统时钟异常（now - 1h 下溢）或 mtime 不可读：不删。
                _ => false,
            };
            if !stale {
                continue;
            }
            let size = meta.map_or(0, |meta| meta.len());
            match fs::remove_file(&path).await {
                Ok(()) => {
                    stats.removed = stats.removed.saturating_add(1);
                    stats.bytes = stats.bytes.saturating_add(size);
                    tracing::debug!(path = %path.display(), "删除超龄的中转文件");
                },
                Err(error) if error.kind() == ErrorKind::NotFound => {},
                Err(error) => {
                    tracing::warn!(path = %path.display(), error = %error, "删除超龄中转文件失败");
                },
            }
        }
    }
    stats
}

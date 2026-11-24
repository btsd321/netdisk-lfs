//! [`Cache`] 本体：命中校验、预算驱逐、启动扫描与收敛。
//!
//! 设计要点（与 `specs/storage.md`「缓存策略」逐条对应）：
//!
//! - **索引是内存里的唯一真相**：启动扫描重建（[`Cache::open`]），运行中插入/命中/
//!   驱逐增量维护；`used_bytes` 与 `max_bytes` 比较决定是否驱逐；
//! - **命中按索引大小校验实际文件**：不符就驱逐并视为未命中（规格「命中但校验失败
//!   则驱逐重下」）。这是按大小校验，同大小的内容损坏查不出来——内容完整性由
//!   `store.fetch` 落盘前那次 sha256 负责，缓存驻留期间不重复哈希（4 GiB 对象每读
//!   一遍都算一遍哈希没有意义）；
//! - **只读命中不写盘**：命中只动内存里的访问序号，不做任何文件写入；
//! - **缓存可随时清空**：索引与磁盘对不上时以「驱逐 + 当未命中」自愈，清空目录后
//!   下一次请求重新回源。

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::fs;

use super::lru::LruIndex;
use super::sweep::{self, SweepReport};
use super::{STALE_PART_AGE, object_file};
use crate::config::CacheConfig;
use crate::store::Oid;

/// 本地磁盘读缓存。
///
/// 内部是 `Arc`，`clone` 只加一次引用计数，可以随便放进 `AppState`、测试与后台任务。
#[derive(Clone)]
pub struct Cache {
    inner: Arc<Inner>,
}

/// 缓存的不可变配置与可变状态。
struct Inner {
    /// 缓存根目录。
    root: PathBuf,
    /// 预算（字节）。
    max_bytes: u64,
    /// LRU 索引；临界区只有内存操作，绝不跨 `.await` 持锁。
    index: Mutex<LruIndex>,
    /// `false` 表示启动扫描失败、降级为直通：不读不写缓存，只把对象下载到临时文件。
    enabled: bool,
}

impl Cache {
    /// 按配置打开缓存：创建目录、扫描重建索引与访问序。
    ///
    /// 扫描或建目录失败**不会**返回错误，而是记 warn 后降级为直通（不读写缓存）：
    /// 缓存可随时清空、清空不影响正确性，所以它的故障不应该阻止服务启动
    /// （`specs/architecture.md`「失败模式」）。
    pub async fn open(config: &CacheConfig) -> Self {
        if let Err(error) = fs::create_dir_all(&config.dir).await {
            tracing::warn!(
                dir = %config.dir.display(),
                error = %error,
                "创建缓存目录失败，本次启动降级为直通（不读写缓存）"
            );
            return Self::with_index(config, LruIndex::default(), false);
        }
        match sweep::scan(&config.dir).await {
            Ok(items) => {
                let mut index = LruIndex::default();
                index.load(items);
                tracing::debug!(
                    dir = %config.dir.display(),
                    objects = index.len(),
                    used_bytes = index.used_bytes(),
                    "缓存索引重建完成"
                );
                Self::with_index(config, index, true)
            },
            Err(error) => {
                tracing::warn!(
                    dir = %config.dir.display(),
                    error = %error,
                    "扫描缓存目录失败，本次启动降级为直通（不读写缓存）"
                );
                Self::with_index(config, LruIndex::default(), false)
            },
        }
    }

    /// 索引为空且不扫描目录的缓存。
    ///
    /// 只给测试与嵌入用法（`AppState::new`）：生产启动必须走 [`Cache::open`]，否则
    /// 磁盘上已有的缓存对象既不知道大小、也进不了 LRU。
    pub fn empty(config: &CacheConfig) -> Self {
        Self::with_index(config, LruIndex::default(), true)
    }

    /// 两个构造入口共用。
    fn with_index(config: &CacheConfig, index: LruIndex, enabled: bool) -> Self {
        Self {
            inner: Arc::new(Inner {
                root: config.dir.clone(),
                max_bytes: config.max_bytes,
                index: Mutex::new(index),
                enabled,
            }),
        }
    }

    /// 缓存根目录。
    pub fn root(&self) -> &Path {
        &self.inner.root
    }

    /// 缓存预算（字节）。
    pub fn max_bytes(&self) -> u64 {
        self.inner.max_bytes
    }

    /// 索引里记账的字节数。
    pub fn used_bytes(&self) -> u64 {
        self.index().used_bytes()
    }

    /// 索引里的对象数。
    pub fn len(&self) -> usize {
        self.index().len()
    }

    /// 缓存是否为空。
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// 缓存是否可用；`false` 表示已降级为直通。
    pub fn is_enabled(&self) -> bool {
        self.inner.enabled
    }

    /// 缓存对象的本地路径：`<root>/<aa>/<bb>/<oid>`。
    pub fn path(&self, oid: &Oid) -> PathBuf {
        object_file(&self.inner.root, oid)
    }

    /// 查缓存：命中返回本地路径，未命中返回 `None`。
    ///
    /// 命中要按索引里的大小校验实际文件：大小不符说明文件被截断/替换/外部改过，
    /// 按规格驱逐后当作未命中重新下载。校验失败或文件消失只影响这一次请求，
    /// 不向上报错——缓存坏了不是请求的错。
    pub async fn get(&self, oid: &Oid) -> Option<PathBuf> {
        if !self.inner.enabled {
            return None;
        }
        // 先记访问序再校验：命中路径上不做任何文件写入（「只读命中不写盘」）。
        // `touch` 的返回值在 `?` 处提前返回 `None`（索引里没有这个 oid）。
        let expected = { self.index().touch(oid)? };

        let path = self.path(oid);
        match fs::metadata(&path).await {
            Ok(meta) if meta.is_file() && meta.len() == expected => Some(path),
            Ok(meta) => {
                tracing::warn!(
                    oid = %oid,
                    expected,
                    actual = meta.len(),
                    "缓存文件大小与索引不符，驱逐后重新下载"
                );
                self.forget(oid);
                None
            },
            Err(error) if error.kind() == ErrorKind::NotFound => {
                tracing::debug!(oid = %oid, path = %path.display(), "索引里有但磁盘上已没有，丢弃索引项");
                self.forget(oid);
                None
            },
            Err(error) => {
                tracing::warn!(
                    oid = %oid,
                    path = %path.display(),
                    error = %error,
                    "读取缓存文件元信息失败，按未命中处理"
                );
                None
            },
        }
    }

    /// 丢掉索引项（**不删文件**），返回记账时的大小。用于命中后发现文件已不可用的场景。
    pub fn forget(&self, oid: &Oid) -> Option<u64> {
        self.index().remove(oid)
    }

    /// 启动清理：删超龄 `.part` 残留，再按预算做一次 LRU 收敛。
    ///
    /// `extra_dirs` 是缓存目录之外的清理目标（上传缓冲目录 `data_dir/upload`）。
    /// 永不返回错误：清理失败只记 warn，绝不阻止服务启动。
    pub async fn sweep(&self, extra_dirs: &[PathBuf]) -> SweepReport {
        let mut report = SweepReport::default();
        let mut dirs = vec![self.inner.root.clone()];
        dirs.extend(extra_dirs.iter().cloned());
        for dir in &dirs {
            let stats = sweep::remove_stale_parts(dir, STALE_PART_AGE).await;
            report.stale_parts = report.stale_parts.saturating_add(stats.removed);
            report.stale_bytes = report.stale_bytes.saturating_add(stats.bytes);
        }

        if !self.inner.enabled {
            return report;
        }
        // 预算被调小、或旧版本留下了过量对象时，这里一次性收敛到预算之内。
        let victims = {
            let mut index = self.index();
            collect_over_budget(&mut index, self.inner.max_bytes)
        };
        report.evicted_objects = victims.len() as u64;
        self.unlink(victims).await;
        report
    }

    /// 索引守卫；持锁期间只做内存操作（调用方必须保证不跨 `.await`）。
    fn index(&self) -> MutexGuard<'_, LruIndex> {
        // 索引只在内存里改，某个线程 panic 不会让索引进入「磁盘与记账不一致」的
        // 状态，所以中毒后继续用（`into_inner`）比让所有请求 500 更合理。
        self.inner.index.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// 删除被驱逐对象。删不掉不算错误：索引已经丢弃，启动扫描会重新收敛。
    async fn unlink(&self, victims: Vec<(Oid, u64)>) {
        for (victim, size) in victims {
            let path = self.path(&victim);
            match fs::remove_file(&path).await {
                Ok(()) => tracing::debug!(oid = %victim, size, "LRU 驱逐缓存对象"),
                Err(error) if error.kind() == ErrorKind::NotFound => {},
                Err(error) => tracing::warn!(
                    oid = %victim,
                    path = %path.display(),
                    error = %error,
                    "删除被驱逐的缓存对象失败（索引已丢弃，重启扫描会重新收敛）"
                ),
            }
        }
    }
}

/// 把超出预算的最久未访问对象摘出索引，返回待删除清单。
///
/// 调用方持锁，所以这里只改内存、不删文件；文件删除由 [`Cache::unlink`] 在锁外做。
fn collect_over_budget(index: &mut LruIndex, max_bytes: u64) -> Vec<(Oid, u64)> {
    let mut victims = Vec::new();
    while index.used_bytes() > max_bytes {
        let Some((victim, size)) = index.oldest() else {
            break;
        };
        index.remove(&victim);
        victims.push((victim, size));
    }
    victims
}

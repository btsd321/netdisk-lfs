//! [`Cache`] 本体：命中校验、单飞下载、预算驱逐与启动收敛。
//!
//! 设计要点（与 `specs/storage.md`「缓存策略」「下载状态机」逐条对应）：
//!
//! - **索引是内存里的唯一真相**：启动扫描重建（[`Cache::open`]），运行中插入/命中/
//!   驱逐增量维护；`used_bytes` 与 `max_bytes` 比较决定是否驱逐；
//! - **命中按索引大小校验实际文件**：不符就驱逐并视为未命中（规格「命中但校验失败
//!   则驱逐重下」）。这是按大小校验，同大小的内容损坏查不出来——内容完整性由
//!   `store.fetch` 落盘前那次 sha256 负责，缓存驻留期间不重复哈希（4 GiB 对象每读
//!   一遍都算一遍哈希没有意义）；
//! - **只读命中不写盘**：命中只动内存里的访问序号，不做任何文件写入；
//! - **单飞按 oid 分片**：256 把 `tokio::sync::Mutex`，同一 oid 的并发未命中只有一个
//!   真正下载，其余排队后二次检查命中。等待者被丢弃只是取消它的排队，不影响在途
//!   fetch；持锁者被丢弃时锁自动释放、下一个请求重下，`.part` 由守卫与启动扫描兜底
//!   （取消安全）；
//! - **要么完整要么不存在**：下载写 `<oid>.part`，校验通过才 `rename` 到最终路径。
//!
//! 另有一组只读计数器（[`Cache::hits_total`] / [`Cache::misses_total`] /
//! [`Cache::evictions_total`]）供 `/metrics` 观测：只做 `Relaxed` 累加，不参与任何
//! 决策，也不改变命中/驱逐的既有语义。

use std::future::Future;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};

use tokio::fs;
use tokio::sync::Mutex as AsyncMutex;

use super::lru::LruIndex;
use super::sweep::{self, SweepReport};
use super::{PART_EXTENSION, STALE_PART_AGE, object_file, transient_dir};
use crate::config::CacheConfig;
use crate::store::{Oid, StoreError};

/// 单飞锁的分片数：oid 前两个十六进制字符的取值空间。
///
/// 分片而不是「一个 oid 一把锁」：后者要一个会无限增长的锁表，还要处理锁的回收；
/// 分片把内存与复杂度都固定住，代价只有「极少数不相关 oid 互相等一下」。
const SHARDS: usize = 256;

/// 中转文件名序号：`Transient` 结果会一直活到响应体发送完毕，同一 oid 的并发请求
/// 绝不能共用同一个中转文件——后到的 `fetch` 会截断前一个正在流式发送的文件。
///
/// 序号只保证进程内唯一；崩溃残留由启动扫描按「超龄 1 小时」清除，数量上限是
/// 进程生命周期内的请求数，不会无限堆积。
static PART_SEQ: AtomicU64 = AtomicU64::new(0);

fn next_part_seq() -> u64 {
    PART_SEQ.fetch_add(1, Ordering::Relaxed)
}

/// 一次取数的结果。
#[non_exhaustive]
pub enum CachedFile {
    /// 已提交进 LRU 缓存：响应结束后**不要**删除这个文件。
    Cached(PathBuf),
    /// 未入缓存（超过预算或缓存已降级）：这是本次请求私有的临时文件，调用方负责删除。
    Transient(PathBuf),
}

impl CachedFile {
    /// 本地文件路径。
    pub fn path(&self) -> &Path {
        match self {
            Self::Cached(path) | Self::Transient(path) => path,
        }
    }

    /// 是否已进缓存（调用方据此决定响应结束后是否删文件）。
    pub fn is_cached(&self) -> bool {
        matches!(self, Self::Cached(_))
    }
}

impl std::fmt::Debug for CachedFile {
    /// 只暴露形态与路径，避免把整个文件内容带进日志的错觉。
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let kind = if self.is_cached() { "Cached" } else { "Transient" };
        f.debug_tuple(kind).field(&self.path()).finish()
    }
}

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
    /// 按 oid 分片的单飞锁。
    shards: Box<[AsyncMutex<()>]>,
    /// `false` 表示启动扫描失败、降级为直通：不读不写缓存，只把对象下载到临时文件。
    enabled: bool,
    /// [`Cache::get`] 命中次数（观测用，详见 [`Cache::hits_total`]）。
    hits: AtomicU64,
    /// [`Cache::get`] 未命中次数。
    misses: AtomicU64,
    /// 真正删掉的被驱逐对象数（含启动收敛时的淘汰）。
    evictions: AtomicU64,
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
        let shards =
            (0..SHARDS).map(|_| AsyncMutex::new(())).collect::<Vec<_>>().into_boxed_slice();
        Self {
            inner: Arc::new(Inner {
                root: config.dir.clone(),
                max_bytes: config.max_bytes,
                index: Mutex::new(index),
                shards,
                enabled,
                hits: AtomicU64::new(0),
                misses: AtomicU64::new(0),
                evictions: AtomicU64::new(0),
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

    /// [`Self::get`] 的命中次数。
    ///
    /// 只统计走 `get` 的查询：`fetch_once` 内部的「二次检查」用不计数的
    /// [`Self::lookup`]，否则一次并发冷读会同时记成 1 次未命中（外层）与 1 次未命中
    /// （锁内二次检查），未命中率被系统性高估。降级模式（`is_enabled() == false`）
    /// 不读写缓存，也不计数——否则会把「缓存没开」算成 100% 未命中。
    pub fn hits_total(&self) -> u64 {
        self.inner.hits.load(Ordering::Relaxed)
    }

    /// [`Self::get`] 的未命中次数；统计口径同 [`Self::hits_total`]。
    pub fn misses_total(&self) -> u64 {
        self.inner.misses.load(Ordering::Relaxed)
    }

    /// 被驱逐（真的从磁盘删掉）的缓存对象数。
    ///
    /// 只数删除成功的那些：索引已丢弃但文件本来就不在（`NotFound`）不算驱逐，
    /// 否则「磁盘上没有的对象」也会被计入淘汰量。
    pub fn evictions_total(&self) -> u64 {
        self.inner.evictions.load(Ordering::Relaxed)
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
    ///
    /// 命中/未命中在这里记计数器（`/metrics` 的数据源）；降级模式直接返回 `None`
    /// 且不计数，理由见 [`Self::hits_total`]。
    pub async fn get(&self, oid: &Oid) -> Option<PathBuf> {
        if !self.inner.enabled {
            return None;
        }
        match self.lookup(oid).await {
            Some(path) => {
                self.inner.hits.fetch_add(1, Ordering::Relaxed);
                Some(path)
            },
            None => {
                self.inner.misses.fetch_add(1, Ordering::Relaxed);
                None
            },
        }
    }

    /// [`Self::get`] 的实现，**不**动计数器。
    ///
    /// 单飞锁内的二次检查与 GET 前置检查走同一份逻辑却只该记一次，所以计数留在
    /// 公开的 `get` 上，内部重复查询走这里。
    async fn lookup(&self, oid: &Oid) -> Option<PathBuf> {
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

    /// 取一个对象：命中直接返回；未命中则在同一 oid 上**只触发一次** `fetch`。
    ///
    /// `fetch` 收到中转文件路径（`<oid>.part`，降级模式下在系统临时目录），负责把
    /// 对象写进去；写成功后本函数负责校验大小、`rename` 进缓存、记账并按预算驱逐。
    /// 哈希校验不在这里重复：`ObjectStore::fetch` 的契约就是「完成后 `dest` 的
    /// sha256 必须等于 oid」，两处各算一遍只是浪费一遍 4 GiB 的读。
    ///
    /// # Errors
    /// `fetch` 的失败原样返回（后端错误、哈希不符、IO 失败）。失败时不留中转文件，
    /// 也不会在缓存里留下任何索引项——404 之类的结果不会被缓存成负面结果。
    pub async fn fetch_once<F, Fut>(&self, oid: &Oid, fetch: F) -> Result<CachedFile, StoreError>
    where
        F: FnOnce(PathBuf) -> Fut + Send,
        Fut: Future<Output = Result<(), StoreError>> + Send,
    {
        if let Some(path) = self.lookup(oid).await {
            return Ok(CachedFile::Cached(path));
        }

        // 单飞：同一 oid 的并发未命中在这里排队。等待者被丢弃只取消它自己的排队，
        // 在途 fetch 不受影响；持锁者被丢弃时锁随守卫释放，后到的请求重新下载。
        let serialized = self.shard(oid).lock().await;

        // 二次检查：排到我们时，前一个请求可能已经把对象放进来了。
        if let Some(path) = self.lookup(oid).await {
            return Ok(CachedFile::Cached(path));
        }

        let part = self.part_path(oid);
        let part = match self.ensure_part_parent(&part).await {
            Ok(()) => part,
            Err(error) => {
                // 缓存侧失败一律降级（模块契约）：改走临时目录直通，请求照常完成。
                tracing::warn!(
                    path = %part.display(),
                    error = %error,
                    "缓存中转目录不可用，本次改走临时目录直通"
                );
                let fallback = self.transient_part_path(oid);
                self.ensure_part_parent(&fallback)
                    .await
                    .map_err(|error| StoreError::io(&fallback, error))?;
                fallback
            },
        };
        let guard = PartFile::new(part.clone());
        fetch(part.clone()).await?;
        let size = fs::metadata(&part).await.map_err(|error| StoreError::io(&part, error))?.len();

        // 降级模式：不建索引，直接把中转文件交出去（由调用方在响应结束后删除）。
        if !self.inner.enabled {
            return Ok(CachedFile::Transient(guard.hand_over()));
        }

        // 单个对象比整个预算还大：缓存它只会立刻把自己驱逐掉，不如直通返回。
        // 这不是错误，请求照常成功（规格：不得报错，记 warn）。
        if size > self.inner.max_bytes {
            tracing::warn!(
                oid = %oid,
                size,
                max_bytes = self.inner.max_bytes,
                "对象大于缓存预算，本次直通返回且不入缓存"
            );
            return Ok(CachedFile::Transient(guard.hand_over()));
        }

        let target = self.path(oid);
        // 同目录 rename 是原子的：要么没有，要么是完整对象（先 `.part` 再 rename）。
        // 失败同样按缓存侧降级处理：文件还完整地在 part 上，直通交出去，
        // 不能因为「缓存写不进去」让一个已经哈希校验通过的下载失败。
        if let Err(error) = fs::rename(&part, &target).await {
            tracing::warn!(
                oid = %oid,
                path = %target.display(),
                error = %error,
                "rename 进缓存失败，本次直通返回"
            );
            return Ok(CachedFile::Transient(guard.hand_over()));
        }
        // rename 已把文件移走，Drop 只会在旧路径上删一个不存在的文件（NotFound 静默）。
        drop(guard);

        // 记账与预算驱逐也在锁内做完（纯内存操作）：先放锁再记账会留一个窗口，
        // 排队者醒来时看到未命中，会把同一份 4 GiB 再完整下载一遍。
        // 文件删除是 IO，放到锁外做。
        let victims = {
            let mut index = self.index();
            index.insert(oid, size);
            collect_over_budget(&mut index, self.inner.max_bytes)
        };
        drop(serialized);
        self.unlink(victims).await;
        Ok(CachedFile::Cached(target))
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

    /// 中转文件路径。
    ///
    /// 正常模式与最终对象同目录（同目录 `rename` 才是原子的），文件名追加进程内
    /// 序号：`Transient` 结果（超预算/降级/rename 失败）会一直活到响应体发送完毕，
    /// 若与下一次同 oid 下载同名，后者的 `create` 会截断前者正在发送的内容。
    /// 降级模式落到 [`transient_dir`] 专用子目录，由启动清理覆盖。
    fn part_path(&self, oid: &Oid) -> PathBuf {
        if self.inner.enabled {
            self.path(oid).with_extension(format!("{}.{PART_EXTENSION}", next_part_seq()))
        } else {
            self.transient_part_path(oid)
        }
    }

    /// 降级/回退的中转文件路径：专用临时子目录 + 唯一序号。
    fn transient_part_path(&self, oid: &Oid) -> PathBuf {
        transient_dir().join(format!("{oid}.{}.{PART_EXTENSION}", next_part_seq()))
    }

    /// 确保中转文件的父目录存在。
    async fn ensure_part_parent(&self, part: &Path) -> std::io::Result<()> {
        match part.parent() {
            Some(parent) => fs::create_dir_all(parent).await,
            None => Ok(()),
        }
    }

    /// oid 所属的单飞分片。
    fn shard(&self, oid: &Oid) -> &AsyncMutex<()> {
        // `Oid` 保证前两个字符是十六进制，`from_str_radix` 不会失败；兜底分片 0
        // 只是为了不在生产路径上 `unwrap`。
        let index = usize::from_str_radix(oid.prefix2(), 16).unwrap_or(0);
        &self.inner.shards[index % SHARDS]
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
                Ok(()) => {
                    self.inner.evictions.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(oid = %victim, size, "LRU 驱逐缓存对象");
                },
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

/// 下载中转文件的守卫。
///
/// 成功路径上 `rename` 把文件移走，之后 Drop 只是删一个不存在的路径（NotFound 静默）；
/// 失败或 future 被取消（客户端断连）时由 Drop 尽力删除。删不掉可以放心留给启动扫描：
/// 中转文件名带进程内序号，数量上限是进程生命周期内的请求数，启动清理会删掉超龄的
/// `*.part`。这里不在 Drop 里做 IO 等待——中转文件只在本请求内部使用，不存在 B5
/// 上传缓冲那种「句柄被延迟关闭」的竞态，因此不需要 `spawn_blocking` 重试。
struct PartFile {
    /// 中转文件路径。
    path: PathBuf,
}

impl PartFile {
    /// 绑定一个待清理路径（文件可以还不存在）。
    fn new(path: PathBuf) -> Self {
        Self { path }
    }

    /// 交出所有权：调用方（超预算直通/降级模式）负责在响应结束后删除。
    fn hand_over(self) -> PathBuf {
        let path = self.path.clone();
        // 不能只靠 Drop：`Drop` 会删掉刚交给调用方的文件。禁止析构是唯一办法。
        std::mem::forget(self);
        path
    }
}

impl Drop for PartFile {
    fn drop(&mut self) {
        match std::fs::remove_file(&self.path) {
            Ok(()) => {},
            Err(error) if error.kind() == ErrorKind::NotFound => {},
            Err(error) => tracing::warn!(
                path = %self.path.display(),
                error = %error,
                "清理下载中转文件失败，留给启动扫描"
            ),
        }
    }
}

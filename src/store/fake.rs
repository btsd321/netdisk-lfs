//! `FakeStore`：用本地真实文件模拟内容寻址的对象存储，供集成测试使用。
//!
//! 契约与真实后端一致（[`super::object_path`] 是唯一布局实现，put 先校验哈希、
//! fetch 后再校验），所以「上传 → 存在性 → 下载 → 删除」的完整回路可以在这里跑，
//! 而不必碰网盘。它是测试替身，允许走捷径：不限流、不重试、不做并发单飞。

use std::io::ErrorKind;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use tokio::fs;
use tokio::io::AsyncWriteExt;

use crate::store::{
    OBJECTS_DIR, ObjectMeta, ObjectStore, Oid, Quota, StoreError, StoreFuture, hash_file,
    object_path,
};

/// 进程内序号：保证同进程并发构造的临时根目录互不碰撞。
static ROOT_SEQ: AtomicU32 = AtomicU32::new(0);

/// 假配额总量：1 TiB。测试对象撑不满，监控路径也不会看起来「磁盘已满」。
const DEFAULT_QUOTA_TOTAL: u64 = 1_099_511_627_776;

/// 用本地真实文件模拟的内容寻址存储。
///
/// 构造时不落任何 IO：根目录与对象目录都在首次写入时按需创建，因此可以在
/// `#[tokio::test]` 里直接 `FakeStore::new()`。
pub struct FakeStore {
    root: PathBuf,
    /// 是否由本实例负责清理根目录（[`FakeStore::new`] 为真，[`FakeStore::with_root`] 为假）。
    owns_root: bool,
    /// 故障注入开关：下一次 fetch 把下载结果写坏，用完自动复位。
    corrupt_next_fetch: AtomicBool,
    /// [`ObjectStore::quota`] 返回的总容量。
    quota_total: u64,
}

impl FakeStore {
    /// 在系统临时目录下取一个唯一根目录；Drop 时递归删除。
    ///
    /// 独占创建（`create_dir`）：上次运行被 SIGKILL、`Drop` 没跑、OS 又复用了
    /// 同一 PID 时，陈旧目录会让脏对象混进本次测试——碰撞时换下一个序号
    /// 重试，而不是静默复用。
    pub fn new() -> Self {
        let pid = std::process::id();
        let mut seq = ROOT_SEQ.fetch_add(1, Ordering::Relaxed);
        loop {
            let root = std::env::temp_dir().join(format!("netdisk-lfs-fake-{pid}-{seq}"));
            match std::fs::create_dir(&root) {
                Ok(()) => return Self::build(root, true),
                Err(err) if err.kind() == ErrorKind::AlreadyExists => seq += 1,
                // 其它失败（如临时目录本身异常）退回尽力而为的创建。
                Err(_) => {
                    if let Err(fallback) = std::fs::create_dir_all(&root) {
                        tracing::warn!(
                            root = %root.display(),
                            error = %fallback,
                            "创建 FakeStore 根目录失败"
                        );
                    }
                    return Self::build(root, true);
                },
            }
        }
    }

    /// 用调用方给的根目录；不负责创建与清理，测试可自行往目录里摆文件。
    pub fn with_root(root: impl Into<PathBuf>) -> Self {
        Self::build(root.into(), false)
    }

    /// 两个构造入口共用，`owns_root` 决定 Drop 是否清理。
    fn build(root: PathBuf, owns_root: bool) -> Self {
        Self {
            root,
            owns_root,
            corrupt_next_fetch: AtomicBool::new(false),
            quota_total: DEFAULT_QUOTA_TOTAL,
        }
    }

    /// 根目录；对象位于其下的 `objects/` 子目录。
    pub fn root(&self) -> &Path {
        &self.root
    }

    /// 改配额总量（监控相关测试用）。
    pub fn with_quota_total(mut self, total: u64) -> Self {
        self.quota_total = total;
        self
    }

    /// 故障注入：下一次 [`fetch`](ObjectStore::fetch) 把下载结果写坏。
    ///
    /// 模拟 `bdpan`「报成功但内容截断」的静默失败，让上层确认失败被哈希校验抓住，
    /// 而不是靠退出码。只影响一次调用。
    pub fn inject_next_fetch_corruption(&self) {
        self.corrupt_next_fetch.store(true, Ordering::SeqCst);
    }

    /// 对象在本地根目录下的绝对路径。
    fn object_abs_path(&self, oid: &Oid) -> PathBuf {
        self.root.join(object_path(oid))
    }
}

impl Default for FakeStore {
    fn default() -> Self {
        Self::new()
    }
}

impl Drop for FakeStore {
    /// 删掉自己建的根目录；临时目录残留只影响磁盘，不该让测试 panic。
    fn drop(&mut self) {
        if !self.owns_root {
            return;
        }
        if let Err(err) = std::fs::remove_dir_all(&self.root) {
            tracing::warn!(root = %self.root.display(), error = %err, "清理 FakeStore 根目录失败");
        }
    }
}

impl ObjectStore for FakeStore {
    fn exists<'a>(&'a self, oid: &'a Oid) -> StoreFuture<'a, Option<ObjectMeta>> {
        Box::pin(async move {
            let target = self.object_abs_path(oid);
            match fs::metadata(&target).await {
                Ok(meta) if meta.is_file() => Ok(Some(ObjectMeta::new(meta.len()))),
                // 同名目录属于布局被污染的异常情形，按「不存在」处理即可，
                // 后续 put 会在 rename 时暴露真实原因。
                Ok(_) => Ok(None),
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(None),
                Err(err) => Err(StoreError::io(&target, err)),
            }
        })
    }

    fn put<'a>(&'a self, oid: &'a Oid, local_source: &'a Path) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            // 契约第一条：先校验来源文件的哈希，再谈落盘位置。
            let digest =
                hash_file(local_source).await.map_err(|err| StoreError::io(local_source, err))?;
            if digest != oid.as_str() {
                return Err(StoreError::hash_mismatch(oid, &digest));
            }

            let target = self.object_abs_path(oid);
            if fs::metadata(&target).await.is_ok_and(|meta| meta.is_file()) {
                // 幂等：同一 oid 的内容必然相同，不必重写。
                return Ok(());
            }

            let Some(parent) = target.parent() else {
                // object_path 固定生成两级父目录，走到这里说明布局实现坏了。
                return Err(StoreError::io(&target, std::io::Error::other("对象路径缺少父目录")));
            };
            fs::create_dir_all(parent).await.map_err(|err| StoreError::io(parent, err))?;

            // 先写同目录的 .part 再 rename：中途失败不会在最终路径留下半个对象。
            // Drop 守卫兜底「future 被取消」（超时/断连）时的清理——与
            // FakeStore::drop 一样用同步删除，这里是一次 unlink，测试替身可接受。
            let staging = target.with_extension("part");
            let guard = StagingGuard(staging.clone());
            if let Err(err) = fs::copy(local_source, &staging).await {
                return Err(StoreError::io(&staging, err));
            }
            if let Err(err) = fs::rename(&staging, &target).await {
                return Err(StoreError::io(&target, err));
            }
            guard.disarm();
            Ok(())
        })
    }

    fn fetch<'a>(&'a self, oid: &'a Oid, dest: &'a Path) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let source = self.object_abs_path(oid);
            let exists = fs::metadata(&source).await.map_err(|err| match err.kind() {
                ErrorKind::NotFound => StoreError::NotFound { oid: oid.clone() },
                _ => StoreError::io(&source, err),
            })?;
            if !exists.is_file() {
                return Err(StoreError::NotFound { oid: oid.clone() });
            }
            if let Some(parent) = dest.parent().filter(|parent| !parent.as_os_str().is_empty()) {
                fs::create_dir_all(parent).await.map_err(|err| StoreError::io(parent, err))?;
            }

            // 从 copy 开始，dest 可能已被写入：此后任何失败都必须清掉，
            // 保证调用方看到的 dest「要么没动过、要么是完整且校验通过的对象」。
            // copy 之前的失败（NotFound 等）不删 dest——那时还没写任何东西。
            let outcome = async {
                fs::copy(&source, dest).await.map_err(|err| StoreError::io(dest, err))?;
                if self.corrupt_next_fetch.swap(false, Ordering::SeqCst) {
                    append_garbage(dest).await?;
                }
                let digest = hash_file(dest).await.map_err(|err| StoreError::io(dest, err))?;
                if digest != oid.as_str() {
                    return Err(StoreError::hash_mismatch(oid, &digest));
                }
                Ok(())
            }
            .await;
            match outcome {
                Ok(()) => Ok(()),
                Err(err) => {
                    discard(dest).await;
                    Err(err)
                },
            }
        })
    }

    fn delete<'a>(&'a self, oid: &'a Oid) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let target = self.object_abs_path(oid);
            match fs::remove_file(&target).await {
                Ok(()) => Ok(()),
                // 幂等：本来就没有的东西，删除也算成功。
                Err(err) if err.kind() == ErrorKind::NotFound => Ok(()),
                Err(err) => Err(StoreError::io(&target, err)),
            }
        })
    }

    fn quota(&self) -> StoreFuture<'_, Quota> {
        Box::pin(async move {
            let objects_root = self.root.join(OBJECTS_DIR);
            let used =
                dir_size(&objects_root).await.map_err(|err| StoreError::io(&objects_root, err))?;
            Ok(Quota::new(self.quota_total, used))
        })
    }
}

/// 删掉一个临时文件；失败只记日志——此时调用方已经在返回另一个错误了。
async fn discard(path: &Path) {
    if let Err(err) = fs::remove_file(path).await {
        tracing::warn!(path = %path.display(), error = %err, "清理临时文件失败");
    }
}

/// 上传 `.part` 中转文件的兜底守卫：正常路径完成后 [`Self::disarm`]，异常返回
/// 或 future 被取消（Drop）时删除中转文件，避免半截对象泄漏进 objects 树。
struct StagingGuard(PathBuf);

impl StagingGuard {
    /// 成功路径：中转文件已 rename 走，解除守卫。
    fn disarm(self) {
        std::mem::forget(self);
    }
}

impl Drop for StagingGuard {
    fn drop(&mut self) {
        // rename 成功后 staging 已不存在，remove 报 NotFound 属预期，静默即可。
        if let Err(err) = std::fs::remove_file(&self.0)
            && err.kind() != ErrorKind::NotFound
        {
            tracing::warn!(path = %self.0.display(), error = %err, "清理 .part 中转文件失败");
        }
    }
}

/// 往文件尾部追加一个字节，模拟传输被静默截断。
async fn append_garbage(path: &Path) -> Result<(), StoreError> {
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(path)
        .await
        .map_err(|err| StoreError::io(path, err))?;
    file.write_all(b"#").await.map_err(|err| StoreError::io(path, err))
}

/// 递归统计目录内文件总字节数；目录不存在按 0 计。
async fn dir_size(dir: &Path) -> std::io::Result<u64> {
    let mut total = 0_u64;
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let mut entries = match fs::read_dir(&current).await {
            Ok(entries) => entries,
            Err(err) if err.kind() == ErrorKind::NotFound => continue,
            Err(err) => return Err(err),
        };
        while let Some(entry) = entries.next_entry().await? {
            let file_type = entry.file_type().await?;
            if file_type.is_dir() {
                pending.push(entry.path());
            } else if file_type.is_file() {
                // .part 是上传中转（含取消泄漏的兜底场景），不算已提交对象。
                if entry.path().extension().is_some_and(|ext| ext == "part") {
                    continue;
                }
                total += entry.metadata().await?.len();
            }
        }
    }
    Ok(total)
}

#[cfg(test)]
mod tests {
    use super::FakeStore;
    use crate::store::{ObjectStore, Oid, StoreError, hash_file};

    use std::path::{Path, PathBuf};

    /// 写一个夹具文件并返回其 oid（哈希即 oid，符合内容寻址）。
    async fn fixture(store: &FakeStore, name: &str, contents: &[u8]) -> (Oid, PathBuf) {
        let path = store.root().join(name);
        if let Some(parent) = path.parent() {
            tokio::fs::create_dir_all(parent).await.expect("创建夹具目录");
        }
        tokio::fs::write(&path, contents).await.expect("写入夹具");
        let digest = hash_file(&path).await.expect("计算夹具哈希");
        (Oid::parse(&digest).expect("合法 oid"), path)
    }

    #[tokio::test]
    async fn given_put_when_exists_then_reports_size() {
        let store = FakeStore::new();
        let (oid, source) = fixture(&store, "a.bin", b"hello lfs").await;

        store.put(&oid, &source).await.expect("写入对象");

        let meta = store.exists(&oid).await.expect("探测").expect("对象应存在");
        assert_eq!(meta.size, 9);
    }

    #[tokio::test]
    async fn given_put_when_fetch_then_content_roundtrips() {
        let store = FakeStore::new();
        let contents = b"roundtrip payload".to_vec();
        let (oid, source) = fixture(&store, "b.bin", &contents).await;
        let dest = store.root().join("out").join("b.bin");

        store.put(&oid, &source).await.expect("写入对象");
        store.fetch(&oid, &dest).await.expect("下载对象");

        assert_eq!(tokio::fs::read(&dest).await.expect("读回"), contents);
    }

    #[tokio::test]
    async fn given_existing_oid_when_put_again_then_idempotent() {
        let store = FakeStore::new();
        let (oid, source) = fixture(&store, "c.bin", b"same bytes").await;

        store.put(&oid, &source).await.expect("首次写入");
        store.put(&oid, &source).await.expect("重复写入应幂等");

        let meta = store.exists(&oid).await.expect("探测").expect("对象应存在");
        assert_eq!(meta.size, 10);
    }

    #[tokio::test]
    async fn given_object_when_delete_then_exists_none() {
        let store = FakeStore::new();
        let (oid, source) = fixture(&store, "d.bin", b"to delete").await;
        store.put(&oid, &source).await.expect("写入对象");

        store.delete(&oid).await.expect("删除对象");

        assert!(store.exists(&oid).await.expect("探测").is_none());
    }

    #[tokio::test]
    async fn given_missing_oid_when_fetch_then_not_found() {
        let store = FakeStore::new();
        let oid = Oid::parse(&"0".repeat(64)).expect("合法 oid");

        let err =
            store.fetch(&oid, &store.root().join("never.bin")).await.expect_err("缺失对象应报错");

        assert!(matches!(err, StoreError::NotFound { .. }), "实际错误：{err}");
    }

    #[tokio::test]
    async fn given_missing_oid_when_delete_then_idempotent() {
        let store = FakeStore::new();
        let oid = Oid::parse(&"1".repeat(64)).expect("合法 oid");

        store.delete(&oid).await.expect("删除不存在的对象应幂等");
    }

    #[tokio::test]
    async fn given_dirty_source_when_put_then_hash_mismatch() {
        let store = FakeStore::new();
        let (oid, source) = fixture(&store, "e.bin", b"original").await;
        let dirty = store.root().join("e-dirty.bin");
        tokio::fs::write(&dirty, b"tampered").await.expect("写入脏文件");

        let err = store.put(&oid, &dirty).await.expect_err("哈希不符应拒绝");

        assert!(matches!(err, StoreError::HashMismatch { .. }), "实际错误：{err}");
        assert!(store.exists(&oid).await.expect("探测").is_none(), "脏内容不得落最终路径");
        assert_eq!(tokio::fs::read(&source).await.expect("读回夹具"), b"original");
    }

    #[tokio::test]
    async fn given_injected_corruption_when_fetch_then_hash_mismatch_and_no_bad_file() {
        let store = FakeStore::new();
        let (oid, source) = fixture(&store, "f.bin", b"verify me").await;
        store.put(&oid, &source).await.expect("写入对象");
        let dest = store.root().join("corrupt.bin");

        store.inject_next_fetch_corruption();
        let err = store.fetch(&oid, &dest).await.expect_err("坏内容应被哈希校验抓住");

        assert!(matches!(err, StoreError::HashMismatch { .. }), "实际错误：{err}");
        assert!(!dest.exists(), "校验失败不得把坏文件留在 dest");
    }

    #[tokio::test]
    async fn given_objects_when_quota_then_used_sums_object_bytes() {
        let store = FakeStore::new().with_quota_total(1_000);
        let (first, first_source) = fixture(&store, "g1.bin", b"12345").await;
        let (second, second_source) = fixture(&store, "g2.bin", b"678").await;
        store.put(&first, &first_source).await.expect("写入对象");
        store.put(&second, &second_source).await.expect("写入对象");

        let quota = store.quota().await.expect("查询配额");

        assert_eq!(quota.total, 1_000);
        assert_eq!(quota.used, 8);
        assert_eq!(quota.free(), 992);
    }

    #[tokio::test]
    async fn given_leaked_part_file_when_quota_then_not_counted() {
        let store = FakeStore::new();
        let (oid, source) = fixture(&store, "g3.bin", b"committed").await;
        store.put(&oid, &source).await.expect("写入对象");

        // 模拟取消泄漏：在 objects 树里塞一个 .part 中转文件。
        let leaked = store.root().join("objects").join("leak.part");
        if let Some(parent) = leaked.parent() {
            tokio::fs::create_dir_all(parent).await.expect("建目录");
        }
        tokio::fs::write(&leaked, b"staging junk").await.expect("写中转文件");

        let quota = store.quota().await.expect("查询配额");

        assert_eq!(quota.used, 9, "只统计已提交对象，.part 不计入");
    }

    #[tokio::test]
    async fn given_shared_root_when_two_stores_then_see_same_objects() {
        let owner = FakeStore::new();
        let shared = Path::new(owner.root());
        let writer = FakeStore::with_root(shared);
        let reader = FakeStore::with_root(shared);
        let (oid, source) = fixture(&owner, "h.bin", b"shared").await;

        writer.put(&oid, &source).await.expect("写入对象");
        let dest = owner.root().join("h-out.bin");
        reader.fetch(&oid, &dest).await.expect("另一个实例应读到同一对象");

        assert_eq!(tokio::fs::read(&dest).await.expect("读回"), b"shared");
    }
}

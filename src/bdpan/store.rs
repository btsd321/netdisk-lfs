//! `BdpanStore`：把 [`ObjectStore`] 的内容寻址契约落到网盘路径上。
//!
//! 网盘侧布局见 `specs/storage.md`：`objects/<aa>/<bb>/<oid>` 是最终对象，
//! `tmp/<oid>` 是上传中转（以 oid 命名，`mv` 后名字不变）。这里的每个决定都围绕两条
//! 网盘事实：
//!
//! - `upload` 只做 metadata 校验，**内容校验必须自己做**；
//! - `download` 出现过「报成功但内容截断」，所以下载后一律用 sha256 复核，这是唯一防线。

use std::io::ErrorKind;
use std::path::Path;

use tracing::{Instrument, Span};

use crate::bdpan::{BdpanClient, BdpanError, DurationTimer};
use crate::config::StorageConfig;
use crate::store::{
    ObjectMeta, ObjectStore, Oid, Quota, StoreError, StoreFuture, hash_file, object_path,
};

/// 网盘后端实现的 [`ObjectStore`]。
///
/// 构造时不做任何 IO：`bdpan` 只在第一次操作时才会被调用，所以构造失败的可能性都
/// 留在真实调用点上（B4 可以在启动时跑一次 `whoami` 提前发现）。
#[derive(Debug)]
pub struct BdpanStore {
    client: BdpanClient,
    /// 对象根，如 `/apps/bdpan/lfs`；构造时去掉尾斜杠，避免拼出 `//`。
    objects_root: String,
    /// 上传中转根，如 `/apps/bdpan/lfs/tmp`。
    tmp_root: String,
}

impl BdpanStore {
    /// 用现成的 [`BdpanClient`] 与两个远端根构造。
    ///
    /// 两个根是**网盘路径**（必须以 `/apps/bdpan/` 开头），不是本地目录；测试用桩脚本
    /// 时也照旧传网盘路径，由桩把前缀映射到本地临时目录。
    pub fn new(
        client: BdpanClient,
        objects_root: impl Into<String>,
        tmp_root: impl Into<String>,
    ) -> Self {
        Self {
            client,
            objects_root: objects_root.into().trim_end_matches('/').to_owned(),
            tmp_root: tmp_root.into().trim_end_matches('/').to_owned(),
        }
    }

    /// 从 `[storage]` 配置构造，超时/重试/并发都取默认值后再由 B4 按需覆盖。
    pub fn from_storage(storage: &StorageConfig) -> Self {
        Self::new(
            BdpanClient::from_storage(storage),
            storage.objects_root.clone(),
            storage.tmp_root.clone(),
        )
    }

    /// 最终对象的远端绝对路径：`<objects_root>/objects/<aa>/<bb>/<oid>`。
    fn remote_object(&self, oid: &Oid) -> String {
        // 布局只有一个实现（`crate::store::object_path`），这里只负责接上根部前缀。
        format!("{}/{}", self.objects_root, object_path(oid))
    }

    /// 对象所在的分片目录；`mv` 的目标只能是目录，文件名由 `src` 决定。
    fn remote_object_dir(&self, oid: &Oid) -> String {
        let path = object_path(oid);
        let dir = path.rsplit_once('/').map_or(path.as_str(), |(dir, _)| dir);
        format!("{}/{dir}", self.objects_root)
    }

    /// 上传中转文件的远端绝对路径：`<tmp_root>/<oid>`。
    fn remote_tmp(&self, oid: &Oid) -> String {
        format!("{}/{}", self.tmp_root, oid)
    }

    async fn exists_inner(&self, oid: &Oid) -> Result<Option<ObjectMeta>, StoreError> {
        let dir = self.remote_object_dir(oid);
        let Some(entries) = self.client.ls(&dir).await.map_err(backend)? else {
            return Ok(None);
        };
        // `ls` 默认返回上限是 1000 条：单个分片目录在 LFS 场景里很少超过这个数，但不是
        // 不可能。真超了就会漏看同名条目，此时 put 里的「mv 目标已存在 → 幂等成功」兜底。
        Ok(entries
            .iter()
            .find(|entry| !entry.is_dir && entry.name == oid.as_str())
            .map(|entry| ObjectMeta::new(entry.size)))
    }

    async fn put_inner(&self, oid: &Oid, local_source: &Path) -> Result<(), StoreError> {
        // 内容寻址第一条：先校验来源文件的哈希，不符就根本不碰网盘。
        let digest =
            hash_file(local_source).await.map_err(|err| StoreError::io(local_source, err))?;
        if digest != oid.as_str() {
            return Err(StoreError::hash_mismatch(oid, &digest));
        }

        // 幂等：同 oid 的内容必然相同，已有对象不值得再花一次 4 GiB 的上行带宽。
        if self.exists(oid).await?.is_some() {
            return Ok(());
        }

        let tmp = self.remote_tmp(oid);
        let dir = self.remote_object_dir(oid);
        let object = self.remote_object(oid);

        // 前次崩溃可能留下 `tmp/<oid>`：不清掉的话 upload 会触发 CLI 的同名自动重命名，
        // 随后的 `mv tmp/<oid>` 就会搬走旧文件（内容可能不完整）。
        self.remove_remote_quietly(&tmp, "上传前清理残留中转文件").await;

        let outcome = async {
            self.client.upload(local_source, &tmp).await.map_err(backend)?;
            // mkdir 幂等且可建多级；放在 upload 之后，上传失败就不留空目录。
            self.client.mkdir(&dir).await.map_err(backend)?;
            match self.client.mv(&tmp, &dir).await {
                Ok(()) => {},
                Err(err @ BdpanError::DestinationExists { .. }) => {
                    // 目标已有同名文件 = 另一个进程（或 ls 的 1000 条上限）已经把同一 oid
                    // 落好了。mv 不覆盖，这里按幂等成功处理，顺手清掉自己的中转文件。
                    if self.exists(oid).await?.is_some() {
                        tracing::debug!(object = %object, error = %err, "mv 目标已存在，按幂等上传处理");
                        self.remove_remote_quietly(&tmp, "mv 冲突后清理中转文件").await;
                        return Ok(());
                    }
                    return Err(backend(err));
                },
                Err(err) => return Err(backend(err)),
            }
            // 回读确认：CLI 说成功不等于对象真的在最终路径上。
            match self.exists(oid).await? {
                Some(_) => Ok(()),
                None => Err(StoreError::Backend {
                    message: format!("上传后回读 {object} 不存在"),
                    source: None,
                }),
            }
        }
        .await;

        if outcome.is_err() {
            self.remove_remote_quietly(&tmp, "上传失败后清理中转文件").await;
        }
        outcome
    }

    async fn fetch_inner(&self, oid: &Oid, dest: &Path) -> Result<(), StoreError> {
        let Some(meta) = self.exists(oid).await? else {
            return Err(StoreError::NotFound { oid: oid.clone() });
        };
        // 在 fetch 的 span 上补一个对象大小，便于事后核对「下载了多少字节」。
        Span::current().record("bytes", meta.size);

        if let Some(parent) = dest.parent().filter(|parent| !parent.as_os_str().is_empty()) {
            tokio::fs::create_dir_all(parent).await.map_err(|err| StoreError::io(parent, err))?;
        }

        let remote = self.remote_object(oid);
        let outcome = async {
            self.client.download(&remote, dest).await.map_err(backend)?;
            // bdpan 已知缺陷：进度 100% 后可能报 403/20013 却仍提示成功。判定标准是哈希，
            // 不是退出码，也不是 CLI 的 JSON——这里是坏对象进入缓存的唯一防线。
            let digest = hash_file(dest).await.map_err(|err| StoreError::io(dest, err))?;
            if digest != oid.as_str() {
                return Err(StoreError::hash_mismatch(oid, &digest));
            }
            Ok(())
        }
        .await;

        if outcome.is_err() {
            // 与 FakeStore 一致：dest 要么没被写、要么是校验通过的完整对象。
            remove_file_quietly(dest).await;
        }
        outcome
    }

    async fn delete_inner(&self, oid: &Oid) -> Result<(), StoreError> {
        let remote = self.remote_object(oid);
        // `rm` 自己把「本来就不存在」折成 Ok(false)，所以这里天然幂等。
        self.client.rm(&remote).await.map(|_removed| ()).map_err(backend)
    }

    /// 删除远端临时文件；失败只告警——此时调用方多半已经在返回另一个错误了。
    async fn remove_remote_quietly(&self, remote: &str, why: &str) {
        match self.client.rm(remote).await {
            Ok(true) => tracing::debug!(remote, why, "已清理远端文件"),
            Ok(false) => tracing::debug!(remote, why, "待清理的远端文件本来就不存在"),
            Err(err) => tracing::warn!(remote, why, error = %err, "清理远端文件失败"),
        }
    }
}

impl ObjectStore for BdpanStore {
    fn exists<'a>(&'a self, oid: &'a Oid) -> StoreFuture<'a, Option<ObjectMeta>> {
        Box::pin(async move {
            let span = operation_span("exists");
            span.record("oid", oid.as_str());
            let _timer = DurationTimer::new(span.clone());
            self.exists_inner(oid).instrument(span).await
        })
    }

    fn put<'a>(&'a self, oid: &'a Oid, local_source: &'a Path) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let span = operation_span("put");
            span.record("oid", oid.as_str());
            let _timer = DurationTimer::new(span.clone());
            // 先 stat 拿 bytes 字段；顺带让「本地源不存在」立刻报错，不必等一次网盘往返。
            match tokio::fs::metadata(local_source).await {
                Ok(meta) => {
                    span.record("bytes", meta.len());
                },
                Err(err) => return Err(StoreError::io(local_source, err)),
            }
            self.put_inner(oid, local_source).instrument(span).await
        })
    }

    fn fetch<'a>(&'a self, oid: &'a Oid, dest: &'a Path) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let span = operation_span("fetch");
            span.record("oid", oid.as_str());
            let _timer = DurationTimer::new(span.clone());
            self.fetch_inner(oid, dest).instrument(span).await
        })
    }

    fn delete<'a>(&'a self, oid: &'a Oid) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            let span = operation_span("delete");
            span.record("oid", oid.as_str());
            let _timer = DurationTimer::new(span.clone());
            self.delete_inner(oid).instrument(span).await
        })
    }

    fn quota(&self) -> StoreFuture<'_, Quota> {
        Box::pin(async move {
            let span = operation_span("quota");
            let _timer = DurationTimer::new(span.clone());
            self.client.quota().instrument(span).await.map_err(backend)
        })
    }
}

/// 建一个带 `op`/`oid`/`bytes`/`duration_ms` 字段的存储层 span。
///
/// 字段声明成 `Empty`：`exists` 不知道字节数、`quota` 没有 oid，缺的字段宁可不出现，
/// 也不要填 0 让日志看起来像「零字节对象」。
fn operation_span(operation: &'static str) -> Span {
    tracing::info_span!(
        "store",
        op = operation,
        oid = tracing::field::Empty,
        bytes = tracing::field::Empty,
        duration_ms = tracing::field::Empty,
    )
}

/// 封装层错误 → 存储层错误；原始错误留在 source 链里供排查。
fn backend(err: BdpanError) -> StoreError {
    StoreError::Backend { message: err.to_string(), source: Some(Box::new(err)) }
}

/// 删掉校验失败的本地下载结果；失败只告警，别盖住真正的哈希错误。
async fn remove_file_quietly(path: &Path) {
    match tokio::fs::remove_file(path).await {
        Ok(()) => {},
        Err(err) if err.kind() == ErrorKind::NotFound => {},
        Err(err) => tracing::warn!(path = %path.display(), error = %err, "清理本地下载结果失败"),
    }
}

#[cfg(test)]
mod tests {
    use super::BdpanStore;
    use crate::bdpan::{BdpanClient, BdpanClientConfig};
    use crate::store::Oid;

    /// 构造一个不会真的起进程的 store：这些用例只验证路径推导，不触发任何 IO。
    fn store() -> BdpanStore {
        let client = BdpanClient::new(BdpanClientConfig::new("/nonexistent/bdpan"));
        BdpanStore::new(client, "/apps/bdpan/lfs/", "/apps/bdpan/lfs/tmp/")
    }

    fn oid() -> Oid {
        Oid::parse(&format!("{}{}", "aabbccdd", "0".repeat(56))).expect("合法 oid")
    }

    #[test]
    fn given_oid_when_remote_paths_then_reuse_object_path_and_trim_root() {
        let store = store();
        let oid = oid();

        assert_eq!(store.remote_object(&oid), format!("/apps/bdpan/lfs/objects/aa/bb/{oid}"));
        assert_eq!(store.remote_object_dir(&oid), "/apps/bdpan/lfs/objects/aa/bb");
        assert_eq!(store.remote_tmp(&oid), format!("/apps/bdpan/lfs/tmp/{oid}"));
    }
}

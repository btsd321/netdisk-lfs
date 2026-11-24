//! 存储层契约的跨模块集成测试：只用 `netdisk_lfs` 的公开 API。
//!
//! 这里刻意把后端装进 `Arc<dyn ObjectStore>`，顺带验证 trait 的 dyn 兼容性——
//! 协议层（B4/B5）就是靠它按配置在 bdpan 后端与 [`FakeStore`] 之间切换。

use std::path::PathBuf;
use std::sync::Arc;

use netdisk_lfs::{FakeStore, ObjectStore, Oid, Sha256Writer, StoreError, hash_file, object_path};

/// 写一个夹具文件并返回 `(oid, 路径)`；内容寻址要求 oid 就是文件内容的哈希。
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
async fn given_content_when_put_exists_fetch_delete_then_full_roundtrip() {
    let fake = FakeStore::new();
    let store: Arc<dyn ObjectStore> = Arc::new(FakeStore::with_root(fake.root()));
    let contents = b"integration payload".to_vec();
    let (oid, source) = fixture(&fake, "payload.bin", &contents).await;
    let dest = fake.root().join("download.bin");

    store.put(&oid, &source).await.expect("写入对象");
    let meta = store.exists(&oid).await.expect("探测").expect("对象应存在");
    assert_eq!(meta.size, contents.len() as u64);

    store.fetch(&oid, &dest).await.expect("下载对象");
    assert_eq!(tokio::fs::read(&dest).await.expect("读回"), contents);

    store.delete(&oid).await.expect("删除对象");
    assert!(store.exists(&oid).await.expect("探测").is_none(), "删除后不应再存在");
}

#[tokio::test]
async fn given_same_oid_when_put_twice_then_idempotent() {
    let store = FakeStore::new();
    let (oid, source) = fixture(&store, "idem.bin", b"idempotent").await;

    store.put(&oid, &source).await.expect("首次写入");
    store.put(&oid, &source).await.expect("重复写入应成功");

    let meta = store.exists(&oid).await.expect("探测").expect("对象应存在");
    assert_eq!(meta.size, 10);
}

#[tokio::test]
async fn given_unknown_oid_when_exists_then_none_without_error() {
    let store = FakeStore::new();
    let oid = Oid::parse(&"a".repeat(64)).expect("合法 oid");

    assert!(store.exists(&oid).await.expect("探测不算错误").is_none());
}

#[tokio::test]
async fn given_unknown_oid_when_fetch_then_not_found() {
    let store = FakeStore::new();
    let oid = Oid::parse(&"b".repeat(64)).expect("合法 oid");

    let err = store
        .fetch(&oid, &store.root().join("missing.bin"))
        .await
        .expect_err("缺失对象应报 NotFound");

    assert!(matches!(err, StoreError::NotFound { .. }), "实际错误：{err}");
}

#[tokio::test]
async fn given_dirty_file_when_put_then_hash_mismatch_and_nothing_stored() {
    let store = FakeStore::new();
    let (oid, _) = fixture(&store, "clean.bin", b"clean").await;
    let dirty = store.root().join("dirty.bin");
    tokio::fs::write(&dirty, b"dirty").await.expect("写入脏文件");

    let err = store.put(&oid, &dirty).await.expect_err("哈希不符应被拒绝");

    assert!(matches!(err, StoreError::HashMismatch { .. }), "实际错误：{err}");
    assert!(store.exists(&oid).await.expect("探测").is_none(), "脏内容不得落最终路径");
    // 落盘位置必须由 oid 推导，不在别处留下副本。
    let stored = store.root().join(object_path(&oid));
    assert!(!stored.exists());
}

#[tokio::test]
async fn given_unknown_oid_when_delete_then_idempotent() {
    let store = FakeStore::new();
    let oid = Oid::parse(&"c".repeat(64)).expect("合法 oid");

    store.delete(&oid).await.expect("删除不存在的对象应成功");
}

#[tokio::test]
async fn given_stored_objects_when_quota_then_used_matches_object_bytes() {
    let store = FakeStore::new().with_quota_total(4096);
    let (first, first_source) = fixture(&store, "q1.bin", b"12345").await;
    let (second, second_source) = fixture(&store, "q2.bin", b"678").await;
    store.put(&first, &first_source).await.expect("写入对象");
    store.put(&second, &second_source).await.expect("写入对象");

    let quota = store.quota().await.expect("查询配额");

    assert_eq!(quota.total, 4096);
    assert_eq!(quota.used, 8);
    assert_eq!(quota.free(), 4088);
}

#[tokio::test]
async fn given_same_bytes_when_file_hash_and_incremental_hash_then_same_oid() {
    let store = FakeStore::new();
    let contents: Vec<u8> = (0..200_000).map(|index| (index % 251) as u8).collect();
    let (oid, source) = fixture(&store, "hash.bin", &contents).await;

    let mut writer = Sha256Writer::new();
    for chunk in contents.chunks(1000) {
        writer.update(chunk);
    }

    assert_eq!(writer.finish(), oid.as_str());
    assert_eq!(hash_file(&source).await.expect("文件哈希"), oid.as_str());
}

#[test]
fn given_oid_when_object_path_then_two_level_fanout() {
    let raw = format!("{}{}", "fedcba98", "0".repeat(56));
    let oid = Oid::parse(&raw).expect("合法 oid");

    assert_eq!(object_path(&oid), format!("objects/fe/dc/{raw}"));
}

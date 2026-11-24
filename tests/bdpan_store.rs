//! `BdpanClient` / `BdpanStore` 的集成测试。
//!
//! bin 一律指向 `tests/fixtures/bdpan` 桩脚本，桩把远端 `/apps/bdpan/...` 映射到临时
//! 目录——任何用例都不可能碰到真实网盘。故障注入也由桩的环境变量开关驱动，且只通过
//! `BdpanClientConfig::with_env` 传给子进程，不改本进程环境（并行测试里那是全局竞态）。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use netdisk_lfs::{
    BdpanClient, BdpanClientConfig, BdpanError, BdpanStore, ObjectStore, Oid, RetryPolicy,
    StoreError, hash_file,
};

/// 与 `specs/storage.md` 一致的两个远端根；桩负责把它们映射到本地临时目录。
const REMOTE_OBJECTS_ROOT: &str = "/apps/bdpan/lfs";
const REMOTE_TMP_ROOT: &str = "/apps/bdpan/lfs/tmp";

/// 防止同进程并发构造的临时目录互相碰撞。
static TEMP_SEQ: AtomicU32 = AtomicU32::new(0);

/// 集成测试自己的临时目录；离开作用域即清理。
struct TempDir {
    path: PathBuf,
}

impl TempDir {
    fn new(prefix: &str) -> Self {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()));
        fs::create_dir(&path).expect("创建临时目录");
        Self { path }
    }

    fn path(&self) -> &Path {
        &self.path
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        if let Err(err) = fs::remove_dir_all(&self.path) {
            eprintln!("清理临时目录 {} 失败：{err}", self.path.display());
        }
    }
}

/// 桩脚本路径（编译期确定，不依赖运行时工作目录）。
fn fixture_bin() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bdpan")
}

/// 一套桩环境：本地「网盘」根、调用日志与临时工作区。
struct Fixture {
    dir: TempDir,
    /// 桩的网盘根：远端 `/apps/bdpan/` 映射到这里。
    remote: PathBuf,
    call_log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let dir = TempDir::new("netdisk-lfs-bdpan");
        let remote = dir.path().join("remote");
        fs::create_dir_all(remote.join("lfs/tmp")).expect("创建桩网盘目录");
        let call_log = dir.path().join("calls.log");
        Self { dir, remote, call_log }
    }

    /// 构造指向桩的客户端；`extra_env` 用于按用例注入故障开关。
    fn client(
        &self,
        timeout: Duration,
        retry: RetryPolicy,
        extra_env: &[(&str, &str)],
    ) -> BdpanClient {
        let mut config = BdpanClientConfig::new(fixture_bin())
            .with_timeout(timeout)
            .with_retry(retry)
            .with_max_procs(4)
            .with_env("FAKE_BDPAN_ROOT", self.remote.as_os_str().to_owned())
            .with_env("FAKE_BDPAN_CALL_LOG", self.call_log.as_os_str().to_owned());
        for (key, value) in extra_env {
            config = config.with_env(*key, *value);
        }
        BdpanClient::new(config)
    }

    /// 默认 store：30s 超时、不重试（重试单独成用例），避免失败用例白等 21 秒。
    fn store(&self, extra_env: &[(&str, &str)]) -> BdpanStore {
        self.store_with(Duration::from_secs(30), RetryPolicy::none(), extra_env)
    }

    fn store_with(
        &self,
        timeout: Duration,
        retry: RetryPolicy,
        extra_env: &[(&str, &str)],
    ) -> BdpanStore {
        BdpanStore::new(
            self.client(timeout, retry, extra_env),
            REMOTE_OBJECTS_ROOT,
            REMOTE_TMP_ROOT,
        )
    }

    /// 桩网盘里的本地路径（`relative` 相对 `/apps/bdpan/lfs/`）。
    fn remote_path(&self, relative: &str) -> PathBuf {
        self.remote.join("lfs").join(relative)
    }

    /// 对象的最终远端落点，按 oid 两段分片。
    fn object_remote_path(&self, oid: &Oid) -> PathBuf {
        let (first, second) = oid.shards();
        self.remote_path(&format!("objects/{first}/{second}/{oid}"))
    }

    /// 写一个本地夹具文件并返回 `(oid, 路径)`；内容寻址要求 oid 就是内容哈希。
    async fn source(&self, name: &str, contents: &[u8]) -> (Oid, PathBuf) {
        let path = self.dir.path().join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("创建夹具目录");
        }
        fs::write(&path, contents).expect("写入夹具");
        let digest = hash_file(&path).await.expect("计算夹具哈希");
        (Oid::parse(&digest).expect("合法 oid"), path)
    }

    /// 桩记录的某子命令调用参数；没有日志时返回空表。
    fn calls(&self, command: &str) -> Vec<String> {
        let Ok(text) = fs::read_to_string(&self.call_log) else {
            return Vec::new();
        };
        text.lines()
            .filter_map(|line| line.split_once('\t'))
            .filter(|(name, _)| *name == command)
            .map(|(_, args)| args.to_owned())
            .collect()
    }
}

#[tokio::test]
async fn given_content_when_put_exists_fetch_delete_then_roundtrip() {
    let fixture = Fixture::new();
    let store: Arc<dyn ObjectStore> = Arc::new(fixture.store(&[]));
    let contents = b"integration payload".to_vec();
    let (oid, source) = fixture.source("payload.bin", &contents).await;

    store.put(&oid, &source).await.expect("写入对象");
    let meta = store.exists(&oid).await.expect("探测").expect("对象应存在");
    assert_eq!(meta.size, contents.len() as u64);
    assert!(fixture.object_remote_path(&oid).is_file(), "对象应落在分片路径上");
    assert!(!fixture.remote_path(&format!("tmp/{oid}")).exists(), "中转文件应已被 mv 走");

    let dest = fixture.dir.path().join("out/payload.bin");
    store.fetch(&oid, &dest).await.expect("下载对象");
    assert_eq!(tokio::fs::read(&dest).await.expect("读回"), contents);

    store.delete(&oid).await.expect("删除对象");
    assert!(store.exists(&oid).await.expect("探测").is_none(), "删除后不应再存在");
}

#[tokio::test]
async fn given_existing_oid_when_put_again_then_does_not_reupload() {
    let fixture = Fixture::new();
    let store = fixture.store(&[]);
    let (oid, source) = fixture.source("idem.bin", b"idempotent").await;

    store.put(&oid, &source).await.expect("首次写入");
    assert_eq!(fixture.calls("upload").len(), 1, "首次应恰好上传一次");
    store.put(&oid, &source).await.expect("重复写入应成功");

    assert_eq!(fixture.calls("upload").len(), 1, "幂等 put 不应重新上传");
    // 每个子进程都必须带统一标志：漏了就说明有人绕过封装层自己拼命令。
    assert!(
        fixture.calls("upload").iter().all(|args| args.contains("--json")),
        "upload 应带 --json：{:?}",
        fixture.calls("upload")
    );
    assert!(
        fixture.calls("upload").iter().all(|args| args.contains("--no-check-update")),
        "upload 应带 --no-check-update"
    );
}

#[tokio::test]
async fn given_unknown_oid_when_exists_then_none_and_fetch_not_found() {
    let fixture = Fixture::new();
    let store = fixture.store(&[]);
    let oid = Oid::parse(&"b".repeat(64)).expect("合法 oid");

    assert!(store.exists(&oid).await.expect("探测不算错误").is_none());
    let err = store
        .fetch(&oid, &fixture.dir.path().join("missing.bin"))
        .await
        .expect_err("缺失对象应报 NotFound");
    assert!(matches!(err, StoreError::NotFound { .. }), "实际错误：{err}");
}

#[tokio::test]
async fn given_dirty_source_when_put_then_hash_mismatch_without_touching_remote() {
    let fixture = Fixture::new();
    let store = fixture.store(&[]);
    let dirty = fixture.dir.path().join("dirty.bin");
    fs::write(&dirty, b"dirty").expect("写脏文件");
    let claimed = Oid::parse(&"c".repeat(64)).expect("合法 oid");

    let err = store.put(&claimed, &dirty).await.expect_err("哈希不符应拒绝");

    assert!(matches!(err, StoreError::HashMismatch { .. }), "实际错误：{err}");
    assert!(fixture.calls("upload").is_empty(), "哈希不符不应碰网盘");
    assert!(fixture.calls("ls").is_empty(), "哈希校验必须发生在 exists 之前");
}

#[tokio::test]
async fn given_silent_truncate_when_fetch_then_hash_mismatch_and_dest_removed() {
    let fixture = Fixture::new();
    let contents = b"truncation guard payload".to_vec();
    let (oid, source) = fixture.source("truncate.bin", &contents).await;
    // 上传走干净客户端；截断开关只影响 download。
    fixture.store(&[]).put(&oid, &source).await.expect("写入对象");

    let store = fixture.store(&[("FAKE_BDPAN_SILENT_TRUNCATE", "1")]);
    let dest = fixture.dir.path().join("out/truncate.bin");
    let err = store.fetch(&oid, &dest).await.expect_err("截断内容应被哈希抓住");

    assert!(matches!(err, StoreError::HashMismatch { .. }), "实际错误：{err}");
    assert!(!dest.exists(), "校验失败不得把坏文件留在 dest");
}

#[tokio::test]
async fn given_stale_tmp_file_when_put_then_object_correct_and_tmp_cleaned() {
    let fixture = Fixture::new();
    let contents = b"payload after stale tmp".to_vec();
    let (oid, source) = fixture.source("stale.bin", &contents).await;
    // 模拟上次崩溃留下的中转文件：内容故意是坏的，若 mv 搬走它就会污染最终对象。
    let stale = fixture.remote_path(&format!("tmp/{oid}"));
    fs::write(&stale, b"stale partial").expect("写残留中转");

    fixture.store(&[]).put(&oid, &source).await.expect("残留中转不应影响上传");

    assert_eq!(fs::read(fixture.object_remote_path(&oid)).expect("读回对象"), contents);
    assert!(!stale.exists(), "残留中转应被清理");
    let leftovers: Vec<String> = fs::read_dir(fixture.remote_path("tmp"))
        .expect("列 tmp")
        .filter_map(Result::ok)
        .map(|entry| entry.file_name().to_string_lossy().into_owned())
        .filter(|name| name.starts_with(oid.as_str()))
        .collect();
    assert!(leftovers.is_empty(), "tmp 下不应残留 {oid} 的副本：{leftovers:?}");
}

#[tokio::test]
async fn given_upload_failure_when_put_then_backend_error_and_no_object() {
    let fixture = Fixture::new();
    let store = fixture.store(&[("FAKE_BDPAN_FAIL_UPLOAD", "1")]);
    let (oid, source) = fixture.source("fail.bin", b"will fail").await;

    let err = store.put(&oid, &source).await.expect_err("上传失败应报错");

    assert!(matches!(err, StoreError::Backend { .. }), "实际错误：{err}");
    assert!(!fixture.object_remote_path(&oid).exists(), "失败不得留下对象");
    assert_eq!(fixture.calls("upload").len(), 1, "不重试策略下只应尝试一次");
}

#[tokio::test]
async fn given_mv_failure_when_put_then_tmp_cleaned() {
    let fixture = Fixture::new();
    let store = fixture.store(&[("FAKE_BDPAN_FAIL_MV", "1")]);
    let (oid, source) = fixture.source("mvfail.bin", b"mv will fail").await;

    let err = store.put(&oid, &source).await.expect_err("mv 失败应报错");

    assert!(matches!(err, StoreError::Backend { .. }), "实际错误：{err}");
    assert!(!fixture.remote_path(&format!("tmp/{oid}")).exists(), "失败后中转文件应被清理");
    assert!(!fixture.object_remote_path(&oid).exists(), "失败不得留下对象");
}

#[tokio::test]
async fn given_quota_env_when_quota_then_numbers_parsed() {
    let fixture = Fixture::new();
    let store =
        fixture.store(&[("FAKE_BDPAN_QUOTA_TOTAL", "4096"), ("FAKE_BDPAN_QUOTA_USED", "1024")]);

    let quota = store.quota().await.expect("查询配额");

    assert_eq!(quota.total, 4096);
    assert_eq!(quota.used, 1024);
    assert_eq!(quota.free(), 3072);
}

#[tokio::test]
async fn given_four_oids_when_concurrent_put_and_fetch_then_no_cross_talk() {
    let fixture = Fixture::new();
    let store: Arc<dyn ObjectStore> = Arc::new(fixture.store(&[]));

    let mut writers = Vec::new();
    for index in 0..4_u8 {
        let contents = format!("concurrent payload {index}").into_bytes();
        let (oid, source) = fixture.source(&format!("c{index}.bin"), &contents).await;
        let store = Arc::clone(&store);
        writers.push(tokio::spawn(async move {
            store.put(&oid, &source).await.expect("并发写入");
            (oid, contents)
        }));
    }
    let mut written = Vec::new();
    for writer in writers {
        written.push(writer.await.expect("写入任务不应 panic"));
    }

    let mut readers = Vec::new();
    for (oid, contents) in written {
        let store = Arc::clone(&store);
        let dest = fixture.dir.path().join(format!("out/{oid}.bin"));
        readers.push(tokio::spawn(async move {
            store.fetch(&oid, &dest).await.expect("并发下载");
            (dest, contents)
        }));
    }
    for reader in readers {
        let (dest, contents) = reader.await.expect("读取任务不应 panic");
        assert_eq!(tokio::fs::read(&dest).await.expect("读回"), contents, "并发不得串号");
    }
}

#[tokio::test]
async fn given_transient_failure_when_retried_then_put_succeeds() {
    let fixture = Fixture::new();
    // 极短退避：只验证「重试一次后成功」的路径，不陪 1s/4s/16s 睡觉。
    let retry = RetryPolicy::new(1, Duration::from_millis(10), 4);
    let store =
        fixture.store_with(Duration::from_secs(30), retry, &[("FAKE_BDPAN_FLAKY_UPLOAD", "1")]);
    let (oid, source) = fixture.source("flaky.bin", b"retry me").await;

    store.put(&oid, &source).await.expect("退避重试后应成功");

    assert_eq!(fixture.calls("upload").len(), 2, "应是一次失败加一次重试");
    assert!(fixture.object_remote_path(&oid).is_file(), "对象应已落位");
}

#[tokio::test]
async fn given_slow_bdpan_when_call_then_timeout_error() {
    let fixture = Fixture::new();
    let client = fixture.client(
        Duration::from_millis(150),
        RetryPolicy::none(),
        &[("FAKE_BDPAN_SLEEP", "3")],
    );

    let started = Instant::now();
    let err = client.quota().await.expect_err("超时应报错");

    assert!(matches!(err, BdpanError::Timeout { .. }), "实际错误：{err}");
    assert!(started.elapsed() < Duration::from_secs(2), "超时后应立即返回，不等子进程");
}

#[tokio::test]
async fn given_path_outside_authorized_root_when_ls_then_error_instead_of_none() {
    let fixture = Fixture::new();
    let client = fixture.client(Duration::from_secs(30), RetryPolicy::none(), &[]);

    let err = client.ls("/lfs").await.expect_err("越界路径应报错而不是当成空目录");

    assert!(matches!(err, BdpanError::Unexpected { .. }), "实际错误：{err}");
}

#[tokio::test]
async fn given_taken_name_when_mv_then_destination_exists() {
    let fixture = Fixture::new();
    let client = fixture.client(Duration::from_secs(30), RetryPolicy::none(), &[]);
    let (_, source) = fixture.source("manual.bin", b"conflict").await;
    let remote_tmp = format!("{REMOTE_TMP_ROOT}/manual.bin");
    client.upload(&source, &remote_tmp).await.expect("上传到 tmp");
    let dest_dir = format!("{REMOTE_OBJECTS_ROOT}/objects/ff/ff");
    client.mkdir(&dest_dir).await.expect("建目标目录");
    fs::copy(
        fixture.remote_path("tmp/manual.bin"),
        fixture.remote_path("objects/ff/ff/manual.bin"),
    )
    .expect("摆一个同名文件");

    let err = client.mv(&remote_tmp, &dest_dir).await.expect_err("同名应报冲突");

    assert!(matches!(err, BdpanError::DestinationExists { .. }), "实际错误：{err}");
}

#[tokio::test]
async fn given_remote_name_taken_when_upload_then_conflict_reported() {
    let fixture = Fixture::new();
    let client = fixture.client(Duration::from_secs(30), RetryPolicy::none(), &[]);
    let (_, source) = fixture.source("dup.bin", b"first").await;
    let remote = format!("{REMOTE_TMP_ROOT}/dup.bin");
    client.upload(&source, &remote).await.expect("首次上传");

    let err = client.upload(&source, &remote).await.expect_err("自动改名必须报错");

    assert!(matches!(err, BdpanError::Unexpected { .. }), "实际错误：{err}");
}

#[tokio::test]
async fn given_unknown_oid_when_delete_then_idempotent() {
    let fixture = Fixture::new();
    let store = fixture.store(&[]);
    let oid = Oid::parse(&"d".repeat(64)).expect("合法 oid");

    store.delete(&oid).await.expect("删除不存在的对象应成功");
}

#[tokio::test]
async fn given_logged_in_stub_when_whoami_then_ok() {
    let fixture = Fixture::new();
    let client = fixture.client(Duration::from_secs(30), RetryPolicy::none(), &[]);

    client.whoami().await.expect("桩的登录态应正常");
}

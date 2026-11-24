//! 本地 LRU 缓存与 Range 下载的行为测试。
//!
//! 全部通过 `tower::ServiceExt::oneshot` 直接打 `router(state)`，不绑定端口，也不起
//! 真实 `bdpan`：对象后端是 [`CountingStore`]（包装 [`FakeStore`]，记录
//! `exists`/`fetch` 调用次数），所以「命中不 fetch」「单飞只下载一次」这类断言可以
//! 直接数调用次数，而不必看日志。
//!
//! 覆盖的契约（`specs/storage.md`「缓存策略」「下载状态机」+ `specs/api.md`
//! 「GET /lfs/objects/{oid}」）：LRU 淘汰顺序、命中不写盘不 fetch、单飞、损坏驱逐、
//! Range 206/416/多区间、启动扫描重建索引与 `.part` 清理、超预算直通、404 不缓存、
//! 缓存目录不可用时降级为直通。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime};

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::http::{HeaderMap, HeaderValue, Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::BodyExt;
use netdisk_lfs::store::StoreFuture;
use netdisk_lfs::{
    AccountsConfig, AppState, AuthConfig, Cache, CacheConfig, Config, FakeStore, ObjectMeta,
    ObjectStore, Oid, Quota, Role, RuntimeEnv, ServerConfig, Sha256Writer, StorageConfig,
    StoreError, UserConfig, router, transient_dir,
};
use tower::ServiceExt;

const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";
const AUTH_CHALLENGE: &str = "Basic realm=\"netdisk-lfs\"";
const PASSWORD: &str = "s3cret";

/// 单对象上限：给得足够大，本文件的用例都只关心缓存与 Range。
const MAX_OBJECT_BYTES: u64 = 4 * 1024 * 1024;

/// 默认账号：读写角色足够覆盖 GET。
const USERS: &[(&str, Role)] = &[("alice", Role::Readwrite)];

/// 计数用的存储后端：把 `exists`/`fetch` 的调用次数摆到测试能断言的地方。
struct CountingStore {
    inner: FakeStore,
    exists_calls: AtomicUsize,
    fetch_calls: AtomicUsize,
    /// 每次 `fetch` 前的人为延迟：让并发未命中真的重叠，否则「单飞」用例即使实现
    /// 失效也可能因为第一个下载太快而侥幸通过。
    fetch_delay: Duration,
}

impl CountingStore {
    fn new() -> Self {
        Self {
            inner: FakeStore::new(),
            exists_calls: AtomicUsize::new(0),
            fetch_calls: AtomicUsize::new(0),
            fetch_delay: Duration::ZERO,
        }
    }

    /// 让每次 `fetch` 慢 20 ms（单飞用例用）。
    fn with_fetch_delay(mut self, delay: Duration) -> Self {
        self.fetch_delay = delay;
        self
    }

    fn root(&self) -> &Path {
        self.inner.root()
    }

    fn fetch_calls(&self) -> usize {
        self.fetch_calls.load(Ordering::SeqCst)
    }

    fn exists_calls(&self) -> usize {
        self.exists_calls.load(Ordering::SeqCst)
    }

    /// 往后端写一个对象（模拟「网盘上已有该 oid」），返回 oid。
    async fn seed(&self, contents: &[u8]) -> Oid {
        let digest = sha256_hex(contents);
        let oid = Oid::parse(&digest).expect("夹具哈希是合法 oid");
        let source = self.inner.root().join(format!("seed-{digest}.bin"));
        tokio::fs::write(&source, contents).await.expect("写入夹具文件");
        self.inner.put(&oid, &source).await.expect("写入后端对象");
        oid
    }
}

impl ObjectStore for CountingStore {
    fn exists<'a>(&'a self, oid: &'a Oid) -> StoreFuture<'a, Option<ObjectMeta>> {
        self.exists_calls.fetch_add(1, Ordering::SeqCst);
        self.inner.exists(oid)
    }

    fn put<'a>(&'a self, oid: &'a Oid, local_source: &'a Path) -> StoreFuture<'a, ()> {
        self.inner.put(oid, local_source)
    }

    fn fetch<'a>(&'a self, oid: &'a Oid, dest: &'a Path) -> StoreFuture<'a, ()> {
        Box::pin(async move {
            self.fetch_calls.fetch_add(1, Ordering::SeqCst);
            if !self.fetch_delay.is_zero() {
                tokio::time::sleep(self.fetch_delay).await;
            }
            self.inner.fetch(oid, dest).await
        })
    }

    fn delete<'a>(&'a self, oid: &'a Oid) -> StoreFuture<'a, ()> {
        self.inner.delete(oid)
    }

    fn quota(&self) -> StoreFuture<'_, Quota> {
        self.inner.quota()
    }
}

/// 测试应用：router、配置、缓存句柄与后端计数器。
struct TestApp {
    router: Router,
    config: Config,
    cache: Cache,
    store: Arc<CountingStore>,
}

impl TestApp {
    /// 用给定缓存预算建一个测试应用。
    async fn new(cache_max_bytes: u64) -> Self {
        Self::with_store(Arc::new(CountingStore::new()), cache_max_bytes).await
    }

    /// 用现成的后端（可带人为延迟）建一个测试应用。
    async fn with_store(store: Arc<CountingStore>, cache_max_bytes: u64) -> Self {
        // upload/ 与 cache/ 都放在后端根目录下，测试结束随根目录一起清理。
        let data_dir = store.root().join("data");
        let config = test_config(&data_dir, cache_max_bytes);
        let cache = Cache::open(&config.cache).await;
        let backend: Arc<dyn ObjectStore> = store.clone();
        let router = router(AppState::with_cache(backend, Arc::new(config.clone()), cache.clone()));
        Self { router, config, cache, store }
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = self.router.clone().oneshot(request).await.expect("router 应处理请求");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.expect("读取响应体").to_bytes().to_vec();
        (status, headers, body)
    }

    /// 发一个 GET；`range` 为 `None` 时不带 Range 头。
    async fn get(&self, oid: &Oid, range: Option<&str>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let mut request = Request::builder()
            .method(Method::GET)
            .uri(format!("/lfs/objects/{oid}"))
            .header(header::AUTHORIZATION, basic_header("alice", PASSWORD))
            .body(Body::empty())
            .expect("构造请求");
        if let Some(range) = range {
            request
                .headers_mut()
                .insert(header::RANGE, HeaderValue::from_str(range).expect("Range 头值合法"));
        }
        self.send(request).await
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let mut writer = Sha256Writer::new();
    writer.update(input);
    writer.finish()
}

fn basic_header(username: &str, password: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{username}:{password}")))
}

fn test_config(data_dir: &Path, cache_max_bytes: u64) -> Config {
    let mut auth_users = BTreeMap::new();
    for (name, role) in USERS {
        auth_users.insert(
            (*name).to_owned(),
            UserConfig { password_sha256: sha256_hex(PASSWORD.as_bytes()), role: *role },
        );
    }
    Config {
        server: ServerConfig {
            listen: "127.0.0.1:0".parse().expect("合法监听地址"),
            public_base: String::new(),
        },
        storage: StorageConfig {
            objects_root: "/apps/bdpan/lfs".to_owned(),
            tmp_root: "/apps/bdpan/lfs/tmp".to_owned(),
            bdpan_bin: "/bin/true".into(),
            max_object_bytes: MAX_OBJECT_BYTES,
            max_bdpan_procs: 1,
            bdpan_timeout_secs: 300,
            bdpan_min_throughput_bytes_per_sec: 102_400,
        },
        cache: CacheConfig { dir: data_dir.join("cache"), max_bytes: cache_max_bytes },
        accounts: AccountsConfig { db: data_dir.join("accounts.db"), ..AccountsConfig::default() },
        auth: AuthConfig { users: auth_users },
        runtime_env: RuntimeEnv::Dev,
        data_dir: Some(data_dir.to_path_buf()),
    }
}

/// 头值；缺失直接 panic，避免断言静默跳过。
fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("缺少响应头 {name}"))
}

/// 递归收集目录下的 `.part` 文件：缓存对象不带该后缀。
async fn part_files(dir: &Path) -> Vec<PathBuf> {
    let mut found = Vec::new();
    let mut pending = vec![dir.to_path_buf()];
    while let Some(current) = pending.pop() {
        let mut reader = match tokio::fs::read_dir(&current).await {
            Ok(reader) => reader,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => panic!("读取目录 {} 失败：{error}", current.display()),
        };
        while let Some(entry) = reader.next_entry().await.expect("遍历目录") {
            let path = entry.path();
            if entry.file_type().await.expect("文件类型").is_dir() {
                pending.push(path);
            } else if path.extension().is_some_and(|ext| ext == "part") {
                found.push(path);
            }
        }
    }
    found
}

/// 缓存对象在本地目录里的布局；与 `Cache::path` 同一约定（`<root>/<aa>/<bb>/<oid>`）。
fn cache_path(root: &Path, oid: &Oid) -> PathBuf {
    root.join(&oid.as_str()[..2]).join(&oid.as_str()[2..4]).join(oid.as_str())
}

/// 把文件的 mtime 往前挪 `age`，用来造「超龄残留」。
fn set_mtime_ago(path: &Path, age: Duration) {
    let file = std::fs::File::options().write(true).open(path).expect("打开待改 mtime 的文件");
    let when = SystemTime::now().checked_sub(age).expect("时间可回退");
    file.set_times(std::fs::FileTimes::new().set_modified(when)).expect("修改 mtime");
}

/// 往缓存里放一个对象：`oid` 由内容算出，与真实链路一致（`fetch` 负责写中转文件）。
async fn insert_into_cache(cache: &Cache, contents: Vec<u8>) -> Oid {
    let oid = Oid::parse(&sha256_hex(&contents)).expect("合法 oid");
    let payload = contents;
    cache
        .fetch_once(&oid, move |part| async move {
            tokio::fs::write(&part, &payload).await.map_err(|error| StoreError::io(&part, error))
        })
        .await
        .expect("写入缓存");
    oid
}

#[tokio::test]
async fn given_small_budget_when_oldest_is_touched_then_second_oldest_evicted() {
    // 预算 300、对象各 100 字节：装满后访问最旧的 A，再插入 D，应淘汰次旧的 B。
    let workspace = FakeStore::new();
    let config = CacheConfig { dir: workspace.root().join("cache"), max_bytes: 300 };
    let cache = Cache::open(&config).await;

    let a = insert_into_cache(&cache, vec![b'a'; 100]).await;
    let b = insert_into_cache(&cache, vec![b'b'; 100]).await;
    let c = insert_into_cache(&cache, vec![b'c'; 100]).await;
    assert_eq!(cache.used_bytes(), 300, "三个 100 字节对象应恰好填满预算");

    assert!(cache.get(&a).await.is_some(), "A 命中并把访问序推到最新");
    let d = insert_into_cache(&cache, vec![b'd'; 100]).await;

    assert!(cache.get(&a).await.is_some(), "刚访问过的 A 不能被淘汰");
    assert!(cache.get(&c).await.is_some(), "C 比 B 新，也不能被淘汰");
    assert!(cache.get(&d).await.is_some(), "刚插入的 D 必须在缓存里");
    assert!(cache.get(&b).await.is_none(), "被淘汰的应是次旧的 B");
    assert_eq!(cache.used_bytes(), 300, "淘汰一个 100 字节对象后仍装满预算");
    assert!(!cache_path(cache.root(), &b).exists(), "淘汰要真的删掉磁盘文件");
}

#[tokio::test]
async fn given_cached_object_when_get_again_then_no_backend_fetch() {
    let app = TestApp::new(4096).await;
    let contents = b"hit me once".to_vec();
    let oid = app.store.seed(&contents).await;

    let (status, headers, body) = app.get(&oid, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(app.store.exists_calls(), 0, "GET 走 fetch，不额外探测 exists");
    assert_eq!(header_str(&headers, "content-type"), "application/octet-stream");
    assert_eq!(header_str(&headers, "content-length"), contents.len().to_string());
    assert_eq!(body, contents);
    assert_eq!(app.store.fetch_calls(), 1, "首次未命中共下载一次");

    // 第二个请求（另一个 oneshot）应命中缓存，不再触达后端。
    let (status, headers, body) = app.get(&oid, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, contents);
    assert_eq!(header_str(&headers, "content-length"), contents.len().to_string());
    assert_eq!(app.store.fetch_calls(), 1, "命中缓存不得再 fetch");
    assert!(part_files(&app.config.cache.dir).await.is_empty(), "命中路径不应留下中转文件");
}

#[tokio::test]
async fn given_concurrent_misses_when_four_gets_then_single_fetch_and_same_bodies() {
    // 后端每次 fetch 慢 20 ms：若单飞失效，四个请求会真的同时在下载，计数就会 >1。
    let store = Arc::new(CountingStore::new().with_fetch_delay(Duration::from_millis(20)));
    let app = TestApp::with_store(store, 4096).await;
    let contents: Vec<u8> = (0..2048).map(|index| (index % 251) as u8).collect();
    let oid = app.store.seed(&contents).await;

    // 四个请求必须真的并发：先建好四个 future，再一起 await。
    let (first, second, third, fourth) = tokio::join!(
        app.get(&oid, None),
        app.get(&oid, None),
        app.get(&oid, None),
        app.get(&oid, None)
    );

    for (status, headers, body) in [first, second, third, fourth] {
        assert_eq!(status, StatusCode::OK);
        assert_eq!(header_str(&headers, "content-length"), contents.len().to_string());
        assert_eq!(body, contents, "四个响应必须内容一致");
    }
    assert_eq!(app.store.fetch_calls(), 1, "同一 oid 的并发未命中只能触发一次 fetch");
}

#[tokio::test]
async fn given_corrupted_cache_file_when_get_then_evicted_and_refetched() {
    let app = TestApp::new(4096).await;
    let contents = b"cache me then corrupt".to_vec();
    let oid = app.store.seed(&contents).await;

    let (status, _, _) = app.get(&oid, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(app.store.fetch_calls(), 1);

    // 篡改成不同大小：命中校验按索引里的大小比对，必须抓住并驱逐。
    let path = app.cache.path(&oid);
    tokio::fs::write(&path, b"broken").await.expect("篡改缓存文件");

    let (status, _, body) = app.get(&oid, None).await;
    assert_eq!(status, StatusCode::OK, "缓存损坏只影响这一次请求，不能变成 500");
    assert_eq!(body, contents, "驱逐后必须重新下载出正确内容");
    assert_eq!(app.store.fetch_calls(), 2, "损坏的缓存要重新下载一份");
    assert_eq!(
        tokio::fs::read(&path).await.expect("读回缓存文件"),
        contents,
        "重新下载后缓存文件应被修复"
    );
}

#[tokio::test]
async fn given_range_header_when_get_then_partial_206_with_content_range() {
    let app = TestApp::new(4096).await;
    let contents = b"0123456789".to_vec();
    let oid = app.store.seed(&contents).await;

    // 闭区间 bytes=0-3 → 206 + Content-Range + 4 字节。
    let (status, headers, body) = app.get(&oid, Some("bytes=0-3")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(header_str(&headers, "content-length"), "4");
    assert_eq!(header_str(&headers, "content-range"), "bytes 0-3/10");
    assert_eq!(header_str(&headers, "accept-ranges"), "bytes");
    assert_eq!(body, b"0123");

    // 开区间 bytes=5- → 从 5 到结尾。
    let (status, headers, body) = app.get(&oid, Some("bytes=5-")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(header_str(&headers, "content-length"), "5");
    assert_eq!(header_str(&headers, "content-range"), "bytes 5-9/10");
    assert_eq!(body, b"56789");

    // 后缀区间 bytes=-2 → 最后 2 字节。
    let (status, headers, body) = app.get(&oid, Some("bytes=-2")).await;
    assert_eq!(status, StatusCode::PARTIAL_CONTENT);
    assert_eq!(header_str(&headers, "content-length"), "2");
    assert_eq!(header_str(&headers, "content-range"), "bytes 8-9/10");
    assert_eq!(body, b"89");

    // 三次区间请求共用同一份缓存，不应额外下载。
    assert_eq!(app.store.fetch_calls(), 1);
}

#[tokio::test]
async fn given_multiple_ranges_when_get_then_full_200() {
    // api.md：多区间不支持，回 200 全量（不是 400，也不是 206）。
    let app = TestApp::new(4096).await;
    let contents = b"multi range falls back".to_vec();
    let oid = app.store.seed(&contents).await;

    let (status, headers, body) = app.get(&oid, Some("bytes=0-1,3-4")).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header_str(&headers, "content-length"), contents.len().to_string());
    assert!(!headers.contains_key(header::CONTENT_RANGE), "全量响应不应带 Content-Range");
    assert_eq!(body, contents);
}

#[tokio::test]
async fn given_out_of_range_start_when_get_then_416_with_total_length() {
    let app = TestApp::new(4096).await;
    let contents = b"0123456789".to_vec();
    let oid = app.store.seed(&contents).await;

    let (status, headers, body) = app.get(&oid, Some("bytes=999-")).await;

    assert_eq!(status, StatusCode::RANGE_NOT_SATISFIABLE);
    assert_eq!(header_str(&headers, "content-range"), "bytes */10");
    // 错误体仍是 LFS JSON：客户端只认这一种格式。
    assert_eq!(header_str(&headers, "content-type"), LFS_MEDIA_TYPE);
    let value: serde_json::Value = serde_json::from_slice(&body).expect("416 也应回 JSON 错误体");
    assert_eq!(value["request_id"].as_str(), Some(header_str(&headers, "x-request-id")));
    assert!(
        value["message"].as_str().is_some_and(|message| message.contains("Range")),
        "错误信息应指向 Range：{value}"
    );
    assert!(part_files(&app.config.cache.dir).await.is_empty(), "416 也要清掉中转文件");
}

#[tokio::test]
async fn given_object_larger_than_budget_when_get_then_served_but_not_cached() {
    // 预算 16 字节、对象 64 字节：直通返回，不报错，也不进缓存。
    let app = TestApp::new(16).await;
    let contents = vec![b'x'; 64];
    let oid = app.store.seed(&contents).await;

    let (status, headers, body) = app.get(&oid, None).await;

    assert_eq!(status, StatusCode::OK, "超过预算不是错误，必须照常返回");
    assert_eq!(header_str(&headers, "content-length"), "64");
    assert_eq!(body, contents);
    assert_eq!(app.cache.len(), 0, "超预算对象不入缓存");
    assert_eq!(app.cache.used_bytes(), 0);
    assert!(part_files(&app.config.cache.dir).await.is_empty(), "直通文件在响应结束后必须删除");

    // 没进缓存，所以下一次仍要下载。
    let (status, _, body) = app.get(&oid, None).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, contents);
    assert_eq!(app.store.fetch_calls(), 2);
}

#[tokio::test]
async fn given_missing_object_when_get_twice_then_404_both_times_and_not_cached() {
    let app = TestApp::new(4096).await;
    let oid = Oid::parse(&"a".repeat(64)).expect("合法 oid");

    for _ in 0..2 {
        let (status, headers, _) = app.get(&oid, None).await;
        assert_eq!(status, StatusCode::NOT_FOUND);
        assert_eq!(header_str(&headers, "content-type"), LFS_MEDIA_TYPE);
    }

    assert_eq!(app.store.fetch_calls(), 2, "404 不得被缓存成负面结果");
    assert_eq!(app.cache.len(), 0);
    assert!(part_files(&app.config.cache.dir).await.is_empty(), "404 后不得留下中转文件");
}

#[tokio::test]
async fn given_preseeded_cache_when_open_then_index_rebuilt_and_stale_parts_swept() {
    let workspace = FakeStore::new();
    let root = workspace.root().join("cache");
    let upload = workspace.root().join("upload");

    // 1) 正确布局的缓存对象：构造 Cache 后应被索引出来。
    let kept = b"kept object".to_vec();
    let kept_oid = Oid::parse(&sha256_hex(&kept)).expect("合法 oid");
    let kept_path = cache_path(&root, &kept_oid);
    tokio::fs::create_dir_all(kept_path.parent().expect("对象路径有父目录"))
        .await
        .expect("建缓存目录");
    tokio::fs::write(&kept_path, &kept).await.expect("写缓存对象");

    // 2) 缓存目录下两个 `.part`：一个超龄（2 小时前）应删，一个新建应保留。
    let stale_cache_part = kept_path.with_extension("part");
    tokio::fs::write(&stale_cache_part, b"stale").await.expect("写超龄中转文件");
    set_mtime_ago(&stale_cache_part, Duration::from_secs(2 * 3600));
    let fresh_cache_part = root.join("fresh.part");
    tokio::fs::write(&fresh_cache_part, b"in flight").await.expect("写新建中转文件");

    // 3) 上传目录下也有一个超龄 `.part`：sweep 的清理目标包含上传目录。
    tokio::fs::create_dir_all(&upload).await.expect("建上传目录");
    let stale_upload_part = upload.join("alice-0001.part");
    tokio::fs::write(&stale_upload_part, b"half uploaded").await.expect("写上传残留");
    set_mtime_ago(&stale_upload_part, Duration::from_secs(2 * 3600));

    let config = CacheConfig { dir: root.clone(), max_bytes: 4096 };
    let cache = Cache::open(&config).await;

    // 索引重建：对象在、大小对、`.part` 不计入。
    assert_eq!(cache.len(), 1, "只索引提交完成的缓存对象");
    assert_eq!(cache.used_bytes(), kept.len() as u64);
    assert!(cache.get(&kept_oid).await.is_some(), "启动后应能直接命中预置对象");

    let report = cache.sweep(&[upload]).await;

    assert!(!stale_cache_part.exists(), "超龄缓存中转文件必须删除");
    assert!(fresh_cache_part.exists(), "未超龄的中转文件是在途下载，不能删");
    assert!(!stale_upload_part.exists(), "超龄上传缓冲必须删除");
    assert_eq!(report.stale_parts, 2);
    assert_eq!(report.stale_bytes, b"stale".len() as u64 + b"half uploaded".len() as u64);
    assert_eq!(cache.used_bytes(), kept.len() as u64, "sweep 不能动合法缓存对象");
    assert!(cache.get(&kept_oid).await.is_some());
}

#[tokio::test]
async fn given_cache_over_budget_when_sweep_then_converges_to_budget_by_mtime() {
    // 预算 150、三个 100 字节对象：启动收敛应淘汰两个最旧的（按 mtime）。
    let workspace = FakeStore::new();
    let root = workspace.root().join("cache");
    let mut oids = Vec::new();
    for (index, age_hours) in [(b'a', 3_u64), (b'b', 2), (b'c', 1)] {
        let contents = vec![index; 100];
        let oid = Oid::parse(&sha256_hex(&contents)).expect("合法 oid");
        let path = cache_path(&root, &oid);
        tokio::fs::create_dir_all(path.parent().expect("对象路径有父目录")).await.expect("建目录");
        tokio::fs::write(&path, &contents).await.expect("写缓存对象");
        set_mtime_ago(&path, Duration::from_secs(age_hours * 3600));
        oids.push(oid);
    }

    let cache = Cache::open(&CacheConfig { dir: root, max_bytes: 150 }).await;
    assert_eq!(cache.len(), 3, "启动扫描应索引全部对象");
    assert_eq!(cache.used_bytes(), 300);

    let report = cache.sweep(&[]).await;

    assert_eq!(report.evicted_objects, 2, "应淘汰两个最旧的对象");
    assert_eq!(cache.len(), 1);
    assert!(cache.used_bytes() <= 150, "收敛后必须回到预算之内");
    assert!(cache.get(&oids[2]).await.is_some(), "剩下的应是最新的那个");
}

#[tokio::test]
async fn given_unusable_cache_dir_when_open_then_degraded_passthrough_still_works() {
    // 缓存目录位置被一个普通文件占住：扫描必然失败，服务必须降级而不是拒绝启动。
    let workspace = FakeStore::new();
    let blocked = workspace.root().join("cache-is-a-file");
    tokio::fs::write(&blocked, b"not a directory").await.expect("占位文件");
    let cache = Cache::open(&CacheConfig { dir: blocked, max_bytes: 4096 }).await;

    assert!(!cache.is_enabled(), "目录不可用时应降级为直通");
    let oid = Oid::parse(&sha256_hex(b"payload")).expect("合法 oid");
    assert!(cache.get(&oid).await.is_none(), "直通模式不查缓存");

    let fetched = cache
        .fetch_once(&oid, |part| async move {
            tokio::fs::write(&part, b"payload").await.map_err(|error| StoreError::io(&part, error))
        })
        .await
        .expect("直通模式仍要能下载");

    assert!(!fetched.is_cached(), "降级模式不得声称对象已进缓存");
    assert_eq!(tokio::fs::read(fetched.path()).await.expect("读回直通文件"), b"payload");
    tokio::fs::remove_file(fetched.path()).await.expect("清理直通文件");
    assert_eq!(cache.len(), 0, "降级模式不建索引");
}

#[tokio::test]
async fn given_no_authorization_when_get_then_401_before_touching_cache() {
    // 认证在路由层，缓存不应被未认证请求影响（避免任何人用 401 请求把缓存写满）。
    let app = TestApp::new(4096).await;
    let contents = b"auth first".to_vec();
    let oid = app.store.seed(&contents).await;

    let request = Request::builder()
        .method(Method::GET)
        .uri(format!("/lfs/objects/{oid}"))
        .body(Body::empty())
        .expect("构造请求");
    let (status, headers, _) = app.send(request).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(header_str(&headers, "lfs-authenticate"), AUTH_CHALLENGE);
    assert_eq!(app.store.fetch_calls(), 0, "未认证请求不得触达后端");
    assert_eq!(app.cache.len(), 0);
}

/// 直通下载的 fake fetch：把固定内容写进给定中转路径。
async fn write_payload(part: PathBuf) -> Result<(), StoreError> {
    tokio::fs::write(&part, b"0123456789abcdef").await.map_err(|error| StoreError::io(&part, error))
}

#[tokio::test]
async fn given_oversized_object_when_two_concurrent_fetches_then_transient_paths_distinct() {
    // 预算 10、内容 16 字节：两次 fetch 都只能是 Transient。Transient 文件会活到
    // 响应发送完毕，若并发请求共用同一个中转路径，后到的 create 会截断前者。
    let workspace = FakeStore::new();
    let root = workspace.root().join("cache");
    let config = CacheConfig { dir: root, max_bytes: 10 };
    let cache = Cache::open(&config).await;
    let contents = b"0123456789abcdef";
    let oid = Oid::parse(&sha256_hex(contents)).expect("合法 oid");

    let (first, second) =
        tokio::join!(cache.fetch_once(&oid, write_payload), cache.fetch_once(&oid, write_payload));

    let first = first.expect("第一份直通下载");
    let second = second.expect("第二份直通下载");
    assert!(!first.is_cached() && !second.is_cached(), "超预算对象不缓存");
    assert_ne!(first.path(), second.path(), "并发直通必须使用不同的中转文件");
    assert_eq!(tokio::fs::read(first.path()).await.expect("读第一份"), contents);
    assert_eq!(tokio::fs::read(second.path()).await.expect("读第二份"), contents);
    // Transient 文件由调用方（响应结束时）清理。
    tokio::fs::remove_file(first.path()).await.expect("清理第一份");
    tokio::fs::remove_file(second.path()).await.expect("清理第二份");
}

#[tokio::test]
async fn given_degraded_cache_when_sweep_then_stale_transient_part_removed() {
    // 缓存目录不可用 → 降级直通，中转落 netdisk-lfs-transient 专用目录。
    // 启动清理必须覆盖它（否则 kill -9 残留会永远占着系统临时目录）。
    let workspace = FakeStore::new();
    let blocked = workspace.root().join("cache-is-a-file");
    tokio::fs::write(&blocked, b"not a directory").await.expect("占位文件");
    let cache = Cache::open(&CacheConfig { dir: blocked, max_bytes: 4096 }).await;
    assert!(!cache.is_enabled(), "目录不可用时应降级为直通");

    let transient = transient_dir();
    tokio::fs::create_dir_all(&transient).await.expect("建中转目录");
    let oid = Oid::parse(&sha256_hex(b"stale payload")).expect("合法 oid");
    let stale = transient.join(format!("{oid}.9999.part"));
    tokio::fs::write(&stale, b"stale").await.expect("写超龄残留");
    set_mtime_ago(&stale, Duration::from_secs(2 * 3600));

    let report = cache.sweep(std::slice::from_ref(&transient)).await;

    assert!(!stale.exists(), "降级模式的超龄中转文件必须被清理");
    assert!(report.stale_parts >= 1, "清理计数应包含该文件");
}

#[tokio::test]
async fn given_hits_misses_and_evictions_when_observed_then_counters_are_exact() {
    // `/metrics` 的数据源：命中/未命中记在 `get` 上，驱逐记在真正删掉对象时。
    let workspace = FakeStore::new();
    let config = CacheConfig { dir: workspace.root().join("cache"), max_bytes: 200 };
    let cache = Cache::open(&config).await;
    assert_eq!(cache.hits_total(), 0);
    assert_eq!(cache.misses_total(), 0);
    assert_eq!(cache.evictions_total(), 0);

    let a = insert_into_cache(&cache, vec![b'a'; 100]).await;
    assert_eq!(cache.misses_total(), 0, "fetch_once 内部查询不算未命中，否则冷读被记两次");

    assert!(cache.get(&a).await.is_some(), "第一次查是命中");
    let missing = Oid::parse(&"ef".repeat(32)).expect("合法 oid");
    assert!(cache.get(&missing).await.is_none(), "不存在的 oid 是未命中");
    assert_eq!((cache.hits_total(), cache.misses_total()), (1, 1));

    // 预算 200：a、b 填满；插入 c 时淘汰最久未访问的 a（b、c 都比它新）。
    let b = insert_into_cache(&cache, vec![b'b'; 100]).await;
    let c = insert_into_cache(&cache, vec![b'c'; 100]).await;

    assert_eq!(cache.evictions_total(), 1, "超预算应驱逐一个对象");
    assert!(!cache_path(cache.root(), &a).exists(), "被驱逐的应是最久未访问的 a");
    assert!(cache_path(cache.root(), &b).exists(), "b 比 a 新，应留在缓存里");
    assert!(cache_path(cache.root(), &c).exists(), "刚插入的 c 必须在缓存里");
    assert_eq!(cache.len(), 2, "淘汰后索引里应剩两个对象");

    // 降级模式不读写缓存，也不记账：否则「缓存没开」会被算成 100% 未命中。
    let blocked = workspace.root().join("cache-is-a-file");
    tokio::fs::write(&blocked, b"not a directory").await.expect("占位文件");
    let degraded = Cache::open(&CacheConfig { dir: blocked, max_bytes: 4096 }).await;
    assert!(!degraded.is_enabled(), "目录不可用时应降级");
    assert!(degraded.get(&a).await.is_none());
    assert_eq!((degraded.hits_total(), degraded.misses_total()), (0, 0), "降级模式不计数");
}

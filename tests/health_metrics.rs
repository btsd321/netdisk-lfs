//! `/healthz` 与 `/metrics` 的行为测试。
//!
//! 探活走 `tests/fixtures/bdpan` 桩：`whoami` 成功、报登录态失效、可执行文件不存在
//! 三种情形都能手工构造，任何用例都不碰真实网盘，也不调用真实 `bdpan`。
//!
//! 覆盖的契约（`specs/api.md`「端点」+ `specs/architecture.md`「失败模式」）：
//! `status=ok` → 200、任何降级 → 503、探活结论按 TTL 复用、两个端点都不需要认证、
//! `/metrics` 的六个指标名与取值来源。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::BodyExt;
use netdisk_lfs::{
    AppState, AuthConfig, BdpanClient, BdpanClientConfig, BdpanProbe, Cache, CacheConfig, Config,
    FakeStore, ObjectStore, Oid, RetryPolicy, Role, RuntimeEnv, ServerConfig, Sha256Writer,
    StorageConfig, UserConfig, router,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const PASSWORD: &str = "s3cret";
const MAX_OBJECT_BYTES: u64 = 1_048_576;
const CACHE_MAX_BYTES: u64 = 4 * 1024 * 1024;

/// 桩脚本路径（编译期确定，不依赖运行时工作目录）。
fn fixture_bin() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/bdpan")
}

fn sha256_hex(input: &[u8]) -> String {
    let mut writer = Sha256Writer::new();
    writer.update(input);
    writer.finish()
}

fn basic_header(username: &str, password: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{username}:{password}")))
}

fn request(method: Method, uri: &str, auth: Option<&str>) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    builder.body(Body::empty()).expect("构造请求")
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("缺少响应头 {name}"))
}

/// 一套测试夹具：桩「网盘」根、调用日志、缓存目录与 `FakeStore` 后端。
struct Fixture {
    store: FakeStore,
    config: Config,
    call_log: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        // FakeStore 自带一个临时根目录；缓存目录挂在它下面，Drop 时一起清理。
        let store = FakeStore::new();
        let call_log = store.root().join("bdpan-calls.log");
        let config = test_config(store.root(), max_users());
        Self { store, config, call_log }
    }

    /// 指向桩的探活器；`ttl` 控制结论复用时长，`extra_env` 注入故障开关。
    fn probe(&self, ttl: Duration, extra_env: &[(&str, &str)]) -> BdpanProbe {
        BdpanProbe::new(self.client(&fixture_bin(), extra_env), ttl)
    }

    /// 指向任意可执行文件的探活器（用于「CLI 不存在」用例）。
    fn probe_with_bin(&self, bin: &Path) -> BdpanProbe {
        BdpanProbe::new(self.client(bin, &[]), Duration::from_secs(60))
    }

    fn client(&self, bin: &Path, extra_env: &[(&str, &str)]) -> BdpanClient {
        let mut client = BdpanClientConfig::new(bin)
            .with_timeout(Duration::from_secs(30))
            .with_retry(RetryPolicy::none())
            .with_env("FAKE_BDPAN_ROOT", self.store.root().as_os_str().to_owned())
            .with_env("FAKE_BDPAN_CALL_LOG", self.call_log.as_os_str().to_owned());
        for (key, value) in extra_env {
            client = client.with_env(*key, *value);
        }
        BdpanClient::new(client)
    }

    /// 用给定探活器装配 router；缓存索引为空、不扫描目录（`AppState::new` 语义）。
    async fn app(&self, probe: Option<BdpanProbe>) -> Router {
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::with_root(self.store.root()));
        let cache = Cache::open(&self.config.cache).await;
        let state = AppState::with_cache(backend, Arc::new(self.config.clone()), cache);
        match probe {
            Some(probe) => router(state.with_bdpan_probe(Arc::new(probe))),
            None => router(state),
        }
    }

    /// 桩记录里某个子命令被调用的次数（没有日志就是 0 次）。
    fn calls(&self, command: &str) -> usize {
        let Ok(text) = std::fs::read_to_string(&self.call_log) else {
            return 0;
        };
        text.lines()
            .filter_map(|line| line.split_once('\t'))
            .filter(|(name, _)| *name == command)
            .count()
    }

    /// 写一个对象到 FakeStore 并返回 oid（内容寻址：oid 即内容哈希）。
    async fn seed(&self, contents: &[u8]) -> Oid {
        let oid = Oid::parse(&sha256_hex(contents)).expect("合法 oid");
        let source = self.store.root().join(format!("fixture-{oid}.bin"));
        tokio::fs::write(&source, contents).await.expect("写夹具文件");
        self.store.put(&oid, &source).await.expect("写入 FakeStore");
        oid
    }
}

fn max_users() -> &'static [(&'static str, Role)] {
    &[("alice", Role::Readwrite)]
}

fn test_config(root: &Path, users: &[(&str, Role)]) -> Config {
    let mut auth_users = BTreeMap::new();
    for (name, role) in users {
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
            bdpan_bin: fixture_bin(),
            max_object_bytes: MAX_OBJECT_BYTES,
            max_bdpan_procs: 1,
            bdpan_timeout_secs: 21_600,
        },
        cache: CacheConfig { dir: root.join("cache"), max_bytes: CACHE_MAX_BYTES },
        auth: AuthConfig { users: auth_users },
        runtime_env: RuntimeEnv::Dev,
        data_dir: Some(root.to_path_buf()),
    }
}

async fn get_json(router: &Router, uri: &str) -> (StatusCode, Value) {
    let response =
        router.clone().oneshot(request(Method::GET, uri, None)).await.expect("router 应处理请求");
    let status = response.status();
    let body = response.into_body().collect().await.expect("读取响应体").to_bytes();
    let value = serde_json::from_slice(&body).expect("响应体应是 JSON");
    (status, value)
}

async fn get_text(router: &Router, uri: &str) -> (StatusCode, String, String) {
    let response =
        router.clone().oneshot(request(Method::GET, uri, None)).await.expect("router 应处理请求");
    let status = response.status();
    let content_type = header_str(response.headers(), "content-type").to_owned();
    let body = response.into_body().collect().await.expect("读取响应体").to_bytes();
    (status, content_type, String::from_utf8(body.to_vec()).expect("响应体应是 UTF-8"))
}

#[tokio::test]
async fn given_healthy_bdpan_when_healthz_then_200_ok_without_auth() {
    let fixture = Fixture::new();
    let app = fixture.app(Some(fixture.probe(Duration::from_secs(60), &[]))).await;

    // 不带 Authorization：探针不持有 LFS 账号，/healthz 必须在认证层之外。
    let (status, body) = get_json(&app, "/healthz").await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, json!({ "status": "ok", "bdpan": "ok", "cache_enabled": true }));
    assert_eq!(fixture.calls("whoami"), 1, "首次探活应真的调用一次 whoami");
}

#[tokio::test]
async fn given_two_probes_within_ttl_when_healthz_twice_then_whoami_called_once() {
    let fixture = Fixture::new();
    let app = fixture.app(Some(fixture.probe(Duration::from_secs(60), &[]))).await;

    let (first, _) = get_json(&app, "/healthz").await;
    let (second, _) = get_json(&app, "/healthz").await;

    assert_eq!((first, second), (StatusCode::OK, StatusCode::OK));
    assert_eq!(fixture.calls("whoami"), 1, "TTL 内的第二次探活必须复用上次结论");
}

#[tokio::test]
async fn given_zero_ttl_when_healthz_twice_then_whoami_called_each_time() {
    let fixture = Fixture::new();
    let app = fixture.app(Some(fixture.probe(Duration::ZERO, &[]))).await;

    let (first, body) = get_json(&app, "/healthz").await;
    let (second, _) = get_json(&app, "/healthz").await;

    assert_eq!((first, second), (StatusCode::OK, StatusCode::OK));
    assert_eq!(body["bdpan"], "ok");
    assert_eq!(fixture.calls("whoami"), 2, "TTL 为 0 时每次探活都要重新调用 whoami");
}

#[tokio::test]
async fn given_expired_token_when_healthz_then_503_auth_failed() {
    let fixture = Fixture::new();
    let probe = fixture.probe(Duration::from_secs(60), &[("FAKE_BDPAN_FAIL_AUTH", "1")]);
    let app = fixture.app(Some(probe)).await;

    let (status, body) = get_json(&app, "/healthz").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE, "token 失效必须让探针发现");
    assert_eq!(
        body,
        json!({ "status": "degraded", "bdpan": "auth_failed", "cache_enabled": true })
    );
}

#[tokio::test]
async fn given_missing_bdpan_binary_when_healthz_then_503_unavailable() {
    let fixture = Fixture::new();
    let app = fixture.app(Some(fixture.probe_with_bin(Path::new("/nonexistent/bdpan")))).await;

    let (status, body) = get_json(&app, "/healthz").await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(body["status"], "degraded");
    assert_eq!(body["bdpan"], "unavailable");
}

#[tokio::test]
async fn given_degraded_bdpan_when_cache_hit_then_get_still_serves() {
    // token 失效只影响回源：缓存命中仍要能下载。这条性质必须在 /healthz 降级时成立，
    // 否则运维会误以为「整个服务挂了」而去做无谓的回滚。
    let fixture = Fixture::new();
    let contents = b"cached payload".to_vec();
    let oid = fixture.seed(&contents).await;
    let probe = fixture.probe(Duration::from_secs(60), &[("FAKE_BDPAN_FAIL_AUTH", "1")]);
    let app = fixture.app(Some(probe)).await;
    let auth = basic_header("alice", PASSWORD);

    // 第一次 GET 未命中（走 FakeStore 后端），把对象放进缓存。
    let response = app
        .clone()
        .oneshot(request(Method::GET, &format!("/lfs/objects/{oid}"), Some(&auth)))
        .await
        .expect("router 应处理请求");
    assert_eq!(response.status(), StatusCode::OK);

    let (status, body) = get_json(&app, "/healthz").await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);

    let response = app
        .clone()
        .oneshot(request(Method::GET, &format!("/lfs/objects/{oid}"), Some(&auth)))
        .await
        .expect("router 应处理请求");
    assert_eq!(response.status(), StatusCode::OK, "缓存命中不受 token 失效影响：{body}");
    let served = response.into_body().collect().await.expect("读取响应体").to_bytes();
    assert_eq!(served.as_ref(), contents.as_slice());
}

#[tokio::test]
async fn given_no_auth_when_metrics_then_prometheus_text() {
    let fixture = Fixture::new();
    let app = fixture.app(None).await;

    let (status, content_type, text) = get_text(&app, "/metrics").await;

    assert_eq!(status, StatusCode::OK, "只监听 127.0.0.1，/metrics 不挂认证");
    assert_eq!(content_type, "text/plain; version=0.0.4; charset=utf-8");
    assert_eq!(fixture.calls("whoami"), 0, "/metrics 不触达 bdpan");
    for name in [
        "netdisk_lfs_cache_objects",
        "netdisk_lfs_cache_used_bytes",
        "netdisk_lfs_cache_max_bytes",
        "netdisk_lfs_cache_hits_total",
        "netdisk_lfs_cache_misses_total",
        "netdisk_lfs_cache_evictions_total",
    ] {
        assert!(text.contains(&format!("# TYPE {name} ")), "缺少 TYPE 行：{name}\n{text}");
        assert!(text.contains(&format!("\n{name} ")), "缺少样本行：{name}\n{text}");
    }
    assert!(
        text.contains(&format!("netdisk_lfs_cache_max_bytes {CACHE_MAX_BYTES}")),
        "预算应来自配置：{text}"
    );
}

#[tokio::test]
async fn given_get_miss_then_hit_when_metrics_then_counters_reflect_one_each() {
    let fixture = Fixture::new();
    let contents = b"counted payload".to_vec();
    let oid = fixture.seed(&contents).await;
    let app = fixture.app(None).await;
    let auth = basic_header("alice", PASSWORD);
    let uri = format!("/lfs/objects/{oid}");

    for _ in 0..2 {
        let response = app
            .clone()
            .oneshot(request(Method::GET, &uri, Some(&auth)))
            .await
            .expect("router 应处理请求");
        assert_eq!(response.status(), StatusCode::OK);
        let _ = response.into_body().collect().await.expect("读完响应体");
    }

    let (_, _, text) = get_text(&app, "/metrics").await;

    assert!(text.contains("netdisk_lfs_cache_misses_total 1"), "一次冷读只记一次未命中：{text}");
    assert!(text.contains("netdisk_lfs_cache_hits_total 1"), "第二次请求命中缓存：{text}");
    assert!(text.contains("netdisk_lfs_cache_objects 1"), "对象应进缓存：{text}");
    assert!(
        text.contains(&format!("netdisk_lfs_cache_used_bytes {}", contents.len())),
        "已用字节应等于对象大小：{text}"
    );
    assert!(text.contains("netdisk_lfs_cache_evictions_total 0"), "预算充足不应有驱逐：{text}");
}

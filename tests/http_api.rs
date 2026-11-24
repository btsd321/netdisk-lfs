//! HTTP 协议层集成测试：健康检查、Basic 认证、batch 协商与错误体。
//!
//! 全部通过 `tower::ServiceExt::oneshot` 直接打 `router(state)`，不绑定端口，
//! 也不起真实 `bdpan`：存储用 [`FakeStore`]，绝不访问网盘。

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::header;
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::BodyExt;
use netdisk_lfs::{
    AppState, AuthConfig, CacheConfig, Config, FakeStore, ObjectStore, Oid, Role, RuntimeEnv,
    ServerConfig, Sha256Writer, StorageConfig, UserConfig, router,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const BATCH_PATH: &str = "/lfs/objects/batch";
const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";
const AUTH_CHALLENGE: &str = "Basic realm=\"netdisk-lfs\"";
const PASSWORD: &str = "s3cret";
const MAX_OBJECT_BYTES: u64 = 1_048_576;

/// 测试请求统一带 Host；batch 的 action href 由它推导成绝对 URL。
const TEST_HOST: &str = "lfs.test";
const TEST_ORIGIN: &str = "http://lfs.test";

/// 默认测试账号：一个读写、一个只读。
const USERS: &[(&str, Role)] = &[("alice", Role::Readwrite), ("reader", Role::Readonly)];

/// 测试应用：router + 一个与 router 共享根目录的 FakeStore（写夹具用）。
struct TestApp {
    router: Router,
    store: FakeStore,
}

impl TestApp {
    fn new(users: &[(&str, Role)]) -> Self {
        Self::from_config(config_with_users(users))
    }

    fn from_config(config: Config) -> Self {
        let store = FakeStore::new();
        // router 里的后端与夹具写入共用同一根目录；外层 store 负责 Drop 清理。
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::with_root(store.root()));
        let state = AppState::new(backend, Arc::new(config));
        Self { router: router(state), store }
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Vec<u8>) {
        let response = self.router.clone().oneshot(request).await.expect("router 应处理请求");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.expect("读取响应体").to_bytes().to_vec();
        (status, headers, body)
    }

    async fn send_json(&self, request: Request<Body>) -> (StatusCode, HeaderMap, Value) {
        let (status, headers, body) = self.send(request).await;
        let value = serde_json::from_slice(&body)
            .unwrap_or_else(|error| panic!("响应体应是 JSON（{error}）：{body:?}"));
        (status, headers, value)
    }

    /// 写一个夹具文件并写入 FakeStore，返回其 oid。
    async fn put_object(&self, contents: &[u8]) -> Oid {
        let digest = sha256_hex(contents);
        let oid = Oid::parse(&digest).expect("夹具哈希是合法 oid");
        let source = self.store.root().join(format!("fixture-{digest}.bin"));
        tokio::fs::write(&source, contents).await.expect("写入夹具文件");
        self.store.put(&oid, &source).await.expect("写入 FakeStore");
        oid
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let mut writer = Sha256Writer::new();
    writer.update(input);
    writer.finish()
}

fn config_with_users(users: &[(&str, Role)]) -> Config {
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
            bdpan_bin: "/bin/true".into(),
            max_object_bytes: MAX_OBJECT_BYTES,
            max_bdpan_procs: 1,
            bdpan_timeout_secs: 21_600,
        },
        cache: CacheConfig { dir: std::env::temp_dir(), max_bytes: 0 },
        auth: AuthConfig { users: auth_users },
        runtime_env: RuntimeEnv::Dev,
        data_dir: None,
    }
}

fn basic_header(username: &str, password: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{username}:{password}")))
}

fn request(
    method: Method,
    uri: &str,
    auth: Option<&str>,
    content_type: Option<&str>,
    body: String,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri).header(header::HOST, TEST_HOST);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder.body(Body::from(body)).expect("构造请求")
}

fn batch_request(auth: Option<&str>, body: &str) -> Request<Body> {
    request(Method::POST, BATCH_PATH, auth, Some(LFS_MEDIA_TYPE), body.to_owned())
}

fn object_json(oid: &Oid, size: u64) -> Value {
    json!({ "oid": oid.as_str(), "size": size })
}

fn batch_body(operation: &str, objects: &[Value]) -> String {
    json!({
        "operation": operation,
        "transfers": ["basic"],
        "objects": objects,
    })
    .to_string()
}

/// 构造一个固定字符的 oid，用于「必然不存在于 FakeStore」的对象。
fn missing_oid(hex_char: char) -> Oid {
    Oid::parse(&hex_char.to_string().repeat(64)).expect("合法 oid")
}

fn header_str<'a>(headers: &'a HeaderMap, name: &str) -> &'a str {
    headers
        .get(name)
        .and_then(|value| value.to_str().ok())
        .unwrap_or_else(|| panic!("缺少响应头 {name}"))
}

/// 断言错误体符合 api.md：LFS 媒体类型、message 非空、request id 与响应头一致。
fn assert_error_contract(headers: &HeaderMap, body: &Value) {
    assert_eq!(header_str(headers, "content-type"), LFS_MEDIA_TYPE);
    let header_id = header_str(headers, "x-request-id");
    assert_eq!(
        body["request_id"].as_str(),
        Some(header_id),
        "错误体与响应头的 request id 必须一致"
    );
    assert!(
        body["message"].as_str().is_some_and(|message| !message.is_empty()),
        "错误体必须带非空 message：{body}"
    );
}

#[tokio::test]
async fn given_no_bdpan_probe_when_healthz_then_degraded_503_with_request_id() {
    // 测试应用没有注入 bdpan 探活器（`AppState::new` 不探测）：宁可报降级，也不谎报
    // 健康。探活成功/失败的完整矩阵在 tests/health_metrics.rs。
    let app = TestApp::new(USERS);

    let (status, headers, body) =
        app.send_json(request(Method::GET, "/healthz", None, None, String::new())).await;

    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(
        body,
        json!({ "status": "degraded", "bdpan": "unavailable", "cache_enabled": true })
    );
    assert!(!header_str(&headers, "x-request-id").is_empty());
}

#[tokio::test]
async fn given_unknown_route_when_get_then_404_with_request_id() {
    let app = TestApp::new(USERS);

    let (status, headers, _) =
        app.send(request(Method::GET, "/no-such-route", None, None, String::new())).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(!header_str(&headers, "x-request-id").is_empty());
}

#[tokio::test]
async fn given_client_supplied_request_id_when_request_then_server_id_wins() {
    let app = TestApp::new(USERS);
    // 用 /metrics 做载体：它和 /healthz 一样不挂认证且恒回 200，断言不受后端影响。
    let request = Request::builder()
        .uri("/metrics")
        .header("x-request-id", "client-controlled")
        .body(Body::empty())
        .expect("构造请求");

    let (status, headers, _) = app.send(request).await;

    assert_eq!(status, StatusCode::OK);
    assert_ne!(header_str(&headers, "x-request-id"), "client-controlled");
}

#[tokio::test]
async fn given_no_authorization_when_batch_then_401_with_challenge() {
    let app = TestApp::new(USERS);
    let body = batch_body("download", &[]);

    let (status, headers, parsed) = app.send_json(batch_request(None, &body)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(header_str(&headers, "lfs-authenticate"), AUTH_CHALLENGE);
    assert_error_contract(&headers, &parsed);
}

#[tokio::test]
async fn given_bad_credentials_when_batch_then_same_401_as_missing() {
    let app = TestApp::new(USERS);
    let body = batch_body("download", &[]);

    let (_, _, missing) = app.send_json(batch_request(None, &body)).await;
    let wrong_password = basic_header("alice", "wrong");
    let (status, headers, wrong) = app.send_json(batch_request(Some(&wrong_password), &body)).await;
    let unknown_user = basic_header("nobody", PASSWORD);
    let (unknown_status, unknown_headers, unknown) =
        app.send_json(batch_request(Some(&unknown_user), &body)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_eq!(unknown_status, StatusCode::UNAUTHORIZED);
    assert_eq!(header_str(&headers, "lfs-authenticate"), AUTH_CHALLENGE);
    assert_eq!(header_str(&unknown_headers, "lfs-authenticate"), AUTH_CHALLENGE);
    // 不泄漏用户名是否存在：三种失败的 message 必须完全一致。
    assert_eq!(wrong["message"], missing["message"]);
    assert_eq!(unknown["message"], missing["message"]);
    assert_error_contract(&headers, &wrong);
    assert_error_contract(&unknown_headers, &unknown);
}

#[tokio::test]
async fn given_malformed_authorization_when_batch_then_401() {
    let app = TestApp::new(USERS);
    let body = batch_body("download", &[]);

    for raw in ["Bearer token", "Basic", "Basic !!!", "Basic %%%"] {
        let (status, headers, parsed) = app.send_json(batch_request(Some(raw), &body)).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "认证头 {raw:?} 应被拒绝");
        assert_eq!(header_str(&headers, "lfs-authenticate"), AUTH_CHALLENGE, "认证头 {raw:?}");
        assert_error_contract(&headers, &parsed);
    }
}

#[tokio::test]
async fn given_readonly_user_when_upload_batch_then_403() {
    let app = TestApp::new(USERS);
    let oid = app.put_object(b"shared bytes").await;
    let body = batch_body("upload", &[object_json(&oid, 12)]);
    let auth = basic_header("reader", PASSWORD);

    let (status, headers, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!headers.contains_key("lfs-authenticate"), "403 不应带认证挑战头");
    assert_error_contract(&headers, &parsed);
}

#[tokio::test]
async fn given_readonly_user_when_download_batch_then_ok() {
    let app = TestApp::new(USERS);
    let contents = b"readable bytes";
    let oid = app.put_object(contents).await;
    let body = batch_body("download", &[object_json(&oid, contents.len() as u64)]);
    let auth = basic_header("reader", PASSWORD);

    let (status, headers, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header_str(&headers, "content-type"), LFS_MEDIA_TYPE);
    assert_eq!(
        parsed["objects"][0]["actions"]["download"]["href"].as_str(),
        Some(format!("{TEST_ORIGIN}/lfs/objects/{oid}").as_str())
    );
}

#[tokio::test]
async fn given_stale_declared_size_when_download_batch_then_response_uses_stored_size() {
    let app = TestApp::new(USERS);
    let contents = b"authoritative size";
    let oid = app.put_object(contents).await;
    // 客户端声明一个过期/错误的大小：响应必须回存储层的权威值，而不是原样回显。
    let body = batch_body("download", &[object_json(&oid, 999_999)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, _, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(parsed["objects"][0]["size"].as_u64(), Some(contents.len() as u64));
}

#[tokio::test]
async fn given_existing_object_when_download_batch_then_absolute_href_and_size() {
    let app = TestApp::new(USERS);
    let contents = b"download me";
    let oid = app.put_object(contents).await;
    let body = batch_body("download", &[object_json(&oid, contents.len() as u64)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(parsed["transfer"], "basic");
    assert_eq!(parsed["objects"][0]["oid"].as_str(), Some(oid.as_str()));
    assert_eq!(parsed["objects"][0]["size"].as_u64(), Some(contents.len() as u64));
    assert_eq!(
        parsed["objects"][0]["actions"]["download"]["href"].as_str(),
        Some(format!("{TEST_ORIGIN}/lfs/objects/{oid}").as_str())
    );
    assert_eq!(parsed["objects"][0]["actions"]["download"]["header"], json!({}));
    assert!(!header_str(&headers, "x-request-id").is_empty());
}

#[tokio::test]
async fn given_missing_object_when_download_batch_then_object_error_404_and_http_200() {
    let app = TestApp::new(USERS);
    let oid = missing_oid('b');
    let body = batch_body("download", &[object_json(&oid, 10)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK, "单对象缺失不应让整批失败");
    assert_eq!(parsed["objects"][0]["error"]["code"].as_u64(), Some(404));
    assert_eq!(parsed["objects"][0]["error"]["message"], "object not found");
    assert!(parsed["objects"][0].get("actions").is_none(), "缺失对象不应给 actions");
    assert_eq!(header_str(&headers, "content-type"), LFS_MEDIA_TYPE);
}

#[tokio::test]
async fn given_existing_object_when_upload_batch_then_no_upload_action() {
    let app = TestApp::new(USERS);
    let contents = b"already uploaded";
    let oid = app.put_object(contents).await;
    let body = batch_body("upload", &[object_json(&oid, contents.len() as u64)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, _, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(parsed["objects"][0]["actions"].get("upload").is_none(), "已存在对象不得再给 upload");
    assert_eq!(
        parsed["objects"][0]["actions"]["verify"]["href"].as_str(),
        Some(format!("{TEST_ORIGIN}/lfs/objects/{oid}/verify").as_str())
    );
}

#[tokio::test]
async fn given_missing_object_when_upload_batch_then_upload_and_verify_hrefs() {
    let app = TestApp::new(USERS);
    let oid = missing_oid('c');
    let body = batch_body("upload", &[object_json(&oid, 2048)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, _, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    let actions = &parsed["objects"][0]["actions"];
    assert_eq!(
        actions["upload"]["href"].as_str(),
        Some(format!("{TEST_ORIGIN}/lfs/objects/{oid}").as_str())
    );
    assert_eq!(actions["upload"]["header"]["Content-Type"], "application/octet-stream");
    assert_eq!(
        actions["verify"]["href"].as_str(),
        Some(format!("{TEST_ORIGIN}/lfs/objects/{oid}/verify").as_str())
    );
}

#[tokio::test]
async fn given_public_base_when_batch_then_href_uses_configured_base() {
    // 反代改写主机名/端口时用 server.public_base 固定对外地址。
    let mut config = config_with_users(USERS);
    config.server.public_base = "https://lfs.example.com".to_owned();
    let app = TestApp::from_config(config);
    let oid = missing_oid('e');
    let body = batch_body("upload", &[object_json(&oid, 2048)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, _, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        parsed["objects"][0]["actions"]["upload"]["href"].as_str(),
        Some(format!("https://lfs.example.com/lfs/objects/{oid}").as_str())
    );
}

#[tokio::test]
async fn given_forwarded_proto_when_batch_then_href_uses_https() {
    // 没有 public_base 时按 Host + X-Forwarded-Proto 推导（Caddy 反代会传这两个头）。
    let app = TestApp::new(USERS);
    let oid = missing_oid('f');
    let body = batch_body("upload", &[object_json(&oid, 2048)]);
    let auth = basic_header("alice", PASSWORD);
    let request = Request::builder()
        .method(Method::POST)
        .uri(BATCH_PATH)
        .header(header::HOST, TEST_HOST)
        .header("x-forwarded-proto", "https")
        .header(header::AUTHORIZATION, auth)
        .header(header::CONTENT_TYPE, LFS_MEDIA_TYPE)
        .body(Body::from(body))
        .expect("构造请求");

    let (status, _, parsed) = app.send_json(request).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(
        parsed["objects"][0]["actions"]["upload"]["href"].as_str(),
        Some(format!("https://{TEST_HOST}/lfs/objects/{oid}").as_str())
    );
}

#[tokio::test]
async fn given_unlimited_max_bytes_when_batch_declares_huge_object_then_no_422() {
    // max_object_bytes = 0：不限制单对象大小，50 GiB 的声明也不应被对象级 422 拒绝。
    let mut config = config_with_users(USERS);
    config.storage.max_object_bytes = 0;
    let app = TestApp::from_config(config);
    let oid = missing_oid('9');
    let body = batch_body("upload", &[object_json(&oid, 50 * 1024 * 1024 * 1024)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, _, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(parsed["objects"][0].get("error").is_none(), "不限制时不应有对象级错误");
    assert!(parsed["objects"][0]["actions"]["upload"]["href"].is_string());
}

#[tokio::test]
async fn given_mixed_objects_when_download_batch_then_results_keep_request_order() {
    let app = TestApp::new(USERS);
    let existing = app.put_object(b"present").await;
    let missing = missing_oid('d');
    let body = batch_body("download", &[object_json(&missing, 1), object_json(&existing, 7)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, _, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(parsed["objects"][0]["oid"].as_str(), Some(missing.as_str()));
    assert_eq!(parsed["objects"][0]["error"]["code"].as_u64(), Some(404));
    assert_eq!(parsed["objects"][1]["oid"].as_str(), Some(existing.as_str()));
    assert!(parsed["objects"][1]["actions"]["download"]["href"].is_string());
}

#[tokio::test]
async fn given_more_than_100_objects_when_batch_then_400() {
    let app = TestApp::new(USERS);
    let objects: Vec<Value> = (0..101_u8)
        .map(|index| {
            let oid = Oid::parse(&format!("{index:02x}{}", "0".repeat(62))).expect("合法 oid");
            object_json(&oid, 1)
        })
        .collect();
    let body = batch_body("download", &objects);
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        parsed["message"].as_str().is_some_and(|message| message.contains("100")),
        "错误信息应说明上限：{parsed}"
    );
    assert_error_contract(&headers, &parsed);
}

#[tokio::test]
async fn given_invalid_oid_when_batch_then_400() {
    let app = TestApp::new(USERS);
    let body = json!({
        "operation": "download",
        "objects": [{ "oid": "not-a-hex-oid", "size": 1 }],
    })
    .to_string();
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        parsed["message"].as_str().is_some_and(|message| message.contains("oid")),
        "错误信息应指向 oid：{parsed}"
    );
    assert_error_contract(&headers, &parsed);
}

#[tokio::test]
async fn given_oversized_object_when_batch_then_object_error_422_and_http_200() {
    let app = TestApp::new(USERS);
    let oid = missing_oid('e');
    let body = batch_body("upload", &[object_json(&oid, MAX_OBJECT_BYTES + 1)]);
    let auth = basic_header("alice", PASSWORD);

    let (status, _, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK, "单对象超限不应让整批失败");
    assert_eq!(parsed["objects"][0]["error"]["code"].as_u64(), Some(422));
    assert!(parsed["objects"][0].get("actions").is_none(), "超限对象不得给 upload action");
}

#[tokio::test]
async fn given_lfs_content_type_with_charset_when_batch_then_accepted() {
    let app = TestApp::new(USERS);
    let oid = missing_oid('f');
    let body = batch_body("download", &[object_json(&oid, 1)]);
    let auth = basic_header("alice", PASSWORD);
    let request = request(
        Method::POST,
        BATCH_PATH,
        Some(&auth),
        Some("application/vnd.git-lfs+json; charset=utf-8"),
        body,
    );

    let (status, _, parsed) = app.send_json(request).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(parsed["objects"][0]["error"]["code"].as_u64(), Some(404));
}

#[tokio::test]
async fn given_garbage_body_when_batch_then_400_with_error_contract() {
    let app = TestApp::new(USERS);
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, parsed) =
        app.send_json(batch_request(Some(&auth), "not json at all")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        parsed["message"].as_str().is_some_and(|message| message.contains("JSON")),
        "错误信息应说明 JSON 非法：{parsed}"
    );
    assert_error_contract(&headers, &parsed);
}

#[tokio::test]
async fn given_unsupported_operation_or_hash_algo_when_batch_then_400() {
    let app = TestApp::new(USERS);
    let auth = basic_header("alice", PASSWORD);
    let bad_operation = json!({ "operation": "verify", "objects": [] }).to_string();
    let bad_hash_algo =
        json!({ "operation": "download", "hash_algo": "md5", "objects": [] }).to_string();

    let (operation_status, _, operation_body) =
        app.send_json(batch_request(Some(&auth), &bad_operation)).await;
    let (hash_status, _, hash_body) =
        app.send_json(batch_request(Some(&auth), &bad_hash_algo)).await;

    assert_eq!(operation_status, StatusCode::BAD_REQUEST);
    assert!(
        operation_body["message"].as_str().is_some_and(|message| message.contains("operation"))
    );
    assert_eq!(hash_status, StatusCode::BAD_REQUEST);
    assert!(hash_body["message"].as_str().is_some_and(|message| message.contains("hash_algo")));
}

#[tokio::test]
async fn given_unknown_fields_when_batch_then_tolerated() {
    let app = TestApp::new(USERS);
    let oid = missing_oid('a');
    let body = json!({
        "operation": "download",
        "transfers": ["basic"],
        "ref": { "name": "refs/heads/main" },
        "hash_algo": "sha256",
        "objects": [object_json(&oid, 1)],
        "unknown_field": { "future": true },
    })
    .to_string();
    let auth = basic_header("alice", PASSWORD);

    let (status, _, parsed) = app.send_json(batch_request(Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(parsed["objects"][0]["error"]["code"].as_u64(), Some(404));
}

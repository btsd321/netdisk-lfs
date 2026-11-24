//! 对象传输端点集成测试：`PUT/GET/POST /lfs/objects/{oid}[/verify]` 的回路与失败路径。
//!
//! 全部通过 `tower::ServiceExt::oneshot` 直接打 `router(state)`，不绑定端口，
//! 也不起真实 `bdpan`：存储用 [`FakeStore`]，绝不访问网盘。
//!
//! 失败路径按 `docs/rust-style.md` 第 10 节必须覆盖：哈希不符、超限、对象不存在、
//! 非法 oid、角色不足、未认证，并逐一断言「对象没落库」与「本地缓冲无残留」。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};
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

const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";
const OCTET_STREAM: &str = "application/octet-stream";
const AUTH_CHALLENGE: &str = "Basic realm=\"netdisk-lfs\"";
const PASSWORD: &str = "s3cret";

/// 默认上限：1 MiB；超限用例单独构造更小的上限。
const MAX_OBJECT_BYTES: u64 = 1_048_576;

/// 默认测试账号：一个读写、一个只读。
const USERS: &[(&str, Role)] = &[("alice", Role::Readwrite), ("reader", Role::Readonly)];

/// 测试应用：router、配置与一个与 router 共享根目录的 FakeStore（写夹具用）。
struct TestApp {
    router: Router,
    config: Config,
    store: FakeStore,
}

impl TestApp {
    fn new() -> Self {
        Self::with_max_object_bytes(MAX_OBJECT_BYTES)
    }

    fn with_max_object_bytes(max_object_bytes: u64) -> Self {
        let store = FakeStore::new();
        // upload/ 与 cache/ 都放在 FakeStore 根目录下，测试结束随根目录一起清理。
        let data_dir = store.root().join("data");
        let config = test_config(&data_dir, max_object_bytes);
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::with_root(store.root()));
        let router = router(AppState::new(backend, Arc::new(config.clone())));
        Self { router, config, store }
    }

    /// 上传缓冲目录：`data_dir/upload`。
    fn upload_dir(&self) -> PathBuf {
        self.config.data_dir.as_ref().expect("测试配置带本地数据根").join("upload")
    }

    /// 下载中转目录：本分支沿用 `[cache] dir`。
    fn download_dir(&self) -> PathBuf {
        self.config.cache.dir.clone()
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

    /// 直接写入 FakeStore 一个对象（模拟「已存在」），返回其 oid。
    async fn seed_object(&self, contents: &[u8]) -> Oid {
        let digest = sha256_hex(contents);
        let oid = Oid::parse(&digest).expect("夹具哈希是合法 oid");
        let source = self.store.root().join(format!("seed-{digest}.bin"));
        tokio::fs::write(&source, contents).await.expect("写入夹具文件");
        self.store.put(&oid, &source).await.expect("写入 FakeStore");
        oid
    }

    /// 断言存储层没有该对象。
    async fn assert_absent(&self, oid: &Oid) {
        assert!(
            self.store.exists(oid).await.expect("探测对象").is_none(),
            "失败的上传不得在存储层留下对象"
        );
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let mut writer = Sha256Writer::new();
    writer.update(input);
    writer.finish()
}

fn test_config(data_dir: &Path, max_object_bytes: u64) -> Config {
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
            max_object_bytes,
            max_bdpan_procs: 1,
        },
        cache: CacheConfig { dir: data_dir.join("cache"), max_bytes: 1024 },
        auth: AuthConfig { users: auth_users },
        runtime_env: RuntimeEnv::Dev,
        data_dir: Some(data_dir.to_path_buf()),
    }
}

fn basic_header(username: &str, password: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{username}:{password}")))
}

fn object_uri(oid: &Oid) -> String {
    format!("/lfs/objects/{oid}")
}

fn verify_uri(oid: &Oid) -> String {
    format!("/lfs/objects/{oid}/verify")
}

fn request(method: Method, uri: &str, auth: Option<&str>) -> Request<Body> {
    request_with_body(method, uri, auth, Body::empty())
}

fn request_with_body(method: Method, uri: &str, auth: Option<&str>, body: Body) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    builder.body(body).expect("构造请求")
}

fn verify_request(oid: &Oid, auth: Option<&str>, body: &str) -> Request<Body> {
    let mut request =
        request_with_body(Method::POST, &verify_uri(oid), auth, Body::from(body.to_owned()));
    request
        .headers_mut()
        .insert(header::CONTENT_TYPE, header::HeaderValue::from_static(LFS_MEDIA_TYPE));
    request
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

/// 目录里的文件名；目录不存在按空处理。
async fn dir_entries(dir: &Path) -> Vec<String> {
    let mut reader = match tokio::fs::read_dir(dir).await {
        Ok(reader) => reader,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Vec::new(),
        Err(error) => panic!("读取目录 {} 失败：{error}", dir.display()),
    };
    let mut names = Vec::new();
    while let Some(entry) = reader.next_entry().await.expect("遍历目录") {
        names.push(entry.file_name().to_string_lossy().into_owned());
    }
    names
}

#[tokio::test]
async fn given_valid_object_when_put_then_get_roundtrips_with_content_length() {
    let app = TestApp::new();
    let contents = b"roundtrip payload".to_vec();
    let oid = Oid::parse(&sha256_hex(&contents)).expect("合法 oid");
    let auth = basic_header("alice", PASSWORD);

    let (put_status, put_headers, put_body) = app
        .send(request_with_body(
            Method::PUT,
            &object_uri(&oid),
            Some(&auth),
            Body::from(contents.clone()),
        ))
        .await;

    assert_eq!(put_status, StatusCode::OK);
    assert!(put_body.is_empty(), "PUT 成功应回空体：{put_body:?}");
    assert!(put_headers.get(header::CONTENT_TYPE).is_none(), "PUT 成功不设 Content-Type");
    assert_eq!(
        app.store.exists(&oid).await.expect("探测对象").expect("对象应已落库").size,
        contents.len() as u64
    );

    let (get_status, get_headers, get_body) =
        app.send(request(Method::GET, &object_uri(&oid), Some(&auth))).await;

    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(header_str(&get_headers, "content-type"), OCTET_STREAM);
    assert_eq!(header_str(&get_headers, "content-length"), contents.len().to_string());
    assert_eq!(get_body, contents);

    assert!(dir_entries(&app.upload_dir()).await.is_empty(), "上传缓冲必须清理");
    assert!(dir_entries(&app.download_dir()).await.is_empty(), "下载中转必须清理");
}

#[tokio::test]
async fn given_hash_mismatch_when_put_then_422_and_no_object_no_leftover() {
    let app = TestApp::new();
    // 路径 oid 指向的内容与实际 body 不同：必须被哈希校验拦下。
    let oid = Oid::parse(&sha256_hex(b"expected contents")).expect("合法 oid");
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, body) = app
        .send_json(request_with_body(
            Method::PUT,
            &object_uri(&oid),
            Some(&auth),
            Body::from(b"tampered contents".to_vec()),
        ))
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["message"].as_str().is_some_and(|message| message.contains("哈希不符")),
        "错误信息应说明哈希不符：{body}"
    );
    assert_error_contract(&headers, &body);
    app.assert_absent(&oid).await;
    assert!(dir_entries(&app.upload_dir()).await.is_empty(), "哈希失败后缓冲必须删除");
}

#[tokio::test]
async fn given_body_over_limit_when_put_then_422_and_no_object_no_leftover() {
    // 上限 16 字节，body 64 字节且 oid 与之匹配：仍须在超限处拒绝。
    let app = TestApp::with_max_object_bytes(16);
    let contents = vec![b'x'; 64];
    let oid = Oid::parse(&sha256_hex(&contents)).expect("合法 oid");
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, body) = app
        .send_json(request_with_body(
            Method::PUT,
            &object_uri(&oid),
            Some(&auth),
            Body::from(contents),
        ))
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        body["message"].as_str().is_some_and(|message| message.contains("上限")),
        "错误信息应说明单文件上限：{body}"
    );
    assert_error_contract(&headers, &body);
    app.assert_absent(&oid).await;
    assert!(dir_entries(&app.upload_dir()).await.is_empty(), "超限中止后缓冲必须删除");
}

#[tokio::test]
async fn given_existing_object_when_put_same_content_then_idempotent_200() {
    let app = TestApp::new();
    let contents = b"already stored";
    let oid = app.seed_object(contents).await;
    let auth = basic_header("alice", PASSWORD);

    let (status, _, body) = app
        .send(request_with_body(
            Method::PUT,
            &object_uri(&oid),
            Some(&auth),
            Body::from(contents.to_vec()),
        ))
        .await;

    assert_eq!(status, StatusCode::OK, "目标已存在也应幂等返回 200");
    assert!(body.is_empty());
    assert_eq!(
        app.store.exists(&oid).await.expect("探测对象").expect("对象仍在").size,
        contents.len() as u64
    );
    assert!(dir_entries(&app.upload_dir()).await.is_empty());
}

#[tokio::test]
async fn given_existing_object_when_put_wrong_content_then_422() {
    // 幂等不等于跳过校验：已存在的 oid 收到脏 body 仍必须 422。
    let app = TestApp::new();
    let oid = app.seed_object(b"original contents").await;
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, body) = app
        .send_json(request_with_body(
            Method::PUT,
            &object_uri(&oid),
            Some(&auth),
            Body::from(b"dirty contents".to_vec()),
        ))
        .await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert_error_contract(&headers, &body);
    assert_eq!(
        app.store.exists(&oid).await.expect("探测对象").expect("原对象仍在").size,
        b"original contents".len() as u64
    );
}

#[tokio::test]
async fn given_readonly_when_put_then_403_without_touching_storage() {
    let app = TestApp::new();
    let contents = b"readonly cannot upload";
    let oid = Oid::parse(&sha256_hex(contents)).expect("合法 oid");
    let auth = basic_header("reader", PASSWORD);

    let (status, headers, body) = app
        .send_json(request_with_body(
            Method::PUT,
            &object_uri(&oid),
            Some(&auth),
            Body::from(contents.to_vec()),
        ))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(!headers.contains_key("lfs-authenticate"), "403 不应带认证挑战头");
    assert_error_contract(&headers, &body);
    app.assert_absent(&oid).await;
    assert!(dir_entries(&app.upload_dir()).await.is_empty(), "被拒绝的上传不应留缓冲");
}

#[tokio::test]
async fn given_both_roles_when_get_existing_then_200() {
    let app = TestApp::new();
    let contents = b"both roles can read";
    let oid = app.seed_object(contents).await;

    for username in ["alice", "reader"] {
        let auth = basic_header(username, PASSWORD);
        let (status, headers, body) =
            app.send(request(Method::GET, &object_uri(&oid), Some(&auth))).await;

        assert_eq!(status, StatusCode::OK, "{username} 应可下载");
        assert_eq!(header_str(&headers, "content-type"), OCTET_STREAM);
        assert_eq!(body, contents, "{username} 读到的内容应一致");
    }
}

#[tokio::test]
async fn given_missing_object_when_get_then_404_with_error_contract() {
    let app = TestApp::new();
    let oid = Oid::parse(&"a".repeat(64)).expect("合法 oid");
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, body) =
        app.send_json(request(Method::GET, &object_uri(&oid), Some(&auth))).await;

    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_error_contract(&headers, &body);
    assert!(dir_entries(&app.download_dir()).await.is_empty(), "404 后中转文件必须清理");
}

#[tokio::test]
async fn given_invalid_oid_when_put_get_or_verify_then_400() {
    let app = TestApp::new();
    let auth = basic_header("alice", PASSWORD);
    let uri = "/lfs/objects/not-a-valid-oid";
    let verify = "/lfs/objects/not-a-valid-oid/verify";

    let (put_status, put_headers, put_body) =
        app.send_json(request_with_body(Method::PUT, uri, Some(&auth), Body::from("x"))).await;
    assert_eq!(put_status, StatusCode::BAD_REQUEST);
    assert!(
        put_body["message"].as_str().is_some_and(|message| message.contains("oid")),
        "错误信息应指向 oid：{put_body}"
    );
    assert_error_contract(&put_headers, &put_body);

    let (get_status, get_headers, get_body) =
        app.send_json(request(Method::GET, uri, Some(&auth))).await;
    assert_eq!(get_status, StatusCode::BAD_REQUEST);
    assert_error_contract(&get_headers, &get_body);

    let (verify_status, verify_headers, verify_body) =
        app.send_json(request_with_body(Method::POST, verify, Some(&auth), Body::from("{}"))).await;
    assert_eq!(verify_status, StatusCode::BAD_REQUEST);
    assert_error_contract(&verify_headers, &verify_body);
}

#[tokio::test]
async fn given_matching_size_when_verify_then_200_empty_body() {
    let app = TestApp::new();
    let contents = b"verify me";
    let oid = app.seed_object(contents).await;
    let auth = basic_header("alice", PASSWORD);
    let body = json!({ "oid": oid.as_str(), "size": contents.len() }).to_string();

    let (status, _, response_body) = app.send(verify_request(&oid, Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::OK);
    assert!(response_body.is_empty(), "verify 成功应回空体：{response_body:?}");
}

#[tokio::test]
async fn given_size_mismatch_when_verify_then_422() {
    let app = TestApp::new();
    let contents = b"verify size";
    let oid = app.seed_object(contents).await;
    let auth = basic_header("alice", PASSWORD);
    let body = json!({ "oid": oid.as_str(), "size": contents.len() + 1 }).to_string();

    let (status, headers, response) = app.send_json(verify_request(&oid, Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
    assert!(
        response["message"].as_str().is_some_and(|message| message.contains("大小不符")),
        "错误信息应说明大小不符：{response}"
    );
    assert_error_contract(&headers, &response);
}

#[tokio::test]
async fn given_missing_object_when_verify_then_422() {
    let app = TestApp::new();
    let oid = Oid::parse(&"b".repeat(64)).expect("合法 oid");
    let auth = basic_header("alice", PASSWORD);
    let body = json!({ "oid": oid.as_str(), "size": 1 }).to_string();

    let (status, headers, response) = app.send_json(verify_request(&oid, Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "verify 缺失按校验失败回 422，而不是 404");
    assert!(
        response["message"].as_str().is_some_and(|message| message.contains("不存在")),
        "错误信息应说明对象不存在：{response}"
    );
    assert_error_contract(&headers, &response);
}

#[tokio::test]
async fn given_body_oid_differs_from_path_when_verify_then_400() {
    let app = TestApp::new();
    let path_oid = app.seed_object(b"path object").await;
    let other_oid = Oid::parse(&sha256_hex(b"another object")).expect("合法 oid");
    let auth = basic_header("alice", PASSWORD);
    let body = json!({ "oid": other_oid.as_str(), "size": 1 }).to_string();

    let (status, headers, response) =
        app.send_json(verify_request(&path_oid, Some(&auth), &body)).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        response["message"].as_str().is_some_and(|message| message.contains("不一致")),
        "错误信息应说明 oid 不一致：{response}"
    );
    assert_error_contract(&headers, &response);
}

#[tokio::test]
async fn given_malformed_json_when_verify_then_400() {
    let app = TestApp::new();
    let oid = Oid::parse(&"c".repeat(64)).expect("合法 oid");
    let auth = basic_header("alice", PASSWORD);

    let (status, headers, response) =
        app.send_json(verify_request(&oid, Some(&auth), "not json at all")).await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(
        response["message"].as_str().is_some_and(|message| message.contains("JSON")),
        "错误信息应说明 JSON 非法：{response}"
    );
    assert_error_contract(&headers, &response);
}

#[tokio::test]
async fn given_no_authorization_when_transfer_endpoints_then_401_with_challenge() {
    let app = TestApp::new();
    let oid = Oid::parse(&"d".repeat(64)).expect("合法 oid");

    let requests = [
        request_with_body(Method::PUT, &object_uri(&oid), None, Body::empty()),
        request(Method::GET, &object_uri(&oid), None),
        request_with_body(Method::POST, &verify_uri(&oid), None, Body::from("{}")),
    ];

    for request in requests {
        let method = request.method().clone();
        let (status, headers, body) = app.send_json(request).await;

        assert_eq!(status, StatusCode::UNAUTHORIZED, "{method} 未认证应 401");
        assert_eq!(header_str(&headers, "lfs-authenticate"), AUTH_CHALLENGE, "{method}");
        assert_error_contract(&headers, &body);
    }
}

#[tokio::test]
async fn given_range_header_when_get_then_ignores_and_returns_full_200() {
    // B5 不实现 Range：不得报错，也不能只回片段，必须忽略头并回全量 200。
    let app = TestApp::new();
    let contents = b"range is a B6 concern".to_vec();
    let oid = app.seed_object(&contents).await;
    let auth = basic_header("alice", PASSWORD);
    let mut request = request(Method::GET, &object_uri(&oid), Some(&auth));
    request.headers_mut().insert(header::RANGE, header::HeaderValue::from_static("bytes=0-3"));

    let (status, headers, body) = app.send(request).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(header_str(&headers, "content-length"), contents.len().to_string());
    assert!(!headers.contains_key(header::CONTENT_RANGE), "B5 不应回 206/Content-Range");
    assert_eq!(body, contents);
}

#[tokio::test]
async fn given_dropped_get_body_when_response_dropped_then_temp_file_cleaned() {
    // 客户端拿到响应头就断连：body 一次都没被 poll，临时文件仍必须删除。
    let app = TestApp::new();
    let contents = b"drop the body immediately".to_vec();
    let oid = app.seed_object(&contents).await;
    let auth = basic_header("alice", PASSWORD);

    let response = app
        .router
        .clone()
        .oneshot(request(Method::GET, &object_uri(&oid), Some(&auth)))
        .await
        .expect("router 应处理请求");

    assert_eq!(response.status(), StatusCode::OK);
    // 不读 body，直接丢弃响应。
    drop(response);

    assert!(dir_entries(&app.download_dir()).await.is_empty(), "响应被丢弃后中转文件必须清理");
}

#[tokio::test]
async fn given_body_larger_than_axum_default_when_put_then_roundtrips() {
    // axum 默认请求体上限是 2 MiB；用一个 3 MiB 对象证明对象端点没有被框架层截断，
    // 也顺带覆盖「单请求多帧」的流式写入与读出。
    let app = TestApp::with_max_object_bytes(4 * 1024 * 1024);
    let contents: Vec<u8> = (0..3 * 1024 * 1024).map(|index| (index % 251) as u8).collect();
    let oid = Oid::parse(&sha256_hex(&contents)).expect("合法 oid");
    let auth = basic_header("alice", PASSWORD);

    let (put_status, _, _) = app
        .send(request_with_body(
            Method::PUT,
            &object_uri(&oid),
            Some(&auth),
            Body::from(contents.clone()),
        ))
        .await;
    assert_eq!(put_status, StatusCode::OK);

    let (get_status, headers, body) =
        app.send(request(Method::GET, &object_uri(&oid), Some(&auth))).await;

    assert_eq!(get_status, StatusCode::OK);
    assert_eq!(header_str(&headers, "content-length"), contents.len().to_string());
    assert_eq!(body.len(), contents.len(), "大对象不得被截断");
    assert_eq!(body, contents);
}

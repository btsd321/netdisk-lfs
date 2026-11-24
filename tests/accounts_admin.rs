//! 管理员账户管理端点的集成测试：JSON API、HTML 管理页与保护规则。
//!
//! 全部经 `tower::ServiceExt::oneshot` 直接打 `router(state)`，不绑定端口；账户库
//! 落在每个用例自己的临时目录，对象存储用 [`FakeStore`]，绝不访问网盘、不起真实
//! `bdpan`。
//!
//! Argon2 在 debug 构建里很慢（约几十到几百毫秒），因此：
//!
//! - 同一个测试二进制里同一条口令的 PHC 哈希只算一次（[`shared_hash`]）；
//! - 只需要「库里有这一行」的用例（分页、HTML 表格、表单操作）直接写 SQL 造数据，
//!   不付哈希成本；只有真的要登录的用例才建带真实哈希的账户。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::BodyExt;
use netdisk_lfs::{
    AccountsConfig, AppState, AuthConfig, CacheConfig, Config, FakeStore, ObjectStore, Role,
    RuntimeEnv, ServerConfig, Sha256Writer, StorageConfig, UserConfig, UserStatus, UserStore,
    hash_password, router,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const TEST_HOST: &str = "lfs.test";
/// 默认口令：21 个字符，满足 12 位下限；也是 [`shared_hash`] 缓存的那一条。
const PASSWORD: &str = "correct horse battery";
/// 重置口令用例用的新口令（与默认口令不同，用来证明旧口令失效）。
const NEW_PASSWORD: &str = "another correct horse";
/// 第三个口令：管理员重置自己口令时用。
const OTHER_PASSWORD: &str = "yet another passphrase";
const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";
const FORM: &str = "application/x-www-form-urlencoded";
/// 只用于「直接写库造行」的占位 PHC 串：不会被任何用例拿去校验。
const DUMMY_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 每个用例一个临时目录；Drop 时连同 SQLite 的 `-wal` / `-shm` 一起删除。
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("netdisk-lfs-accounts-admin-{}-{seq}", std::process::id()));
        std::fs::create_dir(&path).expect("创建临时目录");
        Self { path }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 测试应用：router + 与 router 共享的账户库句柄 + 账户库路径（用来直接造行）。
struct TestApp {
    router: Router,
    /// `None` 表示没有接入账户库（验证 503 行为）。
    store: Option<Arc<UserStore>>,
    db: PathBuf,
    /// 临时目录必须比账户库活得久。
    _workspace: Workspace,
}

impl TestApp {
    /// 默认配置（approval 策略、无 config 用户、默认限速），带账户库。
    fn new() -> Self {
        Self::with(|_| {})
    }

    /// 在默认配置上做修改；`tweak` 在打开账户库之后、装配 router 之前执行。
    fn with(tweak: impl FnOnce(&mut Config)) -> Self {
        let workspace = Workspace::new();
        let db = workspace.path.join("accounts.db");
        let store = Arc::new(UserStore::open(&db).expect("账户库应能打开"));
        let mut config = base_config(db.clone());
        tweak(&mut config);
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::new());
        let state = AppState::with_accounts(backend, Arc::new(config), Arc::clone(&store));
        Self { router: router(state), store: Some(store), db, _workspace: workspace }
    }

    /// 没有接入账户库的实例：配置里有一个**管理员**用户，用来验证「认证与角色都通过、
    /// 但端点仍 503」。
    fn without_accounts() -> Self {
        let workspace = Workspace::new();
        let db = workspace.path.join("accounts.db");
        let mut config = base_config(db.clone());
        add_config_user(&mut config, "cfgadmin", PASSWORD, Role::Admin);
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::new());
        let state = AppState::new(backend, Arc::new(config));
        Self { router: router(state), store: None, db, _workspace: workspace }
    }

    fn store(&self) -> &Arc<UserStore> {
        self.store.as_ref().expect("本用例应接入账户库")
    }

    /// 直接在库里建一个账户（哈希真实口令，便于随后用它登录）。
    async fn create_user(&self, name: &str, password: &str, role: Role, status: UserStatus) {
        self.store()
            .create(name, &shared_hash(password), role, status)
            .await
            .unwrap_or_else(|error| panic!("创建 {name} 失败：{error}"));
    }

    /// 直接写库造一行：不走 Argon2，用于分页数量、HTML 表格与「恶意用户名」等场景。
    fn seed(&self, username: &str, role: &str, status: &str) {
        let conn = rusqlite::Connection::open(&self.db).expect("直连账户库");
        conn.execute(
            "INSERT INTO users (username, password_hash, role, status, created_at, updated_at, last_login_at)
             VALUES (?1, ?2, ?3, ?4, 0, 0, NULL)",
            rusqlite::params![username, DUMMY_HASH, role, status],
        )
        .unwrap_or_else(|error| panic!("插入种子账户 {username} 失败：{error}"));
    }

    /// 批量造 `count` 个 readwrite/active 账户（`seed000`、`seed001`…）。
    fn seed_many(&self, count: usize) {
        let conn = rusqlite::Connection::open(&self.db).expect("直连账户库");
        for index in 0..count {
            conn.execute(
                "INSERT INTO users (username, password_hash, role, status, created_at, updated_at, last_login_at)
                 VALUES (?1, ?2, 'readwrite', 'active', 0, 0, NULL)",
                rusqlite::params![format!("seed{index:03}"), DUMMY_HASH],
            )
            .expect("批量插入种子账户");
        }
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
}

/// 同一条口令在整个测试二进制里只做一次 Argon2 哈希。
fn shared_hash(password: &str) -> String {
    static PASSWORD_HASH: OnceLock<String> = OnceLock::new();
    if password == PASSWORD {
        return PASSWORD_HASH.get_or_init(|| hash_password(PASSWORD).expect("哈希应成功")).clone();
    }
    hash_password(password).expect("哈希应成功")
}

fn base_config(db: PathBuf) -> Config {
    Config {
        server: ServerConfig {
            listen: "127.0.0.1:0".parse().expect("合法监听地址"),
            public_base: String::new(),
        },
        storage: StorageConfig {
            objects_root: "/apps/bdpan/lfs".to_owned(),
            tmp_root: "/apps/bdpan/lfs/tmp".to_owned(),
            bdpan_bin: "/bin/true".into(),
            max_object_bytes: 0,
            max_bdpan_procs: 1,
            bdpan_timeout_secs: 300,
            bdpan_min_throughput_bytes_per_sec: 102_400,
        },
        cache: CacheConfig { dir: std::env::temp_dir(), max_bytes: 0 },
        accounts: AccountsConfig { db, ..AccountsConfig::default() },
        auth: AuthConfig { users: std::collections::BTreeMap::new() },
        runtime_env: RuntimeEnv::Dev,
        data_dir: None,
    }
}

fn sha256_hex(input: &[u8]) -> String {
    let mut writer = Sha256Writer::new();
    writer.update(input);
    writer.finish()
}

fn add_config_user(config: &mut Config, name: &str, password: &str, role: Role) {
    config.auth.users.insert(
        name.to_owned(),
        UserConfig { password_sha256: sha256_hex(password.as_bytes()), role },
    );
}

fn basic_header(username: &str, password: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{username}:{password}")))
}

fn request(
    method: Method,
    uri: &str,
    auth: Option<&str>,
    accept: Option<&str>,
    content_type: Option<&str>,
    body: String,
) -> Request<Body> {
    let mut builder = Request::builder().method(method).uri(uri).header(header::HOST, TEST_HOST);
    if let Some(auth) = auth {
        builder = builder.header(header::AUTHORIZATION, auth);
    }
    if let Some(accept) = accept {
        builder = builder.header(header::ACCEPT, accept);
    }
    if let Some(content_type) = content_type {
        builder = builder.header(header::CONTENT_TYPE, content_type);
    }
    builder.body(Body::from(body)).expect("构造请求")
}

/// JSON API 请求（可选请求体）。
fn api(
    method: Method,
    uri: &str,
    username: &str,
    password: &str,
    body: Option<&Value>,
) -> Request<Body> {
    let (content_type, body) = match body {
        Some(value) => (Some("application/json"), value.to_string()),
        None => (None, String::new()),
    };
    request(method, uri, Some(&basic_header(username, password)), None, content_type, body)
}

/// 管理页的表单 POST（浏览器会带 `Accept: text/html`）。
fn form_post(uri: &str, username: &str, password: &str, body: &str) -> Request<Body> {
    request(
        Method::POST,
        uri,
        Some(&basic_header(username, password)),
        Some("text/html"),
        Some(FORM),
        body.to_owned(),
    )
}

/// 浏览器打开管理页的 GET。
fn page_get(uri: &str, username: &str, password: &str) -> Request<Body> {
    request(
        Method::GET,
        uri,
        Some(&basic_header(username, password)),
        Some("text/html,application/xhtml+xml"),
        None,
        String::new(),
    )
}

fn content_type(headers: &HeaderMap) -> &str {
    headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("")
}

fn location(headers: &HeaderMap) -> &str {
    headers.get(header::LOCATION).and_then(|value| value.to_str().ok()).unwrap_or("")
}

fn body_text(body: Vec<u8>) -> String {
    String::from_utf8(body).expect("HTML 响应应是 UTF-8")
}

/// 断言错误体符合既有契约：`{message, request_id}`。
fn assert_error_contract(headers: &HeaderMap, body: &Value) {
    assert_eq!(content_type(headers), LFS_MEDIA_TYPE);
    assert!(
        body["message"].as_str().is_some_and(|message| !message.is_empty()),
        "错误体必须带非空 message：{body}"
    );
    assert!(body["request_id"].as_str().is_some_and(|id| !id.is_empty()));
}

/// 断言 HTML 错误页：状态码一致、媒体类型是 HTML、带 request id 与回管理页的链接。
fn assert_html_error(status: StatusCode, headers: &HeaderMap, body: &str) {
    assert!(content_type(headers).starts_with("text/html"), "实际：{}", content_type(headers));
    assert!(body.contains("<!doctype html>"), "应是完整页面：{body}");
    assert!(body.contains("请求 id："), "错误页应带 request id：{body}");
    assert!(body.contains(r#"href="/admin""#), "错误页应能回到管理页：{body}");
    assert!(!body.contains("<script"), "管理页不得含脚本：{body}");
    assert!(status.is_client_error(), "错误页状态码应是 4xx，实际 {status}");
}

// ---------------------------------------------------------------------------
// 权限与账户库缺失
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_non_admin_when_admin_endpoints_then_403_json_or_html_page() {
    let app = TestApp::new();
    app.create_user("bob", PASSWORD, Role::Readwrite, UserStatus::Active).await;

    let (status, headers, body) =
        app.send_json(api(Method::GET, "/admin/users", "bob", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_contract(&headers, &body);
    assert!(
        body["message"].as_str().is_some_and(|message| message.contains("管理员")),
        "应说明需要管理员权限：{body}"
    );

    // 浏览器（Accept: text/html）拿到 403 页而不是 JSON。
    let (status, headers, body) = app.send(page_get("/admin", "bob", PASSWORD)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
    let body = body_text(body);
    assert!(content_type(&headers).starts_with("text/html"), "实际：{}", content_type(&headers));
    assert!(body.contains("禁止访问"), "应是 403 页：{body}");
    assert!(!body.contains("<script"), "页面不得含脚本：{body}");

    // 未认证仍然是 401：认证先于角色判定。
    let anonymous = request(Method::GET, "/admin/users", None, None, None, String::new());
    let (status, _, _) = app.send_json(anonymous).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_no_account_store_when_admin_endpoints_then_503() {
    let app = TestApp::without_accounts();

    let (status, headers, body) =
        app.send_json(api(Method::GET, "/admin/users", "cfgadmin", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_contract(&headers, &body);

    let (status, headers, body) = app.send(page_get("/admin", "cfgadmin", PASSWORD)).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(content_type(&headers).starts_with("text/html"));
    assert!(body_text(body).contains("账户库未启用"), "应说明原因，而不是空表格");
}

// ---------------------------------------------------------------------------
// 列表
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_accounts_when_list_then_total_status_filter_and_paging() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("alice", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    app.create_user("bob", PASSWORD, Role::Readwrite, UserStatus::Pending).await;
    app.create_user("carol", PASSWORD, Role::Readonly, UserStatus::Disabled).await;

    let (status, headers, body) =
        app.send_json(api(Method::GET, "/admin/users", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type(&headers), "application/json");
    assert_eq!(body["total"], 4);
    let users = body["users"].as_array().expect("users 应是数组");
    assert_eq!(users.len(), 4);
    assert_eq!(users[0]["username"], "root");
    assert_eq!(users[0]["role"], "admin");
    assert_eq!(users[0]["status"], "active");
    assert!(users[0]["created_at"].as_i64().is_some_and(|created| created > 0));
    assert!(users[0]["last_login_at"].as_i64().is_some_and(|login| login > 0));
    assert!(users[0].get("password_hash").is_none(), "不回显口令哈希");
    assert!(users[0].get("password").is_none(), "不回显口令");

    let (status, _, filtered) = app
        .send_json(api(Method::GET, "/admin/users?status=pending", "root", PASSWORD, None))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(filtered["total"], 1, "total 是过滤后的总数");
    assert_eq!(filtered["users"][0]["username"], "bob");

    // 分页：total 与当页条数解耦；offset 按账户库 id 顺序跳过。
    let (status, _, paged) = app
        .send_json(api(Method::GET, "/admin/users?limit=1&offset=1", "root", PASSWORD, None))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(paged["total"], 4);
    assert_eq!(paged["users"].as_array().map(Vec::len), Some(1));
    assert_eq!(paged["users"][0]["username"], "alice");

    // 非法过滤/分页参数是 400，不是「静默忽略」。
    let (status, headers, body) =
        app.send_json(api(Method::GET, "/admin/users?status=bogus", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_contract(&headers, &body);
    let (status, _, _) =
        app.send_json(api(Method::GET, "/admin/users?limit=abc", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn given_many_accounts_when_list_then_limit_capped_and_default_page_size() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.seed_many(104);

    // 单页上限 100：请求再大也只回 100 条，total 仍是全量。
    let (status, _, body) =
        app.send_json(api(Method::GET, "/admin/users?limit=1000", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["total"], 105);
    assert_eq!(body["users"].as_array().map(Vec::len), Some(100), "limit 上限应是 100");

    // 不传 limit 与 limit=0 都按 50 处理。
    for uri in ["/admin/users", "/admin/users?limit=0"] {
        let (status, _, body) = app.send_json(api(Method::GET, uri, "root", PASSWORD, None)).await;
        assert_eq!(status, StatusCode::OK);
        assert_eq!(body["total"], 105);
        assert_eq!(body["users"].as_array().map(Vec::len), Some(50), "{uri} 应默认 50 条");
    }
}

// ---------------------------------------------------------------------------
// 创建
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_admin_create_when_valid_then_201_and_can_login() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;

    let payload = json!({ "username": "newadmin", "password": PASSWORD, "role": "admin" });
    let (status, headers, body) =
        app.send_json(api(Method::POST, "/admin/users", "root", PASSWORD, Some(&payload))).await;
    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(content_type(&headers), "application/json");
    assert_eq!(body["username"], "newadmin");
    assert_eq!(body["role"], "admin", "管理员可以创建管理员");
    assert_eq!(body["status"], "active", "status 缺省是 active");
    assert!(body["created_at"].as_i64().is_some_and(|created| created > 0));
    assert_eq!(body["last_login_at"], Value::Null);

    // 新管理员立刻可用：能过认证、能进管理端点。
    let (status, _, _) =
        app.send_json(api(Method::GET, "/admin/users", "newadmin", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::OK);

    // 重名 409。
    let (status, headers, body) =
        app.send_json(api(Method::POST, "/admin/users", "root", PASSWORD, Some(&payload))).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_contract(&headers, &body);

    // 弱口令 400（在哈希之前就拒）。
    let weak = json!({ "username": "weakling", "password": "short", "role": "readwrite" });
    let (status, headers, body) =
        app.send_json(api(Method::POST, "/admin/users", "root", PASSWORD, Some(&weak))).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_error_contract(&headers, &body);

    // 非法角色 / 非法用户名 / 非法状态都是 400。
    for payload in [
        json!({ "username": "someone", "password": PASSWORD, "role": "superuser" }),
        json!({ "username": "a:b", "password": PASSWORD, "role": "readwrite" }),
        json!({ "username": "someone", "password": PASSWORD, "role": "readwrite", "status": "gone" }),
        json!({ "username": "someone", "password": PASSWORD, "role": "readwrite", "extra": 1 }),
    ] {
        let (status, headers, body) = app
            .send_json(api(Method::POST, "/admin/users", "root", PASSWORD, Some(&payload)))
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "载荷 {payload} 应被拒");
        assert_error_contract(&headers, &body);
    }
    assert_eq!(app.store().get("weakling").await.expect("查询"), None, "被拒的请求不得建账户");
}

// ---------------------------------------------------------------------------
// 修改
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_pending_account_when_patched_active_then_login_works() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    let created = json!({ "username": "pat", "password": PASSWORD, "role": "readwrite", "status": "pending" });
    let (status, _, _) =
        app.send_json(api(Method::POST, "/admin/users", "root", PASSWORD, Some(&created))).await;
    assert_eq!(status, StatusCode::CREATED);

    let (status, _, _) =
        app.send_json(api(Method::GET, "/account/me", "pat", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "待审批账户不能登录");

    let (status, _, body) = app
        .send_json(api(
            Method::PATCH,
            "/admin/users/pat",
            "root",
            PASSWORD,
            Some(&json!({ "status": "active" })),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "active");

    let (status, _, _) =
        app.send_json(api(Method::GET, "/account/me", "pat", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::OK, "审批通过后即可登录");
}

#[tokio::test]
async fn given_only_admin_when_patch_self_then_409_last_admin() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;

    for payload in [json!({ "role": "readwrite" }), json!({ "status": "disabled" })] {
        let (status, headers, body) = app
            .send_json(api(Method::PATCH, "/admin/users/root", "root", PASSWORD, Some(&payload)))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "载荷 {payload} 必须被拒");
        assert_error_contract(&headers, &body);
        assert!(
            body["message"].as_str().is_some_and(|message| message.contains("管理员")),
            "应说明最后一个管理员的限制：{body}"
        );
    }
    // 状态与角色都没变：拒绝不产生副作用。
    let stored = app.store().get("root").await.expect("查询").expect("账户存在");
    assert_eq!(stored.role, Role::Admin);
    assert_eq!(stored.status, UserStatus::Active);

    // 空补丁与不存在的用户。
    let (status, _, _) = app
        .send_json(api(Method::PATCH, "/admin/users/root", "root", PASSWORD, Some(&json!({}))))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let (status, _, _) = app
        .send_json(api(
            Method::PATCH,
            "/admin/users/nobody",
            "root",
            PASSWORD,
            Some(&json!({ "status": "active" })),
        ))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test]
async fn given_config_same_name_admin_when_patch_last_admin_then_still_409() {
    // 配置里同名条目是 admin，但它就是同一个人：不算「另一个管理员」，因此库里
    // 唯一的 active 管理员仍然受保护（文案是「最后一个管理员」，不是「不能改自己」）。
    let app = TestApp::with(|config| add_config_user(config, "root", PASSWORD, Role::Admin));
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;

    let (status, headers, body) = app
        .send_json(api(
            Method::PATCH,
            "/admin/users/root",
            "root",
            PASSWORD,
            Some(&json!({ "status": "disabled" })),
        ))
        .await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_contract(&headers, &body);
    assert!(
        body["message"].as_str().is_some_and(|message| message.contains("最后一个")),
        "配置同名条目不得被当成另一个管理员：{body}"
    );
}

#[tokio::test]
async fn given_two_admins_when_patch_self_then_409_but_other_admin_demotable() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("helper", PASSWORD, Role::Admin, UserStatus::Active).await;

    // 改自己：即使还有别的管理员也不允许。
    for payload in [json!({ "role": "readwrite" }), json!({ "status": "disabled" })] {
        let (status, headers, body) = app
            .send_json(api(Method::PATCH, "/admin/users/root", "root", PASSWORD, Some(&payload)))
            .await;
        assert_eq!(status, StatusCode::CONFLICT, "载荷 {payload} 必须被拒");
        assert_error_contract(&headers, &body);
        assert!(
            body["message"].as_str().is_some_and(|message| message.contains("自己")),
            "应说明不能改自己：{body}"
        );
    }

    // 降级另一个管理员：允许（还剩 root 一个管理员）。
    let (status, _, body) = app
        .send_json(api(
            Method::PATCH,
            "/admin/users/helper",
            "root",
            PASSWORD,
            Some(&json!({ "role": "readwrite" })),
        ))
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["role"], "readwrite");

    // 降级立即生效：helper 不再能进管理端点。
    let (status, _, _) =
        app.send_json(api(Method::GET, "/admin/users", "helper", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::FORBIDDEN);
}

// ---------------------------------------------------------------------------
// 删除
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_only_admin_when_delete_self_then_409() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;

    let (status, headers, body) =
        app.send_json(api(Method::DELETE, "/admin/users/root", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_contract(&headers, &body);
    assert!(
        body["message"].as_str().is_some_and(|message| message.contains("管理员")),
        "最后一个管理员必须被保护：{body}"
    );
    assert!(app.store().get("root").await.expect("查询").is_some(), "账户仍应在库中");
}

#[tokio::test]
async fn given_two_admins_when_delete_self_then_409() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("helper", PASSWORD, Role::Admin, UserStatus::Active).await;

    let (status, headers, body) =
        app.send_json(api(Method::DELETE, "/admin/users/root", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_contract(&headers, &body);
    assert!(
        body["message"].as_str().is_some_and(|message| message.contains("自己")),
        "应说明不能删自己：{body}"
    );
}

#[tokio::test]
async fn given_target_account_when_deleted_then_204_and_login_rejected() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("dora", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    assert_eq!(
        app.send_json(api(Method::GET, "/account/me", "dora", PASSWORD, None)).await.0,
        StatusCode::OK,
        "删除前应能登录"
    );

    let (status, headers, body) =
        app.send(api(Method::DELETE, "/admin/users/dora", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty(), "204 不应带响应体");
    assert!(headers.get(header::CONTENT_TYPE).is_none(), "204 不带 Content-Type");

    let (status, _, _) =
        app.send_json(api(Method::GET, "/account/me", "dora", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "删除后凭据立即失效");

    let (status, _, _) =
        app.send_json(api(Method::DELETE, "/admin/users/dora", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "重复删除是 404");
}

#[tokio::test]
async fn given_config_same_name_when_delete_then_409() {
    // 配置里有 legacy 的旧 sha256 口令；库里也有同名账户。
    let app = TestApp::with(|config| add_config_user(config, "legacy", PASSWORD, Role::Readwrite));
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("legacy", PASSWORD, Role::Readwrite, UserStatus::Active).await;

    let (status, headers, body) =
        app.send_json(api(Method::DELETE, "/admin/users/legacy", "root", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_contract(&headers, &body);
    assert!(
        body["message"].as_str().is_some_and(|message| message.contains("[auth.users]")),
        "应提示先移除配置条目：{body}"
    );
    assert!(app.store().get("legacy").await.expect("查询").is_some(), "被拒时不得删行");
}

// ---------------------------------------------------------------------------
// 重置口令
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_account_when_admin_resets_password_then_old_rejected_new_works() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("erin", PASSWORD, Role::Readwrite, UserStatus::Active).await;

    let payload = json!({ "password": NEW_PASSWORD });
    let (status, headers, body) = app
        .send(api(Method::POST, "/admin/users/erin/password", "root", PASSWORD, Some(&payload)))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(body.is_empty(), "204 不应带响应体");
    assert!(headers.get(header::CONTENT_TYPE).is_none());

    let (status, _, _) =
        app.send_json(api(Method::GET, "/account/me", "erin", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "旧口令必须失效");
    let (status, _, _) =
        app.send_json(api(Method::GET, "/account/me", "erin", NEW_PASSWORD, None)).await;
    assert_eq!(status, StatusCode::OK, "新口令应可登录");

    // 弱口令 400，且不改动现有哈希。
    let before = app.store().password_hash("erin").await.expect("读哈希").expect("有哈希");
    let (status, _, _) = app
        .send_json(api(
            Method::POST,
            "/admin/users/erin/password",
            "root",
            PASSWORD,
            Some(&json!({ "password": "short" })),
        ))
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    let after = app.store().password_hash("erin").await.expect("读哈希").expect("有哈希");
    assert_eq!(before, after, "被拒的重置不得改动哈希");

    // 管理员可以重置自己的口令。
    let (status, _, _) = app
        .send(api(
            Method::POST,
            "/admin/users/root/password",
            "root",
            PASSWORD,
            Some(&json!({ "password": OTHER_PASSWORD })),
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);
    let (status, _, _) =
        app.send_json(api(Method::GET, "/account/me", "root", OTHER_PASSWORD, None)).await;
    assert_eq!(status, StatusCode::OK, "重置自己的口令后应能用新口令登录");
}

// ---------------------------------------------------------------------------
// HTML 管理页
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_admin_page_when_get_then_table_with_escaped_username() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.seed("pending-pal", "readwrite", "pending");
    // 绕过 API 校验直接写库：模拟「有人手工改库」把恶意字符串塞进用户名。
    // 页面必须照样转义——这正是 escape_html 存在的理由。
    app.seed("<script>alert(1)</script>", "readwrite", "disabled");

    let (status, headers, body) = app.send(page_get("/admin", "root", PASSWORD)).await;
    assert_eq!(status, StatusCode::OK);
    assert!(content_type(&headers).starts_with("text/html"));
    let body = body_text(body);
    assert!(body.contains("账户管理"));
    assert!(body.contains("<table>"));
    assert!(body.contains("pending-pal"));
    assert!(body.contains("&lt;script&gt;alert(1)&lt;/script&gt;"), "用户名必须转义：{body}");
    assert!(!body.contains("<script"), "页面不得出现脚本标签：{body}");

    // 每行都有状态按钮、角色下拉、口令输入与带确认框的删除表单。
    assert!(body.contains(r#"action="/admin/users/pending-pal/approve""#));
    assert!(body.contains(r#"action="/admin/users/root/disable""#));
    assert!(body.contains(r#"<select name="role">"#));
    assert!(body.contains(r#"name="password""#));
    assert!(body.contains(r#"action="/admin/users/root/delete""#));
    assert!(body.contains(r#"name="confirm""#));

    // 状态过滤：只显示待审批。
    let (status, _, filtered) = app.send(page_get("/admin?status=pending", "root", PASSWORD)).await;
    assert_eq!(status, StatusCode::OK);
    let filtered = body_text(filtered);
    assert!(filtered.contains("pending-pal"));
    assert!(!filtered.contains(">root<"), "过滤后不应出现 normal 账户：{filtered}");

    // 无法识别的过滤值：忽略并转义回显，不 500。
    let (status, _, unknown) =
        app.send(page_get("/admin?status=%3Cscript%3E", "root", PASSWORD)).await;
    assert_eq!(status, StatusCode::OK);
    let unknown = body_text(unknown);
    assert!(unknown.contains("无法识别的状态过滤"), "应提示过滤值无效：{unknown}");
    assert!(unknown.contains("&lt;script&gt;"), "回显必须转义：{unknown}");
}

#[tokio::test]
async fn given_admin_page_when_form_approve_role_and_missing_user_then_303_or_404() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.seed("pat", "readwrite", "pending");

    // 批准：带上页面里的隐藏过滤字段，成功后回到同一个过滤视图。
    let (status, headers, body) =
        app.send(form_post("/admin/users/pat/approve", "root", PASSWORD, "status=pending")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin?status=pending");
    assert!(body.is_empty(), "303 不带响应体");
    let stored = app.store().get("pat").await.expect("查询").expect("账户存在");
    assert_eq!(stored.status, UserStatus::Active, "批准后状态应是 active");

    // 角色切换表单。
    let (status, headers, _) =
        app.send(form_post("/admin/users/pat/role", "root", PASSWORD, "role=readonly")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin");
    assert_eq!(app.store().get("pat").await.expect("查询").expect("账户存在").role, Role::Readonly);

    // 未知用户：404 页而不是 500。
    let (status, headers, body) =
        app.send(form_post("/admin/users/nobody/approve", "root", PASSWORD, "")).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_html_error(status, &headers, &body_text(body));

    // 非法角色：400 页。
    let (status, headers, body) =
        app.send(form_post("/admin/users/pat/role", "root", PASSWORD, "role=superuser")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_html_error(status, &headers, &body_text(body));
}

#[tokio::test]
async fn given_admin_page_when_disable_and_enable_forms_then_303_and_state_flips() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.seed("flip", "readwrite", "active");

    let (status, headers, _) =
        app.send(form_post("/admin/users/flip/disable", "root", PASSWORD, "")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin");
    assert_eq!(
        app.store().get("flip").await.expect("查询").expect("账户存在").status,
        UserStatus::Disabled
    );

    let (status, headers, _) =
        app.send(form_post("/admin/users/flip/enable", "root", PASSWORD, "status=disabled")).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin?status=disabled");
    assert_eq!(
        app.store().get("flip").await.expect("查询").expect("账户存在").status,
        UserStatus::Active
    );
}

#[tokio::test]
async fn given_admin_page_when_password_and_delete_forms_then_303_and_effect() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.seed("victim", "readwrite", "active");

    // 重置口令表单：哈希被换掉（不在这里做登录，省一次 Argon2 校验）。
    let before = app.store().password_hash("victim").await.expect("读哈希").expect("有哈希");
    let body = format!("password={NEW_PASSWORD}");
    let (status, headers, _) =
        app.send(form_post("/admin/users/victim/password-form", "root", PASSWORD, &body)).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin");
    let after = app.store().password_hash("victim").await.expect("读哈希").expect("有哈希");
    assert_ne!(before, after, "重置后哈希应变化");

    // 删除表单：没有勾选确认框时 400，勾选后 303 且行真的没了。
    let (status, headers, error_body) =
        app.send(form_post("/admin/users/victim/delete", "root", PASSWORD, "status=active")).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_html_error(status, &headers, &body_text(error_body));
    assert!(app.store().get("victim").await.expect("查询").is_some(), "未确认时不得删除");

    let (status, headers, _) = app
        .send(form_post(
            "/admin/users/victim/delete",
            "root",
            PASSWORD,
            "status=active&confirm=yes",
        ))
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin?status=active");
    assert_eq!(app.store().get("victim").await.expect("查询"), None, "确认后应删除");
}

//! 账户 HTTP 端点的集成测试：注册策略、认证接入账户库、自身账户管理。
//!
//! 全部经 `tower::ServiceExt::oneshot` 直接打 `router(state)`，不绑定端口；账户库
//! 落在每个用例自己的临时目录，对象存储用 [`FakeStore`]，绝不访问网盘、不起真实
//! `bdpan`。
//!
//! Argon2 每个哈希约几十毫秒，用例数量刻意收敛：能用 config 用户（sha256，便宜）
//! 覆盖的路径就不建库内账户。

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

use axum::Router;
use axum::body::Body;
use axum::http::{HeaderMap, Method, Request, StatusCode, header};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::BodyExt;
use netdisk_lfs::{
    AccountsConfig, AppState, AuthConfig, CacheConfig, Config, FakeStore, ObjectStore,
    RegistrationPolicy, Role, RuntimeEnv, ServerConfig, Sha256Writer, StorageConfig, UserConfig,
    UserStatus, UserStore, hash_password, router,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const TEST_HOST: &str = "lfs.test";
/// 默认口令：21 个字符，满足 12 位下限。
const PASSWORD: &str = "correct horse battery";
/// 改密用例用的新口令。
const NEW_PASSWORD: &str = "another correct horse";
const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";

/// 每个用例一个临时目录；Drop 时连同 SQLite 的 `-wal` / `-shm` 一起删除。
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("netdisk-lfs-accounts-http-{}-{seq}", std::process::id()));
        std::fs::create_dir(&path).expect("创建临时目录");
        Self { path }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 测试应用：router + 与 router 共享的账户库句柄（用来直接改库状态）。
struct TestApp {
    router: Router,
    /// `None` 表示没有接入账户库（验证 503 行为）。
    store: Option<Arc<UserStore>>,
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
        let mut config = base_config(db);
        tweak(&mut config);
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::new());
        let state = AppState::with_accounts(backend, Arc::new(config), Arc::clone(&store));
        Self { router: router(state), store: Some(store), _workspace: workspace }
    }

    /// 没有接入账户库的实例：配置里有一个用户，用来验证「认证通过后端点仍 503」。
    fn without_accounts() -> Self {
        let workspace = Workspace::new();
        let mut config = base_config(workspace.path.join("accounts.db"));
        add_config_user(&mut config, "legacy", PASSWORD, Role::Readwrite);
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::new());
        let state = AppState::new(backend, Arc::new(config));
        Self { router: router(state), store: None, _workspace: workspace }
    }

    fn store(&self) -> &Arc<UserStore> {
        self.store.as_ref().expect("本用例应接入账户库")
    }

    /// 直接在库里建一个账户（哈希真实口令，便于随后用它登录）。
    async fn create_user(&self, name: &str, password: &str, role: Role, status: UserStatus) {
        let hash = hash_password(password).expect("哈希应成功");
        self.store()
            .create(name, &hash, role, status)
            .await
            .unwrap_or_else(|error| panic!("创建 {name} 失败：{error}"));
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
        auth: AuthConfig { users: BTreeMap::new() },
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

fn post_json(uri: &str, body: &Value) -> Request<Body> {
    request(Method::POST, uri, None, Some("application/json"), body.to_string())
}

fn authed(
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
    request(method, uri, Some(&basic_header(username, password)), content_type, body)
}

fn content_type(headers: &HeaderMap) -> &str {
    headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("")
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

// ---------------------------------------------------------------------------
// 注册策略
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_open_policy_when_register_then_201_active_and_login_works() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Open);

    let (status, headers, body) = app
        .send_json(post_json(
            "/account/register",
            &json!({ "username": "alice", "password": PASSWORD }),
        ))
        .await;

    assert_eq!(status, StatusCode::CREATED);
    assert_eq!(content_type(&headers), "application/json");
    assert_eq!(body["username"], "alice");
    assert_eq!(body["role"], "readwrite", "默认角色是 readwrite");
    assert_eq!(body["status"], "active");
    assert!(body.get("password").is_none(), "不回显口令");
    assert!(body.get("password_hash").is_none(), "不回显口令哈希");

    // 注册后立即可用：认证中间件走 DB 哈希。
    let (me_status, _, me) =
        app.send_json(authed(Method::GET, "/account/me", "alice", PASSWORD, None)).await;
    assert_eq!(me_status, StatusCode::OK);
    assert_eq!(me["username"], "alice");
    assert_eq!(me["role"], "readwrite");
    assert_eq!(me["status"], "active");
    assert!(me["created_at"].as_i64().is_some_and(|created| created > 0));
    assert!(
        me["last_login_at"].as_i64().is_some_and(|login| login > 0),
        "首次登录应记录 last_login_at：{me}"
    );
}

#[tokio::test]
async fn given_approval_policy_when_register_then_202_pending_until_approved() {
    let app = TestApp::new();
    assert_eq!(app.store().get("bob").await.expect("查询"), None);

    let (status, _, body) = app
        .send_json(post_json(
            "/account/register",
            &json!({ "username": "bob", "password": PASSWORD }),
        ))
        .await;

    assert_eq!(status, StatusCode::ACCEPTED);
    assert_eq!(body["status"], "pending");
    let stored = app.store().get("bob").await.expect("查询").expect("账户应已创建");
    assert_eq!(stored.status, UserStatus::Pending);

    // 待审批账户即使口令正确也 401，且文案与「口令错误」完全一致。
    let (pending_status, pending_headers, pending) =
        app.send_json(authed(Method::GET, "/account/me", "bob", PASSWORD, None)).await;
    assert_eq!(pending_status, StatusCode::UNAUTHORIZED);
    assert_eq!(
        pending_headers.get("lfs-authenticate").and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"netdisk-lfs\"")
    );
    assert_error_contract(&pending_headers, &pending);

    app.store().update_status("bob", UserStatus::Active).await.expect("审批应成功");
    let (active_status, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "bob", PASSWORD, None)).await;
    assert_eq!(active_status, StatusCode::OK);
}

#[tokio::test]
async fn given_disabled_account_when_login_then_401_same_message() {
    let app = TestApp::new();
    app.create_user("dora", PASSWORD, Role::Readwrite, UserStatus::Disabled).await;

    let (status, headers, body) =
        app.send_json(authed(Method::GET, "/account/me", "dora", PASSWORD, None)).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_error_contract(&headers, &body);
    assert_eq!(
        body["message"], "需要 HTTP Basic 认证",
        "禁用账户与口令错误必须同一文案，不泄漏账户状态"
    );
}

#[tokio::test]
async fn given_closed_policy_when_register_then_403_and_no_account() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Closed);

    let (status, headers, body) = app
        .send_json(post_json(
            "/account/register",
            &json!({ "username": "carol", "password": PASSWORD }),
        ))
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_error_contract(&headers, &body);
    assert_eq!(app.store().get("carol").await.expect("查询"), None, "closed 时不得建账户");
}

#[tokio::test]
async fn given_duplicate_username_when_register_then_409() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Open);
    let payload = json!({ "username": "dave", "password": PASSWORD });

    let (first, _, _) = app.send_json(post_json("/account/register", &payload)).await;
    let (second, headers, body) = app.send_json(post_json("/account/register", &payload)).await;

    assert_eq!(first, StatusCode::CREATED);
    assert_eq!(second, StatusCode::CONFLICT);
    assert_error_contract(&headers, &body);
    assert!(body["message"].as_str().is_some_and(|message| message.contains("已被占用")));
}

#[tokio::test]
async fn given_bad_username_or_short_password_when_register_then_400() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Open);

    let (bad_name, name_headers, name_body) = app
        .send_json(post_json(
            "/account/register",
            &json!({ "username": "a b", "password": PASSWORD }),
        ))
        .await;
    let (short, short_headers, short_body) = app
        .send_json(post_json(
            "/account/register",
            &json!({ "username": "erin", "password": "short" }),
        ))
        .await;

    assert_eq!(bad_name, StatusCode::BAD_REQUEST);
    assert_error_contract(&name_headers, &name_body);
    assert!(name_body["message"].as_str().is_some_and(|message| message.contains("用户名")));
    assert_eq!(short, StatusCode::BAD_REQUEST);
    assert_error_contract(&short_headers, &short_body);
    assert!(short_body["message"].as_str().is_some_and(|message| message.contains("口令")));
    assert_eq!(app.store().get("erin").await.expect("查询"), None);
}

#[tokio::test]
async fn given_registration_limit_of_one_when_second_register_then_429() {
    let app = TestApp::with(|config| {
        config.accounts.registration = RegistrationPolicy::Open;
        config.accounts.registration_per_hour = 1;
    });

    let (first, _, _) = app
        .send_json(post_json(
            "/account/register",
            &json!({ "username": "frank", "password": PASSWORD }),
        ))
        .await;
    let (second, headers, body) = app
        .send_json(post_json(
            "/account/register",
            &json!({ "username": "grace", "password": PASSWORD }),
        ))
        .await;

    assert_eq!(first, StatusCode::CREATED);
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS);
    assert_error_contract(&headers, &body);
    assert!(headers.contains_key("retry-after"), "429 应带 Retry-After");
    assert_eq!(app.store().get("grace").await.expect("查询"), None);
}

#[tokio::test]
async fn given_trust_proxy_when_forwarded_for_differs_then_each_ip_has_its_own_bucket() {
    let app = TestApp::with(|config| {
        config.accounts.registration = RegistrationPolicy::Open;
        config.accounts.registration_per_hour = 1;
        config.accounts.trust_proxy = true;
    });
    let register = |forwarded: &str, username: &str| {
        Request::builder()
            .method(Method::POST)
            .uri("/account/register")
            .header(header::HOST, TEST_HOST)
            // 代理追加语义：最后一段才是代理观测到的对端，前面是客户端可伪造的。
            .header("x-forwarded-for", format!("client-supplied-junk, {forwarded}"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "username": username, "password": PASSWORD }).to_string()))
            .expect("构造请求")
    };

    let (first, _, _) = app.send_json(register("203.0.113.7", "nina")).await;
    let (second, _, _) = app.send_json(register("198.51.100.9", "olga")).await;

    assert_eq!(first, StatusCode::CREATED);
    assert_eq!(second, StatusCode::CREATED, "信任反代时不同 XFF 应各算一个来源");
}

#[tokio::test]
async fn given_trust_proxy_when_only_spoofed_prefix_differs_then_same_bucket() {
    // 最后一段相同 → 同一个来源桶；伪造前缀不能“换 IP”绕过限速。
    let app = TestApp::with(|config| {
        config.accounts.registration = RegistrationPolicy::Open;
        config.accounts.registration_per_hour = 1;
        config.accounts.trust_proxy = true;
    });
    let register = |prefix: &str, username: &str| {
        Request::builder()
            .method(Method::POST)
            .uri("/account/register")
            .header(header::HOST, TEST_HOST)
            .header("x-forwarded-for", format!("{prefix}, 203.0.113.7"))
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "username": username, "password": PASSWORD }).to_string()))
            .expect("构造请求")
    };

    let (first, _, _) = app.send_json(register("fake-a", "nina")).await;
    let (second, _, _) = app.send_json(register("fake-b", "olga")).await;

    assert_eq!(first, StatusCode::CREATED);
    assert_eq!(second, StatusCode::TOO_MANY_REQUESTS, "伪造前缀不应产生新桶");
}

#[tokio::test]
async fn given_untrusted_proxy_when_forwarded_for_differs_then_shared_bucket() {
    let app = TestApp::with(|config| {
        config.accounts.registration = RegistrationPolicy::Open;
        config.accounts.registration_per_hour = 1;
        assert!(!config.accounts.trust_proxy);
    });
    let register = |forwarded: &str, username: &str| {
        Request::builder()
            .method(Method::POST)
            .uri("/account/register")
            .header(header::HOST, TEST_HOST)
            .header("x-forwarded-for", forwarded)
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(json!({ "username": username, "password": PASSWORD }).to_string()))
            .expect("构造请求")
    };

    let (first, _, _) = app.send_json(register("203.0.113.7", "peter")).await;
    let (second, _, _) = app.send_json(register("198.51.100.9", "quinn")).await;

    assert_eq!(first, StatusCode::CREATED);
    assert_eq!(
        second,
        StatusCode::TOO_MANY_REQUESTS,
        "不信任反代时 XFF 不能换桶，否则伪造 IP 就能绕过限速"
    );
}

// ---------------------------------------------------------------------------
// 认证：登录限速、DB 优先、懒升级
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_login_failures_over_limit_when_correct_password_then_429() {
    let app = TestApp::with(|config| {
        add_config_user(config, "legacy", PASSWORD, Role::Readwrite);
        config.accounts.login_failures_per_5min = 3;
    });

    for _ in 0..3 {
        let (status, _, _) =
            app.send_json(authed(Method::GET, "/account/me", "legacy", "wrong", None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // 超过上限后，正确口令同样被拒——否则限速对爆破毫无意义。
    let (status, headers, body) =
        app.send_json(authed(Method::GET, "/account/me", "legacy", PASSWORD, None)).await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_error_contract(&headers, &body);
    assert!(headers.contains_key("retry-after"));
}

#[tokio::test]
async fn given_below_limit_then_success_clears_failure_counter() {
    let app = TestApp::with(|config| {
        add_config_user(config, "legacy", PASSWORD, Role::Readwrite);
        config.accounts.login_failures_per_5min = 3;
    });

    // 两次失败仍在阈值内。
    for _ in 0..2 {
        let (status, _, _) =
            app.send_json(authed(Method::GET, "/account/me", "legacy", "wrong", None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }
    let (ok, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "legacy", PASSWORD, None)).await;
    assert_eq!(ok, StatusCode::OK, "阈值内成功登录应被接受");

    // 成功应清零计数：再失败 3 次仍是 401（若计数未清零，第 3 次之前就该 429）。
    for attempt in 0..3 {
        let (status, _, _) =
            app.send_json(authed(Method::GET, "/account/me", "legacy", "wrong", None)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "第 {} 次失败", attempt + 1);
    }
    let (limited, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "legacy", PASSWORD, None)).await;
    assert_eq!(limited, StatusCode::TOO_MANY_REQUESTS);
}

#[tokio::test]
async fn given_db_password_changed_when_old_config_password_then_401() {
    let app = TestApp::with(|config| {
        add_config_user(config, "henry", PASSWORD, Role::Readwrite);
        config.accounts.registration = RegistrationPolicy::Open;
    });
    // 库里已有该用户（模拟「曾经懒升级过」），随后在库外改掉口令。
    app.create_user("henry", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let new_hash = hash_password(NEW_PASSWORD).expect("哈希应成功");
    app.store().update_password_hash("henry", &new_hash).await.expect("改哈希应成功");

    // DB 优先：config 里的旧口令必须完全失效。
    let (old_status, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "henry", PASSWORD, None)).await;
    let (new_status, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "henry", NEW_PASSWORD, None)).await;

    assert_eq!(old_status, StatusCode::UNAUTHORIZED, "旧 config 口令不得复活");
    assert_eq!(new_status, StatusCode::OK);
}

#[tokio::test]
async fn given_config_user_when_first_login_then_lazy_upgrade_to_argon2id() {
    let app = TestApp::with(|config| add_config_user(config, "legacy", PASSWORD, Role::Readwrite));
    assert_eq!(app.store().get("legacy").await.expect("查询"), None, "登录前库中应无该用户");

    let (status, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "legacy", PASSWORD, None)).await;

    assert_eq!(status, StatusCode::OK);
    let stored = app.store().get("legacy").await.expect("查询").expect("首次登录后应懒升级入库");
    assert_eq!(stored.role, Role::Readwrite);
    assert_eq!(stored.status, UserStatus::Active);
    let hash = app.store().password_hash("legacy").await.expect("读哈希").expect("应存在哈希");
    assert!(hash.starts_with("$argon2id$"), "升级后必须是 Argon2id：{hash}");
    assert!(stored.last_login_at.is_some(), "懒升级后应记录登录时间");
}

#[tokio::test]
async fn given_two_char_config_username_when_login_then_falls_back_to_config() {
    // 账户库规则是 3–32 个字符；2 个字符的旧 config 用户名查库会得到
    // InvalidUsername，必须当作「DB 里没有」回落 config，而不是 500。
    let app = TestApp::with(|config| add_config_user(config, "ab", PASSWORD, Role::Readonly));

    let (status, _, me) =
        app.send_json(authed(Method::GET, "/account/me", "ab", PASSWORD, None)).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(me["username"], "ab");
    assert_eq!(me["role"], "readonly");
    assert_eq!(me["created_at"], Value::Null, "config 用户没有创建时间");
    // 账户库连查询都拒绝这个用户名（要落库得先改名），这正是必须回落 config 的原因。
    let error = app.store().get("ab").await.expect_err("2 个字符的用户名查库应报错");
    assert!(
        matches!(error, netdisk_lfs::AccountError::InvalidUsername { .. }),
        "实际错误：{error}"
    );
}

// ---------------------------------------------------------------------------
// 自身账户管理
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_password_change_when_old_or_new_password_then_401_or_200() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Open);
    app.create_user("iris", PASSWORD, Role::Readwrite, UserStatus::Active).await;

    let (status, _, _) = app
        .send(authed(
            Method::POST,
            "/account/password",
            "iris",
            PASSWORD,
            Some(&json!({ "old_password": PASSWORD, "new_password": NEW_PASSWORD })),
        ))
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (old_status, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "iris", PASSWORD, None)).await;
    let (new_status, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "iris", NEW_PASSWORD, None)).await;
    assert_eq!(old_status, StatusCode::UNAUTHORIZED, "旧口令应失效");
    assert_eq!(new_status, StatusCode::OK, "新口令应可用");

    // 旧口令不对时不能改：401，且新口令不生效。
    let (wrong_old, _, _) = app
        .send(authed(
            Method::POST,
            "/account/password",
            "iris",
            NEW_PASSWORD,
            Some(
                &json!({ "old_password": "not the old one", "new_password": "yet another horse" }),
            ),
        ))
        .await;
    assert_eq!(wrong_old, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_delete_self_when_deleted_then_account_cannot_login() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Open);
    app.create_user("jack", PASSWORD, Role::Readwrite, UserStatus::Active).await;

    let (status, _, _) = app
        .send(authed(
            Method::DELETE,
            "/account",
            "jack",
            PASSWORD,
            Some(&json!({ "password": PASSWORD })),
        ))
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(app.store().get("jack").await.expect("查询"), None);
    let (login, _, _) =
        app.send_json(authed(Method::GET, "/account/me", "jack", PASSWORD, None)).await;
    assert_eq!(login, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_single_db_admin_when_delete_self_then_409() {
    let app = TestApp::new();
    app.create_user("rootadmin", PASSWORD, Role::Admin, UserStatus::Active).await;

    let (status, headers, body) = app
        .send_json(authed(
            Method::DELETE,
            "/account",
            "rootadmin",
            PASSWORD,
            Some(&json!({ "password": PASSWORD })),
        ))
        .await;

    assert_eq!(status, StatusCode::CONFLICT);
    assert_error_contract(&headers, &body);
    assert!(
        body["message"].as_str().is_some_and(|message| message.contains("管理员")),
        "错误信息应说明最后管理员保护：{body}"
    );
    assert!(app.store().get("rootadmin").await.expect("查询").is_some(), "不得真的删掉");
}

#[tokio::test]
async fn given_config_admin_exists_when_db_admin_deletes_self_then_allowed() {
    let app = TestApp::with(|config| {
        // 配置文件里的引导管理员：即使库里的管理员删掉自己，系统仍有人能进 /admin/*。
        add_config_user(config, "maintainer", PASSWORD, Role::Admin);
    });
    app.create_user("rootadmin", PASSWORD, Role::Admin, UserStatus::Active).await;

    let (status, _, _) = app
        .send(authed(
            Method::DELETE,
            "/account",
            "rootadmin",
            PASSWORD,
            Some(&json!({ "password": PASSWORD })),
        ))
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert_eq!(app.store().get("rootadmin").await.expect("查询"), None);
}

// ---------------------------------------------------------------------------
// HTML 注册页
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_register_page_when_get_then_html_with_policy_hint() {
    let app = TestApp::new();

    let (status, headers, body) =
        app.send(request(Method::GET, "/account/register", None, None, String::new())).await;
    let body = body_text(body);

    assert_eq!(status, StatusCode::OK);
    assert!(content_type(&headers).starts_with("text/html"), "实际：{}", content_type(&headers));
    assert!(body.contains("name=\"username\""), "应有用户名输入框：{body}");
    assert!(body.contains("name=\"confirm_password\""), "应有确认口令输入框");
    assert!(body.contains("管理员审批"), "approval 策略应提示需审批");
    assert!(!body.contains("<script"), "注册页不得含脚本");
}

#[tokio::test]
async fn given_form_register_when_open_then_html_201_and_escaped_errors() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Open);
    let form = format!(
        "username=kate&password={}&confirm_password={}",
        "encoded%20pass%20123", "encoded%20pass%20123"
    );

    let (status, headers, body) = app
        .send(request(
            Method::POST,
            "/account/register",
            None,
            Some("application/x-www-form-urlencoded"),
            form,
        ))
        .await;
    let body = body_text(body);

    assert_eq!(status, StatusCode::CREATED);
    assert!(content_type(&headers).starts_with("text/html"), "表单请求应回 HTML");
    assert!(body.contains("注册成功"), "应显示结果页：{body}");
    assert!(!body.contains("<script"), "结果页不得含脚本");

    // 注入用例：非法用户名里的 `<script>` 必须转义后出现在错误页上。
    let injected = format!(
        "username=%3Cscript%3Ealert(1)%3C%2Fscript%3E&password={PASSWORD}&confirm_password={PASSWORD}"
    );
    let (bad_status, bad_headers, bad_body) = app
        .send(request(
            Method::POST,
            "/account/register",
            None,
            Some("application/x-www-form-urlencoded"),
            injected,
        ))
        .await;
    let bad_body = body_text(bad_body);

    assert_eq!(bad_status, StatusCode::BAD_REQUEST);
    assert!(content_type(&bad_headers).starts_with("text/html"));
    assert!(!bad_body.contains("<script"), "用户输入必须被转义：{bad_body}");
    assert!(bad_body.contains("&lt;script&gt;"), "转义后的文本应出现：{bad_body}");
}

#[tokio::test]
async fn given_form_password_mismatch_when_register_then_400_html() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Open);

    let (status, headers, body) = app
        .send(request(
            Method::POST,
            "/account/register",
            None,
            Some("application/x-www-form-urlencoded"),
            format!("username=liam&password={PASSWORD}&confirm_password=another correct horse"),
        ))
        .await;

    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(content_type(&headers).starts_with("text/html"));
    assert!(body_text(body).contains("不一致"));
}

// ---------------------------------------------------------------------------
// 没有账户库
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_no_account_store_when_account_endpoints_then_503() {
    let app = TestApp::without_accounts();

    let (register, register_headers, register_body) = app
        .send_json(post_json(
            "/account/register",
            &json!({ "username": "mike", "password": PASSWORD }),
        ))
        .await;
    let (page, _, _) =
        app.send(request(Method::GET, "/account/register", None, None, String::new())).await;
    let (unknown, unknown_headers, unknown_body) =
        app.send_json(authed(Method::GET, "/account/me", "nobody", PASSWORD, None)).await;
    let (me, me_headers, me_body) =
        app.send_json(authed(Method::GET, "/account/me", "legacy", PASSWORD, None)).await;

    assert_eq!(register, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_contract(&register_headers, &register_body);
    assert_eq!(page, StatusCode::SERVICE_UNAVAILABLE);
    // 认证仍按配置执行：没有这个用户照样 401，不会因为端点 503 就放行。
    assert_eq!(unknown, StatusCode::UNAUTHORIZED);
    assert_error_contract(&unknown_headers, &unknown_body);
    // 凭据有效、但账户库没接入：端点 503 并说明原因。
    assert_eq!(me, StatusCode::SERVICE_UNAVAILABLE);
    assert_error_contract(&me_headers, &me_body);
    assert!(
        me_body["message"].as_str().is_some_and(|message| message.contains("账户库")),
        "503 应说明账户库未启用：{me_body}"
    );
}

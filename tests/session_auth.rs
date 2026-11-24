//! 会话与双通道认证的集成测试：会话 Cookie、角色复核、撤销钩子与跨站守卫。
//!
//! 全部经 `tower::ServiceExt::oneshot` 直接打 `router(state)`，不绑定端口；账户库落在
//! 每个用例自己的临时目录，对象存储用 [`FakeStore`]，绝不访问网盘、不起真实 `bdpan`。
//!
//! 会话直接用 `state.sessions().create(...)` 造：登录端点是 L2 的事，本分支要验证的是
//! 「会话存在之后，受保护端点与写操作怎么表现」。口令哈希仍要付 Argon2 成本，所以需要
//! 登录的用例共用同一条口令的哈希（[`shared_hash`]）。

use std::path::PathBuf;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, OnceLock};

use axum::Router;
use axum::body::Body;
use axum::http::header::{self, COOKIE};
use axum::http::{HeaderMap, Method, Request, StatusCode};
use base64::Engine;
use base64::engine::general_purpose::STANDARD as BASE64;
use http_body_util::BodyExt;
use netdisk_lfs::{
    AccountsConfig, AppState, AuthConfig, CacheConfig, Config, FakeStore, ObjectStore, Role,
    RuntimeEnv, SESSION_COOKIE_NAME, ServerConfig, SessionId, Sha256Writer, StorageConfig,
    UserConfig, UserStatus, UserStore, hash_password, router,
};
use serde_json::{Value, json};
use tower::ServiceExt;

const TEST_HOST: &str = "lfs.test";
/// 默认口令：21 个字符，满足 12 位下限；也是 [`shared_hash`] 缓存的那一条。
const PASSWORD: &str = "correct horse battery";
/// 改密用例的新口令。
const NEW_PASSWORD: &str = "another correct horse";
const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";
/// 32 字节全 0 的 base64url：格式合法，但服务端会话表里一定没有（等价于过期/伪造）。
const UNKNOWN_SESSION: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";

/// 每个用例一个临时目录；Drop 时连同 SQLite 的 `-wal` / `-shm` 一起删除。
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("netdisk-lfs-session-auth-{}-{seq}", std::process::id()));
        std::fs::create_dir(&path).expect("创建临时目录");
        Self { path }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 测试应用：router + 与 router 共享状态的 state（造会话用）+ 账户库句柄。
struct TestApp {
    router: Router,
    state: AppState,
    /// `None` 表示没有接入账户库（验证 config 回落的会话路径）。
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
        Self { router: router(state.clone()), state, store: Some(store), _workspace: workspace }
    }

    /// 没有接入账户库的实例：`cfgadmin`（管理员）与 `olduser`（只读）只在配置里。
    fn without_accounts() -> Self {
        let workspace = Workspace::new();
        let db = workspace.path.join("accounts.db");
        let mut config = base_config(db);
        add_config_user(&mut config, "cfgadmin", PASSWORD, Role::Admin);
        add_config_user(&mut config, "olduser", PASSWORD, Role::Readonly);
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::new());
        let state = AppState::new(backend, Arc::new(config));
        Self { router: router(state.clone()), state, store: None, _workspace: workspace }
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

    /// 直接造一个会话（登录端点属 L2）。
    fn session(&self, username: &str, role: Role) -> SessionId {
        self.state.sessions().create(username, role).expect("应能建立会话")
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

/// 请求构造器：默认带 `Host`，按需加 Cookie、Basic、额外头与 JSON 体。
struct Req {
    method: Method,
    uri: String,
    headers: Vec<(String, String)>,
    content_type: Option<String>,
    body: String,
}

impl Req {
    fn new(method: Method, uri: &str) -> Self {
        Self {
            method,
            uri: uri.to_owned(),
            headers: Vec::new(),
            content_type: None,
            body: String::new(),
        }
    }

    /// 带上一个真实存在的会话。
    fn cookie(mut self, id: &SessionId) -> Self {
        self.headers.push((COOKIE.to_string(), format!("{SESSION_COOKIE_NAME}={}", id.as_str())));
        self
    }

    /// 带一个伪造/过期的 Cookie 值。
    fn cookie_value(mut self, value: &str) -> Self {
        self.headers.push((COOKIE.to_string(), format!("{SESSION_COOKIE_NAME}={value}")));
        self
    }

    fn basic(mut self, username: &str, password: &str) -> Self {
        self.headers.push((header::AUTHORIZATION.to_string(), basic_header(username, password)));
        self
    }

    fn header(mut self, name: &str, value: &str) -> Self {
        self.headers.push((name.to_owned(), value.to_owned()));
        self
    }

    fn json(mut self, body: &Value) -> Self {
        self.content_type = Some("application/json".to_owned());
        self.body = body.to_string();
        self
    }

    fn accept_html(mut self) -> Self {
        self.headers
            .push((header::ACCEPT.to_string(), "text/html,application/xhtml+xml".to_owned()));
        self
    }

    fn build(self) -> Request<Body> {
        let mut builder =
            Request::builder().method(self.method).uri(self.uri).header(header::HOST, TEST_HOST);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        if let Some(content_type) = self.content_type {
            builder = builder.header(header::CONTENT_TYPE, content_type);
        }
        builder.body(Body::from(self.body)).expect("构造请求")
    }
}

fn content_type(headers: &HeaderMap) -> &str {
    headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("")
}

/// 响应里所有 `Set-Cookie` 值。
fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

/// 断言清除会话 Cookie 的那条 `Set-Cookie` 存在且形态正确。
fn assert_clear_cookie(headers: &HeaderMap, secure: bool) {
    let cookies = set_cookies(headers);
    assert_eq!(cookies.len(), 1, "应恰好下发一条 Set-Cookie：{cookies:?}");
    let cookie = &cookies[0];
    assert!(
        cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=;")),
        "应把会话 Cookie 置空：{cookie}"
    );
    assert!(cookie.contains("Max-Age=0"), "清除必须用 Max-Age=0：{cookie}");
    assert!(cookie.contains("HttpOnly"), "会话 Cookie 必须是 HttpOnly：{cookie}");
    assert_eq!(cookie.contains("Secure"), secure, "Secure 属性应与请求是否 HTTPS 一致：{cookie}");
}

/// 断言错误体符合既有契约：`{message, request_id}`，媒体类型是 LFS JSON。
fn assert_error_contract(headers: &HeaderMap, body: &Value) {
    assert_eq!(content_type(headers), LFS_MEDIA_TYPE);
    assert!(
        body["message"].as_str().is_some_and(|message| !message.is_empty()),
        "错误体必须带非空 message：{body}"
    );
    assert!(body["request_id"].as_str().is_some_and(|id| !id.is_empty()));
}

/// 401 必须继续带两个认证挑战头（git 客户端与浏览器各认一个）。
fn assert_auth_challenge(headers: &HeaderMap) {
    assert_eq!(
        headers.get(header::WWW_AUTHENTICATE).and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"netdisk-lfs\"")
    );
    assert_eq!(
        headers.get("lfs-authenticate").and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"netdisk-lfs\"")
    );
}

// ---------------------------------------------------------------------------
// 会话认证：有效、伪造、缺省与 Basic 优先
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_valid_session_when_get_account_me_then_200_with_db_role() {
    let app = TestApp::new();
    app.create_user("alice", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    // 会话里故意记成 readonly：实际角色必须以账户库为准。
    let id = app.session("alice", Role::Readonly);

    let (status, headers, value) =
        app.send_json(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type(&headers), "application/json");
    assert_eq!(value["username"], "alice");
    assert_eq!(value["role"], "readwrite", "角色以库为准，不信任会话里的快照");
    assert!(set_cookies(&headers).is_empty(), "成功的会话请求不该再下发 Cookie");
}

#[tokio::test]
async fn given_unknown_session_when_protected_endpoint_then_401_and_clear_cookie() {
    let app = TestApp::new();

    let (status, headers, body) =
        app.send(Req::new(Method::GET, "/account/me").cookie_value(UNKNOWN_SESSION).build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_auth_challenge(&headers);
    assert_clear_cookie(&headers, false);
    let value: Value = serde_json::from_slice(&body).expect("错误体应是 JSON");
    assert_error_contract(&headers, &value);
}

#[tokio::test]
async fn given_no_credentials_when_protected_endpoint_then_401_without_set_cookie() {
    let app = TestApp::new();

    let (status, headers, _) = app.send(Req::new(Method::GET, "/account/me").build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_auth_challenge(&headers);
    assert!(set_cookies(&headers).is_empty(), "没有 Cookie 可清，不该凭空下发 Set-Cookie");
}

#[tokio::test]
async fn given_malformed_cookie_when_protected_endpoint_then_401_and_clear_cookie() {
    let app = TestApp::new();

    // 值不是合法会话 id：必须与「过期」一样被清掉，否则浏览器会一直重发同一个坏值。
    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/account/me").cookie_value("not-a-session").build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_clear_cookie(&headers, false);
}

#[tokio::test]
async fn given_untrusted_proxy_when_session_invalid_then_clear_cookie_not_secure() {
    let app = TestApp::new();

    // 默认不信任代理（`[accounts] trust_proxy = false`）：客户端伪造的 XFP 不能让
    // 服务端以为自己在 HTTPS 上，清除 Cookie 也就不该带 Secure。
    let (status, headers, _) = app
        .send(
            Req::new(Method::GET, "/admin/users")
                .cookie_value(UNKNOWN_SESSION)
                .header("x-forwarded-proto", "https")
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_clear_cookie(&headers, false);
}

#[tokio::test]
async fn given_trusted_proxy_when_session_invalid_then_clear_cookie_is_secure() {
    let app = TestApp::with(|config| config.accounts.trust_proxy = true);

    let (status, headers, _) = app
        .send(
            Req::new(Method::GET, "/admin/users")
                .cookie_value(UNKNOWN_SESSION)
                .header("x-forwarded-proto", "https")
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_clear_cookie(&headers, true);
}

#[tokio::test]
async fn given_https_public_base_when_session_invalid_then_clear_cookie_is_secure() {
    let app = TestApp::with(|config| config.server.public_base = "https://lfs.test".to_owned());

    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/account/me").cookie_value(UNKNOWN_SESSION).build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_clear_cookie(&headers, true);
}

#[tokio::test]
async fn given_basic_and_session_when_same_request_then_basic_wins() {
    let app = TestApp::new();
    app.create_user("alice", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    app.create_user("bob", PASSWORD, Role::Admin, UserStatus::Active).await;
    let id = app.session("alice", Role::Readwrite);

    let (status, _, value) = app
        .send_json(Req::new(Method::GET, "/account/me").cookie(&id).basic("bob", PASSWORD).build())
        .await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["username"], "bob", "两套凭据同时出现时以 Basic 身份为准");
    assert_eq!(value["role"], "admin");
}

#[tokio::test]
async fn given_wrong_basic_with_valid_session_then_401_without_cookie_fallback() {
    let app = TestApp::new();
    app.create_user("alice", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("alice", Role::Readwrite);

    let (status, headers, _) = app
        .send(
            Req::new(Method::GET, "/account/me")
                .cookie(&id)
                .basic("alice", "definitely wrong")
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "Basic 失败不得回退到会话 Cookie");
    assert_auth_challenge(&headers);
    assert!(set_cookies(&headers).is_empty(), "会话本身仍然有效，不该被清掉");
    assert_eq!(app.state.sessions().len(), 1);
}

// ---------------------------------------------------------------------------
// 账户状态与角色复核、撤销钩子
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_db_user_disabled_when_session_then_401_and_session_revoked() {
    let app = TestApp::new();
    app.create_user("alice", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("alice", Role::Readwrite);
    app.store().update_status("alice", UserStatus::Disabled).await.expect("禁用应成功");

    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "禁用的账户不能继续用旧会话");
    assert_clear_cookie(&headers, false);
    assert!(app.state.sessions().is_empty(), "失效会话应被删除，不是留着等过期");
}

#[tokio::test]
async fn given_db_user_deleted_when_session_then_401_and_session_revoked() {
    let app = TestApp::new();
    app.create_user("alice", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("alice", Role::Readwrite);
    app.store().delete("alice").await.expect("删除应成功");

    let (status, _, _) = app.send(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(app.state.sessions().is_empty());
}

#[tokio::test]
async fn given_admin_disables_user_when_session_then_401() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("dave", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("dave", Role::Readwrite);

    let (status, _, value) = app
        .send_json(
            Req::new(Method::PATCH, "/admin/users/dave")
                .basic("root", PASSWORD)
                .json(&json!({ "status": "disabled" }))
                .build(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["status"], "disabled");
    assert!(app.state.sessions().is_empty(), "禁用后应立即撤销该用户的会话");

    let (after, _, _) = app.send(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;
    assert_eq!(after, StatusCode::UNAUTHORIZED, "禁用后原会话立即失效");
}

#[tokio::test]
async fn given_admin_changes_role_when_session_then_401() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("dave", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("dave", Role::Readwrite);

    let (status, _, _) = app
        .send_json(
            Req::new(Method::PATCH, "/admin/users/dave")
                .basic("root", PASSWORD)
                .json(&json!({ "role": "readonly" }))
                .build(),
        )
        .await;
    assert_eq!(status, StatusCode::OK);

    let (after, _, _) = app.send(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;
    assert_eq!(after, StatusCode::UNAUTHORIZED, "角色变更后旧会话不应继续按旧角色操作");
}

#[tokio::test]
async fn given_admin_resets_password_when_session_then_401() {
    let app = TestApp::new();
    app.create_user("root", PASSWORD, Role::Admin, UserStatus::Active).await;
    app.create_user("dave", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("dave", Role::Readwrite);

    let (status, _, _) = app
        .send(
            Req::new(Method::POST, "/admin/users/dave/password")
                .basic("root", PASSWORD)
                .json(&json!({ "password": NEW_PASSWORD }))
                .build(),
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT);

    let (after, _, _) = app.send(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;
    assert_eq!(after, StatusCode::UNAUTHORIZED, "重置口令后旧会话立即失效");
}

#[tokio::test]
async fn given_self_password_change_when_done_then_own_sessions_revoked() {
    let app = TestApp::new();
    app.create_user("frank", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("frank", Role::Readwrite);

    let (status, _, _) = app
        .send(
            Req::new(Method::POST, "/account/password")
                .cookie(&id)
                .header("sec-fetch-site", "same-origin")
                .json(&json!({ "old_password": PASSWORD, "new_password": NEW_PASSWORD }))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(app.state.sessions().is_empty(), "改密后自己的会话也应被撤销");
    let (after, _, _) = app.send(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;
    assert_eq!(after, StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn given_self_delete_when_done_then_sessions_revoked() {
    let app = TestApp::new();
    app.create_user("jack", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("jack", Role::Readwrite);

    let (status, _, _) = app
        .send(
            Req::new(Method::DELETE, "/account")
                .cookie(&id)
                .json(&json!({ "password": PASSWORD }))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
    assert!(app.state.sessions().is_empty(), "注销后会话必须消失");
    assert_eq!(app.store().get("jack").await.expect("查询账户"), None);
}

// ---------------------------------------------------------------------------
// 没有账户库：config 用户与会话
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_config_only_user_when_session_then_allowed_with_config_role() {
    // 账户库接入着，但这个名字只在 `[auth.users]` 里（还没懒升级）：会话必须能用，
    // 规则与 Basic 的 config 回落一致。
    let app = TestApp::with(|config| add_config_user(config, "legacy", PASSWORD, Role::Readwrite));
    let id = app.session("legacy", Role::Admin);

    let (status, _, value) =
        app.send_json(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["username"], "legacy");
    assert_eq!(value["role"], "readwrite", "角色取配置，不取会话里的快照");
    assert_eq!(value["created_at"], Value::Null, "config 用户没有账户库创建时间");

    // 会话里记成 admin 也没用：配置里的角色才是真的，管理端点仍按 readwrite 拒绝。
    let (admin, _, _) = app.send(Req::new(Method::GET, "/admin/users").cookie(&id).build()).await;
    assert_eq!(admin, StatusCode::FORBIDDEN);
}

#[tokio::test]
async fn given_db_and_config_same_name_when_session_then_db_role_wins() {
    let app = TestApp::with(|config| add_config_user(config, "alice", PASSWORD, Role::Readonly));
    app.create_user("alice", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("alice", Role::Admin);

    let (status, _, value) =
        app.send_json(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(value["role"], "readwrite", "库里有这个人时以库为准");
    assert_ne!(value["role"], "admin", "会话里的 admin 不该被当回事");
}

#[tokio::test]
async fn given_no_account_store_when_config_user_session_then_authenticated() {
    let app = TestApp::without_accounts();
    let id = app.session("cfgadmin", Role::Admin);

    // `/account/me` 需要账户库：503 说明认证已通过（没通过会是 401）。
    let (status, _, _) = app.send(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;
    assert_eq!(status, StatusCode::SERVICE_UNAVAILABLE);
    // 管理员角色同样来自配置：能进管理端点，只是账户库没接入 → 503。
    let (admin, _, _) = app.send(Req::new(Method::GET, "/admin/users").cookie(&id).build()).await;
    assert_eq!(admin, StatusCode::SERVICE_UNAVAILABLE);
}

#[tokio::test]
async fn given_no_account_store_when_session_user_missing_from_config_then_401() {
    let app = TestApp::without_accounts();
    let id = app.session("ghostuser", Role::Readwrite);

    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/account/me").cookie(&id).build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "配置里没有这个人，会话不能放行");
    assert_clear_cookie(&headers, false);
    assert!(app.state.sessions().is_empty());
}

// ---------------------------------------------------------------------------
// 跨站写守卫
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_session_and_cross_site_origin_when_post_password_then_403() {
    let app = TestApp::new();
    app.create_user("erin", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("erin", Role::Readwrite);

    let (status, headers, body) = app
        .send(
            Req::new(Method::POST, "/account/password")
                .cookie(&id)
                .header("origin", "https://evil.example")
                .json(&json!({ "old_password": PASSWORD, "new_password": NEW_PASSWORD }))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    let value: Value = serde_json::from_slice(&body).expect("错误体应是 JSON");
    assert_error_contract(&headers, &value);
    // 口令没被改：旧口令用 Basic 仍然能过。
    let (login, _, _) =
        app.send(Req::new(Method::GET, "/account/me").basic("erin", PASSWORD).build()).await;
    assert_eq!(login, StatusCode::OK, "被拒的跨站请求不该产生副作用");
}

#[tokio::test]
async fn given_session_and_cross_site_sec_fetch_site_when_write_then_403() {
    let app = TestApp::new();
    app.create_user("gina", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("gina", Role::Readwrite);

    let (status, _, _) = app
        .send(
            Req::new(Method::DELETE, "/account")
                .cookie(&id)
                .header("sec-fetch-site", "cross-site")
                .json(&json!({ "password": PASSWORD }))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(
        app.store().get("gina").await.expect("查询账户").map(|user| user.username),
        Some("gina".to_owned())
    );
}

#[tokio::test]
async fn given_session_and_same_host_origin_when_write_then_allowed() {
    let app = TestApp::new();
    app.create_user("henry", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("henry", Role::Readwrite);

    // 同主机名、不同 scheme/端口：反代换端口或终结 TLS 的正常形态。
    let (status, _, _) = app
        .send(
            Req::new(Method::POST, "/account/password")
                .cookie(&id)
                .header("origin", "http://lfs.test:9001")
                .json(&json!({ "old_password": PASSWORD, "new_password": NEW_PASSWORD }))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn given_session_and_same_origin_when_write_then_allowed() {
    let app = TestApp::new();
    app.create_user("iris", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("iris", Role::Readwrite);

    let (status, _, _) = app
        .send(
            Req::new(Method::POST, "/account/password")
                .cookie(&id)
                .header("sec-fetch-site", "same-origin")
                .json(&json!({ "old_password": PASSWORD, "new_password": NEW_PASSWORD }))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn given_basic_request_without_cookie_when_cross_site_write_then_not_blocked() {
    let app = TestApp::new();
    app.create_user("kate", PASSWORD, Role::Readwrite, UserStatus::Active).await;

    // CLI/脚本不会自动附带凭据，跨站守卫只管会话 Cookie，不能误伤 Basic。
    let (status, _, _) = app
        .send(
            Req::new(Method::POST, "/account/password")
                .basic("kate", PASSWORD)
                .header("origin", "https://evil.example")
                .json(&json!({ "old_password": PASSWORD, "new_password": NEW_PASSWORD }))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT);
}

#[tokio::test]
async fn given_session_when_cross_site_read_then_not_blocked() {
    let app = TestApp::new();
    app.create_user("luke", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("luke", Role::Readwrite);

    let (status, _, _) = app
        .send(
            Req::new(Method::GET, "/account/me")
                .cookie(&id)
                .header("sec-fetch-site", "cross-site")
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::OK, "读请求没有 CSRF 面，跨站读也不该挡");
}

#[tokio::test]
async fn given_session_and_cross_site_write_when_browser_request_then_403_page() {
    let app = TestApp::new();
    app.create_user("mia", PASSWORD, Role::Readwrite, UserStatus::Active).await;
    let id = app.session("mia", Role::Readwrite);

    let (status, headers, body) = app
        .send(
            Req::new(Method::POST, "/account/password")
                .cookie(&id)
                .accept_html()
                .header("origin", "https://evil.example")
                .json(&json!({ "old_password": PASSWORD, "new_password": NEW_PASSWORD }))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(
        content_type(&headers).starts_with("text/html"),
        "浏览器请求应拿到页面，实际：{}",
        content_type(&headers)
    );
    let page = String::from_utf8(body).expect("HTML 应是 UTF-8");
    assert!(page.contains("<!doctype html>"), "应是完整页面：{page}");
    assert!(page.contains("请求 id："), "错误页应带 request id：{page}");
    assert!(!page.contains("<script"), "页面不得含脚本：{page}");
}

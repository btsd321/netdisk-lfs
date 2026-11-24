//! 浏览器登录页、表单登录、退出与未登录跳转的集成测试。
//!
//! 全部经 `tower::ServiceExt::oneshot` 直接打 `router(state)`，不绑定端口；账户库落在
//! 每个用例自己的临时目录，对象存储用 [`FakeStore`]，绝不访问网盘、不起真实 `bdpan`。
//!
//! Argon2 每次校验约几十毫秒，用例数量刻意收敛：能用 config 用户（sha256，便宜）
//! 覆盖的路径就不建库内账户；同一条口令在整个测试二进制里只哈希一次（[`shared_hash`]）。

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
    AccountsConfig, AppState, AuthConfig, CacheConfig, Config, FakeStore, ObjectStore,
    RegistrationPolicy, Role, RuntimeEnv, SESSION_COOKIE_NAME, ServerConfig, SessionId,
    Sha256Writer, StorageConfig, UserConfig, UserStatus, UserStore, hash_password, router,
};
use serde_json::Value;
use tower::ServiceExt;

const TEST_HOST: &str = "lfs.test";
/// 默认口令：21 个字符，满足 12 位下限；也是 [`shared_hash`] 缓存的那一条。
const PASSWORD: &str = "correct horse battery";
const LFS_MEDIA_TYPE: &str = "application/vnd.git-lfs+json";
/// 登录失败与「账户未激活」共用的文案（两条路径必须一模一样）。
const LOGIN_FAILED_MESSAGE: &str = "用户名或口令错误，或账户未激活";

/// 每个用例一个临时目录；Drop 时连同 SQLite 的 `-wal` / `-shm` 一起删除。
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir()
            .join(format!("netdisk-lfs-login-page-{}-{seq}", std::process::id()));
        std::fs::create_dir(&path).expect("创建临时目录");
        Self { path }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 测试应用：router + 与 router 共享状态的 state（造会话/查会话数用）+ 账户库句柄。
struct TestApp {
    router: Router,
    state: AppState,
    /// `None` 表示没有接入账户库（验证 config 回落的登录路径）。
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

    /// 没有接入账户库的实例：`cfgadmin`（管理员）只在配置里，用于 config 回落的登录。
    fn without_accounts() -> Self {
        let workspace = Workspace::new();
        let db = workspace.path.join("accounts.db");
        let mut config = base_config(db);
        add_config_user(&mut config, "cfgadmin", PASSWORD, Role::Admin);
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::new());
        let state = AppState::new(backend, Arc::new(config));
        Self { router: router(state.clone()), state, store: None, _workspace: workspace }
    }

    fn store(&self) -> &Arc<UserStore> {
        self.store.as_ref().expect("本用例应接入账户库")
    }

    /// 直接在库里建一个账户（哈希真实口令，便于随后用它登录）。
    async fn create_user(&self, name: &str, role: Role, status: UserStatus) {
        self.store()
            .create(name, &shared_hash(PASSWORD), role, status)
            .await
            .unwrap_or_else(|error| panic!("创建 {name} 失败：{error}"));
    }

    /// 直接造一个会话（跳过登录表单，用来验证「已登录」的各条路径）。
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

/// 表单值的百分号编码：只用于本文件的短字段（空格、`:`、`&`、`=` 等）。
fn encode_value(raw: &str) -> String {
    let mut encoded = String::with_capacity(raw.len());
    for byte in raw.bytes() {
        match byte {
            b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.' | b'_' | b'~' => {
                encoded.push(char::from(byte));
            },
            other => encoded.push_str(&format!("%{other:02X}")),
        }
    }
    encoded
}

/// 把键值对拼成 `application/x-www-form-urlencoded` 请求体；空值也保留（缺字段用例要它）。
fn form_body(pairs: &[(&str, &str)]) -> String {
    pairs
        .iter()
        .map(|(key, value)| format!("{}={}", encode_value(key), encode_value(value)))
        .collect::<Vec<_>>()
        .join("&")
}

/// 请求构造器：默认带 `Host`，按需加 Cookie、Basic、Accept 与表单体。
struct Req {
    method: Method,
    uri: String,
    headers: Vec<(String, String)>,
    form: Option<String>,
}

impl Req {
    fn new(method: Method, uri: &str) -> Self {
        Self { method, uri: uri.to_owned(), headers: Vec::new(), form: None }
    }

    /// 带一个真实存在的会话。
    fn cookie(mut self, id: &SessionId) -> Self {
        self.headers.push((COOKIE.to_string(), format!("{SESSION_COOKIE_NAME}={}", id.as_str())));
        self
    }

    /// 带一个伪造/过期/畸形的 Cookie 值。
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

    fn accept_html(self) -> Self {
        self.header(header::ACCEPT.as_str(), "text/html,application/xhtml+xml")
    }

    /// 提交登录表单（不带任何同站头：同站/跨站由各用例显式给出，避免默认值掩盖判定）。
    fn login(mut self, username: &str, password: &str, next: Option<&str>) -> Self {
        let mut pairs = vec![("username", username), ("password", password)];
        if let Some(next) = next {
            pairs.push(("next", next));
        }
        self.form = Some(form_body(&pairs));
        self
    }

    fn build(self) -> Request<Body> {
        let mut builder =
            Request::builder().method(self.method).uri(self.uri).header(header::HOST, TEST_HOST);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        if let Some(form) = self.form {
            builder = builder.header(header::CONTENT_TYPE, "application/x-www-form-urlencoded");
            return builder.body(Body::from(form)).expect("构造请求");
        }
        builder.body(Body::empty()).expect("构造请求")
    }
}

fn content_type(headers: &HeaderMap) -> &str {
    headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("")
}

fn location(headers: &HeaderMap) -> &str {
    headers.get(header::LOCATION).and_then(|value| value.to_str().ok()).unwrap_or("")
}

fn body_text(body: Vec<u8>) -> String {
    String::from_utf8(body).expect("页面应是 UTF-8")
}

/// 响应里所有 `Set-Cookie` 值。
fn set_cookies(headers: &HeaderMap) -> Vec<String> {
    headers
        .get_all(header::SET_COOKIE)
        .iter()
        .filter_map(|value| value.to_str().ok().map(str::to_owned))
        .collect()
}

/// 断言「登录成功」下发的会话 Cookie：HttpOnly/SameSite/Path 齐全，`Secure` 按需。
fn assert_session_cookie(headers: &HeaderMap, secure: bool) -> String {
    let cookies = set_cookies(headers);
    assert_eq!(cookies.len(), 1, "登录成功应恰好下发一条 Set-Cookie：{cookies:?}");
    let cookie = cookies.into_iter().next().unwrap_or_default();
    assert!(cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=")), "应是会话 Cookie：{cookie}");
    assert!(cookie.contains("HttpOnly"), "会话 Cookie 必须 HttpOnly：{cookie}");
    assert!(cookie.contains("SameSite=Lax"), "会话 Cookie 必须 SameSite=Lax：{cookie}");
    assert!(cookie.contains("Path=/"), "会话 Cookie 必须 Path=/: {cookie}");
    assert!(cookie.contains("Max-Age="), "会话 Cookie 必须带 Max-Age：{cookie}");
    assert_eq!(cookie.contains("Secure"), secure, "Secure 应与请求是否 HTTPS 一致：{cookie}");
    cookie
}

/// 从 `Set-Cookie` 里取出会话 id 的原始值（`SessionId` 的解析是 crate 内部 API，
/// 测试只需要把它当成不透明串再带回去）。
fn session_cookie_value(cookie: &str) -> String {
    let value = cookie
        .split(';')
        .next()
        .and_then(|pair| pair.split_once('='))
        .map(|(_, value)| value.trim().to_owned())
        .expect("Set-Cookie 应是 name=value 形式");
    assert_eq!(value.len(), 43, "32 字节 base64url 无填充应是 43 个字符：{value}");
    assert!(
        value.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'-' || byte == b'_'),
        "会话 id 必须是 base64url：{value}"
    );
    value
}

/// 断言清除会话 Cookie 的那条 `Set-Cookie` 存在且形态正确。
fn assert_clear_cookie(headers: &HeaderMap, secure: bool) {
    let cookies = set_cookies(headers);
    assert_eq!(cookies.len(), 1, "应恰好下发一条 Set-Cookie：{cookies:?}");
    let cookie = &cookies[0];
    assert!(cookie.starts_with(&format!("{SESSION_COOKIE_NAME}=;")), "应置空：{cookie}");
    assert!(cookie.contains("Max-Age=0"), "清除必须用 Max-Age=0：{cookie}");
    assert_eq!(cookie.contains("Secure"), secure, "Secure 应与请求是否 HTTPS 一致：{cookie}");
}

/// 401 的错误体契约：LFS 媒体类型、`{message, request_id}`、两个认证挑战头。
fn assert_json_401(headers: &HeaderMap, body: &[u8]) {
    assert_eq!(content_type(headers), LFS_MEDIA_TYPE);
    assert_eq!(
        headers.get(header::WWW_AUTHENTICATE).and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"netdisk-lfs\"")
    );
    assert_eq!(
        headers.get("lfs-authenticate").and_then(|value| value.to_str().ok()),
        Some("Basic realm=\"netdisk-lfs\"")
    );
    let value: Value = serde_json::from_slice(body).expect("错误体应是 JSON");
    assert!(value["message"].as_str().is_some_and(|message| !message.is_empty()));
    assert!(value["request_id"].as_str().is_some_and(|id| !id.is_empty()));
}

// ---------------------------------------------------------------------------
// 登录页
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_root_when_get_then_login_page_with_fields_register_link_and_approval_hint() {
    let app = TestApp::new();

    let (status, headers, body) = app.send(Req::new(Method::GET, "/").build()).await;
    let page = body_text(body);

    assert_eq!(status, StatusCode::OK);
    assert!(content_type(&headers).starts_with("text/html"), "实际：{}", content_type(&headers));
    assert!(page.contains(r#"action="/login""#), "表单应提交到 /login：{page}");
    assert!(page.contains(r#"name="username""#), "应有用户名输入框");
    assert!(page.contains(r#"name="password""#), "应有口令输入框");
    assert!(page.contains("登录"), "应有登录按钮");
    assert!(page.contains(r#"href="/account/register""#), "应有注册链接");
    // 默认 approval 策略：注册后要管理员审批，登录页必须说清楚。
    assert!(page.contains("管理员审批"), "approval 策略应提示需审批");
    assert!(!page.contains("<script"), "登录页不得含脚本");
    assert!(set_cookies(&headers).is_empty(), "未登录的登录页不该下发 Cookie");
}

#[tokio::test]
async fn given_open_policy_when_get_root_then_no_approval_hint() {
    let app = TestApp::with(|config| config.accounts.registration = RegistrationPolicy::Open);

    let (_, _, body) = app.send(Req::new(Method::GET, "/").build()).await;
    let page = body_text(body);

    assert!(page.contains(r#"href="/account/register""#), "注册链接仍要在");
    assert!(!page.contains("管理员审批"), "open 策略不该提示审批：{page}");
}

#[tokio::test]
async fn given_malformed_cookie_when_get_root_then_login_page_and_clear_cookie() {
    let app = TestApp::new();

    let (status, headers, body) =
        app.send(Req::new(Method::GET, "/").cookie_value("not-a-session").build()).await;

    assert_eq!(status, StatusCode::OK, "坏 Cookie 只该被清掉，不该挡登录页");
    assert!(body_text(body).contains(r#"name="password""#));
    assert_clear_cookie(&headers, false);
}

#[tokio::test]
async fn given_valid_session_when_get_root_then_redirect_to_landing_and_respect_next() {
    let app = TestApp::new();
    app.create_user("root", Role::Admin, UserStatus::Active).await;
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;
    let admin = app.session("root", Role::Admin);
    let reader = app.session("alice", Role::Readwrite);

    let (status, headers, _) = app.send(Req::new(Method::GET, "/").cookie(&admin).build()).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin", "管理员默认落管理页");

    // 站内 next 优先于角色落地页（readwrite 默认去 /account，这里显式要 /admin）。
    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/?next=%2Fadmin").cookie(&reader).build()).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin", "合法 next 应被尊重");

    // 非法 next 被忽略，回落到角色落地页。
    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/?next=%2F%2Fevil.example").cookie(&reader).build()).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/account");
}

// ---------------------------------------------------------------------------
// 表单登录
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_admin_when_login_then_303_admin_with_session_cookie() {
    let app = TestApp::new();
    app.create_user("root", Role::Admin, UserStatus::Active).await;

    let (status, headers, body) =
        app.send(Req::new(Method::POST, "/login").login("root", PASSWORD, None).build()).await;

    assert_eq!(status, StatusCode::SEE_OTHER, "登录成功用 303，浏览器刷新不会重复提交");
    assert_eq!(location(&headers), "/admin", "管理员落管理页");
    let cookie = assert_session_cookie(&headers, false);
    // 下发的会话必须真的进了会话表，否则就是「登录成功、下一请求 401」。
    session_cookie_value(&cookie);
    assert_eq!(app.state.sessions().len(), 1, "会话应已建立");
    assert!(body.is_empty(), "303 不带响应体");
}

#[tokio::test]
async fn given_readwrite_when_login_then_303_account() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    let (status, headers, _) =
        app.send(Req::new(Method::POST, "/login").login("alice", PASSWORD, None).build()).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/account");
    assert_session_cookie(&headers, false);
}

#[tokio::test]
async fn given_https_public_base_when_login_then_cookie_is_secure() {
    let app = TestApp::with(|config| config.server.public_base = "https://lfs.test".to_owned());
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    let (status, headers, _) =
        app.send(Req::new(Method::POST, "/login").login("alice", PASSWORD, None).build()).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_session_cookie(&headers, true);
}

#[tokio::test]
async fn given_wrong_password_when_login_then_401_same_message_without_cookie() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    let (status, headers, body) = app
        .send(Req::new(Method::POST, "/login").login("alice", "definitely wrong", None).build())
        .await;
    let page = body_text(body);

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(content_type(&headers).starts_with("text/html"), "登录失败应回到登录页");
    assert!(page.contains(LOGIN_FAILED_MESSAGE), "应显示统一文案：{page}");
    assert!(!page.contains("口令不正确"), "不能区分「口令错」与「没这个人」：{page}");
    assert!(set_cookies(&headers).is_empty(), "失败不得下发会话 Cookie");
    assert!(app.state.sessions().is_empty(), "失败的登录不该建会话");
}

#[tokio::test]
async fn given_pending_or_disabled_account_when_login_then_401_same_message() {
    let app = TestApp::new();
    app.create_user("pending_user", Role::Readwrite, UserStatus::Pending).await;
    app.create_user("disabled_user", Role::Readwrite, UserStatus::Disabled).await;

    // 口令正确、账户状态不对：对外必须与「口令错」完全同一条文案。
    for name in ["pending_user", "disabled_user"] {
        let (status, headers, body) =
            app.send(Req::new(Method::POST, "/login").login(name, PASSWORD, None).build()).await;
        let page = body_text(body);

        assert_eq!(status, StatusCode::UNAUTHORIZED, "{name} 不应登录成功");
        assert!(page.contains(LOGIN_FAILED_MESSAGE), "{name} 应显示统一文案：{page}");
        assert!(!page.contains("待审批") && !page.contains("已禁用"), "不能泄漏账户状态：{page}");
        assert!(set_cookies(&headers).is_empty());
    }
    assert!(app.state.sessions().is_empty());
}

#[tokio::test]
async fn given_login_over_limit_when_login_then_429_with_retry_after() {
    // 用 config 用户（sha256）覆盖限速，省掉 Argon2 的开销。
    let app = TestApp::with(|config| {
        add_config_user(config, "legacy", PASSWORD, Role::Readwrite);
        config.accounts.login_failures_per_5min = 2;
    });

    for _ in 0..2 {
        let (status, _, _) =
            app.send(Req::new(Method::POST, "/login").login("legacy", "wrong", None).build()).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED);
    }

    // 超过上限后，正确口令同样被拒——否则限速对爆破毫无意义。
    let (status, headers, body) =
        app.send(Req::new(Method::POST, "/login").login("legacy", PASSWORD, None).build()).await;

    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert!(content_type(&headers).starts_with("text/html"), "浏览器应拿到 429 页面");
    assert!(headers.contains_key(header::RETRY_AFTER), "429 必须带 Retry-After");
    assert!(body_text(body).contains("秒后重试"), "页面应说明多久后重试");
    assert!(set_cookies(&headers).is_empty(), "被限速的请求不得下发会话 Cookie");
}

#[tokio::test]
async fn given_missing_form_fields_when_login_then_400() {
    let app = TestApp::new();

    let (status, headers, body) =
        app.send(Req::new(Method::POST, "/login").login("", "whatever", None).build()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(content_type(&headers).starts_with("text/html"));

    let (status, _, _) =
        app.send(Req::new(Method::POST, "/login").login("alice", "", None).build()).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "口令为空同样是缺字段");
    assert!(!body_text(body).contains(LOGIN_FAILED_MESSAGE), "缺字段不是口令错误");
}

// ---------------------------------------------------------------------------
// next 校验（开放重定向）
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_in_site_next_when_login_then_redirect_to_it() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    // 带查询串的站内路径：编码后整体回跳，不会被拆成外层查询参数。
    let (status, headers, _) = app
        .send(
            Req::new(Method::POST, "/login")
                .login("alice", PASSWORD, Some("/admin?status=pending"))
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin?status=pending");
}

#[tokio::test]
async fn given_offsite_next_when_login_then_falls_back_to_role_landing() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    // 协议相对 URL、绝对 URL、含控制字符、含反斜杠：全部按非法 next 处理。
    for next in ["//evil.example", "https://evil.example", "/a\nb", "/\\evil.example"] {
        let (status, headers, body) = app
            .send(Req::new(Method::POST, "/login").login("alice", PASSWORD, Some(next)).build())
            .await;

        assert_eq!(status, StatusCode::SEE_OTHER, "next={next:?} 仍应登录成功");
        assert_eq!(location(&headers), "/account", "next={next:?} 必须被拒并回落到角色落地页");
        assert!(!body_text(body).contains("evil.example"));
    }
}

// ---------------------------------------------------------------------------
// 登录 CSRF
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_cross_site_origin_when_login_then_403_without_session() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    let (status, headers, body) = app
        .send(
            Req::new(Method::POST, "/login")
                .login("alice", PASSWORD, None)
                .header("origin", "https://evil.example")
                .build(),
        )
        .await;
    let page = body_text(body);

    assert_eq!(status, StatusCode::FORBIDDEN, "跨站登录必须被拒（login CSRF）");
    assert!(content_type(&headers).starts_with("text/html"), "浏览器应拿到 403 页面");
    assert!(!page.contains(LOGIN_FAILED_MESSAGE), "403 不是口令错误页：{page}");
    assert!(app.state.sessions().is_empty(), "被拒的跨站请求不得建会话");
    assert!(set_cookies(&headers).is_empty());
}

#[tokio::test]
async fn given_cross_site_sec_fetch_site_when_login_then_403() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    let (status, _, _) = app
        .send(
            Req::new(Method::POST, "/login")
                .login("alice", PASSWORD, None)
                .header("sec-fetch-site", "cross-site")
                .build(),
        )
        .await;

    // Sec-Fetch-Site 优先于 Origin：即使不带 Origin 也一律拒。
    assert_eq!(status, StatusCode::FORBIDDEN);
    assert!(app.state.sessions().is_empty());
}

#[tokio::test]
async fn given_same_origin_when_login_then_303() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    let (status, headers, _) = app
        .send(
            Req::new(Method::POST, "/login")
                .login("alice", PASSWORD, None)
                .header("origin", "http://lfs.test:9001")
                .build(),
        )
        .await;

    // 同主机名、不同 scheme/端口：反代终结 TLS 或换端口的正常形态，必须放行。
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/account");
}

// ---------------------------------------------------------------------------
// /account 落地页
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_session_when_get_account_then_200_with_identity_and_logout_form() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;
    let id = app.session("alice", Role::Readwrite);

    let (status, headers, body) =
        app.send(Req::new(Method::GET, "/account").cookie(&id).build()).await;
    let page = body_text(body);

    assert_eq!(status, StatusCode::OK);
    assert!(content_type(&headers).starts_with("text/html"));
    assert!(page.contains("alice"), "应显示用户名：{page}");
    assert!(page.contains("读写"), "应显示角色：{page}");
    assert!(page.contains("正常"), "应显示状态：{page}");
    assert!(page.contains("创建时间") && page.contains("最后登录"), "应显示时间：{page}");
    assert!(page.contains("http://lfs.test"), "应显示 LFS 端点：{page}");
    assert!(page.contains(".lfsconfig"), "应给出 .lfsconfig 片段：{page}");
    assert!(page.contains(r#"action="/logout""#), "应有退出表单：{page}");
    assert!(page.contains("退出登录"));
    assert!(!page.contains("管理账户"), "普通用户不该看到管理入口：{page}");
    assert!(!page.contains("<script"), "账户页不得含脚本");
}

#[tokio::test]
async fn given_admin_session_when_get_account_then_admin_link_present() {
    let app = TestApp::new();
    app.create_user("root", Role::Admin, UserStatus::Active).await;
    let id = app.session("root", Role::Admin);

    let (_, _, body) = app.send(Req::new(Method::GET, "/account").cookie(&id).build()).await;
    let page = body_text(body);

    assert!(page.contains(r#"href="/admin""#), "管理员应看到管理入口：{page}");
}

#[tokio::test]
async fn given_no_cookie_when_get_account_with_accept_html_then_303_to_login() {
    let app = TestApp::new();

    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/account").accept_html().build()).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/?next=%2Faccount");
}

#[tokio::test]
async fn given_no_accept_when_get_account_then_401_json() {
    let app = TestApp::new();

    let (status, headers, body) = app.send(Req::new(Method::GET, "/account").build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "没有 Accept: text/html 就维持 JSON 401");
    assert_json_401(&headers, &body);
}

#[tokio::test]
async fn given_no_cookie_when_get_admin_page_then_303_with_query_preserved() {
    let app = TestApp::new();

    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/admin?status=pending").accept_html().build()).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/?next=%2Fadmin%3Fstatus%3Dpending");
}

#[tokio::test]
async fn given_revoked_session_when_get_account_then_303_login_and_clear_cookie() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;
    let id = app.session("alice", Role::Readwrite);
    app.state.sessions().revoke(&id);

    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/account").cookie(&id).accept_html().build()).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/?next=%2Faccount");
    assert_clear_cookie(&headers, false);
}

#[tokio::test]
async fn given_no_credentials_when_lfs_batch_then_401_json_with_challenge() {
    let app = TestApp::new();

    // git 客户端不带 Accept: text/html，LFS 端点的 401 语义必须完全不变。
    let (status, headers, body) =
        app.send(Req::new(Method::POST, "/lfs/objects/batch").build()).await;

    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_json_401(&headers, &body);
}

#[tokio::test]
async fn given_config_only_user_when_login_then_account_page_shows_dash_for_timestamps() {
    // 2 个字符的用户名达不到账户库 3–32 的规则：它永远只在 `[auth.users]` 里，
    // 登录后也没有库行，`/account` 的创建/最后登录时间必须是空值而不是 500。
    let app = TestApp::with(|config| add_config_user(config, "ab", PASSWORD, Role::Readwrite));

    let (status, headers, _) =
        app.send(Req::new(Method::POST, "/login").login("ab", PASSWORD, None).build()).await;
    assert_eq!(status, StatusCode::SEE_OTHER, "config 用户必须能登录");
    assert_eq!(location(&headers), "/account");
    let cookie = assert_session_cookie(&headers, false);
    let value = session_cookie_value(&cookie);

    // 登录成功、下一请求也必须被认出来（判定口径与 Basic 完全一致）。
    let (status, _, body) =
        app.send(Req::new(Method::GET, "/account").cookie_value(&value).build()).await;
    let page = body_text(body);
    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("ab"));
    assert!(page.contains('—'), "空时间应显示破折号：{page}");
}

#[tokio::test]
async fn given_no_account_store_when_login_then_config_admin_lands_on_admin_page() {
    let app = TestApp::without_accounts();

    let (status, headers, _) =
        app.send(Req::new(Method::POST, "/login").login("cfgadmin", PASSWORD, None).build()).await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/admin", "角色取配置，管理员落管理页");
    assert_eq!(app.state.sessions().len(), 1);
}

// ---------------------------------------------------------------------------
// 退出
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_session_when_logout_then_303_clear_cookie_and_session_gone() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;

    let (_, headers, _) =
        app.send(Req::new(Method::POST, "/login").login("alice", PASSWORD, None).build()).await;
    let value = session_cookie_value(&assert_session_cookie(&headers, false));
    assert_eq!(app.state.sessions().len(), 1);

    let (status, headers, _) = app
        .send(
            Req::new(Method::POST, "/logout")
                .cookie_value(&value)
                .header("sec-fetch-site", "same-origin")
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/");
    assert_clear_cookie(&headers, false);
    assert!(app.state.sessions().is_empty(), "显式退出必须自己 revoke 会话");

    // 旧 Cookie 立刻失效：页面请求跳登录页，API 请求 401。
    let (status, headers, _) = app
        .send(Req::new(Method::GET, "/account").cookie_value(&value).accept_html().build())
        .await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/?next=%2Faccount");

    let (status, headers, body) =
        app.send(Req::new(Method::GET, "/account").cookie_value(&value).build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_json_401(&headers, &body);
}

#[tokio::test]
async fn given_no_cookie_when_logout_then_still_303_and_clears_cookie() {
    let app = TestApp::new();

    let (status, headers, _) = app.send(Req::new(Method::POST, "/logout").build()).await;

    // 退出必须幂等：没有会话也回 303 并清一次 Cookie（重放、刷新都不出错）。
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(location(&headers), "/");
    assert_clear_cookie(&headers, false);
}

#[tokio::test]
async fn given_session_when_cross_site_logout_then_403_and_session_kept() {
    let app = TestApp::new();
    app.create_user("alice", Role::Readwrite, UserStatus::Active).await;
    let id = app.session("alice", Role::Readwrite);

    // 带会话 Cookie 的跨站写请求由全局守卫拦下：不能让恶意页面替用户退出。
    let (status, _, _) = app
        .send(
            Req::new(Method::POST, "/logout")
                .cookie(&id)
                .header("sec-fetch-site", "cross-site")
                .build(),
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN);
    assert_eq!(app.state.sessions().len(), 1, "被拒的跨站退出不得撤销会话");
}

// ---------------------------------------------------------------------------
// 零回归：Basic 与注册页
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_basic_when_account_me_and_admin_users_then_still_works() {
    let app = TestApp::new();
    app.create_user("root", Role::Admin, UserStatus::Active).await;

    let (status, headers, body) =
        app.send(Req::new(Method::GET, "/account/me").basic("root", PASSWORD).build()).await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type(&headers), "application/json");
    let value: Value = serde_json::from_slice(&body).expect("应是 JSON");
    assert_eq!(value["username"], "root");
    assert_eq!(value["role"], "admin");

    let (status, _, _) =
        app.send(Req::new(Method::GET, "/admin/users").basic("root", PASSWORD).build()).await;
    assert_eq!(status, StatusCode::OK, "Basic 管理端点不受登录页改动影响");

    // 错误 Basic 仍是 401 + 挑战头，且不会回退到会话 Cookie。
    let (status, headers, body) =
        app.send(Req::new(Method::GET, "/account/me").basic("root", "wrong").build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert_json_401(&headers, &body);
}

#[tokio::test]
async fn given_register_page_when_get_then_has_link_back_to_login() {
    let app = TestApp::new();

    let (status, _, body) = app.send(Req::new(Method::GET, "/account/register").build()).await;
    let page = body_text(body);

    assert_eq!(status, StatusCode::OK);
    assert!(page.contains(r#"href="/""#), "注册页应有返回登录的链接：{page}");
    assert!(page.contains("返回登录"));
}

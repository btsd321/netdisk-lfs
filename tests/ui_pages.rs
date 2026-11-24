//! 页面级验收：共享台账布局在 `/account`、`/admin`、登录页与注册页上的表现。
//!
//! 这里只关心「页面本身」：身份信息是否出现、退出表单在两种认证通道下的差异、
//! 管理页的统计条与筛选页签、以及**页面绝不引外部资源**（离线可用、无追踪）。
//! 端点语义（303/401/403、CSRF、会话失效）由 `login_page.rs` 与 `accounts_*.rs` 覆盖。
//!
//! 认证刻意只用 `[auth.users]` 里的 config 用户（sha256，便宜）：本文件不需要
//! Argon2 登录流程，用例才能保持秒级。

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU32, Ordering};

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
    UserConfig, UserStatus, UserStore, router,
};
use tower::ServiceExt;

const TEST_HOST: &str = "lfs.test";
const PASSWORD: &str = "correct horse battery";

/// 每个用例一个临时目录；Drop 时连同 SQLite 的 `-wal` / `-shm` 一起删除。
struct Workspace {
    path: PathBuf,
}

impl Workspace {
    fn new() -> Self {
        static SEQ: AtomicU32 = AtomicU32::new(0);
        let seq = SEQ.fetch_add(1, Ordering::Relaxed);
        let path =
            std::env::temp_dir().join(format!("netdisk-lfs-ui-pages-{}-{seq}", std::process::id()));
        std::fs::create_dir(&path).expect("创建临时目录");
        Self { path }
    }
}

impl Drop for Workspace {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// 测试应用：账户库 + 两个 config 用户（`root` 管理员、`alice` 读写）。
struct TestApp {
    router: Router,
    state: AppState,
    store: Arc<UserStore>,
    _workspace: Workspace,
}

impl TestApp {
    fn new() -> Self {
        let workspace = Workspace::new();
        let db = workspace.path.join("accounts.db");
        let store = Arc::new(UserStore::open(&db).expect("账户库应能打开"));
        let mut config = base_config(db);
        add_config_user(&mut config, "root", Role::Admin);
        add_config_user(&mut config, "alice", Role::Readwrite);
        let backend: Arc<dyn ObjectStore> = Arc::new(FakeStore::new());
        let state = AppState::with_accounts(backend, Arc::new(config), Arc::clone(&store));
        Self { router: router(state.clone()), state, store, _workspace: workspace }
    }

    /// 直接写一行账户（哈希是占位串：本文件不会用这些账户登录）。
    async fn seed(&self, name: &str, role: Role, status: UserStatus) {
        self.store
            .create(name, "placeholder-hash", role, status)
            .await
            .unwrap_or_else(|error| panic!("写入 {name} 失败：{error}"));
    }

    /// 直接造一个会话（跳过登录表单）。
    fn session(&self, username: &str, role: Role) -> SessionId {
        self.state.sessions().create(username, role).expect("应能建立会话")
    }

    async fn send(&self, request: Request<Body>) -> (StatusCode, HeaderMap, String) {
        let response = self.router.clone().oneshot(request).await.expect("router 应处理请求");
        let status = response.status();
        let headers = response.headers().clone();
        let body = response.into_body().collect().await.expect("读取响应体").to_bytes();
        (status, headers, String::from_utf8(body.to_vec()).expect("HTML 应是 UTF-8"))
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
        auth: AuthConfig { users: std::collections::BTreeMap::new() },
        runtime_env: RuntimeEnv::Dev,
        data_dir: None,
    }
}

fn add_config_user(config: &mut Config, name: &str, role: Role) {
    let mut hasher = Sha256Writer::new();
    hasher.update(PASSWORD.as_bytes());
    config
        .auth
        .users
        .insert(name.to_owned(), UserConfig { password_sha256: hasher.finish(), role });
}

fn basic_header(username: &str) -> String {
    format!("Basic {}", BASE64.encode(format!("{username}:{PASSWORD}")))
}

/// 请求构造器：默认带 `Host`，按需加 Cookie / Basic / `Accept`。
struct Req {
    method: Method,
    uri: String,
    headers: Vec<(&'static str, String)>,
}

impl Req {
    fn new(method: Method, uri: &str) -> Self {
        Self { method, uri: uri.to_owned(), headers: Vec::new() }
    }

    fn cookie(mut self, id: &SessionId) -> Self {
        self.headers.push((COOKIE.as_str(), format!("{SESSION_COOKIE_NAME}={}", id.as_str())));
        self
    }

    fn basic(mut self, username: &str) -> Self {
        self.headers.push((header::AUTHORIZATION.as_str(), basic_header(username)));
        self
    }

    fn accept_html(mut self) -> Self {
        self.headers.push((header::ACCEPT.as_str(), "text/html".to_owned()));
        self
    }

    fn build(self) -> Request<Body> {
        let mut builder =
            Request::builder().method(self.method).uri(self.uri).header(header::HOST, TEST_HOST);
        for (name, value) in self.headers {
            builder = builder.header(name, value);
        }
        builder.body(Body::empty()).expect("请求应能构造")
    }
}

/// 页面里所有指向站外的地址（`href` / `src` 以 `http://`、`https://` 或 `//` 开头）。
fn external_references(page: &str) -> Vec<String> {
    let mut found = Vec::new();
    for attribute in [r#"href=""#, r#"src=""#] {
        let mut rest = page;
        while let Some(index) = rest.find(attribute) {
            rest = &rest[index + attribute.len()..];
            let value = rest.split('"').next().unwrap_or_default();
            if value.starts_with("http://")
                || value.starts_with("https://")
                || value.starts_with("//")
            {
                found.push(value.to_owned());
            }
        }
    }
    found
}

/// 断言页面离线可用：没有脚本、没有外部样式表/字体、没有任何外链。
fn assert_offline_page(page: &str) {
    assert!(!page.contains("<script"), "页面不得含脚本：{page}");
    assert!(!page.contains("<link"), "页面不得引外部样式表或字体：{page}");
    assert!(!page.contains("@import"), "样式里不得 @import：{page}");
    assert!(!page.contains("https://fonts."), "不得引在线字体：{page}");
    let external = external_references(page);
    assert!(external.is_empty(), "页面不得含外链，实际发现 {external:?}");
}

// ---------------------------------------------------------------------------
// 账户页
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_session_when_get_account_then_identity_panels_and_logout() {
    let app = TestApp::new();
    let id = app.session("alice", Role::Readwrite);

    let (status, headers, page) =
        app.send(Req::new(Method::GET, "/account").cookie(&id).build()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(content_type(&headers), "text/html; charset=utf-8");
    assert_eq!(cache_control(&headers), "no-store", "账户页不得被缓存");
    assert_offline_page(&page);

    // 身份面板：首字母方块、用户名、角色、状态、时间。
    assert!(page.contains("我的账户"), "应有页面标题：{page}");
    assert!(page.contains(r#"class="initial""#), "应有首字母方块：{page}");
    assert!(page.contains("alice"));
    assert!(page.contains(">读写<"), "角色徽章：{page}");
    assert!(page.contains(">已启用<"), "状态点 + 文字：{page}");
    assert!(page.contains("创建时间") && page.contains("最后登录"));
    // LFS 面板：端点、.lfsconfig 片段、三步命令。
    assert!(page.contains("http://lfs.test/lfs/"));
    assert!(page.contains(".lfsconfig"));
    assert!(page.contains("git lfs install"));
    assert!(page.contains("git lfs track") && page.contains("git push"));
    // 页头退出：会话通道只有这一个退出入口。
    assert_eq!(page.matches(r#"action="/logout""#).count(), 1, "退出表单只出现一次：{page}");
    assert!(page.contains("退出登录"));
    // 非管理员没有管理入口，也没有 Basic 提示。
    assert!(!page.contains(r#"href="/admin""#), "非管理员不该看到管理入口：{page}");
    assert!(!page.contains("HTTP Basic 认证"), "会话通道不该出现 Basic 提示：{page}");
}

#[tokio::test]
async fn given_admin_session_when_get_account_then_admin_entry() {
    let app = TestApp::new();
    let id = app.session("root", Role::Admin);

    let (_, _, page) = app.send(Req::new(Method::GET, "/account").cookie(&id).build()).await;

    assert!(page.contains(r#"href="/admin""#), "管理员应看到管理入口：{page}");
    assert!(page.contains("管理账户"), "账户页给管理员的入口文案：{page}");
}

#[tokio::test]
async fn given_basic_when_get_account_then_no_logout_form_and_honest_hint() {
    let app = TestApp::new();

    let (status, _, page) =
        app.send(Req::new(Method::GET, "/account").basic("alice").build()).await;

    assert_eq!(status, StatusCode::OK);
    assert!(!page.contains(r#"action="/logout""#), "Basic 通道不能给无效的退出按钮：{page}");
    assert!(page.contains("当前为 HTTP Basic 认证"), "必须说明当前通道：{page}");
    assert!(page.contains("清除浏览器"), "必须给出真正的退出方式：{page}");
    // Basic 用户同样要拿到完整的 LFS 接入信息。
    assert!(page.contains("http://lfs.test/lfs/"));
}

// ---------------------------------------------------------------------------
// 管理页
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_session_when_get_admin_then_stats_tabs_and_logout() {
    let app = TestApp::new();
    app.seed("pending-pal", Role::Readwrite, UserStatus::Pending).await;
    app.seed("old-timer", Role::Readonly, UserStatus::Disabled).await;
    app.seed("worker", Role::Readwrite, UserStatus::Active).await;
    let id = app.session("root", Role::Admin);

    let (status, headers, page) =
        app.send(Req::new(Method::GET, "/admin").cookie(&id).build()).await;

    assert_eq!(status, StatusCode::OK);
    assert_eq!(cache_control(&headers), "no-store");
    assert_offline_page(&page);

    // 账号 chip：当前管理员自己。
    assert!(page.contains("root"));
    assert!(page.contains(">管理员<"), "角色徽章：{page}");
    assert_eq!(page.matches(r#"action="/logout""#).count(), 1, "退出表单只出现一次：{page}");

    // 统计条：总数 3、待审批 1、已启用 1、已禁用 1。
    assert!(page.contains(r#"aria-label="账户统计""#), "应有统计条：{page}");
    for (count, label) in [("3", "总数"), ("1", "待审批"), ("1", "已启用"), ("1", "已禁用")]
    {
        assert!(
            page.contains(&format!(r#"<span class="stat-n">{count}</span>"#)),
            "统计条应给出 {label}={count}：{page}"
        );
        assert!(page.contains(&format!(r#"<span class="stat-k">{label}</span>"#)));
    }

    // 筛选页签：四项、当前项 aria-current、链接保留 ?status=。
    assert!(page.contains(r#"aria-label="按状态筛选""#), "应有筛选页签：{page}");
    assert!(page.contains(r#"<a href="/admin" aria-current="page">全部</a>"#));
    for (href, label) in [
        ("/admin?status=pending", "待审批"),
        ("/admin?status=active", "已启用"),
        ("/admin?status=disabled", "已禁用"),
    ] {
        assert!(
            page.contains(&format!(r#"<a href="{href}">{label}</a>"#)),
            "缺页签 {label}：{page}"
        );
    }

    // 状态文案只有一套：表格、统计条、页签都用「已启用 / 待审批 / 已禁用」。
    assert!(!page.contains(">正常<"), "表格不该再用「正常」：{page}");
    assert!(page.contains(">已启用<"), "表格与统计条都写「已启用」：{page}");

    // 表格行：三种状态各一行，操作表单保留原有端点。
    assert!(page.contains("<table>"));
    assert!(page.contains("/admin/users/pending-pal/approve"));
    assert!(page.contains("/admin/users/worker/disable"));
    assert!(page.contains("/admin/users/old-timer/enable"));
    assert!(page.contains(r#"name="confirm""#), "删除要勾选确认：{page}");
}

#[tokio::test]
async fn given_session_when_filter_has_no_match_then_empty_state() {
    let app = TestApp::new();
    app.seed("worker", Role::Readwrite, UserStatus::Active).await;
    let id = app.session("root", Role::Admin);

    let (status, _, page) =
        app.send(Req::new(Method::GET, "/admin?status=pending").cookie(&id).build()).await;

    assert_eq!(status, StatusCode::OK);
    assert!(page.contains("当前筛选下没有账户"), "空筛选要有空状态：{page}");
    assert!(!page.contains("<table>"), "没有行就不渲染空表格：{page}");
}

#[tokio::test]
async fn given_offset_beyond_total_when_get_admin_then_out_of_range_hint_and_first_page_link() {
    let app = TestApp::new();
    app.seed("worker", Role::Readwrite, UserStatus::Active).await;
    let id = app.session("root", Role::Admin);

    let (status, _, page) = app
        .send(Req::new(Method::GET, "/admin?status=active&offset=100").cookie(&id).build())
        .await;

    assert_eq!(status, StatusCode::OK);
    // 越界不是「这个筛选下没有账户」：说清实际总数，并给一条保留筛选的回头路。
    assert!(page.contains("超出范围"), "越界要有专门提示：{page}");
    assert!(page.contains("共 1 个账户"), "要说清当前筛选下的实际总数：{page}");
    assert!(
        page.contains(r#"<a href="/admin?status=active">回到第一页</a>"#),
        "回到第一页要保留筛选：{page}"
    );
    assert!(!page.contains("当前筛选下没有账户"), "不能把越界说成空筛选：{page}");
}

#[tokio::test]
async fn given_basic_when_get_admin_then_no_logout_form_and_basic_hint() {
    let app = TestApp::new();

    let (status, _, page) = app.send(Req::new(Method::GET, "/admin").basic("root").build()).await;

    assert_eq!(status, StatusCode::OK);
    assert!(!page.contains(r#"action="/logout""#), "Basic 通道不渲染退出表单：{page}");
    assert!(page.contains("Basic 凭据由浏览器保存"), "应给出 Basic 的退出说明：{page}");
    assert!(page.contains("清除浏览器"));
    assert!(page.contains(r#"aria-label="账户统计""#), "页面主体照常渲染：{page}");
}

// ---------------------------------------------------------------------------
// 公开页与未登录跳转
// ---------------------------------------------------------------------------

#[tokio::test]
async fn given_root_when_get_then_ticket_form_register_link_and_approval_hint() {
    let app = TestApp::new();

    let (status, _, page) = app.send(Req::new(Method::GET, "/").build()).await;

    assert_eq!(status, StatusCode::OK);
    assert_offline_page(&page);
    assert!(page.contains(r#"<h1>登录</h1>"#), "票根标题：{page}");
    assert!(page.contains(r#"action="/login""#));
    assert!(page.contains(r#"name="username""#) && page.contains(r#"name="password""#));
    assert!(page.contains(r#"href="/account/register""#), "应有注册链接：{page}");
    assert!(page.contains("注册账号"));
    assert!(page.contains("管理员审批"), "approval 策略要提示需审批：{page}");
    // 左侧三条事实：协议、存储、账户。
    assert!(page.contains("Git LFS 协议"));
    assert!(page.contains("网盘对象存储"));
    assert!(page.contains("账户分级"), "事实必须与注册策略无关");
}

#[tokio::test]
async fn given_register_when_get_then_back_to_login() {
    let app = TestApp::new();

    let (status, _, page) = app.send(Req::new(Method::GET, "/account/register").build()).await;

    assert_eq!(status, StatusCode::OK);
    assert_offline_page(&page);
    assert!(page.contains(r#"action="/account/register""#));
    assert!(page.contains(r#"name="confirm_password""#));
    assert!(page.contains("返回登录"), "注册页要能走回登录页：{page}");
    assert!(page.contains(r#"href="/""#));
}

#[tokio::test]
async fn given_no_credentials_when_get_admin_page_then_redirect_or_401_json() {
    let app = TestApp::new();

    // 浏览器：303 到登录页并带原地址（语义不变）。
    let (status, headers, _) =
        app.send(Req::new(Method::GET, "/admin").accept_html().build()).await;
    assert_eq!(status, StatusCode::SEE_OTHER);
    assert_eq!(
        headers.get(header::LOCATION).and_then(|value| value.to_str().ok()),
        Some("/?next=%2Fadmin")
    );

    // 脚本客户端：401 + 挑战头（语义不变）。
    let (status, headers, _) = app.send(Req::new(Method::GET, "/admin/users").build()).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
    assert!(headers.get(header::WWW_AUTHENTICATE).is_some());
}

#[tokio::test]
async fn given_rendered_page_when_read_css_then_ledger_tokens_and_breakpoints() {
    let app = TestApp::new();
    let id = app.session("alice", Role::Readwrite);

    let (_, _, page) = app.send(Req::new(Method::GET, "/account").cookie(&id).build()).await;

    // 设计 token：石色底 + 蓝图蓝强调 + 一个 2px 圆角。
    assert!(page.contains("--bg: #dfdedb"));
    assert!(page.contains("--surface: #d3d2ce"));
    assert!(page.contains("--ink: #26251e"));
    assert!(page.contains("--muted: #55544d"));
    assert!(page.contains("--danger-ink: #b42318"));
    assert!(page.contains("--rule: #c2c1ba"));
    assert!(page.contains("--accent: #2456d6"));
    assert!(page.contains("--radius: 2px"));
    // 深色模式与降级动效。
    assert!(page.contains("prefers-color-scheme: dark") && page.contains("--bg: #141613"));
    assert!(page.contains("prefers-reduced-motion: reduce"));
    // 焦点环、等宽数字与 720px 断点。
    assert!(page.contains(":focus-visible"));
    assert!(page.contains("font-variant-numeric: tabular-nums"));
    assert!(page.contains("max-width: 720px"));
    assert!(page.contains("overflow-x: auto"), "表格容器要能横向滚动");
    // 不引外部字体：只用系统栈里的字体名。
    assert!(page.contains(r#""Noto Sans SC""#));
    assert!(!page.contains("fonts.googleapis.com"));
}

fn content_type(headers: &HeaderMap) -> &str {
    headers.get(header::CONTENT_TYPE).and_then(|value| value.to_str().ok()).unwrap_or("")
}

fn cache_control(headers: &HeaderMap) -> &str {
    headers.get(header::CACHE_CONTROL).and_then(|value| value.to_str().ok()).unwrap_or("")
}

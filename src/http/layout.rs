//! 共享页面布局：台账式外壳、顶部书脊栏、账号 chip 与唯一一份内联样式。
//!
//! 两类页面：登录/注册这类未登录页用 [`public_page`]（说明 + 票根表单两栏），
//! 登录后的账户页与管理页用 [`authed_page`]（导航 + 账号 chip + 退出）。两类页面
//! 共用同一份 [`STYLE`]：CSS 是单例，避免两套样式各自漂移。
//!
//! 硬性约束（与 [`super::html`] 一致）：不引外部字体/CDN、页面里没有一行脚本，
//! 离线可用；所有动态文本先过 [`escape_html`]；缓存头由
//! [`super::html::html_response`] 统一加 `no-store`。

use axum::http::HeaderMap;
use axum::http::header::AUTHORIZATION;

use super::auth::AuthUser;
use super::html::escape_html;
use crate::accounts::UserStatus;
use crate::config::Role;

/// 顶部导航的当前项：只用来给对应链接加 `aria-current` 与强调底线。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Nav {
    /// `/account`。
    Account,
    /// `/admin`。
    Admin,
}

/// 这次请求是怎么认证的：决定要不要渲染退出表单。
///
/// 会话 Cookie 可以服务端撤销，退出表单真的有效；HTTP Basic 的凭据由浏览器自己
/// 保存，页面上的按钮清不掉它，只能给出「关闭浏览器 / 清除站点凭据」的说明。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum CredentialChannel {
    /// 会话 Cookie（登录页签发）。
    Session,
    /// HTTP Basic（git 客户端与浏览器缓存的凭据）。
    Basic,
}

impl CredentialChannel {
    /// 按请求头判定通道：带 `Authorization` 就是 Basic。
    ///
    /// 与认证中间件同一口径——两条通道同时出现时以 Basic 为准，页面提示必须跟着
    /// 实际生效的那条走，否则会给出一个按了也不生效的退出按钮。
    pub(crate) fn of(headers: &HeaderMap) -> Self {
        if headers.contains_key(AUTHORIZATION) { Self::Basic } else { Self::Session }
    }

    /// 日志字段值。
    pub(crate) fn as_str(self) -> &'static str {
        match self {
            Self::Session => "session",
            Self::Basic => "basic",
        }
    }
}

/// 角色在页面上的中文标签。
pub(crate) fn role_label(role: Role) -> &'static str {
    match role {
        Role::Readonly => "只读",
        Role::Readwrite => "读写",
        Role::Admin => "管理员",
    }
}

/// 状态在页面上的中文标签。
pub(crate) fn status_label(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "正常",
        UserStatus::Pending => "待审批",
        UserStatus::Disabled => "已禁用",
    }
}

/// 状态点在样式表里对应的颜色类。
///
/// 颜色只是辅助：文字标签始终同时出现，色觉差异不影响读数。
pub(crate) fn status_dot(status: UserStatus) -> &'static str {
    match status {
        UserStatus::Active => "dot-ok",
        UserStatus::Pending => "dot-warn",
        UserStatus::Disabled => "dot-danger",
    }
}

/// 登录后的页面外壳。
///
/// `active` 决定导航高亮；`channel` 决定右侧是退出表单还是 Basic 说明；`body` 是
/// 调用方渲染好的正文（其中的动态文本由调用方转义）。
pub(crate) fn authed_page(
    title: &str,
    user: &AuthUser,
    status: UserStatus,
    channel: CredentialChannel,
    active: Nav,
    body: &str,
) -> String {
    let header = format!(
        r#"<header class="spine">
<div class="spine-bar wrap">
{brand}
<nav class="nav" aria-label="主导航">{nav}</nav>
{chip}
</div>
</header>"#,
        brand = brand_link(),
        nav = render_nav(active, user.role),
        chip = render_chip(user, status, channel),
    );
    document(title, &header, body)
}

/// 未登录的页面外壳：左侧一句话定位 + 三条事实，右侧票根表单。
///
/// `body` 是表单正文（标题由本函数渲染），错误块、提示与链接都在 `body` 里。
pub(crate) fn public_page(title: &str, subtitle: &str, body: &str) -> String {
    let header = format!(
        r#"<header class="spine">
<div class="spine-bar wrap">
{brand}
</div>
</header>"#,
        brand = brand_link(),
    );
    let gate = format!(
        r#"<div class="gate">
<section class="gate-brand">
{brand_mark}
<p class="gate-lede">{subtitle}</p>
{facts}
</section>
<div class="ticket">
<h1>{title}</h1>
{body}
</div>
</div>"#,
        brand_mark = BRAND_MARK,
        facts = FACTS,
        subtitle = escape_html(subtitle),
        title = escape_html(title),
    );
    document(title, &header, &gate)
}

/// 品牌标记：两个错位的小方块，一实一空，作为「书脊」上的印记。
///
/// 纯 CSS 画，不用图片也不引字体图标；`aria-hidden` 让读屏器跳过装饰。
const BRAND_MARK: &str =
    r#"<span class="brand-mark" aria-hidden="true"><span></span><span></span></span>"#;

/// 左侧说明里固定出现的三条事实：写清楚这个网关是什么、对象放哪、账户怎么来。
const FACTS: &str = r#"<ul class="facts">
<li><span class="fact-k">Git LFS 协议</span><span class="fact-v">git push/pull 照常使用，大对象不进 Git 历史，仓库里只留指针。</span></li>
<li><span class="fact-k">网盘对象存储</span><span class="fact-v">对象按 sha256 内容寻址，落在百度网盘 <code>/apps/bdpan/</code> 下。</span></li>
<li><span class="fact-k">审批制账户</span><span class="fact-v">自助注册后由管理员启用；浏览器用会话 Cookie，Git 客户端用 HTTP Basic。</span></li>
</ul>"#;

/// 页脚：服务身份 + 探针/指标端点（相对链接，注明只在本机监听）。
const FOOTER: &str = r#"<footer class="wrap foot">
<span>Git LFS 网关</span>
<span class="foot-sep" aria-hidden="true">·</span>
<a href="/healthz">/healthz</a>
<span class="foot-sep" aria-hidden="true">·</span>
<a href="/metrics">/metrics</a>
<span class="foot-note">探针与指标端点仅监听本机，对外暴露需在反向代理上加白名单</span>
</footer>"#;

/// 品牌链接：回到 `/`（已登录时 `/` 自己会 303 到落地页）。
fn brand_link() -> String {
    let mut link = String::from(r#"<a class="brand" href="/">"#);
    link.push_str(BRAND_MARK);
    link.push_str(r#"<span class="brand-name">NETDISK·LFS</span></a>"#);
    link
}

/// 导航：账户对所有人可见，管理只对管理员显示。
fn render_nav(active: Nav, role: Role) -> String {
    let mut nav = nav_link("/account", "账户", active == Nav::Account);
    if role == Role::Admin {
        nav.push_str(&nav_link("/admin", "管理", active == Nav::Admin));
    }
    nav
}

/// 一个导航项；当前项用 `aria-current` 标记，样式表据此画 2px 强调底线。
fn nav_link(href: &str, label: &str, current: bool) -> String {
    let current = if current { r#" aria-current="page""# } else { "" };
    format!(r#"<a href="{href}"{current}>{label}</a>"#)
}

/// 右上角账号 chip：用户名、角色徽章、状态点 + 文字，以及退出方式。
fn render_chip(user: &AuthUser, status: UserStatus, channel: CredentialChannel) -> String {
    let mut chip = format!(
        r#"<div class="chip">
<span class="chip-name">{name}</span>
<span class="badge">{role}</span>
<span class="state"><span class="dot {dot}" aria-hidden="true"></span>{status}</span>"#,
        name = escape_html(&user.username),
        role = escape_html(role_label(user.role)),
        dot = status_dot(status),
        status = escape_html(status_label(status)),
    );
    match channel {
        // 会话通道：退出是一个真表单，CSRF 由全局会话守卫处理，这里不需要隐藏字段。
        CredentialChannel::Session => chip.push_str(
            r#"<form method="post" action="/logout" class="logout"><button type="submit" class="btn btn-quiet btn-small">退出登录</button></form>"#,
        ),
        // Basic 通道：不给出一个按了也不生效的按钮，只诚实说明退出方式。
        CredentialChannel::Basic => chip.push_str(
            r#"<p class="chip-note">Basic 凭据由浏览器保存；退出请关闭浏览器或清除浏览器站点凭据</p>"#,
        ),
    }
    chip.push_str("</div>");
    chip
}

/// 完整文档：`<head>` 内联样式，`<body>` 是跳过链接 + 页头 + 正文 + 页脚。
fn document(title: &str, header: &str, body: &str) -> String {
    // 这个片段里有 `href="#main"`：`"#` 会提前结束 `r#"…"#`，所以用双井号定界。
    format!(
        r##"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="light dark">
<title>{title} · netdisk-lfs</title>
<style>{style}</style>
</head>
<body>
<a class="skip" href="#main">跳到正文</a>
{header}
<main id="main" class="wrap page">
{body}
</main>
{footer}
</body>
</html>
"##,
        title = escape_html(title),
        style = STYLE,
        footer = FOOTER,
    )
}

/// 全部页面共用的内联样式（单例）。
///
/// 方向是「归档台账」：平色、细线、表格行、状态点；强调色只有一个，只出现在交互
/// 与状态上。没有渐变、没有阴影、没有圆角卡片——页面靠线和对齐立住，而不是靠装饰。
pub(crate) const STYLE: &str = r#"
:root {
  --bg: #dfdedb;
  --surface: #d3d2ce;
  --ink: #26251e;
  --muted: #6b6a62;
  --rule: #c2c1ba;
  --accent: #2456d6;
  --accent-ink: #ffffff;
  --ok: #2f6b4f;
  --warn: #b45309;
  --danger: #b42318;
  --radius: 2px;
  --sans: "Chivo", "Noto Sans SC", "Source Han Sans SC", "PingFang SC", system-ui, sans-serif;
  --mono: "DM Mono", "JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace;
}
@media (prefers-color-scheme: dark) {
  :root {
    --bg: #141613;
    --surface: #1d201b;
    --ink: #f2f1ea;
    --muted: #a3a297;
    --rule: #33362f;
    --accent: #6c8cff;
  }
}
*, *::before, *::after { box-sizing: border-box; }
body {
  display: flex;
  flex-direction: column;
  min-height: 100vh;
  margin: 0;
  background: var(--bg);
  color: var(--ink);
  font-family: var(--sans);
  font-size: 15.5px;
  line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}
h1, h2 { margin: 0; font-weight: 600; letter-spacing: -0.01em; line-height: 1.25; }
h1 { font-size: 26px; }
h2 { font-size: 17px; }
p { margin: 12px 0 0; }
a { color: var(--accent); text-decoration: none; }
a:hover { text-decoration: underline; text-underline-offset: 3px; }
:focus-visible { outline: 2px solid var(--accent); outline-offset: 2px; }
.wrap { width: 100%; max-width: 1080px; margin: 0 auto; padding: 0 24px; }
.skip {
  position: absolute;
  left: -9999px;
  top: 0;
  padding: 8px 12px;
  background: var(--ink);
  color: var(--bg);
  z-index: 10;
}
.skip:focus { left: 12px; top: 12px; }
.spine { border-bottom: 1px solid var(--rule); }
.spine-bar {
  display: flex;
  align-items: center;
  gap: 32px;
  min-height: 56px;
  padding-top: 8px;
  padding-bottom: 8px;
  flex-wrap: wrap;
}
.brand { display: inline-flex; align-items: center; gap: 10px; color: var(--ink); }
.brand:hover { text-decoration: none; }
.brand-name { font-size: 14px; font-weight: 600; letter-spacing: 0.08em; }
.brand-mark { position: relative; display: inline-block; width: 18px; height: 18px; flex: none; }
.brand-mark span { position: absolute; width: 11px; height: 11px; }
.brand-mark span:first-child { top: 0; left: 0; background: var(--ink); }
.brand-mark span:last-child { right: 0; bottom: 0; border: 1.5px solid var(--ink); }
.nav { display: flex; align-items: center; gap: 24px; }
.nav a {
  display: inline-flex;
  align-items: center;
  padding: 6px 0 4px;
  font-size: 14px;
  color: var(--muted);
  border-bottom: 2px solid transparent;
}
.nav a:hover { color: var(--ink); text-decoration: none; }
.nav a[aria-current="page"] { color: var(--ink); border-bottom-color: var(--accent); }
.chip { display: flex; align-items: center; gap: 10px; margin-left: auto; flex-wrap: wrap; }
.chip-name { font-size: 14px; font-weight: 600; overflow-wrap: anywhere; }
.badge {
  padding: 0 6px;
  font-size: 12px;
  line-height: 18px;
  color: var(--muted);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
  white-space: nowrap;
}
.state {
  display: inline-flex;
  align-items: center;
  gap: 6px;
  font-size: 12.5px;
  color: var(--muted);
  white-space: nowrap;
}
.dot { display: inline-block; width: 7px; height: 7px; border-radius: 50%; background: var(--muted); }
.dot-ok { background: var(--ok); }
.dot-warn { background: var(--warn); }
.dot-danger { background: var(--danger); }
.chip-note { margin: 0; max-width: 26ch; font-size: 11.5px; line-height: 1.35; color: var(--muted); }
.logout { display: inline-flex; margin: 0; }
.page { flex: 1; padding-top: 32px; padding-bottom: 32px; }
.foot {
  display: flex;
  flex-wrap: wrap;
  align-items: baseline;
  gap: 8px 10px;
  padding-top: 16px;
  padding-bottom: 24px;
  border-top: 1px solid var(--rule);
  font-size: 12.5px;
  color: var(--muted);
}
.foot a { color: var(--muted); }
.foot a:hover { color: var(--accent); }
.foot-sep { color: var(--rule); }
.foot-note { margin-left: auto; }
.lede { display: flex; flex-wrap: wrap; align-items: baseline; gap: 4px 16px; margin-bottom: 24px; }
.lede p { margin: 0; font-size: 13.5px; color: var(--muted); }
.split {
  display: grid;
  grid-template-columns: minmax(0, 0.85fr) minmax(0, 1.15fr);
  gap: 32px;
  align-items: start;
}
.panel { min-width: 0; padding-top: 16px; border-top: 1px solid var(--ink); }
.panel-k { margin: 0 0 16px; font-size: 12.5px; color: var(--muted); letter-spacing: 0.04em; }
.id-head { display: flex; align-items: center; gap: 12px; }
.id-head > div { min-width: 0; }
.initial {
  display: grid;
  place-items: center;
  width: 44px;
  height: 44px;
  flex: none;
  font-size: 18px;
  font-weight: 600;
  background: var(--surface);
  border: 1px solid var(--rule);
}
.id-name { font-size: 18px; font-weight: 600; overflow-wrap: anywhere; }
.id-sub { display: flex; align-items: center; gap: 8px; margin-top: 2px; }
.meta {
  display: grid;
  grid-template-columns: max-content minmax(0, 1fr);
  gap: 8px 20px;
  margin: 20px 0 0;
  font-size: 14px;
  font-variant-numeric: tabular-nums;
}
.meta dt { font-size: 13px; color: var(--muted); }
.meta dd { margin: 0; overflow-wrap: anywhere; }
.panel-note { margin-top: 16px; font-size: 13px; color: var(--muted); }
code {
  padding: 1px 5px;
  font-family: var(--mono);
  font-size: 0.88em;
  background: var(--surface);
  border-radius: var(--radius);
  overflow-wrap: anywhere;
}
pre {
  margin: 12px 0 0;
  padding: 12px 16px;
  overflow-x: auto;
  font-family: var(--mono);
  font-size: 13px;
  line-height: 1.6;
  background: var(--surface);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
}
pre code { padding: 0; background: none; }
.steps { display: grid; gap: 8px; margin: 16px 0 0; padding-left: 20px; font-size: 14px; }
.steps li::marker { color: var(--muted); }
.note { margin: 16px 0 0; font-size: 13px; color: var(--muted); }
.stats {
  display: grid;
  grid-template-columns: repeat(4, minmax(0, 1fr));
  margin: 8px 0 0;
  border-top: 1px solid var(--rule);
  border-bottom: 1px solid var(--rule);
}
.stat { display: grid; gap: 2px; padding: 16px 20px 16px 0; }
.stat + .stat { padding-left: 20px; border-left: 1px solid var(--rule); }
.stat-n { font-size: 28px; font-weight: 600; letter-spacing: -0.02em; font-variant-numeric: tabular-nums; }
.stat-k { font-size: 12.5px; color: var(--muted); }
.tabs { display: flex; flex-wrap: wrap; gap: 20px; margin: 20px 0 0; border-bottom: 1px solid var(--rule); }
.tabs a {
  display: inline-flex;
  align-items: center;
  min-height: 40px;
  margin-bottom: -1px;
  font-size: 14px;
  color: var(--muted);
  border-bottom: 2px solid transparent;
}
.tabs a:hover { color: var(--ink); text-decoration: none; }
.tabs a[aria-current="page"] { color: var(--ink); border-bottom-color: var(--accent); }
.pager { display: flex; gap: 24px; margin: 16px 0 0; font-size: 13.5px; }
.table-scroll { margin-top: 4px; overflow-x: auto; }
/* 窄屏上宁可横向滚动，也不要把「用户名」「状态」压成两行。 */
.table-scroll table { min-width: 980px; }
table { width: 100%; border-collapse: collapse; font-size: 14px; font-variant-numeric: tabular-nums; }
th, td { padding: 10px 12px 10px 0; text-align: left; vertical-align: top; border-bottom: 1px solid var(--rule); }
th { font-size: 12.5px; font-weight: 500; color: var(--muted); white-space: nowrap; }
th:last-child, td:last-child { padding-right: 0; }
td:first-child { white-space: nowrap; }
/* 操作格给足宽度：否则它会把每行撑成四五行高（窄屏横向滚动本来就要滚）。 */
td:last-child { min-width: 22rem; }
.num { white-space: nowrap; font-variant-numeric: tabular-nums; }
tbody tr:hover { background: var(--surface); }
.actions { display: flex; flex-wrap: wrap; align-items: center; gap: 6px 10px; }
.actions form { display: inline-flex; align-items: center; gap: 4px; margin: 0; }
.actions select, .actions input[type="password"] {
  padding: 4px 6px;
  font: inherit;
  font-size: 13px;
  color: var(--ink);
  background: var(--bg);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
}
.actions input[type="password"] { width: 9rem; }
.actions .btn { min-height: 28px; }
.inline { display: inline-flex; align-items: center; gap: 4px; font-size: 12px; color: var(--muted); }
input[type="checkbox"] { width: 14px; height: 14px; accent-color: var(--accent); }
.btn {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  min-height: 34px;
  padding: 0 14px;
  font: inherit;
  font-size: 13.5px;
  font-weight: 500;
  color: var(--accent-ink);
  background: var(--accent);
  border: 1px solid var(--accent);
  border-radius: var(--radius);
  cursor: pointer;
  transition: transform 120ms ease, background-color 120ms ease, border-color 120ms ease;
}
.btn:hover { transform: translateY(-1px); }
.btn:active { transform: translateY(0); }
.btn-quiet { color: var(--ink); background: transparent; border-color: var(--rule); }
.btn-quiet:hover { color: var(--accent); border-color: var(--accent); }
.btn-danger { color: #ffffff; background: var(--danger); border-color: var(--danger); }
.btn-small { min-height: 28px; padding: 0 10px; font-size: 12.5px; }
.btn-wide { width: 100%; min-height: 40px; }
.form { display: grid; gap: 16px; margin: 20px 0 0; }
.field { display: grid; gap: 6px; }
.field span { font-size: 13px; color: var(--muted); }
.form input:not([type="hidden"]) {
  width: 100%;
  padding: 9px 12px;
  font: inherit;
  font-size: 15px;
  color: var(--ink);
  background: var(--bg);
  border: 1px solid var(--rule);
  border-radius: var(--radius);
}
.form input:not([type="hidden"]):focus { border-color: var(--accent); }
.alert {
  margin: 16px 0 0;
  padding: 10px 0 10px 12px;
  font-size: 14px;
  color: var(--danger);
  border-left: 2px solid var(--danger);
}
.gate {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(320px, 420px);
  gap: 64px;
  align-items: start;
  padding: 48px 0 40px;
}
.gate-brand { min-width: 0; padding-top: 20px; border-top: 1px solid var(--ink); }
.gate-brand .brand-mark { margin-bottom: 20px; }
.gate-lede { margin: 0; max-width: 26em; font-size: 19px; font-weight: 600; line-height: 1.45; letter-spacing: -0.01em; }
.facts { display: grid; gap: 16px; margin: 28px 0 0; padding: 0; list-style: none; }
.facts li { display: grid; gap: 2px; padding-top: 12px; border-top: 1px solid var(--rule); }
.fact-k { font-size: 13px; font-weight: 600; }
.fact-v { font-size: 13.5px; color: var(--muted); }
.ticket { min-width: 0; padding-top: 20px; border-top: 1px solid var(--ink); }
.ticket h1 { font-size: 26px; }
.ticket .form { margin-top: 24px; }
@media (max-width: 880px) {
  .gate { grid-template-columns: minmax(0, 1fr); gap: 32px; padding-top: 32px; }
  .gate-lede { max-width: none; }
  /* 单栏时表单不跟着整页拉宽：一张 700px 宽的输入框比两栏更难用。 */
  .ticket { max-width: 30rem; }
}
@media (max-width: 720px) {
  h1 { font-size: 22px; }
  .spine-bar { gap: 4px 12px; }
  .brand-name { font-size: 13px; letter-spacing: 0.06em; }
  .nav { order: 3; width: 100%; gap: 20px; border-top: 1px solid var(--rule); }
  .nav a { min-height: 40px; }
  .chip { gap: 8px; margin-left: auto; }
  .chip-name { font-size: 13px; }
  .badge { font-size: 11px; }
  .state { font-size: 11.5px; }
  .chip .btn-small { min-height: 26px; padding: 0 8px; font-size: 12px; }
  .chip-note { max-width: 100%; }
  .page { padding-top: 24px; }
  .split { grid-template-columns: minmax(0, 1fr); gap: 24px; }
  .stats { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .stat { padding: 12px 12px 12px 0; }
  .stat + .stat { padding-left: 0; border-left: none; }
  .stat:nth-child(2n) { padding-left: 12px; border-left: 1px solid var(--rule); }
  .stat:nth-child(n+3) { border-top: 1px solid var(--rule); }
  th, td { padding: 8px 10px 8px 0; }
  .foot-note { margin-left: 0; }
}
@media (prefers-reduced-motion: reduce) {
  *, *::before, *::after { transition: none !important; animation: none !important; }
  .btn:hover, .btn:active { transform: none; }
}
"#;

#[cfg(test)]
mod tests {
    use super::{CredentialChannel, Nav, authed_page, public_page, status_dot};
    use crate::accounts::UserStatus;
    use crate::config::Role;
    use crate::http::auth::AuthUser;

    fn user(name: &str, role: Role) -> AuthUser {
        AuthUser { username: name.to_owned(), role }
    }

    #[test]
    fn given_session_when_authed_page_then_chip_shows_identity_and_logout() {
        let page = authed_page(
            "我的账户",
            &user("alice", Role::Readwrite),
            UserStatus::Active,
            CredentialChannel::Session,
            Nav::Account,
            "<p>正文</p>",
        );

        assert!(page.contains("alice"), "chip 必须显示用户名");
        assert!(page.contains("读写"), "chip 必须显示角色");
        assert!(page.contains(">正常<"), "chip 必须显示状态");
        assert!(page.contains(r#"aria-current="page""#), "当前导航项要标出来");
        assert!(page.contains(r#"<form method="post" action="/logout""#));
        assert!(page.contains("退出登录"));
        assert!(!page.contains("HTTP Basic"), "会话通道不该出现 Basic 提示");
    }

    #[test]
    fn given_basic_when_authed_page_then_no_logout_form_and_honest_hint() {
        let page = authed_page(
            "我的账户",
            &user("bob", Role::Readonly),
            UserStatus::Pending,
            CredentialChannel::Basic,
            Nav::Account,
            "",
        );

        assert!(!page.contains(r#"action="/logout""#), "Basic 通道不能给无效的退出按钮");
        assert!(page.contains("Basic 凭据由浏览器保存"), "必须说明退出方式");
        assert!(page.contains("清除浏览器"), "必须提示清除站点凭据");
        assert!(page.contains(">待审批<"));
    }

    #[test]
    fn given_role_when_nav_then_admin_link_only_for_admin() {
        let admin = authed_page(
            "账户管理",
            &user("root", Role::Admin),
            UserStatus::Active,
            CredentialChannel::Session,
            Nav::Admin,
            "",
        );
        assert!(admin.contains(r#"<a href="/admin" aria-current="page">管理</a>"#));

        let reader = authed_page(
            "我的账户",
            &user("eve", Role::Readwrite),
            UserStatus::Active,
            CredentialChannel::Session,
            Nav::Account,
            "",
        );
        assert!(!reader.contains(r#"href="/admin""#), "非管理员不该看到管理入口");
    }

    #[test]
    fn given_hostile_username_when_chip_then_escaped() {
        let page = authed_page(
            "我的账户",
            &user("<script>alert(1)</script>", Role::Readwrite),
            UserStatus::Active,
            CredentialChannel::Session,
            Nav::Account,
            "",
        );

        assert!(!page.contains("<script"), "用户名必须转义：{page}");
        assert!(page.contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
    }

    #[test]
    fn given_public_page_when_render_then_no_external_assets() {
        let page = public_page("登录", "自建 Git LFS 网关。", "<p>form</p>");

        assert!(page.starts_with("<!doctype html>"));
        assert!(page.contains(r#"<html lang="zh-CN">"#));
        assert!(page.contains("<title>登录 · netdisk-lfs</title>"));
        assert!(!page.contains("<script"), "页面不得含脚本");
        assert!(!page.contains("<link"), "不得引外部样式表/字体");
        assert!(!page.contains("http://") && !page.contains("https://"), "不得含外链");
        assert!(page.contains(r#"href="/healthz""#) && page.contains(r#"href="/metrics""#));
        // 断点、焦点环与降级动效都在同一份样式里，换页面不会漏。
        assert!(page.contains(":focus-visible"));
        assert!(page.contains("max-width: 720px"));
        assert!(page.contains("prefers-reduced-motion: reduce"));
        assert!(page.contains("--bg: #dfdedb") && page.contains("--accent: #2456d6"));
    }

    #[test]
    fn given_subtitle_when_escaped_then_no_markup_leaks() {
        let page = public_page("登录", "<b>x</b>", "");

        assert!(page.contains("&lt;b&gt;x&lt;/b&gt;"));
        assert!(!page.contains("<b>x</b>"));
    }

    #[test]
    fn given_status_when_dot_then_maps_to_status_colour() {
        assert_eq!(status_dot(UserStatus::Active), "dot-ok");
        assert_eq!(status_dot(UserStatus::Pending), "dot-warn");
        assert_eq!(status_dot(UserStatus::Disabled), "dot-danger");
    }
}

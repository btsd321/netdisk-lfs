//! 进程内会话存储与会话 Cookie 助手。
//!
//! **为什么放内存**：本服务是单实例自托管，会话数以「人」计（每用户上限 10 个），
//! 进程内 `HashMap` 足够；落库会带来 schema 迁移与每次请求一次写事务，而重启后
//! 重新登录的代价可以接受（服务端重启本来就意味着一次部署）。代价是重启丢会话，
//! 这写进文档，需要持久会话时再上签名 Cookie。
//!
//! **会话 id**：32 字节系统随机数的 base64url（无填充）编码，客户端猜不到，也不
//! 携带任何用户信息。随机源取自 `getrandom`（`argon2` 的 `password-hash` 只把
//! `rand_core` 作为可选 re-export，本项目的 feature 组合下拿不到，因此直接依赖
//! 同一个已在用的 crate；理由见 `.agents/decisions/0008-session-random.md`）。
//!
//! **过期策略**：空闲 12 小时、绝对 7 天。每用户最多 10 个会话、全库最多 4096 个，
//! 超限时淘汰最久未活动的那个——同一个人的多设备登录只挤掉最旧的那台，不会把刚
//! 登录的会话踢掉。
//!
//! **Cookie**：`HttpOnly` + `SameSite=Lax`，仅在 HTTPS 请求上追加 `Secure`（本机
//! 明文调试不该因为多一个 `Secure` 而完全无法登录）。Cookie 只是 id 的载体，
//! 权限判定永远发生在服务端。

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{Duration, Instant};

use axum::http::HeaderMap;
use axum::http::header::COOKIE;
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;

use crate::config::{Config, Role};

/// 空闲过期：`last_seen` 超过它没被刷新即失效。
pub(crate) const IDLE_TIMEOUT: Duration = Duration::from_secs(12 * 60 * 60);

/// 绝对过期：从建立会话起算，无论多活跃都失效。
pub(crate) const ABSOLUTE_TTL: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// 每用户会话上限。
pub(crate) const MAX_SESSIONS_PER_USER: usize = 10;

/// 全库会话上限；也是内存占用的上界（单条会话约 100 字节量级）。
pub(crate) const MAX_SESSIONS: usize = 4096;

/// 会话 id 的随机字节数。
const SESSION_ID_BYTES: usize = 32;

/// 会话 Cookie 名；会话 id 与 CSRF 守卫都按这个名字认。
pub const SESSION_COOKIE_NAME: &str = "netdisk_lfs_session";

/// 会话 id：32 字节随机数的 base64url（无填充）编码。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SessionId(String);

impl SessionId {
    /// 生成一个新的会话 id；系统随机源不可用时返回 `None`。
    ///
    /// 随机源故障时**不**退回时间戳/计数器之类的可猜值：宁可建立不了会话（端点
    /// 回 500），也不能发一个能被预测的凭据。
    fn generate() -> Option<Self> {
        let mut bytes = [0_u8; SESSION_ID_BYTES];
        if let Err(error) = getrandom::fill(&mut bytes) {
            tracing::error!(error = %error, "生成会话 id 失败：系统随机源不可用");
            return None;
        }
        Some(Self(URL_SAFE_NO_PAD.encode(bytes)))
    }

    /// 解析并校验会话 id：必须是 32 字节随机数的**规范** base64url 编码。
    ///
    /// 校验长度与规范编码，非法值直接当「没有会话」处理：这样伪造的 Cookie 不会
    /// 在哈希表里制造无意义的长键，也让「值一定来自本服务」成为可依赖的前提。
    pub(crate) fn parse(raw: &str) -> Option<Self> {
        let decoded = URL_SAFE_NO_PAD.decode(raw.as_bytes()).ok()?;
        if decoded.len() != SESSION_ID_BYTES || URL_SAFE_NO_PAD.encode(&decoded) != raw {
            return None;
        }
        Some(Self(raw.to_owned()))
    }

    /// 字符串形式；可直接放进 Cookie 值。
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// 一个已认证的浏览器会话。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Session {
    /// 用户名；账户库用户取库里的写法，config 用户取配置里的写法。
    pub username: String,
    /// 建立会话时的角色；每次请求实际使用的角色以账户库/配置的当前值为准。
    pub role: Role,
    /// 建立时间（单调时钟，不随系统时间调整而跳变）。
    pub created_at: Instant,
    /// 最后一次被使用的时间（单调时钟）；[`SessionStore::get`] 会滑动它。
    pub last_seen: Instant,
}

/// 进程内会话表；`AppState` 用 `Arc` 共享同一个实例。
#[derive(Debug)]
#[non_exhaustive]
pub struct SessionStore {
    sessions: Mutex<HashMap<SessionId, Session>>,
    /// 全库上限；生产固定 [`MAX_SESSIONS`]，测试用它调小以免真的造 4096 条。
    max_total: usize,
    /// 每用户上限；同上。
    max_per_user: usize,
}

impl SessionStore {
    /// 空的会话表，使用默认上限。
    pub fn new() -> Self {
        Self::with_limits(MAX_SESSIONS, MAX_SESSIONS_PER_USER)
    }

    /// 用指定上限构造；生产走 [`Self::new`]，单测用它把上限调小。
    fn with_limits(max_total: usize, max_per_user: usize) -> Self {
        Self { sessions: Mutex::new(HashMap::new()), max_total, max_per_user }
    }

    /// 建立会话并返回其 id；系统随机源不可用时返回 `None`（调用方应回 500）。
    ///
    /// 顺带做三件事：清理已过期会话、把该用户会话数压到上限以下、把全库会话数
    /// 压到上限以下。淘汰按「最久未活动」排序，同一个人的其他设备只被挤掉最旧的。
    pub fn create(&self, username: &str, role: Role) -> Option<SessionId> {
        self.create_at(username, role, Instant::now())
    }

    /// [`Self::create`] 的可注入时间版本；单测用它构造「已经放了很久」的会话。
    fn create_at(&self, username: &str, role: Role, now: Instant) -> Option<SessionId> {
        // 先生成 id：随机源故障时直接失败，不改动任何已有会话。
        let id = SessionId::generate()?;
        let mut sessions = self.lock();
        purge_expired(&mut sessions, now);

        // 先腾位置再插入：`>=` 保证插入后不会超过上限。
        while count_for_user(&sessions, username) >= self.max_per_user {
            if !evict_least_active(&mut sessions, |session| {
                session.username.eq_ignore_ascii_case(username)
            }) {
                break;
            }
        }
        while sessions.len() >= self.max_total {
            if !evict_least_active(&mut sessions, |_| true) {
                break;
            }
        }

        sessions.insert(
            id.clone(),
            Session { username: username.to_owned(), role, created_at: now, last_seen: now },
        );
        Some(id)
    }

    /// 取出会话并刷新 `last_seen`；不存在、空闲过期或绝对过期都返回 `None`。
    ///
    /// 过期的会话顺手删除：读路径是唯一能确定「这条已经没用」的地方，不需要额外
    /// 的后台清理任务。
    pub fn get(&self, id: &SessionId) -> Option<Session> {
        self.get_at(id, Instant::now())
    }

    /// [`Self::get`] 的可注入时间版本。
    fn get_at(&self, id: &SessionId, now: Instant) -> Option<Session> {
        let mut sessions = self.lock();
        let expired = {
            let session = sessions.get(id)?;
            is_expired(session, now)
        };
        if expired {
            sessions.remove(id);
            tracing::debug!("清理已过期会话");
            return None;
        }
        let session = sessions.get_mut(id)?;
        session.last_seen = now;
        Some(session.clone())
    }

    /// 撤销单个会话；不存在时什么也不做。
    pub fn revoke(&self, id: &SessionId) {
        let mut sessions = self.lock();
        if sessions.remove(id).is_some() {
            tracing::debug!("撤销会话");
        }
    }

    /// 撤销某个用户的全部会话，返回撤销数量（大小写不敏感）。
    ///
    /// 改口令、禁用、删除账户、角色变更都调它：凭据或权限一变，旧会话就不能再代表
    /// 这个人。返回数量进日志，运维能对账「踢掉了几台设备」。
    pub fn revoke_user(&self, username: &str) -> usize {
        let mut sessions = self.lock();
        let before = sessions.len();
        sessions.retain(|_, session| !session.username.eq_ignore_ascii_case(username));
        let removed = before - sessions.len();
        if removed > 0 {
            tracing::info!(username = %username, removed, "撤销用户的全部会话");
        }
        removed
    }

    /// 当前会话数；只给测试与运维观测用。
    pub fn len(&self) -> usize {
        self.lock().len()
    }

    /// 会话表是否为空；与 [`Self::len`] 配对。
    pub fn is_empty(&self) -> bool {
        self.lock().is_empty()
    }

    /// 取锁；持锁代码不会 panic，若真被毒化则取回内部数据继续用——
    /// 会话表丢状态会让所有浏览器掉线，比直接 panic 更糟（与 `limits` 同一取舍）。
    fn lock(&self) -> std::sync::MutexGuard<'_, HashMap<SessionId, Session>> {
        self.sessions.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new()
    }
}

/// 会话是否已失效：空闲超时或总年龄超限。
fn is_expired(session: &Session, now: Instant) -> bool {
    let idle = now.saturating_duration_since(session.last_seen);
    let age = now.saturating_duration_since(session.created_at);
    idle >= IDLE_TIMEOUT || age >= ABSOLUTE_TTL
}

/// 该用户名名下的会话数（大小写不敏感）。
fn count_for_user(sessions: &HashMap<SessionId, Session>, username: &str) -> usize {
    sessions.values().filter(|session| session.username.eq_ignore_ascii_case(username)).count()
}

/// 删除满足 `matches` 的会话里最久没有活动的那一个；没有可删的返回 `false`。
///
/// 排序键 `(last_seen, created_at)`：同一时刻建立的一批会话再按建立时间兜底，
/// 保证淘汰顺序稳定、可测。
fn evict_least_active(
    sessions: &mut HashMap<SessionId, Session>,
    matches: impl Fn(&Session) -> bool,
) -> bool {
    let victim = sessions
        .iter()
        .filter(|(_, session)| matches(session))
        .min_by_key(|(_, session)| (session.last_seen, session.created_at))
        .map(|(id, _)| id.clone());
    match victim {
        Some(id) => sessions.remove(&id).is_some(),
        None => false,
    }
}

/// 清理已过期会话。
fn purge_expired(sessions: &mut HashMap<SessionId, Session>, now: Instant) {
    let before = sessions.len();
    sessions.retain(|_, session| !is_expired(session, now));
    let removed = before - sessions.len();
    if removed > 0 {
        tracing::debug!(removed, "清理过期会话");
    }
}

/// 会话 Cookie 的解析结果。
///
/// 区分「没带」与「带了但畸形」是为了**能清掉坏的 Cookie**：浏览器会一直重发同一个
/// 值，只有下发一次 `Max-Age=0` 才能让它停下；压根没带 Cookie 的请求则不该凭空收到
/// 一条 `Set-Cookie`。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum SessionCookieState {
    /// 请求没有会话 Cookie。
    Missing,
    /// 带了会话 Cookie，但值不是合法的会话 id（含无法按 UTF-8 解析的 Cookie 头）。
    Malformed,
    /// 解析出合法的会话 id；是否仍然有效要再查会话表。
    Present(SessionId),
}

/// 解析请求里的会话 Cookie。
///
/// 支持多条 `Cookie` 头（HTTP/2 允许）与 `a=1; b=2` 形式；同名 cookie 取**第一个**。
///
/// 注意 RFC 6265 并不保证同名 cookie 的先后顺序，所以「取第一个」只是尽力而为，
/// 不构成任何安全保证：一旦取到的值畸形、或真正的会话 cookie 被另一个同名值挡住，
/// 一律 fail-closed（[`SessionCookieState::Malformed`] → 401 并清除 Cookie），
/// 不去猜第二个值，也不把失败伪装成「没带 Cookie」。
pub fn parse_session_cookie(headers: &HeaderMap) -> SessionCookieState {
    if let Some(value) = header_cookie_value(headers, SESSION_COOKIE_NAME) {
        return match SessionId::parse(value) {
            Some(id) => SessionCookieState::Present(id),
            None => SessionCookieState::Malformed,
        };
    }
    if cookie_header_mentions(headers, SESSION_COOKIE_NAME) {
        // Cookie 头不是合法 UTF-8，取不出值，但确实提到了会话名：仍按畸形处理，
        // 让它被清掉，而不是每个请求都带着重试、永远 401。
        return SessionCookieState::Malformed;
    }
    SessionCookieState::Missing
}

/// 请求是否带会话 Cookie（**不**校验值，畸形也算带）。
///
/// CSRF 守卫用它判断「浏览器会不会自动附带凭据」：值是否有效是认证层的事，跨站写
/// 请求在认证之前就该被挡住，所以这里只看有没有这个名字的 cookie。
pub fn has_session_cookie(headers: &HeaderMap) -> bool {
    header_cookie_value(headers, SESSION_COOKIE_NAME).is_some()
        || cookie_header_mentions(headers, SESSION_COOKIE_NAME)
}

/// 在所有 `Cookie` 头里找同名 cookie 的值（名字大小写不敏感，取第一个）。
///
/// 返回借用而不是 `String`：调用方只需要读一眼，每请求多一次堆分配没有意义。
fn header_cookie_value<'a>(headers: &'a HeaderMap, name: &str) -> Option<&'a str> {
    headers
        .get_all(COOKIE)
        .iter()
        .find_map(|value| value.to_str().ok().and_then(|raw| first_cookie(raw, name)))
}

/// 在一条 `Cookie` 头里找同名 cookie 的值。
fn first_cookie<'a>(raw: &'a str, name: &str) -> Option<&'a str> {
    raw.split(';').find_map(|pair| {
        let (key, value) = pair.split_once('=')?;
        if !key.trim().eq_ignore_ascii_case(name) {
            return None;
        }
        let value = value.trim();
        // RFC 6265 允许 cookie-value 用双引号包裹；去掉引号再解析。
        Some(value.strip_prefix('"').and_then(|rest| rest.strip_suffix('"')).unwrap_or(value))
    })
}

/// `Cookie` 头不是合法 UTF-8 时，退一步在原始字节里找会话名。
///
/// 只用于「要不要把它清掉」的判定：命中即按畸形 Cookie 处理，取不出值也不去猜。
fn cookie_header_mentions(headers: &HeaderMap, name: &str) -> bool {
    let needle = name.as_bytes();
    headers.get_all(COOKIE).iter().any(|value| {
        value.to_str().is_err()
            && value
                .as_bytes()
                .windows(needle.len())
                .any(|window| window.eq_ignore_ascii_case(needle))
    })
}

/// 构造设置会话 Cookie 的 `Set-Cookie` 值（不含 `Secure`；HTTPS 场景用
/// [`secure_cookie`]）。
pub fn session_cookie(id: &SessionId) -> String {
    cookie_header(id.as_str(), ABSOLUTE_TTL.as_secs(), false)
}

/// 同 [`session_cookie`]，按请求是否 HTTPS 决定是否追加 `Secure`。
///
/// `Max-Age` 取绝对 TTL：浏览器侧与服务端的硬上限一致，空闲过期仍由服务端判定
/// （会话表是唯一真相源，客户端的 Cookie 只是 id 的载体）。
pub fn secure_cookie(id: &SessionId, secure: bool) -> String {
    cookie_header(id.as_str(), ABSOLUTE_TTL.as_secs(), secure)
}

/// 构造清除会话 Cookie 的 `Set-Cookie` 值（空值 + `Max-Age=0`）。
pub fn clear_session_cookie() -> String {
    cookie_header("", 0, false)
}

/// 清除会话 Cookie 并保留 `Secure`：HTTPS 站点上不带 `Secure` 的同名 cookie
/// 覆盖不掉原来那条，浏览器会继续把旧 id 发上来。
pub fn secure_clear_cookie(secure: bool) -> String {
    cookie_header("", 0, secure)
}

/// Cookie 的公共拼装：属性顺序固定，测试与浏览器都不依赖顺序但人要能一眼读完。
fn cookie_header(value: &str, max_age_secs: u64, secure: bool) -> String {
    let mut cookie = format!(
        "{SESSION_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Lax; Max-Age={max_age_secs}"
    );
    if secure {
        cookie.push_str("; Secure");
    }
    cookie
}

/// 本次请求是否经 HTTPS 到达。
///
/// 判定只看两处，且**不**无条件相信转发头：
///
/// - `X-Forwarded-Proto: https`（大小写不敏感，多级代理的逗号列表取第一个）：只有
///   `[accounts] trust_proxy = true` 时才接受。这个头客户端可以随便伪造，不信任
///   代理时采信它，等于让任何人决定服务端要不要下发 `Secure` Cookie；与
///   `register::client_key` 对 `X-Forwarded-For` 的策略保持一致；
/// - 否则看配置的 `public_base` 是否以 `https://` 开头：这是运维写死的对外地址，
///   客户端改不了。
///
/// 两者都没有 HTTPS 信息时按 http 处理——`Secure` Cookie 在明文连接上根本存不住。
pub fn request_is_https(headers: &HeaderMap, config: &Config) -> bool {
    if config.accounts.trust_proxy && forwarded_proto_is_https(headers) {
        return true;
    }
    config.server.public_base.trim().to_ascii_lowercase().starts_with("https://")
}

/// `X-Forwarded-Proto` 的第一个值是不是 https。
fn forwarded_proto_is_https(headers: &HeaderMap) -> bool {
    headers
        .get("x-forwarded-proto")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.split(',').next())
        .is_some_and(|value| value.trim().eq_ignore_ascii_case("https"))
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};
    use std::time::{Duration, Instant};

    use super::{
        ABSOLUTE_TTL, IDLE_TIMEOUT, MAX_SESSIONS, MAX_SESSIONS_PER_USER, SESSION_COOKIE_NAME,
        SessionCookieState, SessionId, SessionStore, clear_session_cookie, has_session_cookie,
        parse_session_cookie, request_is_https, secure_clear_cookie, secure_cookie, session_cookie,
    };
    use crate::config::Role;
    use crate::config::{
        AccountsConfig, AuthConfig, CacheConfig, Config, RuntimeEnv, ServerConfig, StorageConfig,
    };

    fn test_config(public_base: &str, trust_proxy: bool) -> Config {
        Config {
            server: ServerConfig {
                listen: "127.0.0.1:9001".parse().expect("合法监听地址"),
                public_base: public_base.to_owned(),
            },
            storage: StorageConfig {
                objects_root: "/apps/bdpan/lfs".to_owned(),
                tmp_root: "/apps/bdpan/lfs/tmp".to_owned(),
                bdpan_bin: "/bin/true".into(),
                max_object_bytes: 1024,
                max_bdpan_procs: 1,
                bdpan_timeout_secs: 300,
                bdpan_min_throughput_bytes_per_sec: 102_400,
            },
            cache: CacheConfig { dir: std::env::temp_dir(), max_bytes: 0 },
            accounts: AccountsConfig {
                db: std::env::temp_dir().join("netdisk-lfs-session-tests.db"),
                trust_proxy,
                ..AccountsConfig::default()
            },
            auth: AuthConfig::default(),
            runtime_env: RuntimeEnv::Dev,
            data_dir: None,
        }
    }

    /// 解析结果里的会话 id；只关心「解析成功」的用例用它，避免到处写 match。
    fn cookie_id(state: &SessionCookieState) -> Option<&SessionId> {
        match state {
            SessionCookieState::Present(id) => Some(id),
            _ => None,
        }
    }

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.append(
                HeaderName::from_bytes(name.as_bytes()).expect("头名合法"),
                HeaderValue::from_str(value).expect("头值合法"),
            );
        }
        map
    }

    #[test]
    fn given_session_when_created_then_id_is_random_base64url_and_unique() {
        let store = SessionStore::new();
        let first = store.create("alice", Role::Readwrite).expect("应能建立会话");
        let second = store.create("alice", Role::Readwrite).expect("应能建立会话");

        // 32 字节 base64url 无填充 = 43 个字符。
        assert_eq!(first.as_str().len(), 43);
        assert_ne!(first, second, "每次登录都必须是新 id，天然防 session fixation");
        assert_eq!(store.len(), 2);
        assert!(!store.is_empty());
    }

    #[test]
    fn given_session_when_get_then_slides_last_seen() {
        let store = SessionStore::new();
        let now = Instant::now();
        let id = store.create_at("alice", Role::Readwrite, now).expect("应能建立会话");

        let used = now + Duration::from_secs(60);
        let session = store.get_at(&id, used).expect("未过期应可用");
        assert_eq!(session.username, "alice");
        assert_eq!(session.role, Role::Readwrite);
        assert_eq!(session.created_at, now);
        assert_eq!(session.last_seen, used, "读取即滑动空闲计时");

        // 空闲计时从最后一次使用算起：再过 IDLE-1s 仍然有效。
        assert!(store.get_at(&id, used + IDLE_TIMEOUT - Duration::from_secs(1)).is_some());
    }

    #[test]
    fn given_idle_session_when_get_then_expired_and_removed() {
        let store = SessionStore::new();
        let now = Instant::now();
        let id = store.create_at("alice", Role::Readwrite, now).expect("应能建立会话");

        assert!(store.get_at(&id, now + IDLE_TIMEOUT).is_none(), "空闲到 12 小时即失效");
        assert_eq!(store.len(), 0, "过期会话应在读路径上被清掉");
    }

    #[test]
    fn given_session_older_than_absolute_ttl_when_get_then_expired_even_if_recently_used() {
        let store = SessionStore::new();
        let created = Instant::now();
        let id = store.create_at("alice", Role::Readwrite, created).expect("应能建立会话");

        // 每 6 小时用一次，连用 6 天 23 小时：空闲计时一直被刷新，会话始终有效。
        let step = Duration::from_secs(6 * 60 * 60);
        let mut now = created;
        while now + step < created + ABSOLUTE_TTL {
            now += step;
            assert!(store.get_at(&id, now).is_some(), "持续活跃的会话不应因空闲过期");
        }
        assert!(now + step >= created + ABSOLUTE_TTL, "应已接近绝对过期");

        // 再往后 1 小时：空闲只有 6 小时，但总年龄超过 7 天 → 绝对过期。
        let expired = created + ABSOLUTE_TTL + Duration::from_secs(3_600);
        assert!(store.get_at(&id, expired).is_none(), "绝对过期优先于空闲判断");
        assert_eq!(store.len(), 0);
    }

    #[test]
    fn given_more_sessions_than_per_user_cap_when_create_then_evicts_least_active() {
        let store = SessionStore::with_limits(MAX_SESSIONS, 3);
        let now = Instant::now();
        let first = store.create_at("alice", Role::Readwrite, now).expect("应能建立会话");
        let second =
            store.create_at("alice", Role::Readwrite, now + Duration::from_secs(1)).expect("会话");
        let third =
            store.create_at("alice", Role::Readwrite, now + Duration::from_secs(2)).expect("会话");
        // 别的用户的会话不该被这个上限波及。
        let other = store.create_at("bob", Role::Readonly, now).expect("应能建立会话");

        let fourth =
            store.create_at("alice", Role::Readwrite, now + Duration::from_secs(3)).expect("会话");

        assert_eq!(store.len(), 4, "alice 3 个 + bob 1 个");
        assert!(store.get_at(&first, now + Duration::from_secs(3)).is_none(), "最久未活动的被淘汰");
        for id in [&second, &third, &fourth] {
            assert!(store.get_at(id, now + Duration::from_secs(3)).is_some(), "较新的会话应保留");
        }
        assert!(store.get_at(&other, now + Duration::from_secs(3)).is_some());
    }

    #[test]
    fn given_more_sessions_than_total_cap_when_create_then_oldest_evicted() {
        let store = SessionStore::with_limits(3, MAX_SESSIONS_PER_USER);
        let now = Instant::now();
        let first = store.create_at("alice", Role::Readwrite, now).expect("应能建立会话");
        store.create_at("bob", Role::Readwrite, now + Duration::from_secs(1)).expect("会话");
        store.create_at("carol", Role::Readwrite, now + Duration::from_secs(2)).expect("会话");

        let newest = store.create_at("dave", Role::Readwrite, now + Duration::from_secs(3));

        assert_eq!(store.len(), 3, "全库上限 3");
        assert!(store.get_at(&first, now + Duration::from_secs(3)).is_none(), "最久未活动的被淘汰");
        assert!(newest.is_some());
    }

    #[test]
    fn given_sessions_of_one_user_when_purge_expired_then_only_that_user_affected() {
        let store = SessionStore::new();
        let now = Instant::now();
        let stale = store.create_at("alice", Role::Readwrite, now).expect("应能建立会话");
        let fresh = store
            .create_at("bob", Role::Readwrite, now + IDLE_TIMEOUT - Duration::from_secs(1))
            .expect("会话");

        // 新建会话触发顺带清理：alice 的那条已空闲超时，bob 的还在窗口内。
        store.create_at("carol", Role::Readwrite, now + IDLE_TIMEOUT).expect("会话");

        assert!(store.get_at(&stale, now + IDLE_TIMEOUT).is_none());
        assert!(store.get_at(&fresh, now + IDLE_TIMEOUT).is_some());
    }

    #[test]
    fn given_id_when_revoke_then_gone_and_repeated_revoke_is_noop() {
        let store = SessionStore::new();
        let id = store.create("alice", Role::Readwrite).expect("应能建立会话");

        store.revoke(&id);
        assert!(store.get(&id).is_none());
        assert_eq!(store.len(), 0);

        store.revoke(&id);
        assert_eq!(store.len(), 0, "撤销不存在的会话不应 panic");
    }

    #[test]
    fn given_user_sessions_when_revoke_user_then_only_that_user_and_count_reported() {
        let store = SessionStore::new();
        let alice_first = store.create("alice", Role::Readwrite).expect("应能建立会话");
        let alice_second = store.create("alice", Role::Readonly).expect("应能建立会话");
        let bob = store.create("Bob", Role::Admin).expect("应能建立会话");

        assert_eq!(store.revoke_user("ALICE"), 2, "大小写不敏感");
        assert!(store.get(&alice_first).is_none());
        assert!(store.get(&alice_second).is_none());
        assert!(store.get(&bob).is_some(), "别的用户的会话不受影响");
        assert_eq!(store.revoke_user("alice"), 0, "没有会话时返回 0");
    }

    #[test]
    fn given_cookie_header_when_parse_then_finds_session_and_ignores_noise() {
        let store = SessionStore::new();
        let id = store.create("alice", Role::Readwrite).expect("应能建立会话");
        let value = id.as_str();

        // 多个 cookie、空格、名字大小写都不影响识别。
        let map = headers(&[(
            "cookie",
            &format!("theme=dark;  NETDISK_LFS_SESSION = {value} ; lang=zh"),
        )]);
        assert_eq!(cookie_id(&parse_session_cookie(&map)), Some(&id));
        assert!(has_session_cookie(&map));

        // 多条 Cookie 头（HTTP/2 允许）逐条找。
        let mut multi = HeaderMap::new();
        multi.append(HeaderName::from_static("cookie"), HeaderValue::from_static("a=1"));
        multi.append(
            HeaderName::from_static("cookie"),
            HeaderValue::from_str(&format!("{SESSION_COOKIE_NAME}={value}")).expect("合法头值"),
        );
        assert_eq!(cookie_id(&parse_session_cookie(&multi)), Some(&id));

        // 双引号包裹的合法值可以解析。
        let map = headers(&[("cookie", &format!("{SESSION_COOKIE_NAME}=\"{value}\""))]);
        assert_eq!(cookie_id(&parse_session_cookie(&map)), Some(&id));
    }

    #[test]
    fn given_no_session_cookie_when_parse_then_missing_not_malformed() {
        // 完全没有 Cookie 头。
        assert_eq!(parse_session_cookie(&HeaderMap::new()), SessionCookieState::Missing);
        assert!(!has_session_cookie(&HeaderMap::new()));

        // 只有别的 cookie：同样算「没带会话」，不该因此清 Cookie。
        let map = headers(&[("cookie", "session=deadbeef; theme=dark")]);
        assert_eq!(parse_session_cookie(&map), SessionCookieState::Missing);
        assert!(!has_session_cookie(&map));
    }

    #[test]
    fn given_malformed_cookie_when_parse_then_malformed_so_it_gets_cleared() {
        let store = SessionStore::new();
        let id = store.create("alice", Role::Readwrite).expect("应能建立会话");
        let value = id.as_str();

        // 非法值：太短、空、非 base64url、长度对但尾部有多余位（非规范编码）。
        let noncanonical = format!("{}B", "A".repeat(42));
        for bad in ["abc", "", "!!!", noncanonical.as_str(), &"A".repeat(44)] {
            let map = headers(&[("cookie", &format!("{SESSION_COOKIE_NAME}={bad}"))]);
            assert_eq!(
                parse_session_cookie(&map),
                SessionCookieState::Malformed,
                "非法值 {bad:?} 必须按畸形处理（否则永远清不掉）"
            );
            assert!(has_session_cookie(&map), "CSRF 守卫仍认为请求带了会话 cookie");
        }

        // 同名 cookie 取第一个（RFC 6265 不保证顺序，这里只是尽力而为）：
        // 取到的那个坏了就 fail-closed，不去猜后面那个可能是真的值。
        let map = headers(&[(
            "cookie",
            &format!("{SESSION_COOKIE_NAME}=bad; {SESSION_COOKIE_NAME}={value}"),
        )]);
        assert_eq!(parse_session_cookie(&map), SessionCookieState::Malformed);

        // Cookie 头不是合法 UTF-8 但提到了会话名：也按畸形处理，让它被清掉。
        let mut opaque = HeaderMap::new();
        opaque.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_bytes(format!("{SESSION_COOKIE_NAME}=v\u{00ff}").as_bytes())
                .expect("obs-text 头值合法"),
        );
        assert_eq!(parse_session_cookie(&opaque), SessionCookieState::Malformed);
        assert!(has_session_cookie(&opaque));

        // 不透明 Cookie 头里没有会话名：与「没带」等价。
        let mut unrelated = HeaderMap::new();
        unrelated.insert(
            HeaderName::from_static("cookie"),
            HeaderValue::from_bytes("theme=v\u{00ff}".as_bytes()).expect("obs-text 头值合法"),
        );
        assert_eq!(parse_session_cookie(&unrelated), SessionCookieState::Missing);
        assert!(!has_session_cookie(&unrelated));
    }

    #[test]
    fn given_session_cookie_when_serialize_then_attributes_and_max_age() {
        let store = SessionStore::new();
        let id = store.create("alice", Role::Readwrite).expect("应能建立会话");

        assert_eq!(
            session_cookie(&id),
            format!(
                "netdisk_lfs_session={}; Path=/; HttpOnly; SameSite=Lax; Max-Age=604800",
                id.as_str()
            )
        );
        assert_eq!(session_cookie(&id), secure_cookie(&id, false), "secure=false 不加 Secure");
        assert!(secure_cookie(&id, true).ends_with("; Secure"));
        assert_eq!(
            clear_session_cookie(),
            "netdisk_lfs_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0"
        );
        assert_eq!(
            secure_clear_cookie(true),
            "netdisk_lfs_session=; Path=/; HttpOnly; SameSite=Lax; Max-Age=0; Secure"
        );
        assert!(!secure_clear_cookie(false).contains("Secure"));
    }

    #[test]
    fn given_untrusted_proxy_when_request_is_https_then_forwarded_proto_ignored() {
        // 不信任代理时，客户端伪造的 XFP 不能把明文请求变成「HTTPS」。
        assert!(!request_is_https(
            &headers(&[("x-forwarded-proto", "https")]),
            &test_config("", false)
        ));
        assert!(!request_is_https(
            &headers(&[("x-forwarded-proto", "HTTPS, http")]),
            &test_config("http://lfs.example.com", false)
        ));
        // 此时只有运维写死的 public_base 能证明是 HTTPS。
        assert!(request_is_https(
            &HeaderMap::new(),
            &test_config("https://lfs.example.com", false)
        ));
    }

    #[test]
    fn given_trusted_proxy_when_request_is_https_then_forwarded_proto_accepted() {
        assert!(request_is_https(
            &headers(&[("x-forwarded-proto", "https")]),
            &test_config("", true)
        ));
        // scheme 大小写不敏感；多级代理的逗号列表取第一个值。
        assert!(request_is_https(
            &headers(&[("x-forwarded-proto", "HTTPS, http")]),
            &test_config("", true)
        ));
        assert!(!request_is_https(
            &headers(&[("x-forwarded-proto", "http")]),
            &test_config("", true)
        ));
        assert!(!request_is_https(
            &headers(&[("x-forwarded-proto", "gopher")]),
            &test_config("", true)
        ));
    }

    #[test]
    fn given_public_base_when_request_is_https_then_scheme_decides() {
        assert!(request_is_https(&HeaderMap::new(), &test_config("https://lfs.example.com", true)));
        assert!(request_is_https(
            &HeaderMap::new(),
            &test_config(" HTTPS://lfs.example.com/", true)
        ));
        assert!(!request_is_https(&HeaderMap::new(), &test_config("http://lfs.example.com", true)));
        assert!(!request_is_https(&HeaderMap::new(), &test_config("", true)));
    }
}

//! 账户库：SQLite schema、用户名校验与 CRUD。
//!
//! **异步边界**：rusqlite 是阻塞 API。内部用 `Arc<std::sync::Mutex<Connection>>`
//! 串行化同一进程内的访问，所有语句都在 [`tokio::task::spawn_blocking`] 里执行；
//! 持锁期间不做 `.await`（见 `docs/rust-style.md` 第 8 节）。`open` 只在启动期
//! 调用，保持同步签名，直接做建目录与建表。
//!
//! **用户名规则**：3–32 个字符，仅 `[A-Za-z0-9._-]`，不含 `:`（Basic Auth 的
//! `user:password` 拆分有歧义）。规则在创建与查询入口统一校验，避免「写得进、
//! 查不到」的脏数据。

use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{SystemTime, UNIX_EPOCH};

use rusqlite::{Connection, OptionalExtension, Row, TransactionBehavior, params};
use serde::{Deserialize, Serialize};

use super::AccountError;
use crate::config::Role;

/// 当前 schema 版本；`schema_meta.version` 高于它时拒绝启动，避免旧二进制写坏新库。
const SCHEMA_VERSION: i64 = 1;

/// `list` 未指定 limit（0）时的默认页大小。
const DEFAULT_LIST_LIMIT: u32 = 50;

/// `list` 单页上限，防止一次把整库拉进内存。
const MAX_LIST_LIMIT: u32 = 100;

/// 用户名最少字符数。
const USERNAME_MIN_CHARS: usize = 3;

/// 用户名最多字符数。
const USERNAME_MAX_CHARS: usize = 32;

/// 查询用户时统一使用的列顺序，与 [`read_raw_user`] 一一对应。
const USER_COLUMNS: &str = "username, role, status, created_at, last_login_at";

/// 账户状态。
///
/// DB 里存小写字符串（`active` / `pending` / `disabled`），未知值在读取时报
/// [`AccountError::CorruptRow`]，不静默降级成某个默认状态。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum UserStatus {
    /// 正常可用。
    Active,
    /// 待管理员审批（注册策略为 approval 时的新账户）。
    Pending,
    /// 已禁用：认证应拒绝，但记录保留。
    Disabled,
}

impl UserStatus {
    /// 稳定字符串表示，与 serde 的 lowercase 输出、账户库 `status` 列一致。
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Active => "active",
            Self::Pending => "pending",
            Self::Disabled => "disabled",
        }
    }

    /// 从字符串解析状态；未知值返回 `None`。
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "active" => Some(Self::Active),
            "pending" => Some(Self::Pending),
            "disabled" => Some(Self::Disabled),
            _ => None,
        }
    }
}

/// 一个账户（不含口令哈希——哈希只在认证路径内部使用，不随用户对象外流）。
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct User {
    /// 用户名（创建后不可改）。
    pub username: String,
    /// 权限档位。
    pub role: Role,
    /// 账户状态。
    pub status: UserStatus,
    /// 创建时间（unix 秒）。
    pub created_at: i64,
    /// 最后一次成功登录时间（unix 秒）；从未登录为 `None`。
    pub last_login_at: Option<i64>,
}

/// 账户库句柄。
///
/// 轻量：内部是 `Arc`，clone 后共享同一连接与互斥锁；可放进 `AppState` 供各
/// handler 克隆。
#[derive(Debug, Clone)]
pub struct UserStore {
    conn: Arc<Mutex<Connection>>,
    path: PathBuf,
}

impl UserStore {
    /// 打开（必要时创建）账户库：建父目录、开 WAL、建表并校验 schema 版本。
    ///
    /// 只在启动期调用，因此保持同步签名；不要在请求处理里调用它。
    ///
    /// # Errors
    ///
    /// 建目录/打开文件失败返回 [`AccountError::Io`] / [`AccountError::Db`]；
    /// `schema_meta.version` 高于本程序支持的版本返回 [`AccountError::SchemaTooNew`]。
    pub fn open(path: &Path) -> Result<Self, AccountError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        let conn = Connection::open(path)?;
        // WAL：读写不互相阻塞；foreign_keys 目前没有外键，仍按规划打开，给后续表留好语义。
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", true)?;
        // 跨进程写竞争（例如运维手工改库、两个实例短暂重叠）时给 5s 重试窗口，
        // 而不是让 SQLITE_BUSY 立刻变成 500；单实例下这条不会触发。
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        init_schema(&conn)?;
        Ok(Self { conn: Arc::new(Mutex::new(conn)), path: path.to_path_buf() })
    }

    /// 账户库文件路径，用于启动日志与排障。
    pub fn path(&self) -> &Path {
        &self.path
    }

    /// 创建账户；用户名重复（含大小写变体）返回 [`AccountError::DuplicateUsername`]。
    ///
    /// `password_hash` 必须是 [`super::hash_password`] 生成的 PHC 字符串；本方法
    /// 不接触明文口令。
    ///
    /// # Errors
    ///
    /// 用户名不合法、已存在，或 SQLite 写入失败。
    pub async fn create(
        &self,
        username: &str,
        password_hash: &str,
        role: Role,
        status: UserStatus,
    ) -> Result<User, AccountError> {
        validate_username(username)?;
        let username = username.to_owned();
        let password_hash = password_hash.to_owned();
        self.with_conn(move |conn| {
            if fetch_user(conn, &username)?.is_some() {
                return Err(AccountError::DuplicateUsername { username });
            }
            let now = unix_now();
            let inserted = conn.execute(
                "INSERT INTO users (username, password_hash, role, status, created_at, updated_at, last_login_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?5, NULL)",
                params![&username, &password_hash, role.as_str(), status.as_str(), now],
            );
            match inserted {
                Ok(_) => {
                    Ok(User { username, role, status, created_at: now, last_login_at: None })
                },
                // 预检查之外仍可能撞唯一约束（例如另一个进程刚写入）；按重复用户名报，
                // 不把 SQLite 的英文约束错误直接抛给调用方。
                Err(error) if is_unique_violation(&error) => {
                    Err(AccountError::DuplicateUsername { username })
                },
                Err(error) => Err(error.into()),
            }
        })
        .await
    }

    /// 按用户名查询（大小写不敏感，由 `COLLATE NOCASE` 保证）。
    ///
    /// 用户名本身不合法时返回 [`AccountError::InvalidUsername`]。
    ///
    /// # Errors
    ///
    /// 用户名不合法或 SQLite 查询失败。
    pub async fn get(&self, username: &str) -> Result<Option<User>, AccountError> {
        validate_username(username)?;
        let username = username.to_owned();
        self.with_conn(move |conn| fetch_user(conn, &username)).await
    }

    /// 读取账户的口令哈希（PHC 字符串）；用户不存在返回 `Ok(None)`。
    ///
    /// 只给认证路径用：`User` 故意不带哈希，避免账户视图在 handler 之间流转时把
    /// 哈希也带出去。哈希取出后由调用方在**独立**的阻塞任务里做 Argon2 校验——
    /// 校验要几十毫秒，不能占着账户库的连接锁。
    ///
    /// # Errors
    ///
    /// 用户名不合法或 SQLite 查询失败。
    pub async fn password_hash(&self, username: &str) -> Result<Option<String>, AccountError> {
        validate_username(username)?;
        let username = username.to_owned();
        self.with_conn(move |conn| {
            conn.query_row(
                "SELECT password_hash FROM users WHERE username = ?1",
                params![&username],
                |row| row.get(0),
            )
            .optional()
            .map_err(AccountError::from)
        })
        .await
    }

    /// 分页列出账户，返回 `(当页用户, 总数)`。
    ///
    /// `limit = 0` 按 50 处理，上限 100；`offset` 为跳过的行数。`status` 为 `None`
    /// 时不过滤。
    ///
    /// # Errors
    ///
    /// SQLite 查询失败，或库里的 `role` / `status` 不是已知取值。
    pub async fn list(
        &self,
        status: Option<UserStatus>,
        limit: u32,
        offset: u32,
    ) -> Result<(Vec<User>, u64), AccountError> {
        let limit = effective_limit(limit);
        self.with_conn(move |conn| {
            let status = status.map(UserStatus::as_str);
            let total: i64 = match status {
                Some(status) => conn.query_row(
                    "SELECT COUNT(*) FROM users WHERE status = ?1",
                    params![status],
                    |row| row.get(0),
                )?,
                None => conn.query_row("SELECT COUNT(*) FROM users", [], |row| row.get(0))?,
            };
            let limit = i64::from(limit);
            let offset = i64::from(offset);
            let raw = match status {
                Some(status) => {
                    let mut statement = conn.prepare(&format!(
                        "SELECT {USER_COLUMNS} FROM users WHERE status = ?1 ORDER BY id LIMIT ?2 OFFSET ?3"
                    ))?;
                    let rows = statement.query_map(
                        params![status, limit, offset],
                        read_raw_user,
                    )?;
                    rows.collect::<Result<Vec<_>, _>>()?
                },
                None => {
                    let mut statement = conn.prepare(&format!(
                        "SELECT {USER_COLUMNS} FROM users ORDER BY id LIMIT ?1 OFFSET ?2"
                    ))?;
                    let rows = statement.query_map(params![limit, offset], read_raw_user)?;
                    rows.collect::<Result<Vec<_>, _>>()?
                },
            };
            let users = raw.into_iter().map(parse_user).collect::<Result<Vec<_>, _>>()?;
            Ok((users, u64::try_from(total).unwrap_or(0)))
        })
        .await
    }

    /// 修改角色，并刷新 `updated_at`；用户不存在返回 [`AccountError::NotFound`]。
    ///
    /// # Errors
    ///
    /// 用户名不合法、用户不存在或 SQLite 写入失败。
    pub async fn update_role(&self, username: &str, role: Role) -> Result<(), AccountError> {
        self.update_column(
            username,
            "UPDATE users SET role = ?2, updated_at = ?3 WHERE username = ?1",
            role.as_str(),
        )
        .await
    }

    /// 修改状态，并刷新 `updated_at`；用户不存在返回 [`AccountError::NotFound`]。
    ///
    /// # Errors
    ///
    /// 用户名不合法、用户不存在或 SQLite 写入失败。
    pub async fn update_status(
        &self,
        username: &str,
        status: UserStatus,
    ) -> Result<(), AccountError> {
        self.update_column(
            username,
            "UPDATE users SET status = ?2, updated_at = ?3 WHERE username = ?1",
            status.as_str(),
        )
        .await
    }

    /// 替换口令哈希，并刷新 `updated_at`；用户不存在返回 [`AccountError::NotFound`]。
    ///
    /// # Errors
    ///
    /// 用户名不合法、用户不存在或 SQLite 写入失败。
    pub async fn update_password_hash(
        &self,
        username: &str,
        password_hash: &str,
    ) -> Result<(), AccountError> {
        self.update_column(
            username,
            "UPDATE users SET password_hash = ?2, updated_at = ?3 WHERE username = ?1",
            password_hash,
        )
        .await
    }

    /// 记录一次成功登录；只更新 `last_login_at`，不算账户资料变更。
    ///
    /// # Errors
    ///
    /// 用户名不合法、用户不存在或 SQLite 写入失败。
    pub async fn touch_last_login(&self, username: &str) -> Result<(), AccountError> {
        validate_username(username)?;
        let username = username.to_owned();
        self.with_conn(move |conn| {
            let changed = conn.execute(
                "UPDATE users SET last_login_at = ?2 WHERE username = ?1",
                params![&username, unix_now()],
            )?;
            not_found_if_unchanged(changed, username)
        })
        .await
    }

    /// 删除账户；不存在返回 [`AccountError::NotFound`]。
    ///
    /// 只删 `users` 行，**不删除任何 LFS 对象**：对象是全局共享、内容寻址的，
    /// 其他仓库可能引用同一 oid。
    ///
    /// # Errors
    ///
    /// 用户名不合法、用户不存在或 SQLite 写入失败。
    pub async fn delete(&self, username: &str) -> Result<(), AccountError> {
        validate_username(username)?;
        let username = username.to_owned();
        self.with_conn(move |conn| {
            let changed =
                conn.execute("DELETE FROM users WHERE username = ?1", params![&username])?;
            not_found_if_unchanged(changed, username)
        })
        .await
    }

    /// 原子地改「角色 + 状态」，并在同一个事务里守住「最后一个 active 管理员」。
    ///
    /// 与 [`Self::update_role`] / [`Self::update_status`] 的区别：读目标、判定、写回
    /// 三步在**一个 `BEGIN IMMEDIATE` 事务**里完成。拆成两步（先统计再更新）时，两个
    /// 管理员并发互降都能看到「还有 2 个管理员」而同时成功，事后一个管理员都不剩。
    ///
    /// `config_admins` 是 `[auth.users]` 里与目标**不同名**的 active 管理员数：配置文件
    /// 启动后不可变，调用方在事务外数好传进来，当作数据库之外的兜底管理员。同名条目
    /// 不算——删掉库里的行之后，那是同一个人换个入口复活，不是第二个管理员。
    ///
    /// # Errors
    ///
    /// 用户名不合法、用户不存在、会移除最后一个 active 管理员
    /// （[`AccountError::LastAdmin`]）或 SQLite 操作失败。
    pub async fn update_profile_guarded(
        &self,
        username: &str,
        role: Option<Role>,
        status: Option<UserStatus>,
        config_admins: u64,
    ) -> Result<User, AccountError> {
        validate_username(username)?;
        let username = username.to_owned();
        self.with_conn_mut(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let Some(target) = fetch_user(&tx, &username)? else {
                return Err(AccountError::NotFound { username });
            };
            let new_role = role.unwrap_or(target.role);
            let new_status = status.unwrap_or(target.status);
            if new_role == target.role && new_status == target.status {
                return Ok(target);
            }
            if loses_last_admin(&tx, &target, new_role, new_status, config_admins)? {
                return Err(AccountError::LastAdmin { username });
            }
            tx.execute(
                "UPDATE users SET role = ?2, status = ?3, updated_at = ?4 WHERE username = ?1",
                params![&username, new_role.as_str(), new_status.as_str(), unix_now()],
            )?;
            let Some(updated) = fetch_user(&tx, &username)? else {
                return Err(AccountError::NotFound { username });
            };
            tx.commit()?;
            Ok(updated)
        })
        .await
    }

    /// 原子地删除账户，并在同一个事务里守住「最后一个 active 管理员」。
    ///
    /// 参数与判定规则同 [`Self::update_profile_guarded`]。只删 `users` 行，
    /// **不删除任何 LFS 对象**：对象全局共享、内容寻址。
    ///
    /// # Errors
    ///
    /// 用户名不合法、用户不存在、目标是最后一个 active 管理员
    /// （[`AccountError::LastAdmin`]）或 SQLite 操作失败。
    pub async fn delete_guarded(
        &self,
        username: &str,
        config_admins: u64,
    ) -> Result<(), AccountError> {
        validate_username(username)?;
        let username = username.to_owned();
        self.with_conn_mut(move |conn| {
            let tx = conn.transaction_with_behavior(TransactionBehavior::Immediate)?;
            let Some(target) = fetch_user(&tx, &username)? else {
                return Err(AccountError::NotFound { username });
            };
            let last_admin = target.role == Role::Admin
                && target.status == UserStatus::Active
                && active_admin_count(&tx)?.saturating_add(config_admins) <= 1;
            if last_admin {
                return Err(AccountError::LastAdmin { username });
            }
            let changed =
                tx.execute("DELETE FROM users WHERE username = ?1", params![&username])?;
            not_found_if_unchanged(changed, username)?;
            tx.commit()?;
            Ok(())
        })
        .await
    }

    /// 统计 `role = admin AND status = active` 的账户数，供「最后一个管理员」保护。
    ///
    /// # Errors
    ///
    /// SQLite 查询失败。
    pub async fn count_active_admins(&self) -> Result<u64, AccountError> {
        self.with_conn(active_admin_count).await
    }

    /// 在阻塞线程里持锁执行一条 DB 操作。
    ///
    /// `spawn_blocking` 的 future 要求闭包与返回值都 `Send + 'static`，因此调用方
    /// 先把借用的参数转成 `String` 再 move 进来；闭包内不出现 `.await`。
    async fn with_conn<T, F>(&self, operation: F) -> Result<T, AccountError>
    where
        T: Send + 'static,
        F: FnOnce(&Connection) -> Result<T, AccountError> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let guard = conn.lock().map_err(|_| AccountError::LockPoisoned)?;
            operation(&guard)
        })
        .await?
    }

    /// 与 [`Self::with_conn`] 相同，但把 `&mut Connection` 交给闭包：事务需要独占连接
    /// （`transaction_with_behavior`）。
    async fn with_conn_mut<T, F>(&self, operation: F) -> Result<T, AccountError>
    where
        T: Send + 'static,
        F: FnOnce(&mut Connection) -> Result<T, AccountError> + Send + 'static,
    {
        let conn = Arc::clone(&self.conn);
        tokio::task::spawn_blocking(move || {
            let mut guard = conn.lock().map_err(|_| AccountError::LockPoisoned)?;
            operation(&mut guard)
        })
        .await?
    }

    /// `update_role` / `update_status` / `update_password_hash` 的公共实现：
    /// 都是「按用户名改一列 + 刷新 updated_at」。
    async fn update_column(
        &self,
        username: &str,
        sql: &'static str,
        value: &str,
    ) -> Result<(), AccountError> {
        validate_username(username)?;
        let username = username.to_owned();
        let value = value.to_owned();
        self.with_conn(move |conn| {
            let changed = conn.execute(sql, params![&username, &value, unix_now()])?;
            not_found_if_unchanged(changed, username)
        })
        .await
    }
}

/// 建表并校验版本；版本高于本程序支持的版本时拒绝启动。
fn init_schema(conn: &Connection) -> Result<(), AccountError> {
    conn.execute_batch(
        "CREATE TABLE IF NOT EXISTS schema_meta (version INTEGER NOT NULL);
         CREATE TABLE IF NOT EXISTS users (
             id            INTEGER PRIMARY KEY,
             username      TEXT NOT NULL UNIQUE COLLATE NOCASE,
             password_hash TEXT NOT NULL,
             role          TEXT NOT NULL,
             status        TEXT NOT NULL,
             created_at    INTEGER NOT NULL,
             updated_at    INTEGER NOT NULL,
             last_login_at INTEGER
         );",
    )?;
    let found: Option<i64> = conn
        .query_row("SELECT version FROM schema_meta LIMIT 1", [], |row| row.get(0))
        .optional()?;
    match found {
        None => {
            conn.execute("INSERT INTO schema_meta (version) VALUES (?1)", params![SCHEMA_VERSION])?;
            Ok(())
        },
        Some(SCHEMA_VERSION) => Ok(()),
        Some(found) if found > SCHEMA_VERSION => {
            Err(AccountError::SchemaTooNew { found, supported: SCHEMA_VERSION })
        },
        Some(found) => Err(AccountError::SchemaUnsupported { found, supported: SCHEMA_VERSION }),
    }
}

/// 用户名校验：3–32 个字符、仅 `[A-Za-z0-9._-]`、不含 `:`。
///
/// 公开给注册/管理端点做「先校验再哈希」的早期拒绝：Argon2 不便宜，非法用户名
/// 不该先付一次哈希成本。
///
/// # Errors
///
/// 违反长度或字符集规则时返回 [`AccountError::InvalidUsername`]。
pub fn validate_username(username: &str) -> Result<(), AccountError> {
    let length = username.chars().count();
    if !(USERNAME_MIN_CHARS..=USERNAME_MAX_CHARS).contains(&length) {
        return Err(AccountError::InvalidUsername {
            username: username.to_owned(),
            reason: format!(
                "长度必须在 {USERNAME_MIN_CHARS}–{USERNAME_MAX_CHARS} 个字符之间，实际 {length} 个"
            ),
        });
    }
    if let Some(found) =
        username.chars().find(|ch| !(ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-')))
    {
        return Err(AccountError::InvalidUsername {
            username: username.to_owned(),
            reason: format!(
                "只能包含字母、数字、'.'、'_'、'-'（不允许 ':' 或空白），发现 '{found}'"
            ),
        });
    }
    Ok(())
}

/// 一行的原始列值；解析成 [`User`] 前先脱离 `Row` 的借用。
type RawUser = (String, String, String, i64, Option<i64>);

/// 按 [`USER_COLUMNS`] 的顺序读一行。
fn read_raw_user(row: &Row<'_>) -> rusqlite::Result<RawUser> {
    Ok((row.get(0)?, row.get(1)?, row.get(2)?, row.get(3)?, row.get(4)?))
}

/// 把原始列值解析成 [`User`]；未知 `role` / `status` 报 [`AccountError::CorruptRow`]。
fn parse_user(raw: RawUser) -> Result<User, AccountError> {
    let (username, role, status, created_at, last_login_at) = raw;
    let parsed_role = Role::parse(&role)
        .ok_or_else(|| AccountError::CorruptRow { column: "role", value: role })?;
    let parsed_status = UserStatus::parse(&status)
        .ok_or_else(|| AccountError::CorruptRow { column: "status", value: status })?;
    Ok(User { username, role: parsed_role, status: parsed_status, created_at, last_login_at })
}

/// 按用户名查一行；调用方需先校验用户名。
fn fetch_user(conn: &Connection, username: &str) -> Result<Option<User>, AccountError> {
    let raw = conn
        .query_row(
            &format!("SELECT {USER_COLUMNS} FROM users WHERE username = ?1"),
            params![username],
            read_raw_user,
        )
        .optional()?;
    raw.map(parse_user).transpose()
}

/// 把 `target` 改成 (`new_role`, `new_status`) 之后，系统是否不再有 active 管理员。
///
/// 只有「原本是 active 管理员」且「改完不再是」才需要数人头；`config_admins` 是数据库
/// 之外的兜底管理员数（见 [`UserStore::update_profile_guarded`]）。
fn loses_last_admin(
    conn: &Connection,
    target: &User,
    new_role: Role,
    new_status: UserStatus,
    config_admins: u64,
) -> Result<bool, AccountError> {
    let was_active_admin = target.role == Role::Admin && target.status == UserStatus::Active;
    let stays_active_admin = new_role == Role::Admin && new_status == UserStatus::Active;
    if !was_active_admin || stays_active_admin {
        return Ok(false);
    }
    Ok(active_admin_count(conn)?.saturating_add(config_admins) <= 1)
}

/// `role = admin AND status = active` 的行数；事务内外都可用。
fn active_admin_count(conn: &Connection) -> Result<u64, AccountError> {
    let count: i64 = conn.query_row(
        "SELECT COUNT(*) FROM users WHERE role = ?1 AND status = ?2",
        params![Role::Admin.as_str(), UserStatus::Active.as_str()],
        |row| row.get(0),
    )?;
    Ok(u64::try_from(count).unwrap_or(0))
}

/// 单行更新/删除的影响行数为 0 时转成 [`AccountError::NotFound`]。
fn not_found_if_unchanged(changed: usize, username: String) -> Result<(), AccountError> {
    if changed == 0 { Err(AccountError::NotFound { username }) } else { Ok(()) }
}

/// SQLite 唯一约束冲突（用户名重复）。
///
/// 只认 `SQLITE_CONSTRAINT_UNIQUE`：外键/NOT NULL 等其它约束失败必须原样上报，
/// 不能被误判成「用户名已存在」。
fn is_unique_violation(error: &rusqlite::Error) -> bool {
    matches!(
        error,
        rusqlite::Error::SqliteFailure(inner, _)
            if inner.extended_code == rusqlite::ffi::SQLITE_CONSTRAINT_UNIQUE
    )
}

/// `limit = 0` 用默认页大小，其余按上限截断。
fn effective_limit(limit: u32) -> u32 {
    match limit {
        0 => DEFAULT_LIST_LIMIT,
        value => value.min(MAX_LIST_LIMIT),
    }
}

/// 当前 unix 秒；时钟早于 epoch 时回退 0，避免把负数写进库。
fn unix_now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| i64::try_from(elapsed.as_secs()).unwrap_or(0))
}

#[cfg(test)]
mod tests {
    use super::{MAX_LIST_LIMIT, effective_limit, validate_username};
    use crate::accounts::AccountError;

    #[test]
    fn given_username_boundaries_when_validate_then_rules_enforced() {
        assert!(validate_username("abc").is_ok());
        assert!(validate_username("Alice_01-x.y").is_ok());
        assert!(validate_username(&"a".repeat(32)).is_ok());

        for invalid in ["", "ab", &"a".repeat(33), "has space", "has:colon", "中文名字"] {
            let error = validate_username(invalid).expect_err("应拒绝非法用户名");
            assert!(matches!(error, AccountError::InvalidUsername { .. }), "实际错误：{error}");
        }
    }

    #[test]
    fn given_limit_values_when_effective_limit_then_default_and_cap() {
        assert_eq!(effective_limit(0), 50);
        assert_eq!(effective_limit(7), 7);
        assert_eq!(effective_limit(MAX_LIST_LIMIT), MAX_LIST_LIMIT);
        assert_eq!(effective_limit(MAX_LIST_LIMIT + 500), MAX_LIST_LIMIT);
    }
}

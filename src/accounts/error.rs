//! 账户层的域内错误。
//!
//! 与 `ConfigError` 一样只描述「什么失败了、关键参数是什么」：错误信息小写开头、
//! 不加句号，供启动日志与 HTTP 边界映射状态码。

/// 账户库、用户名校验与口令哈希失败的原因。
#[derive(Debug, thiserror::Error)]
pub enum AccountError {
    /// SQLite 语句或连接失败。
    #[error("账户库操作失败：{0}")]
    Db(#[from] rusqlite::Error),
    /// 账户库目录或文件操作失败。
    #[error("账户库文件操作失败：{0}")]
    Io(#[from] std::io::Error),
    /// 阻塞任务执行失败：运行时已关闭，或任务在阻塞线程里 panic。
    #[error("账户库任务执行失败：{0}")]
    Task(#[from] tokio::task::JoinError),
    /// 连接锁被毒化：此前有持锁任务 panic。
    #[error("账户库连接锁已被毒化")]
    LockPoisoned,
    /// `schema_meta` 记录的版本高于本程序支持的版本。
    #[error("账户库 schema 版本为 {found}，高于本程序支持的 {supported}，请升级 netdisk-lfs")]
    SchemaTooNew {
        /// 账户库里记录的版本。
        found: i64,
        /// 本程序支持的版本。
        supported: i64,
    },
    /// `schema_meta` 记录的版本低于本程序支持的版本，且没有可用迁移。
    #[error("账户库 schema 版本为 {found}，本程序只支持 {supported}")]
    SchemaUnsupported {
        /// 账户库里记录的版本。
        found: i64,
        /// 本程序支持的版本。
        supported: i64,
    },
    /// 用户名已存在（大小写不敏感）。
    #[error("用户名 {username} 已存在")]
    DuplicateUsername {
        /// 冲突的用户名。
        username: String,
    },
    /// 目标用户不存在。
    #[error("用户 {username} 不存在")]
    NotFound {
        /// 查询的用户名。
        username: String,
    },
    /// 用户名不符合规则。
    #[error("用户名 {username} 不合法：{reason}")]
    InvalidUsername {
        /// 被拒绝的用户名。
        username: String,
        /// 具体哪条规则不满足。
        reason: String,
    },
    /// 口令不符合策略。
    #[error("口令不合法：{reason}")]
    InvalidPassword {
        /// 具体哪条规则不满足。
        reason: String,
    },
    /// 数据库里的 `role` / `status` 不是已知取值（手工改库或版本不匹配）。
    #[error("账户库字段 {column} 的值 {value} 不合法")]
    CorruptRow {
        /// 出问题的列名。
        column: &'static str,
        /// 列里的原始值。
        value: String,
    },
    /// Argon2 哈希生成失败（随机数或参数问题）。
    #[error("口令哈希失败：{reason}")]
    Hash {
        /// 底层密码库给出的原因。
        reason: String,
    },
}

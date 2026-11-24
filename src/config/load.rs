//! TOML 解析、环境变量覆盖与启动期校验。
//!
//! 原始结构（`Raw*`）只负责如实反序列化；校验与归一化集中在 [`Config::from_raw`]，
//! 让「缺字段 / 类型错 / 语义错」在启动时就暴露，而不是等到第一个请求。

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::config::env::{self, EnvSource};
use crate::config::error::ConfigError;
use crate::config::model::{
    AccountsConfig, AuthConfig, CacheConfig, Config, DEFAULT_LOGIN_FAILURES_PER_5MIN,
    DEFAULT_MIN_PASSWORD_LEN, DEFAULT_REGISTRATION_PER_HOUR, RegistrationPolicy, Role, RuntimeEnv,
    ServerConfig, StorageConfig, UserConfig,
};

/// 缓存预算缺省值：200 GiB，与 `specs/storage.md` 一致。
const DEFAULT_CACHE_MAX_BYTES: u64 = 214_748_364_800;
/// `bdpan` 授权目录；配置里的网盘路径必须落在它下面。
const AUTHORIZED_REMOTE_PREFIX: &str = "/apps/bdpan";

impl Config {
    /// 读取并校验配置文件；`env` 中的机器相关值覆盖 TOML 中的同名配置。
    pub fn load_with(config_path: &Path, env: &EnvSource) -> Result<Self, ConfigError> {
        let raw_text = std::fs::read_to_string(config_path)
            .map_err(|source| ConfigError::Read { path: config_path.to_path_buf(), source })?;
        let raw: RawConfig = toml::from_str(&raw_text)
            .map_err(|source| ConfigError::Parse { path: config_path.to_path_buf(), source })?;
        Self::from_raw(raw, env)
    }

    /// 归一化并校验；返回的配置可直接用于启动。
    fn from_raw(raw: RawConfig, env: &EnvSource) -> Result<Self, ConfigError> {
        let RawConfig { server, storage, cache, accounts, auth } = raw;

        let runtime_env = match env.get(env::NETDISK_LFS_ENV) {
            Some(raw_env) => RuntimeEnv::parse(raw_env)?,
            None => RuntimeEnv::default(),
        };
        let data_dir = env.path(env::NETDISK_LFS_DATA_DIR);
        // 数据根必须是绝对路径：cache 与 accounts.db 都从它推导，相对路径会让
        // 数据库落点随进程 CWD 漂移（换目录启动就悄悄建一个空库）。
        if let Some(dir) = &data_dir
            && !dir.is_absolute()
        {
            return Err(ConfigError::invalid(format!(
                "NETDISK_LFS_DATA_DIR 必须是绝对路径，实际为 {}",
                dir.display()
            )));
        }

        let server = ServerConfig {
            listen: server.listen,
            public_base: validate_public_base(&server.public_base)?,
        };

        let storage = StorageConfig {
            objects_root: validate_remote_root(&storage.objects_root, "storage.objects_root")?,
            tmp_root: validate_remote_root(&storage.tmp_root, "storage.tmp_root")?,
            bdpan_bin: {
                let path = env.path(env::BDPAN_BIN).or(storage.bdpan_bin).ok_or_else(|| {
                    ConfigError::invalid("缺少 storage.bdpan_bin，且未设置 BDPAN_BIN")
                })?;
                if !path.is_absolute() {
                    return Err(ConfigError::invalid(format!(
                        "storage.bdpan_bin 必须是绝对路径，实际为 {}",
                        path.display()
                    )));
                }
                path
            },
            max_object_bytes: storage.max_object_bytes,
            max_bdpan_procs: storage.max_bdpan_procs,
            bdpan_timeout_secs: storage.bdpan_timeout_secs,
            bdpan_min_throughput_bytes_per_sec: storage.bdpan_min_throughput_bytes_per_sec,
        };

        let cache_dir = match (cache.dir, &data_dir) {
            (Some(dir), _) if !dir.as_os_str().is_empty() => dir,
            (_, Some(root)) => root.join("cache"),
            _ => {
                return Err(ConfigError::invalid(
                    "缺少 cache.dir，且未设置 NETDISK_LFS_DATA_DIR（缺省取 $NETDISK_LFS_DATA_DIR/cache）",
                ));
            },
        };

        let accounts_db = match (accounts.db.as_os_str().is_empty(), &data_dir) {
            (false, _) if accounts.db.is_absolute() => accounts.db,
            (false, _) => {
                return Err(ConfigError::invalid(format!(
                    "accounts.db 必须是绝对路径，实际为 {}",
                    accounts.db.display()
                )));
            },
            (true, Some(root)) => root.join("accounts.db"),
            (true, None) => {
                return Err(ConfigError::invalid(
                    "缺少 accounts.db，且未设置 NETDISK_LFS_DATA_DIR：请把 accounts.db 配成绝对路径，或设置 NETDISK_LFS_DATA_DIR（缺省取 $NETDISK_LFS_DATA_DIR/accounts.db）",
                ));
            },
        };

        let config = Self {
            server,
            storage,
            cache: CacheConfig { dir: cache_dir, max_bytes: cache.max_bytes },
            accounts: AccountsConfig {
                db: accounts_db,
                min_password_len: accounts.min_password_len,
                registration: accounts.registration,
                default_role: accounts.default_role,
                registration_per_hour: accounts.registration_per_hour,
                login_failures_per_5min: accounts.login_failures_per_5min,
                trust_proxy: accounts.trust_proxy,
            },
            auth: AuthConfig { users: auth.users },
            runtime_env,
            data_dir,
        };
        config.validate()?;
        Ok(config)
    }

    /// 语义校验：网关只能操作 `/apps/bdpan/` 下的路径，且各项上限必须为正。
    fn validate(&self) -> Result<(), ConfigError> {
        if !is_under_authorized_root(&self.storage.objects_root) {
            return Err(ConfigError::invalid(format!(
                "storage.objects_root 必须位于 {AUTHORIZED_REMOTE_PREFIX}/ 下，实际为 {}",
                self.storage.objects_root
            )));
        }
        let tmp_prefix = format!("{}/", self.storage.objects_root);
        if !self.storage.tmp_root.starts_with(&tmp_prefix) {
            return Err(ConfigError::invalid(format!(
                "storage.tmp_root 必须是 storage.objects_root（{}）的子目录，实际为 {}",
                self.storage.objects_root, self.storage.tmp_root
            )));
        }
        // `max_object_bytes = 0` 是合法的「不限制」，只校验并发上限。
        if self.storage.max_bdpan_procs == 0 {
            return Err(ConfigError::invalid("storage.max_bdpan_procs 必须至少为 1"));
        }
        if self.cache.max_bytes == 0 {
            return Err(ConfigError::invalid("cache.max_bytes 必须大于 0"));
        }
        // 与 accounts::password::MAX_PASSWORD_CHARS（128）保持一致：下界为 0 会关掉
        // 长度下限，上界超过 128 会让口令策略永远无法满足。
        if self.accounts.min_password_len == 0 || self.accounts.min_password_len > 128 {
            return Err(ConfigError::invalid(format!(
                "accounts.min_password_len 必须在 1..=128 之间，实际为 {}",
                self.accounts.min_password_len
            )));
        }
        // 默认角色只能是普通角色：admin 必须由 `[auth.users]` 显式引导，否则开放注册
        // 就等于任何人都能自助拿到管理员权限。
        if self.accounts.default_role == Role::Admin {
            return Err(ConfigError::invalid(
                "accounts.default_role 不能是 admin，管理员只能通过 [auth.users] 引导",
            ));
        }
        for (name, user) in &self.auth.users {
            if name.is_empty() {
                return Err(ConfigError::invalid("auth.users 的用户名不能为空"));
            }
            if name.contains(':') {
                return Err(ConfigError::invalid(format!(
                    "auth.users 用户名 {name} 不允许包含 ':'，否则 Basic Auth 的 user:password 拆分有歧义"
                )));
            }
            if user.password_sha256.is_empty() {
                return Err(ConfigError::invalid(format!(
                    "auth.users.{name}.password_sha256 不能为空"
                )));
            }
        }
        Ok(())
    }
}

/// 去掉尾部 `/` 并拒绝空路径；网盘路径统一成不带尾斜杠的形式，便于后续拼接。
///
/// 同时拒绝 `.` / `..` 路径段：后续会在 root 下拼接对象子路径再交给 bdpan，
/// 词法逃逸（如 `/apps/bdpan/../etc`）必须在这里拦截。
fn validate_remote_root(raw: &str, key: &str) -> Result<String, ConfigError> {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return Err(ConfigError::invalid(format!("{key} 不能为空")));
    }
    if trimmed.split('/').any(|segment| segment == "." || segment == "..") {
        return Err(ConfigError::invalid(format!(
            "{key} 不允许包含 . 或 .. 路径段，实际为 {trimmed}"
        )));
    }
    Ok(trimmed.to_owned())
}

/// `public_base` 留空表示走相对路径；非空时必须是 http(s) 绝对地址。
fn validate_public_base(raw: &str) -> Result<String, ConfigError> {
    let trimmed = raw.trim_end_matches('/');
    if trimmed.is_empty() {
        return Ok(String::new());
    }
    if !(trimmed.starts_with("http://") || trimmed.starts_with("https://")) {
        return Err(ConfigError::invalid(format!(
            "server.public_base 必须留空或以 http:// / https:// 开头，实际为 {trimmed}"
        )));
    }
    Ok(trimmed.to_owned())
}

/// 判断网盘路径是否落在授权目录内（允许授权目录本身）。
fn is_under_authorized_root(remote: &str) -> bool {
    remote == AUTHORIZED_REMOTE_PREFIX
        || remote.starts_with(&format!("{AUTHORIZED_REMOTE_PREFIX}/"))
}

/// 与 TOML 一一对应的原始结构，只做反序列化；`deny_unknown_fields` 让拼错的键启动即报错。
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawConfig {
    server: RawServer,
    storage: RawStorage,
    #[serde(default)]
    cache: RawCache,
    #[serde(default)]
    accounts: RawAccounts,
    #[serde(default)]
    auth: RawAuth,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawServer {
    listen: SocketAddr,
    #[serde(default)]
    public_base: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawStorage {
    objects_root: String,
    tmp_root: String,
    bdpan_bin: Option<PathBuf>,
    max_object_bytes: u64,
    max_bdpan_procs: usize,
    #[serde(default = "default_bdpan_timeout_secs")]
    bdpan_timeout_secs: u64,
    #[serde(default = "default_bdpan_min_throughput")]
    bdpan_min_throughput_bytes_per_sec: u64,
}

/// 非传输命令超时 / 传输启动宽限的缺省值：300s。
fn default_bdpan_timeout_secs() -> u64 {
    300
}

/// 传输最低吞吐缺省值：100 KiB/s（低于它视为卡死，按文件大小放大超时）。
fn default_bdpan_min_throughput() -> u64 {
    102_400
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawCache {
    dir: Option<PathBuf>,
    #[serde(default = "default_cache_max_bytes")]
    max_bytes: u64,
}

impl Default for RawCache {
    fn default() -> Self {
        Self { dir: None, max_bytes: DEFAULT_CACHE_MAX_BYTES }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAccounts {
    /// 账户库路径；留空时由数据根推导。
    #[serde(default)]
    db: PathBuf,
    #[serde(default = "default_min_password_len")]
    min_password_len: usize,
    #[serde(default = "default_registration")]
    registration: RegistrationPolicy,
    #[serde(default = "default_default_role")]
    default_role: Role,
    #[serde(default = "default_registration_per_hour")]
    registration_per_hour: u64,
    #[serde(default = "default_login_failures_per_5min")]
    login_failures_per_5min: u64,
    #[serde(default)]
    trust_proxy: bool,
}

impl Default for RawAccounts {
    fn default() -> Self {
        // 整个 `[accounts]` 段缺失时走这里；字段级 serde default 不会生效，
        // 因此必须显式给出每个缺省值，否则会静默退化成 0（口令下限）或未知策略。
        Self {
            db: PathBuf::new(),
            min_password_len: default_min_password_len(),
            registration: default_registration(),
            default_role: default_default_role(),
            registration_per_hour: default_registration_per_hour(),
            login_failures_per_5min: default_login_failures_per_5min(),
            trust_proxy: false,
        }
    }
}

/// 口令最小长度缺省值。
fn default_min_password_len() -> usize {
    DEFAULT_MIN_PASSWORD_LEN
}

/// 注册策略缺省值：`approval`（新账户需管理员审批后才可登录）。
fn default_registration() -> RegistrationPolicy {
    RegistrationPolicy::Approval
}

/// 默认角色缺省值：`readwrite`。
fn default_default_role() -> Role {
    Role::Readwrite
}

/// 注册限速缺省值。
fn default_registration_per_hour() -> u64 {
    DEFAULT_REGISTRATION_PER_HOUR
}

/// 登录失败限速缺省值。
fn default_login_failures_per_5min() -> u64 {
    DEFAULT_LOGIN_FAILURES_PER_5MIN
}

#[derive(Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawAuth {
    #[serde(default)]
    users: BTreeMap<String, UserConfig>,
}

fn default_cache_max_bytes() -> u64 {
    DEFAULT_CACHE_MAX_BYTES
}

#[cfg(test)]
mod tests {
    use super::{Config, DEFAULT_CACHE_MAX_BYTES};
    use crate::config::env::EnvSource;
    use crate::config::error::ConfigError;
    use crate::config::model::{RegistrationPolicy, Role};
    use crate::test_support::TempDir;

    use std::net::SocketAddr;
    use std::path::{Path, PathBuf};

    /// 口令哈希用占位串：本阶段只校验非空，格式校验留给 B4 认证分支。
    const PASSWORD_HASH: &str = "0000000000000000000000000000000000000000000000000000000000000000";

    const VALID_CONFIG: &str = r#"
[server]
listen = "127.0.0.1:9001"
public_base = ""

[storage]
objects_root = "/apps/bdpan/lfs"
tmp_root = "/apps/bdpan/lfs/tmp"
bdpan_bin = "/usr/local/bin/bdpan"
max_object_bytes = 4294967296
max_bdpan_procs = 4

[cache]
dir = "/var/lib/netdisk-lfs/cache"
max_bytes = 214748364800

[accounts]
db = "/var/lib/netdisk-lfs/accounts.db"

[auth.users]
alice = { password_sha256 = "0000000000000000000000000000000000000000000000000000000000000000", role = "readwrite" }
bob = { password_sha256 = "0000000000000000000000000000000000000000000000000000000000000000", role = "readonly" }
"#;

    fn load(contents: &str, env_pairs: &[(&str, &str)]) -> Result<Config, ConfigError> {
        let dir = TempDir::new("netdisk-lfs-config");
        let path = dir.write("config.toml", contents);
        Config::load_with(&path, &EnvSource::from_pairs(env_pairs))
    }

    fn load_error(contents: &str, env_pairs: &[(&str, &str)]) -> String {
        load(contents, env_pairs).expect_err("配置应被拒绝").to_string()
    }

    #[test]
    fn given_valid_config_when_load_then_all_sections_are_parsed() {
        let config = load(VALID_CONFIG, &[]).expect("合法配置应加载成功");

        assert_eq!(config.server.listen, "127.0.0.1:9001".parse::<SocketAddr>().expect("地址"));
        assert_eq!(config.server.public_base, "");
        assert_eq!(config.storage.objects_root, "/apps/bdpan/lfs");
        assert_eq!(config.storage.tmp_root, "/apps/bdpan/lfs/tmp");
        assert_eq!(config.storage.bdpan_bin, PathBuf::from("/usr/local/bin/bdpan"));
        assert_eq!(config.storage.max_object_bytes, 4_294_967_296);
        assert_eq!(config.storage.max_bdpan_procs, 4);
        assert_eq!(config.storage.bdpan_timeout_secs, 300);
        assert_eq!(config.storage.bdpan_min_throughput_bytes_per_sec, 102_400);
        assert_eq!(config.cache.dir, PathBuf::from("/var/lib/netdisk-lfs/cache"));
        assert_eq!(config.cache.max_bytes, 214_748_364_800);
        assert_eq!(config.accounts.db, PathBuf::from("/var/lib/netdisk-lfs/accounts.db"));
        assert_eq!(config.accounts.min_password_len, 12);
        assert_eq!(
            config.accounts.registration,
            RegistrationPolicy::Approval,
            "默认需要管理员审批"
        );
        assert_eq!(config.accounts.default_role, Role::Readwrite, "新账户默认读写");
        assert_eq!(config.accounts.registration_per_hour, 5);
        assert_eq!(config.accounts.login_failures_per_5min, 10);
        assert!(!config.accounts.trust_proxy, "默认不信任 X-Forwarded-For");
        assert_eq!(config.auth.users.len(), 2);
        assert_eq!(config.auth.users["alice"].role, Role::Readwrite);
        assert_eq!(config.auth.users["bob"].role, Role::Readonly);
        assert_eq!(config.runtime_env, crate::config::model::RuntimeEnv::Dev);
        assert_eq!(config.data_dir, None);
    }

    #[test]
    fn given_missing_required_section_when_load_then_parse_error_names_field() {
        let contents = VALID_CONFIG.replace("[server]", "[server-typo]");

        let message = load_error(&contents, &[]);

        assert!(message.contains("server"), "实际错误：{message}");
    }

    #[test]
    fn given_illegal_type_when_load_then_parse_error_points_at_key() {
        let contents = VALID_CONFIG.replace("listen = \"127.0.0.1:9001\"", "listen = 9001");

        let message = load_error(&contents, &[]);

        assert!(message.contains("invalid type"), "实际错误：{message}");
        assert!(message.contains("9001"), "实际错误：{message}");
    }

    #[test]
    fn given_unknown_field_when_load_then_typo_is_rejected() {
        let contents = VALID_CONFIG.replace("max_bdpan_procs = 4", "max_bdpan_proc = 4");

        let message = load_error(&contents, &[]);

        assert!(message.contains("unknown field"), "实际错误：{message}");
    }

    #[test]
    fn given_env_overrides_when_load_then_env_wins_and_data_dir_fills_cache() {
        let contents = r#"
[server]
listen = "127.0.0.1:9001"

[storage]
objects_root = "/apps/bdpan/lfs"
tmp_root = "/apps/bdpan/lfs/tmp"
bdpan_bin = "/usr/local/bin/bdpan"
max_object_bytes = 4294967296
max_bdpan_procs = 4
"#;
        let env = [
            ("BDPAN_BIN", "/opt/bdpan/bin/bdpan"),
            ("NETDISK_LFS_DATA_DIR", "/srv/netdisk-lfs"),
            ("NETDISK_LFS_ENV", "prod"),
        ];

        let config = load(contents, &env).expect("env 覆盖后应合法");

        assert_eq!(config.storage.bdpan_bin, PathBuf::from("/opt/bdpan/bin/bdpan"));
        assert_eq!(config.cache.dir, PathBuf::from("/srv/netdisk-lfs/cache"));
        assert_eq!(config.cache.max_bytes, DEFAULT_CACHE_MAX_BYTES);
        assert_eq!(config.accounts.db, PathBuf::from("/srv/netdisk-lfs/accounts.db"));
        assert_eq!(
            config.accounts.min_password_len, 12,
            "[accounts] 段缺失时最小口令长度仍应是缺省 12"
        );
        assert_eq!(config.runtime_env, crate::config::model::RuntimeEnv::Prod);
        assert_eq!(config.data_dir.as_deref(), Some(Path::new("/srv/netdisk-lfs")));
    }

    #[test]
    fn given_no_cache_and_no_data_dir_when_load_then_cache_dir_required() {
        let contents = r#"
[server]
listen = "127.0.0.1:9001"

[storage]
objects_root = "/apps/bdpan/lfs"
tmp_root = "/apps/bdpan/lfs/tmp"
bdpan_bin = "/usr/local/bin/bdpan"
max_object_bytes = 4294967296
max_bdpan_procs = 4
"#;

        let message = load_error(contents, &[]);

        assert!(message.contains("cache.dir"), "实际错误：{message}");
        assert!(message.contains("NETDISK_LFS_DATA_DIR"), "实际错误：{message}");
    }

    #[test]
    fn given_bdpan_bin_absent_when_load_then_env_hint_reported() {
        let contents = r#"
[server]
listen = "127.0.0.1:9001"

[storage]
objects_root = "/apps/bdpan/lfs"
tmp_root = "/apps/bdpan/lfs/tmp"
max_object_bytes = 4294967296
max_bdpan_procs = 4

[cache]
dir = "/var/lib/netdisk-lfs/cache"
"#;

        let message = load_error(contents, &[]);

        assert!(message.contains("BDPAN_BIN"), "实际错误：{message}");
    }

    #[test]
    fn given_remote_root_outside_authorized_dir_when_load_then_rejected() {
        let contents =
            VALID_CONFIG.replace("objects_root = \"/apps/bdpan/lfs\"", "objects_root = \"/lfs\"");

        let message = load_error(&contents, &[]);

        assert!(message.contains("/apps/bdpan"), "实际错误：{message}");
    }

    #[test]
    fn given_dotdot_segment_in_remote_root_when_load_then_rejected() {
        let contents = VALID_CONFIG.replace(
            "objects_root = \"/apps/bdpan/lfs\"",
            "objects_root = \"/apps/bdpan/lfs/../..\"",
        );
        let tmp = VALID_CONFIG.replace(
            "tmp_root = \"/apps/bdpan/lfs/tmp\"",
            "tmp_root = \"/apps/bdpan/lfs/tmp/../..\"",
        );

        assert!(load_error(&contents, &[]).contains("路径段"), "实际错误见上");
        assert!(load_error(&tmp, &[]).contains("路径段"), "实际错误见上");
    }

    #[test]
    fn given_relative_bdpan_bin_when_load_then_rejected() {
        let contents =
            VALID_CONFIG.replace("bdpan_bin = \"/usr/local/bin/bdpan\"", "bdpan_bin = \"bdpan\"");

        let message = load_error(&contents, &[]);

        assert!(message.contains("绝对路径"), "实际错误：{message}");
    }

    #[test]
    fn given_empty_or_colon_username_when_load_then_rejected() {
        let empty = VALID_CONFIG.replace("bob = { password_sha256", "\"\" = { password_sha256");
        let colon = VALID_CONFIG.replace("bob = { password_sha256", "\"a:b\" = { password_sha256");

        assert!(load_error(&empty, &[]).contains("用户名不能为空"), "实际错误见上");
        assert!(load_error(&colon, &[]).contains("':'"), "实际错误见上");
    }

    #[test]
    fn given_tmp_root_outside_objects_root_when_load_then_rejected() {
        let contents = VALID_CONFIG
            .replace("tmp_root = \"/apps/bdpan/lfs/tmp\"", "tmp_root = \"/apps/bdpan/other-tmp\"");

        let message = load_error(&contents, &[]);

        assert!(message.contains("storage.tmp_root"), "实际错误：{message}");
    }

    #[test]
    fn given_zero_max_object_bytes_when_load_then_unlimited() {
        // 0 = 不限制（大对象场景），不是非法值。
        let contents =
            VALID_CONFIG.replace("max_object_bytes = 4294967296", "max_object_bytes = 0");

        let config = load(&contents, &[]).expect("0 表示不限制，应通过校验");

        assert_eq!(config.storage.max_object_bytes, 0);
    }

    #[test]
    fn given_zero_bdpan_procs_when_load_then_rejected() {
        let contents = VALID_CONFIG.replace("max_bdpan_procs = 4", "max_bdpan_procs = 0");

        assert!(load_error(&contents, &[]).contains("max_bdpan_procs"));
    }

    #[test]
    fn given_relative_data_dir_when_load_then_rejected() {
        // 相对路径会让 cache/accounts.db 落点随 CWD 漂移。
        let message = load_error(VALID_CONFIG, &[("NETDISK_LFS_DATA_DIR", "relative/data")]);

        assert!(message.contains("绝对路径"), "实际错误：{message}");
    }

    #[test]
    fn given_out_of_range_min_password_len_when_load_then_rejected() {
        let anchor = "[accounts]\ndb = \"/var/lib/netdisk-lfs/accounts.db\"";
        let zero = VALID_CONFIG.replace(anchor, &format!("{anchor}\nmin_password_len = 0"));
        let too_big = VALID_CONFIG.replace(anchor, &format!("{anchor}\nmin_password_len = 129"));

        let zero_error = load_error(&zero, &[]);
        let big_error = load_error(&too_big, &[]);
        assert!(zero_error.contains("min_password_len"), "0 应被拒绝；实际错误：{zero_error}");
        assert!(big_error.contains("min_password_len"), ">128 应被拒绝；实际错误：{big_error}");
    }

    #[test]
    fn given_no_accounts_section_when_load_then_min_password_len_defaults_to_12() {
        let config = load(VALID_CONFIG, &[]).expect("合法配置");

        assert_eq!(config.accounts.min_password_len, 12);
    }

    #[test]
    fn given_unknown_role_when_load_then_rejected() {
        let contents = VALID_CONFIG.replace("role = \"readonly\"", "role = \"owner\"");

        let message = load_error(&contents, &[]);

        assert!(message.contains("role"), "实际错误：{message}");
    }

    #[test]
    fn given_admin_role_when_load_then_accepted() {
        let contents = VALID_CONFIG.replace("role = \"readonly\"", "role = \"admin\"");

        let config = load(&contents, &[]).expect("admin 是合法角色");

        assert_eq!(config.auth.users["bob"].role, Role::Admin);
    }

    #[test]
    fn given_empty_accounts_db_and_data_dir_when_load_then_under_data_root() {
        let contents = r#"
[server]
listen = "127.0.0.1:9001"

[storage]
objects_root = "/apps/bdpan/lfs"
tmp_root = "/apps/bdpan/lfs/tmp"
bdpan_bin = "/usr/local/bin/bdpan"
max_object_bytes = 0
max_bdpan_procs = 4

[cache]
dir = "/var/lib/netdisk-lfs/cache"

[accounts]
db = ""
"#;

        let config = load(contents, &[("NETDISK_LFS_DATA_DIR", "/srv/netdisk-lfs")])
            .expect("空 db 应由数据根推导");

        assert_eq!(config.accounts.db, PathBuf::from("/srv/netdisk-lfs/accounts.db"));
        assert_eq!(config.accounts.min_password_len, 12);
    }

    #[test]
    fn given_relative_accounts_db_when_load_then_rejected() {
        let contents = VALID_CONFIG
            .replace("db = \"/var/lib/netdisk-lfs/accounts.db\"", "db = \"accounts.db\"");

        let message = load_error(&contents, &[]);

        assert!(message.contains("绝对路径"), "实际错误：{message}");
    }

    #[test]
    fn given_no_accounts_db_and_no_data_dir_when_load_then_both_options_reported() {
        let contents =
            VALID_CONFIG.replace("db = \"/var/lib/netdisk-lfs/accounts.db\"", "db = \"\"");

        let message = load_error(&contents, &[]);

        assert!(message.contains("accounts.db"), "实际错误：{message}");
        assert!(message.contains("NETDISK_LFS_DATA_DIR"), "实际错误：{message}");
    }

    #[test]
    fn given_empty_password_hash_when_load_then_rejected() {
        let contents = VALID_CONFIG.replace(
            &format!("password_sha256 = \"{PASSWORD_HASH}\", role = \"readonly\""),
            "password_sha256 = \"\", role = \"readonly\"",
        );

        let message = load_error(&contents, &[]);

        assert!(message.contains("password_sha256"), "实际错误：{message}");
    }

    #[test]
    fn given_non_http_public_base_when_load_then_rejected() {
        let contents =
            VALID_CONFIG.replace("public_base = \"\"", "public_base = \"lfs.example.com\"");

        let message = load_error(&contents, &[]);

        assert!(message.contains("public_base"), "实际错误：{message}");
    }

    #[test]
    fn given_public_base_with_trailing_slash_when_load_then_normalized() {
        let contents = VALID_CONFIG
            .replace("public_base = \"\"", "public_base = \"https://lfs.example.com/\"");

        let config = load(&contents, &[]).expect("合法配置");

        assert_eq!(config.server.public_base, "https://lfs.example.com");
    }

    #[test]
    fn given_invalid_runtime_env_when_load_then_rejected() {
        let message = load_error(VALID_CONFIG, &[("NETDISK_LFS_ENV", "staging")]);

        assert!(message.contains("NETDISK_LFS_ENV"), "实际错误：{message}");
    }

    #[test]
    fn given_explicit_registration_fields_when_load_then_parsed() {
        let anchor = "[accounts]\ndb = \"/var/lib/netdisk-lfs/accounts.db\"";
        let contents = VALID_CONFIG.replace(
            anchor,
            &format!(
                "{anchor}\nregistration = \"open\"\ndefault_role = \"readonly\"\nregistration_per_hour = 0\nlogin_failures_per_5min = 3\ntrust_proxy = true"
            ),
        );

        let config = load(&contents, &[]).expect("显式注册配置应合法");

        assert_eq!(config.accounts.registration, RegistrationPolicy::Open);
        assert_eq!(config.accounts.default_role, Role::Readonly);
        assert_eq!(config.accounts.registration_per_hour, 0, "0 = 不限");
        assert_eq!(config.accounts.login_failures_per_5min, 3);
        assert!(config.accounts.trust_proxy);
    }

    #[test]
    fn given_unknown_registration_policy_when_load_then_rejected() {
        let anchor = "[accounts]\ndb = \"/var/lib/netdisk-lfs/accounts.db\"";
        let contents =
            VALID_CONFIG.replace(anchor, &format!("{anchor}\nregistration = \"invite\""));

        let message = load_error(&contents, &[]);

        assert!(message.contains("registration"), "实际错误：{message}");
    }

    #[test]
    fn given_admin_default_role_when_load_then_rejected() {
        let anchor = "[accounts]\ndb = \"/var/lib/netdisk-lfs/accounts.db\"";
        let contents = VALID_CONFIG.replace(anchor, &format!("{anchor}\ndefault_role = \"admin\""));

        let message = load_error(&contents, &[]);

        assert!(message.contains("default_role"), "实际错误：{message}");
        assert!(message.contains("admin"), "实际错误：{message}");
    }
}

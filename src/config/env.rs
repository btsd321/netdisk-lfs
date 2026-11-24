//! 环境变量快照：进程环境与 `.env` 文件的合并结果。
//!
//! 配置解析只依赖一个显式的 [`EnvSource`]，不直接读进程环境，因此单测无需修改全局状态
//! （Rust 2024 中 `std::env::set_var` 是 `unsafe`，本仓库 `unsafe_code = "forbid"`）。

use std::collections::HashMap;
use std::path::{Path, PathBuf};

use crate::config::error::ConfigError;

/// `.env` 契约中的四个键，键名语义见 `plans/2026-11-24-execution-plan.md`。
pub(crate) const BDPAN_BIN: &str = "BDPAN_BIN";
pub(crate) const NETDISK_LFS_CONFIG: &str = "NETDISK_LFS_CONFIG";
pub(crate) const NETDISK_LFS_DATA_DIR: &str = "NETDISK_LFS_DATA_DIR";
pub(crate) const NETDISK_LFS_ENV: &str = "NETDISK_LFS_ENV";

/// 进程环境与 `.env` 的只读合并结果，进程环境优先。
#[derive(Debug, Default, Clone)]
pub(crate) struct EnvSource {
    vars: HashMap<String, String>,
}

impl EnvSource {
    /// 读取进程环境，并用 `dotenv_path` 中缺失的键补齐；`.env` 不存在不算错误。
    ///
    /// `dotenv_path` 按原样读取（通常是工作目录下的 `.env`），不向父目录回溯。
    ///
    /// 只解析文件、不修改进程环境，避免全局副作用影响测试与后续库调用。
    pub(crate) fn load(dotenv_path: &Path) -> Result<Self, ConfigError> {
        // 跳过非 UTF-8 的环境变量：vars() 遇到它们会 panic，而本模块
        // 只消费少量 ASCII 键，忽略个别异常项比未类型化的启动崩溃更可接受。
        let mut vars: HashMap<String, String> = std::env::vars_os()
            .filter_map(|(key, value)| Some((key.into_string().ok()?, value.into_string().ok()?)))
            .collect();
        for (key, value) in read_dotenv(dotenv_path)? {
            vars.entry(key).or_insert(value);
        }
        Ok(Self { vars })
    }

    /// 用给定的键值对构造快照；只在测试里构造受控环境。
    #[cfg(test)]
    pub(crate) fn from_pairs(pairs: &[(&str, &str)]) -> Self {
        let vars =
            pairs.iter().map(|(key, value)| ((*key).to_owned(), (*value).to_owned())).collect();
        Self { vars }
    }

    /// 取原始字符串；空值按「未设置」处理，避免误把空路径当成合法配置。
    pub(crate) fn get(&self, key: &str) -> Option<&str> {
        self.vars.get(key).map(String::as_str).filter(|value| !value.is_empty())
    }

    /// 取路径类变量；空值同样视为未设置。
    pub(crate) fn path(&self, key: &str) -> Option<PathBuf> {
        self.get(key).map(PathBuf::from)
    }
}

/// 解析 `.env` 文件；文件不存在时返回空列表。
///
/// 只认给定路径，不向父目录查找：避免从工作目录之外意外读到另一个项目的 `.env`。
fn read_dotenv(path: &Path) -> Result<Vec<(String, String)>, ConfigError> {
    let entries = match dotenvy::from_path_iter(path) {
        Ok(entries) => entries,
        Err(err) if err.not_found() => return Ok(Vec::new()),
        Err(err) => {
            return Err(ConfigError::Dotenv { path: path.to_path_buf(), message: err.to_string() });
        },
    };

    entries
        .map(|entry| {
            entry.map_err(|err| ConfigError::Dotenv {
                path: path.to_path_buf(),
                message: err.to_string(),
            })
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::{EnvSource, NETDISK_LFS_DATA_DIR};
    use crate::config::error::ConfigError;
    use crate::test_support::TempDir;

    #[test]
    fn given_dotenv_with_comments_and_quotes_when_load_then_values_are_trimmed() {
        // 用测试专用键名，避免断言受宿主进程环境（如 CI 导出的同名变量）影响。
        let dir = TempDir::new("netdisk-lfs-dotenv");
        let path = dir.write(
            ".env",
            "# 本机数据目录\nNETDISK_LFS_TEST_TRIM_A=\"/tmp/netdisk-lfs-data\"\nNETDISK_LFS_TEST_TRIM_B=dev\n",
        );

        let env = EnvSource::load(&path).expect("加载 .env");

        assert_eq!(env.get("NETDISK_LFS_TEST_TRIM_A"), Some("/tmp/netdisk-lfs-data"));
        assert_eq!(env.get("NETDISK_LFS_TEST_TRIM_B"), Some("dev"));
    }

    #[test]
    fn given_missing_dotenv_when_load_then_succeeds_without_values() {
        let dir = TempDir::new("netdisk-lfs-dotenv-missing");
        let env = EnvSource::load(&dir.path().join(".env")).expect("缺失 .env 不报错");

        assert_eq!(env.get("NETDISK_LFS_TEST_NEVER_SET"), None);
    }

    #[test]
    fn given_same_key_in_process_and_dotenv_when_load_then_process_wins() {
        // PATH 一定存在于进程环境；用同名键验证优先级，不修改任何全局状态。
        let dir = TempDir::new("netdisk-lfs-dotenv-precedence");
        let path = dir.write(".env", "PATH=/dotenv/should/not/win\n");
        let expected = std::env::var("PATH").expect("进程环境存在 PATH");

        let env = EnvSource::load(&path).expect("加载 .env");

        assert_eq!(env.get("PATH"), Some(expected.as_str()));
    }

    #[test]
    fn given_malformed_dotenv_line_when_load_then_reports_path() {
        let dir = TempDir::new("netdisk-lfs-dotenv-malformed");
        let path = dir.write(".env", "THIS LINE IS NOT A PAIR\n");

        let err = EnvSource::load(&path).expect_err("非法行应报错");

        assert!(matches!(err, ConfigError::Dotenv { .. }), "实际错误：{err}");
    }

    #[test]
    fn given_dotenv_in_parent_only_when_load_child_path_then_not_inherited() {
        let dir = TempDir::new("netdisk-lfs-dotenv-parent");
        dir.write(".env", "NETDISK_LFS_TEST_PARENT_ONLY=should-not-leak\n");
        let child_dir = dir.path().join("child");
        std::fs::create_dir_all(&child_dir).expect("创建子目录");

        let env = EnvSource::load(&child_dir.join(".env")).expect("缺失 .env 不报错");

        assert_eq!(env.get("NETDISK_LFS_TEST_PARENT_ONLY"), None);
    }

    #[test]
    fn given_empty_value_when_get_then_treated_as_unset() {
        let env = EnvSource::from_pairs(&[(NETDISK_LFS_DATA_DIR, "")]);

        assert_eq!(env.get(NETDISK_LFS_DATA_DIR), None);
        assert_eq!(env.path(NETDISK_LFS_DATA_DIR), None);
    }
}

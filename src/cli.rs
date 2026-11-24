//! 启动参数。

use std::path::PathBuf;

use clap::Parser;

use netdisk_lfs::{EnvSource, NETDISK_LFS_CONFIG};

/// 缺省配置文件路径；环境变量与 `--config` 都未提供时使用。
const DEFAULT_CONFIG_PATH: &str = "config.toml";

/// 命令行参数；目前只有配置文件路径。
#[derive(Debug, Parser)]
#[command(name = "netdisk-lfs", version, about = "自建 Git LFS 服务端，对象存储后端为百度网盘")]
pub(crate) struct Cli {
    /// 配置文件路径（TOML）；缺省取环境变量 NETDISK_LFS_CONFIG，再缺省为 ./config.toml
    #[arg(long, value_name = "FILE")]
    config: Option<PathBuf>,
}

impl Cli {
    /// 解析最终配置文件路径：`--config` > `NETDISK_LFS_CONFIG` > `./config.toml`。
    pub(crate) fn config_path(&self, env: &EnvSource) -> PathBuf {
        self.config
            .clone()
            .or_else(|| env.path(NETDISK_LFS_CONFIG))
            .unwrap_or_else(|| PathBuf::from(DEFAULT_CONFIG_PATH))
    }
}

#[cfg(test)]
mod tests {
    use super::{Cli, DEFAULT_CONFIG_PATH};
    use netdisk_lfs::{EnvSource, NETDISK_LFS_CONFIG};

    use clap::Parser;
    use std::path::PathBuf;

    #[test]
    fn given_config_arg_when_resolve_then_cli_wins() {
        let cli = Cli::parse_from(["netdisk-lfs", "--config", "/etc/netdisk-lfs/config.toml"]);
        let env = EnvSource::from_pairs(&[(NETDISK_LFS_CONFIG, "/tmp/env.toml")]);

        assert_eq!(cli.config_path(&env), PathBuf::from("/etc/netdisk-lfs/config.toml"));
    }

    #[test]
    fn given_env_config_when_no_arg_then_env_used() {
        let cli = Cli::parse_from(["netdisk-lfs"]);
        let env = EnvSource::from_pairs(&[(NETDISK_LFS_CONFIG, "/tmp/env.toml")]);

        assert_eq!(cli.config_path(&env), PathBuf::from("/tmp/env.toml"));
    }

    #[test]
    fn given_nothing_when_resolve_then_default_path() {
        let cli = Cli::parse_from(["netdisk-lfs"]);

        assert_eq!(cli.config_path(&EnvSource::default()), PathBuf::from(DEFAULT_CONFIG_PATH));
    }
}

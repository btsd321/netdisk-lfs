//! 入库的 `config.toml.example` 必须始终能被**真实配置解析器**接受。
//!
//! 比 `tomllib.load()` 更强：`Config` 的 `deny_unknown_fields` 会抓出拼错的键，
//! 语义校验会抓出「远程路径不在 /apps/bdpan/ 下」「上限为 0」这类错误。示例文件
//! 一旦与 `src/config/model.rs` 脱节，这里立刻失败——比等到部署时才发现好。
//!
//! 同时锁定部署形态的关键取值（listen、objects_root、缓存预算等），避免有人「顺手
//! 调整」示例里的值却没同步 docs/deploy.md。

use std::path::Path;

use netdisk_lfs::{Config, EnvSource, Role};

fn example_path() -> std::path::PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("config.toml.example")
}

#[test]
fn given_shipped_example_when_loaded_then_valid_and_deploy_shaped() {
    let config = Config::load_with(&example_path(), &EnvSource::from_pairs(&[]))
        .expect("config.toml.example 必须能被真实配置解析器加载");

    assert_eq!(config.server.listen.to_string(), "127.0.0.1:9001", "只监听回环");
    assert_eq!(config.server.public_base, "", "留空时按请求 Host/协议推导绝对 href");
    assert_eq!(config.storage.objects_root, "/apps/bdpan/lfs");
    assert_eq!(config.storage.tmp_root, "/apps/bdpan/lfs/tmp");
    assert_eq!(config.storage.bdpan_bin, Path::new("/home/lixinlong/.local/bin/bdpan"));
    assert_eq!(config.storage.max_object_bytes, 0, "0 = 不限制单对象大小");
    assert_eq!(config.storage.max_bdpan_procs, 4);
    assert_eq!(config.storage.bdpan_timeout_secs, 300, "非传输/启动宽限 5 分钟");
    assert_eq!(
        config.storage.bdpan_min_throughput_bytes_per_sec, 102_400,
        "传输按 100 KiB/s 下限推导超时"
    );
    assert_eq!(config.cache.dir, Path::new("/var/lib/netdisk-lfs/cache"));
    assert_eq!(config.cache.max_bytes, 214_748_364_800, "缓存预算 200 GiB");
    assert_eq!(config.auth.users.len(), 2, "示例给一个读写、一个只读账号");
    assert_eq!(config.auth.users["maintainer"].role, Role::Readwrite);
    assert_eq!(config.auth.users["reader"].role, Role::Readonly);
}

#[test]
fn given_shipped_example_when_reading_hashes_then_they_are_sha256_hex_placeholders() {
    let config =
        Config::load_with(&example_path(), &EnvSource::from_pairs(&[])).expect("示例必须可加载");

    for (name, user) in &config.auth.users {
        assert_eq!(
            user.password_sha256.len(),
            64,
            "auth.users.{name}.password_sha256 必须是 64 个十六进制字符（sha256 摘要）"
        );
        assert!(
            user.password_sha256.bytes().all(|byte| byte.is_ascii_hexdigit()),
            "auth.users.{name}.password_sha256 含非十六进制字符"
        );
    }
}

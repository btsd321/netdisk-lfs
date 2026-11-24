//! `/metrics`：Prometheus 文本格式（零新依赖，手写 exposition format）。
//!
//! 只暴露缓存维度的几个指标——它们回答了运维最关心的两个问题：缓存有没有起作用
//! （hits/misses）、预算够不够（used_bytes / max_bytes / evictions）。
//!
//! **无认证**：与 `/healthz` 一样挂在认证层之外，供本机 Prometheus/脚本抓取。服务只
//! 监听 `127.0.0.1`（`specs/architecture.md`「部署」），外部访问一律经反向代理；若要
//! 把它暴露到公网，必须在反代上加 ACL（或单独的抓取凭据）——metrics 会泄露缓存的
//! 容量与命中情况。
//!
//! 格式约束（Prometheus 文档）：每个指标先 `# HELP` 再 `# TYPE`，随后是
//! `<name> <value>`；`_total` 后缀表示只增计数器，gauge 是可增可减的瞬时值。

use axum::body::Body;
use axum::extract::State;
use axum::http::Response;
use axum::http::header::{self, HeaderValue};

use crate::cache::Cache;
use crate::http::AppState;

/// Prometheus 文本格式的媒体类型；版本号写死 `0.0.4`，抓取端据此选解析器。
const CONTENT_TYPE: &str = "text/plain; version=0.0.4; charset=utf-8";

/// `/metrics` 的 handler。
pub(crate) async fn metrics(State(state): State<AppState>) -> Response<Body> {
    render(state.cache())
}

/// 把缓存指标渲染成 Prometheus 文本响应。
fn render(cache: &Cache) -> Response<Body> {
    let mut out = String::with_capacity(1024);
    // 对象数：`len()` 是进程内索引计数，启动扫描后与磁盘一致。
    push(
        &mut out,
        "netdisk_lfs_cache_objects",
        "gauge",
        "Objects tracked in the local disk cache.",
        count(cache.len()),
    );
    push(
        &mut out,
        "netdisk_lfs_cache_used_bytes",
        "gauge",
        "Bytes currently accounted to cached objects.",
        cache.used_bytes(),
    );
    push(
        &mut out,
        "netdisk_lfs_cache_max_bytes",
        "gauge",
        "Configured cache budget in bytes.",
        cache.max_bytes(),
    );
    push(
        &mut out,
        "netdisk_lfs_cache_hits_total",
        "counter",
        "Cache lookups served from disk.",
        cache.hits_total(),
    );
    push(
        &mut out,
        "netdisk_lfs_cache_misses_total",
        "counter",
        "Cache lookups that required a backend fetch.",
        cache.misses_total(),
    );
    push(
        &mut out,
        "netdisk_lfs_cache_evictions_total",
        "counter",
        "Cached objects deleted by LRU eviction.",
        cache.evictions_total(),
    );

    let mut response = Response::new(Body::from(out));
    response.headers_mut().insert(header::CONTENT_TYPE, HeaderValue::from_static(CONTENT_TYPE));
    response
}

/// 追加一个指标：`# HELP`、`# TYPE` 与样本行。
fn push(out: &mut String, name: &str, kind: &str, help: &str, value: u64) {
    out.push_str(&format!("# HELP {name} {help}\n# TYPE {name} {kind}\n{name} {value}\n"));
}

/// `usize` → `u64`；64 位平台上恒等，32 位平台也不会截断。
fn count(value: usize) -> u64 {
    u64::try_from(value).unwrap_or(u64::MAX)
}

#[cfg(test)]
mod tests {
    use super::{CONTENT_TYPE, render};
    use crate::cache::Cache;
    use crate::config::CacheConfig;
    use crate::test_support::TempDir;

    #[tokio::test]
    async fn given_empty_cache_when_render_then_all_six_metrics_with_zero_values() {
        let workspace = TempDir::new("netdisk-lfs-metrics");
        let config = CacheConfig { dir: workspace.path().join("cache"), max_bytes: 4096 };
        let cache = Cache::open(&config).await;

        let response = render(&cache);
        assert_eq!(response.headers()["content-type"], CONTENT_TYPE);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024).await.expect("读取响应体");
        let text = String::from_utf8(body.to_vec()).expect("指标必须是 UTF-8");

        for name in [
            "netdisk_lfs_cache_objects",
            "netdisk_lfs_cache_used_bytes",
            "netdisk_lfs_cache_max_bytes",
            "netdisk_lfs_cache_hits_total",
            "netdisk_lfs_cache_misses_total",
            "netdisk_lfs_cache_evictions_total",
        ] {
            assert!(text.contains(&format!("# TYPE {name} ")), "缺少 TYPE 行：{name}");
            assert!(text.contains(&format!("\n{name} ")), "缺少样本行：{name}");
        }
        assert!(text.contains("netdisk_lfs_cache_max_bytes 4096"), "预算取自配置：{text}");
        assert!(text.contains("netdisk_lfs_cache_objects 0"));
        assert!(text.ends_with('\n'), "Prometheus 文本以换行结束");
    }
}

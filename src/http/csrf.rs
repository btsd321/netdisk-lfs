//! 会话 Cookie 的跨站写守卫，以及管理员端点复用的同站判定。
//!
//! 会话 Cookie 会被浏览器**自动**附带到同站与跨站的表单 POST 上，而恶意页面不需要
//! 读到响应就能让浏览器替它提交（`<form action="https://lfs.example.com/account/password">`）。
//! 因此凡是「带会话 Cookie 且会改状态」的请求，都要先过同站校验。
//!
//! 判定顺序（`Sec-Fetch-Site` 优先于 `Origin`）：
//!
//! 1. `Sec-Fetch-Site` 存在时只认 `same-origin` / `same-site` / `none`：现代浏览器一定
//!    会带它，页面脚本无法伪造；`none` 是用户在地址栏直接输入的情况；
//! 2. 否则看 `Origin`：与请求 `Host` 的主机名比对（忽略 scheme 与端口——反代可能换
//!    端口或终结 TLS），不一致即拒绝；
//! 3. 两者都没有（curl / CLI / 老客户端）**放行**：这类客户端不会自动附带凭据，
//!    不存在 CSRF 面，挡掉它们只会误伤脚本。
//!
//! 管理员端点（`admin::require_admin`）对 Basic 请求复用同一套判定：Basic 凭据是
//! 浏览器的「环境凭据」，同样会被跨站表单借用。

use axum::extract::Request;
use axum::http::header::{HOST, ORIGIN};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::middleware::Next;
use axum::response::Response;

use super::RequestId;
use super::error::ApiError;
use super::html::{escape_html, html_response, wants_html};
use super::layout;
use super::session;

/// 跨站写请求的拒绝文案：说清「为什么」以及「怎么改」，不泄漏任何账户信息。
const CROSS_SITE_MESSAGE: &str =
    "拒绝跨站写请求：带会话 Cookie 的写操作只接受本站页面或明确的 API 客户端";

/// 全局会话 CSRF 守卫。
///
/// 挂在 `router` 上，位于请求级 span 之内（要用它注入的 request id）、路由处理之外
/// （在认证之前就挡掉跨站写）。只对「带会话 Cookie 的写请求」生效：无 Cookie 的
/// Basic 请求由管理员端点自己的同站校验负责，两者规则相同、互不重复判定。
pub(crate) async fn guard(request: Request, next: Next) -> Response {
    // 先判完再进入异步：`&request` 的借用不能跨 `.await`（`Request<Body>` 不是 `Sync`）。
    let reason =
        if is_write_method(request.method()) && session::has_session_cookie(request.headers()) {
            cross_site_reason(request.headers())
        } else {
            None
        };
    let Some(reason) = reason else {
        return next.run(request).await;
    };

    let request_id =
        request.extensions().get::<RequestId>().cloned().unwrap_or_else(RequestId::generate);
    let html_page = wants_html(request.headers());
    tracing::warn!(
        request_id = %request_id,
        method = %request.method(),
        path = %request.uri().path(),
        reason,
        "拒绝跨站会话写请求"
    );
    forbidden(&request_id, html_page, CROSS_SITE_MESSAGE)
}

/// 403：浏览器给页面，脚本客户端给统一 JSON 错误体（与管理员端点同一形态）。
///
/// `pub(crate)`：登录端点（`POST /login`）自己没有会话 Cookie，全局守卫覆盖不到，
/// 它还要用同一形态的 403 页，不能另写一份文案与样式。
pub(crate) fn forbidden(request_id: &RequestId, html_page: bool, message: &str) -> Response {
    if html_page {
        let body = format!(
            r#"<p class="alert" role="alert">{}</p><p class="note">请求 id：{}</p>"#,
            escape_html(message),
            escape_html(request_id.as_str())
        );
        html_response(
            StatusCode::FORBIDDEN,
            layout::public_page("禁止访问", "跨站请求不会被执行。", &body),
        )
    } else {
        // 与管理员端点同样的错误体与状态码，脚本客户端只认一种形态。
        ApiError::Forbidden(message.to_owned()).into_response_with(request_id)
    }
}

/// 会改状态的方法；读方法不参与同站校验（跨站读没有 CORS 头也读不到内容）。
pub(crate) fn is_write_method(method: &Method) -> bool {
    !matches!(*method, Method::GET | Method::HEAD | Method::OPTIONS)
}

/// 跨站写请求的原因；`None` 表示可以放行。
///
/// `Sec-Fetch-Site` 优先于 `Origin`：现代浏览器一定会带前者，它无法被页面脚本
/// 伪造；`Origin` 是给不带 Fetch Metadata 的客户端的兜底。
pub(crate) fn cross_site_reason(headers: &HeaderMap) -> Option<&'static str> {
    if let Some(site) = headers.get("sec-fetch-site").and_then(|value| value.to_str().ok()) {
        return match site.trim().to_ascii_lowercase().as_str() {
            "same-origin" | "same-site" | "none" => None,
            _ => Some("sec_fetch_site"),
        };
    }
    let origin = headers.get(ORIGIN).and_then(|value| value.to_str().ok())?;
    let origin_host = authority_host(origin);
    let request_host =
        headers.get(HOST).and_then(|value| value.to_str().ok()).and_then(authority_host);
    match (origin_host, request_host) {
        (Some(origin_host), Some(request_host)) if origin_host == request_host => None,
        _ => Some("origin_mismatch"),
    }
}

/// 从 `Origin` / `Host` 值里取主机名：去掉 scheme、路径与端口，IPv6 保留方括号。
///
/// 用字符串处理而不是 `http::Uri` 解析：`Origin` 允许 `null` 这类不是 URI 的值，
/// 而这里只需要「两边的主机名写法是否一致」，越简单越不容易在某些取值上意外 panic。
fn authority_host(value: &str) -> Option<String> {
    let rest = value.split_once("://").map_or(value, |(_, rest)| rest);
    let authority = rest.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    let host = if let Some(stripped) = authority.strip_prefix('[') {
        let end = stripped.find(']')?;
        format!("[{}]", &stripped[..end])
    } else {
        authority.rsplit_once(':').map_or(authority, |(host, _)| host).to_owned()
    };
    (!host.is_empty()).then(|| host.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

    use super::{authority_host, cross_site_reason, is_write_method};
    use axum::http::Method;

    fn headers(pairs: &[(&str, &str)]) -> HeaderMap {
        let mut map = HeaderMap::new();
        for (name, value) in pairs {
            map.insert(
                HeaderName::from_bytes(name.as_bytes()).expect("头名合法"),
                HeaderValue::from_str(value).expect("头值合法"),
            );
        }
        map
    }

    #[test]
    fn given_method_when_is_write_method_then_only_reads_pass() {
        for method in [Method::GET, Method::HEAD, Method::OPTIONS] {
            assert!(!is_write_method(&method), "{method} 是读方法");
        }
        for method in [Method::POST, Method::PUT, Method::PATCH, Method::DELETE] {
            assert!(is_write_method(&method), "{method} 会改状态");
        }
    }

    #[test]
    fn given_sec_fetch_site_when_cross_site_reason_then_only_same_site_values_pass() {
        for site in ["same-origin", "same-site", "none", "SAME-ORIGIN"] {
            let map = headers(&[("sec-fetch-site", site)]);
            assert_eq!(cross_site_reason(&map), None, "{site} 应放行");
        }
        for site in ["cross-site", "bogus"] {
            let map = headers(&[("sec-fetch-site", site)]);
            assert_eq!(cross_site_reason(&map), Some("sec_fetch_site"), "{site:?} 应拒绝");
        }
        // 头值前后的空白不算跨站（代理可能补空格）。
        let map = headers(&[("sec-fetch-site", " same-origin ")]);
        assert_eq!(cross_site_reason(&map), None);
        // Sec-Fetch-Site 优先于 Origin：即使 Origin 同源也不再看。
        let map = headers(&[
            ("sec-fetch-site", "cross-site"),
            ("origin", "https://lfs.test"),
            ("host", "lfs.test"),
        ]);
        assert_eq!(cross_site_reason(&map), Some("sec_fetch_site"));
    }

    #[test]
    fn given_origin_and_host_when_cross_site_reason_then_compares_host_only() {
        // 同主机名不同 scheme/端口：反代换端口、终结 TLS 都属正常。
        let map = headers(&[("origin", "http://lfs.test:9001"), ("host", "lfs.test")]);
        assert_eq!(cross_site_reason(&map), None);

        let map = headers(&[("origin", "https://LFS.TEST"), ("host", "lfs.test:9001")]);
        assert_eq!(cross_site_reason(&map), None);

        // 跨站来源一律拒绝。
        let map = headers(&[("origin", "https://evil.example"), ("host", "lfs.test")]);
        assert_eq!(cross_site_reason(&map), Some("origin_mismatch"));

        // Origin 有、Host 缺失：无法比对，按拒绝处理（fail closed）。
        let map = headers(&[("origin", "https://lfs.test")]);
        assert_eq!(cross_site_reason(&map), Some("origin_mismatch"));

        // 两者都没有：curl/CLI，放行。
        assert_eq!(cross_site_reason(&HeaderMap::new()), None);
    }

    #[test]
    fn given_authority_values_when_authority_host_then_host_only() {
        assert_eq!(authority_host("https://lfs.test:9001/path"), Some("lfs.test".to_owned()));
        assert_eq!(authority_host("lfs.test:9001"), Some("lfs.test".to_owned()));
        assert_eq!(authority_host("LFS.Test"), Some("lfs.test".to_owned()));
        // IPv6 保留方括号，端口照旧剥掉。
        assert_eq!(authority_host("http://[::1]:9001"), Some("[::1]".to_owned()));
        assert_eq!(authority_host("null"), Some("null".to_owned()));
        assert_eq!(authority_host(""), None);
        assert_eq!(authority_host("http://"), None);
        assert_eq!(authority_host("http://[::1"), None);
    }
}

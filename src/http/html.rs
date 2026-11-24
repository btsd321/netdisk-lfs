//! 极简 HTML 渲染与表单解析：注册页与管理员页共用。
//!
//! 不引模板引擎、不加载任何外部资源、页面里没有一行脚本：页面全靠字符串拼接。
//! 正因如此，**所有**动态文本都必须先经 [`escape_html`]。
//!
//! 表单一律用 `application/x-www-form-urlencoded`，与查询串同源，所以
//! [`parse_form`] 也用来解析 `?status=` 这类查询参数。

use std::collections::HashMap;

use axum::body::Body;
use axum::http::header::CONTENT_TYPE;
use axum::http::{HeaderValue, StatusCode};
use axum::response::Response;

use super::error::ApiError;

/// 页面样式：只做可读性，不引外部资源（离线可用、无追踪）。
///
/// 注册页与管理员页共用一份：体量不值得拆，也不值得为此引一个 CSS 依赖。
pub(crate) const PAGE_STYLE: &str = r#"
body { font-family: system-ui, -apple-system, "Segoe UI", sans-serif; margin: 2.5rem auto;
       max-width: 48rem; padding: 0 1rem; line-height: 1.6; color: #1f2328; }
h1 { font-size: 1.4rem; margin-bottom: .5rem; }
p { margin: .5rem 0; }
form { display: grid; gap: .85rem; margin: 1rem 0; max-width: 32rem; }
label { display: grid; gap: .3rem; font-size: .95rem; }
input { padding: .5rem; border: 1px solid #d0d7de; border-radius: .375rem; font-size: 1rem; }
button { padding: .55rem 1rem; border: 0; border-radius: .375rem; background: #1f6feb;
         color: #fff; font-size: 1rem; cursor: pointer; }
button.danger { background: #b42318; }
.hint { color: #59636e; font-size: .9rem; }
.error { color: #b42318; }
nav.filters { display: flex; flex-wrap: wrap; gap: .75rem; margin: 1rem 0; font-size: .9rem; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: .9rem; }
th, td { border-bottom: 1px solid #d0d7de; padding: .4rem .5rem; text-align: left;
         vertical-align: top; }
th { font-weight: 600; white-space: nowrap; }
.actions { display: flex; flex-wrap: wrap; gap: .35rem; align-items: center; }
.actions form { display: inline-flex; gap: .25rem; align-items: center; margin: 0;
                max-width: none; }
.actions select, .actions input[type="password"] { padding: .3rem; font-size: .85rem; }
.actions button { padding: .3rem .6rem; font-size: .85rem; }
label.inline { display: inline-flex; align-items: center; gap: .25rem; font-size: .85rem; }
"#;

/// HTML 转义：`&` 最先替换，避免把后续生成的实体二次转义。
pub(crate) fn escape_html(raw: &str) -> String {
    let mut escaped = String::with_capacity(raw.len());
    for character in raw.chars() {
        match character {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#39;"),
            other => escaped.push(other),
        }
    }
    escaped
}

/// 页面外壳：内联样式，不引外部资源，不含任何脚本。
pub(crate) fn page_shell(title: &str, body: &str) -> String {
    format!(
        r#"<!doctype html>
<html lang="zh-CN">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} · netdisk-lfs</title>
<style>{PAGE_STYLE}</style>
</head>
<body>
<main>
{body}
</main>
</body>
</html>
"#,
        title = escape_html(title),
        body = body,
    )
}

/// 构造 HTML 响应（`text/html; charset=utf-8`）。
pub(crate) fn html_response(status: StatusCode, body: String) -> Response {
    let mut response = Response::new(Body::from(body));
    response
        .headers_mut()
        .insert(CONTENT_TYPE, HeaderValue::from_static("text/html; charset=utf-8"));
    *response.status_mut() = status;
    response
}

/// 解析 `application/x-www-form-urlencoded`：`&` 分隔、`=` 切分、`+` 与 `%XX` 解码。
///
/// 同名键取第一次出现的值（浏览器不会重复提交同一个控件），避免后出现的值覆盖
/// 前面的校验结果。
pub(crate) fn parse_form(body: &str) -> Result<HashMap<String, String>, ApiError> {
    let mut fields = HashMap::new();
    for pair in body.split('&').filter(|pair| !pair.is_empty()) {
        let (raw_key, raw_value) = pair.split_once('=').unwrap_or((pair, ""));
        let key = percent_decode(raw_key)?;
        let value = percent_decode(raw_value)?;
        fields.entry(key).or_insert(value);
    }
    Ok(fields)
}

/// 百分号与 `+` 解码；非法转义或非 UTF-8 都报 400。
pub(crate) fn percent_decode(raw: &str) -> Result<String, ApiError> {
    let bytes = raw.as_bytes();
    let mut decoded = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'+' => {
                decoded.push(b' ');
                index += 1;
            },
            b'%' => {
                let pair = bytes
                    .get(index + 1..index + 3)
                    .ok_or_else(|| ApiError::BadRequest("表单转义不完整".to_owned()))?;
                let pair = std::str::from_utf8(pair)
                    .map_err(|_| ApiError::BadRequest("表单转义不是十六进制".to_owned()))?;
                let byte = u8::from_str_radix(pair, 16)
                    .map_err(|_| ApiError::BadRequest("表单转义不是十六进制".to_owned()))?;
                decoded.push(byte);
                index += 3;
            },
            byte => {
                decoded.push(byte);
                index += 1;
            },
        }
    }
    String::from_utf8(decoded).map_err(|_| ApiError::BadRequest("表单不是合法的 UTF-8".to_owned()))
}

#[cfg(test)]
mod tests {
    use super::{escape_html, parse_form, percent_decode};

    #[test]
    fn given_html_special_chars_when_escape_then_entities() {
        assert_eq!(
            escape_html("<script>alert(1)</script>"),
            "&lt;script&gt;alert(1)&lt;/script&gt;"
        );
        assert_eq!(escape_html("a & b \"c\" 'd'"), "a &amp; b &quot;c&quot; &#39;d&#39;");
        // & 必须先替换，否则会二次转义成 &amp;lt;
        assert_eq!(escape_html("&lt;"), "&amp;lt;");
    }

    #[test]
    fn given_urlencoded_body_when_parse_then_fields_decoded() {
        let fields = parse_form("username=Alice_01&password=a%2Bb+c&confirm_password=a%2Bb+c")
            .expect("合法表单");

        assert_eq!(fields["username"], "Alice_01");
        assert_eq!(fields["password"], "a+b c");
        assert_eq!(fields["confirm_password"], "a+b c");
    }

    #[test]
    fn given_duplicate_key_when_parse_then_first_wins() {
        let fields = parse_form("username=alice&username=bob").expect("合法表单");

        assert_eq!(fields["username"], "alice");
    }

    #[test]
    fn given_broken_percent_escape_when_decode_then_bad_request() {
        assert!(percent_decode("%2").is_err(), "不完整的转义应被拒");
        assert!(percent_decode("%zz").is_err(), "非十六进制应被拒");
        assert!(percent_decode("%ff").is_err(), "非 UTF-8 字节应被拒");
        assert_eq!(percent_decode("a%20b").expect("合法转义"), "a b");
    }
}

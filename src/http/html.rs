//! 极简 HTML 渲染与表单解析：注册页与管理员页共用。
//!
//! 不引模板引擎、不加载任何外部资源、页面里没有一行脚本：页面全靠字符串拼接。
//! 正因如此，**所有**动态文本都必须先经 [`escape_html`]；[`table`] 的单元格是
//! 「已渲染的 HTML 片段」（按钮、表单等），转义责任在调用方——纯文本单元格请传
//! `escape_html(text)`，不要直接把用户输入塞进去。
//!
//! 表单一律用 `application/x-www-form-urlencoded`，与查询串同源，所以
//! [`parse_form`] 也用来解析 `?status=` 这类查询参数。

use std::collections::HashMap;

use axum::body::Body;
use axum::http::header::{ACCEPT, CONTENT_TYPE, LOCATION};
use axum::http::{HeaderMap, HeaderValue, StatusCode};
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
nav.filters, nav.pager { display: flex; flex-wrap: wrap; gap: .75rem; margin: 1rem 0;
                           font-size: .9rem; }
table { width: 100%; border-collapse: collapse; margin-top: 1rem; font-size: .9rem; }
th, td { border-bottom: 1px solid #d0d7de; padding: .4rem .5rem; text-align: left;
         vertical-align: top; }
th { font-weight: 600; white-space: nowrap; }
pre { background: #f6f8fa; padding: .75rem; border-radius: .375rem; overflow-x: auto;
      font-size: .9rem; }
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

/// 请求是否期望 HTML 响应：`Accept` 头里带 `text/html` 就按浏览器处理。
///
/// 只有「错误该回 JSON 还是 HTML」需要这个判断（例如 403）：同一路径上既有脚本
/// 客户端也有浏览器的表单提交，按 `Accept` 分流比按路径猜更准。
pub(crate) fn wants_html(headers: &HeaderMap) -> bool {
    headers
        .get(ACCEPT)
        .and_then(|value| value.to_str().ok())
        .is_some_and(|value| value.to_ascii_lowercase().contains("text/html"))
}

/// 303 See Other：浏览器按 GET 跟随目标，不会把原来的 POST 再提交一次。
///
/// 回跳地址由本服务构造（登录页的 `?next=` 只保留站内路径），正常情况下一定合法；
/// 万一不是合法头值（含控制字符等）就只记日志、不发 `Location`——宁可少一个跳转，
/// 也不能让脏值进响应头。
pub(crate) fn see_other(location: &str) -> Response {
    let mut response = Response::new(Body::empty());
    *response.status_mut() = StatusCode::SEE_OTHER;
    match HeaderValue::from_str(location) {
        Ok(value) => {
            response.headers_mut().insert(LOCATION, value);
        },
        Err(error) => {
            tracing::error!(location = %location, error = %error, "回跳地址不是合法的响应头值");
        },
    }
    response
}

/// 渲染一张表：表头按纯文本转义，单元格是**已渲染的 HTML 片段**。
///
/// 单元格里要放纯文本时请传 [`escape_html`] 的结果；要放按钮/表单时由调用方拼接
/// 并自行保证其中没有未转义的用户输入。
pub(crate) fn table(headers: &[&str], rows: &[Vec<String>]) -> String {
    let mut html = String::from("<table>\n<thead><tr>");
    for header in headers {
        html.push_str(&format!("<th>{}</th>", escape_html(header)));
    }
    html.push_str("</tr></thead>\n<tbody>\n");
    for row in rows {
        html.push_str("<tr>");
        for cell in row {
            html.push_str(&format!("<td>{cell}</td>"));
        }
        html.push_str("</tr>\n");
    }
    html.push_str("</tbody>\n</table>");
    html
}

/// unix 秒格式化成 `YYYY-MM-DD HH:MM:SS UTC`。
///
/// 页面只需要「人能读的时间」，为此引一个日期库不划算：公历换算用 Howard
/// Hinnant 的 `civil_from_days`，闰年与世纪规则都已包含在整数运算里。
pub(crate) fn format_unix_seconds(seconds: i64) -> String {
    let days = seconds.div_euclid(86_400);
    let rest = seconds.rem_euclid(86_400);
    let (year, month, day) = civil_from_days(days);
    let hour = rest / 3_600;
    let minute = rest % 3_600 / 60;
    let second = rest % 60;
    format!("{year:04}-{month:02}-{day:02} {hour:02}:{minute:02}:{second:02} UTC")
}

/// 1970-01-01 起的天数 → `(年, 月, 日)`；支持 1970 之前的负数天数。
fn civil_from_days(days: i64) -> (i64, i64, i64) {
    // 把纪元挪到 0000-03-01，让闰日落在年末，月份换算就成了线性公式。
    let shifted = days + 719_468;
    let era = if shifted >= 0 { shifted } else { shifted - 146_096 } / 146_097;
    let day_of_era = shifted - era * 146_097;
    let year_of_era =
        (day_of_era - day_of_era / 1_460 + day_of_era / 36_524 - day_of_era / 146_096) / 365;
    let year = year_of_era + era * 400;
    let day_of_year = day_of_era - (365 * year_of_era + year_of_era / 4 - year_of_era / 100);
    let month_prime = (5 * day_of_year + 2) / 153;
    let day = day_of_year - (153 * month_prime + 2) / 5 + 1;
    let month = if month_prime < 10 { month_prime + 3 } else { month_prime - 9 };
    (if month <= 2 { year + 1 } else { year }, month, day)
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
                // 先逐字节校验是 ASCII 十六进制：`u8::from_str_radix` 接受正负号，
                // `%+b` / `%-b` 会被解析成 0x0b / 0x-b 的怪异结果，绕开「非法转义」判断。
                let is_hex = pair.iter().all(u8::is_ascii_hexdigit);
                let byte = if is_hex {
                    u8::from_str_radix(std::str::from_utf8(pair).unwrap_or_default(), 16)
                        .map_err(|_| ApiError::BadRequest("表单转义不是十六进制".to_owned()))?
                } else {
                    return Err(ApiError::BadRequest("表单转义不是十六进制".to_owned()));
                };
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
    use super::{
        civil_from_days, escape_html, format_unix_seconds, parse_form, percent_decode, table,
        wants_html,
    };
    use axum::http::{HeaderMap, HeaderName, HeaderValue};

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
        // `u8::from_str_radix` 会把 `+`/`-` 当符号：带符号的「十六进制」必须被拒，
        // 否则 `%+b` 会被解码成 0x0b 而绕过转义校验。
        assert!(percent_decode("%+b").is_err(), "带符号的转义应被拒");
        assert!(percent_decode("%-b").is_err(), "带负号的转义应被拒");
        assert_eq!(percent_decode("%2B").expect("合法转义"), "+", "%2B 才是加号");
        assert_eq!(percent_decode("a%20b").expect("合法转义"), "a b");
    }

    #[test]
    fn given_unix_seconds_when_format_then_utc_calendar_time() {
        assert_eq!(format_unix_seconds(0), "1970-01-01 00:00:00 UTC");
        // 2026-11-24T12:34:56Z：闰年与世纪规则都落在这条路径上。
        assert_eq!(format_unix_seconds(1_795_523_696), "2026-11-24 12:34:56 UTC");
        // 2000-02-29（闰日）与 2100-03-01（非闰年的世纪年）。
        assert_eq!(format_unix_seconds(951_782_400), "2000-02-29 00:00:00 UTC");
        assert_eq!(format_unix_seconds(4_107_542_400), "2100-03-01 00:00:00 UTC");
        assert_eq!(civil_from_days(0), (1970, 1, 1));
    }

    #[test]
    fn given_headers_when_wants_html_then_checks_accept() {
        let mut headers = HeaderMap::new();
        assert!(!wants_html(&headers), "没有 Accept 按 API 客户端处理");

        headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("application/json"),
        );
        assert!(!wants_html(&headers));

        headers.insert(
            HeaderName::from_static("accept"),
            HeaderValue::from_static("text/html,application/xhtml+xml;q=0.9"),
        );
        assert!(wants_html(&headers), "浏览器表单一定带 text/html");
    }

    #[test]
    fn given_rows_when_table_then_headers_and_cells_rendered() {
        let html = table(
            &["用户名", "操作"],
            &[vec![escape_html("<script>"), "<form></form>".to_owned()]],
        );

        assert!(html.starts_with("<table>"));
        assert!(html.contains("<th>用户名</th>"));
        assert!(html.contains("<td>&lt;script&gt;</td>"), "文本单元格必须已转义：{html}");
        assert!(html.contains("<td><form></form></td>"), "HTML 片段原样输出：{html}");
    }
}

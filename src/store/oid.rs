//! `Oid`：Git LFS 对象的 sha256 标识。

use std::fmt;

use thiserror::Error;

/// 十六进制 oid 的字符数（sha256 摘要 32 字节）。
const OID_HEX_LEN: usize = 64;

/// 对象 id：内容寻址的 sha256 摘要，构造后保证是 64 位小写十六进制。
///
/// 只经 [`Oid::parse`] 构造，所以「长度不对」「混入非十六进制字符」这类错误在进入
/// 存储层之前就被挡住。下游拼接路径、比较哈希时不必再校验一遍——这正是用 newtype
/// 而不是 `String` 的理由。
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Oid(String);

impl Oid {
    /// 解析 oid：接受大写十六进制，统一归一化为小写。
    ///
    /// # Errors
    /// 长度不是 64 个字符，或含非十六进制字符时返回 [`OidError`]。
    pub fn parse(raw: &str) -> Result<Self, OidError> {
        if raw.len() != OID_HEX_LEN {
            return Err(OidError::Length { actual: raw.len() });
        }
        if !raw.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(OidError::NotHex { value: raw.to_owned() });
        }
        Ok(Self(raw.to_ascii_lowercase()))
    }

    /// 取小写十六进制字符串。
    pub fn as_str(&self) -> &str {
        &self.0
    }

    /// 一级分片目录名：`oid[0:2]`。
    pub fn prefix2(&self) -> &str {
        &self.0[..2]
    }

    /// 前四字符：`oid[0:4]`，两级分片拼起来，用于日志分组与按前缀聚合。
    pub fn prefix4(&self) -> &str {
        &self.0[..4]
    }

    /// 分片目录的两段：`(oid[0:2], oid[2:4])`。
    ///
    /// 路径布局 `objects/<aa>/<bb>/<oid>` 由 [`object_path`](crate::store::object_path)
    /// 唯一实现，它只从这里取分片段，避免分片规则散落多处。
    pub fn shards(&self) -> (&str, &str) {
        (&self.0[..2], &self.0[2..4])
    }
}

impl fmt::Display for Oid {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// `Oid` 构造失败的原因。
#[derive(Debug, Clone, PartialEq, Eq, Error)]
#[non_exhaustive]
pub enum OidError {
    /// 长度不是 64 个字符。
    #[error("oid 必须是 64 位十六进制字符串，实际 {actual} 位")]
    Length {
        /// 实际收到的字符数。
        actual: usize,
    },
    /// 含非十六进制字符。
    #[error("oid 含非十六进制字符：{value}")]
    NotHex {
        /// 原始输入，便于日志定位是哪个客户端传错了。
        value: String,
    },
}

#[cfg(test)]
mod tests {
    use super::{Oid, OidError};

    /// 64 位十六进制：写成分片拼接，一眼能数出长度。
    const VALID: &str =
        concat!("0123456789abcdef", "0123456789abcdef", "0123456789abcdef", "0123456789abcdef",);

    #[test]
    fn given_64_hex_chars_when_parse_then_ok() {
        let oid = Oid::parse(VALID).expect("合法 oid");

        assert_eq!(oid.as_str(), VALID);
        assert_eq!(oid.to_string(), VALID);
    }

    #[test]
    fn given_uppercase_hex_when_parse_then_normalized_to_lowercase() {
        let oid = Oid::parse(&VALID.to_uppercase()).expect("大写也应接受");

        assert_eq!(oid.as_str(), VALID);
    }

    #[test]
    fn given_too_short_or_too_long_when_parse_then_length_error() {
        let short = Oid::parse(&VALID[..63]).expect_err("63 位应被拒绝");
        let long = Oid::parse(&format!("{VALID}0")).expect_err("65 位应被拒绝");

        assert!(matches!(short, OidError::Length { actual: 63 }), "实际错误：{short}");
        assert!(matches!(long, OidError::Length { actual: 65 }), "实际错误：{long}");
    }

    #[test]
    fn given_non_hex_character_when_parse_then_not_hex_error() {
        let raw = VALID.replace('d', "z");

        let err = Oid::parse(&raw).expect_err("非十六进制应被拒绝");

        assert!(matches!(err, OidError::NotHex { .. }), "实际错误：{err}");
        assert!(err.to_string().contains(&raw), "错误信息应带上原始输入：{err}");
    }

    #[test]
    fn given_valid_oid_when_shards_then_first_two_and_next_two_chars() {
        let oid = Oid::parse(VALID).expect("合法 oid");

        assert_eq!(oid.prefix2(), &VALID[..2]);
        assert_eq!(oid.prefix4(), &VALID[..4]);
        assert_eq!(oid.shards(), (&VALID[..2], &VALID[2..4]));
    }

    #[test]
    fn given_oids_when_order_then_lexicographic_by_hex() {
        let low = Oid::parse(VALID).expect("合法 oid");
        let high = Oid::parse(&VALID.replacen('0', "f", 1)).expect("合法 oid");

        assert!(low < high);
    }
}

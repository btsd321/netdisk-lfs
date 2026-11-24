//! 流式 sha256：文件级摘要与「边写边算」的增量器。
//!
//! 4 GiB 级对象全程流式，任何路径都不把整个文件读进内存（见 docs/rust-style.md 第 9 节）。

use std::fmt;
use std::io;
use std::path::Path;

use sha2::{Digest, Sha256};
use tokio::io::AsyncReadExt;

/// 读缓冲大小：64 KiB。
///
/// 够摊薄系统调用，又不至于让并发传输各自占住大块内存。
pub const HASH_BUFFER_BYTES: usize = 64 * 1024;

/// 流式计算本地文件的 sha256，返回小写十六进制字符串。
///
/// 按 [`HASH_BUFFER_BYTES`] 分块读、逐块喂给哈希器，内存占用与文件大小无关。
///
/// # Errors
/// 文件打不开或读失败时返回 [`io::Error`]；路径上下文由调用方补
/// （存储层用 `StoreError::io` 包装，日志里才看得到是哪个文件）。
pub async fn hash_file(path: &Path) -> io::Result<String> {
    let file = tokio::fs::File::open(path).await?;
    let mut reader = tokio::io::BufReader::with_capacity(HASH_BUFFER_BYTES, file);
    let mut hasher = Sha256::new();
    let mut buffer = vec![0_u8; HASH_BUFFER_BYTES];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
    }
    Ok(hex::encode(hasher.finalize()))
}

/// 增量 sha256：把陆续到达的字节块喂进来，收尾时取小写十六进制摘要。
///
/// B5 的 `PUT /objects/{oid}` 边收 body 边算哈希，不必先落盘再读一遍。这里刻意
/// 不实现 [`std::io::Write`]：HTTP body 是异步 chunk 流，直接 [`update`](Self::update)
/// 比包一层同步 Writer 简单，也避免有人误在 async 上下文里做阻塞写。
pub struct Sha256Writer {
    hasher: Sha256,
}

impl Sha256Writer {
    /// 新建一个空增量器。
    pub fn new() -> Self {
        Self { hasher: Sha256::new() }
    }

    /// 喂入一块字节。
    pub fn update(&mut self, chunk: &[u8]) {
        self.hasher.update(chunk);
    }

    /// 结束计算，取小写十六进制摘要。
    pub fn finish(self) -> String {
        hex::encode(self.hasher.finalize())
    }
}

impl Default for Sha256Writer {
    fn default() -> Self {
        Self::new()
    }
}

impl fmt::Debug for Sha256Writer {
    /// 摘要状态属于内部细节（且会随数据变化），只暴露类型名。
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Sha256Writer").finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::{HASH_BUFFER_BYTES, Sha256Writer, hash_file};
    use crate::test_support::TempDir;

    use sha2::{Digest, Sha256};

    /// 空字符串的 sha256（NIST 测试向量）。
    const EMPTY_SHA256: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
    /// `"abc"` 的 sha256（NIST 测试向量）。
    const ABC_SHA256: &str = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad";

    /// 造一段可复现的伪随机字节：单纯递增会让哈希器遇到重复块时也可能凑巧通过，
    /// 这里用线性同余生成，确保内容无规律。
    fn patterned_bytes(len: usize) -> Vec<u8> {
        let mut state = 0x5a17_u64;
        (0..len)
            .map(|_| {
                state = state.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
                (state >> 33) as u8
            })
            .collect()
    }

    #[tokio::test]
    async fn given_empty_file_when_hash_then_matches_known_digest() {
        let dir = TempDir::new("netdisk-lfs-hash-empty");
        let path = dir.write("empty", "");

        let digest = hash_file(&path).await.expect("哈希空文件");

        assert_eq!(digest, EMPTY_SHA256);
    }

    #[tokio::test]
    async fn given_file_larger_than_buffer_when_hash_then_equals_single_pass_digest() {
        let dir = TempDir::new("netdisk-lfs-hash-large");
        // 故意跨过缓冲边界且不是整数倍，覆盖「最后一次不满缓冲」的分支。
        let data = patterned_bytes(HASH_BUFFER_BYTES * 2 + 1234);
        let path = dir.path().join("large");
        std::fs::write(&path, &data).expect("写入大文件");

        let digest = hash_file(&path).await.expect("哈希大文件");

        // 单次 update 的整块摘要与流式结果对比，验证分块循环没有漏读或重复读。
        assert_eq!(digest, hex::encode(Sha256::digest(&data)));
        assert_ne!(digest, EMPTY_SHA256);
    }

    #[tokio::test]
    async fn given_missing_file_when_hash_then_io_error() {
        let dir = TempDir::new("netdisk-lfs-hash-missing");

        let err = hash_file(&dir.path().join("nope")).await.expect_err("缺失文件应报错");

        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
    }

    #[test]
    fn given_no_chunks_when_finish_then_empty_digest() {
        assert_eq!(Sha256Writer::new().finish(), EMPTY_SHA256);
    }

    #[test]
    fn given_chunks_in_pieces_when_finish_then_matches_one_shot_digest() {
        let data = patterned_bytes(3 * HASH_BUFFER_BYTES);
        let mut writer = Sha256Writer::new();
        for chunk in data.chunks(777) {
            writer.update(chunk);
        }

        assert_eq!(writer.finish(), hex::encode(Sha256::digest(&data)));
    }

    #[test]
    fn given_abc_when_finish_then_matches_known_digest() {
        let mut writer = Sha256Writer::default();
        writer.update(b"a");
        writer.update(b"bc");

        // Debug 不打印摘要状态：它随数据变化，进日志只会误导。
        assert_eq!(format!("{writer:?}"), "Sha256Writer { .. }");
        assert_eq!(writer.finish(), ABC_SHA256);
    }
}

//! 测试专用工具：进程内唯一的临时目录，Drop 时递归删除。
//!
//! 只在 `cargo test` 构建中编译，不进入发布二进制。

use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

static TEMP_SEQ: AtomicU32 = AtomicU32::new(0);

/// 临时目录句柄；离开作用域即清理。
pub(crate) struct TempDir {
    path: PathBuf,
}

impl TempDir {
    /// 在系统临时目录下创建一个唯一子目录。
    pub(crate) fn new(prefix: &str) -> Self {
        let seq = TEMP_SEQ.fetch_add(1, Ordering::Relaxed);
        let path = std::env::temp_dir().join(format!("{prefix}-{}-{seq}", std::process::id()));
        // 独占创建：路径唯一是构造出来的约定，碰撞（同 PID 复用 + 上次残留）
        // 应当响亮失败而不是静默复用旧目录。
        fs::create_dir(&path).expect("创建临时目录");
        Self { path }
    }

    /// 目录路径。
    pub(crate) fn path(&self) -> &Path {
        &self.path
    }

    /// 在目录内写一个文件并返回其路径。
    pub(crate) fn write(&self, name: &str, contents: &str) -> PathBuf {
        let file = self.path.join(name);
        fs::write(&file, contents).expect("写入临时文件");
        file
    }
}

impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.path);
    }
}

# Rust 编程规范

- 版本：v1（2026-11-24）
- 适用：本仓库全部 Rust 代码
- 定位：**只写会分歧的部分**。能被工具判定的交给工具，语言惯例交给官方指南。

## 0. 三层依据

| 层 | 依据 | 处理方式 |
|---|---|---|
| 机器判定 | `rustfmt`、`clippy`、`cargo-deny`、`typos` | 进 CI，不在本文重复 |
| 语言惯例 | [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/checklist.html) | 本文只引用，不复制 |
| 项目约定 | 本文正文 | 真正需要人判断的 8~10 条 |

遇到本文没覆盖的情况，按 [Microsoft Pragmatic Rust Guidelines](https://microsoft.github.io/rust-guidelines/) 的 Golden Rule 处理：
先想清楚规则在保护什么，再决定要不要变通；变通要在 PR 里说明理由。

## 1. 三条原则

1. **编译器优先**：能让类型系统表达的约束，不要靠注释和运行时检查。`Oid` 是 newtype 而不是 `String`，就是这个意思。
2. **显式优于隐式**：不写“聪明”的宏和运算符重载；调用方一眼能看出会分配、会阻塞、会失败。
3. **错误即数据**：错误是返回值，不是异常；能用 `?` 传播就不要 `match` 套 `match`。

## 2. 工具链与门禁

`rust-toolchain.toml`（入库，固定版本；首次构建后把实际版本号写回）：

```toml
[toolchain]
channel = "stable"
components = ["rustfmt", "clippy"]
```

CI 必跑四条，任一失败即阻断合并：

```bash
cargo fmt --check
cargo clippy --all-targets --all-features -- -D warnings
cargo nextest run --all-features
cargo deny check
```

外加 `typos`（注释与文档拼写）。

## 3. Lint 配置

集中写在 `Cargo.toml` 的 `[lints]`，**不要在代码里散落 `#[allow]`**（rust-analyzer 团队的做法）。

```toml
[lints.rust]
unsafe_code = "forbid"
missing_docs = "warn"
rust_2018_idioms = { level = "warn", priority = -1 }
unreachable_pub = "warn"
unused_qualifications = "warn"

[lints.clippy]
all = { level = "warn", priority = -1 }
# 精挑的 pedantic：这几条对本项目有实际收益
explicit_iter_loop = "warn"
needless_pass_by_value = "warn"
manual_let_else = "warn"
semicolon_if_nothing_returned = "warn"
redundant_closure_for_method_calls = "warn"
uninlined_format_args = "warn"
# 明确关闭的噪音（pedantic 全开会淹没真正的问题）
module_name_repetitions = "allow"
must_use_candidate = "allow"
missing_errors_doc = "allow"
doc_markdown = "allow"
```

`rustfmt.toml`（只用 stable 支持的选项）：

```toml
edition = "2024"
max_width = 100
use_small_heuristics = "Max"
newline_style = "Unix"
match_block_trailing_comma = true
```

> `imports_granularity`、`group_imports` 是 nightly-only，本项目不用 nightly，因此**不加**。

## 4. 模块与可见性

- 默认 `pub(crate)`；只有真正对外的 API 才 `pub`。`unreachable_pub` 会帮你抓漏。
- `lib.rs` / `main.rs` 不写业务逻辑，只做模块声明与 re-export。
- 用 `foo.rs` + `foo/bar.rs` 的布局，**不用 `mod.rs`**。
- 对外 API 通过 `pub use` 从 crate 根导出，内部模块路径不作为对外契约。

## 5. 命名

遵循 API Guidelines 的 C-CASE / C-CONV / C-GETTER / C-ITER，本项目常用的几条：

| 场景 | 规则 | 例子 |
|---|---|---|
| 便宜地借用 | `as_` | `as_bytes()` |
| 有转换成本 | `to_` | `to_string()` |
| 消耗所有权 | `into_` | `into_inner()` |
| 判断 | `is_` | `is_empty()` |
| 迭代器 | `iter` / `iter_mut` / `into_iter` | — |
| getter | **不加 `get_` 前缀** | `fn oid(&self) -> &Oid` |
| 可变访问 | `_mut` 后缀 | `fn buffer_mut(&mut self)` |
| 构造 | `new` 或语义化名字 | `Oid::parse(s)` |

`len()` 必须配 `is_empty()`；两者同时提供。

## 6. 类型设计

**newtype 表达不变量**（本项目高频）：

```rust
// 好：构造时校验，之后全流程不会再错
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Oid(String);

impl Oid {
    pub fn parse(raw: &str) -> Result<Self, OidError> {
        let is_hex = raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit());
        if !is_hex {
            return Err(OidError::Malformed { value: raw.to_owned() });
        }
        Ok(Self(raw.to_ascii_lowercase()))
    }
    pub fn as_str(&self) -> &str { &self.0 }
}

// 坏：到处传 String，每个用到的地方都得再校验一遍
fn fetch(oid: String) -> Result<Vec<u8>> { /* ... */ }
```

其他约定：

- 参数不要用 `bool`（`upload(path, true)` 读不懂），用 enum 或拆成两个方法。
- 公开的 enum / struct 加 `#[non_exhaustive]`，给将来留余地。
- 能派生就派生：`Debug` 必须有（`C-DEBUG`），其余按需 `Clone`/`PartialEq`/`Default`。
- 容器参数用 `&[T]` / `&str`，不要 `&Vec<T>` / `&String`。

## 7. 错误处理

**分层，不统一**：

- `netdisk_lfs` 库内：`thiserror` 定义域错误枚举，每个变体描述“发生了什么”；
- `main.rs` 与 handler 边界：`anyhow` 聚合上下文，最终映射成 HTTP 状态码。

```rust
// 库内
#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("对象 {oid} 不存在")]
    NotFound { oid: Oid },
    #[error("bdpan 命令失败（{cmd}），退出码 {code}")]
    Backend { cmd: String, code: i32 },
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

// 边界
let bytes = store
    .get(&oid)
    .await
    .with_context(|| format!("读取对象 {oid}"))?;
```

规则：

- 错误信息**小写开头、不加句号**，说清“什么失败了、关键参数是什么”。
- `#[from]` 只用于真正无损转换；跨层转换时保留原始错误为 `source`。
- `.context()` 在最外层加一次就够，**不要每层都加**，否则日志全是噪声。
- 禁止 `Result<T, String>`。
- 库代码不用 `unwrap()` / `expect()`；`main` 启动期的配置校验可以用 `expect("缺少 [cache] dir")`，信息必须说明缺什么。

## 8. 异步与阻塞（本项目最容易踩的坑）

tokio 的规则只有一条：**在 async 函数里不许做阻塞操作**，否则会卡住整个线程。

| 别用 | 用 |
|---|---|
| `std::fs::*` | `tokio::fs::*`；大文件读写用 `spawn_blocking` + `std::fs` |
| `std::process::Command` | `tokio::process::Command` |
| `std::thread::sleep` | `tokio::time::sleep` |
| `std::sync::Mutex` 跨 `.await` 持锁 | `tokio::sync::Mutex` |
| CPU 密集计算 | `tokio::task::spawn_blocking` |
| `reqwest::blocking` | `reqwest` async |

其他：

- 子进程一律带超时：`tokio::time::timeout(Duration::from_secs(600), cmd.output())`。
- `.await` 点要考虑**取消安全**：被 `select!` 打断时会不会留下半截文件？我们的答案是“临时文件 + 启动时清理”，见 `storage.md`。
- 不要自己 `Runtime::new().block_on()` 嵌在 async 里。

## 9. 资源与 IO

- 4 GiB 级对象**全程流式**，禁止 `fs::read` 整文件进内存；用 `BufReader` + 8 KiB~64 KiB 缓冲。
- 需要清理的临时资源，用 RAII guard（`struct TempPath(PathBuf)` + `Drop` 删文件）；异步清理不要依赖 `Drop` 做 I/O，改用显式 `async fn cleanup()`。
- 落盘写完后是否 `fsync` 取决于需求：缓存目录不需要，上传中转文件在 `mv` 前不需要（网盘侧才是真相源）。

## 10. 测试

- 单元测试写在同文件 `#[cfg(test)] mod tests`，只测本模块；
- 集成测试放 `tests/`，跨模块、走 HTTP 或文件系统；
- 异步测试用 `#[tokio::test]`；
- **任何测试都不许访问真实网盘**：`bdpan` 用 shell 脚本桩（`tests/fixtures/bdpan`）或 `FakeStore` 替代；
- 测试命名 `given_<前提>_when_<动作>_then_<结果>`；
- 失败路径必须有测试：哈希不符、超限、对象不存在、`bdpan` 超时。

## 11. 文档与注释

- `//!` 写模块职责（一两句），`///` 写公开项的契约。
- `#![warn(missing_docs)]` 只要求 `pub` 项；内部实现不强制，避免为写而写。
- 返回 `Result` 的公开函数写 `# Errors`；可能 panic 的写 `# Panics`；`unsafe` 写 `# Safety`。
- 注释解释**为什么**，不是**做什么**（代码已经说了做什么）。
- 中文注释可以，但标识符、类型名、日志字段一律英文。

## 12. 依赖与 unsafe

- 新依赖必须在 `.agents/decisions/` 记一条：为什么需要、有没有更小的替代。`dashmap`、`lru` 这种自己写容易出并发 bug 的，直接用库。
- `default-features = false`，只开需要的 feature。
- `cargo deny` 管许可证与重复版本；`Cargo.lock` 入库（二进制项目）。
- `unsafe` 一律 forbid。确有需要时：单独 ADR + `# Safety` 文档 + 最小化作用域。

## 13. 反模式清单

| # | 反模式 | 正确写法 |
|---|---|---|
| 1 | 生产路径 `unwrap()` | `?` 或 `ok_or(StoreError::...)` |
| 2 | 为过借用检查器到处 `clone()` | 先想清楚所有权边界；必要时用 `Cow` 或重构函数签名 |
| 3 | `Arc<Mutex<HashMap<..>>>` 一把梭 | 明确并发粒度；读多写少用 `RwLock` 或 `DashMap` |
| 4 | `Result<T, String>` | 定义错误枚举 |
| 5 | `fn upload(path, overwrite: bool)` | `enum Overwrite { Yes, No }` 或方法名区分 |
| 6 | async 里调 `std::fs` / `block_on` | 见第 8 节 |
| 7 | 到处 `impl Into<String>` 过度泛型 | 参数类型写具体；泛型只给真正需要复用的地方 |
| 8 | `let _ = result;` 吞掉错误 | `if let Err(e) = ... { warn!(...) }` 或显式忽略并注释原因 |
| 9 | `fn f(s: &String)` / `fn f(v: &Vec<T>)` | `&str` / `&[T]` |
| 10 | 每个层级都 `.context()` | 只在边界加一次 |

## 14. 新手阅读顺序

1. The Rust Book 第 4 章（所有权）、第 9 章（错误处理）、第 10 章（trait 与生命周期）；
2. `tokio` 教程的 “async 基础” 一节，重点看“不要在 async 里阻塞”；
3. 本文件第 7、8、13 节——这三节覆盖本项目 80% 的返工来源。

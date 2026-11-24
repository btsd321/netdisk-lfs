# netdisk-lfs

本文件面向在本仓库工作的 AI agent。人类使用说明见 [README.md](README.md)。

## 项目一句话

一个自建的 Git LFS 服务端（Rust），对象存储后端是百度网盘，经由服务器上的 `bdpan` CLI 读写。

## 工作流

分支、提交与合并遵循 [docs/git-workflow.md](docs/git-workflow.md)：特性分支从 `develop` 切出、以 `--no-ff` 合回；提交用 Conventional Commits 中文描述并带 `-s` 签署；特性分支不 push 到远程。

## 硬约束（改动前必读）

- **存储通道唯一**：对象只能通过 `bdpan` CLI 子进程读写，作用域固定为网盘 `/apps/bdpan/`。不要试图绕过 CLI 直连开放平台 API，除非同时提交新的 ADR。
- **协议以官方规范为准**：Git LFS batch API 见 `.agents/specs/api.md`，任何端点行为变更先改文档再改代码。
- **内容寻址不可妥协**：对象路径由 oid（sha256）决定，上传必须校验哈希后再落最终路径，禁止「先写最终路径再校验」。
- **单对象上限可配**：`storage.max_object_bytes`，默认 `0` = 不限制（实际大小受网盘单文件限制与磁盘余量约束）；非 0 时超限直接拒绝（422），不做内部分片映射。大对象上传依赖可配的 `bdpan_timeout_secs`（默认 6 小时，0 = 不设超时）。

## 目录

```text
src/            实现
tests/          集成测试（含 fake bdpan）
docs/           入库文档：Git 工作流、Rust 规范
.agents/        本地规划与调研（**不入 git**，见 .gitignore）
```

## 构建与测试

```bash
cargo build
cargo test
cargo clippy --all-targets --all-features -- -D warnings
cargo fmt --check
```

## 编码约定

完整规范见 [docs/rust-style.md](docs/rust-style.md)（入库）。以下为必须遵守的摘要：

- 生产路径不使用 `unwrap()` / `expect()`（启动期配置校验除外），错误用 `thiserror` 定义域内错误类型。
- lint 统一配置在 `Cargo.toml` 的 `[lints]`，禁止在代码里散落 `#[allow]`。
- async 里禁止阻塞调用（`std::fs`、`std::process`、`thread::sleep`），见规范第 8 节。
- 所有对外 HTTP 行为打 `tracing` span，字段至少含 `oid`、`bytes`、`duration_ms`。
- 调用 `bdpan` 一律走统一的封装层，禁止在 handler 里直接 `Command::new`。
- 新增依赖先进 `.agents/decisions/` 记一条理由，再改 `Cargo.toml`。

## 本地工作区

`.agents/` 存放规划、规格、ADR 与调研笔记，已被 `.gitignore` 排除。提交前确认 `git status` 里没有它的内容。

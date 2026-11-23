# Git 分支管理与提交规范

本文档是 `netdisk-lfs` 仓库的 Git 工作流约定。AI agent 与人类开发者在本仓库中创建分支、提交代码、合并变更时**必须**遵循本规范。

> 技术栈：Rust（stable）+ axum + tokio，对象存储后端是服务器上的 `bdpan` CLI。
> 代码规范见 [rust-style.md](rust-style.md)，项目概览见 [README.md](../README.md)，agent 约定见 [AGENTS.md](../AGENTS.md)。本文只管分支、提交与发布。

---

## 一、分支模型

本项目采用**短生命周期特性分支 + 主干发布**模型（参考 Trunk-Based Development），适配 AI agent 并行协作场景。

### 1.1 长期分支

| 分支 | 用途 | 保护规则 |
|------|------|---------|
| `main` | 发布分支，始终可构建、可发布 | 只接受从 `develop` 的 `--no-ff` merge |
| `develop` | 集成分支，所有特性在此汇聚 | 只接受从特性分支的 `--no-ff` merge |

**核心约束：合并方向单向——`develop → main`，禁止反向合并。**

```
特性分支 ──→ develop ──→ main
              ↑
         （唯一入口）
```

- ✅ `git checkout main && git merge develop --no-ff`
- ❌ `git checkout develop && git merge main`（禁止）

当 main 上有 develop 没有的 commit 时（如发布时的版本号提交），应通过 cherry-pick 或重新在 develop 上做相同改动来同步，而非反向 merge。

### 1.2 特性分支

命名格式：`<type>/<short-description>`，全小写连字符。

| 前缀 | 用途 | 示例 |
|------|------|------|
| `feat/` | 新功能 | `feat/lfs-batch-api`、`feat/disk-lru` |
| `fix/` | Bug 修复 | `fix/hash-mismatch-400`、`fix/bdpan-timeout` |
| `refactor/` | 重构（不改行为） | `refactor/split-store-trait` |
| `docs/` | 纯文档更新 | `docs/git-workflow` |
| `test/` | 纯测试补充 | `test/fake-bdpan` |
| `chore/` | 构建/工具/配置/依赖 | `chore/rust-toolchain`、`chore/cargo-deny` |

**生命周期规则：**

1. 从 `develop` 的最新 HEAD 创建：`git checkout develop && git checkout -b <name>`
2. 完成后以 `--no-ff` merge 回 `develop`
3. merge 后立即删除本地特性分支
4. 特性分支**不直接 merge 到 main**
5. 特性分支之间**不互相 merge**——如有依赖，先合并上游分支到 develop，再从 develop 重新切分支
6. **特性分支不 push 到远程**：特性分支只在**本地**创建、提交、merge；merge 回 `develop` 后立即 `git branch -d`。远程只保留 `develop`/`main`/tag 三类引用——推特性分支只会造成分支堆积与「幽灵分支」

> 远程只保留长期分支 `develop`/`main` 与版本 tag。特性分支若需远端可见（如走 PR 评审），也**不**作为本仓库的常规流程——merge 由 Lead 在本地执行，见 1.3 与第三节。

### 1.3 AI Agent 分支约定

1. **每个 agent 任务使用独立分支**：避免多个 agent 在同一分支上并发写入导致冲突
2. **写作用域不重叠**：Lead 分配任务时确保不同 agent 修改的文件集合不相交（尤其 `Cargo.toml`、`Cargo.lock`、`rust-toolchain.toml`、`deny.toml`、`rustfmt.toml` 这类全局文件）
3. **agent 不自行 merge 到 develop/main**：完成工作后提交到特性分支，由 Lead 审核并执行 merge
4. **agent 不做反向 merge**：需要同步其他分支改动时通知 Lead 处理
5. **特性分支命名加编号**：便于追踪，如 `refactor/smell-1-store-layout`
6. **agent 不 push 特性分支到远程**：推送是 Lead 的职责，且需仓库维护者确认

### 1.4 git worktree 与 Agent 团队协作

使用 Agent 团队或多 agent 并行协作时，**必须**用 `git worktree` 为每个 agent 创建独立工作区，而不是共享同一工作目录。

#### 1.4.1 为什么必须用 worktree

多 agent 共享同一工作目录时，任何一次 `git checkout` 会**改变整个工作区的分支引用**：

- agent A 在 `feat/a` 上编辑 `src/store/bdpan.rs`，agent B 执行 `git checkout develop`，A 的未提交改动可能被覆盖
- `target/` 是工作区级状态，切分支后增量编译产物与源码不匹配，测试结果会误导人
- 并发 `git checkout` 存在竞态：索引与 HEAD 的更新不是原子的，可能损坏 `.git/index`

`git worktree` 为每个分支创建**独立工作目录**，共享同一 `.git` 对象库，从根本上消除上述问题。

#### 1.4.2 worktree 工作流

**Lead（创建）：**

```bash
# 1. 确认 develop 最新
git checkout develop && git pull --ff-only

# 2. 为每个 agent 从 develop 创建独立 worktree + 特性分支
#    worktree 放在仓库内部 .worktrees/，不写到仓库外
git worktree add .worktrees/agent-a -b feat/lfs-batch-api develop
git worktree add .worktrees/agent-b -b test/fake-bdpan develop
```

**Agent（在 worktree 中工作）：**

1. 进入 Lead 指定的 worktree 目录（如 `.worktrees/agent-a`）作为工作目录
2. 在该目录内完成所有编辑、构建、测试、commit——**不要切换分支**，worktree 已绑定特性分支
3. 构建使用**本 worktree 自己的 `target/`**，不指向主工作区或其他 worktree 的 `target/`
4. 完成后向 Lead 报告 commit hash 与 worktree 路径，**不要自行 merge**

**Lead（收集与合并）：**

```bash
git -C .worktrees/agent-a log --oneline develop..HEAD

git checkout develop
git merge --no-ff feat/lfs-batch-api -m "merge: develop ← feat/lfs-batch-api — batch 端点与存在性查询"
git merge --no-ff test/fake-bdpan -m "merge: develop ← test/fake-bdpan — 测试桩与超时用例"

git worktree remove .worktrees/agent-a
git worktree remove .worktrees/agent-b
git branch -d feat/lfs-batch-api test/fake-bdpan
```

#### 1.4.3 worktree 约定

| 约定 | 说明 |
|------|------|
| **worktree 位置** | 仓库内部 `.worktrees/<agent名>`，**不写到仓库外部**——同级目录可能因权限不足导致 `git worktree add` 失败 |
| 分支来源 | 一律从 `develop` 最新 HEAD 创建，不从 main |
| 单一归属 | 每个 worktree 只分配给一个 agent，不跨 agent 复用 |
| 构建目录 | 每个 worktree 独立 `target/`；**不要**用 `CARGO_TARGET_DIR` 指到共享目录，增量编译会互相覆盖 |
| 依赖缓存 | 共享 `CARGO_HOME`（默认 `~/.cargo`）的 registry/git 缓存，跨 worktree 复用，无需重复下载；`cargo fetch` 的结果对所有 worktree 可见 |
| 工具链 | `rust-toolchain.toml` 随仓库分发，rustup 按目录自动选择版本，不在 worktree 里手改 |
| 清理 | 合并回 develop 后 Lead 立即 `git worktree remove`，不残留 |
| 不提交 | `.worktrees/` 与 `target/` 均在 `.gitignore` 中排除 |

#### 1.4.4 何时用 worktree

| 场景 | 是否用 worktree |
|------|----------------|
| Agent Teams 多 agent 并行修改不同文件 | ✅ 必须用 |
| Lead 单 agent 串行完成全部工作 | ❌ 不用，直接在特性分支工作 |
| 两个 agent 修改同一文件 | ❌ 不用——先拆分任务让写作用域不重叠 |
| 对比两版实现的基准表现 | ✅ 适合并行跑两个构建 |

### 1.5 发布流程

```
develop (稳定) ──merge──→ main ──tag──→ v0.x.y
```

1. 确认 develop 上改动已通过第三节清单与 [rust-style.md](rust-style.md) 第 2 节的门禁
2. `git checkout main && git merge develop --no-ff -m "merge: develop → main — <摘要>"`
3. 版本号**单点修改**：`Cargo.toml` 的 `[package] version`，提交到 main；`Cargo.lock` 一并更新
4. `git tag -a v0.x.y -m "v0.x.y: <发布摘要>"`
5. 经维护者确认后 push main 与 tag
6. 产物：`cargo build --release --locked` 得到的 `netdisk-lfs` 二进制 + `config.toml.example`；产物不入库，只挂 Release

---

## 二、提交规范

采用 [Conventional Commits](https://www.conventionalcommits.org/zh-hans/v1.0.0/)，提交信息一律**中文描述**。

### 2.1 格式

```
<类型>(<范围>): <中文描述>

[可选正文]

[可选脚注]
```

### 2.2 类型

| 类型 | 含义 | SemVer 对应 |
|------|------|------------|
| `feat` | 新功能 | MINOR |
| `fix` | Bug 修复 | PATCH |
| `refactor` | 重构（不改外部行为） | — |
| `docs` | 文档更新 | — |
| `test` | 测试增删改 | — |
| `chore` | 构建/工具/配置/依赖 | — |
| `perf` | 性能优化 | PATCH |
| `style` | 代码格式（不影响逻辑） | — |
| `ci` | CI/CD 配置 | — |
| `revert` | 回滚 | — |

### 2.3 范围（scope）

范围取代码模块名，`src/` 下的目录与之同名；非代码改动按仓库目录归类：

| 范围 | 对应位置 |
|------|---------|
| `http` | src/http/（路由、batch/upload/download/verify、认证） |
| `store` | src/store/（`ObjectStore` trait 与驱动实现） |
| `bdpan` | src/bdpan/（`bdpan` 子进程封装：超时、重试、并发限流） |
| `cache` | src/cache/（本地磁盘 LRU、单飞、索引重建） |
| `config` | src/config/（配置解析与启动期校验） |
| `tests` | tests/（集成测试、fake bdpan、测试夹具） |
| `build` | Cargo.toml、Cargo.lock、rust-toolchain.toml、rustfmt.toml、deny.toml、.cargo/ |
| `ci` | .github/workflows/ |
| `docs` | docs/ |

省略范围也可以，改动集中在单个模块时推荐标注。

### 2.4 描述要求

- 中文，简洁明了（≤ 50 字为佳）
- 祈使语气："新增…"、"修复…"、"拆分…"，不用"了"、"过"
- 不以句号结尾

### 2.5 正文与脚注

- 正文用空行与标题分隔，解释"为什么"而非"做了什么"
- 破坏性变更在标题加 `!` 或在脚注写 `BREAKING CHANGE:`
- 引用 issue/PR 用 `Refs: #123`
- 依据本地规格时写文件名即可：`Refs: specs/storage.md`（对应当前工作区的 `.agents/specs/`）
- 提交一律用 `git commit -s` 带 `Signed-off-by`；**不加** `Co-Authored-By: <AI 工具>` 之类的署名脚注

### 2.6 示例

```
feat(http): batch 上传前先查网盘是否存在该 oid

已存在的对象不回 upload action，客户端自动跳过上传；
避免重复推送同一份大对象时浪费网盘流量。

Refs: specs/api.md
```

```
fix(store): bdpan 报成功但对象截断时改用 sha256 拦截

bdpan 偶发「退出码 0、文件大小不符」的静默成功，单看退出码会把
半截对象写进最终路径。改为上传完成后一律校验哈希与大小，不符即
删除临时对象并返回 502。

Refs: #18
```

```
perf(cache): 命中路径去掉重复 open，改为一处 stat

每对象多一次 syscall，10 GiB 仓库冷启动扫描时集中体现。
```

```
chore(build): 固定 rust-toolchain 版本并启用 cargo-deny

CI 与本地用同一组门禁命令，许可证与重复依赖由 deny.toml 统一裁决。
```

```
docs: 新增 Git 分支与提交规范

Refs: docs/rust-style.md
```

### 2.7 Merge Commit 格式

合入 develop：

```
merge: develop ← <type>/<name> — <本次合并的摘要>
```

发布到 main：

```
merge: develop → main — <本次合并的摘要>
```

---

## 三、Agent 工作流检查清单

### 开始前

- [ ] 确认当前在正确的特性分支上（不在 main/develop 上直接改）
- [ ] 确认特性分支从 develop 最新 HEAD 创建
- [ ] 确认写作用域与其他 agent 不重叠
- [ ] **Agent 团队协作时**：确认已分配独立 worktree，且当前目录在 worktree 内
- [ ] 已读 [rust-style.md](rust-style.md) 与相关规格；协议或存储行为变更先改 `.agents/specs/`，再改代码

### 工作中

- [ ] 每个逻辑独立的改动单独 commit，不攒大提交
- [ ] commit message 符合 Conventional Commits，中文描述，带 `-s` 签署
- [ ] `cargo fmt --check` 无 diff
- [ ] `cargo clippy --all-targets --all-features -- -D warnings` 零告警
- [ ] `cargo test` 全绿（CI 门禁含 nextest 与 `cargo deny check`，见 rust-style 第 2 节）
- [ ] 新增依赖先在 `.agents/decisions/` 记一条理由，再改 `Cargo.toml`
- [ ] 改动没有绕过 `bdpan` CLI，也没有破坏内容寻址（oid 决定路径、先校验哈希再落最终路径）
- [ ] 测试不访问真实网盘：用 `FakeStore` 或 `tests/fixtures/bdpan` 桩

### 完成后

- [ ] 所有改动已 commit 到特性分支，`git status` 干净
- [ ] 向 Lead 报告完成状态、commit hash、构建与测试结果
- [ ] **不自行 merge 到 develop 或 main**
- [ ] **不做 main → develop 的反向 merge**
- [ ] **不 push 特性分支到远程**
- [ ] **Agent 团队协作时**：报告 worktree 路径，由 Lead 合并后清理

---

## 四、禁止事项

### 4.1 分支与合并

| 禁止操作 | 原因 |
|---------|------|
| 直接在 main/develop 上 commit | 所有改动必须经特性分支 |
| 从 main 创建特性分支 | 特性分支只能从 develop 创建 |
| main → develop 的 merge | 破坏单向合并规则 |
| 特性分支之间互相 merge | 应通过 develop 中转 |
| **push 特性分支到远程** | 远程只保留 develop/main/tag |
| **共享工作区切分支** | 多 agent 时必须用 worktree 隔离 |
| **worktree 创建到仓库外部** | 同级目录可能权限不足，必须放 `.worktrees/` |
| **worktree 未清理残留** | 合并后 Lead 立即 `git worktree remove` |
| force push 已推送的分支 | 除非维护者明确要求重写历史 |
| `git merge --squash` | 保留完整历史，merge 用 `--no-ff` |

### 4.2 内容与资产

| 禁止操作 | 原因 |
|---------|------|
| 提交 `.agents/` | 本地规划/规格/ADR/调研，已 gitignore，不随仓库分发 |
| 提交 `target/`、`.worktrees/` | 构建产物与临时工作区，已 gitignore |
| 提交 `config.toml`、`data/` | 含账号口令哈希与缓存/中转文件；只提交 `config.toml.example` |
| 提交 `bdpan` 的 token、cookie 或 `whoami --json` 原始输出 | 授权凭据，不得入库 |
| 提交签名证书、密钥、账号信息 | 安全 |
| 提交 > 1 MiB 的测试夹具或真实对象数据 | 大对象由脚本生成，或用 `FakeStore` 替代 |
| 提交信息用英文 | 本仓库一律中文 |
| 提交带 AI 工具署名的 trailer | 只保留 `Signed-off-by` |

`Cargo.lock` 是例外：本仓库是二进制项目，**必须**入库。

---

## 五、常用命令

```bash
# 从 develop 切特性分支
git checkout develop && git pull --ff-only
git checkout -b feat/lfs-batch-api

# 提交（Conventional Commits + DCO 签署）
git add -A && git commit -s -m "feat(http): 新增 batch 端点的存在性查询"

# 合并回 develop（Lead 执行）
git checkout develop
git merge --no-ff feat/lfs-batch-api -m "merge: develop ← feat/lfs-batch-api — batch 端点与存在性查询"
git branch -d feat/lfs-batch-api

# 发布
git checkout main
git merge --no-ff develop -m "merge: develop → main — v0.1.0"
git tag -a v0.1.0 -m "v0.1.0: 首个可运行版本"
git push origin main v0.1.0   # 需维护者确认
```

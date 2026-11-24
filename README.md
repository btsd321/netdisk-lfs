# netdisk-lfs

用百度网盘当对象存储的自建 Git LFS 服务端。

客户端是标准 `git-lfs`，不需要百度账号；服务器上的网关把 LFS 协议的读写翻译成 `bdpan` CLI 调用，
对象最终落在网盘 `/apps/bdpan/lfs/objects/`。

> 状态：核心链路已实现（配置、`ObjectStore` 与 `bdpan` 封装、batch/PUT/GET/verify、
> 磁盘 LRU 缓存、`/healthz` 探活与 `/metrics`、systemd 部署单元、分级账户体系）；
> 真实网盘端到端验证（大对象实测、token 吊销演练）仍待完成。设计规格在本地
> `.agents/`（不入库），仓库约定见 [`docs/`](docs/)。

## 它解决什么

- 自建 Git 服务器想挂 LFS，但不想为二进制历史买额外的对象存储；
- 已有大容量网盘（TiB 级）闲置，希望复用它做 LFS 的持久层；
- 同事只需要标准 `git clone` / `git lfs pull`，不接触网盘；
- 需要给人开账号、按人分权限（只读 / 读写 / 管理员），而不是共用一个口令。

## 账户与权限

账户存在服务端 SQLite（`$NETDISK_LFS_DATA_DIR/accounts.db`），口令用 Argon2id；`config.toml` 的
`[auth.users]` 只保留引导管理员与应急入口。

| 角色 | 下载 | 上传 | 管理账户 |
|---|---|---|---|
| `readonly` | ✅ | ❌ | ❌ |
| `readwrite`（新账户默认） | ✅ | ✅ | ❌ |
| `admin` | ✅ | ✅ | ✅ |

- 自助注册：`GET/POST /account/register`（HTML 表单或 JSON）。策略 `approval`（默认，
  需管理员审批）/ `open`（立即生效）/ `closed`（关闭注册）。
- 自身账户：`GET /account/me`、`POST /account/password`、`DELETE /account`。
- 管理员：`/admin` HTML 管理页，或 `/admin/users` JSON API（列表 / 创建 / 改角色 /
  禁用 / 删除 / 重置口令）。
- 删除账户**不删除任何 LFS 对象**（对象全局共享、内容寻址）。
- 详见 [docs/accounts.md](docs/accounts.md)。

## 它不做什么

- 不支持 LFS 文件锁（`git lfs lock`）；
- 不做网盘内部分片，单对象超过上限直接拒绝；
- 不是通用对象存储网关，只实现 LFS 需要的那几个端点。

## 快速开始

```bash
# 服务器（systemd unit 会以普通用户运行它，只监听 127.0.0.1）
netdisk-lfs --config /etc/netdisk-lfs/config.toml

# 客户端仓库
git config -f .lfsconfig lfs.url https://lfs.example.com/lfs/
git lfs push --all origin main
```

## 部署

服务器安装、`bdpan` 首次登录、systemd、Caddy 反代、缓存运维与排障见
[docs/deploy.md](docs/deploy.md)。

- systemd unit：[deploy/netdisk-lfs.service](deploy/netdisk-lfs.service)
  （system unit、`Restart=always`、只监听回环，对外一律经反向代理）
- 配置样例：[config.toml.example](config.toml.example)
  （复制到 `/etc/netdisk-lfs/config.toml`，权限 `600`）
- 一键脚本：[scripts/deploy.sh](scripts/deploy.sh) / [scripts/uninstall.sh](scripts/uninstall.sh)
  （默认装到 `/opt/netdisk-lfs`；卸载默认保留配置与数据）
- 账户库：`/var/lib/netdisk-lfs/accounts.db`（**必须纳入备份**，与可随时清空的缓存不同；
  见 [docs/accounts.md](docs/accounts.md) 第 8 节）
- 观测端点：`GET /healthz`（无认证；`bdpan` 探活降级时回 **503**）、
  `GET /metrics`（Prometheus 文本，仅缓存维度）

## 开发文档

- [docs/git-workflow.md](docs/git-workflow.md)：分支模型、提交规范、worktree 协作与发布流程
- [docs/rust-style.md](docs/rust-style.md)：Rust 编码规范、lint 配置与门禁
- [docs/deploy.md](docs/deploy.md)：部署与运维（systemd、反代、缓存、token 排障、升级）
- [docs/accounts.md](docs/accounts.md)：账户与权限（角色、注册审批、管理员操作、备份迁移）

## 参考项目

协议与实现大量参考以下开源项目，借鉴的是结构与接口设计，不复制代码。

| 项目 | 语言 | 参考点 |
|---|---|---|
| [git-lfs/git-lfs](https://github.com/git-lfs/git-lfs) | Go | `docs/api/` 是 batch API 的权威规范：字段、`transfers` 协商、错误体 |
| [git-lfs/lfs-test-server](https://github.com/git-lfs/lfs-test-server) | Go | 最小 LFS 服务端骨架（batch 路由、存储接口形状），官方定位为测试用 |
| [go-gitea/gitea](https://github.com/go-gitea/gitea) | Go | 协议层与存储层解耦：`ObjectStorage` 接口 + 多后端实现 |
| [jasonwhite/rudolfs](https://github.com/jasonwhite/rudolfs) | Rust | 同语言最佳参考：本地磁盘缓存、并发去重、损坏对象探测 |
| [OpenListTeam/OpenList](https://github.com/OpenListTeam/OpenList) | Go | 百度网盘接口细节（>20 MB 需 `User-Agent: pan.baidu.com`、分片上传）与服务端代理下载 |
| [rclone/rclone](https://github.com/rclone/rclone) | Go | 不可随机 seek 的后端如何对外提供 `Range`/`HEAD` 与缓存 |

客户端传输代理路线（备用方案，本仓库未采用）可参考：
[lfs-folderstore](https://github.com/sinbad/lfs-folderstore)、
[git-lfs-webdav](https://github.com/mpotthoff/git-lfs-webdav)、
[lfs-dal](https://github.com/regen100/lfs-dal)。

## 许可

待定。


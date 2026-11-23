# netdisk-lfs

用百度网盘当对象存储的自建 Git LFS 服务端。

客户端是标准 `git-lfs`，不需要百度账号；服务器上的网关把 LFS 协议的读写翻译成 `bdpan` CLI 调用，
对象最终落在网盘 `/apps/bdpan/lfs/objects/`。

> 状态：**规划阶段**，代码尚未开始。设计与里程碑见 `.agents/`（本地目录，不入库）。

## 它解决什么

- 自建 Git 服务器想挂 LFS，但不想为二进制历史买额外的对象存储；
- 已有大容量网盘（TiB 级）闲置，希望复用它做 LFS 的持久层；
- 同事只需要标准 `git clone` / `git lfs pull`，不接触网盘。

## 它不做什么

- 不支持 LFS 文件锁（`git lfs lock`）；
- 不做网盘内部分片，单对象超过上限直接拒绝；
- 不是通用对象存储网关，只实现 LFS 需要的那几个端点。

## 快速开始

待实现。目标形态：

```bash
# 服务器
netdisk-lfs --config /etc/netdisk-lfs/config.toml

# 客户端仓库
git config -f .lfsconfig lfs.url https://lfs.example.com/lfs/
git lfs push --all origin main
```

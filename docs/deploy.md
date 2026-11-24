# 部署与运维

本文面向在 Linux 服务器上把 netdisk-lfs 跑起来并长期维护的人。协议与存储设计见
`AGENTS.md` 指向的本地规格（`.agents/specs/`），代码规范见
[rust-style.md](rust-style.md)，分支与发布流程见 [git-workflow.md](git-workflow.md)。

部署形态（`specs/architecture.md`「部署」）：

```text
git-lfs 客户端 ──HTTPS + Basic Auth──▶ Caddy（TLS 终止，可选）
                                          │ http://127.0.0.1:9001
                                          ▼
                                   netdisk-lfs（systemd system unit，User=lixinlong）
                                          │ bdpan CLI 子进程
                                          ▼
                                   百度网盘 /apps/bdpan/lfs/
```

## 0. 目标形态与假设

- 单实例：**同一数据根只允许一个 netdisk-lfs 进程**——启动时对 `DATA_DIR/netdisk-lfs.lock`
  flock，第二个实例在绑定端口前就以「已有实例在运行」退出（见第 10 节）。
- 服务只监听 `127.0.0.1:9001`，对外一律经反向代理；`/healthz` 与 `/metrics` 没有认证。
- 运行身份是普通用户 `lixinlong`。换用户要同时改 unit 的 `User=`/`Group=`、`PATH`、
  `ReadWritePaths=` 与 `bdpan_bin`（四处漏一处就会在运行期才暴露）。

安装后的文件与来源：

| 目标路径 | 来源 | 权限 |
|---|---|---|
| `/usr/local/bin/netdisk-lfs` | `cargo build --release` 产物 | `755 root:root` |
| `/etc/systemd/system/netdisk-lfs.service` | 仓库 `deploy/netdisk-lfs.service` | `644 root:root` |
| `/etc/netdisk-lfs/config.toml` | 仓库 `config.toml.example` 复制后修改 | `600 lixinlong:lixinlong` |
| `/var/lib/netdisk-lfs/` | unit 的 `StateDirectory=` 自动创建 | `750 lixinlong:lixinlong` |
| `/home/lixinlong/.config/bdpan/` | `bdpan login` 自动写入 | `700 lixinlong:lixinlong` |

## 1. 前置条件

- 构建机有 Rust 工具链（`rust-toolchain.toml` 固定版本）与网络：
  `cargo build --release --locked`。
- 服务器有 `bdpan` CLI，且放在 `/home/lixinlong/.local/bin/bdpan`（`config.toml` 的
  `storage.bdpan_bin` 是绝对路径，不会去 `PATH` 里找）。
- 网盘目录 `/apps/bdpan/lfs/{objects,tmp}` 已存在（`bdpan mkdir` 幂等，可一次建多级）。
  `tmp` 必须是 `objects` 的兄弟目录且以 `objects_root` 为前缀，配置校验会拦。
- 反向代理（可选但推荐）：Caddy 或 nginx，能签发证书。

## 2. bdpan 首次登录（带外操作，**不**放进 unit）

登录是交互式的：CLI 打印一个 URL 与设备码，等你在浏览器里授权。systemd 里没有
TTY、也没人盯着屏幕，把它写进 `ExecStartPre=` 只会让服务在无人值守时卡住，所以
**登录是一次性的人工步骤**，与 unit 无关。

以**服务运行用户**登录（凭据按用户隔离，用 root 登录会让凭据落在 `/root` 下，
服务进程读不到）：

```bash
sudo -u lixinlong -H bash -lc 'bdpan login'
```

- 输出里的 URL 与设备码就是凭据：不要贴进 issue、聊天记录或提交信息。
- 凭据落在 `/home/lixinlong/.config/bdpan/`（`config.json`、`.token_key`），
  权限 `600`。
- token 约 30 天有效；续期由 CLI 自己完成，前提是该目录**可写**（第 4 节的沙箱说
  明为什么 `ProtectHome` 不能设成 `true`）。续期失败时 `/healthz` 会报
  `auth_failed`（第 8 节）。
- 确认方式（不要贴输出）：

```bash
sudo -u lixinlong -H /home/lixinlong/.local/bin/bdpan whoami
```

## 3. 安装二进制、配置与目录

```bash
# 1) 二进制
sudo install -m 755 target/release/netdisk-lfs /usr/local/bin/netdisk-lfs

# 2) 配置目录（750 让运行用户能进，其他人不能列目录）
sudo install -d -m 750 -o root -g lixinlong /etc/netdisk-lfs

# 3) 配置文件：600，owner 是运行用户（unit 以 lixinlong 读它）
sudo install -m 600 -o lixinlong -g lixinlong config.toml.example /etc/netdisk-lfs/config.toml
sudoedit /etc/netdisk-lfs/config.toml
```

`config.toml` 里必须改两处：

1. `[auth.users]` 的口令哈希与用户名。生成哈希：

   ```bash
   printf '%s' '<口令>' | sha256sum      # 取输出的第一个字段（64 个十六进制字符）
   ```

   `role` 只能是 `readwrite`（可上传可下载）或 `readonly`（只能下载）。
   不要把口令本身写进配置文件或提交信息。

2. `[storage] bdpan_bin` 指向真实的 CLI 绝对路径（默认已写好
   `/home/lixinlong/.local/bin/bdpan`）。

数据目录 `/var/lib/netdisk-lfs` 由 unit 的 `StateDirectory=` 在首次启动时创建并
chown 给 `User=`；想提前建也行：

```bash
sudo install -d -m 750 -o lixinlong -g lixinlong /var/lib/netdisk-lfs
```

> 目前没有 `--check-config` 之类的“只校验不启动”开关：配置错误会在启动时立刻以
> 非零码退出，错误信息带字段名（`journalctl -u netdisk-lfs -n 50` 即可看到）。
> 这是已知边界（第 10 节）。

## 4. systemd 安装与启动

```bash
sudo install -m 644 deploy/netdisk-lfs.service /etc/systemd/system/netdisk-lfs.service
# 可选：unit 的 Documentation= 指向这份本地副本（没有也不影响服务）
sudo install -D -m 644 docs/deploy.md /usr/share/doc/netdisk-lfs/deploy.md
sudo systemctl daemon-reload
sudo systemctl enable --now netdisk-lfs      # enable：开机自启；--now：立即启动
systemctl status netdisk-lfs
journalctl -u netdisk-lfs -f
```

首次启动会扫描缓存目录重建索引（200 GiB 预算、盘上已有大量对象时可能几十秒），
日志里出现「缓存启动扫描完成」才算就绪。这个扫描不受 systemd 启动超时约束
（unit 用 `Type=exec`，exec 成功即视为 started，原因写在 unit 注释里）。

冒烟检查：

```bash
curl -fsS http://127.0.0.1:9001/healthz            # 期望 {"status":"ok","bdpan":"ok","cache_enabled":true}
curl -s  http://127.0.0.1:9001/metrics | head      # 期望 6 个 netdisk_lfs_cache_* 指标
```

启动失败怎么查：

| 现象 | 常见原因 |
|---|---|
| `status=1`，日志有「配置加载失败」 | 字段拼错、缺字段、`objects_root` 不在 `/apps/bdpan/` 下、`cache.max_bytes = 0` |
| `status=1`，日志有「绑定监听地址失败」 | 9001 被占（`ss -ltnp \| grep 9001`），或 `listen` 写了别的地址 |
| `status=1`，日志有「创建缓存目录失败」 | `/var/lib/netdisk-lfs` 权限不对，或不在 `ReadWritePaths=` 内（`ProtectSystem=strict` 会拒绝写） |
| `/healthz` 503 `bdpan unavailable` | CLI 路径错/无执行权限/网盘不可达（第 8 节） |
| `/healthz` 503 `bdpan auth_failed` | token 过期或被吊销，重新 `bdpan login`（第 2 节） |

崩溃循环会被 systemd 限速（默认 5 次/10 秒），此时 `systemctl status` 显示
`start request repeated too quickly`；修好配置后 `sudo systemctl reset-failed netdisk-lfs`
再启动。

## 5. Caddy 反向代理（TLS + Basic 透传 + 保留流式）

```caddyfile
lfs.example.com {
	# 刻意不开全局 `encode`：对象响应的 Content-Type 是 application/octet-stream，
	# 压缩只会烧 CPU 并可能推迟流式刷新；batch/verify 的 JSON 很小，压缩收益可忽略。

	# 可选：不想把 /metrics 暴露到公网就挡掉（服务本身不鉴权）。
	@metrics path /metrics
	respond @metrics 404

	reverse_proxy 127.0.0.1:9001 {
		# 关闭响应刷新缓冲：4 GiB 对象要边读边发，攒包会让客户端首字节和进度卡住。
		flush_interval -1
	}
}
```

三条**不要做**：

1. **不要设请求体上限**（`request_body { max_size ... }`）。Caddy 默认不限，对象上限由
   服务端按 `storage.max_object_bytes` 判定并返回协议错误（422）。在反代先截断，客户端
   看到的是 413，`git lfs` 只会报一个语焉不详的传输失败。
2. **不要开响应缓冲，也不要开响应压缩**。本项目所有大对象都是流式转发
   （`Content-Length` + 逐块写），缓冲只会增加内存与首字节延迟；`application/
   octet-stream` 的对象再压一遍纯属浪费 CPU（LFS 里存的多半已经是压缩过的二进制）。
   确实想省内网带宽，就用 matcher 只对 `/lfs/objects/batch` 这类 JSON 响应启用
   `encode`，并保持对象路径不压缩。
3. **不要在 Caddy 里再配 `basic_auth`**。LFS 的凭据由服务端校验（`[auth.users]`），
   Caddy 默认透传 `Authorization` 头即可；再叠一层会出现两套口令、401 挑战头错乱，
   以及 `git-lfs` 反复重试认证。

防火墙只放 `80/443`；`9001` 只监听回环，不需要对外。若必须跨机抓取 `/metrics`，用
SSH 隧道或在内网直连，不要把它开到公网。

## 6. 客户端配置

仓库内提交 `.lfsconfig`（不含口令）：

```ini
[lfs]
url = https://lfs.example.com/lfs/
```

- 结尾的 `/` 必须保留：客户端会拼 `objects/batch`。
- 凭据交给 git credential（或 `~/.netrc`）：

  ```bash
  git config --global credential.https://lfs.example.com.helper store
  git lfs push --all origin main     # 首次会提示输入用户名/口令
  ```

- 只读账号（`role = "readonly"`）只能下载，`push` 会得到 403。
- 用自签证书时优先把 CA 装进系统信任库；临时绕过是
  `git config --global http.https://lfs.example.com.sslVerify false`（不推荐长期使用）。
- 排障时**不要**开 `GIT_CURL_VERBOSE`：它会把 `Authorization` 头（含 base64 口令）
  打到终端，粘日志前务必清掉。用 `GIT_TRACE=1 GIT_TRANSFER_TRACE=1` 足够看清
  协议往返。

## 7. 缓存运维

```bash
# 看缓存现状（对象数、已用/预算字节、命中/未命中/驱逐）
curl -s http://127.0.0.1:9001/metrics | grep '^netdisk_lfs_cache_'

# 清空缓存（随时可做，正确性不受影响，下一次 GET 会回源重下）
sudo systemctl stop netdisk-lfs
sudo rm -rf /var/lib/netdisk-lfs/cache/*
sudo systemctl start netdisk-lfs

# 调整预算：改 config.toml 的 cache.max_bytes 后重启，
# 启动扫描会按新预算做一次 LRU 收敛（不重启不会自动缩小）
sudoedit /etc/netdisk-lfs/config.toml
sudo systemctl restart netdisk-lfs
```

- 目录布局：`<cache.dir>/<aa>/<bb>/<oid>`；`*.part` 是在途下载的中转文件，
  启动时会删掉超过 1 小时的残留。
- 缓存命中不写盘（访问序记在内存），所以 `atime` 不可作运维依据，看 `/metrics`。
- 上传缓冲在 `/var/lib/netdisk-lfs/upload/`，正常情况下请求结束即删除，残留同样
  由启动清理兜底。
- 磁盘写满会让上传/入缓存失败（请求报错，缓存按“可降级”处理），目前**没有**
  剩余空间阈值主动拒绝上传（第 10 节），需要靠监控告警。

## 8. 排障：token 失效与降级

`/healthz` 是判定入口。它有三个降级维度，任何一项不对就回 **503**：

```json
{"status":"degraded","bdpan":"auth_failed","cache_enabled":true}
```

| 字段/取值 | 含义 | 处理 |
|---|---|---|
| `bdpan="ok"` | `bdpan whoami` 成功 | — |
| `bdpan="auth_failed"` | token 过期或被吊销 | 重新 `bdpan login`（第 2 节），无需重启：探活结论最多 30s 后自动刷新 |
| `bdpan="unavailable"` | CLI 起不来/输出无法解析/网盘不可达 | 看 `journalctl` 里带 `cmd=` 的 warn，检查 `bdpan_bin`、PATH、网络 |
| `cache_enabled=false` | 缓存目录建不出来或扫描失败，已降级为直通 | 看启动 warn，检查目录权限与 `ReadWritePaths=` |

**token 失效不等于服务不可用**：它只影响回源（batch 探测、PUT、缓存未命中的 GET）。
已经在本地缓存里的对象仍可正常下载，只是没有缓存的请求会失败。所以看到 503 时先
确认影响面，再去续 token，不要把缓存也一起清掉（会让影响面扩大到全部对象）。

定位具体请求：

```bash
# 每条响应都有服务端生成的 x-request-id，把它与日志里的 request_id 对上
journalctl -u netdisk-lfs --since "15 min ago" | grep -i 'bdpan 探活失败'
journalctl -u netdisk-lfs --since "15 min ago" | grep '<粘贴的 request_id>'
```

> 请求 id 一律由服务端生成：客户端或反代传来的 `x-request-id` 不会被采信（防止伪造
> 关联关系），回写的是服务端自己那个。

## 9. 升级流程

```bash
# 1) 构建（在开发机或服务器上）
cargo build --release --locked

# 2) 留一份回滚用的旧二进制
sudo cp -a /usr/local/bin/netdisk-lfs /usr/local/bin/netdisk-lfs.bak

# 3) 换二进制并重启
sudo systemctl stop netdisk-lfs
sudo install -m 755 target/release/netdisk-lfs /usr/local/bin/netdisk-lfs
sudo systemctl start netdisk-lfs

# 4) 验收
curl -fsS http://127.0.0.1:9001/healthz
curl -s  http://127.0.0.1:9001/metrics | grep -c '^netdisk_lfs_'
```

- 停机窗口主要是启动时的缓存扫描（重建索引，不重新下载对象），保留
  `/var/lib/netdisk-lfs/cache` 就不会变长。
- 改了 unit 文件要 `sudo systemctl daemon-reload`；只改 `config.toml` 要
  `sudo systemctl restart netdisk-lfs`。
- 回滚：把 `netdisk-lfs.bak` 换回去再 `restart`，配置向后兼容（新字段有默认值；
  本仓库目前没有破坏性配置变更）。

## 10. 已知边界

| 边界 | 说明 |
|---|---|
| 单实例 | 进程内强制：`DATA_DIR/netdisk-lfs.lock` 的 flock 由内核维护，第二个实例启动即失败（崩溃自动释放，无残留锁）。跨机器仍没有分布式锁，同 oid 并发上传只靠 `mv` 冲突兜底 |
| token 30 天 | access_token 官方有效期 30 天、刷新后仍 30 天；长期凭据是 refresh_token（官方文档标称 **10 年**）。`bdpan` 内置刷新流程（`grant_type=refresh_token`），前提是 `~/.config/bdpan` 可写；只有 refresh_token 失效/被撤销或用户解除授权才需人工 `login` |
| 单对象 4 GiB | 超限直接 422，不做分片；3 GiB 以上的真实对象仍待端到端实测 |
| 无 LFS 锁 | `git lfs lock` 系列端点未实现 |
| 无配额/限速 | 不按用户限额，也没有请求速率限制 |
| 指标有限 | `/metrics` 只有缓存维度；HTTP 延迟/状态码计数尚未导出 |
| 无配置自检 | 没有 `--check-config`，配置错误靠启动失败暴露 |
| 故障发现延迟 | 探活结论缓存 30s，最长 30s 后才发现 token 失效（换来的是不为每个探针起子进程） |
| 磁盘写满 | 请求会失败，但没有“剩余空间低于阈值就拒绝上传”的主动保护 |
| 无优雅分片上传 | 客户端 `git lfs` 的 basic transfer 是一次 PUT 整个对象，中断即重传 |

## 11. 监控接入

Prometheus 抓取（只在同机或经隧道可达，因为服务只听回环）：

```yaml
scrape_configs:
  - job_name: netdisk-lfs
    static_configs:
      - targets: ["127.0.0.1:9001"]     # 与 Prometheus 同机；跨机请走 ssh -L 或内网直连
```

```bash
# 跨机抓取的最小做法（读端执行）
ssh -N -L 9001:127.0.0.1:9001 lixinlong@lfs-host
```

建议告警：

| 指标来源 | 条件 | 含义 |
|---|---|---|
| `/healthz` 状态码 | 持续 503 超过 2 分钟 | 后端不可用或 token 失效 |
| `netdisk_lfs_cache_used_bytes / netdisk_lfs_cache_max_bytes` | 长期 > 0.9 | 预算太小，缓存在反复淘汰 |
| `rate(netdisk_lfs_cache_evictions_total[10m])` | 明显 > 0 | 同上，且表现为反复回源 |
| `rate(netdisk_lfs_cache_misses_total[10m])` | 突然抬升 | 新仓库拉取、缓存被清、或对象集合变化 |

## 12. 一键安装与卸载脚本

`scripts/` 下两个脚本把第 3、4 节的步骤自动化，默认装到 `/opt/netdisk-lfs`：

```bash
# 安装（默认 /opt/netdisk-lfs；会构建 release、渲染 unit、启动服务）
sudo scripts/deploy.sh

# 只装文件、不碰 systemd（无 root 也可，供自测/容器用）
SKIP_SYSTEMD=1 PREFIX=/tmp/ndlfs-smoke/opt/netdisk-lfs scripts/deploy.sh

# 卸载（默认保留配置与数据，方便重装）
sudo scripts/uninstall.sh

# 彻底清理（连 /etc/netdisk-lfs 与 /var/lib/netdisk-lfs 一起删）
sudo scripts/uninstall.sh --yes --purge
```

脚本行为约定：

| 行为 | 说明 |
|---|---|
| 安装位置 | `PREFIX`（默认 `/opt/netdisk-lfs`）：`bin/netdisk-lfs` + `share/deploy.md` + `share/config.toml.example` |
| 配置 | 缺失时才从 `config.toml.example` 生成到 `CONFIG_DIR`（默认 `/etc/netdisk-lfs`，权限 `600`），并把 `bdpan_bin`、`cache.dir` 改成当前环境值；**已存在则不覆盖**，但会校正属主并检查 `bdpan_bin`/`cache.dir` 是否与当前身份、`DATA_DIR` 一致 |
| 数据 | 创建 `DATA_DIR` 及 `cache/`、`upload/` 并 chown 给运行用户（默认 `/var/lib/netdisk-lfs`） |
| unit | 由 `deploy/netdisk-lfs.service` 渲染 `ExecStart`/`User`/`Group`/`WorkingDirectory`/`Environment`/`ReadWritePaths`（每个替换都校验模板未漂移），安装后 `daemon-reload` + `enable` + `restart`，再用 `is-active` 确认进程没在崩溃循环 |
| 构建 | 以调用用户（`SUDO_USER`）身份 `cargo build --release --locked`，避免 root 污染 `target/` 与 sudo 的 secure_path 找不到 cargo |
| 运行身份 | 默认 `$SUDO_USER`；不允许 root（bdpan 凭据在普通用户家目录） |
| 幂等 | 重复执行只刷新二进制与 unit 并重启服务（可当升级用），配置不动 |
| 路径安全 | 所有路径先归一化（去尾斜杠、拒绝空段/`.`/`..`），再按白名单校验：`PREFIX` 只能在 `/opt`、`/usr/local`、`/tmp` 下，`CONFIG_DIR` 只能在 `/etc`、`/tmp` 下，`DATA_DIR` 只能在 `/var/lib`、`/tmp` 下，且不能等于这些顶层目录本身 |
| 自测 | `scripts/deploy.sh --self-test` / `scripts/uninstall.sh --self-test` 覆盖归一化与白名单边界；`SKIP_SYSTEMD=1` 且 `UNIT_DIR` 仍是 `/etc/systemd/system` 时，卸载脚本拒绝删除 unit 文件，避免自测误删生产 unit |
| 卸载护栏 | 默认保留配置与数据；`--purge` 才删除；非交互环境必须显式 `--yes`；每个删除步骤失败都会带上下文报错 |
| 不触碰 | bdpan 登录凭据（`~/.config/bdpan`）、Caddy 配置、网盘对象 |

脚本不做、需要你手动完成的两件事：替换配置里的占位口令哈希、以运行用户执行 `bdpan login`
（见第 2 节）。命令细节用 `scripts/deploy.sh --help` / `scripts/uninstall.sh --help` 查看。

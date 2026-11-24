# 账户与权限

netdisk-lfs 的账户分三级：只读、读写、管理员。账户存在服务端的 SQLite 库
（`accounts.db`）里，口令用 Argon2id；`config.toml` 的 `[auth.users]` 退居**引导与
应急**入口。部署步骤见 [deploy.md](deploy.md)，本文只讲账户模型、注册审批、管理员
操作、备份与迁移。

> 客户端始终是 HTTP Basic：每次请求都带用户名与口令，服务端每次请求都查库（或比对
> config 里的摘要）。没有 cookie，也没有会话，因此也没有「退出登录」。

## 1. 角色与权限

| 角色 | 下载 | 上传（batch / PUT） | 管理账户 | 典型用途 |
|---|---|---|---|---|
| `readonly` | ✅ | ❌ 403 | ❌ | CI 拉取、只读镜像、临时借看 |
| `readwrite` | ✅ | ✅ | ❌ | 日常开发（新账户默认） |
| `admin` | ✅ | ✅ | ✅ | 运维、团队负责人 |

- `admin` 拥有 `readwrite` 的全部 LFS 权限，额外可访问 `/admin` 与 `/admin/*`。
- 只读账户的 upload 请求在 **batch 阶段**就返回 403（`只读账号不允许 upload 操作`），
  不会先传完几个 GiB 再拒绝；直接 `PUT /lfs/objects/{oid}` 同样是 403。
- 角色只能由管理员或配置文件改变，用户不能给自己升权。

## 2. 账户状态

| 状态 | 含义 | 能否登录 | 怎么产生 |
|---|---|---|---|
| `active` | 正常可用 | ✅ | `open` 策略注册、管理员创建/批准、config 用户首次登录懒升级 |
| `pending` | 待管理员审批 | ❌ 401 | `approval` 策略下的自助注册 |
| `disabled` | 已禁用（记录保留） | ❌ 401 | 管理员禁用 |

- 非 `active` 账户即使口令正确也进不来；具体状态只写日志（`reason=inactive_account`），
  响应与「口令错误」完全一致（401），不泄漏账户是否存在。
- `disabled` 不删除账户，也不删任何对象；重新启用即恢复。
- 账户库里没有、只在 `[auth.users]` 里的旧账户，一律视为 `active`（状态由配置文件决定，
  即删掉条目就不能登录了）。

## 3. 引导管理员

管理员**不能**自助注册，只能由配置文件引导：

```toml
[auth.users]
maintainer = { password_sha256 = "<sha256>", role = "admin" }
```

- `[accounts] default_role` 不允许写 `admin`（启动时报配置错误）——否则开放注册等于把
  管理员权限发给所有人。
- 用该账户首次登录成功后，服务会把明文口令换成 Argon2id 写进 `accounts.db`，此后以库里
  的记录为准：再改 config 里的哈希不影响这个账户（要改就用 `/account/password`）。
- 一个 admin 都没有时，服务照常提供 LFS 读写，但 `/admin` 与 `/admin/*` 一律 403，
  自助注册出来的 `pending` 账户没人能批准。部署后**第一件事**就是用引导管理员登录一次、
  打开 `/admin` 确认能进。
- 建议长期保留至少一个 config 引导管理员：账户库误删或损坏时，它还能重新建库登录。它的
  用户名要挑一个不容易被猜到的：自助注册只查账户库，不查 `[auth.users]`（见第 10 节）。

## 4. 注册与审批

### 4.1 用户视角

1. 浏览器打开 `https://lfs.example.com/account/register`；
2. 填用户名（3–32 个 `A-Z a-z 0-9 . _ -`）与口令，再确认一次。口令至少
   `min_password_len` 个字符（默认 12），不能等于用户名，不能全为空白；
3. 提交后页面提示「已提交，等待管理员审批」——此时账户是 `pending`，Git 客户端登录
   会拿到 401；
4. 管理员批准后，用同一组凭据即可 `git lfs pull` / `git lfs push`。

`registration = "open"` 时第 3 步变成「立即可以登录」；`closed` 时注册页显示「注册已
关闭」，提交直接 403。

注册页与结果页都是无脚本的静态 HTML，内联样式、不引外部资源，也不回显口令。

**保留用户名**：`[auth.users]` 里已有的用户名不能自助注册。否则账户库优先会让原 config
账户——通常就是引导管理员——再也登不上，属于可被利用的抢占路径。对外与普通重名返回
**同一条 409 文案**「用户名已被占用」，不暴露哪些名字是配置里的引导账户；管理员在
`POST /admin/users` 显式创建同名账户不受限，那是迁移动作。`closed` 策略下注册一律 403，
且策略判定先于任何用户名/口令检查（连非法用户名也 403），不给探测留差异。

### 4.2 管理员视角

浏览器打开 `https://lfs.example.com/admin`（会弹 Basic 认证框，用 admin 账户登录）。
页面是账户表格：`pending` 行可以批准，其他行可以启用/禁用、删除、改角色、重置口令。
表单提交后回到列表页，没有 JavaScript。

也可以用 JSON 直接查待审批的账户：

```bash
curl -fsS -u 'admin:<管理员口令>' \
  'https://lfs.example.com/admin/users?status=pending'
```

### 4.3 注册接口与状态码

`POST /account/register` 不需要认证，同时接受 JSON 与浏览器表单：

```bash
curl -sS -o /dev/null -w '%{http_code}\n' \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"<至少 12 位口令>"}' \
  https://lfs.example.com/account/register
```

| 情况 | 状态码 | 说明 |
|---|---|---|
| `approval`（默认） | 202 | 建 `pending`，等管理员批准 |
| `open` | 201 | 建 `active`，立即可登录 |
| 用户名已存在，或在 `[auth.users]` 里保留 | 409 | 同一文案「用户名已被占用」，不区分原因 |
| 用户名/口令不合法 | 400 | 按提示修正；口令至少 `min_password_len` 位 |
| 超过注册限速 | 429 | 按 `Retry-After` 等待 |
| `closed` | 403 | 自助注册关闭，只能由管理员开户 |
| 用户名已被占用 | 409 | 账户库里已有同名账户（不与 `[auth.users]` 查重，见第 10 节） |
| 输入不合法 | 400 | 用户名规则、口令策略、两次口令不一致 |
| 超出注册限速 | 429 | 带 `Retry-After` 头 |
| 账户库不可用 | 503 | 库打不开或在请求中查询失败（磁盘满、文件被删、权限不对） |

- 表单（`application/x-www-form-urlencoded`）必须带 `username`、`password`、
  `confirm_password`；JSON 里 `confirm_password` 可选，给了也会校验。
- 表单请求回 HTML 结果页，状态码与 JSON 一致；错误页里带 `request_id`，便于对照日志。
- 请求体上限 16 KiB，超出 400。

## 5. 登录后的自身账户

三个端点都挂 Basic 认证（任意角色），只能操作**自己**：

| 方法与路径 | 作用 | 成功响应 |
|---|---|---|
| `GET /account/me` | 查看自己 | 200 `{username, role, status, created_at, last_login_at}` |
| `POST /account/password` | 改自己的口令 | 204 |
| `DELETE /account` | 注销自己 | 204 |

```bash
# 我是谁
curl -fsS -u 'alice:<口令>' https://lfs.example.com/account/me

# 改口令：旧口令错 → 401；新口令不合策略 → 400
curl -sS -o /dev/null -w '%{http_code}\n' -u 'alice:<旧口令>' \
  -H 'Content-Type: application/json' \
  -d '{"old_password":"<旧口令>","new_password":"<新口令>"}' \
  https://lfs.example.com/account/password

# 注销：口令错 → 401；最后一个 active admin → 409
curl -sS -o /dev/null -w '%{http_code}\n' -u 'alice:<口令>' -X DELETE \
  -H 'Content-Type: application/json' -d '{"password":"<口令>"}' \
  https://lfs.example.com/account
```

- 用户名取自认证结果，没有「指定他人」的入口，所以不存在越权改他人账户。
- 只在 `[auth.users]` 里、尚未懒升级的旧账户不能自助改密/注销（503 / 409），改
  `config.toml` 后重启即可。
- **注销只删账户，不删任何 LFS 对象**：对象全局共享、内容寻址，别的仓库可能引用同一个
  oid。日志里会写明这一点。
- 如果 `[auth.users]` 里还有同名条目，注销会成功，但会打一条 warn：那套旧 config 口令
  会重新可用。迁移完成后请清掉不再需要的条目。

## 6. 管理员操作

### 6.1 JSON API

| 方法与路径 | 作用 |
|---|---|
| `GET /admin/users?status=&limit=&offset=` | 列表（分页，返回总数；`limit` 缺省 50、单页上限 100） |
| `POST /admin/users` | 创建账户（绕过注册策略，可直接给 `active` 或 `admin`） |
| `PATCH /admin/users/{name}` | 改角色/状态；批准 pending 就是 `{"status":"active"}` |
| `DELETE /admin/users/{name}` | 删除账户 |
| `POST /admin/users/{name}/password` | 重置他人口令（不需要旧口令，旧口令立即失效） |

列表响应是 `{users: [...], total: <总数>}`；账户视图与 `/account/me` 同构，不含口令
哈希。错误体沿用 `{message, request_id}`。

```bash
BASE=https://lfs.example.com
AUTH='admin:<管理员口令>'

# 列表（默认第一页）
curl -fsS -u "$AUTH" "$BASE/admin/users?limit=50&offset=0"

# 创建：直接 active 的只读 CI 账户
curl -sS -o /dev/null -w '%{http_code}\n' -u "$AUTH" \
  -H 'Content-Type: application/json' \
  -d '{"username":"ci-bot","password":"<至少 12 位口令>","role":"readonly","status":"active"}' \
  "$BASE/admin/users"

# 批准 pending 账户
curl -sS -o /dev/null -w '%{http_code}\n' -u "$AUTH" -X PATCH \
  -H 'Content-Type: application/json' -d '{"status":"active"}' \
  "$BASE/admin/users/alice"

# 降为只读 / 禁用 / 重新启用（把 role 换成 status 即可）
curl -sS -o /dev/null -w '%{http_code}\n' -u "$AUTH" -X PATCH \
  -H 'Content-Type: application/json' -d '{"role":"readonly"}' \
  "$BASE/admin/users/alice"

# 重置口令
curl -sS -o /dev/null -w '%{http_code}\n' -u "$AUTH" -X POST \
  -H 'Content-Type: application/json' -d '{"password":"<新口令>"}' \
  "$BASE/admin/users/alice/password"

# 删除（不删任何 LFS 对象）
curl -sS -o /dev/null -w '%{http_code}\n' -u "$AUTH" -X DELETE \
  "$BASE/admin/users/alice"
```

保护规则：

| 规则 | 结果 |
|---|---|
| 删除自己 | 拒绝（改用 `DELETE /account`） |
| 改/删自己 | 409（删除自己请走 `DELETE /account`，需要旧口令） |
| 删除/降级/禁用最后一个 `active` admin | 409：先加另一个 admin 或保留 config 引导管理员 |
| 删除库里有、`[auth.users]` 也有同名条目的账户 | 409：删掉库行会让旧 config 口令复活，先移除配置条目 |
| 非 admin 访问 `/admin` 或 `/admin/*` | 403 |
| 账户不存在，或只在 `[auth.users]`、尚未登录升级入库 | 404（提示先登录一次完成入库） |
| 写请求跨站（`Origin`/`Sec-Fetch-Site` 不符） | 403；用 curl 等无来源头的客户端不受影响 |
| JSON 写请求的 `Content-Type` 不是 JSON | 415 |

最后一个 admin 的判定同时看账户库与 `[auth.users]`；config 里的**同名**条目不算
「另一个管理员」（删掉库行只是同一个人重新拿到 config 权限）。检查与写入在账户库的
同一个事务里完成，两个管理员并发互相降级/删除时只会成功一个，不会出现「零管理员」。
已知边界：config 兜底管理员若在账户库里的行已被 `disabled`，仍会被算作「另一个管理员」。

### 6.2 HTML 管理页

`GET /admin` 需要 Basic 认证（admin），页面提供批准、启用、禁用、删除、改角色、重置
口令的表单。适合手机或临时处理；批量操作、脚本化仍建议用 JSON API，两者改的是同一份
账户库、同一套保护规则。

表单提交到这些**便捷端点**（只接受表单 POST，成功一律 `303 → /admin[?status=…]`，
失败页状态码与 JSON 一致）：

| 方法与路径 | 表单字段 | 作用 |
|---|---|---|
| `POST /admin/users/{name}/approve` | — | `pending → active` |
| `POST /admin/users/{name}/disable` | — | `active → disabled` |
| `POST /admin/users/{name}/enable` | — | `disabled → active` |
| `POST /admin/users/{name}/role` | `role` | 改角色 |
| `POST /admin/users/{name}/password-form` | `password` | 重置口令 |
| `POST /admin/users/{name}/delete` | `confirm`（必填勾选） | 删除账户 |

页面上的时间按 **UTC** 显示；每页最多 100 行，底部有上一页/下一页链接（保留
`?status=`），也可以直接用 `?offset=` 跳页。

**CSRF 与媒体类型**：管理端所有写请求（JSON 与表单）都会校验同站来源——
`Sec-Fetch-Site` 只接受 `same-origin`/`same-site`/`none`，否则回落比对 `Origin` 与
`Host` 的主机名；两者都没有的 CLI 请求放行。因此反代必须保留原始 `Host`
（Caddy 默认满足），否则浏览器写操作会被 403。JSON 写端点只收
`Content-Type: application/json`（可带 `+json`），表单端点只收
`application/x-www-form-urlencoded`，其余一律 **415**。

## 7. 配置

`[accounts]` 段的全部字段（也见 [config.toml.example](../config.toml.example)）：

```toml
[accounts]
db = "/var/lib/netdisk-lfs/accounts.db"
min_password_len = 12
registration = "approval"
default_role = "readwrite"
registration_per_hour = 5
login_failures_per_5min = 10
trust_proxy = false
```

| 键 | 默认值 | 说明 |
|---|---|---|
| `db` | 空，取 `$NETDISK_LFS_DATA_DIR/accounts.db` | 账户库路径，必须绝对路径；两项都没配则启动报错 |
| `min_password_len` | 12 | 口令最小字符数，允许 `1..=128` |
| `registration` | `approval` | `approval` / `open` / `closed` |
| `default_role` | `readwrite` | 新注册账户的角色：`readonly` 或 `readwrite`，不能是 `admin` |
| `registration_per_hour` | 5 | 每个来源地址每小时的注册成功上限，`0` = 不限 |
| `login_failures_per_5min` | 10 | 每个用户名 5 分钟内的登录失败上限，`0` = 不限 |
| `trust_proxy` | false | 用 `X-Forwarded-For` 的**最后一段**作为注册限速来源 |

账户库是本机 SQLite（WAL 模式），服务启动时自动创建，父目录不存在也会建。

### 7.1 常见组合

| 场景 | 建议 |
|---|---|
| 公网 / 团队（推荐） | `approval` + `readwrite`：注册要审批，新人是读写 |
| 内网小圈子 | `open` + `readwrite`：注册即用 |
| 只自己用 | `closed`：不接受注册，全部由管理员 `POST /admin/users` 开户 |
| 只读镜像 / 分发 | `approval` + `readonly`：批准后也只能下载 |

### 7.2 口令与认证

- 新口令一律 **Argon2id**（PHC 字符串，盐与参数编码在哈希里），校验时读串内参数，
  日后调参不需要迁移旧哈希。
- 策略：长度 `min_password_len..=128`、不能等于用户名（不区分大小写）、不能全空白。
  注册、改密、管理员创建与重置都走同一套校验。
- 旧 `[auth.users]` 的 sha256 口令仍能登录，但**首次成功登录后立即升级为 Argon2id
  写库**；此后以库为准。
- **DB 优先**：账户库里有该用户名时，`[auth.users]` 的同名条目完全不参与认证。改 config
  里的哈希不会改掉已入库账户的口令——请用 `/account/password` 或管理员重置。
- 账户库里没有的 config 用户名（例如 2 个字符的历史用户名，达不到账户库 3–32 的规则）
  继续走 config 校验，不会每登录一次就尝试入库。

### 7.3 限速

| 限制 | 键 | 窗口 | 计数方式 |
|---|---|---|---|
| 注册 | `registration_per_hour` | 1 小时 | 按来源地址；只有**创建成功**才计数 |
| 登录失败 | `login_failures_per_5min` | 5 分钟 | 按小写用户名；成功登录清零；超限后**即使口令正确也 429** |

- 注册限速的检查排在参数校验之前：超额时统一先回 429。只有**创建成功**才计数，被 429
  拒掉或校验失败的请求都不延长窗口，避免攻击者把额度耗在无效请求上。
- `trust_proxy = true` 时来源地址取 `X-Forwarded-For` 的**最后一段**（代理是追加语义，
  第一段由客户端控制、可伪造）。只有服务确实在自己控制的反代之后才打开：直连场景下
  这个头完全由客户端控制，打开等于关掉注册限速。
- 限速是进程内存状态：重启清零，多实例不共享（本项目按单实例设计）。

## 8. 备份与恢复

`accounts.db` 是**运行数据**，与缓存正相反：缓存随时可删（下一次 GET 回源），账户库删了
就没人能登录。

| 文件 | 内容 | 能否删除 |
|---|---|---|
| `accounts.db` | 账户、Argon2id 哈希、角色、状态、创建/登录时间 | ❌ 必须纳入备份 |
| `accounts.db-wal` / `-shm` | WAL 模式的在途页与共享内存索引 | 正常停服后会被合并/清理，不单独备份 |

权限：文件由服务进程创建，unit 的 `UMask=0027` 得到 `0640`。里面有口令哈希，不要放宽到
world-readable。

### 8.1 在线备份（推荐，不停服务）

```bash
sudo install -d -m 700 /var/backups/netdisk-lfs
sudo sqlite3 /var/lib/netdisk-lfs/accounts.db \
  ".backup '/var/backups/netdisk-lfs/accounts-$(date +%F).db'"
```

`.backup` 是 SQLite 的一致性快照（自动处理 WAL），比 `cp` 安全。服务器没装 `sqlite3`
命令行时用 8.2 的停机复制。

### 8.2 停机备份

```bash
sudo systemctl stop netdisk-lfs
sudo cp -a /var/lib/netdisk-lfs/accounts.db /var/backups/netdisk-lfs/
sudo systemctl start netdisk-lfs
```

正常停服时最后一个连接关闭会 checkpoint 并删除 `-wal`，主库即完整；进程被 `kill -9`
或机器断电后，要连 `accounts.db-wal` 一起复制。

### 8.3 恢复

```bash
# 1) 停服务，并留一份现状（恢复错了还能退回去）
sudo systemctl stop netdisk-lfs
sudo cp -a /var/lib/netdisk-lfs/accounts.db /var/lib/netdisk-lfs/accounts.db.before-restore

# 2) 放回备份；旧 WAL 必须清掉，否则会和主库对不上
sudo install -m 640 -o <运行用户> -g <运行用户> \
  /var/backups/netdisk-lfs/accounts-2026-11-24.db /var/lib/netdisk-lfs/accounts.db
sudo rm -f /var/lib/netdisk-lfs/accounts.db-wal /var/lib/netdisk-lfs/accounts.db-shm

# 3) 启动并验证
sudo systemctl start netdisk-lfs
curl -fsS http://127.0.0.1:9001/healthz
```

恢复后用管理员打开 `/admin/users` 核对账户数，再抽查一个普通账户能否 `git lfs pull`。
`uninstall.sh --purge` 会删除整个数据目录（含账户库），卸载前先备份。

### 8.4 丢失管理员

按顺序试：

1. **加一个未入库的引导管理员**：在 `[auth.users]` 里加一个**新用户名**、`role = "admin"`，
   重启后用它登录。库里没有这个名字，会走 config 校验并自动入库，然后到 `/admin` 重置
   或恢复目标账户。
2. **直接改库**（先备份）：停服务后执行
   `sqlite3 /var/lib/netdisk-lfs/accounts.db "UPDATE users SET role='admin', status='active' WHERE username='<名字>';"`，
   再启动。运行中改库有并发风险，务必先停服务。
3. **删库重建**（最后手段）：所有账户丢失，LFS 对象不受影响。删掉 `accounts.db` 后重启，
   `[auth.users]` 的条目会在各自首次登录时重新入库。

不要指望「改掉 config 里同名条目的口令」来救一个已入库或被禁用的账户：库里有同名记录
时 config 完全不参与。

## 9. 安全建议

- **公网一律 `approval`**；只自己用就 `closed`。`open` 只适合内网/小圈子——公网上等于
  允许陌生人占用户名、消耗注册额度。
- **全程 HTTPS**：Basic 每次请求都带 base64 口令，明文 HTTP 等于公开口令；注册页与
  `/admin` 同样要经反向代理。
- **`trust_proxy` 只在可信反代之后开**：Caddy 默认会追加 `X-Forwarded-For`，取最后一段
  即真实客户端；服务直连公网时保持 `false`。
- **口令不要复用**：这是存在 LFS 客户端里的第三方口令，泄露影响面要按「网盘里所有
  对象」评估。
- **管理员越少越好**，改完权限后过一眼审计日志。
- **登录与管理页**：401 同时带 `WWW-Authenticate: Basic realm="netdisk-lfs"`，浏览器
  打开 `/admin` 会正常弹登录框（git-lfs 仍优先看 `lfs-authenticate`）。
- **审计日志走 journald**（写操作 `actor/action/target/request_id`，`action` 取
  `user.create` / `user.update` / `user.delete` / `user.reset_password`，口令不落日志）：

  ```bash
  # 注册、登录失败、改密、注销、config 用户懒升级
  journalctl -u netdisk-lfs --since today | grep -E '注册|认证失败|账户|管理员'

  # 管理员操作（actor / action / target / request_id）
  journalctl -u netdisk-lfs --since today | grep 'admin'
  ```

  管理员操作都带 `request_id`，与响应头 `x-request-id` 对得上，可用来追一次具体操作。
- 反向代理上**不要**再叠一层 Basic Auth（见 [deploy.md](deploy.md) 5.3）：会出现两套
  口令与 401 挑战头错乱。

## 10. 已知限制

| 限制 | 说明 |
|---|---|
| 无邮箱验证 | 服务没有邮件通道，注册不验证邮箱，用户名只是个名字 |
| 无找回口令 | 忘记口令只能让管理员重置（`POST /admin/users/{name}/password`），或改 config 引导管理员 |
| 无邀请码 | 不实现 invite 模式；控制谁能注册请用 `approval` / `closed` |
| 注册查重只看账户库 | 自助注册不与 `[auth.users]` 比对：用引导管理员的名字注册会建出一条库记录，此后 DB 优先，原 config 账户反而登不上（`pending` 时一律 401）。给引导管理员取一个不易猜到的名字，或直接用 `closed` |
| 账户与对象无归属 | 对象全局共享、内容寻址：删账户**不删任何 LFS 对象**，也没有「某人的对象」视图 |
| 无会话 | 每次请求都做 Basic 认证，浏览器管理页每次打开都会弹认证框；没有退出登录 |
| 用户名不可改 | 改用户名等于重建账户（对象本来就不归属账户，影响有限） |
| 无按账户配额/限速 | 只有注册与登录失败限速；传输速率与容量仍不按账户限制（见 deploy.md 第 10 节） |
| 单实例 | 账户库是本机 SQLite，按单实例设计；多实例共享同一个 `accounts.db` 不受支持 |

## 11. 从纯 config 账户迁移

升级前只有 `[auth.users]`（sha256 + `readonly`/`readwrite`）。切到账户库是**向后兼容**的：

1. **备份** `config.toml` 与数据目录（至少 `accounts.db`，已有的话）。
2. **加配置段**：`[accounts]` 整段可以留空（`db` 为空时取
   `$NETDISK_LFS_DATA_DIR/accounts.db`），建议先保持 `registration = "approval"`。
3. **指定引导管理员**：把日常用的账户改成 `role = "admin"`：

   ```toml
   [auth.users]
   maintainer = { password_sha256 = "<sha256>", role = "admin" }
   ```

4. **重启**：`sudo systemctl restart netdisk-lfs`，确认 `/healthz` 正常（配置没有热更新）。
5. **触发升级**：用这个账户请求一次，例如
   `curl -fsS -u 'maintainer:<口令>' https://lfs.example.com/account/me`。日志里出现
   「config 用户首次登录，已升级为 Argon2id 账户」就说明已经入库；此后 config 里的哈希
   不再影响它。
6. **确认管理入口**：浏览器打开 `https://lfs.example.com/admin` 应能看到账户列表。看不到
   就是没有 admin：检查第 3 步与重启。
7. **收敛 config**：其余账户在各自首次登录时自动入库；都迁移完成后，可以删掉不再需要的
   `[auth.users]` 条目，只留一个引导管理员。

两个容易踩的坑：

- **改了 config 口令却登录不上**：该账户已入库，库优先。用升级那一刻的明文口令登录，
  或让管理员重置。
- **迁移后想改管理员口令**：改 config 无效，用 `POST /account/password` 或让另一个管理员
  重置。

未迁移的旧账户行为不变，可以长期与账户库并存：库里有就查库，库里没有就回落到 config。

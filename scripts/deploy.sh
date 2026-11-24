#!/usr/bin/env bash
#
# netdisk-lfs 一键部署：构建 release 二进制，安装到 /opt/netdisk-lfs（默认），
# 生成配置与 systemd unit，并（默认）启动/重启服务。
#
# 完整用法：scripts/deploy.sh --help
#
# 默认值：PREFIX=/opt/netdisk-lfs  CONFIG_DIR=/etc/netdisk-lfs
#         DATA_DIR=/var/lib/netdisk-lfs  UNIT_DIR=/etc/systemd/system
# 运行身份：$SUDO_USER（不允许 root）。SKIP_BUILD=1 复用已有 release 二进制；
# SKIP_SYSTEMD=1 只落文件不碰 systemd（自测用，需同时覆盖四个路径变量到可写目录）。
#
# 相关文档：docs/deploy.md（首次 bdpan 登录、Caddy 反代、排障）。

set -euo pipefail

PREFIX="${PREFIX:-/opt/netdisk-lfs}"
CONFIG_DIR="${CONFIG_DIR:-/etc/netdisk-lfs}"
DATA_DIR="${DATA_DIR:-/var/lib/netdisk-lfs}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="netdisk-lfs.service"
SERVICE_USER="${SERVICE_USER:-${SUDO_USER:-$(id -un)}}"
SKIP_BUILD="${SKIP_BUILD:-0}"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "$SCRIPT_DIR/.." && pwd)"

info()  { printf '\033[32m[deploy]\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m[deploy] 警告：\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[31m[deploy] 错误：\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法：scripts/deploy.sh [--help] [--self-test]

环境变量（默认值）：
  PREFIX        安装根目录            /opt/netdisk-lfs
  CONFIG_DIR    配置目录              /etc/netdisk-lfs
  DATA_DIR      本地数据根            /var/lib/netdisk-lfs
  UNIT_DIR      systemd unit 目录     /etc/systemd/system
  SERVICE_USER  运行身份              $SUDO_USER（不允许 root）
  SKIP_BUILD=1  不重新构建，复用 target/release/netdisk-lfs
  SKIP_SYSTEMD=1 只装文件，不执行 systemctl（自测；需把四个路径都指到可写目录）

行为：
  - 已存在的 CONFIG_DIR/config.toml 不会被覆盖，只校正属主并检查 bdpan 路径；
  - 二进制、unit 每次刷新；服务用 enable + restart 生效（可当升级用）；
  - 构建以调用者身份执行（避免 root 污染 target/），安装以 root 执行。

路径安全：PREFIX 只允许 /opt、/usr/local、/tmp 之下，CONFIG_DIR 只允许 /etc、/tmp，
DATA_DIR 只允许 /var/lib、/tmp，且不允许等于这些顶层目录本身。
EOF
}

# ---------------------------------------------------------------- 路径安全
# 去掉尾部斜杠（"/opt/" → "/opt"），死循环保护："/" 本身保持不动。
normalize_path() {
  local path="$1"
  while [[ "$path" == */ && "$path" != "/" ]]; do path="${path%/}"; done
  printf '%s\n' "$path"
}

# 路径里不允许空段、"."、".."：这些会让 rm -rf 的去向与肉眼看到的不一致。
has_bad_segments() {
  local path="$1" segment
  IFS='/' read -ra segments <<< "${path#/}"
  for segment in "${segments[@]}"; do
    [[ -z "$segment" || "$segment" == "." || "$segment" == ".." ]] && return 0
  done
  return 1
}

under_root() {
  local path="$1" root="$2"
  [[ "$path" == "$root" || "$path" == "$root/"* ]]
}

# 校验一个可写路径：必须是绝对路径、没有坏段、且落在允许的根之下、且不等于根本身。
require_under() {
  local name="$1" path="$2"
  shift 2
  local root
  [[ "$path" == /* ]] || die "$name 必须是绝对路径：$path"
  has_bad_segments "$path" && die "$name 含空段/./..，拒绝使用：$path"
  for root in "$@"; do
    under_root "$path" "$root" || continue
    [[ "$path" != "$root" ]] || die "$name 不能等于顶层目录：$path"
    return 0
  done
  die "$name 必须位于 $* 之下，实际为：$path"
}

# 最近的已存在祖先目录是否可写（不创建任何东西）。
nearest_writable() {
  local path="$1"
  while [[ ! -e "$path" ]]; do
    [[ "$path" == "/" ]] && return 1
    path="$(dirname -- "$path")"
  done
  [[ -w "$path" ]]
}

self_test() {
  local failures=0
  check() {
    local expected="$1" actual="$2" label="$3"
    if [[ "$actual" == "$expected" ]]; then
      printf 'ok   %s\n' "$label"
    else
      printf 'FAIL %s（期望 %s，实际 %s）\n' "$label" "$expected" "$actual"
      failures=$((failures + 1))
    fi
  }
  check "/opt/netdisk-lfs" "$(normalize_path "/opt/netdisk-lfs/")" "尾斜杠归一化"
  check "/" "$(normalize_path "/")" "根路径保持"
  check 0 "$(has_bad_segments "/opt/x/../y"; echo $?)" "拒绝 .. 段"
  check 0 "$(has_bad_segments "/opt//x"; echo $?)" "拒绝空段"
  check 0 "$(under_root "/opt/netdisk-lfs/bin" "/opt"; echo $?)" "前缀匹配"
  check 1 "$(under_root "/opt2/x" "/opt"; echo $?)" "不误匹配 /opt2"
  if [[ "$failures" -ne 0 ]]; then
    printf '%s 个自测失败\n' "$failures" >&2
    exit 1
  fi
  info "自测通过"
  exit 0
}

case "${1:-}" in
  -h|--help) usage; exit 0 ;;
  --self-test) self_test ;;
esac

# ---------------------------------------------------------------- 归一化与前置校验
PREFIX="$(normalize_path "$PREFIX")"
CONFIG_DIR="$(normalize_path "$CONFIG_DIR")"
DATA_DIR="$(normalize_path "$DATA_DIR")"
UNIT_DIR="$(normalize_path "$UNIT_DIR")"

require_under PREFIX "$PREFIX" /opt /usr/local /tmp
require_under CONFIG_DIR "$CONFIG_DIR" /etc /tmp
require_under DATA_DIR "$DATA_DIR" /var/lib /tmp
# unit 目录允许就是 /etc/systemd/system 本身（默认值），只删/装其中的 netdisk-lfs.service。
[[ "$UNIT_DIR" == /* ]] || die "UNIT_DIR 必须是绝对路径：$UNIT_DIR"
has_bad_segments "$UNIT_DIR" && die "UNIT_DIR 含空段/./..，拒绝使用：$UNIT_DIR"
{ under_root "$UNIT_DIR" /etc/systemd/system || under_root "$UNIT_DIR" /tmp; } || \
  die "UNIT_DIR 必须位于 /etc/systemd/system 或 /tmp 之下，实际为：$UNIT_DIR"

[[ "$(id -u)" -eq 0 ]] || [[ "$SKIP_SYSTEMD" == "1" ]] || \
  die "需要 root（sudo scripts/deploy.sh）；只装文件可加 SKIP_SYSTEMD=1"

[[ -f "$REPO_ROOT/Cargo.toml" ]] || die "找不到仓库根（$REPO_ROOT/Cargo.toml），请从仓库内运行"
[[ "$SERVICE_USER" != "root" ]] || \
  die "SERVICE_USER 不能是 root：bdpan 凭据在普通用户家目录，服务以 root 跑会读不到"

SERVICE_HOME="$(getent passwd "$SERVICE_USER" | cut -d: -f6 || true)"
[[ -n "$SERVICE_HOME" ]] || die "取不到用户 $SERVICE_USER 的家目录"
SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
BDPAN_BIN="$SERVICE_HOME/.local/bin/bdpan"
BDPAN_DIR="$(dirname "$BDPAN_BIN")"

# 非 root 的 SKIP_SYSTEMD 自测：必须在构建前就确认四个目录都可写，否则白等一次构建。
if [[ "$(id -u)" -ne 0 ]]; then
  for target in "$PREFIX" "$CONFIG_DIR" "$DATA_DIR" "$UNIT_DIR"; do
    nearest_writable "$target" || \
      die "非 root 且 $target 不可写；自测请把 PREFIX/CONFIG_DIR/DATA_DIR/UNIT_DIR 都指到 /tmp 下可写目录"
  done
fi

if [[ ! -x "$BDPAN_BIN" ]]; then
  warn "找不到 $BDPAN_BIN（服务运行时会用它；先按 docs/deploy.md 第 2 节安装并登录 bdpan）"
fi

info "安装根：$PREFIX"
info "配置目录：$CONFIG_DIR"
info "数据目录：$DATA_DIR"
info "运行身份：$SERVICE_USER:$SERVICE_GROUP（bdpan：$BDPAN_BIN）"

# ---------------------------------------------------------------- 构建
BINARY="$REPO_ROOT/target/release/netdisk-lfs"
if [[ "$SKIP_BUILD" == "1" ]]; then
  [[ -x "$BINARY" ]] || die "SKIP_BUILD=1 但找不到 $BINARY；先 cargo build --release --locked"
else
  BUILD_USER="${SUDO_USER:-$(id -un)}"
  if [[ "$(id -u)" -eq 0 && "$BUILD_USER" != "root" ]]; then
    # 以调用者身份构建：sudo 的 secure_path 不含 ~/.cargo/bin，root 也别污染 target/。
    info "以 $BUILD_USER 身份构建（cargo build --release --locked）…"
    sudo -u "$BUILD_USER" -H bash -lc \
      "cd '$REPO_ROOT' && cargo build --release --locked" || \
      die "构建失败（检查 $BUILD_USER 的 Rust 工具链与网络）"
  else
    command -v cargo >/dev/null 2>&1 || \
      die "找不到 cargo：把 ~/.cargo/bin 加进 PATH 或安装 Rust 工具链"
    info "构建 release 二进制（cargo build --release --locked）…"
    ( cd "$REPO_ROOT" && cargo build --release --locked )
  fi
  [[ -x "$BINARY" ]] || die "构建结束但 $BINARY 不存在"
fi

# ---------------------------------------------------------------- 目录与二进制
info "安装二进制与目录…"
install -d -m 0755 "$PREFIX" "$PREFIX/bin" "$PREFIX/share"
install -m 0755 "$BINARY" "$PREFIX/bin/netdisk-lfs"
install -m 0644 "$REPO_ROOT/docs/deploy.md" "$PREFIX/share/deploy.md"
install -m 0644 "$REPO_ROOT/config.toml.example" "$PREFIX/share/config.toml.example"

install -d -m 0750 "$DATA_DIR" "$DATA_DIR/cache" "$DATA_DIR/upload"
if [[ "$(id -u)" -eq 0 ]]; then
  chown -R "$SERVICE_USER:$SERVICE_GROUP" "$DATA_DIR"
fi

# ---------------------------------------------------------------- 配置
install -d -m 0750 "$CONFIG_DIR"
if [[ "$(id -u)" -eq 0 ]]; then
  chown "root:$SERVICE_GROUP" "$CONFIG_DIR"
fi

CONFIG_FILE="$CONFIG_DIR/config.toml"
if [[ -f "$CONFIG_FILE" ]]; then
  info "配置已存在，保持内容不动：$CONFIG_FILE"
  if [[ "$(id -u)" -eq 0 ]]; then
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_FILE"
  fi
  configured_bdpan="$(sed -n 's/^bdpan_bin = "\(.*\)"$/\1/p' "$CONFIG_FILE" | head -n1)"
  if [[ -n "$configured_bdpan" && "$configured_bdpan" != "$BDPAN_BIN" ]]; then
    warn "配置里的 bdpan_bin=$configured_bdpan 与当前运行身份期望的 $BDPAN_BIN 不一致"
  fi
  configured_cache="$(sed -n 's/^dir = "\(.*\)"$/\1/p' "$CONFIG_FILE" | head -n1)"
  if [[ -n "$configured_cache" ]] && ! under_root "$configured_cache" "$DATA_DIR"; then
    warn "配置里的 cache.dir=$configured_cache 不在当前 DATA_DIR=$DATA_DIR 之下："
    warn "systemd 的 ReadWritePaths 只放行 DATA_DIR，缓存会被拒绝写并静默降级为直通"
  fi
  if grep -q 'password_sha256 = "0000000000000000000000000000000000000000000000000000000000000000"' "$CONFIG_FILE"; then
    warn "配置里仍有占位口令哈希，部署后无法登录；见下方「后续必做」第 1 条"
  fi
else
  info "生成配置：$CONFIG_FILE（占位口令哈希，需手动替换）"
  install -m 0600 "$REPO_ROOT/config.toml.example" "$CONFIG_FILE"
  sed -i "s|^bdpan_bin = .*|bdpan_bin = \"${BDPAN_BIN}\"|" "$CONFIG_FILE"
  sed -i "s|^dir = .*|dir = \"${DATA_DIR}/cache\"|" "$CONFIG_FILE"
  grep -q "^bdpan_bin = \"${BDPAN_BIN}\"$" "$CONFIG_FILE" || die "配置替换失败：bdpan_bin"
  grep -q "^dir = \"${DATA_DIR}/cache\"$" "$CONFIG_FILE" || die "配置替换失败：cache.dir"
  if [[ "$(id -u)" -eq 0 ]]; then
    chown "$SERVICE_USER:$SERVICE_GROUP" "$CONFIG_FILE"
  fi
fi

# ---------------------------------------------------------------- systemd unit
info "渲染 systemd unit：$UNIT_DIR/$UNIT_NAME"
UNIT_TMP="$(mktemp)"
trap 'rm -f "$UNIT_TMP"' EXIT
cp "$REPO_ROOT/deploy/netdisk-lfs.service" "$UNIT_TMP"

sed -i "s|^ExecStart=.*|ExecStart=${PREFIX}/bin/netdisk-lfs --config ${CONFIG_DIR}/config.toml|" "$UNIT_TMP"
sed -i "s|^User=.*|User=${SERVICE_USER}|" "$UNIT_TMP"
sed -i "s|^Group=.*|Group=${SERVICE_GROUP}|" "$UNIT_TMP"
sed -i "s|^WorkingDirectory=.*|WorkingDirectory=${DATA_DIR}|" "$UNIT_TMP"
sed -i "s|^Environment=NETDISK_LFS_DATA_DIR=.*|Environment=NETDISK_LFS_DATA_DIR=${DATA_DIR}|" "$UNIT_TMP"
sed -i "s|^Environment=PATH=.*|Environment=PATH=${BDPAN_DIR}:/usr/local/bin:/usr/bin:/bin|" "$UNIT_TMP"
sed -i "s|^ReadWritePaths=.*|ReadWritePaths=${DATA_DIR}|" "$UNIT_TMP"
sed -i "s|^Documentation=file:.*|Documentation=file:${PREFIX}/share/deploy.md|" "$UNIT_TMP"

# StateDirectory 只接受 /var/lib 下的相对名；自定义数据目录时不启用它。
if [[ "$DATA_DIR" == /var/lib/?* && "${DATA_DIR#/var/lib/}" != */* ]]; then
  sed -i "s|^StateDirectory=.*|StateDirectory=${DATA_DIR#/var/lib/}|" "$UNIT_TMP"
else
  sed -i "s|^StateDirectory=.*|# StateDirectory 已移除：数据目录 ${DATA_DIR} 不在 /var/lib 下（目录由 deploy.sh 创建）|" "$UNIT_TMP"
fi

# 每个替换都要验证：unit 模板漂移时必须立刻失败，而不是装一个半成品。
grep -q "^ExecStart=${PREFIX}/bin/netdisk-lfs " "$UNIT_TMP" || die "unit 渲染失败：ExecStart"
grep -q "^User=${SERVICE_USER}$" "$UNIT_TMP" || die "unit 渲染失败：User"
grep -q "^Group=${SERVICE_GROUP}$" "$UNIT_TMP" || die "unit 渲染失败：Group"
grep -q "^WorkingDirectory=${DATA_DIR}$" "$UNIT_TMP" || die "unit 渲染失败：WorkingDirectory"
grep -q "^Environment=NETDISK_LFS_DATA_DIR=${DATA_DIR}$" "$UNIT_TMP" || die "unit 渲染失败：NETDISK_LFS_DATA_DIR"
grep -q "^Environment=PATH=${BDPAN_DIR}:" "$UNIT_TMP" || die "unit 渲染失败：PATH"
grep -q "^ReadWritePaths=${DATA_DIR}$" "$UNIT_TMP" || die "unit 渲染失败：ReadWritePaths"
grep -q "^Documentation=file:${PREFIX}/share/deploy.md$" "$UNIT_TMP" || die "unit 渲染失败：Documentation"

install -d -m 0755 "$UNIT_DIR"
install -m 0644 "$UNIT_TMP" "$UNIT_DIR/$UNIT_NAME"

# ---------------------------------------------------------------- 启动/重启
DEPLOY_FAILED=0
if [[ "$SKIP_SYSTEMD" == "1" ]]; then
  warn "SKIP_SYSTEMD=1：未执行 systemctl（自测模式）"
elif command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload || { warn "daemon-reload 失败"; DEPLOY_FAILED=1; }
  # enable 负责开机自启；restart 对「未启动」和「已在跑旧二进制」都正确——
  # 只 enable --now 会在升级时留下旧进程继续服务。
  systemctl enable "$UNIT_NAME" || { warn "enable 失败"; DEPLOY_FAILED=1; }
  systemctl restart "$UNIT_NAME" || { warn "restart 失败（journalctl -u $UNIT_NAME 查看原因）"; DEPLOY_FAILED=1; }
  if [[ "$DEPLOY_FAILED" == "0" ]]; then
    # Type=exec 下 restart 成功不代表进程活着（可能 exec 后立刻崩），再确认一次。
    sleep 2
    if systemctl is-active --quiet "$UNIT_NAME"; then
      info "服务已启用并运行：systemctl status $UNIT_NAME"
    else
      warn "服务启动后未保持运行（journalctl -u $UNIT_NAME 查看原因）"
      DEPLOY_FAILED=1
    fi
  fi
else
  warn "系统没有 systemctl：unit 已安装到 $UNIT_DIR，请按 docs/deploy.md 手动启用"
fi

# ---------------------------------------------------------------- 收尾提示
cat <<EOF

[deploy] 部署完成（服务管理失败时见上方警告）。
后续必做（本脚本不会替你做）：
  1. 编辑配置，把占位口令哈希换成真实值：
       sudoedit $CONFIG_FILE
       # 生成哈希：printf '%s' '<口令>' | sha256sum   （取 64 位十六进制，别加换行）
     改完重启：sudo systemctl restart $UNIT_NAME
  2. 用运行用户登录 bdpan（凭据在 $SERVICE_HOME/.config/bdpan，带外操作）：
       sudo -u $SERVICE_USER -H $BDPAN_BIN login
  3. 探活与观测：
       curl -s http://127.0.0.1:9001/healthz
       curl -s http://127.0.0.1:9001/metrics
  4. 对外暴露走 Caddy 反代（不要直连公网），见 $PREFIX/share/deploy.md

卸载：sudo "$SCRIPT_DIR/uninstall.sh"（默认保留配置与数据，--purge 才删除）
EOF

if [[ "$DEPLOY_FAILED" != "0" ]]; then
  exit 1
fi

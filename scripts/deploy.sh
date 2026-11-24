#!/usr/bin/env bash
#
# netdisk-lfs 一键部署：构建 release 二进制，安装到 /opt/netdisk-lfs（默认），
# 生成配置与 systemd unit，并（默认）启动服务。
#
# 用法：
#   sudo scripts/deploy.sh                        # 默认：/opt/netdisk-lfs + /etc/netdisk-lfs + /var/lib/netdisk-lfs
#   sudo PREFIX=/opt/netdisk-lfs-test scripts/deploy.sh
#   sudo SKIP_BUILD=1 scripts/deploy.sh           # 复用现有 target/release/netdisk-lfs
#   sudo SKIP_SYSTEMD=1 scripts/deploy.sh         # 只落文件，不碰 systemd（无 root 也可用，供自测）
#
# 可覆盖的环境变量（默认见下方常量）：
#   PREFIX        安装根目录             默认 /opt/netdisk-lfs
#   CONFIG_DIR    配置目录               默认 /etc/netdisk-lfs
#   DATA_DIR      本地数据根（缓存/上传） 默认 /var/lib/netdisk-lfs
#   UNIT_DIR      systemd unit 目录      默认 /etc/systemd/system
#   SERVICE_USER  运行身份               默认 $SUDO_USER（无则取当前用户；不允许 root）
#   SKIP_BUILD    1 = 不重新构建
#   SKIP_SYSTEMD  1 = 不执行 systemctl（仅测试/容器用）
#
# 幂等说明：
#   - 已存在的 $CONFIG_DIR/config.toml **不会被覆盖**（含口令哈希，重复部署不应丢配置）；
#     只会在缺失时从 config.toml.example 生成，并把 bdpan 路径与 cache 目录改成当前环境值。
#   - 二进制、systemd unit 每次都会刷新为当前构建产物。
#
# 相关文档：docs/deploy.md（首次 bdpan 登录、Caddy 反代、排障）。

set -euo pipefail

# ---------------------------------------------------------------- 默认值
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

# ---------------------------------------------------------------- 输出小工具
info() { printf '\033[32m[deploy]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[deploy] 警告：\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[deploy] 错误：\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  sed -n '2,30p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'
  exit 0
}
case "${1:-}" in
  -h|--help) usage ;;
esac

# ---------------------------------------------------------------- 前置检查
[[ "$(id -u)" -eq 0 ]] || [[ "$SKIP_SYSTEMD" == "1" ]] || \
  die "需要 root（sudo scripts/deploy.sh）；只装文件可加 SKIP_SYSTEMD=1"

[[ -f "$REPO_ROOT/Cargo.toml" ]] || die "找不到仓库根（$REPO_ROOT/Cargo.toml），请从仓库内运行本脚本"
[[ "$SERVICE_USER" != "root" ]] || \
  die "SERVICE_USER 不能是 root：bdpan 凭据在普通用户家目录，服务以 root 跑会读不到"

SERVICE_HOME="$(getent passwd "$SERVICE_USER" | cut -d: -f6 || true)"
[[ -n "$SERVICE_HOME" ]] || die "取不到用户 $SERVICE_USER 的家目录（getent passwd 失败）"
SERVICE_GROUP="$(id -gn "$SERVICE_USER")"
BDPAN_BIN="$SERVICE_HOME/.local/bin/bdpan"
BDPAN_DIR="$(dirname "$BDPAN_BIN")"

info "安装根：$PREFIX"
info "配置目录：$CONFIG_DIR"
info "数据目录：$DATA_DIR"
info "运行身份：$SERVICE_USER:$SERVICE_GROUP（bdpan：$BDPAN_BIN）"

# ---------------------------------------------------------------- 构建
if [[ "$SKIP_BUILD" == "1" ]]; then
  BINARY="$REPO_ROOT/target/release/netdisk-lfs"
  [[ -x "$BINARY" ]] || die "SKIP_BUILD=1 但找不到 $BINARY；先 cargo build --release"
else
  command -v cargo >/dev/null 2>&1 || \
    die "找不到 cargo（把 ~/.cargo/bin 加进 PATH，或安装 Rust 工具链）"
  info "构建 release 二进制（cargo build --release --locked）…"
  ( cd "$REPO_ROOT" && cargo build --release --locked )
  BINARY="$REPO_ROOT/target/release/netdisk-lfs"
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
  info "配置已存在，保持不动：$CONFIG_FILE"
else
  info "生成配置：$CONFIG_FILE（占位口令哈希，需手动替换）"
  install -m 0600 "$REPO_ROOT/config.toml.example" "$CONFIG_FILE"
  # 把样例里的部署形态值替换成当前环境的实际值（路径必须与 unit/数据目录一致）。
  sed -i "s|^bdpan_bin = .*|bdpan_bin = \"${BDPAN_BIN}\"|" "$CONFIG_FILE"
  sed -i "s|^dir = .*|dir = \"${DATA_DIR}/cache\"|" "$CONFIG_FILE"
  grep -q "^bdpan_bin = \"${BDPAN_BIN}\"" "$CONFIG_FILE" || die "配置替换失败：bdpan_bin"
  grep -q "^dir = \"${DATA_DIR}/cache\"" "$CONFIG_FILE" || die "配置替换失败：cache.dir"
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

grep -q "^ExecStart=${PREFIX}/bin/netdisk-lfs " "$UNIT_TMP" || die "unit 渲染失败：ExecStart"
grep -q "^User=${SERVICE_USER}$" "$UNIT_TMP" || die "unit 渲染失败：User"
grep -q "^ReadWritePaths=${DATA_DIR}$" "$UNIT_TMP" || die "unit 渲染失败：ReadWritePaths"

install -d -m 0755 "$UNIT_DIR"
install -m 0644 "$UNIT_TMP" "$UNIT_DIR/$UNIT_NAME"

# ---------------------------------------------------------------- 启动
if [[ "$SKIP_SYSTEMD" == "1" ]]; then
  warn "SKIP_SYSTEMD=1：未执行 systemctl，也未校验 unit（自测模式）"
elif command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload
  systemctl enable --now "$UNIT_NAME"
  info "服务已启用并启动：systemctl status $UNIT_NAME"
else
  warn "系统没有 systemctl：unit 已安装到 $UNIT_DIR，请按 docs/deploy.md 手动启用"
fi

# ---------------------------------------------------------------- 收尾提示
cat <<EOF

$(info "部署完成。")
后续必做（本脚本不会替你做）：
  1. 编辑配置，把占位口令哈希换成真实值：
       sudoedit $CONFIG_FILE
       # 生成哈希：printf '%s' '<口令>' | sha256sum   （取 64 位十六进制，别加换行）
     改完重启：sudo systemctl restart $UNIT_NAME
  2. 用运行用户登录 bdpan（凭据在 $SERVICE_HOME/.config/bdpan，带外操作）：
       sudo -u $SERVICE_USER -H bdpan login
  3. 探活与观测：
       curl -s http://127.0.0.1:9001/healthz
       curl -s http://127.0.0.1:9001/metrics
  4. 对外暴露走 Caddy 反代（不要直连公网），见 $PREFIX/share/deploy.md

卸载：sudo "$SCRIPT_DIR/uninstall.sh"（默认保留配置与数据，--purge 才删除）
EOF

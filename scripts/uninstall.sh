#!/usr/bin/env bash
#
# netdisk-lfs 卸载：停止并移除 systemd 服务，删除安装目录。
#
# 默认行为（保守）：
#   - 停服务、禁用开机启动、删除 unit、删 $PREFIX（默认 /opt/netdisk-lfs）；
#   - **保留**配置（/etc/netdisk-lfs）与数据（/var/lib/netdisk-lfs，含缓存），
#     方便重装或排查；加 --purge 才一并删除。
#
# 用法：
#   sudo scripts/uninstall.sh                  # 交互确认
#   sudo scripts/uninstall.sh --yes            # 不询问
#   sudo scripts/uninstall.sh --yes --purge    # 连配置与数据一起删
#   sudo SKIP_SYSTEMD=1 PREFIX=/tmp/x scripts/uninstall.sh --yes   # 自测
#
# 可覆盖的环境变量同 deploy.sh：PREFIX CONFIG_DIR DATA_DIR UNIT_DIR。
# 安全约束：拒绝删除 /、/opt、/etc、/var、/tmp 等顶层目录，且路径至少两级。
#
# 不会动的东西：bdpan 登录凭据（~/.config/bdpan）、Caddy 配置、备份。

set -euo pipefail

PREFIX="${PREFIX:-/opt/netdisk-lfs}"
CONFIG_DIR="${CONFIG_DIR:-/etc/netdisk-lfs}"
DATA_DIR="${DATA_DIR:-/var/lib/netdisk-lfs}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="netdisk-lfs.service"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"
ASSUME_YES=0
PURGE=0

for arg in "$@"; do
  case "$arg" in
    -h|--help) sed -n '2,28p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --purge) PURGE=1 ;;
    *) printf '未知参数：%s（--help 查看用法）\n' "$arg" >&2; exit 2 ;;
  esac
done

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"

info() { printf '\033[32m[uninstall]\033[0m %s\n' "$*"; }
warn() { printf '\033[33m[uninstall] 警告：\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[31m[uninstall] 错误：\033[0m %s\n' "$*" >&2; exit 1; }

# ---------------------------------------------------------------- 安全护栏
# 只允许删除「至少两级、且不在顶层目录名单里」的绝对路径。
is_safe_path() {
  local path="$1"
  [[ "$path" == /* ]] || return 1
  case "$path" in
    /|/opt|/etc|/var|/var/lib|/usr|/usr/local|/home|/root|/tmp|/srv|/boot) return 1 ;;
  esac
  # 去掉开头 / 后按 / 切分，至少两级（如 /opt/netdisk-lfs）。
  local rest="${path#/}"
  [[ "$rest" == */* ]] || return 1
  [[ "$path" != *"/.."* && "$path" != *"//"* ]] || return 1
  return 0
}

confirm() {
  local prompt="$1"
  if [[ "$ASSUME_YES" == "1" ]]; then
    return 0
  fi
  [[ -t 0 ]] || die "非交互环境请加 --yes（待确认：$prompt）"
  local answer
  read -r -p "$prompt [y/N] " answer
  [[ "$answer" == "y" || "$answer" == "Y" ]]
}

[[ "$(id -u)" -eq 0 ]] || [[ "$SKIP_SYSTEMD" == "1" ]] || \
  die "需要 root（sudo scripts/uninstall.sh）；只删文件可加 SKIP_SYSTEMD=1"

is_safe_path "$PREFIX" || die "拒绝删除不安全的安装路径：$PREFIX"
if [[ "$PURGE" == "1" ]]; then
  is_safe_path "$DATA_DIR" || die "拒绝删除不安全的数据路径：$DATA_DIR"
  is_safe_path "$CONFIG_DIR" || die "拒绝删除不安全的配置路径：$CONFIG_DIR"
fi

info "将卸载：$PREFIX（二进制与文档）"
[[ "$PURGE" == "1" ]] && info "并将删除：$CONFIG_DIR 与 $DATA_DIR（--purge）"
[[ "$PURGE" == "0" ]] && info "配置与数据会保留：$CONFIG_DIR、$DATA_DIR"

confirm "确认卸载？" || { info "已取消"; exit 0; }

# ---------------------------------------------------------------- 停服务
if [[ "$SKIP_SYSTEMD" == "1" ]]; then
  warn "SKIP_SYSTEMD=1：跳过 systemctl 操作"
elif command -v systemctl >/dev/null 2>&1; then
  if systemctl list-unit-files "$UNIT_NAME" >/dev/null 2>&1; then
    info "停止并禁用 $UNIT_NAME"
    systemctl disable --now "$UNIT_NAME" 2>/dev/null || warn "服务停止/禁用未完全成功（可能本来就没跑）"
  else
    info "服务未安装，跳过 stop/disable"
  fi
else
  warn "系统没有 systemctl，跳过服务操作"
fi

# ---------------------------------------------------------------- 删 unit
if [[ -f "$UNIT_DIR/$UNIT_NAME" ]]; then
  info "删除 unit：$UNIT_DIR/$UNIT_NAME"
  rm -f "$UNIT_DIR/$UNIT_NAME"
  if [[ "$SKIP_SYSTEMD" != "1" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload
  fi
else
  info "unit 不存在，跳过：$UNIT_DIR/$UNIT_NAME"
fi

# ---------------------------------------------------------------- 删安装目录
if [[ -d "$PREFIX" ]]; then
  info "删除安装目录：$PREFIX"
  rm -rf -- "$PREFIX"
else
  info "安装目录不存在，跳过：$PREFIX"
fi

# ---------------------------------------------------------------- 可选：配置与数据
if [[ "$PURGE" == "1" ]]; then
  if [[ -d "$CONFIG_DIR" ]]; then
    info "删除配置目录：$CONFIG_DIR"
    rm -rf -- "$CONFIG_DIR"
  fi
  if [[ -d "$DATA_DIR" ]]; then
    info "删除数据目录：$DATA_DIR"
    rm -rf -- "$DATA_DIR"
  fi
else
  warn "已保留配置与数据（重装时可直接复用）；彻底清理：加 --purge"
fi

cat <<EOF

$(info "卸载完成。")
未触碰：bdpan 登录凭据（~/.config/bdpan）、Caddy 配置与证书、网盘上的对象。
如需清理网盘对象：bdpan rm /apps/bdpan/lfs/objects -R（确认无其他使用者后再执行）。
EOF

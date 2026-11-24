#!/usr/bin/env bash
#
# netdisk-lfs 卸载：停止并移除 systemd 服务，删除安装目录。
#
# 默认行为（保守）：停服务、禁用开机启动、删除 unit、删 $PREFIX（默认 /opt/netdisk-lfs）；
# **保留**配置（/etc/netdisk-lfs）与数据（/var/lib/netdisk-lfs，含缓存），
# 方便重装或排查；加 --purge 才一并删除。
#
# 完整用法：scripts/uninstall.sh --help
#
# 安全约束：路径先去尾斜杠并检查空段/./..，再按白名单校验——
#   PREFIX 只允许 /opt、/usr/local、/tmp 之下，CONFIG_DIR 只允许 /etc、/tmp，
#   DATA_DIR 只允许 /var/lib、/tmp；且都不允许等于顶层目录本身（如 /opt/）。
#
# 不会动：bdpan 登录凭据（~/.config/bdpan）、Caddy 配置、网盘对象。

set -euo pipefail

PREFIX="${PREFIX:-/opt/netdisk-lfs}"
CONFIG_DIR="${CONFIG_DIR:-/etc/netdisk-lfs}"
DATA_DIR="${DATA_DIR:-/var/lib/netdisk-lfs}"
UNIT_DIR="${UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="netdisk-lfs.service"
SKIP_SYSTEMD="${SKIP_SYSTEMD:-0}"
ASSUME_YES=0
PURGE=0

info()  { printf '\033[32m[uninstall]\033[0m %s\n' "$*"; }
warn()  { printf '\033[33m[uninstall] 警告：\033[0m %s\n' "$*" >&2; }
die()   { printf '\033[31m[uninstall] 错误：\033[0m %s\n' "$*" >&2; exit 1; }

usage() {
  cat <<'EOF'
用法：scripts/uninstall.sh [--yes] [--purge] [--self-test] [--help]

  --yes      不询问（非交互环境必须）
  --purge    连配置（CONFIG_DIR）与数据（DATA_DIR）一起删除；默认保留

环境变量（默认值）：PREFIX=/opt/netdisk-lfs CONFIG_DIR=/etc/netdisk-lfs
                    DATA_DIR=/var/lib/netdisk-lfs UNIT_DIR=/etc/systemd/system
  SKIP_SYSTEMD=1  不执行 systemctl；且当 UNIT_DIR 仍是默认 /etc/systemd/system 时
                  不删除 unit 文件（保护生产环境，自测请覆盖 UNIT_DIR）

路径安全：只允许删除 /opt、/usr/local、/tmp 下的 PREFIX，/etc、/tmp 下的 CONFIG_DIR，
/var/lib、/tmp 下的 DATA_DIR；拒绝 /、/opt/、含 .. 或空段的路径。
EOF
}

# ---------------------------------------------------------------- 路径安全
normalize_path() {
  local path="$1"
  while [[ "$path" == */ && "$path" != "/" ]]; do path="${path%/}"; done
  printf '%s\n' "$path"
}

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
  check 0 "$(under_root "/opt/netdisk-lfs" "/opt"; echo $?)" "前缀匹配"
  check 1 "$(under_root "/opt2/x" "/opt"; echo $?)" "不误匹配 /opt2"
  if [[ "$failures" -ne 0 ]]; then
    printf '%s 个自测失败\n' "$failures" >&2
    exit 1
  fi
  info "自测通过"
  exit 0
}

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    --yes|-y) ASSUME_YES=1 ;;
    --purge) PURGE=1 ;;
    --self-test) self_test ;;
    *) printf '未知参数：%s（--help 查看用法）\n' "$arg" >&2; exit 2 ;;
  esac
done

# ---------------------------------------------------------------- 归一化与校验
PREFIX="$(normalize_path "$PREFIX")"
CONFIG_DIR="$(normalize_path "$CONFIG_DIR")"
DATA_DIR="$(normalize_path "$DATA_DIR")"
UNIT_DIR="$(normalize_path "$UNIT_DIR")"

require_under PREFIX "$PREFIX" /opt /usr/local /tmp
[[ "$UNIT_DIR" == /* ]] || die "UNIT_DIR 必须是绝对路径：$UNIT_DIR"
has_bad_segments "$UNIT_DIR" && die "UNIT_DIR 含空段/./..，拒绝使用：$UNIT_DIR"
{ under_root "$UNIT_DIR" /etc/systemd/system || under_root "$UNIT_DIR" /tmp; } || \
  die "UNIT_DIR 必须位于 /etc/systemd/system 或 /tmp 之下，实际为：$UNIT_DIR"
if [[ "$PURGE" == "1" ]]; then
  require_under CONFIG_DIR "$CONFIG_DIR" /etc /tmp
  require_under DATA_DIR "$DATA_DIR" /var/lib /tmp
fi

[[ "$(id -u)" -eq 0 ]] || [[ "$SKIP_SYSTEMD" == "1" ]] || \
  die "需要 root（sudo scripts/uninstall.sh）；只删文件可加 SKIP_SYSTEMD=1"

info "将卸载：$PREFIX（二进制与文档）"
if [[ "$PURGE" == "1" ]]; then
  info "并将删除：$CONFIG_DIR 与 $DATA_DIR（--purge）"
else
  info "配置与数据会保留：$CONFIG_DIR、$DATA_DIR"
fi

confirm "确认卸载？" || { info "已取消"; exit 0; }

REMOVED_UNIT=0
UNIT_FILE="$UNIT_DIR/$UNIT_NAME"

# ---------------------------------------------------------------- 停服务
if [[ -f "$UNIT_FILE" ]] && [[ "$SKIP_SYSTEMD" != "1" ]] && command -v systemctl >/dev/null 2>&1; then
  info "停止并禁用 $UNIT_NAME"
  systemctl disable --now "$UNIT_NAME" || warn "服务停止/禁用未完全成功（可能本来就没跑）"
elif [[ ! -f "$UNIT_FILE" ]]; then
  info "未发现 unit 文件，跳过服务操作：$UNIT_FILE"
fi

# ---------------------------------------------------------------- 删 unit
if [[ ! -f "$UNIT_FILE" ]]; then
  info "unit 不存在，跳过：$UNIT_FILE"
elif [[ "$SKIP_SYSTEMD" == "1" ]] && [[ "$UNIT_DIR" == "/etc/systemd/system" ]]; then
  # 自测模式 + 默认 unit 目录：删掉它会在服务仍运行时打消生产 unit（重启即失效）。
  warn "SKIP_SYSTEMD=1 且 UNIT_DIR 是生产目录，跳过 unit 删除：$UNIT_FILE"
else
  info "删除 unit：$UNIT_FILE"
  rm -f -- "$UNIT_FILE" || die "删除 unit 失败：$UNIT_FILE"
  REMOVED_UNIT=1
  if [[ "$SKIP_SYSTEMD" != "1" ]] && command -v systemctl >/dev/null 2>&1; then
    systemctl daemon-reload || warn "daemon-reload 失败（unit 文件已删，影响仅在下次开机）"
  fi
fi

# ---------------------------------------------------------------- 删安装目录
if [[ -d "$PREFIX" ]]; then
  info "删除安装目录：$PREFIX"
  rm -rf -- "$PREFIX" || die "删除安装目录失败：$PREFIX（可能有进程占用或权限不足）"
else
  info "安装目录不存在，跳过：$PREFIX"
fi

# ---------------------------------------------------------------- 可选：配置与数据
if [[ "$PURGE" == "1" ]]; then
  if [[ -d "$CONFIG_DIR" ]]; then
    info "删除配置目录：$CONFIG_DIR"
    rm -rf -- "$CONFIG_DIR" || die "删除配置目录失败：$CONFIG_DIR"
  fi
  if [[ -d "$DATA_DIR" ]]; then
    info "删除数据目录：$DATA_DIR"
    rm -rf -- "$DATA_DIR" || die "删除数据目录失败：$DATA_DIR（服务可能仍在运行）"
  fi
else
  warn "已保留配置与数据（重装时可直接复用）；彻底清理：加 --purge"
fi

if [[ "$REMOVED_UNIT" == "0" ]] && [[ -f "$UNIT_FILE" ]]; then
  warn "unit 文件仍在：$UNIT_FILE（服务可能在下次开机时重新启动）"
fi

cat <<EOF

[uninstall] 卸载完成。
未触碰：bdpan 登录凭据（~/.config/bdpan）、Caddy 配置与证书、网盘上的对象。
如需清理网盘对象：bdpan rm /apps/bdpan/lfs/objects -R（确认无其他使用者后再执行）。
EOF

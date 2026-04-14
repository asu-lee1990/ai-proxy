#!/usr/bin/env bash
set -euo pipefail

# 清理 ai-proxy TUN / 透明代理 iptables 规则

CHAIN_NAME="${CHAIN_NAME:-AI_PROXY_TUN}"
IPTABLES="${IPTABLES:-iptables}"
MODE="${MODE:-output}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[ai-proxy] 需要 root 权限运行该脚本" >&2
  exit 1
fi

if ! command -v "$IPTABLES" >/dev/null 2>&1; then
  echo "[ai-proxy] 找不到 iptables 命令，请先安装 iptables" >&2
  exit 1
fi

case "$MODE" in
  output|prerouting)
    ;;
  *)
    echo "[ai-proxy] MODE 仅支持 output 或 prerouting，当前值：$MODE" >&2
    exit 1
    ;;
esac

for chain in OUTPUT PREROUTING; do
  if "$IPTABLES" -t nat -C "$chain" -j "$CHAIN_NAME" >/dev/null 2>&1; then
    "$IPTABLES" -t nat -D "$chain" -j "$CHAIN_NAME"
  fi
done

if "$IPTABLES" -t nat -L "$CHAIN_NAME" >/dev/null 2>&1; then
  "$IPTABLES" -t nat -F "$CHAIN_NAME"
  "$IPTABLES" -t nat -X "$CHAIN_NAME" 2>/dev/null || true
fi

echo "[ai-proxy] 透明代理重定向规则已清理。"

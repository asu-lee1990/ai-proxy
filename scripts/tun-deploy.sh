#!/usr/bin/env bash
set -euo pipefail

# ai-proxy TUN / 透明代理部署脚本（Linux）
#
# 这个脚本不负责创建真正的 kernel TUN 设备，而是把系统流量
# 通过 iptables 重定向到本地运行的 ai-proxy transparent 监听端口。
# 对大多数 HTTP/HTTPS 透明代理场景，这已经足够。
#
# 依赖：
#   - root 权限
#   - iptables
#
# 环境变量：
#   PROXY_PORT       本地 ai-proxy 监听端口，默认 8080
#   PROXY_UID        代理进程运行的 UID，用于避免重定向代理自身的出站流量
#   PROXY_USER       代理进程运行的用户名（如果未设置 PROXY_UID，会自动解析）
#   MODE             output(默认) | prerouting
#   CHAIN_NAME       自定义 iptables chain 名称，默认 AI_PROXY_TUN
#   HTTP_PORTS       要重定向的 HTTP 端口列表，默认 80
#   HTTPS_PORTS      要重定向的 HTTPS 端口列表，默认 443
#   IPTABLES         iptables 命令路径，默认 iptables

PROXY_PORT="${PROXY_PORT:-8080}"
CHAIN_NAME="${CHAIN_NAME:-AI_PROXY_TUN}"
MODE="${MODE:-output}"
HTTP_PORTS="${HTTP_PORTS:-80}"
HTTPS_PORTS="${HTTPS_PORTS:-443}"
IPTABLES="${IPTABLES:-iptables}"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[ai-proxy] 需要 root 权限运行该脚本" >&2
  exit 1
fi

if ! command -v "$IPTABLES" >/dev/null 2>&1; then
  echo "[ai-proxy] 找不到 iptables 命令，请先安装 iptables" >&2
  exit 1
fi

if [[ -z "${PROXY_UID:-}" ]]; then
  if [[ -n "${PROXY_USER:-}" ]]; then
    PROXY_UID="$(id -u "$PROXY_USER")"
  else
    PROXY_UID="$(id -u)"
  fi
fi

case "$MODE" in
  output|prerouting)
    ;;
  *)
    echo "[ai-proxy] MODE 仅支持 output 或 prerouting，当前值：$MODE" >&2
    exit 1
    ;;
esac

ensure_chain() {
  "$IPTABLES" -t nat -N "$CHAIN_NAME" 2>/dev/null || true
  "$IPTABLES" -t nat -F "$CHAIN_NAME"
}

ensure_jump() {
  local chain="$1"
  if ! "$IPTABLES" -t nat -C "$chain" -j "$CHAIN_NAME" >/dev/null 2>&1; then
    "$IPTABLES" -t nat -A "$chain" -j "$CHAIN_NAME"
  fi
}

add_redirect_rules() {
  local ports="$1"
  if [[ -n "$ports" ]]; then
    "$IPTABLES" -t nat -A "$CHAIN_NAME" -p tcp -m multiport --dports "$ports" -j REDIRECT --to-ports "$PROXY_PORT"
  fi
}

ensure_chain

# 避免代理自身的流量被再次重定向。
"$IPTABLES" -t nat -A "$CHAIN_NAME" -d 127.0.0.0/8 -j RETURN
"$IPTABLES" -t nat -A "$CHAIN_NAME" -d 10.0.0.0/8 -j RETURN
"$IPTABLES" -t nat -A "$CHAIN_NAME" -d 172.16.0.0/12 -j RETURN
"$IPTABLES" -t nat -A "$CHAIN_NAME" -d 192.168.0.0/16 -j RETURN
"$IPTABLES" -t nat -A "$CHAIN_NAME" -d 169.254.0.0/16 -j RETURN
"$IPTABLES" -t nat -A "$CHAIN_NAME" -d 100.64.0.0/10 -j RETURN

# 代理进程本身的出站连接不做重定向，避免循环。
if [[ -n "$PROXY_UID" ]]; then
  "$IPTABLES" -t nat -A "$CHAIN_NAME" -m owner --uid-owner "$PROXY_UID" -j RETURN
fi

add_redirect_rules "$HTTP_PORTS"
add_redirect_rules "$HTTPS_PORTS"

case "$MODE" in
  output)
    ensure_jump OUTPUT
    ;;
  prerouting)
    ensure_jump PREROUTING
    ;;
esac

cat <<EOF
[ai-proxy] 透明代理重定向已配置完成。

下一步：
  1) 用透明模式启动代理：
     npm start -- --protocol transparent --host 127.0.0.1 --port $PROXY_PORT

  2) 如果要开启 MITM：
     npm start -- --protocol transparent --host 127.0.0.1 --port $PROXY_PORT --mitm \
       --mitm-ca-key ./ssl/ca.key.pem --mitm-ca-cert ./ssl/ca.cert.pem --mitm-cache-dir ./ssl/mitm-cache

当前规则：
  模式: $MODE
  端口: $PROXY_PORT
  HTTP: $HTTP_PORTS
  HTTPS: $HTTPS_PORTS
  chain: $CHAIN_NAME
  proxy uid: $PROXY_UID
EOF

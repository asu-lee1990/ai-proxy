#!/usr/bin/env bash
set -euo pipefail

# Compile-and-run wrapper for the tiny TUN helper.
# This is the prerequisite for a real kernel TUN bridge.

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
HELPER_SRC="$ROOT_DIR/scripts/tun-helper.c"
HELPER_BIN="$ROOT_DIR/scripts/.build/tun-helper"

if [[ "${EUID:-$(id -u)}" -ne 0 ]]; then
  echo "[ai-proxy] 需要 root 权限运行该脚本" >&2
  exit 1
fi

mkdir -p "$ROOT_DIR/scripts/.build"

gcc -O2 -Wall -Wextra -std=c11 "$HELPER_SRC" -o "$HELPER_BIN"

if [[ "$#" -eq 0 ]]; then
  cat <<'EOF'
Usage:
  sudo ./scripts/tun-run.sh --iface tun0 -- <command> [args...]

Examples:
  sudo ./scripts/tun-run.sh --iface ai0 -- npm start -- --protocol transparent --host 127.0.0.1 --port 8080
  sudo ./scripts/tun-run.sh --iface ai0 -- /usr/bin/env | grep TUN_
EOF
  exit 1
fi

exec "$HELPER_BIN" "$@"

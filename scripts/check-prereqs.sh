#!/usr/bin/env bash
set -euo pipefail

ok=true

check() {
  local name="$1"; shift
  if "$@" &>/dev/null; then
    echo "[ok] $name"
  else
    echo "[missing] $name"
    ok=false
  fi
}

check "docker"         docker info
check "docker compose" docker compose version
check "go"             go version

if ! $ok; then
  echo ""
  echo "Install missing prerequisites and re-run 'make quickstart'."
  exit 1
fi

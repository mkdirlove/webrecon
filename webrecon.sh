#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GO_FILE="$SCRIPT_DIR/webrecon.go"
BIN_FILE="$SCRIPT_DIR/.webrecon_bin"

if ! command -v go >/dev/null 2>&1; then
    echo "[!] go is required to build webrecon.go" >&2
    exit 1
fi

if [[ ! -x "$BIN_FILE" || "$GO_FILE" -nt "$BIN_FILE" ]]; then
    go build -o "$BIN_FILE" "$GO_FILE"
fi

exec "$BIN_FILE" "$@"

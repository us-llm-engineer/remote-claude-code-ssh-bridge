#!/usr/bin/env bash
set -euo pipefail
PID_FILE="$HOME/.remote-gateway/https-bridge/pids"
if [ -f "$PID_FILE" ]; then
    while read -r pid; do
        [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
    done < "$PID_FILE"
    rm -f "$PID_FILE"
fi

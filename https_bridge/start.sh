#!/usr/bin/env bash
# Start the authenticated HTTPS bridge for the reviewed local MCP servers.
set -euo pipefail

BRIDGE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
GATEWAY_DIR="$(cd "$BRIDGE_DIR/.." && pwd)"
RUNTIME_DIR="$HOME/.remote-gateway/https-bridge"
LOG_DIR="$RUNTIME_DIR/logs"
PID_FILE="$RUNTIME_DIR/pids"
URL_FILE="$RUNTIME_DIR/url.txt"
RELOAD_MARKER="$RUNTIME_DIR/reload-capable.pid"
SECRETS_FILE="$HOME/.remote-gateway/secrets.env"
GATEWAY_PORT=8798
FOREGROUND=false

if [ "${1:-}" = "--foreground" ]; then
    FOREGROUND=true
fi

mkdir -p -m 700 "$RUNTIME_DIR" "$LOG_DIR"
if [ ! -f "$SECRETS_FILE" ]; then
    echo "Missing $SECRETS_FILE; create REMOTE_GATEWAY_TOKEN first." >&2
    exit 1
fi
set -a
source "$SECRETS_FILE"
set +a
: "${REMOTE_GATEWAY_TOKEN:?REMOTE_GATEWAY_TOKEN is required}"

rm -f "$PID_FILE" "$URL_FILE"
touch "$PID_FILE"

cleanup() {
    rm -f "$RELOAD_MARKER"
    if [ -f "$PID_FILE" ]; then
        while read -r pid; do
            [ -n "$pid" ] && kill "$pid" 2>/dev/null || true
        done < "$PID_FILE"
    fi
}
trap cleanup EXIT INT TERM

start_process() {
    local label=$1
    shift
    "$@" >> "$LOG_DIR/${label}.log" 2>&1 &
    echo "$!" >> "$PID_FILE"
}

wait_for_port() {
    local port=$1 label=$2 start=$SECONDS
    while ! timeout 1 bash -c "</dev/tcp/127.0.0.1/$port" >/dev/null 2>&1; do
        if [ $((SECONDS - start)) -ge 120 ]; then
            echo "$label did not listen on $port; see $LOG_DIR/${label}.log" >&2
            exit 1
        fi
        sleep 1
    done
}

echo "Starting the authenticated MCP-over-HTTPS and SSH-over-WebSocket gateway..."
start_process gateway env REMOTE_GATEWAY_TOKEN="$REMOTE_GATEWAY_TOKEN" REMOTE_GATEWAY_HOST=127.0.0.1 REMOTE_GATEWAY_PORT="$GATEWAY_PORT" \
    PYTHONPATH="$GATEWAY_DIR" /usr/local/bin/python3 "$GATEWAY_DIR/gateway/server.py"
wait_for_port "$GATEWAY_PORT" gateway
gateway_pid=$(head -n 1 "$PID_FILE")

reload_gateway() {
    echo "Reloading the authenticated gateway while preserving Cloudflare..."
    kill "$gateway_pid" 2>/dev/null || true
    wait "$gateway_pid" 2>/dev/null || true
    start_process gateway env REMOTE_GATEWAY_TOKEN="$REMOTE_GATEWAY_TOKEN" REMOTE_GATEWAY_HOST=127.0.0.1 REMOTE_GATEWAY_PORT="$GATEWAY_PORT" \
        PYTHONPATH="$GATEWAY_DIR" /usr/local/bin/python3 "$GATEWAY_DIR/gateway/server.py"
    gateway_pid=$(tail -n 1 "$PID_FILE")
    # Keep the PID file canonical: gateway first, Cloudflare second.
    printf '%s\n%s\n' "$gateway_pid" "$cloudflared_pid" > "$PID_FILE"
    wait_for_port "$GATEWAY_PORT" gateway
}

: > "$LOG_DIR/cloudflared.log"
start_process cloudflared /home/centos/.local/bin/cloudflared tunnel --url "http://127.0.0.1:$GATEWAY_PORT"
cloudflared_pid=$(tail -n 1 "$PID_FILE")
trap reload_gateway HUP
printf '%s\n' "$$" > "$RELOAD_MARKER"
echo -n "Waiting for Cloudflare quick-tunnel URL..."
for _ in $(seq 1 240); do
    tunnel_url=$(grep -aoE 'https://[a-zA-Z0-9.-]+\.trycloudflare\.com' "$LOG_DIR/cloudflared.log" 2>/dev/null | head -1 || true)
    if [ -n "$tunnel_url" ]; then
        printf '%s\n' "$tunnel_url" > "$URL_FILE"
        echo " ready"
        echo "HTTPS bridge: $tunnel_url"
        echo "Remote MCP: $tunnel_url/<approved-alias>/mcp/"
        echo "Restricted SSH: wss://${tunnel_url#https://}/ssh"
        break
    fi
    sleep 1
done
if [ ! -s "$URL_FILE" ]; then
    echo " Cloudflare did not issue a URL; see $LOG_DIR/cloudflared.log" >&2
    exit 1
fi

if [ "$FOREGROUND" = true ]; then
    while kill -0 "$cloudflared_pid" 2>/dev/null; do
        wait "$cloudflared_pid" 2>/dev/null || true
    done
fi

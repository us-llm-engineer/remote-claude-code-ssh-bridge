#!/usr/bin/env bash
# Start the supervised Cloudflare HTTPS bridge and print its current endpoint.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
UNIT=remote-claude-bridge.service
URL_FILE="$HOME/.remote-gateway/https-bridge/url.txt"
LOCK_FILE="$HOME/.remote-gateway/start.lock"
LOCAL_HEALTH=http://127.0.0.1:8798/healthz

mkdir -p -m 700 "$(dirname "$LOCK_FILE")"
exec 9>"$LOCK_FILE"
flock -w 10 9 || { echo "Another remote-gateway lifecycle command is running." >&2; exit 1; }

read_endpoint() {
    if [ -s "$URL_FILE" ]; then
        tr -d '\r\n' < "$URL_FILE"
    fi
}

valid_endpoint() {
    [[ ${1:-} =~ ^https://[a-zA-Z0-9-]+\.trycloudflare\.com$ ]]
}

health_is_ok() {
    local url=$1 body
    body=$(curl --connect-timeout 2 --max-time 5 --fail --silent --show-error "$url" 2>/dev/null) || return 1
    jq -e '.status == "ok" and .transport == "mcp-streamable-http+ssh-websocket"' <<<"$body" >/dev/null 2>&1
}

print_endpoint() {
    local endpoint=$1
    echo "Bridge: $endpoint"
    echo "Remote MCP base: $endpoint/<approved-alias>/mcp/"
    echo "SSH WebSocket: wss://${endpoint#https://}/ssh"
    echo "Run remote-gateway-test to validate and display the two-hour authorization."
}

if ! systemctl cat "$UNIT" >/dev/null 2>&1; then
    "$ROOT_DIR/https_bridge/install-service.sh"
fi

endpoint=$(read_endpoint || true)
if systemctl is-active --quiet "$UNIT" \
    && valid_endpoint "$endpoint" \
    && health_is_ok "$LOCAL_HEALTH" \
    && health_is_ok "$endpoint/healthz"; then
    echo "Cloudflare HTTPS bridge is already healthy."
    print_endpoint "$endpoint"
    exit 0
fi

if systemctl is-active --quiet "$UNIT"; then
    echo "Existing bridge is stale or unreachable; replacing its Quick Tunnel."
    action=restart
else
    echo "Starting Cloudflare HTTPS bridge."
    action=start
fi

# A URL file is runtime output, not readiness state. Clear it before changing
# the service so the wait loop cannot consume a URL from an earlier invocation.
install -d -m 700 "$(dirname "$URL_FILE")"
: > "$URL_FILE"
sudo systemctl "$action" "$UNIT"

echo -n "Waiting for a verified public Cloudflare HTTPS endpoint"
deadline=$((SECONDS + 120))
while [ "$SECONDS" -lt "$deadline" ]; do
    if ! systemctl is-active --quiet "$UNIT"; then
        echo " failed"
        sudo systemctl status "$UNIT" --no-pager -l >&2 || true
        exit 1
    fi
    endpoint=$(read_endpoint || true)
    if valid_endpoint "$endpoint" \
        && health_is_ok "$LOCAL_HEALTH" \
        && health_is_ok "$endpoint/healthz"; then
        echo " ready"
        print_endpoint "$endpoint"
        exit 0
    fi
    echo -n "."
    sleep 1
done

echo " failed" >&2
echo "No publicly reachable endpoint became healthy; inspect:" >&2
echo "  sudo systemctl status $UNIT" >&2
echo "  tail -100 $HOME/.remote-gateway/https-bridge/logs/cloudflared.log" >&2
exit 1

#!/usr/bin/env bash
# Start the HTTPS bridge, validate it, and reuse or rotate one SSH session.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
SECRETS_FILE="$HOME/.remote-gateway/secrets.env"
URL_FILE="$HOME/.remote-gateway/https-bridge/url.txt"
STATE_DIR="$HOME/.remote-gateway/ssh-session"
STATE_FILE="$STATE_DIR/current.env"

force_rotate=0
case "${1:-}" in
    "") ;;
    --rotate) force_rotate=1 ;;
    *) echo "Usage: remote-gateway-test [--rotate]" >&2; exit 2 ;;
esac

"$ROOT_DIR/start.sh"
if [ ! -f "$SECRETS_FILE" ] || [ ! -s "$URL_FILE" ]; then
    echo "Bridge configuration is incomplete." >&2
    exit 1
fi
set -a
source "$SECRETS_FILE"
set +a
: "${REMOTE_GATEWAY_TOKEN:?REMOTE_GATEWAY_TOKEN is required}"
BRIDGE_URL=$(tr -d '\r\n' < "$URL_FILE")

local_health=$(curl --connect-timeout 2 --max-time 5 --fail --silent --show-error http://127.0.0.1:8798/healthz)
jq -e '.status == "ok" and .transport == "mcp-streamable-http+ssh-websocket"' <<<"$local_health" >/dev/null
public_health=$(curl --connect-timeout 3 --max-time 8 --fail --silent --show-error "$BRIDGE_URL/healthz")
jq -e '.status == "ok" and .transport == "mcp-streamable-http+ssh-websocket"' <<<"$public_health" >/dev/null
public_status="reachable and healthy"

mkdir -p -m 700 "$STATE_DIR"
chmod 700 "$STATE_DIR"
rotate=1
token=""
key_b64=""
expiry=""
if [ -f "$STATE_FILE" ] && [ "$(stat -c '%a' "$STATE_FILE" 2>/dev/null || true)" = 600 ]; then
    set -a
    source "$STATE_FILE"
    set +a
    token="${REMOTE_GATEWAY_SSH_TOKEN:-}"
    key_b64="${REMOTE_GATEWAY_SSH_KEY_B64:-}"
    expiry=$(PYTHONPATH="$ROOT_DIR" REMOTE_GATEWAY_TOKEN="$REMOTE_GATEWAY_TOKEN" REMOTE_GATEWAY_SSH_SESSION="$token" /usr/local/bin/python3 - <<'PY'
import os
from gateway.session import verify_ssh_session
expiry = verify_ssh_session(os.environ.get("REMOTE_GATEWAY_SSH_SESSION"), os.environ["REMOTE_GATEWAY_TOKEN"])
print(int(expiry or 0))
PY
    )
    now=$(date +%s)
    if [ "$force_rotate" -eq 0 ] && [ -n "$token" ] && [ -n "$key_b64" ] && [ "$expiry" -gt "$now" ]; then
        rotate=0
    fi
fi

if [ "$rotate" -eq 1 ]; then
    token=$(PYTHONPATH="$ROOT_DIR" REMOTE_GATEWAY_TOKEN="$REMOTE_GATEWAY_TOKEN" /usr/local/bin/python3 -m gateway.session)
    expiry=$(PYTHONPATH="$ROOT_DIR" REMOTE_GATEWAY_TOKEN="$REMOTE_GATEWAY_TOKEN" REMOTE_GATEWAY_SSH_SESSION="$token" /usr/local/bin/python3 - <<'PY'
import os
from gateway.session import verify_ssh_session
expiry = verify_ssh_session(os.environ["REMOTE_GATEWAY_SSH_SESSION"], os.environ["REMOTE_GATEWAY_TOKEN"])
if expiry is None:
    raise SystemExit("newly issued SSH session failed verification")
print(int(expiry))
PY
    )
    session_key="$STATE_DIR/claude-shell-$(date +%s)-$$"
    ssh-keygen -q -t ed25519 -N '' -f "$session_key" -C remote-gateway-two-hour
    key_b64=$(base64 -w0 "$session_key")
    rm -f "$session_key" "$session_key.pub"
    state_tmp=$(mktemp "$STATE_DIR/.current.XXXXXX")
    chmod 600 "$state_tmp"
    printf 'REMOTE_GATEWAY_SSH_TOKEN=%s\nREMOTE_GATEWAY_SSH_KEY_B64=%s\nREMOTE_GATEWAY_SSH_EXPIRES_AT=%s\n' "$token" "$key_b64" "$expiry" >"$state_tmp"
    mv -f "$state_tmp" "$STATE_FILE"
    status="rotated"
else
    status="reused"
fi

# The two-hour bundle is deliberately shared by the restricted shell, SFTP,
# and dedicated Playwright identities. The SSH account selected by the client
# determines the capability: claude-sync is forced to internal-sftp;
# claude-playwright can start only the reviewed Playwright MCP process.
key_tmp=$(mktemp "$STATE_DIR/.authorize.XXXXXX")
chmod 600 "$key_tmp"
printf '%s' "$key_b64" | base64 -d >"$key_tmp"
session_public=$(ssh-keygen -y -f "$key_tmp")
rm -f "$key_tmp"
auth_line="from=\"127.0.0.1\" $session_public remote-gateway-ssh-session"
for account in claude-shell claude-sync claude-playwright; do
    auth_file="/etc/claude-remote/authorized_keys/$account"
    if ! sudo grep -Fqx "$auth_line" "$auth_file" 2>/dev/null; then
        printf '%s\n' "$auth_line" | sudo tee -a "$auth_file" >/dev/null
        sudo chown root:root "$auth_file"
        sudo chmod 0644 "$auth_file"
    fi
done

remaining=$((expiry - $(date +%s)))
remaining_minutes=$(( (remaining + 59) / 60 ))
printf 'Public bridge check passed: SSH-WebSocket gateway is healthy.\n'
printf 'Public endpoint status: %s\n' "$public_status"
printf 'Credential status: %s\n' "$status"
printf 'Token expires: %s UTC (%d seconds; about %d minutes remaining)\n' "$(date -u -d "@$expiry" '+%Y-%m-%d %H:%M:%S')" "$remaining" "$remaining_minutes"
printf 'Endpoint: %s\n' "$BRIDGE_URL"
printf 'Remote MCP URL pattern: %s/<approved-alias>/mcp/\n' "$BRIDGE_URL"
printf 'SSH WebSocket: wss://%s/ssh\n' "${BRIDGE_URL#https://}"
printf 'Two-hour authorization (usable for MCP OAuth consent or restricted SSH/SFTP):\n'
printf 'REMOTE_GATEWAY_SSH_TOKEN=%s\n' "$token"
printf 'REMOTE_GATEWAY_SSH_KEY_B64=%s\n' "$key_b64"

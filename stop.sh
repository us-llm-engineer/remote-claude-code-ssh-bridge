#!/usr/bin/env bash
# Stop every bridge process, including cloudflared, through its systemd unit.
set -euo pipefail

UNIT=remote-claude-bridge.service
if systemctl is-active --quiet "$UNIT"; then
    sudo systemctl stop "$UNIT"
    echo "Cloudflare HTTPS bridge stopped."
else
    echo "Cloudflare HTTPS bridge is already stopped."
fi

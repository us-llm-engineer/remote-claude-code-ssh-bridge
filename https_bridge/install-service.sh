#!/usr/bin/env bash
set -euo pipefail
SOURCE_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
sudo -n true
sudo install -o root -g root -m 0644 "$SOURCE_DIR/systemd/remote-claude-bridge.service" /etc/systemd/system/remote-claude-bridge.service
sudo systemctl daemon-reload
sudo systemctl enable --now remote-claude-bridge.service

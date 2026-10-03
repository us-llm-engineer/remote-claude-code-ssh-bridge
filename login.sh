#!/usr/bin/env bash
# Sign the gateway in to an allowlisted HTTP MCP (huggingface, data-host-mcp).
set -euo pipefail
ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONPATH="$ROOT_DIR" exec /usr/local/bin/python3 -m gateway.upstream_auth "$@"

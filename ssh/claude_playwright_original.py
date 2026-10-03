#!/usr/local/bin/python3
"""Start the user's original, headed Playwright MCP configuration safely.

The extension token stays in the user's existing Codex configuration rather
than in the bridge registry.  This process is reachable only through the
dedicated forced-command SSH identity.
"""

from __future__ import annotations

import os
import sys
import tomllib
from pathlib import Path


CONFIG = Path("/home/centos/.codex/config.toml")
NODE = "/home/centos/.nvm/versions/node/v26.7.0/bin/node"
CLI = "/home/centos/.claude/mcp-servers/playwright-mcp/packages/playwright-core/cli.js"
EXPECTED_ARGS = [
    CLI,
    "mcp",
    "--extension",
    "--browser",
    "chrome",
    "--executable-path",
    "/mnt/c/Program Files/Google/Chrome/Application/chrome.exe",
    "--profile-name",
    "Default",
]


def main() -> int:
    try:
        config = tomllib.loads(CONFIG.read_text(encoding="utf-8"))
        server = config["mcp_servers"]["playwright"]
        token = server["env"]["PLAYWRIGHT_MCP_EXTENSION_TOKEN"]
        args = server["args"]
    except (KeyError, OSError, TypeError, tomllib.TOMLDecodeError) as exc:
        print(f"Playwright bridge configuration is unavailable: {exc}", file=sys.stderr)
        return 126

    if not isinstance(token, str) or not token or not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        print("Playwright bridge configuration has an invalid token or argument list", file=sys.stderr)
        return 126
    if args != EXPECTED_ARGS:
        print("Playwright bridge requires the exact approved extension configuration", file=sys.stderr)
        return 126

    environment = dict(os.environ)
    environment["PLAYWRIGHT_MCP_EXTENSION_TOKEN"] = token
    os.execve(NODE, [NODE, *args], environment)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

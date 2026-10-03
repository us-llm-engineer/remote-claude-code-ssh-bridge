#!/usr/local/bin/python3
"""Forced-command entry point for the dedicated local Playwright MCP."""

from __future__ import annotations

import os


SUDO = "/usr/bin/sudo"
RUNNER = "/usr/local/libexec/claude-mcp-runner"


def main() -> int:
    # Ignore SSH_ORIGINAL_COMMAND deliberately: this identity can start only
    # the root-reviewed Playwright alias and never a shell or another MCP.
    os.execv(SUDO, [SUDO, "-n", "-u", "centos", RUNNER, "playwright"])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/local/bin/python3
"""Forced-command gate for the claude-mcp SSH account.

The SSH client may request exactly ``mcp <approved-alias>``.  No shell is
involved after this point; the approved runner receives the alias as one argv
element and is the only command that this account may sudo to ``centos``.
"""

from __future__ import annotations

import os
import shlex
import sys


RUNNER = "/usr/local/libexec/claude-mcp-runner"
SUDO = "/usr/bin/sudo"


def parse_requested_alias(command: str | None) -> str:
    """Return the requested MCP alias or raise ValueError for any other SSH command."""
    if not command:
        raise ValueError("an MCP command is required")
    try:
        parts = shlex.split(command, posix=True)
    except ValueError as exc:
        raise ValueError("invalid command quoting") from exc
    if len(parts) != 2 or parts[0] != "mcp" or not parts[1]:
        raise ValueError("only 'mcp <server-alias>' is allowed")
    return parts[1]


def main() -> int:
    try:
        alias = parse_requested_alias(os.environ.get("SSH_ORIGINAL_COMMAND"))
    except ValueError as exc:
        print(f"claude-mcp: {exc}", file=sys.stderr)
        return 126

    # execvp is deliberately given an argv list, never a shell command line.
    os.execv(SUDO, [SUDO, "-n", "-u", "centos", RUNNER, alias])
    return 127  # pragma: no cover - execv either replaces this process or raises


if __name__ == "__main__":
    raise SystemExit(main())

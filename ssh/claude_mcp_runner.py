#!/usr/local/bin/python3
"""Execute a root-reviewed local stdio MCP server as the centos user."""

from __future__ import annotations

import json
import os
import sys
from pathlib import Path
from typing import Any


ALLOWLIST_PATH = Path("/etc/claude-remote/mcp-allowlist.json")
SAFE_PATH = "/home/centos/.local/bin:/home/centos/.nvm/versions/node/v26.7.0/bin:/usr/local/bin:/usr/bin:/bin"
PROJECTS_ROOT = Path("/home/centos/data/projects").resolve()


def load_allowlist(path: Path = ALLOWLIST_PATH) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"servers"} or not isinstance(data["servers"], dict):
        raise ValueError("allowlist must contain only a 'servers' object")
    servers = data["servers"]
    for alias, spec in servers.items():
        if not isinstance(alias, str) or not alias or not isinstance(spec, dict):
            raise ValueError("invalid server entry")
        if not {"command", "args"}.issubset(spec) or set(spec) - {"command", "args", "cwd"}:
            raise ValueError(f"{alias}: server specs must contain command, args, and optional cwd only")
        command, args = spec["command"], spec["args"]
        if not isinstance(command, str) or not command.startswith("/"):
            raise ValueError(f"{alias}: command must be an absolute path")
        if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
            raise ValueError(f"{alias}: args must be a string list")
        cwd = spec.get("cwd")
        if cwd is not None:
            if not isinstance(cwd, str) or not cwd.startswith("/"):
                raise ValueError(f"{alias}: cwd must be an absolute path")
            try:
                Path(cwd).resolve().relative_to(PROJECTS_ROOT)
            except ValueError as exc:
                raise ValueError(f"{alias}: cwd must remain under projects") from exc
    return servers


def build_exec_spec(alias: str, allowlist: dict[str, dict[str, Any]]) -> tuple[list[str], dict[str, str]]:
    if alias not in allowlist:
        raise ValueError("unknown MCP server alias")
    spec = allowlist[alias]
    argv = [spec["command"], *spec["args"]]
    environment = {
        "HOME": "/home/centos",
        "LOGNAME": "centos",
        "USER": "centos",
        "PATH": SAFE_PATH,
        "LANG": "C.UTF-8",
    }
    return argv, environment


def main() -> int:
    if len(sys.argv) != 2:
        print("claude-mcp: exactly one MCP server alias is required", file=sys.stderr)
        return 126
    try:
        allowlist = load_allowlist()
        argv, environment = build_exec_spec(sys.argv[1], allowlist)
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print(f"claude-mcp: {exc}", file=sys.stderr)
        return 126
    # A server may opt into a project-scoped working directory. This keeps
    # Playwright's default file access boundary inside the exposed projects.
    os.chdir(allowlist[sys.argv[1]].get("cwd", "/home/centos"))
    os.execve(argv[0], argv, environment)
    return 127  # pragma: no cover - execve either replaces this process or raises


if __name__ == "__main__":
    raise SystemExit(main())

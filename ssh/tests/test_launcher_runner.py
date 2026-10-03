import importlib.util
import json
from pathlib import Path

import pytest


SSH_DIR = Path(__file__).resolve().parents[1]


def load_module(name: str, filename: str):
    spec = importlib.util.spec_from_file_location(name, SSH_DIR / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


launcher = load_module("claude_mcp_launcher", "claude_mcp_launcher.py")
runner = load_module("claude_mcp_runner", "claude_mcp_runner.py")


@pytest.mark.parametrize(
    ("command", "expected"),
    [("mcp modal-gpu", "modal-gpu"), ("  mcp   local-folder-stream  ", "local-folder-stream")],
)
def test_launcher_accepts_only_two_token_mcp_requests(command, expected):
    assert launcher.parse_requested_alias(command) == expected


@pytest.mark.parametrize(
    "command",
    [None, "", "mcp", "mcp modal-gpu extra", "sh -c id", "mcp modal-gpu; id", "mcp 'unterminated"],
)
def test_launcher_rejects_shell_and_malformed_requests(command):
    with pytest.raises(ValueError):
        launcher.parse_requested_alias(command)


def test_allowlist_is_static_and_executes_only_absolute_programs():
    servers = runner.load_allowlist(SSH_DIR / "mcp-allowlist.json")
    assert set(servers) == {
        "colab-proxy-mcp",
        "modal-gpu",
        "scopus-mcp",
        "messaging-watcher",
        "codex-opencode-bridge",
        "game-market",
        "local-folder-stream",
        "playwright",
    }
    for alias, spec in servers.items():
        argv, env = runner.build_exec_spec(alias, servers)
        assert argv[0] == spec["command"]
        assert argv[0].startswith("/")
        assert env == {
            "HOME": "/home/centos",
            "LOGNAME": "centos",
            "USER": "centos",
            "PATH": runner.SAFE_PATH,
            "LANG": "C.UTF-8",
        }


def test_all_registered_programs_exist_on_this_host():
    servers = runner.load_allowlist(SSH_DIR / "mcp-allowlist.json")
    assert all(Path(spec["command"]).is_file() for spec in servers.values())


def test_unknown_alias_cannot_be_turned_into_an_executable():
    servers = runner.load_allowlist(SSH_DIR / "mcp-allowlist.json")
    with pytest.raises(ValueError, match="unknown MCP server alias"):
        runner.build_exec_spec("modal-gpu;id", servers)


@pytest.mark.parametrize(
    "entry",
    [
        {"command": "python3", "args": []},
        {"command": "/bin/true", "args": "--help"},
        {"command": "/bin/true", "args": [], "cwd": "/tmp"},
    ],
)
def test_corrupt_registry_fails_closed(tmp_path, entry):
    candidate = tmp_path / "allowlist.json"
    candidate.write_text(json.dumps({"servers": {"bad": entry}}), encoding="utf-8")
    with pytest.raises(ValueError):
        runner.load_allowlist(candidate)

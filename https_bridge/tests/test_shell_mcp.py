import base64
import json
import os
import stat
import sys
import time
from pathlib import Path

import pytest
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from gateway.mcp_proxy import load_allowlist
from gateway.oauth import ACCESS_TTL, SHELL_REFRESH_TTL, OAuthServer
from gateway.server import build_gateway
from gateway.session import issue_ssh_session

SECRET = "signing-key"

FAKE_SSH = r'''#!/usr/bin/env python3
import json, os, sys, time
args = sys.argv[1:]
cmd = args[-1]
key = args[args.index("-i") + 1]
log = os.environ.get("FAKE_SSH_LOG")
record = {"args": args, "key_exists": os.path.exists(key), "key_mode": oct(os.stat(key).st_mode & 0o777), "key": open(key).read(), "key_path": key}
open(os.path.join(os.path.dirname(key), "last-call.json"), "w").write(json.dumps(record))
if cmd == "echo hi":
    print("hi")
elif cmd == "fail":
    sys.stderr.write("boom\n"); sys.exit(3)
elif cmd == "sleep":
    open(os.path.join(os.path.dirname(key), "sleeper.pid"), "w").write(str(os.getpid()))
    time.sleep(60)
elif cmd == "big":
    sys.stdout.write("x" * 200000)
elif cmd == "authfail":
    sys.stderr.write("Permission denied (publickey)\n"); sys.exit(255)
else:
    print("ran:" + cmd)
'''


def write_bundle(directory: Path, *, ttl: int = 7200, issued_ago: int = 0, key: bytes = b"FAKE-KEY\n") -> Path:
    token = issue_ssh_session(SECRET, now=time.time() - issued_ago, ttl_seconds=ttl)
    path = directory / "current.env"
    path.write_text(
        f"REMOTE_GATEWAY_SSH_TOKEN={token}\nREMOTE_GATEWAY_SSH_KEY_B64={base64.b64encode(key).decode()}\n"
        f"REMOTE_GATEWAY_SSH_EXPIRES_AT=0\n"
    )
    path.chmod(0o600)
    return path


@pytest.fixture
def gateway(tmp_path):
    session_dir = tmp_path / "ssh-session"
    session_dir.mkdir()
    fake = tmp_path / "fake-ssh"
    fake.write_text(FAKE_SSH)
    fake.chmod(0o755)
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text('{"servers":{"demo":{"command":"/bin/true","args":[]}}}')
    env_path = write_bundle(session_dir)
    app = build_gateway(
        SECRET,
        allowlist_path=allowlist,
        oauth_state_path=str(tmp_path / "oauth.json"),
        tool_cache_dir=tmp_path / "cache",
        upstream_oauth_dir=tmp_path / "upstream",
        shell_options={"env_path": env_path, "known_hosts": session_dir / "known_hosts", "ssh_bin": str(fake), "port": 1},
    )
    headers = {
        "Authorization": f"Bearer {issue_ssh_session(SECRET)}",
        "Accept": "application/json, text/event-stream",
    }
    with TestClient(app) as client:
        yield client, headers, session_dir


def rpc(client, headers, method, params=None, path="/shell/mcp/"):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    response = client.post(path, json=body, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["result"]


def run(client, headers, command, **extra):
    return rpc(client, headers, "tools/call", {"name": "ssh_run", "arguments": {"command": command, **extra}})


def test_shell_route_requires_auth_and_lists_one_tool(gateway):
    client, headers, _ = gateway
    assert client.post("/shell/mcp/", json={}).status_code == 401
    tools = rpc(client, headers, "tools/list")["tools"]
    assert [t["name"] for t in tools] == ["ssh_run"]
    assert tools[0]["inputSchema"]["required"] == ["command"]


def test_shell_tool_is_not_part_of_the_aggregate_endpoint(gateway):
    client, headers, _ = gateway
    names = [t["name"] for t in rpc(client, headers, "tools/list", path="/all/mcp/")["tools"]]
    assert not any("ssh_run" in n or n.startswith("shell") for n in names)


def test_exit_code_stdout_and_stderr_are_reported(gateway):
    client, headers, _ = gateway
    ok = run(client, headers, "echo hi")
    assert not ok["isError"] and "exit_code: 0" in ok["content"][0]["text"] and "hi" in ok["content"][0]["text"]
    failed = run(client, headers, "fail")
    text = failed["content"][0]["text"]
    assert not failed["isError"] and "exit_code: 3" in text and "boom" in text


def test_command_is_one_argv_element_and_the_key_exists_only_during_the_call(gateway):
    client, headers, session_dir = gateway
    nasty = "echo a; touch /tmp/x && $(id) `id` | cat"
    run(client, headers, nasty)
    record = json.loads((session_dir / "run" / "last-call.json").read_text())
    assert record["args"][-1] == nasty and record["args"].count(nasty) == 1
    assert record["args"][-2] == "claude-shell@127.0.0.1"
    for flag in ("BatchMode=yes", "IdentitiesOnly=yes"):
        assert flag in record["args"]
    assert record["key"] == "FAKE-KEY\n" and record["key_mode"] == "0o600" and record["key_exists"]
    assert not os.path.exists(record["key_path"])  # removed afterwards
    assert not [p for p in (session_dir / "run").iterdir() if p.name.startswith("k-")]


def test_missing_or_expired_session_is_reported_not_attempted(gateway):
    client, headers, session_dir = gateway
    write_bundle(session_dir, ttl=60, issued_ago=3000)  # expired long ago
    expired = run(client, headers, "echo hi")
    assert expired["isError"] and "remote-gateway-test" in expired["content"][0]["text"]
    assert not (session_dir / "run" / "last-call.json").exists()
    (session_dir / "current.env").unlink()
    missing = run(client, headers, "echo hi")
    assert missing["isError"] and "remote-gateway-test" in missing["content"][0]["text"]


def test_bundle_signed_with_another_secret_is_rejected(gateway):
    client, headers, session_dir = gateway
    token = issue_ssh_session("someone-elses-key")
    (session_dir / "current.env").write_text(
        f"REMOTE_GATEWAY_SSH_TOKEN={token}\nREMOTE_GATEWAY_SSH_KEY_B64={base64.b64encode(b'k').decode()}\n"
    )
    assert run(client, headers, "echo hi")["isError"]


def test_timeout_kills_the_remote_command(gateway):
    client, headers, session_dir = gateway
    started = time.time()
    result = run(client, headers, "sleep", timeout_seconds=1)
    assert result["isError"] and "timed out" in result["content"][0]["text"]
    assert time.time() - started < 15
    pid = int((session_dir / "run" / "sleeper.pid").read_text())
    time.sleep(0.3)
    with pytest.raises(ProcessLookupError):
        os.kill(pid, 0)


def test_output_is_capped_and_marked(gateway):
    client, headers, _ = gateway
    text = run(client, headers, "big")["content"][0]["text"]
    assert "(truncated)" in text and len(text) < 70_000


def test_ssh_transport_failure_is_distinguished_from_command_failure(gateway):
    client, headers, _ = gateway
    result = run(client, headers, "authfail")
    assert result["isError"] and "could not reach the restricted shell" in result["content"][0]["text"]


def test_rejects_empty_and_oversized_commands(gateway):
    client, headers, _ = gateway
    assert run(client, headers, "   ")["isError"]
    assert run(client, headers, "x" * 20_001)["isError"]


def test_shell_is_a_reserved_alias_and_grants_are_route_bound(tmp_path):
    for name in ("shell", "all"):
        path = tmp_path / f"{name}.json"
        path.write_text('{"servers":{"%s":{"command":"/bin/true","args":[]}}}' % name)
        with pytest.raises(ValueError):
            load_allowlist(path)
    oauth = OAuthServer("k", str(tmp_path / "s.json"), {"shell", "all", "playwright"})
    oauth.clients["c"] = {"redirect_uris": ["http://127.0.0.1/cb"], "client_name": "x", "created": 0}
    shell = oauth._issue("c", "shell")
    allgrant = oauth._issue("c", "all")["access_token"]
    assert oauth.bearer_ok(f"Bearer {shell['access_token']}", "shell")
    assert not oauth.bearer_ok(f"Bearer {shell['access_token']}", "all")
    assert not oauth.bearer_ok(f"Bearer {allgrant}", "shell")


def test_shell_grant_is_shorter_than_the_general_grant(tmp_path):
    oauth = OAuthServer("k", str(tmp_path / "s.json"), {"shell", "all"})
    oauth.clients["c"] = {"redirect_uris": ["http://127.0.0.1/cb"], "client_name": "x", "created": 0}
    shell_refresh = oauth._issue("c", "shell")["refresh_token"]
    all_refresh = oauth._issue("c", "all")["refresh_token"]
    from gateway.oauth import _sha

    shell_exp = oauth.refresh[_sha(shell_refresh)]["exp"]
    all_exp = oauth.refresh[_sha(all_refresh)]["exp"]
    assert shell_exp - time.time() <= SHELL_REFRESH_TTL + 5
    assert shell_exp < all_exp


def test_oauth_access_tokens_use_the_two_hour_cap(tmp_path):
    oauth = OAuthServer("k", str(tmp_path / "s.json"), {"all"})
    oauth.clients["c"] = {"redirect_uris": ["http://127.0.0.1/cb"], "client_name": "x", "created": 0}
    issued = oauth._issue("c", "all")
    assert ACCESS_TTL == 7200
    assert ACCESS_TTL - 2 <= issued["expires_in"] <= ACCESS_TTL

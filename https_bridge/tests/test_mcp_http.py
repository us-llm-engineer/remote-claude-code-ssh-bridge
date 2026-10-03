import sys
import asyncio
import base64
import hashlib
from pathlib import Path

import anyio
from starlette.testclient import TestClient

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from gateway.mcp_proxy import LocalStdioUpstream
from gateway.server import build_gateway
from gateway.session import issue_ssh_session


def write_allowlist(path: Path) -> Path:
    path.write_text('{"servers":{"demo":{"command":"/bin/true","args":[]}}}', encoding="utf-8")
    return path


def test_mcp_route_requires_auth_and_advertises_oauth(tmp_path):
    app = build_gateway(
        "signing-key",
        allowlist_path=write_allowlist(tmp_path / "allowlist.json"),
        oauth_state_path=str(tmp_path / "oauth.json"),
    )
    with TestClient(app) as client:
        response = client.get("/demo/mcp/")
    assert response.status_code == 401
    assert "oauth-protected-resource/demo/mcp" in response.headers["www-authenticate"]


def test_two_hour_session_token_can_authenticate_mcp_route(tmp_path):
    app = build_gateway(
        "signing-key",
        allowlist_path=write_allowlist(tmp_path / "allowlist.json"),
        oauth_state_path=str(tmp_path / "oauth.json"),
    )
    token = issue_ssh_session("signing-key")
    with TestClient(app) as client:
        response = client.get("/demo/mcp/", headers={"Authorization": f"Bearer {token}"})
    assert response.status_code == 406  # authenticated; MCP transport rejects the incomplete request


def test_oauth_consent_accepts_only_two_hour_session_token(tmp_path):
    app = build_gateway(
        "signing-key",
        allowlist_path=write_allowlist(tmp_path / "allowlist.json"),
        oauth_state_path=str(tmp_path / "oauth.json"),
    )
    verifier = "v" * 43
    challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).rstrip(b"=").decode()
    with TestClient(app) as client:
        registered = client.post(
            "/register",
            json={
                "client_name": "test connector",
                "redirect_uris": ["http://127.0.0.1/callback"],
                "token_endpoint_auth_method": "none",
                "grant_types": ["authorization_code", "refresh_token"],
                "response_types": ["code"],
            },
        )
        assert registered.status_code == 201
        form = {
            "response_type": "code",
            "client_id": registered.json()["client_id"],
            "redirect_uri": "http://127.0.0.1/callback",
            "code_challenge": challenge,
            "code_challenge_method": "S256",
            "state": "test-state",
            "resource": "https://testserver/demo/mcp",
        }
        rejected = client.post("/authorize", data={**form, "gateway_token": "signing-key"})
        accepted = client.post(
            "/authorize",
            data={**form, "gateway_token": issue_ssh_session("signing-key")},
            follow_redirects=False,
        )
    assert rejected.status_code == 401
    assert accepted.status_code == 302
    assert accepted.headers["location"].startswith("http://127.0.0.1/callback?code=")


def test_stdio_upstream_replays_real_tool_schema_and_result(tmp_path):
    script = tmp_path / "demo_mcp.py"
    script.write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('demo')\n"
        "@mcp.tool()\n"
        "def echo(value: str) -> str:\n"
        "    return 'seen:' + value\n"
        "mcp.run()\n",
        encoding="utf-8",
    )

    async def exercise():
        upstream = LocalStdioUpstream("demo", {"command": sys.executable, "args": [str(script)]})
        try:
            session = await upstream.session()
            tools = await session.list_tools()
            assert [tool.name for tool in tools.tools] == ["echo"]
            result = await session.call_tool("echo", {"value": "ok"})
            assert result.isError is False
            assert result.content[0].text == "seen:ok"
        finally:
            await upstream.close()

    anyio.run(exercise)


def test_stdio_upstream_closes_in_its_owner_task(tmp_path):
    script = tmp_path / "long_lived_mcp.py"
    script.write_text(
        "from mcp.server.fastmcp import FastMCP\n"
        "mcp = FastMCP('long-lived')\n"
        "@mcp.tool()\n"
        "def ping() -> str:\n"
        "    return 'pong'\n"
        "mcp.run()\n",
        encoding="utf-8",
    )

    async def exercise():
        upstream = LocalStdioUpstream("long-lived", {"command": sys.executable, "args": [str(script)]})
        # Start from a short-lived request task, then close from the app-lifespan
        # task. The stdio cancel scope must still be exited by its owner task.
        session = await asyncio.create_task(upstream.session())
        assert (await session.list_tools()).tools[0].name == "ping"
        await upstream.close()

    anyio.run(exercise)


def test_aggregate_endpoint_namespaces_and_routes_every_reviewed_mcp(tmp_path):
    scripts = {}
    for alias, reply in (("alpha", "a"), ("beta", "b")):
        script = tmp_path / f"{alias}.py"
        script.write_text(
            "from mcp.server.fastmcp import FastMCP\n"
            f"mcp = FastMCP('{alias}')\n"
            "@mcp.tool()\n"
            "def ping() -> str:\n"
            f"    return '{reply}'\n"
            "mcp.run()\n",
            encoding="utf-8",
        )
        scripts[alias] = LocalStdioUpstream(alias, {"command": sys.executable, "args": [str(script)]})
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text(
        '{"servers":{%s}}' % ",".join(
            [f'"{a}":{{"command":"{sys.executable}","args":["{tmp_path / (a + ".py")}"]}}' for a in ("alpha", "beta")]
            + ['"broken":{"command":"/nonexistent/mcp","args":[]}']
        ),
        encoding="utf-8",
    )
    app = build_gateway(
        "signing-key", allowlist_path=allowlist, oauth_state_path=str(tmp_path / "oauth.json"),
        tool_cache_dir=tmp_path / "cache", upstream_oauth_dir=tmp_path / "upstream",
    )
    headers = {
        "Authorization": f"Bearer {issue_ssh_session('signing-key')}",
        "Accept": "application/json, text/event-stream",
    }

    def rpc(client, method, params=None):
        body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
        response = client.post("/all/mcp/", json=body, headers=headers)
        assert response.status_code == 200, response.text
        return response.json()["result"]

    with TestClient(app) as client:
        assert client.post("/all/mcp/", json={}).status_code == 401
        names = sorted(t["name"] for t in rpc(client, "tools/list")["tools"])
        assert names == ["alpha__ping", "beta__ping"]  # a dead MCP does not sink the listing
        result = rpc(client, "tools/call", {"name": "beta__ping", "arguments": {}})
        assert result["content"][0]["text"] == "b"
        bad = rpc(client, "tools/call", {"name": "gamma__ping", "arguments": {}})
        assert bad["isError"] is True


def test_alias_bound_oauth_grant_cannot_use_aggregate(tmp_path):
    from gateway.oauth import OAuthServer

    oauth = OAuthServer("k", str(tmp_path / "s.json"), {"playwright", "all"})
    oauth.clients["c"] = {"redirect_uris": ["http://127.0.0.1/cb"], "client_name": "x", "created": 0}
    bound = oauth._issue("c", "playwright")["access_token"]
    full = oauth._issue("c", "all")["access_token"]
    assert oauth.bearer_ok(f"Bearer {bound}", "playwright")
    assert not oauth.bearer_ok(f"Bearer {bound}", "all")
    assert oauth.bearer_ok(f"Bearer {full}", "all")
    assert not oauth.bearer_ok(f"Bearer {full}", "playwright")


def test_long_tool_names_fit_client_limit_and_stay_stable():
    from gateway.mcp_proxy import MAX_TOOL_NAME, public_tool_name

    long = public_tool_name("game-market", "get_gamedeveloper_postmortem_development_process_insights")
    assert len(long) <= MAX_TOOL_NAME and len("mcp__local-mcps__" + long) <= 64
    assert long == public_tool_name("game-market", "get_gamedeveloper_postmortem_development_process_insights")
    assert long != public_tool_name("game-market", "get_gamedeveloper_postmortem_development_process_insights2")
    assert public_tool_name("playwright", "browser_tabs") == "playwright__browser_tabs"


def test_allowlist_accepts_only_https_or_loopback_http_upstreams(tmp_path):
    import pytest
    from gateway.mcp_proxy import load_allowlist

    def check(spec):
        path = tmp_path / "a.json"
        path.write_text('{"servers":{"x":%s}}' % spec, encoding="utf-8")
        return load_allowlist(path)

    assert check('{"url":"https://huggingface.co/mcp?login"}')
    assert check('{"url":"http://127.0.0.1:8791/mcp"}')
    for bad in ('{"url":"http://evil.example/mcp"}', '{"url":"file:///etc/passwd"}',
                '{"url":"https://a/mcp","command":"/bin/sh","args":[]}'):
        with pytest.raises(ValueError):
            check(bad)


def test_failed_upstream_restarts_on_next_use(tmp_path):
    script = tmp_path / "late.py"
    upstream = LocalStdioUpstream("late", {"command": sys.executable, "args": [str(script)]})

    async def exercise():
        try:
            await upstream.session()
            raise AssertionError("missing script must fail")
        except RuntimeError:
            pass
        script.write_text(
            "from mcp.server.fastmcp import FastMCP\n"
            "mcp = FastMCP('late')\n"
            "@mcp.tool()\n"
            "def ping() -> str:\n"
            "    return 'up'\n"
            "mcp.run()\n",
            encoding="utf-8",
        )
        session = await upstream.session()
        assert (await session.list_tools()).tools[0].name == "ping"
        await upstream.close()

    anyio.run(exercise)


def test_http_upstream_token_storage_is_private(tmp_path):
    from gateway.upstream_auth import FileTokenStorage
    from mcp.shared.auth import OAuthToken

    storage = FileTokenStorage("hf", tmp_path)

    async def exercise():
        await storage.set_tokens(OAuthToken(access_token="a", token_type="Bearer", refresh_token="r"))
        assert (await storage.get_tokens()).refresh_token == "r"

    anyio.run(exercise)
    assert oct((tmp_path / "hf.json").stat().st_mode & 0o777) == "0o600"


def _rpc(client, headers, method, params=None):
    body = {"jsonrpc": "2.0", "id": 1, "method": method, "params": params or {}}
    response = client.post("/all/mcp/", json=body, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()["result"]


def test_signin_tool_returns_url_and_cached_tools_stay_listed(tmp_path, monkeypatch):
    import json as _json
    from gateway.upstream_auth import SignInFlows

    started = {}

    async def fake_start(self, alias, url, redirect_uri):
        started.update(alias=alias, url=url, redirect=redirect_uri)
        self.by_state["st"] = asyncio.get_running_loop().create_future()
        return "https://idp.example/authorize?state=st"

    monkeypatch.setattr(SignInFlows, "start", fake_start)
    cache = tmp_path / "cache"
    cache.mkdir()
    (cache / "hub.json").write_text(_json.dumps([{"name": "whoami", "inputSchema": {"type": "object"}}]))
    allowlist = tmp_path / "allowlist.json"
    allowlist.write_text('{"servers":{"hub":{"url":"http://127.0.0.1:9/mcp"}}}', encoding="utf-8")
    app = build_gateway(
        "signing-key", allowlist_path=allowlist, oauth_state_path=str(tmp_path / "oauth.json"),
        tool_cache_dir=cache, upstream_oauth_dir=tmp_path / "upstream",
    )
    headers = {
        "Authorization": f"Bearer {issue_ssh_session('signing-key')}",
        "Accept": "application/json, text/event-stream",
    }
    with TestClient(app) as client:
        names = sorted(t["name"] for t in _rpc(client, headers, "tools/list")["tools"])
        assert names == ["gateway__sign_in", "hub__whoami"]  # down upstream still listed from cache
        blocked = _rpc(client, headers, "tools/call", {"name": "hub__whoami", "arguments": {}})
        assert blocked["isError"] and "gateway__sign_in" in blocked["content"][0]["text"]
        reply = _rpc(client, headers, "tools/call", {"name": "gateway__sign_in", "arguments": {"alias": "hub"}})
        assert "https://idp.example/authorize?state=st" in reply["content"][0]["text"]
        assert started["redirect"] == "http://testserver/oauth/upstream-callback" or started["redirect"].endswith(
            "/oauth/upstream-callback")
        assert client.get("/oauth/upstream-callback?code=c&state=wrong").status_code == 400
        assert client.get("/oauth/upstream-callback?code=c&state=st").status_code == 200
        assert client.get("/oauth/upstream-callback?code=c&state=st").status_code == 400  # single use
        refused = _rpc(client, headers, "tools/call", {"name": "gateway__sign_in", "arguments": {"alias": "nope"}})
        assert refused["isError"]


def test_signin_flow_completes_against_real_oauth_mcp(tmp_path):
    """The flow is driven through a real MCP OAuth server: our own gateway
    (as the upstream) with its consent page, PKCE and token endpoint."""
    import threading
    import time as _time
    from urllib.parse import parse_qs, urlparse

    import httpx
    import uvicorn
    from gateway.upstream_auth import FileTokenStorage, SignInFlows

    upstream_app = build_gateway(
        "up-key", allowlist_path=write_allowlist(tmp_path / "up.json"),
        oauth_state_path=str(tmp_path / "up-oauth.json"),
        tool_cache_dir=tmp_path / "up-cache", upstream_oauth_dir=tmp_path / "up-upstream",
    )
    config = uvicorn.Config(upstream_app, host="127.0.0.1", port=0, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    while not server.started:
        _time.sleep(0.05)
    port = server.servers[0].sockets[0].getsockname()[1]
    upstream_url = f"http://127.0.0.1:{port}/demo/mcp/"

    async def exercise():
        flows = SignInFlows(tmp_path / "tokens")
        redirect = "http://127.0.0.1/oauth/upstream-callback"
        auth_url = await flows.start("demo", upstream_url, redirect)
        q = {k: v[0] for k, v in parse_qs(urlparse(auth_url).query).items()}
        async with httpx.AsyncClient() as http:  # the human fills in the consent page
            consent = await http.post(
                f"http://127.0.0.1:{port}/authorize",
                data={**q, "gateway_token": issue_ssh_session("up-key")},
            )
        assert consent.status_code == 302
        back = {k: v[0] for k, v in parse_qs(urlparse(consent.headers["location"]).query).items()}
        assert flows.callback(back["code"], back.get("state"), None)
        _, task = flows.pending["demo"]
        try:
            await asyncio.wait_for(task, 30)
        except Exception:
            pass  # the demo upstream (/bin/true) cannot serve MCP; the grant is what matters
        tokens = await FileTokenStorage("demo", tmp_path / "tokens").get_tokens()
        assert tokens is not None and tokens.access_token.startswith("gat_")

    try:
        anyio.run(exercise)
    finally:
        server.should_exit = True
        thread.join(5)

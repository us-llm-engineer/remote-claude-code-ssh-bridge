"""Authenticated HTTPS gateway for reviewed local MCPs and restricted SSH."""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager
import logging
import os
import time
from pathlib import Path
from typing import Any

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import FileResponse, HTMLResponse, JSONResponse, Response
from starlette.routing import Mount, Route, WebSocketRoute
from starlette.websockets import WebSocket, WebSocketDisconnect

from gateway.mcp_proxy import AGGREGATE_ALIAS, CALLBACK_PATH, DEFAULT_ALLOWLIST, TOOL_CACHE_DIR, build_aggregate, build_proxy, load_allowlist
from gateway.upstream_auth import STATE_DIR, SignInFlows
from gateway.oauth import OAuthServer
from gateway.shell_mcp import SHELL_ALIAS, build_shell
from gateway.session import verify_ssh_session

logger = logging.getLogger(__name__)

ENV_TOKEN = "REMOTE_GATEWAY_TOKEN"
ENV_HOST = "REMOTE_GATEWAY_HOST"
ENV_PORT = "REMOTE_GATEWAY_PORT"
SSH_HOST = "127.0.0.1"
SSH_PORT = 2223
COOKIE_NAME = "remote_gateway_ssh"
DEFAULT_OAUTH_STATE = "/home/centos/.remote-gateway/oauth-state.json"


def _public_base(scope: dict[str, Any]) -> str:
    headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
    host = (headers.get("x-forwarded-host") or headers.get("host") or "").split(",")[0].strip()
    scheme = "http" if host.startswith(("127.0.0.1", "localhost")) else "https"
    return f"{scheme}://{host}"


class AuthenticatedMCP:
    def __init__(self, alias: str, manager: Any, oauth: OAuthServer, signing_key: str):
        self.alias, self.manager, self.oauth, self.signing_key = alias, manager, oauth, signing_key

    async def __call__(self, scope: dict[str, Any], receive: Any, send: Any) -> None:
        headers = {k.decode().lower(): v.decode() for k, v in scope.get("headers", [])}
        authorization = headers.get("authorization")
        direct_ok = False
        if authorization:
            scheme, _, presented = authorization.partition(" ")
            direct_ok = scheme.lower() == "bearer" and verify_ssh_session(presented, self.signing_key) is not None
        if not (direct_ok or self.oauth.bearer_ok(authorization, self.alias)):
            metadata = f'{_public_base(scope)}/.well-known/oauth-protected-resource/{self.alias}/mcp'
            response = JSONResponse(
                {"error": "unauthorized", "error_description": "valid two-hour MCP authorization required"},
                status_code=401,
                headers={
                    "Cache-Control": "no-store",
                    "WWW-Authenticate": f'Bearer resource_metadata="{metadata}", scope="mcp"',
                },
            )
            await response(scope, receive, send)
            return
        await self.manager.handle_request(scope, receive, send)


async def _close(writer: asyncio.StreamWriter | None, websocket: WebSocket) -> None:
    if writer is not None:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
    try:
        await websocket.close()
    except (RuntimeError, WebSocketDisconnect):
        pass  # already closed, or the Cloud client dropped first


def build_gateway(
    token: str,
    *,
    allowlist_path: Path = DEFAULT_ALLOWLIST,
    oauth_state_path: str = DEFAULT_OAUTH_STATE,
    tool_cache_dir: Path = TOOL_CACHE_DIR,
    upstream_oauth_dir: Path = STATE_DIR,
    shell_options: dict[str, Any] | None = None,
) -> Starlette:
    """Build the public bridge. ``token`` is only a signing key, never accepted directly."""
    if not token:
        raise ValueError(f"{ENV_TOKEN} is required")

    servers = load_allowlist(allowlist_path)
    oauth = OAuthServer(token, oauth_state_path, {*servers, AGGREGATE_ALIAS, SHELL_ALIAS})
    upstreams = {}
    managers = []
    mounts = []
    for alias, spec in servers.items():
        upstream, manager = build_proxy(alias, spec)
        upstreams[alias] = upstream
        managers.append(manager)
        mounts.append(Mount(f"/{alias}/mcp", app=AuthenticatedMCP(alias, manager, oauth, token), name=f"mcp-{alias}"))
    # One connector for every reviewed MCP; an OAuth grant bound to a single
    # alias does not reach it (OAuthServer.bearer_ok checks the resource).
    flows = SignInFlows(upstream_oauth_dir)
    aggregate = build_aggregate(upstreams, cache_dir=tool_cache_dir, flows=flows)
    managers.append(aggregate)
    # Separate connector for command execution; never part of /all.
    shell = build_shell(token, **(shell_options or {}))
    managers.append(shell)
    mounts.append(Mount(f"/{SHELL_ALIAS}/mcp", app=AuthenticatedMCP(SHELL_ALIAS, shell, oauth, token), name="mcp-shell"))
    mounts.append(Mount(f"/{AGGREGATE_ALIAS}/mcp", app=AuthenticatedMCP(AGGREGATE_ALIAS, aggregate, oauth, token), name="mcp-all"))

    @asynccontextmanager
    async def lifespan(_: Starlette):
        Path(oauth_state_path).parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        async with AsyncExitStack() as stack:
            for upstream in upstreams.values():
                stack.push_async_callback(upstream.close)
            for manager in managers:
                await stack.enter_async_context(manager.run())
            yield

    async def health(_: object) -> Response:
        return JSONResponse({
            "status": "ok",
            "transport": "mcp-streamable-http+ssh-websocket",
            "mcp_servers": sorted(servers),
            "aggregate": f"/{AGGREGATE_ALIAS}/mcp/",
            "shell": f"/{SHELL_ALIAS}/mcp/",
        })

    async def upstream_callback(request: Request) -> Response:
        q = request.query_params
        ok = flows.callback(q.get("code"), q.get("state"), q.get("error"))
        message = "Signed in. You can close this tab and tell the agent to continue." if ok and q.get("code") else (
            "This sign-in link is unknown, expired, or was refused. Ask the agent to start again.")
        return HTMLResponse(f'<!doctype html><meta charset="utf-8"><p>{message}</p>',
                            status_code=200 if ok else 400, headers={"Cache-Control": "no-store"})

    async def client(_: object) -> Response:
        return FileResponse(Path(__file__).parent.parent / "https_bridge" / "ssh_ws_proxy.py", media_type="text/x-python")

    async def ssh(websocket: WebSocket) -> None:
        expiry = verify_ssh_session(websocket.cookies.get(COOKIE_NAME), token)
        if expiry is None:
            await websocket.close(code=4401, reason="valid unexpired SSH session required")
            return
        try:
            reader, writer = await asyncio.open_connection(SSH_HOST, SSH_PORT)
        except OSError:
            logger.error("restricted SSH daemon is unavailable")
            await websocket.close(code=1013, reason="SSH service unavailable")
            return
        await websocket.accept()

        async def ws_to_ssh() -> None:
            try:
                while True:
                    event = await websocket.receive()
                    if event["type"] == "websocket.disconnect":
                        return
                    payload = event.get("bytes")
                    if payload is None:
                        raise ValueError("SSH WebSocket accepts binary frames only")
                    writer.write(payload)
                    await writer.drain()
            except WebSocketDisconnect:
                return

        async def ssh_to_ws() -> None:
            while data := await reader.read(65536):
                await websocket.send_bytes(data)

        async def expiry_guard() -> None:
            await asyncio.sleep(max(0, expiry - time.time()))

        tasks = [asyncio.create_task(ws_to_ssh()), asyncio.create_task(ssh_to_ws()), asyncio.create_task(expiry_guard())]
        try:
            done, _ = await asyncio.wait(tasks, return_when=asyncio.FIRST_COMPLETED)
            if tasks[2] in done:
                logger.info("expired SSH session disconnected")
        finally:
            for task in tasks:
                task.cancel()
            await asyncio.gather(*tasks, return_exceptions=True)
            await _close(writer, websocket)

    return Starlette(lifespan=lifespan, routes=[
        Route("/healthz", health, methods=["GET"]),
        Route("/ssh-client.py", client, methods=["GET"]),
        Route(CALLBACK_PATH, upstream_callback, methods=["GET"]),
        WebSocketRoute("/ssh", ssh),
        *oauth.routes(),
        *mounts,
    ])


def main() -> None:
    import uvicorn

    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
    uvicorn.run(build_gateway(os.environ.get(ENV_TOKEN, "")), host=os.environ.get(ENV_HOST, "127.0.0.1"), port=int(os.environ.get(ENV_PORT, "8798")))


if __name__ == "__main__":
    main()

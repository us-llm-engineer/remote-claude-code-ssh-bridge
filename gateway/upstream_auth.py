"""OAuth for allowlisted HTTP upstreams (e.g. huggingface, data-host-mcp).

The gateway is the OAuth *client* of these servers. The human signs in once on
this machine with ``remote-gateway-mcp-login ALIAS``; the gateway then refreshes
the stored grant itself. Tokens live only in a 0600 file under
``~/.remote-gateway/upstream-oauth`` and never reach a Cloud caller. The running
gateway never starts an interactive sign-in: an expired grant makes that one
upstream unavailable until the human logs in again.
"""

from __future__ import annotations

import asyncio
import json
import os
import subprocess
import sys
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from mcp.client.auth import OAuthClientProvider, TokenStorage
from mcp.shared.auth import OAuthClientInformationFull, OAuthClientMetadata, OAuthToken

STATE_DIR = Path("/home/centos/.remote-gateway/upstream-oauth")
CALLBACK_PORT = 8797
REDIRECT_URI = f"http://127.0.0.1:{CALLBACK_PORT}/callback"


class FileTokenStorage(TokenStorage):
    def __init__(self, alias: str, state_dir: Path = STATE_DIR):
        self.path = state_dir / f"{alias}.json"

    def _read(self) -> dict:
        try:
            return json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            return {}

    def _write(self, key: str, value: dict) -> None:
        data = self._read()
        data[key] = value
        self.path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        tmp = self.path.with_suffix(".tmp")
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump(data, fh)
        os.replace(tmp, self.path)

    async def get_tokens(self) -> OAuthToken | None:
        raw = self._read().get("tokens")
        return OAuthToken.model_validate(raw) if raw else None

    async def set_tokens(self, tokens: OAuthToken) -> None:
        self._write("tokens", tokens.model_dump(mode="json", exclude_none=True))

    async def get_client_info(self) -> OAuthClientInformationFull | None:
        raw = self._read().get("client")
        return OAuthClientInformationFull.model_validate(raw) if raw else None

    async def set_client_info(self, client_info: OAuthClientInformationFull) -> None:
        self._write("client", client_info.model_dump(mode="json", exclude_none=True))

    def forget_client_unless(self, redirect_uri: str) -> None:
        """Drop a registration made for another redirect (the tunnel host moved,
        or the other sign-in path was used) so the next flow registers afresh."""
        data = self._read()
        if data.get("client") and data["client"].get("redirect_uris") != [redirect_uri]:
            data.pop("client")
            data.pop("tokens", None)
            self.path.write_text(json.dumps(data), encoding="utf-8")


def _metadata(redirect_uri: str = REDIRECT_URI) -> OAuthClientMetadata:
    return OAuthClientMetadata(
        client_name="remote-gateway",
        redirect_uris=[redirect_uri],
        grant_types=["authorization_code", "refresh_token"],
        response_types=["code"],
        token_endpoint_auth_method="none",
    )


def gateway_provider(alias: str, url: str) -> OAuthClientProvider:
    """Non-interactive provider used by the running gateway."""

    async def refuse(_: str) -> None:
        raise RuntimeError(f"{alias}: sign-in required; run remote-gateway-mcp-login {alias} locally")

    async def no_callback() -> tuple[str, str | None]:
        raise RuntimeError(f"{alias}: sign-in required")

    return OAuthClientProvider(url, _metadata(), FileTokenStorage(alias), refuse, no_callback)


async def _login(alias: str, url: str) -> None:
    loop = asyncio.get_running_loop()
    result: asyncio.Future[tuple[str, str | None]] = loop.create_future()

    async def on_request(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        line = (await reader.readline()).decode(errors="replace")
        while (await reader.readline()) not in (b"\r\n", b"\n", b""):
            pass
        query = parse_qs(urlparse(line.split(" ")[1] if " " in line else "").query)
        ok = "code" in query
        writer.write(b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n"
                     + (b"Signed in. You can close this tab." if ok else b"Sign-in failed."))
        await writer.drain()
        writer.close()
        if not result.done():
            if ok:
                result.set_result((query["code"][0], query.get("state", [None])[0]))
            else:
                result.set_exception(RuntimeError(f"authorization failed: {query.get('error', ['unknown'])[0]}"))

    server = await asyncio.start_server(on_request, "127.0.0.1", CALLBACK_PORT)

    async def open_browser(auth_url: str) -> None:
        print(f"Open this URL to sign in to {alias}:\n{auth_url}\n", flush=True)
        for opener in ("wslview", "xdg-open"):
            try:
                subprocess.Popen([opener, auth_url], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                break
            except OSError:
                continue

    async def wait_callback() -> tuple[str, str | None]:
        return await asyncio.wait_for(result, 300)

    storage = FileTokenStorage(alias)
    storage.forget_client_unless(REDIRECT_URI)
    provider = OAuthClientProvider(url, _metadata(), storage, open_browser, wait_callback)
    from mcp.client.session import ClientSession
    from mcp.client.streamable_http import streamablehttp_client

    try:
        async with streamablehttp_client(url, auth=provider) as (read, write, _):
            async with ClientSession(read, write) as session:
                await session.initialize()
                tools = (await session.list_tools()).tools
        print(f"{alias}: signed in; {len(tools)} tools available through the gateway.")
    finally:
        server.close()


class SignInFlows:
    """Sign-ins started by a Cloud agent (``gateway__sign_in``) and finished by
    the human in any browser. The redirect returns to the public gateway at
    ``/oauth/upstream-callback``; the PKCE verifier and tokens stay here, so the
    agent only ever sees the authorization URL."""

    def __init__(self, state_dir: Path = STATE_DIR):
        self.state_dir = state_dir
        self.pending: dict[str, tuple[str, asyncio.Task[None]]] = {}
        self.by_state: dict[str, asyncio.Future[tuple[str, str | None]]] = {}

    async def start(self, alias: str, url: str, redirect_uri: str) -> str | None:
        """Return a URL for the human to open, or None if already signed in."""
        current = self.pending.get(alias)
        if current and not current[1].done():
            return current[0]
        loop = asyncio.get_running_loop()
        url_ready: asyncio.Future[str] = loop.create_future()
        code: asyncio.Future[tuple[str, str | None]] = loop.create_future()
        storage = FileTokenStorage(alias, self.state_dir)
        storage.forget_client_unless(redirect_uri)

        async def on_redirect(auth_url: str) -> None:
            state = parse_qs(urlparse(auth_url).query).get("state", [""])[0]
            self.by_state[state] = code
            url_ready.set_result(auth_url)

        async def on_callback() -> tuple[str, str | None]:
            return await asyncio.wait_for(code, 900)

        provider = OAuthClientProvider(url, _metadata(redirect_uri), storage, on_redirect, on_callback)

        async def run() -> None:
            from mcp.client.session import ClientSession
            from mcp.client.streamable_http import streamablehttp_client

            async with streamablehttp_client(url, auth=provider) as (read, write, _):
                async with ClientSession(read, write) as session:
                    await session.initialize()

        task = asyncio.create_task(run(), name=f"sign-in-{alias}")
        task.add_done_callback(lambda t: t.cancelled() or t.exception())
        await asyncio.wait({task, url_ready}, timeout=60, return_when=asyncio.FIRST_COMPLETED)
        if url_ready.done():
            self.pending[alias] = (url_ready.result(), task)
            return url_ready.result()
        if task.done() and task.exception() is None:
            return None
        task.cancel()
        raise RuntimeError(f"{alias}: could not start sign-in") from (task.exception() if task.done() else None)

    def callback(self, code: str | None, state: str | None, error: str | None) -> bool:
        future = self.by_state.pop(state or "", None)
        if future is None or future.done():
            return False
        if code:
            future.set_result((code, state))
        else:
            future.set_exception(RuntimeError(f"authorization failed: {error or 'unknown'}"))
        return True


def main() -> None:
    from gateway.mcp_proxy import load_allowlist

    if len(sys.argv) != 2:
        sys.exit("usage: remote-gateway-mcp-login ALIAS")
    alias = sys.argv[1]
    spec = load_allowlist().get(alias)
    if not spec or "url" not in spec:
        sys.exit(f"{alias} is not an allowlisted HTTP MCP")
    asyncio.run(_login(alias, spec["url"]))


if __name__ == "__main__":
    main()

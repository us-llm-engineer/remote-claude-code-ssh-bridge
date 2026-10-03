"""Authenticated Streamable-HTTP façades for root-reviewed local stdio MCPs."""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
from contextlib import AsyncExitStack
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from mcp import types
from mcp.client.session import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client
from mcp.client.streamable_http import streamablehttp_client
from mcp.server.lowlevel.helper_types import ReadResourceContents
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http import TransportSecuritySettings
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

logger = logging.getLogger(__name__)

DEFAULT_ALLOWLIST = Path("/etc/claude-remote/mcp-allowlist.json")
PROJECTS_ROOT = Path("/home/centos/data/projects").resolve()
AGGREGATE_ALIAS = "all"
RESERVED_ALIASES = frozenset({AGGREGATE_ALIAS, "shell"})
SEP = "__"
UPSTREAM_LIST_TIMEOUT = 60
SIGN_IN_TOOL = "gateway__sign_in"
CALLBACK_PATH = "/oauth/upstream-callback"
TOOL_CACHE_DIR = Path("/home/centos/.remote-gateway/tool-cache")
MAX_TOOL_NAME = 44  # with "mcp__<connector>__" (7 chars + name) this fits the 64-character limit for names up to 13 characters
SAFE_PATH = "/home/centos/.local/bin:/home/centos/.nvm/versions/node/v26.7.0/bin:/usr/local/bin:/usr/bin:/bin"


def load_allowlist(path: Path = DEFAULT_ALLOWLIST) -> dict[str, dict[str, Any]]:
    data = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(data, dict) or set(data) != {"servers"} or not isinstance(data["servers"], dict):
        raise ValueError("allowlist must contain only a servers object")
    for alias, spec in data["servers"].items():
        if not isinstance(alias, str) or not alias or "/" in alias or SEP in alias or alias in RESERVED_ALIASES or not isinstance(spec, dict):
            raise ValueError("invalid MCP alias")
        if set(spec) == {"url"}:
            url = urlparse(spec["url"]) if isinstance(spec["url"], str) else None
            loopback = url is not None and url.scheme == "http" and url.hostname in {"127.0.0.1", "localhost"}
            if url is None or not (url.scheme == "https" or loopback) or not url.hostname:
                raise ValueError(f"{alias}: url must be https or loopback http")
            continue
        if not {"command", "args"}.issubset(spec) or set(spec) - {"command", "args", "cwd"}:
            raise ValueError(f"{alias}: invalid server specification")
        if not isinstance(spec["command"], str) or not spec["command"].startswith("/"):
            raise ValueError(f"{alias}: command must be absolute")
        if not isinstance(spec["args"], list) or not all(isinstance(arg, str) for arg in spec["args"]):
            raise ValueError(f"{alias}: args must be strings")
        cwd = spec.get("cwd")
        if cwd is not None:
            try:
                Path(cwd).resolve().relative_to(PROJECTS_ROOT)
            except (AttributeError, ValueError) as exc:
                raise ValueError(f"{alias}: cwd must remain under projects") from exc
    return data["servers"]


class LocalStdioUpstream:
    """One lazily started upstream shared by HTTP sessions: a local stdio
    process, or an allowlisted HTTP MCP the gateway signs in to itself."""

    def __init__(self, alias: str, spec: dict[str, Any]):
        self.alias = alias
        self.spec = spec
        self._session: ClientSession | None = None
        self._owner: asyncio.Task[None] | None = None
        self._start_lock = asyncio.Lock()
        self._ready = asyncio.Event()
        self._stop = asyncio.Event()
        self._error: Exception | None = None

    async def _run(self) -> None:
        """Own the stdio contexts for their full lifetime in this one task."""
        try:
            async with AsyncExitStack() as stack:
                if "url" in self.spec:
                    from gateway.upstream_auth import gateway_provider
                    read_stream, write_stream, _ = await stack.enter_async_context(
                        streamablehttp_client(self.spec["url"], auth=gateway_provider(self.alias, self.spec["url"])))
                    client = await stack.enter_async_context(ClientSession(read_stream, write_stream))
                    await client.initialize()
                    self._session = client
                    logger.info("remote MCP connected alias=%s", self.alias)
                    self._ready.set()
                    await self._stop.wait()
                    return
                env = {
                    "HOME": "/home/centos", "LOGNAME": "centos", "USER": "centos",
                    "PATH": SAFE_PATH, "LANG": "C.UTF-8",
                }
                params = StdioServerParameters(
                    command=self.spec["command"], args=self.spec["args"], env=env,
                    cwd=self.spec.get("cwd", "/home/centos"),
                )
                read_stream, write_stream = await stack.enter_async_context(stdio_client(params))
                client = await stack.enter_async_context(ClientSession(read_stream, write_stream))
                await client.initialize()
                self._session = client
                logger.info("local MCP started alias=%s", self.alias)
                self._ready.set()
                await self._stop.wait()
        except Exception as exc:
            self._error = exc
            self._ready.set()
            logger.exception("local MCP failed alias=%s", self.alias)
        finally:
            self._session = None

    async def session(self) -> ClientSession:
        async with self._start_lock:
            if self._owner is not None and self._owner.done() and not self._stop.is_set():
                # A failed or exited upstream restarts on next use, e.g. after
                # remote-gateway-mcp-login, without reloading the gateway.
                self._owner, self._error = None, None
                self._ready.clear()
            if self._owner is None:
                self._owner = asyncio.create_task(self._run(), name=f"mcp-upstream-{self.alias}")
        await self._ready.wait()
        if self._error is not None:
            raise RuntimeError(f"local MCP failed to start: {self.alias}") from self._error
        if self._session is None:
            raise RuntimeError(f"local MCP is unavailable: {self.alias}")
        return self._session

    async def close(self) -> None:
        if self._owner is not None:
            self._stop.set()
            await self._owner


def build_proxy(alias: str, spec: dict[str, Any]) -> tuple[LocalStdioUpstream, StreamableHTTPSessionManager]:
    upstream = LocalStdioUpstream(alias, spec)
    server = Server(name=f"remote-gateway-{alias}", version="1.0")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return (await (await upstream.session()).list_tools()).tools

    @server.call_tool(validate_input=True)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        return await (await upstream.session()).call_tool(name, arguments)

    @server.list_resources()
    async def list_resources() -> types.ListResourcesResult:
        return await (await upstream.session()).list_resources()

    @server.list_resource_templates()
    async def list_resource_templates() -> list[types.ResourceTemplate]:
        return (await (await upstream.session()).list_resource_templates()).resourceTemplates

    @server.read_resource()
    async def read_resource(uri: Any) -> list[ReadResourceContents]:
        result = await (await upstream.session()).read_resource(uri)
        converted: list[ReadResourceContents] = []
        for content in result.contents:
            if isinstance(content, types.TextResourceContents):
                converted.append(ReadResourceContents(content=content.text, mime_type=content.mimeType, meta=content.meta))
            else:
                import base64
                converted.append(ReadResourceContents(content=base64.b64decode(content.blob), mime_type=content.mimeType, meta=content.meta))
        return converted

    @server.list_prompts()
    async def list_prompts() -> types.ListPromptsResult:
        return await (await upstream.session()).list_prompts()

    @server.get_prompt()
    async def get_prompt(name: str, arguments: dict[str, str] | None) -> types.GetPromptResult:
        return await (await upstream.session()).get_prompt(name, arguments)

    return upstream, _manager(server)


def _manager(server: Server) -> StreamableHTTPSessionManager:
    return StreamableHTTPSessionManager(
        app=server,
        json_response=True,
        stateless=True,
        max_request_body_size=4 * 1024 * 1024,
        # The listener is loopback-only behind Cloudflare; bearer auth is the
        # public boundary and the quick-tunnel Host changes on every start.
        security_settings=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )


def public_tool_name(alias: str, tool: str) -> str:
    """``<alias>__<tool>``, shortened with a stable hash when it would push the
    client's ``mcp__<connector>__`` name past the 64-character tool-name limit."""
    name = f"{alias}{SEP}{tool}"
    if len(name) <= MAX_TOOL_NAME:
        return name
    return f"{name[:MAX_TOOL_NAME - 9]}_{hashlib.sha256(name.encode()).hexdigest()[:8]}"


def build_aggregate(
    upstreams: dict[str, LocalStdioUpstream],
    *,
    cache_dir: Path = TOOL_CACHE_DIR,
    flows: Any = None,
) -> StreamableHTTPSessionManager:
    """One endpoint exposing every reviewed MCP's tools as ``<alias>__<tool>``.

    It reuses the per-alias upstreams, so each local process still runs once
    (Playwright keeps a single browser profile). Each alias's last good tool
    listing is cached, so an MCP that is down or awaiting sign-in stays listed;
    calling one of its tools then reports what to do. HTTP upstreams that need
    the gateway signed in get ``gateway__sign_in``: the agent starts it and the
    human finishes it in a browser.
    """
    from gateway.upstream_auth import SignInFlows

    flows = flows or SignInFlows()
    server = Server(name="remote-gateway-all", version="1.0")
    routes: dict[str, tuple[str, str]] = {}
    signable = sorted(alias for alias, u in upstreams.items() if "url" in u.spec)
    sign_in = types.Tool(
        name=SIGN_IN_TOOL,
        description=(
            "Start signing the user's local gateway in to an MCP that needs its own login "
            "(its tools fail with 'sign-in required'). Returns a URL: give it to the user to "
            "open and complete in their browser, then retry the original tool. The agent "
            "never receives the credentials."
        ),
        inputSchema={
            "type": "object",
            "properties": {"alias": {"type": "string", "enum": signable}},
            "required": ["alias"],
        },
    )

    def cache_path(alias: str) -> Path:
        return cache_dir / f"{alias}.json"

    def cached(alias: str) -> list[types.Tool]:
        try:
            raw = json.loads(cache_path(alias).read_text(encoding="utf-8"))
            return [types.Tool.model_validate(tool) for tool in raw]
        except (OSError, ValueError):
            return []

    def remember(alias: str, tools: list[types.Tool]) -> None:
        try:
            cache_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            tmp = cache_path(alias).with_suffix(".tmp")
            tmp.write_text(json.dumps([t.model_dump(mode="json", exclude_none=True) for t in tools]), encoding="utf-8")
            tmp.replace(cache_path(alias))
        except OSError:
            logger.exception("aggregate: could not cache tools alias=%s", alias)

    async def tools_of(alias: str, upstream: LocalStdioUpstream) -> list[types.Tool]:
        try:
            listed = (await asyncio.wait_for((await upstream.session()).list_tools(), UPSTREAM_LIST_TIMEOUT)).tools
            remember(alias, listed)
        except Exception as exc:
            logger.warning("aggregate: serving cached tools alias=%s (%s)", alias, exc)
            listed = cached(alias)
        tools = []
        for tool in listed:
            name = public_tool_name(alias, tool.name)
            routes[name] = (alias, tool.name)
            tools.append(tool.model_copy(update={"name": name}))
        return tools

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        per_alias = await asyncio.gather(*(tools_of(a, u) for a, u in upstreams.items()))
        return [tool for tools in per_alias for tool in tools] + ([sign_in] if signable else [])

    def text(message: str, error: bool = False) -> types.CallToolResult:
        return types.CallToolResult(content=[types.TextContent(type="text", text=message)], isError=error)

    async def start_sign_in(alias: str) -> types.CallToolResult:
        if alias not in signable:
            return text(f"{alias!r} does not use gateway sign-in; choose one of {signable}", True)
        request = server.request_context.request
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
        scheme = "http" if host.startswith(("127.0.0.1", "localhost")) else "https"
        url = await flows.start(alias, upstreams[alias].spec["url"], f"{scheme}://{host}{CALLBACK_PATH}")
        if url is None:
            return text(f"{alias} is already signed in; retry its tools.")
        return text(
            f"Ask the user to open this URL and finish signing in to {alias}:\n{url}\n"
            "When they confirm, retry the original tool. The link stays valid for 15 minutes."
        )

    @server.call_tool(validate_input=False)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        if name == SIGN_IN_TOOL:
            return await start_sign_in(str(arguments.get("alias", "")))
        if name not in routes:
            await list_tools()
        if name not in routes:
            raise ValueError(f"unknown tool: {name}")
        alias, tool = routes[name]
        try:
            session = await upstreams[alias].session()
        except RuntimeError as exc:
            if alias in signable:
                return text(f"{alias}: sign-in required. Call {SIGN_IN_TOOL} with alias={alias!r}.", True)
            return text(f"{alias} is unavailable on the user's machine ({exc}); ask them to run remote-gateway-sync.", True)
        return await session.call_tool(tool, arguments)

    return _manager(server)

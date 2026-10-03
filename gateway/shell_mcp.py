"""``/shell/mcp/``: the restricted SSH shell, offered to Cloud agents as one MCP tool.

A Cloud session's auto-mode check blocks a hand-built SSH tunnel and a decoded
private key, but a native connector tool carries neither. The gateway itself
makes the SSH connection, over loopback, to the same restricted ``claude-shell``
account, with the same forced command, chroot and mounts that ``/ssh`` uses. The
Cloud caller never receives the key, the token or a tunnel.

The tool works only while the two-hour bundle printed by ``remote-gateway-test``
is valid (``~/.remote-gateway/ssh-session/current.env``), so a longer-lived
connector grant never extends shell access beyond that hour.
"""

from __future__ import annotations

import asyncio
import base64
import logging
import os
import signal
import tempfile
import time
from pathlib import Path
from typing import Any

from mcp import types
from mcp.server.lowlevel.server import Server
from mcp.server.streamable_http_manager import StreamableHTTPSessionManager

from gateway.mcp_proxy import _manager
from gateway.session import verify_ssh_session

logger = logging.getLogger(__name__)

SHELL_ALIAS = "shell"
TOOL_NAME = "ssh_run"
SESSION_ENV = Path("/home/centos/.remote-gateway/ssh-session/current.env")
KNOWN_HOSTS = Path("/home/centos/.remote-gateway/ssh-session/known_hosts")
SSH_USER, SSH_HOST, SSH_PORT = "claude-shell", "127.0.0.1", 2223
MAX_COMMAND_CHARS = 20_000
MAX_OUTPUT_BYTES = 64 * 1024
DEFAULT_TIMEOUT, MAX_TIMEOUT = 120, 600
MAX_CONCURRENT = 4
MIN_REMAINING_SECONDS = 10

TOOL = types.Tool(
    name=TOOL_NAME,
    description=(
        "Run one shell command in the user's restricted local shell (the same jail as the "
        "/ssh bridge): read/write /workspace/projects, read-only /workspace/skills and "
        "/workspace/agents, no host files, no system installs. Returns the exit code, stdout "
        "and stderr (each capped at 64 KB). Works only while the user's two-hour session is "
        "valid; if it reports an expired session, ask the user to run remote-gateway-test."
    ),
    inputSchema={
        "type": "object",
        "properties": {
            "command": {"type": "string", "description": "Shell command, run by bash -lc in /workspace/projects."},
            "timeout_seconds": {"type": "integer", "minimum": 1, "maximum": MAX_TIMEOUT, "default": DEFAULT_TIMEOUT},
        },
        "required": ["command"],
        "additionalProperties": False,
    },
)


class ShellUnavailable(RuntimeError):
    """The two-hour session is missing or expired; the message tells the agent what to ask for."""


def _load_bundle(secret: str, env_path: Path) -> tuple[bytes, float]:
    try:
        values = dict(
            line.split("=", 1) for line in env_path.read_text(encoding="utf-8").splitlines() if "=" in line
        )
        token, key_b64 = values["REMOTE_GATEWAY_SSH_TOKEN"], values["REMOTE_GATEWAY_SSH_KEY_B64"]
        key = base64.b64decode(key_b64, validate=True)
    except (OSError, KeyError, ValueError):
        raise ShellUnavailable("no two-hour SSH session is available; ask the user to run remote-gateway-test") from None
    expiry = verify_ssh_session(token, secret)
    if expiry is None or expiry - time.time() < MIN_REMAINING_SECONDS:
        raise ShellUnavailable("the two-hour SSH session has expired; ask the user to run remote-gateway-test")
    return key, expiry


async def _pump(stream: asyncio.StreamReader, cap: int) -> tuple[bytes, bool]:
    """Keep the first ``cap`` bytes; keep draining so the child never blocks on a full pipe."""
    kept, truncated = bytearray(), False
    while chunk := await stream.read(65536):
        room = cap - len(kept)
        if room > 0:
            kept += chunk[:room]
        if len(chunk) > room:
            truncated = True
    return bytes(kept), truncated


class SshRunner:
    def __init__(
        self,
        secret: str,
        *,
        env_path: Path = SESSION_ENV,
        known_hosts: Path = KNOWN_HOSTS,
        ssh_bin: str = "/usr/bin/ssh",
        host: str = SSH_HOST,
        port: int = SSH_PORT,
        user: str = SSH_USER,
    ):
        self.secret, self.env_path, self.known_hosts = secret, env_path, known_hosts
        self.ssh_bin, self.host, self.port, self.user = ssh_bin, host, port, user
        self._slots = asyncio.Semaphore(MAX_CONCURRENT)

    async def run(self, command: str, timeout: int) -> types.CallToolResult:
        if not command.strip() or len(command) > MAX_COMMAND_CHARS:
            return _result(f"command must be 1 to {MAX_COMMAND_CHARS} characters", error=True)
        try:
            key, expiry = _load_bundle(self.secret, self.env_path)
        except ShellUnavailable as exc:
            return _result(str(exc), error=True)
        timeout = max(1, min(timeout, MAX_TIMEOUT, int(expiry - time.time())))
        async with self._slots:
            return await self._ssh(command, key, timeout)

    async def _ssh(self, command: str, key: bytes, timeout: int) -> types.CallToolResult:
        run_dir = self.env_path.parent / "run"
        run_dir.mkdir(mode=0o700, parents=True, exist_ok=True)
        fd, key_path = tempfile.mkstemp(dir=run_dir, prefix="k-")
        try:
            with os.fdopen(fd, "wb") as fh:
                fh.write(key)
            args = [
                self.ssh_bin, "-T", "-i", key_path,
                "-o", "IdentitiesOnly=yes", "-o", "BatchMode=yes", "-o", "LogLevel=ERROR",
                "-o", "StrictHostKeyChecking=accept-new", "-o", f"UserKnownHostsFile={self.known_hosts}",
                "-o", "ConnectTimeout=10", "-o", "ServerAliveInterval=15",
                "-p", str(self.port), f"{self.user}@{self.host}", command,
            ]
            proc = await asyncio.create_subprocess_exec(
                *args, stdin=asyncio.subprocess.DEVNULL, stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE, start_new_session=True,
                env={"PATH": "/usr/bin:/bin", "HOME": str(self.env_path.parent)},
            )
            logger.info("shell run pid=%s chars=%d cmd=%r", proc.pid, len(command), command[:200])
            try:
                (out, out_cut), (err, err_cut) = await asyncio.wait_for(
                    asyncio.gather(_pump(proc.stdout, MAX_OUTPUT_BYTES), _pump(proc.stderr, MAX_OUTPUT_BYTES)), timeout
                )
                code = await asyncio.wait_for(proc.wait(), 5)
            except asyncio.TimeoutError:
                os.killpg(proc.pid, signal.SIGKILL)
                await proc.wait()
                logger.warning("shell run timed out after %ss pid=%s", timeout, proc.pid)
                return _result(f"command timed out after {timeout}s and was killed", error=True)
            logger.info("shell run done pid=%s exit=%s", proc.pid, code)
            if code == 255:  # ssh itself failed (auth, connection), not the remote command
                return _result("ssh could not reach the restricted shell: " + err.decode(errors="replace")[:500], error=True)
            return _result(
                f"exit_code: {code}\n--- stdout{' (truncated)' if out_cut else ''} ---\n{out.decode(errors='replace')}"
                f"\n--- stderr{' (truncated)' if err_cut else ''} ---\n{err.decode(errors='replace')}"
            )
        finally:
            try:
                os.unlink(key_path)
            except OSError:
                pass


def _result(text: str, error: bool = False) -> types.CallToolResult:
    return types.CallToolResult(content=[types.TextContent(type="text", text=text)], isError=error)


def build_shell(secret: str, **kwargs: Any) -> StreamableHTTPSessionManager:
    runner = SshRunner(secret, **kwargs)
    server = Server(name="remote-gateway-shell", version="1.0")

    @server.list_tools()
    async def list_tools() -> list[types.Tool]:
        return [TOOL]

    @server.call_tool(validate_input=True)
    async def call_tool(name: str, arguments: dict[str, Any]) -> types.CallToolResult:
        if name != TOOL_NAME:
            raise ValueError(f"unknown tool: {name}")
        return await runner.run(arguments["command"], int(arguments.get("timeout_seconds", DEFAULT_TIMEOUT)))

    return _manager(server)

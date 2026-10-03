#!/usr/bin/python3
"""Least-privilege host broker for the chroot's nlm-v2 command."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import socketserver
import struct
import subprocess
import tempfile
from typing import Any, Dict, List, Sequence, Tuple


SOCKET_PATH = Path("/run/claude-nlm/nlm-v2.sock")
NLM_EXECUTABLE = Path(
    "/home/centos/.local/share/uv/tools/notebooklm-mcp-cli-v2/bin/nlm-v2"
)
CLIENT_PROJECT_ROOT = Path("/workspace/projects")
HOST_PROJECT_ROOT = Path("/home/centos/data/projects")
STATE_ROOT = Path("/home/centos/.notebooklm-mcp-cli")
MAX_REQUEST_BYTES = 64 * 1024
MAX_OUTPUT_BYTES = 16 * 1024 * 1024
COMMAND_TIMEOUT_SECONDS = 30 * 60

# These commands can modify authentication, host-side CLI configuration,
# sharing, exports, or installed software.  Reject the words at every command
# depth so forms such as ``notebook delete`` also fail closed.
DENIED_COMMAND_WORDS = frozenset(
    {
        "config",
        "configure",
        "delete",
        "doctor",
        "export",
        "install",
        "login",
        "set",
        "setup",
        "share",
        "skill",
        "sync",
        "uninstall",
        "update",
    }
)
DENIED_OPTIONS = frozenset({"--debug", "--install-completion", "--show-completion"})
ALLOWED_TOP_LEVEL = frozenset(
    {
        "add",
        "audio",
        "batch",
        "chats",
        "chat",
        "content",
        "create",
        "cross",
        "data-table",
        "describe",
        "download",
        "flashcards",
        "get",
        "infographic",
        "label",
        "list",
        "mindmap",
        "note",
        "notebook",
        "pipeline",
        "query",
        "quiz",
        "rename",
        "report",
        "research",
        "show",
        "slides",
        "source",
        "stale",
        "status",
        "studio",
        "tag",
        "video",
    }
)
PATH_OPTIONS = frozenset(
    {"--directory", "--dir", "--file", "--input", "--output", "--output-dir", "--path"}
)


class RequestError(ValueError):
    """An untrusted client request failed validation."""


def _read_exact(stream: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise EOFError("connection closed before message completed")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def recv_message(stream: socket.socket, limit: int) -> Dict[str, Any]:
    length = struct.unpack("!I", _read_exact(stream, 4))[0]
    if length > limit:
        raise RequestError("message is too large")
    value = json.loads(_read_exact(stream, length).decode("utf-8"))
    if not isinstance(value, dict):
        raise RequestError("message must be a JSON object")
    return value


def send_message(stream: socket.socket, value: Dict[str, Any]) -> None:
    payload = json.dumps(value, separators=(",", ":")).encode("utf-8")
    stream.sendall(struct.pack("!I", len(payload)) + payload)


def map_client_path(value: str) -> str:
    """Map the only exposed absolute tree; reject all other local paths."""
    if value == str(CLIENT_PROJECT_ROOT):
        return str(HOST_PROJECT_ROOT)
    client_prefix = str(CLIENT_PROJECT_ROOT) + "/"
    if value.startswith(client_prefix):
        relative = value[len(client_prefix) :]
        candidate = (HOST_PROJECT_ROOT / relative).resolve(strict=False)
        try:
            candidate.relative_to(HOST_PROJECT_ROOT)
        except ValueError as exc:
            raise RequestError("path escapes /workspace/projects") from exc
        return str(candidate)
    if value.startswith("/"):
        raise RequestError("absolute paths must stay under /workspace/projects")
    return value


def map_argument(argument: str) -> str:
    if "\x00" in argument:
        raise RequestError("arguments cannot contain NUL bytes")
    if "=" in argument:
        name, value = argument.split("=", 1)
        if value.startswith("/"):
            return name + "=" + map_client_path(value)
    return map_client_path(argument)


def map_path_argument(value: str, mapped_cwd: str) -> str:
    """Resolve CLI file options and prove they remain inside projects."""
    if value == "~" or value.startswith("~/"):
        raise RequestError("home-relative paths are not exposed")
    if value.startswith("/"):
        return map_client_path(value)
    candidate = (Path(mapped_cwd) / value).resolve(strict=False)
    try:
        candidate.relative_to(HOST_PROJECT_ROOT)
    except ValueError as exc:
        raise RequestError("file paths must stay under /workspace/projects") from exc
    return str(candidate)


def map_arguments(args: Sequence[str], mapped_cwd: str) -> List[str]:
    mapped = []
    expect_path = False
    for argument in args:
        if expect_path:
            mapped.append(map_path_argument(argument, mapped_cwd))
            expect_path = False
            continue
        option, separator, value = argument.partition("=")
        if option in PATH_OPTIONS:
            if separator:
                mapped.append(option + "=" + map_path_argument(value, mapped_cwd))
            else:
                mapped.append(argument)
                expect_path = True
            continue
        mapped.append(map_argument(argument))
    if expect_path:
        raise RequestError("a file option is missing its path")
    return mapped


def validate_request(request: Dict[str, Any]) -> Tuple[List[str], str]:
    if set(request) != {"version", "args", "cwd"} or request["version"] != 1:
        raise RequestError("unsupported request shape or protocol version")
    args = request["args"]
    cwd = request["cwd"]
    if not isinstance(args, list) or not all(isinstance(arg, str) for arg in args):
        raise RequestError("args must be a list of strings")
    if len(args) > 256 or any(len(arg.encode("utf-8")) > 16 * 1024 for arg in args):
        raise RequestError("too many or oversized arguments")
    if not isinstance(cwd, str):
        raise RequestError("cwd must be a string")

    for argument in args:
        if argument in DENIED_OPTIONS or argument.split("=", 1)[0] in DENIED_OPTIONS:
            raise RequestError("that diagnostic option is not exposed")
        if not argument.startswith("-") and argument.casefold() in DENIED_COMMAND_WORDS:
            raise RequestError("that nlm-v2 operation is not exposed")

    command = next((arg for arg in args if not arg.startswith("-")), None)
    if command is not None and command not in ALLOWED_TOP_LEVEL:
        raise RequestError("unknown or unexposed nlm-v2 command")

    mapped_cwd = map_client_path(cwd)
    mapped_args = map_arguments(args, mapped_cwd)
    return mapped_args, mapped_cwd


def _safe_environment() -> Dict[str, str]:
    return {
        "HOME": "/home/centos",
        "LOGNAME": "centos",
        "USER": "centos",
        "LANG": "C.UTF-8",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "NOTEBOOKLM_MCP_CLI_PATH": str(STATE_ROOT),
        "XDG_CACHE_HOME": "/tmp/claude-nlm-cache",
    }


def run_cli(args: Sequence[str], cwd: str) -> Tuple[int, bytes, bytes]:
    """Execute without a shell and capture a bounded response."""
    with tempfile.TemporaryFile() as stdout_file, tempfile.TemporaryFile() as stderr_file:
        try:
            completed = subprocess.run(
                [str(NLM_EXECUTABLE), *args],
                cwd=cwd,
                env=_safe_environment(),
                stdin=subprocess.DEVNULL,
                stdout=stdout_file,
                stderr=stderr_file,
                timeout=COMMAND_TIMEOUT_SECONDS,
                check=False,
            )
            exit_code = completed.returncode
        except subprocess.TimeoutExpired:
            exit_code = 124
            stderr_file.write(b"nlm-v2: command exceeded the 30-minute bridge limit\n")
        stdout_file.seek(0)
        stderr_file.seek(0)
        stdout = stdout_file.read(MAX_OUTPUT_BYTES + 1)
        stderr = stderr_file.read(MAX_OUTPUT_BYTES + 1)
    if len(stdout) > MAX_OUTPUT_BYTES or len(stderr) > MAX_OUTPUT_BYTES:
        return 125, b"", b"nlm-v2: output exceeded the 16-MiB bridge limit\n"
    # Do not disclose the host-side home path in diagnostics.
    return exit_code, stdout.replace(b"/home/centos", b"<host-home>"), stderr.replace(
        b"/home/centos", b"<host-home>"
    )


def handle_request(request: Dict[str, Any]) -> Dict[str, Any]:
    try:
        args, cwd = validate_request(request)
        exit_code, stdout, stderr = run_cli(args, cwd)
    except RequestError as exc:
        return {
            "exit_code": 126,
            "stdout_b64": "",
            "stderr_b64": base64.b64encode((f"nlm-v2: {exc}\n").encode()).decode(),
        }
    except Exception:
        return {
            "exit_code": 125,
            "stdout_b64": "",
            "stderr_b64": base64.b64encode(b"nlm-v2: broker execution failed\n").decode(),
        }
    return {
        "exit_code": exit_code,
        "stdout_b64": base64.b64encode(stdout).decode("ascii"),
        "stderr_b64": base64.b64encode(stderr).decode("ascii"),
    }


class NlmRequestHandler(socketserver.BaseRequestHandler):
    def handle(self) -> None:
        try:
            request = recv_message(self.request, MAX_REQUEST_BYTES)
            response = handle_request(request)
            send_message(self.request, response)
        except Exception:
            # Protocol errors close only this local connection.  No traceback or
            # host detail is returned across the trust boundary.
            return


class NlmUnixServer(socketserver.UnixStreamServer):
    allow_reuse_address = True


def systemd_activated_server() -> NlmUnixServer | None:
    """Adopt the single AF_UNIX listener passed by systemd, if present."""
    try:
        listen_pid = int(os.environ.get("LISTEN_PID", "0"))
        listen_fds = int(os.environ.get("LISTEN_FDS", "0"))
    except ValueError:
        return None
    if listen_pid != os.getpid() or listen_fds != 1:
        return None
    server = NlmUnixServer(str(SOCKET_PATH), NlmRequestHandler, bind_and_activate=False)
    server.socket.close()
    server.socket = socket.socket(fileno=3)
    server.server_address = str(SOCKET_PATH)
    return server


def main() -> int:
    activated = systemd_activated_server()
    if activated is not None:
        server = activated
    else:
        SOCKET_PATH.parent.mkdir(mode=0o750, parents=True, exist_ok=True)
        SOCKET_PATH.unlink(missing_ok=True)
        server = NlmUnixServer(str(SOCKET_PATH), NlmRequestHandler)
        os.chmod(SOCKET_PATH, 0o660)
    with server:
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/python3
"""Chroot-side client for the restricted host nlm-v2 broker."""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
import socket
import struct
import sys


SOCKET_PATH = Path("/run/claude-nlm/nlm-v2.sock")
MAX_RESPONSE_BYTES = 24 * 1024 * 1024


def read_exact(stream: socket.socket, size: int) -> bytes:
    chunks = []
    remaining = size
    while remaining:
        chunk = stream.recv(remaining)
        if not chunk:
            raise RuntimeError("broker closed the connection")
        chunks.append(chunk)
        remaining -= len(chunk)
    return b"".join(chunks)


def main() -> int:
    request = json.dumps(
        {"version": 1, "args": sys.argv[1:], "cwd": os.getcwd()},
        separators=(",", ":"),
    ).encode("utf-8")
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as stream:
            stream.connect(str(SOCKET_PATH))
            stream.sendall(struct.pack("!I", len(request)) + request)
            response_size = struct.unpack("!I", read_exact(stream, 4))[0]
            if response_size > MAX_RESPONSE_BYTES:
                raise RuntimeError("broker response is too large")
            response = json.loads(read_exact(stream, response_size).decode("utf-8"))
        stdout = base64.b64decode(response["stdout_b64"], validate=True)
        stderr = base64.b64decode(response["stderr_b64"], validate=True)
        sys.stdout.buffer.write(stdout)
        sys.stderr.buffer.write(stderr)
        return int(response["exit_code"])
    except Exception:
        print("nlm-v2: restricted local broker is unavailable", file=sys.stderr)
        return 125


if __name__ == "__main__":
    raise SystemExit(main())

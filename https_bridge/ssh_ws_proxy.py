#!/usr/bin/env python3
"""OpenSSH ProxyCommand: relay stdin/stdout through the authenticated SSH WebSocket."""

from __future__ import annotations

import argparse
import os
import threading

from websockets.sync.client import connect


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    token = os.environ.get("REMOTE_GATEWAY_SSH_TOKEN")
    if not token:
        raise SystemExit("REMOTE_GATEWAY_SSH_TOKEN is required")

    with connect(args.url, additional_headers={"Cookie": f"remote_gateway_ssh={token}"}, max_size=None) as websocket:
        def stdin_to_websocket() -> None:
            while data := os.read(0, 65536):
                websocket.send(data)

        sender = threading.Thread(target=stdin_to_websocket, daemon=True)
        sender.start()
        for data in websocket:
            if not isinstance(data, bytes):
                raise RuntimeError("SSH bridge returned a non-binary WebSocket frame")
            os.write(1, data)


if __name__ == "__main__":
    main()

"""Two-hour signed cookies for the SSH-over-WebSocket transport."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import time

DEFAULT_TTL_SECONDS = 2 * 60 * 60


def _b64(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _unb64(value: str) -> bytes:
    return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))


def issue_ssh_session(secret: str, *, now: float | None = None, ttl_seconds: int = DEFAULT_TTL_SECONDS) -> str:
    if not secret or not 1 <= ttl_seconds <= DEFAULT_TTL_SECONDS:
        raise ValueError(f"a signing secret and a TTL from 1 to {DEFAULT_TTL_SECONDS} seconds are required")
    issued = int(time.time() if now is None else now)
    body = _b64(json.dumps({"aud": "ssh", "exp": issued + ttl_seconds, "v": 1}, separators=(",", ":")).encode())
    signature = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    return f"{body}.{signature}"


def verify_ssh_session(value: str | None, secret: str, *, now: float | None = None) -> float | None:
    if not value or not secret:
        return None
    body, dot, signature = value.partition(".")
    if not dot or not body or not signature:
        return None
    expected = _b64(hmac.new(secret.encode(), body.encode(), hashlib.sha256).digest())
    if not hmac.compare_digest(signature, expected):
        return None
    try:
        claims = json.loads(_unb64(body))
        expiry = int(claims["exp"])
    except (KeyError, TypeError, ValueError, json.JSONDecodeError):
        return None
    current = time.time() if now is None else now
    if claims.get("v") != 1 or claims.get("aud") != "ssh" or expiry <= current:
        return None
    return float(expiry)


def main() -> None:
    print(issue_ssh_session(os.environ.get("REMOTE_GATEWAY_TOKEN", "")))


if __name__ == "__main__":
    main()

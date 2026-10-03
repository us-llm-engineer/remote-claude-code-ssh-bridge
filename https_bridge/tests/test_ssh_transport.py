import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT))

from gateway.server import build_gateway
from gateway.session import issue_ssh_session, verify_ssh_session


def test_two_hour_cookie_authenticates_only_before_expiry():
    token = issue_ssh_session("signing-key", now=1_000, ttl_seconds=7_200)
    assert verify_ssh_session(token, "signing-key", now=8_199) == 8_200
    assert verify_ssh_session(token, "signing-key", now=8_200) is None


def test_modified_or_wrong_secret_cookie_is_rejected():
    token = issue_ssh_session("signing-key", now=1_000)
    assert verify_ssh_session(token + "x", "signing-key", now=1_001) is None
    assert verify_ssh_session(token, "other-key", now=1_001) is None


def test_cookie_cannot_be_minted_for_more_than_two_hours():
    with pytest.raises(ValueError):
        issue_ssh_session("signing-key", ttl_seconds=7_201)


def test_gateway_exposes_only_reviewed_mcp_aliases_plus_auth_and_ssh():
    paths = {route.path for route in build_gateway("signing-key").routes}
    assert {"/healthz", "/ssh-client.py", "/ssh", "/authorize", "/token", "/register"} <= paths
    assert {
        "/colab-proxy-mcp/mcp", "/modal-gpu/mcp", "/scopus-mcp/mcp",
        "/huggingface/mcp", "/data-host-mcp/mcp", "/all/mcp",
        "/game-market/mcp", "/local-folder-stream/mcp", "/playwright/mcp",
    } <= paths
    assert "/{source}/mcp" not in paths
    assert "/messaging-watcher/mcp" not in paths and "/codex-opencode-bridge/mcp" not in paths

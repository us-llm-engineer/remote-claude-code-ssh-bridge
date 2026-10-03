#!/usr/local/bin/python3
"""Forced SSH command gate for the jailed Claude shell."""

from __future__ import annotations

import os
import sys

SUDO = "/usr/bin/sudo"
RUNNER = "/usr/local/libexec/claude-shell-runner"
GIT_PUSH_BROKER = "/usr/local/libexec/claude-git-push-broker"


def main() -> int:
    # The original command is intentionally opaque here. It is interpreted only
    # by bash *inside* the mount namespace created by the root-owned runner.
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    # A distinct, exact command grammar is handled before entering the chroot.
    # The broker permits only a locally approved commit-to-branch push and
    # never returns its GitHub App token to the SSH caller.
    if command.startswith("push "):
        os.execv(SUDO, [SUDO, "-n", GIT_PUSH_BROKER, "--request", command])
    os.execv(SUDO, [SUDO, "-n", RUNNER, command])
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/local/bin/python3
"""Forced command gate for an approval-bound Git push request."""
import os

os.execv("/usr/bin/sudo", ["sudo", "-n", "/usr/local/libexec/claude-git-push-broker", "--request", os.environ.get("SSH_ORIGINAL_COMMAND", "")])

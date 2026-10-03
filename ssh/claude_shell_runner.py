#!/usr/local/bin/python3
"""Enter the root-prepared Claude chroot, then drop to the restricted UID."""

from __future__ import annotations

import os
import pwd
import sys

CHROOT = "/srv/claude-shell-root"
SHELL_USER = "claude-shell"


def make_standard_fds_reopenable(identity: pwd.struct_passwd) -> None:
    """Let the jailed UID reopen its own inherited stdin/stdout/stderr via /dev/fd."""
    for descriptor in (0, 1, 2):
        try:
            os.fchown(descriptor, identity.pw_uid, identity.pw_gid)
        except OSError:
            # A descriptor can be a socket or another endpoint that does not
            # support ownership changes. It remains usable through its open FD.
            pass


def main() -> int:
    if os.geteuid() != 0 or len(sys.argv) != 2:
        print("claude-shell: invalid invocation", file=sys.stderr)
        return 126
    identity = pwd.getpwnam(SHELL_USER)
    os.chroot(CHROOT)
    os.chdir("/workspace/projects")
    os.setgroups([])
    make_standard_fds_reopenable(identity)
    os.setgid(identity.pw_gid)
    os.setuid(identity.pw_uid)
    environment = {
        "HOME": "/workspace/projects", "USER": SHELL_USER, "LOGNAME": SHELL_USER,
        "PATH": "/opt/bridge-tools/bin:/opt/tools/bin:/opt/cuda/bin:/usr/lib/wsl/lib:/usr/local/bin:/usr/bin:/bin",
        "PYTHONPATH": "/opt/python-site", "PYTHONUSERBASE": "/opt/pyuser", "CMAKE_PREFIX_PATH": "/opt/vcpkg",
        "VCPKG_ROOT": "/opt/vcpkg", "LD_LIBRARY_PATH": "/usr/lib/wsl/lib", "TMPDIR": "/tmp",
        "LANG": "C.UTF-8",
    }
    command = sys.argv[1]
    if command:
        os.execve("/bin/bash", ["/bin/bash", "-lc", command], environment)
    os.execve("/bin/bash", ["/bin/bash", "-l"], environment)
    return 127


if __name__ == "__main__":
    raise SystemExit(main())

# Restricted local SSH service

The dedicated daemon listens only at `127.0.0.1:2223`. It is reached solely
through the HTTPS/WebSocket bridge; do not add router port forwarding.

| Identity | Access |
|---|---|
| `claude-shell` | Bash in a chroot: projects read/write, skills and agents read-only |
| `claude-sync` | SFTP only: projects read/write; skills and agents read-only |
| `claude-mcp` | `mcp <allowlisted-alias>` stdio only |

The shell also provides `nlm-v2` through a local Unix-socket broker. The broker
runs the host-managed CLI but exposes neither `/home/centos` nor its NotebookLM
authentication files. Authentication/configuration, sharing/export, deletion,
software installation, debug output, and paths outside `/workspace/projects`
are rejected. The legacy `nlm` command is not exposed. Systemd owns the stable
Unix socket and starts the broker on demand, so a broker restart cannot strand
the chroot on an empty runtime directory.

`claude-shell` starts from `/workspace/projects`. Its root filesystem contains
only minimal runtime binaries plus `/workspace/projects`, `/workspace/skills`,
and `/workspace/agents`. It cannot access `/home/centos`, host SSH keys, or a
normal host shell. Port forwarding, agent forwarding, X11, and tunnels are
disabled for every restricted identity.

`remote-gateway-test` mints the temporary key used by `claude-shell`,
`claude-sync`, and `claude-playwright`, together with its two-hour WebSocket
session token. The signed WebSocket cookie closes the SSH connection at expiry;
the SSH daemon has no public listener. SFTP transfers binary files directly, so
a Cloud Linux container can pull images from `/projects`, `/skills`, or
`/agents`, and can upload only under `/projects`.

`remote-gateway-sync` hot-deploys reviewed helper updates into a running bridge.
It does not restart Cloudflare or SSH, rotate/read credentials, change the URL,
or rerun the complete mount provisioner. Existing shell sessions remain alive.
Because SSH has a private mount namespace, sync adds the NLM socket's exact
read-only bind there when needed; it does not expose any additional host path.

Local MCP servers are normal stdio servers. `claude-mcp` may launch only the
root-reviewed aliases from `/etc/claude-remote/mcp-allowlist.json`.

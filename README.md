# remote-claude-code-ssh-bridge

A small, security-focused bridge that lets a **Claude Code cloud session** (the
sandboxed VM you get at claude.ai/code) use **your own computer**: run commands in a
locked-down shell, and call the MCP servers you already run locally (browser, GPU
sandboxes, notebooks, search, files).

It does this without opening a router port, without giving the cloud VM a private key,
and without the cloud agent ever building a tunnel itself. Everything the cloud agent
sees arrives as **two ordinary MCP connectors**:

| Connector (suggested name) | URL | What the cloud agent gets |
|---|---|---|
| `local-ssh` | `https://<tunnel-host>/shell/mcp/` | One tool, `ssh_run`: run a shell command in a chroot jail on your machine |
| `local-mcp` | `https://<tunnel-host>/all/mcp/` | Every MCP server you allow-listed, merged into one tool list (`<server>__<tool>`) |

The rest of this document explains why it is built this way, how every piece works,
and how to clone, install and use it. If you only want to get going, jump to
[Quick start](#quick-start).

---

## Contents

1. [Why this exists](#why-this-exists)
2. [Architecture at a glance](#architecture-at-a-glance)
3. [How it works, piece by piece](#how-it-works-piece-by-piece)
4. [Repository layout](#repository-layout)
5. [Requirements](#requirements)
6. [Quick start](#quick-start)
7. [Configure Claude: allowed domains and the two connectors](#configure-claude-allowed-domains-and-the-two-connectors)
8. [Script reference](#script-reference)
9. [Day-to-day operation](#day-to-day-operation)
10. [Configuration reference](#configuration-reference)
11. [Security model](#security-model)
12. [Tests](#tests)
13. [Troubleshooting](#troubleshooting)
14. [Limitations and honest caveats](#limitations-and-honest-caveats)
15. [License](#license)

---

## Why this exists

A cloud session runs on a remote VM. Your useful tools (a logged-in browser, a GPU, a
Colab tab, local notebooks, project files) live on your own machine. Three obstacles
stand in the way:

1. **Reachability.** Your computer is behind NAT. You do not want to forward a port.
2. **Trust.** Handing a cloud VM an SSH key, a shell on your real account, or your
   service logins is a bad idea. Whatever it gets must be narrow and short-lived.
3. **The cloud session's own permission check.** In auto mode a second model reviews
   each tool call and blocks things that look like opening a tunnel, decoding a private
   key, or reaching a host by a non-direct route. A hand-built SSH tunnel from the VM
   trips exactly those rules.

The design answer is to keep every sensitive step **on your machine** and give the cloud
agent only **native MCP connector tools**:

* A Cloudflare *quick tunnel* publishes a single loopback web service (the *gateway*).
  No inbound port, no account, no domain.
* The gateway authenticates every request (OAuth 2.1 for the connectors, a signed token
  for the older WebSocket path).
* For the shell, the **gateway makes the SSH connection itself**, over loopback, to a
  dedicated, unprivileged account whose login is forced into a chroot jail. The cloud
  agent never sees the key, the token or a tunnel.
* For MCP servers, the gateway starts your already-installed stdio servers from a
  **root-owned allowlist** and re-exposes them over Streamable HTTP.

Credentials of services you are logged in to (GitHub, NotebookLM, Hugging Face, Google,
Modal) never enter the jail or the cloud VM; where a cloud agent needs them, a small
broker on your machine performs the single approved action.

---

## Architecture at a glance

```text
 Claude Code cloud session (Anthropic VM)
        │  native tools:  mcp__local-ssh__ssh_run     mcp__local-mcp__<server>__<tool>
        ▼
 Anthropic connector proxy ──── HTTPS ────►  https://<random>.trycloudflare.com
                                                    │   (Cloudflare quick tunnel)
                                                    ▼
                                      cloudflared (host)  ──►  127.0.0.1:8798
                                                                  │
                          ┌───────────────────────────────────────┴──────────────────────────────┐
                          │  gateway/  (Starlette app, one process)                              │
                          │                                                                      │
                          │  /.well-known/*  /register  /authorize  /token     OAuth 2.1 server  │
                          │  /shell/mcp/   ──► shell_mcp.py   (ssh_run)                          │
                          │  /all/mcp/     ──► mcp_proxy.py   (aggregate of every allowlisted MCP)
                          │  /<alias>/mcp/ ──► mcp_proxy.py   (one MCP per route)                │
                          │  /ssh          ──► WebSocket ⇄ TCP relay to sshd (legacy path)       │
                          │  /healthz  /ssh-client.py  /oauth/upstream-callback                  │
                          └───────┬──────────────────────────────┬───────────────────────────────┘
                                  │ ssh over loopback            │ stdio children / HTTP upstreams
                                  ▼                              ▼
              sshd on 127.0.0.1:2223 (dedicated)        your MCP servers (allowlist)
                  │ ForceCommand                         e.g. browser, Colab, Modal, Scopus …
                  ▼
        claude-shell-launch ─► sudo claude-shell-runner ─► chroot /srv/claude-shell-root
                  │                                         setuid claude-shell, bash -lc "<cmd>"
                  └─ "push …" ─► sudo git-push-broker (one-shot, locally approved)
```

Two things never leave your machine: the SSH private key for the current session
(`~/.remote-gateway/ssh-session/current.env`, mode 0600) and the gateway signing secret
(`~/.remote-gateway/secrets.env`, mode 0600).

---

## How it works, piece by piece

### 1. The tunnel and the process supervisor

`https_bridge/start.sh --foreground` is the `ExecStart` of the systemd unit
`remote-claude-bridge.service`. It:

1. loads `REMOTE_GATEWAY_TOKEN` (the signing secret) from `~/.remote-gateway/secrets.env`;
2. starts the gateway: `python3 gateway/server.py` bound to `127.0.0.1:8798`;
3. starts `cloudflared tunnel --url http://127.0.0.1:8798` and scrapes the random
   `https://….trycloudflare.com` hostname from its log into `~/.remote-gateway/https-bridge/url.txt`;
4. writes its own PID to `reload-capable.pid` and traps **SIGHUP**: on HUP it restarts
   *only the gateway child*, keeping `cloudflared` (and therefore the public URL) alive.
   This is how new gateway code goes live with no URL change.

`start.sh` (top level) is the user-facing wrapper: it installs the unit if missing,
reuses a healthy tunnel (local and public `/healthz` both answer), or restarts the unit
and waits up to 120 s for a *verified* public endpoint.

A quick tunnel gets a **new random hostname every time the tunnel (not just the gateway)
restarts**. Whenever that happens you edit the two connector URLs (see
[Troubleshooting](#troubleshooting)).

### 2. The gateway (`gateway/`)

One Starlette application, built by `gateway/server.py:build_gateway()`. See
[`gateway/README.md`](gateway/README.md) for a module-by-module walkthrough. Routes:

| Route | Auth | Purpose |
|---|---|---|
| `GET /healthz` | none | Liveness: status, transport name, allowlisted aliases, aggregate and shell paths |
| `/.well-known/oauth-protected-resource[/…]`, `/.well-known/oauth-authorization-server[/…]`, `/.well-known/openid-configuration` | none | OAuth discovery for connector clients |
| `POST /register` | none (inert) | RFC 7591 dynamic client registration; grants nothing by itself |
| `GET/POST /authorize` | consent form needs the current session token | Issues an authorization code (PKCE S256 required) |
| `POST /token` | PKCE / refresh token | Issues route-bound access and refresh tokens |
| `/<alias>/mcp/` | bearer | One allowlisted MCP server, Streamable HTTP |
| `/all/mcp/` | bearer bound to `all` | All allowlisted MCP servers merged into one list |
| `/shell/mcp/` | bearer bound to `shell` | The `ssh_run` tool |
| `WS /ssh` | signed cookie | Relays raw bytes to the local sshd (legacy fallback) |
| `GET /ssh-client.py` | none | Serves `https_bridge/ssh_ws_proxy.py` for the legacy path |
| `GET /oauth/upstream-callback` | single-use `state` | Finishes a sign-in the gateway started *to an upstream MCP* |

Every MCP mount is wrapped in `AuthenticatedMCP`, which accepts exactly two credentials:
a *directly presented* signed session token, or an OAuth access token whose recorded
resource equals that route's alias. A token for `playwright` cannot open `/all`, a token
for `all` cannot open `/shell`, and so on. Missing or invalid credentials get
`401` with a `WWW-Authenticate` header that points clients at the discovery document.

### 3. Authentication in detail

* **Signing secret.** `REMOTE_GATEWAY_TOKEN` is never accepted from anyone; it only signs
  and verifies short-lived tokens (HMAC-SHA256).
* **Session token ("bundle token").** `gateway/session.py` issues
  `base64url({"aud":"ssh","exp":…,"v":1}).base64url(HMAC)`. Maximum lifetime: **two hours**
  (`DEFAULT_TTL_SECONDS`). `remote-gateway-test` mints one together with a fresh ed25519
  SSH key and stores both in `current.env`.
* **OAuth 2.1 (`gateway/oauth.py`).** Implements discovery, dynamic client registration,
  authorization code with **mandatory PKCE S256**, exact `redirect_uri` match, and refresh.
  Redirect URIs are restricted to `https://claude.ai`, `https://claude.com` and loopback
  `http`. The consent page issues a code only if the human pastes a *currently valid*
  session token. Failed consents are rate-limited (5 per IP and 30 total per 10 minutes).
  Access tokens last 2 hours; refresh grants last 30 days (24 hours for the shell route).
  Only SHA-256 hashes of tokens are written to `~/.remote-gateway/oauth-state.json`.
* **Why the long refresh grant is safe enough.** A connector is account-level, so a long
  grant means you do not re-authorize for every new cloud session. Reading state or
  running commands is still gated: the shell tool also needs a *valid two-hour bundle*
  on your disk, so a stale grant cannot run anything.

### 4. MCP re-exposure (`gateway/mcp_proxy.py`)

`/etc/claude-remote/mcp-allowlist.json` (root-owned) lists the servers. Each entry is
either a **stdio server** (`command` absolute path, `args`, optional `cwd` that must stay
under the projects folder) or an **HTTP upstream** (`{"url": …}`, https or loopback http).
Callers can never choose a command, path, environment or new alias.

`LocalStdioUpstream` owns one long-lived child per alias, started lazily on first use and
restarted on next use if it died. The child gets a minimal environment (`HOME`, `USER`,
`LOGNAME`, a fixed `PATH`, `LANG`) and no gateway secrets. For HTTP upstreams the gateway
acts as an OAuth *client* (`gateway/upstream_auth.py`), storing tokens in
`~/.remote-gateway/upstream-oauth/` with mode 0600.

`/all/mcp/` is built by `build_aggregate()`:

* tool names become `<alias>__<tool>`; names that would exceed the client's 64-character
  tool-name limit are shortened with a stable 8-hex hash (`public_tool_name`);
* every alias's last good tool list is cached under `~/.remote-gateway/tool-cache/`, so an
  MCP that is down or signed-out stays *listed* and its calls return an explanation;
* one extra tool, `gateway__sign_in(alias)`, starts a sign-in to an HTTP upstream and
  returns a URL for the human to finish (PKCE verifier and tokens stay on your machine).

### 5. The shell connector (`gateway/shell_mcp.py`)

`ssh_run(command, timeout_seconds)` is a thin, careful wrapper around the local `ssh`
client:

1. read `current.env`; verify the token's signature and expiry (needs ≥ 10 s left);
2. write the key to a private temp file (mode 0600, removed in `finally`);
3. run `ssh -T -i <key> -o IdentitiesOnly=yes -o BatchMode=yes -o StrictHostKeyChecking=accept-new -p 2223 claude-shell@127.0.0.1 <command>`
   with the command as **one argv element** (never interpolated into a local shell);
4. keep at most 64 KB of stdout and 64 KB of stderr (it keeps draining so the child never
   blocks), kill the process group on timeout, allow 4 concurrent calls;
5. return `exit_code`, stdout and stderr. SSH's own failure (exit 255) is reported as a
   tool error, distinct from the remote command's exit status.

### 6. The jail (`ssh/`)

A **dedicated sshd** (`/etc/claude-remote/sshd_config`) listens only on `127.0.0.1:2223`,
public-key only, no forwarding of any kind. Four accounts, each with a forced command:

| Account | Forced command | Can do |
|---|---|---|
| `claude-shell` | `claude-shell-launch` | Run bash inside the chroot jail |
| `claude-sync` | `internal-sftp` (chrooted) | SFTP: projects read/write, skills and agents read-only |
| `claude-mcp` | `claude-mcp-launch` | Start exactly `mcp <allowlisted-alias>` over stdio |
| `claude-playwright` | `claude-playwright-launch` | Start only the reviewed browser MCP |

For `claude-shell`, `claude_shell_launcher.py` treats the original command as opaque. If it
starts with `push ` it goes to the Git push broker; everything else goes to
`sudo claude-shell-runner <command>`. The runner (root, via a single sudoers rule) does
`chroot /srv/claude-shell-root`, `chdir /workspace/projects`, drops all groups, `setgid`,
`setuid` to `claude-shell`, then `exec bash -lc <command>` with a fixed environment
(`HOME=/workspace/projects`, a fixed `PATH`, `PYTHONUSERBASE`, `CMAKE_PREFIX_PATH`, …).

The chroot is assembled at boot by `claude_shell_mounts.sh` (unit
`claude-shell-sandbox.service`) from bind mounts:

| Path in the jail | Source on the host | Mode |
|---|---|---|
| `/usr`, `/bin`, `/lib`, `/lib64` | same paths | read-only |
| `/workspace/projects` | `~/data/projects` | **read-write** |
| `/workspace/skills`, `/workspace/agents` | `~/.claude/skills`, `~/.claude/agents` | read-only |
| `/opt/tools/bin` | `~/.local/bin` | read-only |
| `/opt/cuda`, `/opt/nvidia/nsight-compute` | CUDA toolkit, Nsight Compute | read-only |
| `/opt/pyuser/lib/python3.12/site-packages` | `~/.local/lib/python3.12/site-packages` | read-only |
| `/opt/vcpkg`, `/opt/python-site/cmake` | vcpkg install tree, CMake's Python package | read-only |
| `/dev/null`, `zero`, `random`, `urandom`, `dxg` | host devices (`dxg` = WSL GPU) | read-write |
| `/tmp` | private 4 GB tmpfs | read-write |
| `/etc/resolv.conf`, CA bundles | host files | read-only |
| `/run/claude-nlm` | NotebookLM broker socket | read-only |

Everything else (the rest of your home folder, SSH keys, credentials, shell history,
`~/.claude`) is simply absent.

### 7. Brokers: doing one thing for the jail without giving it the secret

* **NotebookLM (`claude_nlm_broker.py` / `claude_nlm_client.py`).** `nlm-v2` inside the
  jail is a tiny client that sends the arguments over a Unix socket to a systemd-managed
  broker running as you. The broker validates the command against an allow list (no
  `login`, `config`, `share`, `export`, `delete`, `install`, …), maps `/workspace/projects`
  paths to host paths and rejects any other absolute path, caps request and output sizes,
  and runs the real CLI. Your NotebookLM login is never visible to the jail.
* **Git push (`claude_git_push_broker.py`).** The jail has no GitHub credential. To push,
  *you* run `remote-gateway-git-authorize REPO COMMIT_SHA BRANCH` on your machine; the
  broker verifies the repository (exactly one `origin` under your projects folder matching
  `https://github.com/<owner>/<repo>.git`) and commit, then prints a single-use,
  10-minute approval nonce. The agent runs `push REPO COMMIT_SHA BRANCH NONCE` through the
  shell; the broker re-checks everything, consumes the nonce *before* touching the
  network, mints credentials (GitHub App installation token, or, if no App is configured,
  your `gh` login) inside the root process and pushes with hooks and config disabled.
  The token never reaches the jail.

### 8. The legacy SSH-over-WebSocket path

Before the shell connector existed, a client could reach the same sshd through
`WS /ssh` (cookie `remote_gateway_ssh` = the session token) using
`https_bridge/ssh_ws_proxy.py` as an OpenSSH `ProxyCommand`. It is kept as a fallback and
for SFTP. It requires the cloud side to hold the session token and key, which is exactly
what a cloud session's permission check tends to block, so **prefer the connectors**.

---

## Repository layout

```text
remote-claude-code-ssh-bridge/
├── README.md                    this file
├── requirements.txt             Python packages the gateway and tests need (pinned)
├── pyproject.toml               package metadata (web-server basics only)
├── start.sh                     user command: start/verify the bridge  (remote-gateway-start)
├── stop.sh                      user command: stop everything          (remote-gateway-stop)
├── start-test.sh                user command: validate + show/rotate the session bundle (remote-gateway-test)
├── sync.sh                      user command: hot-deploy changes       (remote-gateway-sync)
├── login.sh                     user command: sign the gateway in to an HTTP MCP (remote-gateway-mcp-login)
├── gateway/                     the public web application (see gateway/README.md)
│   ├── server.py                routes, auth wrapper, /ssh WebSocket relay, health
│   ├── oauth.py                 OAuth 2.1 authorization server (discovery, DCR, PKCE, refresh)
│   ├── session.py               signed two-hour session tokens
│   ├── mcp_proxy.py             allowlist loader, stdio/HTTP upstreams, per-alias and aggregate servers
│   ├── shell_mcp.py             the ssh_run tool
│   └── upstream_auth.py         OAuth *client* for HTTP upstreams + gateway__sign_in flows
├── https_bridge/                process supervision and the legacy client
│   ├── start.sh / stop.sh       systemd ExecStart/ExecStop: gateway + cloudflared
│   ├── install-service.sh       installs remote-claude-bridge.service
│   ├── systemd/                 the unit file
│   ├── ssh_ws_proxy.py          OpenSSH ProxyCommand for the legacy WebSocket path
│   ├── README.md                bridge-level notes
│   └── tests/                   gateway, OAuth, MCP proxy and shell-tool tests
├── ssh/                         the restricted SSH service and its helpers
│   ├── install.sh               one-time provisioning (accounts, ACLs, keys, units, sudoers)
│   ├── sshd_config              dedicated sshd (port 2223, loopback only)
│   ├── claude_shell_launcher.py / claude_shell_runner.py / claude_shell_mounts.sh    the jail
│   ├── claude_mcp_launcher.py / claude_mcp_runner.py / claude_playwright_*.py        MCP over SSH
│   ├── claude_nlm_broker.py / claude_nlm_client.py                                   NotebookLM broker
│   ├── claude_git_push_broker.py / claude-git-push-askpass / remote-gateway-git-authorize   push approval
│   ├── *.sudoers, *.gitconfig, *.tmpfiles.conf, git-push-policy.example.json         root-owned policy files
│   ├── mcp-allowlist.json       example allowlist (the author's servers: edit before installing)
│   ├── systemd/                 sshd, sandbox, broker and mount units
│   ├── README.md                notes on the SSH service
│   └── tests/                   launcher, runner and broker tests
└── tests/                       lifecycle-script tests
```

---

## Requirements

This was built and run on **CentOS Stream 9 under WSL2** (systemd enabled) with an NVIDIA
GPU exposed through WSL. Plain Linux with systemd should work as well; the GPU
mounts are guarded and skipped when the device is absent, but only WSL's `/dev/dxg` GPU
path is wired up.

| Need | Why |
|---|---|
| Linux with **systemd**, `sudo` without a password for the installing user | installs accounts, units, sudoers, mounts |
| `sshd` (OpenSSH server), `ssh`, `ssh-keygen` | the dedicated daemon and the client the gateway runs |
| `setfacl` (`acl` package), `visudo`, `flock`, `jq`, `curl`, `base64` | provisioning and the lifecycle scripts |
| **Python 3.12** at `/usr/local/bin/python3` | the scripts hard-code this interpreter |
| the packages in `requirements.txt` for that interpreter | `mcp`, `starlette`, `uvicorn`, `httpx`, `anyio`, `pytest`, `websockets` |
| [`cloudflared`](https://github.com/cloudflare/cloudflared/releases) at `~/.local/bin/cloudflared` | the quick tunnel (no Cloudflare account needed) |
| the MCP servers you want to expose, installed locally | whatever you put in the allowlist |

**Account and path names.** The code assumes the installing user is called `centos` and
lives in `/home/centos`. These values are literals in the sources (see
[Adapting the paths](#2-adapt-the-account-and-paths)). Plan one mechanical replacement
before installing.

---

## Quick start

> Read [Security model](#security-model) first. The install adds four system accounts,
> sudoers rules, mounts and a systemd service to your machine.

### 1. Clone

```bash
git clone https://github.com/us-llm-engineer/remote-claude-code-ssh-bridge.git
cd remote-claude-code-ssh-bridge
```

Keep the checkout in a stable place: the systemd unit and the scripts refer to its path.
The author keeps it at `~/.claude/mcp-servers/remote-gateway`; the examples below use
`$REPO` for wherever you cloned.

```bash
export REPO="$PWD"
```

### 2. Adapt the account and paths

The sources use the literals `centos` (user and group) and `/home/centos` (home). Replace
them with yours. Check what will change first:

```bash
grep -rIn '/home/centos\|centos' --exclude-dir=.git . | grep -v '^./README.md' | wc -l
```

Then apply it (example: user `alice`, home `/home/alice`; use your real values). Do the
home path first, then the bare account name:

```bash
NEWHOME=/home/alice; NEWUSER=alice
grep -rIl '/home/centos' . --exclude=README.md --exclude-dir=.git | xargs sed -i "s|/home/centos|$NEWHOME|g"
grep -rIl '\bcentos\b'  . --exclude=README.md --exclude-dir=.git | xargs sed -i "s/\bcentos\b/$NEWUSER/g"
git diff --stat      # review: only paths and the account name should change
```

(The account name appears as a user and group in the systemd unit, sudoers rules,
launchers, the broker units and the tests, which is why the second command runs over
everything.) After this, the test suite passes except the two host-specific tests
described under [Tests](#tests).

Two more places are host-specific by design:

* **The allowlist** `ssh/mcp-allowlist.json` lists the author's MCP servers. Replace its
  entries with your own (see [Choosing which MCP servers to expose](#choosing-which-mcp-servers-to-expose)).
* **Jail mounts** in `ssh/claude_shell_mounts.sh`. The GPU device, CUDA toolkit
  (`CUDA_ROOT`), Nsight Compute, the Python 3.12 packages (`PY312_SITE`) and the WSL driver
  folders are *skipped when missing*, so no GPU is fine. Three host directories are
  **required** to exist, otherwise the `claude-shell-sandbox` service fails at boot. If you
  do not use those toolchains, create them empty (or delete the matching lines):

  ```bash
  mkdir -p ~/.local/bin                                  # mounted read-only at /opt/tools/bin
  mkdir -p ~/vcpkg/installed/x64-linux                   # mounted read-only at /opt/vcpkg
  mkdir -p ~/.local/lib/python3.9/site-packages/cmake    # mounted read-only at /opt/python-site/cmake
  ```

### 3. Install the Python packages

For the interpreter the scripts call (`/usr/local/bin/python3`, version 3.12):

```bash
/usr/local/bin/python3 -m pip install --user -r requirements.txt
```

Install `cloudflared` and make sure it is where `https_bridge/start.sh` expects it:

```bash
mkdir -p ~/.local/bin
curl -fsSL -o ~/.local/bin/cloudflared \
  https://github.com/cloudflare/cloudflared/releases/latest/download/cloudflared-linux-amd64
chmod +x ~/.local/bin/cloudflared && ~/.local/bin/cloudflared --version
```

### 4. Create the signing secret

```bash
mkdir -p -m 700 ~/.remote-gateway
umask 077
printf 'REMOTE_GATEWAY_TOKEN=%s\n' "$(openssl rand -hex 32)" > ~/.remote-gateway/secrets.env
chmod 600 ~/.remote-gateway/secrets.env
```

This value only signs and verifies tokens. You never paste it anywhere.

### 5. Provision the restricted SSH service (once)

```bash
sudo -v                 # confirm passwordless sudo works for your user
bash ssh/install.sh
```

What it does (read the script; it is commented): creates the four system accounts, sets
ACLs so the restricted accounts can reach only the projects tree (read-write) and
skills/agents (read-only), installs the launchers into `/usr/local/libexec`, the sudoers
rules into `/etc/sudoers.d`, the allowlist and `sshd_config` into `/etc/claude-remote`,
generates the host key, creates the systemd units, builds the jail mounts, starts the
NotebookLM broker socket, and starts the dedicated sshd on `127.0.0.1:2223`.

### 6. Start the bridge

```bash
bash start.sh
```

It installs `remote-claude-bridge.service` on first use, starts the gateway and
`cloudflared`, waits for a verified public URL and prints it, for example:

```text
Bridge: https://some-random-words.trycloudflare.com
Remote MCP base: https://some-random-words.trycloudflare.com/<approved-alias>/mcp/
```

### 7. Add the shell aliases (optional but convenient)

```bash
cat >> ~/.bashrc <<EOF
# ---- remote-gateway BEGIN ----
alias remote-gateway-start='$REPO/start.sh'
alias remote-gateway-stop='$REPO/stop.sh'
alias remote-gateway-test='$REPO/start-test.sh'
alias remote-gateway-sync='$REPO/sync.sh'
alias remote-gateway-mcp-login='$REPO/login.sh'
# ---- remote-gateway END ----
EOF
source ~/.bashrc
```

### 8. Deploy the helper set once

`sync.sh` installs the pieces `ssh/install.sh` does not (the Git push broker and its
sudoers rule, the `remote-gateway-git-authorize` command) and re-checks everything. It
needs the bridge running, which it now is:

```bash
remote-gateway-sync
```

### 9. Mint the session bundle and check the whole chain

```bash
remote-gateway-test
```

It prints the public endpoint, the remaining lifetime, and the bundle:

```text
Credential status: rotated
Token expires: 2026-10-03 11:02:41 UTC (120 seconds…; about 120 minutes remaining)
Endpoint: https://some-random-words.trycloudflare.com
REMOTE_GATEWAY_SSH_TOKEN=eyJ…
REMOTE_GATEWAY_SSH_KEY_B64=LS0t…
```

Treat both values as secrets. For the connectors you need only the **token** (once, on a
consent page). Continue with the next section.

---

## Configure Claude: allowed domains and the two connectors

### Allowed domains for the cloud environment (optional but recommended)

Connector traffic travels through Anthropic's servers and does **not** use your cloud
environment's network allowlist. You only need to allow the tunnel host if the VM must
reach it directly, for example the legacy WebSocket path or a `curl` of
`/healthz` from inside the session. To allow it:

1. Open claude.ai/code and edit the cloud environment you use (the environment dialog).
2. Set **Network access** to **Custom**.
3. In **Allowed domains** add one line:

   ```text
   *.trycloudflare.com
   ```

   (One domain per line, no URLs; `*.` matches every subdomain.) You can keep
   "Also include default list of common package managers" ticked so installs still work.
4. Save. Changes apply to new sessions.

### Add the two connectors

Do this once per Claude account, after the bridge is running and you have a bundle from
`remote-gateway-test`.

| Step | Connector 1: shell | Connector 2: tools |
|---|---|---|
| 1. claude.ai → **Settings → Connectors → Add custom connector** | Name `local-ssh` | Name `local-mcp` |
| 2. URL (note the trailing slash) | `https://<tunnel-host>/shell/mcp/` | `https://<tunnel-host>/all/mcp/` |
| 3. **Add / Connect** | the gateway's consent page opens | same |
| 4. On the consent page paste the **`REMOTE_GATEWAY_SSH_TOKEN`** value (the whole `KEY=value` line is accepted) and press **Authorize** | grant lasts 24 h | grant lasts 30 days |
| 5. In each new cloud session, open the connector menu and **enable** both | tool: `ssh_run` | tools: `<server>__<tool>` |

Rules and tips:

* **Name length.** The client builds tool names as `mcp__<connector>__<tool>` and caps them
  at 64 characters. Keep connector names to **13 characters or fewer** (`local-ssh` and
  `local-mcp` are 9).
* **Do not paste `REMOTE_GATEWAY_SSH_KEY_B64` anywhere.** The connectors never need it; the
  gateway reads the key from your disk.
* The token on the consent page is valid for two hours. If it has expired, run
  `remote-gateway-test` again and paste the new one.
* When the add dialog says the server was "not found (404)", the gateway on your machine is
  not running the code that serves that route yet. Run `remote-gateway-sync`, then retry.
* After the tunnel restarts the hostname changes: edit each connector's URL and reconnect.

### Using them from a cloud session

```text
ssh_run  { "command": "pwd && ls && python3 -c 'import sys; print(sys.version)'", "timeout_seconds": 60 }
```

Returns `exit_code`, `stdout`, `stderr` (each capped at 64 KB). A non-zero `exit_code` is a
normal result; an *error* result means the tool could not run it (session expired,
timeout, SSH unreachable). `ssh_run` only works while a valid bundle exists on your
machine, so run `remote-gateway-test` at the start of each working period (see below).

For MCP tools the agent calls, for example, `mcp__local-mcp__playwright__browser_tabs`.
Servers that need their own login (HTTP upstreams in the allowlist) appear in the list
immediately; the first call returns "sign-in required" and the agent calls
`gateway__sign_in` with the alias. It hands you a URL; you finish the sign-in in a browser
and the agent retries.

### Choosing which MCP servers to expose

Edit the allowlist **before** `ssh/install.sh` (or reinstall it later). Each entry is
exactly one of these shapes:

```json
{
  "servers": {
    "my-stdio-server": {
      "command": "/usr/bin/python3",
      "args": ["/home/alice/tools/my_server.py"],
      "cwd": "/home/alice/data/projects/some-project"
    },
    "my-http-server": { "url": "http://127.0.0.1:8791/mcp" }
  }
}
```

* `command` must be an absolute path; `cwd` (optional) must stay under the projects folder.
* Aliases may not contain `/` or `__` and may not be `all` or `shell`.
* The live copy is root-owned: `/etc/claude-remote/mcp-allowlist.json`. After editing the
  repo copy run `sudo install -o root -g root -m 0644 ssh/mcp-allowlist.json /etc/claude-remote/mcp-allowlist.json`
  and then `remote-gateway-sync` so the gateway reloads it.
* For HTTP upstreams that need a login, sign in once with `remote-gateway-mcp-login <alias>`
  (browser opens on your machine) or let the agent start it with `gateway__sign_in`.

---

## Script reference

All scripts are plain Bash; read them, they are short and commented. "Alias" is the name
used in the Quick start's `~/.bashrc` block.

| Script (alias) | Run as | What it does | Typical use |
|---|---|---|---|
| `start.sh` (`remote-gateway-start`) | you | Takes a lock, installs the systemd unit if missing, reuses a healthy tunnel or restarts the unit and waits (≤ 120 s) for a verified public `/healthz`, then prints the endpoints | after boot, or when the tunnel looks stale |
| `stop.sh` (`remote-gateway-stop`) | you | `systemctl stop remote-claude-bridge.service`: stops the gateway **and** `cloudflared`, closing all public access at once | when you are done, or as an emergency off-switch |
| `start-test.sh [--rotate]` (`remote-gateway-test`) | you | Runs `start.sh`, checks local and public health, then reuses the current session bundle if it is valid or issues a new one (token + fresh ed25519 key, stored 0600), authorizes the key for `claude-shell`, `claude-sync` and `claude-playwright` (only from `127.0.0.1`) and prints the endpoint, expiry and bundle. `--rotate` forces a new bundle | at the start of each working period, and when a connector asks for a token |
| `sync.sh` (`remote-gateway-sync`) | you | Hot-deploys reviewed changes with no URL change: runs the test suites; boots the new gateway on a private port (8799) and requires `/healthz`; atomically installs launchers, runner, mounts script, brokers, units and sudoers; applies the jail's extra read-only binds in both the host and sshd's private namespace; sends **HUP** to reload only the gateway; verifies the PID and public URL did not change | after every code change; first-time install of the push broker |
| `login.sh <alias>` (`remote-gateway-mcp-login`) | you | Runs `gateway.upstream_auth` to sign the gateway in to an HTTP upstream: opens your browser, receives the redirect on `127.0.0.1:8797`, stores tokens 0600 | HTTP MCP servers that need an account |
| `ssh/install.sh` | you, once | Provisions everything for the SSH service (accounts, ACLs, keys, units, sudoers, mounts, broker socket, sshd) | first install, or after changing account or path literals |
| `ssh/remote-gateway-git-authorize` (installed as `remote-gateway-git-authorize`) | you | `sudo` wrapper that grants **one** push: `remote-gateway-git-authorize REPO FULL_SHA BRANCH` prints a nonce valid 10 minutes | when an agent asks to push |
| `ssh/claude_shell_mounts.sh` | root (boot, via `claude-shell-sandbox.service`) | Builds the jail's bind mounts | automatic |
| `https_bridge/start.sh --foreground` | systemd | Supervisor: gateway + `cloudflared`, writes `url.txt`, handles HUP | automatic |
| `https_bridge/stop.sh` | systemd | Kills the PIDs in `pids` | automatic |
| `https_bridge/install-service.sh` | you (via `start.sh`) | Installs and enables the unit | automatic |

Worked examples:

```bash
# Start of the day
remote-gateway-start         # tunnel up (prints the URL)
remote-gateway-test          # prints a bundle; paste the TOKEN into a connector if it asks

# You changed gateway code
python3 -m pytest -q         # all green?
remote-gateway-sync          # candidate boots on :8799, live gateway reloads, URL unchanged

# An agent wants to push commit 0123…cdef of repo "my-repo" to branch "main"
remote-gateway-git-authorize my-repo 0123456789abcdef0123456789abcdef01234567 main
#   → prints an approval nonce; give it to the active session only.
#   The agent then runs, through ssh_run:  push my-repo <sha> main <nonce>

# Shut everything down
remote-gateway-stop
```

---

## Day-to-day operation

| When | What to do |
|---|---|
| Start a work period | `remote-gateway-start`, then `remote-gateway-test`; enable both connectors in the session |
| `ssh_run` says the session expired | run `remote-gateway-test` (it rotates the bundle when the old one has expired) |
| A connector shows an auth error | reconnect it; paste the current token |
| Tunnel URL changed | edit both connector URLs; reconnect |
| You changed the code | `remote-gateway-sync` (never edit or signal the live gateway by hand) |
| You changed the allowlist | install the file as shown above, then `remote-gateway-sync` |
| Revoke all connector grants | delete `~/.remote-gateway/oauth-state.json`, then `remote-gateway-sync` |
| Look at logs | `~/.remote-gateway/https-bridge/logs/{gateway,cloudflared}.log`; `journalctl -u remote-claude-bridge`, `journalctl -u claude-remote-sshd` |
| Emergency stop | `remote-gateway-stop` |

---

## Configuration reference

**Environment variables (gateway process):**

| Variable | Default | Meaning |
|---|---|---|
| `REMOTE_GATEWAY_TOKEN` | required | signing secret (from `secrets.env`) |
| `REMOTE_GATEWAY_HOST` / `REMOTE_GATEWAY_PORT` | `127.0.0.1` / `8798` | listen address |
| `REMOTE_GATEWAY_OAUTH_GRANT_DAYS` | `30` | refresh-grant lifetime for `/all` and `/<alias>` routes |
| `REMOTE_GATEWAY_SHELL_GRANT_HOURS` | `24` | refresh-grant lifetime for `/shell` |

**Ports:** `8798` gateway (loopback), `8799` candidate during `sync.sh`, `2223` dedicated sshd
(loopback), `8797` temporary sign-in callback of `login.sh`.

**Lifetimes:** session token and SSH key 2 h · OAuth access token 2 h · OAuth refresh grant
30 d (`/shell`: 24 h) · authorization code 5 min · Git push approval 10 min · tool output cap
64 KB · tool timeout ≤ 600 s · 4 concurrent `ssh_run` calls.

**Files and directories:**

| Path | Contents |
|---|---|
| `~/.remote-gateway/secrets.env` | `REMOTE_GATEWAY_TOKEN` (0600) |
| `~/.remote-gateway/https-bridge/{url.txt,pids,reload-capable.pid,logs/}` | tunnel URL, PIDs, logs |
| `~/.remote-gateway/ssh-session/current.env` | current bundle: token, key (base64), expiry (0600) |
| `~/.remote-gateway/ssh-session/{known_hosts,run/}` | loopback host key; transient key files |
| `~/.remote-gateway/oauth-state.json` | registered clients, hashed tokens |
| `~/.remote-gateway/upstream-oauth/<alias>.json` | tokens for HTTP upstreams (0600) |
| `~/.remote-gateway/tool-cache/<alias>.json` | last good tool list per alias |
| `/etc/claude-remote/` | `mcp-allowlist.json`, `sshd_config`, host key, `authorized_keys/<account>`, optional `git-push-policy.json` |
| `/usr/local/libexec/claude-*` | root-owned launchers, runner, brokers |
| `/etc/sudoers.d/claude-*` | the narrow sudo rules |
| `/srv/claude-shell-root` | the jail root; `/srv/claude-remote` the SFTP root |

**Optional Git-push policy** (`/etc/claude-remote/git-push-policy.json`, root-owned 0600):
copy `ssh/git-push-policy.example.json`. Fill in a GitHub App (`app_id`, `installation_id`,
`private_key` path) to push with an App installation token; leave the fields empty to use
your own `gh` login inside the root broker. Either way the token never enters the jail.

---

## Security model

**What an attacker with the connector grant can do:** run commands as the unprivileged
`claude-shell` user inside the jail, for as long as a valid two-hour bundle exists on your
disk. That means: read and write everything under your projects folder, read skills and
agents, use the GPU, reach the internet (outbound only), and call NotebookLM through the
broker. They cannot see your home folder, keys or other logins, become root, listen on a
port, or push to GitHub without a fresh approval you issued.

**Trust boundaries and what protects each:**

| Boundary | Protection |
|---|---|
| Internet → gateway | OAuth 2.1 + PKCE, exact redirect URIs, route-bound tokens, hashed storage, consent rate limits; unsigned or expired tokens rejected |
| Gateway → sshd | loopback only; `from="127.0.0.1"` on every authorized key; public-key only; per-session ed25519 key |
| sshd → jail | forced command; opaque command string; root-owned runner via one sudoers rule; chroot, dropped groups, unprivileged UID |
| Jail → host | only the bind mounts listed above; read-only wherever possible; no host devices except the GPU |
| Jail → secrets | brokers (NotebookLM, Git push) run outside the jail and never return credentials |
| Gateway → MCP servers | root-owned allowlist; fixed command, arguments and working directory; minimal environment |

**Caveats you should know:**

* The projects folder is read-write for the jail. Anything in it (all projects, not just
  one) can be changed or deleted by a command the agent runs. Keep backups or use version
  control.
* A tunnel hostname is an unguessable but public URL; the security comes from the
  authentication above, not from secrecy of the URL.
* The quick tunnel offers no uptime guarantee and a new hostname per start.
* `claude-sync`'s ACLs and the `claude-shell` write access are applied recursively to your
  projects tree by `ssh/install.sh`; read that section before you run it.
* The example allowlist and several literals are specific to the author's machine
  ([Adapting the account and paths](#2-adapt-the-account-and-paths)).

If you find a vulnerability, please report it privately (the repository's Security tab, "Report a vulnerability") instead of opening a public issue.

---

## Tests

```bash
/usr/local/bin/python3 -m pip install --user -r requirements.txt
python3 -m pytest -q
```

72 tests, no network or real tunnel needed, run in a few seconds:

| File | Tests | Covers |
|---|---|---|
| `https_bridge/tests/test_mcp_http.py` | 13 | route auth, OAuth consent and PKCE, stdio upstream lifecycle, aggregate namespacing, tool cache, sign-in tool and callback (including a real OAuth round trip against a second gateway), allowlist validation |
| `https_bridge/tests/test_shell_mcp.py` | 13 | `ssh_run` with a fake `ssh`: argv handling, key-file lifecycle, expiry, wrong-secret bundle, timeouts, output caps, 255 vs command failure, route-bound grants, grant lifetimes |
| `https_bridge/tests/test_ssh_transport.py` | 4 | two-hour session cookie: valid, tampered, wrong secret, over-long; which routes the gateway mounts |
| `ssh/tests/test_launcher_runner.py` | 15 | forced-command parsing, runner and allowlist validation |
| `ssh/tests/test_nlm_bridge.py` | 19 | NotebookLM broker allow/deny rules, path mapping, size limits |
| `tests/test_lifecycle_scripts.py` | 8 | text-level checks that `start.sh`, `start-test.sh` and `sync.sh` keep their contracts: real health checks, stale-URL clearing, wall-clock deadlines, rotate-only-when-expired, hot reload only with a capable supervisor |

**Two tests are tied to the author's machine** and fail on a fresh install until you
adapt them: `ssh/tests/test_launcher_runner.py::test_all_registered_programs_exist_on_this_host`
checks that every program in `ssh/mcp-allowlist.json` exists on disk, and
`https_bridge/tests/test_ssh_transport.py::test_gateway_exposes_only_reviewed_mcp_aliases_plus_auth_and_ssh`
builds the gateway from the *installed* `/etc/claude-remote/mcp-allowlist.json` and expects
the author's alias set. After you replace the allowlist with your own servers, update those
two expectations.

---

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| Adding a connector says **404 / Not found** | The running gateway does not serve that route yet (old code). `remote-gateway-sync`, then retry. Also check the URL ends with `/mcp/` |
| **401** on a route | Normal until you authorize. Connect the connector and paste a current token |
| Consent page says **"That token is not correct."** | Token expired or from an older bundle. `remote-gateway-test`, paste the new `REMOTE_GATEWAY_SSH_TOKEN` |
| **Too many failed attempts** on consent | Rate limit (5 per IP per 10 min). Wait, then retry with the right token |
| `ssh_run`: "no … SSH session is available" / "has expired" | `remote-gateway-test` |
| `ssh_run`: "could not reach the restricted shell" | sshd down or bundle not authorized: `systemctl status claude-remote-sshd`, then `remote-gateway-test` |
| Tools show up but a call says **sign-in required** | HTTP upstream: let the agent call `gateway__sign_in`, or run `remote-gateway-mcp-login <alias>` |
| A tool name looks truncated with a hash | Intended: names over the limit are shortened deterministically |
| Connector works, then fails after a restart | Tunnel hostname changed: edit the URL |
| `remote-gateway-sync`: "Live supervisor predates hot-reload support" | Run `remote-gateway-start` once, then sync again |
| `install: cannot change owner and permissions … Read-only file system` | Old copy of the sync script; the current one only prepares unmounted targets |
| `ssh/install.sh` fails on `sudo -n true` | Your user needs passwordless sudo for the install |
| Browser MCP cannot connect | Its own extension/config must be running on your machine; the bridge only starts the process |

---

## Limitations and honest caveats

* Written for one machine first. Account name, home folder, interpreter path and a handful
  of tool locations are literals; the README shows how to replace them, but this is not a
  packaged installer.
* `pyproject.toml` lists only the web-server basics (the MCP SDK is also required);
  `requirements.txt` is the source of truth for dependencies.
* The cloud client's behaviour (connector UI, permission checks, name limits) belongs to
  that product and can change; the notes here describe what was observed when this was
  built.
* The jail is a chroot with a dropped-privilege user, not a VM or container. It is a
  reasonable boundary for a tool you control and trust to be steered, not for hostile code.
* Quick tunnels are for development. For a stable URL use a named Cloudflare tunnel on a
  domain you own (not covered here).

## License

MIT. See [LICENSE](LICENSE).

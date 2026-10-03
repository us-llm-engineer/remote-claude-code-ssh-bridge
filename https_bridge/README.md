# Authenticated remote MCP and SSH bridge

The gateway publishes each root-reviewed local stdio MCP as a standard
Streamable HTTP endpoint:

```text
https://CURRENT.trycloudflare.com/<approved-alias>/mcp/
```

The exact aliases come from `/etc/claude-remote/mcp-allowlist.json`; callers
cannot choose a command, executable, working directory, or environment. The
local server continues to run on this computer with its existing local
configuration. The public route is only a protocol adapter.

Remote MCP routes require either OAuth 2.1 or the two-hour bearer printed by
`remote-gateway-test`. OAuth supports discovery, dynamic client registration,
authorization code with PKCE, exact redirect validation, route-bound tokens,
and two-hour access-token expiry. Token values are stored only as SHA-256
hashes. The OAuth consent page accepts the current two-hour
`REMOTE_GATEWAY_SSH_TOKEN`; the caller never receives the gateway signing key.

The supported endpoint is the aggregate one, which serves every approved MCP's
tools as `<alias>__<tool>` from a single connector:

```text
/all/mcp/
```

Per-alias routes (`/playwright/mcp/`, `/modal-gpu/mcp/`, ...) remain. Grants
are route-bound: an alias grant does not open `/all`, and vice versa. OAuth
access tokens last two hours; the refresh grant lasts
`REMOTE_GATEWAY_OAUTH_GRANT_DAYS` (default 30) so an account-level claude.ai
connector survives across Cloud sessions. Revoke all grants by deleting
`~/.remote-gateway/oauth-state.json` and reloading the gateway.

`/shell/mcp/` is a separate connector with one tool, `ssh_run`, that runs a command in
the restricted `claude-shell` account. The gateway makes the SSH connection itself over
loopback (`127.0.0.1:2223`), using the two-hour key in
`~/.remote-gateway/ssh-session/current.env`, so a Cloud caller needs no tunnel, key or
token. The tool refuses to run when that bundle has expired, so connector sign-in
(24 hours, `REMOTE_GATEWAY_SHELL_GRANT_HOURS`) never extends shell access past the
two-hour session. `shell` and `all` are reserved aliases.

Allowlist entries are either stdio (`command`, `args`, optional `cwd`) or HTTP
(`url`, https or loopback http only). The gateway signs in to HTTP upstreams
itself: a Cloud agent calls the `gateway__sign_in` tool, hands the returned URL
to the human, and the provider redirects back to `/oauth/upstream-callback` on
the gateway (`remote-gateway-mcp-login ALIAS` does the same locally). Tokens stay
in `~/.remote-gateway/upstream-oauth/`. Each alias's last tool listing is cached
in `~/.remote-gateway/tool-cache/`, so a down or signed-out MCP stays listed and
its calls explain what to do.

Register `https://HOST/all/mcp/` as a claude.ai custom connector in the Cloud platform
before starting the agent session. Complete its OAuth flow in the browser and
paste the current two-hour authorization only into the gateway consent page.
The Cloud agent needs no local launcher, SSH key, Python package, environment
variable, or stdio registration for MCP usage.

The existing `/ssh` WebSocket remains available for the restricted project
shell. It is separate from MCP-over-HTTPS and retains its temporary SSH-key and
two-hour-cookie requirements.

`remote-gateway-start` reuses a healthy tunnel. `remote-gateway-test` validates
both the public endpoint and the current two-hour authorization.
`remote-gateway-stop` closes public access.

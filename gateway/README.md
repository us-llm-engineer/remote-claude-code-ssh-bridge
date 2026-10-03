# `gateway/`: the public web application

One Starlette (ASGI) application, served by uvicorn on `127.0.0.1:8798` and published to
the internet only through a Cloudflare quick tunnel. It is the only component that talks
to the outside world; everything it controls (local MCP servers, the SSH daemon, the
brokers) is reachable from it over loopback or stdio.

Entry point: `python gateway/server.py` (what `https_bridge/start.sh` runs), which calls
`server.main()` → `uvicorn.run(build_gateway(REMOTE_GATEWAY_TOKEN), …)`.

| Module | Lines | Responsibility |
|---|---|---|
| `server.py` | ~210 | Builds the app: routes, the per-route auth wrapper, the `/ssh` WebSocket relay, health, upstream-sign-in callback |
| `oauth.py` | ~370 | OAuth 2.1 authorization server (discovery, dynamic registration, authorize with PKCE, token, refresh) |
| `session.py` | ~60 | Signs and verifies the two-hour session token |
| `mcp_proxy.py` | ~320 | Allowlist loader; stdio/HTTP upstream lifecycle; per-alias MCP servers; the aggregate (`/all`) server |
| `shell_mcp.py` | ~190 | The `ssh_run` tool |
| `upstream_auth.py` | ~220 | The gateway as an OAuth *client* of HTTP MCP upstreams; the `gateway__sign_in` flow state machine |

## `session.py`: the root of trust

```text
token  = base64url(JSON{"aud":"ssh","exp":<unix>,"v":1}) "." base64url(HMAC-SHA256(secret, body))
```

* `issue_ssh_session(secret, ttl_seconds=7200)` refuses an empty secret or a TTL above two
  hours (`DEFAULT_TTL_SECONDS`).
* `verify_ssh_session(value, secret)` returns the expiry as a float, or `None` for: empty
  input, malformed token, bad signature (constant-time compare), unparsable claims, wrong
  `v` or `aud`, or `exp <= now`.
* `python -m gateway.session` prints a fresh token for the secret in `REMOTE_GATEWAY_TOKEN`
  (used by `start-test.sh`).

Nothing else in the system trusts a caller; everything reduces to "does this token verify
against the secret in `secrets.env`".

## `oauth.py`: OAuth 2.1 for connector clients

`OAuthServer(secret, state_path, sources)` is constructed with the set of valid *route
aliases* (`sources`): every allowlisted alias plus `all` and `shell`.

**Discovery.** `/.well-known/oauth-protected-resource[/{tail}]` returns the resource URL and
the issuer; `/.well-known/oauth-authorization-server[/{tail}]` (and `openid-configuration`)
returns the endpoints, `S256` as the only PKCE method, `none` as the token endpoint auth
method, and scope `mcp`. The public base URL is derived from `X-Forwarded-Host`/`Host`;
loopback hosts use `http`, everything else `https`.

**Registration** (`POST /register`). Accepts up to 10 `redirect_uris`, each of which must be
`https://claude.ai/…`, `https://claude.com/…` or loopback `http`. Registration grants
nothing: it only creates a `client_id` (`c_…`). The registry is capped at 200 clients
(oldest quarter evicted).

**Authorize** (`GET`/`POST /authorize`). `_check_authz` insists on a known client, an exact
`redirect_uri` match, `response_type=code`, and `code_challenge_method=S256` with a 43–128
character challenge. `GET` renders the consent page (strict CSP, `frame-ancestors 'none'`,
no referrer). `POST` normalizes the pasted secret (`normalize_secret` accepts a bare token,
`REMOTE_GATEWAY_SSH_TOKEN=…`, `Bearer …`, with or without quotes), verifies it with
`verify_ssh_session`, and on success stores a hashed code (5-minute TTL) that remembers the
client, redirect URI, challenge and the *resource* alias taken from the RFC 8707 `resource`
parameter (`_source_of` maps it to the first path segment if that segment is a valid alias).
Failed attempts are rate-limited: 5 per client IP and 30 overall within 10 minutes.

**Token** (`POST /token`). `authorization_code`: code is single-use, must belong to the
client and not be expired, `redirect_uri` must match, and `sha256(verifier)` must equal the
stored challenge (`hmac.compare_digest`). `refresh_token`: must be known, unexpired and the
client's; returns a new access token and keeps the same refresh token and expiry.

**Lifetimes.** `ACCESS_TTL` = 2 h. The refresh grant is `REFRESH_TTL`
(`REMOTE_GATEWAY_OAUTH_GRANT_DAYS`, default 30 d), except for the `shell` resource, where it
is `min(REFRESH_TTL, SHELL_REFRESH_TTL)` (`REMOTE_GATEWAY_SHELL_GRANT_HOURS`, default 24 h).
The access token never outlives its grant.

**Storage.** `oauth-state.json` (0600, atomic replace) holds clients plus *SHA-256 hashes*
of access and refresh tokens with their expiry, client and resource. Codes live only in
memory. Expired entries are purged on every save.

**Verification at request time.** `bearer_ok(header, source)` hashes the presented bearer,
looks it up, checks expiry, and accepts it only if the recorded resource is `None` or equals
`source` (the alias of the route being called).

## `server.py`: routes and the auth wrapper

`build_gateway(token, …)` does, in order:

1. `load_allowlist()`, then one `OAuthServer` for all aliases.
2. For each allowlisted alias: `build_proxy(alias, spec)` → an upstream and a
   `StreamableHTTPSessionManager`, mounted at `/<alias>/mcp` behind `AuthenticatedMCP`.
3. `build_shell(token)` mounted at `/shell/mcp`, and `build_aggregate(upstreams)` mounted at
   `/all/mcp`. Both are separate mounts with their own alias, so grants cannot cross.
4. A lifespan that creates the OAuth state directory (0700), starts each session manager
   and closes every upstream on shutdown.

`AuthenticatedMCP.__call__` accepts either `Authorization: Bearer <session token>` (verified
directly) or an OAuth bearer accepted by `oauth.bearer_ok(…, alias)`. Otherwise it answers
`401` with `WWW-Authenticate: Bearer resource_metadata="<base>/.well-known/oauth-protected-resource/<alias>/mcp", scope="mcp"`
so a connector can find its way to the consent page.

**`/ssh` (WebSocket relay).** Requires cookie `remote_gateway_ssh` to be a valid session
token; otherwise closes with 4401. It opens a TCP connection to `127.0.0.1:2223`, then runs
three tasks until the first finishes: websocket→TCP (binary frames only), TCP→websocket, and
an expiry guard that sleeps until the token's `exp` and then tears everything down.
`_close()` swallows already-closed errors, so a client dropping first leaves no traceback.

**`/healthz`** returns `{"status":"ok","transport":"mcp-streamable-http+ssh-websocket",
"mcp_servers":[…aliases…],"aggregate":"/all/mcp/","shell":"/shell/mcp/"}`. The lifecycle
scripts require exactly that `status` and `transport` for a successful health check.

## `mcp_proxy.py`: bringing local MCP servers online

**`load_allowlist(path)`** validates `/etc/claude-remote/mcp-allowlist.json`: the top level
must be exactly `{"servers": {…}}`; an alias is a non-empty string without `/` or `__` and
not in `RESERVED_ALIASES` (`all`, `shell`); an entry is either `{"url": …}` (https, or http
to `127.0.0.1`/`localhost`) or `{"command": "/abs/path", "args": [str…], "cwd"?: "/abs/under/projects"}`.
Anything else raises `ValueError` and the gateway refuses to start.

**`LocalStdioUpstream(alias, spec)`** keeps one connection per alias:

* a single owner task enters the stdio (or Streamable HTTP) client contexts and holds them
  open until `close()`; this matters because anyio cancel scopes must be exited by the task
  that entered them;
* it starts lazily on the first `session()` call under a lock; if the owner task has ended
  (crash, failed start) and the upstream was not deliberately stopped, the next call starts
  it again, so fixing a missing prerequisite (for example, signing in) needs no reload;
* stdio children get `{HOME, LOGNAME, USER, PATH=SAFE_PATH, LANG}` and `cwd` from the spec
  (default: the home directory); no gateway secret is passed;
* HTTP upstreams use `streamablehttp_client` with an OAuth provider from
  `upstream_auth.gateway_provider`, which can refresh stored tokens but **never** starts an
  interactive login inside the server.

**`build_proxy(alias, spec)`** returns the upstream plus a low-level MCP `Server` that
forwards `list_tools`, `call_tool` (with input validation), resources, resource templates
and prompts to the upstream session. **`_manager(server)`** wraps a server in a
`StreamableHTTPSessionManager` configured `stateless=True`, `json_response=True`, 4 MB max
body, and DNS-rebinding protection off (the listener is loopback behind a tunnel whose host
changes per start; the bearer check is the boundary).

**`build_aggregate(upstreams, cache_dir, flows)`** is the `/all` server:

* `tools_of(alias, upstream)` lists an upstream's tools (60 s timeout), renames each to
  `public_tool_name(alias, tool)` (`<alias>__<tool>`, shortened to 44 characters with a
  `_<8-hex>` hash suffix if longer; 44 + `mcp__<name>__` stays within 64 for connector names
  up to 13 characters), records the routing table `public name → (alias, tool)` and writes the
  listing to `tool-cache/<alias>.json`. On any failure it serves the cached listing instead.
* `list_tools` gathers all aliases concurrently and appends `gateway__sign_in` when at least
  one alias is an HTTP upstream.
* `call_tool` resolves the public name (refreshing the listing once if unknown), obtains the
  upstream session and forwards. If the upstream cannot start it returns a text result with
  `isError`: either "sign-in required, call `gateway__sign_in`" (HTTP upstream) or "unavailable
  on the user's machine" (stdio).
* `gateway__sign_in(alias)` validates the alias, derives the public callback URL from the
  request's `Host`, and asks `SignInFlows.start(…)` for the authorization URL, which it
  returns as text.

## `shell_mcp.py`: `ssh_run`

`build_shell(secret, **kwargs)` returns a manager for a one-tool server. `SshRunner.run`:

1. rejects empty commands and commands over 20,000 characters;
2. `_load_bundle` reads `current.env` (`REMOTE_GATEWAY_SSH_TOKEN`, `REMOTE_GATEWAY_SSH_KEY_B64`),
   decodes the key strictly, verifies the token against the secret and requires at least 10
   seconds of lifetime; otherwise it raises `ShellUnavailable` whose message tells the agent
   to ask for `remote-gateway-test`;
3. clamps `timeout_seconds` to 1–600 and to the bundle's remaining lifetime;
4. under a semaphore of 4, writes the key to `ssh-session/run/k-*` (0600), spawns
   `ssh` with `start_new_session=True`, `stdin=DEVNULL`, a two-variable environment and the
   command as the final argv element, and pumps stdout/stderr with a 64 KB cap each (it keeps
   reading past the cap so the child never stalls);
5. on timeout kills the whole process group; on exit code 255 reports an SSH failure; else
   returns `exit_code`, stdout and stderr, marking `(truncated)` where cut;
6. always unlinks the key file.

The command is logged (first 200 characters) with the PID and exit status in the gateway
log; the key and token are never logged.

## `upstream_auth.py`: the gateway as an OAuth client

* `FileTokenStorage(alias)` stores tokens and the registered client in
  `upstream-oauth/<alias>.json` (0600, atomic replace). `forget_client_unless(redirect_uri)`
  drops a registration made for a different redirect URI so the next flow registers afresh.
* `gateway_provider(alias, url)` is the *non-interactive* provider used by the running
  server; if a login is needed it raises an error naming the alias instead of opening a
  browser.
* `SignInFlows` is the state machine behind `gateway__sign_in`. `start(alias, url,
  redirect_uri)` launches the MCP SDK's OAuth client in a background task whose "open the
  browser" hook publishes the authorization URL and whose "wait for the callback" hook waits
  (15 min) on a future keyed by the `state` value. `callback(code, state, error)` resolves
  that future exactly once (so replays and unknown states fail). Tokens are saved by
  `FileTokenStorage`; the code verifier never leaves the process.
* `python -m gateway.upstream_auth <alias>` (via `login.sh`) is the local variant: it listens
  on `127.0.0.1:8797`, opens your browser and finishes the same flow.

## Reading order

1. `session.py` (60 lines) → 2. `oauth.py` `bearer_ok` and `authorize` → 3. `server.py`
`build_gateway` → 4. `mcp_proxy.py` `LocalStdioUpstream` → 5. `shell_mcp.py` → 6.
`build_aggregate`. The tests in `../https_bridge/tests/` are written to be read alongside:
each test names the behavior it pins down.

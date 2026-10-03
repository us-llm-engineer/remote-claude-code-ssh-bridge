"""Minimal OAuth 2.1 authorization server for the gateway.

claude.ai connectors expect to sign in with OAuth (discovery, dynamic client
registration, authorization code + PKCE, refresh). This provides exactly that, and
nothing more, in front of the gateway's two-hour session authorization:

* /authorize shows a consent page. Issuing a code REQUIRES a current two-hour
  session token, typed by the human in their own browser. Registering a client
  (open by design, RFC 7591) grants nothing on its own.
* Redirect URIs are restricted to claude.ai / claude.com (https) and loopback (http),
  and must match the registered value exactly. PKCE (S256) is mandatory.
* Access / refresh tokens are random, stored only as SHA-256 hashes, and can be bound
  to one route via the RFC 8707 `resource` parameter.
* Failed consent attempts are rate limited per client IP and globally.

The long-lived gateway signing secret is never accepted by the consent form.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import logging
import os
import re
import secrets
import time
from urllib.parse import parse_qsl, urlencode, urlparse

from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from starlette.routing import Route

logger = logging.getLogger("gateway.oauth")

ALLOWED_REDIRECT_HOSTS = frozenset({"claude.ai", "claude.com"})
LOOPBACK_HOSTS = frozenset({"localhost", "127.0.0.1", "::1", "[::1]"})

CODE_TTL = 300
ACCESS_TTL = 2 * 3600
# A claude.ai connector is account-level and reused by every new cloud session;
# a long refresh grant keeps it signed in. Access tokens expire after two hours.
# Revoke every grant with `remote-gateway-revoke` (or delete the state file).
REFRESH_TTL = int(float(os.environ.get("REMOTE_GATEWAY_OAUTH_GRANT_DAYS", "30")) * 86400)
# Command execution gets a shorter standing grant than read-only tools. The tool also
# needs the user's two-hour SSH bundle, so this only bounds how long a stale grant lingers.
SHELL_REFRESH_TTL = int(float(os.environ.get("REMOTE_GATEWAY_SHELL_GRANT_HOURS", "24")) * 3600)
MAX_CLIENTS = 200
MAX_FAILS_PER_IP = 5
MAX_FAILS_TOTAL = 30
FAIL_WINDOW = 600

_NO_STORE = {"Cache-Control": "no-store", "Pragma": "no-cache"}
_PAGE_HEADERS = {
    **_NO_STORE,
    "X-Frame-Options": "DENY",
    "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; frame-ancestors 'none'",
    "Referrer-Policy": "no-referrer",
}


def _sha(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def _pkce_s256(verifier: str) -> str:
    digest = hashlib.sha256(verifier.encode()).digest()
    return base64.urlsafe_b64encode(digest).rstrip(b"=").decode()


def normalize_secret(value: str | None) -> str:
    """Accept the token however it was pasted (whole `KEY=value` line, quotes, Bearer)."""
    v = (value or "").strip().strip('"').strip("'")
    for prefix in ("REMOTE_GATEWAY_SSH_TOKEN=", "Bearer ", "bearer "):
        if v.startswith(prefix):
            v = v[len(prefix):].strip().strip('"').strip("'")
    return v


def _oauth_error(error: str, description: str = "", status: int = 400) -> JSONResponse:
    body = {"error": error}
    if description:
        body["error_description"] = description
    return JSONResponse(body, status_code=status, headers=_NO_STORE)


class OAuthServer:
    def __init__(self, secret: str, state_path: str, sources: set[str]):
        self.secret = secret
        self.path = state_path
        self.sources = set(sources)
        self.clients: dict[str, dict] = {}
        self.access: dict[str, dict] = {}
        self.refresh: dict[str, dict] = {}
        self.codes: dict[str, dict] = {}
        self.fails: list[tuple[float, str]] = []
        self._load()

    # ---- persistence (hashes only) -------------------------------------------------
    def _load(self) -> None:
        try:
            with open(self.path) as fh:
                data = json.load(fh)
        except (OSError, ValueError):
            return
        self.clients = data.get("clients", {})
        self.access = data.get("access", {})
        self.refresh = data.get("refresh", {})
        self._purge()

    def _purge(self) -> None:
        now = time.time()
        self.access = {k: v for k, v in self.access.items() if v["exp"] > now}
        self.refresh = {k: v for k, v in self.refresh.items() if v["exp"] > now}
        self.codes = {k: v for k, v in self.codes.items() if v["exp"] > now}

    def _save(self) -> None:
        self._purge()
        tmp = self.path + ".tmp"
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            json.dump({"clients": self.clients, "access": self.access, "refresh": self.refresh}, fh)
        os.replace(tmp, self.path)

    # ---- helpers -----------------------------------------------------------------
    def base(self, request: Request) -> str:
        host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or "").split(",")[0].strip()
        hostname = host.rsplit(":", 1)[0] if not host.startswith("[") else host
        scheme = "http" if hostname in LOOPBACK_HOSTS else "https"
        return f"{scheme}://{host}"

    @staticmethod
    def _redirect_ok(uri: object) -> bool:
        if not isinstance(uri, str) or len(uri) > 500:
            return False
        try:
            u = urlparse(uri)
        except ValueError:
            return False
        if u.fragment or not u.hostname:
            return False
        if u.scheme == "https" and u.hostname in ALLOWED_REDIRECT_HOSTS:
            return True
        return u.scheme == "http" and u.hostname in LOOPBACK_HOSTS

    def _source_of(self, resource: str | None) -> str | None:
        if not resource:
            return None
        try:
            first = urlparse(resource).path.strip("/").split("/")[0]
        except ValueError:
            return None
        return first if first in self.sources else None

    @staticmethod
    def _client_ip(request: Request) -> str:
        return request.client.host if request.client else "?"

    def _rate_limited(self, ip: str) -> bool:
        now = time.time()
        self.fails = [f for f in self.fails if now - f[0] < FAIL_WINDOW]
        return (
            sum(1 for _, i in self.fails if i == ip) >= MAX_FAILS_PER_IP
            or len(self.fails) >= MAX_FAILS_TOTAL
        )

    # ---- bearer check used by the proxy -------------------------------------------
    def bearer_ok(self, header: str | None, source: str) -> bool:
        if not header:
            return False
        scheme, _, presented = header.partition(" ")
        if scheme.lower() != "bearer" or not presented:
            return False
        entry = self.access.get(_sha(presented))
        if not entry or entry["exp"] <= time.time():
            return False
        return entry.get("resource") in (None, source)

    # ---- discovery ---------------------------------------------------------------
    async def protected_resource(self, request: Request) -> Response:
        base = self.base(request)
        tail = request.path_params.get("tail", "").strip("/")
        resource = f"{base}/{tail}" if tail.split("/")[0] in self.sources else base
        return JSONResponse({
            "resource": resource,
            "authorization_servers": [base],
            "bearer_methods_supported": ["header"],
            "scopes_supported": ["mcp"],
        }, headers=_NO_STORE)

    async def auth_server_metadata(self, request: Request) -> Response:
        base = self.base(request)
        return JSONResponse({
            "issuer": base,
            "authorization_endpoint": f"{base}/authorize",
            "token_endpoint": f"{base}/token",
            "registration_endpoint": f"{base}/register",
            "response_types_supported": ["code"],
            "grant_types_supported": ["authorization_code", "refresh_token"],
            "code_challenge_methods_supported": ["S256"],
            "token_endpoint_auth_methods_supported": ["none"],
            "scopes_supported": ["mcp"],
        }, headers=_NO_STORE)

    # ---- dynamic client registration (RFC 7591) -------------------------------------
    async def register(self, request: Request) -> Response:
        try:
            body = await request.json()
        except ValueError:
            return _oauth_error("invalid_client_metadata", "body must be JSON")
        uris = body.get("redirect_uris") if isinstance(body, dict) else None
        if not isinstance(uris, list) or not uris or len(uris) > 10 or not all(self._redirect_ok(u) for u in uris):
            return _oauth_error("invalid_redirect_uri", "redirect_uris must be https://claude.ai|claude.com or loopback http URLs")
        if len(self.clients) >= MAX_CLIENTS:
            oldest = sorted(self.clients, key=lambda k: self.clients[k].get("created", 0))[: MAX_CLIENTS // 4]
            for k in oldest:
                self.clients.pop(k, None)
        client_id = "c_" + secrets.token_urlsafe(18)
        name = str(body.get("client_name") or "client")[:80]
        self.clients[client_id] = {"redirect_uris": uris, "client_name": name, "created": time.time()}
        self._save()
        logger.info("OAUTH register client=%s name=%r", client_id, name)
        return JSONResponse({
            "client_id": client_id,
            "client_name": name,
            "redirect_uris": uris,
            "grant_types": ["authorization_code", "refresh_token"],
            "response_types": ["code"],
            "token_endpoint_auth_method": "none",
        }, status_code=201, headers=_NO_STORE)

    # ---- authorization endpoint ---------------------------------------------------
    def _check_authz(self, p: dict) -> tuple[dict | None, str]:
        client = self.clients.get(p.get("client_id", ""))
        if not client:
            return None, "Unknown client. Start the connection again from claude.ai."
        if p.get("redirect_uri") not in client["redirect_uris"]:
            return None, "redirect_uri does not match the registered value."
        if p.get("response_type") != "code":
            return None, "Only response_type=code is supported."
        if p.get("code_challenge_method") != "S256" or not re.fullmatch(r"[A-Za-z0-9_\-]{43,128}", p.get("code_challenge", "")):
            return None, "PKCE with S256 is required."
        return client, ""

    def _page(self, p: dict, client: dict, error: str = "", status: int = 200) -> HTMLResponse:
        hidden = "".join(
            f'<input type="hidden" name="{k}" value="{html.escape(p.get(k, ""), quote=True)}">'
            for k in ("response_type", "client_id", "redirect_uri", "code_challenge", "code_challenge_method", "state", "scope", "resource")
        )
        dest = html.escape(urlparse(p["redirect_uri"]).hostname or "")
        err = f'<p class="err">{html.escape(error)}</p>' if error else ""
        body = f"""<!doctype html><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Authorize access</title>
<style>body{{font:16px system-ui;max-width:30rem;margin:12vh auto;padding:0 1rem;color:#222}}
input[type=password]{{width:100%;padding:.6rem;font:inherit;box-sizing:border-box}}
button{{margin-top:1rem;padding:.6rem 1.2rem;font:inherit;cursor:pointer}}.err{{color:#b00020}}
small{{color:#666}}</style>
<h2>Authorize "{html.escape(client["client_name"])}"</h2>
<p>This will let <b>{dest}</b> use the reviewed MCP server shown by this authorization request on your machine.</p>
{err}
<form method="post" action="/authorize">{hidden}
<label>Two-hour session token<br><input type="password" name="gateway_token" autocomplete="off" autofocus required></label><br>
<small>The current REMOTE_GATEWAY_SSH_TOKEN printed by remote-gateway-test</small><br>
<button type="submit">Authorize</button></form>"""
        return HTMLResponse(body, status_code=status, headers=_PAGE_HEADERS)

    async def authorize(self, request: Request) -> Response:
        if request.method == "GET":
            params = dict(request.query_params)
        else:
            params = dict(parse_qsl((await request.body()).decode(errors="replace"), keep_blank_values=True))
        client, problem = self._check_authz(params)
        if client is None:
            return HTMLResponse(
                f'<!doctype html><meta charset="utf-8"><p>{html.escape(problem)}</p>',
                status_code=400, headers=_PAGE_HEADERS,
            )

        if request.method == "GET":
            return self._page(params, client)

        ip = self._client_ip(request)
        if self._rate_limited(ip):
            logger.warning("OAUTH authorize rate-limited ip=%s", ip)
            return self._page(params, client, "Too many failed attempts. Wait a few minutes.", 429)
        presented = normalize_secret(params.get("gateway_token"))
        from gateway.session import verify_ssh_session
        if verify_ssh_session(presented, self.secret) is None:
            self.fails.append((time.time(), ip))
            logger.warning("OAUTH authorize bad token ip=%s client=%s", ip, params.get("client_id"))
            return self._page(params, client, "That token is not correct.", 401)

        code = secrets.token_urlsafe(32)
        self.codes[_sha(code)] = {
            "client_id": params["client_id"],
            "redirect_uri": params["redirect_uri"],
            "challenge": params["code_challenge"],
            "resource": self._source_of(params.get("resource")),
            "exp": time.time() + CODE_TTL,
        }
        query = {"code": code}
        if params.get("state"):
            query["state"] = params["state"]
        sep = "&" if "?" in params["redirect_uri"] else "?"
        logger.info("OAUTH authorize ok ip=%s client=%s", ip, params["client_id"])
        return RedirectResponse(params["redirect_uri"] + sep + urlencode(query), status_code=302, headers=_NO_STORE)

    # ---- token endpoint -----------------------------------------------------------
    def _issue(
        self, client_id: str, resource: str | None, with_refresh: bool = True,
        grant_exp: float | None = None,
    ) -> dict:
        now = time.time()
        ttl = min(REFRESH_TTL, SHELL_REFRESH_TTL) if resource == "shell" else REFRESH_TTL
        grant_exp = min(grant_exp or now + ttl, now + ttl)
        access_exp = min(now + ACCESS_TTL, grant_exp)
        access = "gat_" + secrets.token_urlsafe(32)
        self.access[_sha(access)] = {"exp": access_exp, "client_id": client_id, "resource": resource}
        out = {"access_token": access, "token_type": "Bearer", "expires_in": max(1, int(access_exp - now)), "scope": "mcp"}
        if with_refresh:
            refresh = "grt_" + secrets.token_urlsafe(32)
            self.refresh[_sha(refresh)] = {"exp": grant_exp, "client_id": client_id, "resource": resource}
            out["refresh_token"] = refresh
        self._save()
        return out

    async def token(self, request: Request) -> Response:
        form = dict(parse_qsl((await request.body()).decode(errors="replace"), keep_blank_values=True))
        grant = form.get("grant_type")
        client_id = form.get("client_id", "")
        if client_id not in self.clients:
            return _oauth_error("invalid_client", "unknown client_id", 401)

        if grant == "authorization_code":
            entry = self.codes.pop(_sha(form.get("code", "")), None)
            if not entry or entry["exp"] <= time.time() or entry["client_id"] != client_id:
                return _oauth_error("invalid_grant", "code is invalid, expired or already used")
            if form.get("redirect_uri") and form["redirect_uri"] != entry["redirect_uri"]:
                return _oauth_error("invalid_grant", "redirect_uri mismatch")
            verifier = form.get("code_verifier", "")
            if not (43 <= len(verifier) <= 128) or not hmac.compare_digest(_pkce_s256(verifier), entry["challenge"]):
                return _oauth_error("invalid_grant", "PKCE verification failed")
            logger.info("OAUTH token issued (code) client=%s resource=%s", client_id, entry["resource"])
            return JSONResponse(self._issue(client_id, entry["resource"]), headers=_NO_STORE)

        if grant == "refresh_token":
            presented = form.get("refresh_token", "")
            entry = self.refresh.get(_sha(presented))
            if not entry or entry["exp"] <= time.time() or entry["client_id"] != client_id:
                return _oauth_error("invalid_grant", "refresh token is invalid or expired")
            out = self._issue(client_id, entry.get("resource"), with_refresh=False, grant_exp=entry["exp"])
            out["refresh_token"] = presented
            logger.info("OAUTH token refreshed client=%s", client_id)
            return JSONResponse(out, headers=_NO_STORE)

        return _oauth_error("unsupported_grant_type")

    # ---- routes ---------------------------------------------------------------
    def routes(self) -> list[Route]:
        wk = "/.well-known"
        return [
            Route(f"{wk}/oauth-protected-resource", self.protected_resource, methods=["GET"]),
            Route(f"{wk}/oauth-protected-resource/{{tail:path}}", self.protected_resource, methods=["GET"]),
            Route(f"{wk}/oauth-authorization-server", self.auth_server_metadata, methods=["GET"]),
            Route(f"{wk}/oauth-authorization-server/{{tail:path}}", self.auth_server_metadata, methods=["GET"]),
            Route(f"{wk}/openid-configuration", self.auth_server_metadata, methods=["GET"]),
            Route("/register", self.register, methods=["POST"]),
            Route("/authorize", self.authorize, methods=["GET", "POST"]),
            Route("/token", self.token, methods=["POST"]),
        ]

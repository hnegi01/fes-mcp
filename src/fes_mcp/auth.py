"""OAuth 2.1 authorization server with a Sisense login bridge.

FastMCP's InMemoryOAuthProvider supplies the protocol plumbing (dynamic client
registration, PKCE, auth codes, access/refresh token issuance and rotation).
This subclass replaces its auto-approve `authorize` step with a real login:

    Claude → /authorize            → redirect to our /login page
    user   → /login (browser)      → Sisense domain + username/password
                                     (or a pasted API token, for SSO instances)
    we     → Sisense login API     → mint/verify the user's Sisense token
    we     → Claude                → authorization code → MCP access token

The user's Sisense credential never leaves this server; every issued MCP
token (access and refresh) maps internally to it. Storage is in-memory:
a restart logs everyone out, which is acceptable for v1.
"""

from __future__ import annotations

import asyncio
import html
import logging
import re
import secrets
import time
from dataclasses import dataclass

from urllib.parse import parse_qs, quote, urlparse

import requests as _requests
from fastmcp.server.auth.auth import AccessToken as FastMCPAccessToken
from fastmcp.server.auth.providers.in_memory import (
    DEFAULT_AUTH_CODE_EXPIRY_SECONDS,
    InMemoryOAuthProvider,
)
from mcp.server.auth.provider import AuthorizationParams, construct_redirect_uri
from mcp.server.auth.settings import ClientRegistrationOptions
from mcp.shared.auth import OAuthClientInformationFull, OAuthToken
from mcp.server.auth.provider import AuthorizationCode, RefreshToken
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, RedirectResponse
from starlette.routing import Route

from .credentials import SisenseCredential

logger = logging.getLogger("fes_mcp.auth")

LOGIN_SESSION_TTL_SECONDS = 600
LOGIN_RATE_LIMIT_ATTEMPTS = 5
LOGIN_RATE_LIMIT_WINDOW_SECONDS = 60


class SisenseLoginError(Exception):
    """User-facing login failure (bad credentials, unreachable domain, ...)."""


@dataclass
class _PendingLogin:
    client: OAuthClientInformationFull
    params: AuthorizationParams
    expires_at: float
    csrf: str
    # Sisense origin from the connector URL's ?target= (already normalized).
    # When set, the login page skips its domain field and this value wins.
    target: str | None = None


class _RateLimiter:
    """Sliding-window limiter keyed by client IP, protecting /login from
    password brute-forcing through this server."""

    def __init__(self, max_attempts: int, window_seconds: float):
        self._max = max_attempts
        self._window = window_seconds
        self._attempts: dict[str, list[float]] = {}

    def allow(self, key: str) -> bool:
        now = time.time()
        attempts = [t for t in self._attempts.get(key, []) if t > now - self._window]
        if len(attempts) >= self._max:
            self._attempts[key] = attempts
            return False
        attempts.append(now)
        self._attempts[key] = attempts
        if len(self._attempts) > 10_000:  # bound memory under address-spraying
            self._attempts = {
                k: v for k, v in self._attempts.items() if v and v[-1] > now - self._window
            }
        return True


def _client_ip(request: Request) -> str:
    # Behind the EC2 reverse proxy the peer address is the proxy; the proxy
    # appends the real client to X-Forwarded-For.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.client.host if request.client else "unknown"


def _target_from_resource(resource: str | None) -> str | None:
    """Extract + normalize the ?target= a client carried in its RFC 8707
    resource indicator (e.g. resource=https://host/mcp?target=https://acme...).
    Any problem → None, which falls back to the login form's domain field."""
    if not resource:
        return None
    try:
        raw = (parse_qs(urlparse(str(resource)).query).get("target") or [""])[0].strip()
        return normalize_domain(raw) if raw else None
    except (SisenseLoginError, ValueError):
        return None


def normalize_domain(raw: str) -> str:
    """'acme.sisense.com/' or 'https://acme.sisense.com' → canonical URL form."""
    domain = raw.strip().rstrip("/")
    if not domain:
        raise SisenseLoginError("Sisense URL is required.")
    if not re.match(r"^https?://", domain):
        domain = f"https://{domain}"
    return domain


def login_with_password(domain: str, username: str, password: str, ssl_verify: bool) -> str:
    """Call Sisense's login API and return the user's bearer token."""
    try:
        resp = _requests.post(
            f"{domain}/api/v1/authentication/login",
            json={"username": username, "password": password},
            verify=ssl_verify,
            timeout=20,
        )
    except _requests.RequestException as exc:
        raise SisenseLoginError(f"Could not reach {domain}: {exc}") from exc

    if resp.status_code in (401, 403):
        raise SisenseLoginError(
            "Sisense rejected the username/password. If your instance uses SSO, "
            "log in with an API token instead."
        )
    if resp.status_code != 200:
        raise SisenseLoginError(f"Sisense login failed (HTTP {resp.status_code}).")

    token = (resp.json() or {}).get("access_token")
    if not token:
        raise SisenseLoginError("Sisense login succeeded but returned no access token.")
    return token


def verify_api_token(domain: str, token: str, ssl_verify: bool) -> None:
    """Confirm an API token works against the instance.

    Goes through the PySisense client — the exact connection path every tool
    call takes — rather than a raw HTTP GET, so quirks the SDK handles (e.g.
    non-SSL instances serve the API on :30845, not :80) can't make
    verification and dispatch disagree about the same credential.
    """
    from pysisense import SisenseClient

    try:
        client = SisenseClient.from_connection(
            domain=domain, token=token, is_ssl=ssl_verify
        )
        # The un-versioned route, as the SDK's own get_my_user uses: on some
        # Sisense versions /api/v1/users/loggedin is parsed as /users/{id}
        # and 422s ("loggedin" is not a 24-hex id).
        resp = client.get("/api/users/loggedin")
    except Exception as exc:  # noqa: BLE001 — network/SDK errors → login error
        raise SisenseLoginError(f"Could not reach {domain}: {exc}") from exc
    if resp is None or resp.status_code != 200:
        status = getattr(resp, "status_code", "no response")
        raise SisenseLoginError(f"Sisense did not accept the API token (HTTP {status}).")


class SisenseAuthProvider(InMemoryOAuthProvider):
    """OAuth provider whose authorization step is a Sisense login."""

    def __init__(self, public_url: str):
        super().__init__(
            base_url=public_url,
            client_registration_options=ClientRegistrationOptions(enabled=True),
        )
        self._pending_logins: dict[str, _PendingLogin] = {}
        # Any issued token string (auth code, access, refresh) → the user's
        # Sisense credential.
        self._credentials: dict[str, SisenseCredential] = {}
        self._login_limiter = _RateLimiter(
            LOGIN_RATE_LIMIT_ATTEMPTS, LOGIN_RATE_LIMIT_WINDOW_SECONDS
        )

    # -- step 1: Claude hits /authorize → send the user to our login page ----

    async def authorize(
        self, client: OAuthClientInformationFull, params: AuthorizationParams
    ) -> str:
        login_id = secrets.token_urlsafe(24)
        self._pending_logins[login_id] = _PendingLogin(
            client=client,
            params=params,
            expires_at=time.time() + LOGIN_SESSION_TTL_SECONDS,
            csrf=secrets.token_urlsafe(16),
            target=_target_from_resource(params.resource),
        )
        self._sweep_pending()
        return f"{str(self.base_url).rstrip('/')}/login?session={login_id}"

    def _sweep_pending(self) -> None:
        now = time.time()
        for key in [k for k, v in self._pending_logins.items() if v.expires_at < now]:
            del self._pending_logins[key]

    # -- step 2: the login page ----------------------------------------------

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        # Replace the SDK's static protected-resource-metadata route with a
        # dynamic one that echoes ?target= back in `resource`, so the target
        # survives the client's discovery hop (it sends the PRM `resource`
        # value as the `resource` param on /authorize).
        routes = [
            r
            for r in routes
            if not str(getattr(r, "path", "")).startswith(
                "/.well-known/oauth-protected-resource"
            )
        ]
        routes.append(
            Route(
                "/.well-known/oauth-protected-resource/mcp",
                self._protected_resource_metadata,
                methods=["GET", "OPTIONS"],
            )
        )
        routes.append(Route("/login", self._login_endpoint, methods=["GET", "POST"]))
        return routes

    async def _protected_resource_metadata(self, request: Request):
        base = str(self.base_url).rstrip("/")
        resource = f"{base}/mcp"
        target = (request.query_params.get("target") or "").strip()
        if target:
            resource = f"{resource}?target={quote(target, safe='')}"
        return JSONResponse(
            {
                "resource": resource,
                "authorization_servers": [base],
                "bearer_methods_supported": ["header"],
            },
            headers={"Access-Control-Allow-Origin": "*"},
        )

    async def _login_endpoint(self, request: Request):
        if request.method == "GET":
            login_id = request.query_params.get("session", "")
            if not self._valid_login_id(login_id):
                return HTMLResponse(_page("This login link is invalid or has expired. "
                                          "Close this window and reconnect from your MCP client."),
                                    status_code=400)
            pending_get = self._pending_logins[login_id]
            return HTMLResponse(
                _page(_form(login_id, pending_get.csrf, target=pending_get.target))
            )

        form = await request.form()
        login_id = str(form.get("session", ""))
        if not self._valid_login_id(login_id):
            return HTMLResponse(_page("This login link is invalid or has expired. "
                                      "Close this window and reconnect from your MCP client."),
                                status_code=400)

        pending_check = self._pending_logins[login_id]
        if not secrets.compare_digest(str(form.get("csrf", "")), pending_check.csrf):
            logger.warning("CSRF token mismatch on /login")
            return HTMLResponse(_page("This request could not be verified. "
                                      "Close this window and reconnect from your MCP client."),
                                status_code=400)

        ip = _client_ip(request)
        if not self._login_limiter.allow(ip):
            logger.warning("Login rate limit exceeded for ip=%s", ip)
            return HTMLResponse(
                _page(_form(login_id, pending_check.csrf,
                            error="Too many login attempts. Wait a minute and try again.",
                            target=pending_check.target)),
                status_code=429,
            )

        try:
            credential = await asyncio.to_thread(
                self._authenticate_form,
                # The connector URL's target wins over anything in the form.
                pending_check.target or str(form.get("domain", "")),
                str(form.get("username", "")),
                str(form.get("password", "")),
                str(form.get("api_token", "")),
                form.get("skip_tls") == "on",
            )
        except SisenseLoginError as exc:
            return HTMLResponse(
                _page(_form(login_id, pending_check.csrf, error=str(exc),
                            target=pending_check.target)),
                status_code=200,
            )

        pending = self._pending_logins.pop(login_id)
        redirect_url = self._issue_code(pending, credential)
        return RedirectResponse(redirect_url, status_code=302)

    def _valid_login_id(self, login_id: str) -> bool:
        self._sweep_pending()
        return bool(login_id) and login_id in self._pending_logins

    @staticmethod
    def _authenticate_form(
        domain: str, username: str, password: str, api_token: str, skip_tls: bool
    ) -> SisenseCredential:
        """Blocking: validate the submitted form against Sisense."""
        domain = normalize_domain(domain)
        ssl_verify = not skip_tls

        if api_token.strip():
            token = api_token.strip()
            verify_api_token(domain, token, ssl_verify)
        elif username.strip() and password:
            token = login_with_password(domain, username.strip(), password, ssl_verify)
        else:
            raise SisenseLoginError(
                "Provide either username and password, or an API token."
            )

        logger.info("Sisense login succeeded for domain=%s", domain)
        return SisenseCredential(domain=domain, token=token, ssl_verify=ssl_verify)

    def _issue_code(self, pending: _PendingLogin, credential: SisenseCredential) -> str:
        """Mint the authorization code for a completed login and build the
        redirect back to the MCP client."""
        client, params = pending.client, pending.params
        code_value = f"fes_auth_code_{secrets.token_hex(16)}"
        self.auth_codes[code_value] = AuthorizationCode(
            code=code_value,
            client_id=client.client_id,
            redirect_uri=params.redirect_uri,
            redirect_uri_provided_explicitly=params.redirect_uri_provided_explicitly,
            scopes=params.scopes or [],
            expires_at=time.time() + DEFAULT_AUTH_CODE_EXPIRY_SECONDS,
            code_challenge=params.code_challenge,
            # RFC 8707: bind the code (and the tokens minted from it) to the
            # resource the client asked for; the proxy enforces the audience.
            resource=params.resource,
        )
        self._credentials[code_value] = credential
        # RFC 9207: identify the issuer in the authorization response so
        # clients can detect authorization-server mix-up attacks.
        return construct_redirect_uri(
            str(params.redirect_uri),
            code=code_value,
            state=params.state,
            iss=str(self.base_url),
        )

    # -- step 3: keep the token→credential map across issuance/rotation ------

    async def exchange_authorization_code(
        self, client: OAuthClientInformationFull, authorization_code: AuthorizationCode
    ) -> OAuthToken:
        credential = self._credentials.pop(authorization_code.code, None)
        token = await super().exchange_authorization_code(client, authorization_code)
        self._map_tokens(token, credential, resource=authorization_code.resource)
        return token

    async def exchange_refresh_token(
        self,
        client: OAuthClientInformationFull,
        refresh_token: RefreshToken,
        scopes: list[str],
    ) -> OAuthToken:
        credential = self._credentials.pop(refresh_token.token, None)
        old_access = self._refresh_to_access_map.get(refresh_token.token)
        # RefreshToken carries no resource; the audience binding survives
        # rotation by copying it from the access token being replaced.
        prior = self.access_tokens.get(old_access) if old_access else None
        prior_resource = getattr(prior, "resource", None)
        token = await super().exchange_refresh_token(client, refresh_token, scopes)
        if old_access:
            self._credentials.pop(old_access, None)
        self._map_tokens(token, credential, resource=prior_resource)
        return token

    async def revoke_token(self, token) -> None:
        self._credentials.pop(token.token, None)
        linked = self._access_to_refresh_map.get(token.token) or self._refresh_to_access_map.get(
            token.token
        )
        if linked:
            self._credentials.pop(linked, None)
        await super().revoke_token(token)

    def _map_tokens(
        self,
        token: OAuthToken,
        credential: SisenseCredential | None,
        resource: str | None = None,
    ) -> None:
        # get_access_token() in the tool layer requires FastMCP's AccessToken
        # subclass; the in-memory base class stores the low-level SDK type.
        # The rebuild also stamps the RFC 8707 audience onto the stored token.
        stored = self.access_tokens.get(token.access_token)
        if stored is not None:
            fields = stored.model_dump(exclude_none=True)
            if resource is not None:
                fields["resource"] = resource
            self.access_tokens[token.access_token] = FastMCPAccessToken(**fields)

        if credential is None:
            logger.warning("No Sisense credential associated with issued token")
            return
        self._credentials[token.access_token] = credential
        if token.refresh_token:
            self._credentials[token.refresh_token] = credential

    # -- lookup used by the tool layer ---------------------------------------

    def credential_for(self, token_str: str) -> SisenseCredential | None:
        return self._credentials.get(token_str)


def make_credential_resolver(provider: SisenseAuthProvider):
    """Resolver for SisenseTool: current request's access token → credential."""

    def resolve() -> SisenseCredential | None:
        from fastmcp.server.dependencies import get_access_token

        token = get_access_token()
        if token is None:
            return None
        return provider.credential_for(token.token)

    return resolve


# -----------------------------------------------------------------------------
# Login page HTML
# -----------------------------------------------------------------------------

def _page(body: str) -> str:
    return f"""<!doctype html>
<html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width, initial-scale=1">
<title>Sisense MCP — Sign in</title>
<style>
  body {{ font-family: -apple-system, Segoe UI, sans-serif; background:#f5f6f8; margin:0;
         display:flex; justify-content:center; align-items:flex-start; min-height:100vh; }}
  .card {{ background:#fff; border-radius:12px; box-shadow:0 2px 12px rgba(0,0,0,.08);
          max-width:420px; width:100%; margin:8vh 16px; padding:32px; }}
  h1 {{ font-size:1.15rem; margin:0 0 4px; }}
  p.sub {{ color:#666; font-size:.85rem; margin:0 0 20px; }}
  label {{ display:block; font-size:.8rem; font-weight:600; margin:14px 0 4px; }}
  input[type=text], input[type=password] {{ width:100%; box-sizing:border-box; padding:9px 10px;
          border:1px solid #ccc; border-radius:6px; font-size:.9rem; }}
  .divider {{ text-align:center; color:#999; font-size:.75rem; margin:18px 0 4px;
             text-transform:uppercase; letter-spacing:.05em; }}
  .check {{ font-size:.8rem; margin-top:16px; display:flex; gap:6px; align-items:center; }}
  .check label {{ margin:0; font-weight:400; }}
  button {{ width:100%; margin-top:20px; padding:10px; border:0; border-radius:6px;
           background:#111; color:#fff; font-size:.95rem; cursor:pointer; }}
  .error {{ background:#fdecec; color:#b3261e; border-radius:6px; padding:10px 12px;
           font-size:.85rem; margin-bottom:12px; }}
  .hint {{ color:#888; font-size:.72rem; margin-top:2px; }}
  .fixed {{ background:#f5f6f8; border:1px solid #e2e4e8; border-radius:6px;
           padding:9px 10px; font-size:.9rem; color:#444; word-break:break-all; }}
</style></head>
<body><div class="card">{body}</div></body></html>"""


def _form(
    login_id: str, csrf: str, error: str | None = None, target: str | None = None
) -> str:
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    if target:
        # Instance fixed by the connector URL's ?target= — show, don't ask.
        domain_html = f"""  <label>Sisense instance</label>
  <div class="fixed">{html.escape(target)}</div>"""
        username_extra = " autofocus"
    else:
        domain_html = """  <label>Sisense URL</label>
  <input type="text" name="domain" placeholder="acme.sisense.com" autofocus>"""
        username_extra = ""
    return f"""
<h1>Connect to Sisense</h1>
<p class="sub">Sign in to let your MCP client run Sisense tools as you.
Your credentials go only to your Sisense instance — the client never sees them.</p>
{error_html}
<form method="post" action="login">
  <input type="hidden" name="session" value="{html.escape(login_id)}">
  <input type="hidden" name="csrf" value="{html.escape(csrf)}">
{domain_html}
  <label>Username</label>
  <input type="text" name="username" placeholder="you@example.com" autocomplete="username"{username_extra}>
  <label>Password</label>
  <input type="password" name="password" autocomplete="current-password">
  <div class="divider">or, if your instance uses SSO</div>
  <label>API token</label>
  <input type="password" name="api_token" placeholder="paste your Sisense API token">
  <div class="hint">Find it in Sisense under your user profile → API token.</div>
  <div class="check">
    <input type="checkbox" name="skip_tls" id="skip_tls">
    <label for="skip_tls">Instance uses a self-signed certificate</label>
  </div>
  <button type="submit">Sign in</button>
</form>"""

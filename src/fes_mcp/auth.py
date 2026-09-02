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

# Absolute refresh-token lifetime. The SDK default is "never expires", which
# would keep a Sisense credential alive in the vault indefinitely for an
# abandoned or stolen refresh token; rotation renews the window.
REFRESH_TOKEN_TTL_SECONDS = 30 * 24 * 3600


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
    # Behind the reverse proxy the peer address is the proxy; the proxy
    # APPENDS the connecting address to X-Forwarded-For, so the rightmost
    # entry is the one our own proxy wrote. The leftmost entries are
    # client-supplied and trivially spoofable — never key rate limits on them.
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",")[-1].strip()
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


def domain_uses_ssl(domain: str) -> bool:
    """Whether a normalized Sisense URL is HTTPS — this, not the certificate
    checkbox, is what PySisense's is_ssl means (it also selects port 30845
    for HTTP instances)."""
    return not domain.lower().startswith("http://")


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
        # Log the detail, show a generic message: connection errors echoed to
        # the browser would let any visitor probe the internal network.
        logger.warning("Sisense login unreachable domain=%s: %s", domain, exc)
        raise SisenseLoginError(f"Could not reach {domain}.") from exc

    if resp.status_code in (401, 403):
        raise SisenseLoginError(
            "Sisense rejected the username/password. If your instance uses SSO, "
            "log in with an API token instead."
        )
    if resp.status_code != 200:
        raise SisenseLoginError(f"Sisense login failed (HTTP {resp.status_code}).")

    try:
        payload = resp.json() or {}
    except ValueError as exc:
        raise SisenseLoginError("Sisense returned an unexpected response.") from exc
    token = payload.get("access_token")
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
            domain=domain,
            token=token,
            # The SDK strips the scheme from `domain` and rebuilds the URL from
            # is_ssl (https:443 vs http:30845) — so is_ssl must mirror the URL
            # scheme, and the self-signed-certificate checkbox maps to
            # verify_ssl (certificate verification), never to is_ssl.
            is_ssl=domain_uses_ssl(domain),
            verify_ssl=ssl_verify,
        )
        # The un-versioned route, as the SDK's own get_my_user uses: on some
        # Sisense versions /api/v1/users/loggedin is parsed as /users/{id}
        # and 422s ("loggedin" is not a 24-hex id).
        resp = client.get("/api/users/loggedin")
    except Exception as exc:  # noqa: BLE001 — network/SDK errors → login error
        logger.warning("Sisense token check unreachable domain=%s: %s", domain, exc)
        raise SisenseLoginError(f"Could not reach {domain}.") from exc
    if resp is None or resp.status_code != 200:
        status = getattr(resp, "status_code", "no response")
        raise SisenseLoginError(f"Sisense did not accept the API token (HTTP {status}).")


class _IssuerNormalizer:
    """ASGI wrapper for the SDK's authorization-server-metadata endpoint:
    rewrites the JSON body's `issuer` to drop the trailing slash pydantic's
    URL type appends (RFC 8414 §3.3 requires a byte-match with the issuer
    identifier the client derived the metadata URL from)."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        import json as _json

        messages: list[dict] = []

        async def capture(message) -> None:
            messages.append(message)

        await self.app(scope, receive, capture)

        start = next((m for m in messages if m["type"] == "http.response.start"), None)
        if start is None:
            for m in messages:
                await send(m)
            return
        body = b"".join(
            m.get("body", b"") for m in messages if m["type"] == "http.response.body"
        )
        try:
            data = _json.loads(body)
            data["issuer"] = str(data["issuer"]).rstrip("/")
            body = _json.dumps(data).encode()
        except Exception:  # noqa: BLE001 — non-JSON body: pass through as-is
            pass
        headers = [
            (k, v) for k, v in start["headers"] if k.lower() != b"content-length"
        ] + [(b"content-length", str(len(body)).encode())]
        await send(
            {"type": "http.response.start", "status": start["status"], "headers": headers}
        )
        await send({"type": "http.response.body", "body": body})


class SisenseAuthProvider(InMemoryOAuthProvider):
    """OAuth provider whose authorization step is a Sisense login."""

    def __init__(self, public_url: str, allowed_origins: tuple[str, ...] | None = None):
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
        # When set, the login page only connects to these Sisense origins —
        # without it, anyone reaching the page can use this server to probe
        # arbitrary hosts (the connect attempt itself is the oracle).
        self._allowed_origins = (
            tuple(normalize_domain(o).lower() for o in allowed_origins)
            if allowed_origins is not None
            else None
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
        self._sweep_expired_tokens()
        return f"{str(self.base_url).rstrip('/')}/login?session={login_id}"

    def _sweep_pending(self) -> None:
        now = time.time()
        for key in [k for k, v in self._pending_logins.items() if v.expires_at < now]:
            del self._pending_logins[key]
        # /authorize has no rate limit; bound memory under a flood by evicting
        # the soonest-to-expire sessions (a real user re-authorizes anyway).
        while len(self._pending_logins) > 10_000:
            oldest = min(
                self._pending_logins, key=lambda k: self._pending_logins[k].expires_at
            )
            del self._pending_logins[oldest]

    def _sweep_expired_tokens(self) -> None:
        """Evict expired state the base class only cleans lazily, so abandoned
        flows can't accumulate Sisense credentials in memory: never-exchanged
        auth codes, and fully dead sessions (expired access token whose refresh
        token is also gone or expired). An expired access token with a live
        refresh token is kept — it carries the RFC 8707 resource binding that
        rotation copies forward."""
        now = time.time()
        for code in [c for c, v in self.auth_codes.items() if v.expires_at < now]:
            del self.auth_codes[code]
            self._credentials.pop(code, None)
        for access_str, access in list(self.access_tokens.items()):
            if not (access.expires_at and access.expires_at < now):
                continue
            refresh_str = self._access_to_refresh_map.get(access_str)
            refresh = self.refresh_tokens.get(refresh_str) if refresh_str else None
            if refresh is not None and (
                refresh.expires_at is None or refresh.expires_at >= now
            ):
                continue  # session still refreshable
            del self.access_tokens[access_str]
            self._credentials.pop(access_str, None)
            if refresh_str:
                self._access_to_refresh_map.pop(access_str, None)
                self._refresh_to_access_map.pop(refresh_str, None)
                self.refresh_tokens.pop(refresh_str, None)
                self._credentials.pop(refresh_str, None)

    # -- step 2: the login page ----------------------------------------------

    def get_routes(self, mcp_path: str | None = None) -> list[Route]:
        routes = super().get_routes(mcp_path)
        # RFC 8414 §3.3: the metadata's `issuer` must byte-match the issuer
        # identifier the client derived it from — no trailing slash. The SDK
        # serializes base_url as a pydantic URL, which appends one; strict
        # clients (MCP Inspector) refuse the mismatch. Wrap the SDK's
        # metadata route and normalize.
        for i, route in enumerate(routes):
            if str(getattr(route, "path", "")).startswith(
                "/.well-known/oauth-authorization-server"
            ):
                routes[i] = Route(
                    route.path,
                    self._patched_as_metadata(route.endpoint),
                    methods=["GET", "OPTIONS"],
                )
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

    @staticmethod
    def _patched_as_metadata(original):
        """Wrap the SDK's authorization-server-metadata endpoint (an ASGI app,
        CORS-wrapped), stripping the trailing slash pydantic appends to the
        issuer."""
        return _IssuerNormalizer(original)

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
            return HTMLResponse(_page(self._render_form(login_id, pending_get)))

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
                _page(self._render_form(
                    login_id, pending_check,
                    error="Too many login attempts. Wait a minute and try again.")),
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
                _page(self._render_form(login_id, pending_check, error=str(exc))),
                status_code=200,
            )

        # pop with a default: a concurrent double-submit must get the
        # invalid-link page, not an unhandled KeyError.
        pending = self._pending_logins.pop(login_id, None)
        if pending is None:
            return HTMLResponse(_page("This login link is invalid or has expired. "
                                      "Close this window and reconnect from your MCP client."),
                                status_code=400)
        redirect_url = self._issue_code(pending, credential)
        return RedirectResponse(redirect_url, status_code=302)

    def _render_form(
        self, login_id: str, pending: _PendingLogin, error: str | None = None
    ) -> str:
        # Identify the requesting OAuth client and where the browser goes
        # afterwards, so a genuine login link sent by someone else reads as
        # what it is (consent-phishing defense; see _form).
        client_label = pending.client.client_name or pending.client.client_id
        redirect_host = urlparse(str(pending.params.redirect_uri)).netloc
        return _form(
            login_id,
            pending.csrf,
            error=error,
            target=pending.target,
            client_label=str(client_label or "An MCP client"),
            redirect_host=redirect_host,
        )

    def _valid_login_id(self, login_id: str) -> bool:
        self._sweep_pending()
        return bool(login_id) and login_id in self._pending_logins

    def _authenticate_form(
        self, domain: str, username: str, password: str, api_token: str, skip_tls: bool
    ) -> SisenseCredential:
        """Blocking: validate the submitted form against Sisense."""
        domain = normalize_domain(domain)
        if self._allowed_origins is not None and domain.lower() not in self._allowed_origins:
            logger.warning("Login refused: %s is not an allowed Sisense origin", domain)
            raise SisenseLoginError(
                "This server is not configured to connect to that Sisense instance."
            )
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
        # clients can detect authorization-server mix-up attacks. Must
        # byte-match the metadata issuer (no trailing slash — RFC 8414 §3.3).
        return construct_redirect_uri(
            str(params.redirect_uri),
            code=code_value,
            state=params.state,
            iss=str(self.base_url).rstrip("/"),
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
        # Read (don't pop) before super(): if the SDK rejects the exchange
        # (e.g. invalid_scope) the refresh token survives, so its credential
        # must too — popping first would strand a credential-less session.
        credential = self._credentials.get(refresh_token.token)
        old_access = self._refresh_to_access_map.get(refresh_token.token)
        # RefreshToken carries no resource; the audience binding survives
        # rotation by copying it from the access token being replaced.
        prior = self.access_tokens.get(old_access) if old_access else None
        prior_resource = getattr(prior, "resource", None)
        token = await super().exchange_refresh_token(client, refresh_token, scopes)
        self._credentials.pop(refresh_token.token, None)
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

        if token.refresh_token:
            # The base class issues refresh tokens with no expiry; stamp the
            # absolute lifetime (load_refresh_token enforces expires_at).
            refresh = self.refresh_tokens.get(token.refresh_token)
            if refresh is not None and refresh.expires_at is None:
                self.refresh_tokens[token.refresh_token] = refresh.model_copy(
                    update={"expires_at": int(time.time() + REFRESH_TOKEN_TTL_SECONDS)}
                )

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
  .consent {{ background:#f0f4fb; border:1px solid #d5e0f0; border-radius:6px;
           padding:10px 12px; font-size:.82rem; color:#334; margin-bottom:16px; }}
</style></head>
<body><div class="card">{body}</div></body></html>"""


def _form(
    login_id: str,
    csrf: str,
    error: str | None = None,
    target: str | None = None,
    client_label: str = "An MCP client",
    redirect_host: str = "",
) -> str:
    error_html = f'<div class="error">{html.escape(error)}</div>' if error else ""
    # Consent-phishing defense: anyone can register an OAuth client and send a
    # victim a genuine link to this page, so the page must say who asked and
    # where the browser goes next — a victim expecting Claude who reads
    # "sent back to attacker.example" has a reason to stop.
    returned_to = (
        f" After signing in, your browser will be sent back to "
        f"<strong>{html.escape(redirect_host)}</strong>."
        if redirect_host
        else ""
    )
    consent_html = (
        f'<div class="consent"><strong>{html.escape(client_label)}</strong> is '
        f"requesting access to run Sisense tools as you.{returned_to} "
        "If you did not start this connection from that app, close this window.</div>"
    )
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
<p class="sub">Your credentials go only to your Sisense instance — the client
never sees them.</p>
{consent_html}{error_html}
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

"""Upstream-injected credentials: the resource server's default auth.

fes_mcp (the resource server) does no end-user authentication itself.
fes-auth — the project's authorization server — owns login and credential
custody, and injects two headers into every proxied MCP call:

    Authorization: Bearer <the user's Sisense API token>
    X-Sisense-Url:  <origin of the target Sisense instance>

Contract with the upstream: a missing or Sisense-rejected credential must
surface as HTTP 401, so an upstream that re-authenticates on 401 self-heals.
Returning None from verify_token produces that 401 via FastMCP's auth
middleware; this server issues no WWW-Authenticate challenge routes of its
own (re-auth is the upstream's job).

Trust is network-level — there is no shared secret between the upstream and
this server — so upstream mode must only be reachable from the upstream's
internal network, never the public edge.
"""

from __future__ import annotations

import asyncio
import logging
import time
from collections import OrderedDict

from fastmcp.server.auth.auth import AccessToken, TokenVerifier

from .auth import SisenseLoginError, normalize_domain, verify_api_token
from .credentials import SisenseCredential
from .settings import Settings

logger = logging.getLogger(__name__)

SISENSE_URL_HEADER = "x-sisense-url"

# Bound on remembered (domain, token) verifications; LRU-evicted like the
# dispatcher's client cache.
MAX_VERIFIED_ENTRIES = 500


class UpstreamTokenVerifier(TokenVerifier):
    """Validates upstream-injected Sisense credentials. No OAuth routes.

    Each new (domain, token) pair is checked once against Sisense
    (GET /api/v1/users/loggedin) and the success is remembered for
    `verify_ttl` seconds. A token revoked on the Sisense side therefore
    turns into an HTTP 401 within at most that TTL. Any verification
    failure — including Sisense being unreachable — is a 401 by design:
    fail closed, let the upstream re-establish the credential.
    """

    def __init__(self, settings: Settings):
        super().__init__()
        self._ssl_verify = settings.sisense_ssl_verify
        self._ttl = settings.verify_ttl
        self._allowed: tuple[str, ...] | None = (
            tuple(normalize_domain(o) for o in settings.allowed_sisense_origins)
            if settings.allowed_sisense_origins is not None
            else None
        )
        self._verified: OrderedDict[tuple[str, str], float] = OrderedDict()

    async def verify_token(self, token: str) -> AccessToken | None:
        from fastmcp.server.dependencies import get_http_headers

        raw_url = (get_http_headers().get(SISENSE_URL_HEADER) or "").strip()
        if not token or not raw_url:
            logger.warning(
                "upstream auth rejected: missing %s",
                f"{SISENSE_URL_HEADER} header" if token else "bearer token",
            )
            return None

        try:
            domain = normalize_domain(raw_url)
        except SisenseLoginError:
            logger.warning("upstream auth rejected: malformed %s", SISENSE_URL_HEADER)
            return None

        if self._allowed is not None and domain not in self._allowed:
            logger.warning("upstream auth rejected: origin not allowlisted domain=%s", domain)
            return None

        if not await self._is_verified(domain, token):
            return None

        return AccessToken(
            token=token,
            client_id=domain,
            scopes=[],
            claims={"domain": domain, "ssl_verify": self._ssl_verify},
        )

    async def _is_verified(self, domain: str, token: str) -> bool:
        key = (domain, token)
        now = time.monotonic()
        expiry = self._verified.get(key)
        if expiry is not None and expiry > now:
            self._verified.move_to_end(key)
            return True
        try:
            await asyncio.to_thread(verify_api_token, domain, token, self._ssl_verify)
        except SisenseLoginError as exc:
            self._verified.pop(key, None)
            logger.warning("upstream auth rejected: domain=%s %s", domain, exc)
            return False
        self._verified[key] = now + self._ttl
        self._verified.move_to_end(key)
        while len(self._verified) > MAX_VERIFIED_ENTRIES:
            self._verified.popitem(last=False)
        return True


def upstream_credential_resolver() -> SisenseCredential | None:
    """Per-request credential from the verified token's claims.

    Runs inside the tool call, where fastmcp exposes the AccessToken minted
    by UpstreamTokenVerifier.
    """
    from fastmcp.server.dependencies import get_access_token

    token = get_access_token()
    if token is None:
        return None
    claims = getattr(token, "claims", None) or {}
    domain = claims.get("domain")
    if not domain:
        return None
    return SisenseCredential(
        domain=domain,
        token=token.token,
        ssl_verify=bool(claims.get("ssl_verify", True)),
    )

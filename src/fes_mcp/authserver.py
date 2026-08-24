"""fes-auth: the authorization server + MCP proxy.

The counterpart of fes-mcp (the resource server). This service owns everything
about *who is calling*:

- OAuth 2.1 authorization server (dynamic client registration, PKCE, refresh)
  via SisenseAuthProvider, including the /login page.
- The credential vault: every issued MCP token maps to the user's Sisense
  credential, in memory (restart = everyone signs in again, by design).
- The /mcp reverse proxy: validates the caller's MCP access token, then
  streams the request to the resource server (FES_MCP_RS_URL) with the
  Sisense credential injected as headers:

      Authorization: Bearer <the user's Sisense API token>
      X-Sisense-Url:  <origin of the user's Sisense instance>

- Self-healing: if the resource server rejects the credential (401), the
  vault entry is revoked and the client is re-challenged to authenticate.

The resource server never learns about OAuth; this service never runs tools.
"""

from __future__ import annotations

import logging
import sys
import time
from contextlib import asynccontextmanager
from urllib.parse import quote

import httpx
from dotenv import load_dotenv
from starlette.applications import Starlette
from starlette.background import BackgroundTask
from starlette.middleware import Middleware
from starlette.requests import Request
from starlette.responses import JSONResponse, PlainTextResponse, Response, StreamingResponse
from starlette.routing import Route

from .auth import SisenseAuthProvider
from .middleware import AccessLogMiddleware
from .settings import REPO_ROOT, Settings

logger = logging.getLogger("fes_mcp.authserver")

# Hop-by-hop / connection-managed headers never forwarded either direction.
_SKIP_REQUEST_HEADERS = {
    "host",
    "content-length",
    "connection",
    "transfer-encoding",
    "keep-alive",
    "upgrade",
    "te",
    "trailers",
    "proxy-authorization",
    "authorization",  # replaced with the injected Sisense credential
}
_SKIP_RESPONSE_HEADERS = {"content-length", "transfer-encoding", "connection", "keep-alive"}


def build_auth_app(settings: Settings, provider: SisenseAuthProvider) -> Starlette:
    if not settings.rs_url:
        raise RuntimeError("fes-auth requires FES_MCP_RS_URL (the resource server URL).")
    rs_mcp_url = f"{settings.rs_url}/mcp"
    public_url = str(provider.base_url).rstrip("/")

    def _challenge(request: Request, presented: bool) -> Response:
        meta = f"{public_url}/.well-known/oauth-protected-resource/mcp"
        target = (request.query_params.get("target") or "").strip()
        if target:
            meta += f"?target={quote(target, safe='')}"
        detail = 'error="invalid_token", ' if presented else ""
        return Response(
            status_code=401,
            headers={"WWW-Authenticate": f'Bearer {detail}resource_metadata="{meta}"'},
        )

    async def proxy_mcp(request: Request) -> Response:
        auth_header = request.headers.get("authorization", "")
        token_str = auth_header[7:].strip() if auth_header.lower().startswith("bearer ") else ""
        if not token_str:
            return _challenge(request, presented=False)

        access = provider.access_tokens.get(token_str)
        if access is None or (access.expires_at and access.expires_at < time.time()):
            return _challenge(request, presented=True)
        credential = provider.credential_for(token_str)
        if credential is None:
            return _challenge(request, presented=True)

        headers = {
            k: v
            for k, v in request.headers.items()
            if k.lower() not in _SKIP_REQUEST_HEADERS
        }
        headers["Authorization"] = f"Bearer {credential.token}"
        headers["X-Sisense-Url"] = credential.domain

        client: httpx.AsyncClient = request.app.state.rs_client
        upstream_req = client.build_request(
            request.method, rs_mcp_url, headers=headers, content=request.stream()
        )
        try:
            upstream = await client.send(upstream_req, stream=True)
        except httpx.HTTPError as exc:
            logger.error("resource server unreachable: %s", exc)
            return JSONResponse({"error": "resource server unreachable"}, status_code=502)

        if upstream.status_code == 401:
            # The resource server rejected the Sisense credential (revoked or
            # expired). Drop the vault entry and re-challenge the client.
            await upstream.aclose()
            token_obj = provider.access_tokens.get(token_str)
            if token_obj is not None:
                await provider.revoke_token(token_obj)
            logger.warning(
                "credential rejected by resource server; revoked session domain=%s",
                credential.domain,
            )
            return _challenge(request, presented=True)

        resp_headers = {
            k: v
            for k, v in upstream.headers.items()
            if k.lower() not in _SKIP_RESPONSE_HEADERS
        }
        return StreamingResponse(
            upstream.aiter_raw(),
            status_code=upstream.status_code,
            headers=resp_headers,
            background=BackgroundTask(upstream.aclose),
        )

    async def root(request: Request) -> PlainTextResponse:
        return PlainTextResponse(
            "Sisense Meta-Management MCP server (authorization server) is running.\n"
            "Add this URL's /mcp path as a connector in your MCP client, "
            "optionally with ?target=https://your-instance.sisense.com.\n"
        )

    async def healthz(request: Request) -> JSONResponse:
        return JSONResponse({"ok": True, "service": "fes-auth"})

    @asynccontextmanager
    async def lifespan(app: Starlette):
        # No read timeout: MCP responses stream (SSE) and can idle for long.
        app.state.rs_client = httpx.AsyncClient(
            timeout=httpx.Timeout(None, connect=10)
        )
        try:
            yield
        finally:
            await app.state.rs_client.aclose()

    routes = list(provider.get_routes())
    routes.append(Route("/mcp", proxy_mcp, methods=["GET", "POST", "DELETE"]))
    routes.append(Route("/", root, methods=["GET"]))
    routes.append(Route("/healthz", healthz, methods=["GET"]))

    return Starlette(
        routes=routes,
        lifespan=lifespan,
        middleware=[Middleware(AccessLogMiddleware)],
    )


def main() -> None:
    import uvicorn

    load_dotenv(REPO_ROOT / ".env")
    settings = Settings.from_env()
    logging.basicConfig(
        level=getattr(logging, settings.log_level, logging.INFO),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )
    public_url = settings.public_url or f"http://{settings.host}:{settings.port}"
    provider = SisenseAuthProvider(public_url)
    app = build_auth_app(settings, provider)
    uvicorn.run(app, host=settings.host, port=settings.port, log_level="warning")


if __name__ == "__main__":
    main()

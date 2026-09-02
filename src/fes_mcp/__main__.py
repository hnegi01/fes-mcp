"""Entry point: `fes-mcp` (or `python -m fes_mcp`) — the resource server.

The authorization server has its own entry point: `fes-auth`
(fes_mcp.authserver). This process only serves tools.
"""

from __future__ import annotations

from dotenv import load_dotenv

from .logsetup import setup_logging
from .settings import REPO_ROOT, Settings
from .server import build_server


def main() -> None:
    # Real environment variables (e.g. from an MCP client's config) win over .env.
    load_dotenv(REPO_ROOT / ".env")
    settings = Settings.from_env()
    setup_logging(settings.log_level, "fes-mcp")

    if settings.auth_mode == "upstream":
        if settings.transport != "http":
            raise SystemExit("FES_MCP_AUTH=upstream requires FES_MCP_TRANSPORT=http.")
        from starlette.middleware import Middleware

        from .middleware import AccessLogMiddleware
        from .upstream import UpstreamTokenVerifier, upstream_credential_resolver

        mcp = build_server(
            settings,
            credential_resolver=upstream_credential_resolver,
            auth=UpstreamTokenVerifier(settings),
        )
        mcp.run(
            transport="http",
            host=settings.host,
            port=settings.port,
            middleware=[Middleware(AccessLogMiddleware)],
        )
        return

    # env mode: local development on the single SISENSE_* credential.
    mcp = build_server(settings)

    if settings.transport == "http":
        from starlette.middleware import Middleware

        from .middleware import AccessLogMiddleware

        mcp.run(
            transport="http",
            host=settings.host,
            port=settings.port,
            middleware=[Middleware(AccessLogMiddleware)],
        )
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

"""Entry point: `fes-mcp` (or `python -m fes_mcp`)."""

from __future__ import annotations

import logging
import sys

from dotenv import load_dotenv

from .settings import REPO_ROOT, Settings
from .server import build_server


def _setup_logging(level: str) -> None:
    # stderr only — stdout belongs to the stdio MCP transport.
    logging.basicConfig(
        level=getattr(logging, level, logging.INFO),
        stream=sys.stderr,
        format="%(asctime)s %(levelname)s %(name)s %(message)s",
    )


def main() -> None:
    # Real environment variables (e.g. from Claude Desktop's config) win over .env.
    load_dotenv(REPO_ROOT / ".env")
    settings = Settings.from_env()
    _setup_logging(settings.log_level)

    if settings.auth_mode == "bearer":
        raise SystemExit("FES_MCP_AUTH=bearer is not implemented; use none or oauth.")

    if settings.auth_mode == "oauth":
        if settings.transport != "http":
            raise SystemExit("FES_MCP_AUTH=oauth requires FES_MCP_TRANSPORT=http.")
        from .auth import SisenseAuthProvider, make_credential_resolver

        public_url = settings.public_url or f"http://{settings.host}:{settings.port}"
        provider = SisenseAuthProvider(public_url)
        mcp = build_server(
            settings,
            credential_resolver=make_credential_resolver(provider),
            auth=provider,
        )
        mcp.run(transport="http", host=settings.host, port=settings.port)
        return

    mcp = build_server(settings)

    if settings.transport == "http":
        mcp.run(transport="http", host=settings.host, port=settings.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

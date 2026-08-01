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

    if settings.auth_mode != "none":
        raise SystemExit(
            f"FES_MCP_AUTH={settings.auth_mode} is not implemented yet; use FES_MCP_AUTH=none."
        )

    mcp = build_server(settings)

    if settings.transport == "http":
        mcp.run(transport="http", host=settings.host, port=settings.port)
    else:
        mcp.run(transport="stdio")


if __name__ == "__main__":
    main()

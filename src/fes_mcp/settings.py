"""Environment-driven configuration for the fes_mcp server.

The server is single-tenant: one Sisense connection, configured entirely from
environment variables. See .env.example for the full reference.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

# Repo root when running from a checkout (the supported v1 deployment mode).
REPO_ROOT = Path(__file__).resolve().parents[2]
DEFAULT_REGISTRY_PATH = REPO_ROOT / "config" / "tools.registry.with_examples.json"
DEFAULT_ALLOWLIST_PATH = REPO_ROOT / "config" / "allowlist.txt"

AUTH_MODES = ("none", "bearer", "oauth")
TRANSPORTS = ("stdio", "http")


def _env_bool(name: str, default: bool) -> bool:
    raw = os.getenv(name)
    if raw is None or raw.strip() == "":
        return default
    return raw.strip().lower() in ("1", "true", "yes", "y", "on")


@dataclass(frozen=True)
class Settings:
    sisense_domain: str | None
    sisense_token: str | None
    sisense_ssl_verify: bool

    auth_mode: str
    bearer_token: str | None

    allowlist: tuple[str, ...]
    allow_mutations: bool

    transport: str
    host: str
    port: int

    registry_path: Path
    log_level: str

    @classmethod
    def from_env(cls) -> "Settings":
        auth_mode = os.getenv("FES_MCP_AUTH", "none").strip().lower()
        if auth_mode not in AUTH_MODES:
            raise ValueError(f"FES_MCP_AUTH must be one of {AUTH_MODES}, got {auth_mode!r}")

        transport = os.getenv("FES_MCP_TRANSPORT", "stdio").strip().lower()
        if transport not in TRANSPORTS:
            raise ValueError(f"FES_MCP_TRANSPORT must be one of {TRANSPORTS}, got {transport!r}")

        raw_tools = os.getenv("FES_MCP_TOOLS", "").strip()
        if raw_tools:
            allowlist = tuple(t.strip() for t in raw_tools.split(",") if t.strip())
        else:
            allowlist = _load_allowlist_file(DEFAULT_ALLOWLIST_PATH)

        return cls(
            sisense_domain=os.getenv("SISENSE_DOMAIN") or None,
            sisense_token=os.getenv("SISENSE_TOKEN") or None,
            sisense_ssl_verify=_env_bool("SISENSE_SSL_VERIFY", True),
            auth_mode=auth_mode,
            bearer_token=os.getenv("FES_MCP_BEARER_TOKEN") or None,
            allowlist=allowlist,
            allow_mutations=_env_bool("FES_MCP_ALLOW_MUTATIONS", False),
            transport=transport,
            host=os.getenv("FES_MCP_HOST", "127.0.0.1"),
            port=int(os.getenv("FES_MCP_PORT", "8200")),
            registry_path=Path(os.getenv("FES_MCP_REGISTRY_PATH") or DEFAULT_REGISTRY_PATH),
            log_level=os.getenv("FES_MCP_LOG_LEVEL", "INFO").upper(),
        )


def _load_allowlist_file(path: Path) -> tuple[str, ...]:
    """Read the curated allowlist file: one tool_id or module name per line,
    blank lines and #-comments ignored."""
    if not path.exists():
        return ()
    entries: list[str] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.split("#", 1)[0].strip()
        if line:
            entries.append(line)
    return tuple(entries)

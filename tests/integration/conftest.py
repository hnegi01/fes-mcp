"""Shared fixtures for integration tests.

Credentials live in ONE place — tests/integration/integration_config.yaml
(gitignored). Copy integration_config.example.yaml to that name and fill it
in. If the file is missing or still holds the example placeholder values,
every integration test is SKIPPED rather than failed, so CI and unconfigured
machines stay green while the suite can still run end-to-end locally.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import pytest
import yaml

from fes_mcp.registry import load_registry, select_tools
from fes_mcp.settings import DEFAULT_ALLOWLIST_PATH, DEFAULT_REGISTRY_PATH, _load_allowlist_file
from tests.conftest import make_settings

_CONFIG_PATH = Path(__file__).resolve().parent / "integration_config.yaml"
_PLACEHOLDER_MARKERS = ("your-real-token", "your-sisense-instance.example.com")


def _load_config() -> dict[str, Any]:
    if not _CONFIG_PATH.exists():
        pytest.skip(
            f"integration_config.yaml not found at {_CONFIG_PATH}. Copy "
            "integration_config.example.yaml and fill in credentials."
        )
    data = yaml.safe_load(_CONFIG_PATH.read_text()) or {}
    tenant = data.get("tenant") or {}
    domain, token = str(tenant.get("domain", "")), str(tenant.get("token", ""))
    if not domain or not token or any(m in domain + token for m in _PLACEHOLDER_MARKERS):
        pytest.skip(
            "integration_config.yaml is not configured (still has placeholder "
            "values). Fill in a real Sisense domain and token."
        )
    return data


@pytest.fixture(scope="session")
def integration_config() -> dict[str, Any]:
    return _load_config()


@pytest.fixture(scope="session")
def tenant(integration_config) -> dict[str, Any]:
    raw = integration_config["tenant"]
    domain = str(raw["domain"]).strip().rstrip("/")
    if "://" not in domain:
        domain = f"https://{domain}"
    return {
        "domain": domain,
        "token": raw["token"],
        "ssl_verify": bool(raw.get("verify_ssl", True)),
    }


@pytest.fixture(scope="session")
def live_settings(tenant):
    """env-mode Settings against the real tenant, curated allowlist,
    mutations OFF — integration tests are read-only by policy."""
    return make_settings(
        sisense_domain=tenant["domain"],
        sisense_token=tenant["token"],
        sisense_ssl_verify=tenant["ssl_verify"],
        registry_path=DEFAULT_REGISTRY_PATH,
        allowlist=_load_allowlist_file(DEFAULT_ALLOWLIST_PATH),
        allow_mutations=False,
    )


@pytest.fixture(scope="session")
def read_surface(live_settings) -> dict[str, dict[str, Any]]:
    registry = load_registry(live_settings.registry_path)
    return select_tools(registry, live_settings.allowlist, allow_mutations=False)


@pytest.fixture(scope="session")
def live_dispatcher(live_settings, read_surface):
    from fes_mcp.dispatcher import SisenseDispatcher

    return SisenseDispatcher(live_settings, read_surface)

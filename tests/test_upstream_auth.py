"""Upstream auth mode: fes_mcp as a pure resource server.

Simulates fes-auth proxying MCP calls with the two injected
headers (Authorization bearer + X-Sisense-Url) against a real HTTP server,
with Sisense token verification mocked.
"""

import socket
import threading
import time

import httpx
import pytest
import uvicorn
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

import fes_mcp.upstream as upstream_mod
from fes_mcp.auth import SisenseLoginError
from fes_mcp.upstream import UpstreamTokenVerifier, upstream_credential_resolver
from fes_mcp.server import build_server
from fes_mcp.settings import DEFAULT_REGISTRY_PATH
from tests.conftest import make_settings

TARGET_A = "https://a.sisense.example.com"
TARGET_B = "https://b.sisense.example.com"


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class EchoDashboard:
    """Fake pysisense.Dashboard that echoes which credential reached the SDK."""

    def __init__(self, api_client):
        self.api_client = api_client

    def get_all_dashboards(self):
        conn = self.api_client["connection"]
        return {"domain": conn["domain"], "token": conn["token"]}


@pytest.fixture
def upstream_env(monkeypatch):
    """Mocked Sisense: from_connection echoes, token verification is a set lookup."""
    import pysisense

    monkeypatch.setattr(
        pysisense.SisenseClient,
        "from_connection",
        staticmethod(lambda **kw: {"connection": kw}),
    )
    monkeypatch.setattr(pysisense, "Dashboard", EchoDashboard)

    state = {"valid_tokens": {"tok-alice", "tok-bob"}, "verify_calls": []}

    def fake_verify(domain, token, ssl_verify):
        state["verify_calls"].append((domain, token))
        if token not in state["valid_tokens"]:
            raise SisenseLoginError("Sisense did not accept the API token (HTTP 401).")

    monkeypatch.setattr(upstream_mod, "verify_api_token", fake_verify)
    return state


def _start_server(settings) -> tuple[str, uvicorn.Server, threading.Thread]:
    mcp = build_server(
        settings,
        credential_resolver=upstream_credential_resolver,
        auth=UpstreamTokenVerifier(settings),
    )
    port = _free_port()
    config = uvicorn.Config(mcp.http_app(), host="127.0.0.1", port=port, log_level="error")
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.05)
    return f"http://127.0.0.1:{port}", server, thread


def _upstream_settings(**overrides):
    defaults = dict(
        auth_mode="upstream",
        transport="http",
        sisense_domain=None,  # upstream mode: no env credential
        sisense_token=None,
        registry_path=DEFAULT_REGISTRY_PATH,
        allowlist=("dashboard.get_all_dashboards",),
    )
    defaults.update(overrides)
    return make_settings(**defaults)


@pytest.fixture
def upstream_server(upstream_env):
    base, server, thread = _start_server(_upstream_settings())
    yield base, upstream_env
    server.should_exit = True
    thread.join(timeout=5)


def _mcp_client(base: str, token: str | None, target: str | None) -> Client:
    headers = {}
    if token is not None:
        headers["Authorization"] = f"Bearer {token}"
    if target is not None:
        headers["X-Sisense-Url"] = target
    return Client(StreamableHttpTransport(f"{base}/mcp", headers=headers))


async def test_injected_headers_run_tool_as_that_credential(upstream_server):
    base, _ = upstream_server
    async with _mcp_client(base, "tok-alice", TARGET_A) as client:
        res = await client.call_tool("dashboard_get_all_dashboards", {})
    assert res.structured_content == {"domain": TARGET_A, "token": "tok-alice"}


async def test_two_users_two_targets_same_server(upstream_server):
    base, _ = upstream_server
    async with _mcp_client(base, "tok-alice", TARGET_A) as client:
        res_a = await client.call_tool("dashboard_get_all_dashboards", {})
    async with _mcp_client(base, "tok-bob", TARGET_B) as client:
        res_b = await client.call_tool("dashboard_get_all_dashboards", {})
    assert res_a.structured_content == {"domain": TARGET_A, "token": "tok-alice"}
    assert res_b.structured_content == {"domain": TARGET_B, "token": "tok-bob"}


async def test_missing_sisense_url_header_is_401(upstream_server):
    base, _ = upstream_server
    with pytest.raises(httpx.HTTPStatusError) as exc:
        async with _mcp_client(base, "tok-alice", None) as client:
            await client.call_tool("dashboard_get_all_dashboards", {})
    assert exc.value.response.status_code == 401


async def test_missing_bearer_is_401(upstream_server):
    base, _ = upstream_server
    with pytest.raises(httpx.HTTPStatusError) as exc:
        async with _mcp_client(base, None, TARGET_A) as client:
            await client.call_tool("dashboard_get_all_dashboards", {})
    assert exc.value.response.status_code == 401


async def test_sisense_rejected_token_is_401(upstream_server):
    base, _ = upstream_server
    with pytest.raises(httpx.HTTPStatusError) as exc:
        async with _mcp_client(base, "tok-revoked", TARGET_A) as client:
            await client.call_tool("dashboard_get_all_dashboards", {})
    assert exc.value.response.status_code == 401


async def test_origin_allowlist_enforced(upstream_env):
    base, server, thread = _start_server(
        _upstream_settings(allowed_sisense_origins=(TARGET_A,))
    )
    try:
        async with _mcp_client(base, "tok-alice", TARGET_A) as client:
            res = await client.call_tool("dashboard_get_all_dashboards", {})
        assert res.structured_content["domain"] == TARGET_A
        with pytest.raises(httpx.HTTPStatusError) as exc:
            async with _mcp_client(base, "tok-bob", TARGET_B) as client:
                await client.call_tool("dashboard_get_all_dashboards", {})
        assert exc.value.response.status_code == 401
    finally:
        server.should_exit = True
        thread.join(timeout=5)


async def test_ttl_revocation_turns_into_401(upstream_env):
    # TTL 0 = re-verify against Sisense on every request, so a server-side
    # revocation surfaces as a 401 on the very next call.
    base, server, thread = _start_server(_upstream_settings(verify_ttl=0))
    try:
        async with _mcp_client(base, "tok-alice", TARGET_A) as client:
            await client.call_tool("dashboard_get_all_dashboards", {})
        upstream_env["valid_tokens"].discard("tok-alice")  # revoked on Sisense side
        with pytest.raises(httpx.HTTPStatusError) as exc:
            async with _mcp_client(base, "tok-alice", TARGET_A) as client:
                await client.call_tool("dashboard_get_all_dashboards", {})
        assert exc.value.response.status_code == 401
    finally:
        server.should_exit = True
        thread.join(timeout=5)


async def test_verification_is_cached_within_ttl(upstream_server):
    base, env = upstream_server
    async with _mcp_client(base, "tok-alice", TARGET_A) as client:
        await client.call_tool("dashboard_get_all_dashboards", {})
        await client.call_tool("dashboard_get_all_dashboards", {})
    alice_verifies = [c for c in env["verify_calls"] if c[1] == "tok-alice"]
    assert len(alice_verifies) == 1  # verified once, cached for the TTL

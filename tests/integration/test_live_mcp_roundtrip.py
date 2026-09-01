"""Live MCP round-trips: a real client against a real server against a real
Sisense box — including the upstream-auth trust path, whose token verification
(GET /api/v1/users/loggedin) only unit tests with mocks otherwise."""

from __future__ import annotations

import socket
import threading
import time

import httpx
import pytest
from fastmcp import Client
from fastmcp.client.transports import StreamableHttpTransport

from fes_mcp.server import build_server
from fes_mcp.upstream import UpstreamTokenVerifier, upstream_credential_resolver
from tests.conftest import make_settings

pytestmark = pytest.mark.integration


def _serve(mcp):
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        port = s.getsockname()[1]
    import uvicorn

    server = uvicorn.Server(
        uvicorn.Config(mcp.http_app(), host="127.0.0.1", port=port, log_level="error")
    )
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()
    deadline = time.time() + 10
    while not server.started:
        if time.time() > deadline:
            raise RuntimeError("uvicorn did not start")
        time.sleep(0.05)
    return f"http://127.0.0.1:{port}", server, thread


@pytest.fixture
def env_mode_server(live_settings):
    mcp = build_server(live_settings)
    base, server, thread = _serve(mcp)
    yield base
    server.should_exit = True
    thread.join(timeout=5)


@pytest.fixture
def upstream_mode_server(live_settings, tenant):
    settings = make_settings(
        auth_mode="upstream",
        transport="http",
        sisense_domain=None,
        sisense_token=None,
        sisense_ssl_verify=tenant["ssl_verify"],
        registry_path=live_settings.registry_path,
        allowlist=live_settings.allowlist,
    )
    mcp = build_server(
        settings,
        credential_resolver=upstream_credential_resolver,
        auth=UpstreamTokenVerifier(settings),
    )
    base, server, thread = _serve(mcp)
    yield base
    server.should_exit = True
    thread.join(timeout=5)


async def test_env_mode_roundtrip(env_mode_server, read_surface):
    async with Client(f"{env_mode_server}/mcp") as client:
        tools = await client.list_tools()
        assert len(tools) == len(read_surface)
        res = await client.call_tool("dashboard_get_dashboards", {"fields": ["oid", "title"]})
        assert res.is_error is False


async def test_upstream_mode_verifies_real_token(upstream_mode_server, tenant):
    """The trust path end-to-end: injected headers verified against the REAL
    Sisense instance, then the tool runs as that credential."""
    transport = StreamableHttpTransport(
        f"{upstream_mode_server}/mcp",
        headers={
            "Authorization": f"Bearer {tenant['token']}",
            "X-Sisense-Url": tenant["domain"],
        },
    )
    async with Client(transport) as client:
        res = await client.call_tool("dashboard_get_dashboards", {"fields": ["oid"]})
        assert res.is_error is False


async def test_upstream_mode_rejects_garbage_token(upstream_mode_server, tenant):
    transport = StreamableHttpTransport(
        f"{upstream_mode_server}/mcp",
        headers={
            "Authorization": "Bearer not-a-real-sisense-token",
            "X-Sisense-Url": tenant["domain"],
        },
    )
    with pytest.raises(httpx.HTTPStatusError) as exc:
        async with Client(transport) as client:
            await client.call_tool("dashboard_get_dashboards", {})
    assert exc.value.response.status_code == 401

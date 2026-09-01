import pytest
from fastmcp import Client, FastMCP

from fes_mcp.dispatcher import SisenseDispatcher
from fes_mcp.server import build_tool


@pytest.fixture
def mcp(settings, sample_tools, fake_sdk):
    dispatcher = SisenseDispatcher(settings, sample_tools)
    server = FastMCP(name="test")
    for entry in sample_tools.values():
        server.add_tool(build_tool(entry, dispatcher))
    return server


async def test_list_tools_names_and_annotations(mcp):
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
    assert set(tools) == {
        "dashboard_get_all_dashboards",
        "dashboard_get_dashboard_by_id",
        "dashboard_delete_dashboard",
    }
    read = tools["dashboard_get_all_dashboards"]
    write = tools["dashboard_delete_dashboard"]
    assert read.annotations.readOnlyHint is True
    assert read.annotations.destructiveHint is False
    assert write.annotations.readOnlyHint is False
    assert write.annotations.destructiveHint is True
    assert read.meta["tool_id"] == "dashboard.get_all_dashboards"


async def test_schema_passthrough(mcp):
    async with Client(mcp) as client:
        tools = {t.name: t for t in await client.list_tools()}
    schema = tools["dashboard_get_dashboard_by_id"].inputSchema
    assert schema["properties"]["dashboard_id"]["type"] == "string"
    assert schema["required"] == ["dashboard_id"]


async def test_call_tool_success(mcp):
    async with Client(mcp) as client:
        res = await client.call_tool("dashboard_get_all_dashboards", {})
    assert res.is_error is False
    assert res.structured_content == {"result": [{"oid": "d1", "title": "Sales"}]}


async def test_call_tool_error_is_mcp_error(mcp):
    async with Client(mcp) as client:
        res = await client.call_tool(
            "dashboard_get_dashboard_by_id", {"dashboard_id": 42}, raise_on_error=False
        )
    assert res.is_error is True
    assert "not of type 'string'" in res.content[0].text

"""Human approval via elicitation for mutating tools, and mutates-flag corrections."""

import pytest
from fastmcp import Client, FastMCP
from fastmcp.client.elicitation import ElicitResult

from tests.conftest import make_settings
from fes_mcp.dispatcher import SisenseDispatcher
from fes_mcp.server import build_tool


def test_registry_applies_mutates_overrides(tmp_path):
    import json

    from fes_mcp.registry import load_registry

    rows = [
        {
            "tool_id": "queries.elasticube_run_jaql_query",
            "module": "queries",
            "class": "Queries",
            "method": "elasticube_run_jaql_query",
            "mutates": True,  # heuristic artifact — override corrects it
            "parameters": {},
        },
    ]
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(rows))
    tools = load_registry(path)
    assert tools["queries.elasticube_run_jaql_query"]["mutates"] is False


def test_stale_override_keys_warn(tmp_path, caplog):
    # An override whose tool_id no longer exists must not fail silently.
    import json
    import logging

    from fes_mcp.registry import load_registry

    rows = [
        {
            "tool_id": "dashboard.get_all_dashboards",
            "module": "dashboard",
            "class": "Dashboard",
            "method": "get_all_dashboards",
            "mutates": False,
            "parameters": {},
        },
    ]
    path = tmp_path / "registry.json"
    path.write_text(json.dumps(rows))
    with caplog.at_level(logging.WARNING, logger="fes_mcp.registry"):
        load_registry(path)
    assert "MUTATES_OVERRIDES keys not found" in caplog.text
    assert "datamodel.load_datamodel" in caplog.text


# ---------------------------------------------------------------------------
# Elicitation gate on mutating tools (mocked SDK, in-memory MCP client)
# ---------------------------------------------------------------------------

FOLDER_TOOL = {
    "folder.delete_folder": {
        "tool_id": "folder.delete_folder",
        "module": "folder",
        "class": "Folder",
        "method": "delete_folder",
        "description": "Delete a folder by OID.",
        "mutates": True,
        "parameters": {
            "type": "object",
            "properties": {"folder_id": {"type": "string"}},
            "required": ["folder_id"],
        },
    }
}


class FakeFolder:
    """Stands in for pysisense.Folder; records deletions."""

    deleted: list = []

    def __init__(self, api_client):
        self.api_client = api_client

    def delete_folder(self, folder_id):
        FakeFolder.deleted.append(folder_id)
        return {"status": "deleted", "oid": folder_id}


@pytest.fixture
def confirm_mcp(fake_sdk, monkeypatch):
    import pysisense

    FakeFolder.deleted = []
    monkeypatch.setattr(pysisense, "Folder", FakeFolder, raising=False)
    settings = make_settings(allow_mutations=True)
    dispatcher = SisenseDispatcher(settings, FOLDER_TOOL)
    server = FastMCP(name="test")
    for entry in FOLDER_TOOL.values():
        server.add_tool(build_tool(entry, dispatcher))
    return server


async def test_mutation_asks_and_runs_on_approval(confirm_mcp):
    asked = []

    async def approve(message, response_type, params, context):
        asked.append(message)
        return {"value": "proceed"}

    async with Client(confirm_mcp, elicitation_handler=approve) as client:
        res = await client.call_tool("folder_delete_folder", {"folder_id": "f1"})
    assert asked and "folder_delete_folder" in asked[0]
    assert res.structured_content == {"status": "deleted", "oid": "f1"}
    assert FakeFolder.deleted == ["f1"]


async def test_confirmation_discloses_arguments(confirm_mcp):
    asked = []

    async def approve(message, response_type, params, context):
        asked.append(message)
        return {"value": "proceed"}

    async with Client(confirm_mcp, elicitation_handler=approve) as client:
        await client.call_tool("folder_delete_folder", {"folder_id": "f-oid-42"})
    assert "f-oid-42" in asked[0]  # the human confirms the operation, not just the name


async def test_mutation_aborts_on_abort_choice(confirm_mcp):
    async def choose_abort(message, response_type, params, context):
        return {"value": "abort"}

    async with Client(confirm_mcp, elicitation_handler=choose_abort) as client:
        res = await client.call_tool("folder_delete_folder", {"folder_id": "f1"})
    payload = res.structured_content
    assert payload["aborted"] is True
    assert payload["mutated"] is False
    assert FakeFolder.deleted == []


async def test_mutation_aborts_on_decline(confirm_mcp):
    async def decline(message, response_type, params, context):
        return ElicitResult(action="decline")

    async with Client(confirm_mcp, elicitation_handler=decline) as client:
        res = await client.call_tool("folder_delete_folder", {"folder_id": "f1"})
    assert res.structured_content["aborted"] is True
    assert FakeFolder.deleted == []


async def test_mutation_runs_directly_without_capability(confirm_mcp):
    # Client without elicitation (Claude Desktop, claude.ai): the call just
    # runs — the client's own tool-approval UI is the safeguard.
    async with Client(confirm_mcp) as client:
        res = await client.call_tool("folder_delete_folder", {"folder_id": "f1"})
    assert res.structured_content == {"status": "deleted", "oid": "f1"}
    assert FakeFolder.deleted == ["f1"]


async def test_read_tool_never_asks(settings, sample_tools, fake_sdk):
    async def deny_everything(message, response_type, params, context):
        raise AssertionError("read tool must not elicit")

    dispatcher = SisenseDispatcher(settings, sample_tools)
    server = FastMCP(name="test")
    for entry in sample_tools.values():
        server.add_tool(build_tool(entry, dispatcher))
    async with Client(server, elicitation_handler=deny_everything) as client:
        res = await client.call_tool("dashboard_get_all_dashboards", {})
    assert res.structured_content == {"result": [{"oid": "d1", "title": "Sales"}]}

"""Field-description overlay + SDK payload contracts (pysisense >= 1.1.0).

Structure (properties/required) now comes from the SDK's TypedDict contracts
via the generator; this project only overlays per-field descriptions. Drift
guards keep the overlay honest against the installed SDK, and the dispatcher
tests prove the SDK-derived required fields are enforced before any call.
"""

import inspect
import logging

import pytest

from fes_mcp.dispatcher import DispatchError, SisenseDispatcher
from fes_mcp.registry import _apply_field_descriptions, load_registry
from fes_mcp.schema_patches import FIELD_DESCRIPTIONS
from fes_mcp.settings import DEFAULT_REGISTRY_PATH
from tests.conftest import make_settings


@pytest.fixture(scope="module")
def registry():
    return load_registry(DEFAULT_REGISTRY_PATH)


# --- drift guards against the installed SDK ---------------------------------


def test_described_fields_exist_in_sdk_contracts(registry):
    """Every field we describe must exist in the generated (SDK-derived)
    schema — otherwise the overlay is describing a dropped field."""
    for tool_id, params in FIELD_DESCRIPTIONS.items():
        entry = registry[tool_id]  # KeyError = tool gone from registry
        for param, fields in params.items():
            props = entry["parameters"]["properties"][param].get("properties", {})
            assert props, f"{tool_id}.{param}: SDK contract has no properties"
            for field in fields:
                assert field in props, (
                    f"{tool_id}.{param}: described field {field!r} not in the "
                    f"SDK contract — delete its description"
                )


def test_overlay_produces_no_warnings_on_installed_registry(caplog):
    with caplog.at_level(logging.WARNING, logger="fes_mcp.registry"):
        load_registry(DEFAULT_REGISTRY_PATH)
    assert "FIELD_DESCRIPTIONS" not in caplog.text


def test_overlay_never_defines_structure():
    """This module's contract: descriptions only — plain strings, never
    schema fragments (types/required/properties)."""
    for params in FIELD_DESCRIPTIONS.values():
        for fields in params.values():
            for value in fields.values():
                assert isinstance(value, str)


# --- SDK-contract schemas as advertised ---------------------------------------


def test_create_user_schema_from_sdk_contract(registry):
    schema = registry["access_management.create_user"]["parameters"]["properties"]["user_data"]
    assert schema["type"] == "object"
    assert schema["required"] == ["email", "role"]
    assert len(schema["properties"]) >= 8  # SDK contract is richer than our old patch
    # overlay attached our description to a contract field
    assert schema["properties"]["email"]["description"] == "The user's email address."


def test_update_user_patch_semantics(registry):
    schema = registry["access_management.update_user"]["parameters"]["properties"]["user_data"]
    assert schema["required"] == []  # PATCH semantics: only fields to change


def test_connection_params_union_merged(registry):
    schema = registry["datamodel.generate_connections_payload"]["parameters"]["properties"][
        "connection_params"
    ]
    assert schema["type"] == "object"
    assert len(schema["properties"]) >= 20  # merged across the 4 provider payloads


# --- enforcement through the dispatcher --------------------------------------


class FakeAccessManagement:
    def __init__(self, api_client):
        self.api_client = api_client

    def create_user(self, user_data):
        return {"created": user_data}


@pytest.fixture
def user_dispatcher(registry, fake_sdk, monkeypatch):
    import pysisense

    monkeypatch.setattr(pysisense, "AccessManagement", FakeAccessManagement, raising=False)
    tools = {"access_management.create_user": registry["access_management.create_user"]}
    return SisenseDispatcher(make_settings(allow_mutations=True), tools)


def test_incomplete_user_data_rejected_before_sdk(user_dispatcher):
    with pytest.raises(DispatchError, match="'(email|role)' is a required property"):
        user_dispatcher.invoke(
            "access_management.create_user",
            {"user_data": {"firstName": "Himanshu", "lastName": "Negi"}},
        )
    with pytest.raises(DispatchError, match="'role' is a required property"):
        user_dispatcher.invoke(
            "access_management.create_user",
            {"user_data": {"email": "h@acme.com", "firstName": "Himanshu"}},
        )


def test_complete_user_data_dispatches(user_dispatcher):
    payload = {"email": "h@acme.com", "role": "Viewer", "firstName": "Himanshu"}
    result = user_dispatcher.invoke(
        "access_management.create_user", {"user_data": payload}
    )
    assert result == {"created": payload}


async def test_enriched_schema_reaches_mcp_clients(registry, fake_sdk, monkeypatch):
    # list_tools must advertise the SDK contract + our descriptions.
    import pysisense

    from fastmcp import Client, FastMCP

    from fes_mcp.server import build_tool

    monkeypatch.setattr(pysisense, "AccessManagement", FakeAccessManagement, raising=False)
    entry = registry["access_management.create_user"]
    d = SisenseDispatcher(make_settings(allow_mutations=True), {entry["tool_id"]: entry})
    server = FastMCP(name="test")
    server.add_tool(build_tool(entry, d))
    async with Client(server) as client:
        tools = await client.list_tools()
    inner = tools[0].inputSchema["properties"]["user_data"]
    assert inner["required"] == ["email", "role"]
    assert inner["properties"]["role"]["description"]


# --- drift-warning behavior ----------------------------------------------------


def test_dropped_field_warns_and_skips(caplog):
    entry = {
        "parameters": {
            "type": "object",
            "properties": {
                "user_data": {
                    "type": "object",
                    "properties": {"email": {"type": "string"}},  # no "role" etc.
                }
            },
            "required": [],
        }
    }
    with caplog.at_level(logging.WARNING, logger="fes_mcp.registry"):
        _apply_field_descriptions("access_management.create_user", entry)
    assert "drift" in caplog.text
    assert entry["parameters"]["properties"]["user_data"]["properties"]["email"][
        "description"
    ] == "The user's email address."

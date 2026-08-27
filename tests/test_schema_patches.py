"""Schema patches for dict-typed params: drift guards + behavior.

The drift guards introspect the INSTALLED pysisense: if a version bump
renames a method/parameter or drops a documented field, these fail before a
stale schema is ever advertised to a client.
"""

import inspect
import logging

import pytest

from fes_mcp.dispatcher import DispatchError, SisenseDispatcher
from fes_mcp.registry import _apply_schema_patches, load_registry
from fes_mcp.schema_patches import SCHEMA_PATCHES
from fes_mcp.settings import DEFAULT_REGISTRY_PATH
from tests.conftest import make_settings


@pytest.fixture(scope="module")
def registry():
    return load_registry(DEFAULT_REGISTRY_PATH)


# --- drift guards against the installed SDK ---------------------------------


def test_patched_methods_and_params_exist_in_installed_sdk(registry):
    import pysisense

    for tool_id, params in SCHEMA_PATCHES.items():
        entry = registry[tool_id]  # KeyError = tool gone from registry
        cls = getattr(pysisense, entry["class"])
        method = getattr(cls, entry["method"])
        sig_params = inspect.signature(method).parameters
        for param in params:
            assert param in sig_params, (
                f"{tool_id}: patched parameter {param!r} no longer in the "
                f"installed SDK signature — update or delete the patch"
            )


def test_patched_fields_still_documented_in_sdk(registry):
    import pysisense

    for tool_id, params in SCHEMA_PATCHES.items():
        entry = registry[tool_id]
        doc = inspect.getdoc(getattr(getattr(pysisense, entry["class"]), entry["method"])) or ""
        for param, inner in params.items():
            for field in inner.get("properties", {}):
                assert field in doc, (
                    f"{tool_id}.{param}: field {field!r} not mentioned in the "
                    f"installed SDK docstring — contract drifted, fix the patch"
                )


def test_no_patch_is_stale_on_installed_registry(caplog):
    with caplog.at_level(logging.WARNING, logger="fes_mcp.registry"):
        load_registry(DEFAULT_REGISTRY_PATH)
    assert "SCHEMA_PATCHES" not in caplog.text


# --- advertised schema -------------------------------------------------------


def test_create_user_schema_declares_required_fields(registry):
    schema = registry["access_management.create_user"]["parameters"]["properties"]["user_data"]
    assert set(schema["required"]) == {"email", "role"}
    assert {"email", "firstName", "lastName", "role", "groups"} <= schema["properties"].keys()
    assert schema["additionalProperties"] is True
    assert schema.get("description")  # generated docstring text preserved


def test_update_user_has_properties_but_no_required(registry):
    schema = registry["access_management.update_user"]["parameters"]["properties"]["user_data"]
    assert schema["required"] == []
    assert "userName" in schema["properties"]


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
    # both email and role are missing; jsonschema names the first one
    with pytest.raises(DispatchError, match="'(email|role)' is a required property"):
        user_dispatcher.invoke(
            "access_management.create_user",
            {"user_data": {"firstName": "Himanshu", "lastName": "Negi"}},
        )
    # email supplied, role still missing → the error names role
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


def test_snapshot_without_plugins_key_rejected(registry, fake_sdk):
    tools = {"plugins.restore_snapshot": registry["plugins.restore_snapshot"]}
    d = SisenseDispatcher(make_settings(allow_mutations=True), tools)
    with pytest.raises(DispatchError, match="'plugins' is a required property"):
        d.invoke("plugins.restore_snapshot", {"snapshot": {"enabled": ["foo"]}})


async def test_enriched_schema_reaches_mcp_clients(registry, fake_sdk):
    # The point of the patch layer: list_tools must advertise the inner fields.
    from fastmcp import Client, FastMCP

    from fes_mcp.server import build_tool

    entry = registry["access_management.create_user"]
    d = SisenseDispatcher(make_settings(allow_mutations=True), {entry["tool_id"]: entry})
    server = FastMCP(name="test")
    server.add_tool(build_tool(entry, d))
    async with Client(server) as client:
        tools = await client.list_tools()
    inner = tools[0].inputSchema["properties"]["user_data"]
    assert inner["required"] == ["email", "role"]
    assert "role" in inner["properties"]


# --- stale-patch self-retirement ---------------------------------------------


def test_stale_patch_warns_and_keeps_generated_schema(caplog):
    entry = {
        "parameters": {
            "type": "object",
            "properties": {
                "user_data": {"type": "object", "properties": {"already": {"type": "string"}}}
            },
            "required": [],
        }
    }
    with caplog.at_level(logging.WARNING, logger="fes_mcp.registry"):
        _apply_schema_patches("access_management.create_user", entry)
    assert "stale" in caplog.text
    assert entry["parameters"]["properties"]["user_data"]["properties"] == {
        "already": {"type": "string"}
    }

"""Captured output schemas: inference invariants, registry loading, and the
tool advertising them.

The schemas exist to inform clients, never to reject a result: every object
is open (additionalProperties true, no required) and every leaf nullable, so
data captured on one Sisense instance cannot fail validation on another.
"""

import importlib
import json

import jsonschema
import pytest

from fes_mcp.registry import load_registry
from fes_mcp.server import build_tool

capture = importlib.import_module("scripts.06_capture_output_schemas")


def _assert_permissive(schema):
    assert schema.get("required") in (None, [])
    types = schema.get("type")
    if types != "object":  # top level is the one plain-object node
        assert isinstance(types, list) and "null" in types
    for sub in schema.get("properties", {}).values():
        _assert_permissive(sub)
    if "items" in schema and schema["items"]:
        _assert_permissive(schema["items"])


def test_infer_dict_result_is_open_and_nullable():
    result = {"title": "Sales", "oid": "a" * 24, "shares": [{"userId": "u1"}], "n": 3}
    schema = capture.schema_for_result(result)
    assert schema["type"] == "object"
    assert schema["additionalProperties"] is True
    assert set(schema["properties"]) == {"title", "oid", "shares", "n"}
    _assert_permissive(schema)
    jsonschema.validate(result, schema)
    # A different instance: missing keys, extra keys, nulls — still valid.
    jsonschema.validate({"title": None, "extra": [1, 2]}, schema)


def test_infer_list_result_wraps_like_the_server():
    result = [{"name": "g1"}, {"name": None, "roleId": "r"}]
    schema = capture.schema_for_result(result)
    assert schema["type"] == "object"
    assert set(schema["properties"]) == {"result"}
    items = schema["properties"]["result"]["items"]
    assert set(items["properties"]) == {"name", "roleId"}
    jsonschema.validate({"result": result}, schema)
    jsonschema.validate({"result": []}, schema)


def test_merge_unions_types_and_properties():
    a = capture.infer_schema({"x": 1})
    b = capture.infer_schema({"x": "s", "y": True})
    merged = capture.merge_schemas(a, b)
    assert set(merged["properties"]) == {"x", "y"}
    assert set(merged["properties"]["x"]["type"]) == {"number", "string", "null"}


def test_large_maps_omit_data_keyed_properties():
    schema = capture.infer_schema({f"group-{i}": [1] for i in range(50)})
    assert "properties" not in schema  # data-keyed map: no key leakage


def test_load_registry_attaches_output_schemas(tmp_path, caplog):
    rows = [{"tool_id": "a.b", "module": "a", "class": "A", "method": "b"}]
    (tmp_path / "reg.json").write_text(json.dumps(rows))
    (tmp_path / "output_schemas.json").write_text(json.dumps({
        "schemas": {
            "a.b": {"type": "object", "additionalProperties": True},
            "gone.tool": {"type": "object"},
        }
    }))
    tools = load_registry(tmp_path / "reg.json")
    assert tools["a.b"]["output_schema"] == {"type": "object", "additionalProperties": True}
    assert "gone.tool" in caplog.text  # drift warning, not a crash


def test_load_registry_without_output_schemas_file(tmp_path):
    rows = [{"tool_id": "a.b", "module": "a", "class": "A", "method": "b"}]
    (tmp_path / "reg.json").write_text(json.dumps(rows))
    assert "output_schema" not in load_registry(tmp_path / "reg.json")["a.b"]


@pytest.fixture
def entry():
    return {
        "tool_id": "dashboard.get_dashboards",
        "module": "dashboard",
        "method": "get_dashboards",
        "class": "Dashboard",
        "mutates": False,
        "parameters": {"type": "object", "properties": {}, "required": []},
        "output_schema": {
            "type": "object",
            "properties": {"result": {"type": ["array", "null"]}},
            "additionalProperties": True,
        },
    }


def test_build_tool_advertises_output_schema(entry, settings):
    from fes_mcp.dispatcher import SisenseDispatcher

    dispatcher = SisenseDispatcher(settings, {entry["tool_id"]: entry})
    tool = build_tool(entry, dispatcher)
    assert tool.output_schema == entry["output_schema"]

    entry.pop("output_schema")
    assert build_tool(entry, dispatcher).output_schema is None

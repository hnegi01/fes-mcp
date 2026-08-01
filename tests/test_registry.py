import json

import pytest

from fes_mcp.registry import load_registry, select_tools
from fes_mcp.settings import DEFAULT_REGISTRY_PATH


@pytest.fixture(scope="module")
def real_registry():
    return load_registry(DEFAULT_REGISTRY_PATH)


def test_load_real_registry(real_registry):
    assert len(real_registry) > 100
    entry = real_registry["dashboard.get_all_dashboards"]
    assert entry["module"] == "dashboard"
    assert entry["class"] == "Dashboard"
    assert entry["mutates"] is False
    assert entry["parameters"]["type"] == "object"


def test_load_normalizes_and_skips_bad_rows(tmp_path):
    rows = [
        {"tool_id": "a.b", "module": "a", "class": "A", "method": "b"},  # no params
        {"tool_id": "broken", "module": "a"},  # missing method/class -> skipped
        {"tool_id": "a.c", "module": "a", "class": "A", "method": "c",
         "mutates": True, "parameters": {"properties": {"x": {"type": "string"}}}},
    ]
    p = tmp_path / "reg.json"
    p.write_text(json.dumps(rows))
    tools = load_registry(p)
    assert set(tools) == {"a.b", "a.c"}
    assert tools["a.b"]["parameters"] == {"type": "object", "properties": {}, "required": []}
    assert tools["a.c"]["mutates"] is True
    assert tools["a.c"]["parameters"]["required"] == []


def test_missing_registry_file(tmp_path):
    with pytest.raises(RuntimeError, match="not found"):
        load_registry(tmp_path / "nope.json")


def test_select_by_module_and_tool_id(real_registry):
    sel = select_tools(real_registry, ("wellcheck", "dashboard.get_all_dashboards"), False)
    assert "dashboard.get_all_dashboards" in sel
    assert all(e["module"] in ("wellcheck", "dashboard") for e in sel.values())
    assert sum(1 for e in sel.values() if e["module"] == "dashboard") == 1


def test_select_filters_mutations(real_registry):
    read_only = select_tools(real_registry, ("dashboard",), False)
    with_writes = select_tools(real_registry, ("dashboard",), True)
    assert all(not e["mutates"] for e in read_only.values())
    assert len(with_writes) > len(read_only)


def test_select_always_excludes_migration(real_registry):
    sel = select_tools(real_registry, ("migration", "migration.migrate_all_users"), True)
    assert sel == {}


def test_empty_allowlist_selects_nothing(real_registry):
    assert select_tools(real_registry, (), True) == {}

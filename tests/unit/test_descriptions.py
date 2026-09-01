"""Advertised description composition: docstring lifting, example selection
by the extraction-teaching bar, and drift guards for the hand-written
overlays."""

import pytest

from fes_mcp.descriptions import (
    EXAMPLE_TOOLS,
    USAGE_NOTES,
    _best_example,
    compose_description,
)
from fes_mcp.registry import load_registry
from fes_mcp.settings import DEFAULT_REGISTRY_PATH


@pytest.fixture(scope="module")
def registry():
    return load_registry(DEFAULT_REGISTRY_PATH)


DOC = """Do the thing for the user.

Longer intro explaining when to use this — as opposed to other_tool,
which needs admin access.

Parameters
----------
x : str
    The x.

Returns
-------
dict
    The thing, or {"error": ...} on failure.

Notes
-----
Slow on large instances.
"""


def test_compose_lifts_intro_returns_notes_and_skips_parameters():
    entry = {"tool_id": "m.t", "description": "Do the thing.", "full_doc": DOC}
    out = compose_description(entry)
    assert "as opposed to other_tool" in out          # intro guidance kept
    assert "Returns:" in out and '{"error": ...}' in out
    assert "Note: Slow on large instances." in out
    assert "The x." not in out                        # Parameters section skipped


def test_compose_falls_back_to_one_liner_without_full_doc():
    assert compose_description({"tool_id": "m.t", "description": "One line."}) == "One line."


def test_example_only_for_free_form_tools():
    ex = [{"user_query": "run it", "arguments": {"q": "select"}}]
    plain = {"tool_id": "m.not_listed", "description": "d", "full_doc": DOC, "examples": ex}
    assert "Example" not in compose_description(plain)
    jaql = {"tool_id": "queries.elasticube_run_jaql_query", "description": "d",
            "full_doc": DOC, "examples": ex}
    assert 'Example — "run it"' in compose_description(jaql)


def test_best_example_prefers_extraction_teaching():
    # FES finding: pick the example whose argument values are spoken in the
    # query; one with invented values teaches the model to invent.
    invented = {"user_query": "Delete the dashboard.", "arguments": {"dashboard_id": "5f3a9b"}}
    extractive = {"user_query": "Delete the dashboard 'Sales Overview'.",
                  "arguments": {"dashboard_id": "Sales Overview"}}
    assert _best_example([invented, extractive]) is extractive


def test_usage_notes_appear_in_composed_description(registry):
    entry = registry["wellcheck.run_full_wellcheck"]
    assert "Can be slow" in compose_description(entry)


def test_overlay_keys_exist_in_registry(registry):
    # Drift guards: a rebuild/rename must not leave ghost overlay entries.
    for tid in USAGE_NOTES:
        assert tid in registry, f"USAGE_NOTES key {tid} vanished from the registry"
    for tid in EXAMPLE_TOOLS:
        assert tid in registry, f"EXAMPLE_TOOLS key {tid} vanished from the registry"


def test_battery_cases_reference_live_tools(registry):
    """The eval battery must not rot: every expected tool_id has to exist in
    the registry (an SDK removal silently invalidated a case once)."""
    import json
    from pathlib import Path

    from fes_mcp.settings import REPO_ROOT

    cases = json.loads(
        (REPO_ROOT / "evals" / "tool_selection_cases.json").read_text()
    )["cases"]
    unknown = [t for c in cases for t in c["expect"] if t not in registry]
    assert not unknown, f"battery references tools not in the registry: {unknown}"

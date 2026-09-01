"""Live validation of the curated read surface against a real Sisense box.

Everything here is READ-ONLY: the surface is selected with mutations off, and
arguments are derived from earlier results (a real dashboard id, a real model
title) — never invented. The point is to validate the curation on a real
instance instead of on paper: every advertised read tool answers, references
resolve, and failures arrive as clean errors, not silent successes.
"""

from __future__ import annotations

import importlib

import pytest

from fes_mcp.dispatcher import DispatchError

pytestmark = pytest.mark.integration

smoke = importlib.import_module("scripts.05_live_smoke")


def test_every_advertised_read_tool_answers(live_dispatcher, read_surface):
    """The whole read surface, one call each (scripts/05 derivation rules)."""
    results: dict = {}
    failures: list[str] = []
    order = sorted(
        read_surface, key=lambda t: bool(read_surface[t]["parameters"].get("required"))
    )
    for tool_id in order:
        entry = read_surface[tool_id]
        assert not entry["mutates"], f"{tool_id} is a write tool — refusing"
        if tool_id in smoke.SKIP:
            continue
        args = {}
        required = entry["parameters"].get("required") or []
        if required:
            param, source, keys = smoke.DERIVE.get(tool_id, (None, None, None))
            if not param or source not in results:
                continue
            value = smoke._first_value(results[source], keys)
            if value is None:
                continue
            args[param] = value
        try:
            results[tool_id] = live_dispatcher.invoke(tool_id, args)
        except DispatchError as exc:
            failures.append(f"{tool_id}: {exc}")
    assert not failures, "live read tools failed:\n  " + "\n  ".join(failures)
    assert len(results) >= 15, f"only {len(results)} tools actually ran — derivation broke?"


def test_dashboard_title_resolves_live(live_dispatcher):
    """The dispatcher's ID-or-title resolution against real data: fetch a
    dashboard by its TITLE through a tool whose SDK parameter wants an OID."""
    dashboards = live_dispatcher.invoke("dashboard.get_dashboards", {"fields": ["oid", "title"]})
    if not dashboards:
        pytest.skip("tenant has no dashboards visible to this token")
    title = next((d["title"] for d in dashboards if d.get("title")), None)
    result = live_dispatcher.invoke("dashboard.get_dashboard_by_id", {"dashboard_id": title})
    got = result[0] if isinstance(result, list) else result
    assert got.get("title") == title


def test_unknown_model_fails_cleanly(live_dispatcher):
    """A nonexistent data model must surface as a clean error (the 2.0
    ok-marker contract), never as an empty success."""
    with pytest.raises(DispatchError, match="(?i)not found|failed|error"):
        live_dispatcher.invoke(
            "datamodel.describe_datamodel",
            {"datamodel_name": "no-such-model-fes-mcp-integration-test"},
        )


def test_folder_tree_via_structure_param(live_dispatcher):
    """get_folders(structure='tree') — the capability that justified cutting
    the get_all_folders alias — must work live."""
    tree = live_dispatcher.invoke("folder.get_folders", {"structure": "tree"})
    assert isinstance(tree, list)

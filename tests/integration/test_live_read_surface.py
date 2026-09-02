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

# Clean errors that are correct answers about the box's data, not tool
# failures — e.g. none of the sampled dashboards carries a script.
_BENIGN_ERRORS = ("has no dashboard script",)


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
        required = entry["parameters"].get("required") or []
        if required:
            param, source, keys = smoke.DERIVE.get(tool_id, (None, None, None))
            if not param or source not in results:
                continue
            # A shared box can hold rows that list but don't resolve (another
            # tenant's model, a script-less dashboard) — try a few candidates
            # before declaring the tool broken.
            candidates = smoke._candidate_values(results[source], keys)
            if not candidates:
                continue
            last_error: DispatchError | None = None
            for value in candidates:
                try:
                    results[tool_id] = live_dispatcher.invoke(tool_id, {param: value})
                    last_error = None
                    break
                except DispatchError as exc:
                    last_error = exc
            if last_error is not None and not any(
                b in str(last_error) for b in _BENIGN_ERRORS
            ):
                failures.append(f"{tool_id}: {last_error}")
            continue
        try:
            results[tool_id] = live_dispatcher.invoke(tool_id, {})
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
    try:
        result = live_dispatcher.invoke(
            "datamodel.describe_datamodel",
            {"datamodel_name": "no-such-model-fes-mcp-integration-test"},
        )
    except DispatchError:
        return  # the contract holds
    if result == []:
        pytest.xfail(
            "pysisense contract gap: describe_datamodel returns [] for an "
            "unknown model instead of the 2.0 ok:False marker — fix in the SDK"
        )
    pytest.fail(f"expected a clean error, got success: {result!r:.200}")


def test_folder_tree_via_structure_param(live_dispatcher, read_surface):
    """get_folders(structure='tree') live-verified shape: 'tree' returns the
    ROOT FOLDER NODE (a dict with nested children), 'flat' a list of rows.
    Skips when the tool is curated out of the surface."""
    if "folder.get_folders" not in read_surface:
        pytest.skip("folder.get_folders is not in the curated surface")
    tree = live_dispatcher.invoke("folder.get_folders", {"structure": "tree"})
    root = tree[0] if isinstance(tree, list) else tree
    assert isinstance(root, dict) and root.get("type") == "folder"

    flat = live_dispatcher.invoke("folder.get_folders", {"structure": "flat"})
    assert isinstance(flat, list)

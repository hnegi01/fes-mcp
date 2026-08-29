"""SDK-upgrade reconciliation: example porting across renames + allowlist
staging/deprecation. Adapted from the FES Assistant's upgrade automation."""

import importlib

rec = importlib.import_module("scripts.03_reconcile")


def _entry(tool_id, module=None, props=(), required=(), mutates=False, examples=None,
           description="Some tool."):
    return {
        "tool_id": tool_id,
        "module": module or tool_id.split(".")[0],
        "mutates": mutates,
        "description": description,
        "examples": examples or [],
        "parameters": {
            "type": "object",
            "properties": {p: {"type": "string"} for p in props},
            "required": list(required),
        },
    }


EX = [{"user_query": "q", "arguments": {}, "notes": "n"}]


# --- example porting -----------------------------------------------------------


def test_port_on_clean_rename():
    old = {"m.get_things": _entry("m.get_things", props=("a",), required=("a",), examples=EX)}
    new = {"m.get_things_all": _entry("m.get_things_all", props=("a",), required=("a",))}
    ports = rec.port_examples(old, new)
    assert ports == [("m.get_things", "m.get_things_all")]
    assert new["m.get_things_all"]["examples"] == EX


def test_no_port_for_dissimilar_names_with_empty_schemas():
    old = {"m.get_users": _entry("m.get_users", examples=EX)}
    new = {"m.list_dashboards": _entry("m.list_dashboards")}
    assert rec.port_examples(old, new) == []
    assert new["m.list_dashboards"]["examples"] == []


def test_no_port_when_ambiguous():
    old = {"m.get_things": _entry("m.get_things", props=("a",), examples=EX)}
    new = {
        "m.get_things_all": _entry("m.get_things_all", props=("a",)),
        "m.get_things_v2": _entry("m.get_things_v2", props=("a",)),
    }
    assert rec.port_examples(old, new) == []


def test_no_port_when_parameter_shape_changed():
    old = {"m.get_things": _entry("m.get_things", props=("a",), required=("a",), examples=EX)}
    new = {"m.get_things_all": _entry("m.get_things_all", props=("a", "b"), required=("a",))}
    assert rec.port_examples(old, new) == []


# --- allowlist reconciliation ----------------------------------------------------


REGISTRY = {
    "m.alive_tool": _entry("m.alive_tool", description="Alive."),
    "m.hidden_tool": _entry("m.hidden_tool", description="Hidden on purpose."),
    "m.brand_new": _entry("m.brand_new", description="Fresh from the SDK."),
    "m.new_writer": _entry("m.new_writer", mutates=True, description="Writes things."),
}

TEXT = """# Curated tool surface — prose header that must survive.

# ===== m (2 read) =====
m.alive_tool     # Alive.
# [excluded: dup group 9 — rationale that must survive]
# m.hidden_tool    # Hidden on purpose.
m.dead_tool      # Removed by the SDK.
"""


def test_dead_active_line_moves_to_deprecated_with_description():
    out, report = rec.reconcile_allowlist(TEXT, REGISTRY, "9.9.9")
    assert report["deprecated"] == ["m.dead_tool"]
    assert "m.dead_tool      # Removed by the SDK." in out
    assert out.index(rec.DEPRECATED_HEADER) < out.index("m.dead_tool      #")
    assert "# --- removed in pysisense 9.9.9 ---" in out
    # moved line is commented
    dep_section = out.split(rec.DEPRECATED_HEADER)[1]
    assert "# m.dead_tool" in dep_section


def test_prose_and_hidden_tools_survive_and_are_not_restaged():
    out, report = rec.reconcile_allowlist(TEXT, REGISTRY, "9.9.9")
    assert "prose header that must survive" in out
    assert "[excluded: dup group 9 — rationale that must survive]" in out
    assert "# m.hidden_tool" in out
    assert "m.hidden_tool" not in report["staged"]


def test_new_tools_staged_commented_with_write_tag():
    out, report = rec.reconcile_allowlist(TEXT, REGISTRY, "9.9.9")
    assert report["staged"] == ["m.brand_new", "m.new_writer"]
    staged = out.split(rec.STAGED_HEADER)[1]
    assert "# --- new in pysisense 9.9.9 ---" in staged
    assert "# m.brand_new" in staged
    assert "# m.new_writer    # [write] Writes things." in staged
    # staged lines are commented: the tools are NOT exposed
    for line in staged.splitlines():
        assert not line.strip() or line.strip().startswith("#")


def test_dead_staged_line_moves_to_deprecated():
    text = TEXT + f"\n{rec.STAGED_HEADER}\n# --- new in pysisense 9.9.8 ---\n# m.dead_staged    # Was staged, now gone.\n"
    out, report = rec.reconcile_allowlist(text, REGISTRY, "9.9.9")
    assert "m.dead_staged" in report["deprecated"]
    dep = out.split(rec.DEPRECATED_HEADER)[1].split(rec.STAGED_HEADER)[0]
    assert "m.dead_staged" in dep


def test_idempotent():
    once, _ = rec.reconcile_allowlist(TEXT, REGISTRY, "9.9.9")
    twice, report = rec.reconcile_allowlist(once, REGISTRY, "9.9.9")
    assert twice == once
    assert report["deprecated"] == [] and report["staged"] == []

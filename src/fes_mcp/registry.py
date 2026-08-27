"""Tool registry loading and filtering.

The registry JSON is auto-generated from PySisense SDK docstrings by
scripts/01_build_registry_from_sdk.py — never handwritten. This module loads
it, normalizes each entry, and applies the curated allowlist that defines the
exposed tool surface.
"""

from __future__ import annotations

import copy
import json
import logging
from pathlib import Path
from typing import Any

from .schema_patches import SCHEMA_PATCHES

logger = logging.getLogger("fes_mcp.registry")

# Dual-tenant migration tools are out of scope for v1 (they need their own
# source/target connection mode).
EXCLUDED_MODULES = {"migration"}

# Corrections to the generated `mutates` heuristic, verified against the SDK
# source: these only execute queries or lookups (POSTs to query/GraphQL
# endpoints, or GETs) and change nothing on the Sisense instance.
MUTATES_OVERRIDES: dict[str, bool] = {
    "queries.elasticube_run_jaql_query": False,
    "queries.elasticubes_run_jaql_csv": False,
    "datamodel.generate_connections_payload": False,
    "datamodel.load_datamodel": False,
    "plugins.save_snapshot": False,
}


def _normalize_parameters_schema(raw: Any) -> dict[str, Any]:
    """Ensure the parameters schema is a well-formed object schema."""
    schema = copy.deepcopy(raw) if isinstance(raw, dict) else {}
    schema.setdefault("type", "object")
    schema.setdefault("properties", {})
    schema.setdefault("required", [])
    if not isinstance(schema["properties"], dict):
        schema["properties"] = {}
    if not isinstance(schema["required"], list):
        schema["required"] = []
    return schema


def _apply_schema_patches(tool_id: str, entry: dict[str, Any]) -> None:
    """Merge SCHEMA_PATCHES inner schemas into bare dict-typed parameters.

    A patch applies only while the generated schema for the parameter is
    still a bare object (no properties) — once the SDK ships real payload
    types and regeneration produces properties, the patch is stale and only
    logs a warning, so it can be deleted.
    """
    for param, inner in SCHEMA_PATCHES.get(tool_id, {}).items():
        target = entry["parameters"]["properties"].get(param)
        if target is None:
            logger.warning(
                "SCHEMA_PATCHES: %s has no parameter %r (typo, or renamed by a "
                "registry refresh?) — patch skipped",
                tool_id,
                param,
            )
            continue
        if target.get("properties"):
            logger.warning(
                "SCHEMA_PATCHES stale: %s.%s already has properties (SDK ships "
                "a real schema now?) — delete the patch",
                tool_id,
                param,
            )
            continue
        merged = copy.deepcopy(inner)
        # The generated description (from the SDK docstring) is useful model
        # context — keep it unless the patch brings its own.
        if target.get("description") and "description" not in merged:
            merged["description"] = target["description"]
        entry["parameters"]["properties"][param] = merged


def load_registry(path: Path) -> dict[str, dict[str, Any]]:
    """Load the registry JSON and return {tool_id: normalized entry}."""
    if not path.exists():
        raise RuntimeError(
            f"Registry file not found: {path}. Run ./refresh_registry.sh to generate it."
        )
    payload = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(payload, list):
        raise RuntimeError(f"Registry JSON must be a list, got {type(payload).__name__}")

    tools: dict[str, dict[str, Any]] = {}
    skipped = 0
    for row in payload:
        tool_id = row.get("tool_id")
        if not tool_id or not row.get("module") or not row.get("method") or not row.get("class"):
            skipped += 1
            continue
        entry = dict(row)
        entry["mutates"] = MUTATES_OVERRIDES.get(
            tool_id, bool(entry.get("mutates", False))
        )
        entry["parameters"] = _normalize_parameters_schema(entry.get("parameters"))
        _apply_schema_patches(tool_id, entry)
        tools[tool_id] = entry

    unknown_overrides = MUTATES_OVERRIDES.keys() - tools.keys()
    if unknown_overrides:
        logger.warning(
            "MUTATES_OVERRIDES keys not found in registry (typo, or tool renamed "
            "by a registry refresh?): %s",
            ", ".join(sorted(unknown_overrides)),
        )

    unknown_patches = SCHEMA_PATCHES.keys() - tools.keys()
    if unknown_patches:
        logger.warning(
            "SCHEMA_PATCHES keys not found in registry (typo, or tool renamed "
            "by a registry refresh?): %s",
            ", ".join(sorted(unknown_patches)),
        )

    logger.info("Loaded registry: %d tools (%d rows skipped) from %s", len(tools), skipped, path)
    return tools


def select_tools(
    tools: dict[str, dict[str, Any]],
    allowlist: tuple[str, ...],
    allow_mutations: bool,
) -> dict[str, dict[str, Any]]:
    """Apply the allowlist (tool_ids and/or module names) and mutation policy.

    An empty allowlist selects nothing — the tool surface is always explicit.
    """
    modules = {e for e in allowlist if "." not in e}
    tool_ids = {e for e in allowlist if "." in e}

    unknown = tool_ids - tools.keys()
    known_modules = {t["module"] for t in tools.values()}
    unknown |= modules - known_modules
    if unknown:
        logger.warning("Allowlist entries not found in registry: %s", ", ".join(sorted(unknown)))

    selected: dict[str, dict[str, Any]] = {}
    dropped_mutating = 0
    for tool_id, entry in tools.items():
        if entry["module"] in EXCLUDED_MODULES:
            continue
        if not (tool_id in tool_ids or entry["module"] in modules):
            continue
        if entry["mutates"] and not allow_mutations:
            dropped_mutating += 1
            continue
        selected[tool_id] = entry

    if dropped_mutating:
        logger.info(
            "Excluded %d mutating tools (FES_MCP_ALLOW_MUTATIONS=false)", dropped_mutating
        )
    logger.info("Tool surface: %d tools selected", len(selected))
    return selected

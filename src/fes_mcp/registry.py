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

from .schema_patches import FIELD_DESCRIPTIONS

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
    # Pure fan-out over the eight check_* methods; issues no writes (the
    # generator's heuristic misreads verbs in its docstring).
    "wellcheck.run_full_wellcheck": False,
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


def _apply_field_descriptions(tool_id: str, entry: dict[str, Any]) -> None:
    """Overlay human-written field descriptions onto SDK payload schemas.

    The SDK's TypedDict contracts define structure (properties/required) but
    carry no per-field descriptions; this fills only that gap. Descriptions
    are applied solely to fields the generated schema already has — a field
    named here that the SDK dropped logs a drift warning.
    """
    for param, fields in FIELD_DESCRIPTIONS.get(tool_id, {}).items():
        target = entry["parameters"]["properties"].get(param)
        props = (target or {}).get("properties")
        if not props:
            logger.warning(
                "FIELD_DESCRIPTIONS: %s.%s has no generated properties "
                "(param renamed, or SDK contract regressed?) — overlay skipped",
                tool_id,
                param,
            )
            continue
        for field, description in fields.items():
            if field not in props:
                logger.warning(
                    "FIELD_DESCRIPTIONS drift: %s.%s no longer has field %r — "
                    "delete its description",
                    tool_id,
                    param,
                    field,
                )
                continue
            props[field].setdefault("description", description)


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
        _apply_field_descriptions(tool_id, entry)
        tools[tool_id] = entry

    unknown_overrides = MUTATES_OVERRIDES.keys() - tools.keys()
    if unknown_overrides:
        logger.warning(
            "MUTATES_OVERRIDES keys not found in registry (typo, or tool renamed "
            "by a registry refresh?): %s",
            ", ".join(sorted(unknown_overrides)),
        )

    unknown_patches = FIELD_DESCRIPTIONS.keys() - tools.keys()
    if unknown_patches:
        logger.warning(
            "FIELD_DESCRIPTIONS keys not found in registry (typo, or tool renamed "
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

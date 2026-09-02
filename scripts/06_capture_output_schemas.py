"""Capture tool result shapes from a live Sisense instance into outputSchema.

PySisense declares no return contracts, so output schemas are captured
empirically: every advertised READ tool is run once (same derivation and
safety rules as scripts/05_live_smoke) and the shape of what came back is
distilled into a deliberately permissive JSON Schema — property names and
typical types only, everything nullable, nothing required,
additionalProperties always true — so a schema can inform the client without
ever failing validation on another instance whose data differs.

    SISENSE_DOMAIN=... SISENSE_TOKEN=... uv run python -m scripts.06_capture_output_schemas

Writes config/output_schemas.json (merged with any previous capture, so runs
against different instances accumulate). load_registry picks the file up
automatically. Write tools are never run and get no output schema.

Review the generated file before committing: an API that returns an object
keyed by data values (names, emails) would leak instance specifics as
property names — the _MAX_PROPS cap catches large maps, not small ones.
"""

from __future__ import annotations

import importlib
import json
from typing import Any

from dotenv import load_dotenv

from fes_mcp.dispatcher import DispatchError, SisenseDispatcher
from fes_mcp.registry import OUTPUT_SCHEMAS_FILENAME, load_registry, select_tools
from fes_mcp.settings import REPO_ROOT, Settings

_smoke = importlib.import_module("scripts.05_live_smoke")

_MAX_DEPTH = 4  # deeper structure is left as a bare permissive object
_SAMPLE_ITEMS = 20  # array items sampled per capture
_MAX_PROPS = 40  # more looks like a data-keyed map, not a record — omit props


def infer_schema(value: Any, depth: int = 0) -> dict[str, Any]:
    """A permissive schema for one observed value (see module docstring)."""
    if isinstance(value, dict):
        out: dict[str, Any] = {"type": ["object", "null"], "additionalProperties": True}
        if depth < _MAX_DEPTH and 0 < len(value) <= _MAX_PROPS:
            out["properties"] = {
                str(k): infer_schema(v, depth + 1) for k, v in value.items()
            }
        return out
    if isinstance(value, list):
        items: dict[str, Any] = {}
        for v in value[:_SAMPLE_ITEMS]:
            items = merge_schemas(items, infer_schema(v, depth + 1))
        out = {"type": ["array", "null"]}
        if items:
            out["items"] = items
        return out
    if value is None:
        return {"type": ["null"]}
    if isinstance(value, bool):
        return {"type": ["boolean", "null"]}
    if isinstance(value, (int, float)):
        return {"type": ["number", "null"]}
    if isinstance(value, str):
        return {"type": ["string", "null"]}
    return {}  # exotic type — no constraint at all


def merge_schemas(a: dict[str, Any], b: dict[str, Any]) -> dict[str, Any]:
    """Union of two inferred schemas: anything either allowed stays allowed."""
    if not a:
        return b
    if not b:
        return a
    types = sorted(set(_types(a)) | set(_types(b)))
    out: dict[str, Any] = {"type": types} if types else {}
    if "object" in types:
        out["additionalProperties"] = True
        props_a, props_b = a.get("properties", {}), b.get("properties", {})
        # Properties only when every object observation had them: a capture
        # that hit the _MAX_PROPS map heuristic poisons keys, don't keep them.
        if props_a and props_b:
            out["properties"] = {
                k: merge_schemas(props_a.get(k, {}), props_b.get(k, {}))
                for k in {*props_a, *props_b}
            }
        elif ("object" in _types(a)) != ("object" in _types(b)):
            out["properties"] = props_a or props_b  # only one side was an object
    if "array" in types:
        items = merge_schemas(a.get("items", {}), b.get("items", {}))
        if items:
            out["items"] = items
    return out


def _types(schema: dict[str, Any]) -> list[str]:
    t = schema.get("type", [])
    return t if isinstance(t, list) else [t]


def schema_for_result(result: Any) -> dict[str, Any]:
    """Schema of the structuredContent the server sends (server.py wraps
    non-dict results as {"result": ...}); top level is a plain object."""
    if isinstance(result, dict):
        inner = infer_schema(result)
        inner["type"] = "object"
        return inner
    return {
        "type": "object",
        "properties": {"result": infer_schema(result)},
        "additionalProperties": True,
    }


def main() -> None:
    load_dotenv(REPO_ROOT / ".env")
    settings = Settings.from_env()
    if not (settings.sisense_domain and settings.sisense_token):
        raise SystemExit(
            "No credentials. Put SISENSE_DOMAIN and SISENSE_TOKEN in .env "
            "(gitignored) or pass them as environment variables."
        )

    registry = load_registry(settings.registry_path)
    surface = select_tools(registry, settings.allowlist, allow_mutations=False)
    dispatcher = SisenseDispatcher(settings, surface)

    out_path = settings.registry_path.parent / OUTPUT_SCHEMAS_FILENAME
    schemas: dict[str, Any] = {}
    if out_path.exists():
        schemas = json.loads(out_path.read_text(encoding="utf-8")).get("schemas", {})

    print(f"instance: {settings.sisense_domain}")
    print(f"advertised read tools: {len(surface)}\n")

    results: dict[str, Any] = {}
    ok = skipped = failed = 0
    order = sorted(surface, key=lambda t: bool(surface[t]["parameters"].get("required")))
    for tool_id in order:
        entry = surface[tool_id]
        assert not entry["mutates"], f"{tool_id} is a write tool — refusing"
        if tool_id in _smoke.SKIP:
            print(f"  SKIP  {tool_id:<46} {_smoke.SKIP[tool_id]}")
            skipped += 1
            continue

        args: dict[str, Any] = {}
        required = entry["parameters"].get("required") or []
        if required:
            param, source, keys = _smoke.DERIVE.get(tool_id, (None, None, None))
            value = _smoke._first_value(results.get(source), keys) if param else None
            if value is None:
                print(f"  SKIP  {tool_id:<46} no derivable {required}")
                skipped += 1
                continue
            args[param] = value

        try:
            result = dispatcher.invoke(tool_id, args)
        except DispatchError as exc:
            print(f"  FAIL  {tool_id:<46} {exc}")
            failed += 1
            continue
        results[tool_id] = result
        schemas[tool_id] = merge_schemas(schemas.get(tool_id, {}), schema_for_result(result))
        print(f"  OK    {tool_id:<46} captured")
        ok += 1

    payload = {
        "note": (
            "Generated by scripts/06_capture_output_schemas.py from live tool "
            "runs; permissive by construction (no required fields, everything "
            "nullable). Do not hand-edit — re-run the script."
        ),
        "schemas": {k: schemas[k] for k in sorted(schemas)},
    }
    out_path.write_text(json.dumps(payload, indent=2) + "\n", encoding="utf-8")
    print(f"\n{ok} captured · {failed} failed · {skipped} skipped → {out_path}")


if __name__ == "__main__":
    main()

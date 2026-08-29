"""Post-rebuild reconciliation: port curated examples across renames and keep
the allowlist honest — without ever exposing a tool automatically.

Runs after 01_build_registry_from_sdk (see refresh_registry.sh):

1. EXAMPLE PORTING. Curated examples are keyed by tool_id, so an SDK rename
   (get_connections -> get_connections_all) makes the tool look brand-new and
   silently drops its examples. Port them from a vanished id to a new id ONLY
   on an unambiguous match — all of:
     - same module
     - identical parameter names AND identical required list (no-arg read
       tools share an empty schema, so shape alone is not enough)
     - similar name (one contains the other, or >= 0.8 difflib ratio)
     - exactly ONE candidate in each direction
   Anything murkier is left alone and regenerates. Every port is logged.

2. ALLOWLIST RECONCILIATION (--apply). Maintains two extra sections:
     # ===== DEPRECATED: removed from the SDK — history only ... =====
     # ===== STAGED: new in the registry — uncomment to expose ... =====
   Lines whose tool_id vanished from the registry MOVE (commented) to
   DEPRECATED under a batch header naming the SDK version — the file doubles
   as the tool surface's changelog. New registry ids are APPENDED to STAGED
   as commented lines ([write]-tagged when mutating): exposing stays a human
   decision, but it becomes "delete one # character". Ids already listed,
   staged, or deprecated are never touched (idempotent), and prose comments /
   deliberately-hidden tools (commented lines with a rationale) are never
   deleted or re-staged.
"""

from __future__ import annotations

import difflib
import json
import re
from pathlib import Path
from typing import Any, Dict, List, Tuple

_TOOL_ID_RE = re.compile(r"^[a-z_]+\.[a-z0-9_]+$")

DEPRECATED_HEADER = (
    "# ===== DEPRECATED: removed from the SDK — history only, never uncomment ====="
)
STAGED_HEADER = (
    "# ===== STAGED: new in the registry — uncomment a line to expose the tool ====="
)


# ---------------------------------------------------------------------------
# 1. Example porting across renames
# ---------------------------------------------------------------------------


def _param_shape(entry: Dict[str, Any]) -> Tuple[tuple, tuple]:
    params = entry.get("parameters") or {}
    return (
        tuple(sorted((params.get("properties") or {}).keys())),
        tuple(sorted(params.get("required") or [])),
    )


def _similar_name(a: str, b: str) -> bool:
    a, b = a.rsplit(".", 1)[-1], b.rsplit(".", 1)[-1]
    if a in b or b in a:
        return True
    return difflib.SequenceMatcher(None, a, b).ratio() >= 0.8


def port_examples(
    old_tools: Dict[str, Dict[str, Any]], new_tools: Dict[str, Dict[str, Any]]
) -> List[Tuple[str, str]]:
    """Carry examples from vanished old ids to unambiguously-renamed new ids.

    Mutates new_tools in place; returns the (old_id, new_id) ports performed.
    """
    vanished = {
        tid: e for tid, e in old_tools.items() if tid not in new_tools and e.get("examples")
    }
    fresh = {
        tid: e for tid, e in new_tools.items() if tid not in old_tools and not e.get("examples")
    }

    def candidates(src_id, src_entry, pool):
        shape = _param_shape(src_entry)
        module = src_entry.get("module")
        return [
            tid
            for tid, e in pool.items()
            if e.get("module") == module
            and _param_shape(e) == shape
            and _similar_name(src_id, tid)
        ]

    ports: List[Tuple[str, str]] = []
    for old_id, old_entry in vanished.items():
        forward = candidates(old_id, old_entry, fresh)
        if len(forward) != 1:
            continue
        new_id = forward[0]
        backward = candidates(new_id, new_tools[new_id], vanished)
        if backward != [old_id]:
            continue
        new_tools[new_id]["examples"] = old_entry["examples"]
        ports.append((old_id, new_id))
        print(f"  ported examples: {old_id} -> {new_id}")
    return ports


# ---------------------------------------------------------------------------
# 2. Allowlist reconciliation
# ---------------------------------------------------------------------------


def _tool_id_of_line(line: str) -> str | None:
    """The tool_id a line refers to — active ('module.method ...') or
    commented ('# module.method ...') — else None for prose/blank."""
    s = line.strip()
    if s.startswith("#"):
        s = s.lstrip("#").strip()
    token = s.split()[0] if s.split() else ""
    return token if _TOOL_ID_RE.match(token) else None


def reconcile_allowlist(
    text: str,
    registry: Dict[str, Dict[str, Any]],
    sdk_version: str,
    exclude_modules: frozenset[str] = frozenset(),
) -> Tuple[str, Dict[str, List[str]]]:
    """Return (new_text, report) — see module docstring for the rules."""
    lines = text.splitlines()

    # Locate existing special sections (everything after a header belongs to it
    # until the next special header).
    def section_of(idx_markers: List[Tuple[int, str]], i: int) -> str:
        current = "live"
        for pos, name in idx_markers:
            if i >= pos:
                current = name
        return current

    markers = [
        (i, "deprecated" if line.strip() == DEPRECATED_HEADER else "staged")
        for i, line in enumerate(lines)
        if line.strip() in (DEPRECATED_HEADER, STAGED_HEADER)
    ]

    mentioned: set[str] = set()
    dead_live: List[str] = []  # reconstructed commented lines to move
    kept: List[str] = []
    deprecated_block: List[str] = []
    staged_block: List[str] = []

    for i, line in enumerate(lines):
        sec = section_of(markers, i)
        tid = _tool_id_of_line(line)
        if tid:
            mentioned.add(tid)
        if line.strip() in (DEPRECATED_HEADER, STAGED_HEADER):
            continue  # re-emitted below
        if sec == "deprecated":
            deprecated_block.append(line)
            continue
        if sec == "staged":
            if tid and tid not in registry:
                dead_live.append(line if line.strip().startswith("#") else f"# {line}")
                continue
            staged_block.append(line)
            continue
        # live section
        if tid and tid not in registry:
            dead_live.append(line if line.strip().startswith("#") else f"# {line}")
            print(f"  deprecated: {tid} (removed from the SDK)")
            continue
        kept.append(line)

    report = {"deprecated": [], "staged": [], "ported": []}

    if dead_live:
        if not any(l.strip() for l in deprecated_block):
            deprecated_block = []
        deprecated_block += [f"# --- removed in pysisense {sdk_version} ---"] + dead_live
        report["deprecated"] = [_tool_id_of_line(l) for l in dead_live]

    # Modules excluded in code (e.g. migration) are never staged — a staged
    # line would invite uncommenting a tool the runtime refuses to load.
    new_ids = sorted(
        tid
        for tid, e in registry.items()
        if tid not in mentioned and e.get("module") not in exclude_modules
    )
    if new_ids:
        batch = [f"# --- new in pysisense {sdk_version} ---"]
        for tid in new_ids:
            entry = registry[tid]
            desc = (entry.get("description") or "").strip().splitlines()
            desc = desc[0] if desc else ""
            tag = "[write] " if entry.get("mutates") else ""
            batch.append(f"# {tid}    # {tag}{desc}"[:160])
            print(f"  staged: {tid}")
        staged_block += batch
        report["staged"] = new_ids

    out = kept
    # trim trailing blanks before appending sections
    while out and not out[-1].strip():
        out.pop()
    if any(l.strip() for l in deprecated_block):
        out += ["", DEPRECATED_HEADER] + [l for l in deprecated_block if l.strip()]
    if any(l.strip() for l in staged_block):
        out += ["", STAGED_HEADER] + [l for l in staged_block if l.strip()]
    return "\n".join(out) + "\n", report


# ---------------------------------------------------------------------------
# Pipeline entry point
# ---------------------------------------------------------------------------


def main() -> None:
    import pysisense

    root = Path(__file__).resolve().parents[1]
    flat_path = root / "config" / "tools.registry.json"
    merged_path = root / "config" / "tools.registry.with_examples.json"
    allowlist_path = root / "config" / "allowlist.txt"
    version = getattr(pysisense, "__version__", "unknown")

    fresh = {t["tool_id"]: t for t in json.loads(flat_path.read_text())}
    old = (
        {t["tool_id"]: t for t in json.loads(merged_path.read_text())}
        if merged_path.exists()
        else {}
    )

    # carry same-id examples, then port across renames
    carried = 0
    for tid, entry in fresh.items():
        prev = old.get(tid)
        if prev and prev.get("examples"):
            entry["examples"] = prev["examples"]
            carried += 1
    ports = port_examples(old, fresh)
    print(f"examples: {carried} carried, {len(ports)} ported across renames")

    merged = list(fresh.values())
    with merged_path.open("w") as f:
        json.dump(merged, f, indent=2, ensure_ascii=False)
        f.write("\n")

    from .registry_core import build_registry_hierarchical

    build_registry_hierarchical(merged)

    from fes_mcp.registry import EXCLUDED_MODULES

    new_text, report = reconcile_allowlist(
        allowlist_path.read_text(), fresh, version, exclude_modules=frozenset(EXCLUDED_MODULES)
    )
    allowlist_path.write_text(new_text)
    print(
        f"allowlist: {len(report['deprecated'])} moved to DEPRECATED, "
        f"{len(report['staged'])} staged (all commented — exposure stays a human decision)"
    )


if __name__ == "__main__":
    main()

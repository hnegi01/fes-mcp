"""Advertised tool descriptions, composed from the registry's SDK docstrings.

A tool description is prompt engineering: it is the only thing standing
between the model and misusing the tool. The registry keeps the SDK's full
docstring (`full_doc`) and curated examples server-side; this module composes
what is actually advertised per tool:

- the docstring's intro (which carries the when-to-use-which guidance, e.g.
  get_dashboards vs get_all_dashboards) and its Returns/Notes sections,
  condensed — the Parameters section is skipped because the input schema
  already carries per-parameter descriptions;
- for FREE-FORM payload tools only (JAQL, metadata queries, Blox JSON,
  scripts, datasecurity rules, encryption) one worked example, because no
  schema can teach those payloads — example-teaching exactly where
  schema-teaching can't reach.

Token budget (measured 2026-08-29): ~9.5k tokens for the 47-tool read-only
surface, ~20k with mutations enabled.
"""

from __future__ import annotations

import json
import re
from typing import Any

_SECTION_RE = re.compile(r"^(Parameters|Returns|Yields|Raises|Notes|Examples)\n-+\n", re.M)

_INTRO_LIMIT = 600
_SECTION_LIMIT = 220
# An example is only included whole — truncating mid-JSON would advertise
# malformed arguments, worse than no example.
_EXAMPLE_LIMIT = 700

# Free-form payload tools: their payload "schema" is a language, so one worked
# example is the guidance that matters.
EXAMPLE_TOOLS = frozenset(
    {
        "queries.elasticube_run_jaql_query",
        "queries.elasticubes_run_jaql_csv",
        "metadata.post_metadata_query",
        "blox.save_blox_action",
        "dashboard.add_dashboard_script",
        "dashboard.add_widget_script",
        "datamodel.update_datasecurity",
        "datamodel.set_live_datasecurity_add_many",
        "encryption.encrypt",
        "encryption.decrypt",
    }
)


# Hand-written usage guidance the SDK docstrings don't carry (chiefly
# "when NOT to use this"). Keyed by tool_id and applied at compose time so a
# registry rebuild can never erase it; a drift test fails if a key vanishes
# from the registry. Prefer pushing durable guidance upstream into the SDK
# docstring — an entry here is the stopgap.
USAGE_NOTES: dict[str, str] = {
    "wellcheck.run_full_wellcheck": (
        "Can be slow: the m2m check runs real aggregate SQL. Prefer a single "
        "targeted check when the user asked about one dashboard or model."
    ),
    "datamodel.get_all_datamodel": (
        "Uses an internal Linux-only route; on Windows-based Sisense use "
        "get_elasticubes instead."
    ),
    # Open SDK issue (reported 2026-09-01): partial success must not read as
    # plain success.
    "datamodel.add_datamodel_shares": (
        "IMPORTANT: check the `skipped` array in the result — those shares "
        "were requested but NOT applied (unknown or inactive user); report "
        "them to the user, never as success."
    ),
    # Open SDK issue: LIVE silently discards mis-keyed share entries.
    "datamodel.set_live_datasecurity_add_many": (
        "Share entries must use the `partyId` key — entries keyed `party` "
        "are silently discarded on LIVE models."
    ),
}


def _example_score(example: dict[str, Any]) -> float:
    """FES finding: a good example teaches EXTRACTION — argument values are
    spoken in the query text. One whose args contain values absent from the
    query teaches the model it may invent plausible values. Score = fraction
    of scalar leaf values that appear in the user_query."""
    query = (example.get("user_query") or "").lower()
    leaves: list[str] = []

    def walk(v):
        if isinstance(v, dict):
            for x in v.values():
                walk(x)
        elif isinstance(v, list):
            for x in v:
                walk(x)
        elif isinstance(v, (str, int, float)) and not isinstance(v, bool):
            s = str(v).strip()
            if len(s) >= 3:
                leaves.append(s.lower())

    walk(example.get("arguments") or {})
    if not leaves:
        return 0.0
    return sum(1 for leaf in leaves if leaf in query) / len(leaves)


def _best_example(examples: list[dict[str, Any]]) -> dict[str, Any]:
    return max(examples, key=_example_score)


def _split_sections(doc: str) -> dict[str, str]:
    parts = _SECTION_RE.split(doc)
    out = {"intro": parts[0].strip()}
    for name, body in zip(parts[1::2], parts[2::2]):
        out[name] = body.strip()
    return out


def _condense(text: str, limit: int) -> str:
    text = re.sub(r"\s+", " ", text).strip()
    if len(text) <= limit:
        return text
    return text[:limit].rsplit(" ", 1)[0] + " …"


def compose_description(entry: dict[str, Any]) -> str:
    """The advertised description for one registry entry."""
    doc = (entry.get("full_doc") or "").strip()
    if not doc:
        return entry.get("description", "")

    sections = _split_sections(doc)
    pieces = [_condense(sections["intro"], _INTRO_LIMIT)]
    if sections.get("Returns"):
        pieces.append("Returns: " + _condense(sections["Returns"], _SECTION_LIMIT))
    if sections.get("Notes"):
        pieces.append("Note: " + _condense(sections["Notes"], _SECTION_LIMIT))

    note = USAGE_NOTES.get(entry.get("tool_id", ""))
    if note:
        pieces.append(note)

    if entry.get("tool_id") in EXAMPLE_TOOLS and entry.get("examples"):
        example = _best_example(entry["examples"])
        rendered = (
            f'Example — "{example.get("user_query", "")}": '
            f'{json.dumps(example.get("arguments", {}))}'
        )
        if len(rendered) <= _EXAMPLE_LIMIT:
            pieces.append(rendered)

    return "\n".join(pieces)

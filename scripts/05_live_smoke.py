"""Read-only live sweep against a real Sisense instance.

Calls every advertised READ tool once and reports what came back, so the
curated surface can be validated against a real box instead of on paper:
which tools work, which fail (and how), and which return nothing.

    SISENSE_DOMAIN=... SISENSE_TOKEN=... uv run python -m scripts.05_live_smoke
    uv run python -m scripts.05_live_smoke --only dashboard,folder

Safety: refuses to run any tool the registry flags as mutating (and the
dispatcher's own gate stays closed unless FES_MCP_ALLOW_MUTATIONS=true, so a
write cannot slip through even if this script were wrong). Arguments for tools
that need them are DERIVED from earlier read results — a real dashboard id, a
real data model title — never invented, so nothing is created or addressed by
guess.
"""

from __future__ import annotations

import sys
from typing import Any

from dotenv import load_dotenv

from fes_mcp.dispatcher import DispatchError, SisenseDispatcher
from fes_mcp.registry import load_registry, select_tools
from fes_mcp.settings import REPO_ROOT, Settings

# Tools whose single required argument can be filled from another tool's
# output: {tool_id: (param, source_tool, key_candidates)}
DERIVE = {
    "dashboard.get_dashboard_by_id": ("dashboard_id", "dashboard.get_dashboards", ("oid", "_id")),
    "dashboard.export_dashboard": ("dashboard_id", "dashboard.get_dashboards", ("oid", "_id")),
    "dashboard.get_dashboard_columns": ("dashboard_name", "dashboard.get_dashboards", ("title",)),
    "dashboard.get_dashboard_share": ("dashboard_name", "dashboard.get_dashboards", ("title",)),
    "dashboard.get_dashboard_script": ("dashboard_id", "dashboard.get_dashboards", ("oid",)),
    "datamodel.describe_datamodel": ("datamodel_name", "datamodel.get_all_datamodel", ("title",)),
    "datamodel.get_model_schema": ("datamodel_name", "datamodel.get_all_datamodel", ("title",)),
    "datamodel.get_datasecurity_detail": (
        "datamodel_name", "datamodel.get_all_datamodel", ("title",)),
    "datamodel.get_datamodel_shares": (
        "datamodel_name", "datamodel.get_all_datamodel", ("title",)),
    "access_management.get_user": ("user_email", "access_management.get_my_user", ("email",)),
    "access_management.users_per_group": (None, None, None),  # optional arg: call bare
    "folder.get_folder_id": ("folder_id", "folder.get_folders", ("oid", "_id")),
}

# Tools skipped in a smoke run: heavy, or need an argument nothing else yields.
SKIP = {
    "wellcheck.run_full_wellcheck": "slow: runs aggregate SQL",
    "datamodel.get_data": "needs a table name; run manually",
    "datamodel.get_table_schema": "needs connection + table",
    "queries.elasticube_run_jaql_query": "needs a hand-written JAQL body",
    "metadata.get_datasource_measures": "needs a datasource name",
    "metadata.get_datasource_dimensions": "needs a datasource name",
    "custom_code.export_notebook": "needs a notebook id",
    "custom_code.list_notebook_folder_contents": "needs a folder path",
    "access_management.get_datamodel_columns": "slow: paginates per dataset",
    "access_management.get_unused_columns_bulk": "slow: full column scan",
    "report_manager.get_report": "needs a report id",
}


def _candidate_values(result: Any, keys: tuple[str, ...], limit: int = 5) -> list[Any]:
    """Up to `limit` distinct derivable values, in row order — a shared box can
    hold rows (another tenant's model, a script-less dashboard) that list but
    don't resolve, so callers may need to try more than the first."""
    rows = result if isinstance(result, list) else [result]
    values: list[Any] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        for k in keys:
            if row.get(k) and row[k] not in values:
                values.append(row[k])
                break
        if len(values) >= limit:
            break
    return values


def _first_value(result: Any, keys: tuple[str, ...]) -> Any:
    values = _candidate_values(result, keys, limit=1)
    return values[0] if values else None


def _summarize(result: Any) -> str:
    if isinstance(result, list):
        return f"{len(result)} rows" + (" (EMPTY)" if not result else "")
    if isinstance(result, dict):
        keys = list(result)[:5]
        return f"dict[{len(result)}] {keys}" + (" (EMPTY)" if not result else "")
    return f"{type(result).__name__}"


def main() -> None:
    load_dotenv(REPO_ROOT / ".env")
    settings = Settings.from_env()
    if not (settings.sisense_domain and settings.sisense_token):
        raise SystemExit(
            "No credentials. Put SISENSE_DOMAIN and SISENSE_TOKEN in .env "
            "(gitignored) or pass them as environment variables."
        )

    only = None
    if "--only" in sys.argv:
        only = set(sys.argv[sys.argv.index("--only") + 1].split(","))

    registry = load_registry(settings.registry_path)
    # allow_mutations=False → the selection itself contains reads only.
    surface = select_tools(registry, settings.allowlist, allow_mutations=False)
    dispatcher = SisenseDispatcher(settings, surface)

    print(f"instance: {settings.sisense_domain}")
    print(f"advertised read tools: {len(surface)}\n")

    results: dict[str, Any] = {}
    ok = failed = skipped = 0
    # no-argument tools first: their output feeds the derived arguments
    order = sorted(surface, key=lambda t: bool(surface[t]["parameters"].get("required")))

    for tool_id in order:
        entry = surface[tool_id]
        if only and entry["module"] not in only:
            continue
        assert not entry["mutates"], f"{tool_id} is a write tool — refusing"
        if tool_id in SKIP:
            print(f"  SKIP  {tool_id:<46} {SKIP[tool_id]}")
            skipped += 1
            continue

        args: dict[str, Any] = {}
        required = entry["parameters"].get("required") or []
        if required:
            param, source, keys = DERIVE.get(tool_id, (None, None, None))
            if not param or source not in results:
                print(f"  SKIP  {tool_id:<46} no source for {required}")
                skipped += 1
                continue
            value = _first_value(results[source], keys)
            if value is None:
                print(f"  SKIP  {tool_id:<46} {source} yielded no {keys}")
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
        shown = f" args={args}" if args else ""
        print(f"  OK    {tool_id:<46} {_summarize(result)}{shown}")
        ok += 1

    print(f"\n{ok} ok · {failed} failed · {skipped} skipped")
    if failed:
        raise SystemExit(1)


if __name__ == "__main__":
    main()

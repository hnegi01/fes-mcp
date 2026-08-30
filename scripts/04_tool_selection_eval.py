"""Tool-selection battery: measure which tool an LLM picks for real prompts.

Rewriting tool descriptions blind is how you find out six weeks later that it
got worse — run this BEFORE and AFTER any description, example, or allowlist
change and compare pass rates. Cases live in evals/tool_selection_cases.json;
when a prompt misbehaves in the wild, add it there as a case.

The selector sees exactly what an MCP client sees: the advertised tool names
and composed descriptions (schemas omitted — selection, not argument filling,
is what this measures).

Requires the same LLM env as scripts/02 (LLM_PROVIDER=databricks with
DATABRICKS_HOST/DATABRICKS_TOKEN/LLM_ENDPOINT, or LLM_PROVIDER=azure with
AZURE_OPENAI_*). Usage:

    uv run python -m scripts.04_tool_selection_eval [--read-only]
"""

from __future__ import annotations

import json
import os
import sys
import time
from pathlib import Path

import requests

ROOT = Path(__file__).resolve().parents[1]
CASES_PATH = ROOT / "evals" / "tool_selection_cases.json"


def _llm_config():
    provider = os.getenv("LLM_PROVIDER", "databricks").lower()
    if provider == "azure":
        endpoint = os.environ["AZURE_OPENAI_ENDPOINT"].rstrip("/")
        deployment = os.environ["AZURE_OPENAI_DEPLOYMENT"]
        ver = os.getenv("AZURE_OPENAI_API_VERSION", "2024-11-20")
        url = f"{endpoint}/openai/deployments/{deployment}/chat/completions?api-version={ver}"
        headers = {"api-key": os.environ["AZURE_OPENAI_API_KEY"], "Content-Type": "application/json"}
    else:
        host = os.environ["DATABRICKS_HOST"].rstrip("/")
        endpoint = os.environ["LLM_ENDPOINT"]
        url = f"{host}/serving-endpoints/{endpoint}/invocations"
        headers = {
            "Authorization": f"Bearer {os.environ['DATABRICKS_TOKEN']}",
            "Content-Type": "application/json",
        }
    return url, headers


def _select_tool(url, headers, tool_lines: str, prompt: str, retries: int = 4) -> str:
    payload = {
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are an agent choosing exactly ONE tool for the user's request. "
                    "Reply with only the tool name, nothing else.\n\nAvailable tools:\n"
                    + tool_lines
                ),
            },
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 30,
        "temperature": 0,
    }
    for attempt in range(retries):
        resp = requests.post(url, headers=headers, json=payload, timeout=60)
        if resp.status_code == 200:
            return resp.json()["choices"][0]["message"]["content"].strip().strip("`\"'")
        if resp.status_code in (429, 500, 502, 503, 504):
            time.sleep(2 * (2**attempt))
            continue
        raise RuntimeError(f"LLM call failed {resp.status_code}: {resp.text[:200]}")
    raise RuntimeError("Exceeded retries")


def run_battery(allow_mutations: bool = True) -> dict:
    from fes_mcp.descriptions import compose_description
    from fes_mcp.registry import load_registry, select_tools
    from fes_mcp.settings import DEFAULT_ALLOWLIST_PATH, DEFAULT_REGISTRY_PATH, _load_allowlist_file

    reg = load_registry(DEFAULT_REGISTRY_PATH)
    surface = select_tools(reg, _load_allowlist_file(DEFAULT_ALLOWLIST_PATH), allow_mutations)
    name_of = {tid: tid.replace(".", "_") for tid in surface}
    tool_lines = "\n\n".join(
        f"{name_of[tid]}: {compose_description(e)}" for tid, e in surface.items()
    )

    cases = json.loads(CASES_PATH.read_text())["cases"]
    url, headers = _llm_config()

    results = []
    for case in cases:
        acceptable = {name_of.get(t, t.replace(".", "_")) for t in case["expect"]}
        exposed = any(t in surface for t in case["expect"])
        if not exposed:
            results.append({**case, "picked": None, "ok": None, "skipped": "expected tool not exposed"})
            continue
        picked = _select_tool(url, headers, tool_lines, case["prompt"])
        results.append({**case, "picked": picked, "ok": picked in acceptable})

    scored = [r for r in results if r["ok"] is not None]
    passed = sum(1 for r in scored if r["ok"])
    return {
        "tools_advertised": len(surface),
        "cases": results,
        "passed": passed,
        "scored": len(scored),
        "pass_rate": passed / len(scored) if scored else 0.0,
    }


def main() -> None:
    allow_mut = "--read-only" not in sys.argv
    report = run_battery(allow_mutations=allow_mut)
    for r in report["cases"]:
        if r["ok"] is None:
            mark = "SKIP"
        else:
            mark = " OK " if r["ok"] else "FAIL"
        print(f"[{mark}] {r['prompt'][:64]:<64} -> {r.get('picked')}")
        if r["ok"] is False:
            print(f"        expected one of: {r['expect']}")
    print(
        f"\n{report['passed']}/{report['scored']} passed "
        f"({report['pass_rate']:.0%}) over {report['tools_advertised']} advertised tools"
    )


if __name__ == "__main__":
    main()

# Scripts

The registry pipeline and its supporting tools. `./refresh_registry.sh` runs
the generation steps in order; the rest are run on demand.

1. `01_build_registry_from_sdk.py`
   Introspects every PySisense module facade and writes
   `config/tools.registry.json`: one entry per SDK method with a JSON Schema
   derived from its type annotations and docstring.

2. `02_add_llm_examples_to_registry.py`
   Uses an LLM to generate worked example calls per tool and writes
   `config/tools.registry.with_examples.json` (the registry the server
   loads). For a small set of free-form payload tools, the best example is
   included in the tool's advertised description to teach clients the
   payload shape; the rest are metadata only.

3. `03_reconcile.py`
   Diffs a freshly generated registry against the curated
   `config/allowlist.txt` and appends review sections for new or removed SDK
   methods, so an SDK upgrade never silently changes the tool surface.

4. `04_tool_selection_eval.py`
   Runs a battery of natural-language prompts against the advertised tool
   descriptions with an LLM and reports which tool it selects — a regression
   check that description changes don't degrade tool choice.

5. `05_live_smoke.py`
   Read-only sweep of every advertised read tool against a real Sisense
   instance (credentials via environment). Arguments are derived from earlier
   read results, never invented.

6. `06_capture_output_schemas.py`
   Runs the read surface against a live instance and distills each result's
   shape into a permissive output schema (`config/output_schemas.json`),
   which tools then advertise as `outputSchema`. Optional; not currently
   generated.

`registry_core.py` holds the shared introspection helpers used by the
numbered scripts.

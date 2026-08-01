# Kickoff prompt for the fes_mcp session

Paste everything below the line into the new Claude Code session opened in `~/Desktop/Sisense/fes_mcp`.

---

I'm building **fes_mcp**: a standalone, industry-standard Sisense admin MCP server. It is decoupled from my other project, `fes-assistant` (an internal agent app) — this repo is **tools only, no agent**: Claude Desktop / Claude Code / any MCP client brings its own agent; this server just advertises and executes Sisense admin tools via the PySisense SDK.

## What's already in this folder (seeded from fes-assistant — treat as inputs, not the app)

- `config/tools.registry.with_examples.json` — flat registry of ~119 tools, each entry: `tool_id` (e.g. `datamodel.get_all_datamodel`), `module`, `mutates` flag, `description`, `parameters` (JSON Schema). Auto-generated from PySisense SDK docstrings — **never handwritten**.
- `config/registry/` — the same registry split per package (datamodel, dashboard, access_management, migration, …) with `index.json` files.
- `scripts/01_build_registry_from_sdk.py`, `scripts/02_add_llm_examples_to_registry.py`, `scripts/registry_core.py`, `refresh_registry.sh` — the regeneration pipeline for when PySisense updates. Keep this working.
- `reference/tools_core_REFERENCE.py` — the proven registry-load + SDK-dispatch + validation code from fes-assistant. Read it, mine it, but the new dispatcher should be a slimmed-down single-tenant version.
- `reference/server_REFERENCE.py` — the old hand-rolled Starlette MCP transport. **Reference only — do NOT port it.** It exists because fes-assistant needed nonstandard behavior (per-call multi-tenant cred injection, agent-coupled cancel flags). This project wants the opposite: maximum protocol conformance.

## The stack (decided — don't relitigate)

| Layer | Choice |
|---|---|
| Framework | **FastMCP** (Python) — streamable HTTP transport, sessions, and the OAuth 2.1 machinery for free |
| Tool registration | **Registry-driven factory, not decorators.** Loop over the registry JSON and register each tool programmatically (schema-first: name + description + JSON Schema + dispatcher closure). If the installed FastMCP version fights schema-first registration, fall back to the official `mcp` SDK's low-level `list_tools`/`call_tool` handlers (they accept arbitrary schemas) while keeping the SDK's transport/auth. |
| Dispatcher | `tool_id` → PySisense SDK method. Slim down `reference/tools_core_REFERENCE.py`: keep registry loading, arg validation against the JSON Schema, SDK client construction, dispatch. Drop: per-call multi-tenant cred injection, cancel flags, progress-emit plumbing tied to the old agent. |
| Credentials | **Single tenant, env-configured** (`SISENSE_DOMAIN`, `SISENSE_TOKEN`, SSL flag). Standard MCP shape — the server IS the tenant connection. |
| Auth ladder | `none` (local dev) → `bearer` (static token, for the product-team proxy) → `oauth` (OAuth 2.1, for direct claude.ai connectors). Selected by env var. Build in that order. |
| Tool surface | **Curated allowlist** of admin tools from the registry (env or config-file list of tool_ids / packages), not all 119 blindly. Keep the `mutates` flag surfaced in tool annotations (`destructiveHint`/`readOnlyHint`) so clients can warn before writes. |
| Out of scope v1 | Migration tools (dual-tenant → needs its own mode/endpoint later), any agent loop, multi-tenancy. |

## Context you should know

- The Sisense product team has a TypeScript MCP server (github.com/sisense/sisense-mcp-server, has OAuth + remote hosting). The long-term plan is that it **proxies to this server as an MCP client** for admin tools — merge = proxy, never reimplementation (PySisense orchestrates multi-step API chains infeasible to port to TypeScript). Nothing to build for that now, but don't make design choices that block being consumed by another MCP server as a client.
- Test target for v1: connect it to **Claude Desktop** (local stdio or streamable HTTP connector) and exercise read tools against a real Sisense instance.

## What to do first

1. Scaffold the repo: `pyproject.toml` (uv-managed, Python 3.11), `src/fes_mcp/` package, `.env.example`, README, `.gitignore`, git init.
2. Prove the core thesis in a walking skeleton: FastMCP server + registry factory registering ~5 read-only tools from one package (e.g. `dashboard`) + env-cred dispatcher → verify tool list + a live `get_all_dashboards` call from Claude Desktop with auth=`none`.
3. Then widen: full curated allowlist, `mutates` annotations, bearer auth, tests (unit with mocked SDK; integration gated behind local creds — never put Sisense/LLM secrets in CI).
4. OAuth last, once the tool surface is solid.

Start with step 1 and 2 and show me the walking skeleton before widening.

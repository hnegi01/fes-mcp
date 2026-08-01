# fes_mcp — Sisense Admin MCP Server

A standalone, standards-conformant [MCP](https://modelcontextprotocol.io) server that
exposes Sisense administration tools backed by the
[PySisense](https://pypi.org/project/pysisense/) SDK.

**Tools only, no agent.** Claude Desktop, Claude Code, or any MCP client brings its own
agent; this server advertises and executes Sisense admin tools against a single,
env-configured Sisense tenant.

## Architecture

```
MCP client (Claude Desktop / Claude Code / another MCP server)
        │  stdio or streamable HTTP
        ▼
FastMCP server (src/fes_mcp/server.py)
        │  registry-driven tool factory — one MCP tool per allowlisted registry entry
        ▼
Dispatcher (src/fes_mcp/dispatcher.py)
        │  tool_id → PySisense SDK method, args validated against JSON Schema
        ▼
PySisense SDK  ──►  Sisense REST APIs (single tenant from env)
```

- `config/tools.registry.with_examples.json` — auto-generated tool registry
  (~119 tools). **Never handwritten**; regenerate with `./refresh_registry.sh`
  when PySisense updates.
- `config/allowlist.txt` — curated default tool surface (override with `FES_MCP_TOOLS`).
- Mutating tools carry `destructiveHint`/`readOnlyHint` annotations so clients can
  warn before writes; they are also blocked server-side unless
  `FES_MCP_ALLOW_MUTATIONS=true`.

## Quick start

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
cp .env.example .env   # fill in SISENSE_DOMAIN / SISENSE_TOKEN
uv run fes-mcp         # stdio transport by default
```

Streamable HTTP instead:

```bash
FES_MCP_TRANSPORT=http FES_MCP_PORT=8200 uv run fes-mcp
# MCP endpoint: http://127.0.0.1:8200/mcp
```

## Claude Desktop (local stdio)

Add to `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "sisense-admin": {
      "command": "uv",
      "args": ["run", "--directory", "/absolute/path/to/fes_mcp", "fes-mcp"],
      "env": {
        "SISENSE_DOMAIN": "your-instance.sisense.com",
        "SISENSE_TOKEN": "your-api-token",
        "SISENSE_SSL_VERIFY": "true"
      }
    }
  }
}
```

## Configuration

All configuration is via environment variables (see `.env.example`):

| Variable | Default | Purpose |
|---|---|---|
| `SISENSE_DOMAIN` | — | Sisense instance domain (required) |
| `SISENSE_TOKEN` | — | Sisense API token (required) |
| `SISENSE_SSL_VERIFY` | `true` | Verify TLS certs when calling Sisense |
| `FES_MCP_AUTH` | `none` | `none` \| `bearer` \| `oauth` (client-facing auth ladder) |
| `FES_MCP_TOOLS` | curated list | Comma-separated tool_ids and/or module names |
| `FES_MCP_ALLOW_MUTATIONS` | `false` | Expose/permit mutating tools |
| `FES_MCP_TRANSPORT` | `stdio` | `stdio` \| `http` |
| `FES_MCP_HOST` / `FES_MCP_PORT` | `127.0.0.1` / `8200` | HTTP bind address |
| `FES_MCP_REGISTRY_PATH` | bundled registry | Alternate registry JSON |
| `FES_MCP_LOG_LEVEL` | `INFO` | Log verbosity (logs go to stderr, never stdout) |

## Registry regeneration

```bash
./refresh_registry.sh   # rebuilds config/ from the installed PySisense SDK
```

## Out of scope (v1)

- Migration tools (dual-tenant — needs its own mode later)
- Multi-tenancy, any agent loop

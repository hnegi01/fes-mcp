# Integration Tests

**Unit tests** (`tests/unit/`) run on every `pytest` invocation: fast, mocked,
no credentials — the default `testpaths` only includes them.

**Integration tests** (this folder) hit a **real Sisense instance** and are
**read-only by policy**: the tool surface is selected with mutations off, no
write tool is ever invoked, and arguments are derived from earlier read
results, never invented. They skip automatically (not fail) when no
credentials are configured, so CI stays green.

## Credentials — one place

```bash
cp tests/integration/integration_config.example.yaml \
   tests/integration/integration_config.yaml
# edit it with a real Sisense domain + API token (file is gitignored)
```

## Run

```bash
uv run python -m pytest tests/integration -m integration -v
```

For a quick sweep without pytest: `uv run python -m scripts.05_live_smoke`
(same derivation rules; the surface test here reuses them).

## What they cover

- every advertised read tool answers on a real box (`test_live_read_surface`)
- the dispatcher's ID-or-title resolution against real data
- clean-error contract for a nonexistent model (the 2.0 `ok` marker, live)
- MCP round-trips through a real server: env mode, and upstream mode with the
  injected-header trust path verified against the real instance (valid token
  works, garbage token → 401)

## Reading a failure

A tenant is live data: a failure can mean the tenant changed (no dashboards
visible to the token, a renamed model) rather than a code bug. Re-run the
single test, then look at what the tenant actually holds before suspecting
the code.

# fes_mcp — Sisense MCP server. Multi-stage build producing the project's
# two service images:
#
#   docker build --target fes-auth -t sisense-fes-auth .   # authorization server (login UI + proxy)
#   docker build --target fes-mcp  -t sisense-fes-mcp  .   # resource server (tools)
#
# `docker compose up --build` builds and runs both — see docker-compose.yml.

FROM python:3.11-slim AS base

COPY --from=ghcr.io/astral-sh/uv:latest /uv /uvx /usr/local/bin/

WORKDIR /app

# Dependency layer first so code changes don't re-resolve the environment.
COPY pyproject.toml uv.lock README.md ./
RUN uv sync --frozen --no-dev --no-install-project

# The app: src layout + config/ (tool registry + curated allowlist).
COPY src ./src
COPY config ./config
RUN uv sync --frozen --no-dev

# Non-root. pysisense writes ./logs/pysisense.log relative to CWD.
RUN mkdir -p /app/logs && useradd -r -u 10001 fesmcp && chown fesmcp /app/logs
USER fesmcp

# Network server defaults; with http transport the resource server's auth
# mode defaults to `upstream` (credentials injected per request by fes-auth).
ENV FES_MCP_TRANSPORT=http \
    FES_MCP_HOST=0.0.0.0 \
    FES_MCP_PORT=8200

EXPOSE 8200

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s CMD \
    python -c "import os,urllib.request,sys; p=os.environ.get('FES_MCP_PORT','8200'); sys.exit(0 if urllib.request.urlopen(f'http://127.0.0.1:{p}/healthz',timeout=3).status==200 else 1)"

# ---- the two shipped images (venv fully built; no uv needed at runtime) ----

FROM base AS fes-mcp
CMD ["/app/.venv/bin/fes-mcp"]

FROM base AS fes-auth
CMD ["/app/.venv/bin/fes-auth"]

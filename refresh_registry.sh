#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "=== Refreshing PySisense tool registry ==="
echo "Repo root: ${REPO_ROOT}"
echo

cd "${REPO_ROOT}"

echo "[0/3] Syncing the pinned environment..."
uv sync

echo "[1/3] Building tool registry from SDK..."
uv run python -m scripts.01_build_registry_from_sdk

echo "[2/3] Reconciling: port examples across renames, merge, stage/deprecate allowlist..."
uv run python -m scripts.03_reconcile

echo "[3/3] (optional) LLM examples for NEW tools — needs LLM_PROVIDER env:"
echo "        uv run python -m scripts.02_add_llm_examples_to_registry"

echo
echo "Generated files:"
echo "  - config/tools.registry.json"
echo "  - config/tools.registry.with_examples.json"
echo "  - config/registry/  (hierarchical, with examples)"
echo
echo "=== Done ==="

# Contributing

Issues and pull requests are welcome. This is a community-contributed project
from Sisense Field Engineering — see the experimental notice in the README for
what that means for support.

## Development setup

```bash
git clone https://github.com/hnegi01/fes-mcp
cd fes-mcp
uv sync
uv run python -m pytest        # unit tests: fast, mocked, no credentials
```

Branches: work happens on `dev`; `main` moves only through pull requests and
carries the release tags.

## Guidelines

- **Tests**: every change lands with unit tests; `uv run python -m pytest`
  must be green. Integration tests (`tests/integration/`) need a real Sisense
  instance and are opt-in — see `tests/integration/README.md`.
- **Tool surface**: the advertised tools come from `config/allowlist.txt`
  (hand-curated) applied to the generated registry. Never edit the registry
  JSON by hand — regenerate it with `./refresh_registry.sh` (see
  `scripts/README.md`).
- **Security posture**: no credentials, instance URLs, or deployment
  specifics in the repo — placeholders only. Mutating tools stay behind
  `FES_MCP_ALLOW_MUTATIONS` and must carry `destructiveHint`.
- **Docs**: describe what the server does, not the history of how it got
  there.

## Releases

Maintainers cut releases by tagging `main` (`git tag v0.x.y && git push
origin v0.x.y`); GitHub Actions runs the tests, publishes the two container
images to GHCR, and creates the GitHub release.

# Contributing

## Development setup

1. `python3.11 -m venv .venv && source .venv/bin/activate`
2. `pip install -e .[dev]`
3. `PYTHONPATH=src pytest -v`

## Commit style (Conventional Commits)

Use commit messages like:
- `feat: add anthropic wrapper`
- `fix: handle missing upstream key`
- `docs: improve proxy readme`
- `test: add proxy integration test`

Allowed types: `feat`, `fix`, `docs`, `test`, `refactor`, `chore`, `ci`, `perf`, `build`, `revert`.

## Pull requests

- Keep PRs focused and small.
- Add/update tests for behavior changes.
- Update docs/config examples if behavior changes.
- Ensure CI is green.

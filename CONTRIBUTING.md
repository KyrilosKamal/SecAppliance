# Contributing

```bash
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"
ruff check . && pytest -q
```

- One change per pull request, with tests for parsing/matching logic.
- New offline CVE signatures must cite the advisory for the exact product and version range.
- Bump `secappliance/__init__.py` and `pyproject.toml` together, then add a `CHANGELOG.md` entry. Releases are cut by pushing a `vX.Y.Z` tag.

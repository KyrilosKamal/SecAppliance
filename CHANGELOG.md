## 2.2.0

- Version bump to 2.2.0.

# Changelog

## 2.1.0

### Breaking
- `python main.py ...` no longer exists. Run `secappliance ...` or `python -m secappliance ...` after `pip install .` (or use a release binary).
- Source moved: `core/`, `utils/`, `main.py` are now `secappliance/core/`, `secappliance/utils/`, `secappliance/cli.py`. `config/signatures.json` is now `secappliance/data/signatures.json`; `reporting/templates/` is now `secappliance/templates/`.

### Packaging
- Proper Python package with `pyproject.toml`, `secappliance` console command, `python -m secappliance`, and `--version`.
- Data and templates ship inside the wheel; source, wheel and frozen (PyInstaller) builds resolve them through one helper (`secappliance/utils/paths.py`).
- PyInstaller spec moved to `packaging/` and rewritten for the package layout.
- Release workflow: pushing tag `vX.Y.Z` builds wheel, sdist, Linux/Windows/macOS binaries and `SHA256SUMS`; the tag must match the package version.
- CI runs ruff and pytest on Linux and Windows (Python 3.11 and 3.13) and smoke-tests the built wheel. Dependabot enabled.
- Dev tools are now the `dev` extra: `pip install -e ".[dev]"` (`requirements-dev.txt` and `pytest.ini` removed). `requirements.txt` stays as the pinned set used for binary builds.
- Added `LICENSE` (MIT), `SECURITY.md`, `CONTRIBUTING.md`; README rewritten for end users; `.gitignore` expanded.
- Removed the internal review log (`REVIEW_FIXES.md`) from the tree. It remains in git history.

### Fixed
- SSH collector: `ss` parser checked `len >= 5` then read `parts[5]` (IndexError, silent data loss). Now `RemoteCollector.parse_ss_output`, which skips short rows; the SSH client is always closed.
- Offline signatures: removed two wrong CVE mappings (Postfix -> `CVE-2013-0241` is a QXL driver bug; RealVNC -> `CVE-2018-7226` is LibVNC/vncterm).
- Offline matching uses boundaries, so "MySQL 5.5" no longer matches "5.55".
- `net_utils`: duplicate `"CLOSING"` dict key; unused imports removed.
- Port scan runs in chunks of 1000 per host, so full-range sweeps no longer create tens of thousands of coroutines per host at once.
- `colorama` is a hard dependency on all platforms (it was imported unconditionally).

### Changed
- Online CVE version matching understands `lessThan`, `lessThanOrEqual` and textual ranges ("through X"), not just two-component prefixes.
- Web header probe retry without TLS verification is logged explicitly and documented in the README.

### Added
- `--offline` flag: skips the CIRCL lookup so no banner or version data leaves the machine.
- `--version` flag.
- pytest suite (21 tests) for parsing, version-range matching, signature matching, port chunking and the SSH parser.

## 2.0.0
- Security: plaintext WinRM off by default (`--allow-insecure-winrm-http`), `--password` CLI flag removed (env var or hidden prompt), SSL check no longer reports `verified=True` after a failed handshake.
- Stability: `asyncio.Lock` around SQLite writes; SSH/WinRM, psutil and DNS no longer block the event loop.
- Performance: batched transactions (`executemany`) and SQLite indexes; a /24 scan's commit time dropped from about 14.8 s to about 1.8 s.
- Reporting: CVE findings affect risk score and counts; HSTS/Server header false positives fixed; derived ports are labeled and no longer shown as active connections.
- Operations: database and logs moved to per-user OS directories (`platformdirs`); dependencies pinned; dead code removed.
- Online CVE layer: CIRCL lookups with a 7-day SQLite cache, client-side version filtering and dedicated report sections.

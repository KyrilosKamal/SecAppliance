<div align="center">

# SecAppliance

![Python Version](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)
![Code Review](https://img.shields.io/badge/code%20review-25%20items%20resolved-success)


</div>

**SecAppliance** is a professional-grade network security scanner designed for automated vulnerability assessment and reconnaissance. It combines high-performance asynchronous scanning with offline CVE mapping and credentialed auditing.


##  Key Features
- Async Scanning**: High-performance, asynchronous scanning engine for rapid target assessment.
- Offline CVE Mapping**: Localized, signature-based vulnerability detection requiring no external API dependencies.
- Credentialed Audit Mode**: Supports SSH and WinRM for deep, authenticated configuration auditing.
- HTML Reporting**: Automated, professional-grade executive reports in HTML format.
- CLI Interface**: Intuitive command-line interface for seamless integration into automation workflows.
- Secure by Default**: SSH host keys are verified against `known_hosts`, and WinRM/web TLS certificates are validated by default. Passwords are never accepted via CLI arguments.

## Prerequisites
- Python **3.11** or higher. The pinned dependency set requires it (`platformdirs` 4.14.5 needs 3.11+; `click` 8.5.1, `aiohttp` 3.14.5, and `typer` 0.28.0 need 3.10+).

## Installation

We recommend running SecAppliance in an isolated virtual environment to prevent dependency conflicts.

1. Clone the repository:
   ```bash
   git clone https://github.com/KyrilosKamal/SecAppliance.git
   cd SecAppliance
   ```

2. Create and activate a virtual environment:
   ```bash
   # Linux / macOS
   python3 -m venv venv
   source venv/bin/activate

   # Windows (Command Prompt)
   python -m venv venv
   venv\Scripts\activate

   # Windows (PowerShell)
   .\venv\Scripts\Activate.ps1
   ```

3. Install dependencies:
   ```bash
   pip install --upgrade pip
   pip install -r requirements.txt
   ```
   *(All dependencies are strictly pinned for reproducible builds. To upgrade, test, and re-pin deliberately).*

## CLI Usage

```bash
python main.py [OPTIONS]
```

| Flag | Type | Description | Default |
| :--- | :--- | :--- | :--- |
| `--target`, `-t` | str | Target IP address or CIDR range (required) | N/A |
| `--ports`, `-p` | str | Port range to scan (e.g. `1-65535`, `80,443,8080`) | 1-1024 |
| `--web-ports`, `-w` | str | Comma-separated list of web ports to scan (1-65535) | 80,443,8080,8443 |
| `--username`, `-u` | str | Remote SSH/WinRM username | None |
| `--auth-type`, `-a` | `winrm`\|`ssh` | Auth protocol for credentialed deep collection | winrm |
| `--output-dir`, `-o` | path | Output directory for reports | reports |
| `--verbose`, `-v` | bool | Enable detailed debug logging | False |
| `--accept-unknown-hosts` | bool | Auto-accept unknown SSH host keys (insecure) | False |
| `--accept-invalid-certs` | bool | Skip TLS validation for WinRM/web checks (insecure) | False |
| `--allow-insecure-winrm-http` | bool | Allow WinRM over plaintext HTTP 5985 (insecure) | False |
| `--force` | bool | Allow scanning CIDR ranges larger than `/16` | False |

> **Password Handling**: Credentials are never accepted on the command line. The password is read from the `SECAPPLIANCE_PASSWORD` environment variable, or prompted interactively without echo when unset.
> 
> **Data Directory**: The scan database and log file live in the per-user data directory (`~/.local/share/SecAppliance/` on Linux, or `%LOCALAPPDATA%\SecAppliance` on Windows). Generated reports stay relative to the current directory.

### Usage Examples

1. **Fast unauthenticated subnet scan**:
   ```bash
   python main.py -t 192.168.1.0/24
   ```
2. **Custom port range + output dir**:
   ```bash
   python main.py -t 10.0.0.1 -p 1-65535 -o ./my_reports
   ```
3. **Credentialed WinRM deep audit (secure password handling)**:
   ```bash
   export SECAPPLIANCE_PASSWORD='secret123'
   python main.py -t 10.0.0.5 -u admin -a winrm
   ```
4. **Verbose scan of a single host with a wide port range**:
   ```bash
   python main.py -t 10.0.0.1 -p 1-65535 -v
   ```

## Project Architecture
```text
SecAppliance/
├── config/              # JSON configuration files (signatures.json)
├── core/                # Core scanning logic
│   ├── database.py      # Async SQLite manager (WAL-ready, batched commits)
│   ├── network_scanner.py # Network scanning & banner grabbing
│   ├── remote_collector.py# SSH/WinRM configuration collector
│   ├── report_generator.py# HTML report generation logic
│   ├── vuln_lookup.py   # Local CVE signature matching
│   └── web_scanner.py   # Web-specific vulnerability scanner
├── reporting/           # HTML/CSS templates for executive reports
├── utils/               # Utility functions (logger, net_utils)
├── main.py              # CLI entry point
├── requirements.txt     # Strictly pinned project dependencies
├── REVIEW_FIXES.md      # Engineering log: 25-point code review & fixes
└── SecAppliance.spec    # PyInstaller configuration
```

## Engineering Log & Changelog

This project underwent a rigorous 25-point architectural and security review. All Critical, Major, and Improvement items have been resolved.

**To read the detailed decisions, trade-offs, and verification methods for every fix (including DB indexes, concurrency locks, and event-loop blocking), please see [REVIEW_FIXES.md](REVIEW_FIXES.md).**

### Latest Updates (v2.0.0)

- **Security Hardening**: Removed plaintext WinRM by default (requires `--allow-insecure-winrm-http`), eliminated the `--password` CLI flag entirely, and fixed SSL checks reporting `verified=True` on failed handshakes.
- **Concurrency & Stability**: Implemented a robust `asyncio.Lock` for SQLite writes to prevent silent data loss during concurrent rollbacks. Eliminated Event Loop blocking (SSH/WinRM, psutil, DNS).
- **Performance**: Replaced per-row commits with batched transactions (`executemany`), reducing a /24 scan commit time from ~14.8s to ~1.8s. Added SQLite indexes for all report/host lookups.
- **Report Accuracy**: CVE findings now affect the risk score and vulnerability counts. Fixed HSTS/Server header false positives. Derived ports (open but unconnected) are now explicitly labeled and no longer fabricated as active connections.
- **Operations**: Data paths (DB, logs) moved to per-user OS directories (`platformdirs`). Requirements are strictly pinned. Dead code and unused dependencies removed.

## Known Limitations
- **Authenticated collection requires reachable services**: SSH/WinRM connection collection only succeeds when the target exposes those services and valid credentials are provided.
- **WinRM SSL validation**: When WinRM runs over HTTPS with a self-signed certificate, collection fails until `--accept-invalid-certs` is used.
- **SSH host key verification**: New hosts not present in `known_hosts` are rejected by default. Use `ssh-keyscan` or `--accept-unknown-hosts` (insecure).
- **Offline CVE database**: Relies on local `config/signatures.json`; newly published CVEs require manual signature updates.
- **HTTP/HTTPS detection**: Assumes HTTPS on ports 443 and 8443, and HTTP otherwise. Non-standard SSL ports are not auto-detected.
- **No automated test suite**: The repository ships no `tests/` directory or CI. The 25 fixes were verified ad hoc; treat `REVIEW_FIXES.md` as the record of what was verified and how.

## Legal Disclaimer
**Authorized use only.** This tool is for security testing of systems you own or have explicit permission to audit. Scanning without prior written permission is illegal. The developers assume no liability for misuse.

## License
MIT

# SecAppliance

![CI](https://github.com/KyrilosKamal/SecAppliance/actions/workflows/ci.yml/badge.svg)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![License](https://img.shields.io/badge/license-MIT-green)

Async network and web security scanner. Finds open ports, grabs banners, checks web security headers and TLS, matches service versions to CVEs (offline signatures plus optional live CIRCL lookup), optionally collects connections from hosts over SSH/WinRM, and writes a self-contained HTML report.

> **Authorized use only.** Scan systems you own or have written permission to test. You are responsible for how you use this tool.

## Install

Requires Python 3.11+.

```bash
# isolated install from GitHub (recommended)
pipx install git+https://github.com/KyrilosKamal/SecAppliance.git

# or with pip inside a virtualenv
python -m venv .venv && source .venv/bin/activate     # Windows: .venv\Scripts\activate
pip install git+https://github.com/KyrilosKamal/SecAppliance.git
```

Standalone binaries (Linux, Windows, macOS) and checksums are attached to each [release](https://github.com/KyrilosKamal/SecAppliance/releases).

## Usage

```bash
secappliance -t 192.168.1.0/24                  # scan a subnet, ports 1-1024
secappliance -t 10.0.0.1 -p 1-65535 -o ./reports
secappliance -t 10.0.0.1 --offline              # no data leaves this machine
export SECAPPLIANCE_PASSWORD='...'              # credentialed audit
secappliance -t 10.0.0.5 -u admin -a winrm
secappliance --help
```

| Flag | Description | Default |
| :--- | :--- | :--- |
| `-t, --target` | IP or CIDR (required) | - |
| `-p, --ports` | Ports, e.g. `1-65535` or `80,443` | `1-1024` |
| `-w, --web-ports` | Ports checked as web services | `80,443,8080,8443` |
| `-u, --username` | SSH/WinRM username | none |
| `-a, --auth-type` | `winrm` or `ssh` | `winrm` |
| `-o, --output-dir` | Report directory | `reports` |
| `-v, --verbose` | Debug logging | off |
| `--offline` | Skip live CIRCL CVE lookup | off |
| `--accept-unknown-hosts` | Accept unknown SSH host keys (insecure) | off |
| `--accept-invalid-certs` | Skip TLS validation for WinRM/web (insecure) | off |
| `--allow-insecure-winrm-http` | WinRM over plaintext 5985 (insecure) | off |
| `--force` | Allow ranges larger than /16 | off |
| `--version` | Print version | - |

Passwords are never accepted on the command line. The scan database and log live in the per-user data directory (`~/.local/share/SecAppliance` on Linux, `%LOCALAPPDATA%\SecAppliance` on Windows).

## Privacy

Unless `--offline` is set, product/version strings parsed from service banners are sent to the public CIRCL CVE API (results cached 7 days). Nothing else leaves the machine.

## Known limitations

- Offline CVE list is small and hand-verified (`secappliance/core/vuln_lookup.py`). The live layer depends on CIRCL availability and banner accuracy. Treat findings as leads to verify, not proof.
- Banner grabbing is passive. No active protocol probes, no UDP.
- If an HTTPS port fails certificate validation, the certificate problem is reported and a header-only GET is retried without verification (no credentials sent).
- HTTPS is assumed on 443/8443, HTTP elsewhere.
- Authenticated collection needs reachable SSH/WinRM and valid credentials. Unknown SSH host keys are rejected unless `--accept-unknown-hosts`.
- Network scanning is covered by unit tests of parsing and matching logic, not by integration tests.

## Development

```bash
pip install -e ".[dev]"
ruff check . && pytest -q
```

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), [CHANGELOG.md](CHANGELOG.md).

## License

MIT, see [LICENSE](LICENSE).

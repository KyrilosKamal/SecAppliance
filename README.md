# SecAppliance

SecAppliance is a professional-grade network security scanner designed for automated vulnerability assessment and reconnaissance.

## Key Features
- **Async Scanning**: High-performance, asynchronous scanning engine for rapid target assessment.
- **Offline CVE Mapping**: Localized, signature-based vulnerability detection requiring no external API dependencies.
- **Credentialed Audit Mode**: Supports SSH and WinRM for deep, authenticated configuration auditing.
- **HTML Reporting**: Automated, professional-grade executive reports in HTML format.
- **CLI Interface**: Intuitive command-line interface for seamless integration into automation workflows.
- **Secure by Default**: SSH host keys are verified against `known_hosts` and WinRM/web TLS certificates are validated by default.

## Prerequisites
- Python 3.9 or higher

## Installation
1. Clone the repository:
   ```bash
   git clone https://github.com/KyrilosKamal/SecAppliance.git
   ```
2. Navigate to the repository:
   ```bash
   cd SecAppliance
   ```
3. Install dependencies:
   ```bash
   pip install -r requirements.txt
   ```

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
| `--password`, `-P` | str | Remote password (visible in process list; prefer `SECAPPLIANCE_PASSWORD`) | None |
| `--auth-type`, `-a` | str | Auth protocol (`winrm` or `ssh`) | winrm |
| `--output-dir`, `-o` | path | Output directory for reports | reports |
| `--verbose`, `-v` | bool | Enable detailed debug logging | False |
| `--accept-unknown-hosts` | bool | Automatically accept unknown SSH host keys (insecure) | False |
| `--accept-invalid-certs` | bool | Skip TLS certificate validation for WinRM and web checks (insecure) | False |

> **Password handling**: Passwords are resolved from the `SECAPPLIANCE_PASSWORD`
> environment variable, falling back to an interactive prompt. Passing a password
> via `--password` exposes it in the process list and shell history and should be
> avoided.
>
> **Transport security**: SSH host keys are verified against `known_hosts`
> (`RejectPolicy`) and WinRM/web TLS certificates are validated by default. Use
> the `--accept-unknown-hosts` / `--accept-invalid-certs` flags only against
> targets you control.

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
4. **Credentialed SSH deep audit**:
   ```bash
   export SECAPPLIANCE_PASSWORD='secret123'
   python main.py -t 10.0.0.6 -u root -a ssh
   ```
5. **Verbose scan of a single host with a wide port range**:
   ```bash
   python main.py -t 10.0.0.1 -p 1-65535 -v
   ```

## Project Architecture
```text
SecAppliance/
├── config/            # JSON configuration files
│   └── signatures.json # Security signatures
├── core/              # Core scanning logic
│   ├── database.py    # Async SQLite manager
│   ├── network_scanner.py # Network scanning & banner grabbing
│   ├── remote_collector.py # SSH/WinRM configuration collector
│   ├── report_generator.py # HTML report generation logic
│   ├── vuln_lookup.py # Local CVE signature matching
│   └── web_scanner.py # Web-specific vulnerability scanner
├── reporting/         # Reporting templates
│   └── templates/
│       ├── executive_report.html # HTML template
│       └── style.css  # CSS styling
├── reports/           # Generated reports output
├── utils/             # Utility functions
│   ├── logger.py      # Logging configuration
│   └── net_utils.py   # Networking helpers
├── main.py            # CLI entry point
├── requirements.txt   # Project dependencies
└── SecAppliance.spec  # PyInstaller configuration
```

## Report Generation
Reports are automatically generated upon scan completion, saved in HTML format within the `reports/` directory, named with a timestamp for easy tracking.

## Latest Updates (v1.1.0 — 2026-08-14)

### Security improvements
- SSH host keys are now verified against `known_hosts` (`RejectPolicy`) instead of being auto-accepted, preventing man-in-the-middle attacks. Unknown hosts fail with remediation guidance; opt in to insecure auto-accept with `--accept-unknown-hosts`.
- WinRM TLS certificates are validated by default instead of `server_cert_validation='ignore'`; opt in to insecure validation with `--accept-invalid-certs`.
- Web header checks and SSL checks now use a verified TLS context. Certificate failures are classified (expired, self-signed, hostname mismatch, untrusted issuer) and still probed so expiry can be reported.
- Passwords can be supplied via the `SECAPPLIANCE_PASSWORD` environment variable or an interactive prompt, avoiding exposure in the process list and shell history.

### Bug fixes
- Fixed incorrect TCP state mapping (`map_tcp_state`): numeric Linux state codes, `ss` abbreviations (e.g. `ESTAB`), and Windows states are now translated correctly.
- Removed a false-positive "BlueKeep" finding that matched every RDP host regardless of version.
- Fixed CVE signature matching so real banners match (e.g. `SSH-2.0-OpenSSH_7.2p2`, `Apache/2.4.49`); matching now uses both the service name and the banner.
- Scan status is marked `completed` before report generation so the recorded duration is accurate.
- `--web-ports` values are now validated to the 1-65535 range.
- WebScanner loads `config/signatures.json` relative to the project root, so it works from any working directory.
- Host scans are processed in bounded batches to avoid exhausting memory on large target ranges; reverse-DNS lookups no longer block the event loop.

### Maintenance
- Removed unused imports, duplicate helpers, and dead code.
- Removed unused dependencies (`weasyprint`, `scapy`) from `requirements.txt`.

## Known Limitations
- **Authenticated collection requires reachable services**: SSH/WinRM connection collection only succeeds when the target exposes those services and valid credentials are provided. WinRM requires port 5985 (HTTP) or 5986 (HTTPS) to be reachable.
- **WinRM SSL validation**: When WinRM runs over HTTPS with a self-signed certificate, collection fails by default until the certificate is trusted or `--accept-invalid-certs` is used (insecure).
- **SSH host key verification**: New hosts not present in `known_hosts` are rejected by default. Add them with `ssh-keyscan <host> >> ~/.ssh/known_hosts` or use `--accept-unknown-hosts` (insecure).
- **Offline CVE database**: Vulnerability detection relies on the local `config/signatures.json` signature set and does not query live CVE databases (e.g. NVD). Newly published CVEs will not be detected until signatures are updated.
- **HTTP/HTTPS detection**: The web scanner assumes HTTPS on ports 443 and 8443 and HTTP otherwise; non-standard SSL ports are not auto-detected.
- **Firewall/rate limiting**: Port scanning and web checks can be slowed or blocked by host firewalls, IDS/IPS, or rate limiting. `--verbose` enables debug logging for troubleshooting.
- **Platform dependence of connection collection**: Local connection collection uses `psutil` and remote collection relies on `ss` (Linux) or PowerShell `Get-NetTCPConnection` (Windows); behavior may vary across platforms.

## Legal Disclaimer
**Authorized use only.** This tool is for security testing of systems you own or have explicit permission to audit. Scanning without prior written permission is illegal. The developers assume no liability for misuse.

## License
MIT

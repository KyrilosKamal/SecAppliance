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
- Python **3.11** or higher. The pinned dependency set requires it
  (`platformdirs` 4.14.5 needs 3.11+; `click` 8.5.1, `aiohttp` 3.14.5 and
  `typer` 0.28.0 need 3.10+).

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
   Every entry in `requirements.txt` is pinned to an exact version, so installs
   are reproducible. Upgrade deliberately (`pip install -U <pkg>`, re-test, then
   re-pin), not by floating ranges.

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
| `--accept-unknown-hosts` | bool | Automatically accept unknown SSH host keys (insecure) | False |
| `--accept-invalid-certs` | bool | Skip TLS certificate validation for WinRM and web checks (insecure) | False |
| `--allow-insecure-winrm-http` | bool | Allow WinRM over plaintext HTTP on 5985, sending NTLM credentials unencrypted (insecure) | False |
| `--force` | bool | Allow scanning CIDR ranges larger than `/16` (hosts are streamed, not materialized) | False |

> **Password handling**: Credentials are never accepted on the command line — there
> is no password flag. The password is read from the `SECAPPLIANCE_PASSWORD`
> environment variable, or prompted for interactively without echo when that
> variable is unset, keeping it out of the process list and shell history.
> The scan database and log file live in the per-user data directory
> (`~/.local/share/SecAppliance/` on Linux, or `%LOCALAPPDATA%\SecAppliance` on
> Windows); generated reports stay relative to the current directory.
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
├── reporting/         # Reporting templates and styles
│   └── templates/
│       ├── executive_report.html # HTML template
│       └── style.css  # CSS styling
├── reports/           # Generated reports output
├── utils/             # Utility functions
│   ├── logger.py      # Logging configuration
│   └── net_utils.py   # Networking helpers
├── main.py            # CLI entry point
├── requirements.txt   # Pinned project dependencies
├── REVIEW_FIXES.md    # Code-review fix log (what changed and why)
└── SecAppliance.spec  # PyInstaller configuration
```

## Report Generation
Reports are automatically generated upon scan completion, saved in HTML format,
and named with a timestamp for easy tracking. The destination is `--output-dir`
(default `reports`), resolved relative to the current working directory — unlike
the scan database and log file, which live in the per-user data directory.

## Latest Updates (v1.2.0 — 2026-11-08)

A full code review of the 1.1.0 tree produced 25 findings; all Critical, Major
and Improvement items are now resolved. `REVIEW_FIXES.md` carries one entry per
finding with root cause, exact change and verification output.

### Correctness and data integrity
- Fixed an unbound `scan_id` in the scan error path, which could mask the real
  failure with a `NameError`.
- CIDR ranges are no longer expanded into a full host list in memory: hosts are
  streamed, so targets larger than `/16` are possible with `--force` instead of
  exhausting RAM.
- Web scanning now actually runs for CIDR targets; it previously no-opped and
  reported success with zero web findings.
- CVE findings are included in the risk score, the vulnerability total and the
  severity breakdown; they were previously counted only in one of the four
  places a reader saw a number.
- Scan duration no longer mixes a naive-UTC start with a local-time fallback.
  `datetime.utcnow()` (deprecated) was replaced throughout.
- Active-connection rows now record the observation time rather than the
  report-generation time, and rows derived from open ports are no longer
  presented as observed traffic — they appear in a separate, explicitly labelled
  "Derived Ports" section.
- Fixed the inverted `Server` header check and the HSTS check running against
  plain HTTP.
- Reports now carry working CSS: the embedded stylesheet is no longer
  HTML-escaped (`>` became `&gt;`), and the risk/severity class names match the
  selectors that exist in `style.css` (`N/A` classifications included).
- List queries now have explicit `ORDER BY` clauses (vulnerability severity rank,
  then host and port; ports by number), so report sections are stable across
  runs. The duplicated vulnerability SQL in `report_generator.py` got the
  identical clause to prevent drift.

### Concurrency and performance
- All hosts shared one aiosqlite connection with no write serialization: a
  rollback in one task silently discarded another host's committed rows. Writes
  now go through a `_write_lock`, verified with 25 concurrent iterations and
  zero lost rows.
- The SSH/WinRM round trip, `is_local()`'s hostname lookup and the `psutil`
  connection sweep no longer block the event loop; each runs on a thread while
  database writes stay on the loop.
- Per-row commits replaced with batch writes: 1000 ports went from ~6272 ms to
  ~10 ms on btrfs.
- Added indexes on the columns the report and host lookups filter on
  (`hosts(scan_id, ip_address)`, `ports(host_id)`, `vulnerabilities(host_id)`,
  `active_connections(scan_id)`, `derived_ports(scan_id)`).

### Security
- Removed the `--password` flag entirely: the secret is read from
  `SECAPPLIANCE_PASSWORD` or prompted without echo, so it never appears in the
  process list or shell history.
- WinRM over plaintext HTTP now requires explicit opt-in
  (`--allow-insecure-winrm-http`); NTLM credentials are no longer sent
  unencrypted by default.
- SSL checks no longer report `verified=True` for connections that never
  completed a handshake.

### CLI and operations
- `auth_type` defaults agree between the CLI and the collector (`winrm`), and
  the option rejects anything outside `winrm|ssh` at parse time.
- The scan database and log file moved to the per-user data directory
  (`platformdirs`) instead of the current working directory. Logging is
  console-only by default and falls back to it if the log path is unwritable,
  including on import in a read-only directory.
- Dependencies are pinned exactly, and `requirements.txt` now lists `click` and
  `platformdirs`, which the code imported but which were only satisfied
  transitively.

### Maintenance
- Deleted dead code, including an unused `DatabaseManager.add_vulnerability`
  method superseded by the batch path.

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
- **No automated test suite**: the repository ships no `tests/` directory and no CI. Regression checks for the fixes in the release notes above were run ad hoc against in-memory databases; treat `REVIEW_FIXES.md` as the current record of what was verified and how.

## Legal Disclaimer
**Authorized use only.** This tool is for security testing of systems you own or have explicit permission to audit. Scanning without prior written permission is illegal. The developers assume no liability for misuse.

## License
MIT

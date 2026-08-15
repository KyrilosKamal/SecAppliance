# SecAppliance

SecAppliance is a professional-grade network security scanner designed for automated vulnerability assessment and reconnaissance.

## Key Features
- **Async Scanning**: High-performance, asynchronous scanning engine for rapid target assessment.
- **Offline CVE Mapping**: Localized, signature-based vulnerability detection requiring no external API dependencies.
- **Credentialed Audit Mode**: Supports SSH and WinRM for deep, authenticated configuration auditing.
- **HTML Reporting**: Automated, professional-grade executive reports in HTML format.
- **CLI Interface**: Intuitive command-line interface for seamless integration into automation workflows.

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
| `--ports`, `-p` | str | Port range to scan | 1-1024 |
| `--web-ports`, `-w` | str | Comma-separated list of web ports to scan | 80,443,8080,8443 |
| `--username`, `-u` | str | Remote SSH/WinRM username | None |
| `--password`, `-P` | str | Remote password (visible in process list; prefer `SECAPPLIANCE_PASSWORD`) | None |
| `--auth-type`, `-a` | str | Auth protocol ('winrm' or 'ssh') | winrm |
| `--output-dir`, `-o` | path | Output directory for reports | reports |
| `--verbose`, `-v` | bool | Enable detailed debug logging | False |
| `--accept-unknown-hosts` | bool | Automatically accept unknown SSH host keys (insecure) | False |
| `--accept-invalid-certs` | bool | Skip TLS certificate validation for WinRM and web checks (insecure) | False |

> **Password handling**: Passwords are verified against the `SECAPPLIANCE_PASSWORD`
> environment variable and an interactive prompt as fallback. Avoid passing them
> via `--password`, which exposes them in the process list and shell history.
>
> **Transport security**: SSH host keys are verified against `known_hosts` and
> WinRM/web TLS certificates are validated by default. Use the
> `--accept-unknown-hosts` / `--accept-invalid-certs` flags only against
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

## Legal Disclaimer
**Authorized use only.** This tool is for security testing of systems you own or have explicit permission to audit. Scanning without prior written permission is illegal. The developers assume no liability for misuse.

## License
MIT

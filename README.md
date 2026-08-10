# SecAppliance - Network & Vulnerability Assessment Appliance

**SecAppliance** is an enterprise-grade, lightweight, and high-performance network scanner and vulnerability collection appliance. Designed for IT Administrators, SOC Analysts, and Security Auditors, it automates network discovery, service versioning, offline CVE correlation, and executive report generation—with support for both unauthenticated network scans and deep credentialed audits (via WinRM/SSH). 

---

## Key Features

* **Asynchronous & Concurrent Scanning:** Built using Python's `asyncio` to execute fast, parallel host discovery and port scanning across entire `/24` subnets or IP ranges.
* **Offline Vulnerability Mapping (CVE Lookup):** Automatically maps detected open ports and banners against a localized database of critical vulnerabilities (CVE IDs, CVSS severity, and summaries).
* **Dynamic Remediation Engine:** Rule-based security scoring that generates actionable recommendations with visual severity badges (HIGH / MEDIUM / LOW) based on exposure (LAN vs. WAN).
* **Flexible Authentication Modes:**
  * **Unauthenticated Mode (Default):** Runs port scans, service/banner identification, CVE mapping, and report generation without requiring target credentials.
  * **Credentialed Audit Mode (Optional):** Utilizes WinRM or SSH to perform deep target inspection—extracting active network sockets, process IDs (PIDs), and process names directly from target operating systems.
* **Executive HTML Reporting:** Standardizes all outputs into interactive, beautifully styled HTML reports automatically stored inside the `reports/` directory.
* **Rich CLI Interface:** Interactive progress indicators, real-time feedback via `rich`, clean exception handling for unreachable hosts, and detailed logging levels (`--verbose`).

---

## Installation & Setup

### Prerequisites
* **Python 3.9+**
* Operating System: Linux, Windows, or macOS

### Step 1: Clone the Repository
```bash
git clone [https://github.com/your-username/SecAppliance.git](https://github.com/your-username/SecAppliance.git)
cd SecAppliance

```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt

```

---

## CLI Usage & Flags Reference

### Syntax Overview

```bash
python main.py [OPTIONS]

```

### Complete Options & Flags Table

| Flag / Option | Short | Type | Description | Default |
| --- | --- | --- | --- | --- |
| `--target` | `-t` | String | Target IP address or CIDR range (e.g., `'192.168.1.0/24'` or `'10.0.0.1'`). **[Required]** | *None* |
| `--ports` | `-p` | String | Port range to scan (e.g., `'1-65535'`, `'1-1024'`, or `'80,443,8080'`). | `1-1024` |
| `--web-ports` | `-w` | String | Comma-separated list of web ports to scan. | `80,443,8080,8443` |
| `--username` | `-u` | String | Remote SSH/WinRM username for deep credentialed audits. | *None* |
| `--password` | `-P` | String | Remote password for SSH/WinRM authentication. | *None* |
| `--auth-type` | `-a` | String | Authentication protocol to use for deep collection (`winrm` or `ssh`). | `winrm` |
| `--output-dir` | `-o` | Path | Output directory path for saving generated reports. | `reports` |
| `--verbose` | `-v` | Flag | Enable detailed debug logging and real-time execution tracing. | `False` |
| `--install-completion` | - | - | Install completion for the current shell. | - |
| `--show-completion` | - | - | Show completion for the current shell to copy or customize. | - |
| `--help` | - | - | Show the command-line help message and exit. | - |

---

## Usage Examples

### 1. Fast Unauthenticated Subnet Scan (Default Mode)

Scans an entire `/24` subnet across default ports without credentials, performs CVE mapping, and generates an HTML executive report.

```bash
python main.py -t 192.168.1.0/24 -p 1-1024 -v

```

### 2. Custom Port Range and Output Directory

Scans a specific target on custom web/standard ports and saves results in a designated report folder:

```bash
python main.py -t 10.0.0.1 -p 1-65535 -w 80,443,8080,8443,3000 -o custom_reports/

```

### 3. Credentialed Deep Audit (WinRM / Windows Remote Inspection)

Performs an authenticated deep inspection over WinRM, merging internal system telemetry into the assessment:

```bash
python main.py -t 192.168.1.50 -u "Administrator" -P "YourSecurePassword" --auth-type winrm -v

```

---

## Project Architecture Overview

```text
SecAppliance/
├── core/
│   ├── network_scanner.py    # Asynchronous host discovery & port scanning engine
│   ├── remote_collector.py   # Credentialed WinRM/SSH deep data collector
│   ├── vuln_lookup.py        # Localized CVE & vulnerability correlation engine
│   └── report_generator.py   # Dynamic HTML executive report builder
├── utils/
│   └── net_utils.py          # TCP state mappers, RFC 1918 IP classifier (LAN/WAN)
├── reporting/
│   └── templates/            # HTML executive report templates
├── reports/                  # Default directory for generated audit reports
├── main.py                   # CLI entrypoint and argument parser
├── requirements.txt          # Project dependencies
└── README.md                 # Project documentation

```

---

## Legal Disclaimer

This software is designed for legitimate security auditing, network maintenance, and authorized penetration testing only. Scanning networks without prior permission or proper authorization from the system owner is illegal. The developers assume no liability and are not responsible for any misuse or damage caused by this utility.

---

## License

This project is open-source and provided under the MIT License.

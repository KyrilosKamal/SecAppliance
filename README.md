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
python main.py scan [FLAGS]

```

### Complete Options & Flags Table

| Flag / Option | Short | Type | Description | Default |
| --- | --- | --- | --- | --- |
| `--target` | `-t` | String | Target IP address, hostname, IP range (e.g., `10.30.10.1-10.30.10.50`), or CIDR subnet (e.g., `10.30.10.0/24`). **[Required]** | *None* |
| `--ports` | `-p` | String | Port ranges or specific ports to scan (e.g., `80,445,3389` or `1-1024`). | `1-1024` |
| `--username` | `-u` | String | *(Optional)* Remote authentication username for WinRM/SSH credentialed inspection. | *None* |
| `--password` | `-P` | String | *(Optional)* Remote authentication password or secret for WinRM/SSH. | *None* |
| `--auth-type` | `-a` | String | Authentication protocol to use for deep collection (`winrm` or `ssh`). | `winrm` |
| `--output-dir` | `-o` | String | Output directory path for saving generated reports. | `reports/` |
| `--verbose` | `-v` | Flag | Enables detailed execution logs and debugging output on stdout. | `False` |
| `--help` | `-h` | Flag | Displays command-line help message and available flags. | *None* |

---

## Usage Examples

### 1. Fast Unauthenticated Subnet Scan (Default Mode)

Scans an entire `/24` subnet for open ports and banners without needing credentials, performing CVE mapping and generating an HTML executive report.

```bash
python main.py scan -t 10.30.10.0/24 --ports 80,445,3389,5985 -v

```

### 2. Specific Target Port Range Scan

Scans a specific single target across ports `1` through `1000`:

```bash
python main.py scan -t ip_address -p 1-1000

```

### 3. Credentialed Deep Audit (WinRM / Windows Remote Inspection)

When credentials are provided, **SecAppliance** verifies if WinRM ports (5985/5986) are open, connects remotely to inspect active TCP connections, maps processes to PIDs via PowerShell JSON payloads, and merges internal system telemetry into the final report.

```bash
python main.py scan -t ip_address -u "admin_user" -P "Password" --auth-type winrm

```

### 4. Custom Output Directory

Saves the generated assessment report into a custom folder:

```bash
python main.py scan -t 10.30.10.0/24 -o my_custom_reports/

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

This project is open-source and provided under the MIT License (Free of any commercial license restrictions or activation keys).

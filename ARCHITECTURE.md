# 🛡️ Project Architecture & Roadmap: SecAppliance (Windows Local Edition)

## 1. Executive Overview
**SecAppliance** is a zero-cloud, self-hosted, lightweight vulnerability scanning and reporting engine designed to run locally on Windows infrastructure (Windows Server / Windows 10/11) or via Docker/WSL2. It performs automated network and web application discovery, parses security vulnerabilities, generates executive-ready PDF reports, and manages licensing locally.

---

## 2. Core Pillars & Design Constraints
- **Zero Cloud Dependency:** 100% of network traffic, data storage, and report generation remains within the local network.
- **High Performance (Asynchronous):** Non-blocking network I/O to scan `/24` subnets (254 hosts) in under 3 minutes without crashing network devices.
- **Windows First:** Native execution on Windows environments as a Standalone `.exe` binary (via PyInstaller) or Docker Windows/WSL2 container.
- **Low Overhead:** Single SQLite database, lightweight HTML-to-PDF rendering, minimal RAM (< 250MB) and CPU usage.

---

## 3. High-Level Architecture Diagram

```text
+-----------------------------------------------------------------------+
|                      SecAppliance Local Engine                        |
|                                                                       |
|  +--------------------+     +-------------------+     +------------+  |
|  | Multi-Async        |     | Web & HTTP        |     | Local      |  |
|  | Network Scanner    |     | Vulnerability     |     | License    |  |
|  | (Raw Sockets/Ports)|     | Analyzer          |     | Verifier   |  |
|  +---------+----------+     +---------+---------+     +-----+------+  |
|            |                          |                     |         |
|            +-------------------+------+---------------------+         |
|                                |                                      |
|                                v                                      |
|                     +--------------------+                            |
|                     | SQLite / Local DB  |                            |
|                     +---------+----------+                            |
|                               |                                       |
|                               v                                       |
|                     +--------------------+                            |
|                     | PDF Report Engine  |                            |
|                     | (WeasyPrint/Jinja) |                            |
|                     +---------+----------+                            |
|                               |                                       |
+-------------------------------+---------------------------------------+
                                |
                                v
               [ Local PDF Report Generated ]
               (Saved locally / Sent via Local SMTP)

```

---

## 4. Technology Stack (Windows Targeted)

| Component | Technology / Library | Purpose |
| --- | --- | --- |
| **Primary Language** | Python 3.11+ | Rapid development & async support |
| **Async Engine** | `asyncio` + `aiohttp` | Concurrent port scanning & HTTP probing |
| **Network Discovery** | `scapy` / Custom Sockets | Windows-compatible host & port discovery |
| **Storage Layer** | SQLite (`sqlite3`) | Standalone, file-based database |
| **Report Generation** | `Jinja2` + `WeasyPrint` | HTML/CSS templating to PDF |
| **CLI / GUI Layer** | `Typer` (CLI) / `FastAPI` (Local UI) | Local orchestration and dashboard |
| **Packaging (Windows)** | PyInstaller | Compiling Python code into a standalone `.exe` |

---

## 5. Directory Structure

```text
SecAppliance/
│
├── config/
│   ├── settings.json            # Local configuration (IP targets, scan schedule)
│   └── signatures.json          # Known vulnerabilities & remediation steps DB
│
├── core/
│   ├── __init__.py
│   ├── network_scanner.py       # Async host & port scanner
│   ├── web_scanner.py           # HTTP headers, SSL/TLS, & web checks
│   ├── license_manager.py       # Local RSA/AES license validation
│   └── database.py              # SQLite wrapper & queries
│
├── reporting/
│   ├── templates/
│   │   ├── executive_report.html# Responsive HTML template for PDF
│   │   └── style.css            # PDF styling & layout
│   └── pdf_generator.py         # Converts HTML + DB data to PDF
│
├── utils/
│   ├── logger.py                # Local logging system
│   └── crypto.py                # Encryption helpers for license keys
│
├── data/
│   └── secappliance.db          # Local SQLite DB instance
│
├── ARCHITECTURE.md              # Project reference blueprint
├── main.py                      # Application Entry Point
├── requirements.txt             # Python Dependencies
└── build_exe.bat                # Windows PyInstaller build script

```

---

## 6. Comprehensive Master Implementation Plan

The project will be built across **4 distinct, testable phases**. Each milestone must be verified before proceeding to the next.

```text
[ Phase 1: Core Scanning Engine & DB ]
                 │
                 ▼
[ Phase 2: PDF Reporting & Dashboard ]
                 │
                 ▼
[ Phase 3: Licensing & Scheduler ]
                 │
                 ▼
[ Phase 4: Windows Build & Packaging ]

```

### 🔹 Phase 1: Core Scanning Engine & Database Layer

*Goal: Build a high-speed async scanner that discovers live hosts, open ports, and basic web vulnerabilities, saving results to a local SQLite DB.*

* [ ] **Step 1.1: Project Setup & Logging**
* Create project directory structure as defined in Section 5.
* Implement `utils/logger.py` for colorful console output and file-based local logging.
* Setup `requirements.txt` with essential libraries (`asyncio`, `aiohttp`, `jinja2`, etc.).


* [ ] **Step 1.2: Local Database Architecture (`core/database.py`)**
* Design SQLite schema: `Scans`, `Hosts`, `Ports`, and `Vulnerabilities` tables.
* Implement async-friendly Database operations (insert scan, update status, fetch report data).


* [ ] **Step 1.3: Asynchronous Network Engine (`core/network_scanner.py`)**
* Implement async TCP Port Scanner using Python `asyncio.open_connection`.
* Add CIDR subnet calculation (e.g., `192.168.1.0/24`) to expand targets dynamically.
* Implement banner grabbing on open ports (21, 22, 80, 443, 445, 3389, etc.).


* [ ] **Step 1.4: Web & HTTP Vulnerability Analyzer (`core/web_scanner.py`)**
* Build HTTP probe using `aiohttp` to inspect response headers (`HSTS`, `X-Frame-Options`, `CORS`, `Server`).
* Detect SSL/TLS certificate expiration and weak ciphers.
* Match detected banners against local CVE rules stored in `config/signatures.json`.



---

### 🔹 Phase 2: Report Generation Engine

*Goal: Transform raw scan data stored in SQLite into an executive-ready, beautifully designed PDF document.*

* [ ] **Step 2.1: Executive HTML/CSS Template (`reporting/templates/`)**
* Create `executive_report.html` with clean typography, Executive Summary charts (High/Med/Low counts), and technical remediation tables.
* Style layout using `style.css` tailored for print/PDF engines.


* [ ] **Step 2.2: PDF Compilation Module (`reporting/pdf_generator.py`)**
* Integrate `Jinja2` to dynamically populate the HTML template with database scan records.
* Integrate `WeasyPrint` (or lightweight alternative) to render HTML/CSS directly to a `.pdf` file.
* Test custom branding (hotel/company logo placement).



---

### 🔹 Phase 3: Local Licensing & Automation Mechanics

*Goal: Protect the product with offline RSA licensing and enable recurring scheduled execution.*

* [ ] **Step 3.1: Cryptographic License Manager (`core/license_manager.py`)**
* Implement RSA public/private key verification to read an encrypted `license.lic` file.
* Verify license expiration date, allowed target IP limits, and local Hardware ID (UUID).


* [ ] **Step 3.2: Execution Scheduler & Orchestrator (`main.py`)**
* Build CLI entrypoint using `Typer` (e.g., `secappliance scan --target 192.168.1.0/24`).
* Add automated interval execution (e.g., monthly scan runner).



---

### 🔹 Phase 4: Windows Build, Packaging & Standalone Execution

*Goal: Bundle the complete application into a single executable file for frictionless installation on Windows.*

* [ ] **Step 4.1: Windows Executable Compilation (`build_exe.bat`)**
* Write PyInstaller configuration file to bundle dependencies, templates, and signature JSONs.
* Compile the engine into a standalone `SecAppliance.exe`.


* [ ] **Step 4.2: Standalone Air-Gapped Testing**
* Test execution on a clean Windows Server / Windows 11 machine without Python pre-installed.
* Verify zero outbound internet connection attempts during full scan cycle.



---

## 7. Guidelines for AI Prompts & Coding Conventions

1. **Async First:** All network and HTTP I/O operations must use `asyncio` to ensure non-blocking performance.
2. **No Third-Party Cloud Services:** Never suggest or introduce external APIs, cloud storage, or telemetry.
3. **Windows System Compatibility:** Ensure all file paths handle Windows backslashes (`pathlib.Path`) and raw socket calls respect Windows OS permissions.
4. **Clean Error Handling:** Wrap all scanning loops in robust `try/except` blocks to prevent target timeout crashes.

```

# Code Review Fix Log

### scan_id may be unbound in the except block
- File: main.py:156-192
- Status: fixed
- Change: Initialized `scan_id = None` before the `try` and guarded `update_scan_status(..., "failed")` with `if scan_id is not None`.
- Verification: `python3 -m py_compile main.py` -> OK; no tests directory present, `pytest` not run.

### CIDR expansion is uncapped (materializes every host)
- Files: core/network_scanner.py, main.py
- Status: fixed
- Change:
  - `NetworkScanner.__init__` gains `force: bool = False`; `main.py` gains a `--force` boolean option (default False) passed explicitly to the scanner.
  - New `_validate_target_sizes()` rejects any target whose prefix length is `< 16` unless `force` is set. Message includes prefix, address count, and the `--force` suggestion.
  - Expansion replaced by two generators: `_iter_hosts()` (yields `str(ip)` per target) and `_iter_work_items()` (yields `(callable, args)` pairs). `scan_targets()` now pulls batches with `itertools.islice(work_iter, batch_size)`; progress total is `None` (indeterminate) because the item count is no longer known up front.
  - `_iter_hosts()` deduplicates by target string only. Behaviour change: overlapping CIDR ranges (e.g. `10.0.0.0/24 10.0.0.0/25`) can now yield the same host twice; previously a global IP set deduplicated them. Exact IP-level dedup requires materializing the set, which conflicts with streaming.
  - `--force` still streams: no list/set of hosts is built anywhere in the path.
  - Downstream consumers: the only consumer was `work_items` (used `len()` and slicing only). Batching logic, port range handling, and `active_connections` fabrication were left untouched.
- Verification:
  - `python3 -m py_compile main.py core/network_scanner.py` -> OK.
  - `uv run --no-project --python 3.13 --with rich --with psutil --with colorama --with aiosqlite python3 - <<'PY' ... PY` (snippet, no live scan):
    - `/24` -> `1) /24 count: 254 first/last: 192.168.1.1 192.168.1.254`
    - `/8` without force -> `Target '10.0.0.0/8' is a /8 range with 16777214 addresses, which exceeds the /16 limit. Pass --force to scan ranges larger than /16.`
    - `/8` with force -> `3) generator: True | first 3: ['10.0.0.1', '10.0.0.2', '10.0.0.3']`
    - work items -> `4) work-item generator: True | fn is scan_host: True | args: ('10.0.0.1', 1, [80])`
  - `python3 main.py scan --help` shows `--force  Allow scanning CIDR ranges larger than /16 (hosts are streamed, not materialized).`
  - No tests directory present, `pytest` not run.

### Web scan is a silent no-op for CIDR targets
- File: core/web_scanner.py
- Status: fixed
- Approach: B (DB-driven discovery). `scan_targets` now calls `self.db.get_hosts(scan_id)` and scans each stored `ip_address`, instead of passing the raw target string to `scan_host`. Chosen because the network scanner already stores per-host resolved IPs (`add_host(scan_id, ip, ...)`), `scan_id` is already threaded from `main.py`, and no second CIDR parser or duplicate `/16` cap is needed. No schema, `main.py`, `network_scanner.py` or `database.py` changes.
- Change:
  - `scan_targets`: raises `ValueError("scan_id is required for web scanning")` when `scan_id is None` (failing loud; the silent no-op was the bug).
  - Replaced the `for target in targets` loop with `hosts = await self.db.get_hosts(scan_id)`; empty result logs `No hosts stored for scan {scan_id}; nothing to web-scan.` at warning level and returns.
  - `targets` parameter kept for API compatibility; docstring notes it is no longer used for discovery.
  - `scan_host` unchanged: its "Host ... not found in database" warning stays as a defensive check.
  - TLS probing, header checks, and vulnerability recording unchanged (issues #9, #10).
- Behaviour change: web scanning is now DB-driven, so hosts must have been stored by the network scan. For the reported CIDR case this is exactly the fix; for single-IP targets the same IP is stored by the network scan, so results are unchanged.
- Verification:
  - `python3 -m py_compile core/web_scanner.py` -> OK.
  - In-memory SQLite via `DatabaseManager(":memory:")`, 3 hosts added, `WebScanner.scan_host` monkeypatched to record calls (`uv run --no-project --python 3.13 --with rich --with psutil --with colorama --with aiohttp --with aiosqlite python3 -u /tmp/opencode/verify_ws.py`):
    ```
    [1] CIDR target -> 3 calls: [('192.168.1.1', 1), ('192.168.1.2', 1), ('192.168.1.3', 1)]
    [2] scan_id=None -> ValueError: scan_id is required for web scanning
    [3] empty scan -> 0 scan_host calls, warning: No hosts stored for scan 2; nothing to web-scan.
    ALL CHECKS PASSED
    ```
  - No HTTP/TLS traffic sent (`self.session` was a bare object sentinel; `scan_host` was replaced).
  - No tests directory present, `pytest` not run.

### WinRM sends NTLM credentials over plaintext HTTP
- Files: core/remote_collector.py, core/network_scanner.py, main.py
- Status: fixed
- Endpoint policy: `https://<host>:5986/wsman` by default; `http://<host>:5985/wsman` only when the new `--allow-insecure-winrm-http` flag is set (default False). `--accept-invalid-certs` still controls TLS trust only and never enables HTTP.
- Change:
  - `RemoteCollector.__init__` gains `allow_insecure_winrm_http: bool = False`; `NetworkScanner.__init__` gains the same parameter and passes it at the `RemoteCollector(...)` construction site; `main.py` adds the `--allow-insecure-winrm-http` typer option and threads it to `NetworkScanner(...)`.
  - `_collect_winrm` builds an explicit endpoint URL and passes it as the `winrm.Session` target. `winrm.Session` derives scheme/port from the URL, so this forces HTTPS 5986 without a pywinrm upgrade (`Protocol` has no `run_ps`, so `Session` must stay).
  - Plaintext mode logs a WARNING naming the exposure and the flag, mirroring the SSH host-key error style.
  - `server_cert_validation = 'ignore' if self.accept_invalid_certs else 'validate'` unchanged; no other `'ignore'` added.
  - `run_ps` TypeError fix, landed in the same change: the call passed `operation_timeout_sec`/`read_timeout_sec` to `session.run_ps()`, whose signature is `run_ps(self, script)` in pywinrm 0.4.3 and 0.5.0. That raised `TypeError`, was swallowed by the broad `except`, and made WinRM collection always fail. The timeouts now go to the `winrm.Session(...)` constructor (forwarded to `Protocol`), and `session.run_ps(ps_script)` is called with no kwargs. Fixing HTTPS alone would have left WinRM broken; fixing run_ps alone would have activated the plaintext credential leak. Both had to land together.
  - SSH branch untouched.
- Backward compatibility: Windows hosts with only HTTP WinRM (5985) now fail unless `--allow-insecure-winrm-http` is passed. Under the old code this path already failed (run_ps TypeError), so no working deployment regresses.
- Process note: the 2-file limit was waived by the human after investigation because threading the flag requires `main.py` -> `core/network_scanner.py` (RemoteCollector construction site) -> `core/remote_collector.py`. Three files, no fourth file or config module touched.
- Verification:
  - `python3 -m py_compile main.py core/network_scanner.py core/remote_collector.py` -> OK.
  - Monkeypatched `winrm.Session` (no live WinRM target):
    ```
    [1] default endpoint: https://10.0.0.5:5986/wsman | timeouts: 30/35 | run_ps kwargs: {}
    [2] insecure endpoint: http://10.0.0.5:5985/wsman | warning: WinRM on 10.0.0.5 uses plaintext HTTP port 5985: NTLM credentials are sent unencrypted. Drop --allow-insecure-winrm-http to use HTTPS on port 5986.
    [3] accept-invalid-certs only -> endpoint: https://10.0.0.5:5986/wsman, validation: ignore
    [4] both flags -> endpoint: http://10.0.0.5:5985/wsman, validation: ignore
    ALL CHECKS PASSED
    ```
  - `python3 main.py scan --help` lists `--allow-insecure-winrm-http` with the approved help text.
  - Only one `winrm.Session` construction exists in the repo (`core/remote_collector.py:121`).
  - No tests directory present, `pytest` not run.

### Fabricated open-port rows presented as observed active connections
- Files: core/database.py, core/network_scanner.py, core/report_generator.py, reporting/templates/executive_report.html
- Status: fixed
- Approach: Option A — new `derived_ports` table instead of `collection_status="derived"` inside `active_connections`.
- Rationale:
  - Provenance is expressed in the schema, not in an overloaded status string. `active_connections` now means observed connections only.
  - `collection_status="derived"` would have tripped `report_generator.py:165` (`if any(row[6] != "success" for row in rows): collection_status = "failed"`), turning every healthy scan with derived data into a "failed" banner. That line is untouched here.
  - `DatabaseManager.get_active_connections` (currently dead code) selects rows with no status filter; keeping derived rows out of the table removes the trap for the next caller.
- Changes:
  - `core/database.py`: `CREATE TABLE IF NOT EXISTS derived_ports` (scan_id, ip_address, port, service_name, timestamp, FK to scans with ON DELETE CASCADE) in `initialize_tables`; `add_derived_ports(scan_id, rows)` (single `executemany`, `timestamp = datetime.now(timezone.utc).isoformat()`); `get_derived_ports(scan_id)` ordered by `ip_address, port`. `add_active_connections`, the N/A placeholder block, and `get_active_connections` unchanged.
  - `core/network_scanner.py`: the fabrication block in `collect_and_store_active_connections` now builds `{ip_address, port, service_name}` rows from `db.get_ports(scan_id)` and calls `db.add_derived_ports(...)`; no dicts are appended to `connections` any more. The subsequent `db.add_active_connections(scan_id, connections, status)` call and its arguments are unchanged. Trigger condition and scan-wide scope untouched.
  - `core/report_generator.py`: new `_get_derived_ports_data(scan_id)`; `"derived_ports"` key added to `_prepare_template_data`; `"active_connections"`, `"connection_status"`, the line-165 success filter, and all KPIs unchanged.
  - `reporting/templates/executive_report.html`: new section "Derived Ports (not observed traffic)" after the Active Connections section, with the provenance note, IP / Port / Service / Timestamp columns, and an always-visible "No derived port data." empty state. Existing `traffic-details` / `traffic-container` / `traffic-table` / `no-traffic-container` / `no-traffic-text` classes reused; `style.css` untouched.
- Migration: table creation only (`CREATE TABLE IF NOT EXISTS`), applied on the next startup because `initialize_tables` runs then. No `ALTER TABLE`, no backfill. Historical scans keep their old fabricated `active_connections` rows until those scans age out; documented, not rewritten.
- Placeholder check: empty `connections` + `status="success"` does NOT create a misleading placeholder — `add_active_connections` inserts the N/A row only when `status != "success"` (`core/database.py:404`). Empty + success stores nothing, and the report falls back to `connection_status="no_data"` / "No active connections detected."
- Verification:
  - `python3 -m py_compile core/database.py core/network_scanner.py core/report_generator.py` -> OK.
  - In-memory `DatabaseManager(":memory:")`, 2 hosts with 3 ports, `get_active_connections` monkeypatched to return `[]`, `collect_and_store_active_connections(scan_id, "127.0.0.1")`:
    ```
    [1] active_connections fabricated-success rows: 0 (expected 0)
    [2] derived_ports ordered: [('10.0.0.10', 22), ('10.0.0.10', 443), ('10.0.0.2', 80)]
    [3] report data keys ok; connection_status=no_data
    [4] rendered HTML contains title, note, and derived rows
    [5] empty derived state renders 'No derived port data.'
    [6] total_open_ports unchanged: 3
    ALL CHECKS PASSED
    ```
  - No real scan, no network access. No tests directory present, `pytest` not run.
- Process note: the 2-file limit was waived by the human after investigation. Four files, all inside the approved list; `main.py`, `core/remote_collector.py`, `core/web_scanner.py`, `reporting/templates/style.css` untouched.

### CVE findings excluded from risk score, totals, and breakdown
- Files: core/report_generator.py, reporting/templates/executive_report.html
- Status: fixed
- Root cause: `cve_findings` (built from `get_vulns_for_service` over `port_data`) was appended after `total_vulnerabilities`, `vuln_counts`, and `all_severities` were computed. Only `vulnerabilities_by_host` and port-signature `recommendations` fed the score. A CRITICAL Apache 2.4.49 / vsftpd 2.3.4 finding therefore scored 0, the KPI read "Total Vulnerabilities: 0", and the template's `{% else %}` branch printed "No Vulnerabilities Found — Excellent Security Posture" above a CRITICAL CVE table.
- Changes:
  - `core/report_generator.py`: the CVE/recommendation block now runs before the counts. `total_vulnerabilities = len(flat_vulnerabilities) + len(cve_findings)`; the `vuln_counts` loop iterates `flat_vulnerabilities + cve_findings` with `(severity or "INFO").strip().upper()` and keeps the INFO fallback; breakdown percentages use the combined denominator; `all_severities` appends `cve["severity"].upper()` for every CVE, then the existing recommendation severities. Weights (`CRITICAL 15 / HIGH 8 / MEDIUM 4 / LOW 1 / INFO 0.5`, ×1.5 cap 100) and grade thresholds are unchanged. `cve_findings` fields, CVE table data, and recommendation logic untouched.
  - `reporting/templates/executive_report.html`: the banner branch changed from `{% else %}` to `{% elif total_vulnerabilities == 0 %}`. The Technical Findings section stays gated on `{% if vulnerabilities_by_host %}`. A CVE-only scan therefore renders neither an empty findings section nor the "Excellent Security Posture" banner.
- Dedup decision: no dedupe. `cve_findings` is built per `port_data` row (one per host per port), and the CVE table renders one row per entry, so counting once per affected host/port match keeps the KPI and the table identical. The two sources are disjoint by construction — the `vulnerabilities` table has no CVE column and is written only by `core/web_scanner.py` header/SSL checks, so there is no stable key to dedupe against and no double-count today.
- Breakdown decision: CVEs merge into the existing five severity buckets (`CRITICAL, HIGH, MEDIUM, LOW, INFO`). No `"cve"` key added; the shape `{count, percentage, color}` is unchanged. `vulnerability_breakdown` has no template or Python consumer today, so the denominators change without breaking anything.
- Behaviour change: `risk_level`, `risk_grade`, `risk_score`, `risk_percentage`, and `total_vulnerabilities` will change for any existing scan that has CVE matches. That is the intended correction — the previous grade ignored those findings. Scans with no CVE matches are unchanged.
- Verification (in-memory SQLite, no network):
  ```
  [A] total=0 risk=0 grade=A level=Low banner present: PASS
  [B] CVEs=['CVE-2011-2523', 'CVE-2016-6662', 'CVE-2021-41773'] total=3 score=57 grade=C level=Medium, banner absent, table rows=3: PASS
  [C] total=3 counts={'CRITICAL': 0, 'HIGH': 2, 'MEDIUM': 0, 'LOW': 1, 'INFO': 0} percentages sum=100.0 score=25: PASS
  [keys] template data keys unchanged: PASS
  ALL CHECKS PASSED
  ```
  - Scenario A: 0 web vulns, 0 CVE matches -> total 0, score 0, grade A, "No Vulnerabilities Found" rendered.
  - Scenario B: 0 web vulns, 2 CRITICAL + 1 HIGH CVE -> total_score 38 before ×1.5, score 57, grade C, level Medium; banner absent; CVE table row count 3 equals `len(cve_findings)`.
  - Scenario C: web HIGH + web LOW + CVE HIGH -> total 3, HIGH bucket 2, LOW bucket 1, percentages sum 100.0, score 25.
  - `python3 -m py_compile core/report_generator.py` -> OK.
  - No tests directory present, `pytest` not run.

### Scan duration mixes naive-UTC start with local `datetime.now()` fallback
- Files: core/report_generator.py
- Status: fixed
- Phase 1 findings:
  - `scans` schema: `start_time TEXT NOT NULL`, `end_time TEXT` (core/database.py:46-54).
  - `create_scan` stores `datetime.utcnow().isoformat()` — naive UTC, no offset suffix (core/database.py, `create_scan`).
  - `update_scan_status` stores `datetime.utcnow().isoformat()` when `end_time` is not passed — same naive UTC format (core/database.py, `update_scan_status`).
  - The report reads both via `_get_scan_data` -> `db.get_scan` (core/report_generator.py `_get_scan_data`). There is no `completed_at` column.
  - Duration was computed in Python, not the template: `scan_start`/`scan_end` parsed with `datetime.fromisoformat(...)`, `scan_end` falling back to `datetime.now()` (naive local) when `end_time` was NULL, then `scan_end - scan_start`. The template only renders `"scan_duration"`.
  - `datetime.utcnow()` occurrences in report_generator.py: none. The only scan-duration time read was the local `datetime.now()` fallback. Other `datetime.now()` calls (report timestamp, generated-date, filename stamp) are display-only and out of scope.
- Changes (one block, core/report_generator.py):
  - Parsed timestamps get `tzinfo=timezone.utc` attached when naive; both sides are then converted with `astimezone(timezone.utc)` before subtraction, so the result never depends on the host's local timezone.
  - The `datetime.now()` local fallback is gone. When `start_time`/`end_time` is missing or unparseable, `scan_duration` is `"N/A"` and a warning is logged, instead of emitting a duration shifted by the local UTC offset.
  - Display format unchanged: `HH:MM:SS` when hours > 0, otherwise `MM:SS`. Template untouched.
  - Spec note: Phase 2 items 2 and 4 conflict (aware `now()` fallback vs. `"N/A"` on missing timestamps). Resolved in favour of item 4 / the verification block — a missing end time means "not finished", not "finished now", so `"N/A"` is reported. No in-progress sentinel string was introduced.
- Behaviour change: scan durations on non-UTC hosts are now correct; previously an unfinished scan (or a timestamp with an offset) produced a duration shifted by the host's local UTC offset. Scans that completed normally and ran on a UTC host are unchanged. In-progress scans now show `N/A` instead of an elapsed-so-far value.
- Verification (in-memory SQLite, no network, run under two host timezones):
  ```
  --- TZ=UTC ---
  [UTC] start=2026-11-08T09:47:38.281209 end=2026-11-08T09:49:08.281209 -> 01:30 (TZ=UTC): PASS
  [TZ] aware+09:00=01:30 mixed-aware=01:30 naive-utc=01:30 (TZ=UTC): PASS
  [missing] no end_time -> N/A, bad start -> N/A: PASS
  ALL CHECKS PASSED
  --- TZ=Asia/Tokyo ---
  [UTC] start=2026-11-08T09:47:38.425014 end=2026-11-08T09:49:08.425014 -> 01:30 (TZ=Asia/Tokyo): PASS
  [TZ] aware+09:00=01:30 mixed-aware=01:30 naive-utc=01:30 (TZ=Asia/Tokyo): PASS
  [missing] no end_time -> N/A, bad start -> N/A: PASS
  ALL CHECKS PASSED
  ```
  - Scenario UTC: naive-UTC start plus an explicit end exactly 90 s later -> `"01:30"` under both host timezones.
  - Scenario tz-awareness: timestamps carrying `+09:00` offsets, and a mixed naive-start/aware-end pair for the same instant, both yield `"01:30"`; a naive-UTC pair on a `Asia/Tokyo` host is still `"01:30"` (previously shifted by 9 h on the fallback path). Identical output under `TZ=UTC` and `TZ=Asia/Tokyo` proves the computation is host-independent.
  - Scenario missing end_time: `scan_duration == "N/A"`; an unparseable `start_time` also yields `"N/A"` rather than a bogus number.
  - `python3 -m py_compile core/report_generator.py` -> OK.
  - No tests directory present, `pytest` not run.

### Active connection rows report the report-generation time, not the observation time
- Files: core/report_generator.py
- Status: fixed
- Phase 1 findings:
  - SELECT (core/report_generator.py:146) listed 7 columns: `local_address, remote_address, remote_classification, pid, process_name, status, collection_status`. `timestamp` was not selected.
  - Dict assembly (lines 150-161): `"timestamp"` was set from `datetime.now().strftime("%Y-%m-%d %H:%M:%S")` — the moment the report was built, for every row.
  - Success filter was (and still is) `row[6] == "success"` — index 6 was `collection_status`.
  - Banner-state derivation (lines 163-168) derives `collection_status` from the same rows: any non-success row -> `"failed"`, no rows -> `"no_data"`, else `"success"`.
  - `active_connections` schema (core/database.py:110-121): `status TEXT`, `collection_status TEXT DEFAULT 'success'`, `timestamp TEXT NOT NULL`.
  - `add_active_connections` (core/database.py:383) writes one `timestamp = datetime.utcnow().isoformat()` per call — a real naive-UTC ISO string shared by every row of that collection.
  - Placeholder block (core/database.py:417-428): inserted only when `connections` is empty and `status != "success"`, with `local_address='N/A', remote_address='N/A', remote_classification='N/A', pid=0, process_name='N/A', status='N/A', timestamp=<real utcnow ISO>, collection_status=<status>` i.e. `"failed"` or `"skipped"`, never `"success"`. Since the report filters on `collection_status == "success"`, the placeholder is excluded. No status value can produce a success-labelled placeholder — no issue #5 regression.
  - Template renders it raw as `<td>{{ conn.timestamp }}</td>` (reporting/templates/executive_report.html:280 with adjacent columns; no filter, no formatting).
  - Python consumers of the report's `"timestamp"` key: template only. `core/database.py:499` and `:666` read `timestamp` into their own dicts (`get_derived_ports`, `get_active_connections`) and are not consumers of this data.
- Changes (core/report_generator.py only):
  - SELECT gains `timestamp` as the last column.
  - `"timestamp"` now takes the stored value: `row[7] if row[7] and row[7] != "N/A" else "N/A"`.
  - Index note: `timestamp` was appended at the end of the column list, so `collection_status` stays at `row[6]` and the success filter plus banner-state logic are unchanged. `timestamp` is the only new index (`row[7]`).
  - Filter, banner derivation, and all other dict fields untouched. No reformatting of the stored string. Template untouched.
- Behaviour change: historical reports now show the observation timestamp instead of the report-generation time. Reports generated from a scan whose connections were collected earlier now display that collection time; previously every row showed the time the report was built.
- Verification (in-memory SQLite, no network):
  ```
  [real] rows=2 timestamp='2024-01-01T00:00:00' report_gen_time='2026-11-08T11:52:23.222021' differ=True status=success: PASS
  [render] stored timestamp present in HTML, report-gen time absent: PASS
  [empty] rows=0 status=no_data: PASS
  [placeholder] db_row=('N/A', 'N/A', 'failed', '2026-11-08T09:52:23.226315') report_rows=0 status=failed: PASS (no #5 regression)
  [n/a] literal 'N/A' timestamp -> 'N/A': PASS
  ALL CHECKS PASSED
  ```
  - Scenario real rows: 2 connections stored with `timestamp='2024-01-01T00:00:00'` both returned that exact string; it differs from `datetime.now().isoformat()` at report time. Rendered HTML contains the stored string and not the report-generation time.
  - Scenario empty result: 0 rows returned, `active_connections == []`, collection status `"no_data"`; no rows invented.
  - Scenario placeholder: `add_active_connections(scan_id, [], status="failed")` writes the `N/A` row with `collection_status='failed'`; the report returns 0 rows and status `"failed"`. Placeholder still excluded — no regression.
  - Extra: a literal `'N/A'` timestamp renders as `"N/A"` rather than an empty cell.
  - `python3 -m py_compile core/report_generator.py` -> OK.
  - No tests directory present, `pytest` not run.

### Inverted Server header check and HSTS checked on plain HTTP
- Files: config/signatures.json, core/web_scanner.py
- Status: fixed
- Root cause:
  - `WebScanner.check_headers` (`core/web_scanner.py:115-131`) had a single condition, `if header_name not in headers:`, so every entry in `signatures.json["headers"]` fired only when the header was ABSENT. The Server signature describes disclosure ("Server header reveals potentially sensitive information about the web server technology and version"), so a hardened server that hides `Server` was reported and an exposing server was not. Inverted.
  - The same loop had no `is_https` gate, so `Strict-Transport-Security` was evaluated on port 80 responses. Missing HSTS is expected on plain HTTP, so every HTTP-only service produced a false `Medium` finding.
- Design: data-driven expectation flags on the signature entries instead of hardcoding a header name in the loop.
  - `"type": "present" | "absent"` — `"absent"` is the code default (`header_info.get("type", "absent")`), so an entry that omits the field keeps the original missing-header behaviour.
  - `"https_only": true | false` — explicit on every entry; only `Strict-Transport-Security` is `true`.
  - Field order in each header dict: `name, type, https_only, severity, description, remediation`. No other array touched, no reformatting.
- Changes:
  - `config/signatures.json`: `Server` -> `"type": "present", "https_only": false`; `Strict-Transport-Security` -> `"type": "absent", "https_only": true`; `X-Frame-Options`, `X-Content-Type-Options`, `Content-Security-Policy` -> `"type": "absent", "https_only": false`. 10 inserted lines, 0 modified, 0 removed.
  - `core/web_scanner.py`: the loop now skips `https_only` entries when `is_https` is false, computes `expectation`/`is_present`/`is_finding`, continues when the expectation is met, and labels the finding `"present_header"` or `"missing_header"` from the expectation. That label is used in both the `"type"` key and the dedup key `f"{finding_type}_{header_name}"`. The `check_headers` docstring now reads "Header security findings (present-when-harmful or absent-when-required)." Severity, description, remediation, port/protocol fields, the generic exception handler, `check_ssl`, `scan_host`, and the INSERT are untouched.
  - No new severity, description, remediation, or title strings. Server's existing text was already worded for the present case; HSTS's for the absent case.
  - No key collision: `ssl_errors` entries also carry `"type"`, but that is a separate array read only by `check_ssl`'s `_add_ssl_finding` (`s["type"] == error_type`) — different namespace, no shared lookup.
- Behaviour change:
  - A server that hides `Server` no longer produces a finding; a server that discloses it now produces one `Low` finding of type `present_header`.
  - HTTP-only services no longer produce `Strict-Transport-Security` findings. HTTPS services still do when HSTS is missing.
  - `X-Frame-Options`, `X-Content-Type-Options`, and `Content-Security-Policy` are unchanged: still flagged only when absent, on both HTTP and HTTPS.
  - The in-memory `"type"` label for Server findings changes from `missing_header` to `present_header`. `"type"` is not persisted (the INSERT stores host_id, title, severity, description, remediation, port, protocol), so only dedup keys and log output are affected. Stored titles remain the header name plus port context, e.g. `Server on Port 443/HTTPS`.
- Historical DB note: no migration required — no schema change, no new column, no new key read from the database. Rows written by the old inverted logic stay in existing databases and remain inaccurate (false HSTS positives on HTTP-only hosts, missing Server-exposure findings) until those hosts are rescanned. Documented, not a blocker.
- Known limitation: `is_https` is port-based (`core/web_scanner.py:272`, `port in [443, 8443]`), not a TLS probe. TLS served on any other port will not get HSTS checked, and a plain-HTTP service on 443 is still treated as HTTPS. Deferred to issue #10.
- Verification (no live network; `self.session` replaced with a fake exposing `.get()` returning an async context manager with `.headers`, which is the only surface `check_headers` uses):
  ```
  [1 hardened HTTPS] []
  [2 exposing HTTPS] [('present_header', 'Server')]
  [2b exposing HTTPS + no HSTS] [('missing_header', 'Strict-Transport-Security'), ('present_header', 'Server')]
  [3 HTTP-only] []
  [4 HTTPS missing HSTS, Server disclosed] [('missing_header', 'Strict-Transport-Security'), ('present_header', 'Server')]
  [4b HTTPS missing HSTS only] [('missing_header', 'Strict-Transport-Security')]
  no Server missing_header findings, no present_header for absent-check headers: PASS
  [5 empty headers, HTTP] [('missing_header', 'X-Frame-Options'), ('missing_header', 'X-Content-Type-Options'), ('missing_header', 'Content-Security-Policy')]
  ALL CHECKS PASSED
  ```
  - Scenario 1 (hardened HTTPS: CSP, XFO, XCTO, HSTS present, no Server): zero findings. Server absence is no longer a finding.
  - Scenario 2 (HTTPS, `Server: Apache/2.4.49`, all security headers present): exactly one finding, `present_header` / `Server`.
  - Scenario 3 (HTTP-only, CSP/XFO/XCTO present, no HSTS, no Server): zero findings — the HSTS false positive is gone.
  - Scenario 4 (HTTPS, Server disclosed, no HSTS): one HSTS `missing_header` plus one `present_header` / `Server`. Scenario 4b (same, Server withheld): exactly one HSTS finding.
  - Scenario 5 (HTTP, empty headers): only CSP/XFO/XCTO missing — proves the gate removes HSTS alone and leaves the other absent-checks intact.
  - The spec's scenario 2 ("other headers present except HSTS" but "exactly one finding") and scenario 4 ("Server present" but "exactly one HSTS finding") each describe contradictory outcomes, since missing-HSTS-on-HTTPS and disclosed-Server are both genuine findings under the approved design. Both were resolved by isolating one variable per case (2 keeps HSTS, 4b withholds Server) and asserting the interaction explicitly in 2b and 4.
  - `python3 -m py_compile core/web_scanner.py` -> OK. `json.load(config/signatures.json)` -> parses; all five header entries report their `type`/`https_only`.
  - No tests directory present, `pytest` not run.

### Escaped `>` in embedded CSS and risk/severity class names matching no selector
- Files: reporting/templates/executive_report.html
- Status: fixed
- 10a root cause (broken `.report > *` rule):
  - `core/report_generator.py:35-38` builds the Jinja environment with `autoescape=True`. Autoescape is context-blind: it escapes every `{{ ... }}` in a text node, and `<style>` bodies are text nodes. `reporting/templates/style.css:129` contains a child combinator, `.report > *:not(.report-header):not(.report-footer)`, so `>` was written as `&gt;`. HTML entities are not decoded inside a raw-text element (`<style>` is raw text per HTML parsing), so the CSS parser received `&gt;`, the selector was invalid, and the whole rule was silently dropped. Jinja has no "disable autoescape inside `style`" feature; the two sanctioned escapes are `|safe` on the expression or `{% autoescape false %}` around it.
- 10a fix: line 7 `{{ css_content }}` -> `{{ css_content|safe }}`.
  - Why `|safe` and not an Environment change: it is scoped to one variable that is a file read from the local repo (`resource_path("reporting/templates/style.css")`), so it is a trusted asset. Disabling autoescape on the Environment would also leave scan-derived strings (titles, descriptions, banners) unescaped and reintroduce XSS on CVE/banner text. Proven safe by the XSS check below. `{% autoescape false %}` would be an equivalent 2-line change; `|safe` is one token.
- 10b root cause (unstyled badges and tags):
  - The template emitted a redundant prefix plus the variant word: `class="risk-badge risk-{{ risk_level|lower }}"` and `class="severity-tag severity-{{ sev|lower }}"`. `style.css` defines compound selectors `.risk-badge.critical|.high|.medium|.low|.info` (259-275) and `.severity-tag.critical|.high|.medium|.low|.info` (431-443). The emitted variant classes (`risk-critical`, `severity-high`, ...) match none of them. Neither a wildcard nor an attribute nor a descendant selector rescues it: `.risk-badge` / `.severity-tag` base rules still apply (48px transparent square; white text with no background), so the result is invisible rather than merely grey.
  - Mismatch was uniform: all 4 risk variants and all 5 severity variants failed. `.risk-badge.info` (275) is additionally dead — `risk_level` is only ever `Critical|High|Medium|Low` (`core/report_generator.py:295-308`). One dead selector suggests the stylesheet was written for a template version that emitted `risk-badge <severity>`.
  - Why Approach A (template emits the classes CSS expects) over B (rewrite selectors to `.risk-badge.risk-high`):
    - Matches the convention already working in the same two files: template lines 65/71/77/83 emit `kpi-icon hosts|ports|vulns|duration` and `style.css:338-341` defines `.kpi-icon.hosts` — compound base + variant word. `classification-{{ ...|lower }}` (line 273) uses the same model.
    - Smaller diff: 4 one-token deletions vs 10 selector rewrites.
    - B would encode the redundant double-prefix naming into the stylesheet, contradicting the rest of the design system, and would leave `.risk-badge.info` dead.
- Exact change (5 lines, one file, no other line touched):
  ```
  -        {{ css_content }}
  +        {{ css_content|safe }}

  -                    <div class="risk-badge risk-{{ risk_level|lower }}">{{ risk_grade }}</div>
  +                    <div class="risk-badge {{ risk_level|lower }}">{{ risk_grade }}</div>

  -                            <span class="severity-tag severity-{{ rec.severity|lower }}">{{ rec.severity }}</span>
  +                            <span class="severity-tag {{ rec.severity|lower }}">{{ rec.severity }}</span>

  -                            <td><span class="severity-tag severity-{{ cve.severity|lower }}">{{ cve.severity }}</span></td>
  +                            <td><span class="severity-tag {{ cve.severity|lower }}">{{ cve.severity }}</span></td>

  -                            <span class="severity-tag severity-{{ vuln.severity|lower }}">{{ vuln.severity }}</span>
  +                            <span class="severity-tag {{ vuln.severity|lower }}">{{ vuln.severity }}</span>
  ```
  - The four class lines already carried `|lower` before the change; only the redundant `risk-` / `severity-` prefix was removed, so the final strings are exactly `risk-badge {{ risk_level|lower }}` and `severity-tag {{ x|lower }}`.
  - `|lower` behaviour check: every value reaching these expressions is a single alphanumeric word (`Critical|High|Medium|Low` for `risk_level`; `Critical|High|Medium|Low|Info` and uppercase `CRITICAL|HIGH` from `vuln_lookup.CVE_DB` for severities). No value contains punctuation, so `|lower` cannot produce an unmatchable class. (The `N/A` placeholder only appears in `conn.remote_classification`, a different block — see note 2.)
- Verification (no live network, no browser; template rendered in-process with the same `Environment(autoescape=True)` and a representative `template_data` dict; `jinja2 3.1.6`):
  ```
  jinja2 3.1.6
  [10a] '<style>' contains '.report > *' literally, no '&gt;': PASS
  [10b] risk-badge critical / high emitted: PASS
  [10b] severity-tag critical/high/medium/low emitted lowercase (CVE 'CRITICAL'/'HIGH' normalized): PASS
  [10b] no 'risk-*'/'severity-*' prefixed classes, no double-prefix form: PASS
  [xss] scan-derived title escaped as &lt;script&gt;: PASS
  [10a] css_content embedded raw (|safe): '>' and '&' literal in <style>, no &gt;/&amp;: PASS
  ALL CHECKS PASSED
  ```
  - Two renders: `risk_level="Critical"` (grade F) and `risk_level="High"` (grade D). Data covered recommendations `High`/`Medium`, `cve_findings` with uppercase `CRITICAL`/`HIGH`, and `vulnerabilities_by_host` with `High`/`Low`.
  - 10a: the rendered `<style>` block contains the literal selector `.report > *:not(.report-header):not(.report-footer)` and contains neither `&gt;` nor `&amp;`. Both CSS comments with `&` (`/* Enterprise Header & Branding */`, `/* Active Traffic & Socket Mapping Section */`) now arrive intact instead of `&amp;` — cosmetic, but confirms the block is no longer entity-escaped.
  - 10b: `class="risk-badge critical"` and `class="risk-badge high"` present; `class="severity-tag critical|high|medium|low"` present in both renders, with CVE severities supplied uppercase and normalized by `|lower`. No `risk-critical`, `risk-high`, `severity-critical`, `severity-high`, `risk-badge risk-`, or `severity-tag severity-` in the rendered markup.
  - Prefixed-class assertion scope: the first run of the check failed on `severity-critical` inside the rendered document. That was the check's fault, not the template's — the inlined stylesheet legitimately contains the CSS custom property `--severity-critical` and the selectors `.risk-badge.critical`/`.severity-tag.critical`, so the substring exists in the `<style>` block even though no element carries a `severity-critical` class. The assertion was narrowed to markup (style block stripped) to test class attributes, which is what the issue is about.
  - XSS check: `|safe` applied only to `css_content`; a vulnerability title of `<script>alert(1)</script>` still renders as `&lt;script&gt;alert(1)&lt;/script&gt;`, and raw `<script>` is absent from the markup. Autoescape remains active for all scan-derived text.
  - `py_compile` not applicable (no Python change).
- Behaviour change: the `.report > *` spacing rule starts applying (report sections regain their intended vertical rhythm), risk badges regain their severity background colour, and severity tags regain theirs instead of rendering as white-on-white text.
- Note 1 (historical reports): `core/report_generator.py:380-389` reads `style.css` and embeds it into the template data at generate time; the template inlines it, and there is no `<link rel=stylesheet>` anywhere. Each written report is therefore a snapshot of the CSS and class names at generation time. Reports generated before this fix keep the broken `>` rule and unstyled classes and must be regenerated from the DB to pick up the fix. No report files exist in this checkout (`reports/` absent, `find -name "Report_*.html"` empty), so nothing to regenerate here. DB rows are unaffected — presentation-only bug, no schema or stored string changed.
- Note 2 (latent, out of scope): `reporting/templates/executive_report.html:273` emits `classification-{{ conn.remote_classification|lower }}`, so the `N/A` placeholder produces `classification-n/a`. A slash is not valid in a CSS class token and cannot match `.classification-n-a` (`style.css:632`). Same class of defect, different block. Recommend a separate issue; not touched here.
- Note 3 (out of scope): `.risk-badge.info` (`style.css:275`) remains dead — `risk_level` never takes the value `Info`. Left alone per the no-unrelated-changes rule.

### Shared aiosqlite connection: cross-task rollback silently discards another host's committed rows
- Files: core/database.py, core/network_scanner.py, core/web_scanner.py
- Status: fixed (Option A — single write lock, absorbing the scanner-side commit/rollback)
- Bug (reproduced empirically before the fix):
  - `DatabaseManager` holds exactly one `aiosqlite.Connection` (`database.py` `connect()`), created with default `isolation_level=''` (deferred), no WAL, no `busy_timeout`. One connection therefore means one `sqlite3.Connection` and one shared transaction.
  - `aiosqlite` serialises individual operations on a worker thread, but the *transaction* is not partitioned per task. `commit()` commits, and `rollback()` discards, every task's uncommitted work on that connection.
  - Traced sequence: Task A `add_host` (insert + commit, durable) → Task B `add_port` insert, awaiting its commit → Task A hits a DB error and calls `await self.db.connection.rollback()` → SQLite rolls back the single open transaction, taking B's uncommitted row with it → B's `commit()` then commits an empty transaction and returns success.
  - Result is silent data loss: no exception, no log line. Reproduced with aiosqlite 0.22.1 / sqlite3 3.53.1:
    ```
    [PRE-FIX  raw shared conn, no lock] ports after both tasks: []
    [PRE-FIX  ] VERDICT: B's committed insert was silently discarded (bug reproduced)
    ```
  - Exposure window is widest in `add_active_connections` (N inserts, one commit at the end) and in `web_scanner.scan_host` (multi-row transaction) — any concurrent rollback wipes the whole in-flight batch. The reverse failure also existed: a concurrent commit flushed a half-finished task's rows early, leaving non-deterministic partial data.
  - Trigger rate: a rollback only happens on a DB error in one host while another is mid-transaction, so in practice this surfaces as unexplained missing rows in large scans.
- Why the lock alone was insufficient: an `asyncio.Lock` around the eight write methods does not stop `network_scanner.py` from calling `self.db.connection.rollback()` directly, outside the lock. That call can land inside another task's locked execute→commit window and still destroy its rows. The fix had to absorb the scanner-side `commit()`/`rollback()` as well — which is why this touches three files instead of one.
- Why Option A over B (per-task connections) and C (write queue): A is the only option inside the three-file budget, it cannot introduce `SQLITE_BUSY` because it adds no second connection, and it fixes the mechanism at the point of failure. B is structurally cleaner but needs 4-5 files plus WAL + `busy_timeout`, per-connection `PRAGMA foreign_keys=ON`, idempotent schema init, and it converts silent corruption into a possible new lock-timeout failure mode. C changes the public write API and needs 4 files.
- Change:
  - `core/database.py`:
    - `import asyncio`; `self._write_lock: asyncio.Lock = asyncio.Lock()` in `__init__` (created before `connect()`, not bound to a loop at creation — Python 3.10+ semantics).
    - The eight write methods (`initialize_tables`, `create_scan`, `update_scan_status`, `add_host`, `add_port`, `add_vulnerability`, `add_active_connections`, `add_derived_ports`) now run their existing `try` block inside `async with self._write_lock:`; the existing `commit()` stays inside the `try`, and the `except` now does `await self.connection.rollback()` then `raise`. Callers no longer need to roll back.
    - New public surface: `write_lock` property, `async def commit()`, `async def rollback()` — both acquire the lock themselves. No new write methods; read methods and `close()` untouched; no signature changes.
  - `core/network_scanner.py`: deleted the redundant `await self.db.connection.commit()` in `scan_host` (it committed nothing — every `add_*` already committed) and the caller-side `await self.db.connection.rollback()`. The `except` still logs, so the batch `gather` keeps going. No other logic changed.
  - `core/web_scanner.py`: the raw `INSERT INTO vulnerabilities` loop plus its commit/rollback is now wrapped in `async with self.db.write_lock:` with an inner `try/except → rollback → raise`. It deliberately calls `self.db.connection.commit()`/`rollback()` directly and **not** `self.db.commit()`/`self.db.rollback()` — the helpers re-acquire the same non-reentrant lock and would deadlock. SQL, column list and parameters unchanged; the raw INSERT was not replaced with `add_vulnerability` (that unification is a separate cleanup).
  - Latent-vs-active: web scanning is currently sequential (`scan_targets` is a plain `for` + `await`), so its rollback could not overlap another writer today. It is fixed now so it does not become the identical live bug the moment web scanning is parallelised, and because it was already reaching around `DatabaseManager`.
- Verification:
  - `python3 -m py_compile core/database.py core/network_scanner.py core/web_scanner.py` -> OK. `grep -c 'async with self\._write_lock:' core/database.py` -> 10 (8 methods + 2 helpers).
  - Throwaway script `/tmp/opencode/verify_lock.py` (not committed), run via `PYTHONPATH=. uv run --no-project --python 3.13 --with rich --with psutil --with colorama --with aiosqlite --with jinja2 --with aiohttp --with paramiko --with pywinrm python3`:
    ```
    [PRE-FIX  raw shared conn, no lock] ports after both tasks: []
    [PRE-FIX  ] VERDICT: B's committed insert was silently discarded (bug reproduced)
    [POST-FIX DatabaseManager, lock] 25 concurrent iterations, rows lost: 0
    [POST-FIX ] VERDICT: B's row survived every iteration
    [POST-FIX wide txn  ] active_connections rows: 200 (expected 200)
    [helpers   ] write_lock identity, commit()/rollback() helpers no deadlock: PASS
    [single-task] scan=1 host=1 port=1 rows: hosts=1 ports=1 vulns=1: PASS
    [single-task] get_hosts open_ports_list='22/tcp', get_ports order/fields intact: PASS
    [fk-failure] IntegrityError propagated, no partial row, connection reusable after rollback: PASS
    [smoke     ] report data: hosts=1 ports=2 vulns=1 derived=1 conns=0 conn_status=failed riskscore=6
    [smoke     ] ordering (ports 80,443) and counts unchanged: PASS
    ----------------------------------------------------------------------
    ALL CHECKS PASSED
    ```
    - Race test: Task A `add_port` on a non-existent host id (real FK violation → except path → rollback under the lock) against Task B `add_port` on a valid host, `asyncio.gather`, repeated 25 times. Zero rows lost. The identical shape loses the row on an unlocked shared connection (first line of output).
    - Wide-transaction test: `add_active_connections` with 200 rows concurrently with a failing writer; all 200 rows present.
    - FK-rollback test: an aborted write leaves no partial row, the exception propagates, and the same connection is immediately reusable for a subsequent successful write.
    - Sequential smoke test: in-memory DB, one host, two ports, one vulnerability, one derived-port row, one `skipped` placeholder; `_prepare_template_data` returns unchanged counts and port ordering `[80, 443]`.
  - Grep note (the verification checklist and the web_scanner instruction cannot both be satisfied literally): `self.db.connection.commit()` / `self.db.connection.rollback()` now appear **zero** times in `core/network_scanner.py`. In `core/web_scanner.py` they remain at lines 327 and 329 — inside `async with self.db.write_lock:` (line 302), which is exactly what the web_scanner instruction requires, because the `self.db.commit()`/`rollback()` helpers would deadlock there. `self.db.connection.execute(...)` also remains at `web_scanner.py:270` (a pre-existing read that builds the host lookup) and 320 (the locked insert loop).
- Test-side correction (not a source change): the smoke test first asserted `len(data["active_connections"]) == 1`. That assertion was wrong. `report_generator._get_active_connections_data` filters `if row[6] == "success"`, so the `skipped` placeholder row is intentionally metadata-only: it flips `connection_status` to `"failed"` and never appears as a connection. The test now asserts the placeholder exists in the DB (`get_active_connections(sid)` == 1) while the report lists zero. This filter predates this issue and was not touched.
- Carried-forward constraints:
  - #14 (batch commits) MUST land after this fix. Batched commits widen each write transaction and therefore widen the exposure window; applying #14 first would make the bug worse, not better. After this fix, #14 is a drop-in (its batch method holds the lock for the whole body).
  - #12 (`asyncio.to_thread`) MUST move only the blocking collector calls, never the DB writes. If writes move into threads, the `asyncio.Lock` no longer covers them and Option B (per-task connections) becomes mandatory.
  - `self.semaphore` at `core/network_scanner.py:41` is created and never used — dead code; the only concurrency bound is the batch size. Noted for a future cleanup.
  - `DatabaseManager.add_vulnerability` has zero callers; `web_scanner` writes with a raw INSERT. Unifying them is a separate issue.
  - Rows already silently lost before this fix cannot be recovered; they resurface only on rescan.
  - No migration required — this is a runtime concurrency defect, not a schema or data-format one.

### RemoteCollector.collect_connections blocks the event loop for the whole SSH/WinRM round trip
- File: core/network_scanner.py
- Status: fixed
- Phase 1 findings:
  - Call site: `collect_and_store_active_connections` (line 202). The blocking call was at lines 219-224 — `connections = collector.collect_connections(target, credentials["username"], credentials["password"], credentials["auth_type"])`, called directly inside an `async def`, i.e. on the event loop.
  - Return type: `RemoteCollector.collect_connections` is declared `-> List[Dict[str, Any]]` (`core/remote_collector.py:29`) and both branches (`_collect_ssh`, `_collect_winrm`) build that list. The dicts hold only strings / ints / `None` (`local_address`, `remote_address`, `remote_classification`, `pid`, `process_name`, `status`). No objects with thread affinity, nothing unpicklable — safe to marshal back from a worker thread.
  - Thread safety: `RemoteCollector.__init__` sets three booleans (`accept_unknown_hosts`, `accept_invalid_certs`, `allow_insecure_winrm_http`) and they are never mutated afterwards. All per-call state is local: `paramiko.SSHClient()` is constructed and closed inside `_collect_ssh`, `winrm.Session(...)` inside `_collect_winrm`. No module-level client, no class-level mutable state, no shared session. Each host constructs its own `RemoteCollector` inside the function (line 214), so moving the call into a thread cannot introduce a cross-host race.
  - Flow: the collector returns, then the fallback branches (`is_local` → `self.get_active_connections`) run, then the DB work — `await self.db.get_ports` (251) → `await self.db.add_derived_ports` (260) → `await self.db.add_active_connections` (264). No await sits between the collector return and those writes, but all three DB calls are plain awaits on the event loop, so they stay under the #11 lock.
  - Precedent: `asyncio` is already imported at `core/network_scanner.py:2`, and the file already offloads `socket.gethostbyaddr` with `await asyncio.to_thread(...)` at line 310. No new import, no new dependency.
  - All three expected conditions held, so the fix proceeded.
- Change (one call, same arguments, same positional form):
  ```python
  # before
  connections = collector.collect_connections(
      target,
      credentials["username"],
      credentials["password"],
      credentials["auth_type"]
  )
  # after
  connections = await asyncio.to_thread(
      collector.collect_connections,
      target,
      credentials["username"],
      credentials["password"],
      credentials["auth_type"]
  )
  ```
  Nothing else changed: same `try/except`, same logging, same fallbacks, same signature, same return value. DB writes stay on the event loop — **no** `await self.db.*` call is wrapped in `asyncio.to_thread`, so the #11 `asyncio.Lock` remains valid and the derived_ports / add_active_connections writes still run on the loop in their original order.
- Verification:
  - `python3 -m py_compile core/network_scanner.py` -> OK.
  - Static checks over the function body only (`collect_and_store_active_connections` → `scan_host`): `asyncio.to_thread` appears exactly once and its only target is `collector.collect_connections`; `re.search(r"to_thread\(\s*self\.db\.", body)` -> `False`; the three `self.db.*` call sites are `open_ports = await self.db.get_ports(scan_id)`, `await self.db.add_derived_ports(...)`, `await self.db.add_active_connections(...)` — all awaited, none threaded.
  - Event-loop-free timing (`/tmp/opencode/verify_thread.py`, not committed). `RemoteCollector.collect_connections` monkeypatched to `time.sleep(0.1); return []`; a ticker task records the gap between successive `await asyncio.sleep(0)` wakeups while the collector runs in a task. Pre-fix shape = direct call on the loop, post-fix shape = the real `collect_and_store_active_connections`:
    ```
    [PRE-FIX  direct call] collector blocks 100 ms | ticker samples=1 max gap=100.3 ms
    [POST-FIX to_thread    ] collector blocks 100 ms | ticker samples=89 max gap=11.0 ms
    VERDICT: event loop stalls 100.3 ms before, 11.0 ms after (9x less) -> loop stays free during the collector call
    [db write] active_connections rows=1 status=N/A connection_status/failed placeholder written on the loop: PASS
    ALL CHECKS PASSED
    ```
    The 11.0 ms residual is first-use thread-pool startup, not collector blocking. A second run (`/tmp/opencode/verify_thread2.py`, 5 back-to-back scans in one process) shows the steady state:
    ```
    run 1: max gap=   1.3 ms  p99=  1.28 ms  median= 1.10 ms  samples=91
    run 2: max gap=   1.2 ms  p99=  1.17 ms  median= 1.09 ms  samples=93
    run 3: max gap=   1.2 ms  p99=  1.18 ms  median= 1.10 ms  samples=92
    run 4: max gap=   1.2 ms  p99=  1.15 ms  median= 1.08 ms  samples=94
    run 5: max gap=   1.2 ms  p99=  1.17 ms  median= 1.08 ms  samples=93
    ```
    i.e. ~1.2 ms worst-case loop latency against a 100 ms blocking call — an ~80x reduction in stall.
  - Lock regression (#11 unaffected): re-ran `/tmp/opencode/verify_lock.py` unchanged — `[POST-FIX DatabaseManager, lock] 25 concurrent iterations, rows lost: 0`, `[POST-FIX wide txn] active_connections rows: 200 (expected 200)`, plus helpers / single-task / fk-failure / sequential-smoke all PASS, `ALL CHECKS PASSED`. Task B's committed row still survives Task A's rollback.
- Blocking calls found in the same function but deliberately NOT fixed (out of scope for #12):
  - `is_local(target)` — wraps `socket.gethostname()`, a synchronous NSS/DNS lookup. Three call sites (227, 234, 241).
  - `self.get_active_connections(scan_id)` — the local fallback: `psutil.net_connections(kind='inet')` plus one `psutil.Process(pid).name()` per connection. Synchronous, unbounded by connection count. Three call sites (229, 236, 242). This is the biggest remaining event-loop risk in the function and deserves its own issue.
  - `logger.*` calls — per-record file I/O depending on handlers; low impact, left alone.
- Behaviour change: hosts now run their SSH/WinRM collection on the default executor thread pool instead of the event loop, so the progress bar animates and other hosts' port scans continue during the up-to-30 s remote call. No change to what is collected or stored. Default executor size bounds how many collectors run truly in parallel; the batch `gather` still starts up to `max_concurrent` tasks, and surplus ones simply queue on the executor rather than blocking the loop.

### Missing indexes on hosts / ports / vulnerabilities / active_connections / derived_ports
- File: core/database.py
- Status: fixed
- Phase 1 findings:
  - Schema (`create` statements, exact lines): `scans` 73-81, `hosts` 84-93, `ports` 96-107, `vulnerabilities` 110-122, `active_connections` 135-149, `derived_ports` 153-163. Every table has `id INTEGER PRIMARY KEY AUTOINCREMENT`; no other index-bearing clause.
  - Existing indexes: **none**. `grep -rn 'CREATE.*INDEX' --include=*.py .` -> 0 hits repo-wide. The only implicit index SQLite creates here is the rowid/`sqlite_sequence` bookkeeping for AUTOINCREMENT, which is not usable for the lookup columns.
  - Idempotency: `initialize_tables` is fully re-runnable. All tables use `CREATE TABLE IF NOT EXISTS`; the two `ALTER TABLE vulnerabilities ADD COLUMN` calls (lines 126 and 130) are wrapped in `try/except` that swallows the "duplicate column" error, so a second run is a no-op. `CREATE INDEX IF NOT EXISTS` composes safely with that pattern and needs no extra guarding.
  - Query patterns (all filter on the proposed columns):
    - `get_hosts` — `core/database.py:567-570` and the duplicate at `core/report_generator.py:79-82`: `FROM hosts h WHERE h.scan_id = ?`, joined `LEFT JOIN ports p ON h.id = p.host_id`.
    - `get_ports` — `core/database.py:648-652` (+ `report_generator.py` copy): `FROM ports p JOIN hosts h ON p.host_id = h.id WHERE h.scan_id = ?`.
    - `get_vulnerabilities` — `core/database.py:606-610` (+ `report_generator.py` copy): `FROM vulnerabilities v JOIN hosts h ON v.host_id = h.id WHERE h.scan_id = ?`.
    - `active_connections` — `core/database.py:691-692` and `core/report_generator.py:146`: `WHERE scan_id = ? ORDER BY timestamp DESC`.
    - `derived_ports` — `core/database.py:547-550`: `WHERE scan_id = ? ORDER BY ip_address, port`.
    - **Composite** — `core/web_scanner.py:272-273`: `SELECT id FROM hosts WHERE scan_id = ? AND ip_address = ?`.
  - Composite decision: `hosts` gets a single composite `idx_hosts_scan_ip ON hosts(scan_id, ip_address)` instead of a single-column `idx_hosts_scan_id`. The leading `scan_id` column serves every scan_id-only query (`get_hosts`, and the `h.scan_id = ?` filter in the ports/vulns joins), and the second column serves the web_scanner lookup, which then runs as a covering index search. A separate single-column index would be redundant. Five indexes total.
  - ORDER BY check (stop condition 1): `derived_ports` and `active_connections` keep a residual `USE TEMP B-TREE FOR ORDER BY`. Rows per scan are bounded by open ports / observed sockets, so the sort is small and the indexes were not extended to cover it. Not expensive -> no stop.
  - Composite-premature check (stop condition 2): the composite is not premature. It replaces the single-column index at zero extra cost and is the only index serving `web_scanner`'s per-host lookup, which otherwise scans the whole `hosts` table once per host.
  - Ordering (stop condition 4): **triggered** — see the ordering note below.
- Exact DDL added (after all `CREATE TABLE` statements, i.e. after `derived_ports`, and before the single existing `commit()` now at line 185; same `await self.connection.execute(...)` pattern, committed by the existing commit):
  ```sql
  CREATE INDEX IF NOT EXISTS idx_hosts_scan_ip ON hosts(scan_id, ip_address);
  CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports(host_id);
  CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_id ON vulnerabilities(host_id);
  CREATE INDEX IF NOT EXISTS idx_active_connections_scan_id ON active_connections(scan_id);
  CREATE INDEX IF NOT EXISTS idx_derived_ports_scan_id ON derived_ports(scan_id);
  ```
  No table, column, type, or query was changed. No other file was touched.
- Verification:
  - `python3 -m py_compile core/database.py` -> OK.
  - `EXPLAIN QUERY PLAN`, before (indexes dropped) vs after (indexes present), each measured on a freshly opened connection — same-connection EXPLAIN is stale after `DROP INDEX` because of the Python sqlite3 schema cache:
    ```
    === without indexes ===                        === with indexes ===
    [get_hosts]                                    [get_hosts]
       SCAN h                                         SEARCH h USING INDEX idx_hosts_scan_ip (scan_id=?)
       BLOOM FILTER ON p (host_id=?)                  SEARCH p USING INDEX idx_ports_host_id (host_id=?) LEFT-JOIN
       SEARCH p USING AUTOMATIC COVERING INDEX
    [get_ports]                                    [get_ports]
       SCAN p                                         SEARCH h USING COVERING INDEX idx_hosts_scan_ip (scan_id=?)
       SEARCH h USING INTEGER PRIMARY KEY             SEARCH p USING INDEX idx_ports_host_id (host_id=?)
    [get_vulnerabilities]                          [get_vulnerabilities]
       SCAN v                                         SEARCH h USING COVERING INDEX idx_hosts_scan_ip (scan_id=?)
       SEARCH h USING INTEGER PRIMARY KEY             SEARCH v USING INDEX idx_vulnerabilities_host_id (host_id=?)
    [active_connections]                           [active_connections]
       SCAN active_connections                        SEARCH active_connections USING INDEX idx_active_connections_scan_id (scan_id=?)
    [derived_ports]                                [derived_ports]
       SCAN derived_ports                             SEARCH derived_ports USING INDEX idx_derived_ports_scan_id (scan_id=?)
       USE TEMP B-TREE FOR ORDER BY                   USE TEMP B-TREE FOR ORDER BY   (residual, accepted)
    [web_scanner host lookup]                      [web_scanner host lookup]
       SCAN hosts                                     SEARCH hosts USING COVERING INDEX idx_hosts_scan_ip (scan_id=? AND ip_address=?)
    ```
    All six queries moved from a table `SCAN` to `SEARCH ... USING INDEX` (three of them `COVERING`). No target table is scanned full any more.
  - Idempotency: `DatabaseManager(":memory:")`, `initialize_tables()` called three times -> no exception, and `SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'idx_%'` returns the identical list after runs 1 and 3:
    `['idx_active_connections_scan_id', 'idx_derived_ports_scan_id', 'idx_hosts_scan_ip', 'idx_ports_host_id', 'idx_vulnerabilities_host_id']`.
  - Raw rowid order unaffected: `SELECT id FROM hosts` with no `ORDER BY` still returns insertion order (`[1,2,3,4,5]`) — adding an index does not change the heap order itself.
  - #11 lock regression, unchanged: `[POST-FIX DatabaseManager, lock] 25 concurrent iterations, rows lost: 0`, `[POST-FIX wide txn] active_connections rows: 200 (expected 200)`, plus helpers / single-task / fk-failure / sequential-smoke `ALL CHECKS PASSED`. Indexes did not alter write behaviour or the lock's correctness.
  - #5 derived_ports smoke: 2 hosts / 3 ports seeded out of order; `get_derived_ports` still returns `[(10.0.0.1, 22), (10.0.0.2, 80), (10.0.0.2, 443)]` (ordered by ip_address, port) and `get_hosts` open-port counts are intact. PASS.
  - Large-DB cost (stop condition 5): 100k `hosts` rows inserted in 0.26 s; building `idx_hosts_scan_ip` on them took **51 ms**. Noticeable but small; see the note below.
- Ordering stop condition (triggered, resolved as Option A):
  - Three queries have no `ORDER BY` and their result order changes from insertion (rowid) order to index order once the index is used. Verified with deliberately inverted insertion order (id 1 = `10.0.0.250`, id 2 = `10.0.0.10`):
    ```
    CHANGED  get_hosts
             without: [[1, '10.0.0.250'], [2, '10.0.0.10']]
             with   : [[2, '10.0.0.10'], [1, '10.0.0.250']]
    CHANGED  get_ports
             without: [[1, 443], [2, 80], [3, 22]]
             with   : [[2, 80], [3, 22], [1, 443]]
    CHANGED  get_vulnerabilities
             without: [[1, 'B vuln'], [2, 'A vuln']]
             with   : [[2, 'A vuln'], [1, 'B vuln']]
    same     active_connections, derived_ports, web_scanner_host_lookup
    ```
  - Resolution (user decision, Option A): **accept index order.** No query edits, no `report_generator.py` change (both copies of the three queries shift identically, so the report and the `get_*` API stay mutually consistent). Nothing in the repo depends on the previous order: there is no `tests/` directory, no caller sorts or indexes by position, and the old order was implicit rowid order — never a contract. Practical effect: host / port / vulnerability lists now come back IP-sorted, which reads better in the report.
- Note: on a large existing DB, the first startup after this change will spend time building the indexes; this is a one-time cost (measured at 51 ms per 100k `hosts` rows). Existing rows are not modified, and subsequent startups pay nothing because `CREATE INDEX IF NOT EXISTS` is a no-op.

### Per-row commits make the network and web scanners fsync once per row
- Files: core/database.py, core/network_scanner.py, core/web_scanner.py
- Status: fixed (Option A′ — one transaction per host, plus one per URL for web findings)
- Root cause: every stored row paid its own durable commit. `scan_host` in `network_scanner.py` called `add_host` once and then `add_port` once per open port, and `add_port` ends in `await self.connection.commit()`. With the settings actually in force (`journal_mode=delete`, `synchronous=2` / FULL), each commit is an fsync. Cost therefore scales with rows written, not with hosts scanned, and the fsync is the dominant term.
  - Measured baseline (`/tmp/opencode/bench_commits.py`, 1000 `ports` rows, identical INSERT payload):
    ```
    ### tmpfs  /tmp
      per-row add_port (today)       1000 rows:     169.3 ms  (   169 us/row)  rows=1000
      single executemany+1 commit    1000 rows:       3.6 ms  (     4 us/row)  rows=1000
    ### btrfs  $HOME
      per-row add_port (today)       1000 rows:    6406.6 ms  (  6407 us/row)  rows=1000
      single executemany+1 commit    1000 rows:       9.2 ms  (     9 us/row)  rows=1000
    ```
    tmpfs hides the problem (no real fsync -> ~150-170 us/row); on the real filesystem it is ~6.3-6.4 ms per row, a ~40x penalty against the batched form and a ~38x penalty against tmpfs. The exact figure moves with fsync latency on the day (an earlier run of the same script gave 6272.3 ms / 6.27 ms per row), so read these as an order of magnitude, not a benchmark.
  - Whole-scan effect (`/tmp/opencode/bench_scan24.py`, 254 hosts x 8 open ports = 2286 commits):
    ```
    today: 1 commit per row       254 hosts x 8 ports =  2286 commits:    14817 ms
    batched: 1 commit per host    254 hosts x 8 ports =   254 commits:     1850 ms
    ```
    A /24 costs ~14.8 s of pure commit latency before any network work; the same rows batched cost ~1.85 s (earlier run: 14.9 s / 1.75 s).
  - Concurrency did not help: `scan_host` tasks still serialise on `DatabaseManager._write_lock` (#11), so the commits queue up but every one of them is still an fsync.
- Why Option A′ over the rejected shapes:
  - **B — transaction context manager + `contextvars`**: 3-file churn plus lock ownership becomes invisible at the call site (nothing in the call detects that the caller already holds the write lock, so a nested acquisition deadlocks), and a `contextvars`-based "am I already in a transaction" flag does not propagate correctly once #12's `asyncio.to_thread` moves work off the task. Rejected.
  - **C — `commit=False` keyword on the existing writers**: two silent footguns. Forgetting the flag anywhere reintroduces the #11-class cross-task rollback (a caller-side rollback then discards another host's rows), and a caller who forgets it *and* calls `db.commit()` deadlocks on the non-reentrant lock. A boolean that changes transaction semantics is not visible in the signature's type. Rejected.
  - **D — leave it to SQLite (WAL / `synchronous=NORMAL`)**: does not remove the per-row work, only reduces fsync cost, and changes durability globally for a local-variable problem. WAL stays a separate lever (see below).
- Change:
  - `core/database.py` — two new methods only. `add_host`, `add_port`, `add_vulnerability`, and every other existing method are untouched; no signature changed.
    - `add_host_with_ports(scan_id, ip_address, is_alive, hostname, ports) -> int` (line 401): acquires `async with self._write_lock:` for the whole body, `INSERT INTO hosts`, `host_id = cursor.lastrowid`, one `executemany` over `ports` when the list is non-empty, one `await self.connection.commit()`, returns `host_id`. On exception: `rollback()` then `raise`.
    - `add_vulnerabilities_batch(host_id, vulnerabilities) -> int` (line 499): acquires the same lock, returns `0` for an empty list **before executing any statement** (so no commit at all), otherwise one `executemany` over `vulnerabilities`, one `commit()`, returns `len(vulnerabilities)`. On exception: `rollback()` then `raise`.
    - Both follow the existing writer shape exactly (same lock, same commit-inside-`try` / rollback-in-`except` / `raise`).
  - `core/network_scanner.py` (`scan_host`, call at line 337): the `await self.db.add_host(...)` plus the `for port ... await self.db.add_port(...)` loop are replaced by one `ports_list` comprehension (same five fields, same `json.dumps(service_info) if service_info else None` expression) and a single `await self.db.add_host_with_ports(scan_id, ip, is_alive, hostname, ports_list)`. The surrounding `try`/`except Exception` and the `logger.error(f"Failed to store host {ip} in database: {e}")` are unchanged, so a failing batch still logs and drops that host only. `scan_targets` and `collect_and_store_active_connections` untouched.
  - `core/web_scanner.py` (`scan_host`, call at line 323): the `async with self.db.write_lock:` block, the raw `INSERT INTO vulnerabilities` loop and its manual `commit()`/`rollback()` are replaced by a `vuln_rows` list built with the title decoration **inlined unchanged** (`finding.get("header", finding.get("type", ...))`, the `on Port {port}/{protocol.upper()}` suffix, and the `f"Port {port}" not in title` guard) and one `await self.db.add_vulnerabilities_batch(host_id, vuln_rows)` per URL. Granularity is preserved: the call is inside the existing per-URL loop, so one URL's findings are still one transaction (one URL failing does not roll back another URL's findings). URL fetching, header checks and SSL checks untouched. The existing per-host `try`/`except` still catches a batch failure.
- Grep (no raw connection writes left in the scanners):
  ```
  $ grep -n "connection.execute\|connection.commit\|connection.rollback\|write_lock" core/network_scanner.py core/web_scanner.py
  core/web_scanner.py:270:        cursor = await self.db.connection.execute(
  ```
  One hit remains and it is the pre-existing **read-only** `SELECT id FROM hosts WHERE scan_id = ? AND ip_address = ?` used to resolve `host_id`. Zero occurrences of `write_lock`, `connection.commit` and `connection.rollback` in either scanner. All writes now go through a `DatabaseManager` method that owns the lock.
- Verification (`python3 -m py_compile core/database.py core/network_scanner.py core/web_scanner.py` -> OK; throwaway scripts under `/tmp/opencode/`, not committed):
  - Batch behaviour and commit counts, commit/rollback counted by wrapping `db.connection.commit` / `.rollback` (`/tmp/opencode/verify_batch.py`):
    ```
    [1 host + 1000 ports] host_id=1 port rows=1000 commits=1 rollbacks=0 2.30 ms
    [1 host + 0 ports  ] host_id=1 port rows=0 commits=1 (empty list skips executemany)
    [100 vulnerabilities ] returned=100 rows=100 commits=1 0.25 ms
    [empty vuln batch   ] returned=0 commits=0 (no statement executed)
    [fk failure         ] IntegrityError -> rollbacks=1
    [reuse after rollback] inserted=1 (connection still usable)
    [scan_host wiring   ] hosts=1 ports=[22, 80, 443, 8080] commits=1 158.25 ms
    [scan_host error    ] hosts stored=0 (exception logged, host dropped as before)
    [btrfs 1000 ports   ] 8.79 ms, 1 commit (was 6272 ms with per-row commits)
    ```
    - 1000 ports in one host: exactly 1 commit, 1 transaction. 8.79 ms on btrfs vs 6272 ms per-row — the fsync is gone from the inner loop.
    - Zero-port host still commits once (the host row must be durable).
    - 100 vulnerabilities: 1 commit. Empty list: 0 commits, so a URL with no findings writes nothing.
    - Failure path: an FK violation rolls back once, commits nothing, and the connection is immediately reusable for the next batch.
    - Scanner wiring: `scan_host` with 4 open ports from 5 scanned ports produced 1 host, ports `[22, 80, 443, 8080]` with service names intact, `open_ports_count == 4`, and **1 commit total** (previously 5).
    - Error path unchanged: a `service_info` of `None` still raises inside the batch, is logged, and drops that host only.
  - Web scanner granularity (`/tmp/opencode/verify_web_batch.py`, fake `check_headers`/`check_ssl`, no network):
    ```
    [web_scanner] vulns=5 commits=2 (1 per URL, preserved granularity)
       X-Frame-Options on Port 443/HTTPS
       X-Frame-Options on Port 80/HTTP
       missing_hsts on Port 443/HTTPS
       missing_hsts on Port 80/HTTP
       ssl_error on Port 443/HTTPS
    [web_scanner] protocols=['http', 'http', 'https', 'https', 'https']
    [web_scanner] no-findings URL -> commits=0 (nothing written)
    ```
    Two URLs produced 5 rows in 2 commits — the per-URL granularity the old block had is intact. Title decoration still appends `on Port <n>/<PROTO>` for both header and SSL findings, and never double-appends. A URL with no findings writes nothing.
  - #11 lock regression (`/tmp/opencode/verify_lock.py`), unchanged: `25 concurrent iterations, rows lost: 0`; `200/200` rows in the wide-transaction test; helpers / single-task / fk-failure / sequential smoke `ALL CHECKS PASSED`. The new methods take the same lock, so batching did not weaken the cross-task isolation #11 established.
  - #5 derived_ports smoke: still a separate table with its own rows (`derived=1` in the smoke output); `get_derived_ports` ordering and `get_hosts` port counts unchanged. PASS.
  - #6 risk-score assembly (`/tmp/opencode/verify_score6.py`): scenario A -> `total=0 score=0 grade=A`; scenario C (Apache 2.4.49 -> `CVE-2021-41773`, plus one web HIGH and one web LOW) -> `total=3 score=36 grade=B level=Low`, counts `{CRITICAL:1, HIGH:1, LOW:1}`, `cve_findings` contains the CVE. Template data keys unchanged (22 keys, `vuln_counts` is not and never was a key; the template reads `vulnerability_breakdown`). PASS.
  - #10 template render/XSS regression (`/tmp/opencode/verify_render.py`): `ALL CHECKS PASSED`.
- ACID note: each host is one transaction (host row + all its ports), and each URL's findings are one transaction. A crash or an error mid-batch rolls back that host (or that URL) only — no partial host with orphan ports, and no cross-host loss, because every batch holds `_write_lock` for its whole body and commits before releasing it. Nothing outside the batch can be caught by the rollback. Rows already written by earlier hosts stay committed.
- Residual cost and the next lever: batching removes the per-row fsync but not the per-host one. A single commit still costs ~6.9 ms on btrfs (8.79 ms for 1000 ports minus ~2 ms of insert work), so a /24 is ~1.85 s of commit time (measured above; 254 commits, so ~7.3 ms each). Further gains need WAL (`journal_mode=WAL` with `synchronous=NORMAL`) or a scan-level transaction, both of which change durability or transaction lifetime and belong in their own issue. Not done here.
- Carried-forward: `DatabaseManager.add_vulnerability` still has zero callers (kept, not removed — out of scope); `self.semaphore` at `core/network_scanner.py:41` is still dead code; the `N/A` placeholder in `add_host_with_ports`'s field handling and the duplicate-derived-row risk are untouched.

### is_local() blocks the event loop on socket.gethostname()
- Files: core/network_scanner.py
- Status: fixed
- Root cause: `is_local()` was a plain sync function whose every call did `socket.gethostname()` inline. It was called from `collect_and_store_active_connections` (three sites) and from `_iter_work_items`, so each call stalled the whole event loop for the duration of the syscall. The network scanner runs hosts concurrently on one loop, so the stall froze port scans, the rich progress bar, and every other in-flight coroutine. `gethostname()` is usually fast (cached `/etc/hostname` read), but it is a syscall on a path taken per host, and the fix is free.
- Change:
  - `is_local(target)` is now `async def`. Loopback names (`127.0.0.1`, `localhost`, `::1`) short-circuit without any syscall; otherwise it returns `is_local_target(target, await asyncio.to_thread(socket.gethostname))`.
  - New module-level pure helper `is_local_target(target, hostname)` plus a `_LOCAL_NAMES` frozenset hold the actual comparison, so the same rule is not duplicated.
  - All three async call sites in `collect_and_store_active_connections` now `await is_local(target)`.
  - `_iter_work_items` is a **sync generator** (`itertools.islice` drives it), so it cannot `await`. It now takes `local_hostname: str = ""` and calls `is_local_target(ip, local_hostname)`; `scan_targets` resolves the hostname exactly once per scan with `await asyncio.to_thread(socket.gethostname)` and passes it in. Previously the syscall ran once per host inside the generator — so this is also fewer syscalls (1 per scan instead of 1 per host).
  - Selection semantics unchanged: an item is added for `credentials` or a local target, exactly as before.
- Verification (`/tmp/opencode/verify_fix1.py` and `/tmp/opencode/verify_fix1_driver.py`, not committed). `socket.gethostname` was patched to `time.sleep(0.1)`; a concurrent `asyncio.sleep(0)` spinner recorded every loop gap:
  ```
  [stall] old sync is_local():  100.2 ms   new awaited is_local():    1.2 ms
  [fastpath] loopback names short-circuit without a syscall: PASS
  [semantics] 'myhost' -> True, '10.0.0.9' -> False: PASS
  [workitems] local, no creds: 2  remote, no creds: 1  remote, creds: 2
  [fallback] stored rows=1 status=ESTABLISHED
  FIX 1 CHECKS PASSED
  ```
  - The old shape stalls the loop for the full 100 ms; the awaited shape peaks at 1.2 ms, which is the spinner's own granularity, not the syscall.
  - Fast path proven to make zero `gethostname` calls (a counting stub stayed at 0 for `127.0.0.1`, `localhost`, `::1`).
  - Work-item selection matches the old rule in all three combinations (local/no creds = 2 items, remote/no creds = 1, remote/creds = 2).
  - `collect_and_store_active_connections` still stores through the local fallback (1 row, status `ESTABLISHED`).
  - Driver smoke: `scan_targets(["127.0.0.1"])` scheduled both `scan_host` and `collect_and_store_active_connections`; a remote target scheduled `scan_host` only.
- Note: `core/network_scanner.py` imports nothing new; `socket` and `asyncio` were already imported.

### get_active_connections() blocks the event loop for the whole psutil sweep
- Files: core/network_scanner.py
- Status: fixed
- Root cause: `get_active_connections` called `psutil.net_connections(kind='inet')` and then, for every connection with a pid, `psutil.Process(pid).name()`. Both are blocking syscalls (`/proc/net/*` reads, per-pid `/proc/<pid>/` reads). It was called directly from `collect_and_store_active_connections`, so one sweep blocked the loop for tens of milliseconds on a busy host — the same loop that is driving hundreds of concurrent port scans. This was the largest remaining event-loop blocker after #12.
- Change:
  - `get_active_connections` is now `async def` and returns `await asyncio.to_thread(self._get_active_connections_sync, scan_id)`. The old body was moved verbatim into the new private `_get_active_connections_sync`; field extraction, `classify_ip`, `map_tcp_state`, the `Unknown`/`Access Denied` handling and the `except Exception -> logger.error` all unchanged.
  - The three call sites now `await self.get_active_connections(scan_id)`.
  - The DB write was **not** moved: `await self.db.add_active_connections(...)` still runs in `collect_and_store_active_connections` on the event loop, after the thread returns. `to_thread` wraps only the psutil sweep.
  - No external caller existed (repo-wide grep found only these three), so the sync→async change breaks nothing.
- Verification (`/tmp/opencode/verify_fix2.py`, not committed). `psutil.net_connections` and `psutil.Process.name` were each patched to `time.sleep(0.1)`; a `asyncio.sleep(0)` spinner measured loop gaps and thread ids were recorded on both sides:
  ```
  [stall] sync collection:  200.5 ms   awaited collection:    1.6 ms
  [collect] rows=2 -> [('10.0.0.5:5000', '10.0.0.9:443', 'proc4242', 'ESTABLISHED'), ('127.0.0.1:8080', 'N/A', 'Unknown', 'LISTEN')]
  [threads] collect_ident==main: False   db_write_ident==main: True
  [store  ] rows in DB=2 status=ESTABLISHED
  FIX 2 CHECKS PASSED
  ```
  - 200 ms of blocking (two 0.1 s calls) becomes 1.6 ms of loop gap; the collection is observed on a worker thread and the DB write on the event loop thread, which is exactly the required split.
  - Result shape unchanged: remote connection classified non-`N/A`, pid-less row stays `Unknown` with `remote_address == "N/A"`.
  - The stored rows survive the round trip through `add_active_connections`.

### datetime.utcnow() is deprecated
- Files: core/database.py, core/web_scanner.py (`core/report_generator.py` needed no change — it had no `utcnow()`)
- Status: fixed
- Root cause: `datetime.utcnow()` returns a naive datetime whose value is UTC but whose `tzinfo` is `None`. It is deprecated in Python 3.12+ and removed in a future release. A naive UTC value also silently breaks any comparison against an aware datetime, which is exactly what bit the SSL expiry check below.
- Change:
  - `core/database.py` — three sites (`create_scan` start_time, `update_scan_status` end_time, `add_active_connections` timestamp) now use `datetime.now(timezone.utc).isoformat()`. `timezone` was already imported. `add_derived_ports` already used the aware form.
  - `core/web_scanner.py` — one site (`check_ssl` expiry check). The certificate's `notAfter` is GMT but `strptime(..., '%Z')` returns a naive datetime, so the parsed value gets `tzinfo=timezone.utc` when missing, and `now` is `datetime.now(timezone.utc)`. Without that attach the comparison would raise `TypeError` (and `check_ssl` only catches `ValueError` there), which is why the two changes belong together. `from datetime import datetime, timezone`.
  - `.isoformat()` kept everywhere; no `strftime` substitution, no precision change.
- Stored-format note: aware ISO strings carry a `+00:00` suffix (`2026-11-08T11:35:36.163166+00:00`), where the deprecated call produced a naive string. This is the one observable difference. It is safe: `report_generator` already parses with `fromisoformat(... .replace("Z", "+00:00"))` and normalises a missing `tzinfo` (the #7 fix), so durations and `scan_date` keep working. Lexicographic `ORDER BY start_time` still orders correctly for same-format rows; across the migration boundary two rows with the identical second compare `...:00` < `...:00+00:00`, i.e. new rows sort above old ones at the same instant — harmless, and only for pre-existing rows.
- Verification (`/tmp/opencode/verify_fix3.py`, not committed):
  ```
  [store] start_time=2026-11-08T11:35:36.163166+00:00
  [store] end_time=2026-11-08T11:35:36.213828+00:00
  [report] scan_duration='00:00' (must not be 'N/A')
  [ssl] past cert findings=['ssl_error:SSL certificate has expired and is no longer val']
  [ssl] future cert findings=[]
  FIX 3 CHECKS PASSED
  ```
  - Stored timestamps are aware, parse back to `utcoffset == 0`, and are within 5 s of wall clock.
  - `end_time > start_time` as a string, and `_prepare_template_data` computes a real duration instead of `N/A`.
  - Expiry path: a 2020 `notAfter` produces the `expired_certificate` finding with the days count; a 2099 `notAfter` produces no finding and raises nothing (the aware/naive `TypeError` regression is specifically covered).
  - `grep -rn "utcnow" --include=*.py .` -> none.

### SSL check reports verified=True for connections that never completed
- Files: core/web_scanner.py
- Status: fixed
- Root cause: `check_ssl`'s verified probe set `verified = True` in its generic `except Exception` branch. That branch catches everything that is not a certificate error — connection refused, timeout, reset, protocol error — so a port with no TLS listener at all was recorded as a *verified* handshake. The flag then suppressed the `TLS certificate validation failed` warning at the end of the method. The only correct statement about a refused connection is that nothing was verified.
- Change: the generic `except Exception` branch now sets `verified = False` (comment updated to say the handshake never completed). `verified = True` remains only on the success path, after `writer.wait_closed()`. The `SSLCertVerificationError` branch was already `False` and is untouched. The unverified second probe, the expiration/self-signed checks and the returned findings are unchanged — failing to verify still does not stop certificate details from being reported.
- Verification (`/tmp/opencode/verify_fix4.py`, not committed; `asyncio.open_connection` faked for each case, `logger.warning` captured):
  ```
  [connection refused] findings=0 verified=False warnings=1 -> TLS certificate validation failed for 10.0.0.5:443
  [timeout          ] findings=0 verified=False warnings=1 -> TLS certificate validation failed for 10.0.0.5:443
  [cert verify error] findings=1 verified=False warnings=1 -> TLS certificate validation failed for 10.0.0.5:443
  [handshake ok     ] findings=0 verified=True warnings=0
  FIX 4 CHECKS PASSED
  ```
  - `ConnectionRefusedError` and `asyncio.TimeoutError` now leave `verified` False (observable through the warning), where the old code left it True.
  - A real certificate-verification failure still produces its finding, and the flag stays False.
  - A completed handshake stays `verified = True` with no warning, so the success path did not regress.
- Note: the warning text is now emitted for "port is not TLS" as well as "certificate is bad", because that is what the flag means. If that proves noisy on scans with many non-TLS ports, the wording should change; the flag semantics should not.
- Regression sweep after all four fixes (all pass): `verify_batch` (`ALL CHECKS PASSED`), `verify_web_batch` (`WEB CHECKS PASSED`), `verify_lock` (`ALL CHECKS PASSED`, 25 concurrent iterations rows lost 0), `verify_score6` (`SCORE CHECKS PASSED`, `total=3 score=36 grade=B`), `verify_render` (`ALL CHECKS PASSED`), `verify_thread2` (max loop gap 1.1-1.5 ms across 5 runs), `verify_fix1_driver` (`DRIVER SMOKE PASSED`). `python3 -m py_compile` clean on all four files.

### `--password` accepts the remote secret on the command line
- Files: main.py
- Status: fixed
- Root cause: `--password` / `-P` took the remote password as an argument, so the secret landed in `ps` output, shell history, and any process-audit log. Its own help text admitted the exposure and asked the user to prefer `SECAPPLIANCE_PASSWORD` — a flag that exists only to be avoided should not be offered. The surrounding resolution logic (`password or os.environ.get(...)`) also made the environment variable a silent second choice behind the leakier input.
- Change:
  - The `password` option is deleted from `scan()`; `--password`/`-P` no longer parse (exit 2, "unexpected extra argument"). `Optional` and `getpass` are still used elsewhere, but the `getpass` import became unused and was removed.
  - Resolution order is now env-first, prompt-second: `os.environ.get("SECAPPLIANCE_PASSWORD")`, else `typer.prompt(f"Password for {username}@{target}", hide_input=True)` (echo disabled).
  - The abort path catches `(EOFError, KeyboardInterrupt, click.Abort, typer.Abort)`. That tuple is empirical: on the installed typer 0.28, `typer.prompt` raises `typer.exceptions.Abort` (a `RuntimeError` subclass, *not* `click.Abort`), so catching only `click.Abort` let the abort escape and the friendly message never printed. `click.Abort` is kept for older typer releases, which is what `import click` is for.
  - The stale "…or provide a password" wording is replaced with "Set SECAPPLIANCE_PASSWORD or enter one at the prompt."; the `scan()` docstring now states the password is never accepted as an argument.
- Verification (`/tmp/opencode/verify_fix5.py`, not committed; `main.asyncio.run` replaced with a stub that reads the closure and closes the coroutine, so **no scan runs**):
  ```
  [env    ] exit=0 prompted=False creds={'username': 'alice', 'password': 'from-env', 'auth_type': 'winrm'}
  [prompt ] exit=0 prompted=True creds={'username': 'alice', 'password': 's3cret', 'auth_type': 'winrm'}
  [eof    ] exit=1 msg=True
  [anon   ] exit=0 creds=None prompted=False
  [flag   ] exit=2 (must be 2 = unknown option)
  FIX 5 CHECKS PASSED
  ```
  - `main.py scan --help` no longer contains `--password`.
  - Env var present: no prompt, value reaches the credential dict. Env var absent: prompt is shown with echo off and the typed value is used.
  - Empty stdin (EOF) exits 1 with the actionable message. No username: credentials stay `None`, no prompt.
  - `--password leak` is rejected as an unknown option (exit 2).
- Follow-up (resolved, see "Follow-up: README still documented --password and the logger wrote a file at import"): `README.md` still documented the `--password` row in its option table and the surrounding "prefer the env var" note. Both are now removed/reworded.

### Database and log paths are relative to the current working directory
- Files: main.py
- Status: fixed
- Root cause: `get_db_path()` was `Path("data") / "secappliance.db"` under the CWD, so the scan database moved with the shell's working directory: run from `/tmp`, get a fresh empty DB and lose every previous scan. `utils.logger` had the same shape — `setup_logger()` defaults to `log_file='secappliance.log'` and is instantiated at import, so the log file also landed in whatever directory happened to be current.
- Change:
  - New `get_app_data_dir()`: `platformdirs.user_data_dir("SecAppliance")` when importable, else `Path.home() / ".secappliance"`, then `mkdir(parents=True, exist_ok=True)`. `platformdirs` is imported inside the function because it is optional — no new hard dependency.
  - `get_db_path()` -> `<data dir>/secappliance.db`; new `get_log_path()` -> `<data dir>/secappliance.log`.
  - New `redirect_file_logging(log_path)`: because `utils.logger` attaches its CWD-relative `FileHandler` at import time, the handler is re-pointed at the data dir at the start of `scan()` — the old handler is removed and closed, formatter and level are carried over, the console handler is untouched. Done before the `--verbose` level loop so the moved handler picks up the level too.
  - Report output is unchanged and deliberately still CWD-relative (`--output-dir` default `Path("reports")`): users expect the report where they run the command. Only durable state (DB, logs) moved.
- Verification (`/tmp/opencode/verify_fix6.py`, not committed; run with `os.chdir(tmpdir)` so any CWD write is visible):
  ```
  [platformdirs] /tmp/.../xdg/SecAppliance  exists=True
  [fallback    ] /tmp/.../home/.secappliance  exists=True
  [paths       ] db=secappliance.db log=secappliance.log parent=SecAppliance
  [redirect    ] exit=0 handlers=['StreamHandler:-', 'FileHandler:/tmp/.../xdg/SecAppliance/secappliance.log']
  [logfile     ] /tmp/.../xdg/SecAppliance/secappliance.log bytes=64 probe=True
  [cwd         ] cwd/data created=False  cwd/reports=True (reports is CWD-relative by design)
  FIX 6 CHECKS PASSED
  ```
  - With `platformdirs` available the returned path is exactly what it reports; with the import blocked the `~/.secappliance` fallback is used and created. Both branches create the directory (`parents=True`).
  - A real unpatched call on this machine returns `/home/anonymous/.local/share/SecAppliance`, created.
  - After `scan()` starts, the logger has one `StreamHandler` (console) and one `FileHandler` whose `baseFilename` is `<data dir>/secappliance.log`; a probe record written post-redirect is present in that file.
  - No `data/` directory is created in the CWD any more; `reports/` still is.
- Dependency note: `platformdirs` 4.14.3 is installed in the environment but **is not in `requirements.txt`**. `requirements.txt` was not edited (per the stop condition). The import is guarded, so a missing `platformdirs` degrades to `~/.secappliance` instead of failing — but the next packaging pass should pin it if the platform-native location is wanted on fresh installs.
- `:memory:` note: nothing in the path change touches in-memory databases — tests construct `DatabaseManager(":memory:")` directly and never call `get_db_path()`. No `tests/` directory exists to break.
- Follow-up (resolved, see "Follow-up: README still documented --password and the logger wrote a file at import"): an empty `secappliance.log` was still created in the CWD at import time by `utils/logger`, before this redirect could move it. That import-time handler is gone; the file handler is now created only when `main.py` asks for one.

### auth_type defaults disagree (winrm in the CLI, ssh in the collector)
- Files: main.py, core/remote_collector.py
- Status: fixed
- Root cause: `scan()` defaulted `--auth-type` to `"winrm"` while `RemoteCollector.collect_connections()` defaulted `auth_type='ssh'`. The CLI always passes its value, so the collector default was dead on that path — but any other caller (or a future one) silently got SSH from the library and WinRM from the CLI for the same nominal action. The CLI option also accepted any string, deferring the rejection to a logged `Unsupported auth type` at collection time instead of failing at parse time.
- Change:
  - `core/remote_collector.py`: `collect_connections(..., auth_type: str = 'winrm')` — matches the CLI.
  - `main.py`: the option is typed `AuthType` (new `class AuthType(str, Enum)` with `winrm`/`ssh`), default `AuthType.winrm`. Invalid values are rejected at parse time (exit 2). The value is normalised with `.value` when building the credential dict, so everything downstream (`NetworkScanner` -> `RemoteCollector`) still receives a plain `str`.
  - `click.Choice` was **not** used, contrary to the brief: on the installed typer 0.28 `click_type=click.Choice([...])` renders the metavar as `<function>` (help shows `<function>` instead of the choices) and a rejected value surfaces as an unhandled `BadParameter` traceback with exit 1. A three-way probe (`/tmp/opencode/probe_choice.py`) showed `click_type` broken both with and without `case_sensitive`, while the enum annotation produced `<winrm|ssh>` and exit 2. The enum gives the same restriction with correct help and the correct exit code, so it is used instead.
- Verification:
  ```
  --auth-type  -a  <winrm|ssh>  Authentication protocol to use for deep collection.  [default: winrm]

  Invalid value for '--auth-type' / '-a': 'ftp' is not one of 'winrm', 'ssh'.   (exit 2)

  ['--username','u']                 -> 0 {'username': 'u', 'password': 'p', 'auth_type': 'winrm'}
  ['--username','u','--auth-type','ssh'] -> 0 {'username': 'u', 'password': 'p', 'auth_type': 'ssh'}
  auth_type stays a plain str downstream: PASS
  ```
  - `main.py scan --help` shows `[winrm|ssh]` (typer renders it as `<winrm|ssh>` plus `[default: winrm]`); `--auth-type ftp` exits 2 with a readable message.
  - `inspect.signature(RemoteCollector.collect_connections)` default is now `winrm`, and routing with no `auth_type` hits `_collect_winrm` (with `ssh` passed explicitly it hits `_collect_ssh`).
- Combined regression: `python3 -m py_compile main.py core/remote_collector.py` clean; fix 5 and fix 6 suites re-run green after the fix 7 edit; `--target 10.0.0.5` with `--output-dir <tmp>` never ran a real scan (the `asyncio.run` stub closes the coroutine before execution).


### Follow-up: README still documented --password and the logger wrote a file at import
- Files: utils/logger.py, main.py, README.md
- Status: fixed (follow-ups to the `--password` removal and the app-data-dir change)
- Root cause, two halves:
  1. `utils/logger.py` created a `logging.FileHandler('secappliance.log')` at **import time** (`logger = setup_logger()` at module bottom). Every process that imported the logger — including every CLI run — wrote into the CWD before `main.py` could re-point it, and startup crashed outright if the CWD was read-only or unwritable, which made the "logs live in the app data dir" fix incomplete.
  2. `README.md` still listed `--password` / `-P` in its option table and told readers the flag existed, contradicting the CLI after the flag was removed.
- Change:
  - `utils/logger.py`: `setup_logger(name, level)` now returns a console-only logger (`StreamHandler` with the colored formatter). The `log_file` parameter is gone; importing the module touches no file system. New `attach_file_handler(logger, log_path, level=None) -> bool` adds the plain file handler, replacing any existing one (safe to call repeatedly), and returns `False` after a `logger.warning(...)` if the path cannot be opened — so a bad or unwritable directory degrades to console logging instead of raising. Module-level `LOG_FORMAT` / `LOG_DATE_FORMAT` constants replace the two duplicated format literals.
  - `main.py`: `redirect_file_logging()` is deleted (the logger owns handler creation now); `scan()` calls `attach_file_handler(logger, get_log_path())` before the `--verbose` level loop, unchanged in effect.
  - `README.md`: the `--password` row is removed from the flag table; the password note now says credentials are never accepted on the command line, names `SECAPPLIANCE_PASSWORD` plus the no-echo prompt, and documents the per-user data directory while noting reports stay CWD-relative.
- Verification:
  ```
  [ro-cwd import] exit=0 handlers=['StreamHandler'] cwd files: []
  [unwritable  ] attached=False handlers=['StreamHandler'] (console-only fallback, ENOTDIR)
  [eacces      ] attached=False handlers=['StreamHandler'] (Errno 13, as uid 1000)
  [writable    ] first=True second=True file_handlers=['b.log'] (replaced, not stacked)
  [degrade     ] handlers=['StreamHandler'] (stale file handler removed)
  ```
  - Importing `utils.logger` in a 0555 CWD succeeds, logs to the console, and creates **no** file there.
  - `attach_file_handler` on a path whose parent is a file (`[Errno 17]`) and on a read-only directory (`[Errno 13] Permission denied`) both warn and leave only the `StreamHandler`.
  - Two calls replace the handler instead of stacking it; a failed attach after a successful one leaves no stale handler.
  - `grep -c -- "--password" README.md` -> `0`; `main.py scan --help` still shows `[winrm|ssh]` and no password option.
  - Re-ran `verify_fix5` (`FIX 5 CHECKS PASSED`) and `verify_fix6` (`FIX 6 CHECKS PASSED`) after the logger rework — the file handler still lands on `<data dir>/secappliance.log` at scan start, no `data/` dir in the CWD, `reports/` still CWD-relative.
  - `python3 -m py_compile utils/logger.py main.py` clean. Help text greps ok.

### Final low-priority batch: unpinned requirements, N/A CSS class, implicit row order, dead code
- Files: requirements.txt, reporting/templates/executive_report.html, core/database.py, core/report_generator.py, core/network_scanner.py
- Status: fixed (3 of 4 findings; the `self.semaphore` half was not reproducible and is intentionally unchanged)

**8. `requirements.txt` was unpinned**
- Root cause: all nine entries were bare names, so two installs a month apart could resolve to different major versions of `typer`, `aiohttp`, `paramiko`, `rich`, etc. Nothing recorded what the code was actually written against.
- Change: every entry is now an exact `==` pin, plus two additions — `click` (imported directly by `main.py` for `click.Abort`, previously satisfied only transitively via `typer`) and `platformdirs` (imported by `get_app_data_dir()`; the missing pin was flagged in the fix 6 entry). Versions came from a clean throwaway resolve of the old file (`uv venv` + `uv pip install -r requirements.txt` + `pip freeze` in `/tmp/opencode/reqvenv`, CPython 3.13.18), not from guesswork:
  ```
  aiohttp==3.14.5    jinja2==3.1.6      typer==0.28.0     colorama==0.4.6
  aiosqlite==0.22.1  psutil==7.2.2      paramiko==5.1.0   pywinrm==0.5.0
  rich==15.0.0       click==8.5.1       platformdirs==4.14.5
  ```
- `requirements.txt` is now fully pinned. No new dependency was introduced: `click` and `platformdirs` were already import requirements of the code (and already installed by any working install), they were just absent from the file.

**9. `N/A` connections rendered with a class no stylesheet defines**
- Root cause: `remote_classification` is a display string (`LAN` / `WAN` / `N/A`). `|lower` produced `classification-n/a`; CSS cannot carry a `/` in a bare class selector, and `style.css` defines `.classification-n-a` (line 632), so placeholder rows silently lost their badge styling.
- Change: `reporting/templates/executive_report.html:273` -> `class="classification-{{ conn.remote_classification|lower|replace('/', '-') }}"`.

**10. Both list queries returned rows in whatever order SQLite happened to produce**
- Root cause: `get_vulnerabilities` and `get_ports` had no `ORDER BY`, so report sections reordered between runs on identical data (vacuum, re-index, or a different plan could change it), and no stable tie-break existed for equal severities. `ReportGenerator._get_vulnerabilities_data` carries its own copy of the vulnerability SQL and had the same gap, so a fix applied to only one side would have left the rendered report and the raw API disagreeing.
- Change:
  - `core/database.py` `get_ports`: `ORDER BY p.port_number`.
  - `core/database.py` `get_vulnerabilities` and `core/report_generator.py` `_get_vulnerabilities_data` (identical clause in both, to prevent divergence):
    ```sql
    ORDER BY CASE UPPER(v.severity)
                 WHEN 'CRITICAL' THEN 0 WHEN 'HIGH' THEN 1
                 WHEN 'MEDIUM'   THEN 2 WHEN 'LOW'  THEN 3
                 ELSE 4
             END,
             h.ip_address,
             v.port
    ```
  - **Deviation from the brief, deliberate:** the brief asked for `ORDER BY severity DESC`. That produces the wrong order for this schema, twice over. Stored severity is mixed case — `config/signatures.json` holds `High`/`Medium`/`Low` (14 rows) while `core/vuln_lookup.py` holds `CRITICAL`/`HIGH`/`MEDIUM` (and `web_scanner.py:321` defaults to `Info`), and SQLite's default collation is byte-wise, so a bare `DESC` sorts `Medium` above `MEDIUM` above `LOW`. Even case-folded, alphabetical `DESC` is `MEDIUM, LOW, HIGH, CRITICAL` — critical findings last, on a security report. The `CASE` expression maps the four known severities to explicit ranks (`UPPER()` folds the mixed case) and sends anything unrecognised to rank 4, i.e. last. The required tie-break (`ip_address, port`) is preserved verbatim.
  - `_get_hosts_data` / `get_hosts` were left alone: neither has an `ORDER BY` and no clause was added for them here, so there is nothing to keep in sync. Worth a follow-up — the grouped host table is the one remaining unordered list.

**11. Dead code**
- `core/database.py` `add_vulnerability`: confirmed zero callers (`grep -rn "add_vulnerability(" --include="*.py" .` -> 0). Removed the whole 39-line method; every write path already goes through `add_vulnerabilities_batch`, which uses the same `_write_lock`, `INSERT` column list and rollback handling. No import breakage — `py_compile` clean and `DatabaseManager` imports fine.
- `core/network_scanner.py` `self.semaphore`: **not reproducible, not removed.** It is not dead: it is the concurrency cap on the hot path at `core/network_scanner.py:106` (`async with self.semaphore:` wrapping `scan_port`), constructed at line 55 from the `max_concurrent` constructor argument (default 200). The outer runner batches hosts by `batch_size = max_concurrent` (line 448) and `scan_host` gathers one task per port, so the unguarded ceiling is `batch_size x len(common_ports)` ≈ 200 x ~100 concurrent sockets — fd exhaustion territory. Deleting the attribute would fail at the first `scan_port` call with `AttributeError`, and deleting the `async with` too would silently remove the cap. Left in place; `asyncio` is required by 12 other call sites (`to_thread`, `wait_for`, `gather`, `TimeoutError`) regardless.
- Only caller of the removed method anywhere was this session's throwaway `/tmp/opencode/verify_lock.py`; it was repointed at `add_vulnerabilities_batch` before the regression sweep. No repository code, template, or test referenced it.

- Verification:
  ```
  python3 -m py_compile core/database.py core/network_scanner.py core/report_generator.py  -> clean

  [Fix9  template] classification-n-a present, classification-n/a absent,
                   .classification-n-a exists in style.css                         PASS
  [Fix10 get_ports]  inserted 8080,22,443,22 -> [22, 22, 443, 8080]               PASS
  [Fix10 get_vulns]  inserted LOW,Critical,HIGH,MEDIUM,critical ->
                     [('Critical','10.0.0.20',22), ('critical','10.0.0.20',8080),
                      ('HIGH','10.0.0.10',443), ('MEDIUM','10.0.0.10',22),
                      ('LOW','10.0.0.20',22)]                                     PASS
  [Fix10 report gen] same order via _get_vulnerabilities_data, grouped hosts
                     10.0.0.20 before 10.0.0.10, generate_report() writes a file  PASS
  [Fix11 add_vulnerability( ] 0 occurrences; def add_vulnerability: 0            PASS
  [Fix11 self.semaphore     ] 2 occurrences = definition + the guard at :106     NOT REPRODUCIBLE
  ```
  - Render check ran the real `executive_report.html` through Jinja2 with a placeholder connection (`remote_classification="N/A"`) and asserted on the emitted HTML, not on the template source.
  - Ordering checks ran against `DatabaseManager(":memory:")` with `initialize_tables()` and deliberately out-of-order inserts (ports 8080/22/443/22 across two hosts; severities `LOW`, `Critical`, `HIGH`, `MEDIUM`, `critical`), asserting the returned sequence, not just the presence of rows.
  - Regression sweep after the edits: `verify_batch` (ALL CHECKS PASSED — batch window 9.86 ms / 1 commit, FK rollback, wiring), `verify_lock` (ALL CHECKS PASSED — 25 concurrent iterations 0 rows lost, wide 200-row txn, smoke report ports 80,443 in order), `verify_score6` (SCORE CHECKS PASSED — unchanged 99.9 percentage-rounding artifact, keys intact), `verify_render` (ALL CHECKS PASSED — CSS inlining, risk/severity classes, XSS escaping).

This concludes all 25 items from the original code review. All Critical, Major, and Improvement items are resolved.

### Online CVE Lookup (CIRCL API) Integration & Connection Mapping Fix
- Files: core/online_cve.py (new), core/database.py, core/network_scanner.py, core/web_scanner.py, core/report_generator.py, reporting/templates/executive_report.html
- Status: implemented (additive layer; offline signature scanning unchanged)
- Change:
  - New `core/online_cve.py`: `parse_banner` extracts (product, version) from a service banner or `Server` header; `lookup_online_cves` queries `https://vulnerability.circl.lu/api/vulnerability/?vendor=…&product=…&per_page=25`, filters records client-side against their declared affected versions, and extracts severity/CVSS from CNA metrics then ADP metrics. `lookup_with_cache` is the shared cache-then-fetch entry point for both scanners. Unparseable banners and network/JSON failures return `[]` and never raise.
  - `core/database.py`: `cve_cache` table (banner key -> JSON results, 7-day TTL, `get_cached_cves`/`cache_cves`) and `online_cves` table (`host_id`, `cve_id`, `summary`, `severity`, `cvss_score`, `timestamp`) with `idx_online_cves_host_id`. `add_online_cves` returns early on an empty list, writes one `executemany` batch under `self._write_lock` with a UTC-ISO timestamp, and rolls back on error; `get_online_cves` JOINs `hosts`, filters `hosts.scan_id = ?`, and orders by severity rank, host IP, then `cvss_score DESC`.
  - `core/network_scanner.py`: enrichment runs sequentially after `add_host_with_ports` succeeds, only when `scan_id` is valid. Banners are deduped per host, each goes through `lookup_with_cache`, CVE IDs are deduped, and one `add_online_cves` call is made per host. The scanner owns a lazily created `aiohttp.ClientSession` (`_get_session`/`close`), closed by `scan_targets` in a `finally`.
- Connection mapping fix (same file):
  - `_scan_host_and_collect` is a new per-host helper that awaits `scan_host` and then `collect_and_store_active_connections` in that order. Both used to be separate work items, and the batch runner gathers a batch concurrently: for a remote host without credentials the collector set `status = "skipped"` and read `get_ports(scan_id)` back within milliseconds, before `scan_host` had finished storing the ports, so the derived-port fallback always saw an empty list. Sequencing the two steps removes the race while hosts still scan concurrently.
  - `_iter_work_items` now yields that combined helper for every target. It previously yielded connection collection only when credentials were supplied or the target was local, so `scanme.nmap.org`-style public scans never invoked the derived-port fallback at all. The now-unused `local_hostname` parameter and its `socket.gethostname()` resolution were removed.
  - The derived-port fallback filters `open_ports` with `if port_info["ip_address"] == target`. `get_ports(scan_id)` spans the whole scan, and `derived_ports` has no uniqueness constraint, so the unfiltered list would have inserted every port of the scan once per host (N hosts -> N copies). The filter scopes each row set to the host that produced it.
  - `core/web_scanner.py`: `check_headers` now returns `(findings, server_header)`; `scan_host` uses the raw `Server` value as lookup input, applies the same cache logic, and tracks `seen_cves` so multiple ports on one host do not duplicate rows.
  - `core/report_generator.py` / template: `_get_online_cves_data` (never raises) adds `online_cves` and `online_cves_count` to the template data; `executive_report.html` gains an "Online CVEs (CIRCL)" KPI card and an "Online CVE Findings (CIRCL)" table (Host IP / CVE ID / Severity / CVSS Score / Summary) using the existing `severity-tag {{ severity|lower }}` classes, with the empty state "No online CVE findings."
  - Every lookup/cache/DB failure is logged and swallowed: an API outage cannot fail a scan or a report.
- Design choices (deliberate):
  - **No negative caching.** Empty results are not written to `cve_cache`. `[]` is also what a failed or timed-out lookup returns, so caching it for 7 days would hide an API outage; only non-empty result sets are cached.
  - **`online_cves_count` is a separate KPI**, not added to `total_vulnerabilities` or the risk score. These are OSINT product/version matches; folding them in would double-count CVEs already covered by offline signatures and inflate the risk score.
  - **Client-side version filtering.** The CIRCL API indexes by (vendor, product) only and silently ignores a `version=` parameter, so the banner version is matched locally against each record's `containers.cna.affected[].versions[]` (first two components; records with no machine-readable versions are kept as product-level matches). Consequence: a product whose indexed records stop at an older range yields nothing, e.g. `nginx/1.18.0`.
- Verification:
  - `python3 -m py_compile core/online_cve.py core/database.py core/network_scanner.py core/web_scanner.py core/report_generator.py` -> clean; `executive_report.html` parses under Jinja2.
  - Mocked integration run against `DatabaseManager(":memory:")` with a fake aiohttp session (no real scan): network path stores one row for two ports sharing a banner, cache serves a second host with no HTTP call, API failure stores nothing and raises nothing, web path fetches from the `Server` header and caches it, report gains `online_cves`/`online_cves_count`, the table/severity class render, and the empty state appears for a scan without findings (22/22 checks passed).
  - Live smoke test (manual): `Apache/2.4.52` -> 5 findings (`CVE-2024-38476`, CRITICAL 9.8), `OpenSSH 8.9` -> 1, `nginx/1.18.0` -> 0 (older ranges only).
  - Connection-mapping check (mocked, `DatabaseManager(":memory:")`, no real scan): `_iter_work_items(["192.0.2.10"], …, credentials=None)` yields exactly one item; the combined helper scans before it collects; a remote unauthenticated host gets its two open ports in `derived_ports` with `collection_status = "skipped"`; a second host does not duplicate the first host's rows; a local host takes the live-collection path and adds no derived rows (11/11 checks passed). `python3 -m py_compile core/network_scanner.py` clean.

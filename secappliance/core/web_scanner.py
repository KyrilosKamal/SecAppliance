import aiohttp
import asyncio
import ssl
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
from datetime import datetime, timezone

from secappliance.utils.logger import logger
from secappliance.utils.paths import package_path
from secappliance.core.database import DatabaseManager
from secappliance.core.online_cve import lookup_with_cache


def _resolve_path(path: str) -> Path:
    """Resolve a config path, honoring relative paths from the project root."""
    if Path(path).is_absolute():
        return Path(path)
    return package_path(path)


class WebScanner:
    def __init__(self, db_manager: DatabaseManager, signatures_path: str = "data/signatures.json", timeout: int = 10, accept_invalid_certs: bool = False,
                 offline: bool = False):
        """
        Initialize the web scanner.

        Args:
            db_manager: Instance of DatabaseManager for storing vulnerabilities.
            signatures_path: Path to the JSON file containing security signatures.
            timeout: Timeout in seconds for HTTP requests.
            accept_invalid_certs: When True, skip TLS certificate validation when
                fetching headers. When False (default), certificates are verified.
        """
        self.db = db_manager
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.signatures = self._load_signatures(signatures_path)
        self.accept_invalid_certs = accept_invalid_certs
        self.offline = offline
        self.session: Optional[aiohttp.ClientSession] = None
        # Track processed vulnerabilities to avoid duplicates
        self.processed_vulns: Set[Tuple[str, int, str]] = set()

    def _load_signatures(self, signatures_path: str) -> Dict[str, Any]:
        """
        Load security signatures from a JSON file.

        Args:
            signatures_path: Path to the JSON signature file.

        Returns:
            Dictionary containing signature definitions.
        """
        try:
            with open(_resolve_path(signatures_path), 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Signature file not found at {signatures_path}. Using empty signatures.")
            return {"headers": [], "ports": [], "ssl_errors": []}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse signature file: {e}")
            return {"headers": [], "ports": [], "ssl_errors": []}

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    def _get_ssl_context(self, verify: bool) -> ssl.SSLContext:
        """Build an SSL context, optionally with verification disabled."""
        context = ssl.create_default_context()
        if not verify:
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
        return context

    async def check_headers(self, host: str, port: int, is_https: bool) -> Tuple[List[Dict[str, str]], Optional[str]]:
        """
        Check HTTP headers for missing security controls.

        Args:
            host: Target hostname or IP.
            port: Target port.
            is_https: Whether to use HTTPS.

        Returns:
            A tuple of (header security findings, raw Server header value or None).
        """
        if not self.session:
            raise RuntimeError("WebScanner must be used as an async context manager.")

        scheme = "https" if is_https else "http"
        url = f"{scheme}://{host}:{port}"
        findings = []
        server_header: Optional[str] = None

        ssl_context = None
        if is_https:
            ssl_context = self._get_ssl_context(verify=not self.accept_invalid_certs)

        try:
            try:
                async with self.session.get(url, ssl=ssl_context, allow_redirects=True) as response:
                    headers = response.headers
            except ssl.SSLCertVerificationError as cert_err:
                # Certificate validation failed. Retry a header-only GET without
                # verification (no credentials are ever sent) so security headers can
                # still be reported; the certificate issue itself is reported
                # separately by check_ssl. Documented in README.
                logger.warning(f"Certificate verification failed for {url} ({cert_err}). "
                               "Retrying header probe without verification (no credentials sent).")
                insecure_context = self._get_ssl_context(verify=False)
                async with self.session.get(url, ssl=insecure_context, allow_redirects=True) as response:
                    headers = response.headers

            # Kept alongside the findings: the banner is CIRCL lookup input even
            # when the Server header itself is not a finding.
            server_header = headers.get("Server")

            # Check each security header from signatures
            for header_info in self.signatures.get("headers", []):
                header_name = header_info["name"]

                # HSTS is only meaningful on HTTPS responses
                if header_info.get("https_only", False) and not is_https:
                    continue

                # "absent" headers are findings when missing; "present" headers
                # (e.g. Server) are findings when disclosed.
                expectation = header_info.get("type", "absent")
                is_present = header_name in headers
                is_finding = is_present if expectation == "present" else not is_present
                if not is_finding:
                    continue

                finding_type = "present_header" if expectation == "present" else "missing_header"
                # Create a unique key for deduplication
                dedup_key = (host, port, f"{finding_type}_{header_name}")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    findings.append({
                        "type": finding_type,
                        "header": header_name,
                        "port": port,
                        "protocol": "https" if is_https else "http",
                        "severity": header_info["severity"],
                        "description": header_info["description"],
                        "remediation": header_info["remediation"],
                        "url": url
                    })
        except asyncio.TimeoutError:
            logger.warning(f"Timeout while checking headers for {url}")
        except Exception as e:
            logger.debug(f"Error checking headers for {url}: {e}")

        return findings, server_header

    @staticmethod
    def _classify_cert_error(error: ssl.SSLCertVerificationError) -> Optional[str]:
        """Map an SSL certificate verification error to a signature error type."""
        message = str(error).lower()
        if "has expired" in message or "expired" in message:
            return "expired_certificate"
        if "self-signed" in message:
            return "self_signed_certificate"
        if "mismatch" in message:
            return "hostname_mismatch"
        if "unable to get local issuer" in message or "unable to get issuer" in message or "not trusted" in message:
            return "untrusted_issuer"
        return None

    async def check_ssl(self, host: str, port: int) -> List[Dict[str, str]]:
        """
        Check SSL/TLS certificate validity and configuration using signatures.json.
        """
        findings = []

        # First attempt a verified connection to surface certificate errors.
        verify_context = ssl.create_default_context()
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=verify_context), timeout=self.timeout.total
            )
            writer.close()
            await writer.wait_closed()
            verified = True
        except ssl.SSLCertVerificationError as e:
            verified = False
            error_type = self._classify_cert_error(e)
            if error_type:
                self._add_ssl_finding(findings, host, port, error_type)
        except Exception:
            # The handshake never completed (refused, timeout, protocol error), so
            # the certificate was not verified. Proceed to the unverified probe so
            # certificate details can still be reported.
            verified = False

        # Grab certificate details with an unverified probe so expiration and
        # self-signed status can be reported even when validation fails.
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context), timeout=self.timeout.total
            )
            ssl_obj = writer.get_extra_info('sslobject')
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                if cert:
                    # Check expiration
                    not_after = cert.get('notAfter')
                    if not_after:
                        try:
                            expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            if expiry_date.tzinfo is None:
                                # cert notAfter is GMT; strptime %Z yields a naive value
                                expiry_date = expiry_date.replace(tzinfo=timezone.utc)
                            now = datetime.now(timezone.utc)
                            if expiry_date < now:
                                days_expired = (now - expiry_date).days
                                self._add_ssl_finding(findings, host, port, "expired_certificate", {"days": days_expired})
                        except ValueError:
                            pass

                    # Self-signed check
                    issuer = dict(x[0] for x in cert.get('issuer', []))
                    subject = dict(x[0] for x in cert.get('subject', []))
                    if issuer == subject:
                        self._add_ssl_finding(findings, host, port, "self_signed_certificate")

            writer.close()
            await writer.wait_closed()
        except Exception as e:
            logger.debug(f"SSL check failed for {host}:{port}: {e}")

        if not verified:
            logger.warning(f"TLS certificate validation failed for {host}:{port}")

        return findings

    def _add_ssl_finding(self, findings: List, host: str, port: int, error_type: str, extra: Dict = None):
        """Helper to add SSL finding from signatures."""
        dedup_key = (host, port, error_type)
        if dedup_key in self.processed_vulns:
            return

        sig = next((s for s in self.signatures.get("ssl_errors", []) if s["type"] == error_type), None)
        if not sig:
            return

        self.processed_vulns.add(dedup_key)
        description = sig["description"]
        if error_type == "expired_certificate" and extra:
            description = f"{description} (Expired {extra['days']} days ago)"

        findings.append({
            "type": "ssl_error",
            "detail": sig["title"],
            "severity": sig["severity"],
            "description": description,
            "remediation": sig["remediation"],
            "host": f"{host}:{port}",
            "port": port,
            "protocol": "https"
        })

    async def scan_host(self, host: str, ports: List[int], scan_id: int) -> None:
        """
        Scan a single host for web vulnerabilities on specified ports.

        Args:
            host: Target hostname or IP.
            ports: List of ports to scan (typically 80, 443, 8080, 8443).
            scan_id: The ID of the scan this host belongs to.
        """
        # First, we need to get the host_id from the database for this scan and IP
        # We assume the host has already been added by the network scanner.
        # Let's retrieve the host_id.
        cursor = await self.db.connection.execute(
            """
            SELECT id FROM hosts
            WHERE scan_id = ? AND ip_address = ?
            """,
            (scan_id, host)
        )
        row = await cursor.fetchone()
        if not row:
            logger.warning(f"Host {host} not found in database for scan {scan_id}. Skipping web scan.")
            return
        host_id = row[0]
        seen_cves: Set[str] = set()

        for port in ports:
            # Determine if we should use HTTPS based on common SSL ports
            is_https = port in [443, 8443]
            url = f"{'https' if is_https else 'http'}://{host}:{port}"

            try:
                # Check headers
                header_findings, server_header = await self.check_headers(host, port, is_https)
                # Check SSL/TLS (only for HTTPS ports)
                ssl_findings = []
                if is_https:
                    ssl_findings = await self.check_ssl(host, port)

                all_findings = header_findings + ssl_findings

                # Findings for this URL go in as one transaction under
                # DatabaseManager's write lock. The title decoration is done
                # here so the batch call stays a plain INSERT.
                vuln_rows = []
                for finding in all_findings:
                    # Determine if we have a title from the finding, otherwise generate one
                    title = finding.get("header", finding.get("type", "Web Vulnerability"))

                    # Add port/protocol info to the title for better context
                    protocol = "https" if is_https else "http"
                    port_info = f" on Port {port}/{protocol.upper()}"

                    # Only add port info if not already in the title
                    if f"Port {port}" not in title and f"port {port}" not in title.lower():
                        title = f"{title}{port_info}"

                    vuln_rows.append({
                        "title": title,
                        "severity": finding.get("severity", "Info"),
                        "description": finding.get("description", ""),
                        "remediation": finding.get("remediation", ""),
                        "port": finding.get("port"),
                        "protocol": finding.get("protocol"),
                    })

                await self.db.add_vulnerabilities_batch(host_id, vuln_rows)

                if all_findings:
                    logger.info(f"Found {len(all_findings)} web vulnerabilities on {url}")
                else:
                    logger.debug(f"No web vulnerabilities found on {url}")

                # Additional layer: online CVE enrichment from the Server header.
                # Failure here must never fail the scan.
                if server_header and scan_id and not self.offline:
                    try:
                        online = await lookup_with_cache(self.session, self.db, server_header)
                    except Exception as lookup_err:
                        logger.warning(f"Online CVE lookup skipped for {url}: {lookup_err}")
                        online = []
                    new_findings = [c for c in online if c["cve_id"] not in seen_cves]
                    if new_findings:
                        try:
                            await self.db.add_online_cves(host_id, new_findings)
                            seen_cves.update(c["cve_id"] for c in new_findings)
                        except Exception as db_err:
                            logger.error(f"Failed to store online CVEs for {url}: {db_err}")

            except Exception as e:
                logger.error(f"Error scanning {url}: {e}")

    async def scan_targets(self, targets: List[str], ports: List[int] = None, scan_id: int = None) -> None:
        """
        Scan the hosts stored for a scan for web vulnerabilities.

        Args:
            targets: Retained for API compatibility; no longer used for discovery.
            ports: List of ports to scan (default: [80, 443, 8080, 8443]).
            scan_id: The ID of the scan to associate results with.

        Raises:
            ValueError: If scan_id is None.
        """
        if scan_id is None:
            raise ValueError("scan_id is required for web scanning")

        if ports is None:
            ports = [80, 443, 8080, 8443]

        if not self.session:
            raise RuntimeError("WebScanner must be used as an async context manager.")

        hosts = await self.db.get_hosts(scan_id)
        if not hosts:
            logger.warning(f"No hosts stored for scan {scan_id}; nothing to web-scan.")
            return

        for row in hosts:
            await self.scan_host(row["ip_address"], ports, scan_id)

        logger.info("Web scanning completed.")

import aiohttp
import asyncio
import ssl
import json
from pathlib import Path
from typing import List, Dict, Any, Optional, Set, Tuple
import socket
from datetime import datetime

from utils.logger import logger
from core.database import DatabaseManager


class WebScanner:
    def __init__(self, db_manager: DatabaseManager, signatures_path: str = "config/signatures.json", timeout: int = 10):
        """
        Initialize the web scanner.

        Args:
            db_manager: Instance of DatabaseManager for storing vulnerabilities.
            signatures_path: Path to the JSON file containing security signatures.
            timeout: Timeout in seconds for HTTP requests.
        """
        self.db = db_manager
        self.timeout = aiohttp.ClientTimeout(total=timeout)
        self.signatures = self._load_signatures(signatures_path)
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
            with open(signatures_path, 'r') as f:
                return json.load(f)
        except FileNotFoundError:
            logger.warning(f"Signature file not found at {signatures_path}. Using empty signatures.")
            return {"headers": [], "ports": []}
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse signature file: {e}")
            return {"headers": [], "ports": []}

    async def __aenter__(self):
        """Async context manager entry."""
        self.session = aiohttp.ClientSession(timeout=self.timeout)
        return self

    async def __aexit__(self, exc_type, exc_val, exc_tb):
        """Async context manager exit."""
        if self.session:
            await self.session.close()

    async def check_headers(self, host: str, port: int, is_https: bool) -> List[Dict[str, str]]:
        """
        Check HTTP headers for missing security controls.

        Args:
            host: Target hostname or IP.
            port: Target port.
            is_https: Whether to use HTTPS.

        Returns:
            List of missing security headers with details.
        """
        if not self.session:
            raise RuntimeError("WebScanner must be used as an async context manager.")

        scheme = "https" if is_https else "http"
        url = f"{scheme}://{host}:{port}"
        findings = []

        try:
            async with self.session.get(url, ssl=False, allow_redirects=True) as response:
                headers = response.headers

                # Check each security header from signatures
                for header_info in self.signatures.get("headers", []):
                    header_name = header_info["name"]
                    if header_name not in headers:
                        # Create a unique key for deduplication
                        dedup_key = (host, port, f"missing_header_{header_name}")
                        if dedup_key not in self.processed_vulns:
                            self.processed_vulns.add(dedup_key)
                            findings.append({
                                "type": "missing_header",
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

        return findings

    async def check_ssl(self, host: str, port: int) -> List[Dict[str, str]]:
        """
        Check SSL/TLS certificate validity and configuration using signatures.json.
        """
        findings = []
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

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
                            # Parse expiration date
                            try:
                                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                            except ValueError:
                                expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z'.replace('  ', ' '))
                            
                            now = datetime.utcnow()
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

        for port in ports:
            # Determine if we should use HTTPS based on common SSL ports
            is_https = port in [443, 8443]
            url = f"{'https' if is_https else 'http'}://{host}:{port}"

            try:
                # Check headers
                header_findings = await self.check_headers(host, port, is_https)
                # Check SSL/TLS (only for HTTPS ports)
                ssl_findings = []
                if is_https:
                    ssl_findings = await self.check_ssl(host, port)

                all_findings = header_findings + ssl_findings

                for finding in all_findings:
                    # Determine if we have a title from the finding, otherwise generate one
                    title = finding.get("header", finding.get("type", "Web Vulnerability"))
                    description = finding.get("description", "")
                    remediation = finding.get("remediation", "")
                    severity = finding.get("severity", "Info")

                    # Add port/protocol info to the title for better context
                    protocol = "https" if is_https else "http"
                    port_info = f" on Port {port}/{protocol.upper()}"

                    # Only add port info if not already in the title
                    if f"Port {port}" not in title and f"port {port}" not in title.lower():
                        title = f"{title}{port_info}"

                    # Insert vulnerability into the database
                    await self.db.connection.execute(
                        """
                        INSERT INTO vulnerabilities (host_id, title, severity, description, remediation, port, protocol)
                        VALUES (?, ?, ?, ?, ?, ?, ?)
                        """,
                        (host_id, title, severity, description, remediation, finding.get("port"), finding.get("protocol"))
                    )
                await self.db.connection.commit()

                if all_findings:
                    logger.info(f"Found {len(all_findings)} web vulnerabilities on {url}")
                else:
                    logger.debug(f"No web vulnerabilities found on {url}")

            except Exception as e:
                logger.error(f"Error scanning {url}: {e}")
                await self.db.connection.rollback()

    async def scan_targets(self, targets: List[str], ports: List[int] = None, scan_id: int = None) -> None:
        """
        Scan a list of target hosts for web vulnerabilities.

        Args:
            targets: List of host IP addresses or hostnames.
            ports: List of ports to scan (default: [80, 443, 8080, 8443]).
            scan_id: The ID of the scan to associate results with.
        """
        if ports is None:
            ports = [80, 443, 8080, 8443]

        if not self.session:
            raise RuntimeError("WebScanner must be used as an async context manager.")

        for target in targets:
            await self.scan_host(target, ports, scan_id)

        logger.info("Web scanning completed.")
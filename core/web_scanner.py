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
        Check SSL/TLS certificate validity and configuration with specific error details.

        Args:
            host: Target hostname or IP.
            port: Target port (should be 443 or 8443 for HTTPS).

        Returns:
            List of SSL/TLS issues found with specific details.
        """
        findings = []
        try:
            # Create an SSL context that doesn't verify certificates (we want to inspect the cert)
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            # Establish a connection and get the peer certificate
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context), timeout=self.timeout.total
            )
            # Get the peer certificate
            ssl_obj = writer.get_extra_info('sslobject')
            if ssl_obj:
                cert = ssl_obj.getpeercert()
                # Check expiration
            not_after = cert.get('notAfter')
            if not_after:
                # Parse the date (format: 'Jan  1 12:00:00 2025 GMT' or 'Jan 1 12:00:00 2025 GMT')
                try:
                    # Try to parse with potential double space first
                    try:
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
                    except ValueError:
                        # Try with single space if double space fails
                        expiry_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z'.replace('  ', ' '))
                    now = datetime.utcnow()
                    if expiry_date < now:
                        days_expired = (now - expiry_date).days
                        dedup_key = (host, port, f"expired_cert_{days_expired}")
                        if dedup_key not in self.processed_vulns:
                            self.processed_vulns.add(dedup_key)
                            findings.append({
                                "type": "ssl_error",
                                "detail": f"SSL certificate expired {days_expired} days ago",
                                "severity": "High",
                                "description": f"SSL certificate has been expired for {days_expired} days.",
                                "remediation": "Renew the SSL certificate immediately.",
                                "host": f"{host}:{port}",
                                "port": port,
                                "protocol": "https"
                            })
                except ValueError:
                    # If we can't parse the date, skip this check
                    pass

                # Check if it's self-signed (simplified check)
                issuer = dict(x[0] for x in cert.get('issuer', []))
                subject = dict(x[0] for x in cert.get('subject', []))
                # Self-signed if issuer and subject are the same
                if issuer == subject:
                    dedup_key = (host, port, "self_signed_cert")
                    if dedup_key not in self.processed_vulns:
                        self.processed_vulns.add(dedup_key)
                        findings.append({
                            "type": "ssl_error",
                            "detail": "Self-signed SSL certificate",
                            "severity": "Medium",
                            "description": "The SSL certificate is self-signed, which is not trusted by browsers.",
                            "remediation": "Replace the self-signed certificate with one from a trusted Certificate Authority.",
                            "host": f"{host}:{port}",
                            "port": port,
                            "protocol": "https"
                        })

            writer.close()
            await writer.wait_closed()
        except ssl.SSLError as e:
            # Handle specific SSL errors
            error_msg = str(e).lower()
            if "certificate verify failed" in error_msg:
                dedup_key = (host, port, "cert_verification_failed")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    findings.append({
                        "type": "ssl_error",
                        "detail": "SSL certificate verification failed",
                        "severity": "Medium",
                        "description": "SSL certificate verification failed - possibly untrusted or expired certificate.",
                        "remediation": "Check the SSL certificate validity and ensure it's issued by a trusted CA.",
                        "host": f"{host}:{port}",
                        "port": port,
                        "protocol": "https"
                    })
            elif "tlsv1 alert unknown ca" in error_msg or "unknown ca" in error_msg:
                dedup_key = (host, port, "unknown_ca")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    findings.append({
                        "type": "ssl_error",
                        "detail": "Unknown Certificate Authority",
                        "severity": "Medium",
                        "description": "The SSL certificate is issued by an unknown or untrusted Certificate Authority.",
                        "remediation": "Install the proper intermediate certificates or use a certificate from a trusted CA.",
                        "host": f"{host}:{port}",
                        "port": port,
                        "protocol": "https"
                    })
            elif "certificate has expired" in error_msg:
                dedup_key = (host, port, "expired_cert")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    findings.append({
                        "type": "ssl_error",
                        "detail": "SSL certificate has expired",
                        "severity": "High",
                        "description": "The SSL certificate has expired and is no longer valid.",
                        "remediation": "Renew the SSL certificate immediately.",
                        "host": f"{host}:{port}",
                        "port": port,
                        "protocol": "https"
                    })
            elif "handshake failure" in error_msg:
                dedup_key = (host, port, "handshake_failure")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    findings.append({
                        "type": "ssl_error",
                        "detail": "SSL handshake failure",
                        "severity": "Medium",
                        "description": "SSL/TLS handshake failed - possibly due to protocol version or cipher suite mismatch.",
                        "remediation": "Ensure the server supports modern TLS versions and secure cipher suites.",
                        "host": f"{host}:{port}",
                        "port": port,
                        "protocol": "https"
                    })
            elif "decrypt error" in error_msg or "decryption failed" in error_msg:
                dedup_key = (host, port, "decrypt_error")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    findings.append({
                        "type": "ssl_error",
                        "detail": "SSL decryption error",
                        "severity": "Medium",
                        "description": "SSL/TLS decryption failed - possibly due to invalid encryption or corrupted data.",
                        "remediation": "Check the server's SSL/TLS configuration and encryption settings.",
                        "host": f"{host}:{port}",
                        "port": port,
                        "protocol": "https"
                    })
            elif "record too large" in error_msg:
                dedup_key = (host, port, "record_too_large")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    findings.append({
                        "type": "ssl_error",
                        "detail": "SSL record too large",
                        "severity": "Low",
                        "description": "Received an SSL/TLS record that was too large to process.",
                        "remediation": "Check for malfunctioning SSL/TLS implementation or network issues.",
                        "host": f"{host}:{port}",
                        "port": port,
                        "protocol": "https"
                    })
            else:
                # Generic SSL error
                dedup_key = (host, port, f"ssl_error_{hash(str(e))}")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    findings.append({
                        "type": "ssl_error",
                        "detail": f"SSL error: {str(e)}",
                        "severity": "Medium",
                        "description": "SSL/TLS connection failed or certificate is invalid.",
                        "remediation": "Ensure a valid SSL certificate is installed and the service is correctly configured.",
                        "host": f"{host}:{port}",
                        "port": port,
                        "protocol": "https"
                    })
        except Exception as e:
            # If we can't connect via SSL, that's a finding too
            error_msg = str(e).lower()
            # Ignore connection refused, timeout, and network unreachable errors as they are not SSL vulnerabilities
            if ("connection refused" in error_msg or "refused" in error_msg or
                "connection timed out" in error_msg or "timed out" in error_msg or
                "no route to host" in error_msg or "network is unreachable" in error_msg):
                # Don't report connection issues as SSL vulnerabilities
                pass
            elif "no route to host" in error_msg:
                # Don't report network unreachable as SSL vulnerabilities
                pass
            else:
                # Other connection issues might indicate SSL/TLS problems
                dedup_key = (host, port, f"ssl_conn_error_{hash(str(e))}")
                if dedup_key not in self.processed_vulns:
                    self.processed_vulns.add(dedup_key)
                    # Provide more specific messaging based on error type
                    if "connection reset" in error_msg or "connection reset by peer" in error_msg:
                        details = "Connection reset by peer during SSL/TLS handshake"
                        description = "The connection was reset during SSL/TLS handshake, possibly indicating SSL/TLS protocol issues."
                        remediation = "Check SSL/TLS configuration and ensure compatible protocols/ciphers are configured."
                        severity = "Medium"
                    elif "connection aborted" in error_msg:
                        details = "Connection aborted during SSL/TLS handshake"
                        description = "The connection was aborted during SSL/TLS handshake."
                        remediation = "Check server SSL/TLS configuration and connectivity."
                        severity = "Medium"
                    elif "broken pipe" in error_msg or "broken pipe" in error_msg:
                        details = "Broken pipe during SSL/TLS handshake"
                        description = "Broken pipe encountered during SSL/TLS handshake."
                        remediation = "The connection was terminated unexpectedly. Check if the service is properly configured for SSL/TLS."
                        severity = "Medium"
                    elif "timeout" in error_msg:
                        details = "SSL/TLS handshake timeout"
                        description = "SSL/TLS handshake timed out."
                        remediation = "Check server responsiveness and SSL/TLS configuration."
                        severity = "Low"
                    else:
                        details = f"SSL connection error: {str(e)}"
                        description = "SSL/TLS connection failed or certificate is invalid."
                        remediation = "Ensure a valid SSL certificate is installed and the service is correctly configured."
                        severity = "Medium"

                    findings.append({
                        "type": "ssl_error",
                        "detail": details,
                        "severity": severity,
                        "description": description,
                        "remediation": remediation,
                        "host": f"{host}:{port}",
                        "port": port,
                        "protocol": "https"
                    })
            logger.debug(f"SSL check failed for {host}:{port}: {e}")

        return findings

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
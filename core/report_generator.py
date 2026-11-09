import json
import sys
from pathlib import Path
from datetime import datetime, timezone
from typing import Dict, Any, List
from jinja2 import Environment, FileSystemLoader

from utils.logger import logger
from core.vuln_lookup import get_vulns_for_service

def resource_path(relative_path: str = "") -> Path:
    """Get absolute path to resource, works for dev and for PyInstaller"""
    if getattr(sys, 'frozen', False) and hasattr(sys, '_MEIPASS'):
        base_path = Path(sys._MEIPASS)
    else:
        # Resolve path relative to project root
        base_path = Path(__file__).parent.parent
    return base_path / relative_path


class HTMLReportGenerator:
    def __init__(self, db_manager, template_dir: str = "reporting/templates", reports_dir: str = "reports"):
        """
        Initialize the HTML report generator.
        """
        self.db = db_manager
        # Use resource_path to handle both development and PyInstaller bundles
        base_path = resource_path("")
        self.template_dir = base_path / template_dir
        self.reports_dir = Path(reports_dir)
        self.reports_dir.mkdir(parents=True, exist_ok=True)
        self.signatures = self._load_signatures("config/signatures.json")

        # Set up Jinja2 environment
        self.env = Environment(
            loader=FileSystemLoader(str(self.template_dir)),
            autoescape=True
        )

    def _load_signatures(self, signatures_path: str) -> Dict[str, Any]:
        """Load signatures."""
        try:
            path = resource_path(signatures_path)
            with open(path, 'r') as f:
                return json.load(f)
        except Exception as e:
            logger.error(f"Failed to load signatures: {e}")
            return {"headers": [], "ports": [], "ssl_errors": []}

    async def _get_scan_data(self, scan_id: int) -> dict:
        """
        Retrieve scan information from the database.

        Args:
            scan_id: The ID of the scan to retrieve.

        Returns:
            Dictionary containing scan details.
        """
        scan = await self.db.get_scan(scan_id)
        if not scan:
            raise ValueError(f"Scan with ID {scan_id} not found.")
        return scan

    async def _get_hosts_data(self, scan_id: int) -> list:
        """
        Retrieve host information for a given scan.

        Args:
            scan_id: The ID of the scan.

        Returns:
            List of dictionaries containing host details.
        """
        query = """
            SELECT h.id, h.ip_address, h.hostname, h.is_alive,
                   COUNT(p.id) as open_ports_count,
                   GROUP_CONCAT(p.port_number || '/' || p.protocol, ', ') as open_ports_list
            FROM hosts h
            LEFT JOIN ports p ON h.id = p.host_id
            WHERE h.scan_id = ?
            GROUP BY h.id, h.ip_address, h.hostname, h.is_alive
        """
        cursor = await self.db.connection.execute(query, (scan_id,))
        rows = await cursor.fetchall()
        return [
            {
                "id": row[0],
                "ip_address": row[1],
                "hostname": row[2],
                "is_alive": bool(row[3]),
                "open_ports_count": row[4],
                "open_ports_list": row[5] if row[5] else ""
            }
            for row in rows
        ]

    async def _get_vulnerabilities_data(self, scan_id: int) -> tuple:
        """
        Retrieve vulnerability information for a given scan.

        Args:
            scan_id: The ID of the scan.

        Returns:
            Tuple of (grouped_vulnerabilities_by_host, flat_vulnerabilities_list)
        """
        query = """
            SELECT v.title, v.severity, v.description, v.remediation, h.ip_address, v.port, v.protocol
            FROM vulnerabilities v
            JOIN hosts h ON v.host_id = h.id
            WHERE h.scan_id = ?
            ORDER BY CASE UPPER(v.severity)
                         WHEN 'CRITICAL' THEN 0
                         WHEN 'HIGH' THEN 1
                         WHEN 'MEDIUM' THEN 2
                         WHEN 'LOW' THEN 3
                         ELSE 4
                     END,
                     h.ip_address,
                     v.port
        """
        cursor = await self.db.connection.execute(query, (scan_id,))
        rows = await cursor.fetchall()

        # Group by host
        vulnerabilities_by_host = {}
        flat_vulnerabilities = []

        for row in rows:
            vuln_data = {
                "title": row[0],
                "severity": row[1],
                "description": row[2] or "No description provided.",
                "remediation": row[3] or "No remediation provided.",
                "ip_address": row[4],
                "port": row[5],
                "protocol": row[6]
            }
            flat_vulnerabilities.append(vuln_data)

            ip_address = row[4]
            if ip_address not in vulnerabilities_by_host:
                vulnerabilities_by_host[ip_address] = []
            vulnerabilities_by_host[ip_address].append(vuln_data)

        return vulnerabilities_by_host, flat_vulnerabilities

    async def _get_active_connections_data(self, scan_id: int) -> tuple:
        """
        Retrieve active network connections for a given scan and their collection status.
        """
        try:
            cursor = await self.db.connection.execute(
                "SELECT local_address, remote_address, remote_classification, pid, process_name, status, collection_status, timestamp FROM active_connections WHERE scan_id = ?",
                (scan_id,)
            )
            rows = await cursor.fetchall()
            connections = [
                {
                    "local_address": row[0],
                    "remote_address": row[1],
                    "remote_classification": row[2],
                    "pid": row[3],
                    "process_name": row[4],
                    "status": row[5],
                    # Stored observation time, not the report-generation time.
                    "timestamp": (row[7] if row[7] and row[7] != "N/A" else "N/A")
                }
                for row in rows if row[6] == "success"
            ]
            
            # Check if any failure/skip occurred
            collection_status = "success"
            if any(row[6] != "success" for row in rows):
                 collection_status = "failed"
            elif not rows:
                 collection_status = "no_data"
            
            return connections, collection_status
        except Exception as e:
            logger.error(f"Failed to retrieve active connections for scan {scan_id}: {e}")
            return [], "error"

    async def _get_online_cves_data(self, scan_id: int) -> list:
        """Retrieve OSINT CVE findings (CIRCL) for a scan; never fails the report."""
        try:
            return await self.db.get_online_cves(scan_id)
        except Exception as e:
            logger.error(f"Failed to retrieve online CVEs for scan {scan_id}: {e}")
            return []

    async def _get_derived_ports_data(self, scan_id: int) -> list:
        """
        Retrieve derived port rows (open-port scan results, not observed traffic).
        """
        try:
            return await self.db.get_derived_ports(scan_id)
        except Exception as e:
            logger.error(f"Failed to retrieve derived ports for scan {scan_id}: {e}")
            return []

    async def _prepare_template_data(self, scan_id: int) -> dict:
        """
        Prepare all data needed for the report template.

        Args:
            scan_id: The ID of the scan to generate a report for.

        Returns:
            Dictionary containing all data for the template.
        """
        # Get basic data
        scan_data = await self._get_scan_data(scan_id)
        hosts_data = await self._get_hosts_data(scan_id)
        vulnerabilities_by_host, flat_vulnerabilities = await self._get_vulnerabilities_data(scan_id)
        active_connections, conn_status = await self._get_active_connections_data(scan_id)
        derived_ports = await self._get_derived_ports_data(scan_id)
        online_cves = await self._get_online_cves_data(scan_id)
        port_data = await self.db.get_ports(scan_id)

        # 1. Populate Recommendations & CVE Findings First (CVE severities feed the counts)
        recommendations = []
        cve_findings = []
        for port_info in port_data:
            port = port_info['port']
            banner = port_info['banner']
            service = port_info['service_name']

            # CVE Lookup
            vulns = get_vulns_for_service(service, banner)
            for v in vulns:
                cve_findings.append({
                    "ip": port_info['ip_address'],
                    "service": f"{service} ({banner})",
                    "cve": v['cve'],
                    "severity": v['severity'],
                    "remediation": v['remediation']
                })

            # Check signatures for known port exposures
            for port_sig in self.signatures.get("ports", []):
                if port == port_sig["port"]:
                    recommendations.append({
                        "severity": port_sig["severity"],
                        "title": port_sig["title"],
                        "description": port_sig["description"]
                    })

        # Calculate summary statistics
        total_hosts = len(hosts_data)
        total_open_ports = sum(h['open_ports_count'] for h in hosts_data)
        # CVE findings count once per affected host/port match, matching the CVE table rows.
        total_vulnerabilities = len(flat_vulnerabilities) + len(cve_findings)

        # Calculate vulnerability breakdown by severity (web findings + CVE findings)
        vuln_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for vuln in flat_vulnerabilities + cve_findings:
            severity = (vuln.get("severity") or "INFO").strip().upper()
            if severity in vuln_counts:
                vuln_counts[severity] += 1
            else:
                # Default to INFO for unknown severities
                vuln_counts["INFO"] += 1

        # Calculate percentages for vulnerability breakdown chart
        vulnerability_breakdown = {}
        for severity, count in vuln_counts.items():
            if total_vulnerabilities > 0:
                percentage = round((count / total_vulnerabilities) * 100, 1)
            else:
                percentage = 0.0

            # Map severity to color
            color_map = {
                "CRITICAL": "#EF4444",
                "HIGH": "#F97316",
                "MEDIUM": "#F59E0B",
                "LOW": "#10B981",
                "INFO": "#0EA5E9"
            }

            vulnerability_breakdown[severity] = {
                "count": count,
                "percentage": percentage,
                "color": color_map.get(severity, "#6B7280")
            }

        # 2. Extract All Severities (Vulnerabilities + CVEs + Recommendations)
        all_severities = []
        for host_ip, vulns in vulnerabilities_by_host.items():
            for vuln in vulns:
                all_severities.append(vuln.get("severity", "LOW").upper())
        for cve in cve_findings:
            all_severities.append(cve.get("severity", "LOW").upper())
        for rec in recommendations:
            all_severities.append(rec.get("severity", "LOW").upper())

        # 3. Determine Highest Severity & Dynamic Risk Metrics
        
        # Weighted vulnerability scoring
        weights = {"CRITICAL": 15, "HIGH": 8, "MEDIUM": 4, "LOW": 1, "INFO": 0.5}
        total_score = 0
        for severity in all_severities:
            total_score += weights.get(severity.upper(), 0)
            
        # Calculate score (cap at 100)
        risk_score = min(int(total_score * 1.5), 100)
        risk_percentage = risk_score

        # Determine Grade and Level based on score
        if risk_score >= 80:
            risk_grade = "F"
            risk_level = "Critical"
        elif risk_score >= 60:
            risk_grade = "D"
            risk_level = "High"
        elif risk_score >= 40:
            risk_grade = "C"
            risk_level = "Medium"
        elif risk_score >= 20:
            risk_grade = "B"
            risk_level = "Low"
        else:
            risk_grade = "A"
            risk_level = "Low"

        # Calculate scan duration. Scan timestamps are stored as naive UTC ISO
        # strings, so attach UTC before subtracting instead of assuming local time.
        scan_duration = "N/A"
        if scan_data.get("start_time") and scan_data.get("end_time"):
            try:
                scan_start = datetime.fromisoformat(scan_data["start_time"].replace("Z", "+00:00"))
                if scan_start.tzinfo is None:
                    scan_start = scan_start.replace(tzinfo=timezone.utc)
                scan_end = datetime.fromisoformat(scan_data["end_time"].replace("Z", "+00:00"))
                if scan_end.tzinfo is None:
                    scan_end = scan_end.replace(tzinfo=timezone.utc)
                scan_duration_delta = (
                    scan_end.astimezone(timezone.utc) - scan_start.astimezone(timezone.utc)
                )

                # Format duration as HH:MM:SS or MM:SS
                total_seconds = int(scan_duration_delta.total_seconds())
                hours = total_seconds // 3600
                minutes = (total_seconds % 3600) // 60
                seconds = total_seconds % 60

                if hours > 0:
                    scan_duration = f"{hours:02d}:{minutes:02d}:{seconds:02d}"
                else:
                    scan_duration = f"{minutes:02d}:{seconds:02d}"
            except (TypeError, ValueError) as exc:
                logger.warning(f"Could not compute scan duration for scan {scan_id}: {exc}")

        # Prepare template data
        template_data = {
            "scan_id": scan_id,
            "target_range": scan_data["target_range"],
            "scan_date": scan_data["start_time"][:10] if scan_data["start_time"] else "Unknown",
            "total_hosts": total_hosts,
            "total_open_ports": total_open_ports,
            "total_vulnerabilities": total_vulnerabilities,
            "risk_level": risk_level,
            "risk_grade": risk_grade,
            "risk_score": risk_score,
            "risk_percentage": risk_percentage,  # For the gauge display (same value as risk_score)
            "vulnerability_breakdown": vulnerability_breakdown,
            "scan_duration": scan_duration,
            "hosts": hosts_data,
            "vulnerabilities_by_host": vulnerabilities_by_host,
            "active_connections": active_connections,
            "derived_ports": derived_ports,
            "connection_status": conn_status,
            "ports": port_data,
            "cve_findings": cve_findings,
            "online_cves": online_cves,
            # Reported as its own KPI: these are OSINT product/version matches and
            # must not silently inflate the offline-signature total or risk score.
            "online_cves_count": len(online_cves),
            "recommendations": recommendations,
            "report_generated_date": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "assessor": "SecAppliance Automated Scanner"
        }

        return template_data

    async def generate_report(self, scan_id: int) -> str:
        """
        Generate an HTML report for the specified scan ID.

        Args:
            scan_id: The ID of the scan to generate a report for.

        Returns:
            The file path of the generated HTML report.
        """
        try:
            # Prepare data for the template
            template_data = await self._prepare_template_data(scan_id)

            # Read CSS content for embedding (works both in dev and when frozen)
            css_path = resource_path("reporting/templates/style.css")
            with open(css_path, "r", encoding="utf-8") as f:
                css_content = f.read()

            # Add CSS content to template data
            template_data["css_content"] = css_content

            # Load and render the template
            template = self.env.get_template("executive_report.html")
            html_content = template.render(**template_data)

            # Define output file path
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            html_path = self.reports_dir / f"Report_{scan_id}_{timestamp}.html"

            with open(html_path, "w", encoding="utf-8") as f:
                f.write(html_content)
            logger.info(f"HTML report generated: {html_path}")
            return str(html_path)

        except Exception as e:
            logger.error(f"Failed to generate report for scan {scan_id}: {e}")
            raise
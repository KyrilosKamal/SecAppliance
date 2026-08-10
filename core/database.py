import aiosqlite
import logging
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime
import json

from utils.logger import logger

class DatabaseManager:
    """Async-compatible SQLite manager for SecAppliance."""

    def __init__(self, db_path: str = "data/secappliance.db"):
        """
        Initialize the database manager.

        Args:
            db_path: Path to the SQLite database file.
        """
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self.connection: Optional[aiosqlite.Connection] = None

    async def connect(self) -> None:
        """Establish a connection to the database."""
        try:
            self.connection = await aiosqlite.connect(self.db_path)
            # Enable foreign key constraints
            await self.connection.execute("PRAGMA foreign_keys = ON")
            await self.connection.commit()
            logger.info(f"Connected to database at {self.db_path}")
        except Exception as e:
            logger.error(f"Failed to connect to database: {e}")
            raise

    async def close(self) -> None:
        """Close the database connection."""
        if self.connection:
            await self.connection.close()
            logger.info("Database connection closed.")

    async def initialize_tables(self) -> None:
        """Create tables if they do not exist."""
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            # Create scans table
            await self.connection.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    target_range TEXT NOT NULL,
                    status TEXT NOT NULL,
                    start_time TEXT NOT NULL,
                    end_time TEXT
                )
            """)

            # Create hosts table
            await self.connection.execute("""
                CREATE TABLE IF NOT EXISTS hosts (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    ip_address TEXT NOT NULL,
                    is_alive BOOLEAN NOT NULL,
                    hostname TEXT,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                )
            """)

            # Create ports table with enhanced columns for service information
            await self.connection.execute("""
                CREATE TABLE IF NOT EXISTS ports (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    port_number INTEGER NOT NULL,
                    protocol TEXT NOT NULL,
                    service_name TEXT,
                    banner TEXT,
                    service_info TEXT,  -- JSON string with additional service info
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
                )
            """)

            # Create vulnerabilities table
            await self.connection.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    host_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    severity TEXT NOT NULL,
                    description TEXT,
                    remediation TEXT,
                    port INTEGER,
                    protocol TEXT,
                    FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
                )
            """)

            # Add columns if they don't exist (for migrations)
            try:
                await self.connection.execute("ALTER TABLE vulnerabilities ADD COLUMN port INTEGER")
            except Exception:
                pass  # Column likely already exists
            try:
                await self.connection.execute("ALTER TABLE vulnerabilities ADD COLUMN protocol TEXT")
            except Exception:
                pass

            # Create active_connections table for storing current network connections
            await self.connection.execute("""
                CREATE TABLE IF NOT EXISTS active_connections (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_id INTEGER NOT NULL,
                    local_address TEXT NOT NULL,
                    remote_address TEXT NOT NULL,
                    remote_classification TEXT NOT NULL,  -- LAN, WAN, etc.
                    pid INTEGER,
                    process_name TEXT,
                    status TEXT,
                    collection_status TEXT DEFAULT 'success',
                    timestamp TEXT NOT NULL,
                    FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                )
            """)

            await self.connection.commit()
            logger.info("Database tables initialized successfully.")
        except Exception as e:
            logger.error(f"Failed to initialize tables: {e}")
            raise

    async def create_scan(self, target_range: str) -> int:
        """
        Create a new scan record.

        Args:
            target_range: The target IP range (e.g., '192.168.1.0/24').

        Returns:
            The ID of the newly created scan.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            start_time = datetime.utcnow().isoformat()
            cursor = await self.connection.execute(
                """
                INSERT INTO scans (target_range, status, start_time)
                VALUES (?, ?, ?)
                """,
                (target_range, "running", start_time)
            )
            await self.connection.commit()
            scan_id = cursor.lastrowid
            logger.info(f"Created scan record with ID {scan_id} for target range {target_range}")
            return scan_id
        except Exception as e:
            logger.error(f"Failed to create scan: {e}")
            raise

    async def update_scan_status(self, scan_id: int, status: str, end_time: Optional[str] = None) -> None:
        """
        Update the status and end time of a scan.

        Args:
            scan_id: The ID of the scan to update.
            status: The new status (e.g., 'completed', 'failed').
            end_time: Optional end time (ISO format). If not provided, current UTC time is used.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            if end_time is None:
                end_time = datetime.utcnow().isoformat()
            await self.connection.execute(
                """
                UPDATE scans
                SET status = ?, end_time = ?
                WHERE id = ?
                """,
                (status, end_time, scan_id)
            )
            await self.connection.commit()
            logger.info(f"Updated scan {scan_id} status to {status} with end time {end_time}")
        except Exception as e:
            logger.error(f"Failed to update scan {scan_id}: {e}")
            raise

    async def get_scan(self, scan_id: int) -> Optional[Dict[str, Any]]:
        """
        Retrieve a scan by its ID.

        Args:
            scan_id: The ID of the scan to retrieve.

        Returns:
            A dictionary representing the scan, or None if not found.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                SELECT id, target_range, status, start_time, end_time
                FROM scans
                WHERE id = ?
                """,
                (scan_id,)
            )
            row = await cursor.fetchone()
            if row:
                return {
                    "id": row[0],
                    "target_range": row[1],
                    "status": row[2],
                    "start_time": row[3],
                    "end_time": row[4]
                }
            return None
        except Exception as e:
            logger.error(f"Failed to retrieve scan {scan_id}: {e}")
            raise

    async def get_scans(self, limit: int = 10) -> List[Dict[str, Any]]:
        """
        Retrieve a list of scans, ordered by start time descending.

        Args:
            limit: Maximum number of scans to return.

        Returns:
            A list of dictionaries representing scans.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                SELECT id, target_range, status, start_time, end_time
                FROM scans
                ORDER BY start_time DESC
                LIMIT ?
                """,
                (limit,)
            )
            rows = await cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "target_range": row[1],
                    "status": row[2],
                    "start_time": row[3],
                    "end_time": row[4]
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"Failed to retrieve scans: {e}")
            raise

    async def add_host(self, scan_id: int, ip_address: str, is_alive: bool, hostname: str = None) -> int:
        """
        Add a host to the database.

        Args:
            scan_id: The ID of the scan.
            ip_address: The IP address of the host.
            is_alive: Whether the host is alive.
            hostname: The hostname of the host (optional).

        Returns:
            The ID of the newly added host.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                INSERT INTO hosts (scan_id, ip_address, is_alive, hostname)
                VALUES (?, ?, ?, ?)
                """,
                (scan_id, ip_address, is_alive, hostname)
            )
            await self.connection.commit()
            host_id = cursor.lastrowid
            logger.debug(f"Added host {ip_address} with ID {host_id}")
            return host_id
        except Exception as e:
            logger.error(f"Failed to add host {ip_address}: {e}")
            raise

    async def add_port(self, host_id: int, port_number: int, protocol: str,
                       service_name: str = None, banner: str = None,
                       service_info: str = None) -> int:
        """
        Add a port to the database.

        Args:
            host_id: The ID of the host.
            port_number: The port number.
            protocol: The protocol (usually tcp).
            service_name: The service name (e.g., HTTP, SSH).
            banner: The banner grabbed from the port.
            service_info: JSON string with additional service information.

        Returns:
            The ID of the newly added port.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                INSERT INTO ports (host_id, port_number, protocol, service_name, banner, service_info)
                VALUES (?, ?, ?, ?, ?, ?)
                """,
                (host_id, port_number, protocol, service_name, banner, service_info)
            )
            await self.connection.commit()
            port_id = cursor.lastrowid
            logger.debug(f"Added port {port_number}/{protocol} for host {host_id} with ID {port_id}")
            return port_id
        except Exception as e:
            logger.error(f"Failed to add port {port_number}/{protocol} for host {host_id}: {e}")
            raise

    async def add_vulnerability(self, host_id: int, title: str, severity: str,
                                description: str = None, remediation: str = None,
                                port: int = None, protocol: str = None) -> int:
        """
        Add a vulnerability to the database.

        Args:
            host_id: The ID of the host.
            title: The title of the vulnerability.
            severity: The severity level (e.g., High, Medium, Low).
            description: Description of the vulnerability.
            remediation: Remediation steps.
            port: The port where the vulnerability was found.
            protocol: The protocol (tcp/udp).

        Returns:
            The ID of the newly added vulnerability.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                INSERT INTO vulnerabilities (host_id, title, severity, description, remediation, port, protocol)
                VALUES (?, ?, ?, ?, ?, ?, ?)
                """,
                (host_id, title, severity, description, remediation, port, protocol)
            )
            await self.connection.commit()
            vuln_id = cursor.lastrowid
            logger.debug(f"Added vulnerability '{title}' for host {host_id} with ID {vuln_id}")
            return vuln_id
        except Exception as e:
            logger.error(f"Failed to add vulnerability '{title}' for host {host_id}: {e}")
            raise

    async def add_active_connections(self, scan_id: int, connections: List[Dict[str, Any]], status: str = "success") -> None:
        """
        Add active connections to the database.

        Args:
            scan_id: The ID of the scan.
            connections: List of connection dictionaries.
            status: The collection status (success/failed/skipped).
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            timestamp = datetime.utcnow().isoformat()
            for conn in connections:
                await self.connection.execute(
                    """
                    INSERT INTO active_connections
                    (scan_id, local_address, remote_address, remote_classification, pid, process_name, status, timestamp, collection_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        scan_id,
                        conn.get("local_address"),
                        conn.get("remote_address"),
                        conn.get("remote_classification"),
                        conn.get("pid"),
                        conn.get("process_name"),
                        conn.get("status"),
                        timestamp,
                        status
                    )
                )
            
            # If no connections but status is not success (failed/skipped), store a record
            if not connections and status != "success":
                 await self.connection.execute(
                    """
                    INSERT INTO active_connections
                    (scan_id, local_address, remote_address, remote_classification, pid, process_name, status, timestamp, collection_status)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (scan_id, "N/A", "N/A", "N/A", 0, "N/A", "N/A", timestamp, status)
                )

            await self.connection.commit()
            logger.debug(f"Added {len(connections)} active connections for scan {scan_id} with status {status}")
        except Exception as e:
            logger.error(f"Failed to add active connections for scan {scan_id}: {e}")
            raise

    async def get_hosts(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve hosts for a specific scan.

        Args:
            scan_id: The ID of the scan.

        Returns:
            A list of dictionaries representing hosts.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                SELECT h.id, h.ip_address, h.hostname, h.is_alive,
                       COUNT(p.id) as open_ports_count,
                       GROUP_CONCAT(p.port_number || '/' || p.protocol, ', ') as open_ports_list
                FROM hosts h
                LEFT JOIN ports p ON h.id = p.host_id
                WHERE h.scan_id = ?
                GROUP BY h.id, h.ip_address, h.hostname, h.is_alive
                """,
                (scan_id,)
            )
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
        except Exception as e:
            logger.error(f"Failed to retrieve hosts for scan {scan_id}: {e}")
            raise

    async def get_vulnerabilities(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve vulnerabilities for a specific scan.

        Args:
            scan_id: The ID of the scan.

        Returns:
            A list of dictionaries representing vulnerabilities.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                SELECT v.id, v.title, v.severity, v.description, v.remediation,
                       v.port, v.protocol, h.ip_address
                FROM vulnerabilities v
                JOIN hosts h ON v.host_id = h.id
                WHERE h.scan_id = ?
                """,
                (scan_id,)
            )
            rows = await cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "title": row[1],
                    "severity": row[2],
                    "description": row[3] or "",
                    "remediation": row[4] or "",
                    "port": row[5],
                    "protocol": row[6],
                    "ip_address": row[7]
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"Failed to retrieve vulnerabilities for scan {scan_id}: {e}")
            raise

    async def get_ports(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve ports for a specific scan.

        Args:
            scan_id: The ID of the scan.

        Returns:
            A list of dictionaries representing ports.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                SELECT p.id, p.port_number, p.protocol, p.service_name, p.banner, p.service_info,
                       h.ip_address
                FROM ports p
                JOIN hosts h ON p.host_id = h.id
                WHERE h.scan_id = ?
                """,
                (scan_id,)
            )
            rows = await cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "port": row[1],
                    "protocol": row[2],
                    "service_name": row[3],
                    "banner": row[4],
                    "service_info": row[5],
                    "ip_address": row[6]
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"Failed to retrieve ports for scan {scan_id}: {e}")
            raise

    async def get_active_connections(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve active connections for a specific scan.

        Args:
            scan_id: The ID of the scan.

        Returns:
            A list of dictionaries representing active connections.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                SELECT id, local_address, remote_address, remote_classification,
                       pid, process_name, status, timestamp
                FROM active_connections
                WHERE scan_id = ?
                ORDER BY timestamp DESC
                """,
                (scan_id,)
            )
            rows = await cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "local_address": row[1],
                    "remote_address": row[2],
                    "remote_classification": row[3],
                    "pid": row[4],
                    "process_name": row[5],
                    "status": row[6],
                    "timestamp": row[7]
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"Failed to retrieve active connections for scan {scan_id}: {e}")
            raise
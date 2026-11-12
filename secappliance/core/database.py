import asyncio
import aiosqlite
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime, timedelta, timezone

from secappliance.utils.logger import logger

def _parse_timestamp(value: str) -> Optional[datetime]:
    """Parse a stored ISO timestamp; assume UTC when the value carries no zone."""
    try:
        parsed = datetime.fromisoformat(value)
    except (TypeError, ValueError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


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
        # Single connection => single transaction. Every write path must hold
        # this lock across execute+commit so one task's rollback cannot discard
        # another task's uncommitted rows.
        self._write_lock: asyncio.Lock = asyncio.Lock()

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

    @property
    def write_lock(self) -> asyncio.Lock:
        """Lock guarding the shared connection's write transaction.

        Callers that must wrap a raw execute/commit block (rather than a
        DatabaseManager method) take this lock themselves. Do not call
        commit()/rollback() while holding it: those helpers re-acquire it.
        """
        return self._write_lock

    async def commit(self) -> None:
        """Commit pending work on the shared connection, under the write lock."""
        async with self._write_lock:
            await self.connection.commit()

    async def rollback(self) -> None:
        """Roll back pending work on the shared connection, under the write lock."""
        async with self._write_lock:
            await self.connection.rollback()

    async def initialize_tables(self) -> None:
        """Create tables if they do not exist."""
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self._write_lock:
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

                # Derived port data (from open-port scan results), kept separate from
                # observed active connections so provenance is explicit in the schema.
                await self.connection.execute("""
                    CREATE TABLE IF NOT EXISTS derived_ports (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        scan_id INTEGER NOT NULL,
                        ip_address TEXT NOT NULL,
                        port INTEGER NOT NULL,
                        service_name TEXT,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (scan_id) REFERENCES scans (id) ON DELETE CASCADE
                    )
                """)

                # CVE enrichment cache: one row per unique banner key, refetched
                # lazily once the row is older than 7 days. Shared by scans
                # because a banner identifies a product/version, not a host.
                await self.connection.execute("""
                    CREATE TABLE IF NOT EXISTS cve_cache (
                        banner_key TEXT PRIMARY KEY,
                        results_json TEXT NOT NULL,
                        timestamp TEXT NOT NULL
                    )
                """)

                # Online CVE findings resolved against the CIRCL API. Separate
                # from `vulnerabilities` (offline signatures) so the two layers
                # stay distinguishable in reports.
                await self.connection.execute("""
                    CREATE TABLE IF NOT EXISTS online_cves (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        host_id INTEGER NOT NULL,
                        cve_id TEXT NOT NULL,
                        summary TEXT,
                        severity TEXT,
                        cvss_score REAL,
                        timestamp TEXT NOT NULL,
                        FOREIGN KEY (host_id) REFERENCES hosts (id) ON DELETE CASCADE
                    )
                """)
                await self.connection.execute(
                    "CREATE INDEX IF NOT EXISTS idx_online_cves_host_id ON online_cves(host_id)"
                )

                # Indexes for the lookup columns every report/host/port query filters
                # on. hosts gets a composite because web_scanner looks a host up by
                # (scan_id, ip_address); the leading scan_id column still serves the
                # scan_id-only queries, so no separate single-column index is needed.
                await self.connection.execute("""
                    CREATE INDEX IF NOT EXISTS idx_hosts_scan_ip ON hosts(scan_id, ip_address)
                """)
                await self.connection.execute("""
                    CREATE INDEX IF NOT EXISTS idx_ports_host_id ON ports(host_id)
                """)
                await self.connection.execute("""
                    CREATE INDEX IF NOT EXISTS idx_vulnerabilities_host_id ON vulnerabilities(host_id)
                """)
                await self.connection.execute("""
                    CREATE INDEX IF NOT EXISTS idx_active_connections_scan_id ON active_connections(scan_id)
                """)
                await self.connection.execute("""
                    CREATE INDEX IF NOT EXISTS idx_derived_ports_scan_id ON derived_ports(scan_id)
                """)

                await self.connection.commit()
                logger.info("Database tables initialized successfully.")
            except Exception as e:
                logger.error(f"Failed to initialize tables: {e}")
                await self.connection.rollback()
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

        async with self._write_lock:
            try:
                start_time = datetime.now(timezone.utc).isoformat()
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
                await self.connection.rollback()
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

        async with self._write_lock:
            try:
                if end_time is None:
                    end_time = datetime.now(timezone.utc).isoformat()
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
                await self.connection.rollback()
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

        async with self._write_lock:
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
                await self.connection.rollback()
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

        async with self._write_lock:
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
                await self.connection.rollback()
                raise

    async def add_host_with_ports(self, scan_id: int, ip_address: str, is_alive: bool,
                                  hostname: Optional[str],
                                  ports: List[Dict[str, Any]]) -> int:
        """
        Add a host and all of its open ports in a single transaction.

        Used by the network scanner so a host with many open ports costs one
        commit instead of one per port.

        Args:
            scan_id: The ID of the scan.
            ip_address: The IP address of the host.
            is_alive: Whether the host is alive.
            hostname: The hostname of the host.
            ports: Dictionaries with port_number, protocol, service_name,
                banner and service_info keys.

        Returns:
            The ID of the newly added host.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self._write_lock:
            try:
                cursor = await self.connection.execute(
                    """
                    INSERT INTO hosts (scan_id, ip_address, is_alive, hostname)
                    VALUES (?, ?, ?, ?)
                    """,
                    (scan_id, ip_address, is_alive, hostname)
                )
                host_id = cursor.lastrowid
                if ports:
                    await self.connection.executemany(
                        """
                        INSERT INTO ports (host_id, port_number, protocol, service_name, banner, service_info)
                        VALUES (?, ?, ?, ?, ?, ?)
                        """,
                        [
                            (
                                host_id,
                                row.get("port_number"),
                                row.get("protocol"),
                                row.get("service_name"),
                                row.get("banner"),
                                row.get("service_info"),
                            )
                            for row in ports
                        ]
                    )
                await self.connection.commit()
                logger.debug(f"Added host {ip_address} (ID {host_id}) with {len(ports)} ports")
                return host_id
            except Exception as e:
                logger.error(f"Failed to add host {ip_address} with its ports: {e}")
                await self.connection.rollback()
                raise

    async def add_vulnerabilities_batch(self, host_id: int,
                                        vulnerabilities: List[Dict[str, Any]]) -> int:
        """
        Add several vulnerabilities for one host in a single transaction.

        Args:
            host_id: The ID of the host the findings belong to.
            vulnerabilities: Dictionaries with title, severity, description,
                remediation, port and protocol keys.

        Returns:
            The number of rows inserted (0 for an empty list).
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self._write_lock:
            try:
                if not vulnerabilities:
                    return 0
                await self.connection.executemany(
                    """
                    INSERT INTO vulnerabilities (host_id, title, severity, description, remediation, port, protocol)
                    VALUES (?, ?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            host_id,
                            row.get("title"),
                            row.get("severity"),
                            row.get("description"),
                            row.get("remediation"),
                            row.get("port"),
                            row.get("protocol"),
                        )
                        for row in vulnerabilities
                    ]
                )
                await self.connection.commit()
                logger.debug(f"Added {len(vulnerabilities)} vulnerabilities for host {host_id}")
                return len(vulnerabilities)
            except Exception as e:
                logger.error(f"Failed to add vulnerabilities for host {host_id}: {e}")
                await self.connection.rollback()
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

        async with self._write_lock:
            try:
                timestamp = datetime.now(timezone.utc).isoformat()
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
                await self.connection.rollback()
                raise

    async def add_derived_ports(self, scan_id: int, rows: List[Dict[str, Any]]) -> None:
        """
        Add derived port rows (from open-port scan results) for a scan.

        These are not observed network connections; they are stored separately
        from active_connections so reports can label their provenance.

        Args:
            scan_id: The ID of the scan.
            rows: Dictionaries with ip_address, port and service_name keys.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        if not rows:
            return

        async with self._write_lock:
            try:
                timestamp = datetime.now(timezone.utc).isoformat()
                await self.connection.executemany(
                    """
                    INSERT INTO derived_ports (scan_id, ip_address, port, service_name, timestamp)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    [
                        (scan_id, row.get("ip_address"), row.get("port"),
                         row.get("service_name"), timestamp)
                        for row in rows
                    ]
                )
                await self.connection.commit()
                logger.debug(f"Added {len(rows)} derived ports for scan {scan_id}")
            except Exception as e:
                logger.error(f"Failed to add derived ports for scan {scan_id}: {e}")
                await self.connection.rollback()
                raise

    async def get_derived_ports(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve derived port rows for a specific scan.

        Args:
            scan_id: The ID of the scan.

        Returns:
            A list of dictionaries ordered by ip_address, then port.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                SELECT ip_address, port, service_name, timestamp
                FROM derived_ports
                WHERE scan_id = ?
                ORDER BY ip_address, port
                """,
                (scan_id,)
            )
            rows = await cursor.fetchall()
            return [
                {
                    "ip_address": row[0],
                    "port": row[1],
                    "service_name": row[2],
                    "timestamp": row[3]
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"Failed to retrieve derived ports for scan {scan_id}: {e}")
            raise

    async def get_cached_cves(self, banner_key: str) -> Optional[str]:
        """
        Return the cached CVE JSON for a banner key, or None if missing or stale.

        Args:
            banner_key: Normalised product/version key (see core.online_cve).

        Returns:
            The cached JSON string, or None when absent or older than 7 days.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                "SELECT results_json, timestamp FROM cve_cache WHERE banner_key = ?",
                (banner_key,)
            )
            row = await cursor.fetchone()
        except Exception as e:
            logger.error(f"Failed to read CVE cache for '{banner_key}': {e}")
            raise

        if not row:
            return None

        cached_at = _parse_timestamp(row[1])
        if cached_at is None:
            # Unreadable timestamp: treat the entry as stale rather than trusting it.
            logger.debug(f"Unparseable CVE cache timestamp for '{banner_key}': {row[1]!r}")
            return None
        if datetime.now(timezone.utc) - cached_at > timedelta(days=7):
            return None
        return row[0]

    async def cache_cves(self, banner_key: str, results_json: str) -> None:
        """
        Store or replace the CVE JSON for a banner key, stamped with the current time.

        Args:
            banner_key: Normalised product/version key (see core.online_cve).
            results_json: The JSON string to cache.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        async with self._write_lock:
            try:
                await self.connection.execute(
                    """
                    INSERT OR REPLACE INTO cve_cache (banner_key, results_json, timestamp)
                    VALUES (?, ?, ?)
                    """,
                    (banner_key, results_json, datetime.now(timezone.utc).isoformat())
                )
                await self.connection.commit()
                logger.debug(f"Cached CVE results for '{banner_key}'")
            except Exception as e:
                logger.error(f"Failed to cache CVE results for '{banner_key}': {e}")
                await self.connection.rollback()
                raise

    async def add_online_cves(self, host_id: int, cves: List[Dict[str, Any]]) -> None:
        """
        Store online CVE findings for one host in a single transaction.

        Args:
            host_id: The ID of the host the findings belong to.
            cves: Dictionaries with cve_id, summary, severity and cvss_score keys.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        if not cves:
            return

        timestamp = datetime.now(timezone.utc).isoformat()
        async with self._write_lock:
            try:
                await self.connection.executemany(
                    """
                    INSERT INTO online_cves
                    (host_id, cve_id, summary, severity, cvss_score, timestamp)
                    VALUES (?, ?, ?, ?, ?, ?)
                    """,
                    [
                        (
                            host_id,
                            row.get("cve_id"),
                            row.get("summary"),
                            row.get("severity"),
                            row.get("cvss_score"),
                            timestamp,
                        )
                        for row in cves
                    ]
                )
                await self.connection.commit()
                logger.debug(f"Added {len(cves)} online CVE findings for host {host_id}")
            except Exception as e:
                logger.error(f"Failed to add online CVE findings for host {host_id}: {e}")
                await self.connection.rollback()
                raise

    async def get_online_cves(self, scan_id: int) -> List[Dict[str, Any]]:
        """
        Retrieve online CVE findings for a scan, most severe first.

        Args:
            scan_id: The ID of the scan.

        Returns:
            Dictionaries with ip_address, cve_id, summary, severity and cvss_score.
        """
        if not self.connection:
            raise RuntimeError("Database not connected. Call connect() first.")

        try:
            cursor = await self.connection.execute(
                """
                SELECT h.ip_address, o.cve_id, o.summary, o.severity, o.cvss_score
                FROM online_cves o
                JOIN hosts h ON o.host_id = h.id
                WHERE h.scan_id = ?
                ORDER BY CASE UPPER(o.severity)
                             WHEN 'CRITICAL' THEN 0
                             WHEN 'HIGH' THEN 1
                             WHEN 'MEDIUM' THEN 2
                             WHEN 'LOW' THEN 3
                             ELSE 4
                         END,
                         h.ip_address,
                         o.cvss_score DESC
                """,
                (scan_id,)
            )
            rows = await cursor.fetchall()
            return [
                {
                    "ip_address": row[0],
                    "cve_id": row[1],
                    "summary": row[2] or "",
                    "severity": row[3] or "UNKNOWN",
                    "cvss_score": row[4] if row[4] is not None else 0.0,
                }
                for row in rows
            ]
        except Exception as e:
            logger.error(f"Failed to retrieve online CVEs for scan {scan_id}: {e}")
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
                ORDER BY CASE UPPER(v.severity)
                             WHEN 'CRITICAL' THEN 0
                             WHEN 'HIGH' THEN 1
                             WHEN 'MEDIUM' THEN 2
                             WHEN 'LOW' THEN 3
                             ELSE 4
                         END,
                         h.ip_address,
                         v.port
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
                ORDER BY p.port_number
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
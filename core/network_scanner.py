import json
import asyncio
import ipaddress
import socket
import psutil
from pathlib import Path
from typing import List, Optional, Tuple, Dict, Any
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn
import logging

from utils.logger import logger
from utils.net_utils import map_tcp_state, classify_ip
from core.database import DatabaseManager


class NetworkScanner:
    def __init__(self, db_manager: DatabaseManager, max_concurrent: int = 200, timeout: float = 3.0, verbose: bool = False):
        """
        Initialize the network scanner.
        """
        self.db = db_manager
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.verbose = verbose
        self.semaphore = asyncio.Semaphore(max_concurrent)

        # Common ports to scan with associated service names for banner grabbing hints
        self.common_ports = {
            21: "FTP",
            22: "SSH",
            23: "Telnet",
            25: "SMTP",
            53: "DNS",
            80: "HTTP",
            110: "POP3",
            111: "RPC",
            135: "MSRPC",
            139: "NetBIOS",
            143: "IMAP",
            443: "HTTPS",
            445: "SMB",
            993: "IMAPS",
            995: "POP3S",
            1433: "MSSQL",
            3306: "MySQL",
            3389: "RDP",
            5900: "VNC",
            8080: "HTTP-Proxy",
            8443: "HTTPS-Alt",
        }

        # Well-known service names for ports (for fallback identification)
        self.well_known_services = {
            20: "FTP-DATA", 21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP",
            53: "DNS", 67: "DHCP", 68: "DHCP", 80: "HTTP", 110: "POP3",
            111: "RPC", 123: "NTP", 135: "MSRPC", 139: "NetBIOS", 143: "IMAP",
            161: "SNMP", 162: "SNMPTRAP", 179: "BGP", 389: "LDAP", 443: "HTTPS",
            445: "SMB", 465: "SMTPS", 514: "SYSLOG", 587: "SMTP", 636: "LDAPS",
            993: "IMAPS", 995: "POP3S", 1080: "SOCKS", 1194: "OpenVPN",
            1433: "MSSQL", 1521: "Oracle", 1723: "PPTP", 2049: "NFS",
            3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
            8080: "HTTP-Proxy", 8443: "HTTPS-Alt"
        }

    async def scan_port(self, ip: str, port: int) -> Optional[Tuple[int, str, str, Dict[str, Any]]]:
        """
        Scan a single TCP port on a given IP address.

        Returns:
            Tuple of (port_number, protocol, banner, service_info) if open, None otherwise.
        """
        async with self.semaphore:
            try:
                # Attempt to open a TCP connection
                reader, writer = await asyncio.wait_for(
                    asyncio.open_connection(ip, port), timeout=self.timeout
                )

                # Try to grab a banner (read up to 1024 bytes)
                banner = ""
                service_info = {}
                try:
                    # Set a short timeout for banner grabbing
                    banner_data = await asyncio.wait_for(reader.read(1024), timeout=2.0)
                    banner = banner_data.decode('utf-8', errors='ignore').strip()

                    # Parse basic service info from banner if possible
                    if banner:
                        service_info["banner"] = banner
                        # Try to extract version info
                        if "SSH" in banner.upper():
                            service_info["service"] = "SSH"
                        elif "HTTP" in banner.upper():
                            service_info["service"] = "HTTP"
                        elif "SMTP" in banner.upper() or "ESMTP" in banner.upper():
                            service_info["service"] = "SMTP"
                        elif "FTP" in banner.upper():
                            service_info["service"] = "FTP"
                except asyncio.TimeoutError:
                    # No banner or timeout during banner grab is fine
                    pass
                except Exception as e:
                    logger.debug(f"Banner grab error on {ip}:{port} - {e}")

                # Close the connection
                writer.close()
                try:
                    await writer.wait_closed()
                except Exception:
                    pass

                # Determine service name from our map, banner, or leave as unknown
                service_name = self.well_known_services.get(port, "unknown")
                if service_info.get("service"):
                    service_name = service_info["service"]
                elif port in self.common_ports:
                    service_name = self.common_ports[port]

                service_info.update({
                    "port": port,
                    "protocol": "tcp",
                    "service_name": service_name,
                    "banner": banner or service_name
                })

                return port, "tcp", banner or service_name, service_info

            except (ConnectionRefusedError, TimeoutError, OSError):
                # Port is closed or unreachable
                return None
            except Exception as e:
                logger.debug(f"Unexpected error scanning {ip}:{port} - {e}")
                return None

    def get_active_connections(self, scan_id: int = None) -> List[Dict[str, Any]]:
        """
        Get active network connections on the local host.
        Fallback: If no active sockets are found, maps all open ports detected in the scan.

        Returns:
            List of dictionaries containing connection information.
        """
        connections = []
        try:
            # Get all network connections
            net_connections = psutil.net_connections(kind='inet')

            for conn in net_connections:
                # Removed: Only consider established TCP connections
                # if conn.status == 'ESTABLISHED' and conn.type == socket.SOCK_STREAM:
                
                local_addr = f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else "N/A"
                remote_addr = f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else "N/A"

                # Classify remote address as LAN or WAN
                remote_classification = "N/A"
                if conn.raddr:
                    remote_classification = classify_ip(conn.raddr.ip)

                # Get process information
                pid = conn.pid
                process_name = "Unknown"
                if pid:
                    try:
                        process = psutil.Process(pid)
                        process_name = process.name()
                    except (psutil.NoSuchProcess, psutil.AccessDenied):
                        process_name = "Access Denied"

                connections.append({
                    "local_address": local_addr,
                    "remote_address": remote_addr,
                    "remote_classification": remote_classification,
                    "pid": pid,
                    "process_name": process_name,
                    "status": map_tcp_state(conn.status)
                })
        except Exception as e:
            logger.error(f"Error getting active connections: {e}")

        # Fallback Logic: If no active sockets, map open ports
        if not connections and scan_id:
            logger.info("No active sockets detected, falling back to open port mapping.")
            # We would need access to the db to get open ports here, 
            # or handle this mapping after scanning finishes.
            # Simplified approach: return an empty list and rely on the database layer 
            # to handle the fallback if 'status' is 'success' but connections list is empty
            pass

        return connections

    async def collect_and_store_active_connections(self, scan_id: int, target: str, credentials: Optional[Dict[str, str]] = None) -> None:
        """
        Collect active network connections and store them in the database.
        """
        try:
            connections = []
            status = "success"
            
            # Helper to check if target is local
            def is_local(t):
                return t in ["127.0.0.1", "localhost", "::1"] or t == socket.gethostname()

            if credentials:
                # Attempt remote collection
                try:
                    from core.remote_collector import RemoteCollector
                    collector = RemoteCollector()
                    connections = collector.collect_connections(
                        target, 
                        credentials["username"], 
                        credentials["password"], 
                        credentials["auth_type"]
                    )
                    if not connections:
                        # Fallback if empty and local
                        if is_local(target):
                            logger.info("[Local Fallback] WinRM unavailable/bypassed. Retrieving active sockets directly via psutil.")
                            connections = self.get_active_connections(scan_id)
                        else:
                            status = "failed"
                except Exception as e:
                    # Fallback on remote failure if local
                    if is_local(target):
                        logger.info(f"[Local Fallback] WinRM error ({e}). Retrieving active sockets directly via psutil.")
                        connections = self.get_active_connections(scan_id)
                    else:
                        status = "failed"
            else:
                # Unauthenticated: Only collect if target is local
                if is_local(target):
                    connections = self.get_active_connections(scan_id)
                else:
                    status = "skipped"
            
            # Dynamic Open Port Fallback mapping if no active connections were found
            if not connections:
                logger.info(f"No active network connections captured. Initiating dynamic fallback mapping for open ports.")
                try:
                    open_ports = await self.db.get_ports(scan_id)
                    for port_info in open_ports:
                        connections.append({
                            "local_address": f"{port_info['ip_address']}:{port_info['port']}",
                            "remote_address": "0.0.0.0:*",
                            "remote_classification": "LAN",
                            "pid": 0,
                            "process_name": f"Listening Service ({port_info['service_name']})",
                            "status": "LISTEN"
                        })
                except Exception as db_err:
                    logger.error(f"Failed to query database for open port fallback: {db_err}")

            await self.db.add_active_connections(scan_id, connections, status)
            logger.info(f"Collected {len(connections)} connections for scan {scan_id} (Status: {status})")
        except Exception as e:
            logger.error(f"Failed to collect and store active connections for scan {scan_id}: {e}")
            raise
    async def scan_host(self, ip: str, scan_id: int, ports: List[int] = None) -> None:
        """
        Scan a single host for open ports and common services, and store results in the database.

        Args:
            ip: The IP address to scan.
            scan_id: The ID of the scan this host belongs to.
            ports: List of ports to scan (if None, use common_ports).
        """
        if ports is None:
            ports = list(self.common_ports.keys())

        logger.info(f"Scanning host: {ip} on {len(ports)} ports")
        tasks = []
        for port in ports:
            task = asyncio.create_task(self.scan_port(ip, port))
            tasks.append(task)

        # Wait for all port scan tasks to complete
        try:
            results = await asyncio.gather(*tasks, return_exceptions=True)
        except KeyboardInterrupt:
            # Cancel all tasks
            for task in tasks:
                task.cancel()
            raise

        # Process results
        open_ports = []
        for result in results:
            if isinstance(result, Exception):
                logger.debug(f"Error during port scan: {result}")
                continue
            if result is not None:
                port, protocol, banner, service_info = result
                open_ports.append((port, protocol, banner, service_info))
                logger.debug(f"Open port found: {ip}:{port} ({protocol}) - Banner: {banner[:50] if banner else 'None'}")

        # If we found any open ports, consider the host alive
        is_alive = len(open_ports) > 0

        # Try to get hostname via reverse DNS (optional, can be slow)
        try:
            hostname = socket.gethostbyaddr(ip)[0]
            # If the hostname is "Anonymous", treat it as failure and fall back to IP
            if hostname == "Anonymous":
                raise socket.herror
        except (socket.herror, socket.gaierror):
            # Fallback to IP address
            hostname = ip

        # Store host information in the database
        try:
            host_id = await self.db.add_host(scan_id, ip, is_alive, hostname)

            # Store each open port
            for port, protocol, banner, service_info in open_ports:
                import json  # Ensure json is available in this scope for PyInstaller
                await self.db.add_port(
                    host_id,
                    port,
                    protocol,
                    service_info.get("service_name", "unknown"),
                    banner,
                    json.dumps(service_info) if service_info else None
                )
            await self.db.connection.commit()
            logger.info(f"Host {ip} stored with {len(open_ports)} open ports.")
        except Exception as e:
            logger.error(f"Failed to store host {ip} in database: {e}")
            await self.db.connection.rollback()

    async def scan_targets(self, targets: List[str], scan_id: int, ports: List[int] = None, credentials: Optional[Dict[str, str]] = None) -> None:
        """
        Scan a list of target IP addresses or CIDR ranges.
        """
        if ports is None:
            ports = list(self.common_ports.keys())

        # Expand CIDR ranges
        ips_to_scan = set()
        for target in targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
                ips_to_scan.update(str(ip) for ip in network.hosts())
            except ValueError:
                ips_to_scan.add(target)

        # Create tasks
        tasks = []
        for ip in ips_to_scan:
            tasks.append(self.scan_host(ip, scan_id, ports))
            # Also collect connections if credentials provided OR if target is local
            def is_local(t):
                return t in ["127.0.0.1", "localhost", "::1"] or t == socket.gethostname()
            if credentials or is_local(ip):
                tasks.append(self.collect_and_store_active_connections(scan_id, ip, credentials))

        # Wait for all tasks to complete concurrently with progress bar
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            transient=True,
        ) as progress:
            task_id = progress.add_task(description="Scanning network...", total=len(tasks))

            # Using semaphore to limit concurrency
            async def run_task(t):
                res = await t
                progress.update(task_id, advance=1)
                return res

            await asyncio.gather(*[run_task(t) for t in tasks], return_exceptions=True)

        logger.info("Network scanning and connection collection completed.")
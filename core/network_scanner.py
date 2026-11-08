import json
import asyncio
import ipaddress
import itertools
import socket
import psutil
from typing import List, Optional, Tuple, Dict, Any, Iterator
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TaskProgressColumn

from utils.logger import logger
from utils.net_utils import map_tcp_state, classify_ip
from core.database import DatabaseManager


_LOCAL_NAMES = frozenset({"127.0.0.1", "localhost", "::1"})


def is_local_target(target: str, hostname: str) -> bool:
    """Return True if the target is a loopback name or the given hostname."""
    return target in _LOCAL_NAMES or target == hostname


async def is_local(target: str) -> bool:
    """Return True if the target refers to the local host.

    socket.gethostname() is a blocking syscall, so it runs off the event loop.
    Callers that already know the hostname should use is_local_target().
    """
    if target in _LOCAL_NAMES:
        return True
    return is_local_target(target, await asyncio.to_thread(socket.gethostname))


class NetworkScanner:
    def __init__(self, db_manager: DatabaseManager, max_concurrent: int = 200, timeout: float = 3.0, verbose: bool = False,
                 accept_unknown_hosts: bool = False, accept_invalid_certs: bool = False, force: bool = False,
                 allow_insecure_winrm_http: bool = False):
        """
        Initialize the network scanner.

        Args:
            db_manager: DatabaseManager instance.
            max_concurrent: Maximum number of concurrent port scans.
            timeout: Connection timeout in seconds.
            verbose: Enable debug logging.
            accept_unknown_hosts: Passed to RemoteCollector (SSH host key verification).
            accept_invalid_certs: Passed to RemoteCollector (WinRM cert validation).
            force: Allow scanning CIDR ranges larger than /16.
            allow_insecure_winrm_http: Passed to RemoteCollector (allow plaintext HTTP WinRM).
        """
        self.db = db_manager
        self.max_concurrent = max_concurrent
        self.timeout = timeout
        self.verbose = verbose
        self.semaphore = asyncio.Semaphore(max_concurrent)
        self.accept_unknown_hosts = accept_unknown_hosts
        self.accept_invalid_certs = accept_invalid_certs
        self.force = force
        self.allow_insecure_winrm_http = allow_insecure_winrm_http

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

    async def get_active_connections(self, scan_id: int = None) -> List[Dict[str, Any]]:
        """
        Get active network connections on the local host.

        psutil.net_connections() and Process().name() are blocking, so the whole
        collection runs in a worker thread. Callers stay on the event loop and
        must await this; the DB write happens after it returns.

        Args:
            scan_id: Unused; kept for interface compatibility.

        Returns:
            List of dictionaries containing connection information.
        """
        return await asyncio.to_thread(self._get_active_connections_sync, scan_id)

    def _get_active_connections_sync(self, scan_id: int = None) -> List[Dict[str, Any]]:
        """Blocking body of get_active_connections; must run off the event loop."""
        connections = []
        try:
            # Get all network connections
            net_connections = psutil.net_connections(kind='inet')

            for conn in net_connections:
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

        return connections

    async def collect_and_store_active_connections(self, scan_id: int, target: str, credentials: Optional[Dict[str, str]] = None) -> None:
        """
        Collect active network connections and store them in the database.
        """
        try:
            connections = []
            status = "success"

            if credentials:
                # Attempt remote collection
                try:
                    from core.remote_collector import RemoteCollector
                    collector = RemoteCollector(
                        accept_unknown_hosts=self.accept_unknown_hosts,
                        accept_invalid_certs=self.accept_invalid_certs,
                        allow_insecure_winrm_http=self.allow_insecure_winrm_http,
                    )
                    # paramiko / pywinrm are blocking; run the collector off the
                    # event loop so the progress bar and parallel hosts are not
                    # frozen for the whole SSH/WinRM round trip.
                    connections = await asyncio.to_thread(
                        collector.collect_connections,
                        target,
                        credentials["username"],
                        credentials["password"],
                        credentials["auth_type"]
                    )
                    if not connections:
                        # Fallback if empty and local
                        if await is_local(target):
                            logger.info("[Local Fallback] WinRM unavailable/bypassed. Retrieving active sockets directly via psutil.")
                            connections = await self.get_active_connections(scan_id)
                        else:
                            status = "failed"
                except Exception as e:
                    # Fallback on remote failure if local
                    if await is_local(target):
                        logger.info(f"[Local Fallback] WinRM error ({e}). Retrieving active sockets directly via psutil.")
                        connections = await self.get_active_connections(scan_id)
                    else:
                        status = "failed"
            else:
                # Unauthenticated: Only collect if target is local
                if await is_local(target):
                    connections = await self.get_active_connections(scan_id)
                else:
                    status = "skipped"

            # No observed connections: store open ports as derived data in their
            # own table so the report never presents them as observed traffic.
            if not connections:
                logger.info(f"No active network connections captured. Recording derived port data for open ports.")
                try:
                    open_ports = await self.db.get_ports(scan_id)
                    derived_rows = [
                        {
                            "ip_address": port_info["ip_address"],
                            "port": port_info["port"],
                            "service_name": port_info["service_name"]
                        }
                        for port_info in open_ports
                    ]
                    await self.db.add_derived_ports(scan_id, derived_rows)
                except Exception as db_err:
                    logger.error(f"Failed to store derived port data: {db_err}")

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

        # Wait for all port scan tasks to complete
        try:
            results = await asyncio.gather(
                *(self.scan_port(ip, port) for port in ports),
                return_exceptions=True
            )
        except KeyboardInterrupt:
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

        # Try to get hostname via reverse DNS (optional, can be slow).
        # Run in a thread to avoid blocking the event loop.
        try:
            hostname = await asyncio.to_thread(socket.gethostbyaddr, ip)
            hostname = hostname[0]
            # If the hostname is "Anonymous", treat it as failure and fall back to IP
            if hostname == "Anonymous":
                raise socket.herror
        except (socket.herror, socket.gaierror):
            # Fallback to IP address
            hostname = ip

        # Store host information in the database. The host row and all of its
        # ports go in as one transaction under DatabaseManager's write lock, so
        # a host with many open ports costs one commit instead of one per port.
        try:
            ports_list = [
                {
                    "port_number": port,
                    "protocol": protocol,
                    "service_name": service_info.get("service_name", "unknown"),
                    "banner": banner,
                    "service_info": json.dumps(service_info) if service_info else None,
                }
                for port, protocol, banner, service_info in open_ports
            ]
            await self.db.add_host_with_ports(scan_id, ip, is_alive, hostname, ports_list)
            logger.info(f"Host {ip} stored with {len(open_ports)} open ports.")
        except Exception as e:
            logger.error(f"Failed to store host {ip} in database: {e}")

    def _validate_target_sizes(self, targets: List[str]) -> None:
        """Reject CIDR ranges larger than /16 unless force is enabled."""
        if self.force:
            return
        for target in targets:
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError:
                continue
            if network.prefixlen >= 16:
                continue
            total = network.num_addresses
            if network.version == 4:
                host_count = total - 2 if network.prefixlen <= 30 else total
            else:
                host_count = total - 1 if network.prefixlen <= 126 else total
            raise ValueError(
                f"Target '{target}' is a /{network.prefixlen} range with {host_count} addresses, "
                f"which exceeds the /16 limit. Pass --force to scan ranges larger than /16."
            )

    def _iter_hosts(self, targets: List[str]) -> Iterator[str]:
        """Yield hosts lazily without materializing the full expansion.

        Targets are deduplicated by string only, so overlapping CIDR ranges may
        still yield the same host more than once.
        """
        seen_targets = set()
        for target in targets:
            if target in seen_targets:
                continue
            seen_targets.add(target)
            try:
                network = ipaddress.ip_network(target, strict=False)
            except ValueError:
                yield target
                continue
            for ip in network.hosts():
                yield str(ip)

    def _iter_work_items(self, targets: List[str], scan_id: int, ports: List[int],
                         credentials: Optional[Dict[str, str]] = None,
                         local_hostname: str = "") -> Iterator[Tuple[Any, Tuple[Any, ...]]]:
        """Yield (callable, args) work items lazily over the target expansion.

        This is a sync generator, so it cannot await the hostname lookup; the
        caller resolves local_hostname once, off the event loop, and passes it in.
        """
        for ip in self._iter_hosts(targets):
            yield (self.scan_host, (ip, scan_id, ports))
            # Also collect connections if credentials provided OR if target is local
            if credentials or is_local_target(ip, local_hostname):
                yield (self.collect_and_store_active_connections, (scan_id, ip, credentials))

    async def scan_targets(self, targets: List[str], scan_id: int, ports: List[int] = None, credentials: Optional[Dict[str, str]] = None) -> None:
        """
        Scan a list of target IP addresses or CIDR ranges.
        """
        if ports is None:
            ports = list(self.common_ports.keys())

        self._validate_target_sizes(targets)

        # Resolve the local hostname once, off the event loop, instead of once
        # per host inside the sync work-item generator.
        local_hostname = await asyncio.to_thread(socket.gethostname)

        # Work items are generated lazily so large target ranges do not
        # exhaust memory.
        work_items = self._iter_work_items(targets, scan_id, ports, credentials, local_hostname)

        # Wait for all tasks to complete concurrently with progress bar,
        # processing in bounded batches.
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TaskProgressColumn(),
            transient=True,
        ) as progress:
            task_id = progress.add_task(description="Scanning network...", total=None)

            batch_size = max(self.max_concurrent, 1)
            while True:
                batch = list(itertools.islice(work_items, batch_size))
                if not batch:
                    break

                async def run_batch(batch):
                    tasks = [asyncio.create_task(fn(*args)) for fn, args in batch]
                    await asyncio.gather(*tasks, return_exceptions=True)

                await run_batch(batch)
                progress.update(task_id, advance=len(batch))

        logger.info("Network scanning and connection collection completed.")

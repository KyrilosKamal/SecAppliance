import os
import paramiko
import winrm
import json
from typing import List, Dict, Any, Optional

from utils.logger import logger
from utils.net_utils import map_tcp_state, classify_ip


class RemoteCollector:
    def __init__(self, accept_unknown_hosts: bool = False, accept_invalid_certs: bool = False):
        """
        Initialize the remote collector.

        Args:
            accept_unknown_hosts: When True, automatically accept unknown SSH host keys.
                When False (default), host keys are verified against known_hosts.
            accept_invalid_certs: When True, skip WinRM TLS certificate validation.
                When False (default), certificates are validated.
        """
        self.accept_unknown_hosts = accept_unknown_hosts
        self.accept_invalid_certs = accept_invalid_certs

    def collect_connections(self, target_ip: str, username: str, password: str, auth_type: str = 'ssh') -> List[Dict[str, Any]]:
        """
        Collect active network connections from a remote host.
        """
        if auth_type == 'ssh':
            return self._collect_ssh(target_ip, username, password)
        elif auth_type == 'winrm':
            return self._collect_winrm(target_ip, username, password)
        else:
            logger.error(f"Unsupported auth type: {auth_type}")
            return []

    def _collect_ssh(self, target_ip: str, username: str, password: str) -> List[Dict[str, Any]]:
        """Collect via SSH using paramiko."""
        connections = []
        try:
            ssh = paramiko.SSHClient()
            if self.accept_unknown_hosts:
                ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            else:
                # Verify host keys against known_hosts to prevent MITM attacks.
                ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
                ssh.load_system_host_keys()
                known_hosts = os.path.expanduser("~/.ssh/known_hosts")
                if os.path.exists(known_hosts):
                    try:
                        ssh.load_host_keys(known_hosts)
                    except (OSError, paramiko.SSHException) as e:
                        logger.warning(f"Failed to load known_hosts from {known_hosts}: {e}")
            ssh.connect(target_ip, username=username, password=password, timeout=10)

            # Use 'ss' if available, otherwise 'netstat'
            stdin, stdout, stderr = ssh.exec_command("ss -tunp")
            output = stdout.read().decode('utf-8')

            # Simple parsing of 'ss' output
            # State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
            lines = output.splitlines()
            for line in lines[1:]:  # Skip header
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[4]
                    remote_addr = parts[5]
                    # Extract remote IP for classification
                    remote_ip = remote_addr.rsplit(':', 1)[0]
                    if remote_ip.startswith('['):
                        remote_ip = remote_ip.strip('[]')

                    connections.append({
                        "local_address": local_addr,
                        "remote_address": remote_addr,
                        "remote_classification": classify_ip(remote_ip),
                        "pid": None,
                        "process_name": "Unknown",
                        "status": map_tcp_state(parts[1])
                    })
            ssh.close()
        except paramiko.SSHException as e:
            logger.error(f"SSH collection failed on {target_ip}: {e}")
            if not self.accept_unknown_hosts and "host key" in str(e).lower():
                logger.error(
                    f"Unknown host key for {target_ip}. Add it to known_hosts "
                    "(e.g. 'ssh-keyscan {target_ip} >> ~/.ssh/known_hosts') or pass "
                    "--accept-unknown-hosts to skip verification."
                )
        except Exception as e:
            logger.error(f"SSH collection failed on {target_ip}: {e}")
        return connections

    def _collect_winrm(self, target_ip: str, username: str, password: str) -> List[Dict[str, Any]]:
        """Collect via WinRM."""
        connections = []
        # Clean username
        clean_username = username
        if clean_username.startswith(".\\"):
            clean_username = clean_username[2:]
        elif clean_username.startswith("localhost\\"):
            clean_username = clean_username[10:]

        cert_validation = 'ignore' if self.accept_invalid_certs else 'validate'

        try:
            session = winrm.Session(
                target_ip,
                auth=(clean_username, password),
                transport='ntlm',
                server_cert_validation=cert_validation
            )
            ps_script = """
            $connections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess;
            $processes = Get-Process | Select-Object Id, Name;
            $result = @{
                connections = $connections;
                processes = $processes
            };
            $result | ConvertTo-Json -Compress
            """
            result = session.run_ps(ps_script, operation_timeout_sec=30, read_timeout_sec=35)

            if result.status_code == 0:
                data = json.loads(result.std_out.decode('utf-8'))

                # Normalize PowerShell JSON to list (it might be a dict if single item)
                raw_conns = data.get('connections', [])
                if isinstance(raw_conns, dict):
                    raw_conns = [raw_conns]

                raw_procs = data.get('processes', [])
                if isinstance(raw_procs, dict):
                    raw_procs = [raw_procs]

                pid_map = {p['Id']: p['Name'] for p in raw_procs}

                for conn in raw_conns:
                    pid = conn.get('OwningProcess')
                    remote_ip = conn.get('RemoteAddress')

                    connections.append({
                        "local_address": f"{conn.get('LocalAddress')}:{conn.get('LocalPort')}",
                        "remote_address": f"{conn.get('RemoteAddress')}:{conn.get('RemotePort')}",
                        "remote_classification": classify_ip(remote_ip),
                        "pid": pid,
                        "process_name": pid_map.get(pid, "Unknown"),
                        "status": map_tcp_state(conn.get('State'))
                    })
            else:
                logger.error(f"WinRM collection failed on {target_ip}. Code: {result.status_code}. Error: {result.std_err.decode('utf-8')}")
        except Exception as e:
            status_code = getattr(e, 'status_code', 'N/A')
            logger.error(f"WinRM collection failed on {target_ip} (Code: {status_code}): {e}")
        return connections

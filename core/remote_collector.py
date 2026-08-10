import paramiko
import winrm
import json
import logging
import socket
from typing import List, Dict, Any, Optional

from utils.logger import logger
from utils.net_utils import map_tcp_state, classify_ip

class RemoteCollector:
    def __init__(self):
        # Set global socket timeout to 5 seconds
        socket.setdefaulttimeout(5)
        pass
...

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
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(target_ip, username=username, password=password, timeout=10)
            
            # Use 'ss' if available, otherwise 'netstat'
            stdin, stdout, stderr = ssh.exec_command("ss -tunp")
            output = stdout.read().decode('utf-8')
            
            # Simple parsing of 'ss' output
            # State  Recv-Q Send-Q Local Address:Port  Peer Address:Port Process
            lines = output.splitlines()
            for line in lines[1:]: # Skip header
                parts = line.split()
                if len(parts) >= 5:
                    local_addr = parts[4]
                    remote_addr = parts[5]
                    # Extract remote IP for classification
                    remote_ip = remote_addr.rsplit(':', 1)[0]
                    
                    connections.append({
                        "local_address": local_addr,
                        "remote_address": remote_addr,
                        "remote_classification": classify_ip(remote_ip),
                        "pid": None,
                        "process_name": "Unknown",
                        "status": map_tcp_state(parts[1])
                    })
            ssh.close()
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
        
        try:
            session = winrm.Session(
                target_ip,
                auth=(clean_username, password),
                transport='ntlm',
                server_cert_validation='ignore'
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
            result = session.run_ps(ps_script)
            
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

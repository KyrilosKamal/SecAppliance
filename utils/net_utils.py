import ipaddress
from typing import Union

def map_tcp_state(state: Union[str, int]) -> str:
    """
    Map numeric or string TCP connection states to human-readable strings.
    """
    mapping = {
        "2": "LISTEN",
        "5": "ESTABLISHED",
        "3": "SYN_SENT",
        "LISTEN": "LISTEN",
        "ESTABLISHED": "ESTABLISHED",
        "SYN_SENT": "SYN_SENT",
        "TIME_WAIT": "TIME_WAIT",
        "CLOSE_WAIT": "CLOSE_WAIT"
    }
    return mapping.get(str(state).upper(), "UNKNOWN")

def classify_ip(ip_str: str) -> str:
    """
    Classify an IP address as 'LAN' or 'WAN' based on private/loopback ranges.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
        if ip.is_private or ip.is_loopback:
            return "LAN"
        return "WAN"
    except ValueError:
        return "UNKNOWN"

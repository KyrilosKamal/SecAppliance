import ipaddress
from typing import Union

# Linux TCP state enum (include/net/tcp_states.h)
_TCP_STATE_CODES = {
    "1": "ESTABLISHED",
    "2": "SYN_SENT",
    "3": "SYN_RECV",
    "4": "FIN_WAIT1",
    "5": "FIN_WAIT2",
    "6": "TIME_WAIT",
    "7": "CLOSE",
    "8": "CLOSE_WAIT",
    "9": "LAST_ACK",
    "10": "LISTEN",
    "11": "CLOSING",
}

# Abbreviations used by 'ss' and Windows Get-NetTCPConnection
_TCP_STATE_ALIASES = {
    "SYN-SENT": "SYN_SENT",
    "SYN-RECV": "SYN_RECV",
    "SYN-RECEIVED": "SYN_RECV",
    "FIN-WAIT-1": "FIN_WAIT1",
    "FIN-WAIT-2": "FIN_WAIT2",
    "TIME-WAIT": "TIME_WAIT",
    "CLOSE-WAIT": "CLOSE_WAIT",
    "LAST-ACK": "LAST_ACK",
    "CLOSING": "CLOSING",
    "LISTENING": "LISTEN",
    "ESTAB": "ESTABLISHED",
    "LISTEN": "LISTEN",
    "ESTABLISHED": "ESTABLISHED",
    "SYN_SENT": "SYN_SENT",
    "SYN_RECV": "SYN_RECV",
    "FIN_WAIT1": "FIN_WAIT1",
    "FIN_WAIT2": "FIN_WAIT2",
    "TIME_WAIT": "TIME_WAIT",
    "CLOSE": "CLOSE",
    "CLOSE_WAIT": "CLOSE_WAIT",
    "LAST_ACK": "LAST_ACK",
    "BOUND": "BOUND",
    "SYNSENT": "SYN_SENT",
    "SYNRECEIVED": "SYN_RECV",
    "FINWAIT1": "FIN_WAIT1",
    "FINWAIT2": "FIN_WAIT2",
    "TIMEWAIT": "TIME_WAIT",
    "CLOSEWAIT": "CLOSE_WAIT",
    "LASTACK": "LAST_ACK",
}


def map_tcp_state(state: Union[str, int]) -> str:
    """
    Map numeric or string TCP connection states to human-readable strings.

    Accepts Linux numeric state codes, psutil states, 'ss' abbreviations,
    and Windows Get-NetTCPConnection states.
    """
    if state is None:
        return "UNKNOWN"
    key = str(state).strip().upper()
    if key in _TCP_STATE_CODES:
        return _TCP_STATE_CODES[key]
    return _TCP_STATE_ALIASES.get(key, "UNKNOWN")


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

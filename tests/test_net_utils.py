from secappliance.utils.net_utils import classify_ip, map_tcp_state


def test_state_numeric_and_aliases():
    assert map_tcp_state("10") == "LISTEN"
    assert map_tcp_state(1) == "ESTABLISHED"
    assert map_tcp_state("estab") == "ESTABLISHED"
    assert map_tcp_state("TIME-WAIT") == "TIME_WAIT"
    assert map_tcp_state(None) == "UNKNOWN"
    assert map_tcp_state("garbage") == "UNKNOWN"


def test_classify_ip():
    assert classify_ip("192.168.1.5") == "LAN"
    assert classify_ip("127.0.0.1") == "LAN"
    assert classify_ip("8.8.8.8") == "WAN"
    assert classify_ip("not-an-ip") == "UNKNOWN"

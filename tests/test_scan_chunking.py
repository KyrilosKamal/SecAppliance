import asyncio

from secappliance.core.network_scanner import NetworkScanner


class _DB:
    async def add_host_with_ports(self, *a, **k):
        return 1


def test_ports_scanned_in_bounded_chunks(monkeypatch):
    scanner = NetworkScanner(_DB(), offline=True)
    scanner.PORT_CHUNK = 100
    live = 0
    peak = 0

    async def fake_scan_port(ip, port):
        nonlocal live, peak
        live += 1
        peak = max(peak, live)
        await asyncio.sleep(0)
        live -= 1
        return None

    monkeypatch.setattr(scanner, "scan_port", fake_scan_port)
    asyncio.run(scanner.scan_host("127.0.0.1", 1, list(range(1, 1001))))
    assert peak <= 100

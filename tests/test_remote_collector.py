from secappliance.core.remote_collector import RemoteCollector

SS = """Netid State Recv-Q Send-Q Local Address:Port Peer Address:Port Process
tcp ESTAB 0 0 10.0.0.5:22 10.0.0.9:51000 users:(("sshd",pid=1,fd=3))
tcp LISTEN 0 128 0.0.0.0:80 0.0.0.0:*
tcp ESTAB 0 0 [::1]:5432 [::1]:40000
udp UNCONN 0 0 0.0.0.0:68
tcp short row
"""


def test_parse_ss_handles_short_rows_without_indexerror():
    conns = RemoteCollector.parse_ss_output(SS)
    assert len(conns) == 3  # 5-field and 3-field rows skipped, no crash
    assert conns[0]["status"] == "ESTABLISHED"
    assert conns[0]["remote_classification"] == "LAN"
    assert conns[2]["remote_classification"] == "LAN"  # ::1 stripped of brackets

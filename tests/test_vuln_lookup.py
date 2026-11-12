from secappliance.core.vuln_lookup import CVE_DB, get_vulns_for_service


def test_exact_banner_matches():
    hit = get_vulns_for_service("SSH", "SSH-2.0-OpenSSH_7.2p2 Ubuntu")
    assert [h["cve"] for h in hit] == ["CVE-2016-6210"]


def test_prefix_pattern_matches_patch_releases():
    assert get_vulns_for_service("MySQL", "MySQL 5.5.62")


def test_no_false_positive_on_longer_version():
    assert not get_vulns_for_service("MySQL", "MySQL 5.55")
    assert not get_vulns_for_service("HTTP", "Apache/2.4.490")


def test_empty_banner():
    assert get_vulns_for_service("SSH", "") == []


def test_removed_bad_signatures_stay_removed():
    ids = {e["cve"] for e in CVE_DB}
    assert "CVE-2013-0241" not in ids  # QXL driver, not Postfix
    assert "CVE-2018-7226" not in ids  # LibVNC/vncterm, not RealVNC

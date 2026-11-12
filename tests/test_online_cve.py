from secappliance.core.online_cve import _entry_matches, _version_matches, parse_banner


def rec(*versions):
    return {"containers": {"cna": {"affected": [{"versions": list(versions)}]}}}


def test_parse_banner():
    assert parse_banner("SSH-2.0-OpenSSH_8.9p1") == ("openssh", "8.9")
    assert parse_banner("Apache/2.4.52 (Ubuntu)") == ("apache", "2.4.52")
    assert parse_banner("nginx/1.18.0") == ("nginx", "1.18.0")
    assert parse_banner("") is None
    assert parse_banner("hello") is None


def test_exact_and_prefix():
    assert _entry_matches({"version": "2.4.52"}, "2.4.52") is True
    assert _entry_matches({"version": "2.4.52"}, "2.4.53") is False
    assert _entry_matches({"version": "2.4"}, "2.4.52") is True


def test_less_than_ranges():
    e = {"version": "2.4.0", "lessThan": "2.4.51"}
    assert _entry_matches(e, "2.4.49") is True
    assert _entry_matches(e, "2.4.51") is False
    assert _entry_matches(e, "2.3.9") is False
    e = {"version": "0", "lessThanOrEqual": "1.6.2"}
    assert _entry_matches(e, "1.6.2") is True
    assert _entry_matches(e, "1.18.0") is False


def test_textual_range():
    assert _entry_matches({"version": "through 1.6.2"}, "1.6.2") is True
    assert _entry_matches({"version": "through 1.6.2"}, "1.18.0") is False
    assert _entry_matches({"version": "before 2.0"}, "2.0") is False


def test_record_without_versions_is_kept():
    assert _version_matches({"containers": {"cna": {}}}, "1.0") is True


def test_record_level():
    r = rec({"version": "0", "lessThan": "1.7"}, {"version": "1.9.0"})
    assert _version_matches(r, "1.6.9") is True
    assert _version_matches(r, "1.9.0") is True
    assert _version_matches(r, "1.18.0") is False

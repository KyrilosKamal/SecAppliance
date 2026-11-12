import pytest
import typer

from secappliance.cli import parse_ports


def test_parse_ports_mixed():
    assert parse_ports("80,443,1000-1002") == [80, 443, 1000, 1001, 1002]


@pytest.mark.parametrize("bad", ["0", "70000", "abc", "10-5", "1-70000"])
def test_parse_ports_rejects_bad(bad):
    with pytest.raises(typer.Exit):
        parse_ports(bad)

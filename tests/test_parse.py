"""Tests for parse_ip / format_ip / parse_cidr."""

import pytest

from cidrcalc import CIDR, CidrCalcError, format_ip, parse_cidr, parse_ip


class TestParseIp:
    def test_zero(self):
        assert parse_ip("0.0.0.0") == 0

    def test_max(self):
        assert parse_ip("255.255.255.255") == 0xFFFFFFFF

    def test_typical(self):
        assert parse_ip("10.0.0.5") == (10 << 24) + 5

    def test_loopback(self):
        assert parse_ip("127.0.0.1") == 0x7F000001

    @pytest.mark.parametrize(
        "bad",
        [
            "",
            "10",
            "10.0.0",
            "10.0.0.0.0",
            "256.0.0.0",
            "10.0.0.-1",
            "10.0.0.a",
            "10.0.0.01",  # leading zero rejected
            "10. 0.0.1",
        ],
    )
    def test_rejects_bad(self, bad):
        with pytest.raises(CidrCalcError):
            parse_ip(bad)

    def test_rejects_non_str(self):
        with pytest.raises(CidrCalcError):
            parse_ip(123456)  # type: ignore[arg-type]


class TestFormatIp:
    def test_zero(self):
        assert format_ip(0) == "0.0.0.0"

    def test_max(self):
        assert format_ip(0xFFFFFFFF) == "255.255.255.255"

    def test_round_trip(self):
        for ip in ["10.0.0.5", "192.168.1.1", "127.0.0.1", "8.8.8.8"]:
            assert format_ip(parse_ip(ip)) == ip

    def test_rejects_negative(self):
        with pytest.raises(CidrCalcError):
            format_ip(-1)

    def test_rejects_too_large(self):
        with pytest.raises(CidrCalcError):
            format_ip(1 << 32)

    def test_rejects_bool(self):
        with pytest.raises(CidrCalcError):
            format_ip(True)  # type: ignore[arg-type]


class TestParseCidr:
    def test_basic(self):
        c = parse_cidr("10.0.0.0/24")
        assert isinstance(c, CIDR)
        assert c.prefix_len == 24
        assert c.network == 0x0A000000

    def test_implicit_host(self):
        c = parse_cidr("10.0.0.5")
        assert c.prefix_len == 32
        assert c.network == 0x0A000005

    def test_normalises_host_bits_when_zero(self):
        # Already on a network boundary — should pass.
        assert parse_cidr("10.0.0.0/24").network == 0x0A000000

    def test_rejects_set_host_bits(self):
        with pytest.raises(CidrCalcError):
            parse_cidr("10.0.0.5/24")

    def test_zero_prefix(self):
        c = parse_cidr("0.0.0.0/0")
        assert c.prefix_len == 0
        assert c.network == 0
        assert c.broadcast == 0xFFFFFFFF

    @pytest.mark.parametrize(
        "bad",
        [
            "10.0.0.0/",
            "10.0.0.0/33",
            "10.0.0.0/-1",
            "10.0.0.0/abc",
            "10.0.0/24",
            "256.0.0.0/24",
        ],
    )
    def test_rejects_bad(self, bad):
        with pytest.raises(CidrCalcError):
            parse_cidr(bad)

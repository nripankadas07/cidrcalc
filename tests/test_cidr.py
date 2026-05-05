"""Tests for CIDR class properties, contains, subnets, supernet, aggregate."""

import pytest

from cidrcalc import (
    CIDR,
    CidrCalcError,
    aggregate,
    contains,
    parse_cidr,
    parse_ip,
    subnets,
    supernet,
)


class TestCidrProperties:
    def test_24(self):
        c = parse_cidr("192.168.1.0/24")
        assert c.netmask == 0xFFFFFF00
        assert c.hostmask == 0x000000FF
        assert c.broadcast == 0xC0A801FF
        assert c.num_addresses == 256
        assert c.first == 0xC0A80101  # .1
        assert c.last == 0xC0A801FE   # .254

    def test_31(self):
        c = parse_cidr("10.0.0.0/31")
        assert c.num_addresses == 2
        # /31 has no network/broadcast distinction — both are usable.
        assert c.first == 0x0A000000
        assert c.last == 0x0A000001

    def test_32(self):
        c = parse_cidr("10.0.0.5/32")
        assert c.num_addresses == 1
        assert c.first == c.last == c.network

    def test_zero(self):
        c = parse_cidr("0.0.0.0/0")
        assert c.num_addresses == 1 << 32
        assert c.netmask == 0
        assert c.hostmask == 0xFFFFFFFF

    def test_str(self):
        assert str(parse_cidr("10.0.0.0/24")) == "10.0.0.0/24"
        assert str(parse_cidr("10.0.0.5")) == "10.0.0.5/32"

    def test_repr(self):
        assert repr(parse_cidr("10.0.0.0/24")) == "CIDR(10.0.0.0/24)"

    def test_construct_invalid_prefix(self):
        with pytest.raises(CidrCalcError):
            CIDR(network=0, prefix_len=33)

    def test_construct_with_host_bits(self):
        with pytest.raises(CidrCalcError):
            CIDR(network=parse_ip("10.0.0.5"), prefix_len=24)


class TestContains:
    def test_string_member(self):
        c = parse_cidr("10.0.0.0/24")
        assert contains(c, "10.0.0.5") is True
        assert contains(c, "10.0.1.0") is False

    def test_int_member(self):
        c = parse_cidr("10.0.0.0/24")
        assert contains(c, parse_ip("10.0.0.5")) is True
        assert contains(c, parse_ip("11.0.0.0")) is False

    def test_cidr_member(self):
        outer = parse_cidr("10.0.0.0/16")
        inner = parse_cidr("10.0.5.0/24")
        assert contains(outer, inner) is True
        assert contains(inner, outer) is False

    def test_in_operator(self):
        c = parse_cidr("10.0.0.0/24")
        assert "10.0.0.1" in c
        assert "11.0.0.1" not in c

    def test_in_operator_swallows_invalid(self):
        # Non-IP-looking string should yield False, not raise.
        c = parse_cidr("10.0.0.0/24")
        assert "not-an-ip" not in c

    def test_rejects_unknown_type(self):
        c = parse_cidr("10.0.0.0/24")
        with pytest.raises(CidrCalcError):
            contains(c, 1.5)  # type: ignore[arg-type]

    def test_rejects_bool(self):
        c = parse_cidr("10.0.0.0/24")
        # bool is technically int, but we should treat 0/1 as int membership.
        assert contains(c, True) is False  # 1 ∈ 10.0.0.0/24? No.


class TestSubnets:
    def test_split_24_into_26(self):
        result = list(subnets(parse_cidr("10.0.0.0/24"), 26))
        assert [str(c) for c in result] == [
            "10.0.0.0/26",
            "10.0.0.64/26",
            "10.0.0.128/26",
            "10.0.0.192/26",
        ]

    def test_no_change_same_prefix(self):
        result = list(subnets(parse_cidr("10.0.0.0/24"), 24))
        assert [str(c) for c in result] == ["10.0.0.0/24"]

    def test_rejects_smaller_prefix(self):
        with pytest.raises(CidrCalcError):
            list(subnets(parse_cidr("10.0.0.0/24"), 22))

    def test_split_full_space(self):
        result = list(subnets(parse_cidr("0.0.0.0/0"), 1))
        assert [str(c) for c in result] == ["0.0.0.0/1", "128.0.0.0/1"]


class TestSupernet:
    def test_default(self):
        s = supernet(parse_cidr("10.0.0.0/24"))
        assert str(s) == "10.0.0.0/23"

    def test_explicit(self):
        s = supernet(parse_cidr("10.0.0.5/32"), 24)
        assert str(s) == "10.0.0.0/24"

    def test_rejects_longer_prefix(self):
        with pytest.raises(CidrCalcError):
            supernet(parse_cidr("10.0.0.0/24"), 26)


class TestAggregate:
    def test_empty(self):
        assert aggregate([]) == []

    def test_single(self):
        c = parse_cidr("10.0.0.0/24")
        assert aggregate([c]) == [c]

    def test_merge_two_siblings(self):
        a = parse_cidr("10.0.0.0/25")
        b = parse_cidr("10.0.0.128/25")
        result = aggregate([a, b])
        assert [str(c) for c in result] == ["10.0.0.0/24"]

    def test_merge_chain(self):
        # /26 + /26 -> /25, /25 + /25 -> /24
        blocks = [
            parse_cidr("10.0.0.0/26"),
            parse_cidr("10.0.0.64/26"),
            parse_cidr("10.0.0.128/26"),
            parse_cidr("10.0.0.192/26"),
        ]
        result = aggregate(blocks)
        assert [str(c) for c in result] == ["10.0.0.0/24"]

    def test_drops_enclosed(self):
        outer = parse_cidr("10.0.0.0/16")
        inner = parse_cidr("10.0.5.0/24")
        result = aggregate([outer, inner])
        assert [str(c) for c in result] == ["10.0.0.0/16"]

    def test_non_adjacent(self):
        a = parse_cidr("10.0.0.0/24")
        b = parse_cidr("10.0.2.0/24")
        result = aggregate([a, b])
        assert [str(c) for c in result] == ["10.0.0.0/24", "10.0.2.0/24"]

    def test_rejects_non_cidr(self):
        with pytest.raises(CidrCalcError):
            aggregate(["10.0.0.0/24"])  # type: ignore[list-item]

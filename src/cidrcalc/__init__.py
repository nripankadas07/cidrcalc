"""cidrcalc — IPv4 CIDR arithmetic without the stdlib ``ipaddress`` module.

Public API:

* :func:`parse_cidr`     — parse ``"10.0.0.0/24"`` into a :class:`CIDR`.
* :func:`parse_ip`       — parse ``"10.0.0.5"`` into a 32-bit int.
* :func:`format_ip`      — format a 32-bit int as a dotted-quad string.
* :class:`CIDR`          — a normalised IPv4 CIDR block.
* :func:`contains`       — membership test for an IP in a CIDR.
* :func:`subnets`        — split a CIDR into equally-sized smaller CIDRs.
* :func:`supernet`       — produce the next-larger enclosing CIDR.
* :func:`aggregate`      — fold an iterable of CIDRs into the smallest set.
* :class:`CidrCalcError` — raised on any invalid input (ValueError subclass).
"""

from __future__ import annotations

from ._core import (
    CIDR,
    CidrCalcError,
    aggregate,
    contains,
    format_ip,
    parse_cidr,
    parse_ip,
    subnets,
    supernet,
)

__all__ = [
    "CIDR",
    "CidrCalcError",
    "aggregate",
    "contains",
    "format_ip",
    "parse_cidr",
    "parse_ip",
    "subnets",
    "supernet",
]

__version__ = "0.1.0"

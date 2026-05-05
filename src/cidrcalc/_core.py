"""Core cidrcalc implementation — pure-Python IPv4 CIDR arithmetic.

We deliberately avoid :mod:`ipaddress` from the stdlib to:

* Keep the API tightly scoped to IPv4 (no IPv6 surprises).
* Produce small, deterministic, JSON-friendly result types.
* Have full control over input validation messages.

Every public symbol is exported from :mod:`cidrcalc`.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable, Iterator, List


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


# IPv4 is 32 bits.
_IP_BITS = 32
_IP_MAX = (1 << _IP_BITS) - 1


class CidrCalcError(ValueError):
    """Raised for any malformed input to the cidrcalc API.

    Subclasses :class:`ValueError` so callers who only catch
    :class:`ValueError` still see these errors, while callers who want
    to distinguish them can match on :class:`CidrCalcError` directly.
    """


def parse_ip(text: str) -> int:
    """Parse a dotted-quad IPv4 string into a 32-bit integer.

    Args:
        text: A string like ``"10.0.0.5"``.

    Returns:
        The integer in the range ``[0, 2**32 - 1]``.

    Raises:
        CidrCalcError: If the input is not exactly four dot-separated
            decimal octets in the range ``[0, 255]``.
    """
    if not isinstance(text, str):
        raise CidrCalcError(f"expected str, got {type(text).__name__}")
    parts = text.split(".")
    if len(parts) != 4:
        raise CidrCalcError(f"not a dotted-quad IPv4 address: {text!r}")
    value = 0
    for part in parts:
        if not part or not part.isdigit() or (len(part) > 1 and part[0] == "0"):
            raise CidrCalcError(f"invalid octet {part!r} in {text!r}")
        n = int(part)
        if n > 255:
            raise CidrCalcError(f"octet out of range {part!r} in {text!r}")
        value = (value << 8) | n
    return value


def format_ip(value: int) -> str:
    """Format a 32-bit integer as a dotted-quad IPv4 string.

    Args:
        value: The integer in the range ``[0, 2**32 - 1]``.

    Returns:
        The dotted-quad representation, e.g. ``"10.0.0.5"``.

    Raises:
        CidrCalcError: If ``value`` is not in range.
    """
    if not isinstance(value, int) or isinstance(value, bool):
        raise CidrCalcError(f"expected int, got {type(value).__name__}")
    if value < 0 or value > _IP_MAX:
        raise CidrCalcError(f"IPv4 integer out of range: {value}")
    return ".".join(
        str((value >> shift) & 0xFF) for shift in (24, 16, 8, 0)
    )


@dataclass(frozen=True)
class CIDR:
    """A normalised IPv4 CIDR block.

    Attributes:
        network: The 32-bit integer network address (the host bits are
            always zero — :func:`parse_cidr` masks them off).
        prefix_len: The prefix length, in ``[0, 32]``.
    """

    network: int
    prefix_len: int

    def __post_init__(self) -> None:
        if not (0 <= self.prefix_len <= _IP_BITS):
            raise CidrCalcError(f"prefix length out of range: {self.prefix_len}")
        if not (0 <= self.network <= _IP_MAX):
            raise CidrCalcError(f"network out of range: {self.network}")
        host_mask = (1 << (_IP_BITS - self.prefix_len)) - 1
        if self.network & host_mask:
            raise CidrCalcError(
                f"network has host bits set: "
                f"{format_ip(self.network)}/{self.prefix_len}"
            )

    @property
    def netmask(self) -> int:
        """The 32-bit netmask integer."""
        return _netmask(self.prefix_len)

    @property
    def hostmask(self) -> int:
        """The 32-bit inverse netmask integer."""
        return _IP_MAX ^ self.netmask

    @property
    def broadcast(self) -> int:
        """The broadcast (last) address as a 32-bit integer."""
        return self.network | self.hostmask

    @property
    def num_addresses(self) -> int:
        """Total number of addresses in the block, including network and broadcast."""
        return 1 << (_IP_BITS - self.prefix_len)

    @property
    def first(self) -> int:
        """First *usable* host address, or the network for /31 and /32."""
        if self.prefix_len >= _IP_BITS - 1:
            return self.network
        return self.network + 1

    @property
    def last(self) -> int:
        """Last *usable* host address, or the broadcast for /31 and /32."""
        if self.prefix_len >= _IP_BITS - 1:
            return self.broadcast
        return self.broadcast - 1

    def __str__(self) -> str:
        return f"{format_ip(self.network)}/{self.prefix_len}"

    def __repr__(self) -> str:
        return f"CIDR({self!s})"

    def __contains__(self, item: object) -> bool:
        try:
            return contains(self, item)
        except CidrCalcError:
            return False


def _netmask(prefix_len: int) -> int:
    if prefix_len == 0:
        return 0
    return (_IP_MAX << (_IP_BITS - prefix_len)) & _IP_MAX


def parse_cidr(text: str) -> CIDR:
    """Parse a CIDR string ``"10.0.0.0/24"`` into a :class:`CIDR`.

    A bare ``"10.0.0.5"`` (no slash) is treated as ``/32``.

    Args:
        text: The CIDR string.

    Returns:
        A normalised :class:`CIDR` (host bits masked off).

    Raises:
        CidrCalcError: If the address or prefix length is invalid, or if
            host bits are set without being implicit.
    """
    if not isinstance(text, str):
        raise CidrCalcError(f"expected str, got {type(text).__name__}")
    if "/" in text:
        ip_part, _, prefix_part = text.partition("/")
        if not prefix_part:
            raise CidrCalcError(f"missing prefix length in {text!r}")
        if not prefix_part.isdigit():
            raise CidrCalcError(f"invalid prefix length {prefix_part!r}")
        prefix_len = int(prefix_part)
    else:
        ip_part = text
        prefix_len = _IP_BITS

    ip_int = parse_ip(ip_part)
    if not (0 <= prefix_len <= _IP_BITS):
        raise CidrCalcError(f"prefix length out of range: {prefix_len}")

    # Strict: reject IPs whose host bits are set inside the network.
    # If a caller has a host address and wants the enclosing block, they
    # can do ``CIDR(parse_ip(text) & netmask, prefix)`` themselves.
    if ip_int & ~_netmask(prefix_len):
        raise CidrCalcError(
            f"host bits set in {text!r}; mask explicitly to normalise"
        )
    return CIDR(network=ip_int, prefix_len=prefix_len)


def contains(cidr: CIDR, item: object) -> bool:
    """Return ``True`` if ``item`` is inside ``cidr``.

    ``item`` can be a 32-bit integer, a dotted-quad string, or another
    :class:`CIDR` (in which case the test is whether the *block* fits).
    """
    if not isinstance(cidr, CIDR):
        raise CidrCalcError(f"expected CIDR, got {type(cidr).__name__}")
    if isinstance(item, str):
        item_int = parse_ip(item)
        return cidr.network <= item_int <= cidr.broadcast
    if isinstance(item, int):  # bool is fine here — it coerces to 0/1
        if not (0 <= int(item) <= _IP_MAX):
            raise CidrCalcError(f"IPv4 integer out of range: {item}")
        return cidr.network <= int(item) <= cidr.broadcast
    if isinstance(item, CIDR):
        return (
            item.prefix_len >= cidr.prefix_len
            and cidr.network <= item.network
            and item.broadcast <= cidr.broadcast
        )
    raise CidrCalcError(f"unsupported membership check: {type(item).__name__}")


def subnets(cidr: CIDR, new_prefix_len: int) -> Iterator[CIDR]:
    """Yield the equally-sized subnets of ``cidr`` at ``new_prefix_len``.

    Args:
        cidr: The block to split.
        new_prefix_len: The new prefix length, must be ``>= cidr.prefix_len``.

    Yields:
        :class:`CIDR` instances in ascending network order.

    Raises:
        CidrCalcError: If ``new_prefix_len`` is smaller than the current
            prefix length, or out of range.
    """
    if not (0 <= new_prefix_len <= _IP_BITS):
        raise CidrCalcError(f"prefix length out of range: {new_prefix_len}")
    if new_prefix_len < cidr.prefix_len:
        raise CidrCalcError(
            f"cannot subnet /{cidr.prefix_len} into /{new_prefix_len}"
        )
    step = 1 << (_IP_BITS - new_prefix_len)
    for net in range(cidr.network, cidr.broadcast + 1, step):
        yield CIDR(network=net, prefix_len=new_prefix_len)


def supernet(cidr: CIDR, prefix_len: int | None = None) -> CIDR:
    """Return the enclosing supernet at ``prefix_len`` (default: one bit shorter).

    Args:
        cidr: The starting block.
        prefix_len: The desired prefix length. ``None`` means
            ``cidr.prefix_len - 1``.

    Returns:
        The enclosing :class:`CIDR`.

    Raises:
        CidrCalcError: If ``prefix_len`` is larger than the current prefix
            length, or out of range, or if shrinking past ``/0``.
    """
    if prefix_len is None:
        prefix_len = cidr.prefix_len - 1
    if not (0 <= prefix_len <= _IP_BITS):
        raise CidrCalcError(f"prefix length out of range: {prefix_len}")
    if prefix_len > cidr.prefix_len:
        raise CidrCalcError(
            f"supernet must be shorter than current /{cidr.prefix_len}"
        )
    network = cidr.network & _netmask(prefix_len)
    return CIDR(network=network, prefix_len=prefix_len)


def aggregate(blocks: Iterable[CIDR]) -> List[CIDR]:
    """Fold an iterable of CIDRs into the smallest equivalent set.

    The result is sorted by network address and merges adjacent
    same-prefix sibling blocks until no more merges are possible.

    Args:
        blocks: Any iterable of :class:`CIDR`.

    Returns:
        The minimal equivalent list of :class:`CIDR` blocks, sorted.

    Raises:
        CidrCalcError: If any element is not a :class:`CIDR`.
    """
    items: list[CIDR] = []
    for b in blocks:
        if not isinstance(b, CIDR):
            raise CidrCalcError(f"expected CIDR, got {type(b).__name__}")
        items.append(b)
    if not items:
        return []

    # Step 1: drop blocks already enclosed by another.
    items.sort(key=lambda c: (c.network, c.prefix_len))
    pruned: list[CIDR] = []
    for c in items:
        if pruned and contains(pruned[-1], c):
            continue
        pruned.append(c)

    # Step 2: repeatedly merge adjacent same-prefix sibling blocks.
    changed = True
    while changed:
        changed = False
        merged: list[CIDR] = []
        i = 0
        while i < len(pruned):
            if i + 1 < len(pruned):
                a, b = pruned[i], pruned[i + 1]
                if (
                    a.prefix_len == b.prefix_len
                    and a.prefix_len > 0
                    and a.broadcast + 1 == b.network
                    and (a.network >> (_IP_BITS - a.prefix_len + 1))
                    == (b.network >> (_IP_BITS - a.prefix_len + 1))
                ):
                    merged.append(supernet(a, a.prefix_len - 1))
                    i += 2
                    changed = True
                    continue
            merged.append(pruned[i])
            i += 1
        pruned = merged
    return pruned

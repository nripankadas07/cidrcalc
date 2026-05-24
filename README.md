# cidrcalc

IPv4 CIDR arithmetic for Python 3.10+. Zero dependencies. **No `ipaddress` import.**

* Strict dotted-quad parsing — leading zeros, out-of-range octets, malformed
  inputs all rejected with a clear `CidrCalcError`.
* Network / broadcast / netmask / hostmask / first / last / num_addresses.
* Membership: integer, string, or another `CIDR` block.
* Subnetting: split a block into equally-sized smaller blocks.
* Supernetting: enclosing block at any shorter prefix length.
* Aggregation: fold an iterable of blocks into the smallest equivalent set.

## Install

```bash
python -m pip install -e .
```

Or from a clone:

```bash
pip install -e .
```

## Quick start

```python
from cidrcalc import parse_cidr, contains, subnets, aggregate

c = parse_cidr("10.0.0.0/24")
str(c)              # '10.0.0.0/24'
c.num_addresses     # 256
c.first, c.last     # (167772161, 167772414)  -> 10.0.0.1 .. 10.0.0.254

contains(c, "10.0.0.5")     # True
"10.0.0.5" in c             # True

[str(s) for s in subnets(c, 26)]
# ['10.0.0.0/26', '10.0.0.64/26', '10.0.0.128/26', '10.0.0.192/26']

aggregate([parse_cidr("10.0.0.0/25"), parse_cidr("10.0.0.128/25")])
# [CIDR(10.0.0.0/24)]
```

## API reference

| Symbol | Purpose |
|---|---|
| `parse_ip(text)` | Dotted-quad string → 32-bit int. |
| `format_ip(value)` | 32-bit int → dotted-quad string. |
| `parse_cidr(text)` | `"10.0.0.0/24"` → `CIDR`. Bare IP → `/32`. |
| `CIDR(network, prefix_len)` | Frozen dataclass. Host bits must be zero. |
| `contains(cidr, x)` | Membership for int, str, or `CIDR`. |
| `subnets(cidr, new_prefix_len)` | Generator of equally-sized children. |
| `supernet(cidr, prefix_len=None)` | Enclosing block (default: one bit shorter). |
| `aggregate(blocks)` | Sort, drop enclosed, merge sibling pairs. |
| `CidrCalcError` | `ValueError` subclass for all bad input. |

## Running tests

```bash
pip install -e ".[dev]"
pytest -q
```

## License

MIT.

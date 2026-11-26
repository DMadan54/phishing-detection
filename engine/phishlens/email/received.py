"""Received headers, and which one to believe.

Every mail server that handles a message adds a Received header at the top,
recording who connected to it ("from ... [IP]") and who it is ("by ...").
So the headers read top to bottom are newest to oldest, and:

- The top headers were added by the recipient's own provider. The sender
  can't forge them, because they were written after the message left the
  sender's hands. The "from [IP]" in the right one is the real address of
  the server that delivered the message.
- The bottom headers were written before the message reached anyone the
  recipient trusts. The sender can put anything there, including whole
  fake hops, so they prove nothing.

SPF must therefore be checked against the IP in the topmost hop that
records a connection from the outside world, never against a lower one.

There's no maintained parser for this header (its format is very loose),
so this one only pulls out the parts the checks need and leaves the rest.
"""

import ipaddress
import re
from collections.abc import Iterable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address

_FROM = re.compile(r"^\s*from\s+(?P<helo>[^\s;()]+)?(?P<rest>.*?)(?=\bby\b|;|$)", re.I | re.S)
_IP_IN_BRACKETS = re.compile(r"\[(?:IPv6:)?(?P<ip>[0-9A-Fa-f:.]+)\]")
_RDNS = re.compile(r"\(\s*(?P<rdns>[A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_BY = re.compile(r"\bby\s+(?P<by>[^\s;()]+)", re.I)

# Addresses that belong to a private or internal network. A hop from one of
# these is a handoff inside some provider's network, not the delivery from
# outside. Documentation ranges (192.0.2.0/24 and friends) are deliberately
# not listed: the test fixtures use them as "outside" addresses.
_INTERNAL_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "10.0.0.0/8",
        "172.16.0.0/12",
        "192.168.0.0/16",
        "100.64.0.0/10",
        "127.0.0.0/8",
        "169.254.0.0/16",
        "0.0.0.0/8",
        "::1/128",
        "fc00::/7",
        "fe80::/10",
        "::/128",
    )
)


@dataclass(frozen=True, slots=True)
class ReceivedHop:
    index: int  # 0 is the top (newest) header
    raw: str
    from_helo: str | None  # the name the connecting server introduced itself with
    from_rdns: str | None  # the name its IP resolved to, if the receiver recorded it
    from_ip: IPAddress | None
    by_host: str | None
    timestamp: datetime | None


def parse_received(value: str, index: int) -> ReceivedHop:
    text = " ".join(value.split())
    helo = rdns = None
    ip: IPAddress | None = None

    from_match = _FROM.match(text)
    if from_match:
        helo = (from_match.group("helo") or "").lower() or None
        rest = from_match.group("rest")
        ip_match = _IP_IN_BRACKETS.search(rest)
        if ip_match:
            ip = _parse_ip(ip_match.group("ip"))
        rdns_match = _RDNS.search(rest)
        if rdns_match:
            rdns = rdns_match.group("rdns").lower()
        if ip is None and helo:
            ip = _parse_ip(helo.strip("[]"))

    by_match = _BY.search(text)
    by_host = by_match.group("by").lower().rstrip(".") if by_match else None

    timestamp = None
    if ";" in text:
        timestamp = _parse_date(text.rsplit(";", 1)[1])

    return ReceivedHop(index, value, helo, rdns, ip, by_host, timestamp)


def is_internal(ip: IPAddress) -> bool:
    return any(ip in net for net in _INTERNAL_NETWORKS if net.version == ip.version)


def _matches(host: str | None, trusted: Iterable[str]) -> bool:
    if not host:
        return False
    return any(host == t or host.endswith("." + t) for t in trusted)


def sending_hop(
    hops: Sequence[ReceivedHop], trusted_receivers: frozenset[str]
) -> ReceivedHop | None:
    """The hop that records the delivery from the outside world.

    Without configuration: the topmost hop with an external "from" IP.

    With trusted_receivers configured (the recipient's own mail hosts):
    walk down from the top while each hop was written "by" a trusted host.
    The first one whose sender is not itself trusted is the delivery. If the
    chain reaches a hop not written by a trusted host first, nothing can be
    trusted and None is returned.
    """
    for hop in hops:
        if trusted_receivers and not _matches(hop.by_host, trusted_receivers):
            return None
        if hop.from_ip is None or is_internal(hop.from_ip):
            continue
        if trusted_receivers and (
            _matches(hop.from_helo, trusted_receivers) or _matches(hop.from_rdns, trusted_receivers)
        ):
            continue
        return hop
    return None


def _parse_ip(text: str) -> IPAddress | None:
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _parse_date(text: str) -> datetime | None:
    try:
        parsed = parsedate_to_datetime(text.strip())
    except (TypeError, ValueError, IndexError):
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=UTC)

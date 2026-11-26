"""Domain helpers: normalising hosts and working out who owns a domain.

The "organisational domain" is the part of a name someone actually
registered: mail.paypal.com and paypal.com both belong to paypal.com, but
a.co.uk and b.co.uk belong to different people. The Public Suffix List says
where the registrable part starts. publicsuffixlist ships a copy of it, so
nothing is downloaded at runtime (the copy is updated by upgrading the
package).

The full list is used, including private suffixes such as github.io, so
alice.github.io and mallory.github.io count as different owners.

DMARC (RFC 7489) defines alignment with exactly this organisational domain.
"""

import ipaddress
from functools import cache
from typing import Literal

import idna
from publicsuffixlist import PublicSuffixList

AlignmentMode = Literal["relaxed", "strict"]


@cache
def _psl() -> PublicSuffixList:
    return PublicSuffixList()


def normalise_domain(name: str) -> str | None:
    """Lower-case ASCII (punycode) form of a domain, or None if it isn't one.

    Internationalised names are converted with UTS #46 processing, the same
    mapping browsers apply, so "PayPal.com." and "paypal.com" compare equal.
    """
    name = name.strip().rstrip(".")
    if not name or any(c.isspace() for c in name):
        return None
    try:
        return idna.encode(name, uts46=True).decode("ascii").lower()
    except (idna.IDNAError, UnicodeError):
        return None


def org_domain(domain: str) -> str:
    """The registrable domain: "mail.paypal.com" -> "paypal.com".

    A name that is itself a public suffix (like "co.uk") is returned as is.
    """
    return _psl().privatesuffix(domain) or domain


def aligned(a: str, b: str, mode: AlignmentMode = "relaxed") -> bool:
    """DMARC alignment: strict needs the same name, relaxed the same owner."""
    a, b = a.lower().rstrip("."), b.lower().rstrip(".")
    if mode == "strict":
        return a == b
    return org_domain(a) == org_domain(b)


def same_owner(a: str, b: str) -> bool:
    return aligned(a, b, "relaxed")


def domain_of_address(address: str) -> str | None:
    """The normalised domain of an email address, or None."""
    _, at, domain = address.rpartition("@")
    return normalise_domain(domain) if at else None


def as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """The IP address a host names directly, or None for a domain name.

    Accepts the bracketed IPv6 form from URLs ("[2001:db8::1]").
    """
    host = host.strip().removeprefix("[").removesuffix("]")
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None
